<#
.SYNOPSIS
    PRA Remote Mailbox - hybrid Exchange disaster recovery: turns on-premises mailboxes into remote
    mailboxes (Exchange Online) when the on-premises Exchange servers are lost, and rolls back later.

.DESCRIPTION
    Four actions, all driven by config\PraRemoteMailbox.config.psd1:

      Convert   On-premises mailbox -> remote mailbox. AD attributes are rewritten (backup first),
                users are added to the licence group, Entra Connect synchronises, then the tool waits
                for the Exchange Online mailboxes and grants the shared mailbox permissions.
      Recover   Roll back a Convert batch: original AD attributes, licence group, shared mailboxes
                deprovisioned in Exchange Online before their on-premises attributes come back.
      Finalize  Last step of a Recover done on two servers: applies, on the AD server, the Finalize
                package produced by the cloud phase.
      Check     Read-only Exchange Online check (mailbox provisioned / deprovisioned / retention).

    Every run starts in Preview: the tool reads, plans and shows the changes, and writes nothing.
    -Mode Apply performs the changes, after one confirmation (or none with -Force). A complete,
    re-read backup of every target is written before the first change; the first error stops the
    batch. Each Apply prints a short batch ID: the next steps use it (-Batch).

    The AD part and the cloud part can run on the same server (Execution.Phase = Both) or on two
    servers (Phase AD, then Phase Cloud with a copy of the batch folder).

.PARAMETER Action
    Convert, Recover, Finalize or Check.

.PARAMETER Mode
    Preview (default): read, plan and report; nothing is changed.
    Apply: perform the changes (one confirmation unless -Force).

.PARAMETER Phase
    Convert and Recover only. Default: Execution.Phase in the configuration.
      Both   AD part, synchronisation, then Exchange Online part on this server.
      AD     AD part only (and synchronisation). The cloud part runs later with -Phase Cloud.
      Cloud  Exchange Online part only, from the batch of the AD part (-Batch). Recover packages
             any final AD restoration for Finalize on the AD server; it never restores AD here.

.PARAMETER Batch
    Batch ID printed at the end of an Apply (8 characters are enough), or the full path of the batch
    JSON file. Required by: Recover (the Convert batch), -Phase Cloud (the batch of the AD part),
    Finalize (the Finalize package). Optional for Check.

.PARAMETER Identity
    One object only. Convert: UPN, sAMAccountName, DN or GUID, instead of the configured scope.
    Recover, cloud phase, Check: one object of the batch (or any UPN for Check).

.PARAMETER Scope
    All (default), UsersOnly or SharedOnly: filters the configured scope or the batch.

.PARAMETER SearchBase
    Convert AD/Both only: select an OU (distinguished name), including its child OUs, for this run.
    Overrides Scope.Mode/SearchBase without changing the configuration. Cannot be combined with Identity or CsvPath.

.PARAMETER CsvPath
    Convert AD/Both only: select a CSV with an Identity column for this run (comma or semicolon).
    Overrides the configured scope without rewriting it. Cannot be combined with Identity or SearchBase.

.PARAMETER MaxObjects
    Convert: process at most N objects (after sorting by sAMAccountName). 0 = no limit.

.PARAMETER Expect
    Check only: Provisioned (default), Deprovisioned or Retained (retention policy coverage).

.PARAMETER ConfigPath
    Configuration file. Default: config\PraRemoteMailbox.config.psd1 next to this script.

.PARAMETER Force
    Apply without the confirmation prompt (scheduled or unattended runs). Never skips a safety check.

.PARAMETER Once
    Cloud checks: one pass only instead of waiting (Polling.TimeoutMinutes) for the cloud.

.PARAMETER PassThru
    Also returns the result of the run as an object (Status, ExitCode, BatchId, NextSteps, counters,
    log and report paths), for a script or an orchestrator. Without it, nothing is written to the pipeline.

.PARAMETER Gui
    Opens the WPF window. PowerShell 7.5+ uses the native Fluent theme; Windows PowerShell 5.1 uses
    compatible WPF controls. Every operation runs in its own Windows PowerShell 5.1 process.

.EXAMPLE
    pwsh -STA -File .\Invoke-PraRemoteMailbox.ps1 -Gui
    Opens the Fluent window with explicit AD + cloud, AD-only and cloud-only execution.

.EXAMPLE
    .\Invoke-PraRemoteMailbox.ps1 -Action Convert
    Preview of the conversion of the configured scope: targets and planned AD changes, nothing written.

.EXAMPLE
    .\Invoke-PraRemoteMailbox.ps1 -Action Convert -Mode Apply
    Converts the configured scope: backup, AD changes, Entra Connect sync, Exchange Online checks and permissions.

.EXAMPLE
    .\Invoke-PraRemoteMailbox.ps1 -Action Convert -Mode Apply -Identity user01@contoso.com -WhatIf
    -WhatIf always means Preview, even with -Mode Apply.

.EXAMPLE
    .\Invoke-PraRemoteMailbox.ps1 -Action Recover -Mode Apply -Batch 490cc62e
    Rolls back the Convert batch 490cc62e.

.EXAMPLE
    .\Invoke-PraRemoteMailbox.ps1 -Action Convert -Phase Cloud -Mode Apply -Batch 490cc62e
    Two-server setup: Exchange Online part of the Convert batch 490cc62e (folder copied from the AD server).

.EXAMPLE
    .\Invoke-PraRemoteMailbox.ps1 -Action Check -Identity user01@contoso.com -Expect Provisioned
    Read-only check of one mailbox in Exchange Online.

.NOTES
    Author     : Nicolas Fabert
    Version    : 2.2.0
    Requires   : Windows PowerShell 5.1 (not PowerShell 7), RSAT ActiveDirectory, ExchangeOnlineManagement
                 3.10+, Microsoft.Graph.Authentication and Microsoft.Graph.Users (cloud part), ADSync (sync).
    Exit codes : 0 = done, 1 = failed, 2 = done but a next step is required (Pending objects).
    Documentation : docs\PraRemoteMailbox-Guide.md (or .html)

    Disclaimer:
    This Script is a Personal project.
    It's provided "AS-IS". It's not an official Microsoft product so no support can be expected from Microsoft.

    As any scripts you must read carefully the documentation and test it first in a Test environment before any run in Production.

    The tool changes production objects in Active Directory and creates mailboxes in Exchange Online: run the preview, review the plan, keep the backups and test in a lab before using it in a real disaster.
#>
#Requires -Version 5.1
[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High', DefaultParameterSetName = 'Run')]
param(
    [Parameter(Mandatory, ParameterSetName = 'Run')][ValidateSet('Convert','Recover','Finalize','Check')][string]$Action,
    [Parameter(ParameterSetName = 'Run')][ValidateSet('Preview','Apply')][string]$Mode = 'Preview',
    [Parameter(ParameterSetName = 'Run')][ValidateSet('Both','AD','Cloud')][string]$Phase,
    [Parameter(ParameterSetName = 'Run')][string]$Batch,
    [Parameter(ParameterSetName = 'Run')][string]$Identity,
    [Parameter(ParameterSetName = 'Run')][string]$SearchBase,
    [Parameter(ParameterSetName = 'Run')][string]$CsvPath,
    [Parameter(ParameterSetName = 'Run')][ValidateSet('All','UsersOnly','SharedOnly')][string]$Scope = 'All',
    [Parameter(ParameterSetName = 'Run')][ValidateRange(0, 2147483647)][int]$MaxObjects = 0,
    [Parameter(ParameterSetName = 'Run')][ValidateSet('Provisioned','Deprovisioned','Retained')][string]$Expect = 'Provisioned',
    [string]$ConfigPath,
    [Parameter(ParameterSetName = 'Run')][switch]$Force,
    [Parameter(ParameterSetName = 'Run')][switch]$Once,
    [Parameter(ParameterSetName = 'Run')][switch]$PassThru,
    [Parameter(Mandatory, ParameterSetName = 'Gui')][switch]$Gui
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
# >>> PRA package integrity bootstrap: identical in every runtime PowerShell file (checked by the tests).
# It authenticates module\Test-PackageIntegrity.ps1 before running it; there is no unsigned or bypass path.
& {
    param([Parameter(Mandatory)][string]$PackageRoot)
    $verifier = [IO.Path]::GetFullPath([IO.Path]::Combine($PackageRoot, 'module', 'Test-PackageIntegrity.ps1'))
    $cursor = $verifier
    while ($cursor) {
        $item = Microsoft.PowerShell.Management\Get-Item -LiteralPath $cursor -Force -ErrorAction Stop
        if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw "Package integrity: reparse point: $cursor" }
        $cursor = [IO.Path]::GetDirectoryName($cursor)
    }
    $signature = Microsoft.PowerShell.Security\Get-AuthenticodeSignature -LiteralPath $verifier -ErrorAction Stop
    if ([string]$signature.Status -cne 'Valid' -or $null -eq $signature.SignerCertificate -or
        $signature.SignerCertificate.Thumbprint -cne '0F28E442889F17B5F4D251E8F96E7CC6E2C9C6D6' -or
        $null -eq $signature.TimeStamperCertificate) {
        throw 'Package integrity: verifier must have the trusted, timestamped owner signature.'
    }
    & $verifier -Root $PackageRoot
} $PSScriptRoot
# <<< PRA package integrity bootstrap
# Not a parameter default: Windows PowerShell 5.1 leaves $PSScriptRoot empty in param() defaults when the script
# runs with powershell.exe -File (scheduled task). An explicit -ConfigPath is unchanged ($script:ConfigPathBound).
if (-not $ConfigPath) { $ConfigPath = Join-Path $PSScriptRoot 'config\PraRemoteMailbox.config.psd1' }
if ($Gui) {
    try {
        Import-Module (Join-Path $PSScriptRoot 'module\PRA.Common.psm1') -Force -ErrorAction Stop
        Import-Module (Join-Path $PSScriptRoot 'module\PRA.Gui.psm1') -Force -ErrorAction Stop
        Show-PraGui -Root $PSScriptRoot -ConfigPath $ConfigPath -Version '2.2.0'
        exit 0
    }
    catch { Write-Error ('The window could not open: {0}' -f $_.Exception.Message) -ErrorAction Continue; exit 1 }
}
if ($PSVersionTable.PSEdition -ne 'Desktop') {
    Write-Error "$Action runs in Windows PowerShell 5.1 Desktop (powershell.exe), not PowerShell 7. Use powershell.exe -File .\Invoke-PraRemoteMailbox.ps1 with the same parameters, or -Gui for the window." -ErrorAction Continue
    exit 1
}
Import-Module (Join-Path $PSScriptRoot 'module\PRA.Common.psm1') -Force -ErrorAction Stop
Import-Module (Join-Path $PSScriptRoot 'module\PRA.Directory.psm1') -Force -ErrorAction Stop

# -WhatIf always wins: the run becomes a Preview whatever -Mode says.
$effectiveMode = if ($WhatIfPreference) { 'Preview' } else { $Mode }
if ($Force -and -not $PSBoundParameters.ContainsKey('Confirm')) { $ConfirmPreference = 'None' }
$caller = $PSCmdlet
function New-PraApprovalCallback {
    <# Callback asked before every AD / Exchange Online write (ShouldProcess: -WhatIf, -Confirm). #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Only builds a callback; the callback itself calls ShouldProcess of the entry script.')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '', Justification = 'ShouldProcess is called on the cmdlet of the entry script, which supports it.')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSReviewUnusedParameter', '', Justification = 'Both parameters are captured by the closure (GetNewClosure).')]
    param($Cmdlet, [hashtable]$RunContext)
    # Created in this function so that the closure only captures these two variables. ShouldProcess
    # reads $ConfirmPreference from the calling scope: it is set from the run context ('None' with
    # -Force, or after the one confirmation of the run).
    return {
        param($Target, $Operation)
        $ConfirmPreference = $RunContext.ConfirmPreference
        $Cmdlet.ShouldProcess([string]$Target, [string]$Operation)
    }.GetNewClosure()
}
$context = @{
    Root = $PSScriptRoot; Version = '2.2.0'; RunId = ((Get-Date -Format 'yyyyMMdd_HHmmss') + '-' + [guid]::NewGuid().ToString('N'))
    StartTime = Get-Date; Action = $Action; Mode = $effectiveMode; Phase = ''
    CurrentPhase = 'Start'; CurrentOperation = ''; CurrentIdentity = ''; StepIndex = 0; StepTotal = 0; Warnings = 0
    Issues = (New-Object 'Collections.Generic.List[object]'); Rows = (New-Object 'Collections.Generic.List[object]')
    BackupFiles = (New-Object 'Collections.Generic.List[string]'); StateFiles = (New-Object 'Collections.Generic.List[string]')
    LogFolder = (Join-Path $PSScriptRoot 'logs'); ReportFolder = (Join-Path $PSScriptRoot 'reports'); BackupFolder = (Join-Path $PSScriptRoot 'Backups')
    LogFile = ''; TranscriptPath = ''; TranscriptStarted = $false; NoReport = $false
    Server = ''; NamingContext = ''; CloudConnectFailed = $false; ExitCode = 0; ResultStatus = ''
    AllowMutation = ($effectiveMode -eq 'Apply' -and $Action -ne 'Check'); Config = @{}; KeepCloudShared = $false
    Approval = $null; ConfirmPreference = [string]$ConfirmPreference
    Once = [bool]$Once; IntervalMinutes = 0; TimeoutMinutes = 0; CloudCheckScope = 'Both'
    VerboseEnabled = ($VerbosePreference -eq 'Continue' -or $DebugPreference -eq 'Continue')
    SourceBackupHash = ''; Source = $null; Proof = $null; LastVerifiedReceipt = $null; OperationFailed = $false; JournalPath = ''
    BatchId = ''; NextSteps = @()
}
$context.Approval = New-PraApprovalCallback $caller $context

# =================================================================================================
# Helper functions of the entry script (they use $context).
# =================================================================================================

function Get-PraShortId {
    <# First 8 characters of a batch or package ID, as shown to the operator. #>
    param([string]$Id)
    if ($Id.Length -gt 8) { return $Id.Substring(0, 8) }
    return $Id
}

function Get-PraCommandLine {
    <# Command line suggested in "Next step", with the options of this run that still apply. #>
    param([string]$ActionName, [string]$ModeName = 'Apply', [string]$PhaseName = '', [string]$BatchId = '', [switch]$KeepFilters, [switch]$OtherServer)
    $parts = @('.\Invoke-PraRemoteMailbox.ps1', "-Action $ActionName")
    if ($PhaseName) { $parts += "-Phase $PhaseName" }
    if ($ModeName -eq 'Apply') { $parts += '-Mode Apply' }
    if ($BatchId) { $parts += $(if ($BatchId -match '[\\/ ]') { "-Batch '$BatchId'" } else { "-Batch $BatchId" }) }
    if ($KeepFilters) {
        if ($Identity) { $parts += "-Identity '$Identity'" }
        if ($Scope -ne 'All') { $parts += "-Scope $Scope" }
        if ($MaxObjects -gt 0) { $parts += "-MaxObjects $MaxObjects" }
        if ($SearchBase) { $parts += "-SearchBase '" + $SearchBase.Replace("'","''") + "'" }
        if ($CsvPath) { $parts += "-CsvPath '" + $CsvPath.Replace("'","''") + "'" }
    }
    # On another server the configuration file is that server's own: -ConfigPath is not repeated.
    if ($script:ConfigPathBound -and -not $OtherServer) { $parts += "-ConfigPath '$ConfigPath'" }
    return ($parts -join ' ')
}

function Get-PraBatchFile {
    <#
    .SYNOPSIS
        Finds the JSON file of a batch from its ID (8+ hexadecimal characters) or from a path.
    .DESCRIPTION
        Batch folders are named Batch-<id> (Convert, Recover, Finalize backups) and Finalize-<id>
        (Finalize package produced by the cloud phase of a Recover). The ID prefix must match one
        folder only under Storage.BackupFolder. The file is chosen by its Operation field.
    .PARAMETER Operations
        Accepted values of the Operation field of the JSON file (Convert, Recover, RecoverFinalize).
    #>
    param([Parameter(Mandatory)][string]$Value, [Parameter(Mandatory)][string[]]$Operations)
    $context.CurrentOperation = 'Resolve-Batch'
    $candidate = $null
    if ($Value -match '[\\/:]' -or $Value -like '*.json') {
        $candidate = Resolve-PraPath $Value 'Batch' (Get-Location).Path
        if (Test-Path -LiteralPath $candidate -PathType Container) { $folders = @(Get-Item -LiteralPath $candidate) }
        elseif (Test-Path -LiteralPath $candidate -PathType Leaf) { return $candidate }
        else { throw "Batch file or folder not found: $candidate" }
    } else {
        if ($Value -notmatch '^[0-9a-fA-F]{8,32}$') { throw "Invalid batch ID '$Value': use the 8 characters (or more) shown at the end of the previous run, or the path of the batch JSON file." }
        if (-not (Test-Path -LiteralPath $context.BackupFolder -PathType Container)) { throw "Backup folder not found: $($context.BackupFolder)" }
        $folders = @(Get-ChildItem -LiteralPath $context.BackupFolder -Directory -Recurse -ErrorAction Stop |
            Where-Object { $_.Name -match ('^(Batch|Finalize)-' + [regex]::Escape($Value.ToLowerInvariant())) })
        if (-not $folders.Count) { throw "Batch $Value not found under $($context.BackupFolder). Copy the batch folder there (Batch-$Value... or Finalize-$Value...) or give the path of its JSON file." }
        if (@($folders | Select-Object -ExpandProperty Name -Unique).Count -gt 1) { throw "Batch ID $Value is ambiguous ($($folders.Count) folders): give more characters." }
    }
    $found = New-Object 'Collections.Generic.List[string]'
    foreach ($folder in $folders) {
        foreach ($file in @(Get-ChildItem -LiteralPath $folder.FullName -File -Filter '*.json' -ErrorAction Stop | Where-Object { $_.Name -notlike 'State-*' })) {
            try { $operation = [string](([IO.File]::ReadAllText($file.FullName) | ConvertFrom-Json -ErrorAction Stop).Operation) } catch { continue }
            # In a Finalize package only the manifest counts (the other JSON files are copies of the source batches).
            if ($operation -in $Operations -and ($folder.Name -match '^Batch-' -or $operation -eq 'RecoverFinalize')) { $found.Add($file.FullName) }
        }
    }
    # The same batch folder copied twice (identical content) is not an ambiguity.
    $distinct = @($found | Group-Object { Get-PraHash $_ } | ForEach-Object { $_.Group[0] })
    if ($distinct.Count -ne 1) { throw ("Batch {0}: expected one {1} file, found {2}. Check the batch ID (the batch of the previous step is expected)." -f $Value, ($Operations -join '/'), $distinct.Count) }
    return $distinct[0]
}

function Find-PraConvertSource {
    <#
    .SYNOPSIS
        Finds the original Convert backup whose SHA-256 is $Hash (read from the .sha256 files only).
        Used by the cloud phase of a Recover: the Recover batch knows the hash of its Convert source.
    #>
    param([Parameter(Mandatory)][string]$Hash)
    $found = @(Get-ChildItem -LiteralPath $context.BackupFolder -Recurse -File -Filter 'Convert-*.json.sha256' -ErrorAction Stop | Where-Object {
            ([IO.File]::ReadAllText($_.FullName).Trim()) -ceq $Hash } | ForEach-Object { $_.FullName.Substring(0, $_.FullName.Length - 7) })
    $original = @($found | Where-Object { (Split-Path (Split-Path $_ -Parent) -Leaf) -match '^Batch-' })
    if ($original.Count) { $found = $original }
    if (-not $found.Count) { throw "The Convert batch used by this Recover is not in $($context.BackupFolder). Copy its Batch-... folder there as well." }
    return $found[0]
}

function Select-PraSourceRecord {
    <# Records of a batch kept for this run (-Identity, -Scope). #>
    param($Source)
    $records = @($Source.Data.Records)
    if ($Identity) {
        $records = @($records | Where-Object { $_.SamAccountName -eq $Identity -or $_.UserPrincipalName -eq $Identity -or $_.ObjectGuid -eq $Identity })
        if ($records.Count -ne 1) { throw "Identity '$Identity' is not in the batch (or matches several objects)." }
    }
    elseif ($Scope -eq 'SharedOnly') { $records = @($records | Where-Object IsShared) }
    elseif ($Scope -eq 'UsersOnly') { $records = @($records | Where-Object { -not $_.IsShared }) }
    return $records
}

function Initialize-PraCloudAuthority {
    <#
    .SYNOPSIS
        Callbacks given to the cloud module. Before each Exchange Online write, AssertCloudAuthorization
        re-reads the AD proof of the object; JournalMutation records the write in the batch journal.
    #>
    # GetNewClosure captures local variables, not the $context of the script: copy it first.
    $capturedContext = $context
    $context.AssertCloudAuthorization = {
        param($Row)
        if (-not $capturedContext.AllowMutation -or $capturedContext.OperationFailed -or $capturedContext.Issues.Count -gt 0 -or $null -eq $capturedContext.Proof) { throw 'Cloud write refused: no authorisation or the run already has an error.' }
        $proof = Import-PraProof $capturedContext $capturedContext.Proof.Path $capturedContext.Source $capturedContext.Action
        if (@($proof.Data.Records | Where-Object ObjectGuid -eq $Row.ObjectGuid).Count -ne 1) { throw 'Cloud write refused: the object is not in a verified AD phase.' }
        Assert-PraReceipt $capturedContext $capturedContext.Source $Row.ObjectGuid
    }.GetNewClosure()
    $context.JournalMutation = { param($Target, $Operation, $Status, $Detail) Write-PraJournal $capturedContext $Target $Operation $Status ([string]$Detail) }.GetNewClosure()
}

function Initialize-PraCloudJournal {
    <# Private folder <RunId>-cloud with the journal of the Exchange Online writes of this run. #>
    $directory = Join-Path $context.BackupFolder ($context.RunId + '-cloud')
    New-PraPrivateDirectory $directory
    $context.JournalPath = Join-Path $directory 'CloudOperations.jsonl'
    Write-PraImmutableFile $context.JournalPath ''
    $context.StateFiles.Add($context.JournalPath)
    Write-PraJournal $context '*' 'CloudPhase' 'Initialized' 'AD proof loaded; no cloud write yet.'
}

function Copy-PraBundleFile {
    param([string]$Path, [string]$Directory)
    $destination = Join-Path $Directory ([IO.Path]::GetFileName($Path))
    if (Test-Path -LiteralPath $destination) {
        if ((Get-PraHash $Path) -cne (Get-PraHash $destination)) { throw 'Two different files with the same name in the Finalize package.' }
        return
    }
    [IO.File]::Copy($Path, $destination, $false)
    if ((Get-PraHash $Path) -cne (Get-PraHash $destination)) { throw 'Copy of a proof file is incomplete.' }
}

function Copy-PraBackupBundle {
    param($Receipt, [string]$Directory)
    Copy-PraBundleFile $Receipt.Path $Directory
    if (-not $Receipt.Legacy) {
        Copy-PraBundleFile ($Receipt.Path + '.sha256') $Directory
        Copy-PraBundleFile (Join-Path (Split-Path $Receipt.Path -Parent) $Receipt.Data.RawFile) $Directory
    }
}

function Save-PraFinalizePackage {
    <#
    .SYNOPSIS
        Recover on two servers: writes the Finalize package (manifest + copies of the Convert and
        Recover batches) that the AD server applies with -Action Finalize.
    #>
    param([object[]]$Rows)
    if (-not $context.AllowMutation -or -not (& $context.Approval 'AD server' 'Publish a Finalize package')) { throw 'Finalize package not authorised.' }
    $proof = Import-PraProof $context $context.Proof.Path $context.Source 'Recover'
    $items = @(foreach ($row in $Rows) {
            if ($row.CloudStatus -ne 'Success' -or $row.DeprovisionConfirmed -ne $true -or $row.ADVerified -ne $true) { throw 'Finalize package refused: AD proof or cloud deprovisioning not confirmed for every object.' }
            [ordered]@{ ObjectGuid = $row.ObjectGuid; RestoreShared = [bool]$row.DeproPending; RestoreTag = [bool](Get-PraValue (Get-PraValue $row.BackupRec 'Retention' $null) 'Enabled' $false); CloudConfirmed = $true; DeprovisionConfirmed = $true }
        })
    $packageId = [guid]::NewGuid().ToString('N')
    $directory = Join-Path $context.BackupFolder ('Finalize-' + $packageId)
    New-PraPrivateDirectory $directory
    Copy-PraBackupBundle $context.Source $directory
    Copy-PraBackupBundle $proof.Receipt $directory
    Copy-PraBundleFile $proof.Path $directory; Copy-PraBundleFile ($proof.Path + '.sha256') $directory
    $path = Join-Path $directory ("Finalize-$($context.Config.Environment)-$(Get-Date -Format 'yyyyMMdd_HHmmss')-$($packageId.Substring(0, 8)).json")
    $manifest = [ordered]@{
        SchemaVersion = 2; Operation = 'RecoverFinalize'; Environment = $context.Config.Environment; CreatedUtc = [DateTime]::UtcNow.ToString('o')
        SourceBackupFile = [IO.Path]::GetFileName($context.Source.Path); SourceBackupHash = $context.Source.Hash
        StateFile = [IO.Path]::GetFileName($proof.Path); StateHash = $proof.Hash; Items = $items
    }
    Write-PraImmutableFile $path ($manifest | ConvertTo-Json -Depth 20)
    Write-PraImmutableFile ($path + '.sha256') (Get-PraHash $path)
    $context.StateFiles.Add($path)
    foreach ($row in $Rows) { $row.RestoreDeferred = $true; $row.FinalStatus = 'Pending'; $row.Detail += ' | Finalize required on the AD server' }
    $short = Get-PraShortId $packageId
    $context.BatchId = $short
    Write-PraItem -Context $context -Status Ok -Icon Batch -Text ("Finalize package {0} written: {1}" -f $short, $directory)
    $context.NextSteps = @("Copy the folder $directory to the Backups folder of the AD server, then run there:",
        (Get-PraCommandLine -ActionName 'Finalize' -BatchId $short -OtherServer))
}

function Get-PraFinalizeInput {
    <# Reads and checks a Finalize package; returns the objects it authorises to restore. #>
    $path = Get-PraBatchFile -Value $Batch -Operations @('RecoverFinalize')
    $context.CurrentOperation = 'Read-FinalizePackage'
    $manifest = Get-Content -LiteralPath $path -Raw -Encoding UTF8 -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
    if ((Get-PraValue $manifest 'SchemaVersion' 0) -ne 2 -or $manifest.Operation -ne 'RecoverFinalize' -or $manifest.Environment -cne $context.Config.Environment) { throw 'Finalize package of another version or Environment: nothing restored.' }
    if ((Get-Content -LiteralPath ($path + '.sha256') -Raw -ErrorAction Stop).Trim() -cne (Get-PraHash $path)) { throw 'Finalize package: SHA-256 mismatch.' }
    foreach ($property in @('SourceBackupFile','StateFile')) {
        if ([IO.Path]::GetFileName($manifest.$property) -cne $manifest.$property) { throw 'Finalize package: a file path points outside the package.' }
    }
    $context.Source = Import-PraBackup $context (Join-Path (Split-Path $path -Parent) $manifest.SourceBackupFile)
    $context.Proof = Import-PraProof $context (Join-Path (Split-Path $path -Parent) $manifest.StateFile) $context.Source 'Recover'
    if ($context.Source.Hash -cne $manifest.SourceBackupHash -or $context.Proof.Hash -cne $manifest.StateHash) { throw 'Finalize package: manifest and proofs do not match.' }
    $records = @(Select-PraSourceRecord $context.Source); $seen = @{}
    $items = @($manifest.Items)
    if (-not $items.Count) { throw 'Finalize package is empty.' }
    foreach ($item in $items) {
        if ($item.CloudConfirmed -isnot [bool] -or -not $item.CloudConfirmed -or $item.DeprovisionConfirmed -isnot [bool] -or -not $item.DeprovisionConfirmed -or $item.RestoreShared -isnot [bool] -or $item.RestoreTag -isnot [bool] -or
            $item.ObjectGuid -notin @($context.Proof.Data.Records.ObjectGuid) -or $seen.ContainsKey($item.ObjectGuid)) { throw 'Finalize package: invalid object confirmation.' }
        $proofEntry = @($context.Proof.Data.Records | Where-Object ObjectGuid -eq $item.ObjectGuid)[0]
        $snapshotEntry = @($context.Proof.Receipt.Data.Records | Where-Object ObjectGuid -eq $item.ObjectGuid)[0]
        $sourceEntry = @($context.Source.Data.Records | Where-Object ObjectGuid -eq $item.ObjectGuid)[0]
        if ($snapshotEntry.PreserveCloudMailbox -or ($item.RestoreShared -and ($proofEntry.Operation -ne 'Deprovision' -or -not $sourceEntry.IsShared)) -or
            ($item.RestoreTag -and -not [bool](Get-PraValue (Get-PraValue $sourceEntry 'Retention' $null) 'Enabled' $false)) -or
            (-not $item.RestoreShared -and -not $item.RestoreTag)) { throw 'Finalize package does not match the AD operations it proves.' }
        $seen[$item.ObjectGuid] = $true
    }
    if ($Identity -and @($records | Where-Object { $_.ObjectGuid -in @($items.ObjectGuid) }).Count -ne 1) { throw "Identity '$Identity' is not authorised by this Finalize package." }
    $context.BatchId = Get-PraShortId ((Split-Path (Split-Path $path -Parent) -Leaf) -replace '^Finalize-', '')
    return @($records | Where-Object { $_.ObjectGuid -in @($items.ObjectGuid) } | ForEach-Object {
            [pscustomobject]@{ Record = $_; Item = ($items | Where-Object ObjectGuid -eq $_.ObjectGuid) } })
}

function Test-PraSyncAvailable {
    <#
    .SYNOPSIS
        Before any AD write: checks that the Entra Connect synchronisation requested by the
        configuration can run (local ADSync module, or WinRM to EntraConnect.Server).
    #>
    $sync = $context.Config.EntraConnect
    if (-not $sync.Sync) { return }
    $context.CurrentOperation = 'Check-EntraConnect'
    if ($sync.Server) {
        try { $null = Test-WSMan -ComputerName $sync.Server -ErrorAction Stop }
        catch { throw "Entra Connect server $($sync.Server) is not reachable with PowerShell remoting (WinRM): $($_.Exception.Message). Fix the access, or set EntraConnect.Sync = `$false and run the synchronisation yourself." }
        Write-PraItem -Context $context -Status Ok -Icon Sync -Text ("Entra Connect: {0} reachable, a {1} cycle runs after the AD changes" -f $sync.Server, $sync.PolicyType)
    }
    elseif (-not @(Get-Module -ListAvailable ADSync).Count) {
        throw 'EntraConnect.Sync = $true but the ADSync module is not on this server. Run the AD part on the Entra Connect server, set EntraConnect.Server, or set EntraConnect.Sync = $false and run the synchronisation yourself.'
    }
    else { Write-PraItem -Context $context -Status Ok -Icon Sync -Text ('Entra Connect: ADSync module found, a {0} cycle runs after the AD changes' -f $sync.PolicyType) }
}

function Confirm-PraApply {
    <#
    .SYNOPSIS
        One confirmation for the whole run, after the plan is shown (skipped with -Force).
        After it, the individual writes do not prompt again (unless -Confirm is given explicitly).
    #>
    param([Parameter(Mandatory)][string]$Question)
    if (-not $context.AllowMutation -or $Force -or $script:ConfirmBound) { return }
    $context.CurrentOperation = 'Confirm-Apply'; $context.CurrentIdentity = ''
    Write-Host ''
    $answer = $false
    try { $answer = $caller.ShouldContinue($Question, 'PRA Remote Mailbox - Apply') }
    catch { throw "Apply needs a confirmation and this console cannot ask for one ($($_.Exception.Message)). Run it in an interactive console or add -Force." }
    if (-not $answer) {
        $context.AllowMutation = $false
        throw 'Cancelled by the operator: nothing was written.'
    }
    $script:ConfirmPreference = 'None'
    $context.ConfirmPreference = 'None'
    Write-PraLog -Context $context -Message ('Operator confirmed: ' + $Question) -Level Detail
}

function Show-PraPlanSummary {
    <# One line per planned object + totals (details of the AD attributes are shown by Write-PraAdDelta). #>
    param([object[]]$Plans)
    $changes = @($Plans | Where-Object { $_.Operation -ne 'AlreadyRecovered' })
    $users = @($Plans | Where-Object { -not $_.Record.IsShared }).Count
    $shared = @($Plans | Where-Object { $_.Record.IsShared }).Count
    $grants = 0
    foreach ($plan in $Plans) { foreach ($right in @('FullAccess','SendAs','SendOnBehalf')) { $grants += @($plan.Record.SharedPermissions.$right).Count } }
    $text = '{0} object(s): {1} user(s), {2} shared' -f $Plans.Count, $users, $shared
    if ($Action -eq 'Convert' -and $shared) { $text += (' {0} {1} permission(s) to reproduce in Exchange Online' -f [char]0x00B7, $grants) }
    Write-PraItem -Context $context -Status Info -Icon Target -Text $text
    return $changes.Count
}

function Skip-PraStep {
    <# Prints a step that does not run in this execution (numbering stays in the announced order). #>
    param([Parameter(Mandatory)][string]$Title, [Parameter(Mandatory)][string]$Reason, [string]$Icon = 'Skip')
    Write-PraStep -Context $context -Title $Title -Icon $Icon
    Write-PraItem -Context $context -Status Skip -Text $Reason
}

function Get-PraSkipReason {
    param([bool]$HasWork = $true)
    if (-not $HasWork) { return 'Nothing to do.' }
    if (-not $context.AllowMutation) { return 'Preview: not run.' }
    return 'Not needed.'
}

# =================================================================================================
# Main
# =================================================================================================
$script:ConfigPathBound = $PSBoundParameters.ContainsKey('ConfigPath')
$script:ConfirmBound = $PSBoundParameters.ContainsKey('Confirm')
try {
    # ---------------------------------------------------------------------------------------------
    # Configuration, audit files, banner.
    # ---------------------------------------------------------------------------------------------
    $context.CurrentOperation = 'Read-Configuration'
    $targetOverride = Get-PraTargetOverride -SearchBase $SearchBase -CsvPath $CsvPath -Identity $Identity
    $context.Config = Import-PraConfiguration -Path $ConfigPath -Root $PSScriptRoot -ScopeOverride $targetOverride
    $config = $context.Config
    $context.BackupFolder = $config.Storage.BackupFolder
    $context.LogFolder = $config.Logging.Folder
    $context.ReportFolder = $config.Report.Folder
    $context.NoReport = -not $config.Report.Enabled
    $context.Server = $config.DomainController
    $context.IntervalMinutes = $config.Polling.IntervalMinutes
    $context.TimeoutMinutes = $config.Polling.TimeoutMinutes
    $context.KeepCloudShared = [bool]$config.SharedMailbox.KeepCloudSharedOnRecover
    $defer = [bool]$config.SharedMailbox.DeferOnPremRestore
    $effectivePhase = switch ($Action) {
        'Finalize' { 'Finalize' }
        'Check' { 'Cloud' }
        default { if ($Phase) { $Phase } else { $config.Execution.Phase } }
    }
    $context.Phase = $effectivePhase
    if (($SearchBase -or $CsvPath) -and ($Action -ne 'Convert' -or $effectivePhase -notin @('AD','Both'))) {
        throw 'SearchBase/CsvPath are only available for Convert -Phase AD or Both.'
    }

    Initialize-PraAudit $context

    $dot = [char]0x00B7
    $modeText = if ($effectiveMode -eq 'Apply') { 'Apply (changes are made)' } else { 'Preview (nothing is changed)' }
    $actionText = $Action
    if ($Action -in @('Convert','Recover')) { $actionText += " $dot phase $effectivePhase" }
    if ($Action -eq 'Check') { $actionText += " $dot expect $Expect" }
    $scopeText = if ($Identity) { "one object: $Identity" }
        elseif ($Batch) { "batch $Batch" + $(if ($Scope -ne 'All') { " $dot $Scope" } else { '' }) }
        else {
            $s = $config.Scope
            $base = switch ($s.Mode) { 'OU' { $s.SearchBase } 'Group' { "members of $($s.GroupDN)" } 'Csv' { "CSV $($s.CsvPath)" } default { if ($s.SearchBase) { $s.SearchBase } else { 'whole domain' } } }
            $kinds = @('users'); if ($s.IncludeShared) { $kinds += 'shared' }; if ($s.IncludeRoom) { $kinds += 'rooms' }; if ($s.IncludeEquip) { $kinds += 'equipment' }
            # -Scope replaces the mailbox types of the configuration.
            if ($Scope -eq 'UsersOnly') { $kinds = @('users only') } elseif ($Scope -eq 'SharedOnly') { $kinds = @('shared mailboxes only') }
            '{0} {1} {2}' -f $base, $dot, ($kinds -join ' + ') + $(if ($MaxObjects) { " $dot max $MaxObjects" } else { '' })
        }
    $banner = [ordered]@{ 'Action' = @('Mode', $actionText); 'Mode' = @($(if ($effectiveMode -eq 'Apply') { 'Write' } else { 'Plan' }), $modeText) }
    if ($Action -ne 'Finalize') { $banner['Scope'] = @('Target', $scopeText) }
    if ($config.Cloud.Organization -and $Action -ne 'Finalize' -and $effectivePhase -ne 'AD') { $banner['Tenant'] = @('Cloud', $config.Cloud.Organization) }
    $banner['Config'] = @('Config', ('{0} {1} Environment {2}' -f (Split-Path $config._Path -Leaf), $dot, $config.Environment))
    $banner['Log'] = @('Log', $context.LogFile)
    Write-PraBanner -Context $context -Title 'PRA Remote Mailbox' -Subtitle "Hybrid Exchange disaster recovery $dot on-premises $([char]0x2192) Exchange Online" -Details $banner

    # Steps of this run (numbered x/total in the console).
    $steps = switch ($Action) {
        'Convert' {
            if ($effectivePhase -eq 'Cloud') { @('Loading the batch of the AD phase','Exchange Online: mailboxes, licences and permissions') }
            else {
                @('Active Directory connection','Targets and planned changes') +
                $(if ($effectivePhase -eq 'Both') { @('Exchange Online pre-check') } else { @() }) +
                @('Backup and Active Directory changes','Entra Connect synchronisation') +
                $(if ($effectivePhase -eq 'Both') { @('Exchange Online: mailboxes, licences and permissions') } else { @() })
            }
        }
        'Recover' {
            if ($effectivePhase -eq 'Cloud') { @('Loading the Recover batch','Exchange Online: deprovisioning checks','Final restore of shared mailboxes and tags') }
            else {
                @('Loading the Convert batch','Active Directory connection','Planned restore','Backup and Active Directory changes','Entra Connect synchronisation') +
                $(if ($effectivePhase -eq 'Both') { @('Exchange Online: deprovisioning checks','Final restore of shared mailboxes and tags') } else { @() })
            }
        }
        'Finalize' { @('Loading the Finalize package','Active Directory connection','Planned restore','Backup and Active Directory changes','Entra Connect synchronisation') }
        'Check' { @('Objects to check','Exchange Online checks') }
    }
    $context.StepTotal = @($steps).Count

    foreach ($forbidden in $config.Storage.ForbiddenBackupRoots) {
        if ($context.AllowMutation -and ($context.BackupFolder.TrimEnd('\') + '\').StartsWith($forbidden, [StringComparison]::OrdinalIgnoreCase)) { throw "Backup folder on a forbidden volume (Storage.ForbiddenBackupRoots): $forbidden" }
    }
    if ($Batch -and $Action -eq 'Convert' -and $effectivePhase -ne 'Cloud') { throw '-Batch is not used by Convert on the AD side: the targets come from the configuration (or -Identity).' }
    if (-not $Batch -and ($Action -in @('Recover','Finalize') -or ($Action -eq 'Convert' -and $effectivePhase -eq 'Cloud'))) {
        throw ("-Batch is required for {0}{1}: give the batch ID printed at the end of the previous step." -f $Action, $(if ($effectivePhase -eq 'Cloud') { ' -Phase Cloud' } else { '' }))
    }
    if ($Action -eq 'Check' -and -not $Batch -and -not $Identity) { throw 'Check needs -Identity or -Batch.' }

    $runCloud = $false; $cloudAction = $Action
    # ---------------------------------------------------------------------------------------------
    # FINALIZE - AD server, after the cloud phase of a Recover.
    # ---------------------------------------------------------------------------------------------
    if ($Action -eq 'Finalize') {
        Write-PraStep -Context $context -Title 'Loading the Finalize package' -Icon Batch
        $finalizeEntries = @(Get-PraFinalizeInput)
        $context.SourceBackupHash = $context.Source.Hash
        Write-PraItem -Context $context -Status Ok -Text ("Package {0}: {1} object(s) confirmed by Exchange Online, proofs verified" -f $context.BatchId, $finalizeEntries.Count)
        if (-not $context.Server) { $context.Server = [string]$context.Proof.Receipt.Data.Server }
        Write-PraStep -Context $context -Title 'Active Directory connection' -Icon Directory
        Initialize-PraDirectory $context
        Write-PraStep -Context $context -Title 'Planned restore' -Icon Plan
        $plans = @(foreach ($entry in $finalizeEntries) {
                if ($entry.Item.RestoreShared) {
                    if (-not $entry.Record.IsShared) { throw 'Finalize package: shared mailbox restore requested for a user mailbox.' }
                    $plan = New-PraPlan $context $entry.Record.ObjectGuid 'Recover' $entry.Record -RestoreRetention:$entry.Item.RestoreTag
                }
                else { $plan = New-PraPlan $context $entry.Record.ObjectGuid 'RestoreTag' $entry.Record }
                Assert-PraFollowupState $context $plan $context.Proof
                $plan
            })
        $null = Show-PraPlanSummary $plans
        Invoke-PraAdPreview $context $plans
        if ($context.AllowMutation) {
            Test-PraSyncAvailable
            Confirm-PraApply ("Restore the on-premises attributes of {0} object(s) listed above?" -f $plans.Count)
        }
        Write-PraStep -Context $context -Title 'Backup and Active Directory changes' -Icon Backup
        $receipt = Invoke-PraAdBatch $context $plans 'Finalize'
        if ($null -ne $receipt) { Write-PraStep -Context $context -Title 'Entra Connect synchronisation' -Icon Sync; Invoke-PraSync $context }
        else { Skip-PraStep -Title 'Entra Connect synchronisation' -Reason (Get-PraSkipReason $plans.Count) }
        if (-not $context.AllowMutation) { $context.NextSteps = @(Get-PraCommandLine -ActionName 'Finalize' -BatchId $context.BatchId) }
    }
    # ---------------------------------------------------------------------------------------------
    # CONVERT - AD side (phase AD or Both).
    # ---------------------------------------------------------------------------------------------
    elseif ($Action -eq 'Convert' -and $effectivePhase -in @('Both','AD')) {
        Write-PraStep -Context $context -Title 'Active Directory connection' -Icon Directory
        Initialize-PraDirectory $context -ValidateScope
        Write-PraStep -Context $context -Title 'Targets and planned changes' -Icon Plan
        $targets = @(Get-PraTarget $context $Identity $Scope $MaxObjects)
        if (-not $targets.Count) { Write-PraItem -Context $context -Status Warn -Text 'No on-premises mailbox found in the scope: nothing to convert.' }
        $plans = @(foreach ($target in $targets) { New-PraPlan $context ([string]$target.ObjectGUID) 'Convert' })
        if ($plans.Count) {
            $null = Show-PraPlanSummary $plans
            Invoke-PraAdPreview $context $plans
        }
        if ($context.AllowMutation -and $plans.Count) {
            Test-PraSyncAvailable
            $question = "Convert the {0} object(s) listed above? A backup is written first; then AD is changed{1}." -f $plans.Count, $(if ($config.EntraConnect.Sync) { ', Entra Connect synchronises' } else { '' })
            if ($effectivePhase -eq 'Both') { $question = $question.TrimEnd('.') + ' and Exchange Online is completed.' }
            Confirm-PraApply $question
        }
        if ($effectivePhase -eq 'Both') {
            if ($context.AllowMutation -and $plans.Count) {
                # Sign-in and identities are checked BEFORE the first AD write.
                Write-PraStep -Context $context -Title 'Exchange Online pre-check' -Icon Cloud
                $context.CurrentOperation = 'CloudPreflightBeforeAD'
                Import-Module (Join-Path $PSScriptRoot 'module\PRA.Cloud.psm1') -Force -ErrorAction Stop
                Initialize-PraCloudPreflight -Context $context -Rows @($plans | ForEach-Object { $_.Row })
                if ($context.Issues.Count) { throw 'Exchange Online pre-check failed: no AD change made.' }
            }
            else { Skip-PraStep -Title 'Exchange Online pre-check' -Reason (Get-PraSkipReason $plans.Count) }
        }
        Write-PraStep -Context $context -Title 'Backup and Active Directory changes' -Icon Backup
        $receipt = Invoke-PraAdBatch $context $plans 'Convert'
        if ($null -ne $receipt) {
            Write-PraStep -Context $context -Title 'Entra Connect synchronisation' -Icon Sync
            $context.Source = $receipt
            $context.Proof = Import-PraProof $context $receipt.StatePath $receipt 'Convert'
            $context.BatchId = Get-PraShortId $receipt.Data.BatchId
            Invoke-PraSync $context
            $runCloud = $effectivePhase -eq 'Both'
            if ($effectivePhase -eq 'AD') {
                $context.NextSteps = @("Copy the folder $(Split-Path $receipt.Path -Parent) to the Backups folder of the cloud server, then run there:",
                    (Get-PraCommandLine -ActionName 'Convert' -PhaseName 'Cloud' -BatchId $context.BatchId -OtherServer))
            }
        }
        else {
            Skip-PraStep -Title 'Entra Connect synchronisation' -Reason (Get-PraSkipReason $plans.Count)
            if ($plans.Count) { $context.NextSteps = @(Get-PraCommandLine -ActionName 'Convert' -PhaseName $(if ($Phase) { $Phase } else { '' }) -KeepFilters) }
        }
    }
    # ---------------------------------------------------------------------------------------------
    # RECOVER - AD side (phase AD or Both).
    # ---------------------------------------------------------------------------------------------
    elseif ($Action -eq 'Recover' -and $effectivePhase -in @('Both','AD')) {
        Write-PraStep -Context $context -Title 'Loading the Convert batch' -Icon Batch
        $context.Source = Import-PraBackup $context (Get-PraBatchFile -Value $Batch -Operations @('Convert'))
        if ($context.Source.Data.Operation -ne 'Convert') { throw 'Recover needs the original Convert batch.' }
        $context.SourceBackupHash = $context.Source.Hash
        $records = @(Select-PraSourceRecord $context.Source)
        Write-PraItem -Context $context -Status Ok -Text ("Convert batch {0}: {1} object(s) selected, backup and SHA-256 verified" -f (Get-PraShortId ([string]$context.Source.Data.BatchId)), $records.Count)
        Write-PraStep -Context $context -Title 'Active Directory connection' -Icon Directory
        Initialize-PraDirectory $context
        Write-PraStep -Context $context -Title 'Planned restore' -Icon Plan
        $plans = @(foreach ($record in $records) {
                $operation = if ($record.IsShared -and -not $context.KeepCloudShared) { 'Deprovision' } else { 'Recover' }
                New-PraPlan $context $record.ObjectGuid $operation $record
            })
        if ($plans.Count) {
            $null = Show-PraPlanSummary $plans
            Invoke-PraAdPreview $context $plans
        }
        if ($context.AllowMutation -and $plans.Count) {
            Test-PraSyncAvailable
            Confirm-PraApply ("Roll back the {0} object(s) listed above? Users get their on-premises attributes back; shared mailboxes are first deprovisioned in Exchange Online." -f $plans.Count)
        }
        Write-PraStep -Context $context -Title 'Backup and Active Directory changes' -Icon Backup
        $receipt = Invoke-PraAdBatch $context $plans 'Recover'
        if ($null -ne $receipt) {
            Write-PraStep -Context $context -Title 'Entra Connect synchronisation' -Icon Sync
            $context.Proof = Import-PraProof $context $receipt.StatePath $context.Source 'Recover'
            $context.BatchId = Get-PraShortId $receipt.Data.BatchId
            Invoke-PraSync $context
            $runCloud = $effectivePhase -eq 'Both'
            if ($effectivePhase -eq 'AD') {
                $context.NextSteps = @("Copy the folders $(Split-Path $receipt.Path -Parent) and $(Split-Path $context.Source.Path -Parent) to the Backups folder of the cloud server, then run there:",
                    (Get-PraCommandLine -ActionName 'Recover' -PhaseName 'Cloud' -BatchId $context.BatchId -OtherServer))
            }
        }
        elseif ($plans.Count) { $context.NextSteps = @(Get-PraCommandLine -ActionName 'Recover' -PhaseName $(if ($Phase) { $Phase } else { '' }) -BatchId $Batch -KeepFilters) }
    }
    # ---------------------------------------------------------------------------------------------
    # CLOUD SIDE - Convert/Recover -Phase Cloud and Check.
    # ---------------------------------------------------------------------------------------------
    else {
        if ($Action -eq 'Check') { $cloudAction = if ($Expect -eq 'Deprovisioned') { 'Recover' } else { 'Convert' } }
        $stepTitle = switch ($Action) { 'Check' { 'Objects to check' } 'Recover' { 'Loading the Recover batch' } default { 'Loading the batch of the AD phase' } }
        Write-PraStep -Context $context -Title $stepTitle -Icon Batch
        if ($Action -eq 'Check' -and $Identity -and -not $Batch) {
            if ($Identity -match '@') { $record = [pscustomobject]@{ ObjectGuid = ''; SamAccountName = $Identity; UserPrincipalName = $Identity; IsShared = ($Scope -eq 'SharedOnly') } }
            else {
                Initialize-PraDirectory $context
                $user = Get-PraUser $context $Identity
                $record = [pscustomobject]@{ ObjectGuid = ([guid]$user.ObjectGUID).ToString(); SamAccountName = $user.SamAccountName; UserPrincipalName = $user.UserPrincipalName; IsShared = ($user.msExchRecipientTypeDetails -in @(4, 34359738368)) }
            }
            $context.Rows.Add((New-PraRow $context $record))
            Write-PraItem -Context $context -Status Ok -Text ("{0} ({1})" -f $record.UserPrincipalName, $(if ($record.IsShared) { 'shared mailbox' } else { 'user mailbox' }))
        }
        else {
            # Which batch? Convert cloud phase and Check: the Convert batch. Recover cloud phase:
            # the Recover batch (proof of the AD part), its Convert source is found by its hash.
            $proofPath = ''
            if ($Action -eq 'Recover') {
                $batchFile = Get-PraBatchFile -Value $Batch -Operations @('Recover','Convert')
                $batchData = [IO.File]::ReadAllText($batchFile) | ConvertFrom-Json
                if ($batchData.Operation -eq 'Recover') {
                    $proofPath = Join-Path (Split-Path $batchFile -Parent) ('State-' + $batchData.BatchId + '.json')
                    $context.Source = Import-PraBackup $context (Find-PraConvertSource -Hash ([string]$batchData.SourceBackupHash))
                    $context.BatchId = Get-PraShortId $batchData.BatchId
                }
                elseif ($context.AllowMutation) { throw "Batch $Batch is a Convert batch: the cloud phase of a Recover needs the batch printed by its AD phase (it proves that AD was restored)." }
                else { $context.Source = Import-PraBackup $context $batchFile; $context.BatchId = Get-PraShortId $batchData.BatchId }
            }
            else {
                $context.Source = Import-PraBackup $context (Get-PraBatchFile -Value $Batch -Operations @('Convert'))
                $context.BatchId = Get-PraShortId ([string]$context.Source.Data.BatchId)
                if (-not $context.Source.Legacy) { $proofPath = Join-Path (Split-Path $context.Source.Path -Parent) ('State-' + $context.Source.Data.BatchId + '.json') }
            }
            if ($context.Source.Data.Operation -ne 'Convert') { throw 'The source of a cloud phase must be the original Convert batch.' }
            $context.SourceBackupHash = $context.Source.Hash
            $records = @(Select-PraSourceRecord $context.Source)
            if ($context.AllowMutation) {
                if (-not $proofPath) { throw 'This batch has no AD proof (State file): the cloud phase cannot write.' }
                $context.Proof = Import-PraProof $context $proofPath $context.Source $Action
                Initialize-PraCloudJournal
            }
            foreach ($record in $records) {
                $row = New-PraRow $context $record
                $originalLicensing = Get-PraValue $record 'Licensing' $null
                $row.PreserveLicense = ($cloudAction -eq 'Recover') -and [bool](Get-PraValue $originalLicensing 'Enabled' $false) -and [bool](Get-PraValue $originalLicensing 'WasMember' $false)
                $row.PreserveCloudMailbox = ($cloudAction -eq 'Recover') -and $row.IsShared -and $context.KeepCloudShared
                $holders = Get-PraValue $record 'SharedPermissions' $null
                $row.SharedFullAccess = Get-PraValue $holders 'FullAccess' @(); $row.SharedSendAs = Get-PraValue $holders 'SendAs' @(); $row.SharedSendOnBehalf = Get-PraValue $holders 'SendOnBehalf' @()
                if ($null -ne $context.Proof) {
                    $verified = @($context.Proof.Data.Records | Where-Object ObjectGuid -eq $record.ObjectGuid)
                    if ($verified.Count -ne 1) { throw "Object not verified by the AD phase of this batch: $($record.SamAccountName)" }
                    $row.ADVerified = $true; $row.DeproPending = ($verified[0].Operation -eq 'Deprovision'); $row.BackupPath = $context.Proof.Receipt.Path
                    $provenPlan = @($context.Proof.Receipt.Data.Records | Where-Object ObjectGuid -eq $record.ObjectGuid)[0]
                    $row.PreserveCloudMailbox = [bool]$provenPlan.PreserveCloudMailbox; $row.PreserveLicense = [bool]$provenPlan.PreserveLicense
                }
                $context.Rows.Add($row)
            }
            Write-PraItem -Context $context -Status Ok -Text ("Batch {0}: {1} object(s){2}" -f $context.BatchId, $records.Count, $(if ($null -ne $context.Proof) { ', AD proof verified' } else { '' }))
        }
        $runCloud = $true
    }

    # ---------------------------------------------------------------------------------------------
    # Exchange Online part (after the AD part in phase Both, or alone in phase Cloud / Check).
    # ---------------------------------------------------------------------------------------------
    if ($runCloud -and $context.Rows.Count -gt 0) {
        if ($context.Issues.Count) { throw 'Cloud part not started: the AD part has errors.' }
        $cloudTitle = switch ($cloudAction) { 'Recover' { 'Exchange Online: deprovisioning checks' } default { 'Exchange Online: mailboxes, licences and permissions' } }
        if ($Action -eq 'Check') { $cloudTitle = 'Exchange Online checks' }
        Write-PraStep -Context $context -Title $cloudTitle -Icon Cloud
        # A preview of the cloud phase looks once: it never waits for the cloud.
        if (-not $context.AllowMutation -and $Action -ne 'Check') { $context.Once = $true }
        if ($context.AllowMutation -and $effectivePhase -eq 'Cloud' -and $Action -eq 'Convert') {
            $grants = 0; foreach ($row in $context.Rows) { $grants += @($row.SharedFullAccess).Count + @($row.SharedSendAs).Count + @($row.SharedSendOnBehalf).Count }
            Confirm-PraApply ("Complete {0} object(s) in Exchange Online (wait for the mailboxes, grant up to {1} shared mailbox permission(s))?" -f $context.Rows.Count, $grants)
        }
        elseif ($context.AllowMutation -and $effectivePhase -eq 'Cloud' -and $Action -eq 'Recover') {
            Confirm-PraApply ("Check the deprovisioning of {0} object(s) in Exchange Online, then package any final shared mailbox and tag restoration for the AD server?" -f $context.Rows.Count)
        }
        Initialize-PraCloudAuthority
        Import-Module (Join-Path $PSScriptRoot 'module\PRA.Cloud.psm1') -Force -ErrorAction Stop
        if ($Action -eq 'Check' -and $Expect -eq 'Retained') { Invoke-PraRetentionCheck -Context $context -Rows $context.Rows.ToArray() }
        else { Invoke-PraCloudPhase -Context $context -Rows $context.Rows.ToArray() -Act $cloudAction }
        if ($context.Issues.Count -or @($context.Rows | Where-Object CloudStatus -eq 'Error').Count) { throw 'Exchange Online check failed: no restore or clean-up is done.' }

        # Recover: shared mailboxes (deprovisioned in the cloud) and retention tags are restored only now.
        if ($Action -eq 'Recover') {
            Write-PraStep -Context $context -Title 'Final restore of shared mailboxes and tags' -Icon Write
            if ($context.AllowMutation) {
                $tagged = @($context.Rows | Where-Object { [bool](Get-PraValue (Get-PraValue $_.BackupRec 'Retention' $null) 'Enabled' $false) })
                foreach ($row in $tagged | Where-Object PreserveCloudMailbox) {
                    $row.FinalStatus = 'Pending'; $row.Detail += ' | Cloud mailbox kept on purpose: the retention tag stays.'
                }
                $followup = @($context.Rows | Where-Object { -not $_.PreserveCloudMailbox -and ($_.DeproPending -or $_ -in $tagged) })
                foreach ($row in $followup) { if ($row.CloudStatus -ne 'Success' -or $row.DeprovisionConfirmed -ne $true -or $row.ADVerified -ne $true) { throw 'Cloud deprovisioning or AD proof not confirmed: restore and tag clean-up blocked.' } }
                if (-not $followup.Count) { Write-PraItem -Context $context -Status Skip -Text 'Nothing left to restore.' }
                elseif ($effectivePhase -eq 'Cloud' -or $defer -or -not @(Get-Module -ListAvailable ActiveDirectory).Count) {
                    if ($effectivePhase -eq 'Cloud') { Write-PraItem -Context $context -Status Info -Text 'Cloud-only phase: final AD restoration is packaged for Finalize on the AD server.' }
                    elseif (-not $defer) { Write-PraItem -Context $context -Status Info -Text 'ActiveDirectory module not found on this server: the restore is packaged for the AD server.' }
                    Save-PraFinalizePackage $followup
                }
                else {
                    if (-not $context.Server) { $context.Server = [string]$context.Proof.Receipt.Data.Server }
                    Initialize-PraDirectory $context
                    $plans = @(foreach ($row in $followup) {
                            $operation = if ($row.DeproPending) { 'Recover' } else { 'RestoreTag' }
                            $plan = New-PraPlan $context $row.ObjectGuid $operation $row.BackupRec -RestoreRetention
                            Assert-PraFollowupState $context $plan $context.Proof
                            $row.DeproPending = $false; $plan.Row = $row
                            $plan
                        })
                    Invoke-PraAdPreview $context $plans
                    $null = Invoke-PraAdBatch $context $plans 'Finalize'
                    Invoke-PraSync $context
                }
            }
            else { Write-PraItem -Context $context -Status Skip -Text 'Preview: nothing restored.' }
        }
        if (-not $context.AllowMutation -and $Action -in @('Convert','Recover') -and -not $context.NextSteps.Count) {
            $context.NextSteps = @(Get-PraCommandLine -ActionName $Action -PhaseName 'Cloud' -BatchId $Batch -KeepFilters)
        }
    }
    elseif ($runCloud) { Write-PraItem -Context $context -Status Warn -Text 'No object to check in Exchange Online.' }

    # Steps announced but not run (preview, nothing to do) are shown as skipped, in their order.
    $announced = @($steps)
    for ($i = [int]$context.StepIndex; $i -lt $announced.Count; $i++) { Skip-PraStep -Title $announced[$i] -Reason (Get-PraSkipReason ($context.Rows.Count -gt 0)) }

    if ($context.AllowMutation -and $Action -eq 'Convert' -and $effectivePhase -in @('Both','Cloud') -and $context.BatchId -and -not $context.Issues.Count) {
        $context.NextSteps = @($(if ($effectivePhase -eq 'Cloud') { 'To roll back this batch later, on the AD server: ' + (Get-PraCommandLine -ActionName 'Recover' -ModeName 'Preview' -BatchId $context.BatchId -OtherServer) } else { 'To roll back this batch later: ' + (Get-PraCommandLine -ActionName 'Recover' -ModeName 'Preview' -BatchId $context.BatchId) }))
    }
}
catch {
    $failure = $_; $failureOperation = $context.CurrentOperation
    if (-not $context.TranscriptStarted -and -not $context.LogFile -and $context.LogFolder) {
        try { Initialize-PraAudit $context } catch { $context.Issues.Add([pscustomobject]@{ Message = "Audit unavailable: $($_.Exception.Message)"; Source = 'Audit' }) }
    }
    $context.CurrentOperation = $failureOperation
    try {
        # The error may already be recorded by the module that raised it: then log the stop only.
        $known = @($context.Issues.ToArray() | Where-Object { ([string](Get-PraValue $_ 'Message' '')).Contains($failure.Exception.Message) }).Count -gt 0
        $stopMessage = "Stopped at step '{0}' (operation {1}{2}): {3}" -f $context.CurrentPhase, $context.CurrentOperation, $(if ($context.CurrentIdentity) { ', object ' + $context.CurrentIdentity } else { '' }), $failure.Exception.Message
        Write-PraLog -Context $context -Message $stopMessage -Level $(if ($known) { 'Detail' } else { 'Error' })
        Write-PraLog -Context $context -Message ("ErrorId={0} | {1} | {2}" -f $failure.FullyQualifiedErrorId, $failure.InvocationInfo.PositionMessage, $failure.ScriptStackTrace) -Level Debug
    }
    catch { $context.Issues.Add([pscustomobject]@{ Message = $failure.Exception.Message; Source = 'Execution' }) }
    $context.ExitCode = 1
}
finally {
    Initialize-PraPermissionCache -Context $context
    if (Get-Command Close-PraCloudSession -ErrorAction SilentlyContinue) {
        try { Close-PraCloudSession -Context $context } catch { $context.Issues.Add([pscustomobject]@{ Message = "Cloud sign-out: $($_.Exception.Message)"; Source = 'Cloud' }) }
    }
    $result = Complete-PraRun -Context $context
    if ($PassThru) { $result }
    exit $result.ExitCode
}

# SIG # Begin signature block
# MIIghgYJKoZIhvcNAQcCoIIgdzCCIHMCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCCpjqYhB1xOrtKu
# ss0ziKekOhi72NF6k9P3wp6stV7Nx6CCDW8wggZyMIIEWqADAgECAghkM1HTxzif
# CDANBgkqhkiG9w0BAQsFADB8MQswCQYDVQQGEwJVUzEOMAwGA1UECAwFVGV4YXMx
# EDAOBgNVBAcMB0hvdXN0b24xGDAWBgNVBAoMD1NTTCBDb3Jwb3JhdGlvbjExMC8G
# A1UEAwwoU1NMLmNvbSBSb290IENlcnRpZmljYXRpb24gQXV0aG9yaXR5IFJTQTAe
# Fw0xNjA2MjQyMDQ0MzBaFw0zMTA2MjQyMDQ0MzBaMHgxCzAJBgNVBAYTAlVTMQ4w
# DAYDVQQIDAVUZXhhczEQMA4GA1UEBwwHSG91c3RvbjERMA8GA1UECgwIU1NMIENv
# cnAxNDAyBgNVBAMMK1NTTC5jb20gQ29kZSBTaWduaW5nIEludGVybWVkaWF0ZSBD
# QSBSU0EgUjEwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQCfgxNzqrDG
# bSHL24t6h3TQcdyOl3Ka5LuINLTdgAPGL0WkdJq/Hg9Q6p5tePOf+lEmqT2d0bKU
# Vz77OYkbkStW72fL5gvjDjmMxjX0jD3dJekBrBdCfVgWQNz51ShEHZVkMGE6ZPKX
# 13NMfXsjAm3zdetVPW+qLcSvvnSsXf5qtvzqXHnpD0OctVIFD+8+sbGP0EmtpuNC
# GVQ/8y8Ooct8/hP5IznaJRy4PgBKOm8yMDdkHseudQfYVdIYyQ6KvKNc8HwKp4WB
# wg6vj5lc02AlvINaaRwlE81y9eucgJvcLGfE3ckJmNVz68Qho+Uyjj4vUpjGYDdk
# jLJvSlRyGMwnh/rNdaJjIUy1PWT9K6abVa8mTGC0uVz+q0O9rdATZlAfC9KJpv/X
# gAbxwxECMzNhF/dWH44vO2jnFfF3VkopngPawismYTJboFblSSmNNqf1x1KiVgMg
# Lzh4gL32Bq5BNMuURb2bx4kYHwu6/6muakCZE93vUN8BuvIE1tAx3zQ4XldbyDge
# VtSsSKbt//m4wTvtwiS+RGCnd83VPZhZtEPqqmB9zcLlL/Hr9dQg1Zc0bl0EawUR
# 0tOSjAknRO1PNTFGfnQZBWLsiePqI3CY5NEv1IoTGEaTZeVYc9NMPSd6Ij/D+KNV
# t/nmh4LsRR7Fbjp8sU65q2j3m2PVkUG8qQIDAQABo4H7MIH4MA8GA1UdEwEB/wQF
# MAMBAf8wHwYDVR0jBBgwFoAU3QQJB6L1en1SUxKSle44gCUNplkwMAYIKwYBBQUH
# AQEEJDAiMCAGCCsGAQUFBzABhhRodHRwOi8vb2NzcHMuc3NsLmNvbTARBgNVHSAE
# CjAIMAYGBFUdIAAwEwYDVR0lBAwwCgYIKwYBBQUHAwMwOwYDVR0fBDQwMjAwoC6g
# LIYqaHR0cDovL2NybHMuc3NsLmNvbS9zc2wuY29tLXJzYS1Sb290Q0EuY3JsMB0G
# A1UdDgQWBBRUwv4QlQCTzWr158DX2bJLuI8M4zAOBgNVHQ8BAf8EBAMCAYYwDQYJ
# KoZIhvcNAQELBQADggIBAPUPJodwr5miyvXWyfCNZj05gtOII9iCv49UhCe204MH
# 154niU2EjlTRIO5gQ9tXQjzHsJX2vszqoz2OTwbGK1mGf+tzG8rlQCbgPW/M9r1x
# xs19DiBAOdYF0q+UCL9/wlG3K7V7gyHwY9rlnOFpLnUdTsthHvWlM98CnRXZ7WmT
# V7pGRS6AvGW+5xI+3kf/kJwQrfZWsqTU+tb8LryXIbN2g9KR+gZQ0bGAKID+260P
# Z+34fdzZcFt6umi1s0pmF4/n8OdX3Wn+vF7h1YyfE7uVmhX7eSuF1W0+Z0duGwdc
# +1RFDxYRLhHDsLy1bhwzV5Qe/kI0Ro4xUE7bM1eV+jjk5hLbq1guRbfZIsr0WkdJ
# LCjoT4xCPGRo6eZDrBmRqccTgl/8cQo3t51Qezxd96JSgjXktefTCm9r/o35pNfV
# HUvnfWII+NnXrJlJ27WEQRQu9i5gl1NLmv7xiHp0up516eDap8nMLDt7TAp4z5T3
# NmC2gzyKVMtODWgqlBF1JhTqIDfM63kXdlV4cW3iSTgzN9vkbFnHI2LmvM4uVEv9
# XgMqyN0eS3FE0HU+MWJliymm7STheh2ENH+kF3y0rH0/NVjLw78a3Z9UVm1F5VPz
# iIorMaPKPlDRADTsJwjDZ8Zc6Gi/zy4WZbg8Zv87spWrmo2dzJTw7XhQf+xkR6Od
# MIIG9TCCBN2gAwIBAgIQBof4ljXihJpmCqqt2mhAWzANBgkqhkiG9w0BAQsFADB4
# MQswCQYDVQQGEwJVUzEOMAwGA1UECAwFVGV4YXMxEDAOBgNVBAcMB0hvdXN0b24x
# ETAPBgNVBAoMCFNTTCBDb3JwMTQwMgYDVQQDDCtTU0wuY29tIENvZGUgU2lnbmlu
# ZyBJbnRlcm1lZGlhdGUgQ0EgUlNBIFIxMB4XDTI2MTAxMzAyNDgwMloXDTI3MTAx
# MzAyNDgwMlowXDELMAkGA1UEBhMCRlIxGzAZBgNVBAcMEkNoYW50ZWxvdXAtRW4t
# QnJpZTEXMBUGA1UECgwOTmljb2xhcyBGYWJlcnQxFzAVBgNVBAMMDk5pY29sYXMg
# RmFiZXJ0MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAsg6CT0mFQ4jB
# V2plIS4uWFSoVqRHd82Y7XYZ4CUTe/7nPBRUlXXdKTZMMHzGgiG8dEXNE8K1Xe90
# Dgl/FnorzAFlrNWSwf6t27UAUw9xkqtRDVVpVgpixpWkAwjcQeLG+YMqBkGbFi35
# TGvS23lPFWvLp4DxARrv15MtZ/NjNTCAAGUlMP2hFVBknEmrnYjEGyeJ93sl20RS
# WXQQLNqlenBdkGCrQW4XjHtRjJAEqAC68hN6nWevopSQ8CLUV7A1RFfHFarDrzrL
# zr0/NjIdSyIfM9hShln31NDrktB6Ups2XIyrtPDNB7fjkW4jpLlOqQGfYKsU9ErE
# 4SnFsh0yOOjitegyh1RvZ9wH++3DF4CmJfTli5l/gEIm8xCCryxI+K5EogW3wu1y
# u8NT2hcvHjdh7OpRyPyFAuLZ8MfX7kPAJpnuCeOuktzY/20eVD8bDglj+4zgqzsn
# cR/t6T/7w1/HxpRyrVoKvEyRx+mphYh5jMdEa0BjxOL0vAJpdGZSfXGmPm/yPqRn
# 5STTkMtzkVQXPbcvgKM0luzFcQKPHk3qdHLEXa8gf93ktYDbLE5Wd2UHrXz3SZxN
# URHPdIXCr1qgrqQve7041kMpzrkDI5DnG2lvRG4108gp02bHG0muKyZlDdCOra7h
# Zonu2nO79sFallruzzNi0o994PoWksUCAwEAAaOCAZUwggGRMAwGA1UdEwEB/wQC
# MAAwHwYDVR0jBBgwFoAUVML+EJUAk81q9efA19myS7iPDOMwegYIKwYBBQUHAQEE
# bjBsMEgGCCsGAQUFBzAChjxodHRwOi8vY2VydC5zc2wuY29tL1NTTGNvbS1TdWJD
# QS1Db2RlU2lnbmluZy1SU0EtNDA5Ni1SMS5jZXIwIAYIKwYBBQUHMAGGFGh0dHA6
# Ly9vY3Nwcy5zc2wuY29tMFEGA1UdIARKMEgwCAYGZ4EMAQQBMDwGDCsGAQQBgqkw
# AQMDATAsMCoGCCsGAQUFBwIBFh5odHRwczovL3d3dy5zc2wuY29tL3JlcG9zaXRv
# cnkwEwYDVR0lBAwwCgYIKwYBBQUHAwMwTQYDVR0fBEYwRDBCoECgPoY8aHR0cDov
# L2NybHMuc3NsLmNvbS9TU0xjb20tU3ViQ0EtQ29kZVNpZ25pbmctUlNBLTQwOTYt
# UjEuY3JsMB0GA1UdDgQWBBRoUx3630l9wA1fUpkKkw2GUIxl/jAOBgNVHQ8BAf8E
# BAMCB4AwDQYJKoZIhvcNAQELBQADggIBAE3oj6cNuwlDToi1BwjgsA5djfRN4DIi
# BYDFZIRYaIRe/rEdnItz3aqQQdFuwXnJA/MQEmi2WAGek8GeZF+R41s8FbcDxBUE
# BoSt98TuBE+0xgxQWDiPhhXaX1Aw9V0GF4ZnlfCSw1eu2KiASaKn7Bo0PLbEAXff
# vftRXof/kyqtw8iID6I4Rhrf5DI3WVZQodakUUmWnbnziWvEZOWbNOfzwP+7BwEt
# 7jQANfbmEfb4p75rfy5dQVwniTDSvdo6xkrbe1Cr93GS7cJta18IG5CoIVUmdK+s
# W38B1sLuy8Mi0MstMXV3004yaRuzLdNaAM0f9WAFerxemiQC0kdmA44/lWV3lVkM
# WJSwkHBkkSg8Eh0hxcGzTH2xmtDhLJHNNLRwkI9u2Ur+HbLCt50oBgSV8BcCs/1i
# qi884iC/yuX+HIv9YgTUNZ8c4lLaq4VuliJpXLu2buHIsTkO0v0+5oCM91zjTVZm
# ULeH38N0Vr83psiJVuBSxQyt5nRVrpYz7FACq5gtXELkyViq/rGOlJKaRrgQ6WWq
# eoIXqKhVFAdP/jAEm2M8ezoVYsUgPyKY2OcuecV9coulAcxUIUydx6qYiOfsGj5u
# Dy7l4aYjvB771wkUMzUQwxzcDYXJtMMTaWRe6n9EemR67jc73u5CJyFg3PfA5WR1
# wZislcdCZuS6MYISbTCCEmkCAQEwgYwweDELMAkGA1UEBhMCVVMxDjAMBgNVBAgM
# BVRleGFzMRAwDgYDVQQHDAdIb3VzdG9uMREwDwYDVQQKDAhTU0wgQ29ycDE0MDIG
# A1UEAwwrU1NMLmNvbSBDb2RlIFNpZ25pbmcgSW50ZXJtZWRpYXRlIENBIFJTQSBS
# MQIQBof4ljXihJpmCqqt2mhAWzANBglghkgBZQMEAgEFAKCBhDAYBgorBgEEAYI3
# AgEMMQowCKACgAChAoAAMBkGCSqGSIb3DQEJAzEMBgorBgEEAYI3AgEEMBwGCisG
# AQQBgjcCAQsxDjAMBgorBgEEAYI3AgEVMC8GCSqGSIb3DQEJBDEiBCA7rJeZawR0
# TARvXGNIPigEjo32GShUB4kZVIt3BUJYPjANBgkqhkiG9w0BAQEFAASCAgCrBfXO
# W/Dl9iul0Vv30tRD81YbdQoRHwcLSJqr4undy2xqfmqO9GO0Yz2irqGq4MWKq4C8
# 8dqnOz1IUw161TkSzqBkTAptAu44HijyVwG2Y8+d5eD3+VHLvOwwbo7NE8ZHARuQ
# AVZQEcg7kKrrM0A87gI+TGRHLBzZq/SvCvPrgeZXZgr/pjIrOiqDJGI/Paq0jVOA
# fzhrzybZKIVN1LGlUYKNID9lyGJ7qdOopDkSZ8IipDnfDHa9/QpcYItQbjFIkjFU
# 2SGIGVUFtquUHA/5SLz8LKfkrS/hT4qohvO7ksCesjx9qjhid75UWddStJZkqrFb
# UQn5l5TyGyQ3iLc9bXYkEsqU+hua8MDaqap4HVScUZ8N5aCcHVtbPuyxdZ64zDEw
# 4aJUaTKTAYQAeNTtjkpNvg9iTTBlRPD3dZC4imxdwvvRQ8YStEF//bODLjAdSGK7
# pgaUgZIxjE1+P4By8ZfGDW7CJrQoRAWFqacWMfUPolkvpuX4SpW9W2vesDbyActS
# +dGf+ahK33ooEfmmSMG3hkVgI4B1X0Xp0bEbvr2vbo731xlf5FQFCt5d+uUQ21s8
# hMILr46OLV0Z4vl4c5uEpdQ4f4bltE86vKWTtI2jAXcriQRwGJhqli14zGFA7rhq
# XAHYzT8mfE9ACDTVNN34eac6UepgsR2lVIBX1qGCDyowgg8mBgorBgEEAYI3AwMB
# MYIPFjCCDxIGCSqGSIb3DQEHAqCCDwMwgg7/AgEDMQ0wCwYJYIZIAWUDBAIBMIGJ
# BgsqhkiG9w0BCRABBKB6BHgwdgIBAQYMKwYBBAGCqTABAwYBMDEwDQYJYIZIAWUD
# BAIBBQAEIDpK8HOXsIFEFjZTRMxoRKSUJEDNCFbb+iE8GDUxDt3rAgheYiDnwDWW
# JhgPMjAyNjEwMTUyMTIyNTdaMAMCAQECEHHciDEehJcio4/xmT3qHH6gggwAMIIE
# /DCCAuSgAwIBAgIQH2sWYtIuG2xd8cDBoGAOODANBgkqhkiG9w0BAQsFADBzMQsw
# CQYDVQQGEwJVUzEOMAwGA1UECAwFVGV4YXMxEDAOBgNVBAcMB0hvdXN0b24xETAP
# BgNVBAoMCFNTTCBDb3JwMS8wLQYDVQQDDCZTU0wuY29tIFRpbWVzdGFtcGluZyBJ
# c3N1aW5nIFJTQSBDQSBSMTAeFw0yNTAyMTgxNjMyMDJaFw0zNDExMTIxODUwMDVa
# MG4xCzAJBgNVBAYTAlVTMQ4wDAYDVQQIDAVUZXhhczEQMA4GA1UEBwwHSG91c3Rv
# bjERMA8GA1UECgwIU1NMIENvcnAxKjAoBgNVBAMMIVNTTC5jb20gVGltZXN0YW1w
# aW5nIFVuaXQgMjAyNSBFMTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABBv7UVHH
# b+ZVluxPXlfE3M6tg0Xnq8dic+O3vPOCRpalUM1vO9A+GRzSVVjyygHhYrBw62XL
# Fh1kv7e+yRd/aTajggFaMIIBVjAfBgNVHSMEGDAWgBQMnRAljpqnG5mHQ88IfuG9
# gZD0zzBRBggrBgEFBQcBAQRFMEMwQQYIKwYBBQUHMAKGNWh0dHA6Ly9jZXJ0LnNz
# bC5jb20vU1NMLmNvbS10aW1lU3RhbXBpbmctSS1SU0EtUjEuY2VyMFEGA1UdIARK
# MEgwPAYMKwYBBAGCqTABAwYBMCwwKgYIKwYBBQUHAgEWHmh0dHBzOi8vd3d3LnNz
# bC5jb20vcmVwb3NpdG9yeTAIBgZngQwBBAIwFgYDVR0lAQH/BAwwCgYIKwYBBQUH
# AwgwRgYDVR0fBD8wPTA7oDmgN4Y1aHR0cDovL2NybHMuc3NsLmNvbS9TU0wuY29t
# LXRpbWVTdGFtcGluZy1JLVJTQS1SMS5jcmwwHQYDVR0OBBYEFM582cAEgMUkEGoJ
# 6hyrJT0R/ajSMA4GA1UdDwEB/wQEAwIHgDANBgkqhkiG9w0BAQsFAAOCAgEAgHN1
# JIW9ZlNip07FfY9r1LJwLKTl1h/y9r1BjDgHMEz7U7J7mAy32JxA1KLyjCCJqNku
# RfhDHGFEfZtjTOru7AQMDSDiUDvCCc3jaz5py9jGvwIe5npkLbXqXhA+SqCzG719
# USigwhHkYr7v8NiXoaY0Xu03p0BiZZreZlpngmGB9+86N94FqIFx2I5Z5iuu7d4j
# 7aAOZBNxfU9jFDIIGDtWfWeCpF0Q8rLE/3DHDlzJKs5Il3i/VoOl7rTU938oSrxM
# www6GDBlKX8rGHxvkjgIb9MXkVglJSDHsNAZDeCS/inaxKHA+ChuB8K4OxIxa6k1
# e+eHBypakAY3wuN7w7PlPmhN6k5IdqZn3HZHs2VjoR841Z9wmVPFdGDdkBZ7XOmb
# 5OZUaKufsvtER0VbY2DkzaqAaItt1kc+I+FUz7PiVz2PUzpegkftRRxvrPyIL08b
# lJTnbMQ0XrqDN0rEfuTLv4XhhnKyJaXhxCUdjO/cRumMzZ35QTUMItBWy1xGp0iy
# oFVnAya2pPsVMuAI+sy1zxlOS9l5iSxvKJ8gpnpOgjqYTa7u1eyZo+4JlcGoiiR1
# 7LthMTrF1q62tO5xOpI8txUZ6gtKGtkJV6wdj+vZLcwKZ2M93GqVpOo6UBlGjx1s
# KsVZ7AIUzJZli4NJ0M2KYcrfNnlebkYKpDnSqWwwggb8MIIE5KADAgECAhBtUhhw
# h+gjTYVgANCAj5NWMA0GCSqGSIb3DQEBCwUAMHwxCzAJBgNVBAYTAlVTMQ4wDAYD
# VQQIDAVUZXhhczEQMA4GA1UEBwwHSG91c3RvbjEYMBYGA1UECgwPU1NMIENvcnBv
# cmF0aW9uMTEwLwYDVQQDDChTU0wuY29tIFJvb3QgQ2VydGlmaWNhdGlvbiBBdXRo
# b3JpdHkgUlNBMB4XDTE5MTExMzE4NTAwNVoXDTM0MTExMjE4NTAwNVowczELMAkG
# A1UEBhMCVVMxDjAMBgNVBAgMBVRleGFzMRAwDgYDVQQHDAdIb3VzdG9uMREwDwYD
# VQQKDAhTU0wgQ29ycDEvMC0GA1UEAwwmU1NMLmNvbSBUaW1lc3RhbXBpbmcgSXNz
# dWluZyBSU0EgQ0EgUjEwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQCu
# URAT0vk8IKAghd7JUBxkyeH9xek0/wp/MUjoclrFXqhh/fGH91Fc+7fm0MHCE7A+
# wmOiqBj9ODrJAYGq3rm33jCnHSsCBNWAQYyoauLq8IjqsS1JlXL29qDNMMdwZ8UN
# zQS7vWZMDJ40JSGNphMGTIA2qn2bohGtgRc4p1395ESypUOaGvJ3t0FNL3BuKmb6
# YctMcQUF2sqooMzd89h0E6ujdvBDo6ZwNnWoxj7YmfWjSXg33A5GuY9ym4QZM5OE
# Vgo8ebz/B+gyhyCLNNhh4Mb/4xvCTCMVmNYrBviGgdPZYrym8Zb84TQCmSuX0JlL
# La6WK1aO6qlwISbb9bVGh866ekKblC/XRP20gAu1CjvcYciUgNTrGFg8f8AJgQPO
# Cc1/CCdaJSYwhJpSdheKOnQgESgNmYZPhFOC6IKaMAUXk5U1tjTcFCgFvvArXtK4
# azAWUOO1Y3fdldIBL6LjkzLUCYJNkFXqhsBVcPMuB0nUDWvLJfPimstjJ8lF4S6E
# CxWnlWi7OElVwTnt1GtRqeY9ydvvGLntU+FecK7DbqHDUd366UreMkSBtzevAc9a
# qoZPnjVMjvFqV1pYOjzmTiVHZtAc80bAfFe5LLfJzPI6DntNyqobpwTevQpHqPDN
# 9qqNO83r3kaw8A9j+HZiSw2AX5cGdQP0kG0vhzfgBwIDAQABo4IBgTCCAX0wEgYD
# VR0TAQH/BAgwBgEB/wIBADAfBgNVHSMEGDAWgBTdBAkHovV6fVJTEpKV7jiAJQ2m
# WTCBgwYIKwYBBQUHAQEEdzB1MFEGCCsGAQUFBzAChkVodHRwOi8vd3d3LnNzbC5j
# b20vcmVwb3NpdG9yeS9TU0xjb21Sb290Q2VydGlmaWNhdGlvbkF1dGhvcml0eVJT
# QS5jcnQwIAYIKwYBBQUHMAGGFGh0dHA6Ly9vY3Nwcy5zc2wuY29tMD8GA1UdIAQ4
# MDYwNAYEVR0gADAsMCoGCCsGAQUFBwIBFh5odHRwczovL3d3dy5zc2wuY29tL3Jl
# cG9zaXRvcnkwEwYDVR0lBAwwCgYIKwYBBQUHAwgwOwYDVR0fBDQwMjAwoC6gLIYq
# aHR0cDovL2NybHMuc3NsLmNvbS9zc2wuY29tLXJzYS1Sb290Q0EuY3JsMB0GA1Ud
# DgQWBBQMnRAljpqnG5mHQ88IfuG9gZD0zzAOBgNVHQ8BAf8EBAMCAYYwDQYJKoZI
# hvcNAQELBQADggIBAJIZdQ2mWkLPGQfZ8vyU+sCb8BXpRJZaL3Ez3VDlE3uZk3cP
# xPtybVfLuqaci0W6SB22JTMttCiQMnIVOsXWnIuAbD/aFTcUkTLBI3xys+wEajzX
# aXJYWACDS47BRjDtYlDW14gLJxf8W6DQoH3jHDGGy8kGJFOlDKG7/YrK7UGfHtBA
# EDVe6lyZ+FtCsrk7dD/IiL/+Q3Q6SFASJLQ2XI89ihFugdYL77CiDNXrI2MFspQG
# swXEAGpHuaQDTHUp/LdR3TyrIsLlnzoLskUGswF/KF8+kpWUiKJNC4rPWtNrxlbX
# YRGgdEdx8SMjUTDClldcrknlFxbqHsVmr9xkT2QtFmG+dEq1v5fsIK0vHaHrWjMM
# maJ9i+4qGJSD0stYfQ6v0PddT7EpGxGd867Ada6FZyHwbuQSadMb0K0P0OC2r7rw
# qBUe0BaMqTa6LWzWItgBjGcObXeMxmbQqlEz2YtAcErkZvh0WABDDE4U8GyV/32F
# daAvJgTfe9MiL2nSBioYe/g5mHUSWAay/Ip1RQmQCvmF9sNfqlhJwkjy/1U1ibUk
# TIUBX3HgymyQvqQTZLLys6pL2tCdWcjI9YuLw30rgZm8+K387L7ycUvqrmQ3ZJlu
# jHl3r1hgV76s3WwMPgKk1bAEFMj+rRXimSC+Ev30hXZdqyMdl/il5Ksd0vhGMYIC
# WTCCAlUCAQEwgYcwczELMAkGA1UEBhMCVVMxDjAMBgNVBAgMBVRleGFzMRAwDgYD
# VQQHDAdIb3VzdG9uMREwDwYDVQQKDAhTU0wgQ29ycDEvMC0GA1UEAwwmU1NMLmNv
# bSBUaW1lc3RhbXBpbmcgSXNzdWluZyBSU0EgQ0EgUjECEB9rFmLSLhtsXfHAwaBg
# DjgwCwYJYIZIAWUDBAIBoIIBYTAaBgkqhkiG9w0BCQMxDQYLKoZIhvcNAQkQAQQw
# HAYJKoZIhvcNAQkFMQ8XDTI2MTAxNTIxMjI1N1owKAYJKoZIhvcNAQk0MRswGTAL
# BglghkgBZQMEAgGhCgYIKoZIzj0EAwIwLwYJKoZIhvcNAQkEMSIEIM2L1d0sO6IO
# lASlHFmd9jlQIsjs1dMNr/kNdun1Sz+vMIHJBgsqhkiG9w0BCRACLzGBuTCBtjCB
# szCBsAQgVCr5oWqNci5mEUl4iumUwYqaruWmXLNEolSa+Wx5x4swgYswd6R1MHMx
# CzAJBgNVBAYTAlVTMQ4wDAYDVQQIDAVUZXhhczEQMA4GA1UEBwwHSG91c3RvbjER
# MA8GA1UECgwIU1NMIENvcnAxLzAtBgNVBAMMJlNTTC5jb20gVGltZXN0YW1waW5n
# IElzc3VpbmcgUlNBIENBIFIxAhAfaxZi0i4bbF3xwMGgYA44MAoGCCqGSM49BAMC
# BEgwRgIhALcapGqWCFks0TlPeAI3O44M1AAiwT6I/0IAeeFh3cocAiEA2MPIZDbW
# LKsDrZbSsafvwHCcCGHWU/Rg+WMKGRjFKd8=
# SIG # End signature block
