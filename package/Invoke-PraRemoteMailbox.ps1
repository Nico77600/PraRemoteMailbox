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
    Convert, Recover, Finalize or Check. The value is case-insensitive (convert, CONVERT); the entry script
    rewrites it to its official spelling right after the parameters are bound.

.PARAMETER Mode
    Preview (default): read, plan and report; nothing is changed.
    Apply: perform the changes (one confirmation unless -Force or -Confirm is given, see -Force).

.PARAMETER Phase
    Convert and Recover only. Default: Execution.Phase in the configuration.
      Both   AD part, synchronisation, then Exchange Online part on this server.
      AD     AD part only (and synchronisation). The cloud part runs later with -Phase Cloud.
             With -Batch (Convert): finishes the AD side of a batch whose AD changes are already made and verified
             (Entra Connect synchronisation again, then the transfer package); AD is not changed again.
      Cloud  Exchange Online part only, from the batch of the AD part (-Batch). Recover packages
             any final AD restoration for Finalize on the AD server; it never restores AD here.

.PARAMETER Batch
    Batch ID printed at the end of an Apply (8 characters are enough), or the full path of the batch
    JSON file, or a transfer package (.zip) written by the other server (a bare file name is looked up in
    <Storage.BackupFolder>\Inbox, then Outbox, then the current folder). The package is verified (checksums,
    Environment, names, sizes) and extracted to private folders first; every proof check then runs unchanged.
    Required by: Recover (the Convert batch), -Phase Cloud (the batch of the AD part),
    Finalize (the Finalize package). Optional for Check. Also accepted by Convert -Phase AD, to finish a batch
    left without its synchronisation or its transfer package.

.PARAMETER Identity
    One object only. Convert: UPN, sAMAccountName, DN or GUID, instead of the configured scope.
    Recover, cloud phase, Check: one object of the batch (or any UPN for Check).

.PARAMETER Scope
    All (default), UsersOnly or SharedOnly: filters the configured scope or the batch.
    Convert with -Identity ignores -Scope: the one named object is converted whatever its type (user, shared
    mailbox, room or equipment mailbox that the eligibility rules accept). -Scope still filters a batch
    (Recover, cloud phase) and the Check of a whole batch.

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

.PARAMETER BaseConfigPath
    Used by the window: -ConfigPath is then the generated, private configuration of ONE run (the configuration file plus the run settings
    changed in the window) and -BaseConfigPath is the configuration file itself, never modified. The settings that differ are listed in the log,
    the summary and the result of the run. Not needed on the command line.

.PARAMETER ForceAdReplication
    Turns Directory.ForceReplication on for this run (it is OFF by default). Before the Entra Connect synchronisation, each object changed in the run is
    pushed from the domain controller that was written to the other writable domain controllers (Sync-ADObject; Directory.ReplicationTargets restricts the
    list), then read back on each of them. A domain controller that does not confirm is a warning that names it; the synchronisation still runs and the
    Next steps say how to run it again later. Needs the right to replicate a single object (normally Domain Admins). A Preview never replicates.

.PARAMETER Force
    Apply without the confirmation prompt (scheduled or unattended runs). Never skips a safety check.
    The single confirmation of an Apply is also skipped when -Confirm is given explicitly, with either value:
    -Confirm:$false behaves like -Force for this prompt (and for the per-write prompts, which are then off),
    whereas a plain -Confirm replaces the single confirmation by the PowerShell confirmation of every write.
    Use -Confirm:$false only in a scheduled or unattended run, after a Preview that was reviewed.

.PARAMETER Once
    Cloud checks: one pass only instead of waiting (Polling.TimeoutMinutes) for the cloud.

.PARAMETER PassThru
    Also returns the result of the run as an object (Status, ExitCode, BatchId, NextSteps, counters,
    log and report paths), for a script or an orchestrator. Without it, nothing is written to the pipeline.

.PARAMETER Gui
    Opens the WPF window (native Fluent theme). Every operation runs in its own PowerShell 7.5+ process (pwsh.exe).

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
    .\Invoke-PraRemoteMailbox.ps1 -Action Convert -Phase AD -Mode Apply -Batch 490cc62e
    AD side of the batch 490cc62e already converted: runs the Entra Connect synchronisation again and writes the transfer
    package. AD is not changed again. Use it when a run ended after the AD changes without a package.

.EXAMPLE
    .\Invoke-PraRemoteMailbox.ps1 -Action Check -Identity user01@contoso.com -Expect Provisioned
    Read-only check of one mailbox in Exchange Online.

.NOTES
    Author     : Nicolas Fabert
    Version    : 3.1.2
    Requires   : PowerShell 7.5 or later (pwsh.exe; Windows PowerShell 5.1 is refused), RSAT ActiveDirectory,
                 ExchangeOnlineManagement 3.10.1+, Microsoft.Graph.Authentication and Microsoft.Graph.Users 2.41.1+ in one same
                 version (cloud part), ADSync (sync; through the Windows PowerShell compatibility layer when local).
    Exit codes : 0 = done, 1 = failed, 2 = done but a next step is required (Pending objects: a phase AD that ends with a package for
                 the other server, or for instance the Entra Connect
                 synchronisation could not start after the AD changes; the Next steps say what to do).
    Documentation : docs\PraRemoteMailbox-Guide.md (or .html)

    Disclaimer:
    This Script is a Personal project.
    It's provided "AS-IS". It's not an official Microsoft product so no support can be expected from Microsoft.

    As any scripts you must read carefully the documentation and test it first in a Test environment before any run in Production.

    The tool changes production objects in Active Directory and creates mailboxes in Exchange Online: run the preview, review the plan, keep the backups and test in a lab before using it in a real disaster.
#>
#Requires -Version 7.5
[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High', DefaultParameterSetName = 'Run')]
param(
    [Parameter(ParameterSetName = 'Run')][ValidateSet('Convert','Recover','Finalize','Check')][string]$Action,
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
    [Parameter(ParameterSetName = 'Run')][string]$BaseConfigPath,
    [Parameter(ParameterSetName = 'Run')][switch]$ForceAdReplication,
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
    if (-not [string]::Equals([string]$signature.Status, 'Valid', [StringComparison]::Ordinal) -or $null -eq $signature.SignerCertificate -or
        -not [string]::Equals([string]$signature.SignerCertificate.Thumbprint, '0F28E442889F17B5F4D251E8F96E7CC6E2C9C6D6', [StringComparison]::Ordinal) -or
        $null -eq $signature.TimeStamperCertificate) {
        throw 'Package integrity: verifier must have the trusted, timestamped owner signature.'
    }
    & $verifier -Root $PackageRoot
} $PSScriptRoot
# <<< PRA package integrity bootstrap
# Not a parameter default (kept from 2.x, where Windows PowerShell 5.1 left $PSScriptRoot empty in param() defaults under
# -File): the default path is computed here. An explicit -ConfigPath is unchanged ($script:ConfigPathBound).
if (-not $ConfigPath) { $ConfigPath = Join-Path $PSScriptRoot 'config\PraRemoteMailbox.config.psd1' }
# ValidateSet accepts any casing (-Action convert) but binds the value AS TYPED, while the proof, batch and journal
# checks of the modules compare the official spelling, ordinally (a tampered file must not pass).
# Rewrite every ValidateSet string parameter to its official spelling NOW, before anything reads it; the
# downstream comparisons stay exactly as strict as they were. ValidateSet itself uses the CULTURE comparison (ICU): it also accepts
# "Apply<U+0001>" or "Ap<U+200B>ply". The lookup below is ordinal (case-insensitive) and refuses any value that has no ordinal match.
foreach ($parameterInfo in $MyInvocation.MyCommand.Parameters.Values) {
    if ($parameterInfo.ParameterType -ne [string]) { continue }
    $validSet = @($parameterInfo.Attributes | Where-Object { $_ -is [Management.Automation.ValidateSetAttribute] })
    if ($validSet.Count -ne 1) { continue }
    $typed = [string](Get-Variable -Name $parameterInfo.Name -ValueOnly)
    if (-not $typed) { continue }
    $official = @($validSet[0].ValidValues | Where-Object { [string]::Equals($_, $typed, [StringComparison]::OrdinalIgnoreCase) })
    if ($official.Count -ne 1) { throw ("Parameter -{0}: '{1}' is not one of the accepted values ({2})." -f $parameterInfo.Name, $typed, ($validSet[0].ValidValues -join ', ')) }
    if (-not [string]::Equals([string]$official[0], $typed, [StringComparison]::Ordinal)) {
        Set-Variable -Name $parameterInfo.Name -Value ([string]$official[0])
        if ($PSBoundParameters.ContainsKey($parameterInfo.Name)) { $PSBoundParameters[$parameterInfo.Name] = [string]$official[0] }
    }
}
# -Action is not a Mandatory parameter on purpose: PowerShell would ask for it with a prompt, and a scheduled or unattended run (no console, no keyboard) would wait for
# an answer forever. A missing -Action stops at once, with the usage. (A new PowerShell process started with -NonInteractive would stop too; this does not depend on it.)
if (-not $Action -and -not $Gui) {
    Write-Error -ErrorAction Continue -Message ('-Action is missing: nothing was done. Give the task: -Action Convert, Recover, Finalize or Check (Preview is the default mode). Example: .\Invoke-PraRemoteMailbox.ps1 -Action Convert -Mode Preview. For the window: -Gui. Help: Get-Help .\Invoke-PraRemoteMailbox.ps1 -Full.')
    exit 1
}
if ($Gui) {
    try {
        Import-Module (Join-Path $PSScriptRoot 'PraRemoteMailbox.psd1') -Force -ErrorAction Stop
        Import-Module (Join-Path $PSScriptRoot 'module\PRA.Gui.psm1') -Force -ErrorAction Stop
        Show-PraGui -Root $PSScriptRoot -ConfigPath $ConfigPath -Version (Get-PraToolVersion)
        exit 0
    }
    catch { Write-Error ('The window could not open: {0}' -f $_.Exception.Message) -ErrorAction Continue; exit 1 }
}
# The manifest loads PRA.Common and PRA.Directory (and PRA.Backup through it). PRA.Cloud is imported later, only when the cloud phase needs it; PRA.Gui only for -Gui.
Import-Module (Join-Path $PSScriptRoot 'PraRemoteMailbox.psd1') -Force -ErrorAction Stop

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
    Root = $PSScriptRoot; Version = (Get-PraToolVersion); RunId = ((Get-Date -Format 'yyyyMMdd_HHmmss') + '-' + [guid]::NewGuid().ToString('N'))
    StartTime = Get-Date; Action = $Action; Mode = $effectiveMode; Phase = ''
    CurrentPhase = 'Start'; CurrentOperation = ''; CurrentIdentity = ''; StepIndex = 0; StepTotal = 0; Warnings = 0
    Issues = (New-Object 'Collections.Generic.List[object]'); Rows = (New-Object 'Collections.Generic.List[object]')
    BackupFiles = (New-Object 'Collections.Generic.List[string]'); StateFiles = (New-Object 'Collections.Generic.List[string]')
    LogFolder = (Join-Path $PSScriptRoot 'logs'); ReportFolder = (Join-Path $PSScriptRoot 'reports'); BackupFolder = (Join-Path $PSScriptRoot 'Backups')
    LogFile = ''; TranscriptPath = ''; TranscriptStarted = $false; NoReport = $false
    Server = ''; NamingContext = ''; CloudConnectFailed = $false; ExitCode = 0; ResultStatus = ''
    AllowMutation = ((Test-PraOrdinalIgnoreCaseEqual $effectiveMode 'Apply') -and (-not (Test-PraOrdinalIgnoreCaseEqual $Action 'Check'))); Config = @{}; KeepCloudShared = $false
    Approval = $null; ConfirmPreference = [string]$ConfirmPreference
    Once = [bool]$Once; IntervalMinutes = 0; TimeoutMinutes = 0
    VerboseEnabled = ((Test-PraOrdinalIgnoreCaseEqual $VerbosePreference 'Continue') -or (Test-PraOrdinalIgnoreCaseEqual $DebugPreference 'Continue'))
    SourceBackupHash = ''; Source = $null; Proof = $null; LastVerifiedReceipt = $null; OperationFailed = $false; JournalPath = ''
    BatchId = ''; NextSteps = @()
}
$context.Approval = New-PraApprovalCallback $caller $context
# Lets the modules write a command line of this run's own style (-ConfigPath kept) in a message; defined here because Get-PraCommandLine is a function of this script.
$context.CommandLineFor = { param([string]$ActionName, [string]$PhaseName, [string]$BatchId) Get-PraCommandLine -ActionName $ActionName -PhaseName $PhaseName -BatchId $BatchId }

# =================================================================================================
# Helper functions of the entry script (they use $context).
# =================================================================================================

function Get-PraShortId {
    <# First 8 characters of a batch or package ID, as shown to the operator. #>
    param([string]$Id)
    if ($Id.Length -gt 8) { return $Id.Substring(0, 8) }
    return $Id
}

function ConvertTo-PraLiteral {
    <# A value as a single-quoted PowerShell literal: the apostrophe AND the typographic quotes that PowerShell also reads as quotes are doubled. #>
    param([AllowEmptyString()][string]$Value)
    $escaped = $Value.Replace("'", "''")
    foreach ($code in @(0x2018, 0x2019, 0x201A, 0x201B)) { $quote = [string][char]$code; $escaped = $escaped.Replace($quote, $quote + $quote) }
    return "'" + $escaped + "'"
}

function Get-PraCommandLine {
    <# Command line suggested in "Next step", with the options of this run that still apply. Every free-text value is quoted as data. #>
    param([string]$ActionName, [string]$ModeName = 'Apply', [string]$PhaseName = '', [string]$BatchId = '', [switch]$KeepFilters, [switch]$OtherServer)
    $parts = @('.\Invoke-PraRemoteMailbox.ps1', "-Action $ActionName")
    if ($PhaseName) { $parts += "-Phase $PhaseName" }
    if ((Test-PraOrdinalIgnoreCaseEqual $ModeName 'Apply')) { $parts += '-Mode Apply' }
    if ($BatchId) { $parts += $(if ($BatchId -match '^[0-9a-fA-F]+$') { "-Batch $BatchId" } else { '-Batch ' + (ConvertTo-PraLiteral $BatchId) }) }
    if ($KeepFilters) {
        if ($Identity) { $parts += '-Identity ' + (ConvertTo-PraLiteral $Identity) }
        if ((-not (Test-PraOrdinalIgnoreCaseEqual $Scope 'All'))) { $parts += "-Scope $Scope" }
        if ($MaxObjects -gt 0) { $parts += "-MaxObjects $MaxObjects" }
        if ($SearchBase) { $parts += '-SearchBase ' + (ConvertTo-PraLiteral $SearchBase) }
        if ($CsvPath) { $parts += '-CsvPath ' + (ConvertTo-PraLiteral $CsvPath) }
    }
    # On another server the configuration file is that server's own: -ConfigPath is not repeated.
    # Run from the window, -ConfigPath is the generated configuration of that run: the suggested command names the configuration file itself.
    if ($script:ConfigPathBound -and -not $OtherServer) { $parts += '-ConfigPath ' + (ConvertTo-PraLiteral $(if ($BaseConfigPath) { $BaseConfigPath } else { $ConfigPath })) }
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
    if ($Value -match '[\\/:]' -or $Value.EndsWith('.json', [StringComparison]::OrdinalIgnoreCase)) {
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
        if (@($folders | ForEach-Object Name | Get-PraOrdinalUnique).Count -gt 1) { throw "Batch ID $Value is ambiguous ($($folders.Count) folders): give more characters." }
    }
    $found = New-Object 'Collections.Generic.List[string]'
    foreach ($folder in $folders) {
        foreach ($file in @(Get-ChildItem -LiteralPath $folder.FullName -File -Filter '*.json' -ErrorAction Stop | Where-Object { -not $_.Name.StartsWith('State-', [StringComparison]::OrdinalIgnoreCase) })) {
            try { $operation = [string](([IO.File]::ReadAllText($file.FullName) | ConvertFrom-PraJson).Operation) } catch { continue }
            # In a Finalize package only the manifest counts (the other JSON files are copies of the source batches).
            if ((Test-PraOrdinalIn $operation $Operations) -and ($folder.Name -match '^Batch-' -or (Test-PraOrdinalEqual $operation 'RecoverFinalize'))) { $found.Add($file.FullName) }
        }
    }
    # The same batch folder copied twice (identical content) is not an ambiguity.
    # (Group-Object would compare the hash texts with the culture comparison.)
    $byHash = New-Object 'Collections.Generic.Dictionary[string,string]' -ArgumentList ([StringComparer]::Ordinal)
    foreach ($candidatePath in $found) { $candidateHash = Get-PraHash $candidatePath; if (-not $byHash.ContainsKey($candidateHash)) { $byHash[$candidateHash] = $candidatePath } }
    $distinct = @($byHash.Values)
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
            [string]::Equals(([IO.File]::ReadAllText($_.FullName).Trim()), $Hash, [StringComparison]::Ordinal) } | ForEach-Object { $_.FullName.Substring(0, $_.FullName.Length - 7) })
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
        $records = @($records | Where-Object { (Test-PraOrdinalIgnoreCaseEqual $_.SamAccountName $Identity) -or (Test-PraOrdinalIgnoreCaseEqual $_.UserPrincipalName $Identity) -or (Test-PraOrdinalIgnoreCaseEqual $_.ObjectGuid $Identity) })
        if ($records.Count -ne 1) { throw "Identity '$Identity' is not in the batch (or matches several objects)." }
    }
    elseif ((Test-PraOrdinalIgnoreCaseEqual $Scope 'SharedOnly')) { $records = @($records | Where-Object IsShared) }
    elseif ((Test-PraOrdinalIgnoreCaseEqual $Scope 'UsersOnly')) { $records = @($records | Where-Object { -not $_.IsShared }) }
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
        if (@($proof.Data.Records | Where-Object { Test-PraOrdinalIgnoreCaseEqual $_.ObjectGuid $Row.ObjectGuid }).Count -ne 1) { throw 'Cloud write refused: the object is not in a verified AD phase.' }
        Assert-PraReceipt $capturedContext $capturedContext.Source $Row.ObjectGuid
    }.GetNewClosure()
    $context.JournalMutation = { param($Target, $Operation, $Status, $Detail) Write-PraJournal $capturedContext $Target $Operation $Status ([string]$Detail) }.GetNewClosure()
}

function Initialize-PraCloudJournal {
    <# Private folder <RunId>-cloud with the journal of the Exchange Online writes of this run. #>
    $directory = Join-Path $context.BackupFolder ($context.RunId + '-cloud')
    New-PraPrivateDirectory $directory -Root $context.BackupFolder
    $context.JournalPath = Join-Path $directory 'CloudOperations.jsonl'
    Write-PraImmutableFile $context.JournalPath ''
    $context.StateFiles.Add($context.JournalPath)
    Write-PraJournal $context '*' 'CloudPhase' 'Initialized' 'AD proof loaded; no cloud write yet.'
}

function Copy-PraBundleFile {
    param([string]$Path, [string]$Directory)
    $destination = Join-Path $Directory ([IO.Path]::GetFileName($Path))
    if (Test-Path -LiteralPath $destination) {
        if (-not (Test-PraOrdinalEqual (Get-PraHash $Path) (Get-PraHash $destination))) { throw 'Two different files with the same name in the Finalize package.' }
        return
    }
    [IO.File]::Copy($Path, $destination, $false)
    if (-not (Test-PraOrdinalEqual (Get-PraHash $Path) (Get-PraHash $destination))) { throw 'Copy of a proof file is incomplete.' }
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
            if (-not (Test-PraOrdinalEqual $row.CloudStatus 'Success') -or $row.DeprovisionConfirmed -ne $true -or $row.ADVerified -ne $true) { throw 'Finalize package refused: AD proof or cloud deprovisioning not confirmed for every object.' }
            [ordered]@{ ObjectGuid = $row.ObjectGuid; RestoreShared = [bool]$row.DeproPending; RestoreTag = [bool](Get-PraValue (Get-PraValue $row.BackupRec 'Retention' $null) 'Enabled' $false); CloudConfirmed = $true; DeprovisionConfirmed = $true }
        })
    $packageId = [guid]::NewGuid().ToString('N')
    $directory = Join-Path $context.BackupFolder ('Finalize-' + $packageId)
    New-PraPrivateDirectory $directory -Root $context.BackupFolder
    Copy-PraBackupBundle $context.Source $directory
    Copy-PraBackupBundle $proof.Receipt $directory
    Copy-PraBundleFile $proof.Path $directory; Copy-PraBundleFile ($proof.Path + '.sha256') $directory
    # The earlier phases (Recover on the AD server, the original Convert) travel with the package, for the global report of the AD server.
    $null = Copy-PraPhaseData -SourceFolder @(Get-PraList $context 'PhaseFolders') -Destination $directory
    $context.PhaseWriteFolder = $directory; $context.PhaseDataSaved = $false
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
    Publish-PraTransferPackage -Kind 'Finalize' -BatchId $packageId -Folders @($directory) -NextAction 'Finalize' `
        -FallbackSteps @("Copy the folder $directory to the Backups folder of the AD server, then run there:", (Get-PraCommandLine -ActionName 'Finalize' -BatchId $short -OtherServer))
}

function Get-PraFinalizeInput {
    <# Reads and checks a Finalize package; returns the objects it authorises to restore. #>
    $path = Get-PraBatchFile -Value $Batch -Operations @('RecoverFinalize')
    $context.CurrentOperation = 'Read-FinalizePackage'
    $manifest = Get-Content -LiteralPath $path -Raw -Encoding UTF8 -ErrorAction Stop | ConvertFrom-PraJson
    if ((Get-PraValue $manifest 'SchemaVersion' 0) -ne 2 -or -not (Test-PraOrdinalEqual $manifest.Operation 'RecoverFinalize') -or -not (Test-PraOrdinalEqual $manifest.Environment $context.Config.Environment)) { throw 'Finalize package of another version or Environment: nothing restored.' }
    if (-not (Test-PraOrdinalEqual (Get-Content -LiteralPath ($path + '.sha256') -Raw -ErrorAction Stop).Trim() (Get-PraHash $path))) { throw 'Finalize package: SHA-256 mismatch.' }
    foreach ($property in @('SourceBackupFile','StateFile')) {
        if (-not (Test-PraOrdinalEqual ([IO.Path]::GetFileName($manifest.$property)) $manifest.$property)) { throw 'Finalize package: a file path points outside the package.' }
    }
    $context.Source = Import-PraBackup $context (Join-Path (Split-Path $path -Parent) $manifest.SourceBackupFile)
    $context.PhaseFolders = @(Split-Path $path -Parent)
    $context.Proof = Import-PraProof $context (Join-Path (Split-Path $path -Parent) $manifest.StateFile) $context.Source 'Recover'
    if (-not (Test-PraOrdinalEqual $context.Source.Hash $manifest.SourceBackupHash) -or -not (Test-PraOrdinalEqual $context.Proof.Hash $manifest.StateHash)) { throw 'Finalize package: manifest and proofs do not match.' }
    $records = @(Select-PraSourceRecord $context.Source); $seen = @{}
    $items = @($manifest.Items)
    if (-not $items.Count) { throw 'Finalize package is empty.' }
    foreach ($item in $items) {
        if ($item.CloudConfirmed -isnot [bool] -or -not $item.CloudConfirmed -or $item.DeprovisionConfirmed -isnot [bool] -or -not $item.DeprovisionConfirmed -or $item.RestoreShared -isnot [bool] -or $item.RestoreTag -isnot [bool] -or
            -not (Test-PraOrdinalIn $item.ObjectGuid @($context.Proof.Data.Records.ObjectGuid) -IgnoreCase) -or $seen.ContainsKey($item.ObjectGuid)) { throw 'Finalize package: invalid object confirmation.' }
        $proofEntry = @($context.Proof.Data.Records | Where-Object { Test-PraOrdinalIgnoreCaseEqual $_.ObjectGuid $item.ObjectGuid })[0]
        $snapshotEntry = @($context.Proof.Receipt.Data.Records | Where-Object { Test-PraOrdinalIgnoreCaseEqual $_.ObjectGuid $item.ObjectGuid })[0]
        $sourceEntry = @($context.Source.Data.Records | Where-Object { Test-PraOrdinalIgnoreCaseEqual $_.ObjectGuid $item.ObjectGuid })[0]
        if ($snapshotEntry.PreserveCloudMailbox -or ($item.RestoreShared -and (-not (Test-PraOrdinalEqual $proofEntry.Operation 'Deprovision') -or -not $sourceEntry.IsShared)) -or
            ($item.RestoreTag -and -not [bool](Get-PraValue (Get-PraValue $sourceEntry 'Retention' $null) 'Enabled' $false)) -or
            (-not $item.RestoreShared -and -not $item.RestoreTag)) { throw 'Finalize package does not match the AD operations it proves.' }
        $seen[$item.ObjectGuid] = $true
    }
    if ($Identity -and @($records | Where-Object { Test-PraOrdinalIn $_.ObjectGuid @($items.ObjectGuid) -IgnoreCase }).Count -ne 1) { throw "Identity '$Identity' is not authorised by this Finalize package." }
    $context.BatchId = Get-PraShortId ((Split-Path (Split-Path $path -Parent) -Leaf) -replace '^Finalize-', '')
    return @($records | Where-Object { Test-PraOrdinalIn $_.ObjectGuid @($items.ObjectGuid) -IgnoreCase } | ForEach-Object {
            $recordGuid = $_.ObjectGuid
            [pscustomobject]@{ Record = $_; Item = ($items | Where-Object { Test-PraOrdinalIgnoreCaseEqual $_.ObjectGuid $recordGuid }) } })
}

function Format-PraByteSize {
    param([long]$Bytes)
    if ($Bytes -ge 1MB) { return ('{0:0.0} MB' -f ($Bytes / 1MB)).Replace(',', '.') }
    if ($Bytes -ge 1KB) { return ('{0:0.0} KB' -f ($Bytes / 1KB)).Replace(',', '.') }
    return ('{0} bytes' -f $Bytes)
}

function Publish-PraTransferPackage {
    <#
    .SYNOPSIS
        Hand-off: writes the ONE transfer package (ZIP + .sha256, in <Storage.BackupFolder>\Outbox) that the other server imports, and sets the
        next steps. The batch folders stay the source of truth; if the package cannot be written the run keeps its result, a warning explains it
        and the next steps fall back to the copy of the folders.
    #>
    param([Parameter(Mandatory)][string]$Kind, [Parameter(Mandatory)][string]$BatchId, [Parameter(Mandatory)][string[]]$Folders,
        [Parameter(Mandatory)][string]$NextAction, [string]$NextPhase = '', [Parameter(Mandatory)][string[]]$FallbackSteps)
    $targetName = if ((Test-PraOrdinalIgnoreCaseEqual $Kind 'Finalize')) { 'AD' } else { 'cloud' }
    $context.CurrentOperation = 'Create-TransferPackage'; $context.CurrentIdentity = ''
    # A hand-over means that the batch is only half done: the objects are Pending (exit code 2, "done, next step required"), whether the package could be written or not.
    foreach ($row in $context.Rows) {
        if ((Test-PraOrdinalIn ([string]$row.FinalStatus) @('Success', 'AlreadyDone'))) { $row.FinalStatus = 'Pending'; $row.Detail = ([string]$row.Detail + (' | next: the {0} part' -f $targetName)).Trim(' ', '|') }
    }
    # This run is not the last one: what it did travels in the package, so that the last server can report on every object from end to end.
    $context.HandOff = $Kind
    $phaseFolder = [string](Get-PraValue $context 'PhaseWriteFolder' '')
    if ($phaseFolder -and -not [bool](Get-PraValue $context 'PhaseDataSaved' $false)) {
        try { $null = Save-PraPhaseData -Context $context -Folder $phaseFolder -HandOff $Kind; $context.PhaseDataSaved = $true }
        catch { Write-PraLog -Context $context -Message ('The data for the global report could not be saved ({0}): the package is complete, the other server will report this side as not available.' -f $_.Exception.Message) -Level Warning }
    }
    try {
        $name = Get-PraTransferPackageName -Kind $Kind -Environment $context.Config.Environment -BatchId $BatchId
        $command = Get-PraCommandLine -ActionName $NextAction -PhaseName $NextPhase -BatchId $name -OtherServer
        $package = New-PraTransferPackage -Kind $Kind -Environment $context.Config.Environment -BatchId $BatchId -Folders $Folders `
            -OutboxFolder (Join-Path $context.BackupFolder 'Outbox') -NextCommand $command -ToolVersion $context.Version
        $context.TransferPackage = $package.Path; $context.TransferPackageKind = $Kind
        Write-PraItem -Context $context -Status Ok -Icon Batch -Text ('Transfer package {0} written ({1}, checksums verified)' -f $package.Name, (Format-PraByteSize $package.SizeBytes)) -Detail $package.Path
        $context.NextSteps = @(('Copy {0} to the {1} server (anywhere), then run there:' -f $package.Path, $targetName), $command)
    }
    catch {
        Write-PraLog -Context $context -Message ('The transfer package could not be created ({0}). The folders are complete: copy them by hand as indicated below.' -f $_.Exception.Message) -Level Warning
        $context.NextSteps = @($FallbackSteps)
    }
}

function Resolve-PraTransferPackagePath {
    <# A -Batch value ending in .zip: a path, or a bare file name looked up in Inbox, then Outbox (under Storage.BackupFolder), then the current folder. #>
    param([Parameter(Mandatory)][string]$Value)
    if ($Value -match '[\/:]') {
        $candidate = Resolve-PraPath $Value 'Batch' (Get-Location).Path
        if (-not (Test-Path -LiteralPath $candidate -PathType Leaf)) { throw "Transfer package not found: $candidate" }
        return $candidate
    }
    foreach ($folder in @((Join-Path $context.BackupFolder 'Inbox'), (Join-Path $context.BackupFolder 'Outbox'), (Get-Location).Path)) {
        $candidate = Join-Path $folder $Value
        if (Test-Path -LiteralPath $candidate -PathType Leaf) { return $candidate }
    }
    throw "Transfer package $Value not found in $(Join-Path $context.BackupFolder 'Inbox'), in the Outbox folder or in the current folder: give its full path."
}

function Test-PraSyncAvailable {
    <#
    .SYNOPSIS
        Proves, with the account that runs the tool, that the Entra Connect synchronisation requested by the configuration is possible: an authenticated
        read-only call to the ADSync module of EntraConnect.Server (PowerShell remoting, bounded time) or of this server. A bare WinRM connection test would not do: it does not authenticate.
    .DESCRIPTION
        Apply: when the check fails, the run STOPS here, before the confirmation and before any AD write (nothing is changed).
        Preview: the same check, reported as a warning that says why the synchronisation will not be possible and what to do.
    #>
    $sync = $context.Config.EntraConnect
    if (-not $sync.Sync) { return }
    $context.CurrentOperation = 'Check-EntraConnect'
    $answer = Test-PraSyncServer -Server ([string]$sync.Server)
    if ($answer.Ok) {
        Write-PraItem -Context $context -Status Ok -Icon Sync -Text ("Entra Connect: {0}, a {1} cycle runs after the AD changes" -f $answer.Reason, $sync.PolicyType)
        return
    }
    $message = 'Entra Connect sync will not be possible: {0}. Either fix that, or set EntraConnect.Sync = $false in the configuration file and run the synchronisation yourself after the AD changes.' -f $answer.Reason
    if ($context.AllowMutation) { throw ('{0} Nothing was changed.' -f $message) }
    Write-PraItem -Context $context -Status Warn -Icon Sync -Text $message -Detail $answer.Technical
}

function Test-PraCloudModuleAvailable {
    <#
    .SYNOPSIS
        Before any change, checks the cloud modules of this server: ExchangeOnlineManagement at the minimum version or later, and ONE version of Microsoft.Graph.Authentication
        and Microsoft.Graph.Users at the minimum version or later (Get-PraCloudModuleReport). The versions found, the minimum and the exact Install-Module command are in the message.
    .DESCRIPTION
        Apply, Check and phase Cloud (they sign in): the run STOPS here, with nothing changed. Preview of phase Both (it does not sign in): a warning.
    #>
    $context.CurrentOperation = 'Check-CloudModules'
    $report = Get-PraCloudModuleReport -MinExo ([string]$context.Config.Exo.MinModuleVersion)
    if ($report.Ok) {
        Write-PraItem -Context $context -Status Ok -Icon Cloud -Text ('Cloud modules: Microsoft Graph {0} (Authentication and Users), ExchangeOnlineManagement {1}' -f $report.Graph.Version, $report.Exo.Version)
        return
    }
    $text = $report.Messages -join ' '
    $signsIn = $context.AllowMutation -or (Test-PraOrdinalIgnoreCaseEqual $Action 'Check') -or (Test-PraOrdinalIgnoreCaseEqual $effectivePhase 'Cloud')
    if ($signsIn) { throw ('The cloud part cannot run on this server. {0} Nothing was changed.' -f $text) }
    Write-PraItem -Context $context -Status Warn -Icon Cloud -Text ('The cloud part will not be possible on this server. {0}' -f $text)
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
    $changes = @($Plans | Where-Object { -not (Test-PraOrdinalEqual $_.Operation 'AlreadyRecovered') })
    $users = @($Plans | Where-Object { -not $_.Record.IsShared }).Count
    $shared = @($Plans | Where-Object { $_.Record.IsShared }).Count
    $grants = 0
    foreach ($plan in $Plans) { foreach ($right in @('FullAccess','SendAs','SendOnBehalf')) { $grants += @($plan.Record.SharedPermissions.$right).Count } }
    $text = '{0} object(s): {1} user(s), {2} shared' -f $Plans.Count, $users, $shared
    if ((Test-PraOrdinalIgnoreCaseEqual $Action 'Convert') -and $shared) { $text += (' {0} {1} permission(s) to reproduce in Exchange Online' -f [char]0x00B7, $grants) }
    Write-PraItem -Context $context -Status Info -Icon Target -Text $text
    return $changes.Count
}

function Skip-PraStep {
    <# Prints a step that does not run in this execution (numbering stays in the announced order). #>
    param([Parameter(Mandatory)][string]$Title, [Parameter(Mandatory)][string]$Reason, [string]$Icon = 'Skip')
    Write-PraStep -Context $context -Title $Title -Icon $Icon -Skipped
    Write-PraItem -Context $context -Status Skip -Text $Reason
}

function Send-PraPlanCount {
    <# Once the objects are known (after targeting), tells the window how many objects each step works on (the batch-wide steps have none). One 'count' event. #>
    param([int]$Count)
    if (-not $env:PRA_EVENT_FILE -or $Count -le 0) { return }
    $batchWide = @('Active Directory connection', 'Entra Connect synchronisation', 'Active Directory replication', 'Creating the transfer package', 'Loading the Convert batch', 'Loading the Recover batch',
        'Loading the batch of the AD phase', 'Loading the Finalize package', 'Exchange Online pre-check')
    $ids = @(); $index = 0
    foreach ($label in @($steps)) { $index++; if (-not (Test-PraOrdinalIn ([string]$label) $batchWide)) { $ids += ('s' + $index) } }
    Write-PraEvent -Kind count -Data @{ count = $Count; stepIds = $ids }
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
$script:PreviewPackage = ''
$script:ConfirmBound = $PSBoundParameters.ContainsKey('Confirm')
try {
    # ---------------------------------------------------------------------------------------------
    # Configuration, audit files, banner.
    # ---------------------------------------------------------------------------------------------
    $context.CurrentOperation = 'Read-Configuration'
    $targetOverride = Get-PraTargetOverride -SearchBase $SearchBase -CsvPath $CsvPath -Identity $Identity
    $context.Config = Import-PraConfiguration -Path $ConfigPath -Root $PSScriptRoot -ScopeOverride $targetOverride -DeferScopeCheck
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
    if ($ForceAdReplication -and -not [bool]$config.Directory.ForceReplication) {
        $config.Directory.ForceReplication = $true
        $context.ConfigOverrides = @(@(Get-PraList $context 'ConfigOverrides') + 'Directory.ForceReplication: False -> True (-ForceAdReplication)')
    }
    $replicate = [bool]$config.Directory.ForceReplication
    # Run from the window: -ConfigPath is the generated configuration of this run, -BaseConfigPath the configuration file (never modified).
    # What differs is written to the log, the summary card and the result.
    $configDifferences = @()
    if ($BaseConfigPath) {
        $baseConfig = Import-PraConfiguration -Path $BaseConfigPath -Root $PSScriptRoot -ScopeOverride $targetOverride -DeferScopeCheck
        $configDifferences = @(Get-PraConfigurationDifference -Base $baseConfig -Effective $config)
        $context.ConfigOverrides = @(@(Get-PraList $context 'ConfigOverrides') + @($configDifferences | ForEach-Object { $_.Text }))
    }
    $effectivePhase = switch ($Action) {
        'Finalize' { 'Finalize' }
        'Check' { 'Cloud' }
        default { if ($Phase) { $Phase } else { $config.Execution.Phase } }
    }
    $context.Phase = $effectivePhase
    if (($SearchBase -or $CsvPath) -and ((-not (Test-PraOrdinalIgnoreCaseEqual $Action 'Convert')) -or (-not (Test-PraOrdinalIn $effectivePhase @('AD','Both') -IgnoreCase)))) {
        throw 'SearchBase/CsvPath are only available for Convert -Phase AD or Both.'
    }

    # Only a new conversion (Convert, phase AD or Both, no batch, no single account) needs to know which mailboxes to take: Check, the cloud phases, Recover and Finalize never ask for the scope.
    if ((Test-PraOrdinalIgnoreCaseEqual $Action 'Convert') -and (Test-PraOrdinalIn $effectivePhase @('AD','Both') -IgnoreCase) -and -not $Batch -and -not $Identity) { Test-PraScopeConfiguration -Config $config }

    Initialize-PraAudit $context

    $dot = [char]0x00B7
    $modeText = if ((Test-PraOrdinalIgnoreCaseEqual $effectiveMode 'Apply')) { 'Apply (changes are made)' } else { 'Preview (nothing is changed)' }
    $actionText = $Action
    if ((Test-PraOrdinalIn $Action @('Convert','Recover') -IgnoreCase)) { $actionText += " $dot phase $effectivePhase" }
    if ((Test-PraOrdinalIgnoreCaseEqual $Action 'Check')) { $actionText += " $dot expect $Expect" }
    $scopeText = if ($Identity) { "one object: $Identity" }
        elseif ($Batch) { "batch $Batch" + $(if ((-not (Test-PraOrdinalIgnoreCaseEqual $Scope 'All'))) { " $dot $Scope" } else { '' }) }
        else {
            $s = $config.Scope
            $base = switch ($s.Mode) { 'OU' { $s.SearchBase } 'Group' { "members of $($s.GroupDN)" } 'Csv' { "CSV $($s.CsvPath)" } default { if ($s.SearchBase) { $s.SearchBase } else { 'whole domain' } } }
            $kinds = @('users'); if ($s.IncludeShared) { $kinds += 'shared' }; if ($s.IncludeRoom) { $kinds += 'rooms' }; if ($s.IncludeEquip) { $kinds += 'equipment' }
            # -Scope replaces the mailbox types of the configuration.
            if ((Test-PraOrdinalIgnoreCaseEqual $Scope 'UsersOnly')) { $kinds = @('users only') } elseif ((Test-PraOrdinalIgnoreCaseEqual $Scope 'SharedOnly')) { $kinds = @('shared mailboxes only') }
            '{0} {1} {2}' -f $base, $dot, ($kinds -join ' + ') + $(if ($MaxObjects) { " $dot max $MaxObjects" } else { '' })
        }
    $banner = [ordered]@{ 'Action' = @('Mode', $actionText); 'Mode' = @($(if ((Test-PraOrdinalIgnoreCaseEqual $effectiveMode 'Apply')) { 'Write' } else { 'Plan' }), $modeText) }
    if ((-not (Test-PraOrdinalIgnoreCaseEqual $Action 'Finalize'))) { $banner['Scope'] = @('Target', $scopeText) }
    if ($config.Cloud.Organization -and (-not (Test-PraOrdinalIgnoreCaseEqual $Action 'Finalize')) -and (-not (Test-PraOrdinalIgnoreCaseEqual $effectivePhase 'AD'))) { $banner['Tenant'] = @('Cloud', $config.Cloud.Organization) }
    $banner['Config'] = @('Config', ('{0} {1} Environment {2}' -f (Split-Path $config._Path -Leaf), $dot, $config.Environment))
    if ($configDifferences.Count) { $banner['Overrides'] = @('Config', ('{0} run setting(s) differ from {1}' -f $configDifferences.Count, (Split-Path $baseConfig._Path -Leaf))) }
    $banner['Log'] = @('Log', $context.LogFile)
    Write-PraBanner -Context $context -Title 'PRA Remote Mailbox' -Subtitle "Hybrid Exchange disaster recovery $dot on-premises $([char]0x2192) Exchange Online" -Details $banner
    foreach ($difference in $configDifferences) {
        Write-PraItem -Context $context -Status Info -Icon Config -Text ('Run setting: {0} {1} (configuration file: {2})' -f $difference.Key, $(if ($difference.Effective) { $difference.Effective } else { '(empty)' }), $(if ($difference.Base) { $difference.Base } else { '(empty)' }))
    }

    # Steps of this run (numbered x/total in the console).
    $steps = switch ($Action) {
        'Convert' {
            if ((Test-PraOrdinalIgnoreCaseEqual $effectivePhase 'Cloud')) { @('Loading the batch of the AD phase','Exchange Online: mailboxes, licences and permissions') }
            elseif ($Batch -and (Test-PraOrdinalIgnoreCaseEqual $effectivePhase 'AD')) { @('Loading the batch of the AD phase','Entra Connect synchronisation','Creating the transfer package') }
            else {
                @('Active Directory connection','Targets and planned changes') +
                $(if ((Test-PraOrdinalIgnoreCaseEqual $effectivePhase 'Both')) { @('Exchange Online pre-check') } else { @() }) +
                @('Backup and Active Directory changes') + $(if ($replicate) { @('Active Directory replication') } else { @() }) + @('Entra Connect synchronisation') +
                $(if ((Test-PraOrdinalIgnoreCaseEqual $effectivePhase 'Both')) { @('Exchange Online: mailboxes, licences and permissions') } else { @('Creating the transfer package') })
            }
        }
        'Recover' {
            if ((Test-PraOrdinalIgnoreCaseEqual $effectivePhase 'Cloud')) { @('Loading the Recover batch','Exchange Online: deprovisioning checks','Final restore of shared mailboxes and tags') }
            else {
                @('Loading the Convert batch','Active Directory connection','Planned restore') +
                $(if ((Test-PraOrdinalIgnoreCaseEqual $effectivePhase 'Both')) { @('Exchange Online pre-check') } else { @() }) +
                @('Backup and Active Directory changes') + $(if ($replicate) { @('Active Directory replication') } else { @() }) + @('Entra Connect synchronisation') +
                $(if ((Test-PraOrdinalIgnoreCaseEqual $effectivePhase 'Both')) { @('Exchange Online: deprovisioning checks','Final restore of shared mailboxes and tags') } else { @('Creating the transfer package') })
            }
        }
        'Finalize' { @('Loading the Finalize package','Active Directory connection','Planned restore','Backup and Active Directory changes') + $(if ($replicate) { @('Active Directory replication') } else { @() }) + @('Entra Connect synchronisation') }
        'Check' { @('Objects to check','Exchange Online checks') }
    }
    $context.StepTotal = @($steps).Count
    # The whole ordered list of steps is announced once, for the window (ids are 's' + the position, as in the step and item events).
    $planSteps = @(); $planIndex = 0
    foreach ($announcedStep in @($steps)) { $planIndex++; $planSteps += [ordered]@{ id = ('s' + $planIndex); label = [string]$announcedStep; count = $null } }
    Write-PraEvent -Kind plan -Data @{ steps = $planSteps }

    foreach ($forbidden in $config.Storage.ForbiddenBackupRoots) {
        if ($context.AllowMutation -and ($context.BackupFolder.TrimEnd('\') + '\').StartsWith($forbidden, [StringComparison]::OrdinalIgnoreCase)) { throw "Backup folder on a forbidden volume (Storage.ForbiddenBackupRoots): $forbidden" }
    }
    if ($Batch -and (Test-PraOrdinalIgnoreCaseEqual $Action 'Convert') -and (-not (Test-PraOrdinalIgnoreCaseEqual $effectivePhase 'Cloud'))) {
        # -Phase AD -Batch finishes a batch already converted (synchronisation and transfer package); a new conversion takes its targets from the configuration.
        if (-not (Test-PraOrdinalIgnoreCaseEqual $effectivePhase 'AD')) { throw '-Batch is not used by Convert -Phase Both: the targets come from the configuration (or -Identity). To finish the AD side of a batch already converted, use -Phase AD -Batch <id>; for its Exchange Online part, -Phase Cloud -Batch <id>.' }
        if ($Identity -or $SearchBase -or $CsvPath) { throw '-Phase AD with -Batch finishes a batch as a whole: -Identity, -SearchBase and -CsvPath cannot be combined with it.' }
    }
    if (-not $Batch -and ((Test-PraOrdinalIn $Action @('Recover','Finalize') -IgnoreCase) -or ((Test-PraOrdinalIgnoreCaseEqual $Action 'Convert') -and (Test-PraOrdinalIgnoreCaseEqual $effectivePhase 'Cloud')))) {
        throw ("-Batch is required for {0}{1}: give the batch ID printed at the end of the previous step." -f $Action, $(if ((Test-PraOrdinalIgnoreCaseEqual $effectivePhase 'Cloud')) { ' -Phase Cloud' } else { '' }))
    }
    if ((Test-PraOrdinalIgnoreCaseEqual $Action 'Check') -and -not $Batch -and -not $Identity) { throw 'Check needs -Identity or -Batch.' }
    if ($Batch -and $Batch.EndsWith('.zip', [StringComparison]::OrdinalIgnoreCase)) {
        # A transfer package from the other server: verified completely, then extracted to private folders; -Batch becomes the batch it carries and every
        # existing proof and hash check runs unchanged on the extracted folders.
        $context.CurrentOperation = 'Import-TransferPackage'
        $packagePath = Resolve-PraTransferPackagePath $Batch
        $expectedKind = switch ($Action) { 'Recover' { if ((Test-PraOrdinalIgnoreCaseEqual $effectivePhase 'Cloud')) { 'Recover' } else { 'Convert' } } 'Finalize' { 'Finalize' } default { 'Convert' } }
        $importRoot = $context.BackupFolder
        if (-not (Test-PraOrdinalIgnoreCaseEqual $effectiveMode 'Apply')) {
            $importRoot = Join-Path $context.LogFolder ('preview-' + [guid]::NewGuid().ToString('N').Substring(0, 12))
            Initialize-PraPrivateFolder -Path $importRoot
            $context.PreviewStaging = $importRoot; $context.BackupFolder = $importRoot
        }
        # A Preview extracts the package to a private folder that is deleted at the end: the batch ID is then nowhere to be found, so the next commands name the package itself.
        if (-not (Test-PraOrdinalIgnoreCaseEqual $effectiveMode 'Apply')) { $script:PreviewPackage = [string]$Batch }
        $imported = Import-PraTransferPackage -Path $packagePath -BackupFolder $importRoot -Environment $config.Environment -ExpectedKind $expectedKind
        Write-PraItem -Context $context -Status Ok -Icon Batch -Text ('Transfer package {0} verified (checksums, Environment, names): {1} folder(s) extracted, {2} already present and identical' -f $imported.Name, $imported.Created.Count, $imported.Existing.Count)
        if ((-not (Test-PraOrdinalIgnoreCaseEqual $effectiveMode 'Apply'))) { Write-PraItem -Context $context -Status Info -Text 'Preview: the package was verified and read from a private temporary folder, deleted at the end. Nothing was written to the backup folder.' }
        $Batch = [string]$imported.BatchId
        if ($PSBoundParameters.ContainsKey('Batch')) { $PSBoundParameters['Batch'] = $Batch }
    }

    $runCloud = $false; $cloudAction = $Action; $needCloudJournal = $false
    # ---------------------------------------------------------------------------------------------
    # FINALIZE - AD server, after the cloud phase of a Recover.
    # ---------------------------------------------------------------------------------------------
    if ((Test-PraOrdinalIgnoreCaseEqual $Action 'Finalize')) {
        Write-PraStep -Context $context -Title 'Loading the Finalize package' -Icon Batch
        $finalizeEntries = @(Get-PraFinalizeInput)
        Send-PraPlanCount $finalizeEntries.Count
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
        Test-PraSyncAvailable
        if ($context.AllowMutation) { Confirm-PraApply ("Restore the on-premises attributes of {0} object(s) listed above?" -f $plans.Count) }
        Write-PraStep -Context $context -Title 'Backup and Active Directory changes' -Icon Backup
        $receipt = Invoke-PraAdBatch $context $plans 'Finalize'
        if ($null -ne $receipt) {
            if ($replicate) { Write-PraStep -Context $context -Title 'Active Directory replication' -Icon Directory; Invoke-PraAdReplication $context $plans }
            Write-PraStep -Context $context -Title 'Entra Connect synchronisation' -Icon Sync; Invoke-PraSync $context
        }
        else {
            if ($replicate) { Skip-PraStep -Title 'Active Directory replication' -Reason (Get-PraSkipReason $plans.Count) -Icon Directory }
            Skip-PraStep -Title 'Entra Connect synchronisation' -Reason (Get-PraSkipReason $plans.Count)
        }
        if (-not $context.AllowMutation) { $context.NextSteps = @(Get-PraCommandLine -ActionName 'Finalize' -BatchId $(if ($script:PreviewPackage) { $script:PreviewPackage } else { $context.BatchId })) }
    }
    # ---------------------------------------------------------------------------------------------
    # CONVERT - finish the AD side of a batch whose AD changes are already made and verified (-Phase AD -Batch):
    # the Entra Connect synchronisation again, then the transfer package. AD is not written.
    # ---------------------------------------------------------------------------------------------
    elseif ((Test-PraOrdinalIgnoreCaseEqual $Action 'Convert') -and (Test-PraOrdinalIgnoreCaseEqual $effectivePhase 'AD') -and $Batch) {
        Write-PraStep -Context $context -Title 'Loading the batch of the AD phase' -Icon Batch
        $context.Source = Import-PraBackup $context (Get-PraBatchFile -Value $Batch -Operations @('Convert'))
        if (-not (Test-PraOrdinalEqual $context.Source.Data.Operation 'Convert')) { throw 'The batch to finish must be a Convert batch.' }
        if ($context.Source.Legacy) { throw 'This batch was written by an old version and has no AD proof (State file): it cannot be finished from here. Nothing was changed.' }
        $batchFolder = Split-Path $context.Source.Path -Parent
        $proofPath = Join-Path $batchFolder ('State-' + $context.Source.Data.BatchId + '.json')
        if (-not (Test-Path -LiteralPath $proofPath -PathType Leaf)) { throw 'This batch has no AD proof (State file): its AD changes were not verified, so it cannot be finished from here. Nothing was changed.' }
        $context.SourceBackupHash = $context.Source.Hash
        $context.Proof = Import-PraProof $context $proofPath $context.Source 'Convert'
        $context.BatchId = Get-PraShortId ([string]$context.Source.Data.BatchId)
        $context.PhaseFolders = @($batchFolder)
        foreach ($record in @($context.Source.Data.Records)) {
            if (@($context.Proof.Data.Records | Where-Object { Test-PraOrdinalIgnoreCaseEqual $_.ObjectGuid $record.ObjectGuid }).Count -ne 1) { throw "Object not verified by the AD phase of this batch: $($record.SamAccountName). The batch cannot be finished from here. Nothing was changed." }
            $row = New-PraRow $context $record
            $row.ADVerified = $true; $row.ADApplied = $true; $row.BackupPath = $context.Proof.Receipt.Path
            $row.FinalStatus = if ($context.AllowMutation) { 'Success' } else { 'Planned' }
            $row.Detail = 'AD changes made and verified by an earlier run of this batch; they are not changed again.'
            $context.Rows.Add($row)
            # The journey of the object in the global report says what this run really did (it did not write AD).
            $context.CurrentIdentity = [string]$record.ObjectGuid
            Write-PraItem -Context $context -Status Info -Text 'AD changes made and verified by an earlier run of this batch; not changed again'
            $context.CurrentIdentity = ''
        }
        Send-PraPlanCount $context.Rows.Count
        Write-PraItem -Context $context -Status Ok -Text ("Batch {0}: {1} object(s), AD changes already made and verified (they are not changed again), backup and proof checked" -f $context.BatchId, $context.Rows.Count)
        Test-PraSyncAvailable
        if ($context.AllowMutation) {
            Confirm-PraApply ("Finish batch {0}? {1}A transfer package is written. AD is not changed again." -f $context.BatchId, $(if ($config.EntraConnect.Sync) { 'Entra Connect synchronises first. ' } else { '' }))
            $context.PhaseWriteFolder = $batchFolder
            $context.JournalPath = Join-Path $batchFolder ('Journal-' + $context.Source.Data.BatchId + '.jsonl')
            Write-PraStep -Context $context -Title 'Entra Connect synchronisation' -Icon Sync
            Invoke-PraSync $context -Resume
            Write-PraStep -Context $context -Title 'Creating the transfer package' -Icon Batch
            Publish-PraTransferPackage -Kind 'Convert' -BatchId ([string]$context.Source.Data.BatchId) -Folders @($batchFolder) -NextAction 'Convert' -NextPhase 'Cloud' `
                -FallbackSteps @("Copy the folder $batchFolder to the Backups folder of the cloud server, then run there:",
                    (Get-PraCommandLine -ActionName 'Convert' -PhaseName 'Cloud' -BatchId $context.BatchId -OtherServer))
        }
        else { $context.NextSteps = @(Get-PraCommandLine -ActionName 'Convert' -PhaseName 'AD' -BatchId $context.BatchId) }
    }
    # ---------------------------------------------------------------------------------------------
    # CONVERT - AD side (phase AD or Both).
    # ---------------------------------------------------------------------------------------------
    elseif ((Test-PraOrdinalIgnoreCaseEqual $Action 'Convert') -and (Test-PraOrdinalIn $effectivePhase @('Both','AD') -IgnoreCase)) {
        Write-PraStep -Context $context -Title 'Active Directory connection' -Icon Directory
        if ((Test-PraOrdinalIgnoreCaseEqual $effectivePhase 'Both')) { Test-PraCloudModuleAvailable }
        Initialize-PraDirectory $context -ValidateScope
        Write-PraStep -Context $context -Title 'Targets and planned changes' -Icon Plan
        $targets = @(Get-PraTarget $context $Identity $Scope $MaxObjects)
        if (-not $targets.Count) { Write-PraItem -Context $context -Status Warn -Text 'No on-premises mailbox found in the scope: nothing to convert.' }
        $plans = @(foreach ($target in $targets) { New-PraPlan $context ([string]$target.ObjectGUID) 'Convert' })
        Send-PraPlanCount $plans.Count
        if ($plans.Count) {
            $null = Show-PraPlanSummary $plans
            Invoke-PraAdPreview $context $plans
        }
        if ($plans.Count) { Test-PraSyncAvailable }
        if ($context.AllowMutation -and $plans.Count) {
            $question = "Convert the {0} object(s) listed above? A backup is written first; then AD is changed{1}." -f $plans.Count, $(if ($config.EntraConnect.Sync) { ', Entra Connect synchronises' } else { '' })
            if ((Test-PraOrdinalIgnoreCaseEqual $effectivePhase 'Both')) { $question = $question.TrimEnd('.') + ' and Exchange Online is completed.' }
            Confirm-PraApply $question
        }
        if ((Test-PraOrdinalIgnoreCaseEqual $effectivePhase 'Both')) {
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
            $context.PhaseWriteFolder = Split-Path $receipt.Path -Parent
            if ($replicate) { Write-PraStep -Context $context -Title 'Active Directory replication' -Icon Directory; Invoke-PraAdReplication $context $plans }
            Write-PraStep -Context $context -Title 'Entra Connect synchronisation' -Icon Sync
            $context.Source = $receipt
            $context.Proof = Import-PraProof $context $receipt.StatePath $receipt 'Convert'
            $context.BatchId = Get-PraShortId $receipt.Data.BatchId
            Invoke-PraSync $context
            # The Exchange Online part does not start when the synchronisation could not run: its mailboxes would not appear. The Next steps say how to go on.
            $runCloud = (Test-PraOrdinalIgnoreCaseEqual $effectivePhase 'Both') -and ($null -eq (Get-PraValue $context 'SyncFailure' $null))
            if ((Test-PraOrdinalIgnoreCaseEqual $effectivePhase 'AD')) {
                Write-PraStep -Context $context -Title 'Creating the transfer package' -Icon Batch
                Publish-PraTransferPackage -Kind 'Convert' -BatchId ([string]$receipt.Data.BatchId) -Folders @(Split-Path $receipt.Path -Parent) -NextAction 'Convert' -NextPhase 'Cloud' `
                    -FallbackSteps @("Copy the folder $(Split-Path $receipt.Path -Parent) to the Backups folder of the cloud server, then run there:",
                        (Get-PraCommandLine -ActionName 'Convert' -PhaseName 'Cloud' -BatchId $context.BatchId -OtherServer))
            }
        }
        else {
            if ($replicate) { Skip-PraStep -Title 'Active Directory replication' -Reason (Get-PraSkipReason $plans.Count) -Icon Directory }
            Skip-PraStep -Title 'Entra Connect synchronisation' -Reason (Get-PraSkipReason $plans.Count)
            if ($plans.Count) { $context.NextSteps = @(Get-PraCommandLine -ActionName 'Convert' -PhaseName $(if ($Phase) { $Phase } else { '' }) -KeepFilters) }
        }
    }
    # ---------------------------------------------------------------------------------------------
    # RECOVER - AD side (phase AD or Both).
    # ---------------------------------------------------------------------------------------------
    elseif ((Test-PraOrdinalIgnoreCaseEqual $Action 'Recover') -and (Test-PraOrdinalIn $effectivePhase @('Both','AD') -IgnoreCase)) {
        Write-PraStep -Context $context -Title 'Loading the Convert batch' -Icon Batch
        if ((Test-PraOrdinalIgnoreCaseEqual $effectivePhase 'Both')) { Test-PraCloudModuleAvailable }
        $context.Source = Import-PraBackup $context (Get-PraBatchFile -Value $Batch -Operations @('Convert'))
        if (-not (Test-PraOrdinalEqual $context.Source.Data.Operation 'Convert')) { throw 'Recover needs the original Convert batch.' }
        $context.SourceBackupHash = $context.Source.Hash
        $records = @(Select-PraSourceRecord $context.Source)
        $context.PhaseFolders = @(Split-Path $context.Source.Path -Parent)
        Send-PraPlanCount $records.Count
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
        if ($plans.Count) { Test-PraSyncAvailable }
        if ($context.AllowMutation -and $plans.Count) {
            Confirm-PraApply ("Roll back the {0} object(s) listed above? Users get their on-premises attributes back; shared mailboxes are first deprovisioned in Exchange Online." -f $plans.Count)
        }
        if ((Test-PraOrdinalIgnoreCaseEqual $effectivePhase 'Both')) {
            if ($context.AllowMutation -and $plans.Count) {
                # Same guarantee as Convert: the Exchange Online sign-in, tenant and targets are checked (read only)
                # BEFORE the first AD write, so a cloud problem does not leave AD restored and the cloud part undone.
                Write-PraStep -Context $context -Title 'Exchange Online pre-check' -Icon Cloud
                $context.CurrentOperation = 'CloudPreflightBeforeAD'
                Import-Module (Join-Path $PSScriptRoot 'module\PRA.Cloud.psm1') -Force -ErrorAction Stop
                Initialize-PraCloudPreflight -Context $context -Rows @($plans | ForEach-Object { $_.Row })
                if ($context.Issues.Count) { throw 'Exchange Online pre-check failed: no AD change made.' }
            }
            else { Skip-PraStep -Title 'Exchange Online pre-check' -Reason (Get-PraSkipReason $plans.Count) }
        }
        Write-PraStep -Context $context -Title 'Backup and Active Directory changes' -Icon Backup
        $receipt = Invoke-PraAdBatch $context $plans 'Recover'
        if ($null -ne $receipt) {
            $context.PhaseWriteFolder = Split-Path $receipt.Path -Parent
            if ($replicate) { Write-PraStep -Context $context -Title 'Active Directory replication' -Icon Directory; Invoke-PraAdReplication $context $plans }
            Write-PraStep -Context $context -Title 'Entra Connect synchronisation' -Icon Sync
            $context.Proof = Import-PraProof $context $receipt.StatePath $context.Source 'Recover'
            $context.BatchId = Get-PraShortId $receipt.Data.BatchId
            Invoke-PraSync $context
            $runCloud = (Test-PraOrdinalIgnoreCaseEqual $effectivePhase 'Both') -and ($null -eq (Get-PraValue $context 'SyncFailure' $null))
            if ((Test-PraOrdinalIgnoreCaseEqual $effectivePhase 'AD')) {
                Write-PraStep -Context $context -Title 'Creating the transfer package' -Icon Batch
                Publish-PraTransferPackage -Kind 'Recover' -BatchId ([string]$receipt.Data.BatchId) -Folders @((Split-Path $receipt.Path -Parent), (Split-Path $context.Source.Path -Parent)) -NextAction 'Recover' -NextPhase 'Cloud' `
                    -FallbackSteps @("Copy the folders $(Split-Path $receipt.Path -Parent) and $(Split-Path $context.Source.Path -Parent) to the Backups folder of the cloud server, then run there:",
                        (Get-PraCommandLine -ActionName 'Recover' -PhaseName 'Cloud' -BatchId $context.BatchId -OtherServer))
            }
        }
        elseif ($plans.Count) {
            if ($replicate) { Skip-PraStep -Title 'Active Directory replication' -Reason (Get-PraSkipReason $plans.Count) -Icon Directory }
            $context.NextSteps = @(Get-PraCommandLine -ActionName 'Recover' -PhaseName $(if ($Phase) { $Phase } else { '' }) -BatchId $(if ($script:PreviewPackage) { $script:PreviewPackage } else { $Batch }) -KeepFilters)
        }
    }
    # ---------------------------------------------------------------------------------------------
    # CLOUD SIDE - Convert/Recover -Phase Cloud and Check.
    # ---------------------------------------------------------------------------------------------
    else {
        if ((Test-PraOrdinalIgnoreCaseEqual $Action 'Check')) { $cloudAction = if ((Test-PraOrdinalIgnoreCaseEqual $Expect 'Deprovisioned')) { 'Recover' } else { 'Convert' } }
        $stepTitle = switch ($Action) { 'Check' { 'Objects to check' } 'Recover' { 'Loading the Recover batch' } default { 'Loading the batch of the AD phase' } }
        Write-PraStep -Context $context -Title $stepTitle -Icon Batch
        Test-PraCloudModuleAvailable
        if ((Test-PraOrdinalIgnoreCaseEqual $Action 'Check') -and $Identity -and -not $Batch) {
            if ($Identity -match '@') { $record = [pscustomobject]@{ ObjectGuid = ''; SamAccountName = $Identity; UserPrincipalName = $Identity; IsShared = ((Test-PraOrdinalIgnoreCaseEqual $Scope 'SharedOnly')); ExpectedX500Note = 'identity given as a UPN, no Active Directory read: give the sAMAccountName or -Batch' } }
            else {
                Initialize-PraDirectory $context
                $user = Get-PraUser $context $Identity
                $record = [pscustomobject]@{ ObjectGuid = ([guid]$user.ObjectGUID).ToString(); SamAccountName = $user.SamAccountName; UserPrincipalName = $user.UserPrincipalName; IsShared = ((Test-PraOrdinalIn $user.msExchRecipientTypeDetails @(4, 34359738368) -IgnoreCase))
                    ExpectedX500 = [string[]]@(Get-PraExpectedX500 -LegacyExchangeDN ([string](Get-PraValue $user 'legacyExchangeDN' '')) -ProxyAddresses @($user.proxyAddresses)) }
            }
            $context.Rows.Add((New-PraRow $context $record))
            Write-PraItem -Context $context -Status Ok -Text ("{0} ({1})" -f $record.UserPrincipalName, $(if ($record.IsShared) { 'shared mailbox' } else { 'user mailbox' }))
        }
        else {
            # Which batch? Convert cloud phase and Check: the Convert batch. Recover cloud phase:
            # the Recover batch (proof of the AD part), its Convert source is found by its hash.
            $proofPath = ''
            if ((Test-PraOrdinalIgnoreCaseEqual $Action 'Recover')) {
                $batchFile = Get-PraBatchFile -Value $Batch -Operations @('Recover','Convert')
                $batchData = [IO.File]::ReadAllText($batchFile) | ConvertFrom-PraJson
                if (Test-PraOrdinalEqual $batchData.Operation 'Recover') {
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
            if (-not (Test-PraOrdinalEqual $context.Source.Data.Operation 'Convert')) { throw 'The source of a cloud phase must be the original Convert batch.' }
            $context.SourceBackupHash = $context.Source.Hash
            $records = @(Select-PraSourceRecord $context.Source)
            if ($context.AllowMutation) {
                if (-not $proofPath) { throw 'This batch has no AD proof (State file): the cloud phase cannot write.' }
                $context.Proof = Import-PraProof $context $proofPath $context.Source $Action
                # The journal folder is created after the operator's confirmation (below), never before it.
                $needCloudJournal = $true
            }
            foreach ($record in $records) {
                $row = New-PraRow $context $record
                $originalLicensing = Get-PraValue $record 'Licensing' $null
                $row.PreserveLicense = ((Test-PraOrdinalIgnoreCaseEqual $cloudAction 'Recover')) -and [bool](Get-PraValue $originalLicensing 'Enabled' $false) -and [bool](Get-PraValue $originalLicensing 'WasMember' $false)
                $row.PreserveCloudMailbox = ((Test-PraOrdinalIgnoreCaseEqual $cloudAction 'Recover')) -and $row.IsShared -and $context.KeepCloudShared
                $holders = Get-PraValue $record 'SharedPermissions' $null
                $row.SharedFullAccess = Get-PraValue $holders 'FullAccess' @(); $row.SharedSendAs = Get-PraValue $holders 'SendAs' @(); $row.SharedSendOnBehalf = Get-PraValue $holders 'SendOnBehalf' @()
                if ($null -ne $context.Proof) {
                    $verified = @($context.Proof.Data.Records | Where-Object { Test-PraOrdinalIgnoreCaseEqual $_.ObjectGuid $record.ObjectGuid })
                    if ($verified.Count -ne 1) { throw "Object not verified by the AD phase of this batch: $($record.SamAccountName)" }
                    $row.ADVerified = $true; $row.DeproPending = (Test-PraOrdinalEqual $verified[0].Operation 'Deprovision'); $row.BackupPath = $context.Proof.Receipt.Path
                    $provenPlan = @($context.Proof.Receipt.Data.Records | Where-Object { Test-PraOrdinalIgnoreCaseEqual $_.ObjectGuid $record.ObjectGuid })[0]
                    $row.PreserveCloudMailbox = [bool]$provenPlan.PreserveCloudMailbox; $row.PreserveLicense = [bool]$provenPlan.PreserveLicense
                }
                $context.Rows.Add($row)
            }
            $context.PhaseFolders = @(@(Split-Path $context.Source.Path -Parent) + $(if ($proofPath) { @(Split-Path $proofPath -Parent) } else { @() }))
            Send-PraPlanCount $context.Rows.Count
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
        if ((Test-PraOrdinalIgnoreCaseEqual $Action 'Check')) { $cloudTitle = 'Exchange Online checks' }
        Write-PraStep -Context $context -Title $cloudTitle -Icon Cloud
        # A preview of the cloud phase looks once: it never waits for the cloud.
        if (-not $context.AllowMutation -and (-not (Test-PraOrdinalIgnoreCaseEqual $Action 'Check'))) { $context.Once = $true }
        if ($context.AllowMutation -and (Test-PraOrdinalIgnoreCaseEqual $effectivePhase 'Cloud') -and (Test-PraOrdinalIgnoreCaseEqual $Action 'Convert')) {
            $grants = 0; foreach ($row in $context.Rows) { $grants += @($row.SharedFullAccess).Count + @($row.SharedSendAs).Count + @($row.SharedSendOnBehalf).Count }
            Confirm-PraApply ("Complete {0} object(s) in Exchange Online (wait for the mailboxes, grant up to {1} shared mailbox permission(s))?" -f $context.Rows.Count, $grants)
        }
        elseif ($context.AllowMutation -and (Test-PraOrdinalIgnoreCaseEqual $effectivePhase 'Cloud') -and (Test-PraOrdinalIgnoreCaseEqual $Action 'Recover')) {
            Confirm-PraApply ("Check the deprovisioning of {0} object(s) in Exchange Online, then package any final shared mailbox and tag restoration for the AD server?" -f $context.Rows.Count)
        }
        if ($needCloudJournal) { Initialize-PraCloudJournal }
        Initialize-PraCloudAuthority
        Import-Module (Join-Path $PSScriptRoot 'module\PRA.Cloud.psm1') -Force -ErrorAction Stop
        if ((Test-PraOrdinalIgnoreCaseEqual $Action 'Check') -and (Test-PraOrdinalIgnoreCaseEqual $Expect 'Retained')) { Invoke-PraRetentionCheck -Context $context -Rows $context.Rows.ToArray() }
        else { Invoke-PraCloudPhase -Context $context -Rows $context.Rows.ToArray() -Act $cloudAction }
        if ($context.Issues.Count -or @($context.Rows | Where-Object { Test-PraOrdinalEqual $_.CloudStatus 'Error' }).Count) { throw 'Exchange Online check failed: no restore or clean-up is done.' }

        # Recover: shared mailboxes (deprovisioned in the cloud) and retention tags are restored only now.
        if ((Test-PraOrdinalIgnoreCaseEqual $Action 'Recover')) {
            Write-PraStep -Context $context -Title 'Final restore of shared mailboxes and tags' -Icon Write
            if ($context.AllowMutation) {
                $tagged = @($context.Rows | Where-Object { [bool](Get-PraValue (Get-PraValue $_.BackupRec 'Retention' $null) 'Enabled' $false) })
                foreach ($row in $tagged | Where-Object PreserveCloudMailbox) {
                    $row.FinalStatus = 'Pending'; $row.Detail += ' | Cloud mailbox kept on purpose: the retention tag stays.'
                }
                $followup = @($context.Rows | Where-Object { -not $_.PreserveCloudMailbox -and ($_.DeproPending -or $tagged.Contains($_)) })
                foreach ($row in $followup) { if (-not (Test-PraOrdinalEqual $row.CloudStatus 'Success') -or $row.DeprovisionConfirmed -ne $true -or $row.ADVerified -ne $true) { throw 'Cloud deprovisioning or AD proof not confirmed: restore and tag clean-up blocked.' } }
                if (-not $followup.Count) { Write-PraItem -Context $context -Status Skip -Text 'Nothing left to restore.' }
                elseif ((Test-PraOrdinalIgnoreCaseEqual $effectivePhase 'Cloud') -or $defer -or -not @(Get-Module -ListAvailable ActiveDirectory).Count) {
                    if ((Test-PraOrdinalIgnoreCaseEqual $effectivePhase 'Cloud')) { Write-PraItem -Context $context -Status Info -Text 'Cloud-only phase: final AD restoration is packaged for Finalize on the AD server.' }
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
                    if ($replicate) { Invoke-PraAdReplication $context $plans }
                    Invoke-PraSync $context
                }
            }
            else { Write-PraItem -Context $context -Status Skip -Text 'Preview: nothing restored.' }
        }
        if (-not $context.AllowMutation -and (Test-PraOrdinalIn $Action @('Convert','Recover') -IgnoreCase) -and -not $context.NextSteps.Count) {
            $context.NextSteps = @(Get-PraCommandLine -ActionName $Action -PhaseName 'Cloud' -BatchId $(if ($script:PreviewPackage) { $script:PreviewPackage } else { $Batch }) -KeepFilters)
        }
    }
    elseif ($runCloud) { Write-PraItem -Context $context -Status Warn -Text 'No object to check in Exchange Online.' }

    # Steps announced but not run (preview, nothing to do) are shown as skipped, in their order.
    $syncFailure = Get-PraValue $context 'SyncFailure' $null
    $announced = @($steps)
    for ($i = [int]$context.StepIndex; $i -lt $announced.Count; $i++) {
        $skipReason = if ($null -ne $syncFailure) { 'Not run: the Entra Connect synchronisation could not start (see the next steps).' } else { Get-PraSkipReason ($context.Rows.Count -gt 0) }
        Skip-PraStep -Title $announced[$i] -Reason $skipReason
    }

    if ($context.AllowMutation -and (Test-PraOrdinalIgnoreCaseEqual $Action 'Convert') -and (Test-PraOrdinalIn $effectivePhase @('Both','Cloud') -IgnoreCase) -and $context.BatchId -and -not $context.Issues.Count -and $null -eq $syncFailure) {
        $context.NextSteps = @($(if ((Test-PraOrdinalIgnoreCaseEqual $effectivePhase 'Cloud')) { 'To roll back this batch later, on the AD server: ' + (Get-PraCommandLine -ActionName 'Recover' -ModeName 'Preview' -BatchId $context.BatchId -OtherServer) } else { 'To roll back this batch later: ' + (Get-PraCommandLine -ActionName 'Recover' -ModeName 'Preview' -BatchId $context.BatchId) }))
    }

    # The synchronisation could not run after the AD changes were verified: say plainly what is done and what to do (the transfer package, when there is one, follows).
    if ($null -ne $syncFailure) {
        $syncLines = @(
            ('AD is changed and verified. The Entra Connect sync could not start: {0}.' -f $syncFailure.Reason),
            ('Run a delta sync on {0} (Start-ADSyncSyncCycle -PolicyType Delta) or wait for the next automatic cycle (about 30 minutes).' -f $syncFailure.Server))
        if ((Test-PraOrdinalIn $Action @('Convert','Recover') -IgnoreCase) -and (Test-PraOrdinalIgnoreCaseEqual $effectivePhase 'Both') -and $context.BatchId) {
            $syncLines += ('Then continue this batch from here (it waits for the Exchange Online part to be ready): ' + (Get-PraCommandLine -ActionName $Action -PhaseName 'Cloud' -BatchId $context.BatchId))
        }
        $context.NextSteps = @($syncLines) + @(Get-PraList $context 'NextSteps')
    }

    # The synchronisation is left to the operator (EntraConnect.Sync = $false): it comes before the copy of the package, in the same list.
    $syncNotRun = Get-PraValue $context 'SyncNotRun' $null
    if ($null -ne $syncNotRun -and $null -eq $syncFailure -and ([string](Get-PraValue $context 'HandOff' '') -or (Test-PraOrdinalIgnoreCaseEqual $Action 'Finalize'))) {
        $context.NextSteps = @(('Run a delta sync on {0} (Start-ADSyncSyncCycle -PolicyType Delta) or wait for the next automatic cycle (about 30 minutes).' -f $syncNotRun.Server)) + @(Get-PraList $context 'NextSteps')
    }

    # X500 addresses missing in Exchange Online (warning of the cloud phase): synchronise, then check again.
    $x500Missing = @(Get-PraList $context 'X500Missing')
    if ($x500Missing.Count) {
        $checkCommand = Get-PraCommandLine -ActionName 'Check' -ModeName 'Preview' -BatchId $(if ($script:PreviewPackage) { $script:PreviewPackage } else { $context.BatchId }) -KeepFilters
        $context.NextSteps = @(@(Get-PraList $context 'NextSteps') + ('X500 missing in Exchange Online for {0} object(s) (replies to old messages can bounce): run an Entra Connect synchronisation, then check again: {1}' -f $x500Missing.Count, $checkCommand))
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
    if ([string](Get-PraValue $context 'PreviewStaging' '')) {
        try { [IO.Directory]::Delete($context.PreviewStaging, $true) } catch { try { Write-PraLog -Context $context -Message ('The temporary Preview folder could not be deleted: {0}' -f $_.Exception.Message) -Level Detail } catch { $null = $_ } }
    }
    if ($context.AllowMutation -and [string](Get-PraValue $context 'PhaseWriteFolder' '') -and -not [bool](Get-PraValue $context 'PhaseDataSaved' $false)) {
        try { $null = Save-PraPhaseData -Context $context -Folder $context.PhaseWriteFolder; $context.PhaseDataSaved = $true }
        catch { Write-PraLog -Context $context -Message ('The data for the global report could not be saved ({0}).' -f $_.Exception.Message) -Level Detail }
    }
    if (Get-Command Close-PraCloudSession -ErrorAction SilentlyContinue) {
        try { Close-PraCloudSession -Context $context } catch { $context.Issues.Add([pscustomobject]@{ Message = "Cloud sign-out: $($_.Exception.Message)"; Source = 'Cloud' }) }
    }
    $result = Complete-PraRun -Context $context
    if ($PassThru) { $result }
    exit $result.ExitCode
}

# SIG # Begin signature block
# MIImKwYJKoZIhvcNAQcCoIImHDCCJhgCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCCl7PKR8vqWmCTH
# Qc+e/OTi5hIqOUuoON9lpDx82WoFXaCCDW8wggZyMIIEWqADAgECAghkM1HTxzif
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
# wZislcdCZuS6MYIYEjCCGA4CAQEwgYwweDELMAkGA1UEBhMCVVMxDjAMBgNVBAgM
# BVRleGFzMRAwDgYDVQQHDAdIb3VzdG9uMREwDwYDVQQKDAhTU0wgQ29ycDE0MDIG
# A1UEAwwrU1NMLmNvbSBDb2RlIFNpZ25pbmcgSW50ZXJtZWRpYXRlIENBIFJTQSBS
# MQIQBof4ljXihJpmCqqt2mhAWzANBglghkgBZQMEAgEFAKCBhDAYBgorBgEEAYI3
# AgEMMQowCKACgAChAoAAMBkGCSqGSIb3DQEJAzEMBgorBgEEAYI3AgEEMBwGCisG
# AQQBgjcCAQsxDjAMBgorBgEEAYI3AgEVMC8GCSqGSIb3DQEJBDEiBCDq9X7m/dph
# PALur9LPRbqQSNv8HOs5QR46QTJ8uV6tOTANBgkqhkiG9w0BAQEFAASCAgCiBFXc
# k/naW9qByhVLEPYI/VPziJ58Cj/SJ9cTj1NIJS9E76bEKnPnULLEg+mFCQZwlqcc
# xDDMrlTsVIHLxL7lJJOvoI8nCjIop+CX008If7n4ZKFk6Mpf9q9Y4pG0shOwdGrK
# vgGXoZU5rC2AzUrgZ5evWgy9gRg0Le1RQNoPGxDDaoPWE6VXTCS8MtO3M2GWxB57
# aBshH6wvuHVofS8UgKp18KuZGK6XMEv8+/SCoe80pb13tUjajZVxnNw9lapr3iXx
# VpQnblkouLZDbs88rkxMjK9Tup1NgRcBpKR12d1k2BqKT9RwZ2XTZp33Oo7wj1Ru
# R3dVu5ADjQdBQVs5f5T9vkMy8vqBm0U7e9N86lA5FeL48tP4J6kMv4AVWLNFMR7h
# Kh1TayfepSAQUAKR0d7VgoCWStudfSyUHrZD9I/CH3qNVtA/TKpZhtKE4VE3qdoj
# h/0cvNwpKwUYArIe7jD+YInlwGu08p0v1/WNwB9NCNdru/9Vjp04uTuH+bAJkgbr
# 8JcNcG2PREThMAxxY+ilMJ96qEiMi42J1Y3JKrCdo6ptp13GlR9Vp5j/5ccZgOC2
# mLQXB3WD0nHrpPsC31NgWiE8pfVTn8Xd/ngNe7JKH0UjW9pngkcXRO59vZ17wxfF
# yyMwIm74/nvK+mWeDXkm1FWXjrajGHSgXft2jaGCFM8wghTLBgorBgEEAYI3AwMB
# MYIUuzCCFLcGCSqGSIb3DQEHAqCCFKgwghSkAgEDMQ0wCwYJYIZIAWUDBAIBMIGJ
# BgsqhkiG9w0BCRABBKB6BHgwdgIBAQYMKwYBBAGCqTABAwYBMDEwDQYJYIZIAWUD
# BAIBBQAEIBH137qTftgYmC7Z3Q+6jRAXrKpG9gy4hRJqaMltI7eTAghfBbZVDpYz
# hBgPMjAyNjExMTAwODMyNTdaMAMCAQECEBkH5v/p8nCU5BoFfINI/WmgghGnMIIE
# 8zCCAtugAwIBAgIQVEP4N71a7hgBhHK4XNqO4zANBgkqhkiG9w0BAQsFADByMQsw
# CQYDVQQGEwJVUzEOMAwGA1UECAwFVGV4YXMxEDAOBgNVBAcMB0hvdXN0b24xETAP
# BgNVBAoMCFNTTCBDb3JwMS4wLAYDVQQDDCVTU0wuY29tIFRpbWVzdGFtcGluZyBJ
# c3N1aW5nIFJTQSBDQSAyMB4XDTI2MDYxMjE3MjI0NloXDTM2MDYwOTE3MjI0NVow
# bjELMAkGA1UEBhMCVVMxDjAMBgNVBAgMBVRleGFzMRAwDgYDVQQHDAdIb3VzdG9u
# MREwDwYDVQQKDAhTU0wgQ29ycDEqMCgGA1UEAwwhU1NMLmNvbSBUaW1lc3RhbXBp
# bmcgVW5pdCAyMDI2IEUxMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE6CWLuGYT
# LkiSOPMLNskOBthXsIhRSA46feOQwvSLcDaNh6vxUzBKEx1KdFBRFs7OHrnH/K0V
# A6MbDQIFpUg0PaOCAVIwggFOMB8GA1UdIwQYMBaAFHCaZcFDgKP86bFkiW7xMJwJ
# Icl8ME0GCCsGAQUFBwEBBEEwPzA9BggrBgEFBQcwAoYxaHR0cDovL2NlcnQuc3Ns
# LmNvbS9TU0wuY29tLXRpbWVTdGFtcGluZy1JLVIyLmNlcjBRBgNVHSAESjBIMDwG
# DCsGAQQBgqkwAQMGATAsMCoGCCsGAQUFBwIBFh5odHRwczovL3d3dy5zc2wuY29t
# L3JlcG9zaXRvcnkwCAYGZ4EMAQQCMBYGA1UdJQEB/wQMMAoGCCsGAQUFBwMIMEIG
# A1UdHwQ7MDkwN6A1oDOGMWh0dHA6Ly9jcmxzLnNzbC5jb20vU1NMLmNvbS10aW1l
# U3RhbXBpbmctSS1SMi5jcmwwHQYDVR0OBBYEFCesA1a6KGq6FzuDPUB/eagk7MM8
# MA4GA1UdDwEB/wQEAwIHgDANBgkqhkiG9w0BAQsFAAOCAgEAT3ZuzvwDnsIZTXBn
# +hjmuBXgzB12fbYxT9uYe6ZvhvpbZWKcyDQgacETkPw8k6yeqnYCYyFZ063lMPEq
# AhAD2nMG614Zh7PtHW9DWqfsgivxbPYBeN+t7UxgkYT3expbWMdPEqBtWVyHOvLc
# KvMxgJWfJjANwVkwVDfky/j7cf28+iimN8PKc7S/u8/LenRRnV2W2YfncRnkz9Cf
# s5nRDzaZguiHrrp2GxwgnNQSH4GBjHOl3PzLsnVbGoZKi4ZEjgXups4mGGOK7+GB
# 2HAlQn+OS944cHqlkH0gElt2WezoCNRpELph9qaxuBnjSEqXWWfgE6yGBwO0uxKN
# qpWVTHmAwr6SvBPofxubXIuEn9ivR4CLOuAxUSrJ41ZBg/qqG0oJjF6GkRKbxq7c
# yWSkEZYJhmKCg2Hg5fXHagOxiwbmn5JPZ1vhWCrbk3v/dTx2gvTK5+erC5H9/rTc
# ljUI776yd2rfhjfkpvyAsbtXs4D7nrnw8i9wor5+fdtRSJBVxqzLmykFftoL0Up2
# Q++tyKCUdribdcnrB4HKS3s+t3AjdcbA06DCL8GifQi9fL0yRBRNlA4o6BP+Sr75
# 5MaCNjURYZDvDyxJHBBT7cqjZIwsiR8s+6860noFbBBtdge2Iw7CPC/1Q31I27hV
# olS7B0yao3v8X2MtWy3msZlXTcEwggXdMIIDxaADAgECAgh7LJvTFoAymTANBgkq
# hkiG9w0BAQsFADB8MQswCQYDVQQGEwJVUzEOMAwGA1UECAwFVGV4YXMxEDAOBgNV
# BAcMB0hvdXN0b24xGDAWBgNVBAoMD1NTTCBDb3Jwb3JhdGlvbjExMC8GA1UEAwwo
# U1NMLmNvbSBSb290IENlcnRpZmljYXRpb24gQXV0aG9yaXR5IFJTQTAeFw0xNjAy
# MTIxNzM5MzlaFw00MTAyMTIxNzM5MzlaMHwxCzAJBgNVBAYTAlVTMQ4wDAYDVQQI
# DAVUZXhhczEQMA4GA1UEBwwHSG91c3RvbjEYMBYGA1UECgwPU1NMIENvcnBvcmF0
# aW9uMTEwLwYDVQQDDChTU0wuY29tIFJvb3QgQ2VydGlmaWNhdGlvbiBBdXRob3Jp
# dHkgUlNBMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEA+Q/doyt9y9Aq
# /uxnhabnLhu6d+Hj9a+k7PpKXZHEV0drGHdrdvL9k+Q9D8IWngtmw1aUnheDhc5W
# 7/IW/QBi9SIJVOhlF05BueBPRpeqG8i4bmJeabFf2yoCfvxsyvNB2O3Q6Pw/YUjt
# sAMUHRAOSxngu07shmX/NvNeZwILnYZVYf16OO3+4hkAt2+hUGJ1dDyg+sglkrRu
# eiLH+B6h47LdkTGrKx0E/6VKBDfphaQzK/3i1lU0fBmkSmjHsqjTt8qhk4jrwZe8
# jPkd2SKEJHTHBD1qqSmTzOu4W+H+XyWqNFjIwSNUnRuYEcM4nH49hmylD0CGfAL0
# XAJPKMuucZ8POsgz/hElNer8usVgPdl8GNWyqdN1eANyIso6wx/vLOUuqfqeLLZR
# Rv2vA9bqYGjqhRY2a4XpHsCz3cQk3IAqgUFtlD7I4MmBQQCeXr9/xQiYohgsQkCz
# +W84J0tOgPQ9gUfgiHzqHM61dVxRLhwrfxpyKOcAtdF0xtfkn60Hk7ZTNTX8N+TD
# 9l0WviFz3pIK+KBjaryWkmo++LxlVZve9Q2JJgT8JRqmJWnLwm3KfOJZX5es6+8u
# yLzXG1k8K8zyGciTaydjGc/86Sb4ynGbf5P+NGeETpnr/LN4CTNwumamdu0bc+sa
# pQ3EIhMglFYKTixsTrH9z5wJuqIz7YcCAwEAAaNjMGEwHQYDVR0OBBYEFN0ECQei
# 9Xp9UlMSkpXuOIAlDaZZMA8GA1UdEwEB/wQFMAMBAf8wHwYDVR0jBBgwFoAU3QQJ
# B6L1en1SUxKSle44gCUNplkwDgYDVR0PAQH/BAQDAgGGMA0GCSqGSIb3DQEBCwUA
# A4ICAQAgGBGUKfsmnRweHnBh8ZVyk3EkrWiTWI4yrxuzcAP8JSt0hZA9eGr0uYul
# lzu1GJG7Hqf5QFuR+VWZrx4R0Fwdp2bjsZQHDDI5puobsHnYHZxwROOK3cT5lR+K
# OEM/AYWlR6c9RrK85SJo93uc2Cw+CiHILTOsv8WBmTF0wXVxxb6x8CNF9J1r/Blj
# naO8BMYYCyW7U4kPs4BQ3kXuRH+rlHhkmNP2KN2H2HBldPsOuRPrpw9hqTKWzN67
# 7WNMGLupQPegVG4giHF1GOp6tDRy4CMnd1y2kOqGJUCr7zMPy5+CvqIg+/a1LRrm
# woWxdA/7yGUCpFIBR91JIsG/2OtrrH7e7GMzFbcjCI/GD41BWt2OxbmP5UU/eNu6
# 0htAsf5xTT/ggaK6XrTsFeCT3QgffuFVmQsh3pOeCvvmo0m9NjD+53eyoHWXtS2B
# iBdlIPfakACfyVLMMso1fPU9D9gr1/UmbMkGNJYW6nBZGjJ5eQu2iH8PUkg9v2zY
# okQu0U63cljTiROV/kSr+NeLG26cvCygW9VqAK9fN+HV+hALmJyG5yaPzvDsbopX
# C4DjTrLAoGNhkLpVaDd0araS25+hhiK2ZScO7LafQmDkZ8K12kELxNOLYRu8+h+R
# K9dEB166KazZxenvU0ha64DxKFghzbAGVfsnP1OQcKkEHlcnuTCCBsswggSzoAMC
# AQICEFKdu8K4iYf1g4DgsOuiBjYwDQYJKoZIhvcNAQELBQAwfDELMAkGA1UEBhMC
# VVMxDjAMBgNVBAgMBVRleGFzMRAwDgYDVQQHDAdIb3VzdG9uMRgwFgYDVQQKDA9T
# U0wgQ29ycG9yYXRpb24xMTAvBgNVBAMMKFNTTC5jb20gUm9vdCBDZXJ0aWZpY2F0
# aW9uIEF1dGhvcml0eSBSU0EwHhcNMjYwNjEyMTY0MjE1WhcNNDEwMjEyMTczOTM5
# WjByMQswCQYDVQQGEwJVUzEOMAwGA1UECAwFVGV4YXMxEDAOBgNVBAcMB0hvdXN0
# b24xETAPBgNVBAoMCFNTTCBDb3JwMS4wLAYDVQQDDCVTU0wuY29tIFRpbWVzdGFt
# cGluZyBJc3N1aW5nIFJTQSBDQSAyMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIIC
# CgKCAgEAny+r5nNNkLwxRps2B3laUGNU9y7vWiJ5013yf0iXz65bQdwa9bjj8l/S
# keXqHGqfSh2Foae+80E8mDEf93oIwjsy2CX2cXmKxqtF8HJGYB4f6yRhKED50wkb
# OysL02IXf+/EZna44jffhhVz4OU/k52xQ/PnIg/uFhc2Wk+Sc/CHqAr+lYVkPz7L
# y5RqB9f1RKGr9JC37W1LgVdHC50dNIdsa3QXPhltYZubR3npE4Bbfi0joUW5n5O0
# ayweN45R/YVLxA0YGlp1OHVfVnsqXq8bhnw1Lc4kjJ6XOgXlOlw/a8ze57TvbduZ
# l3ehewTmvO0Aky/nqOWDS9IPPxdxdG6vprBbSuHlxNANBAbHTiFgkfZmf0dZYlT/
# AnZIoFxAq0HILPolf4OgWgET76SiWSlm2XYRIXwVjpeqG0plvXwRIQBzSiEJj7Qe
# QFnCvHx4gQMINvN3+yG/1rxhEbajGve0tTP3lX4PPOHVAE0QJp4ZzPI1YYJkhVRr
# iVVxVRU4Fsg4BPwP6I+YLmHb1tZ4RLwOFNLh/gJYDgPlChCoxOogFxXgwPZZrDyE
# RYB0aeOexW0OKacN4RRu9cqF2KKu/Ab5AL7eYDLVGUPrEEyYbIMApVKqpebc0/jD
# QniC+3rkauRAjgVc8m1ip/CQgG1Dw4Z9ulVRAY9VR6Za26LsTbUCAwEAAaOCAVEw
# ggFNMBIGA1UdEwEB/wQIMAYBAf8CAQAwHwYDVR0jBBgwFoAU3QQJB6L1en1SUxKS
# le44gCUNplkwTQYIKwYBBQUHAQEEQTA/MD0GCCsGAQUFBzAChjFodHRwOi8vY2Vy
# dC5zc2wuY29tL1NTTGNvbS1Sb290Q0EtUlNBLTQwOTYtUjEuY2VyMD8GA1UdIAQ4
# MDYwNAYEVR0gADAsMCoGCCsGAQUFBwIBFh5odHRwczovL3d3dy5zc2wuY29tL3Jl
# cG9zaXRvcnkwEwYDVR0lBAwwCgYIKwYBBQUHAwgwQgYDVR0fBDswOTA3oDWgM4Yx
# aHR0cDovL2NybHMuc3NsLmNvbS9TU0xjb20tUm9vdENBLVJTQS00MDk2LVIxLmNy
# bDAdBgNVHQ4EFgQUcJplwUOAo/zpsWSJbvEwnAkhyXwwDgYDVR0PAQH/BAQDAgGG
# MA0GCSqGSIb3DQEBCwUAA4ICAQBlFFvNMemA6iBiBYo56IKQjWhWuQaYKuo4qpf0
# KJNERAt1gz+HsA2SL3xA/V+EA8SRPNP9SvX0is+5mDsppYvpKyYGqYP36YFW0mbF
# 1F0ZtXxumCUUO/ZV5mBNKDf5Q4PY7Qb0eWAepUc0rNJr/Mvn5ZiXfJPxDb2xmcg8
# aRD652/nr+Ork2UBP0E43iJdI4LF7Vs29R3SGRLYZOxM15DI4QebsKRl0KDlf4Om
# YGCKc7umTxibkZtN1C1KWgnf9jadU/JwnySaYEBgx6/v+FVC6SGONziY7TcvI9MV
# +qYxHUPlOm6AaQP2dS4bjWXnm86ldCbUkxtOACumSfT97077JNiVa7PZ1IBkd/2P
# E1AC8gs7U+/Yk1BN9XRPIi15k/uA1xF9oeee5KGjyiGKkqIT7W8QkgUT5zeCinFK
# kcKafZMcROSVYpXtmtQqGGR2g4uPYqJ0K1hms6gJXrHt/34p8M9PrV8oNWe0Zl1E
# rDMtXndUg3qhJL4pA3ZUlo7w5lM5ml+A7ijr/3Gk2v4QRoDeE2ShmTXdHgtqo8L/
# fT119mYcETycE2NYGRXsBl3N0rzDsHRr8P3TrprqhRrX04iS0P7eQ+lDxgS3yhGn
# 3OzWGhDt9Gf2x1qe0/qdhFAVOkXxzMZz4Uat6xsAfzX0+/m8GEKW5Ojw/HY+kLvV
# wzSPOzGCAlcwggJTAgEBMIGGMHIxCzAJBgNVBAYTAlVTMQ4wDAYDVQQIDAVUZXhh
# czEQMA4GA1UEBwwHSG91c3RvbjERMA8GA1UECgwIU1NMIENvcnAxLjAsBgNVBAMM
# JVNTTC5jb20gVGltZXN0YW1waW5nIElzc3VpbmcgUlNBIENBIDICEFRD+De9Wu4Y
# AYRyuFzajuMwCwYJYIZIAWUDBAIBoIIBYDAaBgkqhkiG9w0BCQMxDQYLKoZIhvcN
# AQkQAQQwHAYJKoZIhvcNAQkFMQ8XDTI2MTExMDA4MzI1N1owKAYJKoZIhvcNAQk0
# MRswGTALBglghkgBZQMEAgGhCgYIKoZIzj0EAwIwLwYJKoZIhvcNAQkEMSIEIJoU
# ahiePJDtGkxNhbiycvlY45DZrMI+3syJHO9ASsn7MIHIBgsqhkiG9w0BCRACLzGB
# uDCBtTCBsjCBrwQgV0/qF6r6XnxqK5sIyZixc15FCzhzykTmokygkw5j87AwgYow
# dqR0MHIxCzAJBgNVBAYTAlVTMQ4wDAYDVQQIDAVUZXhhczEQMA4GA1UEBwwHSG91
# c3RvbjERMA8GA1UECgwIU1NMIENvcnAxLjAsBgNVBAMMJVNTTC5jb20gVGltZXN0
# YW1waW5nIElzc3VpbmcgUlNBIENBIDICEFRD+De9Wu4YAYRyuFzajuMwCgYIKoZI
# zj0EAwIESDBGAiEA1s+ESC73XnvMwRBaijql8emlCvPxZziYkW8Ofe/B6dgCIQDz
# npa4EVo5LnQW64/td43MZW4CUb2fN84nQwtbNw8BkQ==
# SIG # End signature block
