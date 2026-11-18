<#
.SYNOPSIS
    Times the batch-size sensitive steps of PRA Remote Mailbox on synthetic data (no directory, no tenant, no network).
.DESCRIPTION
    Builds -Count synthetic users (contoso, gate.invalid) behind an in-memory Active Directory and times, with the production modules of -Package:
      Plan          one read-only plan per user (New-PraPlan)
      BackupSave    the backup of the whole batch: JSON, CLIXML, SHA-256, re-read, comparison with the plans (Save-PraBatch)
      AdBatch       the AD phase: backup, then for each object the guarded writes, the journal and the AD proof (Invoke-PraAdBatch)
      ProofImport   the AD proof read and checked against its backup (Import-PraProof) and the per-write checks of the cloud phase
      Journal       one line appended to the batch journal, and the journal readers of a partial batch
      CloudPhase    the cloud phase bookkeeping (Invoke-PraCloudPhase) with every Microsoft 365 call replaced by a local answer
      Report        the per-run CSV and HTML report
      GlobalReport  the phase data, the global model, the global HTML and CSV report
      GuiState      the state read of the console (Read-PraGuiState), cold and warm, on a backup folder of batches
    Nothing is written outside -WorkFolder. The package is copied with the signature check substituted (tests\IntegrityFixture.ps1).
.PARAMETER Count
    Number of synthetic objects (default 5000).
.PARAMETER Package
    The package folder to measure (default: the package of this repository). Give an older package to time the same steps before a change.
.PARAMETER Step
    The steps to run (default: all).
.PARAMETER WorkFolder
    Folder for the copy of the package and the files written by the steps; default: a new folder under the temp folder, deleted at the end.
.PARAMETER OutputPath
    Also writes the timings as JSON.
.EXAMPLE
    pwsh -NoProfile -File .\tools\Measure-PraScale.ps1 -Count 5000
.NOTES
    Author  : Nicolas Fabert
    Version : 3.1.4
#>
#Requires -Version 7.5
[CmdletBinding()]
param(
    [ValidateRange(10, 50000)][int]$Count = 5000,
    [string]$Package = '',
    [string[]]$Step = @('Plan', 'BackupSave', 'AdBatch', 'ProofImport', 'Journal', 'CloudPhase', 'Report', 'GlobalReport', 'GuiState'),
    [string]$WorkFolder = '',
    [string]$OutputPath = ''
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$all = @('Plan', 'BackupSave', 'AdBatch', 'ProofImport', 'Journal', 'CloudPhase', 'Report', 'GlobalReport', 'GuiState')
$Step = @($Step | ForEach-Object { $_ -split ',' } | Where-Object { $_ })
foreach ($name in $Step) { if ($all -notcontains $name) { throw "Unknown step '$name'. Steps: $($all -join ', ')." } }
$repository = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
if (-not $Package) { $Package = Join-Path $repository 'package' }
$Package = [IO.Path]::GetFullPath($Package)
$ownWork = -not $WorkFolder
if ($ownWork) { $WorkFolder = Join-Path ([IO.Path]::GetTempPath()) ('PraScale-' + [guid]::NewGuid().ToString('N').Substring(0, 8)) }
$null = New-Item -ItemType Directory -Path $WorkFolder -Force
. (Join-Path $repository 'tests\IntegrityFixture.ps1')
$fixture = Join-Path $WorkFolder 'package'
$changelog = Join-Path $repository 'CHANGELOG.md'
if (-not (Test-Path -LiteralPath $changelog)) { $changelog = Join-Path $WorkFolder 'CHANGELOG.md'; Set-Content -LiteralPath $changelog -Value '# synthetic' }
New-PraIntegrityFixture -SourcePackage $Package -Destination $fixture -Changelog $changelog
$env:PRA_GATE_NONET = 'SYNTHETIC-NO-NETWORK'
foreach ($name in 'PRA.Common', 'PRA.Backup', 'PRA.Directory') { Import-Module (Join-Path $fixture "module\$name.psm1") -Force -Global }
Import-Module (Join-Path $fixture 'module\PRA.Cloud.psm1') -Force -Global
$timings = New-Object 'Collections.Generic.List[object]'
function Measure-Step {
    param([string]$Name, [string]$Detail, [scriptblock]$Script)
    $clock = [Diagnostics.Stopwatch]::StartNew()
    $value = & $Script 6>$null
    $clock.Stop()
    $row = [pscustomobject]@{ Step = $Name; Detail = $Detail; Seconds = [math]::Round($clock.Elapsed.TotalSeconds, 2) }
    $timings.Add($row)
    Write-Host ('{0,-14} {1,9:N2} s   {2}' -f $Name, $clock.Elapsed.TotalSeconds, $Detail)
    return $value
}

# In-memory Active Directory: the cmdlets the Directory module calls, over a dictionary of synthetic users.
$global:PraScaleAd = @{ Users = New-Object 'Collections.Generic.List[object]'; ByKey = New-Object 'Collections.Generic.Dictionary[string,object]' ([StringComparer]::OrdinalIgnoreCase)
    Members = New-Object 'Collections.Generic.List[string]'; Group = $null }
function global:Get-ADDomainController { [CmdletBinding()] param([switch]$Discover, [switch]$Writable, [string]$Identity, [string]$Server) [pscustomobject]@{ HostName = 'dc01.gate.invalid'; IsReadOnly = $false } }
function global:Get-ADUser {
    [CmdletBinding()]
    param([object]$Identity, [string]$LDAPFilter, [string[]]$Properties, [string]$Server, [string]$SearchBase)
    $found = $null
    if ($Identity -and $global:PraScaleAd.ByKey.TryGetValue([string]$Identity, [ref]$found)) { return $found }
}
function global:Get-ADGroup {
    [CmdletBinding()]
    param([object]$Identity, [string[]]$Properties, [string]$Server, [string]$LDAPFilter)
    return $global:PraScaleAd.Group
}
function global:Set-ADUser {
    [CmdletBinding(SupportsShouldProcess)]
    param([object]$Identity, [hashtable]$Replace, [string[]]$Clear, [string]$Server)
    $user = $global:PraScaleAd.ByKey[[string]$Identity]
    if ($null -ne $Replace) { foreach ($key in $Replace.Keys) { $user.$key = $Replace[$key] } }
    foreach ($key in $Clear) { $user.$key = $null }
    $user.uSNChanged = [long]$user.uSNChanged + 1
}
function global:Add-ADGroupMember {
    [CmdletBinding(SupportsShouldProcess)]
    param([object]$Identity, [object[]]$Members, [string]$Server)
    foreach ($id in $Members) {
        $member = $global:PraScaleAd.ByKey[[string]$id]
        $global:PraScaleAd.Members.Add([string]$member.DistinguishedName)
        $member.memberOf = @([string]$global:PraScaleAd.Group.DistinguishedName)
    }
    $global:PraScaleAd.Group.member = $global:PraScaleAd.Members.ToArray()
}

function New-ScaleUser {
    param([int]$Index)
    $text = 'Synthetic value of the attribute for the user number {0}, long enough to look like a directory value.' -f $Index
    $user = [ordered]@{
        ObjectGUID = [guid]('00000000-0000-0000-0000-{0:000000000000}' -f $Index)
        DistinguishedName = "CN=User$Index,OU=Tests,DC=gate,DC=invalid"; SamAccountName = "user$Index"
        UserPrincipalName = "user$Index@contoso.gate.invalid"; DisplayName = "Synthetic User $Index"; Name = "User$Index"; objectClass = 'user'
        mail = "user$Index@contoso.gate.invalid"; mailNickname = "user$Index"; legacyExchangeDN = "/o=Synthetic/ou=Gate/cn=Recipients/cn=user$Index"
        uSNChanged = [long](1000 + $Index); memberOf = @(); publicDelegates = @(); msExchArchiveGUID = $null
        homeMDB = "CN=Database$($Index % 7),CN=Databases,DC=gate,DC=invalid"; homeMTA = 'CN=OriginalMTA,DC=gate,DC=invalid'
        msExchHomeServerName = '/o=Synthetic/ou=Gate/cn=Servers/cn=Original'; msExchMailboxGuid = [byte[]](0, 1, 2, 127, 128, 254, 255, ($Index % 256), 1, 2, 3, 4, 5, 6, 7, 8)
        mDBUseDefaults = $false; msExchRecipientDisplayType = 0; msExchRecipientTypeDetails = [long]1; msExchRemoteRecipientType = $null; targetAddress = $null
        proxyAddresses = [string[]]@("SMTP:user$Index@contoso.gate.invalid", "smtp:alias$Index@contoso.gate.invalid", "smtp:other$Index@fabrikam.gate.invalid", 'X500:/o=Synthetic/ou=Gate/cn=User')
        extensionAttribute1 = "OriginalTag-$Index"
        nTSecurityDescriptor = [byte[]]::new(2400); msExchMailboxSecurityDescriptor = [byte[]]::new(1800)
    }
    for ($a = 1; $a -le 30; $a++) { $user["scaleAttribute$a"] = $text }
    return [pscustomobject]$user
}

function New-ScaleContext {
    param([string]$Name, [string]$Action = 'Convert', [string]$Mode = 'Apply')
    $root = Join-Path $WorkFolder $Name
    foreach ($folder in 'backups', 'logs', 'reports') { $null = New-Item -ItemType Directory -Path (Join-Path $root $folder) -Force }
    $config = @{
        Environment = 'SYNTHETIC_SCALE'; DomainController = ''
        Scope = @{ Mode = 'Auto'; SearchBase = 'OU=Tests,DC=gate,DC=invalid'; GroupDN = ''; CsvPath = ''; IncludeShared = $false; IncludeRoom = $false; IncludeEquip = $false; ExcludeSamAccountNames = @() }
        Routing = @{ AutoDetect = $false; RoutingDomain = 'contoso.mail.onmicrosoft.com' }
        Licensing = @{ Enabled = $true; GroupDN = 'CN=License,OU=Tests,DC=gate,DC=invalid' }
        SharedMailbox = @{ Enabled = $true; PermissionSource = 'None'; CaptureSendOnBehalf = $false; RemoteRecipientType = 97; ExcludeTrusteeSamAccountNames = @(); GrantFullAccess = $true; GrantSendAs = $true; GrantSendOnBehalf = $true }
        EntraConnect = @{ Sync = $false; Server = ''; PolicyType = 'Delta'; TimeoutMinutes = 1 }
        Retention = @{ Enabled = $true; Tag = @{ Enabled = $true; Attribute = 'extensionAttribute1'; Value = 'Converted' } }
        Remote = @{ RecipientType = 1; HandleArchives = $true; ClearMailboxGuid = $true }
        Cloud = @{ CheckMailbox = $true; CheckLicense = $false; MailboxCheckVia = 'Exo'; IdentityCheck = 'Off' }
        Exo = @{ GrantVerifyAttempts = 3; GrantVerifyDelaySeconds = 1 }
        Execution = @{ Phase = 'AD' }; Storage = @{ BackupFolder = (Join-Path $root 'backups'); ForbiddenBackupRoots = @() }
        Logging = @{ Folder = (Join-Path $root 'logs') }; Report = @{ Enabled = $true; Folder = (Join-Path $root 'reports') }
    }
    @{
        Root = $fixture; RunId = '20261117_100000-' + [guid]::NewGuid().ToString('N').Substring(0, 8); Version = 'scale'; StartTime = Get-Date; Action = $Action; Mode = $Mode; Phase = 'AD'
        CurrentPhase = 'Scale'; CurrentOperation = ''; CurrentIdentity = ''; StepIndex = 0; Warnings = 0; Config = $config
        Issues = (New-Object 'Collections.Generic.List[object]'); Rows = (New-Object 'Collections.Generic.List[object]')
        BackupFiles = (New-Object 'Collections.Generic.List[string]'); StateFiles = (New-Object 'Collections.Generic.List[string]')
        BackupFolder = (Join-Path $root 'backups'); LogFolder = (Join-Path $root 'logs'); ReportFolder = (Join-Path $root 'reports')
        LogFile = (Join-Path $root 'logs\run.log'); TranscriptPath = ''; TranscriptStarted = $false; NoReport = $false; Server = 'dc01.gate.invalid'; NamingContext = 'DC=gate,DC=invalid'
        AllowMutation = ($Mode -eq 'Apply'); Approval = { param($Target, $Operation) $true }
        SourceBackupHash = ''; Source = $null; Proof = $null; JournalPath = ''; ExitCode = 0; ResultStatus = ''; CloudConnectFailed = $false
        TimeoutMinutes = 1; IntervalMinutes = 0; Once = $false
    }
}

Write-Host ('PRA scale measurement: {0} objects, package {1}' -f $Count, $Package)
for ($i = 1; $i -le $Count; $i++) {
    $user = New-ScaleUser $i
    $global:PraScaleAd.Users.Add($user)
    foreach ($key in ([string]$user.ObjectGUID), $user.DistinguishedName, $user.SamAccountName) { $global:PraScaleAd.ByKey[$key] = $user }
}
$global:PraScaleAd.Group = [pscustomobject]@{ ObjectGUID = [guid]'10000000-0000-0000-0000-000000000001'; DistinguishedName = 'CN=License,OU=Tests,DC=gate,DC=invalid'; objectClass = 'group'; member = [string[]]@() }
$guids = @($global:PraScaleAd.Users | ForEach-Object { [string]$_.ObjectGUID })
$context = New-ScaleContext 'plan'
$plans = $null
$runBackupSave = $Step -contains 'BackupSave'
$needPlans = $Step.Count -gt 0
$plans = Measure-Step 'Plan' "$Count plans" { $list = New-Object 'Collections.Generic.List[object]'; foreach ($guid in $guids) { $list.Add((New-PraPlan $context $guid 'Convert')) }; , $list.ToArray() }
$plans = @($plans)

$batchContext = $null; $receipt = $null
if ($Step -contains 'BackupSave') {
    $saveContext = New-ScaleContext 'save'
    $null = Measure-Step 'BackupSave' "$Count records" { & (Get-Module PRA.Directory) { param($c, $p) $null = Save-PraBatch $c $p 'Convert' } $saveContext $plans }
}
$batchContext = New-ScaleContext 'batch'
if ($Step -contains 'AdBatch' -or $Step -contains 'ProofImport') {
    $receipt = Measure-Step 'AdBatch' "$Count objects: backup, guarded writes, journal, proof" { Invoke-PraAdBatch $batchContext $plans 'Convert' }
    $batchContext.Source = $receipt; $batchContext.SourceBackupHash = $receipt.Hash
    $batchFolder = Split-Path $receipt.Path -Parent; $backupHash = $receipt.Hash; $batchId = [string]$receipt.Data.BatchId
}
else {
    # The steps that follow do not need the written backup: a batch folder with the JSON of the records, its proof and its journal is made without the CLIXML codec.
    $batchId = [guid]::NewGuid().ToString('N'); $batchFolder = Join-Path $batchContext.BackupFolder ('Batch-' + $batchId)
    $null = New-Item -ItemType Directory -Path $batchFolder -Force
    $utf8 = New-Object Text.UTF8Encoding($false)
    $backup = [ordered]@{ SchemaVersion = 3; Operation = 'Convert'; Environment = 'SYNTHETIC_SCALE'; BatchId = $batchId; Records = @($plans | ForEach-Object { $_.Record }) }
    $backupPath = Join-Path $batchFolder ('Convert-SYNTHETIC_SCALE-20261117_100000-' + $batchId.Substring(0, 8) + '.json')
    [IO.File]::WriteAllText($backupPath, ($backup | ConvertTo-Json -Depth 30), $utf8)
    $backupHash = Get-PraHash $backupPath
    [IO.File]::WriteAllText($backupPath + '.sha256', $backupHash, $utf8)
    $proof = [ordered]@{ SchemaVersion = 2; Operation = 'Convert'; Kind = 'ADVerified'; Environment = 'SYNTHETIC_SCALE'; BackupHash = $backupHash; CreatedUtc = '2026-11-17T10:00:00.0000000Z'
        Records = @($plans | ForEach-Object { [ordered]@{ ObjectGuid = $_.Record.ObjectGuid; Operation = 'Convert'; ADVerified = $true } }) }
    $statePath = Join-Path $batchFolder ('State-' + $batchId + '.json')
    [IO.File]::WriteAllText($statePath, ($proof | ConvertTo-Json -Depth 5), $utf8)
    [IO.File]::WriteAllText($statePath + '.sha256', (Get-PraHash $statePath), $utf8)
    [IO.File]::WriteAllText((Join-Path $batchFolder ('Journal-' + $batchId + '.jsonl')), '', $utf8)
    foreach ($plan in $plans) { $plan.Row.FinalStatus = 'Success'; $plan.Row.ADApplied = $true; $plan.Row.ADVerified = $true; $plan.Row.BackupPath = $backupPath; $batchContext.Rows.Add($plan.Row) }
    $batchContext.BatchId = $batchId.Substring(0, 8)
}
if ($Step -contains 'ProofImport' -and $null -ne $receipt) {
    $proofContext = New-ScaleContext 'proof'
    $cheap = [bool](& (Get-Module PRA.Directory) { [bool](Get-Command Assert-PraCloudProofObject -ErrorAction SilentlyContinue) })
    $checked = if ($cheap) { $Count } else { [Math]::Min($Count, 20) }
    $null = Measure-Step 'ProofImport' "import of the proof, then $checked per-object checks of the cloud phase" {
        $source = Import-PraBackup $proofContext $receipt.Path
        $proofContext.Source = $source
        $proof = Import-PraProof $proofContext $receipt.StatePath $source 'Convert'
        $proofContext.Proof = $proof
        $proofPath = $receipt.StatePath
        foreach ($guid in ($guids | Select-Object -First $checked)) {
            if ($cheap) {
                & (Get-Module PRA.Directory) { param($c, $p, $s, $g) Assert-PraCloudProofObject -Context $c -ProofPath $p -Source $s -Operation 'Convert' -ObjectGuid $g } $proofContext $proofPath $source $guid
                Assert-PraReceipt $proofContext $source $guid
            }
            else {
                $again = Import-PraProof $proofContext $proofPath $source 'Convert'
                if (@($again.Data.Records | Where-Object { Test-PraOrdinalIgnoreCaseEqual $_.ObjectGuid $guid }).Count -ne 1) { throw 'not in the proof' }
                Assert-PraReceipt $proofContext $source $guid
            }
        }
    }
}
if ($Step -contains 'Journal') {
    $journalContext = New-ScaleContext 'journal'
    $journalContext.JournalPath = Join-Path $batchFolder ('Journal-' + $batchId + '.jsonl')
    $null = Measure-Step 'Journal' "$Count Started lines, then the readers of the partial batch" {
        foreach ($guid in $guids) { Write-PraJournal $journalContext $guid 'Set-ADUser' 'Started' }
        $touched = Get-PraJournalTouchedObject -Path $journalContext.JournalPath
        $null = Find-PraRecoverOfBatch -Context $batchContext -SourceHash $backupHash -ObjectGuid $guids
    }
}
if ($Step -contains 'CloudPhase') {
    $cloudContext = New-ScaleContext 'cloud' 'Convert' 'Apply'
    $cloudContext.Phase = 'Cloud'
    $cloudRows = @($plans | ForEach-Object { $_.Row })
    foreach ($row in $cloudRows) { $row.FinalStatus = 'Pending'; $row.ADVerified = $true }
    $notReady = New-Object 'Collections.Generic.HashSet[string]'
    foreach ($row in ($cloudRows | Select-Object -First ([int]($Count / 5)))) { [void]$notReady.Add([string]$row.UserPrincipalName) }
    $global:PraScaleNotReady = $notReady; $global:PraScalePolls = 0
    & (Get-Module PRA.Cloud) {
        function script:Connect-PraCloudSession { param($Context, $NeedGraph, $NeedExo) }
        function script:Close-PraCloudSession { param($Context) }
        function script:Confirm-PraCloudIdentity { param($Context, $State, [switch]$Throw) 'Ok' }
        function script:Invoke-PraExo { param($Context, $Operation, $Params, $Permit, $OnApplied, $OnProgress)
            if ($Operation -eq 'Mailbox') { return @{ Found = ($global:PraScaleNotReady.Count -eq 0 -or $global:PraScalePolls -gt 0 -or -not $global:PraScaleNotReady.Contains([string]$Params.Upn)); Type = 'UserMailbox'; HasAddresses = $true; Addresses = [string[]]@() } }
            return @{} }
        function script:Invoke-PraSharedPermission { param($Context, $Row, $Requests) 0 }
    }
    $null = Measure-Step 'CloudPhase' "$Count rows, 2 checks, Microsoft 365 answered locally" {
        Invoke-PraCloudPhase -Context $cloudContext -Rows $cloudRows -Act Convert
    }
}
if ($Step -contains 'Report') {
    $null = Measure-Step 'Report' "CSV and HTML of $Count rows" {
        $reports = @{ Csv = (Join-Path $batchContext.ReportFolder 'scale.csv'); Html = (Join-Path $batchContext.ReportFolder 'scale.html'); CsvFailed = $false; HtmlFailed = $false }
        $null = New-Item -ItemType File -Path $reports.Csv, $reports.Html -Force
        & (Get-Module PRA.Common) { param($c, $r) Write-PraReport $c $r } $batchContext $reports
    }
}
if ($Step -contains 'GlobalReport') {
    $batchContext.PhaseFolders = @($batchFolder)
    $null = Measure-Step 'GlobalReport' "phase data, model, HTML and CSV of $Count objects" {
        $null = Save-PraPhaseData -Context $batchContext -Folder $batchFolder
        $null = Write-PraGlobalReport -Context $batchContext
    }
}
if ($Step -contains 'GuiState') {
    Import-Module (Join-Path $fixture 'module\PRA.Gui.psm1') -Force -Global
    $guiRoot = Join-Path $WorkFolder 'gui'
    $null = New-Item -ItemType Directory -Path $guiRoot -Force
    $guiConfig = Join-Path $guiRoot 'gui.config.psd1'
    $backups = Join-Path $guiRoot 'backups'
    Set-Content -LiteralPath $guiConfig -Value ("@{ Environment = 'SYNTHETIC_SCALE'; Scope = @{ Mode = 'Auto' }; Licensing = @{ Enabled = `$false }; EntraConnect = @{ Sync = `$false }; Execution = @{ Phase = 'AD' }; Storage = @{ BackupFolder = '" + $backups.Replace("'", "''") + "' } }")
    $source = $batchFolder
    for ($b = 1; $b -le 5; $b++) {
        $copy = Join-Path $backups ('Batch-' + $b.ToString('x32'))
        $null = New-Item -ItemType Directory -Path $copy -Force
        Copy-Item -Path (Join-Path $source '*.json'), (Join-Path $source '*.sha256') -Destination $copy
    }
    foreach ($label in '5 batches, first read', '5 batches, second read (nothing changed)') {
        $state = Measure-Step 'GuiState' $label { Read-PraGuiState $fixture $guiConfig }
        if ($state.ConfigError -or $state.BatchError -or @($state.Batches | Where-Object Valid).Count -ne 5) { throw ('The console state is not the expected one: ' + $state.ConfigError + $state.BatchError) }
    }
}

$result = [pscustomobject]@{ Count = $Count; Package = $Package; PowerShell = [string]$PSVersionTable.PSVersion; Timings = $timings.ToArray() }
if ($OutputPath) { [IO.File]::WriteAllText($OutputPath, ($result | ConvertTo-Json -Depth 5), (New-Object Text.UTF8Encoding($false))) }
if ($ownWork) { Remove-Item -LiteralPath $WorkFolder -Recurse -Force -ErrorAction SilentlyContinue }
$result
