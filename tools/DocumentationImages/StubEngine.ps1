<#
.SYNOPSIS
    Synthetic engine for the documentation screenshots (repository tool, never shipped, never signed).
.DESCRIPTION
    Stands in for Invoke-PraRemoteMailbox.ps1 inside the temporary runtime that Show-ConsoleScreens.ps1 builds. It takes the same
    parameters as the real script and writes the same events as the real engine (start, plan, count, step, item, progress, result),
    with synthetic names only (contoso.com, SRV-PRA01, D:\PRA\Backups). The scenario file next to it lists the objects. A file named
    hold.<name> in the same folder makes the matching wait (entra, grant) last until the harness deletes it, so a wait can be photographed.
    Nothing here reads Active Directory, Exchange Online, Microsoft Graph or Entra Connect.
.NOTES
    Author  : Nicolas Fabert
    Version : 3.1.2
    Part of : PRA Remote Mailbox (repository tool, not in the package)
#>
param($Action, $Mode, $ConfigPath, $Scope, $Phase, $Identity, $MaxObjects, $SearchBase, $CsvPath, $Batch, $BaseConfigPath, $Expect, [switch]$Once, [switch]$Force)
$ErrorActionPreference = 'Stop'
$here = $PSScriptRoot
$scenario = [IO.File]::ReadAllText((Join-Path $here 'scenario.json')) | ConvertFrom-Json
function Ev($h) { [IO.File]::AppendAllText($env:PRA_EVENT_FILE, (($h | ConvertTo-Json -Depth 6 -Compress) + "`n"), (New-Object Text.UTF8Encoding($false))) }
function Hold($name) { $flag = Join-Path $here ('hold.' + $name); $limit = [datetime]::UtcNow.AddSeconds(90); while ((Test-Path $flag) -and [datetime]::UtcNow -lt $limit) { Start-Sleep -Milliseconds 200 } }
$all = @($scenario)
$objs = if ($Identity) { @($all | Where-Object { $_.upn -eq $Identity -or $_.sam -eq $Identity } | Select-Object -First 1) } else { $all }
if (-not $objs.Count) { $objs = @($all[0]) }
# A rollback of the one-mailbox test batch concerns that mailbox only (on one server; the two-server story rolls back the whole scenario).
if ($Action -eq 'Recover' -and -not $Identity -and $Phase -eq 'Both') { $objs = @($all[0]) }
$apply = ($Mode -eq 'Apply')
# The console passes -Phase AD for a Finalize; the real engine reports the phase Finalize.
if ($Action -eq 'Finalize') { $Phase = 'Finalize' }
$batchId = '490cc62e'; $backup = 'D:\PRA\Backups\Batch-490cc62e5f2b4d0e9c1a7b36d8e41f02\Convert-LAB-20261104_091200-490cc62e.json'
$steps = switch ("$Action|$Phase") {
    'Convert|Both' { @('Active Directory connection', 'Targets and planned changes', 'Exchange Online pre-check', 'Backup and Active Directory changes', 'Entra Connect synchronisation', 'Exchange Online: mailboxes, licences and permissions') }
    'Convert|AD' { @('Active Directory connection', 'Targets and planned changes', 'Backup and Active Directory changes', 'Entra Connect synchronisation', 'Creating the transfer package') }
    'Convert|Cloud' { @('Loading the batch of the AD phase', 'Exchange Online: mailboxes, licences and permissions') }
    'Recover|AD' { @('Loading the Convert batch', 'Active Directory connection', 'Planned restore', 'Backup and Active Directory changes', 'Entra Connect synchronisation', 'Creating the transfer package') }
    'Recover|Cloud' { @('Loading the Recover batch', 'Exchange Online: deprovisioning checks', 'Final restore of shared mailboxes and tags') }
    'Recover|Both' { @('Loading the Convert batch', 'Active Directory connection', 'Planned restore', 'Exchange Online pre-check', 'Backup and Active Directory changes', 'Entra Connect synchronisation', 'Exchange Online: deprovisioning checks') }
    'Finalize|Finalize' { @('Loading the Finalize package', 'Active Directory connection', 'Planned restore', 'Backup and Active Directory changes', 'Entra Connect synchronisation') }
    'Check|Cloud' { @('Exchange Online and Microsoft Graph', 'Mailbox check') }
    default { @('Loading the batch of the AD phase', 'Exchange Online: mailboxes, licences and permissions') }
}
# Finishing a batch whose AD part is done (Convert -Phase AD -Batch): the sync again, then the package; Active Directory is not written.
if ($Action -eq 'Convert' -and $Phase -eq 'AD' -and $Batch) { $steps = @('Loading the batch of the AD phase', 'Entra Connect synchronisation', 'Creating the transfer package') }
# A file syncfail.flag makes the sync of a new conversion fail after the AD changes, as it does when the account has no right on the Entra Connect server.
$syncFailed = (Test-Path (Join-Path $here 'syncfail.flag')) -and -not $Batch
$total = $steps.Count
Ev @{kind = 'start'; title = 'PRA Remote Mailbox'; action = $Action; mode = $Mode; phase = $Phase }
Ev @{kind = 'plan'; steps = @(for ($i = 0; $i -lt $total; $i++) { @{id = 's' + ($i + 1); label = $steps[$i]; count = $null } }) }
$csv = Join-Path $here 'synthetic.csv'; $logPath = Join-Path $here 'logs\PRA_run.log'; $null = New-Item -ItemType Directory -Path (Split-Path $logPath) -Force; [IO.File]::WriteAllText($logPath, 'run log')
$rows = @($objs | ForEach-Object { [pscustomobject]@{ObjectGuid = $_.guid; SamAccountName = $_.sam; UserPrincipalName = $_.upn; Action = $Action; IsShared = [bool]$_.shared; ADApplied = $apply; ADVerified = $apply; CloudStatus = $(if ($apply) { 'Success' } else { 'N/A' }); FinalStatus = $(if ($apply) { 'Success' } else { 'Planned' }); Detail = $(if ($apply) { 'Done' } else { 'Planned' }); BackupPath = $(if ($apply) { $backup } else { '' }); Warnings = $(if ($_.warning -and -not ($Action -eq 'Recover' -and $Phase -eq 'Cloud')) { $_.warning } else { '' }) } })
$rows | Export-Csv -LiteralPath $csv -Delimiter ';' -NoTypeInformation -Encoding UTF8
$perObject = @('Targets and planned changes', 'Planned restore', 'Backup and Active Directory changes', 'Exchange Online: mailboxes, licences and permissions', 'Exchange Online pre-check', 'Exchange Online: deprovisioning checks', 'Mailbox check')
$wholeBatch = @('Active Directory connection', 'Entra Connect synchronisation', 'Creating the transfer package', 'Loading the Convert batch', 'Loading the batch of the AD phase', 'Loading the Recover batch', 'Loading the Finalize package', 'Final restore of shared mailboxes and tags', 'Exchange Online and Microsoft Graph')
Ev @{kind = 'count'; count = $objs.Count; stepIds = @(for ($i = 0; $i -lt $total; $i++) { if ($steps[$i] -notin $wholeBatch) { 's' + ($i + 1) } }) }
for ($i = 0; $i -lt $total; $i++) {
    $id = 's' + ($i + 1); $label = $steps[$i]
    if (-not $apply -and $label -in @('Exchange Online pre-check', 'Entra Connect synchronisation', 'Creating the transfer package', 'Exchange Online: mailboxes, licences and permissions', 'Backup and Active Directory changes', 'Exchange Online: deprovisioning checks', 'Final restore of shared mailboxes and tags')) { Ev @{kind = 'step'; index = $i + 1; total = $total; id = $id; title = $label; state = 'skipped'; startedUtc = [datetime]::UtcNow.ToString('o'); endedUtc = [datetime]::UtcNow.ToString('o') }; continue }
    Ev @{kind = 'step'; index = $i + 1; total = $total; id = $id; title = $label; state = 'running'; startedUtc = [datetime]::UtcNow.ToString('o'); endedUtc = $null }
    $state = 'ok'
    if ($label -in $perObject) {
        foreach ($o in $objs) {
            $warn = ($label -in @('Targets and planned changes', 'Planned restore') -and $o.warning)
            $text = switch ($label) {
                'Targets and planned changes' { if ($o.warning) { $o.warning } else { 'Can be converted' } }
                'Planned restore' { if ($o.warning) { $o.warning } else { 'Can be restored from the backup' } }
                'Backup and Active Directory changes' { if ($apply) { if ($Action -eq 'Convert') { 'Backed up and changed in Active Directory, verified' } else { 'Original attributes restored and verified' } } else { 'Planned' } }
                'Exchange Online pre-check' { 'Found in Exchange Online' }
                'Exchange Online: deprovisioning checks' { 'Cloud mailbox removed as expected' }
                'Mailbox check' { 'Provisioned in Exchange Online' }
                default { 'Mailbox ready, licence checked' }
            }
            if ($warn) { $state = 'warn' }
            $item = @{kind = 'item'; stepId = $id; status = $(if ($warn) { 'Warn' } else { 'Ok' }); text = $text; identity = $o.guid; name = $o.upn; detail = '' }
            if ($apply -and $label -eq 'Backup and Active Directory changes') { $item.backup = $backup }
            Ev $item
            Start-Sleep -Milliseconds 400
        }
    }
    if ($label -eq 'Entra Connect synchronisation' -and $apply -and $syncFailed) {
        Ev @{kind = 'item'; stepId = $id; status = 'Warn'; text = 'Entra Connect sync could not run on SRV-AADC01: this account has no right on SRV-AADC01: it must be allowed to open a remote session there (member of Remote Management Users or Administrators) and to use Entra Connect (member of ADSyncOperators). The AD changes are already made and verified; the sync is the next step.'; identity = ''; name = ''; detail = '' }
        $state = 'warn'
    }
    elseif ($label -eq 'Entra Connect synchronisation' -and $apply) {
        Ev @{kind = 'item'; stepId = $id; status = 'Info'; text = 'Delta cycle started on SRV-AADC01, waiting for its end (max 15 min)...'; identity = ''; name = ''; detail = '' }
        foreach ($a in 1..3) { Ev @{kind = 'progress'; stepId = $id; current = $a * 10; total = 900; attempt = $a; maxAttempts = 13; nextInSeconds = 10; text = 'Entra Connect synchronisation cycle in progress on SRV-AADC01' }; Start-Sleep -Milliseconds 300 }
        Hold 'entra'
    }
    if ($label -like 'Exchange Online: mailboxes*' -and $apply -and ($objs | Where-Object shared)) {
        $shared = @($objs | Where-Object shared)[0]
        Ev @{kind = 'item'; stepId = $id; status = 'Info'; text = 'Granting FullAccess to alex.wilber@contoso.com on finance.shared@contoso.com'; identity = $shared.guid; name = $shared.upn; detail = '' }
        foreach ($a in 1..4) { Ev @{kind = 'progress'; stepId = $id; current = 0; total = 0; attempt = $a; maxAttempts = 13; nextInSeconds = 10; text = 'Verifying FullAccess for alex.wilber@contoso.com on finance.shared@contoso.com' }; Start-Sleep -Milliseconds 300 }
        Hold 'grant'
    }
    if ($label -eq 'Creating the transfer package' -and $apply) {
        $written = if ($Action -eq 'Recover') { 'PRA-LAB-Recover-5ad39f71-for-Cloud.zip' } else { 'PRA-LAB-Convert-490cc62e-for-Cloud.zip' }
        Ev @{kind = 'item'; stepId = $id; status = 'Ok'; text = "Transfer package $written written (18.4 MB, checksums verified)"; identity = ''; name = ''; detail = '' }
    }
    if ($label -eq 'Final restore of shared mailboxes and tags' -and $apply) {
        # Only the shared mailbox that the cloud removed needs a last Active Directory change: it travels to the AD server in the Finalize package.
        Ev @{kind = 'item'; stepId = $id; status = 'Info'; text = 'Cloud-only phase: final AD restoration is packaged for Finalize on the AD server.'; identity = ''; name = ''; detail = '' }
        Ev @{kind = 'item'; stepId = $id; status = 'Ok'; text = 'Finalize package b7d41a9c written: D:\PRA\Backups\Finalize-b7d41a9c'; identity = ''; name = ''; detail = '' }
        Ev @{kind = 'item'; stepId = $id; status = 'Ok'; text = 'Transfer package PRA-LAB-Finalize-b7d41a9c-for-AD.zip written (18.4 MB, checksums verified)'; identity = ''; name = ''; detail = '' }
    }
    Start-Sleep -Milliseconds 250
    Ev @{kind = 'step'; index = $i + 1; total = $total; id = $id; title = $label; state = $state; startedUtc = [datetime]::UtcNow.ToString('o'); endedUtc = [datetime]::UtcNow.ToString('o') }
}
$pkg = ''; $pkgKind = ''; $pkgName = ''
if ($apply -and $Phase -eq 'AD') { $pkgKind = $Action; $pkgName = if ($Action -eq 'Recover') { 'PRA-LAB-Recover-5ad39f71-for-Cloud.zip' } else { 'PRA-LAB-Convert-490cc62e-for-Cloud.zip' } }
# The cloud part of a rollback hands a Finalize package to the AD server (here: the one shared mailbox that the cloud removed).
if ($apply -and $Action -eq 'Recover' -and $Phase -eq 'Cloud') { $pkgKind = 'Finalize'; $pkgName = 'PRA-LAB-Finalize-b7d41a9c-for-AD.zip' }
if ($pkgName) { $pkg = Join-Path $here ('Backups\Outbox\' + $pkgName); $null = New-Item -ItemType Directory -Path (Split-Path $pkg) -Force; [IO.File]::WriteAllBytes($pkg, (New-Object byte[] 18400000)) }
$n = $objs.Count
$globalReport = ''; if ($apply -and -not $pkg -and $Phase -in @('Both', 'Cloud', 'Finalize')) { $globalReport = Join-Path $here 'reports\PRA_global.html'; $null = New-Item -ItemType Directory -Path (Split-Path $globalReport) -Force; [IO.File]::WriteAllText($globalReport, '<html></html>') }
$next = if ($pkgKind -eq 'Finalize') { @("Copy $pkgName to the AD server (anywhere), then run there:", ".\Invoke-PraRemoteMailbox.ps1 -Action Finalize -Mode Apply -Batch '$pkgName'") }
elseif ($pkg -and $syncFailed) { @('AD is changed and verified. The Entra Connect sync could not start: this account has no right on SRV-AADC01: it must be allowed to open a remote session there (member of Remote Management Users or Administrators) and to use Entra Connect (member of ADSyncOperators).', 'Run a delta sync on SRV-AADC01 (Start-ADSyncSyncCycle -PolicyType Delta) or wait for the next automatic cycle (about 30 minutes).', "Copy $pkgName to the cloud server (anywhere), then run there:", ".\Invoke-PraRemoteMailbox.ps1 -Action $pkgKind -Phase Cloud -Mode Apply -Batch '$pkgName'") }
elseif ($pkg) { @("Copy $pkgName to the cloud server (anywhere), then run there:", ".\Invoke-PraRemoteMailbox.ps1 -Action $pkgKind -Phase Cloud -Mode Apply -Batch '$pkgName'") }
elseif ($apply -and $Action -eq 'Convert') { @('To roll back this batch later: .\Invoke-PraRemoteMailbox.ps1 -Action Recover -Mode Preview -Batch 490cc62e') } else { @() }
Ev @{kind = 'result'; status = $(if ($pkg) { 'Pending' } elseif ($apply) { 'Success' } else { 'Planned' }); exitCode = $(if ($pkg) { 2 } else { 0 }); action = $Action; mode = $Mode; phase = $Phase; success = $(if ($pkgKind -eq 'Finalize') { $n - 1 } elseif ($apply -and -not $pkg) { $n } else { 0 }); error = 0; pending = $(if ($pkgKind -eq 'Finalize') { 1 } elseif ($pkg) { $n } else { 0 }); skipped = 0; planned = $(if ($apply) { 0 } else { $n }); total = $n; issues = @()
    nextSteps = $next; batchId = $batchId; csvReport = $csv; logFile = ($logPath); htmlReport = $(if ($apply) { (Join-Path $here 'reports\PRA_phase.html') } else { '' }); globalReport = $globalReport; backupFiles = @($(if ($apply) { $backup })); stateFiles = @(); transferPackage = $pkg; transferPackageKind = $pkgKind; configOverrides = @() }
if ($apply) { $null = New-Item -ItemType Directory -Path (Join-Path $here 'reports') -Force; [IO.File]::WriteAllText((Join-Path $here 'reports\PRA_phase.html'), '<html></html>') }
exit $(if ($pkg) { 2 } else { 0 })
