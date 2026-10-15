#Requires -Version 5.1
<#
.SYNOPSIS
    Synthetic report-only data for the HTML report tests (dot-sourced by tests\PraReport.Tests.ps1).
.DESCRIPTION
    Builds run contexts with N object rows and M run errors/warnings (no AD, no tenant, no network) and writes the
    real CSV and HTML reports through Write-PraReport of the PRA.Common module under test.
#>
Set-StrictMode -Version Latest

function global:New-PraSyntheticRows {
    param([Parameter(Mandatory)][int]$Count)
    $statuses = @('Success','Success','Success','Success','AlreadyDone','AlreadyDone','Pending','Pending','Error','Planned')
    $rows = New-Object 'Collections.Generic.List[object]'
    for ($i = 0; $i -lt $Count; $i++) {
        $sam = 'user{0:d6}' -f $i
        if ($i % 97 -eq 5) { $sam = 'Éloïse-日本語-{0:d6}' -f $i }
        elseif ($i % 101 -eq 7) { $sam = '=cmd|''/c calc''!A0 {0:d6}' -f $i }
        $detail = 'Row {0}: synthetic detail for the report volume test.' -f $i
        if ($i % 89 -eq 3) { $detail = 'Row {0}: <script>alert("x")</script> & ''quotes'' "double" <b>bold</b>' -f $i }
        elseif ($i % 71 -eq 4) { $detail = "Row {0}: first line`r`nsecond line`ttab`nthird line" -f $i }
        elseif ($i % 499 -eq 11) { $detail = ('Row {0}: long detail ' -f $i) + ('0123456789abcdef' * 160) }
        elseif ($i % 211 -eq 9) { $detail = '+SUM(1+1) leading plus, row {0}' -f $i }
        $rows.Add([pscustomobject][ordered]@{
            ObjectGuid = ('{0:x8}-1111-2222-3333-{1:x12}' -f $i, ($i * 7)); SamAccountName = $sam; UserPrincipalName = ('{0}@contoso.example' -f $sam)
            Action = 'Convert'; IsShared = $(if ($i % 50 -eq 0) { $null } else { ($i % 3) -eq 0 }); ADApplied = ($i % 4) -ne 0; ADVerified = $(if ($i % 9 -eq 0) { $false } else { $true })
            GroupAction = $(if ($i % 5 -eq 0) { $null } else { 'Added to the licence group' }); BackupPath = ('Backups\batch\{0}.json' -f $sam); LastOperation = @('AD.Apply','Cloud.Check','Perm.Verify')[$i % 3]
            CloudMailbox = $(if ($i % 6 -eq 0) { $null } else { ($i % 2) -eq 0 }); CloudLicense = $(if ($i % 8 -eq 0) { $false } else { 'SKU-' + ($i % 4) }); CloudStatus = @('Provisioned','N/A','Pending sync','Deprovisioned')[$i % 4]
            CloudDetail = $(if ($i % 13 -eq 0) { 'Cloud check {0}' -f $i } else { '' }); PreserveCloudMailbox = ($i % 7) -eq 0; PreserveLicense = ($i % 11) -eq 0; DeprovisionConfirmed = $(if ($i % 4 -eq 3) { $true } else { $false })
            PermDetail = $(if ($i % 3 -eq 0) { 'FullAccess 2; SendAs 1' } else { '' }); PermMissing = $(if ($i % 17 -eq 0) { @('FullAccess S-1-5-21-1-2-3-{0}' -f $i, 'SendAs missing') } else { @() })
            FinalStatus = $statuses[$i % $statuses.Count]; Detail = $detail; Warnings = $(if ($i % 13 -eq 1) { 'Permission entries ignored (row {0})' -f $i } else { $null })
        })
    }
    return , $rows
}

function global:New-PraSyntheticContext {
    param([Parameter(Mandatory)][string]$PackageRoot, [Parameter(Mandatory)][int]$Rows, [int]$Issues = 0, [int]$Warnings = 0)
    $context = @{
        Root = $PackageRoot; Action = 'Convert'; Phase = '1'; Mode = 'Preview'; Config = @{ Environment = 'SYNTHETIC' }; BatchId = 'SYNTHETIC-BATCH'; Server = 'dc.synthetic.example'
        StartTime = (Get-Date).AddMinutes(-5); RunId = 'synthetic-run'; Version = '2.2.0'; NextSteps = @('Synthetic next step: nothing to run.'); ExitCode = 0; CloudConnectFailed = $false
        Rows = (New-PraSyntheticRows -Count $Rows)
        Issues = (New-Object 'Collections.Generic.List[object]'); WarningList = (New-Object 'Collections.Generic.List[object]')
    }
    for ($i = 0; $i -lt $Issues; $i++) {
        $context.Issues.Add([pscustomobject]@{ Timestamp = (Get-Date).AddSeconds($i).ToString('o'); Phase = 'Phase 1'; Source = $(if ($i % 3 -eq 0) { 'Cloud' } else { 'Execution' })
            Operation = 'Op {0}' -f ($i % 5); Identity = ('issue{0:d5}@contoso.example' -f $i); Message = $(if ($i % 50 -eq 0) { "Issue {0}: <b>html</b> & `"quote`"`r`nsecond line" -f $i } else { 'Issue {0}: synthetic run error.' -f $i }) })
    }
    for ($i = 0; $i -lt $Warnings; $i++) {
        $context.WarningList.Add([pscustomobject]@{ Timestamp = (Get-Date).AddSeconds($i).ToString('o'); Phase = 'Phase 1'; Message = 'Warning {0}: synthetic.' -f $i })
    }
    return $context
}

function global:Invoke-PraSyntheticReport {
    <# Writes the CSV and HTML reports of a synthetic run with Write-PraReport; returns timings and sizes. #>
    param([Parameter(Mandatory)][string]$PackageRoot, [Parameter(Mandatory)][string]$Directory, [Parameter(Mandatory)][int]$Rows, [int]$Issues = 0, [int]$Warnings = 0, [string]$Name = 'report')
    $null = New-Item -ItemType Directory -Path $Directory -Force
    $context = New-PraSyntheticContext -PackageRoot $PackageRoot -Rows $Rows -Issues $Issues -Warnings $Warnings
    $reports = @{ Csv = (Join-Path $Directory "$Name.csv"); Html = (Join-Path $Directory "$Name.html") }
    $module = Get-Module PRA.Common
    $process = [Diagnostics.Process]::GetCurrentProcess()
    $cpu0 = $process.TotalProcessorTime; $clock = [Diagnostics.Stopwatch]::StartNew()
    $outcomeClock = [Diagnostics.Stopwatch]::StartNew()
    $outcome = & $module { param($c) Get-PraOutcome $c } $context
    $outcomeMs = $outcomeClock.ElapsedMilliseconds
    $htmlClock = [Diagnostics.Stopwatch]::StartNew()
    & $module {
        param($c, $o, $path)
        $stream = [IO.File]::Open($path, [IO.FileMode]::Create, [IO.FileAccess]::Write, [IO.FileShare]::None)
        $writer = New-Object IO.StreamWriter($stream, (New-Object Text.UTF8Encoding($true)), 65536)
        try { Write-PraReportHtml -Context $c -Outcome $o -Writer $writer } finally { $writer.Dispose() }
    } $context $outcome (Join-Path $Directory "$Name.htmlonly.html")
    $htmlOnlyMs = $htmlClock.ElapsedMilliseconds
    $fullClock = [Diagnostics.Stopwatch]::StartNew()
    & $module { param($c, $r) Write-PraReport -Context $c -Reports $r } $context $reports
    $fullMs = $fullClock.ElapsedMilliseconds
    $clock.Stop(); $process.Refresh()
    [pscustomobject]@{
        Rows = $Rows; Issues = $Issues; Warnings = $Warnings; Context = $context; Outcome = $outcome; Reports = $reports; HtmlOnlyPath = (Join-Path $Directory "$Name.htmlonly.html")
        Metrics = [ordered]@{
            outcomeMs = $outcomeMs; htmlOnlyMs = $htmlOnlyMs; writeReportMs = $fullMs; totalWallMs = $clock.ElapsedMilliseconds
            cpuSeconds = [math]::Round(($process.TotalProcessorTime - $cpu0).TotalSeconds, 1)
            peakWorkingSetMB = [math]::Round($process.PeakWorkingSet64 / 1MB, 0); peakPagedMB = [math]::Round($process.PeakPagedMemorySize64 / 1MB, 0)
            htmlBytes = (Get-Item -LiteralPath $reports.Html).Length; csvBytes = (Get-Item -LiteralPath $reports.Csv).Length
        }
    }
}

function global:Read-PraReportData {
    <# Decodes the data of a report file like the page does (gzip, base64) so tests can compare it with the outcome. #>
    param([Parameter(Mandatory)][string]$Path)
    $html = [IO.File]::ReadAllText($Path, [Text.Encoding]::UTF8)
    $metaMatch = [regex]::Match($html, '<script type="application/json" id="pra-meta">(.*?)</script>')
    if (-not $metaMatch.Success) { throw 'pra-meta not found' }
    $meta = $metaMatch.Groups[1].Value | ConvertFrom-Json
    $data = @{}
    Add-Type -AssemblyName System.Web.Extensions
    $serializer = New-Object Web.Script.Serialization.JavaScriptSerializer
    $serializer.MaxJsonLength = [int]::MaxValue
    foreach ($kind in @('rows','issues','warnings')) {
        $spec = $meta.$kind
        $data[$kind] = [pscustomobject]@{ Fields = @($spec.fields); Count = 0; Dict = @(for ($f = 0; $f -lt $spec.fields.Count; $f++) { ,(New-Object 'Collections.Generic.List[object]') }); Cols = @(for ($f = 0; $f -lt $spec.fields.Count; $f++) { ,(New-Object 'Collections.Generic.List[int]') }); Chunks = (New-Object 'Collections.Generic.List[int]') }
    }
    foreach ($m in [regex]::Matches($html, '<script type="application/x-pra-chunk" data-kind="(\w+)" data-seq="(\d+)">([A-Za-z0-9+/=]*)</script>')) {
        $ds = $data[$m.Groups[1].Value]
        $input = New-Object IO.MemoryStream (, [Convert]::FromBase64String($m.Groups[3].Value))
        $gz = New-Object IO.Compression.GZipStream($input, [IO.Compression.CompressionMode]::Decompress)
        $reader = New-Object IO.StreamReader($gz, [Text.Encoding]::UTF8)
        $chunk = $serializer.DeserializeObject($reader.ReadToEnd())
        $reader.Dispose()
        $ds.Chunks.Add([int]$chunk['n']); $ds.Count += [int]$chunk['n']
        for ($f = 0; $f -lt $ds.Fields.Count; $f++) {
            foreach ($v in $chunk['d'][$f]) { $ds.Dict[$f].Add($v) }
            $ds.Cols[$f].AddRange([int[]]$chunk['c'][$f])
        }
    }
    [pscustomobject]@{ Meta = $meta; Data = $data; Html = $html }
}
