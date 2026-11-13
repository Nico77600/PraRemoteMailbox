<#
.SYNOPSIS
    Renders every picture of the README and of the two guides (package\docs\images) from the source of the repository.
.DESCRIPTION
    Nothing here is drawn by hand and nothing comes from a real environment. Run it again after any change of the console, of the
    reports or of the guides: every picture is rebuilt, then the HTML guides are rebuilt with the new pictures inside.

        Console     the real WPF window (package\module\PRA.Gui.psm1) against a synthetic runtime, light and dark, with numbered
                    callouts on what the operator clicks (tools\DocumentationImages\Show-ConsoleScreens.ps1, one process per scenario)
        Reports     the real report code of the engine on synthetic phase data: one phase, one phase with a warning, the global
                    report of a Convert and of a Recover across two servers, rendered by Microsoft Edge
        Diagrams    the README and guide graphics (banner through tools\New-ReadmeImages.ps1, the others from the CSS of the built
                    guides), light and dark, 2x

    Synthetic data only: contoso.com, computer SRV-PRA01, account CONTOSO\pra.operator, tool folder D:\PRA\PraRemoteMailbox,
    backups D:\PRA\Backups. The console harness stops if a real machine name, user name or local path reaches a window.

.PARAMETER OutputFolder
    Default: package\docs\images next to the tools folder.

.PARAMETER Part
    Console, Reports, Diagrams or All (default).

.PARAMETER KeepWork
    Keeps the work folder (HTML pages, intermediate pictures) and shows its path.

.EXAMPLE
    .\tools\New-DocumentationImages.ps1
    Rebuilds every picture, then the HTML guides.

.NOTES
    Author  : Nicolas Fabert
    Version : 3.1.4
    Part of : PRA Remote Mailbox (repository tool, not in the package). Needs PowerShell 7.5+, Microsoft Edge, Windows (WPF).
#>
#Requires -Version 7.5
[CmdletBinding()]
param(
    [string]$OutputFolder,
    [ValidateSet('All', 'Console', 'Reports', 'Diagrams')][string]$Part = 'All',
    [switch]$KeepWork
)
$ErrorActionPreference = 'Stop'
$root = Split-Path $PSScriptRoot -Parent
if (-not $OutputFolder) { $OutputFolder = Join-Path $root 'package\docs\images' }
$OutputFolder = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($OutputFolder)
$edge = @("${env:ProgramFiles(x86)}\Microsoft\Edge\Application\msedge.exe", "$env:ProgramFiles\Microsoft\Edge\Application\msedge.exe") | Where-Object { Test-Path $_ } | Select-Object -First 1
if (-not $edge) { throw 'Microsoft Edge not found: it takes the screenshots (headless mode).' }
$work = Join-Path ([IO.Path]::GetTempPath()) ('pra-doc-images-' + [guid]::NewGuid().ToString('N').Substring(0, 8))
New-Item -ItemType Directory -Path $work, $OutputFolder -Force | Out-Null
$pwsh = (Get-Process -Id $PID).Path
$all = ($Part -eq 'All')

#region Edge helpers -------------------------------------------------------------------------------------
function Save-Screenshot([string]$Html, [string]$Png, [int]$Width, [int]$Height, [int]$Scale = 1) {
    $url = 'file:///' + ($Html -replace '\\', '/')
    $profileDir = Join-Path $work 'edge-profile'
    if (Test-Path $Png) { Remove-Item $Png -Force }
    # Start-Process, not &: an Edge helper process can keep the output pipe open after the capture.
    $edgeArgs = @('--headless=new', '--disable-gpu', '--hide-scrollbars', '--no-first-run', "--user-data-dir=`"$profileDir`"", "--window-size=$Width,$Height", "--force-device-scale-factor=$Scale", "--screenshot=`"$Png`"", "`"$url`"")
    $proc = Start-Process -FilePath $edge -ArgumentList $edgeArgs -PassThru -WindowStyle Hidden
    $deadline = (Get-Date).AddSeconds(60)
    while (-not (Test-Path $Png) -and (Get-Date) -lt $deadline) { Start-Sleep -Milliseconds 300 }
    if (-not $proc.WaitForExit(10000)) { Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue }
    if (-not (Test-Path $Png)) { throw "Screenshot not written: $Png" }
}

function Get-PageHeight([string]$Html, [int]$Width) {
    # Height of the page: the page writes it in body[data-h], read with --dump-dom.
    $url = 'file:///' + ($Html -replace '\\', '/')
    $dom = Join-Path $work ('dom-' + [guid]::NewGuid().ToString('N').Substring(0, 8) + '.html')
    $edgeArgs = @('--headless=new', '--disable-gpu', '--hide-scrollbars', '--no-first-run', "--user-data-dir=`"$(Join-Path $work 'edge-profile')`"", "--window-size=$Width,2000", '--virtual-time-budget=4000', '--dump-dom', "`"$url`"")
    $proc = Start-Process -FilePath $edge -ArgumentList $edgeArgs -PassThru -WindowStyle Hidden -RedirectStandardOutput $dom
    if (-not $proc.WaitForExit(60000)) { Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue }
    # Edge helper processes inherit the output handle: read in shared mode, retry until written.
    $m = $null
    for ($i = 0; $i -lt 20 -and -not ($m -and $m.Success); $i++) {
        $stream = [IO.File]::Open($dom, 'Open', 'Read', 'ReadWrite')
        try { $text = [IO.StreamReader]::new($stream).ReadToEnd() } finally { $stream.Dispose() }
        $m = [regex]::Match($text, 'data-h="(\d+)"')
        if (-not $m.Success) { Start-Sleep -Milliseconds 250 }
    }
    if (-not $m.Success) { throw "Height not measured: $Html" }
    return [int]$m.Groups[1].Value
}
#endregion

#region 1. Console -----------------------------------------------------------------------------------------
if ($all -or $Part -eq 'Console') {
    Write-Host 'Photographing the console (synthetic data)...'
    $shots = Join-Path $work 'console'
    New-Item -ItemType Directory -Path $shots -Force | Out-Null
    $harness = Join-Path $PSScriptRoot 'DocumentationImages\Show-ConsoleScreens.ps1'
    $jobs = @(
        @{ Scenario = 'single'; Theme = 'Light' }, @{ Scenario = 'single'; Theme = 'Dark' }
        @{ Scenario = 'scope'; Theme = 'Light' }, @{ Scenario = 'group'; Theme = 'Light' }, @{ Scenario = 'twoserver'; Theme = 'Light' }, @{ Scenario = 'cloud'; Theme = 'Light' }
        @{ Scenario = 'rollback'; Theme = 'Light' }, @{ Scenario = 'rollbackad'; Theme = 'Light' }, @{ Scenario = 'rollbackcloud'; Theme = 'Light' }, @{ Scenario = 'finalize'; Theme = 'Light' }, @{ Scenario = 'check'; Theme = 'Light' }
        @{ Scenario = 'finish'; Theme = 'Light' }, @{ Scenario = 'syncfailed'; Theme = 'Light' }
    )
    $running = @()
    foreach ($job in $jobs) {
        $log = Join-Path $work ("console-$($job.Scenario)-$($job.Theme).log")
        $argList = @('-NoProfile', '-STA', '-File', "`"$harness`"", '-Shots', "`"$shots`"", '-Theme', $job.Theme, '-Scenario', $job.Scenario, '-Repository', "`"$root`"")
        $running += [pscustomobject]@{ Job = $job; Log = $log; Process = (Start-Process -FilePath $pwsh -ArgumentList $argList -PassThru -WindowStyle Hidden -RedirectStandardOutput $log -RedirectStandardError ($log + '.err')) }
        # Four windows at a time.
        while (@($running | Where-Object { -not $_.Process.HasExited }).Count -ge 4) { Start-Sleep -Seconds 2 }
    }
    foreach ($r in $running) {
        $null = $r.Process.WaitForExit()
        $text = [IO.File]::ReadAllText($r.Log)
        if ($text -notmatch 'SHOTS-OK') { throw "Console harness failed ($($r.Job.Scenario), $($r.Job.Theme)):`n$text`n$([IO.File]::ReadAllText($r.Log + '.err'))" }
    }
    # The pictures the documents use. The dark ones are for the README (picture elements).
    $keepLight = @(
        'setup', 'setup-lights', 'settings', 'setup-next', 'task', 'task-identity', 'verify-before', 'verify', 'run-early', 'run-waiting', 'run-finished', 'next'
        'task-scope', 'task-group', 'verify-scope', 'run-grant', 'next-global'
        'setup-red', 'setup-red-lights', 'task-ad', 'run-package', 'next-package'
        'task-continue', 'task-package-selected', 'verify-cloud', 'run-cloud', 'next-cloud'
        'task-rollback', 'task-rollback-selected', 'verify-rollback', 'run-rollback', 'next-rollback'
        'task-rollback-ad', 'next-rollback-package', 'task-rollback-continue', 'task-rollback-package', 'verify-rollback-cloud', 'run-rollback-cloud', 'next-rollback-cloud'
        'task-finalize', 'verify-finalize', 'run-finalize', 'next-finalize', 'task-check', 'verify-check'
        'task-finish', 'run-syncfailed', 'next-syncfailed'
    )
    $keepDark = @('setup', 'run-finished')
    foreach ($name in $keepLight) { Copy-Item -LiteralPath (Join-Path $shots "console-$name-light.png") -Destination (Join-Path $OutputFolder "console-$name-light.png") -Force }
    foreach ($name in $keepDark) { Copy-Item -LiteralPath (Join-Path $shots "console-$name-dark.png") -Destination (Join-Path $OutputFolder "console-$name-dark.png") -Force }
    Write-Host ("  {0} console pictures" -f ($keepLight.Count + $keepDark.Count))
}
#endregion

#region 2. Reports -----------------------------------------------------------------------------------------
if ($all -or $Part -eq 'Reports') {
    Write-Host 'Rendering the reports (synthetic phase data)...'
    $stage = Join-Path $work 'reports'
    . (Join-Path $root 'tests\IntegrityFixture.ps1')
    . (Join-Path $PSScriptRoot 'DocumentationImages\New-PackageCopy.ps1')
    New-DocumentationPackageCopy -Repository $root -Destination (Join-Path $stage 'source')
    $null = New-PraIntegrityFixture -SourcePackage (Join-Path $stage 'source') -Destination (Join-Path $stage 'package') -Changelog (Join-Path $root 'CHANGELOG.md')
    Import-Module (Join-Path $stage 'package\module\PRA.Common.psm1') -Force -Global -WarningAction SilentlyContinue
    $env:USERDOMAIN = 'CONTOSO'; $env:USERNAME = 'pra.operator'
    $names = @('adele.vance', 'alex.wilber', 'diego.siciliani', 'grady.archie', 'finance.shared')
    $guids = @{}; foreach ($n in $names) { $guids[$n] = [guid]::NewGuid().ToString() }
    function New-DocRow($sam, $action, $status, $cloud, $warn = '', $group = 'Added to the licence group') {
        [pscustomobject]@{ ObjectGuid = $guids[$sam]; SamAccountName = $sam; UserPrincipalName = "$sam@contoso.com"; Action = $action; IsShared = ($sam -eq 'finance.shared'); ADApplied = $true; ADVerified = $true
            BackupPath = 'D:\PRA\Backups\Batch-5f2b4d0e\Convert-LAB.json'; CloudStatus = $cloud; CloudDetail = ''; FinalStatus = $status; Detail = ''; Warnings = $warn; LastOperation = ''; GroupAction = $(if ($sam -eq 'finance.shared') { 'N/A' } else { $group })
            CloudMailbox = $(if ($cloud -eq 'Success') { $true } else { $null }); CloudLicense = $(if ($cloud -eq 'Success' -and $sam -ne 'finance.shared') { 'SPE_E3' } else { $null }); PreserveCloudMailbox = $false; PreserveLicense = $false; DeprovisionConfirmed = $false
            PermDetail = $(if ($sam -eq 'finance.shared') { 'FullAccess 3; SendAs 2' } else { '' }); PermMissing = @() }
    }
    function New-DocContext($action, $phase, $rows, $folders, $minutes, $computer, $mode = 'Apply') {
        $env:COMPUTERNAME = $computer
        $c = @{ Root = (Join-Path $stage 'package'); Version = '3.0.0'; RunId = ((Get-Date -Format 'yyyyMMdd_HHmmss') + '-' + [guid]::NewGuid().ToString('N')); StartTime = (Get-Date).AddMinutes($minutes); Action = $action; Mode = $mode; Phase = $phase
            CurrentPhase = 'Start'; CurrentOperation = ''; CurrentIdentity = ''; StepIndex = 0; StepTotal = 0; Warnings = 0; Issues = (New-Object 'Collections.Generic.List[object]'); Rows = (New-Object 'Collections.Generic.List[object]')
            Server = $(if ($phase -eq 'Cloud') { '' } else { 'dc01.contoso.com' }); Config = @{ Environment = 'LAB'; Cloud = @{ Organization = 'contoso.onmicrosoft.com' } }; AllowMutation = $true; ReportFolder = (Join-Path $stage 'reports'); NoReport = $false; BatchId = '5f2b4d0e'
            LogFile = ''; NextSteps = @(); ExitCode = 0; CloudConnectFailed = $false; ResultStatus = ''; PhaseFolders = $folders; ConfigOverrides = @(); WarningList = (New-Object 'Collections.Generic.List[object]') }
        foreach ($r in $rows) { $c.Rows.Add($r) }
        $c
    }
    function Add-DocSteps($c, $title) {
        foreach ($r in $c.Rows) { Register-PraObjectName $c $r.ObjectGuid $r.UserPrincipalName; $c.CurrentIdentity = $r.ObjectGuid; Write-PraStep -Context $c -Title $title 6>$null | Out-Null; Write-PraItem -Context $c -Status Ok -Text 'Done and verified' 6>$null }
    }
    $null = New-Item -ItemType Directory -Path (Join-Path $stage 'reports') -Force
    function Set-DocPhaseEnd($Path, [timespan]$Duration) {
        # Save-PraPhaseData stamps the moment it runs. Synthetic data of a phase that ran earlier: move the end (and the step times, written just before it) to
        # StartedUtc + Duration, then rewrite the .sha256 the way the engine writes it (lower-case hexadecimal digest, UTF-8, no BOM, no line break).
        $invariant = [Globalization.CultureInfo]::InvariantCulture
        $text = [IO.File]::ReadAllText($Path, [Text.UTF8Encoding]::new($false))
        $header = (ConvertFrom-Json $text -DateKind String).Phase
        $started = [datetime]::Parse([string]$header.StartedUtc, $invariant, [Globalization.DateTimeStyles]::RoundtripKind).ToUniversalTime()
        $saved = [datetime]::Parse([string]$header.EndedUtc, $invariant, [Globalization.DateTimeStyles]::RoundtripKind).ToUniversalTime()
        $delta = ($started + $Duration) - $saved
        $builder = New-Object Text.StringBuilder; $position = 0
        foreach ($m in [regex]::Matches($text, '"(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d+)?(?:Z|[+-]\d\d:\d\d))"')) {
            [void]$builder.Append($text, $position, $m.Index - $position); $position = $m.Index + $m.Length
            $value = $m.Groups[1].Value
            if ($value -ceq [string]$header.StartedUtc) { [void]$builder.Append($m.Value) }
            elseif ($value.EndsWith('Z', [StringComparison]::Ordinal)) { [void]$builder.Append('"' + ([datetime]::Parse($value, $invariant, [Globalization.DateTimeStyles]::RoundtripKind).ToUniversalTime() + $delta).ToString('o', $invariant) + '"') }
            else { [void]$builder.Append('"' + ([datetimeoffset]::Parse($value, $invariant) + $delta).ToString('o', $invariant) + '"') }
        }
        [void]$builder.Append($text, $position, $text.Length - $position)
        $text = $builder.ToString()
        $bytes = [Text.UTF8Encoding]::new($false).GetBytes($text)
        [IO.File]::WriteAllBytes($Path, $bytes)
        $sha = [Security.Cryptography.SHA256]::Create()
        try { $digest = ([BitConverter]::ToString($sha.ComputeHash($bytes))).Replace('-', '').ToLowerInvariant() } finally { $sha.Dispose() }
        [IO.File]::WriteAllBytes($Path + '.sha256', [Text.UTF8Encoding]::new($false).GetBytes($digest))
    }
    # One phase, no problem; one phase with a warning (both are what a single server writes).
    $good = New-DocContext Convert Both @(foreach ($n in $names) { New-DocRow $n 'Convert' 'Success' 'Success' }) @() -42 'SRV-PRA01'
    $good.NextSteps = @('To roll back this batch later: .\Invoke-PraRemoteMailbox.ps1 -Action Recover -Mode Preview -Batch 5f2b4d0e')
    $warn = New-DocContext Convert Both @(foreach ($n in $names) { New-DocRow $n 'Convert' 'Success' 'Success' $(if ($n -eq 'finance.shared') { 'Forwarding to an outside address is kept' } else { '' }) }) @() -42 'SRV-PRA01'
    $warn.Warnings = 1
    $warn.WarningList.Add([pscustomobject]@{ Timestamp = (Get-Date).ToString('o'); Phase = 'Targets'; Message = 'finance.shared: forwarding to an outside address is kept.' })
    $pages = [ordered]@{}
    foreach ($entry in @(@('phase', $good), @('phase-warning', $warn))) {
        $reports = @{ Csv = (Join-Path $stage "$($entry[0]).csv"); Html = (Join-Path $stage "$($entry[0]).html") }
        & (Get-Module PRA.Common) { param($c, $r) Write-PraReport -Context $c -Reports $r } $entry[1] $reports
        $pages["report-$($entry[0])-light"] = $reports.Html
    }

    # The global report of a Convert across two servers: AD, then Cloud.
    $packageFolder = Join-Path $stage 'Batch-feed0001'; $null = New-Item -ItemType Directory $packageFolder -Force
    $ad = New-DocContext Convert AD @(foreach ($n in $names) { New-DocRow $n 'Convert' 'Pending' 'N/A' $(if ($n -eq 'finance.shared') { 'Forwarding to an outside address is kept' } else { '' }) }) @() -50 'SRV-AD01'
    Add-DocSteps $ad 'Backup and Active Directory changes'
    Set-DocPhaseEnd (Save-PraPhaseData -Context $ad -Folder $packageFolder -HandOff 'Convert') ([timespan]::FromSeconds(702))
    $cloud = New-DocContext Convert Cloud @(foreach ($n in $names) { New-DocRow $n 'Convert' 'Success' 'Success' }) @($packageFolder) -22 'SRV-CLOUD01'
    Add-DocSteps $cloud 'Exchange Online: mailboxes, licences and permissions'
    $globalConvert = & (Get-Module PRA.Common) { param($c) Write-PraGlobalReport -Context $c } $cloud
    $pages['report-global-light'] = $globalConvert.Html

    # The global report of a Recover across two servers: AD, Cloud, Finalize.
    $recover = Join-Path $stage 'Batch-feed0002'; $final = Join-Path $stage 'Finalize-aaaa0003'; $null = New-Item -ItemType Directory $recover, $final -Force
    $rad = New-DocContext Recover AD @((New-DocRow 'adele.vance' 'Recover' 'Success' 'N/A'), (New-DocRow 'alex.wilber' 'Recover' 'Success' 'N/A'), (New-DocRow 'diego.siciliani' 'Recover' 'Success' 'N/A' 'Forwarding to an outside address was restored'), (New-DocRow 'grady.archie' 'Recover' 'Pending' 'N/A'), (New-DocRow 'finance.shared' 'Recover' 'Pending' 'N/A')) @() -75 'SRV-AD01'
    Add-DocSteps $rad 'Backup and Active Directory changes'
    Set-DocPhaseEnd (Save-PraPhaseData -Context $rad -Folder $recover -HandOff 'Recover') ([timespan]::FromSeconds(618))
    $rcloud = New-DocContext Recover Cloud @((New-DocRow 'adele.vance' 'Recover' 'Success' 'Success'), (New-DocRow 'alex.wilber' 'Recover' 'Success' 'Success'), (New-DocRow 'diego.siciliani' 'Recover' 'Success' 'Success'), (New-DocRow 'finance.shared' 'Recover' 'Pending' 'Success')) @($recover) -40 'SRV-CLOUD01'
    Add-DocSteps $rcloud 'Exchange Online: deprovisioning checks'
    $null = Copy-PraPhaseData -SourceFolder @($recover) -Destination $final
    Set-DocPhaseEnd (Save-PraPhaseData -Context $rcloud -Folder $final -HandOff 'Finalize') ([timespan]::FromSeconds(876))
    $rfin = New-DocContext Finalize Finalize @((New-DocRow 'finance.shared' 'Recover' 'Success' 'N/A')) @($final) -5 'SRV-AD01'
    Add-DocSteps $rfin 'Backup and Active Directory changes'
    $globalRecover = & (Get-Module PRA.Common) { param($c) Write-PraGlobalReport -Context $c } $rfin
    $pages['report-global-recover-light'] = $globalRecover.Html

    foreach ($name in $pages.Keys) {
        # Measure the page, then photograph it at its own height.
        $page = Join-Path $work "$name.html"
        $source = [IO.File]::ReadAllText($pages[$name])
        $probe = "<script>window.addEventListener('load',function(){setTimeout(function(){var b=0;Array.prototype.forEach.call(document.body.children,function(e){if(e.tagName!=='SCRIPT'&&e.tagName!=='STYLE'){b=Math.max(b,e.getBoundingClientRect().bottom+window.scrollY)}});document.body.setAttribute('data-h',Math.ceil(b)+24)},600)});</script></body>"
        $index = $source.LastIndexOf('</body>')
        $source = $source.Substring(0, $index) + $probe + $source.Substring($index + 7)
        [IO.File]::WriteAllText($page, $source, [Text.UTF8Encoding]::new($true))
        $height = Get-PageHeight $page 1400
        Save-Screenshot $page (Join-Path $OutputFolder "$name.png") 1400 ([Math]::Min($height + 10, 3000)) 1
        Write-Host "  $name"
    }
}
#endregion

#region 3. Diagrams ----------------------------------------------------------------------------------------
if ($all -or $Part -eq 'Diagrams') {
    Write-Host 'Rendering the README and guide graphics (light and dark, 2x)...'
    & (Join-Path $PSScriptRoot 'Build-Documentation.ps1') | Out-Null
    & (Join-Path $PSScriptRoot 'New-ReadmeImages.ps1') -OutputFolder $OutputFolder
    function ConvertTo-ReadmeInline([string]$Text) {
        $h = [Net.WebUtility]::HtmlEncode($Text.Trim())
        $h = [regex]::Replace($h, '`([^`]+)`', '<code>$1</code>')
        $h = [regex]::Replace($h, '\*\*([^*]+)\*\*', '<strong>$1</strong>')
        return [regex]::Replace($h, '(?<![\w*])\*([^*\s][^*]*)\*(?![\w*])', '<em>$1</em>')
    }
    function Get-ReadmeAssets {
        $builder = Join-Path $root 'tools\Build-Documentation.ps1'
        $guideHtml = Join-Path $root 'package\docs\PraRemoteMailbox-Guide.html'
        $guideMd = Join-Path $root 'package\docs\PraRemoteMailbox-Guide.md'
        $ast = [Management.Automation.Language.Parser]::ParseFile($builder, [ref]$null, [ref]$null)
        $assign = $ast.Find({ param($n) $n -is [Management.Automation.Language.AssignmentStatementAst] -and $n.Left.Extent.Text -eq '$Icons' }, $true)
        if (-not $assign) { throw "Icon table not found in $builder." }
        $md = [IO.File]::ReadAllText($guideMd) -replace "`r`n", "`n"
        $blocks = foreach ($m in [regex]::Matches($md, '(?s)```(flow|cards)\n(.*?)\n```')) {
            $lines = @($m.Groups[2].Value -split "`n" | Where-Object { $_.Trim() })
            [pscustomobject]@{ Kind = $m.Groups[1].Value; Lines = $lines; First = $lines[0].Split('|')[1].Trim() }
        }
        $userHtml = Join-Path $root 'package\docs\PraRemoteMailbox-UserGuide.html'
        $path = [regex]::Match([IO.File]::ReadAllText($userHtml), '(?s)<!--path-->(.*?)<!--/path-->').Groups[1].Value
        [pscustomobject]@{
            Path = $path
            Icons = & ([scriptblock]::Create($assign.Right.Extent.Text))
            Css = [regex]::Match([IO.File]::ReadAllText($guideHtml), '(?s)<style>(.*?)</style>').Groups[1].Value
            Version = [regex]::Match($md, '(?m)^version:\s*(\S+)').Groups[1].Value
            Blocks = @($blocks)
        }
    }
    function Get-GuideBlock([string]$Kind, [string]$FirstTitle) {
        $block = $assets.Blocks | Where-Object { $_.Kind -eq $Kind -and $_.First -eq $FirstTitle } | Select-Object -First 1
        if (-not $block) { throw "Guide block not found: $Kind starting with '$FirstTitle' (package\docs\PraRemoteMailbox-Guide.md)." }
        return $block.Lines
    }
    function Get-ReadmeIcon([string]$Name, [string]$Class = 'icon') {
        $iconPath = $assets.Icons[$Name]; if (-not $iconPath) { $iconPath = $assets.Icons['info'] }
        "<svg class=""$Class"" viewBox=""0 0 24 24"" fill=""none"" stroke=""currentColor"" stroke-width=""1.7"" stroke-linecap=""round"" stroke-linejoin=""round"">$iconPath</svg>"
    }
    function ConvertTo-ReadmeFlow([string[]]$Lines, [switch]$Vertical) {
        $items = foreach ($l in $Lines) {
            $icon, $title, $sub = $l.Split('|', 3).ForEach({ $_.Trim() })
            $title = [Net.WebUtility]::HtmlEncode($title); $sub = ConvertTo-ReadmeInline $sub
            if ($Vertical) {
                if ($icon -eq 'arrow') {
                    $note = if ($sub) { "<span class=""flow-sub"">$sub</span>" } else { '' }
                    "<div class=""rb-varrow""><svg viewBox=""0 0 12 30""><path d=""M6 1v26M1 21l5 6 5-6"" fill=""none"" stroke=""currentColor"" stroke-width=""1.6""/></svg><span class=""flow-label"">$title</span>$note</div>"
                } else {
                    "<div class=""rb-vnode""><div class=""flow-icon"">$(Get-ReadmeIcon $icon)</div><div><div class=""flow-title"">$title</div><div class=""flow-text"">$sub</div></div></div>"
                }
            } elseif ($icon -eq 'arrow') {
                "<div class=""flow-arrow""><span class=""flow-label"">$title</span><svg viewBox=""0 0 40 12""><path d=""M0 6h36M31 1l6 5-6 5"" fill=""none"" stroke=""currentColor"" stroke-width=""1.6""/></svg><span class=""flow-sub"">$sub</span></div>"
            } else {
                "<div class=""flow-node""><div class=""flow-icon"">$(Get-ReadmeIcon $icon)</div><div class=""flow-title"">$title</div><div class=""flow-text"">$sub</div></div>"
            }
        }
        $class = if ($Vertical) { 'flow rb-vflow' } else { 'flow rb-flow' }
        "<div class=""$class"">$($items -join '')</div>"
    }
    function ConvertTo-ReadmeCards([string[]]$Lines, [string]$Class = '') {
        $items = foreach ($l in $Lines) {
            $icon, $title, $text = $l.Split('|', 3).ForEach({ $_.Trim() })
            "<div class=""card-item""><div class=""card-icon"">$(Get-ReadmeIcon $icon)</div><div><div class=""card-title"">$(ConvertTo-ReadmeInline $title)</div><div class=""card-text"">$(ConvertTo-ReadmeInline $text)</div></div></div>"
        }
        "<div class=""cards $Class"">$($items -join '')</div>"
    }
    function Get-ReadmePill([string]$Text, [string]$Tone) { "<span class=""rb-pill"" style=""--tone: var(--cp-$Tone)"">$Text</span>" }
    $Script:ReadmeCss = @'
html, body { background: #ffffff; }
html[data-theme="dark"], html[data-theme="dark"] body { background: #0d1117; }
:root { --cp-info: #0078d4; --cp-violet: #7c3aed; --cp-teal: #0d9488; }
html[data-theme="dark"] { --cp-info: #4da6ff; --cp-violet: #a78bfa; --cp-teal: #2dd4bf; }
body { display: block; margin: 0; padding: 0; }
.canvas { padding: 6px; }
.rb-pill { display: inline-block; padding: 1px 10px; margin: 8px 6px 0 0; border-radius: 999px; font-size: 11.5px; font-weight: 600; line-height: 1.6;
  color: var(--tone); background: color-mix(in srgb, var(--tone) 11%, transparent); border: 1px solid color-mix(in srgb, var(--tone) 38%, transparent); }
.rb-caption { font-size: 11.5px; font-weight: 700; letter-spacing: 0.1em; text-transform: uppercase; color: var(--cp-accent); margin: 0 0 8px 4px; }
.rb-caption span { color: var(--cp-text-muted); font-weight: 600; letter-spacing: 0.04em; text-transform: none; font-size: 12.5px; }
.cards { margin: 0; }
.cards.rb-cards2 { grid-template-columns: 1fr 1fr; }
.cards.rb-cards3 { grid-template-columns: 1fr 1fr 1fr; }
.rb-cards3 .card-item { flex-direction: column; }
.card-title { font-size: 16px; } .card-text { font-size: 14.5px; }
.rb-flow { margin: 0; flex-wrap: nowrap; padding: 18px; gap: 4px; }
.rb-flow .flow-node { flex: 1 1 0; min-width: 0; padding: 14px 10px; }
.rb-flow .flow-title { font-size: 14px; overflow-wrap: anywhere; }
.rb-flow .flow-arrow { min-width: 0; width: 100px; flex: 0 0 100px; }
.rb-flow .flow-sub { max-width: 100px; }
.rb-space { height: 18px; }
.rb-hiw { display: grid; grid-template-columns: minmax(0, 1.08fr) minmax(0, 1fr); gap: 16px; align-items: stretch; }
.rb-col { display: flex; flex-direction: column; }
.rb-vflow { flex: 1; flex-direction: column; flex-wrap: nowrap; align-items: stretch; justify-content: center; gap: 0; margin: 0; padding: 16px 18px; }
.rb-vnode { display: flex; align-items: center; gap: 14px; padding: 11px 16px; border-radius: 12px; background: var(--cp-surface); border: 1px solid var(--cp-border); }
.rb-vnode .flow-icon { margin: 0; flex-shrink: 0; }
.rb-vnode .flow-text { margin-top: 1px; }
.rb-varrow { display: flex; align-items: center; gap: 10px; min-height: 36px; padding-left: 31px; }
.rb-varrow svg { width: 12px; height: 28px; color: var(--cp-accent); flex-shrink: 0; }
.rb-varrow .flow-sub { max-width: none; font-size: 12px; }
.rb-modes { flex: 1; display: flex; flex-direction: column; gap: 10px; }
.rb-modes .card-item { flex: 1; align-items: center; }
.rb-modes .card-title { display: flex; align-items: center; gap: 8px; }
.rb-chip { font-size: 11px; font-weight: 600; padding: 0 8px; border-radius: 999px; border: 1px solid var(--cp-border); color: var(--cp-text-muted); }
.rb-chip.hot { color: var(--cp-accent-fg); background: var(--cp-accent); border-color: var(--cp-accent); }
'@
    function New-ReadmeGraphic {
        param([string]$Name, [string]$Body, [int]$Width = 1080, [switch]$LightOnly, [string]$Prefix = 'readme')
        $pages = @{}
        $themes = if ($LightOnly) { @('light') } else { @('light', 'dark') }
        foreach ($theme in $themes) {
            $html = "<!doctype html><html lang=""en"" data-theme=""$theme""><head><meta charset=""utf-8""><style>$($assets.Css)`n$($Script:ReadmeCss)</style></head>" +
                "<body><div class=""canvas"" style=""width:$($Width)px"">$Body</div><script>document.body.setAttribute('data-h', Math.ceil(document.querySelector('.canvas').getBoundingClientRect().height));</script></body></html>"
            $pages[$theme] = Join-Path $work "$Prefix-$Name-$theme.html"
            [IO.File]::WriteAllText($pages[$theme], $html, [Text.UTF8Encoding]::new($false))
        }
        $height = Get-PageHeight $pages['light'] $Width
        foreach ($theme in $themes) { Save-Screenshot $pages[$theme] (Join-Path $OutputFolder "$Prefix-$Name-$theme.png") $Width $height 2 }
        Write-Host "  $Prefix-$Name ($($themes -join ', '))"
    }
    $Script:assets = Get-ReadmeAssets
    $mid = '&middot;'

    # Why: the three ideas, in everyday words.
    New-ReadmeGraphic -Name 'why' -Body (ConvertTo-ReadmeCards @(
            'server | 1 · The problem | The mail servers of the company are lost. Nobody can read or send mail.'
            'cloud | 2 · The help | The tool gives each person a **new, empty mailbox in the cloud**. Mail works again the same day.'
            'refresh | 3 · The way back | When the old servers work again, the tool **puts everything back** as the backup says.'
        ) 'rb-cards3')

    # The guided path of the user guide.
    if (-not $assets.Path) { throw 'Guided path not found in package\docs\PraRemoteMailbox-UserGuide.html.' }
    New-ReadmeGraphic -Name 'path' -Body $assets.Path

    # How it works: the pipeline (vertical) and the four actions.
    $actions = @(
        [pscustomobject]@{ Icon = 'target'; Name = 'Convert'; Chip = '<span class="rb-chip hot">changes</span>'; Text = 'Gives every person a mailbox in Exchange Online. A preview first, a backup, then the change.'; Pills = (Get-ReadmePill 'Planned' 'info') + (Get-ReadmePill 'Success' 'success') + (Get-ReadmePill 'Pending' 'warning') + (Get-ReadmePill 'Error' 'danger') }
        [pscustomobject]@{ Icon = 'refresh'; Name = 'Recover'; Chip = '<span class="rb-chip hot">changes</span>'; Text = 'Rolls a Convert back from its backup. The cloud shared mailboxes go first.'; Pills = (Get-ReadmePill 'Planned' 'info') + (Get-ReadmePill 'Success' 'success') + (Get-ReadmePill 'Pending' 'warning') }
        [pscustomobject]@{ Icon = 'batch'; Name = 'Finalize'; Chip = '<span class="rb-chip hot">changes</span>'; Text = 'The last step of a Recover on two servers, on the directory server.'; Pills = (Get-ReadmePill 'Success' 'success') }
        [pscustomobject]@{ Icon = 'search'; Name = 'Check'; Chip = '<span class="rb-chip">read only</span>'; Text = 'Is a mailbox in the cloud, gone from the cloud, or kept? Nothing is written.'; Pills = (Get-ReadmePill 'Success' 'success') + (Get-ReadmePill 'Pending' 'warning') }
    )
    $actionHtml = ($actions | ForEach-Object { "<div class=""card-item""><div class=""card-icon"">$(Get-ReadmeIcon $_.Icon)</div><div><div class=""card-title"">$($_.Name) $($_.Chip)</div><div class=""card-text"">$($_.Text)</div><div>$($_.Pills)</div></div></div>" }) -join ''
    $pipeline = ConvertTo-ReadmeFlow @(
        'settings | Settings file | `PraRemoteMailbox.config.psd1`: the people, the groups, the servers'
        'arrow | read by |'
        'terminal | Console or command | `Invoke-PraRemoteMailbox.ps1 -Gui`, or `-Action`, `-Mode`, `-Batch`'
        'arrow | backs up, then writes | one batch at a time'
        'directory | Active Directory | about ten Exchange attributes per person, the licence group'
        'arrow | synchronises | one Entra Connect cycle'
        'cloud | Exchange Online | mailboxes, licences, shared mailbox access'
        'arrow | writes |'
        'chart | Batch and reports | `Backups\Batch-<id>`, log, CSV, HTML report'
    ) -Vertical
    New-ReadmeGraphic -Name 'how' -Body ("<div class=""rb-hiw""><div class=""rb-col""><div class=""rb-caption"">One tool <span>$mid from the settings to the reports</span></div>$pipeline</div>" +
        "<div class=""rb-col""><div class=""rb-caption"">Four actions <span>$mid Preview by default, Apply on demand</span></div><div class=""rb-modes"">$actionHtml</div></div></div>")

    # Convert and Recover, from the flow blocks of the reference guide.
    New-ReadmeGraphic -Name 'flows' -Body ("<div class=""rb-caption"">Convert <span>$mid on one server</span></div>" + (ConvertTo-ReadmeFlow (Get-GuideBlock 'flow' 'Read AD')) +
        "<div class=""rb-space""></div><div class=""rb-caption"">Recover <span>$mid the way back, from the Convert batch</span></div>" + (ConvertTo-ReadmeFlow (Get-GuideBlock 'flow' 'Convert batch')))

    # Two servers: a zip file and its .sha256 file travel.
    New-ReadmeGraphic -Name 'transfer' -Body ("<div class=""rb-caption"">Move the mailboxes <span>$mid two servers, two files to copy</span></div>" + (ConvertTo-ReadmeFlow @(
                'directory | AD server | Move mailboxes, Phase AD'
                'arrow | writes | a zip and its .sha256'
                'folder | Transfer package | `PRA-LAB-Convert-490cc62e-for-Cloud.zip` + `.zip.sha256`'
                'arrow | you carry it | USB key, shared folder'
                'cloud | Cloud server | Continue a batch, Import package'
                'arrow | writes |'
                'chart | Global report | every person, end to end'
            )) + "<div class=""rb-space""></div><div class=""rb-caption"">Go back <span>$mid three parts, two packages</span></div>" + (ConvertTo-ReadmeFlow @(
                'directory | AD server | Roll back a conversion'
                'arrow | Recover package |'
                'cloud | Cloud server | Continue a rollback'
                'arrow | Finalize package |'
                'directory | AD server | Complete a rollback'
                'arrow | writes |'
                'chart | Global report | done'
            )))

    # The rights to ask the administrator for.
    New-ReadmeGraphic -Name 'rights' -Body (ConvertTo-ReadmeCards @(
            'directory | Active Directory | **Change** the Exchange attributes of the people to move and the **licence group**. **Read** the people and their security lists.'
            'layers | Entra Connect server | Member of **ADSyncOperators**. A remote connection (WinRM) if the tool runs on another server.'
            'people | Microsoft 365 (Graph) | **User.Read.All**, accepted once by an administrator. A role that can read users, for example Global Reader.'
            'mail | Exchange Online | Role **Exchange Recipient Administrator**. Without a person: an application with **Exchange.ManageAsApp** and a certificate.'
        ) 'rb-cards2')

    # The four principles.
    New-ReadmeGraphic -Name 'principles' -Body (ConvertTo-ReadmeCards @(
            'shield | Backup before every change | Every value is saved and read back before the first write.'
            'search | Preview first | Without Apply the tool only reads. Apply asks you to confirm.'
            'check | Stop at the first error | Nothing goes on after an error. Nothing is guessed.'
            'refresh | Always reversible | A Recover puts every saved value back.'
        ) 'rb-cards2')

    # Shared mailbox permissions.
    New-ReadmeGraphic -Name 'permissions' -Body ("<div class=""rb-caption"">Shared mailbox access <span>$mid read in Active Directory, because Exchange on-premises is down</span></div>" + (ConvertTo-ReadmeCards @(
                'key | Full access | Read and manage the mailbox. Read from `msExchMailboxSecurityDescriptor`. Granted by `Add-MailboxPermission`.'
                'mail | Send as | Send mail as the shared mailbox. Read from the Send As right of the account. Granted by `Add-RecipientPermission`.'
                'people | Send on behalf | Send mail on behalf of the shared mailbox. Read from `publicDelegates`. Granted by `Set-Mailbox`.'
            ) 'rb-cards3') + "<div class=""rb-space""></div>" + (ConvertTo-ReadmeFlow @(
                'directory | Read in AD | groups become users'
                'arrow | saved |'
                'batch | In the batch | with its backup'
                'arrow | checked |'
                'cloud | Exchange Online | every holder found'
                'arrow | granted once |'
                'check | Read again | proof of the grant'
            )))

    # The picture dictionary of the user guide (light only).
    New-ReadmeGraphic -Name 'dictionary' -Prefix 'guide' -LightOnly -Body (ConvertTo-ReadmeCards @(
            'mail | Mailbox | The box where the mail of one person is kept.'
            'directory | Active Directory | The company address book on the servers.'
            'cloud | Exchange Online | The mail system in the cloud.'
            'refresh | Sync | One trip that tells the cloud what changed.'
            'shield | Backup | The copy of every value before a change.'
            'folder | Transfer package | One zip file and its .sha256 file between two servers. The tool names them.'
            'chart | Report | The web page that says what was done.'
            'search | Preview | A trial that changes nothing.'
            'batch | Batch | One move of many people, with its short ID.'
            'server | Directory server | The server that reaches Active Directory.'
            'terminal | Cloud server | A machine of your company that reaches Microsoft 365. It is not in the cloud.'
            'layers | Phase | One part of the work: AD, Cloud or Both. A pink pill on the Task page.'
        ) 'rb-cards3')
}
#endregion

if ($all) { & (Join-Path $PSScriptRoot 'Build-Documentation.ps1') | Out-Null }
Get-ChildItem $OutputFolder -Filter '*.png' | Select-Object Name, @{ n = 'KB'; e = { [math]::Round($_.Length / 1KB) } } | Format-Table -AutoSize | Out-String | Write-Host
# Edge helper processes of the temporary profile, if any are left.
Get-CimInstance Win32_Process -Filter "Name='msedge.exe'" | Where-Object { $_.CommandLine -like "*$work*" } | ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }
if ($KeepWork) { Write-Host "Work folder: $work" } else { Remove-Item $work -Recurse -Force -ErrorAction SilentlyContinue }
