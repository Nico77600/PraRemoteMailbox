#Requires -Version 7.4
<#
.SYNOPSIS
    Renders the README banner in light and dark themes using the existing guide assets.
.DESCRIPTION
    Reads the version from Invoke-PraRemoteMailbox.ps1 and requires the guide version to agree.
    Uses the guide's CSS and icon table, with the Purview README banner layout.
    Runs Microsoft Edge locally; no Exchange, tenant or lab connection is made.
.PARAMETER OutputFolder
    Defaults to docs\images. Only readme-banner-light.png and readme-banner-dark.png are written.
.NOTES
    Author: Nicolas Fabert
    Repository documentation tool; not included in the runtime package.
#>
[CmdletBinding()]
param([string]$OutputFolder)

$ErrorActionPreference = 'Stop'
$root = Split-Path $PSScriptRoot -Parent
if (-not $OutputFolder) { $OutputFolder = Join-Path $root 'docs\images' }
$OutputFolder = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($OutputFolder)
$runtime = [IO.File]::ReadAllText((Join-Path $root 'Invoke-PraRemoteMailbox.ps1'))
$versions = [regex]::Matches($runtime, '(?m)^\s*Version\s*:\s*(\d+\.\d+\.\d+)\s*$')
if ($versions.Count -ne 1) { throw 'A unique runtime version was not found in Invoke-PraRemoteMailbox.ps1.' }
$version = $versions[0].Groups[1].Value
$guide = [IO.File]::ReadAllText((Join-Path $root 'docs\PraRemoteMailbox-Guide.md'))
$guideVersion = [regex]::Match($guide, '(?m)^version:\s*(\S+)').Groups[1].Value
if ($guideVersion -ne $version) { throw "Guide version $guideVersion differs from runtime version $version." }

$builder = Join-Path $root 'tools\Build-Documentation.ps1'
$tokens = $null
$errors = $null
$ast = [Management.Automation.Language.Parser]::ParseFile($builder, [ref]$tokens, [ref]$errors)
if ($errors.Count) { throw "Cannot parse the icon source: $builder" }
$assignment = $ast.Find({ param($node)
    $node -is [Management.Automation.Language.AssignmentStatementAst] -and $node.Left.Extent.Text -eq '$Icons'
}, $true)
if (-not $assignment) { throw "Icon table not found: $builder" }
$table = $assignment.Right.Find({ param($node) $node -is [Management.Automation.Language.HashtableAst] }, $true)
if (-not $table) { throw "Literal icon table not found: $builder" }
$icons = $table.SafeGetValue()
function Get-ReadmeIcon([string]$Name, [string]$Class = 'icon') {
    if (-not $icons.ContainsKey($Name)) { throw "Unknown guide icon: $Name" }
    "<svg class=""$Class"" viewBox=""0 0 24 24"" fill=""none"" stroke=""currentColor"" stroke-width=""1.7"" stroke-linecap=""round"" stroke-linejoin=""round"">$($icons[$Name])</svg>"
}
$guideHtml = [IO.File]::ReadAllText((Join-Path $root 'docs\PraRemoteMailbox-Guide.html'))
$css = [regex]::Match($guideHtml, '(?s)<style>(.*?)</style>').Groups[1].Value
if (-not $css) { throw 'Guide CSS was not found. Build the HTML guide first.' }
$css += @'
html, body { background: #ffffff; }
html[data-theme="dark"], html[data-theme="dark"] body { background: #0d1117; }
body { display: block; margin: 0; padding: 0; }
.canvas { padding: 6px; }
.rb-hero { margin: 0; padding: 32px 36px 30px; }
.rb-hero-grid { position: relative; display: grid; grid-template-columns: minmax(0, 1fr) 270px; gap: 34px; align-items: center; }
.rb-hero h1 { font-size: 35px; }
.rb-hero .lead { margin: 18px 0 0; font-size: 17px; max-width: none; }
.rb-hero .badges { margin: 20px 0 0; }
.rb-stats { position: relative; display: grid; gap: 10px; }
.rb-stat { display: flex; align-items: center; gap: 14px; padding: 12px 16px; border-radius: 14px; background: var(--cp-panel-strong); border: 1px solid var(--cp-border); box-shadow: 0 1px 2px rgba(0, 0, 0, 0.08); }
.rb-stat b { font-size: 30px; line-height: 1; color: var(--cp-accent); font-weight: 750; min-width: 40px; text-align: center; }
.rb-stat span { font-size: 13px; color: var(--cp-text-muted); line-height: 1.35; }
.rb-stat strong { display: block; color: var(--cp-text); font-size: 14px; }
'@
$badges = @(
    "<span class=""badge badge-accent"">Version $version</span>"
    "<span class=""badge"">$(Get-ReadmeIcon 'terminal' 'icon-sm')Windows PowerShell 5.1</span>"
    "<span class=""badge"">$(Get-ReadmeIcon 'shield' 'icon-sm')Backup before every change</span>"
    "<span class=""badge"">$(Get-ReadmeIcon 'tag' 'icon-sm')MIT license</span>"
) -join ''
$banner = "<header class=""hero rb-hero""><div class=""rb-hero-grid""><div>" +
    "<div class=""hero-top""><div class=""hero-logo"">$(Get-ReadmeIcon 'lifebuoy')</div><div><div class=""eyebrow"">Hybrid Exchange &middot; disaster recovery</div><h1>PRA Remote Mailbox</h1></div></div>" +
    "<p class=""lead"">When the on-premises <strong>Exchange servers are lost</strong>, gives every user a mailbox in <strong>Exchange Online</strong> &mdash; users and shared mailboxes, with their permissions &mdash; and <strong>rolls everything back</strong> when Exchange is available again.</p>" +
    "<div class=""badges"">$badges</div></div><div class=""rb-stats"">" +
    "<div class=""rb-stat""><b>4</b><span><strong>actions</strong>Convert, Recover, Finalize, Check</span></div>" +
    "<div class=""rb-stat""><b>1</b><span><strong>batch ID</strong>links every step, prints the next command</span></div>" +
    "<div class=""rb-stat""><b>0</b><span><strong>writes before the backup</strong>written, hashed and re-read first</span></div>" +
    "</div></div></header>"
$edge = @("${env:ProgramFiles(x86)}\Microsoft\Edge\Application\msedge.exe", "$env:ProgramFiles\Microsoft\Edge\Application\msedge.exe") |
    Where-Object { Test-Path -LiteralPath $_ } | Select-Object -First 1
if (-not $edge) { throw 'Microsoft Edge was not found.' }
$work = Join-Path ([IO.Path]::GetTempPath()) ('pra-readme-' + [guid]::NewGuid().ToString('N'))
[void][IO.Directory]::CreateDirectory($work)
[void][IO.Directory]::CreateDirectory($OutputFolder)
try {
    foreach ($theme in 'light', 'dark') {
        $page = Join-Path $work "banner-$theme.html"
        $dom = Join-Path $work "dom-$theme.html"
        $png = Join-Path $work "readme-banner-$theme.png"
        $html = "<!doctype html><html lang=""en"" data-theme=""$theme""><head><meta charset=""utf-8""><style>$css</style></head><body><div class=""canvas"" style=""width:1000px"">$banner</div><script>document.body.setAttribute('data-h', Math.ceil(document.querySelector('.canvas').getBoundingClientRect().height));</script></body></html>"
        [IO.File]::WriteAllText($page, $html, [Text.UTF8Encoding]::new($false))
        $url = [Uri]::new($page).AbsoluteUri
        $common = @('--headless=new', '--disable-gpu', '--hide-scrollbars', '--no-first-run')
        $process = Start-Process -FilePath $edge -ArgumentList ($common + @("--user-data-dir=`"$(Join-Path $work "edge-measure-$theme")`"", '--window-size=1000,2000', '--dump-dom', "`"$url`"")) -PassThru -WindowStyle Hidden -RedirectStandardOutput $dom
        # Edge helpers can retain the redirected output handle and keep the parent alive.
        $height = $null
        $deadline = (Get-Date).AddSeconds(45)
        while (-not ($height -and $height.Success) -and (Get-Date) -lt $deadline) {
            if (Test-Path -LiteralPath $dom -PathType Leaf) {
                $stream = [IO.File]::Open($dom, 'Open', 'Read', 'ReadWrite')
                $reader = [IO.StreamReader]::new($stream)
                try { $text = $reader.ReadToEnd() } finally { $reader.Dispose() }
                $height = [regex]::Match($text, 'data-h="(\d+)"')
            }
            if (-not ($height -and $height.Success)) { Start-Sleep -Milliseconds 250 }
        }
        if (-not $process.WaitForExit(1000)) { Stop-Process -Id $process.Id -Force }
        if (-not $height.Success) { throw "Height was not measured for the $theme banner." }
        $process = Start-Process -FilePath $edge -ArgumentList ($common + @("--user-data-dir=`"$(Join-Path $work "edge-capture-$theme")`"", "--window-size=1000,$($height.Groups[1].Value)", '--force-device-scale-factor=2', "--screenshot=`"$png`"", "`"$url`"")) -PassThru -WindowStyle Hidden
        $deadline = (Get-Date).AddSeconds(45)
        while (-not (Test-Path -LiteralPath $png -PathType Leaf) -and (Get-Date) -lt $deadline) { Start-Sleep -Milliseconds 250 }
        if (-not $process.WaitForExit(1000)) { Stop-Process -Id $process.Id -Force }
        if (-not (Test-Path -LiteralPath $png -PathType Leaf)) { throw "Edge failed to write the $theme banner." }
    }
    foreach ($theme in 'light', 'dark') {
        Copy-Item -LiteralPath (Join-Path $work "readme-banner-$theme.png") -Destination (Join-Path $OutputFolder "readme-banner-$theme.png") -Force
    }
} finally {
    # Only stop Edge processes belonging to this unique capture profile before removing it.
    $owned = @(Get-CimInstance Win32_Process -Filter "Name='msedge.exe'" |
        Where-Object { $_.CommandLine -and $_.CommandLine.Contains($work) })
    foreach ($item in $owned) {
        $current = Get-Process -Id $item.ProcessId -ErrorAction SilentlyContinue
        if ($current -and -not $current.HasExited) {
            Stop-Process -Id $item.ProcessId -Force
            if (-not $current.WaitForExit(5000)) { throw "The capture process $($item.ProcessId) did not stop." }
        }
    }
    Remove-Item -LiteralPath $work -Recurse -Force
}
