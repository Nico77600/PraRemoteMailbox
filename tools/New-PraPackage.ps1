#Requires -Version 5.1
<#
.SYNOPSIS
    Copies the files needed to run PRA Remote Mailbox into a separate folder, ready to be zipped.

.DESCRIPTION
    The runtime lives in the package\ folder of the repository; the package keeps the same paths as the folder
    that is extracted from the release ZIP (Invoke-PraRemoteMailbox.ps1 at its root, module\, config\,
    templates\, docs\). The distribution contains only what Invoke-PraRemoteMailbox.ps1 needs at run time,
    plus the guide:
        Invoke-PraRemoteMailbox.ps1, PackageIntegrity.psd1, README.md, LICENSE, CHANGELOG.md (copied from the
        repository root), module\ (modules, GUI, verifier and XAML), templates\, config\ (configuration and
        CSV samples), docs\PraRemoteMailbox-Guide.html and .md (with images)
    It never copies Backups\, logs\, reports\, tests\ or tools\: backups hold AD values of real objects.

    The package source and the finished package must pass the owner-signed integrity check
    (module\Test-PackageIntegrity.ps1 and PackageIntegrity.psd1: exact SHA256 of every stable file). A source
    that is unsigned or changed is refused before anything is written: there is no unsigned mode.

    The configuration file is copied with the environment values emptied (DomainController,
    SearchBase, GroupDN, CsvPath, RoutingDomain, Licensing.GroupDN, EntraConnect.Server, TenantId,
    Organization, AppId, CertificateThumbprint, UserPrincipalName): the administrator fills them in
    (guide, chapter 6). The script then checks that none of these values appears in the package. The
    configuration is data outside the integrity manifest.

.PARAMETER Destination
    Package folder. Default: package\PraRemoteMailbox-<version>, next to the repository folder.

.PARAMETER Force
    Replace the destination folder if it already contains a package. A folder that contains a
    Backups sub-folder (a package that has been used) is never replaced.

.EXAMPLE
    .\tools\New-PraPackage.ps1
    Creates ..\package\PraRemoteMailbox-2.2.0.

.NOTES
    Author  : Nicolas Fabert
    Version : 2.2.0
#>
[CmdletBinding()]
param(
    [string]$Destination,
    [switch]$Force
)

$ErrorActionPreference = 'Stop'
$root = Split-Path $PSScriptRoot -Parent
$packageRoot = Join-Path $root 'package'
$entry = Join-Path $packageRoot 'Invoke-PraRemoteMailbox.ps1'
$version = ([regex]::Match([IO.File]::ReadAllText($entry), "Version = '([0-9.]+)'")).Groups[1].Value
if (-not $version) { throw 'Version not found in package\Invoke-PraRemoteMailbox.ps1.' }

function Assert-AuthenticatedPackage([string]$Path, [switch]$Distribution) {
    $verifier = Join-Path $Path 'module\Test-PackageIntegrity.ps1'
    $cursor = [IO.Path]::GetFullPath($verifier)
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
    if ($Distribution) { & $verifier -Root $Path -Distribution } else { & $verifier -Root $Path }
}
# The source is authenticated first: an unsigned or changed source never produces a package.
Assert-AuthenticatedPackage $packageRoot

if (-not $Destination) { $Destination = Join-Path (Split-Path $root -Parent) "package\PraRemoteMailbox-$version" }
if (-not [IO.Path]::IsPathRooted($Destination)) { $Destination = Join-Path (Get-Location).Path $Destination }
$Destination = [IO.Path]::GetFullPath($Destination).TrimEnd('\')

$rootPrefix = [IO.Path]::GetFullPath($root).TrimEnd('\') + '\'
if (($Destination + '\').StartsWith($rootPrefix, [StringComparison]::OrdinalIgnoreCase) -or $rootPrefix.StartsWith($Destination + '\', [StringComparison]::OrdinalIgnoreCase)) {
    throw "The destination must be outside the tool folder: $Destination"
}
if (Test-Path -LiteralPath $Destination) {
    if (-not $Force) { throw "The destination already exists: $Destination. Use -Force to replace it." }
    if (-not (Test-Path -LiteralPath (Join-Path $Destination 'Invoke-PraRemoteMailbox.ps1'))) { throw "The destination is not a PRA Remote Mailbox package, it is not replaced: $Destination" }
    if (Test-Path -LiteralPath (Join-Path $Destination 'Backups')) { throw "The destination contains a Backups folder (AD values), it is not replaced: $Destination" }
    Remove-Item -LiteralPath $Destination -Recurse -Force
}

# ---- Files needed at run time (paths relative to package\, the same as in the extracted ZIP) ----------------
$files = New-Object 'Collections.Generic.List[string]'
foreach ($f in 'Invoke-PraRemoteMailbox.ps1', 'PackageIntegrity.psd1', 'README.md', 'LICENSE', 'CHANGELOG.md', 'templates\Report.template.html',
    'config\Targets.sample.csv', 'config\SharedPermissions.sample.csv', 'docs\PraRemoteMailbox-Guide.html', 'docs\PraRemoteMailbox-Guide.md') { $files.Add($f) }
foreach ($m in 'PRA.Common.psm1', 'PRA.Directory.psm1', 'PRA.Backup.psm1', 'PRA.Cloud.psm1', 'PRA.Gui.psm1', 'PRA.Gui.xaml', 'PRA.Gui.Directory.ps1', 'Test-PackageIntegrity.ps1') { $files.Add("module\$m") }
Get-ChildItem -LiteralPath (Join-Path $packageRoot 'docs\images') -File -ErrorAction SilentlyContinue | ForEach-Object { $files.Add('docs\images\' + $_.Name) }
if (@($files | Select-Object -Unique).Count -ne $files.Count) { throw 'Package integrity: duplicate distribution file path.' }

foreach ($f in $files) {
    # CHANGELOG.md is the only file copied from the repository root; it is hashed by the manifest.
    $source = if ($f -eq 'CHANGELOG.md') { Join-Path $root $f } else { Join-Path $packageRoot $f }
    if (-not (Test-Path -LiteralPath $source -PathType Leaf)) { throw "Missing file in the tool folder: $f" }
    $target = Join-Path $Destination $f
    [void][IO.Directory]::CreateDirectory((Split-Path $target -Parent))
    Copy-Item -LiteralPath $source -Destination $target
}

# ---- Configuration with the environment values emptied ---------------------------------------------------
$configRelative = 'config\PraRemoteMailbox.config.psd1'
$config = [IO.File]::ReadAllText((Join-Path $packageRoot $configRelative), [Text.Encoding]::UTF8)
$emptied = New-Object 'Collections.Generic.List[string]'
$keys = @(
    @{ Key='DomainController'; Count=1 }, @{ Key='SearchBase'; Count=1 }, @{ Key='GroupDN'; Count=2 }, @{ Key='CsvPath'; Count=2 },
    @{ Key='RoutingDomain'; Count=1 }, @{ Key='Server'; Count=1 }, @{ Key='TenantId'; Count=1 }, @{ Key='Organization'; Count=1 },
    @{ Key='AppId'; Count=1 }, @{ Key='CertificateThumbprint'; Count=1 }, @{ Key='UserPrincipalName'; Count=1 }
)
foreach ($item in $keys) {
    $pattern = "(?m)^(\s*$($item.Key)\s*=\s*)'([^']*)'"
    $found = [regex]::Matches($config, $pattern)
    if ($found.Count -ne $item.Count) { throw "The key $($item.Key) must appear $($item.Count) time(s) in $configRelative (found $($found.Count))." }
    foreach ($match in $found) { if ($match.Groups[2].Value) { $emptied.Add($match.Groups[2].Value) } }
    $config = [regex]::Replace($config, $pattern, '$1''''')
}
$config = [regex]::Replace($config, "(?m)^(\s*Environment\s*=\s*)'[^']*'", '$1''PROD''')
$config = [regex]::Replace($config, "(?m)^(\s*ExcludeTrusteeSamAccountNames\s*=\s*)@\([^)]*\)", '$1@(''Administrator'')')
$configTarget = Join-Path $Destination $configRelative
[void][IO.Directory]::CreateDirectory((Split-Path $configTarget -Parent))
[IO.File]::WriteAllText($configTarget, $config, (New-Object Text.UTF8Encoding($true)))
$files.Add($configRelative)

# ---- Checks ---------------------------------------------------------------------------------------------
$problems = New-Object 'Collections.Generic.List[string]'
foreach ($name in 'Backups', 'reports', 'logs', 'tests', 'tools') {
    if (Test-Path -LiteralPath (Join-Path $Destination $name)) { $problems.Add("Folder $name\ must not be in the package.") }
}
# -Include is ignored with -LiteralPath in Windows PowerShell 5.1: filter on the extension instead.
Get-ChildItem -LiteralPath $Destination -Recurse -File | Where-Object { $_.Extension -in '.clixml', '.jsonl', '.sha256' } | ForEach-Object { $problems.Add("Backup file in the package: $($_.Name)") }
$textFiles = Get-ChildItem -LiteralPath $Destination -Recurse -File | Where-Object { $_.Extension -in '.ps1', '.psm1', '.psd1', '.csv', '.xaml' }
foreach ($value in ($emptied | Select-Object -Unique)) {
    foreach ($file in $textFiles) {
        if ([IO.File]::ReadAllText($file.FullName).IndexOf($value, [StringComparison]::OrdinalIgnoreCase) -ge 0) {
            $problems.Add("An environment value of the configuration ($value) appears in $($file.FullName.Substring($Destination.Length + 1)).")
        }
    }
}
$check = Import-PowerShellDataFile -LiteralPath $configTarget
if ($check.Cloud.TenantId -or $check.Cloud.AppId) { $problems.Add('Tenant values are still in the packaged configuration.') }
$delivered = @(Get-ChildItem -LiteralPath $Destination -Recurse -File | ForEach-Object { $_.FullName.Substring($Destination.Length + 1) })
foreach ($extra in @($delivered | Where-Object { $_ -notin $files })) { $problems.Add("Unexpected file in the package: $extra") }
foreach ($missing in @($files | Where-Object { $_ -notin $delivered })) { $problems.Add("Expected file missing from the package: $missing") }
if ($problems.Count) { throw ("Package not valid ($Destination):`n - " + ($problems -join "`n - ")) }
try { Assert-AuthenticatedPackage $Destination -Distribution }
catch { Remove-Item -LiteralPath $Destination -Recurse -Force -ErrorAction SilentlyContinue; throw }

$all = Get-ChildItem -LiteralPath $Destination -Recurse -File
Write-Host ''
Write-Host "  PRA Remote Mailbox $version - package ready" -ForegroundColor Green
Write-Host "  Folder   : $Destination"
Write-Host ("  Content  : {0} files, {1:N1} MB" -f $all.Count, (($all | Measure-Object Length -Sum).Sum / 1MB))
Write-Host "  Integrity: owner signatures and SHA256 inventory verified"
Write-Host "  Config   : environment values emptied ($(@($emptied | Select-Object -Unique).Count)) - fill in the configuration (guide, chapter 6)"
Write-Host ''
$all | Sort-Object FullName | ForEach-Object { '    {0,12:N0}  {1}' -f $_.Length, $_.FullName.Substring($Destination.Length + 1) }
