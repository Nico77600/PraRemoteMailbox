<#
.SYNOPSIS
    Copy of the package for the documentation tools (repository tool, never shipped): the pictures that do not exist yet are empty placeholders.
.DESCRIPTION
    The integrity fixture (tests\IntegrityFixture.ps1) refuses a package whose docs\images differs from the exact inventory. The documentation tools
    must run when a picture is missing (first run, new picture) or obsolete (removed from the inventory): this copy has exactly the inventory pictures,
    the real file when it exists, an empty placeholder otherwise. Dot-source this file, then call New-DocumentationPackageCopy.
.NOTES
    Author  : Nicolas Fabert
    Version : 3.1.1
    Part of : PRA Remote Mailbox (repository tool, not in the package)
#>
function New-DocumentationPackageCopy {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Repository, [Parameter(Mandatory)][string]$Destination)
    $source = Join-Path $Repository 'package'
    New-Item -ItemType Directory -Path $Destination -Force | Out-Null
    foreach ($item in Get-ChildItem -LiteralPath $source -Force) {
        if ($item.Name -in @('Backups', 'logs', 'reports')) { continue }
        Copy-Item -LiteralPath $item.FullName -Destination $Destination -Recurse -Force
    }
    $images = Join-Path $Destination 'docs\images'
    if (Test-Path -LiteralPath $images) { Remove-Item -LiteralPath $images -Recurse -Force }
    New-Item -ItemType Directory -Path $images -Force | Out-Null
    foreach ($relative in @(Get-PraExpectedInventory | Where-Object { $_ -like 'docs\images\*' })) {
        $real = Join-Path $source $relative
        $target = Join-Path $Destination $relative
        if (Test-Path -LiteralPath $real -PathType Leaf) { Copy-Item -LiteralPath $real -Destination $target -Force }
        else { [IO.File]::WriteAllBytes($target, [byte[]](0)) }
    }
}
