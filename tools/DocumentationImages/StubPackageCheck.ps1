<#
.SYNOPSIS
    Stand-in for module\PRA.Gui.Directory.ps1 inside the temporary runtime of the documentation screenshots (repository tool, never shipped, never signed).
.DESCRIPTION
    The console checks and imports a transfer package in a child process of the package folder. The runtime of Show-ConsoleScreens.ps1 is not a
    package (its engine is synthetic), so this stand-in runs the same two calls with the real code of PRA.Common from the integrity fixture copy
    of the package, whose folder is named in package-root.txt next to the module folder. Same parameters and same answer as the real helper;
    nothing else (no directory read).
.NOTES
    Author  : Nicolas Fabert
    Version : 3.1.2
    Part of : PRA Remote Mailbox (repository tool, not in the package)
#>
param([string]$ConfigPath, [string]$ResultPath, [string]$Identity = '', [string]$PackagePath = '', [string]$Environment = '', [string]$BackupFolder = '', [switch]$Import)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$packageRoot = ([IO.File]::ReadAllText((Join-Path (Split-Path $PSScriptRoot -Parent) 'package-root.txt'))).Trim()
Import-Module (Join-Path $packageRoot 'module\PRA.Common.psm1') -Force
try {
    if ($Import) {
        $imported = Import-PraTransferPackage -Path $PackagePath -BackupFolder $BackupFolder -Environment $Environment
        $answer = @{ Success = $true; Mode = 'Import'; Kind = $imported.Kind; BatchId = $imported.BatchId; Name = $imported.Name; Folders = @($imported.Folders); Created = @($imported.Created); Existing = @($imported.Existing) }
    }
    else {
        $info = Get-PraTransferPackage -Path $PackagePath -Environment $Environment
        $answer = @{ Success = $true; Mode = 'Verify'; Valid = [bool]$info.Valid; Error = [string]$info.Error; Kind = [string]$info.Kind; Environment = [string]$info.Environment; BatchId = [string]$info.BatchId; Name = [string]$info.Name
            SizeBytes = [long]$info.SizeBytes; CreatedUtc = [string]$info.CreatedUtc; EntryCount = [int]$info.EntryCount }
    }
}
catch { $answer = @{ Success = $false; Error = $_.Exception.Message } }
[IO.File]::WriteAllText($ResultPath, ($answer | ConvertTo-Json -Depth 5), (New-Object Text.UTF8Encoding($false)))
exit 0
