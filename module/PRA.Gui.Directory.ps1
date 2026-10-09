#Requires -Version 5.1
#Requires -PSEdition Desktop
<#
.SYNOPSIS
    Reads the OU list for the WPF selector on the configured writable DC. No directory writes.
.NOTES
    Author  : Nicolas Fabert
    Version : 2.1.0
#>
[CmdletBinding()]
param([Parameter(Mandatory)][string]$ConfigPath, [Parameter(Mandatory)][string]$ResultPath)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$root = Split-Path $PSScriptRoot -Parent
Import-Module (Join-Path $PSScriptRoot 'PRA.Common.psm1') -Force
Import-Module (Join-Path $PSScriptRoot 'PRA.Directory.psm1') -Force
$context = @{
    Config=$null; Server=''; NamingContext=''; CurrentPhase='BrowseOU'; CurrentOperation=''; CurrentIdentity=''
    LogFile=''; Warnings=0; Issues=(New-Object 'Collections.Generic.List[object]'); ExitCode=0; VerboseEnabled=$false
}
try {
    $context.Config = Import-PraConfiguration -Path $ConfigPath -Root $root -ScopeOverride @{Mode='Auto';SearchBase='';CsvPath='';GroupDN=''}
    $context.Server = $context.Config.DomainController
    Initialize-PraDirectory -Context $context
    $units = @(Get-ADOrganizationalUnit -Filter * -Server $context.Server -SearchBase $context.NamingContext -SearchScope Subtree -ErrorAction Stop |
        Sort-Object DistinguishedName | Select-Object Name,DistinguishedName)
    $result = @{ Success=$true; Server=$context.Server; NamingContext=$context.NamingContext; Units=$units }
    [IO.File]::WriteAllText($ResultPath,($result | ConvertTo-Json -Depth 5),(New-Object Text.UTF8Encoding($false)))
    exit 0
}
catch {
    $result = @{ Success=$false; Error=$_.Exception.Message }
    [IO.File]::WriteAllText($ResultPath,($result | ConvertTo-Json -Depth 5),(New-Object Text.UTF8Encoding($false)))
    Write-Error $_ -ErrorAction Continue
    exit 1
}
finally { Initialize-PraPermissionCache -Context $context }
