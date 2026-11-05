#Requires -Version 7.5
<#
.SYNOPSIS
    Reads the OU list for the WPF selector on the configured writable DC. No directory writes.
.NOTES
    Author  : Nicolas Fabert
    Version : 3.1.0
#>
[CmdletBinding()]
param([Parameter(Mandatory)][string]$ConfigPath, [Parameter(Mandatory)][string]$ResultPath, [string]$Identity = '', [string]$PackagePath = '', [string]$Environment = '', [string]$BackupFolder = '', [switch]$Import)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
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
} ([IO.Path]::GetDirectoryName($PSScriptRoot))
# <<< PRA package integrity bootstrap
$root = Split-Path $PSScriptRoot -Parent
Import-Module (Join-Path $root 'PraRemoteMailbox.psd1') -Force
$context = @{
    Config=$null; Server=''; NamingContext=''; CurrentPhase='BrowseOU'; CurrentOperation=''; CurrentIdentity=''
    LogFile=''; Warnings=0; Issues=(New-Object 'Collections.Generic.List[object]'); ExitCode=0; VerboseEnabled=$false
}
try {
    if ($PackagePath) {
        # A transfer package, off the window thread: verified (checksums of every entry) against the CONFIGURED Environment, and extracted with -Import. No Active Directory needed.
        try {
            if (-not $Environment) { throw 'The Environment of the configuration is required.' }
            if ($Import) {
                if (-not $BackupFolder) { throw 'The backup folder is required to import.' }
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
    }
    $context.Config = Import-PraConfiguration -Path $ConfigPath -Root $root -ScopeOverride @{Mode='Auto';SearchBase='';CsvPath='';GroupDN=''}
    $context.Server = $context.Config.DomainController
    Initialize-PraDirectory -Context $context
    if ($Identity) {
        # One account, read only: what the Identity box of the window shows under the field.
        $context.CurrentPhase = 'LookupIdentity'
        $found = $null; $count = 0
        try { $found = Get-PraUser $context $Identity -ExtraProperties @('msExchRecipientTypeDetails', 'displayName'); $count = 1 }
        catch {
            if ($_.Exception.Message -match ': (\d+) result') { $count = [int]$Matches[1] } else { throw }
        }
        $kind = ''
        if ($null -ne $found) {
            $code = [string](Get-PraValue $found 'msExchRecipientTypeDetails' '')
            $kind = if (Test-PraOrdinalEqual $code '1') { 'User mailbox' } elseif (Test-PraOrdinalEqual $code '4') { 'Shared mailbox' } elseif (Test-PraOrdinalEqual $code '16') { 'Room mailbox' } elseif (Test-PraOrdinalEqual $code '32') { 'Equipment mailbox' }
                elseif (Test-PraOrdinalIn $code @('2147483648', '34359738368')) { 'Already a remote mailbox' } else { 'No Exchange mailbox recorded' }
        }
        $answer = @{ Success = $true; Found = ($null -ne $found); Count = $count; DisplayName = $(if ($found) { [string](Get-PraValue $found 'DisplayName' (Get-PraValue $found 'Name' '')) } else { '' })
            UserPrincipalName = $(if ($found) { [string](Get-PraValue $found 'UserPrincipalName' '') } else { '' }); SamAccountName = $(if ($found) { [string](Get-PraValue $found 'SamAccountName' '') } else { '' }); MailboxType = $kind }
        [IO.File]::WriteAllText($ResultPath, ($answer | ConvertTo-Json -Depth 4), (New-Object Text.UTF8Encoding($false)))
        exit 0
    }
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

# SIG # Begin signature block
# MIIRWAYJKoZIhvcNAQcCoIIRSTCCEUUCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCD7/uBq630GaQ4y
# AoMax76RKp+K05izxkeBKw8Rj1hY86CCDW8wggZyMIIEWqADAgECAghkM1HTxzif
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
# wZislcdCZuS6MYIDPzCCAzsCAQEwgYwweDELMAkGA1UEBhMCVVMxDjAMBgNVBAgM
# BVRleGFzMRAwDgYDVQQHDAdIb3VzdG9uMREwDwYDVQQKDAhTU0wgQ29ycDE0MDIG
# A1UEAwwrU1NMLmNvbSBDb2RlIFNpZ25pbmcgSW50ZXJtZWRpYXRlIENBIFJTQSBS
# MQIQBof4ljXihJpmCqqt2mhAWzANBglghkgBZQMEAgEFAKCBhDAYBgorBgEEAYI3
# AgEMMQowCKACgAChAoAAMBkGCSqGSIb3DQEJAzEMBgorBgEEAYI3AgEEMBwGCisG
# AQQBgjcCAQsxDjAMBgorBgEEAYI3AgEVMC8GCSqGSIb3DQEJBDEiBCAWBtyISHaw
# 7AF0r3IRJDn70m12Hs2lxG6e8fjqU7UQvTANBgkqhkiG9w0BAQEFAASCAgCII0bO
# aHxJbsLq5ud3iTuvxrNyqYqMBR3n2eKLti6u8yrWzLRV4akfHSiJRzuh/pfbttrM
# xy7BbwLwplu3FaGArlRuE1eUGZXRHCywOuTQaR1VSGYMg/tqMD0jbjbgvVF8kyjW
# lrxmqL/XG9pIPzajvEqecEWuRz1M2L7w5tD/JkYCzsO2NSVGmAaV1E4EXJqGFdwX
# Kvzq9fEkS2p7HsUSjFFbhmYxdRvOGe4dJUpm7/LT8Z7EfZHB6X3KL4iZYqS2TwxH
# 4nJBLKcBJzqEFaB6RJ/ONcAHR3hF0WJxGBwyKKp4j4PdE9QhfwwbUh+G2/W1H6NS
# Zz/fyc831OEV4aiSOpFVL+7bCO+ECUmj1NwyNEy4S/kNXBUeR/PxMoC+XqwUSVAN
# 52yDAMbM24XWHvIirbSwoZ0H/15/5o7Fs4ei4wVozN1nUJqFTyB1GcuxTnOMxGrs
# QM4cx37Ry8sDdYSjsNc2K9icqndc6o6grrDQg0HNvEZ55bfzFhRGRTfNlknIryO/
# 7n3nnvRdqCYIbNSX7jjmTVEcnKe6+QjtQ15aTwMXYJwGxRIjRvjYzUrmFklK9FsZ
# aEPwKhvdYNFikNwPiSCdZlnOpugvEgLP/29FMQqzqFLPa/YvyTnRMDm4XHcct4qU
# eKQmto1oH01kH+YD15ezWf0Xs10z7VeCCmBotg==
# SIG # End signature block
