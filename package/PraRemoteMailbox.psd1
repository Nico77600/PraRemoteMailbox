#
#  PRA Remote Mailbox - module manifest
#  --------------------------------------------------------------------------
#  Author  : Nicolas Fabert
#  Version : see ModuleVersion (single source: Get-PraToolVersion of PRA.Common; a test checks both and the CHANGELOG)
#
#  Imported by Invoke-PraRemoteMailbox.ps1, by the window (PRA.Gui) and by the direct GUI helper
#  (module\PRA.Gui.Directory.ps1) with: Import-Module <package>\PraRemoteMailbox.psd1 -Force
#
#  What the root module (PraRemoteMailbox.psm1) loads: PRA.Common and PRA.Directory (which loads PRA.Backup). The other
#  parts keep their on-demand import, on purpose:
#    - module\PRA.Cloud.psm1 is imported only when the cloud phase needs it (in the dedicated process the Microsoft Graph
#      modules load before ExchangeOnlineManagement, which avoids assembly conflicts);
#    - module\PRA.Gui.psm1 is imported only for -Gui.
#  A manifest cannot express a conditional load order, so those two are not NestedModules.
#
#  FunctionsToExport is the list of the functions that the entry script, the window, the GUI helper, PRA.Cloud, PRA.Backup
#  and PRA.Directory call across module boundaries (a test recomputes it from the code). The other functions stay internal.
#
@{
    RootModule            = 'PraRemoteMailbox.psm1'
    ModuleVersion         = '3.1.0'
    GUID                  = '1d97585b-d077-4d74-bf10-4e36d16308b6'
    Author                = 'Nicolas Fabert'
    Description           = 'PRA Remote Mailbox: disaster-recovery tool for an Exchange hybrid environment. Converts on-premises mailboxes to remote mailboxes and back (Active Directory and Exchange Online), with a backup before every write, a proof after it, a guided console and a transfer package between the Active Directory server and the cloud server.'
    PowerShellVersion     = '7.5'
    CompatiblePSEditions  = @('Core')

    # Functions called by Invoke-PraRemoteMailbox.ps1, the window and the other modules. The other functions stay internal.
    FunctionsToExport     = @(
        # Console, log, audit and run result (PRA.Common)
        'Write-PraBanner', 'Write-PraStep', 'Write-PraItem', 'Write-PraHost', 'Write-PraLog', 'Write-PraEvent', 'Write-PraProgress', 'Initialize-PraAudit', 'Complete-PraRun',
        # Configuration, paths and CSV (PRA.Common)
        'Import-PraConfiguration', 'New-PraEffectiveConfiguration', 'Get-PraConfigurationDifference', 'Resolve-PraPath', 'Read-PraCsvText', 'Read-PraTargetCsv', 'Get-PraTargetOverride', 'Get-PraToolVersion', 'Get-PraValue', 'Get-PraList',
        # Ordinal helpers, JSON and native calls (PRA.Common)
        'Test-PraOrdinalEqual', 'Test-PraOrdinalIgnoreCaseEqual', 'Test-PraOrdinalIn', 'Test-PraOrdinalIgnoreCaseIn', 'Sort-PraOrdinal', 'Get-PraOrdinalUnique', 'Compare-PraX500Address', 'ConvertFrom-PraJson', 'Get-PraNativeProcessApi', 'Get-PraWin32ErrorText',
        # Private folders, phase data and transfer package (PRA.Common)
        'New-PraPrivateDirectorySecurity', 'Initialize-PraPrivateFolder', 'Register-PraObjectName', 'Register-PraObjectBackup', 'Save-PraPhaseData', 'Copy-PraPhaseData', 'Get-PraTransferPackageName', 'Get-PraTransferPackage', 'New-PraTransferPackage', 'Import-PraTransferPackage',
        # Active Directory, backup and proof (PRA.Directory)
        'Initialize-PraDirectory', 'Initialize-PraPermissionCache', 'Get-PraUser', 'Get-PraExpectedX500', 'Get-PraTarget', 'New-PraRow', 'New-PraPlan', 'Invoke-PraAdPreview', 'Invoke-PraAdBatch', 'Invoke-PraAdReplication', 'Invoke-PraSync', 'Import-PraBackup', 'Import-PraProof', 'Assert-PraReceipt', 'Assert-PraFollowupState', 'Get-PraHash', 'Write-PraImmutableFile', 'New-PraPrivateDirectory', 'Write-PraJournal'
    )
    CmdletsToExport       = @()
    VariablesToExport     = @()
    AliasesToExport       = @()
}

# SIG # Begin signature block
# MIIRWAYJKoZIhvcNAQcCoIIRSTCCEUUCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCDMdQ8ldjUL1nO0
# ndxp0ENp5PQASUIHSroRS8iNuvt6v6CCDW8wggZyMIIEWqADAgECAghkM1HTxzif
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
# AQQBgjcCAQsxDjAMBgorBgEEAYI3AgEVMC8GCSqGSIb3DQEJBDEiBCAckLL5GO1N
# uCxZbVxxsv7B1x1SsEJnh+NYrMh7ArJ5ujANBgkqhkiG9w0BAQEFAASCAgBE5Tur
# b96109tLS68I53TryXlgpYgGpi61dV5D1SNX8YaMQbsgaiAtL8t4UUon8tesx8jG
# sUc1nxn395KjavIAxaY8/XNS1nZC/OBgB5QFJgWudeXNO+RNxjo/kt8RwZ0LcZ0G
# mM2ucNbONU9LXxe3fvzdYTPoNIHLqFsrsz3604NOPalDsoKt28qpiEFfQgcYJN+P
# fuuTyJaU4+eWErr7Cj96r8h0dUlP8YroHdXsS/ZfGnhrNblYuo0GiiJ4USLSjkfG
# +i/VJYSLMnloC90vmDu7zEifProo11GhIeQYZkFUMD30r+kjuI6TqQa3/A/dTMq+
# gq9tsL5l7XRCuv/Tfyb2rJ/GVfBWBAgAlX5fco0zUrv5F/q+UJz96lbWsozKB288
# Z5WFR83WIL1Hi8u86itQ5kl4ewqK91WMtJEttIIzNBY/wj9A5fPYsk0Qj2lQcGWw
# N5/mM3Fx/ot8tF0hwwVcpLCw1GyoUcBIOgCk3Q4tKXGzNc55CpWFEOFJUFUeBYOb
# +6YdV58AsE+oWfAtjfFebUnHbpow+ndSMmit4mRZKL0ODVdEx4BFUD53kOpF0Uh+
# sCPcA1oqFITcZuCXaIaRg1672b1DMd/mIJO810nJOIDTlhztVITVE+5nWw1bc9MR
# XFS+rouW0UFYVKBPAv9oCIe9GuvDoRhYqtpyrQ==
# SIG # End signature block
