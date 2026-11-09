<#
.SYNOPSIS
    Controlled integrity fixtures for the offline PRA Remote Mailbox suites (dot-sourced by the test files).
.DESCRIPTION
    The runtime fails closed on any missing, invalid or untrusted signature, and on any change after signing: the package
    in the working tree is only usable once the owner has signed the final bytes and regenerated PackageIntegrity.psd1. These helpers build a
    COPY of the package in which exactly one thing is substituted: every call of
    Microsoft.PowerShell.Security\Get-AuthenticodeSignature (one per runtime PowerShell file: the bootstrap, or the
    verifier's owner check) returns a Valid, timestamped, owner-thumbprint result. Everything else is the real code
    and the real bytes: the bootstrap, the verifier, the exact inventory, the SHA256 comparison, the path/reparse
    guards and the file scan. A manifest is generated from the copy's own bytes.
    This proves the integrity LOGIC. It does NOT prove Authenticode trust: the native signature state is asserted
    separately in PackageIntegrity.Tests.ps1, on the unmodified package, with no substitution. The two are never
    claimed to be equivalent.
.NOTES
    Author : Nicolas Fabert
    Version: 3.1.2
#>
#Requires -Version 7.5

$global:PraIntegrity = @{
    Signer = '0F28E442889F17B5F4D251E8F96E7CC6E2C9C6D6'
    Token = 'Microsoft.PowerShell.Security\Get-AuthenticodeSignature'
    Generated = @('Backups', 'logs', 'reports')
}

function global:Get-PraExpectedInventory {
    # Independent from the verifier: the tests compare both, so neither can drift silently.
    $images = 'console-next-cloud-light', 'console-next-finalize-light', 'console-next-global-light', 'console-next-light',
        'console-next-package-light', 'console-next-rollback-cloud-light', 'console-next-rollback-light', 'console-next-rollback-package-light', 'console-next-syncfailed-light', 'console-run-cloud-light', 'console-run-early-light', 'console-run-finalize-light',
        'console-run-finished-dark', 'console-run-finished-light', 'console-run-grant-light', 'console-run-package-light',
        'console-run-rollback-cloud-light', 'console-run-rollback-light', 'console-run-syncfailed-light', 'console-run-waiting-light', 'console-settings-light', 'console-setup-dark',
        'console-setup-light', 'console-setup-lights-light', 'console-setup-next-light', 'console-setup-red-light',
        'console-setup-red-lights-light', 'console-task-ad-light', 'console-task-check-light', 'console-task-continue-light',
        'console-task-finalize-light', 'console-task-finish-light', 'console-task-identity-light', 'console-task-light',
        'console-task-package-selected-light', 'console-task-rollback-ad-light', 'console-task-rollback-continue-light', 'console-task-rollback-light', 'console-task-rollback-package-light', 'console-task-rollback-selected-light', 'console-task-scope-light',
        'console-verify-before-light', 'console-verify-check-light', 'console-verify-cloud-light', 'console-verify-finalize-light',
        'console-verify-light', 'console-verify-rollback-cloud-light', 'console-verify-rollback-light', 'console-verify-scope-light', 'guide-dictionary-light',
        'readme-banner-dark', 'readme-banner-light', 'readme-flows-dark', 'readme-flows-light',
        'readme-how-dark', 'readme-how-light', 'readme-path-dark', 'readme-path-light',
        'readme-permissions-dark', 'readme-permissions-light', 'readme-principles-dark', 'readme-principles-light',
        'readme-rights-dark', 'readme-rights-light', 'readme-transfer-dark', 'readme-transfer-light',
        'readme-why-dark', 'readme-why-light', 'report-global-light', 'report-global-recover-light',
        'report-phase-light', 'report-phase-warning-light'
    @(
        'Invoke-PraRemoteMailbox.ps1', 'PraRemoteMailbox.psd1', 'PraRemoteMailbox.psm1'
        'module\PRA.Common.psm1', 'module\PRA.Directory.psm1', 'module\PRA.Backup.psm1', 'module\PRA.Cloud.psm1', 'module\PRA.Gui.psm1'
        'module\PRA.Gui.Directory.ps1', 'module\Test-PackageIntegrity.ps1', 'module\PRA.Gui.xaml'
        'templates\Report.template.html'
        'config\Targets.sample.csv', 'config\SharedPermissions.sample.csv'
        'README.md', 'LICENSE'
        'docs\PraRemoteMailbox-Guide.html', 'docs\PraRemoteMailbox-Guide.md', 'docs\PraRemoteMailbox-UserGuide.html', 'docs\PraRemoteMailbox-UserGuide.md'
    ) + @($images | ForEach-Object { 'docs\images\' + $_ + '.png' }) + @('CHANGELOG.md')
}

function global:Get-PraSignedPowerShellFiles {
    @(Get-PraExpectedInventory | Where-Object { $_ -match '\.ps(m1|d1|1)$' })
}

function global:Read-PraFixtureText([string]$Path) {
    $bytes = [IO.File]::ReadAllBytes($Path)
    $bom = $bytes.Length -ge 3 -and $bytes[0] -eq 239 -and $bytes[1] -eq 187 -and $bytes[2] -eq 191
    $encoding = New-Object Text.UTF8Encoding($false, $true)
    [pscustomobject]@{ Text = $(if ($bom) { $encoding.GetString($bytes, 3, $bytes.Length - 3) } else { $encoding.GetString($bytes) }); Bom = $bom }
}

function global:Write-PraFixtureText([string]$Path, [string]$Text, [bool]$Bom) {
    $body = (New-Object Text.UTF8Encoding($false)).GetBytes($Text)
    if ($Bom) { $body = [byte[]](239, 187, 191) + $body }
    [IO.File]::WriteAllBytes($Path, $body)
}

function global:Get-PraSignatureSubstitute {
    '& { [CmdletBinding()] param([string]$LiteralPath) [pscustomobject]@{ Status = ''Valid''; SignerCertificate = [pscustomobject]@{ Thumbprint = ''' +
        $global:PraIntegrity.Signer + ''' }; TimeStamperCertificate = [pscustomobject]@{ Subject = ''TEST-FIXTURE-SUBSTITUTE'' } } }'
}

function global:Write-PraFixtureManifest {
    param([Parameter(Mandatory)][string]$Root, [Parameter(Mandatory)][string]$Changelog)
    $lines = foreach ($relative in Get-PraExpectedInventory) {
        $path = if ($relative -eq 'CHANGELOG.md') { $Changelog } else { Join-Path $Root $relative }
        "        @{ Path = '$relative'; Sha256 = '$((Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash)' }"
    }
    $text = "# TEST FIXTURE manifest generated from the copied bytes; the signature check is substituted. Never a release artifact.`r`n" +
        "@{`r`n    SchemaVersion = 1`r`n    Algorithm = 'SHA256'`r`n    SignerThumbprint = '$($global:PraIntegrity.Signer)'`r`n    Files = @(`r`n" +
        ($lines -join "`r`n") + "`r`n    )`r`n}`r`n"
    Write-PraFixtureText (Join-Path $Root 'PackageIntegrity.psd1') $text $true
}

function global:New-PraIntegrityFixture {
    <# Copies the package, substitutes the signature check only, writes a manifest from the copy's bytes. #>
    param([Parameter(Mandatory)][string]$SourcePackage, [Parameter(Mandatory)][string]$Destination,
        [Parameter(Mandatory)][string]$Changelog, [switch]$IncludeChangelog, [switch]$KeepNativeSignatureCheck)
    $null = New-Item -ItemType Directory -Path (Split-Path $Destination -Parent) -Force
    Copy-Item -LiteralPath $SourcePackage -Destination $Destination -Recurse
    foreach ($folder in $global:PraIntegrity.Generated) { Remove-Item -LiteralPath (Join-Path $Destination $folder) -Recurse -Force -ErrorAction SilentlyContinue }
    if (-not $KeepNativeSignatureCheck) {
        # The module manifest is data (no signature call); every other signed file has exactly one.
        foreach ($relative in Get-PraSignedPowerShellFiles | Where-Object { $_ -notmatch '\.psd1$' }) {
            $path = Join-Path $Destination $relative
            $file = Read-PraFixtureText $path
            $count = ([regex]::Matches($file.Text, [regex]::Escape($global:PraIntegrity.Token))).Count
            if ($count -ne 1) { throw "Integrity fixture: expected exactly one signature call in $relative, found $count." }
            Write-PraFixtureText $path $file.Text.Replace($global:PraIntegrity.Token, (Get-PraSignatureSubstitute)) $file.Bom
        }
    }
    Write-PraFixtureManifest -Root $Destination -Changelog $Changelog
    if ($IncludeChangelog) { Copy-Item -LiteralPath $Changelog -Destination (Join-Path $Destination 'CHANGELOG.md') }
}

function global:Set-PraFixtureHash {
    <# Re-hashes one inventory file in the fixture manifest after a deliberate fixture edit (e.g. the synthetic Cloud barrier). #>
    param([Parameter(Mandatory)][string]$Root, [Parameter(Mandatory)][string]$Relative)
    $manifest = Join-Path $Root 'PackageIntegrity.psd1'
    $file = Read-PraFixtureText $manifest
    $hash = (Get-FileHash -LiteralPath (Join-Path $Root $Relative) -Algorithm SHA256).Hash
    $pattern = "(?m)(Path = '" + [regex]::Escape($Relative) + "'; Sha256 = ')[0-9A-F]{64}(')"
    if (-not [regex]::IsMatch($file.Text, $pattern)) { throw "Integrity fixture: $Relative is not in the manifest." }
    Write-PraFixtureText $manifest ([regex]::Replace($file.Text, $pattern, ('${1}' + $hash + '${2}'))) $file.Bom
}
