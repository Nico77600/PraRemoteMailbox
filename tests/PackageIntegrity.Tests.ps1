<#
.SYNOPSIS
    Package integrity tests for PRA Remote Mailbox 3.1.1 (offline; no AD, Exchange, Graph, signing key or network).
.DESCRIPTION
    Three kinds of evidence, never mixed up:
      * Static: bootstrap identity and order, exact inventory, git attributes, no bypass, no private data.
      * Controlled fixture (IntegrityFixture.ps1): a COPY of the package where only the Authenticode call is
        substituted. It exercises the real verifier, bootstrap, inventory, hash, path and reparse logic. It does not
        prove signature trust.
      * Native: the unmodified package with the real Get-AuthenticodeSignature. While the package is unsigned it must
        fail closed before any import or operation; once the owner has signed all eleven files it must verify. The
        assertion depends on the observed signature state, so it is never skipped and never weakened.
.NOTES
    Author  : Nicolas Fabert
    Version : 3.1.1
#>
#Requires -Version 7.5

BeforeAll {
    . (Join-Path $PSScriptRoot 'IntegrityFixture.ps1')
    $script:Repo = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
    $script:Source = Join-Path $script:Repo 'package'
    $script:Work = Join-Path ([IO.Path]::GetTempPath()) ('PI-' + [guid]::NewGuid().ToString('N').Substring(0, 8))
    $null = New-Item -ItemType Directory -Path $script:Work -Force
    $script:Pwsh = Join-Path $PSHOME 'pwsh.exe'
    $script:Ps51 = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
    $script:Changelog = Join-Path $script:Repo 'CHANGELOG.md'
    $script:Fixture = Join-Path $script:Work 'fixture'
    New-PraIntegrityFixture -SourcePackage $script:Source -Destination $script:Fixture -Changelog $script:Changelog -IncludeChangelog

    function script:Invoke-Pwsh {
        param([Parameter(Mandatory)][string[]]$Arguments)
        $previous = $ErrorActionPreference
        $ErrorActionPreference = 'Continue'
        try { $output = & $script:Pwsh -NoLogo -NoProfile -NonInteractive @Arguments 2>&1 | ForEach-Object { [string]$_ } }
        finally { $ErrorActionPreference = $previous }
        [pscustomobject]@{ Code = $LASTEXITCODE; Text = ($output -join "`n") }
    }
    function script:Copy-Case {
        $case = Join-Path $script:Work ([guid]::NewGuid().ToString('N').Substring(0, 8))
        Copy-Item -LiteralPath $script:Fixture -Destination $case -Recurse
        $case
    }
    function script:Invoke-Verifier([string]$Root, [switch]$Distribution) {
        $arguments = @('-File', (Join-Path $Root 'module\Test-PackageIntegrity.ps1'), '-Root', $Root)
        if ($Distribution) { $arguments += '-Distribution' }
        Invoke-Pwsh -Arguments $arguments
    }
    function script:Edit-Manifest([string]$Root, [scriptblock]$Edit) {
        $path = Join-Path $Root 'PackageIntegrity.psd1'
        $file = Read-PraFixtureText $path
        Write-PraFixtureText $path (& $Edit $file.Text) $true
    }
    function script:Add-Byte([string]$Path) {
        $stream = [IO.File]::Open($Path, 'Append', 'Write')
        try { $stream.WriteByte(32) } finally { $stream.Dispose() }
    }
    function script:Get-NativeState {
        $names = 'Invoke-PraRemoteMailbox.ps1', 'PraRemoteMailbox.psd1', 'PraRemoteMailbox.psm1', 'module\PRA.Common.psm1', 'module\PRA.Directory.psm1', 'module\PRA.Backup.psm1', 'module\PRA.Cloud.psm1',
            'module\PRA.Gui.psm1', 'module\PRA.Gui.Directory.ps1', 'module\Test-PackageIntegrity.ps1', 'PackageIntegrity.psd1'
        $statuses = @($names | ForEach-Object { [string](Get-AuthenticodeSignature -LiteralPath (Join-Path $script:Source $_)).Status })
        [pscustomobject]@{ AllValid = (@($statuses | Where-Object { $_ -ne 'Valid' }).Count -eq 0); Statuses = $statuses }
    }
}

AfterAll {
    if ($script:Work -and [IO.Directory]::Exists($script:Work)) {
        Get-ChildItem -LiteralPath $script:Work -Recurse -Force -Directory -ErrorAction SilentlyContinue |
            Where-Object { $_.Attributes -band [IO.FileAttributes]::ReparsePoint } | ForEach-Object { [IO.Directory]::Delete($_.FullName) }
        Remove-Item -LiteralPath $script:Work -Recurse -Force -ErrorAction SilentlyContinue
    }
}

Describe 'Static package contract' {
    It 'keeps the verifier inventory identical to the independently listed exact inventory' {
        $ast = [Management.Automation.Language.Parser]::ParseFile((Join-Path $script:Source 'module\Test-PackageIntegrity.ps1'), [ref]$null, [ref]$null)
        $assignment = $ast.Find({ param($n) $n -is [Management.Automation.Language.AssignmentStatementAst] -and $n.Left.Extent.Text -eq '$required' }, $true)
        $required = @($assignment.Right.FindAll({ param($n) $n -is [Management.Automation.Language.StringConstantExpressionAst] }, $true) | ForEach-Object Value)
        $expected = @(Get-PraExpectedInventory | Where-Object { $_ -ne 'CHANGELOG.md' })
        (($required | Sort-Object) -join '|') | Should -BeExactly (($expected | Sort-Object) -join '|')
        $expected.Count | Should -Be 82
        $text = [IO.File]::ReadAllText((Join-Path $script:Source 'module\Test-PackageIntegrity.ps1'))
        $text | Should -Match "\`$distributionOnly = @\('CHANGELOG\.md'\)"
    }
    It 'has every inventory file in the source package and no unlisted stable file' {
        foreach ($relative in Get-PraExpectedInventory | Where-Object { $_ -ne 'CHANGELOG.md' }) { Test-Path -LiteralPath (Join-Path $script:Source $relative) -PathType Leaf | Should -BeTrue -Because $relative }
        Test-Path -LiteralPath $script:Changelog -PathType Leaf | Should -BeTrue
        $inventory = @(Get-PraExpectedInventory) + @('PackageIntegrity.psd1', 'config\PraRemoteMailbox.config.psd1')
        $unlisted = @(Get-ChildItem -LiteralPath $script:Source -Recurse -File -Force | ForEach-Object { $_.FullName.Substring($script:Source.Length + 1) } |
                Where-Object { $_ -notin $inventory -and $_ -notmatch '^(Backups|logs|reports)\\' })
        $unlisted | Should -BeNullOrEmpty
    }
    It 'covers every executable PowerShell file of the package (ten, with the module manifest and the root module) plus the inventory manifest as the eleventh signed file' {
        $executables = @(Get-ChildItem -LiteralPath $script:Source -Recurse -File | Where-Object { $_.Extension -in '.ps1', '.psm1', '.psd1' } |
                ForEach-Object { $_.FullName.Substring($script:Source.Length + 1) } | Where-Object { $_ -ne 'config\PraRemoteMailbox.config.psd1' })
        $signed = @(Get-PraSignedPowerShellFiles) + @('PackageIntegrity.psd1')
        $signed.Count | Should -Be 11
        (($executables | Sort-Object) -join '|') | Should -BeExactly (($signed | Sort-Object) -join '|')
    }
    It 'runs an identical bootstrap, before any import or function, in the entry, the root module, the five modules and the direct helper' {
        $files = @(Get-PraSignedPowerShellFiles | Where-Object { $_ -notmatch 'Test-PackageIntegrity|\.psd1$' })
        $files.Count | Should -Be 8
        $blocks = @()
        foreach ($relative in $files) {
            $text = [IO.File]::ReadAllText((Join-Path $script:Source $relative)).Replace("`r`n", "`n")
            $match = [regex]::Match($text, '(?s)# >>> PRA package integrity bootstrap.*?# <<< PRA package integrity bootstrap')
            $match.Success | Should -BeTrue -Because $relative
            ([regex]::Matches($text, '# >>> PRA package integrity bootstrap')).Count | Should -Be 1 -Because $relative
            $blocks += ($match.Value -replace '(?m)^\} .*$', '} <root>')
            $after = $text.Substring($match.Index + $match.Length)
            $first = [regex]::Match($after, '(?m)^\s*(Import-Module|function |\$script:)').Index
            $before = $text.Substring(0, $match.Index)
            $before | Should -Not -Match '(?m)^\s*(Import-Module|function )' -Because $relative
            $first | Should -BeGreaterThan -1
        }
        @($blocks | Select-Object -Unique).Count | Should -Be 1
    }
    It 'has exactly nine native signature call sites in the package and none unqualified' {
        $sites = 0
        foreach ($file in Get-ChildItem -LiteralPath $script:Source -Recurse -File | Where-Object { $_.Extension -in '.ps1', '.psm1' }) {
            $text = [IO.File]::ReadAllText($file.FullName)
            $sites += ([regex]::Matches($text, [regex]::Escape($global:PraIntegrity.Token))).Count
            ([regex]::Matches($text, '(?<!Security\\)Get-AuthenticodeSignature')).Count | Should -Be 0 -Because $file.Name
        }
        $sites | Should -Be 9
    }
    It 'offers no unsigned mode, switch or environment bypass' {
        foreach ($file in Get-ChildItem -LiteralPath $script:Source -Recurse -File | Where-Object { $_.Extension -in '.ps1', '.psm1' }) {
            [IO.File]::ReadAllText($file.FullName) | Should -Not -Match '(?i)AllowUnsigned|SkipIntegrity|NoIntegrity|DisableIntegrity|PRA_(SKIP|ALLOW|BYPASS)\w*|env:\w*(UNSIGNED|INTEGRITY)' -Because $file.Name
        }
    }
    It 'pins the fixed owner thumbprint in the verifier, the bootstrap and the builder' {
        foreach ($path in @((Join-Path $script:Source 'module\Test-PackageIntegrity.ps1'), (Join-Path $script:Source 'Invoke-PraRemoteMailbox.ps1'), (Join-Path $script:Repo 'tools\New-PraPackage.ps1'))) {
            [IO.File]::ReadAllText($path) | Should -Match ([regex]::Escape($global:PraIntegrity.Signer))
        }
    }
    It 'keeps the signed and hashed paths byte-exact through .gitattributes (-text, cr-at-eol on signed files)' {
        $signed = @(Get-PraSignedPowerShellFiles | ForEach-Object { 'package/' + $_.Replace('\', '/') }) + @('package/PackageIntegrity.psd1')
        $hashed = @(Get-PraExpectedInventory | Where-Object { $_ -notmatch '\.ps(m1|d1|1)$' } | ForEach-Object { if ($_ -eq 'CHANGELOG.md') { $_ } else { 'package/' + $_.Replace('\', '/') } })
        Push-Location $script:Repo
        try {
            foreach ($path in $signed + $hashed) {
                $text = (& git check-attr text -- $path) -join ' '
                $text | Should -Match ': text: unset$' -Because $path
            }
            foreach ($path in $signed) {
                ((& git check-attr whitespace -- $path) -join ' ') | Should -Match 'cr-at-eol' -Because $path
            }
        }
        finally { Pop-Location }
    }
    It 'distributes no data, configuration secrets, tests or tools (package source folders and values)' {
        foreach ($forbidden in 'tests', 'tools', 'Backups', 'logs', 'reports', '.github', '.git') { Test-Path -LiteralPath (Join-Path $script:Source $forbidden) | Should -BeFalse -Because $forbidden }
        @(Get-ChildItem -LiteralPath (Join-Path $script:Source 'config') -File | ForEach-Object Name | Sort-Object) -join '|' |
            Should -BeExactly 'PraRemoteMailbox.config.psd1|SharedPermissions.sample.csv|Targets.sample.csv'
    }
}

Describe 'Module manifest - PraRemoteMailbox.psd1 and its root module' {
    BeforeAll {
        $script:ManifestPath = Join-Path $script:Source 'PraRemoteMailbox.psd1'
        $script:ManifestData = Import-PowerShellDataFile -LiteralPath $script:ManifestPath
        function script:Get-ModuleExports([string]$Relative) {
            $ast = [Management.Automation.Language.Parser]::ParseFile((Join-Path $script:Source $Relative), [ref]$null, [ref]$null)
            $export = $ast.Find({ param($n) $n -is [Management.Automation.Language.CommandAst] -and $n.GetCommandName() -ceq 'Export-ModuleMember' }, $true)
            @($export.CommandElements | Select-Object -Skip 1 | ForEach-Object { $_.FindAll({ param($n) $n -is [Management.Automation.Language.StringConstantExpressionAst] }, $true) } |
                    ForEach-Object Value | Where-Object { $_ -cne 'Function' })
        }
        function script:Get-CommandNames([string]$Relative) {
            $ast = [Management.Automation.Language.Parser]::ParseFile((Join-Path $script:Source $Relative), [ref]$null, [ref]$null)
            @($ast.FindAll({ param($n) $n -is [Management.Automation.Language.CommandAst] }, $true) | ForEach-Object { $_.GetCommandName() } | Where-Object { $_ })
        }
    }
    It 'passes Test-ModuleManifest and carries the identity fields of the other tools of the same author' {
        $info = Test-ModuleManifest -Path $script:ManifestPath -ErrorAction Stop
        $info.Name | Should -BeExactly 'PraRemoteMailbox'
        $info.RootModule | Should -BeExactly 'PraRemoteMailbox.psm1'
        $info.Author | Should -BeExactly 'Nicolas Fabert'
        $info.PowerShellVersion.ToString() | Should -BeExactly '7.5'
        @($info.CompatiblePSEditions) -join '|' | Should -BeExactly 'Core'
        $info.Guid | Should -Not -Be ([guid]::Empty)
        $script:ManifestData.Description | Should -Not -BeNullOrEmpty
        foreach ($key in 'CmdletsToExport', 'VariablesToExport', 'AliasesToExport') { @($script:ManifestData[$key]).Count | Should -Be 0 -Because $key }
        Test-Path -LiteralPath (Join-Path $script:Source $script:ManifestData.RootModule) -PathType Leaf | Should -BeTrue
    }
    It 'has one version: the manifest, Get-PraToolVersion and the top entry of the changelog' {
        $common = [IO.File]::ReadAllText((Join-Path $script:Source 'module\PRA.Common.psm1'))
        $toolVersion = [regex]::Match($common, '(?m)^\$script:ToolVersion\s*=\s*''(\d+\.\d+\.\d+)''').Groups[1].Value
        $toolVersion | Should -Not -BeNullOrEmpty
        $script:ManifestData.ModuleVersion | Should -BeExactly $toolVersion
        $top = [regex]::Match([IO.File]::ReadAllText($script:Changelog), '(?m)^## (\d+\.\d+\.\d+) ').Groups[1].Value
        $top | Should -BeExactly $toolVersion
        [IO.File]::ReadAllText((Join-Path $script:Source 'PraRemoteMailbox.psm1')) | Should -Match ('(?m)^\s*Version\s*:\s*' + [regex]::Escape($toolVersion) + '\r?$')
    }
    It 'exports an explicit list: no wildcard, no duplicate, every name defined by a part module' {
        $list = @($script:ManifestData.FunctionsToExport)
        $list.Count | Should -BeGreaterThan 0
        foreach ($name in $list) { $name | Should -Not -Match '[*?]' }
        @($list | Select-Object -Unique).Count | Should -Be $list.Count
        $defined = @(Get-ModuleExports 'module\PRA.Common.psm1') + @(Get-ModuleExports 'module\PRA.Directory.psm1')
        foreach ($name in $list) { $defined -ccontains $name | Should -BeTrue -Because $name }
    }
    It 'exports exactly the functions that the entry script, the window, the GUI helper and the other modules call across a module boundary' {
        $common = @(Get-ModuleExports 'module\PRA.Common.psm1')
        $directory = @(Get-ModuleExports 'module\PRA.Directory.psm1')
        $callers = [ordered]@{
            'Invoke-PraRemoteMailbox.ps1' = $common + $directory; 'module\PRA.Gui.psm1' = $common + $directory; 'module\PRA.Gui.Directory.ps1' = $common + $directory
            'module\PRA.Cloud.psm1' = $common + $directory; 'module\PRA.Backup.psm1' = $common + $directory; 'module\PRA.Directory.psm1' = $common
        }
        $used = New-Object 'Collections.Generic.HashSet[string]' ([StringComparer]::Ordinal)
        foreach ($relative in $callers.Keys) {
            foreach ($name in Get-CommandNames $relative) { if ($callers[$relative] -ccontains $name) { [void]$used.Add($name) } }
        }
        $listed = @($script:ManifestData.FunctionsToExport)
        $missing = @($used | Where-Object { $listed -cnotcontains $_ } | Sort-Object)
        $dead = @($listed | Where-Object { -not $used.Contains($_) } | Sort-Object)
        ($missing -join ',') | Should -BeExactly '' -Because 'called across a module boundary but not exported'
        ($dead -join ',') | Should -BeExactly '' -Because 'exported but called by nobody outside its module'
    }
    It 'is imported by the entry script and by the direct GUI helper, which no longer import Common or Directory by path' {
        foreach ($relative in 'Invoke-PraRemoteMailbox.ps1', 'module\PRA.Gui.Directory.ps1') {
            $text = [IO.File]::ReadAllText((Join-Path $script:Source $relative))
            $text | Should -Match "PraRemoteMailbox\.psd1'\) -Force" -Because $relative
            $text | Should -Not -Match 'PRA\.(Common|Directory)\.psm1' -Because $relative
        }
    }
    It 'keeps PRA.Cloud on demand and PRA.Gui for -Gui only: the root module loads neither' {
        $root = [IO.File]::ReadAllText((Join-Path $script:Source 'PraRemoteMailbox.psm1'))
        $root | Should -Not -Match '(?m)^\s*Import-Module .*PRA\.(Cloud|Gui)\.psm1'
        ([regex]::Matches($root, '(?m)^\s*Import-Module ')).Count | Should -Be 2
        $script:ManifestData.ContainsKey('NestedModules') | Should -BeFalse
        $entry = [IO.File]::ReadAllText((Join-Path $script:Source 'Invoke-PraRemoteMailbox.ps1'))
        ([regex]::Matches($entry, 'Import-Module \(Join-Path \$PSScriptRoot ''module\\PRA\.Cloud\.psm1''\)')).Count | Should -Be 3
        ([regex]::Matches($entry, 'Import-Module \(Join-Path \$PSScriptRoot ''module\\PRA\.Gui\.psm1''\)')).Count | Should -Be 1
    }
    It 'loads the exact list of the manifest, and only PRA.Common, PRA.Directory and PRA.Backup, in a fresh process' {
        $manifest = Join-Path $script:Fixture 'PraRemoteMailbox.psd1'
        $command = @(
            'try {'
            "Import-Module -Name '$manifest' -Force -ErrorAction Stop"
            '''EXPORTED='' + (@((Get-Module PraRemoteMailbox).ExportedFunctions.Keys) -join '','')'
            '''PARTS='' + (@(Get-Module -All | Where-Object { $_.Name -like ''PRA.*'' } | ForEach-Object Name | Sort-Object) -join '','')'
            '} catch { [Console]::Error.WriteLine($_.Exception.Message); exit 1 }'
        ) -join "`n"
        $result = Invoke-Pwsh -Arguments @('-Command', $command)
        $result.Code | Should -Be 0 -Because $result.Text
        $exported = [regex]::Match($result.Text, '(?m)^EXPORTED=(.*)$').Groups[1].Value.Trim().Split(',')
        $exported.Count | Should -Be @($script:ManifestData.FunctionsToExport).Count
        foreach ($name in $script:ManifestData.FunctionsToExport) { $exported -ccontains $name | Should -BeTrue -Because $name }
        [regex]::Match($result.Text, '(?m)^PARTS=(.*)$').Groups[1].Value.Trim() | Should -BeExactly 'PRA.Backup,PRA.Common,PRA.Directory'
    }
    It 'is refused by Windows PowerShell 5.1 with the minimum version in the message' {
        $command = "try { Import-Module -Name '$(Join-Path $script:Fixture 'PraRemoteMailbox.psd1')' -Force -ErrorAction Stop; 'LOADED' } catch { [Console]::Error.WriteLine(`$_.Exception.Message); exit 1 }"
        $output = & $script:Ps51 -NoLogo -NoProfile -NonInteractive -Command $command 2>&1 | ForEach-Object { [string]$_ }
        $LASTEXITCODE | Should -Not -Be 0
        ($output -join "`n") | Should -Match '7\.5'
        ($output -join "`n") | Should -Not -Match 'LOADED|Package integrity'
    }
}

Describe 'Controlled fixture - real verifier, bootstrap, hash and path logic (signature call substituted)' {
    It 'accepts the fixture package, with and without the distribution-only changelog' {
        (Invoke-Verifier $script:Fixture -Distribution).Code | Should -Be 0
        $case = Copy-Case
        Remove-Item -LiteralPath (Join-Path $case 'CHANGELOG.md')
        (Invoke-Verifier $case).Code | Should -Be 0
        $result = Invoke-Verifier $case -Distribution
        $result.Code | Should -Not -Be 0
        $result.Text | Should -Match 'Package integrity:'
    }
    It 'rejects a changed stable file <Name>' -ForEach @(
        @{ Name = 'entry'; Path = 'Invoke-PraRemoteMailbox.ps1' }, @{ Name = 'Common module'; Path = 'module\PRA.Common.psm1' },
        @{ Name = 'Cloud module'; Path = 'module\PRA.Cloud.psm1' }, @{ Name = 'GUI helper'; Path = 'module\PRA.Gui.Directory.ps1' },
        @{ Name = 'module manifest'; Path = 'PraRemoteMailbox.psd1' }, @{ Name = 'root module'; Path = 'PraRemoteMailbox.psm1' },
        @{ Name = 'XAML'; Path = 'module\PRA.Gui.xaml' }, @{ Name = 'report template'; Path = 'templates\Report.template.html' },
        @{ Name = 'sample CSV'; Path = 'config\Targets.sample.csv' }, @{ Name = 'README'; Path = 'README.md' }, @{ Name = 'licence'; Path = 'LICENSE' },
        @{ Name = 'guide'; Path = 'docs\PraRemoteMailbox-Guide.html' }, @{ Name = 'user guide'; Path = 'docs\PraRemoteMailbox-UserGuide.html' }, @{ Name = 'image'; Path = 'docs\images\console-verify-light.png' },
        @{ Name = 'changelog'; Path = 'CHANGELOG.md' }, @{ Name = 'verifier'; Path = 'module\Test-PackageIntegrity.ps1' }
    ) {
        $case = Copy-Case
        Add-Byte (Join-Path $case $Path)
        $result = Invoke-Verifier $case -Distribution
        $result.Code | Should -Not -Be 0
        $result.Text | Should -Match 'Package integrity:'
    }
    It 'rejects a missing stable file <Path>' -ForEach @(@{ Path = 'module\PRA.Gui.xaml' }, @{ Path = 'docs\images\console-next-light.png' }, @{ Path = 'LICENSE' }, @{ Path = 'module\PRA.Backup.psm1' }) {
        $case = Copy-Case
        Remove-Item -LiteralPath (Join-Path $case $Path)
        $result = Invoke-Verifier $case -Distribution
        $result.Code | Should -Not -Be 0
        $result.Text | Should -Match 'Package integrity:'
    }
    It 'rejects an unexpected stable file at <Path>' -ForEach @(
        @{ Path = 'extra.txt' }, @{ Path = 'module\Extra.ps1' }, @{ Path = 'docs\notes.md' }, @{ Path = 'templates\Other.html' },
        @{ Path = 'config\Extra.psd1' }, @{ Path = 'config\nested\data.csv' }, @{ Path = 'docs\Backups\x.txt' }
    ) {
        $case = Copy-Case
        $null = New-Item -ItemType Directory -Path (Split-Path (Join-Path $case $Path) -Parent) -Force
        [IO.File]::WriteAllText((Join-Path $case $Path), 'x')
        $result = Invoke-Verifier $case -Distribution
        $result.Code | Should -Not -Be 0
        $result.Text | Should -Match 'unexpected stable file'
    }
    It 'permits editable configuration, operational CSV lists and generated folders (data, outside integrity)' {
        $case = Copy-Case
        [IO.File]::WriteAllText((Join-Path $case 'config\PraRemoteMailbox.config.psd1'), "@{ Anything = 'edited' }")
        [IO.File]::WriteAllText((Join-Path $case 'config\Operational-List.csv'), 'a;b')
        [IO.File]::WriteAllText((Join-Path $case 'config\Targets.sample.csv.bak'), 'x') | Out-Null
        Remove-Item -LiteralPath (Join-Path $case 'config\Targets.sample.csv.bak')
        foreach ($folder in 'Backups', 'logs', 'reports') {
            $null = New-Item -ItemType Directory -Path (Join-Path $case "$folder\sub") -Force
            [IO.File]::WriteAllText((Join-Path $case "$folder\sub\data.bin"), 'generated')
        }
        $result = Invoke-Verifier $case -Distribution
        $result.Code | Should -Be 0 -Because $result.Text
    }
    It 'rejects a manifest <Name>' -ForEach @(
        @{ Name = 'with a wrong thumbprint'; Edit = { param($t) $t.Replace('0F28E442889F17B5F4D251E8F96E7CC6E2C9C6D6', '1111111111111111111111111111111111111111') } }
        @{ Name = 'with another algorithm'; Edit = { param($t) $t.Replace("'SHA256'", "'SHA1'") } }
        @{ Name = 'with an extra key'; Edit = { param($t) $t.Replace('    Algorithm', "    Extra = 1`r`n    Algorithm") } }
        @{ Name = 'with a duplicated path'; Edit = { param($t) $t.Replace("Path = 'LICENSE'", "Path = 'README.md'") } }
        @{ Name = 'with a traversal path'; Edit = { param($t) $t.Replace("Path = 'LICENSE'", "Path = '..\LICENSE'") } }
        @{ Name = 'with a lowercase hash'; Edit = { param($t) [regex]::Replace($t, "Sha256 = '([0-9A-F]{64})'", { param($m) "Sha256 = '" + $m.Groups[1].Value.ToLowerInvariant() + "'" }, 'None') } }
        @{ Name = 'with a missing entry'; Edit = { param($t) [regex]::Replace($t, "(?m)^\s*@\{ Path = 'LICENSE'.*\r?\n", '') } }
        @{ Name = 'with a schema version 2'; Edit = { param($t) $t.Replace('SchemaVersion = 1', 'SchemaVersion = 2') } }
        @{ Name = 'empty (the unsigned placeholder shape)'; Edit = { param($t) [regex]::Replace($t, '(?s)Files = @\(.*\r?\n    \)', 'Files = @()') } }
    ) {
        $case = Copy-Case
        Edit-Manifest $case $Edit
        $result = Invoke-Verifier $case -Distribution
        $result.Code | Should -Not -Be 0
        $result.Text | Should -Match 'Package integrity:|Import-PowerShellDataFile|parse|Hash'
    }
    It 'rejects a reparse point in the stable tree (<Path>)' -ForEach @(@{ Path = 'docs\images' }, @{ Path = 'templates' }, @{ Path = 'module' }) {
        $case = Copy-Case
        $moved = Join-Path $script:Work ('moved-' + [guid]::NewGuid().ToString('N').Substring(0, 6))
        Move-Item -LiteralPath (Join-Path $case $Path) -Destination $moved
        $null = New-Item -ItemType Junction -Path (Join-Path $case $Path) -Target $moved
        $verifier = if ($Path -eq 'module') { Join-Path $moved 'Test-PackageIntegrity.ps1' } else { Join-Path $case 'module\Test-PackageIntegrity.ps1' }
        $result = Invoke-Pwsh -Arguments @('-File', $verifier, '-Root', $case, '-Distribution')
        $result.Code | Should -Not -Be 0
        $result.Text | Should -Match 'Package integrity:'
    }
    It 'fails the entry (CLI and GUI) before any import, configuration or operation when a stable file changed' {
        $case = Copy-Case
        Add-Byte (Join-Path $case 'LICENSE')
        foreach ($arguments in @(@('-Action', 'Check', '-Mode', 'Preview'), @('-Gui'))) {
            $result = Invoke-Pwsh -Arguments (@('-File', (Join-Path $case 'Invoke-PraRemoteMailbox.ps1')) + $arguments)
            $result.Code | Should -Not -Be 0
            $result.Text | Should -Match 'Package integrity: SHA256 mismatch: LICENSE'
            $result.Text | Should -Not -Match 'ActiveDirectory|Configuration file'
        }
        foreach ($folder in 'Backups', 'logs', 'reports') { Test-Path -LiteralPath (Join-Path $case $folder) | Should -BeFalse -Because $folder }
    }
    It 'does not let a module or the direct GUI helper bypass the check (<Relative>)' -ForEach @(
        @{ Relative = 'module\PRA.Common.psm1' }, @{ Relative = 'module\PRA.Directory.psm1' }, @{ Relative = 'module\PRA.Backup.psm1' },
        @{ Relative = 'module\PRA.Cloud.psm1' }, @{ Relative = 'module\PRA.Gui.psm1' }, @{ Relative = 'module\PRA.Gui.Directory.ps1' },
        @{ Relative = 'PraRemoteMailbox.psm1' }, @{ Relative = 'PraRemoteMailbox.psd1' }
    ) {
        $case = Copy-Case
        Add-Byte (Join-Path $case 'LICENSE')
        $target = Join-Path $case $Relative
        $command = if ($Relative -like '*.psm1' -or $Relative -like '*.psd1') { "Import-Module -Name '$target' -Force -ErrorAction Stop" } else { "& '$target' -ConfigPath 'x.psd1' -ResultPath 'y.json'" }
        $result = Invoke-Pwsh -Arguments @('-Command', ('try { ' + $command + ' } catch { [Console]::Error.WriteLine($_.Exception.Message); exit 1 }'))
        $result.Code | Should -Not -Be 0
        $result.Text | Should -Match 'Package integrity: SHA256 mismatch: LICENSE'
    }
    It 'is refused by Windows PowerShell 5.1 at #Requires, before the integrity bootstrap and any other code (<Relative>)' -ForEach @(
        @{ Relative = 'Invoke-PraRemoteMailbox.ps1' }, @{ Relative = 'PraRemoteMailbox.psm1' }, @{ Relative = 'module\PRA.Common.psm1' }, @{ Relative = 'module\PRA.Directory.psm1' },
        @{ Relative = 'module\PRA.Backup.psm1' }, @{ Relative = 'module\PRA.Cloud.psm1' }, @{ Relative = 'module\PRA.Gui.psm1' },
        @{ Relative = 'module\PRA.Gui.Directory.ps1' }, @{ Relative = 'module\Test-PackageIntegrity.ps1' }
    ) {
        $target = Join-Path $script:Fixture $Relative
        $text = [IO.File]::ReadAllText($target)
        $text | Should -Match '(?m)^#Requires -Version 7\.5\r?$'
        $text | Should -Not -Match '(?m)^#Requires -PSEdition'
        $previous = $ErrorActionPreference
        $ErrorActionPreference = 'Continue'
        try {
            $command = if ($Relative -like '*.psm1') { "Import-Module -Name '$target' -Force -ErrorAction Stop" } else { "& '$target'" }
            $output = & $script:Ps51 -NoLogo -NoProfile -NonInteractive -Command $command 2>&1 | ForEach-Object { [string]$_ }
            $code = $LASTEXITCODE
        }
        finally { $ErrorActionPreference = $previous }
        $code | Should -Not -Be 0
        ($output -join "`n") | Should -Match '7\.5'
        ($output -join "`n") | Should -Not -Match 'Package integrity'
    }
    It 'imports the modules of an intact fixture package (the bootstrap passes, then the module loads)' {
        $result = Invoke-Pwsh -Arguments @('-Command', "try { Import-Module -Name '$(Join-Path $script:Fixture 'module\PRA.Common.psm1')' -Force -ErrorAction Stop; 'LOADED' } catch { [Console]::Error.WriteLine(`$_.Exception.Message); exit 1 }")
        $result.Text | Should -Match 'LOADED'
        $result.Code | Should -Be 0
    }
}

Describe 'Package builder - controlled fixture, same paths and no private data' {
    BeforeAll {
        # A repository-shaped copy: package\ (fixture, no changelog), CHANGELOG.md and the real builder with its own
        # signature call substituted.
        $script:BuilderRepo = Join-Path $script:Work 'builder-repo'
        New-PraIntegrityFixture -SourcePackage $script:Source -Destination (Join-Path $script:BuilderRepo 'package') -Changelog $script:Changelog
        Copy-Item -LiteralPath $script:Changelog -Destination $script:BuilderRepo
        $null = New-Item -ItemType Directory -Path (Join-Path $script:BuilderRepo 'tools') -Force
        $builder = Join-Path $script:BuilderRepo 'tools\New-PraPackage.ps1'
        Copy-Item -LiteralPath (Join-Path $script:Repo 'tools\New-PraPackage.ps1') -Destination $builder
        $file = Read-PraFixtureText $builder
        ([regex]::Matches($file.Text, [regex]::Escape($global:PraIntegrity.Token))).Count | Should -Be 1
        Write-PraFixtureText $builder $file.Text.Replace($global:PraIntegrity.Token, (Get-PraSignatureSubstitute)) $file.Bom
        $script:Builder = $builder
    }
    It 'builds exactly the extracted-runtime layout: inventory, manifest and sanitized config, nothing else' {
        $destination = Join-Path $script:Work 'built'
        $result = Invoke-Pwsh -Arguments @('-File', $script:Builder, '-Destination', $destination)
        $result.Code | Should -Be 0 -Because $result.Text
        $built = @(Get-ChildItem -LiteralPath $destination -Recurse -File | ForEach-Object { $_.FullName.Substring($destination.Length + 1) } | Sort-Object)
        $expected = @(Get-PraExpectedInventory) + @('PackageIntegrity.psd1', 'config\PraRemoteMailbox.config.psd1')
        ($built -join '|') | Should -BeExactly (($expected | Sort-Object) -join '|')
        Test-Path -LiteralPath (Join-Path $destination 'Invoke-PraRemoteMailbox.ps1') -PathType Leaf | Should -BeTrue
        foreach ($forbidden in 'tests', 'tools', 'Backups', 'logs', 'reports', 'package') { Test-Path -LiteralPath (Join-Path $destination $forbidden) | Should -BeFalse }
        (Invoke-Verifier $destination -Distribution).Code | Should -Be 0
    }
    It 'refuses a changed source before writing anything' {
        $changed = Join-Path $script:Work 'builder-changed'
        Copy-Item -LiteralPath $script:BuilderRepo -Destination $changed -Recurse
        Add-Byte (Join-Path $changed 'package\LICENSE')
        $destination = Join-Path $script:Work 'built-refused'
        $result = Invoke-Pwsh -Arguments @('-File', (Join-Path $changed 'tools\New-PraPackage.ps1'), '-Destination', $destination)
        $result.Code | Should -Not -Be 0
        $result.Text | Should -Match 'Package integrity:'
        Test-Path -LiteralPath $destination | Should -BeFalse
    }
}

Describe 'Native state of the real package - no substitution (honest, state-dependent)' {
    It 'fails closed before any import or operation while unsigned, and verifies once all eleven files are signed' {
        $state = Get-NativeState
        $entry = Join-Path $script:Source 'Invoke-PraRemoteMailbox.ps1'
        $verifier = Join-Path $script:Source 'module\Test-PackageIntegrity.ps1'
        $module = Invoke-Pwsh -Arguments @('-Command', "try { Import-Module -Name '$(Join-Path $script:Source 'module\PRA.Common.psm1')' -Force -ErrorAction Stop; 'LOADED' } catch { [Console]::Error.WriteLine(`$_.Exception.Message); exit 1 }")
        $direct = Invoke-Pwsh -Arguments @('-File', $verifier, '-Root', $script:Source)
        if ($state.AllValid) {
            $direct.Code | Should -Be 0 -Because $direct.Text
            $module.Code | Should -Be 0 -Because $module.Text
            $module.Text | Should -Match 'LOADED'
            # An intact signed entry could reach AD or open WPF. Test its native rejection on a tampered copy instead.
            $case = Join-Path $script:Work 'native-signed-tampered'
            Copy-Item -LiteralPath $script:Source -Destination $case -Recurse
            Add-Byte (Join-Path $case 'LICENSE')
            foreach ($arguments in @(@('-Action', 'Check', '-Mode', 'Preview'), @('-Gui'))) {
                $rejected = Invoke-Pwsh -Arguments (@('-File', (Join-Path $case 'Invoke-PraRemoteMailbox.ps1')) + $arguments)
                $rejected.Code | Should -Not -Be 0
                $rejected.Text | Should -Match 'Package integrity: SHA256 mismatch: LICENSE'
                $rejected.Text | Should -Not -Match 'ActiveDirectory|Configuration file'
            }
            foreach ($folder in 'Backups', 'logs', 'reports') {
                Test-Path -LiteralPath (Join-Path $case $folder) | Should -BeFalse -Because $folder
            }
        }
        else {
            $cli = Invoke-Pwsh -Arguments @('-File', $entry, '-Action', 'Check', '-Mode', 'Preview')
            $gui = Invoke-Pwsh -Arguments @('-File', $entry, '-Gui')
            foreach ($result in $cli, $gui, $module, $direct) {
                $result.Code | Should -Not -Be 0
                $result.Text | Should -Match 'Package integrity'
            }
            $module.Text | Should -Not -Match 'LOADED'
            foreach ($folder in 'Backups', 'logs', 'reports') { Test-Path -LiteralPath (Join-Path $script:Source $folder) | Should -BeFalse -Because $folder }
        }
    }
    It 'refuses to build a package from an unsigned source and writes nothing' {
        $state = Get-NativeState
        $destination = Join-Path $script:Work 'native-built'
        $result = Invoke-Pwsh -Arguments @('-File', (Join-Path $script:Repo 'tools\New-PraPackage.ps1'), '-Destination', $destination)
        if ($state.AllValid) { $result.Code | Should -Be 0 -Because $result.Text }
        else {
            $result.Code | Should -Not -Be 0
            $result.Text | Should -Match 'Package integrity'
            Test-Path -LiteralPath $destination | Should -BeFalse
        }
    }
}
