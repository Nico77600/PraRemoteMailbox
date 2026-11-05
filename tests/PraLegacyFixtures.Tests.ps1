<#
.SYNOPSIS
    Proves that the engine still reads every backup, proof and Finalize package written by PraRemoteMailbox 2.2.0
    under Windows PowerShell 5.1 (frozen in tests\fixtures\ps51-2.2.0).
.DESCRIPTION
    Edition neutral: the same file runs under powershell.exe (5.1) and pwsh (7.5+). It never rewrites a fixture and
    reads them only through the PRODUCTION readers of the package under test:
      - backup JSON + .sha256 + CLIXML          Import-PraBackup (schema 3, 2 and 1)
      - raw codec decode                        Test-PraRawCapture (called directly on every .clixml of schema 3)
      - AD proofs                               Import-PraProof (against the Convert source receipt)
      - Finalize manifest                       Get-PraFinalizeInput (extracted unchanged from the entry script)
      - codec identity                          the current Write-PraRawCapture re-serialises the all-types snapshot to the
                                                same bytes as the 5.1 file (any engine edition)
      - negative                                one flipped byte in a JSON, CLIXML, proof or manifest is refused
    The runtime modules are loaded from a COPY of the package in which only the Authenticode check is substituted
    (tests\IntegrityFixture.ps1), exactly like the other suites. The package under test defaults to the repository that
    holds this file; set PRA_FX_REPO to test another checkout (a checkout that holds package\ and tests\IntegrityFixture.ps1).
    Fixtures are synthetic (contoso.com). Do not regenerate them to make a test pass.
.NOTES
    Pester >= 5. Not part of the runtime package.
#>
#Requires -Version 5.1

BeforeDiscovery {
    $fxRoot = Join-Path $PSScriptRoot 'fixtures\ps51-2.2.0'
    $index = @([IO.File]::ReadAllText((Join-Path $fxRoot 'sets.json')) | ConvertFrom-Json | ForEach-Object { $_ })
    $script:Backups = @($index | Where-Object { $_.Role -in @('Backup', 'LegacyBackup') } | ForEach-Object {
            @{ Label = ('{0} {1} schema {2}' -f $_.Set, $_.Operation, $_.Schema); Set = $_.Set; Path = $_.Path; Schema = [int]$_.Schema; Records = [int]$_.Records; Operation = [string]$_.Operation; Legacy = [bool]($_.PSObject.Properties['Legacy'] -and $_.Legacy) } })
    $script:Raw = @($script:Backups | Where-Object { $_.Schema -ge 2 })
    $script:Proofs = @($index | Where-Object { $_.Role -eq 'Proof' } | ForEach-Object { @{ Label = ('{0} {1}' -f $_.Set, $_.Operation); Set = $_.Set; Path = $_.Path; Backup = $_.Backup; Operation = [string]$_.Operation; Records = [int]$_.Records } })
    $script:Finalize = @($index | Where-Object { $_.Role -eq 'FinalizeManifest' } | ForEach-Object { @{ Label = $_.Set; Path = $_.Path; Items = [int]$_.Items } })
    $script:Negatives = @(
        @{ Kind = 'backup JSON'; Target = 'Backup'; Pattern = '^Convert-.*\.json$'; Set = '01-convert-users'; Message = '*SHA-256*' }
        @{ Kind = 'backup CLIXML'; Target = 'Backup'; Pattern = '^Convert-.*\.clixml$'; Set = '01-convert-users'; Message = '*SHA-256*' }
        @{ Kind = 'AD proof'; Target = 'Proof'; Pattern = '^State-[0-9a-f]+\.json$'; Set = '01-convert-users'; Message = '*SHA-256*' }
        @{ Kind = 'Finalize manifest'; Target = 'Finalize'; Pattern = '^Finalize-.*\.json$'; Set = '03-finalize-shared13'; Message = '*SHA-256*' }
    )
}

BeforeAll {
    # A Windows PowerShell launched by pwsh can inherit only Core module paths (same guard as tests\Invoke-TestGate.ps1).
    if ($PSVersionTable.PSEdition -eq 'Desktop') {
        foreach ($name in @('Microsoft.PowerShell.Utility', 'Microsoft.PowerShell.Management', 'Microsoft.PowerShell.Security')) {
            Import-Module (Join-Path $PSHOME ('Modules\' + $name + '\' + $name + '.psd1')) -ErrorAction Stop
        }
    }
    $script:FxRoot = Join-Path $PSScriptRoot 'fixtures\ps51-2.2.0'
    $repo = if ($env:PRA_FX_REPO) { [IO.Path]::GetFullPath($env:PRA_FX_REPO) } else { [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..')) }
    $script:Repo = $repo
    $integrity = Join-Path $repo 'tests\IntegrityFixture.ps1'
    if (-not (Test-Path -LiteralPath $integrity)) { $integrity = Join-Path $PSScriptRoot 'IntegrityFixture.ps1' }
    if (-not (Test-Path -LiteralPath $integrity)) { throw "Package under test not found: expected tests\IntegrityFixture.ps1 under '$repo' (set PRA_FX_REPO to a PraRemoteMailbox checkout)." }
    . $integrity
    $script:Work = Join-Path ([IO.Path]::GetTempPath()) ('PraFxTest-' + [guid]::NewGuid().ToString('N').Substring(0, 8))
    $null = New-Item -ItemType Directory -Path $script:Work -Force
    $script:Package = Join-Path $script:Work 'package-fixture'
    New-PraIntegrityFixture -SourcePackage (Join-Path $repo 'package') -Destination $script:Package -Changelog (Join-Path $repo 'CHANGELOG.md')
    # A package that cannot be loaded by this engine (for example a 2.x package under pwsh) fails every reader test
    # below with that reason, instead of aborting the container.
    $script:LoadError = ''
    try {
        Import-Module (Join-Path $script:Package 'module\PRA.Common.psm1') -Force -Global -ErrorAction Stop
        Import-Module (Join-Path $script:Package 'module\PRA.Backup.psm1') -Force -Global -ErrorAction Stop
        Import-Module (Join-Path $script:Package 'module\PRA.Directory.psm1') -Force -Global -ErrorAction Stop
    }
    catch { $script:LoadError = $_.Exception.Message }
    . (Join-Path $PSScriptRoot 'fixtures\ps51-2.2.0\06-all-types\New-PraAllTypesUser.ps1')

    function New-FxContext {
        # Same shape as the context of the 2.2.0 suites (New-GateContext), without any directory runtime.
        $backupFolder = Join-Path $script:Work ('backups-' + [guid]::NewGuid().ToString('N').Substring(0, 6))
        $null = New-Item -ItemType Directory -Path $backupFolder -Force
        @{
            Root = $script:Package; RunId = [guid]::NewGuid().ToString('N'); Version = 'fixture'; StartTime = Get-Date; Action = 'Check'; Mode = 'Preview'; Phase = 'AD'
            CurrentPhase = 'Test'; CurrentOperation = ''; CurrentIdentity = ''; StepIndex = 0; Warnings = 0
            Config = @{ Environment = 'SYNTHETIC_GATE'; Storage = @{ BackupFolder = $backupFolder } }
            Issues = (New-Object 'Collections.Generic.List[object]'); Rows = (New-Object 'Collections.Generic.List[object]')
            BackupFiles = (New-Object 'Collections.Generic.List[string]'); StateFiles = (New-Object 'Collections.Generic.List[string]')
            BackupFolder = $backupFolder; LogFolder = (Join-Path $script:Work 'logs'); ReportFolder = (Join-Path $script:Work 'reports')
            LogFile = ''; TranscriptPath = ''; TranscriptStarted = $false; NoReport = $true; Server = ''; AllowMutation = $false
            Approval = { param($Target, $Operation) $false }
            SourceBackupHash = ''; Source = $null; Proof = $null; JournalPath = ''; ExitCode = 0; ResultStatus = ''; CloudConnectFailed = $false; CloudCheckScope = 'Both'
        }
    }
    function ConvertFrom-FxJson {
        # The engine reads JSON through ConvertFrom-PraJson (dates stay text on PowerShell 7, where bare ConvertFrom-Json would turn
        # them into DateTime); a package that does not export it (a 2.x checkout under Windows PowerShell 5.1) falls back to ConvertFrom-Json.
        param([Parameter(Mandatory, ValueFromPipeline)][AllowEmptyString()][string]$Text)
        process { if (Get-Command ConvertFrom-PraJson -ErrorAction SilentlyContinue) { ConvertFrom-PraJson -InputObject $Text } else { ConvertFrom-Json -InputObject $Text } }
    }
    function Get-FxPath([string]$Relative) { Join-Path $script:FxRoot ($Relative.Replace('/', '\')) }
    function Copy-FxToWork([string]$SourceFolder) {
        $target = Join-Path $script:Work ('case-' + [guid]::NewGuid().ToString('N').Substring(0, 6))
        Copy-Item -LiteralPath $SourceFolder -Destination $target -Recurse
        return $target
    }
    function Invoke-FxFlip([string]$Path) {
        # Flips the low bit of one ASCII letter well inside the file: still well-formed text, different content.
        $bytes = [IO.File]::ReadAllBytes($Path)
        for ($i = [int]($bytes.Length / 2); $i -lt $bytes.Length; $i++) {
            if (($bytes[$i] -ge 0x61 -and $bytes[$i] -le 0x7A) -or ($bytes[$i] -ge 0x41 -and $bytes[$i] -le 0x5A)) { $bytes[$i] = $bytes[$i] -bxor 1; [IO.File]::WriteAllBytes($Path, $bytes); return $i }
        }
        throw "No ASCII letter to flip in $Path"
    }
    function Get-FxProofInputs($Context, [string]$ProofPath) {
        # The Convert source receipt a proof is checked against (found by hash among the indexed Convert backups).
        $data = [IO.File]::ReadAllText($ProofPath) | ConvertFrom-FxJson
        $want = if ($data.Operation -eq 'Convert') { $data.BackupHash } else { $data.SourceBackupHash }
        $index = @([IO.File]::ReadAllText((Join-Path $script:FxRoot 'sets.json')) | ConvertFrom-FxJson | ForEach-Object { $_ })
        foreach ($entry in @($index | Where-Object { $_.Role -eq 'Backup' -and $_.Operation -eq 'Convert' })) {
            $candidate = Get-FxPath $entry.Path
            if ((Get-PraHash $candidate) -ceq $want) { return (Import-PraBackup $Context $candidate) }
        }
        throw "No Convert fixture with hash $want"
    }
    # Production functions of the entry script, extracted unchanged (they read $context, $Batch, $Identity, $Scope).
    $tokens = $null; $errors = $null
    $mainAst = [Management.Automation.Language.Parser]::ParseFile((Join-Path $repo 'package\Invoke-PraRemoteMailbox.ps1'), [ref]$tokens, [ref]$errors)
    $wanted = @('Get-PraShortId', 'Get-PraBatchFile', 'Select-PraSourceRecord', 'Get-PraFinalizeInput')
    $script:EntryFunctions = (@($mainAst.FindAll({ param($n) $n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -in $wanted }, $true) | ForEach-Object { $_.Extent.Text }) -join "`n")
}

AfterAll {
    if ($script:Work -and (Test-Path -LiteralPath $script:Work)) { Remove-Item -LiteralPath $script:Work -Recurse -Force -ErrorAction SilentlyContinue }
}

Describe 'Frozen Windows PowerShell 5.1 fixtures (PraRemoteMailbox 2.2.0)' {
    It 'keeps every fixture byte identical to fixtures.sha256' {
        $lines = @([IO.File]::ReadAllLines((Join-Path $script:FxRoot 'fixtures.sha256')) | Where-Object { $_ })
        $lines.Count | Should -BeGreaterThan 30
        foreach ($line in $lines) {
            $expected, $relative = $line -split '  ', 2
            (Get-FileHash -LiteralPath (Get-FxPath $relative) -Algorithm SHA256).Hash.ToLowerInvariant() | Should -BeExactly $expected
        }
        # Nothing unlisted: the index covers every file except itself.
        $actual = @(Get-ChildItem -LiteralPath $script:FxRoot -Recurse -File -Force | Where-Object Name -ne 'fixtures.sha256').Count
        $actual | Should -Be $lines.Count
    }

    It 'stays small (synthetic data, under 2 MB)' {
        (Get-ChildItem -LiteralPath $script:FxRoot -Recurse -File -Force | Measure-Object Length -Sum).Sum | Should -BeLessThan 2000000
    }

    Context 'Backup readers' {
        BeforeEach { if ($script:LoadError) { throw ('Production modules not loadable by this engine: ' + $script:LoadError) } }
        It 'Import-PraBackup accepts <Label> (hashes, schema, records, legacy flag)' -ForEach $script:Backups {
            $context = New-FxContext
            $file = Get-FxPath $Path
            $receipt = Import-PraBackup $context $file
            $receipt.Data.SchemaVersion | Should -Be $Schema
            @($receipt.Data.Records).Count | Should -Be $Records
            $receipt.Data.Operation | Should -BeExactly $Operation
            $receipt.Legacy | Should -Be $Legacy
            $receipt.Hash | Should -BeExactly (Get-PraHash $file)
            if ($Schema -ge 2) {
                ([IO.File]::ReadAllText($file + '.sha256')).Trim() | Should -BeExactly $receipt.Hash
                $receipt.Data.RawHash | Should -BeExactly (Get-PraHash (Join-Path (Split-Path $file -Parent) $receipt.Data.RawFile))
            }
            if ($Schema -eq 3) { $receipt.Data.RawFormat | Should -BeExactly 'PraDataOnlyClixml-v1' }
        }

        It 'decodes the raw codec of <Label> with Test-PraRawCapture' -ForEach $script:Raw {
            $context = New-FxContext
            $file = Get-FxPath $Path
            $data = [IO.File]::ReadAllText($file) | ConvertFrom-FxJson
            $raw = Join-Path (Split-Path $file -Parent) $data.RawFile
            $format = if ($Schema -eq 3) { [string]$data.RawFormat } else { '' }
            $checked = Test-PraRawCapture -Context $context -LiteralPath $raw -Records @($data.Records) -RawFormat $format
            $checked.Count | Should -Be $Records
        }
    }

    Context 'AD proofs' {
        BeforeEach { if ($script:LoadError) { throw ('Production modules not loadable by this engine: ' + $script:LoadError) } }
        It 'Import-PraProof accepts the <Label> proof against its Convert source' -ForEach $script:Proofs {
            $context = New-FxContext
            $proofPath = Get-FxPath $Path
            $backupPath = Get-FxPath $Backup
            $folder = Split-Path $proofPath -Parent
            if (-not (Test-Path -LiteralPath $backupPath) -or (Split-Path $backupPath -Parent) -ne $folder) {
                # Set 04 keeps only the proofs: assemble the batch folder from the byte-identical lot in the Finalize package.
                $folder = Join-Path $script:Work ('proof-' + [guid]::NewGuid().ToString('N').Substring(0, 6))
                $null = New-Item -ItemType Directory -Path $folder
                $lotData = [IO.File]::ReadAllText($backupPath) | ConvertFrom-FxJson
                foreach ($source in @($backupPath, ($backupPath + '.sha256'), (Join-Path (Split-Path $backupPath -Parent) $lotData.RawFile), $proofPath, ($proofPath + '.sha256'))) { Copy-Item -LiteralPath $source -Destination $folder }
                $proofPath = Join-Path $folder (Split-Path $proofPath -Leaf)
            }
            $source = Get-FxProofInputs $context (Join-Path $folder (Split-Path $proofPath -Leaf))
            $proof = Import-PraProof $context $proofPath $source $Operation
            $proof.Data.Kind | Should -BeExactly 'ADVerified'
            $proof.Data.SchemaVersion | Should -Be 2
            @($proof.Data.Records).Count | Should -Be $Records
            $proof.Hash | Should -BeExactly (Get-PraHash $proofPath)
            $proof.Receipt.Data.Operation | Should -BeExactly $Operation
        }
    }

    Context 'Finalize package' {
        BeforeEach { if ($script:LoadError) { throw ('Production modules not loadable by this engine: ' + $script:LoadError) } }
        It 'Get-PraFinalizeInput verifies the <Label> manifest, its source batch and its proof' -ForEach $script:Finalize {
            $manifestPath = Get-FxPath $Path
            $context = New-FxContext
            $context.Config.Environment | Should -BeExactly 'SYNTHETIC_GATE'
            $Batch = $manifestPath; $Identity = ''; $Scope = 'All'
            . ([scriptblock]::Create($script:EntryFunctions))
            $result = @(Get-PraFinalizeInput)
            $result.Count | Should -Be $Items
            $context.Source.Data.Operation | Should -BeExactly 'Convert'
            $context.Proof.Data.Operation | Should -BeExactly 'Recover'
            ([IO.File]::ReadAllText($manifestPath + '.sha256')).Trim() | Should -BeExactly (Get-PraHash $manifestPath)
            foreach ($row in $result) { $row.Item.CloudConfirmed | Should -BeTrue }
        }
    }

    Context 'Codec identity (all types)' {
        BeforeEach { if ($script:LoadError) { throw ('Production modules not loadable by this engine: ' + $script:LoadError) } }
        It 'decodes all-types.clixml and the current codec rewrites it to the same bytes' {
            $context = New-FxContext
            $fixture = Get-FxPath '06-all-types/all-types.clixml'
            $snapshot = ConvertTo-PraRawSnapshot -User (New-PraAllTypesUser) -CapturedUtc $script:PraAllTypesCapturedUtc
            $checked = Test-PraRawCapture -Context $context -LiteralPath $fixture -Records @(@{ ObjectGuid = $snapshot.ObjectGUID }) -RawFormat 'PraDataOnlyClixml-v1' -ExpectedSnapshots @($snapshot)
            $checked.Count | Should -Be 1
            $rewritten = Join-Path $script:Work 'all-types-rewritten.clixml'
            @(Write-PraRawCapture -Context $context -LiteralPath $rewritten -Snapshots @($snapshot)).Count | Should -Be 0
            (Get-FileHash -LiteralPath $rewritten -Algorithm SHA256).Hash | Should -BeExactly (Get-FileHash -LiteralPath $fixture -Algorithm SHA256).Hash
            [IO.File]::ReadAllBytes($rewritten).Length | Should -Be ([IO.File]::ReadAllBytes($fixture).Length)
            @(Import-Clixml -LiteralPath $fixture).Count | Should -Be 1
        }
    }

    Context 'Negative: a single flipped byte is refused' {
        BeforeEach { if ($script:LoadError) { throw ('Production modules not loadable by this engine: ' + $script:LoadError) } }
        It 'refuses a flipped byte in the <Kind>' -ForEach $script:Negatives {
            $context = New-FxContext
            $folder = Get-ChildItem -LiteralPath (Join-Path $script:FxRoot $Set) -Directory | Where-Object Name -match '^(Batch|Finalize)-' | Select-Object -First 1
            $copy = Copy-FxToWork $folder.FullName
            $victim = @(Get-ChildItem -LiteralPath $copy -File | Where-Object { $_.Name -match $Pattern })
            $victim.Count | Should -Be 1
            # Control: the untouched copy is accepted by the very same reader.
            $readBackup = { param($ctx, $path) Import-PraBackup $ctx $path }
            $json = @(Get-ChildItem -LiteralPath $copy -File | Where-Object { $_.Name -match '^(Convert|Recover)-.*\.json$' })[0].FullName
            if ($Target -eq 'Backup') { { & $readBackup (New-FxContext) $json } | Should -Not -Throw }
            $null = Invoke-FxFlip $victim[0].FullName
            switch ($Target) {
                'Backup' { { & $readBackup $context $json } | Should -Throw -ExpectedMessage $Message }
                'Proof' {
                    # The proof is checked with a pristine, already validated source receipt.
                    $source = Get-FxProofInputs $context (Join-Path $folder.FullName $victim[0].Name)
                    { Import-PraProof $context $victim[0].FullName $source 'Convert' } | Should -Throw -ExpectedMessage $Message
                }
                'Finalize' {
                    $Batch = $victim[0].FullName; $Identity = ''; $Scope = 'All'
                    . ([scriptblock]::Create($script:EntryFunctions))
                    { Get-PraFinalizeInput } | Should -Throw -ExpectedMessage $Message
                }
            }
        }
    }
}
