<#
.SYNOPSIS
    Native WPF front-end for PRA Remote Mailbox, without directory or cloud imports.
.DESCRIPTION
    Every operation runs the existing CLI in its own PowerShell 7.5+ process (pwsh.exe). A completed,
    consistent Preview and an unchanged content fingerprint are required before typed Apply.
    Local metadata is indicative; the engine remains the authority for all backup/proof checks.
.NOTES
    Author  : Nicolas Fabert
    Version : 3.1.1
#>
#Requires -Version 7.5
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
$script:Gui = $null
$script:GuiModuleRoot = $PSScriptRoot

# Ordinal string comparison (private helpers, not exported). On .NET with ICU every culture-sensitive PowerShell comparison (the equality and
# membership operators, wildcard matching, switch, Select-Object -Unique, Sort-Object ...) ignores zero-weight characters: a string and the same
# string followed by U+0001 compare as equal, even case-sensitively. Every guard of the window
# (batch hash, Environment, Operation, Guard, confirmation) is compared with these helpers or with an explicit [StringComparison].
function Test-GuiOrdinal {
    param([AllowNull()][object]$Left, [AllowNull()][object]$Right, [switch]$IgnoreCase)
    if ($null -eq $Left -or $null -eq $Right) { return ($null -eq $Left -and $null -eq $Right) }
    return [string]::Equals([string]$Left, [string]$Right, $(if ($IgnoreCase) { [StringComparison]::OrdinalIgnoreCase } else { [StringComparison]::Ordinal }))
}

function Test-GuiOrdinalIn {
    param([AllowNull()][object]$Value, [AllowNull()][AllowEmptyCollection()][object]$Set, [switch]$IgnoreCase)
    foreach ($item in @($Set)) { if (Test-GuiOrdinal $Value $item -IgnoreCase:$IgnoreCase) { return $true } }
    return $false
}

function Get-GuiOrdinalUnique {
    <# Distinct strings, first-seen order, compared ordinally (Select-Object -Unique / Sort-Object -Unique use the culture comparison). #>
    param([AllowNull()][AllowEmptyCollection()][object]$Items, [switch]$IgnoreCase)
    $seen = New-Object 'Collections.Generic.HashSet[string]' -ArgumentList $(if ($IgnoreCase) { [StringComparer]::OrdinalIgnoreCase } else { [StringComparer]::Ordinal })
    foreach ($item in @($Items)) { if ($null -ne $item -and $seen.Add([string]$item)) { [string]$item } }
}

function Get-PraGuiValue {
    param($Object, [string]$Name, $Default = $null)
    if ($null -eq $Object) { return $Default }
    if ($Object -is [Collections.IDictionary]) {
        if ($Object.Contains($Name)) { return $Object[$Name] }
    } elseif ($Object.PSObject.Properties[$Name]) { return $Object.$Name }
    return $Default
}

function Get-PraGuiBatchType {
    param([string]$Action, [string]$Phase)
    switch ($Action) {
        'Convert' { if ((Test-GuiOrdinal $Phase 'Cloud' -IgnoreCase)) { return 'Convert' }; return '' }
        'Recover' { if ((Test-GuiOrdinal $Phase 'Cloud' -IgnoreCase)) { return 'Recover' }; return 'Convert' }
        'Finalize' { return 'RecoverFinalize' }
        'Check' { return 'Convert' }
        default { throw 'Unknown action.' }
    }
}

function Resolve-GuiOfficialValue {
    <# The official spelling of a value (ordinal, case-insensitive match); throws when no member of the set matches ordinally. #>
    param([string]$Value, [string[]]$Set)
    foreach ($item in $Set) { if ([string]::Equals($Value, $item, [StringComparison]::OrdinalIgnoreCase)) { return $item } }
    throw 'Request value outside the allowed set (exact spelling required).'
}

function New-PraGuiRequest {
    param(
        [ValidateSet('Convert','Recover','Finalize','Check')][string]$Action = 'Convert',
        [ValidateSet('Preview','Apply')][string]$Mode = 'Preview',
        [ValidateSet('Both','AD','Cloud')][string]$Phase = 'Both',
        [string]$Batch = '', [string]$Identity = '', [string]$SearchBase = '', [string]$CsvPath = '',
        [ValidateSet('All','UsersOnly','SharedOnly')][string]$Scope = 'All',
        [int]$MaxObjects = 0,
        [ValidateSet('Provisioned','Deprovisioned','Retained')][string]$Expect = 'Provisioned',
        [bool]$Once = $false
    )
    # ValidateSet is a culture comparison: 'Convert<U+0001>' would be accepted and bound as typed. The value is matched ordinally (any letter
    # case, as before) and replaced by the official spelling; a value without an ordinal match is refused.
    $Action = Resolve-GuiOfficialValue $Action @('Convert','Recover','Finalize','Check')
    $Mode = Resolve-GuiOfficialValue $Mode @('Preview','Apply')
    $Phase = Resolve-GuiOfficialValue $Phase @('Both','AD','Cloud')
    $Scope = Resolve-GuiOfficialValue $Scope @('All','UsersOnly','SharedOnly')
    $Expect = Resolve-GuiOfficialValue $Expect @('Provisioned','Deprovisioned','Retained')
    foreach ($value in @($Batch, $Identity,$SearchBase,$CsvPath)) {
        if ($value -match '[\x00-\x1f]') { throw 'Selection contains a control character.' }
    }
    if ($MaxObjects -lt 0) { throw 'MaxObjects must be zero or positive.' }
    if ((Test-GuiOrdinal $Action 'Convert' -IgnoreCase) -and (-not (Test-GuiOrdinal $Phase 'Cloud' -IgnoreCase)) -and $Batch) { throw 'Convert AD/Both must not receive a batch: Apply creates a NEW Convert batch.' }
    if (((Test-GuiOrdinalIn $Action @('Recover','Finalize') -IgnoreCase) -or ((Test-GuiOrdinal $Action 'Convert' -IgnoreCase) -and (Test-GuiOrdinal $Phase 'Cloud' -IgnoreCase))) -and -not $Batch) {
        throw ('A {0} batch is required.' -f (Get-PraGuiBatchType $Action $Phase))
    }
    if ((Test-GuiOrdinal $Action 'Check' -IgnoreCase) -and -not $Batch -and -not $Identity) { throw 'Check requires a Convert batch or one identity (prefer a UPN).' }
    if ((Test-GuiOrdinal $Action 'Check' -IgnoreCase) -and (Test-GuiOrdinal $Mode 'Apply' -IgnoreCase)) { throw 'Check is always read-only.' }
    if ($MaxObjects -and -not ((Test-GuiOrdinal $Action 'Convert' -IgnoreCase) -and (Test-GuiOrdinalIn $Phase @('AD','Both') -IgnoreCase))) { throw 'MaxObjects is only available for Convert AD/Both.' }
    $null=Get-PraTargetOverride -SearchBase $SearchBase -CsvPath $CsvPath -Identity $Identity
    if (($SearchBase -or $CsvPath) -and -not ((Test-GuiOrdinal $Action 'Convert' -IgnoreCase) -and (Test-GuiOrdinalIn $Phase @('AD','Both') -IgnoreCase))) { throw 'OU/CSV selection is only available for Convert AD/Both.' }
    return [ordered]@{
        Action=$Action; Mode=$Mode; Phase=$(if ((Test-GuiOrdinal $Action 'Finalize' -IgnoreCase)) { 'Finalize' } elseif ((Test-GuiOrdinal $Action 'Check' -IgnoreCase)) { 'Cloud' } else { $Phase })
        Batch=$Batch; Identity=$Identity; SearchBase=$SearchBase; CsvPath=$CsvPath; Scope=$Scope; MaxObjects=$MaxObjects
        Expect=$(if ((Test-GuiOrdinal $Action 'Check' -IgnoreCase)) { $Expect } else { 'Provisioned' }); Once=$Once
    }
}

function ConvertTo-PraGuiNativeArgument {
    <# CommandLineToArgvW: double backslashes before quotes and the closing quote. No shell is used. #>
    param([AllowEmptyString()][string]$Value)
    if ($Value.Contains([string][char]0)) { throw 'NUL is not a valid argument.' }
    $escaped = [regex]::Replace($Value, '(\\*)"', '$1$1\"')
    $escaped = [regex]::Replace($escaped, '(\\+)$', '$1$1')
    return '"' + $escaped + '"'
}

function Get-PraGuiEngine {
    <# The engine child is the PowerShell 7 that hosts the window (same pwsh.exe, same version, same module paths). #>
    return Join-Path $PSHOME 'pwsh.exe'
}

function ConvertTo-PraGuiPowerShellLiteral {
    param([AllowEmptyString()][string]$Value)
    $escaped=$Value.Replace("'","''")
    foreach ($code in @(0x2018,0x2019,0x201A,0x201B)) {
        $quote=[string][char]$code
        $escaped=$escaped.Replace($quote,($quote+$quote))
    }
    return "'"+$escaped+"'"
}

function Get-PraGuiCommand {
    param([string]$Root, [string]$ConfigPath, [Collections.IDictionary]$Request, [string]$ScriptPath = '', [string]$BaseConfigPath = '')
    if (-not $ScriptPath) { $ScriptPath = Join-Path $Root 'Invoke-PraRemoteMailbox.ps1' }
    $tokens = New-Object 'Collections.Generic.List[string]'
    # No -NonInteractive: an interactive Connect-ExchangeOnline / Connect-MgGraph (Windows broker, WAM) is the normal cloud
    # sign-in of this tool and must be allowed to open its own window. The child's stdin is closed by
    # Start-PraGuiChildProcess instead, so a prompt gets an empty answer (end of file) instead of waiting for a keyboard, and the engine's own checks then refuse.
    foreach ($token in @('-NoProfile','-STA','-File', $ScriptPath, '-Action',$Request.Action,'-Mode',$Request.Mode,'-ConfigPath',$ConfigPath,'-Scope',$Request.Scope)) { $tokens.Add([string]$token) }
    # A run with settings changed in the window reads an effective copy of the configuration (-ConfigPath); -BaseConfigPath names the file it was made
    # from, so that the log, the report and the result list what differs from it.
    if ($BaseConfigPath) { $tokens.Add('-BaseConfigPath'); $tokens.Add($BaseConfigPath) }
    if ((Test-GuiOrdinalIn $Request.Action @('Convert','Recover') -IgnoreCase)) { $tokens.Add('-Phase'); $tokens.Add([string]$Request.Phase) }
    foreach ($name in @('Batch','Identity','SearchBase','CsvPath')) { if ($Request[$name]) { $tokens.Add('-'+$name); $tokens.Add([string]$Request[$name]) } }
    if ((Test-GuiOrdinal $Request.Action 'Convert' -IgnoreCase) -and (Test-GuiOrdinalIn $Request.Phase @('AD','Both') -IgnoreCase)) { $tokens.Add('-MaxObjects'); $tokens.Add([string]$Request.MaxObjects) }
    if ((Test-GuiOrdinal $Request.Action 'Check' -IgnoreCase)) { $tokens.Add('-Expect'); $tokens.Add([string]$Request.Expect) }
    if ($Request.Once) { $tokens.Add('-Once') }
    if ((Test-GuiOrdinal $Request.Mode 'Apply' -IgnoreCase)) { $tokens.Add('-Force') }
    $engine = Get-PraGuiEngine
    $displayTokens = @($engine) + @($tokens)
    # A cloud sign-in may be interactive (WAM needs a parent window): every action that reaches Exchange Online / Graph.
    $needsCloudWindow = ((Test-GuiOrdinal $Request.Action 'Check' -IgnoreCase)) -or ((Test-GuiOrdinalIn $Request.Action @('Convert','Recover') -IgnoreCase) -and (Test-GuiOrdinalIn $Request.Phase @('Cloud','Both') -IgnoreCase))
    return [pscustomobject]@{
        FilePath=$engine; Tokens=$tokens.ToArray(); NeedsCloudWindow=$needsCloudWindow
        Arguments=(@($tokens | ForEach-Object { ConvertTo-PraGuiNativeArgument $_ }) -join ' ')
        Display='& ' + ((@($displayTokens | ForEach-Object { ConvertTo-PraGuiPowerShellLiteral $_ })) -join ' ')
    }
}

function Get-PraGuiFileHash {
    param([string]$Path)
    return (Get-FileHash -LiteralPath $Path -Algorithm SHA256 -ErrorAction Stop).Hash.ToLowerInvariant()
}

function ConvertTo-PraGuiHash {
    param([string]$Value)
    $hash=$Value.Trim()
    if ($hash -notmatch '^[a-fA-F0-9]{64}\z') { throw 'Invalid SHA-256 hexadecimal value.' }
    return $hash.ToLowerInvariant()
}

function Read-PraGuiBatch {
    <# -AnyEnvironment: the Environment of the file is recorded but not compared (the list of batches of every environment of the backup folder). #>
    param([string]$Path, [string]$Environment, [switch]$AnyEnvironment)
    $item = [pscustomobject]@{ Path=$Path; Folder=(Split-Path $Path -Parent); Operation='?'; BatchId=''; Status=''; Valid=$false; Data=$null; Label=''; CopyPaths=@(); Environment=''; EnvMismatch=$false }
    try {
        $data = [IO.File]::ReadAllText($Path) | ConvertFrom-PraJson
        $item.Operation = [string](Get-PraGuiValue $data 'Operation' '?')
        $item.BatchId = [string](Get-PraGuiValue $data 'BatchId' ((Split-Path $item.Folder -Leaf) -replace '^(Batch|Finalize)-',''))
        if (-not (Test-GuiOrdinalIn $item.Operation @('Convert','Recover','RecoverFinalize'))) { throw 'Not a Convert, Recover or RecoverFinalize package.' }
        if (Test-GuiOrdinal (Get-PraGuiValue $data 'Kind' '') 'ADVerified' -IgnoreCase) { throw 'State/proof is not a batch.' }
        $item.Environment = [string](Get-PraGuiValue $data 'Environment' '')
        if (-not $AnyEnvironment -and -not (Test-GuiOrdinal $item.Environment $Environment)) { $item.EnvMismatch=$true; throw 'Environment differs from configuration.' }
        $schema = Get-PraGuiValue $data 'SchemaVersion' 1
        $schema = $schema -as [int]   # numeric comparisons below need an integer, not the raw JSON value (string, long or double)
        if ($null -eq $schema) { throw 'Unsupported schema.' }
        if (((Test-GuiOrdinal $item.Operation 'RecoverFinalize') -and $schema -ne 2) -or (-not (Test-GuiOrdinalIn $schema @(1,2,3) -IgnoreCase))) { throw 'Unsupported schema.' }
        $records = @(if (Test-GuiOrdinal $item.Operation 'RecoverFinalize') { Get-PraGuiValue $data 'Items' @() } else { Get-PraGuiValue $data 'Records' @() })
        if (-not $records.Count -or $null -eq $records[0]) { throw 'Empty or missing records.' }
        if ($schema -ge 2 -and -not (Test-GuiOrdinal (ConvertTo-PraGuiHash ([IO.File]::ReadAllText($Path+'.sha256'))) (Get-PraGuiFileHash $Path))) { throw 'SHA-256 mismatch.' }
        $item.Data=$data; $item.Valid=$true; $item.Status='Readable metadata - the engine still verifies everything'
    } catch { $item.Status='INVALID: '+$_.Exception.Message }
    $item.Label='{0} · {1} · {2}' -f $item.Operation,$item.BatchId,$item.Status
    return $item
}

function Read-PraGuiState {
    param([string]$Root, [string]$ConfigPath, [hashtable]$ScopeOverride=@{})
    $state = [pscustomobject]@{ Root=$Root; ConfigPath=$ConfigPath; Config=$null; ConfigError=''; Batches=@(); OtherEnvironment=@(); BatchError='' }
    try { $state.Config = Import-PraConfiguration -Path $ConfigPath -Root $Root -ScopeOverride $ScopeOverride }
    catch { $state.ConfigError=$_.Exception.Message; return $state }
    $folder = [string]$state.Config.Storage.BackupFolder
    if (-not (Test-Path -LiteralPath $folder)) { $state.BatchError='Backup folder not present yet: '+$folder; return $state }
    try {
        $state.Batches = @(Get-ChildItem -LiteralPath $folder -Recurse -File -Filter '*.json' -ErrorAction Stop |
            Where-Object { -not $_.Name.StartsWith('State-', [StringComparison]::OrdinalIgnoreCase) -and -not $_.Name.StartsWith('Journal-', [StringComparison]::OrdinalIgnoreCase) -and (Split-Path $_.DirectoryName -Leaf) -match '^(Batch|Finalize)-' } |
            ForEach-Object { Read-PraGuiBatch -Path $_.FullName -Environment $state.Config.Environment })
        # A batch of another environment is not an error of the folder: it is listed apart (a run can switch to its environment).
        $state.OtherEnvironment = @($state.Batches | Where-Object { $_.EnvMismatch } | ForEach-Object { Read-PraGuiBatch -Path $_.Path -Environment $state.Config.Environment -AnyEnvironment } | Where-Object { $_.Valid })
    } catch { $state.BatchError=$_.Exception.Message }
    return $state
}

function Resolve-PraGuiBatch {
    param([string]$Value, [string]$Operation, $State)
    if (-not $Value) { return $null }
    if ($Value -match '^[a-fA-F0-9]{8,32}$') {
        $found = @($State.Batches | Where-Object { $_.BatchId.StartsWith($Value,[StringComparison]::OrdinalIgnoreCase) -and (Test-GuiOrdinal $_.Operation $Operation) })
        if ($found.Count -gt 1) {
            $hashes=@(Get-GuiOrdinalUnique @($found | ForEach-Object { Get-PraGuiFileHash $_.Path }))
            if ($hashes.Count -ne 1) { throw 'Batch ID ambiguous: matching files have different contents. Give an exact JSON path.' }
            # Ordinal ranking (folder named after the batch first, then by path): [Array]::Sort with StringComparer.Ordinal, not the culture collation.
            $rankKeys=[string[]]@(foreach ($candidate in $found) {
                $prefix=if (Test-GuiOrdinal $candidate.Operation 'RecoverFinalize') { 'Finalize-' } else { 'Batch-' }
                $rank=if (Test-GuiOrdinal (Split-Path $candidate.Folder -Leaf) ($prefix+$candidate.BatchId) -IgnoreCase) { '0' } else { '1' }
                $rank+[string]$candidate.Path
            })
            $ranked=[object[]]@($found)
            [Array]::Sort([Array]$rankKeys,[Array]$ranked,[Collections.IComparer][StringComparer]::Ordinal)
            $found=@($ranked)
            $selected=$found[0]
            $selected.CopyPaths=@(Get-GuiOrdinalUnique @($found | ForEach-Object Path) -IgnoreCase)
            $found=@($selected)
        }
    } else {
        $path = $Value
        if (-not [IO.Path]::IsPathRooted($path)) { $path=Join-Path $State.Root $path }
        $entry = Get-Item -LiteralPath $path -ErrorAction Stop
        $found = @(if ($entry.PSIsContainer) {
            @(Get-ChildItem -LiteralPath $entry.FullName -File -Filter '*.json' -ErrorAction Stop | Where-Object { -not $_.Name.StartsWith('State-', [StringComparison]::OrdinalIgnoreCase) } |
                ForEach-Object { Read-PraGuiBatch $_.FullName $State.Config.Environment } | Where-Object { Test-GuiOrdinal $_.Operation $Operation })
        } else { Read-PraGuiBatch $entry.FullName $State.Config.Environment })
    }
    if ($found.Count -ne 1) { throw 'Batch not found or ambiguous. Give its exact JSON file; check the configuration backup folder.' }
    $batch = $found[0]
    if (-not $batch.Valid) { throw $batch.Status }
    if (-not (Test-GuiOrdinal $batch.Operation $Operation)) { throw "Expected $Operation, not $($batch.Operation)." }
    return $batch
}

function Get-PraGuiGuard {
    <# Content, not timestamps: all selected batch artifacts and the original Convert source are guarded, and so are the configuration file of the
       run (the effective copy when run settings were changed in the window) and the file it was made from. #>
    param([string]$Root, [string]$ConfigPath, [Collections.IDictionary]$Request, [string]$BaseConfigPath = '')
    $override=Get-PraTargetOverride -SearchBase ([string]$Request.SearchBase) -CsvPath ([string]$Request.CsvPath) -Identity $Request.Identity
    $state = Read-PraGuiState $Root $ConfigPath -ScopeOverride $override
    if ($state.ConfigError) { throw $state.ConfigError }
    $configFile = $ConfigPath
    if (-not [IO.Path]::IsPathRooted($configFile)) { $configFile=Join-Path $Root $configFile }
    $files = New-Object 'Collections.Generic.List[string]'
    $files.Add([IO.Path]::GetFullPath($configFile))
    if ($BaseConfigPath) {
        $baseFile = $BaseConfigPath
        if (-not [IO.Path]::IsPathRooted($baseFile)) { $baseFile=Join-Path $Root $baseFile }
        $files.Add([IO.Path]::GetFullPath($baseFile))
    }
    $files.Add((Join-Path $Root 'Invoke-PraRemoteMailbox.ps1'))
    $moduleFolder=Join-Path $Root 'module'
    if (Test-Path -LiteralPath $moduleFolder -PathType Container) {
        foreach ($file in @(Get-ChildItem -LiteralPath $moduleFolder -Recurse -File -ErrorAction Stop |
            Where-Object { Test-GuiOrdinalIn $_.Extension @('.psm1','.psd1','.ps1','.dll','.xaml') -IgnoreCase })) { $files.Add($file.FullName) }
    }
    foreach ($path in @($state.Config.Scope.CsvPath, $state.Config.SharedMailbox.CsvPath)) { if ($path) { $files.Add([string]$path) } }
    if ((Test-GuiOrdinal $state.Config.Scope.Mode 'Csv' -IgnoreCase) -and (Test-GuiOrdinal $Request.Action 'Convert' -IgnoreCase) -and (Test-GuiOrdinalIn $Request.Phase @('AD','Both') -IgnoreCase) -and -not $Request.Identity) {
        $null=@(Read-PraTargetCsv -Path $state.Config.Scope.CsvPath)
    }
    $batch = Resolve-PraGuiBatch $Request.Batch (Get-PraGuiBatchType $Request.Action $Request.Phase) $state
    if ($batch) {
        foreach ($file in @(Get-ChildItem -LiteralPath $batch.Folder -Recurse -File -ErrorAction Stop)) { $files.Add($file.FullName) }
        foreach ($copy in $batch.CopyPaths) {
            foreach ($file in @(Get-ChildItem -LiteralPath (Split-Path $copy -Parent) -Recurse -File -ErrorAction Stop)) { $files.Add($file.FullName) }
        }
        if ((Test-GuiOrdinalIn $Request.Action @('Convert','Recover') -IgnoreCase) -and (Test-GuiOrdinal $Request.Phase 'Cloud' -IgnoreCase)) {
            $proofPath = Join-Path $batch.Folder ('State-'+$batch.Data.BatchId+'.json')
            $proof = [IO.File]::ReadAllText($proofPath) | ConvertFrom-PraJson
            if (-not (Test-GuiOrdinal (Get-PraGuiValue $proof 'Kind' '') 'ADVerified') -or -not (Test-GuiOrdinal (Get-PraGuiValue $proof 'Operation' '') $Request.Action) -or
                -not (Test-GuiOrdinal (Get-PraGuiValue $proof 'Environment' '') $state.Config.Environment) -or
                -not (Test-GuiOrdinal (ConvertTo-PraGuiHash ([IO.File]::ReadAllText($proofPath+'.sha256'))) (Get-PraGuiFileHash $proofPath))) { throw 'Missing, invalid or mismatched AD proof.' }
        }
        if ((Test-GuiOrdinal $Request.Action 'Recover' -IgnoreCase) -and (Test-GuiOrdinal $Request.Phase 'Cloud' -IgnoreCase)) {
            $hash = [string](Get-PraGuiValue $batch.Data 'SourceBackupHash' '')
            if (-not $hash) { throw 'Recover batch lacks its original Convert source hash.' }
            $hash=ConvertTo-PraGuiHash $hash
            $sources = @($state.Batches | Where-Object { $_.Valid -and (Test-GuiOrdinal $_.Operation 'Convert') -and (Test-GuiOrdinal (Get-PraGuiFileHash $_.Path) $hash) })
            if (-not $sources.Count) { throw 'Copy the ORIGINAL Convert folder into Storage.BackupFolder as well as the Recover folder.' }
            foreach ($source in $sources) {
                foreach ($file in @(Get-ChildItem -LiteralPath $source.Folder -Recurse -File -ErrorAction Stop)) { $files.Add($file.FullName) }
            }
        }
    }
    $selection = [ordered]@{}
    foreach ($key in @('Action','Phase','Batch','Identity','SearchBase','CsvPath','Scope','MaxObjects','Expect','Once')) { $selection[$key]=$Request[$key] }
    # Canonical order of the guarded files: distinct (Windows paths are case-insensitive) then sorted by UTF-16 code unit, never by the culture collation.
    $guardedFiles = [string[]]@(Get-GuiOrdinalUnique @($files) -IgnoreCase)
    [Array]::Sort($guardedFiles, [StringComparer]::Ordinal)
    $artifactHashes = @(foreach ($path in $guardedFiles) { [ordered]@{ Path=$path; Hash=(Get-PraGuiFileHash $path) } })
    $payload = [ordered]@{ Root=[IO.Path]::GetFullPath($Root); Selection=$selection; Artifacts=$artifactHashes } | ConvertTo-Json -Depth 8 -Compress
    $sha = [Security.Cryptography.SHA256]::Create()
    try { return ([BitConverter]::ToString($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($payload)))).Replace('-','').ToLowerInvariant() }
    finally { $sha.Dispose() }
}

function Test-PraGuiResult {
    param($Result, [Collections.IDictionary]$Request, [int]$NativeExitCode, [string[]]$TransportIssues=@(), [string]$StandardError='')
    if ($TransportIssues.Count -or $StandardError.Trim() -or $null -eq $Result) { return $false }
    foreach ($field in @('kind','status','exitCode','action','mode','phase','success','error','pending','skipped','planned','total')) {
        if ($null -eq (Get-PraGuiValue $Result $field)) { return $false }
    }
    if (-not (Test-GuiOrdinal $Result.kind 'result') -or -not (Test-GuiOrdinal $Result.action $Request.Action) -or -not (Test-GuiOrdinal $Result.mode $Request.Mode) -or -not (Test-GuiOrdinal $Result.phase $Request.Phase)) { return $false }
    if ([string]$Result.exitCode -notmatch '^[012]$' -or [int]$Result.exitCode -ne $NativeExitCode -or $NativeExitCode -eq 1) { return $false }
    foreach ($field in @('success','error','pending','skipped','planned','total')) { if ([string]$Result.$field -notmatch '^\d+$') { return $false } }
    if ([int]$Result.error -ne 0 -or @((Get-PraGuiValue $Result 'issues' @())).Count) { return $false }
    if ([int64]$Result.total -ne ([int64]$Result.success+[int64]$Result.error+[int64]$Result.pending+[int64]$Result.skipped+[int64]$Result.planned)) { return $false }
    if ($NativeExitCode -eq 2) { return (Test-GuiOrdinal $Result.status 'Pending') -and [int]$Result.pending -gt 0 }
    return (Test-GuiOrdinalIn $Result.status @('Success','Planned')) -and [int]$Result.pending -eq 0
}

function Test-PraGuiPreview {
    param($Result, [Collections.IDictionary]$Request, [int]$NativeExitCode, [string[]]$TransportIssues=@(), [string]$StandardError='')
    if ((-not (Test-GuiOrdinal $Request.Mode 'Preview' -IgnoreCase)) -or (Test-GuiOrdinal $Request.Action 'Check' -IgnoreCase)) { return $false }
    if (-not (Test-PraGuiResult $Result $Request $NativeExitCode $TransportIssues $StandardError)) { return $false }
    return ([int64]$Result.success+[int64]$Result.pending+[int64]$Result.planned) -gt 0
}

function Read-PraGuiEvents {
    param([string]$Path, [long]$Position=0)
    $result = [pscustomobject]@{ Events=@(); Errors=@(); Position=$Position; HasPartial=$false }
    if (-not (Test-Path -LiteralPath $Path)) { return $result }
    $stream = [IO.File]::Open($Path,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::ReadWrite)
    $last=-1
    try {
        if ($stream.Length -lt $Position) { $result.Errors=@('Event file truncated.'); return $result }
        if ($stream.Length -eq $Position) { return $result }
        $length=$stream.Length
        [void]$stream.Seek($Position,[IO.SeekOrigin]::Begin)
        $buffer = New-Object byte[] ([int][Math]::Min(1048576,($length-$Position)))
        $read=$stream.Read($buffer,0,$buffer.Length)
        if ($read -gt 0) { $last=[Array]::LastIndexOf($buffer,[byte]10,($read-1),$read) }
        if ($last -lt 0 -and $read -gt 0 -and $stream.Position -lt $length) {
            # A single polling message may exceed the normal chunk. Expand until LF
            # (or the snapshotted EOF); never advance past an unfinished record.
            $expanded=[IO.MemoryStream]::new()
            try {
                $expanded.Write($buffer,0,$read)
                while ($last -lt 0 -and $stream.Position -lt $length) {
                    $chunk=New-Object byte[] ([int][Math]::Min(1048576,($length-$stream.Position)))
                    $count=$stream.Read($chunk,0,$chunk.Length)
                    if ($count -le 0) { break }
                    $offset=$expanded.Length
                    $expanded.Write($chunk,0,$count)
                    $newline=[Array]::LastIndexOf($chunk,[byte]10,($count-1),$count)
                    if ($newline -ge 0) { $last=[int]($offset+$newline) }
                }
                $buffer=$expanded.ToArray()
                $read=$buffer.Length
            } finally { $expanded.Dispose() }
        }
    } finally { $stream.Dispose() }
    $result.HasPartial=$last -lt ($read-1)
    if ($last -lt 0) { return $result }
    $events=New-Object 'Collections.Generic.List[object]'
    $errors=New-Object 'Collections.Generic.List[string]'
    $text=[Text.Encoding]::UTF8.GetString($buffer,0,$last+1).TrimStart([char]0xfeff)
    foreach ($line in $text.Split([char]10)) {
        if (-not $line.Trim()) { continue }
        try {
            $record=$line | ConvertFrom-PraJson
            if (-not (Test-GuiOrdinalIn (Get-PraGuiValue $record 'kind' '') @('start','step','item','summary','result','plan','progress','count'))) { throw 'Unknown or missing event kind.' }
            $events.Add($record)
        } catch { $errors.Add('Invalid event JSONL: '+$_.Exception.Message) }
    }
    $result.Events=$events.ToArray(); $result.Errors=$errors.ToArray(); $result.Position=$Position+$last+1
    return $result
}

# The redirected output of the engine child goes straight to a file with pure .NET code: Stream.CopyToAsync (thread pool, no
# PowerShell code on a background thread, no compiler, no temporary DLL) copies the pipe to <base>.stdout.txt / .stderr.txt as the
# child writes, so a child that prints more than the pipe buffer never blocks whatever the window timer does. The window thread only
# reads what has been written so far, through a second FileStream, and decodes it with the console code page of the child.
function New-PraGuiStreamCollector {
    <#
    .SYNOPSIS
        Collector of one redirected child stream: IsCompleted (end of stream), TakeText() (text received since the previous
        call) and Result (the whole text; waits for the end of the stream). The raw bytes are kept in -Path.
    #>
    param([Parameter(Mandatory)][IO.Stream]$Stream, [Parameter(Mandatory)][string]$Path, [Text.Encoding]$Encoding)
    # The child writes with the console code page; without a console in this host, UTF-8.
    if (-not $Encoding) { try { $Encoding = [Console]::OutputEncoding } catch { $Encoding = New-Object Text.UTF8Encoding($false) } }
    # Not buffered (bufferSize 1): each write reaches the file at once, so the window sees it.
    $file = New-Object IO.FileStream($Path, [IO.FileMode]::Create, [IO.FileAccess]::Write, [IO.FileShare]::ReadWrite, 1)
    $state = @{ Stream = $Stream; File = $file; Path = $Path; Task = $Stream.CopyToAsync($file); Offset = [long]0; Decoder = $Encoding.GetDecoder(); Encoding = $Encoding; Closed = $false }
    $collector = New-Object psobject -Property @{ State = $state }
    Add-Member -InputObject $collector -MemberType ScriptMethod -Name Close -Value {
        if (-not $this.State.Closed) {
            $this.State.Closed = $true
            try { $this.State.File.Flush() } catch { Write-Verbose $_.Exception.Message }
            $this.State.File.Dispose(); $this.State.Stream.Dispose()
        }
    }
    Add-Member -InputObject $collector -MemberType ScriptProperty -Name IsCompleted -Value {
        if (-not $this.State.Task.IsCompleted) { return $false }
        $this.Close()
        return $true
    }
    Add-Member -InputObject $collector -MemberType ScriptMethod -Name TakeText -Value {
        $reader = [IO.File]::Open($this.State.Path, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::ReadWrite)
        try {
            $count = [int][Math]::Min(1048576, $reader.Length - $this.State.Offset)
            if ($count -le 0) { return '' }
            [void]$reader.Seek($this.State.Offset, [IO.SeekOrigin]::Begin)
            $buffer = New-Object byte[] $count
            $read = $reader.Read($buffer, 0, $count)
            $this.State.Offset += $read
            $chars = New-Object char[] ($this.State.Encoding.GetMaxCharCount($read))
            $length = $this.State.Decoder.GetChars($buffer, 0, $read, $chars, 0)
            return [string]::new($chars, 0, $length)
        } finally { $reader.Dispose() }
    }
    Add-Member -InputObject $collector -MemberType ScriptProperty -Name Result -Value {
        try { $null = $this.State.Task.GetAwaiter().GetResult() } catch { Write-Verbose $_.Exception.Message }
        $this.Close()
        return $this.State.Encoding.GetString([IO.File]::ReadAllBytes($this.State.Path))
    }
    return $collector
}

function Test-PraGuiSamePath {
    <# Windows paths are case-insensitive: compare the FULL paths with OrdinalIgnoreCase, not the typed text with a culture comparison. #>
    param([AllowEmptyString()][string]$Left, [AllowEmptyString()][string]$Right)
    if (-not $Left.Trim() -or -not $Right.Trim()) { return $false }
    try {
        $a=[IO.Path]::GetFullPath($Left.Trim()).TrimEnd('\'); $b=[IO.Path]::GetFullPath($Right.Trim()).TrimEnd('\')
    } catch { return $false }
    return [string]::Equals($a,$b,[StringComparison]::OrdinalIgnoreCase)
}

function Test-PraGuiConfirmation {
    <# The typed confirmation is the action name (CONVERT, RECOVER, FINALIZE), in any letter case, ignoring surrounding spaces. #>
    param([AllowEmptyString()][string]$Typed, [string]$Action)
    if (-not $Action) { return $false }
    return [string]::Equals($Typed.Trim(),$Action.ToUpperInvariant(),[StringComparison]::OrdinalIgnoreCase)
}

function Start-PraGuiNativeConsoleChild {
    <#
    .SYNOPSIS
        Starts the engine child of a cloud action in its OWN, new, visible console (CREATE_NEW_CONSOLE) with stdin, stdout and
        stderr still redirected to anonymous pipes. Returns the process and the three pipe streams.
    .DESCRIPTION
        .NET cannot ask for a new console together with redirected streams (ProcessStartInfo only inherits the console of the
        parent), so CreateProcessW is called directly through the Reflection.Emit binding of PRA.Common (no compiler, no DLL).
        The child no longer shares the console of the terminal that started the window: closing or hiding that terminal does not
        reach the engine in the middle of an Apply, and the Windows account broker (WAM) of the interactive sign-in gets the
        window of this new console as its parent.
        Only the three pipe ends of the child are inherited: CreateProcess is given a STARTUPINFOEX with a PROC_THREAD_ATTRIBUTE_HANDLE_LIST
        naming them, so no other inheritable handle of the window process (a pipe end of another child, a file) reaches the engine - an
        extra copy of a pipe end held by the child would delay the end of the stream and the run would never complete. The window itself creates
        no inheritable handle but those three client ends, which it closes as soon as the child owns them.
        A child that dies before the window can attach to it (the process list no longer has it) is not silent: its error output is drained
        to the end of the stream, its exit code is read from the process handle, and both are in the error.
    #>
    param($Command, [string]$Root, [hashtable]$Environment)
    $native = Get-PraNativeProcessApi
    $out = New-Object IO.Pipes.AnonymousPipeServerStream([IO.Pipes.PipeDirection]::In, [IO.HandleInheritability]::Inheritable)
    $err = New-Object IO.Pipes.AnonymousPipeServerStream([IO.Pipes.PipeDirection]::In, [IO.HandleInheritability]::Inheritable)
    $in = New-Object IO.Pipes.AnonymousPipeServerStream([IO.Pipes.PipeDirection]::Out, [IO.HandleInheritability]::Inheritable)
    $title = [IntPtr]::Zero; $block = [IntPtr]::Zero; $attributeList = [IntPtr]::Zero; $handleList = [IntPtr]::Zero; $attributeListReady = $false
    $started = $false; $processHandle = $null; $threadHandle = $null
    try {
        $variables = [Environment]::GetEnvironmentVariables()
        $merged = @{}
        foreach ($key in $variables.Keys) { $merged[[string]$key] = [string]$variables[$key] }
        foreach ($key in $Environment.Keys) {
            if ($null -eq $Environment[$key]) { [void]$merged.Remove([string]$key) } else { $merged[[string]$key] = [string]$Environment[$key] }
        }
        # The environment block is sorted by upper-cased name, by UTF-16 code unit (never the culture collation).
        $names = [string[]]@($merged.Keys)
        $sortKeys = [string[]]@(foreach ($name in $names) { $name.ToUpperInvariant() })
        [Array]::Sort([Array]$sortKeys, [Array]$names, [Collections.IComparer][StringComparer]::Ordinal)
        $text = (@($names | ForEach-Object { $_ + '=' + $merged[$_] }) -join [string][char]0) + [string][char]0 + [string][char]0
        $block = [Runtime.InteropServices.Marshal]::StringToHGlobalUni($text)
        $title = [Runtime.InteropServices.Marshal]::StringToHGlobalUni('PRA Remote Mailbox - cloud sign-in (keep this window open until the operation ends)')
        $api = $native.Api
        # The three client ends are the only handles the child may inherit.
        $clientHandles = @($in.ClientSafePipeHandle.DangerousGetHandle(), $out.ClientSafePipeHandle.DangerousGetHandle(), $err.ClientSafePipeHandle.DangerousGetHandle())
        $startupEx = [Activator]::CreateInstance($native.StartupInfoEx)
        $startup = $startupEx.GetType().GetField('StartupInfo').GetValue($startupEx)
        $startup.GetType().GetField('cb').SetValue($startup, [uint32][Runtime.InteropServices.Marshal]::SizeOf($startupEx))
        $startup.GetType().GetField('lpTitle').SetValue($startup, $title)
        $startup.GetType().GetField('dwFlags').SetValue($startup, [uint32]0x100)   # STARTF_USESTDHANDLES
        $startup.GetType().GetField('hStdInput').SetValue($startup, $clientHandles[0])
        $startup.GetType().GetField('hStdOutput').SetValue($startup, $clientHandles[1])
        $startup.GetType().GetField('hStdError').SetValue($startup, $clientHandles[2])
        $startupEx.GetType().GetField('StartupInfo').SetValue($startupEx, $startup)
        # Attribute list with PROC_THREAD_ATTRIBUTE_HANDLE_LIST (0x20002): first call asks the size, second one initialises the list.
        $initialize = New-Object object[] 4
        $initialize[0] = [IntPtr]::Zero; $initialize[1] = [int]1; $initialize[2] = [int]0; $initialize[3] = [IntPtr]::Zero
        [void]$api.GetMethod('InitializeProcThreadAttributeList').Invoke($null, $initialize)
        $size = [IntPtr]$initialize[3]
        if ($size -eq [IntPtr]::Zero) { throw ('The engine child process cannot start (attribute list size: {0}).' -f (Get-PraWin32ErrorText ([Runtime.InteropServices.Marshal]::GetLastWin32Error()))) }
        $attributeList = [Runtime.InteropServices.Marshal]::AllocHGlobal($size)
        $initialize[0] = $attributeList; $initialize[3] = $size
        if (-not [bool]$api.GetMethod('InitializeProcThreadAttributeList').Invoke($null, $initialize)) {
            throw ('The engine child process cannot start (InitializeProcThreadAttributeList failed: {0}).' -f (Get-PraWin32ErrorText ([Runtime.InteropServices.Marshal]::GetLastWin32Error())))
        }
        $attributeListReady = $true
        $handleList = [Runtime.InteropServices.Marshal]::AllocHGlobal([IntPtr]::Size * 3)
        for ($i = 0; $i -lt 3; $i++) { [Runtime.InteropServices.Marshal]::WriteIntPtr($handleList, $i * [IntPtr]::Size, [IntPtr]$clientHandles[$i]) }
        $update = New-Object object[] 7
        $update[0] = $attributeList; $update[1] = [uint32]0; $update[2] = [IntPtr]0x20002; $update[3] = $handleList; $update[4] = [IntPtr]([IntPtr]::Size * 3); $update[5] = [IntPtr]::Zero; $update[6] = [IntPtr]::Zero
        if (-not [bool]$api.GetMethod('UpdateProcThreadAttribute').Invoke($null, $update)) {
            throw ('The engine child process cannot start (UpdateProcThreadAttribute failed: {0}).' -f (Get-PraWin32ErrorText ([Runtime.InteropServices.Marshal]::GetLastWin32Error())))
        }
        $startupEx.GetType().GetField('lpAttributeList').SetValue($startupEx, $attributeList)
        $information = [Activator]::CreateInstance($native.ProcessInformation)
        $commandLine = New-Object Text.StringBuilder ('"' + $Command.FilePath + '" ' + $Command.Arguments)
        # CREATE_NEW_CONSOLE (0x10) | CREATE_UNICODE_ENVIRONMENT (0x400) | EXTENDED_STARTUPINFO_PRESENT (0x80000); bInheritHandles is true, but
        # only the three handles of the list are inherited.
        $arguments = New-Object object[] 10
        $arguments[1] = [Text.StringBuilder]$commandLine; $arguments[2] = [IntPtr]::Zero; $arguments[3] = [IntPtr]::Zero; $arguments[4] = $true
        $arguments[5] = [uint32](0x410 -bor 0x80000); $arguments[6] = [IntPtr]$block; $arguments[7] = [string]$Root; $arguments[8] = $startupEx.psobject.BaseObject; $arguments[9] = $information.psobject.BaseObject
        $created = [bool]$api.GetMethod('CreateProcessEx').Invoke($null, $arguments)
        $lastError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
        if (-not $created) { throw ('The engine child process cannot start (CreateProcess failed, Win32 error {0}).' -f (Get-PraWin32ErrorText $lastError)) }
        $started = $true
        $information = $arguments[9]
        $processId = [int]$information.GetType().GetField('dwProcessId').GetValue($information)
        $processHandle = New-Object Microsoft.Win32.SafeHandles.SafeProcessHandle ($information.GetType().GetField('hProcess').GetValue($information), $true)
        $threadHandle = New-Object Microsoft.Win32.SafeHandles.SafeProcessHandle ($information.GetType().GetField('hThread').GetValue($information), $true)
        # The child owns its ends now: close ours. Closing the write end of its stdin gives it an end of file at once.
        $out.DisposeLocalCopyOfClientHandle(); $err.DisposeLocalCopyOfClientHandle(); $in.DisposeLocalCopyOfClientHandle()
        $in.Dispose()
        # Touching SafeHandle makes the Process object open and keep its own handle now, while ours still pins the process (its exit code stays readable).
        $process = $null
        try { $process = [Diagnostics.Process]::GetProcessById($processId); $null = $process.SafeHandle }
        catch {
            # The child is already gone (it died at start, before the window could attach): its error output and its exit code are not lost.
            $attachError = $_.Exception.Message
            $code = [uint32]0
            $codeArguments = New-Object object[] 2
            $codeArguments[0] = $processHandle.DangerousGetHandle(); $codeArguments[1] = $code
            [void]$api.GetMethod('GetExitCodeProcess').Invoke($null, $codeArguments)
            $exitCode = [uint32]$codeArguments[1]
            $errorText = ''
            if ($exitCode -ne 259) {   # 259 = STILL_ACTIVE: never wait for a child that has not ended
                $reader = New-Object IO.StreamReader($err)
                $task = $reader.ReadToEndAsync()
                if ($task.Wait(5000)) { $errorText = $task.Result.Trim() }
            }
            throw ('The engine child process ended before the window could attach to it (exit code {0}; {1}). Error output: {2}' -f $exitCode,$attachError,$(if ($errorText) { $errorText } else { '(none)' }))
        }
        return [pscustomobject]@{ Process = $process; Output = $out; Errors = $err }
    }
    catch {
        $out.Dispose(); $err.Dispose(); $in.Dispose()
        throw
    }
    finally {
        if ($threadHandle) { $threadHandle.Dispose() }
        if ($processHandle) { $processHandle.Dispose() }
        if ($attributeListReady) { try { $native.Api.GetMethod('DeleteProcThreadAttributeList').Invoke($null, @($attributeList)) | Out-Null } catch { Write-Verbose $_.Exception.Message } }
        if ($attributeList -ne [IntPtr]::Zero) { [Runtime.InteropServices.Marshal]::FreeHGlobal($attributeList) }
        if ($handleList -ne [IntPtr]::Zero) { [Runtime.InteropServices.Marshal]::FreeHGlobal($handleList) }
        if ($title -ne [IntPtr]::Zero) { [Runtime.InteropServices.Marshal]::FreeHGlobal($title) }
        if ($block -ne [IntPtr]::Zero) { [Runtime.InteropServices.Marshal]::FreeHGlobal($block) }
    }
}

function Start-PraGuiChildProcess {
    param($Command, [string]$Root, [string]$EventPath)
    if (-not (Test-Path -LiteralPath $Command.FilePath -PathType Leaf)) { throw 'PowerShell 7 (pwsh.exe) is unavailable for the engine child process.' }
    # Does this child sign in to the cloud? (the AD-only OU lookup has no such flag)
    $needsWindow=($null -ne $Command.PSObject.Properties['NeedsCloudWindow']) -and [bool]$Command.NeedsCloudWindow
    $environment=@{ PRA_EVENT_FILE=$EventPath; PRA_ICONS='Ascii'; PRA_STOP_FILE=$null }
    # The engine output files: <base>.stdout.txt and <base>.stderr.txt next to the event file.
    $base=$EventPath -replace '\.events\.jsonl$',''
    # Console and window of the child:
    #  * Cloud actions (an interactive Connect-ExchangeOnline / Connect-MgGraph may open the Windows account broker, WAM, which
    #    needs a parent window): the child gets its OWN new visible console (CREATE_NEW_CONSOLE, Start-PraGuiNativeConsoleChild). It
    #    does not share the console of the terminal that started the window, so closing that terminal cannot kill an Apply in
    #    the middle, and WAM has a window of its own to attach to. Under Windows Terminal as the default terminal application the
    #    new console opens as a terminal window of its own.
    #  * AD-only children (Phase AD, Finalize, OU lookup) never sign in: CREATE_NO_WINDOW, no console window at all.
    #  * stdin is closed at once in both cases. It replaces -NonInteractive, which would also forbid the interactive sign-in:
    #    a prompt gets an empty answer / end of file and the engine's own checks then refuse; nothing waits for a keyboard.
    if ($needsWindow) { $child=Start-PraGuiNativeConsoleChild $Command $Root $environment }
    else {
        $info=New-Object Diagnostics.ProcessStartInfo
        $info.FileName=$Command.FilePath; $info.Arguments=$Command.Arguments; $info.WorkingDirectory=$Root
        $info.UseShellExecute=$false; $info.CreateNoWindow=$true
        $info.RedirectStandardOutput=$true; $info.RedirectStandardError=$true; $info.RedirectStandardInput=$true
        foreach ($key in $environment.Keys) {
            if ($null -eq $environment[$key]) { [void]$info.EnvironmentVariables.Remove($key) } else { $info.EnvironmentVariables[$key]=[string]$environment[$key] }
        }
        $process=[Diagnostics.Process]::Start($info)
        $process.StandardInput.Close()
        $child=[pscustomobject]@{ Process=$process; Output=$process.StandardOutput.BaseStream; Errors=$process.StandardError.BaseStream }
    }
    return [pscustomobject]@{
        Process=$child.Process
        Output=(New-PraGuiStreamCollector $child.Output ($base+'.stdout.txt'))
        Errors=(New-PraGuiStreamCollector $child.Errors ($base+'.stderr.txt'))
    }
}



#region Window: notifying rows, theme, prerequisite detection
# The rows shown by the window are ExpandoObject instances: they notify WPF whenever a value is set, so a step, an object or a light changes on
# screen at once, with no compiled helper type and no refresh of the whole list.
function New-PraGuiRow {
    param([hashtable]$Data)
    $row=[Dynamic.ExpandoObject]::new()
    foreach ($key in $Data.Keys) { $row.$key=$Data[$key] }
    return ,$row
}

function Set-PraGuiRow {
    param($Row, [hashtable]$Data)
    foreach ($key in $Data.Keys) { $Row.$key=$Data[$key] }
}

function Initialize-PraGuiTheme {
    param([ValidateSet('System','Light','Dark')][string]$Theme='System')
    Add-Type -AssemblyName PresentationFramework,PresentationCore,WindowsBase,System.Xaml
    $app=[Windows.Application]::Current
    if (-not $app) { $app=New-Object Windows.Application; $app.ShutdownMode=[Windows.ShutdownMode]::OnExplicitShutdown }
    # ThemeMode (native Fluent theme) exists on .NET 9+, i.e. PowerShell 7.5+. There is no other window theme.
    $property=[Windows.Application].GetProperty('ThemeMode')
    if (-not $property) { throw 'The window requires the native Fluent theme of PowerShell 7.5+ (.NET 9).' }
    $dark=(Test-GuiOrdinal $Theme 'Dark' -IgnoreCase)
    if ((Test-GuiOrdinal $Theme 'System' -IgnoreCase)) {
        $setting=Get-ItemProperty -LiteralPath 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize' -ErrorAction SilentlyContinue
        $dark=$null -ne $setting -and (Get-PraGuiValue $setting 'AppsUseLightTheme' 1) -eq 0
    }
    $mode=[Activator]::CreateInstance($property.PropertyType,[object[]]@($(if ($dark) { 'Dark' } else { 'Light' })))
    $property.SetValue($app,$mode,$null)
    return [pscustomobject]@{ Fluent=$true; Dark=$dark }
}

function Set-PraGuiTheme {
    param($Window, $Theme)
    # The surface, card and text brushes come from the native Fluent theme (Application.ThemeMode); only the brand and status colours are set here.
    # The Fluent keys that a Fluent build would not define are added from the same palette as the other consoles of the house.
    $colors=@{
        PraBrand=@('#B11F4B','#FD8EA1'); PraBrandText=@('#B11F4B','#FD8EA1'); PraOnBrand=@('#FFFFFF','#1B1B1B'); PraAccentSoft=@('#14B11F4B','#33FD8EA1')
        PraCritical=@('#DC2626','#F87171'); PraSuccess=@('#16A34A','#4ADE80'); PraCaution=@('#B45309','#FBBF24')
        PraInfoBg=@('#F0EEEA','#2E2E2E'); PraSuccessBg=@('#EAF7EE','#334ADE80'); PraCautionBg=@('#FFF7E8','#33FBBF24'); PraCriticalBg=@('#FDECEC','#33F87171')
        PraTrack=@('#E6E3DE','#4A4A4A')
        AccentFillColorDefaultBrush=@('#B11F4B','#FD8EA1'); AccentButtonBackground=@('#B11F4B','#FD8EA1'); AccentButtonBorderBrush=@('#B11F4B','#FD8EA1')
    }
    $fallback=@{
        ApplicationBackgroundBrush=@('#F7F4EF','#202020'); CardBackgroundFillColorDefaultBrush=@('#FFFFFF','#2B2B2B'); CardStrokeColorDefaultBrush=@('#DEDEDE','#3D3D3D')
        ControlFillColorDefaultBrush=@('#FFFFFF','#2D2D2D'); ControlFillColorSecondaryBrush=@('#F5F5F5','#363636'); DividerStrokeColorDefaultBrush=@('#DEDEDE','#3D3D3D')
        LayerFillColorDefaultBrush=@('#FCFBF8','#262626'); TextFillColorPrimaryBrush=@('#242424','#FFFFFF'); TextFillColorSecondaryBrush=@('#5C5C5C','#C5C5C5')
        TextFillColorTertiaryBrush=@('#8A8A8A','#9A9A9A')
    }
    $index=[int][bool]$Theme.Dark
    foreach ($key in $colors.Keys) {
        $brush=[Windows.Media.SolidColorBrush]::new([Windows.Media.ColorConverter]::ConvertFromString($colors[$key][$index]))
        $brush.Freeze(); $Window.Resources[$key]=$brush
    }
    foreach ($key in $fallback.Keys) {
        if ($null -ne $Window.TryFindResource($key)) { continue }
        $brush=[Windows.Media.SolidColorBrush]::new([Windows.Media.ColorConverter]::ConvertFromString($fallback[$key][$index]))
        $brush.Freeze(); $Window.Resources[$key]=$brush
    }
}

function Set-PraGuiPill {
    <# Colours a pill (border + text) for a level: Ok, Warn, Fail, Brand or neutral. #>
    param($Border, $Text, [string]$Level)
    $pair=switch ($Level) {
        'Ok' { 'PraSuccessBg','PraSuccess' }
        'Warn' { 'PraCautionBg','PraCaution' }
        'Fail' { 'PraCriticalBg','PraCritical' }
        'Brand' { 'PraAccentSoft','PraBrandText' }
        default { 'PraInfoBg','TextFillColorSecondaryBrush' }
    }
    $Border.SetResourceReference([Windows.Controls.Border]::BackgroundProperty,$pair[0])
    $Text.SetResourceReference([Windows.Controls.TextBlock]::ForegroundProperty,$pair[1])
}

$script:GuiModuleCache = @{}
function Get-PraGuiHighestModule {
    <# The highest installed version of a module (not imported). Scanning the module path is slow: the answer is kept until -Refresh. #>
    param([string[]]$Name, [switch]$Refresh)
    $key=$Name -join '|'
    if (-not $Refresh -and $script:GuiModuleCache.ContainsKey($key)) { return $script:GuiModuleCache[$key] }
    $best=$null
    foreach ($module in @(Get-Module -ListAvailable -Name $Name -SkipEditionCheck -ErrorAction SilentlyContinue)) {
        if ($null -eq $best -or $module.Version -gt $best.Version) { $best=$module }
    }
    $script:GuiModuleCache[$key]=$best
    return $best
}

function Get-PraGuiPrerequisite {
    <#
    .SYNOPSIS
        Real detection of what this server can do: modules (Get-Module -ListAvailable), the certificate of the sign-in (certificate stores, with its
        expiry), the interactive sign-in (Windows account broker) and the Entra Connect synchronisation. Nothing is imported or connected.
    .OUTPUTS
        Lights (Name, Status Ok/Warn/Fail, Detail), AD and Cloud capabilities and the Role (Both, AD, Cloud, None).
    #>
    [CmdletBinding()]
    param([string]$MinExoVersion='3.10.0', [bool]$DisableWam=$false, [bool]$SyncEnabled=$true, [string]$SyncServer='', [ValidateSet('Cert','Wam')][string]$Signin='Wam', [string]$Thumbprint='', [switch]$Refresh)
    $lights=New-Object 'Collections.Generic.List[object]'
    $light={ param($Name,$Status,$Detail) $lights.Add([ordered]@{ Name=$Name; Status=$Status; Detail=$Detail }) }
    $ad=Get-PraGuiHighestModule @('ActiveDirectory') -Refresh:$Refresh
    if ($ad) { & $light 'RSAT ActiveDirectory' 'Ok' ('Installed, version {0}.' -f $ad.Version) }
    else { & $light 'RSAT ActiveDirectory' 'Fail' 'Not installed: the Active Directory parts cannot run on this server (install the RSAT feature Active Directory module).' }
    $exo=Get-PraGuiHighestModule @('ExchangeOnlineManagement') -Refresh:$Refresh
    $minimum=[version]'0.0'; [void][version]::TryParse($MinExoVersion,[ref]$minimum)
    $exoOk=$false
    if (-not $exo) { & $light 'ExchangeOnlineManagement' 'Fail' ('Not installed (version {0} or later needed): Install-Module ExchangeOnlineManagement.' -f $MinExoVersion) }
    elseif ($exo.Version -lt $minimum) { & $light 'ExchangeOnlineManagement' 'Fail' ('Version {0} is too old: {1} or later is needed.' -f $exo.Version,$MinExoVersion) }
    else { $exoOk=$true; & $light 'ExchangeOnlineManagement' 'Ok' ('Installed, version {0}.' -f $exo.Version) }
    $graph=Get-PraGuiHighestModule @('Microsoft.Graph.Authentication') -Refresh:$Refresh
    $graphUsers=Get-PraGuiHighestModule @('Microsoft.Graph.Users') -Refresh:$Refresh
    $graphOk=$false
    if ($graph -and $graphUsers) { $graphOk=$true; & $light 'Microsoft.Graph' 'Ok' ('Installed, version {0}.' -f $graph.Version) }
    else { & $light 'Microsoft.Graph' 'Fail' 'Not installed (Authentication and Users): the cloud parts and Check cannot run on this server (Install-Module Microsoft.Graph).' }
    if (-not $SyncEnabled) { & $light 'Entra Connect sync' 'NA' 'Not used: EntraConnect.Sync is off in the configuration.' }
    elseif ($SyncServer) { & $light 'Entra Connect sync' 'Ok' ('The synchronisation is started on {0} (reachability is checked when the run starts).' -f $SyncServer) }
    elseif (Get-PraGuiHighestModule @('ADSync') -Refresh:$Refresh) { & $light 'Entra Connect sync' 'Ok' 'ADSync module found on this server.' }
    else { & $light 'Entra Connect sync' 'Warn' 'No ADSync module here and no Entra Connect server in the configuration: an Active Directory run that synchronises will refuse to start.' }
    $signinOk=$false
    if ((Test-GuiOrdinal $Signin 'Cert' -IgnoreCase)) {
        $found=$null; $store=''
        if ($Thumbprint) {
            # The Exchange Online and Graph certificate sign-in of the engine reads CurrentUser\My, the store of the account that runs the tool: that is the store looked at.
            # A thumbprint that is only in LocalMachine\My is reported, because the engine would not find it.
            foreach ($location in @('CurrentUser','LocalMachine')) {
                foreach ($certificate in @(Get-ChildItem -LiteralPath ('Cert:\{0}\My' -f $location) -ErrorAction SilentlyContinue)) {
                    if ([string]::Equals([string]$certificate.Thumbprint,$Thumbprint.Trim(),[StringComparison]::OrdinalIgnoreCase)) { $found=$certificate; $store=$location; break }
                }
                if ($found) { break }
            }
        }
        $short=if ($Thumbprint.Length -gt 12) { $Thumbprint.Substring(0,6)+'...'+$Thumbprint.Substring($Thumbprint.Length-4) } else { $Thumbprint }
        if (-not $Thumbprint) { & $light 'Sign-in: Certificate' 'Fail' 'No certificate thumbprint is set (Run settings, or Cloud.CertificateThumbprint in the configuration).' }
        elseif (-not $found) { & $light 'Sign-in: Certificate' 'Fail' ('Thumbprint {0} is not in CurrentUser\My of the account that runs the tool, where the sign-in looks for it.' -f $short) }
        elseif (Test-GuiOrdinal $store 'LocalMachine') { & $light 'Sign-in: Certificate' 'Fail' ('Certificate {0} is only in LocalMachine\My: the sign-in reads CurrentUser\My of the account that runs the tool. Import it there (with its private key).' -f $short) }
        elseif ($found.NotAfter -lt [datetime]::Now) { & $light 'Sign-in: Certificate' 'Fail' ('Certificate {0} expired on {1}.' -f $short,$found.NotAfter.ToString('d MMM yyyy',[Globalization.CultureInfo]::InvariantCulture)) }
        elseif (-not $found.HasPrivateKey) { & $light 'Sign-in: Certificate' 'Fail' ('Certificate {0} has no private key on this server.' -f $short) }
        else { $signinOk=$true; & $light 'Sign-in: Certificate' 'Ok' ('Thumbprint {0} found in CurrentUser\My ({1}), valid until {2}.' -f $short,$env:USERNAME,$found.NotAfter.ToString('d MMM yyyy',[Globalization.CultureInfo]::InvariantCulture)) }
    } else {
        $build=[Environment]::OSVersion.Version.Build
        if ($DisableWam) { & $light 'Sign-in: Interactive (WAM)' 'Warn' 'The configuration disables the Windows account broker (Exo.DisableWAM): the sign-in falls back to a browser or device code.'; $signinOk=$true }
        elseif ($build -lt 17763) { & $light 'Sign-in: Interactive (WAM)' 'Fail' 'The Windows account broker needs Windows 10 version 1809 or later.' }
        else { $signinOk=$true; & $light 'Sign-in: Interactive (WAM)' 'Ok' 'A Microsoft sign-in window opens when the run starts.' }
    }
    $canAd=[bool]$ad
    $canCloud=$exoOk -and $graphOk -and $signinOk
    $role=if ($canAd -and $canCloud) { 'Both' } elseif ($canAd) { 'AD' } elseif ($canCloud) { 'Cloud' } else { 'None' }
    return [pscustomobject]@{ Lights=$lights.ToArray(); AD=$canAd; Cloud=$canCloud; Role=$role }
}
#endregion

#region Microsoft 365 reachability: decides Both / AD / Cloud once the programs are installed
# The programs alone do not make a server able to run the cloud part: it must also reach Microsoft 365. The test is an HTTPS request (HEAD, port 443)
# to the sign-in endpoint and to the Exchange Online endpoint, sent through the default proxy of the system (HttpClient default: direct when there
# is no proxy, the system proxy otherwise), which is what the Exchange Online and Graph modules use too: a plain TCP connect would fail behind a proxy
# that lets HTTPS through. Any HTTP answer counts as reachable (the question is the road to Microsoft 365, not the answer). It is asynchronous: the
# window timer polls the two tasks, so the window never waits. A test or a screenshot passes -NetworkProbe (a task per host) and no network is used.
$script:GuiM365Hosts = @('login.microsoftonline.com','outlook.office365.com')
$script:GuiNetLight = 'Microsoft 365 reachable'
$script:GuiNetHttp = $null

function Start-PraGuiHttpsProbe {
    <# The default network probe: one HTTPS HEAD to the host through the default system proxy, as a task (nothing is awaited here). #>
    param([string]$HostName, [double]$Seconds=3)
    if (-not $script:GuiNetHttp) {
        $handler=New-Object Net.Http.HttpClientHandler
        $handler.AllowAutoRedirect=$false
        $script:GuiNetHttp=New-Object Net.Http.HttpClient($handler,$true)
        $script:GuiNetHttp.Timeout=[timespan]::FromSeconds($Seconds)
    }
    $request=New-Object Net.Http.HttpRequestMessage([Net.Http.HttpMethod]::Head,('https://{0}/' -f $HostName))
    return $script:GuiNetHttp.SendAsync($request,[Net.Http.HttpCompletionOption]::ResponseHeadersRead)
}

function Get-PraGuiNetworkVerdict {
    <# Ok (every endpoint answered), Partial (some did) or Fail (none did), from the answers (Host, Ok, Why). #>
    param([object[]]$Answers)
    $good=@($Answers | Where-Object { $_.Ok }).Count
    if ($good -ge @($Answers).Count -and $good -gt 0) { return 'Ok' }
    if ($good -gt 0) { return 'Partial' }
    return 'Fail'
}

function Get-PraGuiNetworkState {
    <# The state of the Microsoft 365 test as the detection carries it: '' (not tested), Checking, Ok, Partial or Fail. #>
    param($Detect)
    if ($null -eq $Detect) { return '' }
    $property=$Detect.PSObject.Properties['Net']
    if ($null -eq $property) { return '' }
    return [string]$property.Value
}

function Test-PraGuiNetworkDown {
    $g=$script:Gui
    return ($g.Detect -and (Test-GuiOrdinalIn (Get-PraGuiNetworkState $g.Detect) @('Fail','Partial') -IgnoreCase))
}

function Test-PraGuiPhaseForced {
    <# True when the operator chose the phase in Expert mode (a new Convert or Recover): the console then does not second-guess the choice. #>
    $g=$script:Gui
    return (Test-GuiOrdinalIn $g.Action @('Convert','Recover') -IgnoreCase) -and (Test-GuiOrdinal $g.Mode 'New' -IgnoreCase) -and (-not (Test-GuiOrdinal (Get-PraGuiField 'ExpPhase') 'Auto' -IgnoreCase))
}

function Stop-PraGuiNetworkCheck {
    $g=$script:Gui
    $g.NetJob=$null; $g.NetResult=$null
}

function Start-PraGuiNetworkCheck {
    <# Sends the requests and returns at once; Complete-PraGuiNetworkCheck (window timer) reads the answers. #>
    $g=$script:Gui
    $g.NetResult=$null
    $targets=@(foreach ($name in $script:GuiM365Hosts) {
        $task=$null; $failure=''
        try { $task=& $g.NetProbe $name $g.NetSeconds } catch { $failure=$_.Exception.Message }
        [pscustomobject]@{ Host=$name; Task=$task; Failure=$failure }
    })
    $g.NetJob=@{ Targets=$targets; Clock=[Diagnostics.Stopwatch]::StartNew() }
    $g.Timer.Start()
}

function Complete-PraGuiNetworkCheck {
    <# Called by the window timer: does nothing until both answers are in or the time is up (a host that did not answer in time is not reachable). #>
    $g=$script:Gui; $job=$g.NetJob
    if (-not $job) { return }
    $expired=$job.Clock.Elapsed.TotalSeconds -ge $g.NetSeconds
    $waiting=@($job.Targets | Where-Object { $_.Task -and -not $_.Task.IsCompleted })
    if ($waiting.Count -and -not $expired) { return }
    $answers=@(foreach ($target in $job.Targets) {
        $ok=$false; $why=''
        if (-not $target.Task) { $why=[string]$target.Failure }
        elseif (-not $target.Task.IsCompleted) { $why=('no answer within {0} seconds' -f $g.NetSeconds) }
        elseif ($target.Task.IsCanceled) { $why=('no answer within {0} seconds' -f $g.NetSeconds) }
        elseif ($target.Task.IsFaulted) { $why=[string]$target.Task.Exception.GetBaseException().Message }
        else {
            $ok=$true
            $response=$target.Task.Result
            if ($response -is [IDisposable]) { $response.Dispose() }
        }
        [pscustomobject]@{ Host=[string]$target.Host; Ok=$ok; Why=$why }
    })
    $g.NetJob=$null
    $g.NetResult=[pscustomobject]@{ State=(Get-PraGuiNetworkVerdict $answers); Answers=$answers }
    Sync-PraGuiTimer
    $text=@($answers | ForEach-Object { if ($_.Ok) { '{0}: reachable' -f $_.Host } else { '{0}: not reachable ({1})' -f $_.Host,$_.Why } }) -join '; '
    Add-PraGuiLine ('Microsoft 365 check from this server. ' + $text) $(if ((Test-GuiOrdinal $g.NetResult.State 'Ok' -IgnoreCase)) { 'Info' } else { 'Warn' })
    if (-not $g.Run) { Reset-PraGuiPreview }
    Invoke-PraGuiDetection
    Update-PraGuiView
}

function Add-PraGuiNetworkLight {
    <# Adds the Microsoft 365 light and settles the role, once the programs are installed (the light is absent when the cloud cannot run anyway: the page stays short). #>
    $g=$script:Gui; $d=$g.Detect
    if (-not $g.NetProbe -or -not $d -or -not $d.Cloud) { return }
    if (-not $g.NetResult -and -not $g.NetJob) { Start-PraGuiNetworkCheck }
    $state=if ($g.NetJob) { 'Checking' } else { [string]$g.NetResult.State }
    $unreached=@(if ($g.NetResult) { $g.NetResult.Answers | Where-Object { -not $_.Ok } | ForEach-Object { $_.Host } })
    $twoServers='the cloud part must run on another machine that reaches the Internet (two servers).'
    if (Test-GuiOrdinal $state 'Checking') { $role='Checking'; $status='Info'; $detail='Checking that Microsoft 365 can be reached from this server (a few seconds)...' }
    elseif (Test-GuiOrdinal $state 'Ok') { $role=$(if ($d.AD) { 'Both' } else { 'Cloud' }); $status='Ok'; $detail=('Reachable from this server ({0}).' -f ($script:GuiM365Hosts -join ' and ')) }
    else {
        $role=$(if ($d.AD) { 'AD' } else { 'None' })
        $status=$(if ($d.AD) { 'Warn' } else { 'Fail' })
        $which=$(if ((Test-GuiOrdinal $state 'Partial')) { ' ({0} does not answer)' -f ($unreached -join ', ') } else { '' })
        $detail=$(if ($d.AD) { 'Microsoft 365 not reachable from this server{0}: {1}' -f $which,$twoServers } else { 'Microsoft 365 not reachable from this server{0}: the cloud part cannot run here. Check the Internet access (or the proxy), or use a machine that reaches the Internet.' -f $which })
    }
    $light=[ordered]@{ Name=$script:GuiNetLight; Status=$status; Detail=$detail }
    Add-Member -InputObject $d -NotePropertyName Lights -NotePropertyValue @(@($d.Lights) + $light) -Force
    Add-Member -InputObject $d -NotePropertyName Role -NotePropertyValue $role -Force
    Add-Member -InputObject $d -NotePropertyName Net -NotePropertyValue $state -Force
}
#endregion


#region Window: run settings (fields, overrides), phase, task, batches
$script:GuiTextFields = @('Env','Dc','Tenant','Org','AppId','Thumb','ExpMax','ExpConfig','Identity','Ou','Csv','CheckUpn')
$script:GuiChoices = [ordered]@{
    Scope=@('All','UsersOnly','SharedOnly'); Signin=@('Cert','Wam'); ExpPhase=@('Auto','AD','Cloud','Both'); ExpExpect=@('Provisioned','Deprovisioned','Retained')
    Source=@('Single','Scope','Ou','Csv')
}
# The run settings that can differ from the configuration file (Source, Identity, Ou, Csv and CheckUpn belong to the task, not to the settings).
$script:GuiSettingKeys = @('Env','Dc','Scope','Signin','Tenant','Org','AppId','Thumb','ExpPhase','ExpMax','ExpExpect','ExpOnce','Repl','ExpConfig')
$script:GuiActionTitle = @{ Convert='Move mailboxes to Exchange Online'; Recover='Roll back a conversion'; Finalize='Complete a rollback'; Check='Check a mailbox' }
$script:GuiActionWord = @{ Convert='CONVERT'; Recover='RECOVER'; Finalize='FINALIZE' }

function Get-PraGuiField {
    param([string]$Key)
    $c=$script:Gui.Controls
    if ($script:GuiChoices.Contains($Key)) {
        foreach ($value in $script:GuiChoices[$Key]) {
            $radio=$c[('S_{0}_{1}' -f $Key,$value)]
            if ($radio -and $radio.IsChecked) { return [string]$value }
        }
        return [string]$script:GuiChoices[$Key][0]
    }
    if ((Test-GuiOrdinalIn $Key @('ExpOnce','Repl') -IgnoreCase)) { return [bool]$c[('F_'+$Key)].IsChecked }
    return ([string]$c[('F_'+$Key)].Text).Trim()
}

function Set-PraGuiField {
    param([string]$Key, $Value)
    $g=$script:Gui; $c=$g.Controls
    $g.Updating++
    try {
        if ($script:GuiChoices.Contains($Key)) {
            foreach ($choice in $script:GuiChoices[$Key]) {
                $radio=$c[('S_{0}_{1}' -f $Key,$choice)]
                if ($radio) { $radio.IsChecked=(Test-GuiOrdinal $choice $Value) }
            }
        }
        elseif ((Test-GuiOrdinalIn $Key @('ExpOnce','Repl') -IgnoreCase)) { $c[('F_'+$Key)].IsChecked=[bool]$Value }
        else { $c[('F_'+$Key)].Text=[string]$Value }
    } finally { $g.Updating-- }
}

function Set-PraGuiDefault {
    <# The default of every run setting is the value of the configuration file (what the file says is what the run does unless the operator changes it). #>
    $g=$script:Gui
    $cfg=$g.State.Config
    if (-not $cfg) { $g.Defaults=@{ Env=''; Dc=''; Scope='All'; Signin='Wam'; Tenant=''; Org=''; AppId=''; Thumb=''; ExpPhase='Auto'; ExpMax='0'; ExpExpect='Provisioned'; ExpOnce=$false; Repl=$false; ExpConfig='' }; return }
    $cert=[bool]$cfg.Cloud.AppId -and [bool]$cfg.Cloud.CertificateThumbprint
    $g.Defaults=@{
        Env=[string]$cfg.Environment; Dc=[string]$cfg.DomainController; Scope='All'; Signin=$(if ($cert) { 'Cert' } else { 'Wam' })
        Tenant=[string]$cfg.Cloud.TenantId; Org=[string]$cfg.Cloud.Organization; AppId=[string]$cfg.Cloud.AppId; Thumb=[string]$cfg.Cloud.CertificateThumbprint
        ExpPhase='Auto'; ExpMax='0'; ExpExpect='Provisioned'; ExpOnce=$false; Repl=[bool]$cfg.Directory.ForceReplication; ExpConfig=''
    }
}

function Reset-PraGuiField {
    param([string]$Key)
    Set-PraGuiField $Key $script:Gui.Defaults[$Key]
}

function Test-PraGuiModified {
    param([string]$Key)
    $g=$script:Gui
    if (-not $g.Defaults) { return $false }
    $value=Get-PraGuiField $Key; $default=$g.Defaults[$Key]
    if ((Test-GuiOrdinalIn $Key @('ExpOnce','Repl') -IgnoreCase)) { return [bool]$value -ne [bool]$default }
    return -not (Test-GuiOrdinal ([string]$value) ([string]$default))
}

function Get-PraGuiOverride {
    <# The configuration keys the operator changed for this run (nested like the configuration), empty when nothing differs from the file. #>
    $g=$script:Gui; $d=$g.Defaults
    $override=@{}; $cloud=@{}
    $environment=Get-PraGuiField 'Env'
    if (-not (Test-GuiOrdinal $environment $d.Env)) { $override.Environment=$environment }
    $controller=Get-PraGuiField 'Dc'
    if (-not (Test-GuiOrdinal $controller $d.Dc)) { $override.DomainController=$controller }
    foreach ($pair in @(@('Tenant','TenantId'),@('Org','Organization'))) {
        $value=Get-PraGuiField $pair[0]
        if (-not (Test-GuiOrdinal $value $d[$pair[0]])) { $cloud[$pair[1]]=$value }
    }
    if ((Test-GuiOrdinal (Get-PraGuiField 'Signin') 'Cert' -IgnoreCase)) {
        foreach ($pair in @(@('AppId','AppId'),@('Thumb','CertificateThumbprint'))) {
            $value=Get-PraGuiField $pair[0]
            if (-not (Test-GuiOrdinal $value $d[$pair[0]])) { $cloud[$pair[1]]=$value }
        }
    } else {
        # Interactive sign-in: the certificate pair of the file is not used by this run.
        if ($d.AppId) { $cloud.AppId='' }
        if ($d.Thumb) { $cloud.CertificateThumbprint='' }
    }
    if ($cloud.Count) { $override.Cloud=$cloud }
    if ([bool](Get-PraGuiField 'Repl') -ne [bool]$d.Repl) { $override.Directory=@{ ForceReplication=[bool](Get-PraGuiField 'Repl') } }
    return $override
}

function Get-PraGuiSettingsProblem {
    <# Cheap checks of what the operator typed; the engine validates the whole configuration again with Import-PraConfiguration. #>
    $g=$script:Gui
    $environment=Get-PraGuiField 'Env'
    if ($environment -notmatch '^[A-Za-z0-9_.-]{1,64}\z') { return 'Environment: 1 to 64 letters, digits, dot, dash or underscore.' }
    if ((Get-PraGuiField 'Dc') -notmatch '^[A-Za-z0-9.-]*\z') { return 'Domain controller: a host name (letters, digits, dot, dash).' }
    $limit=0
    if (-not [int]::TryParse((Get-PraGuiField 'ExpMax'),[ref]$limit) -or $limit -lt 0) { return 'MaxObjects: a whole number, 0 or more.' }
    if ((Test-GuiOrdinal (Get-PraGuiField 'Signin') 'Cert' -IgnoreCase)) {
        if (-not (Get-PraGuiField 'AppId') -or -not (Get-PraGuiField 'Thumb')) { return 'Certificate sign-in needs the application ID and the certificate thumbprint.' }
        if (-not (Get-PraGuiField 'Org')) { return 'Certificate sign-in needs the Organization (tenant.onmicrosoft.com).' }
        $guid=[guid]::Empty
        if (-not [guid]::TryParse((Get-PraGuiField 'Tenant'),[ref]$guid) -or $guid -eq [guid]::Empty) { return 'Certificate sign-in needs the Tenant ID (a GUID).' }
    }
    return ''
}

function Get-PraGuiPhase {
    <# The phase of the run, inferred from what the operator picked (the Expert mode can force it). #>
    $g=$script:Gui
    switch ($g.Action) {
        'Check' { return 'Cloud' }
        'Finalize' { return 'AD' }
        'Convert' { }
        'Recover' { }
        default { return '' }
    }
    if ((Test-GuiOrdinal $g.Mode 'Continue' -IgnoreCase)) { return 'Cloud' }
    $forced=Get-PraGuiField 'ExpPhase'
    if ((-not (Test-GuiOrdinal $forced 'Auto' -IgnoreCase))) { return $forced }
    # A server that can run both sides runs the whole batch in one go (no transfer package). The AD phase and its package are only for a server that
    # can run the Active Directory side alone; the Expert mode can still force a phase.
    if ($g.Detect -and (Test-GuiOrdinal $g.Detect.Role 'Both' -IgnoreCase)) { return 'Both' }
    return 'AD'
}

function Test-PraGuiNeedsCloud {
    $g=$script:Gui
    if (-not $g.Action) { return $true }
    return (Test-GuiOrdinal $g.Action 'Check' -IgnoreCase) -or ((Test-GuiOrdinalIn $g.Action @('Convert','Recover') -IgnoreCase) -and (Test-GuiOrdinalIn (Get-PraGuiPhase) @('Cloud','Both') -IgnoreCase))
}

function Get-PraGuiBlocker {
    <# Why this server cannot do the chosen task yet (empty when it can). #>
    $g=$script:Gui
    if (-not $g.Action -or -not $g.Detect) { return '' }
    $phase=Get-PraGuiPhase
    $needAd=(Test-GuiOrdinal $g.Action 'Finalize' -IgnoreCase) -or ((Test-GuiOrdinalIn $g.Action @('Convert','Recover') -IgnoreCase) -and (Test-GuiOrdinalIn $phase @('AD','Both') -IgnoreCase))
    if ($needAd -and -not $g.Detect.AD) { return 'This server cannot do the Active Directory part yet: RSAT ActiveDirectory is not installed. Install it, or run this on the AD server.' }
    if ((Test-PraGuiNeedsCloud) -and $g.Detect.Cloud -and (Test-PraGuiNetworkDown) -and -not (Test-PraGuiPhaseForced)) {
        $net=@($g.Detect.Lights | Where-Object { Test-GuiOrdinal $_.Name $script:GuiNetLight })
        return ('This server cannot do the cloud part yet: {0} Run this on the cloud server, or fix the access on the Setup page.' -f $(if ($net.Count) { [string]$net[0].Detail } else { 'Microsoft 365 is not reachable from this server.' }))
    }
    if ((Test-PraGuiNeedsCloud) -and -not $g.Detect.Cloud) {
        $reason=''
        foreach ($light in $g.Detect.Lights) {
            if ((Test-GuiOrdinal $light.Status 'Fail' -IgnoreCase) -and (-not (Test-GuiOrdinal $light.Name 'RSAT ActiveDirectory' -IgnoreCase))) { $reason=[string]$light.Detail; break }
        }
        if (-not $reason) { $reason='a cloud prerequisite is missing.' }
        return ('This server cannot do the cloud part yet: {0} Fix it on the Setup page, or run this on the cloud server.' -f $reason)
    }
    return ''
}

# Plain words for each step of the engine (by the title the engine announces in its plan).
$script:GuiStepInfo = @{
    'Active Directory connection'='Connects to the domain controller and checks your rights. Nothing is changed.'
    'Targets and planned changes'='Reads each selected account in Active Directory, checks that it can be converted and works out the exact changes.'
    'Exchange Online pre-check'='Signs in to the cloud and checks the tenant and the accounts BEFORE the first Active Directory change.'
    'Backup and Active Directory changes'='Saves the current Active Directory data of every object to the batch folder, changes the attributes, then reads each object back to verify.'
    'Entra Connect synchronisation'='Asks Entra Connect to copy the change to the cloud and waits until it is done.'
    'Active Directory replication'='Pushes each changed object from the domain controller that was written to the other domain controllers and reads it back, so that the synchronisation sees the change.'
    'Exchange Online: mailboxes, licences and permissions'='Waits for each cloud mailbox, checks its licence and puts back the permissions of the shared mailboxes.'
    'Creating the transfer package'='Packs everything the other server needs into ONE file, with its checksums.'
    'Loading the batch of the AD phase'='Opens the batch and the Active Directory proof brought from the AD server and verifies every checksum.'
    'Loading the Recover batch'='Opens the rollback batch and the original conversion batch and verifies every checksum.'
    'Loading the Convert batch'='Finds the original conversion batch and checks that its backup files are there and intact.'
    'Planned restore'='Works out the Active Directory values to put back from the backup.'
    'Exchange Online: deprovisioning checks'='Checks in the cloud that each rolled-back mailbox is back to normal.'
    'Final restore of shared mailboxes and tags'='Restores the last attributes of shared mailboxes and retention tags, or packs them for the AD server.'
    'Loading the Finalize package'='Verifies the Finalize package and every proof inside it.'
    'Objects to check'='Finds the mailbox to check.'
    'Exchange Online checks'='Reads the mailbox in the cloud and compares it with its expected state. Nothing is changed.'
}

function Get-PraGuiPlanTitle {
    <# The steps the engine announces for an action and a phase (kept in line with the main script; the run itself shows the real plan event). #>
    param([string]$Action, [string]$Phase)
    $titles=@(Get-PraGuiBasePlanTitle $Action $Phase)
    $replicate=$false
    if ($script:Gui -and $script:Gui.Controls -and $script:Gui.Controls.ContainsKey('F_Repl')) { $replicate=[bool](Get-PraGuiField 'Repl') }
    if (-not $replicate -or (Test-GuiOrdinal $Action 'Check' -IgnoreCase) -or (Test-GuiOrdinal $Phase 'Cloud' -IgnoreCase)) { return $titles }
    $out=New-Object 'Collections.Generic.List[string]'
    foreach ($title in $titles) {
        if (Test-GuiOrdinal $title 'Entra Connect synchronisation') { $out.Add('Active Directory replication') }
        $out.Add($title)
    }
    return $out.ToArray()
}

function Get-PraGuiBasePlanTitle {
    param([string]$Action, [string]$Phase)
    switch ($Action) {
        'Convert' {
            if ((Test-GuiOrdinal $Phase 'Cloud' -IgnoreCase)) { return @('Loading the batch of the AD phase','Exchange Online: mailboxes, licences and permissions') }
            return @('Active Directory connection','Targets and planned changes') + $(if ((Test-GuiOrdinal $Phase 'Both' -IgnoreCase)) { @('Exchange Online pre-check') } else { @() }) +
                @('Backup and Active Directory changes','Entra Connect synchronisation') + $(if ((Test-GuiOrdinal $Phase 'Both' -IgnoreCase)) { @('Exchange Online: mailboxes, licences and permissions') } else { @('Creating the transfer package') })
        }
        'Recover' {
            if ((Test-GuiOrdinal $Phase 'Cloud' -IgnoreCase)) { return @('Loading the Recover batch','Exchange Online: deprovisioning checks','Final restore of shared mailboxes and tags') }
            return @('Loading the Convert batch','Active Directory connection','Planned restore') + $(if ((Test-GuiOrdinal $Phase 'Both' -IgnoreCase)) { @('Exchange Online pre-check') } else { @() }) +
                @('Backup and Active Directory changes','Entra Connect synchronisation') +
                $(if ((Test-GuiOrdinal $Phase 'Both' -IgnoreCase)) { @('Exchange Online: deprovisioning checks','Final restore of shared mailboxes and tags') } else { @('Creating the transfer package') })
        }
        'Finalize' { return @('Loading the Finalize package','Active Directory connection','Planned restore','Backup and Active Directory changes','Entra Connect synchronisation') }
        'Check' { return @('Objects to check','Exchange Online checks') }
        default { return @() }
    }
}

function Get-PraGuiNetworkPhaseNote {
    <# The reason why the phase is AD when the programs of both sides are installed here (empty otherwise, or when the operator forced the phase). #>
    $g=$script:Gui
    if ((Test-PraGuiNetworkDown) -and $g.Detect.Cloud -and $g.Detect.AD -and -not (Test-PraGuiPhaseForced)) { return ' Microsoft 365 is not reachable from this server, so the cloud part cannot run here.' }
    return ''
}

function Get-PraGuiPhaseText {
    $g=$script:Gui
    $phase=Get-PraGuiPhase
    switch ($g.Action) {
        'Check' { return 'Read only. Looks at the mailbox in Active Directory and in Exchange Online. Nothing is changed.' }
        'Finalize' { return 'This server applies the last Active Directory attributes of a rollback. It never calls the cloud.' }
        'Convert' {
            if ((Test-GuiOrdinal $phase 'Cloud' -IgnoreCase)) { return 'This server checks the package brought from the AD server, then converts the mailboxes in Exchange Online.' }
            if ((Test-GuiOrdinal $phase 'Both' -IgnoreCase)) { return 'This server backs up and changes the Active Directory objects, synchronises, then completes the mailboxes in Exchange Online, all in one run. Everything is done here: no transfer package is needed.' }
            return ('This server backs up and changes the Active Directory objects, then writes ONE transfer package. The cloud part is done afterwards, on the cloud server.' + (Get-PraGuiNetworkPhaseNote))
        }
        'Recover' {
            if ((Test-GuiOrdinal $phase 'Cloud' -IgnoreCase)) { return 'This server checks the rollback in Exchange Online and, if a final Active Directory restore remains, writes ONE package for the AD server. It never writes to Active Directory.' }
            if ((Test-GuiOrdinal $phase 'Both' -IgnoreCase)) { return 'This server puts the original values back in Active Directory using the backup of the conversion, then checks the rollback in Exchange Online. Everything is done here: no transfer package is needed.' }
            return ('This server puts the original values back in Active Directory using the backup of the conversion, then writes ONE transfer package for the cloud server.' + (Get-PraGuiNetworkPhaseNote))
        }
        default { return '' }
    }
}

function ConvertTo-PraGuiPlural {
    param([int]$Count, [string]$One, [string]$Many)
    if ($Count -eq 1) { return ('{0} {1}' -f $Count,$One) }
    return ('{0} {1}' -f $Count,$Many)
}

function Get-PraGuiSourceText {
    <# Title and sentence of the chosen object source. #>
    $g=$script:Gui
    switch (Get-PraGuiField 'Source') {
        'Single' { return @('Single identity (test)',('{0}. The safest way to try a run: one account only.' -f (Get-PraGuiField 'Identity'))) }
        'Scope' {
            $scope=if ($g.State.Config) { $g.State.Config.Scope } else { $null }
            $where=if (-not $scope) { 'unknown' } elseif ((Test-GuiOrdinal $scope.Mode 'OU' -IgnoreCase)) { 'OU ' + $scope.SearchBase } elseif ((Test-GuiOrdinal $scope.Mode 'Group' -IgnoreCase)) { 'members of ' + $scope.GroupDN } elseif ((Test-GuiOrdinal $scope.Mode 'Csv' -IgnoreCase)) { 'CSV ' + $scope.CsvPath } elseif ($scope.SearchBase) { $scope.SearchBase } else { 'the whole domain' }
            return @('Configured scope',('Scope of the configuration file (read only): {0}. Change it in the file, not here.' -f $where))
        }
        'Ou' { return @('Organizational unit',('{0} (sub-OUs included).' -f (Get-PraGuiField 'Ou'))) }
        'Csv' {
            $path=Get-PraGuiField 'Csv'; $rows=''
            try { if ($path -and (Test-Path -LiteralPath $path -PathType Leaf)) { $rows=' ' + (ConvertTo-PraGuiPlural @(Read-PraTargetCsv -Path $path).Count 'row' 'rows') + '.' } } catch { $rows=' ' + $_.Exception.Message }
            return @('CSV file',($path+'.'+$rows))
        }
    }
}

function Get-PraGuiBatchCreated {
    param($Item)
    $runId=[string](Get-PraGuiValue $Item.Data 'RunId' '')
    if ($runId -match '^(\d{4})(\d{2})(\d{2})_(\d{2})(\d{2})(\d{2})') {
        try { return [datetime]::new([int]$Matches[1],[int]$Matches[2],[int]$Matches[3],[int]$Matches[4],[int]$Matches[5],[int]$Matches[6]) } catch { Write-Verbose $_.Exception.Message }
    }
    $created=[string](Get-PraGuiValue $Item.Data 'CreatedUtc' '')
    $parsed=[datetime]::MinValue
    if ($created -and [datetime]::TryParse($created,[Globalization.CultureInfo]::InvariantCulture,[Globalization.DateTimeStyles]::RoundtripKind,[ref]$parsed)) { return $parsed.ToLocalTime() }
    try { return (Get-Item -LiteralPath $Item.Path -ErrorAction Stop).LastWriteTime } catch { return [datetime]::MinValue }
}

function Format-PraGuiDate {
    param([datetime]$When)
    if ($When -eq [datetime]::MinValue) { return 'date unknown' }
    if ($When.Date -eq [datetime]::Today) { return 'Today ' + $When.ToString('HH:mm',[Globalization.CultureInfo]::InvariantCulture) }
    return $When.ToString('d MMM yyyy HH:mm',[Globalization.CultureInfo]::InvariantCulture)
}

function Get-PraGuiBatchEntry {
    <#
    .SYNOPSIS
        The rows of the "On what?" list for the chosen task: the batches found in the backup folder (every environment) and the transfer packages
        waiting in <Storage.BackupFolder>\Inbox, with their state.
    #>
    $g=$script:Gui; $state=$g.State
    $operation=''; $kind=''
    switch ($g.Action) {
        'Convert' { if ((Test-GuiOrdinal $g.Mode 'Continue' -IgnoreCase)) { $operation='Convert'; $kind='Convert' } }
        'Recover' { if ((Test-GuiOrdinal $g.Mode 'Continue' -IgnoreCase)) { $operation='Recover'; $kind='Recover' } else { $operation='Convert' } }
        'Finalize' { $operation='RecoverFinalize'; $kind='Finalize' }
    }
    $rows=New-Object 'Collections.Generic.List[object]'
    if (-not $operation -or -not $state -or $state.ConfigError) { return @() }
    $needsProof=(Test-GuiOrdinal $g.Mode 'Continue' -IgnoreCase) -and (Test-GuiOrdinalIn $g.Action @('Convert','Recover') -IgnoreCase)
    $entries=New-Object 'Collections.Generic.List[object]'
    foreach ($item in @($state.Batches) + @($state.OtherEnvironment)) {
        if ($item.EnvMismatch) { continue }
        if ($item.Valid -and -not (Test-GuiOrdinal $item.Operation $operation)) { continue }
        $entries.Add($item)
    }
    $keys=New-Object 'Collections.Generic.List[string]'
    foreach ($item in $entries) { $keys.Add((Get-PraGuiBatchCreated $item).ToString('yyyyMMddHHmmss',[Globalization.CultureInfo]::InvariantCulture)+$item.Path) }
    $keyArray=[string[]]$keys.ToArray(); $itemArray=[object[]]$entries.ToArray()
    [Array]::Sort([Array]$keyArray,[Array]$itemArray,[Collections.IComparer][StringComparer]::Ordinal)
    [Array]::Reverse($itemArray)
    foreach ($item in $itemArray) {
        if (-not $item.Valid) {
            $rows.Add((New-PraGuiRow @{ Title=('Unreadable {0}' -f (Split-Path $item.Folder -Leaf)); Sub=$item.Status; State='Invalid'; Level='Fail'; Selectable=$false; Glyph=[string][char]0xE7BA
                Package=$false; Path=$item.Path; Environment=''; BatchId=''; Operation='' }))
            continue
        }
        $data=$item.Data
        $records=@(if (Test-GuiOrdinal $item.Operation 'RecoverFinalize') { Get-PraGuiValue $data 'Items' @() } else { Get-PraGuiValue $data 'Records' @() })
        $shared=@($records | Where-Object { [bool](Get-PraGuiValue $_ 'IsShared' $false) }).Count
        $proofPath=Join-Path $item.Folder ('State-'+$item.BatchId+'.json')
        $hasProof=Test-Path -LiteralPath $proofPath -PathType Leaf
        $state_='Ready'; $level='Ok'; $selectable=$true
        switch ($item.Operation) {
            'Convert' { if ($needsProof) { if ($hasProof) { $state_='AD part done, cloud part to do' } else { $state_='No AD proof'; $level='Warn'; $selectable=$false } } else { $state_='Can be rolled back' } }
            'Recover' { if ($hasProof) { $state_='AD rollback done, cloud part to do' } else { $state_='No AD proof'; $level='Warn'; $selectable=$false } }
            'RecoverFinalize' { $state_='Ready to finalize' }
        }
        $glyph=switch ($item.Operation) { 'Convert' { [string][char]0xE753 } 'Recover' { [string][char]0xE7A7 } default { [string][char]0xE930 } }
        $label=if (Test-GuiOrdinal $item.Operation 'RecoverFinalize') { 'Finalize' } else { [string]$item.Operation }
        $sub='{0}, {1} shared · environment {2} · {3}' -f (ConvertTo-PraGuiPlural $records.Count 'mailbox' 'mailboxes'),$shared,$item.Environment,(Split-Path $item.Folder -Leaf)
        $rows.Add((New-PraGuiRow @{ Title=('{0} · {1}' -f $label,(Format-PraGuiDate (Get-PraGuiBatchCreated $item))); Sub=$sub; State=$state_; Level=$level; Selectable=$selectable; Glyph=$glyph
            Package=$false; Path=$item.Path; Environment=$item.Environment; BatchId=$item.BatchId; Operation=[string]$item.Operation }))
    }
    # Transfer packages waiting in the Inbox.
    if ($kind -and (Get-Command Get-PraTransferPackage -ErrorAction SilentlyContinue)) {
        $inbox=Join-Path $state.Config.Storage.BackupFolder 'Inbox'
        if (Test-Path -LiteralPath $inbox -PathType Container) {
            foreach ($file in @(Get-ChildItem -LiteralPath $inbox -File -Filter '*.zip' -ErrorAction SilentlyContinue)) {
                $package=Get-PraGuiPackageInfo $file.FullName
                if ([bool](Get-PraGuiValue $package 'Pending' $false)) {
                    $rows.Insert(0,(New-PraGuiRow @{ Title=('Package '+$file.Name); Sub='Checking the checksums; the window stays usable.'; State='Checking...'; Level='Info'; Selectable=$false; Glyph=[string][char]0xE8B7; Package=$true; Path=$file.FullName; Environment=''; BatchId=''; Operation='' }))
                    continue
                }
                $fits=$package.Valid -and (Test-GuiOrdinal $package.Kind $kind)
                if ($package.Valid -and -not $fits) { continue }
                $rows.Insert(0,(New-PraGuiRow @{
                    Title=$(if ($package.Valid) { 'Package · {0} · {1}' -f $package.Kind,(Format-PraGuiDate ([datetime]::Parse([string]$package.CreatedUtc,[Globalization.CultureInfo]::InvariantCulture,[Globalization.DateTimeStyles]::RoundtripKind).ToLocalTime())) } else { 'Package ' + $file.Name })
                    Sub=$(if ($package.Valid) { '{0} · {1:n1} MB · environment {2}' -f $file.Name,($file.Length/1MB),$package.Environment } else { $package.Error })
                    State=$(if ($package.Valid) { 'Checksums verified' } else { 'Invalid' }); Level=$(if ($package.Valid) { 'Ok' } else { 'Fail' }); Selectable=[bool]$fits
                    Glyph=[string][char]0xE8B7; Package=$true; Path=$file.FullName; Environment=$(if ($package.Valid) { [string]$package.Environment } else { '' }); BatchId=''; Operation='' }))
            }
        }
    }
    return $rows.ToArray()
}
#endregion


#region Window: views of the five pages
function Get-PraGuiVisibility {
    param([bool]$Visible)
    if ($Visible) { return 'Visible' }
    return 'Collapsed'
}

function Invoke-PraGuiDetection {
    <# Runs the prerequisite probe (real detection by default) with the settings of the window, and shows the lights. -Refresh scans the module path again. #>
    param([switch]$Refresh)
    $g=$script:Gui
    $cfg=$g.State.Config
    $request=@{ Signin=(Get-PraGuiField 'Signin'); Thumbprint=(Get-PraGuiField 'Thumb') }
    if ($cfg) {
        $request.MinExoVersion=[string]$cfg.Exo.MinModuleVersion; $request.DisableWam=[bool]$cfg.Exo.DisableWAM
        $request.SyncEnabled=[bool]$cfg.EntraConnect.Sync; $request.SyncServer=[string]$cfg.EntraConnect.Server
    }
    if ($Refresh) { $request.Refresh=$true; Stop-PraGuiNetworkCheck }
    $g.Detect=& $g.Probe $request
    Add-PraGuiNetworkLight
    $g.LightRows.Clear()
    foreach ($light in @($g.Detect.Lights)) { $g.LightRows.Add((New-PraGuiRow @{ Name=[string]$light.Name; Status=[string]$light.Status; Detail=[string]$light.Detail })) }
}

function Update-PraGuiEnvSuggest {
    $g=$script:Gui; $c=$g.Controls
    $c.EnvSuggest.Children.Clear()
    if (@($g.KnownEnvironments).Count -lt 1) { return }
    $label=New-Object Windows.Controls.TextBlock
    $label.Text='Seen here:'; $label.FontSize=12; $label.VerticalAlignment='Center'; $label.Margin=[Windows.Thickness]::new(0,0,4,0)
    $label.SetResourceReference([Windows.Controls.TextBlock]::ForegroundProperty,'TextFillColorSecondaryBrush')
    [void]$c.EnvSuggest.Children.Add($label)
    foreach ($name in @($g.KnownEnvironments)) {
        $button=New-Object Windows.Controls.Button
        $button.Content=[string]$name; $button.Tag=[string]$name; $button.Style=$g.Form.FindResource('LinkBtn')
        $button.Add_Click({ param($sender) if ($c.F_Env.IsEnabled) { Set-PraGuiField 'Env' ([string]$sender.Tag); Invoke-PraGuiChange } }.GetNewClosure())
        [void]$c.EnvSuggest.Children.Add($button)
    }
}

function Update-PraGuiSettingsView {
    $g=$script:Gui; $c=$g.Controls
    $changed=0
    foreach ($key in $script:GuiSettingKeys) {
        $modified=Test-PraGuiModified $key
        if ((Test-GuiOrdinal $key 'Env' -IgnoreCase) -and $g.EnvLock) { $modified=$false }
        $unused=(Test-GuiOrdinalIn $key @('AppId','Thumb') -IgnoreCase) -and (-not (Test-GuiOrdinal (Get-PraGuiField 'Signin') 'Cert' -IgnoreCase))
        if ($modified -and -not $unused) { $changed++ }
        if ($c.ContainsKey('M_'+$key)) { $c['M_'+$key].Visibility=Get-PraGuiVisibility ($modified -and -not $unused) }
    }
    $c.BtnResetAll.Visibility=Get-PraGuiVisibility ($changed -gt 0)
    $signin=Get-PraGuiField 'Signin'
    $c.Row_AppId.Visibility=Get-PraGuiVisibility ((Test-GuiOrdinal $signin 'Cert' -IgnoreCase)); $c.Row_Thumb.Visibility=Get-PraGuiVisibility ((Test-GuiOrdinal $signin 'Cert' -IgnoreCase))
    $c.WamNote.Visibility=Get-PraGuiVisibility ((Test-GuiOrdinal $signin 'Wam' -IgnoreCase))
    $c.CloudFields.Visibility=Get-PraGuiVisibility (Test-PraGuiNeedsCloud)
    $c.F_Env.IsEnabled=-not $g.EnvLock
    $c.EnvLock.Visibility=Get-PraGuiVisibility ([bool]$g.EnvLock)
    if ($g.EnvLock) {
        $text='Locked to {0}: the chosen batch was created there, and a batch only continues in its own environment.' -f $g.EnvLock
        if ($g.State.Config -and -not (Test-GuiOrdinal $g.EnvLock $g.Defaults.Env)) { $text+=' The configuration file says {0}.' -f $g.Defaults.Env }
        $c.EnvLockText.Text=$text
    }
    $c.R_ExpConfig.IsEnabled=[bool](Get-PraGuiField 'ExpConfig')
    $environment=Get-PraGuiField 'Env'
    $c.HdrEnv.Text=$(if ($environment) { $environment } else { 'not set' })
    $organization=Get-PraGuiField 'Org'; $controller=Get-PraGuiField 'Dc'
    $c.HdrEnvSub.Text='Tenant {0} · DC {1}' -f $(if ($organization) { $organization } else { 'not set' }),$(if ($controller) { $controller } else { 'chosen automatically' })
    $role=if ($g.Detect) { [string]$g.Detect.Role } else { 'None' }
    switch ($role) {
        'Both' { $c.RoleName.Text='AD + Cloud'; Set-PraGuiPill $c.RolePill $c.RoleName 'Ok'; $c.RoleText.Text='This server can run every part: Active Directory and cloud.' }
        'AD' {
            $c.RoleName.Text='AD'; Set-PraGuiPill $c.RolePill $c.RoleName 'Warn'
            $c.RoleText.Text=$(if (Test-PraGuiNetworkDown) { 'Can run the Active Directory parts. Microsoft 365 is not reachable from this server: the cloud parts must run on another machine that reaches the Internet (two servers).' } else { 'Can run the Active Directory parts. The cloud parts need the red light below fixed, or must run on the cloud server.' })
        }
        'Cloud' { $c.RoleName.Text='Cloud'; Set-PraGuiPill $c.RolePill $c.RoleName 'Warn'; $c.RoleText.Text='Can run the cloud parts. The Active Directory parts must run on the AD server (RSAT is missing here).' }
        'Checking' { $c.RoleName.Text='Checking...'; Set-PraGuiPill $c.RolePill $c.RoleName 'Info'; $c.RoleText.Text='Checking that Microsoft 365 can be reached from this server. This takes a few seconds.' }
        default {
            $c.RoleName.Text='Nothing yet'; Set-PraGuiPill $c.RolePill $c.RoleName 'Fail'
            $c.RoleText.Text=$(if (Test-PraGuiNetworkDown) { 'Nothing can run here until Microsoft 365 can be reached from this server: see the red light below.' } else { 'Nothing can run here until the red lights below are fixed.' })
        }
    }
    $labels=[ordered]@{ Env='Environment'; Dc='Domain controller'; Scope='Mailbox scope'; Signin='Sign-in'; Tenant='Tenant ID'; Org='Organization'; AppId='Application ID'; Thumb='Certificate'; ExpPhase='Phase'; ExpMax='Max objects'; ExpExpect='Expected state'; ExpOnce='Check once'; Repl='AD replication' }
    $names=New-Object 'Collections.Generic.List[string]'
    foreach ($key in $labels.Keys) {
        if (-not (Test-PraGuiModified $key)) { continue }
        if ((Test-GuiOrdinal $key 'Env' -IgnoreCase) -and $g.EnvLock) { continue }
        if ((Test-GuiOrdinalIn $key @('AppId','Thumb') -IgnoreCase) -and (-not (Test-GuiOrdinal $signin 'Cert' -IgnoreCase))) { continue }
        $names.Add([string]$labels[$key])
    }
    $c.RunLine.Text='This run: {0} · {1}' -f $(if ($environment) { $environment } else { 'no environment' }),$(if ($controller) { $controller } else { 'domain controller chosen automatically' })
    $c.RunLineSub.Text=$(if ($names.Count) { 'Modified for this run only: ' + ($names -join ', ') + '. Everything else comes from the configuration file.' } else { 'Everything comes from the configuration file.' })
    $c.HdrHost.Text=$env:COMPUTERNAME
    $c.HdrHostSub.Text='PowerShell {0} · signed in as {1}\{2}' -f $PSVersionTable.PSVersion,$env:USERDOMAIN,$env:USERNAME
    $c.CmdLine.Text=Get-PraGuiCommandPreview
    $problem=Get-PraGuiSettingsProblem
    $c.SettingsError.Text=$problem
    $c.ConfigError.Text=$(if ($g.State.ConfigError) { 'Configuration INVALID: ' + $g.State.ConfigError } else { '' })
}

function Get-PraGuiCommandPreview {
    <# The command line equivalent to what the window would run now (illustration for Expert mode and the guide; settings changed in the window are not on the command line). #>
    $g=$script:Gui
    if (-not $g.Action) { return 'Choose a task to see the equivalent command line.' }
    try {
        $request=Get-PraGuiWindowRequest 'Apply'
        $override=Get-PraGuiOverride
        $text=(Get-PraGuiCommand $g.Root $g.ConfigPath $request).Display
        if ($override.Count) { $text+="`r`n# This run also uses an effective copy of the configuration with the settings changed in the window (written in the run folder)." }
        return $text
    } catch { return 'Not ready: ' + $_.Exception.Message }
}

function Get-PraGuiWindowRequest {
    param([string]$Mode='Preview')
    $g=$script:Gui
    $action=$g.Action
    if (-not $action) { throw 'Choose a task first.' }
    $phase=Get-PraGuiPhase
    $limit=0
    if ((Test-GuiOrdinal $action 'Convert' -IgnoreCase) -and (-not (Test-GuiOrdinal $phase 'Cloud' -IgnoreCase))) {
        if (-not [int]::TryParse((Get-PraGuiField 'ExpMax'),[ref]$limit) -or $limit -lt 0) { throw 'MaxObjects must be a whole number, 0 or more.' }
    }
    $batch=''
    $row=$g.SelectedBatch
    if ((Test-GuiOrdinal $action 'Finalize' -IgnoreCase) -or (Test-GuiOrdinal $action 'Recover' -IgnoreCase) -or ((Test-GuiOrdinal $action 'Convert' -IgnoreCase) -and (Test-GuiOrdinal $phase 'Cloud' -IgnoreCase))) {
        if (-not $row) { throw 'Pick the batch (or the transfer package) first.' }
        $batch=[string]$row.Path
    }
    $identity=''; $ou=''; $csv=''
    if ((Test-GuiOrdinal $action 'Check' -IgnoreCase)) { $identity=Get-PraGuiField 'CheckUpn' }
    elseif ((Test-GuiOrdinal $action 'Convert' -IgnoreCase) -and (Test-GuiOrdinalIn $phase @('AD','Both') -IgnoreCase)) {
        switch (Get-PraGuiField 'Source') {
            'Single' { $identity=Get-PraGuiField 'Identity'; if (-not $identity) { throw 'Type the identity of the account to process.' } }
            'Ou' { $ou=Get-PraGuiField 'Ou'; if (-not $ou) { throw 'Pick or type the distinguished name of the OU.' } }
            'Csv' { $csv=Get-PraGuiField 'Csv'; if (-not $csv) { throw 'Choose a CSV file with a column named Identity.' } }
        }
    }
    $once=[bool](Get-PraGuiField 'ExpOnce') -and ((Test-GuiOrdinal $action 'Check' -IgnoreCase) -or ((Test-GuiOrdinalIn $action @('Convert','Recover') -IgnoreCase) -and (-not (Test-GuiOrdinal $phase 'AD' -IgnoreCase))))
    $pass=if ((Test-GuiOrdinal $action 'Finalize' -IgnoreCase)) { 'AD' } else { $phase }
    return New-PraGuiRequest -Action $action -Mode $Mode -Phase $pass -Batch $batch -Identity $identity -SearchBase $ou -CsvPath $csv -Scope (Get-PraGuiField 'Scope') -MaxObjects $limit -Expect (Get-PraGuiField 'ExpExpect') -Once $once
}

function Test-PraGuiTaskReady {
    $g=$script:Gui
    if (-not $g.Action) { return $false }
    if ($g.State.ConfigError -or (Get-PraGuiSettingsProblem) -or (Get-PraGuiBlocker)) { return $false }
    switch ($g.Action) {
        'Check' { return [bool](Get-PraGuiField 'CheckUpn') }
        'Convert' {
            if ((Test-GuiOrdinal $g.Mode 'Continue' -IgnoreCase)) { return $null -ne $g.SelectedBatch }
            switch (Get-PraGuiField 'Source') {
                'Single' { return [bool](Get-PraGuiField 'Identity') }
                'Ou' { return [bool](Get-PraGuiField 'Ou') }
                'Csv' { return [bool](Get-PraGuiField 'Csv') }
                default { return $true }
            }
        }
        default { return $null -ne $g.SelectedBatch }
    }
}

function Update-PraGuiEnvLock {
    $g=$script:Gui
    $row=$g.SelectedBatch
    if ($row -and $row.Environment) {
        if ($null -eq $g.EnvSaved) { $g.EnvSaved=Get-PraGuiField 'Env' }
        Set-PraGuiField 'Env' ([string]$row.Environment); $g.EnvLock=[string]$row.Environment
    }
    elseif ($null -ne $g.EnvSaved) { Set-PraGuiField 'Env' $g.EnvSaved; $g.EnvSaved=$null; $g.EnvLock=$null }
    else { $g.EnvLock=$null }
}

function Update-PraGuiBatchList {
    <# Rebuilds the list of batches and packages for the current task, keeping the selection when the entry is still there. #>
    $g=$script:Gui; $c=$g.Controls
    $keep=if ($g.SelectedBatch) { [string]$g.SelectedBatch.Path } else { '' }
    $g.Updating++
    try {
        $g.BatchRows.Clear()
        $selected=$null
        foreach ($row in @(Get-PraGuiBatchEntry)) {
            $g.BatchRows.Add($row)
            if ($keep -and (Test-GuiOrdinal $row.Path $keep -IgnoreCase) -and $row.Selectable) { $selected=$row }
        }
        if ($selected) { $c.BatchList.SelectedItem=$selected } else { $c.BatchList.SelectedItem=$null }
        $g.SelectedBatch=$selected
        Update-PraGuiEnvLock
    } finally { $g.Updating-- }
    $folder=if ($g.State.Config) { [string]$g.State.Config.Storage.BackupFolder } else { '' }
    $c.BatchEmpty.Text=$(if ($g.BatchRows.Count -eq 0) { 'Nothing found in {0}. Import a transfer package, or copy a batch folder there and click Reload.' -f $folder } else { '' })
}

function Update-PraGuiTaskView {
    $g=$script:Gui; $c=$g.Controls
    $action=$g.Action
    $c.T_Finalize.Visibility=Get-PraGuiVisibility ([bool]$g.HasFinalize -or (Test-GuiOrdinal $action 'Finalize' -IgnoreCase))
    $c.OnWhatEmpty.Visibility=Get-PraGuiVisibility (-not $action)
    $c.ModeBox.Visibility=Get-PraGuiVisibility ((Test-GuiOrdinalIn $action @('Convert','Recover') -IgnoreCase))
    $newConvert=(Test-GuiOrdinal $action 'Convert' -IgnoreCase) -and (Test-GuiOrdinal $g.Mode 'New' -IgnoreCase)
    $c.SourceBox.Visibility=Get-PraGuiVisibility $newConvert
    $c.BatchBox.Visibility=Get-PraGuiVisibility (((Test-GuiOrdinal $action 'Convert' -IgnoreCase) -and (Test-GuiOrdinal $g.Mode 'Continue' -IgnoreCase)) -or (Test-GuiOrdinalIn $action @('Recover','Finalize') -IgnoreCase))
    $c.BtnImport.Visibility=Get-PraGuiVisibility (((Test-GuiOrdinalIn $action @('Convert','Recover') -IgnoreCase) -and (Test-GuiOrdinal $g.Mode 'Continue' -IgnoreCase)) -or (Test-GuiOrdinal $action 'Finalize' -IgnoreCase))
    $c.CheckPanel.Visibility=Get-PraGuiVisibility ((Test-GuiOrdinal $action 'Check' -IgnoreCase))
    $c.PhaseCard.Visibility=Get-PraGuiVisibility ([bool]$action)
    $c.OnWhatTitle.Text=$(if ($action) { 'On what? · ' + $script:GuiActionTitle[$action] } else { 'On what?' })
    switch ($action) {
        'Convert' { $c.Mode_New.Content='Start a new batch (Active Directory part)'; $c.Mode_Continue.Content='Continue a batch (cloud part)' }
        'Recover' { $c.Mode_New.Content='Roll back a conversion'; $c.Mode_Continue.Content='Continue a rollback (cloud part)' }
    }
    $g.Updating++
    try { $c.Mode_New.IsChecked=((Test-GuiOrdinal $g.Mode 'New' -IgnoreCase)); $c.Mode_Continue.IsChecked=((Test-GuiOrdinal $g.Mode 'Continue' -IgnoreCase)) } finally { $g.Updating-- }
    if ($newConvert) {
        $source=Get-PraGuiField 'Source'
        $c.Row_Identity.Visibility=Get-PraGuiVisibility ((Test-GuiOrdinal $source 'Single' -IgnoreCase)); $c.Row_ScopeInfo.Visibility=Get-PraGuiVisibility ((Test-GuiOrdinal $source 'Scope' -IgnoreCase))
        $c.Row_Ou.Visibility=Get-PraGuiVisibility ((Test-GuiOrdinal $source 'Ou' -IgnoreCase)); $c.Row_Csv.Visibility=Get-PraGuiVisibility ((Test-GuiOrdinal $source 'Csv' -IgnoreCase))
        $text=Get-PraGuiSourceText
        $c.ScopeInfoText.Text=$text[1]
        $c.SourceInfo.Text=$(if ((Test-GuiOrdinal $source 'Csv' -IgnoreCase) -and (Get-PraGuiField 'Csv')) { $text[1] } else { '' })
    }
    $c.BatchHelp.Text=switch ($action) {
        'Convert' { 'Batches and packages found for this environment folder. Pick the one to continue; greyed ones have nothing to do in the cloud.' }
        'Recover' { if ((Test-GuiOrdinal $g.Mode 'New' -IgnoreCase)) { 'Pick the conversion batch to roll back.' } else { 'Pick the rollback to continue in the cloud.' } }
        'Finalize' { 'Pick the Finalize package to complete. A package appears when the cloud part of a rollback asks for a final AD restore.' }
        default { '' }
    }
    if ($action) {
        $phase=Get-PraGuiPhase
        $c.PhasePillText.Text=$(if ((Test-GuiOrdinal $action 'Check' -IgnoreCase)) { 'Read only' } elseif ((Test-GuiOrdinal $action 'Finalize' -IgnoreCase)) { 'Phase: AD' } else { 'Phase: ' + $phase })
        Set-PraGuiPill $c.PhasePill $c.PhasePillText 'Brand'
        $c.PhaseText.Text=Get-PraGuiPhaseText
        if ((Test-GuiOrdinalIn $action @('Convert','Recover') -IgnoreCase) -and (-not (Test-GuiOrdinal (Get-PraGuiField 'ExpPhase') 'Auto' -IgnoreCase))) { $c.PhaseText.Text+=(' (Expert mode forces phase {0}.)' -f (Get-PraGuiField 'ExpPhase')) }
        $blocker=Get-PraGuiBlocker
        $c.BlockBox.Visibility=Get-PraGuiVisibility ([bool]$blocker); $c.BtnFixHome.Visibility=Get-PraGuiVisibility ([bool]$blocker); $c.BlockText.Text=$blocker
    }
}

function Test-PraGuiConfirmed {
    $g=$script:Gui
    $word=$script:GuiActionWord[$g.Action]
    if (-not $word) { return $true }
    return Test-PraGuiConfirmation $g.Controls.ConfirmBox.Text $g.Action
}

function Update-PraGuiVerifyView {
    $g=$script:Gui; $c=$g.Controls
    $action=$g.Action
    $word=$script:GuiActionWord[$action]
    $c.ConfirmCard.Visibility=Get-PraGuiVisibility ([bool]$word)
    $c.ConfirmBox.IsEnabled=($null -ne $g.Pending) -and -not $g.Run
    $c.ConfirmText.Text=$(if ($word) { "To start, type $word in the box (capitals or not). This avoids a run started by a stray click." } else { '' })
    $c.ConfirmTick.Visibility=$(if ($g.Pending -and $word -and (Test-PraGuiConfirmed)) { 'Visible' } else { 'Hidden' })
    $source=if ($g.SelectedBatch) { ('Batch ' + [string]$g.SelectedBatch.BatchId) } elseif ((Test-GuiOrdinal $action 'Check' -IgnoreCase)) { Get-PraGuiField 'CheckUpn' } elseif ((Test-GuiOrdinal $action 'Convert' -IgnoreCase)) { (Get-PraGuiSourceText)[0] } else { '' }
    $changed=@($script:GuiSettingKeys | Where-Object { -not ((Test-GuiOrdinal $_ 'Env' -IgnoreCase) -and $g.EnvLock) -and -not ((Test-GuiOrdinalIn $_ @('AppId','Thumb') -IgnoreCase) -and (-not (Test-GuiOrdinal (Get-PraGuiField 'Signin') 'Cert' -IgnoreCase))) -and (Test-PraGuiModified $_) }).Count
    $replicationLine=if ((Test-GuiOrdinalIn $action @('Convert','Recover','Finalize') -IgnoreCase) -and [bool](Get-PraGuiField 'Repl')) { "`nActive Directory replication before the sync: on" } else { '' }
    $c.UsedText.Text="Environment: $(Get-PraGuiField 'Env')`nDomain controller: $(if (Get-PraGuiField 'Dc') { Get-PraGuiField 'Dc' } else { 'chosen automatically' })`nObjects: $source`nMailbox scope: $(Get-PraGuiField 'Scope')`nSign-in: $(if ((Test-GuiOrdinal (Get-PraGuiField 'Signin') 'Cert' -IgnoreCase)) { 'Certificate' } else { 'Interactive (WAM)' })$replicationLine" +
        $(if ($changed) { "`n`n" + (ConvertTo-PraGuiPlural $changed 'value differs' 'values differ') + ' from the configuration file, for this run only.' } else { '' })
    $phase=Get-PraGuiPhase
    if (-not ($g.Run -and (Test-GuiOrdinal $g.Run.Request.Mode 'Preview' -IgnoreCase))) {
        $titles=@(Get-PraGuiPlanTitle $action $phase)
        $plan=New-Object 'Collections.ObjectModel.ObservableCollection[object]'
        for ($i=0; $i -lt $titles.Count; $i++) { $plan.Add((New-PraGuiRow @{ N=[string]($i+1); Title=$titles[$i]; What=[string]$script:GuiStepInfo[$titles[$i]] })) }
        $c.PlanList.ItemsSource=$plan
    }
    $c.Chips.Children.Clear()
    $c.VerList.Visibility=Get-PraGuiVisibility ($g.Previewed -and $g.VerRows.Count -gt 0)
    if ($g.Run -and (Test-GuiOrdinal $g.Run.Request.Mode 'Preview' -IgnoreCase)) {
        $c.SumTitle.Text='Preview in progress...'; $c.SumText.Text='Reading Active Directory and the backup folder. The preview only reads: nothing is modified.'
        $c.SumGlyph.Text=[string][char]0xE895; Set-PraGuiPill $c.SumIcon $c.SumGlyph 'Brand'
        $c.VerEmpty.Visibility='Visible'; $c.VerBar.Visibility='Visible'; $c.VerEmptyText.Text=if ($g.Model.Steps.Count) { 'Step: ' + [string]$g.Model.Current } else { 'Starting...' }
    }
    elseif ($g.PreviewError) {
        $c.SumTitle.Text='The preview did not complete'; $c.SumText.Text=$g.PreviewError
        $c.SumGlyph.Text=[string][char]0xEA39; Set-PraGuiPill $c.SumIcon $c.SumGlyph 'Fail'
        $c.VerEmpty.Visibility='Visible'; $c.VerBar.Visibility='Collapsed'; $c.VerEmptyText.Text='Nothing was changed. Read the message above, fix the cause, then preview again.'
    }
    elseif ((Test-GuiOrdinal $action 'Check' -IgnoreCase)) {
        $c.SumTitle.Text='The mailbox will be checked. Nothing is changed.'; $c.SumText.Text='The check reads Active Directory and Exchange Online and tells you whether they agree.'
        $c.SumGlyph.Text=[string][char]0xE721; Set-PraGuiPill $c.SumIcon $c.SumGlyph 'Neutral'
        $c.VerEmpty.Visibility='Visible'; $c.VerBar.Visibility='Collapsed'; $c.VerEmptyText.Text='There is no preview for a check: it never writes. Click the button below to run it.'
    }
    elseif (-not $g.Previewed) {
        $c.SumTitle.Text='Preview needed before running'; $c.SumText.Text='Click Preview: it only reads, nothing is changed. Run unlocks after the preview and the confirmation word.'
        $c.SumGlyph.Text=[string][char]0xE721; Set-PraGuiPill $c.SumIcon $c.SumGlyph 'Neutral'
        $c.VerEmpty.Visibility='Visible'; $c.VerBar.Visibility='Collapsed'; $c.VerEmptyText.Text='Click Preview to see exactly what would change. The preview only reads: nothing is modified.'
    }
    else {
        $rows=@($g.VerRows)
        $shared=@($rows | Where-Object { (Test-GuiOrdinal $_.Type 'Shared' -IgnoreCase) }).Count
        $warn=@($rows | Where-Object { (Test-GuiOrdinal $_.Status 'Warn' -IgnoreCase) }).Count
        $failed=@($rows | Where-Object { (Test-GuiOrdinal $_.Status 'Fail' -IgnoreCase) }).Count
        $verb=switch ($action) { 'Convert' { 'converted' } 'Recover' { 'rolled back' } 'Finalize' { 'finalized' } default { 'checked' } }
        $count=$rows.Count
        $c.VerEmpty.Visibility=Get-PraGuiVisibility ($count -eq 0); $c.VerBar.Visibility='Collapsed'; $c.VerEmptyText.Text='The preview found no object to process.'
        $kinds=New-Object 'Collections.Generic.List[string]'
        if ($count-$shared -gt 0) { $kinds.Add((ConvertTo-PraGuiPlural ($count-$shared) 'user' 'users')) }
        if ($shared -gt 0) { $kinds.Add("$shared shared") }
        $c.SumTitle.Text=('{0} will be {1}{2} · {3}' -f (ConvertTo-PraGuiPlural $count 'mailbox' 'mailboxes'),$verb,$(if ($kinds.Count) { ' (' + ($kinds -join ', ') + ')' } else { '' }),$(if ($failed) { "$failed blocking" } else { 'nothing blocking' }))
        $c.SumText.Text=$(if ($warn) { 'Nothing blocks the run. ' + (ConvertTo-PraGuiPlural $warn 'warning' 'warnings') + ' to read below: you can still go on.' } else { 'Nothing in the way.' })
        if ($word) { $c.SumText.Text+=" Type $word below, then run." }
        $c.SumGlyph.Text=$(if ($failed) { [string][char]0xEA39 } elseif ($warn) { [string][char]0xE7BA } else { [string][char]0xE73E })
        Set-PraGuiPill $c.SumIcon $c.SumGlyph $(if ($failed) { 'Fail' } elseif ($warn) { 'Warn' } else { 'Ok' })
        Add-PraGuiChip (ConvertTo-PraGuiPlural ($count-$shared) 'user' 'users') 'Neutral'
        if ($shared) { Add-PraGuiChip "$shared shared" 'Neutral' }
        Add-PraGuiChip "$failed blocking" $(if ($failed) { 'Fail' } else { 'Ok' })
        if ($warn) { Add-PraGuiChip (ConvertTo-PraGuiPlural $warn 'warning' 'warnings') 'Warn' }
    }
    $c.GridTitle.Text=$(if ($g.VerRows.Count) { "Objects ($($g.VerRows.Count))" } else { 'Objects' })
}

function Add-PraGuiChip {
    param([string]$Text, [string]$Level)
    $border=New-Object Windows.Controls.Border
    $border.CornerRadius=[Windows.CornerRadius]::new(10); $border.Padding=[Windows.Thickness]::new(10,2,10,2); $border.Margin=[Windows.Thickness]::new(0,0,8,0)
    $label=New-Object Windows.Controls.TextBlock
    $label.Text=$Text; $label.FontSize=12; $label.FontWeight=[Windows.FontWeights]::SemiBold; $border.Child=$label
    Set-PraGuiPill $border $label $Level
    [void]$script:Gui.Controls.Chips.Children.Add($border)
}

function Get-PraGuiRunLabel {
    switch ($script:Gui.Action) {
        'Convert' { return 'Convert the mailboxes' }
        'Recover' { return 'Roll back the mailboxes' }
        'Finalize' { return 'Finalize the rollback' }
        'Check' { return 'Check the mailbox' }
        default { return 'Run' }
    }
}

function Update-PraGuiButtons {
    $g=$script:Gui; $c=$g.Controls
    $arrow=[string][char]0x2192
    $busy=[bool]$g.Run -or [bool]$g.OuLookup
    $c.BtnBack.Visibility=Get-PraGuiVisibility (($g.Page -gt 1) -and -not ((Test-PraGuiApplied) -and $g.Page -le 4))
    $c.BtnBack.IsEnabled=-not $busy
    $c.BtnPreview.Visibility=Get-PraGuiVisibility ($g.Page -eq 3 -and (-not (Test-GuiOrdinal $g.Action 'Check' -IgnoreCase)))
    $next=$c.BtnNext
    $next.IsEnabled=$true
    switch ($g.Page) {
        1 { $next.Content="Choose a task  $arrow"; $next.IsEnabled=(-not $g.State.ConfigError) -and -not (Get-PraGuiSettingsProblem) -and -not $busy -and -not $g.NetJob }
        2 { $next.Content="Continue to verification  $arrow"; $next.IsEnabled=(Test-PraGuiTaskReady) -and -not $busy }
        3 {
            $next.Content=Get-PraGuiRunLabel
            $ready=(Test-PraGuiTaskReady) -and -not $busy
            $next.IsEnabled=if ((Test-GuiOrdinal $g.Action 'Check' -IgnoreCase)) { $ready } else { $ready -and ($null -ne $g.Pending) -and (Test-PraGuiConfirmed) }
            $c.BtnPreview.Content=$(if ($g.Previewed) { 'Preview again' } else { 'Preview' })
            $c.BtnPreview.IsEnabled=$ready
            if ($g.Previewed) { $c.BtnPreview.ClearValue([Windows.Controls.Button]::StyleProperty) } else { $c.BtnPreview.Style=$g.Form.FindResource('AccentBtn') }
        }
        4 {
            if ($g.Run) { $next.Content='Running...'; $next.IsEnabled=$false }
            elseif ($g.LastRun -and -not $g.LastRun.Valid) { $next.Content="What now?  $arrow" }
            elseif ($g.LastRun) { $next.Content="What next?  $arrow" }
            else { $next.Content='Nothing running'; $next.IsEnabled=$false }
        }
        5 { $next.Content='Start a new task' }
    }
    $c.Footer.Text=switch ($g.Page) {
        1 { if ($g.NetJob) { 'Checking that Microsoft 365 can be reached from this server (a few seconds)...' } else { 'Check the lights and the run settings. Changes here are for this run only.' } }
        2 { 'Pick what you want to do. The console works out the phase for you.' }
        3 { if ((Test-GuiOrdinal $g.Action 'Check' -IgnoreCase)) { 'A check only reads. Nothing is written.' } else { 'The preview comes first. Run unlocks after the preview and the confirmation word.' } }
        4 { if ($g.Run) { 'Do not close this window: the backup and the AD proof cover the whole batch. There is no stop per object.' } else { '' } }
        5 { 'Keep the transfer package: it is what carries the batch to the next server.' }
    }

    $c.ContextText.Text=if ($g.Action) {
        '{0} · {1} · {2}' -f $script:GuiActionTitle[$g.Action],$(switch ($g.Action) { 'Check' { 'read only' } 'Finalize' { 'finalize package' } default { if ((Test-GuiOrdinal $g.Mode 'New' -IgnoreCase)) { 'new batch' } else { 'continue a batch' } } }),(Get-PraGuiField 'Env')
    } else { 'No task chosen yet · ' + (Get-PraGuiField 'Env') }
}

function Update-PraGuiView {
    <# One refresh of the whole window from its state; cheap (no file or network access except the optional batch list on the Task page). #>
    $g=$script:Gui
    if (-not $g -or $g.Updating -gt 0) { return }
    $g.Updating++
    try {
        Update-PraGuiSettingsView
        switch ($g.Page) { 2 { Update-PraGuiTaskView } 3 { Update-PraGuiVerifyView } }
        Update-PraGuiButtons
    } finally { $g.Updating-- }
}

function Reset-PraGuiPreview {
    <# Any change of the task or of the settings voids the preview and the confirmation. #>
    $g=$script:Gui
    $g.Pending=$null; $g.Previewed=$false; $g.PreviewError=''
    $g.VerRows.Clear()
    $g.Updating++
    try { $g.Controls.ConfirmBox.Clear() } finally { $g.Updating-- }
}

function Invoke-PraGuiChange {
    <# Called by every control that changes the task or the run settings. #>
    $g=$script:Gui
    if (-not $g -or $g.Updating -gt 0 -or $g.Run) { return }
    Reset-PraGuiPreview
    if ($g.Page -eq 1 -or $g.Page -eq 2) { Invoke-PraGuiDetection }
    Update-PraGuiView
}

function Show-PraGuiPage {
    param([int]$Number)
    $g=$script:Gui; $c=$g.Controls
    $g.Page=$Number
    foreach ($index in 1..5) { $c["Page$index"].Visibility=Get-PraGuiVisibility ((Test-GuiOrdinal $index $Number -IgnoreCase)) }
    $g.Updating++
    try { $c["Nav$Number"].IsChecked=$true } finally { $g.Updating-- }
    if ($Number -eq 2) { Update-PraGuiBatchList }
    Update-PraGuiView
}

function Test-PraGuiApplied {
    <# True once an Apply has run (successfully or not) and the operator has not started a new task: Verify must not be reachable again. #>
    $g=$script:Gui
    return ($null -ne $g.LastRun) -and (Test-GuiOrdinal $g.LastRun.Purpose 'Run' -IgnoreCase) -and (Test-GuiOrdinal $g.LastRun.Request.Mode 'Apply' -IgnoreCase)
}

function Test-PraGuiPageReachable {
    param([int]$Number)
    $g=$script:Gui
    if ($g.Run) { return $Number -eq 4 }
    if (Test-PraGuiApplied) { return $Number -ge 4 -and $null -ne $g.LastRun }
    switch ($Number) {
        1 { return $true }
        2 { return (-not $g.State.ConfigError) -and -not $g.NetJob }
        3 { return [bool](Test-PraGuiTaskReady) }
        4 { return $null -ne $g.Model }
        5 { return $null -ne $g.LastRun }
        default { return $false }
    }
}
#endregion


#region Window: activity log, run model (steps, objects, waits), engine events
function Add-PraGuiLine {
    param([string]$Text, [string]$Status='Info')
    $g=$script:Gui
    $key=switch ($Status) { 'Fail' { 'PraCritical' } 'Warn' { 'PraCaution' } 'Ok' { 'PraSuccess' } default { 'TextFillColorSecondaryBrush' } }
    $g.Lines.Add([pscustomobject]@{ Text=$Text; Brush=$g.Form.TryFindResource($key) })
    while ($g.Lines.Count -gt 2000) { $g.Lines.RemoveAt(0) }
    if ($g.Controls.LogExpander.IsExpanded) { $g.Controls.ActivityLog.ScrollIntoView($g.Lines[$g.Lines.Count-1]) }
}

function Format-PraGuiClock {
    param([double]$Seconds)
    $total=[int][Math]::Max(0,[Math]::Floor($Seconds))
    return ('{0:00}:{1:00}' -f [Math]::Floor($total/60),($total % 60))
}

function ConvertTo-PraGuiStatus {
    <# Engine state or item status -> the status of a row (drives the glyph and the colours). #>
    param([string]$Value)
    $map=@{ running='Running'; ok='Ok'; warn='Warn'; fail='Fail'; skipped='Skip'; skip='Skip'; info='Info'; sub='Info'; pending='Pending'; wait='Wait' }
    $key=$Value.ToLowerInvariant()
    if ($map.ContainsKey($key)) { return [string]$map[$key] }
    return 'Info'
}

function ConvertTo-PraGuiUtc {
    param($Value)
    $parsed=[datetime]::MinValue
    if ($Value -and [datetime]::TryParse([string]$Value,[Globalization.CultureInfo]::InvariantCulture,[Globalization.DateTimeStyles]::RoundtripKind,[ref]$parsed)) { return $parsed.ToUniversalTime() }
    return [datetime]::UtcNow
}

function New-PraGuiStepRow {
    param([string]$Id, [int]$Index, [string]$Label, $Expected=0)
    $info=$script:GuiStepInfo[$Label]
    return New-PraGuiRow @{
        Id=$Id; Index=$Index; Label=$Label; Title=('{0}. {1}' -f $Index,$Label); What=$(if ($info) { [string]$info } else { '' }); Status='Pending'
        Counter=$(if ([int]$Expected -gt 0) { ConvertTo-PraGuiPlural ([int]$Expected) 'object' 'objects' } else { '' }); Progress=[double]0; Note=''; NoteBase=''; NextAt=$null
        Elapsed=''; Started=$null; Ended=$null; Expected=[int]$Expected; Warnings=0; WaitWhat=''; WaitAttempt=0; WaitMax=0; WaitLimit=0
    }
}

function Initialize-PraGuiRunModel {
    <# The steps are known before the run starts (the engine announces them in its plan event, which replaces this first list). #>
    param($Request)
    $g=$script:Gui; $c=$g.Controls
    $steps=New-Object 'Collections.ObjectModel.ObservableCollection[object]'
    $model=@{ Steps=$steps; ById=@{}; Objects=@{}; Messages=@{}; Raw=@{}; Current=''; Follow=$true; Dirty=$true; Selected=$null; Info=@{}; BatchBackup='' }
    $titles=@(Get-PraGuiPlanTitle $Request.Action $Request.Phase)
    for ($i=0; $i -lt $titles.Count; $i++) {
        $row=New-PraGuiStepRow ('s'+($i+1)) ($i+1) $titles[$i]
        $steps.Add($row); $model.ById[$row.Id]=$row
    }
    $g.Model=$model
    $g.Updating++
    try { $c.StepList.ItemsSource=$steps } finally { $g.Updating-- }
    $c.StepsTitle.Text=if ($steps.Count) { "Steps ($($steps.Count), all known before the start)" } else { 'Steps' }
    $c.DetObjList.ItemsSource=$null; $c.DetMsgs.ItemsSource=$null
    $c.DetTitle.Text='Waiting for the first step...'; $c.DetWhat.Text=''; $c.DetObjHeader.Text=''; $c.DetPillText.Text=''; $c.DetRaw.Text=''
    $c.DetNoMsg.Visibility='Visible'
    $c.ObjCard.Visibility='Collapsed'; $c.ObjEmpty.Visibility='Visible'
}

function Get-PraGuiModelStep {
    <# The row of a step: by id, by index, or created on the fly when the engine did not announce a plan. #>
    param([string]$Id, [int]$Index=0, [string]$Title='')
    $m=$script:Gui.Model
    if ($Id -and $m.ById.ContainsKey($Id)) { return ,$m.ById[$Id] }
    if ($Index -gt 0 -and $m.ById.ContainsKey('s'+$Index)) { return ,$m.ById['s'+$Index] }
    if (-not $Id) { $Id=if ($Index -gt 0) { 's'+$Index } else { 's'+($m.Steps.Count+1) } }
    if ($Index -le 0) { $Index=$m.Steps.Count+1 }
    $row=New-PraGuiStepRow $Id $Index $(if ($Title) { $Title } else { 'Step ' + $Index })
    $m.Steps.Add($row); $m.ById[$Id]=$row
    return ,$row
}

function Set-PraGuiPlanFromEvent {
    param($Record)
    $g=$script:Gui; $m=$g.Model
    # Replacing the list changes the selection by itself: that is not the operator choosing a step.
    $g.Updating++
    try { $m.Steps.Clear() } finally { $g.Updating-- }
    $m.ById.Clear(); $m.Selected=$null; $m.Follow=$true
    $index=0
    foreach ($step in @(Get-PraGuiValue $Record 'steps' @())) {
        $index++
        $id=[string](Get-PraGuiValue $step 'id' ('s'+$index))
        $row=New-PraGuiStepRow $id $index ([string](Get-PraGuiValue $step 'label' ('Step '+$index))) ([int](Get-PraGuiValue $step 'count' 0))
        $m.Steps.Add($row); $m.ById[$id]=$row
    }
    $g.Controls.StepsTitle.Text="Steps ($($m.Steps.Count), all known before the start)"
    $plan=New-Object 'Collections.ObjectModel.ObservableCollection[object]'
    foreach ($row in $m.Steps) { $plan.Add((New-PraGuiRow @{ N=[string]$row.Index; Title=[string]$row.Label; What=[string]$row.What })) }
    $g.Controls.PlanList.ItemsSource=$plan
    $m.Dirty=$true
}

function Add-PraGuiStepRaw {
    <# Technical lines (item detail, engine console lines) are kept per step, for the "Technical message" box. #>
    param([string]$Text, [string]$StepId='')
    $g=$script:Gui
    if (-not $g -or -not $g.Model) { return }
    $m=$g.Model
    $id=if ($StepId) { $StepId } else { [string]$m.Current }
    if (-not $id) { return }
    if (-not $m.Raw.ContainsKey($id)) { $m.Raw[$id]=New-Object 'Collections.Generic.List[string]' }
    $m.Raw[$id].Add($Text)
    while ($m.Raw[$id].Count -gt 400) { $m.Raw[$id].RemoveAt(0) }
    $m.Dirty=$true
}

function Invoke-PraGuiPlanEvent { param($Record) Set-PraGuiPlanFromEvent $Record }

function Invoke-PraGuiStepEvent {
    param($Record)
    $g=$script:Gui; $m=$g.Model
    $index=[int](Get-PraGuiValue $Record 'index' 0)
    $title=[string](Get-PraGuiValue $Record 'title' '')
    $row=Get-PraGuiModelStep ([string](Get-PraGuiValue $Record 'id' '')) $index $title
    # Without a state (a plan-less engine), a step event means "this step starts, the previous one is done".
    $state=[string](Get-PraGuiValue $Record 'state' '')
    if (-not $state) {
        foreach ($other in $m.Steps) { if ((Test-GuiOrdinalIn $other.Status @('Running','Wait') -IgnoreCase)) { Set-PraGuiRow $other @{ Status='Ok'; Progress=[double]1; NoteBase=''; Note=''; NextAt=$null } } }
        $state='running'
    }
    $status=ConvertTo-PraGuiStatus $state
    $started=ConvertTo-PraGuiUtc (Get-PraGuiValue $Record 'startedUtc' ([datetime]::UtcNow.ToString('o')))
    switch ($status) {
        'Running' {
            Set-PraGuiRow $row @{ Status='Running'; Started=$started; Ended=$null; Elapsed='00:00' }
            $m.Current=[string]$row.Id
            if ($m.Follow) { $g.Updating++; try { $g.Controls.StepList.SelectedItem=$row } finally { $g.Updating-- }; $m.Selected=$row }
        }
        'Skip' { Set-PraGuiRow $row @{ Status='Skip'; Progress=[double]0; Note=''; NoteBase=''; NextAt=$null } }
        default {
            $ended=ConvertTo-PraGuiUtc (Get-PraGuiValue $Record 'endedUtc' ([datetime]::UtcNow.ToString('o')))
            $begun=if ($row.Started) { [datetime]$row.Started } else { $started }
            $count=if ($m.Objects.ContainsKey([string]$row.Id)) { $m.Objects[[string]$row.Id].Count } else { 0 }
            Set-PraGuiRow $row @{ Status=$status; Ended=$ended; Progress=[double]1; Note=''; NoteBase=''; NextAt=$null; Elapsed=(Format-PraGuiClock (($ended-$begun).TotalSeconds))
                Counter=$(if ($count) { ConvertTo-PraGuiPlural $count 'object' 'objects' } else { [string]$row.Counter }) }
            if ($count -gt 0 -and [int]$row.Expected -gt 0) { Set-PraGuiRow $row @{ Counter=('{0} / {1} objects' -f $count,$row.Expected) } }
        }
    }
    $m.Dirty=$true
}

function Invoke-PraGuiItemEvent {
    param($Record)
    $g=$script:Gui; $m=$g.Model; $run=$g.Run
    $status=ConvertTo-PraGuiStatus ([string](Get-PraGuiValue $Record 'status' 'Info'))
    $text=[string](Get-PraGuiValue $Record 'text' '')
    # The engine names the object of an item (`name`: UPN or account name). An identity that is not an object (a DN, a server, 'Batch', a bare GUID) is not
    # listed as a mailbox. An engine that sends no `name` (older, synthetic) is read as before: the identity, when it looks like an account name.
    $identity=[string](Get-PraGuiValue $Record 'name' $null)
    if ($null -eq (Get-PraGuiValue $Record 'name' $null)) {
        $raw=[string](Get-PraGuiValue $Record 'identity' '')
        $identity=if ($raw -match '\A[\w.+@-]+\z' -and $raw -notmatch '\A[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}\z') { $raw } else { '' }
    }
    $detail=[string](Get-PraGuiValue $Record 'detail' '')
    $stepId=[string](Get-PraGuiValue $Record 'stepId' '')
    if (-not $stepId) { $stepId=[string]$m.Current }
    # (no $row=if (...) { row }: an if used as a value would enumerate the dynamic row)
    $row=$null
    if ($stepId -and $m.ById.ContainsKey($stepId)) { $row=$m.ById[$stepId] } elseif ($m.Steps.Count) { $row=$m.Steps[$m.Steps.Count-1] }
    if ($row) {
        $id=[string]$row.Id
        if ($identity) {
            if (-not $m.Objects.ContainsKey($id)) { $m.Objects[$id]=New-Object 'Collections.ObjectModel.ObservableCollection[object]' }
            $existing=$null
            foreach ($candidate in $m.Objects[$id]) { if (Test-GuiOrdinal $candidate.Name $identity -IgnoreCase) { $existing=$candidate; break } }
            $backup=[string](Get-PraGuiValue $Record 'backup' '')
            if ($backup) {
                $key=$identity.ToLowerInvariant()
                if (-not $m.Info.ContainsKey($key)) { $m.Info[$key]=@{ Name=$identity; Upn=$(if ($identity.Contains('@')) { $identity } else { '' }); Type='Mailbox'; Backup=$backup } } else { $m.Info[$key].Backup=$backup }
            }
            $worse=@{ Pending=0; Info=1; Ok=2; Skip=2; Warn=3; Fail=4 }
            if ($existing) {
                $keepStatus=if ([int]$worse[[string]$existing.Status] -gt [int]$worse[$status]) { [string]$existing.Status } else { $status }
                Set-PraGuiRow $existing @{ Result=$text; Status=$keepStatus }
            }
            else { $m.Objects[$id].Add((New-PraGuiRow @{ Name=$identity; Upn=''; Result=$text; Status=$status; Identity=$identity })) }
            if (-not [int]$row.Expected) { Set-PraGuiRow $row @{ Counter=(ConvertTo-PraGuiPlural $m.Objects[$id].Count 'object' 'objects') } }
            else {
                # "1 / 2 objects" and a proportional bar while the step works, not only at its end.
                $doneCount=$m.Objects[$id].Count
                Set-PraGuiRow $row @{ Counter=('{0} / {1} objects' -f $doneCount,$row.Expected); Progress=[double][Math]::Min(1.0,$doneCount/[double]$row.Expected) }
            }
        }
        elseif ([string](Get-PraGuiValue $Record 'backup' '')) { $m.BatchBackup=[string](Get-PraGuiValue $Record 'backup' '') }
        if ((Test-GuiOrdinalIn $status @('Warn','Fail') -IgnoreCase)) {
            if (-not $m.Messages.ContainsKey($id)) { $m.Messages[$id]=New-Object 'Collections.ObjectModel.ObservableCollection[object]' }
            $m.Messages[$id].Add((New-PraGuiRow @{ Text=$(if ($identity) { $identity + ': ' + $text } else { $text }); Status=$status; Identity=$identity }))
            Set-PraGuiRow $row @{ Warnings=([int]$row.Warnings+1) }
        }
        Add-PraGuiStepRaw $(if ($detail) { $text + "`r`n" + $detail } else { $text }) $id
        # An item after a wait: the step is working again.
        if ((Test-GuiOrdinal $row.Status 'Wait' -IgnoreCase)) { Set-PraGuiRow $row @{ Status='Running' } }
    }
    $m.Dirty=$true
}

function Invoke-PraGuiCountEvent {
    <# The engine knows how many objects it works on (after targeting): the steps that work object by object show "0 / N objects". #>
    param($Record)
    $m=$script:Gui.Model
    $count=[int](Get-PraGuiValue $Record 'count' 0)
    if ($count -le 0) { return }
    foreach ($id in @(Get-PraGuiValue $Record 'stepIds' @())) {
        if (-not $m.ById.ContainsKey([string]$id)) { continue }
        $row=$m.ById[[string]$id]
        $done=if ($m.Objects.ContainsKey([string]$id)) { $m.Objects[[string]$id].Count } else { 0 }
        Set-PraGuiRow $row @{ Expected=$count; Counter=('{0} / {1} objects' -f $done,$count) }
    }
    $m.Dirty=$true
}

function Invoke-PraGuiProgressEvent {
    param($Record)
    $g=$script:Gui; $m=$g.Model
    $stepId=[string](Get-PraGuiValue $Record 'stepId' '')
    if (-not $stepId) { $stepId=[string]$m.Current }
    if (-not $stepId -or -not $m.ById.ContainsKey($stepId)) { return }
    $row=$m.ById[$stepId]
    $attempt=[int](Get-PraGuiValue $Record 'attempt' 0); $max=[int](Get-PraGuiValue $Record 'maxAttempts' 0)
    $current=[double](Get-PraGuiValue $Record 'current' 0); $total=[double](Get-PraGuiValue $Record 'total' 0)
    $next=[int](Get-PraGuiValue $Record 'nextInSeconds' 0)
    $note=[string](Get-PraGuiValue $Record 'text' '')
    if ($attempt -gt 0 -and $max -gt 0) { $note+=(' — attempt {0} / {1}' -f $attempt,$max) }
    $fraction=if ($total -gt 0) { [Math]::Min(1.0,$current/$total) } elseif ($max -gt 0) { [Math]::Min(1.0,$attempt/$max) } else { [double]$row.Progress }
    # How long the whole wait may last: the total the engine gives (seconds), else the attempts of the cadence.
    $limit=if ($total -gt 0) { $total } elseif ($max -gt 0 -and $next -gt 0) { [double]$max*$next } else { 0 }
    $data=@{ NoteBase=$note; Note=$note; Progress=[double]$fraction; NextAt=$(if ($next -gt 0) { [datetime]::UtcNow.AddSeconds($next) } else { $null }); WaitWhat=[string](Get-PraGuiValue $Record 'text' ''); WaitAttempt=$attempt; WaitMax=$max; WaitLimit=[double]$limit }
    if ($next -gt 0) { $data.Note=$note + (', next check in {0} s' -f $next); $data.Status='Wait' } else { $data.Status='Running' }
    Set-PraGuiRow $row $data
    $m.Dirty=$true
}

function Invoke-PraGuiEvent {
    param($Record)
    $g=$script:Gui; $run=$g.Run
    foreach ($field in @('title','text')) {
        $shown=[string](Get-PraGuiValue $Record $field '')
        if ($shown.Length -ge 4) { $run.Seen.Add($shown); while ($run.Seen.Count -gt 400) { $run.Seen.RemoveAt(0) } }
    }
    switch -Regex ([string]$Record.kind) {
        '^start\z' { Add-PraGuiLine ([string](Get-PraGuiValue $Record 'title' 'Start')) }
        '^plan\z' { Invoke-PraGuiPlanEvent $Record }
        '^step\z' {
            Invoke-PraGuiStepEvent $Record
            Add-PraGuiLine ('{0}/{1} · {2}' -f [int](Get-PraGuiValue $Record 'index' 0),[int](Get-PraGuiValue $Record 'total' 0),(Get-PraGuiValue $Record 'title' ''))
        }
        '^progress\z' { Invoke-PraGuiProgressEvent $Record }
        '^count\z' { Invoke-PraGuiCountEvent $Record }
        '^item\z' {
            $status=[string](Get-PraGuiValue $Record 'status' 'Info')
            if ($run.Counts.ContainsKey($status)) { $run.Counts[$status]++ }
            if (Test-GuiOrdinal $status 'Fail' -IgnoreCase) { $run.TransportIssues.Add('Engine emitted a Fail item.') }
            Invoke-PraGuiItemEvent $Record
            Add-PraGuiLine (([string](Get-PraGuiValue $Record 'text' ''))+' '+(Get-PraGuiValue $Record 'identity' '')) $status
        }
        '^summary\z' { Add-PraGuiLine ((Get-PraGuiValue $Record 'title' '')+' '+((Get-PraGuiValue $Record 'values' @{}) | ConvertTo-Json -Compress -Depth 5)) ([string](Get-PraGuiValue $Record 'status' 'Info')) }
        '^result\z' {
            $run.ResultCount++; $run.Result=$Record
            if ($run.ResultCount -gt 1) { $run.TransportIssues.Add('Multiple result events.') }
        }
    }
}

function Show-PraGuiStepDetail {
    <# The middle pane: what the step does, its objects, its warnings and errors in plain words, and the raw technical message (collapsed). #>
    param($Row)
    $g=$script:Gui; $c=$g.Controls; $m=$g.Model
    if (-not $Row) { return }
    $id=[string]$Row.Id
    $c.DetTitle.Text=[string]$Row.Title
    $pill=switch ($Row.Status) { 'Ok' { @('Done','Ok') } 'Warn' { @('Done with a warning','Warn') } 'Fail' { @('Failed','Fail') } 'Running' { @('Running','Brand') } 'Wait' { @('Waiting','Warn') } 'Skip' { @('Skipped','Neutral') } default { @('Not started','Neutral') } }
    $c.DetPillText.Text=$pill[0]; Set-PraGuiPill $c.DetPill $c.DetPillText $pill[1]
    $c.DetWhat.Text=[string]$Row.What
    if (Test-GuiOrdinal $Row.Status 'Wait' -IgnoreCase) {
        $c.WaitBox.Visibility='Visible'
        $c.WaitTitle.Text='Waiting: ' + [string]$Row.WaitWhat
        $line=if ([int]$Row.WaitAttempt -gt 0 -and [int]$Row.WaitMax -gt 0) { 'Attempt {0} of {1}' -f [int]$Row.WaitAttempt,[int]$Row.WaitMax } else { 'In progress' }
        if ($Row.NextAt -and ([datetime]$Row.NextAt) -gt [datetime]::UtcNow) { $line+=(' · next check in {0} s' -f [int][Math]::Ceiling((([datetime]$Row.NextAt)-[datetime]::UtcNow).TotalSeconds)) }
        $c.WaitLine.Text=$line
        $limit=[double]$Row.WaitLimit
        $c.WaitNormal.Text=if ($limit -ge 90) { 'This is normal: it can take up to {0} minutes.' -f [int][Math]::Ceiling($limit/60) } elseif ($limit -gt 0) { 'This is normal: it can take up to {0} seconds.' -f [int][Math]::Ceiling($limit) } else { 'This is normal: the directory and the cloud take their time.' }
    }
    else { $c.WaitBox.Visibility='Collapsed' }
    if ($m.Objects.ContainsKey($id)) { $c.DetObjList.ItemsSource=$m.Objects[$id]; $c.DetObjHeader.Text=('OBJECTS  {0}' -f $m.Objects[$id].Count) }
    else { $c.DetObjList.ItemsSource=$null; $c.DetObjHeader.Text='' }
    if ($m.Messages.ContainsKey($id) -and $m.Messages[$id].Count) { $c.DetMsgs.ItemsSource=$m.Messages[$id]; $c.DetNoMsg.Visibility='Collapsed' }
    else { $c.DetMsgs.ItemsSource=$null; $c.DetNoMsg.Visibility='Visible' }
    $c.DetRaw.Text=$(if ($m.Raw.ContainsKey($id)) { $m.Raw[$id] -join "`r`n" } else { '' })
}

function Show-PraGuiObjectCard {
    <# The right pane: the journey of one object across the steps (taken from the item events), its backup and its warnings. #>
    param($Row)
    $g=$script:Gui; $c=$g.Controls; $m=$g.Model
    if (-not $Row) { $c.ObjCard.Visibility='Collapsed'; $c.ObjEmpty.Visibility='Visible'; return }
    $identity=[string]$Row.Identity
    $info=$m.Info[$identity.ToLowerInvariant()]
    $c.CardName.Text=if ($info -and $info.Name) { [string]$info.Name } else { $identity }
    $c.CardUpn.Text=if ($info) { [string]$info.Upn } else { '' }
    $c.CardType.Text=if ($info) { [string]$info.Type } else { 'Mailbox' }
    $journey=New-Object 'Collections.ObjectModel.ObservableCollection[object]'
    $messages=New-Object 'Collections.ObjectModel.ObservableCollection[object]'
    foreach ($step in $m.Steps) {
        $id=[string]$step.Id
        if (-not $m.Objects.ContainsKey($id) -or -not $m.Objects[$id].Count) {
            # A step that works on the whole batch (Entra Connect sync, replication, transfer package, cloud wait) is part of every object's journey.
            if (-not (Test-GuiOrdinal $step.Status 'Skip' -IgnoreCase)) { $journey.Add((New-PraGuiRow @{ Title=[string]$step.Label; Caption=$(if ($step.Note) { 'Whole batch · ' + [string]$step.Note } else { 'Whole batch' }); Status=[string]$step.Status })) }
            continue
        }
        foreach ($candidate in $m.Objects[$id]) {
            if (Test-GuiOrdinal $candidate.Name $identity -IgnoreCase) {
                $journey.Add((New-PraGuiRow @{ Title=[string]$step.Label; Caption=[string]$candidate.Result; Status=[string]$candidate.Status }))
                if ((Test-GuiOrdinalIn $candidate.Status @('Warn','Fail') -IgnoreCase)) { $messages.Add((New-PraGuiRow @{ Text=[string]$candidate.Result; Status=[string]$candidate.Status })) }
            }
        }
    }
    $c.Journey.ItemsSource=$journey
    $c.CardMsgs.ItemsSource=$messages; $c.CardNoMsg.Visibility=Get-PraGuiVisibility ($messages.Count -eq 0)
    $backupPath=if ($info -and $info.Backup) { [string]$info.Backup } elseif ($m.ContainsKey('BatchBackup') -and $m.BatchBackup) { [string]$m.BatchBackup } else { '' }
    $c.CardBackup.Text=$(if ($backupPath) { $backupPath } else { 'No backup written yet (a preview writes none).' })
    $c.BtnCardOpen.IsEnabled=[bool]$backupPath; $c.BtnCardCopy.IsEnabled=[bool]$backupPath
    $c.CardBackup.Tag=$backupPath
    $c.ObjEmpty.Visibility='Collapsed'; $c.ObjCard.Visibility='Visible'
}

function Set-PraGuiRunPill {
    param([string]$Text, [string]$Level)
    $c=$script:Gui.Controls
    $c.RunPillText.Text=$Text; Set-PraGuiPill $c.RunPill $c.RunPillText $Level
}

function Update-PraGuiRunView {
    <# Called by the window timer: elapsed times, the countdown of the waits, the overall bar and the pill. #>
    $g=$script:Gui; $m=$g.Model; $c=$g.Controls
    if (-not $m) { return }
    $now=[datetime]::UtcNow
    $done=0; $fraction=[double]0; $warn=0; $fail=0
    foreach ($row in $m.Steps) {
        switch ($row.Status) {
            { (Test-GuiOrdinalIn $_ @('Running','Wait') -IgnoreCase) } {
                $fraction=[double]$row.Progress
                if ($row.Started) { Set-PraGuiRow $row @{ Elapsed=(Format-PraGuiClock (($now-[datetime]$row.Started).TotalSeconds)) } }
                if ($row.NextAt -and ([datetime]$row.NextAt) -gt $now) { Set-PraGuiRow $row @{ Note=([string]$row.NoteBase + (', next check in {0} s' -f [int][Math]::Ceiling((([datetime]$row.NextAt)-$now).TotalSeconds))) } }
            }
            { (Test-GuiOrdinalIn $_ @('Ok','Skip') -IgnoreCase) } { $done++ }
            'Warn' { $done++; $warn++ }
            'Fail' { $done++; $fail++ }
        }
    }
    $total=$m.Steps.Count
    $c.RunBar.Value=$(if ($total) { [Math]::Min(1.0,($done+$fraction)/$total) } else { 0.0 })
    $elapsed=if ($g.Run) { $g.Run.Clock.Elapsed.TotalSeconds } elseif ($g.LastRun) { $g.LastRun.Seconds } else { 0 }
    $current=@($m.Steps | Where-Object { (Test-GuiOrdinalIn $_.Status @('Running','Wait') -IgnoreCase) } | Select-Object -First 1)
    $c.RunBarText.Text=if ($g.Run) { ('Step {0} of {1} · {2} elapsed' -f $(if ($current.Count) { $current[0].Index } else { [Math]::Min($total,$done+1) }),$total,(Format-PraGuiClock $elapsed)) } else { ('{0} steps · {1}' -f $total,(Format-PraGuiClock $elapsed)) }
    if ($g.Run) { Set-PraGuiRunPill 'Running' 'Brand' }
    if ($m.Dirty) {
        $m.Dirty=$false
        if ($m.Selected) { Show-PraGuiStepDetail $m.Selected }
        elseif ($m.Steps.Count -and -not $m.Selected) { $m.Selected=$m.Steps[0]; Show-PraGuiStepDetail $m.Selected }
    }
    elseif ($m.Selected -and (Test-GuiOrdinalIn $m.Selected.Status @('Running','Wait') -IgnoreCase)) { Show-PraGuiStepDetail $m.Selected }
    if ($g.Page -eq 3 -and $g.Run) {
        $c.VerBar.Value=$c.RunBar.Value
        $label=if ($current.Count) { [string]$current[0].Label } else { 'Starting...' }
        $c.VerEmptyText.Text=if ($current.Count -and $current[0].Note) { $label + ' · ' + $current[0].Note } else { $label }
    }
}
#endregion


#region Window: output of the engine, runs (Preview, Apply, Check), packages, next steps
function Add-PraGuiEngineOutput {
    <#
    .SYNOPSIS
        Shows the engine's console lines in the activity log AS THEY ARRIVE (not only in the .stdout.txt file at the end).
    .DESCRIPTION
        Lines that repeat an event already shown (step, item, summary: the engine writes both) are skipped, so the log
        gains what the events do not carry (module messages, sign-in instructions, warnings). At most 60 lines per tick
        are added; the complete text is always kept in the .stdout.txt file. Polled from the window timer only.
    #>
    param($Run, [switch]$Final)
    $text=$Run.Output.TakeText()
    if (-not $text -and -not ($Final -and ($Run.Partial -or $Run.Hidden -gt 0))) { return }
    $parts=@(([string]$Run.Partial + $text) -split "`r?`n")
    $Run.Partial=[string]$parts[$parts.Count-1]
    $lines=New-Object 'Collections.Generic.List[string]'
    for ($i=0; $i -lt $parts.Count-1; $i++) { $lines.Add([string]$parts[$i]) }
    if ($Run.Partial.Length -gt 8192 -or ($Final -and $Run.Partial)) { $lines.Add($Run.Partial); $Run.Partial='' }
    $added=0
    foreach ($raw in $lines) {
        $line=$raw.Trim()
        if (-not $line) { continue }
        $known=$false
        # A long event text is looked for inside the console line (the engine prefixes it with an icon); a short one must be the whole
        # line, otherwise every console line that merely contains a short word would be hidden.
        foreach ($seen in $Run.Seen) {
            $shown=$seen.Trim()
            if ($(if ($shown.Length -ge 16) { $line.Contains($shown) } else { (Test-GuiOrdinal $line $shown) })) { $known=$true; break }
        }
        if ($known) { continue }
        if ($added -ge 60) { $Run.Hidden++; continue }
        Add-PraGuiLine ('engine · '+$line) 'Info'; $added++
        Add-PraGuiStepRaw $line
    }
    if ($Run.Hidden -gt 0 -and ($added -lt 60 -or $Final)) { Add-PraGuiLine ('engine · {0} output line(s) not shown; the full text is in the .stdout.txt file' -f $Run.Hidden) 'Info'; $Run.Hidden=0 }
}

function Remove-PraGuiCsvGuard {
    <# The server CSV neutralises a leading = + - @ TAB or CR with an apostrophe (spreadsheet formula injection). The grid shows the value, not the guard. #>
    param([AllowEmptyString()][string]$Value)
    if ($Value -cmatch "^'[=+\-@\t\r]") { return $Value.Substring(1) }
    return $Value
}

function Read-PraGuiReport {
    <# The CSV report of a run, with the formula guards removed from the shown values. #>
    param([string]$Path)
    $rows=@(Import-Csv -LiteralPath $Path -Delimiter ';' -Encoding UTF8 -ErrorAction Stop)
    foreach ($row in $rows) {
        foreach ($property in @($row.PSObject.Properties)) {
            if ($property.Value -is [string]) { $property.Value=Remove-PraGuiCsvGuard $property.Value }
        }
        if ($row.PSObject.Properties['IsShared']) { $row.IsShared=(Test-GuiOrdinal $row.IsShared 'True' -IgnoreCase) }
    }
    return $rows
}

function ConvertTo-PraGuiObjectRow {
    param($Row)
    $warnings=[string](Get-PraGuiValue $Row 'Warnings' ''); $final=[string](Get-PraGuiValue $Row 'FinalStatus' ''); $detail=[string](Get-PraGuiValue $Row 'Detail' '')
    $status='Ok'
    if (Test-GuiOrdinalIn $final @('Error','Failed') -IgnoreCase) { $status='Fail' } elseif ($warnings.Trim()) { $status='Warn' }
    $result=if ($warnings.Trim()) { $warnings.Split('|')[0].Trim() } elseif (Test-GuiOrdinal $final 'Planned') { 'Ready' } elseif ($final) { $final } else { 'Ready' }
    $shared=[bool](Get-PraGuiValue $Row 'IsShared' $false)
    return New-PraGuiRow @{
        Name=[string](Get-PraGuiValue $Row 'SamAccountName' ''); Upn=[string](Get-PraGuiValue $Row 'UserPrincipalName' ''); Type=$(if ($shared) { 'Shared' } else { 'User' })
        Status=$status; Result=$result; Plain=$detail
    }
}

function Set-PraGuiBusy {
    <# While the engine (or the OU lookup) works, the Setup and Task pages cannot be edited. #>
    param([bool]$Busy)
    $c=$script:Gui.Controls
    $c.Page1.IsEnabled=-not $Busy; $c.Page2.IsEnabled=-not $Busy
    foreach ($index in 1..5) { $c["Nav$index"].IsEnabled=-not $Busy -or $index -eq 4 }
}

function Show-PraGuiError {
    param([string]$Message)
    $c=$script:Gui.Controls
    Add-PraGuiLine $Message 'Fail'
    $c.TaskError.Text=$Message; $c.ValidationText.Text=$Message; $c.Footer.Text=$Message
}

function New-PraGuiRunConfig {
    <# The configuration of one run: the file itself, or - when run settings were changed in the window - an effective copy written in a private run folder. #>
    $g=$script:Gui
    $override=Get-PraGuiOverride
    $base=[IO.Path]::GetFullPath($(if ([IO.Path]::IsPathRooted($g.ConfigPath)) { $g.ConfigPath } else { Join-Path $g.Root $g.ConfigPath }))
    if (-not $override.Count) { return [pscustomobject]@{ Path=$g.ConfigPath; Base=''; Keys=@(); Hash='' } }
    $folder=Join-Path $g.Root 'logs\gui'
    Initialize-PraPrivateFolder (Join-Path $g.Root 'logs'); Initialize-PraPrivateFolder $folder
    $runFolder=Join-Path $folder ('run-'+[guid]::NewGuid().ToString('N'))
    Initialize-PraPrivateFolder $runFolder
    $made=New-PraEffectiveConfiguration -BasePath $base -Root $g.Root -Overrides $override -Destination (Join-Path $runFolder 'effective.config.psd1')
    return [pscustomobject]@{ Path=[string]$made.Path; Base=$base; Keys=@($made.Keys); Hash=[string]$made.Hash }
}

function Start-PraGuiRun {
    param([ValidateSet('Preview','Apply')][string]$Mode, [ValidateSet('','Preview','Run')][string]$Purpose='')
    $g=$script:Gui; $c=$g.Controls
    if ($g.Run -or $g.OuLookup -or $g.IdLookup -or ($g.PkgJob -and (Test-GuiOrdinal $g.PkgJob.Mode 'Import'))) { throw 'An action, a lookup or a package import is running. Wait for completion.' }
    if (-not $Purpose) { $Purpose=if ((Test-GuiOrdinal $Mode 'Apply' -IgnoreCase)) { 'Run' } else { 'Preview' } }
    $problem=Get-PraGuiSettingsProblem
    if ($problem) { throw $problem }
    $blocker=Get-PraGuiBlocker
    if ($blocker) { throw $blocker }
    $request=Get-PraGuiWindowRequest $Mode
    if ((Test-GuiOrdinal $Mode 'Apply' -IgnoreCase) -and -not $g.Pending) { Reset-PraGuiPreview; Update-PraGuiView; throw 'Apply refused: a successful unchanged Preview and the typed confirmation (the action name, any letter case) are required.' }
    # Apply reuses the effective configuration of the Preview it follows: the same file, so the same guard.
    $config=if ((Test-GuiOrdinal $Mode 'Apply' -IgnoreCase)) { $g.Pending.Config } else { New-PraGuiRunConfig }
    $guard=Get-PraGuiGuard $g.Root $config.Path $request $config.Base
    if ((Test-GuiOrdinal $Mode 'Apply' -IgnoreCase)) {
        if (-not (Test-GuiOrdinal $g.Pending.Guard $guard) -or -not (Test-PraGuiConfirmation $c.ConfirmBox.Text $request.Action)) {
            Reset-PraGuiPreview; Update-PraGuiView
            throw 'Apply refused: a successful unchanged Preview and the typed confirmation (the action name, any letter case) are required.'
        }
    }
    Reset-PraGuiPreview
    $folder=Join-Path $g.Root 'logs\gui'
    Initialize-PraPrivateFolder (Join-Path $g.Root 'logs'); Initialize-PraPrivateFolder $folder
    $base=Join-Path $folder ([guid]::NewGuid().ToString('N'))
    $command=Get-PraGuiCommand $g.Root $config.Path $request -BaseConfigPath $config.Base
    # Re-read immediately before launch, including after typed confirmation and work-folder creation.
    if (-not (Test-GuiOrdinal (Get-PraGuiGuard $g.Root $config.Path $request $config.Base) $guard)) { throw 'Input files changed before launch. Run Preview again.' }
    $child=Start-PraGuiChildProcess $command $g.Root ($base+'.events.jsonl')
    $g.Run=@{
        Request=$request; Guard=$guard; Config=$config; Purpose=$Purpose; Process=$child.Process; Output=$child.Output; Errors=$child.Errors
        EventPath=($base+'.events.jsonl'); Base=$base; Position=[long]0; Result=$null; ResultCount=0
        TransportIssues=(New-Object 'Collections.Generic.List[string]'); Clock=[Diagnostics.Stopwatch]::StartNew(); StartedAt=[datetime]::Now
        Counts=@{Ok=0;Warn=0;Fail=0}; Partial=''; Seen=(New-Object 'Collections.Generic.List[string]'); Hidden=0
    }
    $g.LastResult=$null; $g.LastRun=$null; $g.Lines.Clear(); $g.PreviewError=''
    if ((Test-GuiOrdinal $Purpose 'Preview' -IgnoreCase)) { $g.VerRows.Clear(); $g.Previewed=$false }
    Initialize-PraGuiRunModel $request
    $c.RunTitle.Text=('{0} · {1}' -f $script:GuiActionTitle[$request.Action],$(if ((Test-GuiOrdinal $request.Action 'Check' -IgnoreCase)) { 'read only' } elseif ((Test-GuiOrdinal $request.Action 'Finalize' -IgnoreCase)) { 'AD part' } elseif ((Test-GuiOrdinal $request.Phase 'Both' -IgnoreCase)) { 'AD and cloud, on this server' } else { $request.Phase + ' part' }))
    $c.RunSub.Text=('{0} · {1}{2} · started {3} on {4}' -f $(if ((Test-GuiOrdinal $request.Mode 'Apply' -IgnoreCase)) { 'Apply' } else { 'Preview' }),(Get-PraGuiField 'Env'),$(if ($config.Keys.Count) { ' · ' + (ConvertTo-PraGuiPlural $config.Keys.Count 'setting' 'settings') + ' changed for this run' } else { '' }),[datetime]::Now.ToString('HH:mm',[Globalization.CultureInfo]::InvariantCulture),$env:COMPUTERNAME)
    $c.NextCmd.Text=''
    Set-PraGuiBusy $true
    Add-PraGuiLine ('Started: '+$command.Display)
    if ($config.Keys.Count) { Add-PraGuiLine ('Run settings changed from the configuration file: ' + ($config.Keys -join ', ')) }
    $g.Timer.Start()
    Update-PraGuiView
}

function Get-PraGuiRunIssue {
    <# The first plain reason of a failed run: the first failed item, then the engine's error output. #>
    param($Run, [string]$StandardError)
    $m=$script:Gui.Model
    if ($m) {
        foreach ($row in $m.Steps) {
            if ($m.Messages.ContainsKey([string]$row.Id)) {
                foreach ($message in $m.Messages[[string]$row.Id]) { if ((Test-GuiOrdinal $message.Status 'Fail' -IgnoreCase)) { return [string]$message.Text } }
            }
        }
    }
    foreach ($issue in @(Get-PraGuiValue $Run.Result 'issues' @())) {
        $text=[string](Get-PraGuiValue $issue 'Message' $issue)
        if ($text) { return $text }
    }
    if ($StandardError.Trim()) { return $StandardError.Trim().Split("`n")[0].Trim() }
    foreach ($issue in $Run.TransportIssues) { return [string]$issue }
    return 'The engine ended without a complete result.'
}

function Complete-PraGuiRun {
    $g=$script:Gui; $run=$g.Run; $c=$g.Controls
    $g.Timer.Stop()
    $pending=$null; $valid=$false; $exitCode=-1; $stderr=''; $r=$null; $rows=@()
    try {
        $output=$run.Output.Result; $stderr=$run.Errors.Result
        $exitCode=$run.Process.ExitCode
        $valid=Test-PraGuiResult $run.Result $run.Request $exitCode $run.TransportIssues.ToArray() $stderr
        $r=$run.Result
        $g.LastResult=if ($r) { $r } else { [pscustomobject]@{ logFile=($run.Base+'.stdout.txt'); batchId='' } }
        try {
            $csv=[string](Get-PraGuiValue $r 'csvReport' '')
            if ($csv) { $rows=@(Read-PraGuiReport $csv) }
        } catch {
            $run.TransportIssues.Add('Report unreadable: '+$_.Exception.Message)
            $valid=$false
        }
        if (-not $valid) {
            foreach ($issue in $run.TransportIssues) { Add-PraGuiLine $issue 'Fail' }
            if ($stderr.Trim()) { Add-PraGuiLine $stderr.Trim() 'Fail' }
            Add-PraGuiLine ('Raw output kept in: '+$run.Base+'.stdout.txt / .stderr.txt') 'Fail'
        }
        if (Test-PraGuiPreview $run.Result $run.Request $exitCode $run.TransportIssues.ToArray() $stderr) {
            try {
                $current=Get-PraGuiGuard $g.Root $run.Config.Path $run.Request $run.Config.Base
                if (Test-GuiOrdinal $current $run.Guard) { $pending=@{ Guard=$current; Request=$run.Request; Config=$run.Config } }
                else { Add-PraGuiLine 'Files changed during the preview: the authorisation of Apply is refused.' 'Warn' }
            } catch { Add-PraGuiLine $_.Exception.Message 'Fail' }
        }
    } catch {
        $pending=$null; $valid=$false
        Add-PraGuiLine ('Result or log unreadable: '+$_.Exception.Message) 'Fail'
    } finally {
        $seconds=$run.Clock.Elapsed.TotalSeconds
        $issue=if ($valid) { '' } else { Get-PraGuiRunIssue $run $stderr }
        $run.Process.Dispose(); $g.Run=$null
        # Steps still open when the process ended: the failed one is the one that was running.
        foreach ($row in @($g.Model.Steps)) {
            if ((Test-GuiOrdinalIn $row.Status @('Running','Wait') -IgnoreCase)) { Set-PraGuiRow $row @{ Status=$(if ($valid) { 'Ok' } else { 'Fail' }); Note=''; NoteBase=''; NextAt=$null; Progress=[double]1 } }
        }
        $g.LastRun=[pscustomobject]@{ Request=$run.Request; Result=$r; Valid=$valid; ExitCode=$exitCode; Stderr=$stderr; Base=$run.Base; Seconds=$seconds; Issue=$issue; Purpose=$run.Purpose; Config=$run.Config; StartedAt=$run.StartedAt }
        foreach ($objectRow in $rows) {
            $info=@{ Name=[string](Get-PraGuiValue $objectRow 'SamAccountName' ''); Upn=[string](Get-PraGuiValue $objectRow 'UserPrincipalName' ''); Type=$(if ([bool](Get-PraGuiValue $objectRow 'IsShared' $false)) { 'Shared mailbox' } else { 'User mailbox' }); Backup=[string](Get-PraGuiValue $objectRow 'BackupPath' '') }
            foreach ($key in @($info.Name,$info.Upn)) {
                if (-not $key) { continue }
                # The path known from the events is kept when the report has none for the object.
                if (-not $info.Backup -and $g.Model.Info.ContainsKey($key.ToLowerInvariant())) { $info.Backup=[string]$g.Model.Info[$key.ToLowerInvariant()].Backup }
                $g.Model.Info[$key.ToLowerInvariant()]=$info
            }
        }
        if (-not $g.Model.BatchBackup -and $r) {
            $batchFiles=@(Get-PraGuiValue $r 'backupFiles' @())
            if ($batchFiles.Count) { $g.Model.BatchBackup=[string]$batchFiles[0] }
        }
        if ((Test-GuiOrdinal $run.Purpose 'Preview' -IgnoreCase)) {
            $g.VerRows.Clear()
            foreach ($objectRow in $rows) { $g.VerRows.Add((ConvertTo-PraGuiObjectRow $objectRow)) }
            $g.Previewed=$valid
            $g.PreviewError=if ($valid) { '' } else { $issue }
            $g.Controls.VerList.ItemsSource=$g.VerRows
        }
        Set-PraGuiBusy $false
        $g.State=Read-PraGuiState $g.Root $g.ConfigPath
        $g.Pending=$pending
        $g.Model.Dirty=$true
        Update-PraGuiRunView
        if ($valid) { Set-PraGuiRunPill $(if (@($g.Model.Steps | Where-Object { (Test-GuiOrdinal $_.Status 'Warn' -IgnoreCase) }).Count -or $run.Counts.Warn) { 'Done with warnings' } else { 'Done' }) $(if ($run.Counts.Warn) { 'Warn' } else { 'Ok' }) }
        else { Set-PraGuiRunPill 'Failed' 'Fail' }
        if ((-not (Test-GuiOrdinal $run.Purpose 'Preview' -IgnoreCase))) { Update-PraGuiNext }
        Update-PraGuiView
        Sync-PraGuiTimer
    }
    if ($pending) { Add-PraGuiLine ('Preview validated. Confirm by typing '+$run.Request.Action.ToUpperInvariant()+' (capitals or not); any change requires a new Preview.') 'Ok' }
}

function Invoke-PraGuiTick {
    $g=$script:Gui
    if (-not $g -or $g.InTick) { return }
    if ($g.NetJob) { Complete-PraGuiNetworkCheck }
    if ($g.PkgJob) { Complete-PraGuiPackageJob }
    if ($g.OuLookup) { Complete-PraGuiOuLookup; return }
    if ($g.IdLookup) { Complete-PraGuiIdentityLookup }
    if (-not $g.Run) { return }
    $g.InTick=$true
    try {
        $run=$g.Run; $exited=$run.Process.HasExited
        try {
            do {
                $read=Read-PraGuiEvents $run.EventPath $run.Position
                $old=$run.Position; $run.Position=$read.Position
                foreach ($issue in $read.Errors) { $run.TransportIssues.Add($issue) }
                foreach ($record in $read.Events) { try { Invoke-PraGuiEvent $record } catch { $run.TransportIssues.Add('Event not applied: ' + $_.Exception.Message) } }
            } while ($exited -and $read.Position -gt $old -and (Get-Item -LiteralPath $run.EventPath).Length -gt $read.Position)
            if ($exited -and $read.HasPartial) { $run.TransportIssues.Add('Unterminated event line at process exit.') }
        } catch { $run.TransportIssues.Add($_.Exception.Message); Add-PraGuiLine ($_.ScriptStackTrace) "Fail" }
        Add-PraGuiEngineOutput $run
        Update-PraGuiRunView
        if ($g.Page -eq 4 -or $g.Page -eq 3) { Update-PraGuiButtons }
        if ($exited -and $run.Output.IsCompleted -and $run.Errors.IsCompleted) { Add-PraGuiEngineOutput $run -Final; Complete-PraGuiRun }
    } finally { $g.InTick=$false }
}
#endregion

#region Window: transfer packages and the Next steps page
function Get-PraGuiPackageKey {
    param([string]$Path)
    $item=Get-Item -LiteralPath $Path -ErrorAction Stop
    return ('{0}|{1}|{2}' -f $item.FullName.ToLowerInvariant(),$item.Length,$item.LastWriteTimeUtc.Ticks)
}

function Get-PraGuiPackageInfo {
    <#
    .SYNOPSIS
        The verification of a transfer package against the CONFIGURED Environment. It is cached per (path, size, time); a package that was not seen yet is queued for a child
        process (the window thread never hashes a package) and shown as "checking" meanwhile.
    #>
    param([string]$Path)
    $g=$script:Gui
    $key=Get-PraGuiPackageKey $Path
    if ($g.PkgCache.ContainsKey($key)) { return $g.PkgCache[$key] }
    $known=($g.PkgJob -and (Test-GuiOrdinal $g.PkgJob.Key $key))
    foreach ($entry in $g.PkgQueue) { if (Test-GuiOrdinal $entry.Key $key) { $known=$true } }
    if (-not $known) { [void]$g.PkgQueue.Add(@{ Mode='Verify'; Path=$Path; Key=$key; Then=$null }); Start-PraGuiNextPackageJob }
    return [pscustomobject]@{ Valid=$false; Pending=$true; Error='Checking the checksums...'; Name=[IO.Path]::GetFileName($Path); Kind=''; Environment=''; CreatedUtc=''; BatchId=''; SizeBytes=[long]0 }
}

function Get-PraGuiPackageCommand {
    param([string]$Root, [string]$ConfigPath, [string]$Path, [string]$ResultPath, [string]$Environment, [string]$BackupFolder, [switch]$Import)
    $tokens=@('-NoProfile','-NonInteractive','-STA','-File',(Join-Path $Root 'module\PRA.Gui.Directory.ps1'),'-ConfigPath',$ConfigPath,'-ResultPath',$ResultPath,'-PackagePath',$Path,'-Environment',$Environment)
    if ($Import) { $tokens+=@('-BackupFolder',$BackupFolder,'-Import') }
    return [pscustomobject]@{ FilePath=(Get-PraGuiEngine); Arguments=(@($tokens | ForEach-Object { ConvertTo-PraGuiNativeArgument $_ }) -join ' ') }
}

function Sync-PraGuiTimer {
    <# The window timer runs while something is running or waiting (engine, lookups, package checks) and stops when nothing is. #>
    $g=$script:Gui
    if ($g.Run -or $g.OuLookup -or $g.IdLookup -or $g.NetJob -or $g.PkgJob -or $g.PkgQueue.Count) { $g.Timer.Start() } else { $g.Timer.Stop() }
}

function Start-PraGuiNextPackageJob {
    <# One child process at a time: verification of a package, or its import (verify, then extract through a staging folder). Both bound to the Environment of the configuration. #>
    $g=$script:Gui
    if ($g.PkgJob -or -not $g.PkgQueue.Count -or -not $g.State -or -not $g.State.Config) { return }
    $work=$g.PkgQueue[0]; $g.PkgQueue.RemoveAt(0)
    $config=$g.State.Config
    $folder=Join-Path $g.Root 'logs\gui'
    Initialize-PraPrivateFolder (Join-Path $g.Root 'logs'); Initialize-PraPrivateFolder $folder
    $base=Join-Path $folder ('pkg-'+[guid]::NewGuid().ToString('N'))
    $import=(Test-GuiOrdinal $work.Mode 'Import')
    $command=Get-PraGuiPackageCommand -Root $g.Root -ConfigPath $g.ConfigPath -Path ([string]$work.Path) -ResultPath ($base+'.json') -Environment ([string]$config.Environment) -BackupFolder ([string]$config.Storage.BackupFolder) -Import:$import
    $child=Start-PraGuiChildProcess $command $g.Root ($base+'.events.jsonl')
    $g.PkgJob=@{ Mode=[string]$work.Mode; Path=[string]$work.Path; Key=[string]$work.Key; Then=$work.Then; Process=$child.Process; Output=$child.Output; Errors=$child.Errors; ResultPath=($base+'.json'); Clock=[Diagnostics.Stopwatch]::StartNew() }
    $g.Timer.Start()
}

function Start-PraGuiPackageImport {
    <# Imports a package off the window thread (busy state, no freeze). $Then receives $true when the batch of the package is now selected. #>
    param([string]$Path, [scriptblock]$Then)
    $g=$script:Gui
    if (-not $g.State -or -not $g.State.Config) { throw 'The configuration is not valid: fix it first.' }
    [void]$g.PkgQueue.Insert(0,@{ Mode='Import'; Path=$Path; Key=''; Then=$Then })
    Set-PraGuiBusy $true
    Add-PraGuiLine ('Importing {0}: checksums first, then extraction in a staging folder (the window stays responsive).' -f (Split-Path $Path -Leaf))
    $g.Controls.Footer.Text='Importing the package...'
    Start-PraGuiNextPackageJob
}

function Update-PraGuiHasFinalize {
    <# The "Complete a rollback" tile is offered when a Finalize folder exists OR a verified Finalize package waits (Inbox or imported). #>
    $g=$script:Gui
    $has=@(@($g.State.Batches) + @($g.State.OtherEnvironment) | Where-Object { $_.Valid -and (Test-GuiOrdinal $_.Operation 'RecoverFinalize') }).Count -gt 0
    if (-not $has) { foreach ($info in @($g.PkgCache.Values)) { if ($info.Valid -and (Test-GuiOrdinal $info.Kind 'Finalize')) { $has=$true } } }
    $g.HasFinalize=$has
}

function Complete-PraGuiImport {
    param($Job, $Result)
    $g=$script:Gui; $c=$g.Controls
    Set-PraGuiBusy $false
    if (-not [bool](Get-PraGuiValue $Result 'Success' $false)) { Show-PraGuiError ('Package refused: ' + [string](Get-PraGuiValue $Result 'Error' 'the import failed.')); Update-PraGuiView; return }
    $folder=[string]$g.State.Config.Storage.BackupFolder
    $g.State=Read-PraGuiState $g.Root $g.ConfigPath
    Update-PraGuiHasFinalize
    $kind=[string](Get-PraGuiValue $Result 'Kind' '')
    $operation=switch ($kind) { 'Finalize' { 'RecoverFinalize' } default { $kind } }
    $folders=@(Get-PraGuiValue $Result 'Folders' @())
    $g.SelectedBatch=$null
    Update-PraGuiBatchList
    foreach ($row in $g.BatchRows) {
        if ($row.Package -or -not $row.Selectable -or -not (Test-GuiOrdinal $row.Operation $operation)) { continue }
        foreach ($imported in $folders) {
            if (([string]$row.Path).StartsWith(([string]$imported).TrimEnd('\')+'\',[StringComparison]::OrdinalIgnoreCase)) {
                $g.Updating++
                try { $c.BatchList.SelectedItem=$row } finally { $g.Updating-- }
                $g.SelectedBatch=$row; Update-PraGuiEnvLock
                break
            }
        }
        if ($g.SelectedBatch) { break }
    }
    Add-PraGuiLine ('Package {0} imported: {1} folder(s) verified in {2}' -f (Split-Path $Job.Path -Leaf),$folders.Count,$folder) 'Ok'
    Reset-PraGuiPreview
    Update-PraGuiView
    if ($Job.Then) { & $Job.Then ($null -ne $g.SelectedBatch) }
}

function Complete-PraGuiPackageJob {
    $g=$script:Gui; $job=$g.PkgJob
    $timedOut=$job.Clock.Elapsed.TotalMinutes -gt 20
    if (-not $timedOut -and (-not $job.Process.HasExited -or -not $job.Output.IsCompleted -or -not $job.Errors.IsCompleted)) { return }
    $result=$null
    try {
        if ($timedOut) { try { if (-not $job.Process.HasExited) { $job.Process.Kill() } } catch { Write-Verbose $_.Exception.Message }; throw 'The package check did not end within 20 minutes.' }
        if (-not (Test-Path -LiteralPath $job.ResultPath)) { throw 'The package check returned no result.' }
        $result=[IO.File]::ReadAllText($job.ResultPath) | ConvertFrom-PraJson
    } catch { $result=[pscustomobject]@{ Success=$false; Error=$_.Exception.Message } }
    finally { $job.Process.Dispose(); $g.PkgJob=$null }
    if (Test-GuiOrdinal $job.Mode 'Verify') {
        $ok=[bool](Get-PraGuiValue $Result 'Success' $false)
        $g.PkgCache[$job.Key]=[pscustomobject]@{ Valid=($ok -and [bool](Get-PraGuiValue $Result 'Valid' $false)); Pending=$false
            Error=$(if ($ok) { [string](Get-PraGuiValue $Result 'Error' '') } else { [string](Get-PraGuiValue $Result 'Error' 'the check failed.') }); Name=[string](Get-PraGuiValue $Result 'Name' ([IO.Path]::GetFileName($job.Path)))
            Kind=[string](Get-PraGuiValue $Result 'Kind' ''); Environment=[string](Get-PraGuiValue $Result 'Environment' ''); CreatedUtc=[string](Get-PraGuiValue $Result 'CreatedUtc' ''); BatchId=[string](Get-PraGuiValue $Result 'BatchId' '')
            SizeBytes=[long](Get-PraGuiValue $Result 'SizeBytes' 0) }
        Update-PraGuiHasFinalize
        if ($g.Page -eq 2 -and -not $g.Run) { Update-PraGuiBatchList }
        Update-PraGuiView
    }
    else { Complete-PraGuiImport $job $result }
    Start-PraGuiNextPackageJob
    Sync-PraGuiTimer
}
function Add-PraGuiNextStep {
    param([int]$Number, [string]$Text)
    [void]$script:Gui.NextRows.Add((New-PraGuiRow @{ N=[string]$Number; Text=$Text }))
}

function Add-PraGuiTimeline {
    param([string]$Title, [string]$Caption, [string]$Status, [bool]$Last)
    [void]$script:Gui.TimelineRows.Add((New-PraGuiRow @{ Title=$Title; Caption=$Caption; Status=$Status; Last=$Last }))
}

function Update-PraGuiNext {
    $g=$script:Gui; $c=$g.Controls; $last=$g.LastRun
    $g.NextRows.Clear(); $g.TimelineRows.Clear()
    $c.PackageBox.Visibility='Collapsed'; $c.NextCmdBox.Visibility='Collapsed'
    $c.BtnReport.IsEnabled=$false; $c.BtnLog.IsEnabled=$false
    if (-not $last) {
        $c.NextPillText.Text='Nothing to do yet'; Set-PraGuiPill $c.NextPill $c.NextPillText 'Neutral'
        $c.NextTitle.Text='No run has finished yet'; $c.NextLead.Text='Start a task, verify it and run it: the instruction for the next server appears here, with the transfer package to carry.'
        $c.ResultText.Text='No result.'; $c.BatchLine.Text='No batch.'
        Add-PraGuiTimeline 'Active Directory' 'Not started' 'Pending' $false; Add-PraGuiTimeline 'Cloud' 'Not started' 'Pending' $false; Add-PraGuiTimeline 'Finalize' 'Not started' 'Pending' $true
        return
    }
    $r=$last.Result; $request=$last.Request; $action=$request.Action; $phase=$request.Phase
    $package=[string](Get-PraGuiValue $r 'transferPackage' ''); $kind=[string](Get-PraGuiValue $r 'transferPackageKind' '')
    $batchId=[string](Get-PraGuiValue $r 'batchId' '')
    $globalReport=[string](Get-PraGuiValue $g.LastResult 'globalReport' '')
    $c.BtnLog.IsEnabled=[bool](Get-PraGuiValue $g.LastResult 'logFile' ''); $c.BtnReport.IsEnabled=[bool]$globalReport -or [bool](Get-PraGuiValue $g.LastResult 'htmlReport' '')
    $c.BtnReport.Content=$(if ($globalReport) { 'Open global report' } else { 'Open report' })
    $environment=Get-PraGuiField 'Env'
    $hostText=$env:COMPUTERNAME
    $time=$last.StartedAt.ToString('HH:mm',[Globalization.CultureInfo]::InvariantCulture)
    $steps=@(Get-PraGuiValue $r 'nextSteps' @())
    $commands=@($steps | Where-Object { ([string]$_).Contains('Invoke-PraRemoteMailbox') })
    if ($commands.Count) { $c.NextCmd.Text=[string]$commands[$commands.Count-1]; $c.NextCmdBox.Visibility='Visible' }
    if (-not $last.Valid) {
        $c.NextPillText.Text='Failed'; Set-PraGuiPill $c.NextPill $c.NextPillText 'Fail'
        $c.NextTitle.Text='The run stopped'
        $c.NextLead.Text='Nothing is silently half-done: every step before the failure is complete and verified, the failed step left its object untouched or says so in the log. Reason: ' + [string]$last.Issue
        $c.HowTitle.Text='What to do'
        Add-PraGuiNextStep 1 'Go back to the Run page and click the red step: it explains in plain words what failed.'
        Add-PraGuiNextStep 2 'Fix the cause (the message above says what to look at).'
        Add-PraGuiNextStep 3 "Click 'Start a new task', pick the same batch (or package) again, preview and run. Objects already done are recognised and skipped by the engine."
        foreach ($line in $steps) { if (([string]$line).Contains('replication was NOT confirmed')) { Add-PraGuiNextStep 4 ([string]$line) } }
        $c.ResultText.Text=('Failed (native code {0}). Raw output: {1}.stdout.txt' -f $last.ExitCode,$last.Base)
        $c.BatchLine.Text=$(if ($batchId) { "$batchId · stopped" } else { 'stopped' })
        Add-PraGuiTimeline 'Active Directory' $(if ((Test-GuiOrdinalIn $phase @('AD','Both','Finalize') -IgnoreCase)) { 'Stopped' } else { 'Not part of this run' }) $(if ((Test-GuiOrdinalIn $phase @('AD','Both','Finalize') -IgnoreCase)) { 'Fail' } else { 'Skip' }) $false
        Add-PraGuiTimeline 'Cloud' $(if ((Test-GuiOrdinalIn $phase @('Cloud','Both') -IgnoreCase) -or (Test-GuiOrdinal $action 'Check' -IgnoreCase)) { 'Stopped' } else { 'Not started' }) $(if ((Test-GuiOrdinalIn $phase @('Cloud','Both') -IgnoreCase) -or (Test-GuiOrdinal $action 'Check' -IgnoreCase)) { 'Fail' } else { 'Skip' }) $false
        Add-PraGuiTimeline 'Finalize' 'Not started' 'Skip' $true
        return
    }
    $c.HowTitle.Text='How to do it'
    $counts='{0} success, {1} pending, {2} planned, {3} skipped' -f (Get-PraGuiValue $r 'success' 0),(Get-PraGuiValue $r 'pending' 0),(Get-PraGuiValue $r 'planned' 0),(Get-PraGuiValue $r 'skipped' 0)
    $c.ResultText.Text=('{0} · {1}. {2}' -f (Get-PraGuiValue $r 'status' ''),$counts,$(if ([string](Get-PraGuiValue $r 'globalReport' '')) { 'The global report follows every mailbox from the first server to this one.' } else { 'The report holds the details of every mailbox.' }))
    $c.BatchLine.Text=$(if ($batchId) { "$batchId · $environment" } else { "Read only: no batch was created." })
    if ($package) {
        $target=if (Test-GuiOrdinal $kind 'Finalize') { 'AD' } else { 'cloud' }
        $file=Get-Item -LiteralPath $package -ErrorAction SilentlyContinue
        $c.NextPillText.Text='Next step required'; Set-PraGuiPill $c.NextPill $c.NextPillText 'Warn'
        $c.NextTitle.Text=switch ($kind) { 'Convert' { 'The Active Directory part is done' } 'Recover' { 'The Active Directory rollback is done' } default { 'The cloud part of the rollback is done' } }
        $c.NextLead.Text="Copy ONE file to the $target server: $(Split-Path $package -Leaf)"
        $c.PackageBox.Visibility='Visible'
        $c.PkgName.Text=Split-Path $package -Leaf; $c.PkgPath.Text=$package
        $c.PkgInfo.Text=if ($file) { '{0:n1} MB · checksums verified' -f ($file.Length/1MB) } else { 'The file is no longer at this path.' }
        $inbox=Join-Path $g.State.Config.Storage.BackupFolder 'Inbox'
        $taskName=switch ($kind) { 'Convert' { "'Move mailboxes to Exchange Online'" } 'Recover' { "'Roll back a conversion'" } default { "'Complete a rollback'" } }
        $continue=if (Test-GuiOrdinal $kind 'Finalize') { "click 'Import package...' and pick the file" } else { "choose 'Continue an existing batch', click 'Import package...' and pick the file" }
        Add-PraGuiNextStep 1 "Copy this one file to the $target server, anywhere you like. It carries everything the next part needs, with its checksums."
        Add-PraGuiNextStep 2 "On the $target server, open this console (Invoke-PraRemoteMailbox.ps1 -Gui)."
        Add-PraGuiNextStep 3 "Choose $taskName, $continue. Or drop the file in $inbox : it is listed by itself."
        $timelineKind=$kind
    } else {
        $pendingCount=[int](Get-PraGuiValue $r 'pending' 0)
        if ($pendingCount -gt 0) { $c.NextPillText.Text='Next step required'; Set-PraGuiPill $c.NextPill $c.NextPillText 'Warn'; $c.NextTitle.Text='Part of the work remains' }
        else { $c.NextPillText.Text='Done'; Set-PraGuiPill $c.NextPill $c.NextPillText 'Ok' }
        switch ($action) {
            'Check' { $c.NextTitle.Text='The check is finished'; $c.NextLead.Text='Nothing was changed. Open the report to read what Active Directory and Exchange Online say about this mailbox.' }
            'Finalize' { if ($pendingCount -le 0) { $c.NextTitle.Text='The rollback is complete'; $c.NextLead.Text='Nothing else to do. The mailboxes are back as they were before the conversion.' } }
            default { if ($pendingCount -le 0) { $c.NextTitle.Text='The run is complete'; $c.NextLead.Text=$(if ((Test-GuiOrdinal $action 'Convert' -IgnoreCase)) { 'Nothing else to do. Keep the batch folder: it is needed if you ever roll this batch back.' } else { 'Nothing else to do for this part.' }) } }
        }
        if ($pendingCount -gt 0) { $c.NextLead.Text='Read the steps below, then run the command they give.' }
        $number=0
        foreach ($line in $steps) { $number++; Add-PraGuiNextStep $number ([string]$line) }
        if ((Test-GuiOrdinal $action 'Check' -IgnoreCase)) { Add-PraGuiNextStep 1 "Optional: run 'Check a mailbox' again later to see the cloud settle." }
        $timelineKind=''
    }
    $part=if ((Test-GuiOrdinal $action 'Check' -IgnoreCase)) { 'Read' } else { 'Done' }
    switch ($action) {
        'Convert' {
            if ((Test-GuiOrdinal $phase 'AD' -IgnoreCase)) { Add-PraGuiTimeline 'Active Directory' "Done $time on $hostText" 'Ok' $false; Add-PraGuiTimeline 'Cloud' 'Next: to run on the cloud server' 'Wait' $false }
            elseif ((Test-GuiOrdinal $phase 'Cloud' -IgnoreCase)) { Add-PraGuiTimeline 'Active Directory' 'Done earlier' 'Ok' $false; Add-PraGuiTimeline 'Cloud' "Done $time, verified" 'Ok' $false }
            else { Add-PraGuiTimeline 'Active Directory' "Done $time on $hostText" 'Ok' $false; Add-PraGuiTimeline 'Cloud' "Done $time, verified" 'Ok' $false }
            Add-PraGuiTimeline 'Finalize' 'Only needed if this batch is rolled back later' 'Skip' $true
        }
        'Recover' {
            if ((Test-GuiOrdinal $phase 'AD' -IgnoreCase)) { Add-PraGuiTimeline 'Active Directory' "Done $time on $hostText" 'Ok' $false; Add-PraGuiTimeline 'Cloud' 'Next: to run on the cloud server' 'Wait' $false; Add-PraGuiTimeline 'Finalize' 'After the cloud part, if it asks for a final AD restore' 'Wait' $true }
            elseif ((Test-GuiOrdinal $phase 'Cloud' -IgnoreCase)) { Add-PraGuiTimeline 'Active Directory' 'Done earlier' 'Ok' $false; Add-PraGuiTimeline 'Cloud' "Done $time, verified" 'Ok' $false; Add-PraGuiTimeline 'Finalize' $(if ($package) { 'Next: to run on the AD server' } else { 'Not needed' }) $(if ($package) { 'Wait' } else { 'Skip' }) $true }
            else { Add-PraGuiTimeline 'Active Directory' "Done $time on $hostText" 'Ok' $false; Add-PraGuiTimeline 'Cloud' "Done $time, verified" 'Ok' $false; Add-PraGuiTimeline 'Finalize' $(if ($package) { 'Next: to run on the AD server' } else { 'Not needed' }) $(if ($package) { 'Wait' } else { 'Skip' }) $true }
        }
        'Finalize' { Add-PraGuiTimeline 'Active Directory' 'Done earlier' 'Ok' $false; Add-PraGuiTimeline 'Cloud' 'Done earlier' 'Ok' $false; Add-PraGuiTimeline 'Finalize' "Done $time, verified" 'Ok' $true }
        default { Add-PraGuiTimeline 'Active Directory' 'Read, see the report' 'Ok' $false; Add-PraGuiTimeline 'Cloud' 'Read, see the report' 'Ok' $false; Add-PraGuiTimeline 'Finalize' 'Not part of a check' 'Skip' $true }
    }
}
#endregion


#region Window: OU lookup, clicks, construction
function Assert-PraGuiUnder {
    <# A path reported by the engine is only opened when it is inside the folder of the configuration meant for it (reports, logs). #>
    param([string]$Path, [string]$Folder)
    if (-not $Path) { return '' }
    if (-not $Folder) { throw 'The configuration is not valid: nothing is opened.' }
    $full=[IO.Path]::GetFullPath($Path); $root=[IO.Path]::GetFullPath($Folder).TrimEnd('\')+'\'
    if (-not $full.StartsWith($root,[StringComparison]::OrdinalIgnoreCase)) { throw ('Refused: {0} is not inside {1}.' -f $full,$root.TrimEnd('\')) }
    return $full
}

function Open-PraGuiPath {
    param([string]$Path, [switch]$Folder, [switch]$Select)
    if (-not $Path) { return }
    if (-not (Test-Path -LiteralPath $Path)) { throw "File/folder missing: $Path" }
    if ($Select -and (Test-Path -LiteralPath $Path -PathType Leaf)) {
        # Explorer opens the folder with the file selected (an archive is never opened or run).
        $null=[Diagnostics.Process]::Start('explorer.exe',('/select,"{0}"' -f $Path))
        return
    }
    if ($Folder -and (Test-Path -LiteralPath $Path -PathType Leaf)) { $Path=Split-Path $Path -Parent }
    $extension=[IO.Path]::GetExtension($Path)
    if (-not (Test-Path -LiteralPath $Path -PathType Container) -and -not (Test-GuiOrdinalIn $extension @('.csv','.html','.txt','.log','.json','.psd1') -IgnoreCase)) { throw 'Only reports, logs, configuration files and folders may be opened.' }
    $info=New-Object Diagnostics.ProcessStartInfo
    $info.FileName=$Path; $info.UseShellExecute=$true
    try { $null=[Diagnostics.Process]::Start($info) }
    catch {
        # A configuration file without an associated editor opens in Notepad.
        if (Test-GuiOrdinal $extension '.psd1' -IgnoreCase) { $null=[Diagnostics.Process]::Start('notepad.exe',('"{0}"' -f $Path)) } else { throw }
    }
}

function Get-PraGuiIdentityCommand {
    param([string]$Root, [string]$ConfigPath, [string]$Identity, [string]$ResultPath)
    $tokens=@('-NoProfile','-NonInteractive','-STA','-File',(Join-Path $Root 'module\PRA.Gui.Directory.ps1'),'-ConfigPath',$ConfigPath,'-ResultPath',$ResultPath,'-Identity',$Identity)
    return [pscustomobject]@{ FilePath=(Get-PraGuiEngine); Arguments=(@($tokens | ForEach-Object { ConvertTo-PraGuiNativeArgument $_ }) -join ' ') }
}

function Set-PraGuiIdentityInfo {
    param([string]$Text, [string]$Level='Info')
    $c=$script:Gui.Controls
    $c.IdentityInfo.Text=$Text
    $key=switch ($Level) { 'Ok' { 'PraSuccess' } 'Warn' { 'PraCaution' } 'Fail' { 'PraCritical' } default { 'TextFillColorSecondaryBrush' } }
    $c.IdentityInfo.SetResourceReference([Windows.Controls.TextBlock]::ForegroundProperty,$key)
}

function Show-PraGuiIdentityResult {
    <# What the read-only lookup found: the resolved object, or a plain reason. #>
    param([string]$Identity, $Result)
    if (-not [bool](Get-PraGuiValue $Result 'Success' $false)) { Set-PraGuiIdentityInfo ('Could not check: ' + [string](Get-PraGuiValue $Result 'Error' 'the lookup failed.')) 'Warn'; return }
    $count=[int](Get-PraGuiValue $Result 'Count' 0)
    if ($count -gt 1) { Set-PraGuiIdentityInfo ("$count accounts match '$Identity': type the UPN or the distinguished name to pick one.") 'Warn'; return }
    if ($count -lt 1 -or -not [bool](Get-PraGuiValue $Result 'Found' $false)) { Set-PraGuiIdentityInfo ("Not found in Active Directory: '$Identity'. Check the spelling, or type the UPN.") 'Fail'; return }
    Set-PraGuiIdentityInfo ('{0} · {1} · {2}' -f [string](Get-PraGuiValue $Result 'DisplayName' ''),[string](Get-PraGuiValue $Result 'UserPrincipalName' ''),[string](Get-PraGuiValue $Result 'MailboxType' 'Mailbox type unknown')) 'Ok'
}

function Start-PraGuiIdentityLookup {
    <# Looks the identity up (read only). Tests and screenshots pass -IdentityProbe; otherwise a child process does it, so that the window never waits for Active Directory. #>
    $g=$script:Gui; $c=$g.Controls
    $identity=Get-PraGuiField 'Identity'
    if (-not $identity) { Set-PraGuiIdentityInfo ''; return }
    if ($g.Run -or $g.OuLookup -or $g.IdLookup) { return }
    if ($g.IdentityProbe) {
        try { Show-PraGuiIdentityResult $identity (& $g.IdentityProbe $identity) } catch { Show-PraGuiIdentityResult $identity ([pscustomobject]@{ Success=$false; Error=$_.Exception.Message }) }
        return
    }
    $folder=Join-Path $g.Root 'logs\gui'
    Initialize-PraPrivateFolder (Join-Path $g.Root 'logs'); Initialize-PraPrivateFolder $folder
    $base=Join-Path $folder ('id-'+[guid]::NewGuid().ToString('N'))
    $command=Get-PraGuiIdentityCommand $g.Root $g.ConfigPath $identity ($base+'.json')
    $child=Start-PraGuiChildProcess $command $g.Root ($base+'.events.jsonl')
    $g.IdLookup=@{ Process=$child.Process; Output=$child.Output; Errors=$child.Errors; Path=($base+'.json'); Identity=$identity; Clock=[Diagnostics.Stopwatch]::StartNew() }
    Set-PraGuiIdentityInfo 'Looking it up in Active Directory (read only)...'
    $g.Timer.Start()
}

function Complete-PraGuiIdentityLookup {
    $g=$script:Gui; $lookup=$g.IdLookup
    $timedOut=$lookup.Clock.Elapsed.TotalSeconds -gt 25
    if (-not $timedOut -and (-not $lookup.Process.HasExited -or -not $lookup.Output.IsCompleted -or -not $lookup.Errors.IsCompleted)) { return }
    $result=$null
    try {
        if ($timedOut) { try { if (-not $lookup.Process.HasExited) { $lookup.Process.Kill() } } catch { Write-Verbose $_.Exception.Message }; throw 'Active Directory did not answer within 25 seconds.' }
        if (-not (Test-Path -LiteralPath $lookup.Path)) { throw 'The lookup returned no result.' }
        $result=[IO.File]::ReadAllText($lookup.Path) | ConvertFrom-PraJson
    } catch { $result=[pscustomobject]@{ Success=$false; Error=$_.Exception.Message } }
    finally { $lookup.Process.Dispose(); $g.IdLookup=$null; Sync-PraGuiTimer }
    # An answer for text that was changed meanwhile is dropped.
    if (Test-GuiOrdinal (Get-PraGuiField 'Identity') $lookup.Identity) { Show-PraGuiIdentityResult $lookup.Identity $result } else { Set-PraGuiIdentityInfo '' }
}

function Get-PraGuiOuCommand {
    param([string]$Root, [string]$ConfigPath, [string]$ResultPath)
    $tokens=@('-NoProfile','-NonInteractive','-STA','-File',(Join-Path $Root 'module\PRA.Gui.Directory.ps1'),'-ConfigPath',$ConfigPath,'-ResultPath',$ResultPath)
    return [pscustomobject]@{ FilePath=(Get-PraGuiEngine); Arguments=(@($tokens | ForEach-Object { ConvertTo-PraGuiNativeArgument $_ }) -join ' ') }
}

function Start-PraGuiOuLookup {
    $g=$script:Gui; $c=$g.Controls
    if ($g.Run -or $g.OuLookup) { throw 'Wait for the operation in progress to end.' }
    if ((-not (Test-GuiOrdinal $g.Action 'Convert' -IgnoreCase)) -or (-not (Test-GuiOrdinal $g.Mode 'New' -IgnoreCase)) -or (-not (Test-GuiOrdinal (Get-PraGuiField 'Source') 'Ou' -IgnoreCase))) { throw 'The OU picker is only for a new conversion with the OU source.' }
    $folder=Join-Path $g.Root 'logs\gui'
    Initialize-PraPrivateFolder (Join-Path $g.Root 'logs'); Initialize-PraPrivateFolder $folder
    $base=Join-Path $folder ('ou-'+[guid]::NewGuid().ToString('N'))
    $command=Get-PraGuiOuCommand $g.Root $g.ConfigPath ($base+'.json')
    $child=Start-PraGuiChildProcess $command $g.Root ($base+'.events.jsonl')
    Reset-PraGuiPreview
    $g.OuLookup=@{ Process=$child.Process; Output=$child.Output; Errors=$child.Errors; Path=($base+'.json'); Base=$base }
    Set-PraGuiBusy $true
    Add-PraGuiLine 'Reading the OUs on the configured domain controller: no write to Active Directory.'
    $c.TaskError.Text=''
    $g.Timer.Start()
    Update-PraGuiView
}

function Select-PraGuiOu {
    param([object[]]$Units, [string]$Server)
    $g=$script:Gui
    $xaml=@'
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation" xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
 Title="Pick an OU" Width="780" Height="510" WindowStartupLocation="CenterOwner" FontFamily="Segoe UI"
 Background="{DynamicResource ApplicationBackgroundBrush}">
 <Grid Margin="18"><Grid.RowDefinitions><RowDefinition Height="Auto"/><RowDefinition Height="Auto"/><RowDefinition Height="*"/><RowDefinition Height="Auto"/></Grid.RowDefinitions>
 <TextBlock x:Name="Info" TextWrapping="Wrap" Margin="0,0,0,8" Foreground="{DynamicResource TextFillColorPrimaryBrush}"/>
 <TextBox x:Name="Filter" Grid.Row="1" Margin="0,0,0,8" ToolTip="Filter the name or the DN"/>
 <ListBox x:Name="Units" Grid.Row="2" DisplayMemberPath="DistinguishedName"/>
 <StackPanel Grid.Row="3" Orientation="Horizontal" HorizontalAlignment="Right" Margin="0,12,0,0">
 <Button x:Name="Select" Content="Pick" IsDefault="True" Padding="14,6" Margin="0,0,8,0"/>
 <Button Content="Cancel" IsCancel="True" Padding="14,6"/></StackPanel></Grid>
</Window>
'@
    $dialog=[Windows.Markup.XamlReader]::Parse($xaml)
    $dialog.Resources.MergedDictionaries.Add($g.Form.Resources)
    if ($g.Form.IsVisible) { $dialog.Owner=$g.Form }
    $dialog.FindName('Info').Text="DC: $Server · pick the OU; its sub-OUs are included."
    $dialog.Tag=$Units
    $dialog.FindName('Units').ItemsSource=$Units
    $dialog.FindName('Filter').Add_TextChanged({
        param($box)
        $owner=[Windows.Window]::GetWindow($box)
        $text=[string]$box.Text
        $owner.FindName('Units').ItemsSource=@($owner.Tag | Where-Object { $_.DistinguishedName.IndexOf($text,[StringComparison]::OrdinalIgnoreCase) -ge 0 })
    })
    $dialog.FindName('Select').Add_Click({
        param($button)
        $owner=[Windows.Window]::GetWindow($button)
        if ($owner.FindName('Units').SelectedItem) { $owner.DialogResult=$true }
    })
    $dialog.FindName('Units').Add_MouseDoubleClick({
        param($list)
        if ($list.SelectedItem) { [Windows.Window]::GetWindow($list).DialogResult=$true }
    })
    Set-PraGuiWindowBounds -Window $dialog
    if ($dialog.ShowDialog()) { return [string]$dialog.FindName('Units').SelectedItem.DistinguishedName }
    return ''
}

function Complete-PraGuiOuLookup {
    $g=$script:Gui; $lookup=$g.OuLookup
    if (-not $lookup.Process.HasExited -or -not $lookup.Output.IsCompleted -or -not $lookup.Errors.IsCompleted) { return }
    $g.Timer.Stop()
    $units=@(); $server=''
    try {
        $output=$lookup.Output.Result; $errors=$lookup.Errors.Result
        if (-not (Test-Path -LiteralPath $lookup.Path)) { throw "The OU lookup returned no result. $errors" }
        $result=[IO.File]::ReadAllText($lookup.Path) | ConvertFrom-PraJson
        if ($lookup.Process.ExitCode -ne 0 -or $result.Success -ne $true -or $errors.Trim()) {
            throw ('OU lookup refused: '+[string](Get-PraGuiValue $result 'Error' $errors))
        }
        $units=@($result.Units); $server=[string]$result.Server
        Add-PraGuiLine ('{0} OU(s) read on {1}; nothing was written.' -f $units.Count,$server) 'Ok'
    } catch { Show-PraGuiError $_.Exception.Message }
    finally {
        $lookup.Process.Dispose(); $g.OuLookup=$null
        Set-PraGuiBusy $false
        Update-PraGuiView
        Sync-PraGuiTimer
    }
    if ($units.Count) {
        $chosen=Select-PraGuiOu -Units $units -Server $server
        if ($chosen) { Set-PraGuiField 'Ou' $chosen; Invoke-PraGuiChange }
    }
    elseif ($server) { Add-PraGuiLine 'No OU found. You can type a valid distinguished name directly.' 'Warn' }
}

function Update-PraGuiState {
    <# Reads the configuration and the backup folder again; the run settings go back to the values of the file. #>
    param([switch]$Refresh)
    $g=$script:Gui; $c=$g.Controls
    $g.ConfigPath=[string]$g.ConfigPath
    $c.ConfigPathText.Text=$g.ConfigPath
    $g.State=Read-PraGuiState $g.Root $g.ConfigPath
    Set-PraGuiDefault
    foreach ($key in $script:GuiSettingKeys) { Set-PraGuiField $key $g.Defaults[$key] }
    Set-PraGuiField 'ExpConfig' $(if (Test-PraGuiSamePath $g.ConfigPath $g.InitialConfigPath) { '' } else { $g.ConfigPath })
    $known=New-Object 'Collections.Generic.List[string]'
    if ($g.State.Config) { $known.Add([string]$g.State.Config.Environment) }
    foreach ($item in @($g.State.Batches) + @($g.State.OtherEnvironment)) { if ($item.Valid -and $item.Environment) { $known.Add([string]$item.Environment) } }
    $g.KnownEnvironments=@(Get-GuiOrdinalUnique $known -IgnoreCase)
    Update-PraGuiHasFinalize
    # A package waiting in the Inbox is checked in the background: a Finalize package makes the "Complete a rollback" tile appear when its check ends.
    if ($g.State.Config) {
        $inbox=Join-Path ([string]$g.State.Config.Storage.BackupFolder) 'Inbox'
        if (Test-Path -LiteralPath $inbox -PathType Container) { foreach ($zip in @(Get-ChildItem -LiteralPath $inbox -File -Filter '*.zip' -ErrorAction SilentlyContinue)) { $null=Get-PraGuiPackageInfo $zip.FullName } }
    }
    $g.SelectedBatch=$null; $g.EnvLock=$null; $g.EnvSaved=$null
    Reset-PraGuiPreview
    Update-PraGuiEnvSuggest
    Invoke-PraGuiDetection -Refresh:$Refresh
    Update-PraGuiBatchList
    Update-PraGuiView
}

function Select-PraGuiTask {
    param([string]$Action)
    $g=$script:Gui
    if ($g.Run) { return }
    $g.Action=$Action; $g.Mode='New'; $g.SelectedBatch=$null
    Update-PraGuiEnvLock
    Reset-PraGuiPreview
    $g.Controls.TaskError.Text=''
    Update-PraGuiBatchList
    Update-PraGuiView
}

function Invoke-PraGuiClick {
    param([string]$Name)
    $g=$script:Gui; $c=$g.Controls
    try {
        $c.TaskError.Text=''; $c.ValidationText.Text=''
        switch ($Name) {
            'BtnRecheck' { Invoke-PraGuiDetection -Refresh; $c.RecheckNote.Text='Checked at '+[datetime]::Now.ToString('HH:mm:ss',[Globalization.CultureInfo]::InvariantCulture); Update-PraGuiView }
            'BtnChange' { $c.SettingsCard.Visibility=Get-PraGuiVisibility ((-not (Test-GuiOrdinal $c.SettingsCard.Visibility 'Visible' -IgnoreCase))) }
            'BtnDoneSettings' { $c.SettingsCard.Visibility='Collapsed' }
            'BtnResetAll' {
                foreach ($key in $script:GuiSettingKeys) { if ((-not (Test-GuiOrdinal $key 'ExpConfig' -IgnoreCase)) -and -not ((Test-GuiOrdinal $key 'Env' -IgnoreCase) -and $g.EnvLock)) { Reset-PraGuiField $key } }
                Invoke-PraGuiChange
            }
            'BtnOpenConfig' { Open-PraGuiPath $g.ConfigPath }
            'BtnReload' { if (-not $g.Run) { Update-PraGuiState } }
            'BtnCopyCmd' { [Windows.Clipboard]::SetText($c.CmdLine.Text) }
            'BtnPickOu' { Start-PraGuiOuLookup }
            'BtnCheckIdentity' { Start-PraGuiIdentityLookup }
            'BtnPickCsv' {
                $dialog=New-Object Microsoft.Win32.OpenFileDialog; $dialog.Filter='List (*.csv)|*.csv'
                if ($dialog.ShowDialog($g.Form)) { Set-PraGuiField 'Csv' $dialog.FileName; Invoke-PraGuiChange }
            }
            'BtnPickConfig' {
                $dialog=New-Object Microsoft.Win32.OpenFileDialog; $dialog.Filter='Configuration (*.psd1)|*.psd1'
                if ($dialog.ShowDialog($g.Form)) { $g.ConfigPath=$dialog.FileName; Update-PraGuiState }
            }
            'BtnImport' {
                $dialog=New-Object Microsoft.Win32.OpenFileDialog; $dialog.Filter='Transfer package (*.zip)|*.zip'
                if ($dialog.ShowDialog($g.Form)) {
                    Start-PraGuiPackageImport $dialog.FileName { param($selected) $script:Gui.Controls.BatchEmpty.Text=if ($selected) { 'Package imported and verified: its batch is selected.' } else { 'Package imported and verified, but it does not match the chosen task.' }; Update-PraGuiView }
                }
            }
            'BtnFixHome' { Show-PraGuiPage 1; $c.SettingsCard.Visibility='Visible' }
            'BtnEditSettings' { Show-PraGuiPage 1; $c.SettingsCard.Visibility='Visible' }
            'BtnBack' { if (-not $g.Run -and $g.Page -gt 1 -and -not ((Test-PraGuiApplied) -and $g.Page -le 4)) { Show-PraGuiPage ($g.Page-1) } }
            'BtnPreview' { Start-PraGuiRun -Mode Preview }
            'BtnNext' {
                switch ($g.Page) {
                    1 { if (-not $g.NetJob) { Show-PraGuiPage 2 } }
                    2 {
                        if ($g.SelectedBatch -and $g.SelectedBatch.Package) {
                            Start-PraGuiPackageImport ([string]$g.SelectedBatch.Path) { param($selected) if ($selected) { Show-PraGuiPage 3 } else { Show-PraGuiError 'The package was imported but its batch is not listed: reload the page.' } }
                        }
                        else { Show-PraGuiPage 3 }
                    }
                    3 {
                        if ((Test-GuiOrdinal $g.Action 'Check' -IgnoreCase)) { Start-PraGuiRun -Mode Preview -Purpose Run } else { Start-PraGuiRun -Mode Apply }
                        Show-PraGuiPage 4
                    }
                    4 { if ($g.LastRun) { Show-PraGuiPage 5 } }
                    5 {
                        $g.Action=''; $g.Mode='New'; $g.SelectedBatch=$null; $g.Model=$null; $g.LastRun=$null
                        Update-PraGuiEnvLock; Reset-PraGuiPreview
                        Show-PraGuiPage 2
                    }
                }
            }
            'BtnCardOpen' { Open-PraGuiPath ([string]$c.CardBackup.Tag) -Folder }
            'BtnCardCopy' { [Windows.Clipboard]::SetText([string]$c.CardBackup.Tag) }
            'BtnOpenFolder' { Open-PraGuiPath $c.PkgPath.Text -Select }
            'BtnCopyPath' { [Windows.Clipboard]::SetText($c.PkgPath.Text) }
            'BtnCopyNextCmd' { [Windows.Clipboard]::SetText($c.NextCmd.Text) }
            'BtnReport' { $target=[string](Get-PraGuiValue $g.LastResult 'globalReport' ''); if (-not $target) { $target=[string](Get-PraGuiValue $g.LastResult 'htmlReport' '') }; Open-PraGuiPath (Assert-PraGuiUnder $target $(if ($g.State.Config) { [string]$g.State.Config.Report.Folder } else { '' })) }
            'BtnLog' { Open-PraGuiPath (Assert-PraGuiUnder ([string](Get-PraGuiValue $g.LastResult 'logFile' '')) $(if ($g.State.Config) { [string]$g.State.Config.Logging.Folder } else { '' })) }
            default {
                if ($Name.StartsWith('R_',[StringComparison]::Ordinal)) {
                    $key=$Name.Substring(2)
                    if ((Test-GuiOrdinal $key 'ExpConfig' -IgnoreCase)) { $g.ConfigPath=$g.InitialConfigPath; Update-PraGuiState } else { Reset-PraGuiField $key; Invoke-PraGuiChange }
                }
            }
        }
    } catch { Show-PraGuiError $_.Exception.Message }
}

function Invoke-PraGuiChoice {
    <# A segmented choice, a mode or a filter changed. #>
    param([string]$Name)
    $g=$script:Gui
    if (-not $g -or $g.Updating -gt 0) { return }
    if ($Name.StartsWith('Mode_',[StringComparison]::Ordinal)) {
        if ($g.Run) { return }
        $g.Mode=$Name.Substring(5); $g.SelectedBatch=$null
        Update-PraGuiEnvLock; Reset-PraGuiPreview; Update-PraGuiBatchList; Update-PraGuiView
        return
    }
    if ($Name.StartsWith('Fl_',[StringComparison]::Ordinal)) { $g.Filter=$Name.Substring(3); $g.VerView.Refresh(); return }
    if ($Name.StartsWith('Th_',[StringComparison]::Ordinal)) {
        $info=Initialize-PraGuiTheme $Name.Substring(3)
        $g.Theme=$info; Set-PraGuiTheme $g.Form $info
        return
    }
    Invoke-PraGuiChange
}

function Set-PraGuiWindowBounds {
    param($Window, $WorkArea=$null)
    if ($null -eq $WorkArea) { $WorkArea=[Windows.SystemParameters]::WorkArea }
    $Window.MinWidth=[Math]::Min($Window.MinWidth,$WorkArea.Width)
    $Window.MinHeight=[Math]::Min($Window.MinHeight,$WorkArea.Height)
    $Window.Width=[Math]::Min($Window.Width,$WorkArea.Width)
    $Window.Height=[Math]::Min($Window.Height,$WorkArea.Height)
    $Window.WindowStartupLocation=[Windows.WindowStartupLocation]::Manual
    $Window.Left=$WorkArea.Left+[Math]::Max(0,($WorkArea.Width-$Window.Width)/2)
    $Window.Top=$WorkArea.Top+[Math]::Max(0,($WorkArea.Height-$Window.Height)/2)
}

function New-PraGuiXmlNamespace {
    param([xml]$Xml)
    $manager=New-Object Xml.XmlNamespaceManager $Xml.NameTable
    $manager.AddNamespace('x','http://schemas.microsoft.com/winfx/2006/xaml')
    return ,$manager
}

function New-PraGuiWindow {
    <# Constructs and binds the window without ShowDialog and without starting an operation. -PrerequisiteProbe replaces the real detection (tests, screenshots); with it, Microsoft 365 is not tested unless -NetworkProbe (a task per host) is given too. #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Root, [string]$ConfigPath='', [string]$Version='', [ValidateSet('System','Light','Dark')][string]$Theme='System', [scriptblock]$PrerequisiteProbe, [scriptblock]$IdentityProbe, [scriptblock]$NetworkProbe, [double]$NetworkSeconds=3)
    if ((-not (Test-GuiOrdinal ([Threading.Thread]::CurrentThread.GetApartmentState()) 'STA' -IgnoreCase))) { throw 'WPF requires an STA host (pwsh.exe -STA).' }
    if ($script:Gui -and $script:Gui.Run) { throw 'Cannot replace a window while its engine is running.' }
    if ($script:Gui -and $script:Gui.Form.IsVisible) { throw 'A PRA window is already open in this host.' }
    if (-not $ConfigPath) { $ConfigPath=Join-Path $Root 'config\PraRemoteMailbox.config.psd1' }
    $themeInfo=Initialize-PraGuiTheme $Theme
    $xml=[xml][IO.File]::ReadAllText((Join-Path $script:GuiModuleRoot 'PRA.Gui.xaml'))
    $reader=New-Object Xml.XmlNodeReader $xml
    try { $form=[Windows.Markup.XamlReader]::Load($reader) } finally { $reader.Dispose() }
    Set-PraGuiWindowBounds -Window $form
    Set-PraGuiTheme $form $themeInfo
    $controls=@{}
    foreach ($node in $xml.SelectNodes('//*[@x:Name]',(New-PraGuiXmlNamespace $xml))) {
        $name=$node.GetAttribute('Name','http://schemas.microsoft.com/winfx/2006/xaml')
        $controls[$name]=$form.FindName($name)
    }
    $timer=New-Object Windows.Threading.DispatcherTimer
    $timer.Interval=[timespan]::FromMilliseconds(250)
    $probe=if ($PrerequisiteProbe) { $PrerequisiteProbe } else { { param($Request) Get-PraGuiPrerequisite @Request } }
    $netProbe=if ($NetworkProbe) { $NetworkProbe } elseif ($PrerequisiteProbe) { $null } else { { param($HostName,$Seconds) Start-PraGuiHttpsProbe $HostName $Seconds } }
    $script:Gui=@{
        Form=$form; Controls=$controls; Timer=$timer; Root=[IO.Path]::GetFullPath($Root); ConfigPath=$ConfigPath; InitialConfigPath=$ConfigPath
        PkgCache=@{}; PkgQueue=(New-Object 'Collections.Generic.List[object]'); PkgJob=$null
        State=$null; Run=$null; OuLookup=$null; IdLookup=$null; IdentityProbe=$IdentityProbe; Pending=$null; LastResult=$null; LastRun=$null; Model=$null; Updating=1; InTick=$false; Page=1
        Action=''; Mode='New'; SelectedBatch=$null; EnvLock=$null; EnvSaved=$null; Defaults=$null; Detect=$null; Probe=$probe; NetProbe=$netProbe; NetSeconds=$NetworkSeconds; NetJob=$null; NetResult=$null
        Previewed=$false; PreviewError=''; Filter='All'; HasFinalize=$false; KnownEnvironments=@()
        Lines=(New-Object 'Collections.ObjectModel.ObservableCollection[object]')
        LightRows=(New-Object 'Collections.ObjectModel.ObservableCollection[object]'); BatchRows=(New-Object 'Collections.ObjectModel.ObservableCollection[object]')
        VerRows=(New-Object 'Collections.ObjectModel.ObservableCollection[object]'); NextRows=(New-Object 'Collections.ObjectModel.ObservableCollection[object]')
        TimelineRows=(New-Object 'Collections.ObjectModel.ObservableCollection[object]')
        Theme=$themeInfo; HandlerNames=@()
    }
    $g=$script:Gui; $c=$controls
    $c.VersionText.Text='v'+$Version+' · Nicolas Fabert'
    $c.HeaderSub.ToolTip='Host: '+$env:COMPUTERNAME+' · UI: PowerShell '+$PSVersionTable.PSVersion+' · engine: '+(Get-PraGuiEngine)
    $c.ActivityLog.ItemsSource=$g.Lines; $c.Lights.ItemsSource=$g.LightRows; $c.BatchList.ItemsSource=$g.BatchRows; $c.NextSteps.ItemsSource=$g.NextRows; $c.Timeline.ItemsSource=$g.TimelineRows
    $c.VerList.ItemsSource=$g.VerRows
    $g.VerView=[Windows.Data.CollectionViewSource]::GetDefaultView($g.VerRows)
    $g.VerView.Filter=[Predicate[object]]{
        param($row)
        switch ($script:Gui.Filter) { 'User' { (Test-GuiOrdinal $row.Type 'User' -IgnoreCase) } 'Shared' { (Test-GuiOrdinal $row.Type 'Shared' -IgnoreCase) } 'Warn' { (Test-GuiOrdinal $row.Status 'Warn' -IgnoreCase) } default { $true } }
    }
    $c.F_ExpConfig.IsReadOnly=$true
    $c.F_ExpMax.Text='0'
    foreach ($name in @($controls.Keys)) {
        $control=$controls[$name]
        if ($control -is [Windows.Controls.Button]) {
            $control.Tag=$name
            $control.Add_Click({ param($sender) Invoke-PraGuiClick ([string]$sender.Tag) })
            $g.HandlerNames+=($name+'.Click')
        }
        elseif ($control -is [Windows.Controls.RadioButton]) {
            if ($name.StartsWith('T_',[StringComparison]::Ordinal)) { $control.Tag=$name.Substring(2); $control.Add_Checked({ param($sender) if ($script:Gui.Updating -eq 0) { Select-PraGuiTask ([string]$sender.Tag) } }) }
            elseif ($name.StartsWith('Nav',[StringComparison]::Ordinal) -and $name.Length -eq 4) {
                $control.Add_Checked({ param($sender)
                    $gui=$script:Gui
                    if ($gui.Updating -gt 0) { return }
                    $number=[int]([string]$sender.Name).Substring(3)
                    if ((-not (Test-GuiOrdinal $number $gui.Page -IgnoreCase)) -and (Test-PraGuiPageReachable $number)) { Show-PraGuiPage $number }
                    else { $gui.Updating++; try { $gui.Controls[('Nav'+$gui.Page)].IsChecked=$true } finally { $gui.Updating-- } }
                })
            }
            else { $control.Tag=$name; $control.Add_Checked({ param($sender) Invoke-PraGuiChoice ([string]$sender.Tag) }) }
            $g.HandlerNames+=($name+'.Checked')
        }
        elseif ($control -is [Windows.Controls.TextBox] -and -not $control.IsReadOnly -and $name.StartsWith('F_',[StringComparison]::Ordinal)) {
            $control.Add_TextChanged({ Invoke-PraGuiChange }); $g.HandlerNames+=($name+'.TextChanged')
        }
    }
    $c.F_ExpOnce.Add_Checked({ Invoke-PraGuiChange }); $c.F_ExpOnce.Add_Unchecked({ Invoke-PraGuiChange })
    $c.F_Repl.Add_Checked({ Invoke-PraGuiChange }); $c.F_Repl.Add_Unchecked({ Invoke-PraGuiChange })
    # The identity is looked up when the field loses the focus or Enter is pressed; typing again clears the answer.
    $c.F_Identity.Add_TextChanged({ if ($script:Gui.Updating -eq 0) { Set-PraGuiIdentityInfo '' } })
    $c.F_Identity.Add_LostFocus({ if ($script:Gui.Updating -eq 0 -and $script:Gui.Page -eq 2) { try { Start-PraGuiIdentityLookup } catch { Set-PraGuiIdentityInfo $_.Exception.Message 'Warn' } } })
    $c.F_Identity.Add_KeyDown({ param($sender,$keyArguments) if ([int]$keyArguments.Key -eq [int][Windows.Input.Key]::Return) { try { Start-PraGuiIdentityLookup } catch { Set-PraGuiIdentityInfo $_.Exception.Message 'Warn' } } })
    $c.ConfirmBox.Add_TextChanged({ Update-PraGuiView })
    $c.BatchList.Add_SelectionChanged({
        $gui=$script:Gui
        if ($gui.Updating -gt 0 -or $gui.Run) { return }
        $gui.SelectedBatch=$gui.Controls.BatchList.SelectedItem
        Update-PraGuiEnvLock; Reset-PraGuiPreview; Update-PraGuiView
    })
    $c.StepList.Add_SelectionChanged({
        $gui=$script:Gui
        if ($gui.Updating -gt 0 -or -not $gui.Model) { return }
        $gui.Model.Selected=$gui.Controls.StepList.SelectedItem; $gui.Model.Follow=$false
        Show-PraGuiStepDetail $gui.Model.Selected
    })
    $c.DetObjList.Add_SelectionChanged({ $gui=$script:Gui; if ($gui.Model) { Show-PraGuiObjectCard $gui.Controls.DetObjList.SelectedItem } })
    $timer.Add_Tick({ Invoke-PraGuiTick })
    $form.Add_Closing({
        param($windowControl,$closingArguments)
        if ($script:Gui.Run -or $script:Gui.OuLookup -or $script:Gui.IdLookup -or ($script:Gui.PkgJob -and (Test-GuiOrdinal $script:Gui.PkgJob.Mode 'Import'))) {
            $closingArguments.Cancel=$true
            Add-PraGuiLine ($windowControl.Title+': closing refused, an atomic action is running. Wait for it to end; do not kill the engine.') 'Warn'
        }
    })
    $form.Add_Closed({ $script:Gui.Timer.Stop(); $script:Gui.Pending=$null; $script:Gui.NetJob=$null; if ($script:GuiNetHttp) { $script:GuiNetHttp.Dispose(); $script:GuiNetHttp=$null } })
    $g.HandlerNames+=@('BatchList.SelectionChanged','StepList.SelectionChanged','DetObjList.SelectionChanged','ConfirmBox.TextChanged','F_ExpOnce.Checked','F_ExpOnce.Unchecked','Timer.Tick','Form.Closing','Form.Closed')
    foreach ($name in @('System','Light','Dark')) { $c['Th_'+$name].IsChecked=((Test-GuiOrdinal $name $Theme -IgnoreCase)) }
    $c.Nav1.IsChecked=$true
    Set-PraGuiField 'Source' 'Single'
    $g.Updating=0
    Update-PraGuiState -Refresh
    return $g
}

function Show-PraGui {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Root, [string]$ConfigPath='', [string]$Version='')
    $window=New-PraGuiWindow -Root $Root -ConfigPath $ConfigPath -Version $Version
    $null=$window.Form.ShowDialog()
}

Export-ModuleMember -Function Show-PraGui,New-PraGuiWindow,New-PraGuiRequest,Get-PraGuiBatchType,Get-PraGuiCommand,ConvertTo-PraGuiNativeArgument,Get-PraGuiEngine,Read-PraGuiState,Read-PraGuiBatch,Resolve-PraGuiBatch,Get-PraGuiGuard,Test-PraGuiResult,Test-PraGuiPreview,Read-PraGuiEvents,Start-PraGuiChildProcess,Get-PraGuiOuCommand,Get-PraGuiPrerequisite
#endregion

# SIG # Begin signature block
# MIImKQYJKoZIhvcNAQcCoIImGjCCJhYCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCD4sZgHNji4P2rM
# 13eT/xqK/BGOOWLgxvgLHVcmHKSpBKCCDW8wggZyMIIEWqADAgECAghkM1HTxzif
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
# wZislcdCZuS6MYIYEDCCGAwCAQEwgYwweDELMAkGA1UEBhMCVVMxDjAMBgNVBAgM
# BVRleGFzMRAwDgYDVQQHDAdIb3VzdG9uMREwDwYDVQQKDAhTU0wgQ29ycDE0MDIG
# A1UEAwwrU1NMLmNvbSBDb2RlIFNpZ25pbmcgSW50ZXJtZWRpYXRlIENBIFJTQSBS
# MQIQBof4ljXihJpmCqqt2mhAWzANBglghkgBZQMEAgEFAKCBhDAYBgorBgEEAYI3
# AgEMMQowCKACgAChAoAAMBkGCSqGSIb3DQEJAzEMBgorBgEEAYI3AgEEMBwGCisG
# AQQBgjcCAQsxDjAMBgorBgEEAYI3AgEVMC8GCSqGSIb3DQEJBDEiBCBHqzAKcn/0
# kv8OPfR4t3TUZ47nIFC4EVeow6FqLBW1WTANBgkqhkiG9w0BAQEFAASCAgBWUFys
# DpdSodydKY8Y7yptdRDwUn34X/SJWFRwTk6DQ8u746sbGFrWilQ1+n/1F7VpidQG
# ysYSTsTeBPOLn9dvoh0khgqvqbRmp0dRm/3wECjisgCo+rVA24zVItHW+rNDBrQQ
# JyW1zsN9vdfCt1SynT74h4hFOnm+4c78KqdmaFqix7VuwTUXtkvsog48lvOr4gZV
# BV9smTVhCfRscm3rtgLyVGehim+LWpG+PoFNKK8b/f2p/SF3vWDy5Z+lvIlwTF2j
# jLh1chxAb9KkrD+4bT9eXiF2KManP/CVMeLAfp/vxoK1Gzf+nRTOl840ZyIObRlI
# NB/wUuuvj+ccgfRWftNZGlpbUA08uQgW/emmYLPkcBCDJ4vK6VLxjsiBl9jsKgvl
# fGs+7yNItUvvX7v/JQeQB21RbktGmV2fX4CA2rG+n7+amrBFVIASxi/mAgiMLR/C
# 1RH4uVX7wtMq51S4lYU06CD/03CLwsWIwR+3Ag0Di70w8ibcoGbBYtqHgRzdJ0Xb
# CXiB4YX9PIPn3XGA4SB5BViki/UY041yNh0KgaIPhywFpSFQ849/7OL5yJMjeOcF
# IHPXLvsDT+edDGCm477Tl/h3hi6sFWVQS/FzRYjd1z13Xb3XVK3+fKcrkZq1i6r8
# B1ibID/r37hWaQKUEZ7Id9yeqvO3lDSfDAF9j6GCFM0wghTJBgorBgEEAYI3AwMB
# MYIUuTCCFLUGCSqGSIb3DQEHAqCCFKYwghSiAgEDMQ0wCwYJYIZIAWUDBAIBMIGJ
# BgsqhkiG9w0BCRABBKB6BHgwdgIBAQYMKwYBBAGCqTABAwYBMDEwDQYJYIZIAWUD
# BAIBBQAEICuKKMJhWIHFeGxnrxhmJKpgP6EG8Q6n+W5/Yv0cAnf2AggEGI2pcNZp
# NxgPMjAyNjExMDkxNTMzMzVaMAMCAQECEFGFYn6yFSfO+QDp234ub8mgghGnMIIE
# 8zCCAtugAwIBAgIQVEP4N71a7hgBhHK4XNqO4zANBgkqhkiG9w0BAQsFADByMQsw
# CQYDVQQGEwJVUzEOMAwGA1UECAwFVGV4YXMxEDAOBgNVBAcMB0hvdXN0b24xETAP
# BgNVBAoMCFNTTCBDb3JwMS4wLAYDVQQDDCVTU0wuY29tIFRpbWVzdGFtcGluZyBJ
# c3N1aW5nIFJTQSBDQSAyMB4XDTI2MDYxMjE3MjI0NloXDTM2MDYwOTE3MjI0NVow
# bjELMAkGA1UEBhMCVVMxDjAMBgNVBAgMBVRleGFzMRAwDgYDVQQHDAdIb3VzdG9u
# MREwDwYDVQQKDAhTU0wgQ29ycDEqMCgGA1UEAwwhU1NMLmNvbSBUaW1lc3RhbXBp
# bmcgVW5pdCAyMDI2IEUxMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE6CWLuGYT
# LkiSOPMLNskOBthXsIhRSA46feOQwvSLcDaNh6vxUzBKEx1KdFBRFs7OHrnH/K0V
# A6MbDQIFpUg0PaOCAVIwggFOMB8GA1UdIwQYMBaAFHCaZcFDgKP86bFkiW7xMJwJ
# Icl8ME0GCCsGAQUFBwEBBEEwPzA9BggrBgEFBQcwAoYxaHR0cDovL2NlcnQuc3Ns
# LmNvbS9TU0wuY29tLXRpbWVTdGFtcGluZy1JLVIyLmNlcjBRBgNVHSAESjBIMDwG
# DCsGAQQBgqkwAQMGATAsMCoGCCsGAQUFBwIBFh5odHRwczovL3d3dy5zc2wuY29t
# L3JlcG9zaXRvcnkwCAYGZ4EMAQQCMBYGA1UdJQEB/wQMMAoGCCsGAQUFBwMIMEIG
# A1UdHwQ7MDkwN6A1oDOGMWh0dHA6Ly9jcmxzLnNzbC5jb20vU1NMLmNvbS10aW1l
# U3RhbXBpbmctSS1SMi5jcmwwHQYDVR0OBBYEFCesA1a6KGq6FzuDPUB/eagk7MM8
# MA4GA1UdDwEB/wQEAwIHgDANBgkqhkiG9w0BAQsFAAOCAgEAT3ZuzvwDnsIZTXBn
# +hjmuBXgzB12fbYxT9uYe6ZvhvpbZWKcyDQgacETkPw8k6yeqnYCYyFZ063lMPEq
# AhAD2nMG614Zh7PtHW9DWqfsgivxbPYBeN+t7UxgkYT3expbWMdPEqBtWVyHOvLc
# KvMxgJWfJjANwVkwVDfky/j7cf28+iimN8PKc7S/u8/LenRRnV2W2YfncRnkz9Cf
# s5nRDzaZguiHrrp2GxwgnNQSH4GBjHOl3PzLsnVbGoZKi4ZEjgXups4mGGOK7+GB
# 2HAlQn+OS944cHqlkH0gElt2WezoCNRpELph9qaxuBnjSEqXWWfgE6yGBwO0uxKN
# qpWVTHmAwr6SvBPofxubXIuEn9ivR4CLOuAxUSrJ41ZBg/qqG0oJjF6GkRKbxq7c
# yWSkEZYJhmKCg2Hg5fXHagOxiwbmn5JPZ1vhWCrbk3v/dTx2gvTK5+erC5H9/rTc
# ljUI776yd2rfhjfkpvyAsbtXs4D7nrnw8i9wor5+fdtRSJBVxqzLmykFftoL0Up2
# Q++tyKCUdribdcnrB4HKS3s+t3AjdcbA06DCL8GifQi9fL0yRBRNlA4o6BP+Sr75
# 5MaCNjURYZDvDyxJHBBT7cqjZIwsiR8s+6860noFbBBtdge2Iw7CPC/1Q31I27hV
# olS7B0yao3v8X2MtWy3msZlXTcEwggXdMIIDxaADAgECAgh7LJvTFoAymTANBgkq
# hkiG9w0BAQsFADB8MQswCQYDVQQGEwJVUzEOMAwGA1UECAwFVGV4YXMxEDAOBgNV
# BAcMB0hvdXN0b24xGDAWBgNVBAoMD1NTTCBDb3Jwb3JhdGlvbjExMC8GA1UEAwwo
# U1NMLmNvbSBSb290IENlcnRpZmljYXRpb24gQXV0aG9yaXR5IFJTQTAeFw0xNjAy
# MTIxNzM5MzlaFw00MTAyMTIxNzM5MzlaMHwxCzAJBgNVBAYTAlVTMQ4wDAYDVQQI
# DAVUZXhhczEQMA4GA1UEBwwHSG91c3RvbjEYMBYGA1UECgwPU1NMIENvcnBvcmF0
# aW9uMTEwLwYDVQQDDChTU0wuY29tIFJvb3QgQ2VydGlmaWNhdGlvbiBBdXRob3Jp
# dHkgUlNBMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEA+Q/doyt9y9Aq
# /uxnhabnLhu6d+Hj9a+k7PpKXZHEV0drGHdrdvL9k+Q9D8IWngtmw1aUnheDhc5W
# 7/IW/QBi9SIJVOhlF05BueBPRpeqG8i4bmJeabFf2yoCfvxsyvNB2O3Q6Pw/YUjt
# sAMUHRAOSxngu07shmX/NvNeZwILnYZVYf16OO3+4hkAt2+hUGJ1dDyg+sglkrRu
# eiLH+B6h47LdkTGrKx0E/6VKBDfphaQzK/3i1lU0fBmkSmjHsqjTt8qhk4jrwZe8
# jPkd2SKEJHTHBD1qqSmTzOu4W+H+XyWqNFjIwSNUnRuYEcM4nH49hmylD0CGfAL0
# XAJPKMuucZ8POsgz/hElNer8usVgPdl8GNWyqdN1eANyIso6wx/vLOUuqfqeLLZR
# Rv2vA9bqYGjqhRY2a4XpHsCz3cQk3IAqgUFtlD7I4MmBQQCeXr9/xQiYohgsQkCz
# +W84J0tOgPQ9gUfgiHzqHM61dVxRLhwrfxpyKOcAtdF0xtfkn60Hk7ZTNTX8N+TD
# 9l0WviFz3pIK+KBjaryWkmo++LxlVZve9Q2JJgT8JRqmJWnLwm3KfOJZX5es6+8u
# yLzXG1k8K8zyGciTaydjGc/86Sb4ynGbf5P+NGeETpnr/LN4CTNwumamdu0bc+sa
# pQ3EIhMglFYKTixsTrH9z5wJuqIz7YcCAwEAAaNjMGEwHQYDVR0OBBYEFN0ECQei
# 9Xp9UlMSkpXuOIAlDaZZMA8GA1UdEwEB/wQFMAMBAf8wHwYDVR0jBBgwFoAU3QQJ
# B6L1en1SUxKSle44gCUNplkwDgYDVR0PAQH/BAQDAgGGMA0GCSqGSIb3DQEBCwUA
# A4ICAQAgGBGUKfsmnRweHnBh8ZVyk3EkrWiTWI4yrxuzcAP8JSt0hZA9eGr0uYul
# lzu1GJG7Hqf5QFuR+VWZrx4R0Fwdp2bjsZQHDDI5puobsHnYHZxwROOK3cT5lR+K
# OEM/AYWlR6c9RrK85SJo93uc2Cw+CiHILTOsv8WBmTF0wXVxxb6x8CNF9J1r/Blj
# naO8BMYYCyW7U4kPs4BQ3kXuRH+rlHhkmNP2KN2H2HBldPsOuRPrpw9hqTKWzN67
# 7WNMGLupQPegVG4giHF1GOp6tDRy4CMnd1y2kOqGJUCr7zMPy5+CvqIg+/a1LRrm
# woWxdA/7yGUCpFIBR91JIsG/2OtrrH7e7GMzFbcjCI/GD41BWt2OxbmP5UU/eNu6
# 0htAsf5xTT/ggaK6XrTsFeCT3QgffuFVmQsh3pOeCvvmo0m9NjD+53eyoHWXtS2B
# iBdlIPfakACfyVLMMso1fPU9D9gr1/UmbMkGNJYW6nBZGjJ5eQu2iH8PUkg9v2zY
# okQu0U63cljTiROV/kSr+NeLG26cvCygW9VqAK9fN+HV+hALmJyG5yaPzvDsbopX
# C4DjTrLAoGNhkLpVaDd0araS25+hhiK2ZScO7LafQmDkZ8K12kELxNOLYRu8+h+R
# K9dEB166KazZxenvU0ha64DxKFghzbAGVfsnP1OQcKkEHlcnuTCCBsswggSzoAMC
# AQICEFKdu8K4iYf1g4DgsOuiBjYwDQYJKoZIhvcNAQELBQAwfDELMAkGA1UEBhMC
# VVMxDjAMBgNVBAgMBVRleGFzMRAwDgYDVQQHDAdIb3VzdG9uMRgwFgYDVQQKDA9T
# U0wgQ29ycG9yYXRpb24xMTAvBgNVBAMMKFNTTC5jb20gUm9vdCBDZXJ0aWZpY2F0
# aW9uIEF1dGhvcml0eSBSU0EwHhcNMjYwNjEyMTY0MjE1WhcNNDEwMjEyMTczOTM5
# WjByMQswCQYDVQQGEwJVUzEOMAwGA1UECAwFVGV4YXMxEDAOBgNVBAcMB0hvdXN0
# b24xETAPBgNVBAoMCFNTTCBDb3JwMS4wLAYDVQQDDCVTU0wuY29tIFRpbWVzdGFt
# cGluZyBJc3N1aW5nIFJTQSBDQSAyMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIIC
# CgKCAgEAny+r5nNNkLwxRps2B3laUGNU9y7vWiJ5013yf0iXz65bQdwa9bjj8l/S
# keXqHGqfSh2Foae+80E8mDEf93oIwjsy2CX2cXmKxqtF8HJGYB4f6yRhKED50wkb
# OysL02IXf+/EZna44jffhhVz4OU/k52xQ/PnIg/uFhc2Wk+Sc/CHqAr+lYVkPz7L
# y5RqB9f1RKGr9JC37W1LgVdHC50dNIdsa3QXPhltYZubR3npE4Bbfi0joUW5n5O0
# ayweN45R/YVLxA0YGlp1OHVfVnsqXq8bhnw1Lc4kjJ6XOgXlOlw/a8ze57TvbduZ
# l3ehewTmvO0Aky/nqOWDS9IPPxdxdG6vprBbSuHlxNANBAbHTiFgkfZmf0dZYlT/
# AnZIoFxAq0HILPolf4OgWgET76SiWSlm2XYRIXwVjpeqG0plvXwRIQBzSiEJj7Qe
# QFnCvHx4gQMINvN3+yG/1rxhEbajGve0tTP3lX4PPOHVAE0QJp4ZzPI1YYJkhVRr
# iVVxVRU4Fsg4BPwP6I+YLmHb1tZ4RLwOFNLh/gJYDgPlChCoxOogFxXgwPZZrDyE
# RYB0aeOexW0OKacN4RRu9cqF2KKu/Ab5AL7eYDLVGUPrEEyYbIMApVKqpebc0/jD
# QniC+3rkauRAjgVc8m1ip/CQgG1Dw4Z9ulVRAY9VR6Za26LsTbUCAwEAAaOCAVEw
# ggFNMBIGA1UdEwEB/wQIMAYBAf8CAQAwHwYDVR0jBBgwFoAU3QQJB6L1en1SUxKS
# le44gCUNplkwTQYIKwYBBQUHAQEEQTA/MD0GCCsGAQUFBzAChjFodHRwOi8vY2Vy
# dC5zc2wuY29tL1NTTGNvbS1Sb290Q0EtUlNBLTQwOTYtUjEuY2VyMD8GA1UdIAQ4
# MDYwNAYEVR0gADAsMCoGCCsGAQUFBwIBFh5odHRwczovL3d3dy5zc2wuY29tL3Jl
# cG9zaXRvcnkwEwYDVR0lBAwwCgYIKwYBBQUHAwgwQgYDVR0fBDswOTA3oDWgM4Yx
# aHR0cDovL2NybHMuc3NsLmNvbS9TU0xjb20tUm9vdENBLVJTQS00MDk2LVIxLmNy
# bDAdBgNVHQ4EFgQUcJplwUOAo/zpsWSJbvEwnAkhyXwwDgYDVR0PAQH/BAQDAgGG
# MA0GCSqGSIb3DQEBCwUAA4ICAQBlFFvNMemA6iBiBYo56IKQjWhWuQaYKuo4qpf0
# KJNERAt1gz+HsA2SL3xA/V+EA8SRPNP9SvX0is+5mDsppYvpKyYGqYP36YFW0mbF
# 1F0ZtXxumCUUO/ZV5mBNKDf5Q4PY7Qb0eWAepUc0rNJr/Mvn5ZiXfJPxDb2xmcg8
# aRD652/nr+Ork2UBP0E43iJdI4LF7Vs29R3SGRLYZOxM15DI4QebsKRl0KDlf4Om
# YGCKc7umTxibkZtN1C1KWgnf9jadU/JwnySaYEBgx6/v+FVC6SGONziY7TcvI9MV
# +qYxHUPlOm6AaQP2dS4bjWXnm86ldCbUkxtOACumSfT97077JNiVa7PZ1IBkd/2P
# E1AC8gs7U+/Yk1BN9XRPIi15k/uA1xF9oeee5KGjyiGKkqIT7W8QkgUT5zeCinFK
# kcKafZMcROSVYpXtmtQqGGR2g4uPYqJ0K1hms6gJXrHt/34p8M9PrV8oNWe0Zl1E
# rDMtXndUg3qhJL4pA3ZUlo7w5lM5ml+A7ijr/3Gk2v4QRoDeE2ShmTXdHgtqo8L/
# fT119mYcETycE2NYGRXsBl3N0rzDsHRr8P3TrprqhRrX04iS0P7eQ+lDxgS3yhGn
# 3OzWGhDt9Gf2x1qe0/qdhFAVOkXxzMZz4Uat6xsAfzX0+/m8GEKW5Ojw/HY+kLvV
# wzSPOzGCAlUwggJRAgEBMIGGMHIxCzAJBgNVBAYTAlVTMQ4wDAYDVQQIDAVUZXhh
# czEQMA4GA1UEBwwHSG91c3RvbjERMA8GA1UECgwIU1NMIENvcnAxLjAsBgNVBAMM
# JVNTTC5jb20gVGltZXN0YW1waW5nIElzc3VpbmcgUlNBIENBIDICEFRD+De9Wu4Y
# AYRyuFzajuMwCwYJYIZIAWUDBAIBoIIBYDAaBgkqhkiG9w0BCQMxDQYLKoZIhvcN
# AQkQAQQwHAYJKoZIhvcNAQkFMQ8XDTI2MTEwOTE1MzMzNVowKAYJKoZIhvcNAQk0
# MRswGTALBglghkgBZQMEAgGhCgYIKoZIzj0EAwIwLwYJKoZIhvcNAQkEMSIEIFcO
# GWuR969Nmgn+ciMpkbA09/9czJmi0V8DVE/4+qh7MIHIBgsqhkiG9w0BCRACLzGB
# uDCBtTCBsjCBrwQgV0/qF6r6XnxqK5sIyZixc15FCzhzykTmokygkw5j87AwgYow
# dqR0MHIxCzAJBgNVBAYTAlVTMQ4wDAYDVQQIDAVUZXhhczEQMA4GA1UEBwwHSG91
# c3RvbjERMA8GA1UECgwIU1NMIENvcnAxLjAsBgNVBAMMJVNTTC5jb20gVGltZXN0
# YW1waW5nIElzc3VpbmcgUlNBIENBIDICEFRD+De9Wu4YAYRyuFzajuMwCgYIKoZI
# zj0EAwIERjBEAiAvDj24UuKUkOPdC2w45yuxy9poAPybZkzfU5XJoeNz/gIgOG54
# iQ6r7oLF0LYl92WxVFcs8yzFj2W5myJYNPz2YJY=
# SIG # End signature block
