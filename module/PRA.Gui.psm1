<#
.SYNOPSIS
    Native WPF front-end for PRA Remote Mailbox, without directory or cloud imports.
.DESCRIPTION
    Every operation runs the existing CLI in Windows PowerShell 5.1 Desktop. A completed,
    consistent Preview and an unchanged content fingerprint are required before typed Apply.
    Local metadata is indicative; the engine remains the authority for all backup/proof checks.
.NOTES
    Author  : Nicolas Fabert
    Version : 2.1.0
#>
#Requires -Version 5.1
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$script:Gui = $null
$script:GuiModuleRoot = $PSScriptRoot
$script:GuiInputNames = @('ActionChoice','PhaseChoice','BatchText','BatchChoice','IdentityText','ScopeChoice','LimitText','ExpectChoice','OnceCheck','ConfigPathText','Reload','BrowseConfig','BrowseBatch','BrowseBatchFolder','ConfirmationText','SourceChoice','OuText','CsvText','ChooseOu','BrowseCsv')

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
        'Convert' { if ($Phase -eq 'Cloud') { return 'Convert' }; return '' }
        'Recover' { if ($Phase -eq 'Cloud') { return 'Recover' }; return 'Convert' }
        'Finalize' { return 'RecoverFinalize' }
        'Check' { return 'Convert' }
        default { throw 'Unknown action.' }
    }
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
    foreach ($value in @($Batch, $Identity,$SearchBase,$CsvPath)) {
        if ($value -match '[\x00-\x1f]') { throw 'Selection contains a control character.' }
    }
    if ($MaxObjects -lt 0) { throw 'MaxObjects must be zero or positive.' }
    if ($Action -eq 'Convert' -and $Phase -ne 'Cloud' -and $Batch) { throw 'Convert AD/Both must not receive a batch: Apply creates a NEW Convert batch.' }
    if (($Action -in @('Recover','Finalize') -or ($Action -eq 'Convert' -and $Phase -eq 'Cloud')) -and -not $Batch) {
        throw ('A {0} batch is required.' -f (Get-PraGuiBatchType $Action $Phase))
    }
    if ($Action -eq 'Check' -and -not $Batch -and -not $Identity) { throw 'Check requires a Convert batch or one identity (prefer a UPN).' }
    if ($Action -eq 'Check' -and $Mode -eq 'Apply') { throw 'Check is always read-only.' }
    if ($MaxObjects -and -not ($Action -eq 'Convert' -and $Phase -in @('AD','Both'))) { throw 'MaxObjects is only available for Convert AD/Both.' }
    $null=Get-PraTargetOverride -SearchBase $SearchBase -CsvPath $CsvPath -Identity $Identity
    if (($SearchBase -or $CsvPath) -and -not ($Action -eq 'Convert' -and $Phase -in @('AD','Both'))) { throw 'OU/CSV selection is only available for Convert AD/Both.' }
    return [ordered]@{
        Action=$Action; Mode=$Mode; Phase=$(if ($Action -eq 'Finalize') { 'Finalize' } elseif ($Action -eq 'Check') { 'Cloud' } else { $Phase })
        Batch=$Batch; Identity=$Identity; SearchBase=$SearchBase; CsvPath=$CsvPath; Scope=$Scope; MaxObjects=$MaxObjects
        Expect=$(if ($Action -eq 'Check') { $Expect } else { 'Provisioned' }); Once=$Once
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
    $system = if ([Environment]::Is64BitOperatingSystem -and -not [Environment]::Is64BitProcess) { 'Sysnative' } else { 'System32' }
    return Join-Path $env:SystemRoot ($system + '\WindowsPowerShell\v1.0\powershell.exe')
}

function Get-PraGuiNativeModulePath {
    $paths = New-Object 'Collections.Generic.List[string]'
    $native = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\Modules'
    $paths.Add($native)
    $documents = [Environment]::GetFolderPath('MyDocuments')
    if ($documents) { $paths.Add((Join-Path $documents 'WindowsPowerShell\Modules')) }
    $paths.Add((Join-Path $env:ProgramFiles 'WindowsPowerShell\Modules'))
    foreach ($source in @([Environment]::GetEnvironmentVariable('PSModulePath','User'), [Environment]::GetEnvironmentVariable('PSModulePath','Machine'), $env:PSModulePath)) {
        foreach ($entry in @($source -split ';')) {
            if (-not $entry -or $entry -match '(?i)\\PowerShell\\(7(?:[\\.-]|$)|Modules(?:\\|$))') { continue }
            if ($PSVersionTable.PSEdition -eq 'Core' -and $entry.StartsWith($PSHOME,[StringComparison]::OrdinalIgnoreCase)) { continue }
            if (-not $paths.Contains($entry)) { $paths.Add($entry) }
        }
    }
    return (@($paths | Select-Object -Unique) -join ';')
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
    param([string]$Root, [string]$ConfigPath, [Collections.IDictionary]$Request, [string]$ScriptPath = '')
    if (-not $ScriptPath) { $ScriptPath = Join-Path $Root 'Invoke-PraRemoteMailbox.ps1' }
    $tokens = New-Object 'Collections.Generic.List[string]'
    foreach ($token in @('-NoProfile','-NonInteractive','-STA','-File', $ScriptPath, '-Action',$Request.Action,'-Mode',$Request.Mode,'-ConfigPath',$ConfigPath,'-Scope',$Request.Scope)) { $tokens.Add([string]$token) }
    if ($Request.Action -in @('Convert','Recover')) { $tokens.Add('-Phase'); $tokens.Add([string]$Request.Phase) }
    foreach ($name in @('Batch','Identity','SearchBase','CsvPath')) { if ($Request[$name]) { $tokens.Add('-'+$name); $tokens.Add([string]$Request[$name]) } }
    if ($Request.Action -eq 'Convert' -and $Request.Phase -in @('AD','Both')) { $tokens.Add('-MaxObjects'); $tokens.Add([string]$Request.MaxObjects) }
    if ($Request.Action -eq 'Check') { $tokens.Add('-Expect'); $tokens.Add([string]$Request.Expect) }
    if ($Request.Once) { $tokens.Add('-Once') }
    if ($Request.Mode -eq 'Apply') { $tokens.Add('-Force') }
    $engine = Get-PraGuiEngine
    $displayTokens = @($engine) + @($tokens)
    return [pscustomobject]@{
        FilePath=$engine; Tokens=$tokens.ToArray()
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
    if ($hash -notmatch '^[a-fA-F0-9]{64}$') { throw 'Invalid SHA-256 hexadecimal value.' }
    return $hash.ToLowerInvariant()
}

function Read-PraGuiBatch {
    param([string]$Path, [string]$Environment)
    $item = [pscustomobject]@{ Path=$Path; Folder=(Split-Path $Path -Parent); Operation='?'; BatchId=''; Status=''; Valid=$false; Data=$null; Label=''; CopyPaths=@() }
    try {
        $data = [IO.File]::ReadAllText($Path) | ConvertFrom-Json -ErrorAction Stop
        $item.Operation = [string](Get-PraGuiValue $data 'Operation' '?')
        $item.BatchId = [string](Get-PraGuiValue $data 'BatchId' ((Split-Path $item.Folder -Leaf) -replace '^(Batch|Finalize)-',''))
        if ($item.Operation -notin @('Convert','Recover','RecoverFinalize')) { throw 'Not a Convert, Recover or RecoverFinalize package.' }
        if ((Get-PraGuiValue $data 'Kind' '') -eq 'ADVerified') { throw 'State/proof is not a batch.' }
        if ((Get-PraGuiValue $data 'Environment' '') -cne $Environment) { throw 'Environment differs from configuration.' }
        $schema = Get-PraGuiValue $data 'SchemaVersion' 1
        if (($item.Operation -eq 'RecoverFinalize' -and $schema -ne 2) -or $schema -notin @(1,2,3)) { throw 'Unsupported schema.' }
        $records = @(if ($item.Operation -eq 'RecoverFinalize') { Get-PraGuiValue $data 'Items' @() } else { Get-PraGuiValue $data 'Records' @() })
        if (-not $records.Count -or $null -eq $records[0]) { throw 'Empty or missing records.' }
        if ($schema -ge 2 -and ((ConvertTo-PraGuiHash ([IO.File]::ReadAllText($Path+'.sha256'))) -cne (Get-PraGuiFileHash $Path))) { throw 'SHA-256 mismatch.' }
        $item.Data=$data; $item.Valid=$true; $item.Status='Métadonnées lisibles — validation moteur requise'
    } catch { $item.Status='INVALIDE : '+$_.Exception.Message }
    $item.Label='{0} · {1} · {2}' -f $item.Operation,$item.BatchId,$item.Status
    return $item
}

function Read-PraGuiState {
    param([string]$Root, [string]$ConfigPath, [hashtable]$ScopeOverride=@{})
    $state = [pscustomobject]@{ Root=$Root; ConfigPath=$ConfigPath; Config=$null; ConfigError=''; Batches=@(); BatchError='' }
    try { $state.Config = Import-PraConfiguration -Path $ConfigPath -Root $Root -ScopeOverride $ScopeOverride }
    catch { $state.ConfigError=$_.Exception.Message; return $state }
    $folder = [string]$state.Config.Storage.BackupFolder
    if (-not (Test-Path -LiteralPath $folder)) { $state.BatchError='Backup folder not present yet: '+$folder; return $state }
    try {
        $state.Batches = @(Get-ChildItem -LiteralPath $folder -Recurse -File -Filter '*.json' -ErrorAction Stop |
            Where-Object { $_.Name -notlike 'State-*' -and $_.Name -notlike 'Journal-*' -and (Split-Path $_.DirectoryName -Leaf) -match '^(Batch|Finalize)-' } |
            ForEach-Object { Read-PraGuiBatch -Path $_.FullName -Environment $state.Config.Environment })
    } catch { $state.BatchError=$_.Exception.Message }
    return $state
}

function Resolve-PraGuiBatch {
    param([string]$Value, [string]$Operation, $State)
    if (-not $Value) { return $null }
    if ($Value -match '^[a-fA-F0-9]{8,32}$') {
        $found = @($State.Batches | Where-Object { $_.BatchId.StartsWith($Value,[StringComparison]::OrdinalIgnoreCase) -and $_.Operation -eq $Operation })
        if ($found.Count -gt 1) {
            $hashes=@($found | ForEach-Object { Get-PraGuiFileHash $_.Path } | Select-Object -Unique)
            if ($hashes.Count -ne 1) { throw 'Batch ID ambiguous: matching files have different contents. Give an exact JSON path.' }
            $found=@($found | Sort-Object @{
                Expression={
                    $prefix=if ($_.Operation -eq 'RecoverFinalize') { 'Finalize-' } else { 'Batch-' }
                    if ((Split-Path $_.Folder -Leaf) -ieq ($prefix+$_.BatchId)) { 0 } else { 1 }
                }
            },Path)
            $selected=$found[0]
            $selected.CopyPaths=@($found | ForEach-Object Path | Select-Object -Unique)
            $found=@($selected)
        }
    } else {
        $path = $Value
        if (-not [IO.Path]::IsPathRooted($path)) { $path=Join-Path $State.Root $path }
        $entry = Get-Item -LiteralPath $path -ErrorAction Stop
        $found = @(if ($entry.PSIsContainer) {
            @(Get-ChildItem -LiteralPath $entry.FullName -File -Filter '*.json' -ErrorAction Stop | Where-Object Name -NotLike 'State-*' |
                ForEach-Object { Read-PraGuiBatch $_.FullName $State.Config.Environment } | Where-Object Operation -eq $Operation)
        } else { Read-PraGuiBatch $entry.FullName $State.Config.Environment })
    }
    if ($found.Count -ne 1) { throw 'Batch not found or ambiguous. Give its exact JSON file; check the configuration backup folder.' }
    $batch = $found[0]
    if (-not $batch.Valid) { throw $batch.Status }
    if ($batch.Operation -cne $Operation) { throw "Expected $Operation, not $($batch.Operation)." }
    return $batch
}

function Get-PraGuiGuard {
    <# Content, not timestamps: all selected batch artifacts and the original Convert source are guarded. #>
    param([string]$Root, [string]$ConfigPath, [Collections.IDictionary]$Request)
    $override=Get-PraTargetOverride -SearchBase ([string]$Request.SearchBase) -CsvPath ([string]$Request.CsvPath) -Identity $Request.Identity
    $state = Read-PraGuiState $Root $ConfigPath -ScopeOverride $override
    if ($state.ConfigError) { throw $state.ConfigError }
    $configFile = $ConfigPath
    if (-not [IO.Path]::IsPathRooted($configFile)) { $configFile=Join-Path $Root $configFile }
    $files = New-Object 'Collections.Generic.List[string]'
    $files.Add([IO.Path]::GetFullPath($configFile))
    $files.Add((Join-Path $Root 'Invoke-PraRemoteMailbox.ps1'))
    $moduleFolder=Join-Path $Root 'module'
    if (Test-Path -LiteralPath $moduleFolder -PathType Container) {
        foreach ($file in @(Get-ChildItem -LiteralPath $moduleFolder -Recurse -File -ErrorAction Stop |
            Where-Object { $_.Extension -in @('.psm1','.psd1','.ps1','.dll','.xaml') })) { $files.Add($file.FullName) }
    }
    foreach ($path in @($state.Config.Scope.CsvPath, $state.Config.SharedMailbox.CsvPath)) { if ($path) { $files.Add([string]$path) } }
    if ($state.Config.Scope.Mode -eq 'Csv' -and $Request.Action -eq 'Convert' -and $Request.Phase -in @('AD','Both') -and -not $Request.Identity) {
        $null=@(Read-PraTargetCsv -Path $state.Config.Scope.CsvPath)
    }
    $batch = Resolve-PraGuiBatch $Request.Batch (Get-PraGuiBatchType $Request.Action $Request.Phase) $state
    if ($batch) {
        foreach ($file in @(Get-ChildItem -LiteralPath $batch.Folder -Recurse -File -ErrorAction Stop)) { $files.Add($file.FullName) }
        foreach ($copy in $batch.CopyPaths) {
            foreach ($file in @(Get-ChildItem -LiteralPath (Split-Path $copy -Parent) -Recurse -File -ErrorAction Stop)) { $files.Add($file.FullName) }
        }
        if ($Request.Action -in @('Convert','Recover') -and $Request.Phase -eq 'Cloud') {
            $proofPath = Join-Path $batch.Folder ('State-'+$batch.Data.BatchId+'.json')
            $proof = [IO.File]::ReadAllText($proofPath) | ConvertFrom-Json -ErrorAction Stop
            if ((Get-PraGuiValue $proof 'Kind' '') -cne 'ADVerified' -or (Get-PraGuiValue $proof 'Operation' '') -cne $Request.Action -or
                (Get-PraGuiValue $proof 'Environment' '') -cne $state.Config.Environment -or
                (ConvertTo-PraGuiHash ([IO.File]::ReadAllText($proofPath+'.sha256'))) -cne (Get-PraGuiFileHash $proofPath)) { throw 'Missing, invalid or mismatched AD proof.' }
        }
        if ($Request.Action -eq 'Recover' -and $Request.Phase -eq 'Cloud') {
            $hash = [string](Get-PraGuiValue $batch.Data 'SourceBackupHash' '')
            if (-not $hash) { throw 'Recover batch lacks its original Convert source hash.' }
            $hash=ConvertTo-PraGuiHash $hash
            $sources = @($state.Batches | Where-Object { $_.Valid -and $_.Operation -eq 'Convert' -and (Get-PraGuiFileHash $_.Path) -ceq $hash })
            if (-not $sources.Count) { throw 'Copy the ORIGINAL Convert folder into Storage.BackupFolder as well as the Recover folder.' }
            foreach ($source in $sources) {
                foreach ($file in @(Get-ChildItem -LiteralPath $source.Folder -Recurse -File -ErrorAction Stop)) { $files.Add($file.FullName) }
            }
        }
    }
    $selection = [ordered]@{}
    foreach ($key in @('Action','Phase','Batch','Identity','SearchBase','CsvPath','Scope','MaxObjects','Expect','Once')) { $selection[$key]=$Request[$key] }
    $artifactHashes = @(foreach ($path in @($files | Sort-Object -Unique)) { [ordered]@{ Path=$path; Hash=(Get-PraGuiFileHash $path) } })
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
    if ($Result.kind -cne 'result' -or $Result.action -cne $Request.Action -or $Result.mode -cne $Request.Mode -or $Result.phase -cne $Request.Phase) { return $false }
    if ([string]$Result.exitCode -notmatch '^[012]$' -or [int]$Result.exitCode -ne $NativeExitCode -or $NativeExitCode -eq 1) { return $false }
    foreach ($field in @('success','error','pending','skipped','planned','total')) { if ([string]$Result.$field -notmatch '^\d+$') { return $false } }
    if ([int]$Result.error -ne 0 -or @((Get-PraGuiValue $Result 'issues' @())).Count) { return $false }
    if ([int64]$Result.total -ne ([int64]$Result.success+[int64]$Result.error+[int64]$Result.pending+[int64]$Result.skipped+[int64]$Result.planned)) { return $false }
    if ($NativeExitCode -eq 2) { return $Result.status -ceq 'Pending' -and [int]$Result.pending -gt 0 }
    return $Result.status -cin @('Success','Planned') -and [int]$Result.pending -eq 0
}

function Test-PraGuiPreview {
    param($Result, [Collections.IDictionary]$Request, [int]$NativeExitCode, [string[]]$TransportIssues=@(), [string]$StandardError='')
    if ($Request.Mode -ne 'Preview' -or $Request.Action -eq 'Check') { return $false }
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
            $record=$line | ConvertFrom-Json -ErrorAction Stop
            if ((Get-PraGuiValue $record 'kind' '') -notin @('start','step','item','summary','result')) { throw 'Unknown or missing event kind.' }
            $events.Add($record)
        } catch { $errors.Add('Invalid event JSONL: '+$_.Exception.Message) }
    }
    $result.Events=$events.ToArray(); $result.Errors=$errors.ToArray(); $result.Position=$Position+$last+1
    return $result
}

function Start-PraGuiChildProcess {
    param($Command, [string]$Root, [string]$EventPath)
    if (-not (Test-Path -LiteralPath $Command.FilePath -PathType Leaf)) { throw 'Windows PowerShell 5.1 Desktop is unavailable.' }
    $info=New-Object Diagnostics.ProcessStartInfo
    $info.FileName=$Command.FilePath; $info.Arguments=$Command.Arguments; $info.WorkingDirectory=$Root
    $info.UseShellExecute=$false; $info.CreateNoWindow=$true
    $info.RedirectStandardOutput=$true; $info.RedirectStandardError=$true
    $info.EnvironmentVariables['PSModulePath']=Get-PraGuiNativeModulePath
    $info.EnvironmentVariables['PRA_EVENT_FILE']=$EventPath
    $info.EnvironmentVariables['PRA_ICONS']='Ascii'
    $info.EnvironmentVariables.Remove('PRA_STOP_FILE')
    $process=[Diagnostics.Process]::Start($info)
    # Native Tasks drain both pipes; never execute PowerShell callbacks on background CLR threads.
    return [pscustomobject]@{ Process=$process; Output=$process.StandardOutput.ReadToEndAsync(); Errors=$process.StandardError.ReadToEndAsync() }
}

function Initialize-PraGuiTheme {
    param([ValidateSet('System','Light','Dark')][string]$Theme='System')
    Add-Type -AssemblyName PresentationFramework,PresentationCore,WindowsBase,System.Xaml
    $app=[Windows.Application]::Current
    if (-not $app) { $app=New-Object Windows.Application; $app.ShutdownMode=[Windows.ShutdownMode]::OnExplicitShutdown }
    $property=[Windows.Application].GetProperty('ThemeMode')
    $dark=$false
    if ($property) {
        $dark=$Theme -eq 'Dark'
        if ($Theme -eq 'System') {
            $setting=Get-ItemProperty -LiteralPath 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize' -ErrorAction SilentlyContinue
            $dark=$null -ne $setting -and (Get-PraGuiValue $setting 'AppsUseLightTheme' 1) -eq 0
        }
        # PropertyType is only resolved after the reflection guard; 5.1 never binds ThemeMode.
        $mode=[Activator]::CreateInstance($property.PropertyType,[object[]]@($(if ($dark) { 'Dark' } else { 'Light' })))
        $property.SetValue($app,$mode,$null)
    }
    return [pscustomobject]@{ Fluent=($null -ne $property); Dark=$dark }
}

function Set-PraGuiTheme {
    param($Window, $Theme)
    $colors=@{
        ApplicationBackgroundBrush=@('#F7F4EF','#202020'); CardBackgroundFillColorDefaultBrush=@('#FFFFFF','#2B2B2B')
        CardStrokeColorDefaultBrush=@('#DEDEDE','#3D3D3D'); TextFillColorPrimaryBrush=@('#242424','#FFFFFF')
        TextFillColorSecondaryBrush=@('#5C5C5C','#C5C5C5'); PraBrand=@('#B11F4B','#FD8EA1')
        PraCritical=@('#DC2626','#F87171'); PraSuccess=@('#16A34A','#4ADE80'); PraCaution=@('#B45309','#FBBF24')
        AccentFillColorDefaultBrush=@('#B11F4B','#FD8EA1'); AccentButtonBackground=@('#B11F4B','#FD8EA1')
        AccentButtonBorderBrush=@('#B11F4B','#FD8EA1')
    }
    foreach ($key in $colors.Keys) {
        if ($Theme.Fluent -and $key -notlike 'Pra*' -and $key -notlike 'Accent*') { continue }
        $color=$colors[$key][[int][bool]$Theme.Dark]
        $brush=[Windows.Media.SolidColorBrush]::new([Windows.Media.ColorConverter]::ConvertFromString($color))
        $brush.Freeze(); $Window.Resources[$key]=$brush
    }
    if ($Theme.Fluent) {
        # The local padding/grid styles must inherit the native implicit Fluent styles;
        # otherwise they mask Fluent's templates and WPF falls back to classic controls.
        foreach ($name in @('BrowseConfig','Reload','BrowseBatch','BrowseBatchFolder','OpenBatch','Preview','Apply','CopyCommand','OpenLog','OpenCsv','OpenHtml','CopyBatch','OpenBackup',
            'ConfigPathText','BatchText','IdentityText','LimitText','ConfirmationText','CommandText','NextStepsText',
            'ThemeChoice','ActionChoice','PhaseChoice','BatchChoice','ScopeChoice','ExpectChoice','BatchGrid','PreviewGrid','SourceChoice','OuText','CsvText','ChooseOu','BrowseCsv')) {
            $control=$Window.FindName($name)
            $baseStyle=[Windows.Application]::Current.TryFindResource($control.GetType())
            if ($baseStyle -is [Windows.Style]) {
                $style=[Windows.Style]::new($control.GetType(),$baseStyle)
                if ($control.Style) { foreach ($setter in $control.Style.Setters) { $style.Setters.Add($setter) } }
                $control.Style=$style
            }
        }
    }
    $apply=$Window.FindName('Apply')
    if ($apply) {
        $accent=if ($Theme.Fluent) { $Window.TryFindResource('AccentButtonStyle') } else { $null }
        if ($accent) {
            $style=[Windows.Style]::new([Windows.Controls.Button],$accent)
            $style.Setters.Add([Windows.Setter]::new([Windows.Controls.Control]::PaddingProperty,[Windows.Thickness]::new(12,6,12,6)))
            $style.Setters.Add([Windows.Setter]::new([Windows.FrameworkElement]::MarginProperty,[Windows.Thickness]::new(0,0,8,6)))
            $apply.Style=$style
        } else {
            $apply.SetResourceReference([Windows.Controls.Control]::BackgroundProperty,'PraBrand')
            $apply.Foreground=[Windows.Media.Brushes]::White
        }
    }
}

function Get-PraGuiChoice {
    param($Control)
    return [string]$Control.SelectedItem.Content
}

function Get-PraGuiWindowRequest {
    param([string]$Mode='Preview')
    $c=$script:Gui.Controls
    $action=Get-PraGuiChoice $c.ActionChoice; $phase=Get-PraGuiChoice $c.PhaseChoice
    $limit=0
    if ($action -eq 'Convert' -and $phase -ne 'Cloud') {
        if (-not [int]::TryParse($c.LimitText.Text,[ref]$limit)) { throw 'Maximum must be an integer.' }
    }
    $batch=if ($action -eq 'Convert' -and $phase -ne 'Cloud') { '' } else { $c.BatchText.Text.Trim() }
    $once=$c.OnceCheck.IsChecked -eq $true -and ($action -eq 'Check' -or ($action -in @('Convert','Recover') -and $phase -ne 'AD'))
    $identity=$c.IdentityText.Text.Trim(); $ou=''; $csv=''
    if ($action -eq 'Convert' -and $phase -in @('AD','Both')) {
        switch (Get-PraGuiChoice $c.SourceChoice) {
            'OU' { $ou=$c.OuText.Text.Trim(); $identity=''; if (-not $ou) { throw 'Choisir ou saisir le DN de l''OU.' } }
            'Csv' { $csv=$c.CsvText.Text.Trim(); $identity=''; if (-not $csv) { throw 'Charger un CSV avec une colonne Identity.' } }
        }
    }
    return New-PraGuiRequest -Action $action -Mode $Mode -Phase $phase -Batch $batch -Identity $identity -SearchBase $ou -CsvPath $csv -Scope (Get-PraGuiChoice $c.ScopeChoice) -MaxObjects $limit -Expect (Get-PraGuiChoice $c.ExpectChoice) -Once $once
}

function Add-PraGuiLine {
    param([string]$Text, [string]$Status='Info')
    $g=$script:Gui
    $key=switch ($Status) { 'Fail' { 'PraCritical' } 'Warn' { 'PraCaution' } 'Ok' { 'PraSuccess' } default { 'TextFillColorSecondaryBrush' } }
    $g.Lines.Add([pscustomobject]@{ Text=$Text; Brush=$g.Form.TryFindResource($key) })
    while ($g.Lines.Count -gt 2000) { $g.Lines.RemoveAt(0) }
    $g.Controls.ActivityLog.ScrollIntoView($g.Lines[$g.Lines.Count-1])
}

function Update-PraGuiSelection {
    param([switch]$Invalidate)
    $g=$script:Gui
    if (-not $g -or $g.Updating) { return }
    $g.Updating=$true
    try {
        if ($Invalidate) { $g.Pending=$null; $g.Controls.ConfirmationText.Clear() }
        $c=$g.Controls; $action=Get-PraGuiChoice $c.ActionChoice
        if ($g.LastAction -in @('Convert','Recover')) { $g.ExecutionPhase=Get-PraGuiChoice $c.PhaseChoice }
        $phase=switch ($action) { 'Check' { 'Cloud' } 'Finalize' { 'AD' } default { $g.ExecutionPhase } }
        foreach ($item in $c.PhaseChoice.Items) { if ($item.Content -eq $phase) { $c.PhaseChoice.SelectedItem=$item } }
        $g.LastAction=$action
        $busy=[bool]$g.Run -or [bool]$g.OuLookup
        $c.PhaseChoice.IsEnabled=($action -in @('Convert','Recover') -and -not $busy)
        $selectSource=$action -eq 'Convert' -and $phase -in @('AD','Both')
        $source=Get-PraGuiChoice $c.SourceChoice
        $c.SourcePanel.Visibility=if ($selectSource) { 'Visible' } else { 'Collapsed' }
        $c.OuPanel.Visibility=if ($selectSource -and $source -eq 'OU') { 'Visible' } else { 'Collapsed' }
        $c.CsvPanel.Visibility=if ($selectSource -and $source -eq 'Csv') { 'Visible' } else { 'Collapsed' }
        $single=-not $selectSource -or $source -eq 'Configuration'
        $c.IdentityText.Visibility=if ($single) { 'Visible' } else { 'Collapsed' }
        $c.IdentityLabel.Visibility=$c.IdentityText.Visibility
        $c.ChooseOu.IsEnabled=$selectSource -and $source -eq 'OU' -and -not $busy
        $c.BrowseCsv.IsEnabled=$selectSource -and $source -eq 'Csv' -and -not $busy
        $c.BatchPanel.Visibility=if ($action -eq 'Convert' -and $phase -ne 'Cloud') { 'Collapsed' } else { 'Visible' }
        $c.LimitPanel.Visibility=if ($action -eq 'Convert' -and $phase -ne 'Cloud') { 'Visible' } else { 'Collapsed' }
        $c.ExpectPanel.Visibility=if ($action -eq 'Check') { 'Visible' } else { 'Collapsed' }
        $c.OnceCheck.Visibility=if ($action -eq 'Check' -or ($action -in @('Convert','Recover') -and $phase -ne 'AD')) { 'Visible' } else { 'Collapsed' }
        $c.ConfirmationText.Visibility=if ($action -eq 'Check') { 'Collapsed' } else { 'Visible' }
        $type=Get-PraGuiBatchType $action $phase
        $c.BatchChoice.ItemsSource=@($g.State.Batches | Where-Object { $_.Operation -eq $type -or -not $_.Valid })
        $guide=switch ($action) {
            'Convert' { if ($phase -eq 'Cloud') { 'Cloud seul : batch CONVERT issu du précédent Apply AD, avec sa preuve State. Aucun accès AD. Copier le dossier complet.' } else { 'AD/Both : périmètre configuré ou identité, sans batch. Apply crée un nouveau batch Convert. AD seul : copier ensuite ce batch sur le serveur cloud.' } }
            'Recover' { if ($phase -eq 'Cloud') { 'Cloud seul : batch RECOVER issu de Apply AD + dossier CONVERT original dans Storage.BackupFolder. Produit un package RecoverFinalize si une restauration finale AD reste à faire ; aucune écriture AD, même avec RSAT.' } else { 'AD/Both : batch CONVERT ORIGINAL obligatoire. AD seul : copier le nouveau batch Recover ET le Convert original sur le serveur cloud.' } }
            'Finalize' { 'AD seulement : choisir le manifeste RecoverFinalize produit par Recover Cloud. Restaurer les derniers attributs confirmés par le cloud ; aucun appel cloud ici.' }
            'Check' { 'Lecture seule : batch CONVERT ou une identité UPN, sans écriture. Expect précise le résultat attendu ; Once fait un seul passage.' }
        }
        $c.OperationGuide.Text=$guide
        $c.Apply.IsEnabled=$false; $c.Preview.IsEnabled=$false; $c.ValidationText.Text=''
        $c.ConfirmationInfo.Text=''
        if (-not $g.Run) { $c.CommandText.Clear() }
        try {
            if ($c.ConfigPathText.Text.Trim() -cne $g.ConfigPath) { throw 'Recharger la configuration sélectionnée avant de lancer.' }
            $request=if ($g.Run) { $g.Run.Request } else { Get-PraGuiWindowRequest }
            $override=Get-PraTargetOverride -SearchBase $request.SearchBase -CsvPath $request.CsvPath -Identity $request.Identity
            $effective=if ($override.Count) { Read-PraGuiState $g.Root $g.ConfigPath -ScopeOverride $override } else { $g.State }
            if ($effective.ConfigError) { throw $effective.ConfigError }
            if ($request.CsvPath) {
                $entries=@(Read-PraTargetCsv -Path $effective.Config.Scope.CsvPath)
                $c.CsvInfo.Text='{0} objet(s) listé(s) · Identity · contenu vérifié à nouveau avant Apply' -f $entries.Count
            }
            $null=Resolve-PraGuiBatch $request.Batch (Get-PraGuiBatchType $request.Action $request.Phase) $g.State
            $c.CommandText.Text=(Get-PraGuiCommand $g.Root $g.ConfigPath $request).Display
            $c.Preview.IsEnabled=-not $busy
            $target=if ($request.Identity) { $request.Identity } else { 'Scope '+$request.Scope }
            if (-not $request.Identity -and $action -eq 'Convert' -and $phase -ne 'Cloud') {
                $configured=$effective.Config.Scope
                $target+=' · '+$configured.Mode+' '+$configured.SearchBase+' '+$configured.GroupDN+' '+$configured.CsvPath
            }
            $inputBatch=if ($request.Batch) { $request.Batch } elseif ($action -eq 'Convert') { 'NOUVEAU (aucun batch en entrée)' } else { 'aucun (identité)' }
            $c.ConfirmationInfo.Text='{0} · phase {1} · {2} · batch {3}. Preview obligatoire ; saisir exactement {4} pour autoriser Apply.' -f $action,$request.Phase,$target,$inputBatch,$action.ToUpperInvariant()
            if ($action -eq 'Check') { $c.ConfirmationInfo.Text='Check · Cloud · '+$target+' · batch '+$inputBatch+' · lecture seule, aucune écriture et aucun Apply.' }
            if ($g.Pending -and -not $busy -and $c.ConfirmationText.Text -ceq $action.ToUpperInvariant()) {
                $c.Apply.IsEnabled=(Get-PraGuiGuard $g.Root $g.ConfigPath $request) -ceq $g.Pending.Guard
                if (-not $c.Apply.IsEnabled) { $g.Pending=$null; $c.ValidationText.Text='Fichiers modifiés : nouveau Preview obligatoire.' }
            }
        } catch { $c.ValidationText.Text=$_.Exception.Message }
    } finally { $g.Updating=$false }
}

function Update-PraGuiState {
    $g=$script:Gui
    $g.Pending=$null; $g.Controls.ConfirmationText.Clear()
    $g.ConfigPath=$g.Controls.ConfigPathText.Text.Trim()
    $g.State=Read-PraGuiState $g.Root $g.ConfigPath
    $c=$g.Controls; $c.BatchGrid.ItemsSource=@($g.State.Batches)
    $c.BatchStatus.Text=$g.State.BatchError
    if ($g.State.ConfigError) { $c.ConfigStatus.Text='Configuration INVALIDE : '+$g.State.ConfigError; $c.HeaderInfo.Text='Configuration invalide' }
    else {
        $config=$g.State.Config
        $c.HeaderInfo.Text='{0} · {1}' -f $config.Environment,$config.Cloud.Organization
        $c.ConfigStatus.Text="Environment : $($config.Environment)`nConfiguration : $($g.ConfigPath)`nSauvegardes : $($config.Storage.BackupFolder)`nScope : $($config.Scope.Mode) · OU : $($config.Scope.SearchBase) · Groupe : $($config.Scope.GroupDN) · CSV : $($config.Scope.CsvPath)`nDC : $($config.DomainController) · Tenant : $($config.Cloud.Organization)`nPhase par défaut : $($config.Execution.Phase) · Entra Connect Sync : $($config.EntraConnect.Sync)`nLogs : $($config.Logging.Folder) · Rapports : $($config.Report.Folder)"
        if (-not $g.InitialPhaseSet) {
            $g.Updating=$true
            $g.ExecutionPhase=$config.Execution.Phase
            foreach ($item in $c.PhaseChoice.Items) { if ($item.Content -eq $config.Execution.Phase) { $c.PhaseChoice.SelectedItem=$item } }
            $g.Updating=$false; $g.InitialPhaseSet=$true
        }
    }
    Update-PraGuiSelection
}

function Open-PraGuiPath {
    param([string]$Path, [switch]$Folder)
    if (-not $Path) { return }
    if ($Folder -and (Test-Path -LiteralPath $Path -PathType Leaf)) { $Path=Split-Path $Path -Parent }
    if (-not (Test-Path -LiteralPath $Path)) { throw "File/folder missing: $Path" }
    $extension=[IO.Path]::GetExtension($Path)
    if (-not (Test-Path -LiteralPath $Path -PathType Container) -and $extension -notin @('.csv','.html','.txt','.log','.json')) { throw 'Only reports, logs and folders may be opened.' }
    $info=New-Object Diagnostics.ProcessStartInfo
    $info.FileName=$Path; $info.UseShellExecute=$true
    $null=[Diagnostics.Process]::Start($info)
}

function Invoke-PraGuiClick {
    param([string]$Name)
    $g=$script:Gui; $c=$g.Controls
    try {
        switch ($Name) {
            'Reload' { if (-not $g.Run) { Update-PraGuiState } }
            'BrowseConfig' {
                $dialog=New-Object Microsoft.Win32.OpenFileDialog; $dialog.Filter='Configuration (*.psd1)|*.psd1'
                if ($dialog.ShowDialog($g.Form)) { $c.ConfigPathText.Text=$dialog.FileName; Update-PraGuiState }
            }
            'BrowseBatch' {
                $dialog=New-Object Microsoft.Win32.OpenFileDialog; $dialog.Filter='Batch (*.json)|*.json'
                if ($dialog.ShowDialog($g.Form)) { $c.BatchText.Text=$dialog.FileName }
            }
            'BrowseBatchFolder' {
                Add-Type -AssemblyName System.Windows.Forms
                $dialog=New-Object Windows.Forms.FolderBrowserDialog
                try { if ($dialog.ShowDialog() -eq [Windows.Forms.DialogResult]::OK) { $c.BatchText.Text=$dialog.SelectedPath } }
                finally { $dialog.Dispose() }
            }
            'BrowseCsv' {
                $dialog=New-Object Microsoft.Win32.OpenFileDialog; $dialog.Filter='Liste (*.csv)|*.csv'
                if ($dialog.ShowDialog($g.Form)) { $c.CsvText.Text=$dialog.FileName }
            }
            'ChooseOu' { Start-PraGuiOuLookup }
            'Preview' { Start-PraGuiRun -Mode Preview }
            'Apply' { Start-PraGuiRun -Mode Apply }
            'CopyCommand' { [Windows.Clipboard]::SetText($c.CommandText.Text) }
            'OpenBatch' {
                $request=Get-PraGuiWindowRequest
                $batch=Resolve-PraGuiBatch $request.Batch (Get-PraGuiBatchType $request.Action $request.Phase) $g.State
                if ($batch) { Open-PraGuiPath $batch.Folder -Folder }
            }
            'CopyBatch' { if ($g.LastResult) { [Windows.Clipboard]::SetText([string]$g.LastResult.batchId) } }
            'OpenLog' { Open-PraGuiPath ([string](Get-PraGuiValue $g.LastResult 'logFile' '')) }
            'OpenCsv' { Open-PraGuiPath ([string](Get-PraGuiValue $g.LastResult 'csvReport' '')) }
            'OpenHtml' { Open-PraGuiPath ([string](Get-PraGuiValue $g.LastResult 'htmlReport' '')) }
            'OpenBackup' {
                $paths=@(Get-PraGuiValue $g.LastResult 'backupFiles' @())+@(Get-PraGuiValue $g.LastResult 'stateFiles' @())
                if ($paths.Count) { Open-PraGuiPath ([string]$paths[0]) -Folder }
            }
        }
    } catch { Add-PraGuiLine $_.Exception.Message 'Fail'; $c.ValidationText.Text=$_.Exception.Message }
}

function Get-PraGuiOuCommand {
    param([string]$Root, [string]$ConfigPath, [string]$ResultPath)
    $tokens=@('-NoProfile','-NonInteractive','-STA','-File',(Join-Path $Root 'module\PRA.Gui.Directory.ps1'),'-ConfigPath',$ConfigPath,'-ResultPath',$ResultPath)
    return [pscustomobject]@{ FilePath=(Get-PraGuiEngine); Arguments=(@($tokens | ForEach-Object { ConvertTo-PraGuiNativeArgument $_ }) -join ' ') }
}

function Start-PraGuiOuLookup {
    $g=$script:Gui; $c=$g.Controls
    if ($g.Run -or $g.OuLookup) { throw 'Attendre la fin de l''opération en cours.' }
    if ((Get-PraGuiChoice $c.ActionChoice) -ne 'Convert' -or (Get-PraGuiChoice $c.PhaseChoice) -notin @('AD','Both') -or (Get-PraGuiChoice $c.SourceChoice) -ne 'OU') {
        throw 'Le sélecteur OU est réservé à Convert AD / AD + cloud.'
    }
    if ($c.ConfigPathText.Text.Trim() -cne $g.ConfigPath) { throw 'Recharger la configuration sélectionnée.' }
    $folder=Join-Path $g.Root 'logs\gui'
    $null=New-Item -ItemType Directory -Path $folder -Force
    $base=Join-Path $folder ('ou-'+[guid]::NewGuid().ToString('N'))
    $command=Get-PraGuiOuCommand $g.Root $g.ConfigPath ($base+'.json')
    $child=Start-PraGuiChildProcess $command $g.Root ($base+'.events.jsonl')
    $g.Pending=$null; $c.ConfirmationText.Clear()
    $g.OuLookup=@{ Process=$child.Process; Output=$child.Output; Errors=$child.Errors; Path=($base+'.json'); Base=$base }
    foreach ($name in $script:GuiInputNames) { $c[$name].IsEnabled=$false }
    Update-PraGuiSelection
    $c.RunStatus.Text='Lecture des OU sur le DC configuré — aucune écriture AD'
    Add-PraGuiLine $c.RunStatus.Text
    $g.Timer.Start()
}

function Select-PraGuiOu {
    param([object[]]$Units, [string]$Server)
    $g=$script:Gui
    $xaml=@'
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation" xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
 Title="Choisir une OU" Width="780" Height="510" WindowStartupLocation="CenterOwner" FontFamily="Segoe UI"
 Background="{DynamicResource ApplicationBackgroundBrush}">
 <Grid Margin="18"><Grid.RowDefinitions><RowDefinition Height="Auto"/><RowDefinition Height="Auto"/><RowDefinition Height="*"/><RowDefinition Height="Auto"/></Grid.RowDefinitions>
 <TextBlock x:Name="Info" TextWrapping="Wrap" Margin="0,0,0,8" Foreground="{DynamicResource TextFillColorPrimaryBrush}"/>
 <TextBox x:Name="Filter" Grid.Row="1" Margin="0,0,0,8" ToolTip="Filtrer le nom ou le DN"/>
 <ListBox x:Name="Units" Grid.Row="2" DisplayMemberPath="DistinguishedName"/>
 <StackPanel Grid.Row="3" Orientation="Horizontal" HorizontalAlignment="Right" Margin="0,12,0,0">
 <Button x:Name="Select" Content="Choisir" IsDefault="True" Padding="14,6" Margin="0,0,8,0"/>
 <Button Content="Annuler" IsCancel="True" Padding="14,6"/></StackPanel></Grid>
</Window>
'@
    $dialog=[Windows.Markup.XamlReader]::Parse($xaml)
    $dialog.Resources.MergedDictionaries.Add($g.Form.Resources)
    if ($g.Form.IsVisible) { $dialog.Owner=$g.Form }
    $dialog.FindName('Info').Text="DC : $Server · choisir l'OU ; ses sous-OU seront incluses."
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
        [IO.File]::WriteAllText($lookup.Base+'.stdout.txt',$output)
        [IO.File]::WriteAllText($lookup.Base+'.stderr.txt',$errors)
        if (-not (Test-Path -LiteralPath $lookup.Path)) { throw "Lecture OU sans résultat. $errors" }
        $result=[IO.File]::ReadAllText($lookup.Path) | ConvertFrom-Json -ErrorAction Stop
        if ($lookup.Process.ExitCode -ne 0 -or $result.Success -ne $true -or $errors.Trim()) {
            throw ('Lecture OU refusée : '+[string](Get-PraGuiValue $result 'Error' $errors))
        }
        $units=@($result.Units); $server=[string]$result.Server
        Add-PraGuiLine ('{0} OU lues sur {1} ; aucune écriture.' -f $units.Count,$server) 'Ok'
    } catch { Add-PraGuiLine $_.Exception.Message 'Fail'; $g.Controls.ValidationText.Text=$_.Exception.Message }
    finally {
        $lookup.Process.Dispose(); $g.OuLookup=$null
        foreach ($name in $script:GuiInputNames) { $g.Controls[$name].IsEnabled=$true }
        $g.Controls.RunStatus.Text='Sélection OU terminée — aucune opération de conversion lancée'
        Update-PraGuiSelection
    }
    if ($units.Count) {
        $chosen=Select-PraGuiOu -Units $units -Server $server
        if ($chosen) { $g.Controls.OuText.Text=$chosen }
    }
    elseif ($server) { Add-PraGuiLine 'Aucune OU trouvée. Vous pouvez saisir directement un DN valide.' 'Warn' }
}

function Start-PraGuiRun {
    param([ValidateSet('Preview','Apply')][string]$Mode)
    $g=$script:Gui
    if ($g.Run -or $g.OuLookup) { throw 'An action or OU lookup is running. Wait for completion.' }
    $request=Get-PraGuiWindowRequest $Mode
    if ($g.Controls.ConfigPathText.Text.Trim() -cne $g.ConfigPath) { throw 'Reload the selected configuration first.' }
    $guard=Get-PraGuiGuard $g.Root $g.ConfigPath $request
    if ($Mode -eq 'Apply') {
        if (-not $g.Pending -or $g.Pending.Guard -cne $guard -or $g.Controls.ConfirmationText.Text -cne $request.Action.ToUpperInvariant()) {
            $g.Pending=$null; Update-PraGuiSelection
            throw 'Apply refused: a successful unchanged Preview and the exact confirmation are required.'
        }
    }
    $g.Pending=$null; $g.Controls.ConfirmationText.Clear()
    $folder=Join-Path $g.Root 'logs\gui'
    $null=New-Item -ItemType Directory -Path $folder -Force
    $base=Join-Path $folder ([guid]::NewGuid().ToString('N'))
    $command=Get-PraGuiCommand $g.Root $g.ConfigPath $request
    # Re-read immediately before launch, including after typed confirmation and work-folder creation.
    if ((Get-PraGuiGuard $g.Root $g.ConfigPath $request) -cne $guard) { throw 'Input files changed before launch. Run Preview again.' }
    $child=Start-PraGuiChildProcess $command $g.Root ($base+'.events.jsonl')
    $g.Run=@{
        Request=$request; Guard=$guard; Process=$child.Process; Output=$child.Output; Errors=$child.Errors
        EventPath=($base+'.events.jsonl'); Base=$base; Position=[long]0; Result=$null; ResultCount=0
        TransportIssues=(New-Object 'Collections.Generic.List[string]'); Clock=[Diagnostics.Stopwatch]::StartNew()
        Counts=@{Ok=0;Warn=0;Fail=0}
    }
    $g.LastResult=$null; $g.Lines.Clear(); $g.Controls.PreviewGrid.ItemsSource=$null
    $g.Controls.CommandText.Text=$command.Display; $g.Controls.ResultText.Text=''; $g.Controls.ResultBatch.Text=''; $g.Controls.NextStepsText.Clear()
    foreach ($name in @('OpenLog','OpenCsv','OpenHtml','CopyBatch','OpenBackup')) { $g.Controls[$name].IsEnabled=$false }
    foreach ($name in $script:GuiInputNames) { $g.Controls[$name].IsEnabled=$false }
    Update-PraGuiSelection
    Add-PraGuiLine ('Lancé : '+$command.Display)
    $g.Timer.Start()
}

function Invoke-PraGuiEvent {
    param($Record)
    $g=$script:Gui; $run=$g.Run; $c=$g.Controls
    switch ($Record.kind) {
        'start' { Add-PraGuiLine ([string](Get-PraGuiValue $Record 'title' 'Début')) }
        'step' {
            $index=[int](Get-PraGuiValue $Record 'index' 0); $total=[int](Get-PraGuiValue $Record 'total' 0)
            $c.RunStep.Text='{0}/{1} · {2}' -f $index,$total,(Get-PraGuiValue $Record 'title' '')
            if ($total -gt 0) { $c.RunProgress.Value=[Math]::Min(100,100*$index/$total) }
            Add-PraGuiLine $c.RunStep.Text
        }
        'item' {
            $status=[string](Get-PraGuiValue $Record 'status' 'Info')
            if ($run.Counts.ContainsKey($status)) { $run.Counts[$status]++ }
            if ($status -eq 'Fail') { $run.TransportIssues.Add('Engine emitted a Fail item.') }
            Add-PraGuiLine (([string](Get-PraGuiValue $Record 'text' ''))+' '+(Get-PraGuiValue $Record 'identity' '')) $status
        }
        'summary' { Add-PraGuiLine ((Get-PraGuiValue $Record 'title' '')+' '+((Get-PraGuiValue $Record 'values' @{}) | ConvertTo-Json -Compress -Depth 5)) ([string](Get-PraGuiValue $Record 'status' 'Info')) }
        'result' {
            $run.ResultCount++; $run.Result=$Record
            if ($run.ResultCount -gt 1) { $run.TransportIssues.Add('Multiple result events.') }
        }
    }
    $c.RunCounts.Text='OK {0} · Warn {1} · Fail {2}' -f $run.Counts.Ok,$run.Counts.Warn,$run.Counts.Fail
}

function Complete-PraGuiRun {
    $g=$script:Gui; $run=$g.Run; $c=$g.Controls
    $g.Timer.Stop()
    $pending=$null
    try {
        $output=$run.Output.Result; $stderr=$run.Errors.Result
        [IO.File]::WriteAllText($run.Base+'.stdout.txt',$output,(New-Object Text.UTF8Encoding($true)))
        [IO.File]::WriteAllText($run.Base+'.stderr.txt',$stderr,(New-Object Text.UTF8Encoding($true)))
        $exitCode=$run.Process.ExitCode
        $valid=Test-PraGuiResult $run.Result $run.Request $exitCode $run.TransportIssues.ToArray() $stderr
        $r=$run.Result
        $g.LastResult=if ($r) { $r } else { [pscustomobject]@{ logFile=($run.Base+'.stdout.txt'); batchId='' } }
        $c.ResultBatch.Text='Batch : '+(Get-PraGuiValue $r 'batchId' '')
        $c.NextStepsText.Text=(@(Get-PraGuiValue $r 'nextSteps' @()) -join "`r`n")
        foreach ($pair in @(@('OpenLog','logFile'),@('OpenCsv','csvReport'),@('OpenHtml','htmlReport'))) {
            $c[$pair[0]].IsEnabled=[bool](Get-PraGuiValue $g.LastResult $pair[1] '')
        }
        $c.CopyBatch.IsEnabled=[bool](Get-PraGuiValue $r 'batchId' '')
        $c.OpenBackup.IsEnabled=(@(Get-PraGuiValue $r 'backupFiles' @()).Count+@(Get-PraGuiValue $r 'stateFiles' @()).Count) -gt 0
        try {
            $csv=[string](Get-PraGuiValue $r 'csvReport' '')
            if ($csv) {
                $rows=@(Import-Csv -LiteralPath $csv -Delimiter ';' -Encoding UTF8 -ErrorAction Stop)
                foreach ($row in $rows) { if ($row.PSObject.Properties['IsShared']) { $row.IsShared=$row.IsShared -eq 'True' } }
                $c.PreviewGrid.ItemsSource=$rows
            }
        } catch {
            $run.TransportIssues.Add('Report unreadable: '+$_.Exception.Message)
            $valid=$false
        }
        if (-not $valid) {
            $c.ResultText.Text="ÉCHEC / résultat incomplet ou incohérent (code natif $exitCode). Apply verrouillé."
            foreach ($issue in $run.TransportIssues) { Add-PraGuiLine $issue 'Fail' }
            if ($stderr.Trim()) { Add-PraGuiLine $stderr.Trim() 'Fail' }
            Add-PraGuiLine ('Sorties conservées : '+$run.Base+'.stdout.txt / .stderr.txt') 'Fail'
        } else {
            $c.ResultText.Text='{0} · Success {1} · Pending {2} · Planned {3} · Skipped {4}' -f $r.status,$r.success,$r.pending,$r.planned,$r.skipped
            if ($exitCode -eq 2) { $c.ResultText.Text+=' — passage de relais / action restante, pas terminé' }
        }
        if (Test-PraGuiPreview $run.Result $run.Request $exitCode $run.TransportIssues.ToArray() $stderr) {
            try {
                $current=Get-PraGuiGuard $g.Root $g.ConfigPath $run.Request
                if ($current -ceq $run.Guard) { $pending=@{ Guard=$current; Request=$run.Request } }
                else { Add-PraGuiLine 'Fichiers modifiés pendant Preview : autorisation Apply refusée.' 'Warn' }
            } catch { Add-PraGuiLine $_.Exception.Message 'Fail' }
        }
    } catch {
        $pending=$null
        $c.ResultText.Text='Résultat / journal illisible : Apply verrouillé.'
        Add-PraGuiLine $_.Exception.Message 'Fail'
    } finally {
        $c.RunStatus.Text='{0} · {1:n1} s · processus terminé' -f $run.Request.Action,$run.Clock.Elapsed.TotalSeconds
        $run.Process.Dispose(); $g.Run=$null
        foreach ($name in $script:GuiInputNames) { $c[$name].IsEnabled=$true }
        $g.State=Read-PraGuiState $g.Root $g.ConfigPath; $c.BatchGrid.ItemsSource=@($g.State.Batches); $c.BatchStatus.Text=$g.State.BatchError
        $g.Pending=$pending
        Update-PraGuiSelection
    }
    if ($pending) { Add-PraGuiLine ('Preview validé. Confirmer exactement '+$run.Request.Action.ToUpperInvariant()+' ; tout changement impose un nouveau Preview.') 'Ok' }
}

function Invoke-PraGuiTick {
    $g=$script:Gui
    if (-not $g -or $g.InTick) { return }
    if ($g.OuLookup) { Complete-PraGuiOuLookup; return }
    if (-not $g.Run) { return }
    $g.InTick=$true
    try {
        $run=$g.Run; $exited=$run.Process.HasExited
        try {
            do {
                $read=Read-PraGuiEvents $run.EventPath $run.Position
                $old=$run.Position; $run.Position=$read.Position
                foreach ($issue in $read.Errors) { $run.TransportIssues.Add($issue) }
                foreach ($record in $read.Events) { Invoke-PraGuiEvent $record }
            } while ($exited -and $read.Position -gt $old -and (Get-Item -LiteralPath $run.EventPath).Length -gt $read.Position)
            if ($exited -and $read.HasPartial) { $run.TransportIssues.Add('Unterminated event line at process exit.') }
        } catch { $run.TransportIssues.Add($_.Exception.Message) }
        $g.Controls.RunStatus.Text='{0} · {1} · {2:n1} s — attendre la fin' -f $run.Request.Action,$run.Request.Mode,$run.Clock.Elapsed.TotalSeconds
        if ($exited -and $run.Output.IsCompleted -and $run.Errors.IsCompleted) { Complete-PraGuiRun }
    } finally { $g.InTick=$false }
}

function New-PraGuiWindow {
    <# Constructs and binds the window without ShowDialog and without starting an operation. #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Root, [string]$ConfigPath='', [string]$Version='', [ValidateSet('System','Light','Dark')][string]$Theme='System')
    if ([Threading.Thread]::CurrentThread.GetApartmentState() -ne 'STA') { throw 'WPF requires an STA host (powershell.exe -STA or pwsh.exe -STA).' }
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
    $script:Gui=@{
        Form=$form; Controls=$controls; Timer=$timer; Root=[IO.Path]::GetFullPath($Root); ConfigPath=$ConfigPath
        State=$null; Run=$null; OuLookup=$null; Pending=$null; LastResult=$null; Updating=$true; InTick=$false; InitialPhaseSet=$false
        ExecutionPhase='Both'; LastAction='Convert'
        Lines=(New-Object 'Collections.ObjectModel.ObservableCollection[object]')
        Theme=$themeInfo; HandlerNames=@()
    }
    $g=$script:Gui; $c=$controls
    $c.ConfigPathText.Text=$ConfigPath; $c.VersionText.Text='Version '+$Version
    $c.HostStatus.Text='Hôte : '+$env:COMPUTERNAME+' · UI : '+$PSVersionTable.PSEdition+' '+$PSVersionTable.PSVersion+' · moteur : '+(Get-PraGuiEngine)+' · Fluent natif : '+$themeInfo.Fluent
    $c.ActivityLog.ItemsSource=$g.Lines
    foreach ($name in @('BrowseConfig','Reload','BrowseBatch','BrowseBatchFolder','OpenBatch','Preview','Apply','CopyCommand','OpenLog','OpenCsv','OpenHtml','CopyBatch','OpenBackup','BrowseCsv','ChooseOu')) {
        $c[$name].Tag=$name
        $c[$name].Add_Click({ param($buttonControl) Invoke-PraGuiClick ([string]$buttonControl.Tag) })
        $g.HandlerNames+=($name+'.Click')
    }
    foreach ($name in @('ActionChoice','PhaseChoice','ScopeChoice','ExpectChoice','SourceChoice')) {
        $c[$name].Add_SelectionChanged({ Update-PraGuiSelection -Invalidate })
        $g.HandlerNames+=($name+'.SelectionChanged')
    }
    $c.BatchChoice.Add_SelectionChanged({
        if (-not $script:Gui.Updating -and $script:Gui.Controls.BatchChoice.SelectedItem) { $script:Gui.Controls.BatchText.Text=$script:Gui.Controls.BatchChoice.SelectedItem.Path }
    })
    foreach ($name in @('BatchText','IdentityText','LimitText','ConfigPathText','OuText','CsvText')) {
        $c[$name].Add_TextChanged({ Update-PraGuiSelection -Invalidate }); $g.HandlerNames+=($name+'.TextChanged')
    }
    $c.ConfirmationText.Add_TextChanged({ Update-PraGuiSelection })
    $c.OnceCheck.Add_Checked({ Update-PraGuiSelection -Invalidate }); $c.OnceCheck.Add_Unchecked({ Update-PraGuiSelection -Invalidate })
    $c.ThemeChoice.Add_SelectionChanged({
        $info=Initialize-PraGuiTheme (Get-PraGuiChoice $script:Gui.Controls.ThemeChoice)
        $script:Gui.Theme=$info; Set-PraGuiTheme $script:Gui.Form $info
    })
    $timer.Add_Tick({ Invoke-PraGuiTick })
    $form.Add_Closing({
        param($windowControl,$closingArguments)
        if ($script:Gui.Run -or $script:Gui.OuLookup) {
            $closingArguments.Cancel=$true
            Add-PraGuiLine ($windowControl.Title+' : fermeture refusée, action atomique en cours. Attendre la fin, sans tuer le moteur.') 'Warn'
        }
    })
    $form.Add_Closed({ $script:Gui.Timer.Stop(); $script:Gui.Pending=$null })
    $g.HandlerNames+=@('BatchChoice.SelectionChanged','ConfirmationText.TextChanged','OnceCheck.Checked','OnceCheck.Unchecked','ThemeChoice.SelectionChanged','Timer.Tick','Form.Closing','Form.Closed')
    $g.Updating=$false
    Update-PraGuiState
    return $g
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

function Show-PraGui {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Root, [string]$ConfigPath='', [string]$Version='')
    $window=New-PraGuiWindow -Root $Root -ConfigPath $ConfigPath -Version $Version
    $null=$window.Form.ShowDialog()
}

Export-ModuleMember -Function Show-PraGui,New-PraGuiWindow,New-PraGuiRequest,Get-PraGuiBatchType,Get-PraGuiCommand,ConvertTo-PraGuiNativeArgument,Get-PraGuiNativeModulePath,Read-PraGuiState,Read-PraGuiBatch,Resolve-PraGuiBatch,Get-PraGuiGuard,Test-PraGuiResult,Test-PraGuiPreview,Read-PraGuiEvents,Start-PraGuiChildProcess,Get-PraGuiOuCommand
