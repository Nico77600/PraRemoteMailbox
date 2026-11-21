#Requires -Version 7.5
# Synthetic only: no AD, Exchange, Graph, network or production configuration.
BeforeAll {
    $script:GuiEvidence=Join-Path $PSScriptRoot ('evidence\gui-'+[guid]::NewGuid().ToString('N'))
    $null=New-Item -ItemType Directory -Path $script:GuiEvidence -Force
    # Controlled package copy (signature call substituted, real bootstrap/verifier/hash logic); see IntegrityFixture.ps1.
    . (Join-Path $PSScriptRoot 'IntegrityFixture.ps1')
    $script:GuiProjectRoot=Join-Path $script:GuiEvidence 'package-fixture'
    New-PraIntegrityFixture -SourcePackage ([IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\package'))) -Destination $script:GuiProjectRoot -Changelog ([IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\CHANGELOG.md')))
    $script:GuiModule=Join-Path $script:GuiProjectRoot 'module\PRA.Gui.psm1'
    $script:GuiCommon=Join-Path $script:GuiProjectRoot 'module\PRA.Common.psm1'
    Import-Module $script:GuiCommon -Force
    Import-Module $script:GuiModule -Force
    $script:GuiEncoding=New-Object Text.UTF8Encoding($true)

    function Write-GuiTestFile {
        param([string]$Path,[string]$Text)
        $null=New-Item -ItemType Directory -Path (Split-Path $Path -Parent) -Force
        [IO.File]::WriteAllText($Path,$Text,$script:GuiEncoding)
    }
    function Write-GuiTestJson {
        param([string]$Path,$Data)
        Write-GuiTestFile $Path ($Data | ConvertTo-Json -Depth 15)
        Write-GuiTestFile ($Path+'.sha256') ((Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant())
    }
    function New-GuiTestRoot {
        $root=Join-Path $script:GuiEvidence ([guid]::NewGuid().ToString('N'))
        $null=New-Item -ItemType Directory -Path $root -Force
        $config=Join-Path $root "config space's.psd1"
        Write-GuiTestFile $config "@{Environment='GuiSynthetic'; Scope=@{Mode='Auto'}; Licensing=@{Enabled=`$false}; EntraConnect=@{Sync=`$false}; Execution=@{Phase='AD'}}"
        Write-GuiTestFile (Join-Path $root 'Invoke-PraRemoteMailbox.ps1') '# Synthetic entry marker'
        Write-GuiTestFile (Join-Path $root 'module\PRA.Synthetic.psm1') '# Synthetic runtime marker; never imported'
        return @{Root=$root;Config=$config}
    }
    function New-GuiTestBatch {
        param($Runtime,[string]$Operation='Convert',[string]$SourceHash='')
        $id=[guid]::NewGuid().ToString('N')
        $folder=Join-Path $Runtime.Root ('Backups\'+$(if($Operation -eq 'RecoverFinalize'){'Finalize-'}else{'Batch-'})+$id)
        $path=Join-Path $folder ($Operation+'-fixture.json')
        $record=@{ObjectGuid=[guid]::NewGuid().ToString();SamAccountName='synthetic';UserPrincipalName='synthetic@example.invalid';IsShared=$false}
        $data=@{SchemaVersion=2;Operation=$Operation;Environment='GuiSynthetic';BatchId=$id;SourceBackupHash=$SourceHash;Records=@($record);Items=@($record)}
        Write-GuiTestJson $path $data
        Write-GuiTestFile (Join-Path $folder 'raw.data.clixml') '<SyntheticData />'
        $proof=@{SchemaVersion=2;Operation=$Operation;Kind='ADVerified';Environment='GuiSynthetic';BackupFile=[IO.Path]::GetFileName($path);BackupHash=(Get-FileHash -LiteralPath $path).Hash.ToLowerInvariant();SourceBackupHash=$SourceHash;Records=@(@{ObjectGuid=$record.ObjectGuid;ADVerified=$true})}
        $proofPath=Join-Path $folder ('State-'+$id+'.json')
        Write-GuiTestJson $proofPath $proof
        return @{Path=$path;Folder=$folder;Id=$id;Proof=$proofPath;Data=$data}
    }
    function New-GuiTestResult {
        param($Request,[int]$ExitCode=0,[int]$Planned=1,[int]$Pending=0,[int]$Success=0)
        return [pscustomobject]@{
            kind='result';status=$(if($ExitCode -eq 2){'Pending'}elseif($Planned){'Planned'}else{'Success'})
            exitCode=$ExitCode;action=$Request.Action;mode=$Request.Mode;phase=$Request.Phase
            success=$Success;error=0;pending=$Pending;skipped=0;planned=$Planned;total=($Success+$Planned+$Pending);issues=@()
        }
    }
}

Describe 'Remote GUI action/phase contracts' {
    It 'maps every operation to its required batch type' -TestCases @(
        @{Action='Convert';Phase='Both';Type=''}
        @{Action='Convert';Phase='AD';Type=''}
        @{Action='Convert';Phase='Cloud';Type='Convert'}
        @{Action='Recover';Phase='Both';Type='Convert'}
        @{Action='Recover';Phase='AD';Type='Convert'}
        @{Action='Recover';Phase='Cloud';Type='Recover'}
        @{Action='Finalize';Phase='AD';Type='RecoverFinalize'}
        @{Action='Check';Phase='Cloud';Type='Convert'}
    ) {
        param($Action,$Phase,$Type)
        Get-PraGuiBatchType $Action $Phase | Should -BeExactly $Type
        $batch=if($Type){'01234567'}else{''}
        $r=New-PraGuiRequest -Action $Action -Phase $Phase -Batch $batch
        $command=Get-PraGuiCommand -Root 'C:\Synthetic root' -ConfigPath "C:\Synthetic root\config's.psd1" -Request $r
        $command.FilePath | Should -BeExactly (Join-Path $PSHOME 'pwsh.exe')
        $command.Tokens | Should -Contain '-NoProfile'
        # An interactive cloud sign-in (Windows broker) must be allowed; stdin is closed by the launcher instead.
        $command.Tokens | Should -Not -Contain '-NonInteractive'
        $command.Tokens | Should -Contain '-STA'
        if($Action -in @('Convert','Recover')) {
            $command.Tokens | Should -Contain '-Phase'
            $command.Tokens | Should -Contain $Phase
        } else { $command.Tokens | Should -Not -Contain '-Phase' }
        $command.Tokens | Should -Not -Contain '-Force'
        $command.Display | Should -Match "config''s.psd1"
    }
    It 'rejects unavailable parameters and missing targets' {
        { New-PraGuiRequest -Action Convert -Phase AD -Batch '01234567' } | Should -Throw '*must not*'
        { New-PraGuiRequest -Action Convert -Phase Both -Batch '01234567' } | Should -Throw
        { New-PraGuiRequest -Action Convert -Phase Cloud } | Should -Throw
        { New-PraGuiRequest -Action Recover -Phase AD } | Should -Throw
        { New-PraGuiRequest -Action Recover -Phase Cloud } | Should -Throw
        { New-PraGuiRequest -Action Finalize } | Should -Throw
        { New-PraGuiRequest -Action Check } | Should -Throw
        { New-PraGuiRequest -Action Check -Identity 'synthetic@example.invalid' -Mode Apply } | Should -Throw '*read-only*'
        { New-PraGuiRequest -Action Convert -Phase Cloud -Batch '01234567' -MaxObjects 1 } | Should -Throw
        { New-PraGuiRequest -Identity "bad`nvalue" } | Should -Throw
        { New-PraGuiRequest -Phase Cloud -Batch '01234567' -SearchBase 'OU=Selected,DC=example,DC=invalid' } | Should -Throw
        { New-PraGuiRequest -Action Recover -Batch '01234567' -CsvPath 'targets.csv' } | Should -Throw
        { New-PraGuiRequest -SearchBase 'OU=Selected' -CsvPath 'targets.csv' } | Should -Throw
        { New-PraGuiRequest -Identity 'one@example.invalid' -CsvPath 'targets.csv' } | Should -Throw
    }
    It 'passes selected OU and CSV paths only to Convert AD/Both, preserving the type filter' {
        foreach ($phase in @('AD','Both')) {
            $r=New-PraGuiRequest -Phase $phase -SearchBase 'OU=Selected,DC=example,DC=invalid' -Scope SharedOnly
            $c=Get-PraGuiCommand 'C:\Synthetic' 'C:\Synthetic\config.psd1' $r
            $c.Tokens | Should -Contain '-SearchBase'
            $c.Tokens | Should -Contain 'OU=Selected,DC=example,DC=invalid'
            $c.Tokens | Should -Contain 'SharedOnly'
            $r=New-PraGuiRequest -Phase $phase -CsvPath "C:\Synthetic\list's.csv"
            (Get-PraGuiCommand 'C:\Synthetic' 'C:\Synthetic\config.psd1' $r).Tokens | Should -Contain '-CsvPath'
        }
    }
    It 'passes only supported Remote parameters and Force only for Apply' {
        $r=New-PraGuiRequest -Action Check -Identity 'synthetic@example.invalid' -Expect Retained -Once $true
        $command=Get-PraGuiCommand 'C:\Synthetic' 'C:\Synthetic\config.psd1' $r
        $command.Tokens | Should -Contain '-Expect'
        $command.Tokens | Should -Contain 'Retained'
        $command.Tokens | Should -Contain '-Once'
        $command.Tokens | Should -Not -Contain '-MaxObjects'
        $command.Tokens | Should -Not -Contain '-IdentityPath'
        $r=New-PraGuiRequest -Action Convert -Phase AD -Mode Apply -MaxObjects 3
        $command=Get-PraGuiCommand 'C:\Synthetic' 'C:\Synthetic\config.psd1' $r
        $command.Tokens | Should -Contain '-Force'
        $command.Tokens | Should -Contain '-MaxObjects'
    }
    It 'starts the engine child with the PowerShell 7 that hosts the window and leaves the module path to it' {
        Get-PraGuiEngine | Should -BeExactly (Join-Path $PSHOME 'pwsh.exe')
        Test-Path -LiteralPath (Get-PraGuiEngine) -PathType Leaf | Should -BeTrue
        # The Windows PowerShell 5.1 module-path rewriting of 2.x is gone: the child inherits PSModulePath and adds its own paths.
        Get-Command Get-PraGuiNativeModulePath -ErrorAction SilentlyContinue | Should -BeNullOrEmpty
        (Get-Content -LiteralPath $script:GuiModule -Raw) | Should -Not -Match "EnvironmentVariables\['PSModulePath'\]"
    }
    It 'refuses the window without the native Fluent theme instead of falling back to classic controls' {
        $text=Get-Content -LiteralPath $script:GuiModule -Raw
        $text | Should -Match '(?s)function Initialize-PraGuiTheme.*?if \(-not \$property\) \{ throw ''The window requires the native Fluent theme'
        $text | Should -Not -Match 'Fluent=\(\$null -ne \$property\)'
    }
}

Describe 'Remote GUI local metadata and content guards' {
    It 'guards the selected CSV contents instead of the configured list and invalidates OU switching' {
        $runtime=New-GuiTestRoot
        $path=Join-Path $runtime.Root 'selected.csv'
        Write-GuiTestFile $path "Identity`r`nsynthetic@example.invalid"
        $r=New-PraGuiRequest -Phase AD -CsvPath $path
        $before=Get-PraGuiGuard $runtime.Root $runtime.Config $r
        Write-GuiTestFile $path "Identity`r`nother@example.invalid"
        Get-PraGuiGuard $runtime.Root $runtime.Config $r | Should -Not -Be $before
        $r=New-PraGuiRequest -Phase AD -SearchBase 'OU=First,DC=example,DC=invalid'
        $before=Get-PraGuiGuard $runtime.Root $runtime.Config $r
        $r=New-PraGuiRequest -Phase AD -SearchBase 'OU=Second,DC=example,DC=invalid'
        Get-PraGuiGuard $runtime.Root $runtime.Config $r | Should -Not -Be $before
        Write-GuiTestFile $path "Wrong`r`nsynthetic@example.invalid"
        { Get-PraGuiGuard $runtime.Root $runtime.Config (New-PraGuiRequest -Phase AD -CsvPath $path) } | Should -Throw
    }
    It 'surfaces bad configuration and corrupt metadata, never labels them ready' {
        $runtime=New-GuiTestRoot
        $state=Read-PraGuiState $runtime.Root (Join-Path $runtime.Root 'missing.psd1')
        $state.ConfigError | Should -Not -BeNullOrEmpty
        $batch=New-GuiTestBatch $runtime
        Write-GuiTestFile $batch.Path 'not json'
        $state=Read-PraGuiState $runtime.Root $runtime.Config
        $state.Batches.Count | Should -Be 1
        $state.Batches[0].Valid | Should -BeFalse
        $state.Batches[0].Status | Should -Match 'INVALID'
        { Resolve-PraGuiBatch $batch.Path 'Convert' $state } | Should -Throw
        Write-GuiTestFile $runtime.Config '@{Environment="invalid environment"}'
        (Read-PraGuiState $runtime.Root $runtime.Config).ConfigError | Should -Not -BeNullOrEmpty
    }
    It 'accepts exact files, folders and IDs only with the correct type/environment/hash' {
        $runtime=New-GuiTestRoot
        $convert=New-GuiTestBatch $runtime
        $recover=New-GuiTestBatch $runtime 'Recover'
        $state=Read-PraGuiState $runtime.Root $runtime.Config
        (Resolve-PraGuiBatch $convert.Path 'Convert' $state).Valid | Should -BeTrue
        (Resolve-PraGuiBatch $convert.Folder 'Convert' $state).Path | Should -Be $convert.Path
        (Resolve-PraGuiBatch $convert.Id.Substring(0,8) 'Convert' $state).Path | Should -Be $convert.Path
        { Resolve-PraGuiBatch $recover.Path 'Convert' $state } | Should -Throw '*Expected Convert*'
        $convert.Data.Environment='OtherSynthetic'
        Write-GuiTestJson $convert.Path $convert.Data
        (Read-PraGuiBatch $convert.Path 'GuiSynthetic').Valid | Should -BeFalse
        $convert.Data.Environment='GuiSynthetic'
        Write-GuiTestJson $convert.Path $convert.Data
        Write-GuiTestFile ($convert.Path+'.sha256') 'bad'
        (Read-PraGuiBatch $convert.Path 'GuiSynthetic').Valid | Should -BeFalse
    }
    It 'accepts native lowercase SHA-256 values and uppercase compatibility for schema <Schema>' -TestCases @(
        @{Schema=2;UpperCase=$false}
        @{Schema=3;UpperCase=$false}
        @{Schema=2;UpperCase=$true}
        @{Schema=3;UpperCase=$true}
    ) {
        param($Schema,$UpperCase)
        $runtime=New-GuiTestRoot
        $convert=New-GuiTestBatch $runtime
        $convert.Data.SchemaVersion=$Schema
        $convert.Data.RawFormat='PraDataOnlyClixml-v1'
        Write-GuiTestJson $convert.Path $convert.Data
        $proof=[IO.File]::ReadAllText($convert.Proof)|ConvertFrom-Json -DateKind String
        $proof.BackupHash=(Get-FileHash -LiteralPath $convert.Path).Hash.ToLowerInvariant()
        Write-GuiTestJson $convert.Proof $proof
        $sourceHash=(Get-FileHash -LiteralPath $convert.Path).Hash.ToLowerInvariant()
        if($UpperCase){$sourceHash=$sourceHash.ToUpperInvariant()}
        $recover=New-GuiTestBatch $runtime 'Recover' $sourceHash
        foreach($path in @($convert.Path,$convert.Proof,$recover.Path,$recover.Proof)) {
            $hash=(Get-FileHash -LiteralPath $path).Hash
            if(-not $UpperCase){$hash=$hash.ToLowerInvariant()}
            Write-GuiTestFile ($path+'.sha256') $hash
        }
        (Read-PraGuiBatch $convert.Path 'GuiSynthetic').Valid | Should -BeTrue
        Get-PraGuiGuard $runtime.Root $runtime.Config (New-PraGuiRequest -Action Convert -Phase Cloud -Batch $convert.Path) | Should -Not -BeNullOrEmpty
        Get-PraGuiGuard $runtime.Root $runtime.Config (New-PraGuiRequest -Action Recover -Phase Cloud -Batch $recover.Path) | Should -Not -BeNullOrEmpty
    }
    It 'deduplicates identical ID copies but preserves ambiguity for different contents' {
        $runtime=New-GuiTestRoot
        $convert=New-GuiTestBatch $runtime
        $recover=New-GuiTestBatch $runtime 'Recover' ((Get-FileHash -LiteralPath $convert.Path).Hash.ToLowerInvariant())
        $finalize=New-GuiTestBatch $runtime 'RecoverFinalize'
        foreach($folder in @($recover.Folder,$finalize.Folder)){
            Copy-Item -LiteralPath $convert.Path -Destination $folder
            Copy-Item -LiteralPath ($convert.Path+'.sha256') -Destination $folder
        }
        $state=Read-PraGuiState $runtime.Root $runtime.Config
        $resolved=Resolve-PraGuiBatch $convert.Id.Substring(0,8) 'Convert' $state
        $resolved.Path | Should -Be $convert.Path
        $resolved.CopyPaths.Count | Should -Be 3
        $r=New-PraGuiRequest -Action Recover -Phase AD -Batch $convert.Id.Substring(0,8)
        $before=Get-PraGuiGuard $runtime.Root $runtime.Config $r
        Write-GuiTestFile (Join-Path $finalize.Folder 'copy.raw.clixml') '<CopiedArtifact />'
        Get-PraGuiGuard $runtime.Root $runtime.Config $r | Should -Not -Be $before
        $copy=Join-Path $finalize.Folder ([IO.Path]::GetFileName($convert.Path))
        $different=[IO.File]::ReadAllText($copy)|ConvertFrom-Json -DateKind String
        $different.Records[0].SamAccountName='different-synthetic'
        Write-GuiTestJson $copy $different
        $state=Read-PraGuiState $runtime.Root $runtime.Config
        { Resolve-PraGuiBatch $convert.Id 'Convert' $state } | Should -Throw '*ambiguous*'
    }
    It 'invalidates the guard when configuration content changes without timestamp changes' {
        $runtime=New-GuiTestRoot
        $r=New-PraGuiRequest -Phase AD
        $before=Get-PraGuiGuard $runtime.Root $runtime.Config $r
        $date=(Get-Item -LiteralPath $runtime.Config).LastWriteTimeUtc
        [IO.File]::AppendAllText($runtime.Config,"`r`n# Content change",$script:GuiEncoding)
        (Get-Item -LiteralPath $runtime.Config).LastWriteTimeUtc=$date
        Get-PraGuiGuard $runtime.Root $runtime.Config $r | Should -Not -Be $before
    }
    It 'invalidates Preview when an engine runtime module is changed, added or removed' {
        $runtime=New-GuiTestRoot
        $r=New-PraGuiRequest -Phase AD
        $module=Join-Path $runtime.Root 'module\PRA.Synthetic.psm1'
        $before=Get-PraGuiGuard $runtime.Root $runtime.Config $r
        Write-GuiTestFile $module '# Changed synthetic runtime; never imported'
        Get-PraGuiGuard $runtime.Root $runtime.Config $r | Should -Not -Be $before
        $before=Get-PraGuiGuard $runtime.Root $runtime.Config $r
        $extra=Join-Path $runtime.Root 'module\PRA.Added.psm1'
        Write-GuiTestFile $extra '# Added synthetic runtime; never imported'
        Get-PraGuiGuard $runtime.Root $runtime.Config $r | Should -Not -Be $before
        $before=Get-PraGuiGuard $runtime.Root $runtime.Config $r
        Remove-Item -LiteralPath $extra -Force
        Get-PraGuiGuard $runtime.Root $runtime.Config $r | Should -Not -Be $before
    }
    It 'invalidates phase, scope, identity, limit and Once switching' {
        $runtime=New-GuiTestRoot
        $r=New-PraGuiRequest -Phase AD
        $before=Get-PraGuiGuard $runtime.Root $runtime.Config $r
        foreach($change in @(@{Phase='Both'},@{Scope='SharedOnly'},@{Identity='synthetic@example.invalid'},@{MaxObjects=1},@{Once=$true})) {
            $modified=New-PraGuiRequest -Phase AD
            foreach($key in $change.Keys){$modified[$key]=$change[$key]}
            Get-PraGuiGuard $runtime.Root $runtime.Config $modified | Should -Not -Be $before
        }
    }
    It 'requires AD proof for Convert Cloud and the ORIGINAL Convert source for Recover Cloud' {
        $runtime=New-GuiTestRoot
        $convert=New-GuiTestBatch $runtime
        $request=New-PraGuiRequest -Action Convert -Phase Cloud -Batch $convert.Path
        $before=Get-PraGuiGuard $runtime.Root $runtime.Config $request
        Write-GuiTestFile (Join-Path $convert.Folder 'raw.data.clixml') '<ChangedSyntheticData />'
        Get-PraGuiGuard $runtime.Root $runtime.Config $request | Should -Not -Be $before
        $before=Get-PraGuiGuard $runtime.Root $runtime.Config $request
        $proof=[IO.File]::ReadAllText($convert.Proof)|ConvertFrom-Json -DateKind String
        $proof|Add-Member -NotePropertyName SyntheticChange -NotePropertyValue 'content'
        Write-GuiTestJson $convert.Proof $proof
        Get-PraGuiGuard $runtime.Root $runtime.Config $request | Should -Not -Be $before
        Write-GuiTestFile $convert.Proof '{broken'
        { Get-PraGuiGuard $runtime.Root $runtime.Config $request } | Should -Throw
        $convert=New-GuiTestBatch $runtime
        $recover=New-GuiTestBatch $runtime 'Recover' ((Get-FileHash -LiteralPath $convert.Path).Hash)
        $request=New-PraGuiRequest -Action Recover -Phase Cloud -Batch $recover.Path
        $before=Get-PraGuiGuard $runtime.Root $runtime.Config $request
        Write-GuiTestFile (Join-Path $convert.Folder 'raw.data.clixml') '<ChangedOriginal />'
        Get-PraGuiGuard $runtime.Root $runtime.Config $request | Should -Not -Be $before
        Remove-Item -LiteralPath $convert.Folder -Recurse -Force
        { Get-PraGuiGuard $runtime.Root $runtime.Config $request } | Should -Throw '*ORIGINAL Convert*'
    }
    It 'guards configured CSV inputs and a Finalize manifest package as well as the selected batch' {
        $runtime=New-GuiTestRoot
        $inputPath=Join-Path $runtime.Root 'scope.csv'
        Write-GuiTestFile $inputPath "Identity`nsynthetic@example.invalid"
        Write-GuiTestFile $runtime.Config "@{Environment='GuiSynthetic'; Scope=@{Mode='Csv';CsvPath='.\scope.csv'};Licensing=@{Enabled=`$false};EntraConnect=@{Sync=`$false}}"
        $r=New-PraGuiRequest -Phase AD
        $before=Get-PraGuiGuard $runtime.Root $runtime.Config $r
        Write-GuiTestFile $inputPath "Identity`nother@example.invalid"
        Get-PraGuiGuard $runtime.Root $runtime.Config $r | Should -Not -Be $before
        $package=New-GuiTestBatch $runtime 'RecoverFinalize'
        $r=New-PraGuiRequest -Action Finalize -Batch $package.Path
        $before=Get-PraGuiGuard $runtime.Root $runtime.Config $r
        Write-GuiTestFile (Join-Path $package.Folder 'raw.data.clixml') '<ChangedFinalizeSource />'
        Get-PraGuiGuard $runtime.Root $runtime.Config $r | Should -Not -Be $before
        $wrong=New-GuiTestBatch $runtime 'Recover'
        $state=Read-PraGuiState $runtime.Root $runtime.Config
        { Resolve-PraGuiBatch $wrong.Path 'RecoverFinalize' $state } | Should -Throw
    }
}

Describe 'Remote GUI completed Preview authorization' {
    It 'accepts planned Preview and Pending Cloud targets without requiring Planned > 0' {
        $r=New-PraGuiRequest -Phase AD
        Test-PraGuiPreview (New-GuiTestResult $r) $r 0 | Should -BeTrue
        $r=New-PraGuiRequest -Phase Cloud -Batch '01234567'
        Test-PraGuiPreview (New-GuiTestResult $r -ExitCode 2 -Planned 0 -Pending 1) $r 2 | Should -BeTrue
        Test-PraGuiPreview (New-GuiTestResult $r -Planned 0 -Success 1) $r 0 | Should -BeTrue
    }
    It 'never authorizes failed, absent, inconsistent, zero-target or skipped-only results' {
        $r=New-PraGuiRequest -Phase AD
        Test-PraGuiPreview $null $r 0 | Should -BeFalse
        Test-PraGuiPreview (New-GuiTestResult $r) $r 1 | Should -BeFalse
        Test-PraGuiPreview (New-GuiTestResult $r) $r 2 | Should -BeFalse
        Test-PraGuiPreview (New-GuiTestResult $r -Planned 0) $r 0 | Should -BeFalse
        $result=New-GuiTestResult $r -Planned 0; $result.skipped=1; $result.total=1
        Test-PraGuiPreview $result $r 0 | Should -BeFalse
        foreach($change in @(@{action='Recover'},@{mode='Apply'},@{phase='Both'},@{error=1},@{status='Failed'},@{issues=@('engine error')},@{total=9},@{exitCode=1})) {
            $result=New-GuiTestResult $r
            foreach($key in $change.Keys){$result.$key=$change[$key]}
            Test-PraGuiPreview $result $r 0 | Should -BeFalse
        }
        $result=New-GuiTestResult $r
        $result.PSObject.Properties.Remove('total')
        Test-PraGuiPreview $result $r 0 | Should -BeFalse
        Test-PraGuiPreview (New-GuiTestResult $r) $r 0 @('malformed event') | Should -BeFalse
        Test-PraGuiPreview (New-GuiTestResult $r) $r 0 @() 'stderr failure' | Should -BeFalse
    }
}

Describe 'Remote GUI event and child-process boundary' {
    It 'reads only complete JSONL lines, preserves byte positions and rejects malformed events' {
        $path=Join-Path $script:GuiEvidence 'partial.events.jsonl'
        [IO.File]::WriteAllText($path,"{`"kind`":`"step`",`"index`":1,`"total`":2}`n{`"kind`":`"item`",`"text`":`"é",(New-Object Text.UTF8Encoding($false)))
        $first=Read-PraGuiEvents $path
        $first.Events.Count | Should -Be 1
        $first.HasPartial | Should -BeTrue
        [IO.File]::AppendAllText($path,"`"}`n",(New-Object Text.UTF8Encoding($false)))
        $second=Read-PraGuiEvents $path $first.Position
        $second.Events.Count | Should -Be 1
        $second.Events[0].text | Should -BeExactly 'é'
        $second.HasPartial | Should -BeFalse
        [IO.File]::AppendAllText($path,"{invalid}`n",(New-Object Text.UTF8Encoding($false)))
        (Read-PraGuiEvents $path $second.Position).Errors.Count | Should -Be 1
        (Read-PraGuiEvents $path 99999).Errors.Count | Should -Be 1
    }
    It 'handles a complete JSONL record larger than 1MB and its following result without losing partial positions' {
        $path=Join-Path $script:GuiEvidence 'large.events.jsonl'
        $encoding=[Text.UTF8Encoding]::new($false)
        $text=('x'*1153434)+'é'
        $large=(@{kind='item';status='Info';text=$text}|ConvertTo-Json -Compress)
        $request=New-PraGuiRequest -Phase AD
        $resultLine=(New-GuiTestResult $request|ConvertTo-Json -Compress -Depth 8)
        [IO.File]::WriteAllText($path,$large+"`n"+$resultLine+"`n",$encoding)
        $complete=Read-PraGuiEvents $path
        $complete.Errors.Count | Should -Be 0
        $complete.Events.Count | Should -Be 2
        $complete.Events[0].text | Should -BeExactly $text
        $complete.Position | Should -Be (Get-Item -LiteralPath $path).Length
        $complete.HasPartial | Should -BeFalse
        Test-PraGuiPreview $complete.Events[1] $request 0 | Should -BeTrue

        $prefix="{`"kind`":`"step`",`"index`":1,`"total`":2}`n"
        [IO.File]::WriteAllText($path,$prefix+$large,$encoding)
        $first=Read-PraGuiEvents $path
        $first.Events.Count | Should -Be 1
        $first.Position | Should -Be $encoding.GetByteCount($prefix)
        $first.HasPartial | Should -BeTrue
        $partial=Read-PraGuiEvents $path $first.Position
        $partial.Events.Count | Should -Be 0
        $partial.Position | Should -Be $first.Position
        $partial.HasPartial | Should -BeTrue
        [IO.File]::AppendAllText($path,"`n"+$resultLine+"`n",$encoding)
        $finished=Read-PraGuiEvents $path $partial.Position
        $finished.Events.Count | Should -Be 2
        $finished.Errors.Count | Should -Be 0
        $finished.Events[0].text | Should -BeExactly $text
        $finished.Events[1].kind | Should -BeExactly 'result'
        $finished.Position | Should -Be (Get-Item -LiteralPath $path).Length
        $finished.HasPartial | Should -BeFalse
    }
    It 'round-trips spaces, apostrophes, quotes, trailing slashes and injection-like identities through native -File' {
        $runtime=New-GuiTestRoot
        $fixture=Join-Path $runtime.Root "fixture space's.ps1"
        Write-GuiTestFile $fixture @'
param($Action,$Mode,$ConfigPath,$Scope,$Phase,$Identity,$MaxObjects)
$ErrorActionPreference='Stop'
$data=@{kind='result';status='Planned';exitCode=0;action=$Action;mode=$Mode;phase=$Phase;success=0;error=0;pending=0;skipped=0;planned=1;total=1;issues=@();identity=$Identity;config=$ConfigPath;edition=$PSVersionTable.PSEdition;version=$PSVersionTable.PSVersion.ToString();modulePath=$env:PSModulePath;apartment=[Threading.Thread]::CurrentThread.GetApartmentState().ToString()}
[IO.File]::WriteAllText($env:PRA_EVENT_FILE,($data|ConvertTo-Json -Depth 6 -Compress)+"`n",(New-Object Text.UTF8Encoding($false)))
[Console]::Out.Write(('o'*100000))
[Console]::Error.Write(('e'*100000))
exit 0
'@
        foreach($identity in @("O'Brien@example.invalid",'C:\synthetic space\','quote"inside','x"; Write-Output INJECTED; #')) {
            $request=New-PraGuiRequest -Phase AD -Identity $identity
            $events=Join-Path $runtime.Root ([guid]::NewGuid().ToString('N')+'.events.jsonl')
            $command=Get-PraGuiCommand $runtime.Root $runtime.Config $request -ScriptPath $fixture
            $child=Start-PraGuiChildProcess $command $runtime.Root $events
            try {
                $child.Process.WaitForExit(20000) | Should -BeTrue
                $child.Process.ExitCode | Should -Be 0
                $child.Output.Result.Length | Should -Be 100000
                $child.Errors.Result.Length | Should -Be 100000
                $result=(Read-PraGuiEvents $events).Events[0]
                $result.identity | Should -BeExactly $identity
                $result.config | Should -BeExactly $runtime.Config
                $result.edition | Should -BeExactly 'Core'
                $result.version | Should -Match '^7\.'
                $result.apartment | Should -BeExactly 'STA'
            } finally { $child.Process.Dispose() }
        }
    }
    It 'copies smart apostrophes as literal data and executes Display safely in PowerShell 7' {
        $runtime=New-GuiTestRoot
        $quotes=-join (@(0x2018,0x2019,0x201A,0x201B)|ForEach-Object{[char]$_})
        $fixture=Join-Path $runtime.Root ("fixture's "+$quotes+';exit 91;.ps1')
        $config=Join-Path $runtime.Root ("config's "+$quotes+';exit 92;.psd1')
        $identity="operator's "+$quotes+';Write-Output INJECTED;#@example.invalid'
        Write-GuiTestFile $config '@{Environment="Synthetic"}'
        Write-GuiTestFile $fixture @'
param($Action,$Mode,$ConfigPath,$Scope,$Phase,$Identity,$MaxObjects)
$ErrorActionPreference='Stop'
$record=@{kind='result';identity=$Identity;config=$ConfigPath;script=$PSCommandPath}
[IO.File]::WriteAllText($env:PRA_EVENT_FILE,($record|ConvertTo-Json -Compress)+"`n",(New-Object Text.UTF8Encoding($false)))
exit 0
'@
        $command=Get-PraGuiCommand $runtime.Root $config (New-PraGuiRequest -Phase AD -Identity $identity) -ScriptPath $fixture
        $tokens=$null;$errors=$null
        $ast=[Management.Automation.Language.Parser]::ParseInput($command.Display,[ref]$tokens,[ref]$errors)
        $errors.Count | Should -Be 0
        $ast.EndBlock.Statements.Count | Should -Be 1
        $elements=@($ast.EndBlock.Statements[0].PipelineElements[0].CommandElements)
        $expected=@($command.FilePath)+@($command.Tokens)
        $elements.Count | Should -Be $expected.Count
        for($i=0;$i -lt $expected.Count;$i++){
            $elements[$i] | Should -BeOfType ([Management.Automation.Language.StringConstantExpressionAst])
            $elements[$i].Value | Should -BeExactly $expected[$i]
        }
        $commandFile=Join-Path $runtime.Root 'display.command.txt'
        Write-GuiTestFile $commandFile $command.Display
        $driver=Join-Path $runtime.Root 'display-driver.ps1'
        Write-GuiTestFile $driver @'
param($CommandFile)
$ErrorActionPreference='Stop'
$global:LASTEXITCODE=0
$command=[IO.File]::ReadAllText($CommandFile)
$tokens=$null;$errors=$null
$null=[Management.Automation.Language.Parser]::ParseInput($command,[ref]$tokens,[ref]$errors)
if($errors.Count){throw 'Invalid copied command'}
$null=& ([scriptblock]::Create($command))
exit $LASTEXITCODE
'@
        $engines=@(Join-Path $PSHOME 'pwsh.exe')
        foreach($engine in $engines){
            $eventFile=Join-Path $runtime.Root ([guid]::NewGuid().ToString('N')+'.events.jsonl')
            $info=New-Object Diagnostics.ProcessStartInfo
            $info.FileName=$engine
            $info.Arguments=(@(@('-NoProfile','-NonInteractive','-STA','-File',$driver,'-CommandFile',$commandFile)|ForEach-Object{ConvertTo-PraGuiNativeArgument $_})-join ' ')
            $info.UseShellExecute=$false;$info.CreateNoWindow=$true;$info.RedirectStandardOutput=$true;$info.RedirectStandardError=$true
            $info.EnvironmentVariables['PRA_EVENT_FILE']=$eventFile
            $process=[Diagnostics.Process]::Start($info)
            $output=$process.StandardOutput.ReadToEndAsync();$stderr=$process.StandardError.ReadToEndAsync()
            try {
                $process.WaitForExit(20000) | Should -BeTrue
                $process.ExitCode | Should -Be 0 -Because ($output.Result+$stderr.Result)
                $output.Result | Should -Not -Match 'INJECTED'
                $result=(Read-PraGuiEvents $eventFile).Events[0]
                $result.identity | Should -BeExactly $identity
                $result.config | Should -BeExactly $config
                $result.script | Should -BeExactly $fixture
            } finally { $process.Dispose() }
        }
    }
}

Describe 'Console 3.0.0 - construction, five pages and synthetic workflow under PowerShell 7 (no live connection)' {
    It 'builds the real XAML, walks Setup, Task, Verify, Run and Next steps, and keeps every safety (Preview guard, confirmation, effective configuration)' {
        $runtime=New-GuiTestRoot
        Write-GuiTestFile (Join-Path $runtime.Root 'Invoke-PraRemoteMailbox.ps1') @'
param($Action,$Mode,$ConfigPath,$BaseConfigPath,$Scope,$Phase,$Identity,$MaxObjects,$SearchBase,$CsvPath,$Batch,$Expect,[switch]$Once,[switch]$Force)
$ErrorActionPreference='Stop'
function Ev($h){ [IO.File]::AppendAllText($env:PRA_EVENT_FILE,(($h|ConvertTo-Json -Depth 6 -Compress)+"`n"),(New-Object Text.UTF8Encoding($false))) }
[IO.File]::WriteAllText((Join-Path $PSScriptRoot 'last-args.json'),([ordered]@{Action=$Action;Mode=$Mode;ConfigPath=$ConfigPath;BaseConfigPath=$BaseConfigPath;Batch=$Batch;Identity=$Identity;Phase=$Phase;Force=[bool]$Force}|ConvertTo-Json))
if($Mode -eq 'Apply'){
 if(-not $Force){throw 'Synthetic Apply requires GUI-confirmed Force'}
 [IO.File]::WriteAllText((Join-Path $PSScriptRoot 'synthetic-apply-marker.txt'),'Apply confirmed')
}
if($SearchBase){[IO.File]::WriteAllText((Join-Path $PSScriptRoot 'selected-ou.txt'),$SearchBase)}
if($CsvPath){[IO.File]::WriteAllText((Join-Path $PSScriptRoot 'selected-csv.txt'),$CsvPath)}
$phaseValue=if($Action -eq 'Finalize'){'Finalize'}elseif($Action -eq 'Check'){'Cloud'}else{$Phase}
$titles=@('Active Directory connection','Targets and planned changes','Entra Connect synchronisation')
$status=if($Mode -eq 'Apply'){'Success'}else{'Planned'}
$planned=if($Mode -eq 'Apply'){0}else{1};$success=if($Mode -eq 'Apply'){1}else{0}
$row=[pscustomobject]@{ObjectGuid='11111111-1111-1111-1111-111111111111';SamAccountName='synthetic';UserPrincipalName='synthetic@example.invalid';Action=$Action;IsShared=$false;ADApplied=$false;ADVerified=$false;CloudStatus='N/A';FinalStatus=$status;Detail='Synthetic only';BackupPath='';Warnings=''}
$csv=Join-Path $PSScriptRoot 'synthetic.csv';$row|Export-Csv -LiteralPath $csv -Delimiter ';' -NoTypeInformation -Encoding UTF8
Ev @{kind='start';title='Synthetic run';action=$Action;mode=$Mode;phase=$phaseValue}
Ev @{kind='plan';steps=@(for($i=0;$i -lt 3;$i++){@{id='s'+($i+1);label=$titles[$i];count=$null}})}
Start-Sleep -Milliseconds 400
for($i=0;$i -lt 3;$i++){
 $id='s'+($i+1)
 Ev @{kind='step';index=$i+1;total=3;id=$id;title=$titles[$i];state='running';startedUtc=[datetime]::UtcNow.ToString('o');endedUtc=$null}
 Ev @{kind='item';stepId=$id;status='Ok';text='synthetic item';identity='synthetic';detail='technical'}
 Ev @{kind='item';stepId=$id;status='Ok';text='named by its ID';identity='11111111-1111-1111-1111-111111111111';name='synthetic';detail=''}
 Ev @{kind='item';stepId=$id;status='Info';text='note about a server';identity='CN=Batch,DC=example,DC=invalid';name='';detail=''}
 if($i -eq 2){ Ev @{kind='progress';stepId=$id;current=0;total=0;attempt=2;maxAttempts=13;nextInSeconds=5;text='Entra Connect sync'} }
 Ev @{kind='step';index=$i+1;total=3;id=$id;title=$titles[$i];state='ok';startedUtc=[datetime]::UtcNow.ToString('o');endedUtc=[datetime]::UtcNow.ToString('o')}
}
Ev @{kind='summary';title='Synthetic summary';status='Ok';values=@{Planned=$planned;Success=$success}}
$pkg=''
if($Mode -eq 'Apply' -and $Action -eq 'Convert' -and $Phase -eq 'AD'){ $pkg=Join-Path $PSScriptRoot 'PRA-GuiSynthetic-Convert-12345678-for-Cloud.zip'; [IO.File]::WriteAllBytes($pkg,[byte[]](1..200)) }
Ev @{kind='result';status=$status;exitCode=0;action=$Action;mode=$Mode;phase=$phaseValue;success=$success;error=0;pending=0;skipped=0;planned=$planned;total=1;issues=@();nextSteps=@('Copy the package','.\Invoke-PraRemoteMailbox.ps1 -Action Convert -Phase Cloud -Batch ''x.zip''');batchId='12345678';csvReport=$csv;logFile='';htmlReport='';backupFiles=@();stateFiles=@();transferPackage=$pkg;transferPackageKind=$(if($pkg){'Convert'}else{''});configOverrides=@()}
exit 0
'@
        $probe=Join-Path $runtime.Root 'wpf-probe.ps1'
        Write-GuiTestFile (Join-Path $runtime.Root 'module\PRA.Gui.Directory.ps1') @'
param($ConfigPath,$ResultPath,$Identity,$PackagePath,$Environment,$BackupFolder,[switch]$Import)
if($PackagePath){
 # Synthetic stand-in of the package mode of module\PRA.Gui.Directory.ps1: the same engine functions, no Active Directory.
 Import-Module $env:PRA_TEST_COMMON -Force
 try {
  if($Import){ $r=Import-PraTransferPackage -Path $PackagePath -BackupFolder $BackupFolder -Environment $Environment; $a=@{Success=$true;Mode='Import';Kind=$r.Kind;BatchId=$r.BatchId;Name=$r.Name;Folders=@($r.Folders);Created=@($r.Created);Existing=@($r.Existing)} }
  else { $i=Get-PraTransferPackage -Path $PackagePath -Environment $Environment; $a=@{Success=$true;Mode='Verify';Valid=[bool]$i.Valid;Error=[string]$i.Error;Kind=[string]$i.Kind;Environment=[string]$i.Environment;BatchId=[string]$i.BatchId;Name=[string]$i.Name;SizeBytes=[long]$i.SizeBytes;CreatedUtc=[string]$i.CreatedUtc;EntryCount=[int]$i.EntryCount} }
 } catch { $a=@{Success=$false;Error=$_.Exception.Message} }
 [IO.File]::WriteAllText($ResultPath,($a|ConvertTo-Json -Depth 5),(New-Object Text.UTF8Encoding($false)))
 exit 0
}
Start-Sleep -Milliseconds 400
[IO.File]::WriteAllText($ResultPath,(@{Success=$true;Server='dc.synthetic.invalid';Units=@(@{Name='Selected';DistinguishedName='OU=Selected,DC=example,DC=invalid'})}|ConvertTo-Json -Depth 4))
exit 0
'@
        $other=New-GuiTestBatch $runtime
        # A transfer package waiting in the Inbox (its batch is not on this server: it only exists inside the package).
        $packed=New-GuiTestBatch $runtime
        $null=New-PraTransferPackage -Kind Convert -Environment 'GuiSynthetic' -BatchId $packed.Id -Folders @($packed.Folder) -OutboxFolder (Join-Path $runtime.Root 'Backups\Inbox')
        Remove-Item -LiteralPath $packed.Folder -Recurse -Force
        $labFolder=Join-Path $runtime.Root 'Backups\Batch-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
        $labData=@{SchemaVersion=2;Operation='Convert';Environment='LabSynthetic';BatchId='aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa';SourceBackupHash='';Records=@(@{ObjectGuid=[guid]::NewGuid().ToString();SamAccountName='lab';UserPrincipalName='lab@example.invalid';IsShared=$false})}
        Write-GuiTestJson (Join-Path $labFolder 'Convert-lab.json') $labData
        Write-GuiTestJson (Join-Path $labFolder 'State-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.json') @{SchemaVersion=2;Operation='Convert';Kind='ADVerified';Environment='LabSynthetic';Records=@(@{ObjectGuid=$labData.Records[0].ObjectGuid;ADVerified=$true})}
        Write-GuiTestFile $probe @'
param($Common,$Gui,$Root,$Config,$Packed)
$ErrorActionPreference='Stop'
Import-Module $Common -Force
Import-Module $Gui -Force
function Pump([int]$Milliseconds=60){
 $frame=New-Object Windows.Threading.DispatcherFrame
 $pump=New-Object Windows.Threading.DispatcherTimer
 $pump.Interval=[timespan]::FromMilliseconds($Milliseconds);$pump.Tag=$frame
 $pump.Add_Tick({param($s)$s.Tag.Continue=$false;$s.Stop()})
 $pump.Start();[Windows.Threading.Dispatcher]::PushFrame($frame)
}
function Wait-Run($Window){
 $deadline=[datetime]::UtcNow.AddSeconds(25)
 while($Window.Run -and [datetime]::UtcNow -lt $deadline){ Pump 50 }
 if($Window.Run){throw 'Synthetic child timed out'}
}
function Click($Window,[string]$Name){ $Window.Controls[$Name].RaiseEvent((New-Object Windows.RoutedEventArgs ([Windows.Controls.Button]::ClickEvent))) }
function Check($Window,[string]$Name){ $Window.Controls[$Name].IsChecked=$true; Pump 30 }
$marker=Join-Path $Root 'synthetic-apply-marker.txt'
if(Test-Path -LiteralPath $marker){Remove-Item -LiteralPath $marker -Force}
$detect={ param($Request) [pscustomobject]@{ Lights=@([ordered]@{Name='RSAT ActiveDirectory';Status='Ok';Detail='synthetic'},[ordered]@{Name='ExchangeOnlineManagement';Status='Ok';Detail='synthetic'}); AD=$true; Cloud=$true; Role='Both' } }
$g=New-PraGuiWindow -Root $Root -ConfigPath $Config -Version 'Synthetic' -PrerequisiteProbe $detect
if($g.Run -or $g.Pending -or $g.Controls.BtnNext.Content -notmatch 'Choose a task'){throw 'Construction started/authorized an operation or Setup is not the first page'}
if($g.HandlerNames.Count -lt 25){throw 'Missing handlers'}
if(Get-Module ActiveDirectory,ExchangeOnlineManagement,Microsoft.Graph.Authentication){throw 'Live module imported'}
if(-not $g.Form.Background){throw 'Outer Window margin has no theme background'}
$area=[Windows.SystemParameters]::WorkArea
if($g.Form.Width -gt $area.Width -or $g.Form.Height -gt $area.Height -or $g.Form.MinWidth -gt $area.Width -or $g.Form.MinHeight -gt $area.Height){throw 'Window exceeds actual work area'}
if([Windows.Application].GetProperty('ThemeMode') -and -not $g.Theme.Fluent){throw 'Native Fluent theme missing'}
$g.Form.Show()
try {
 $c=$g.Controls
 # --- Setup: three lines, the settings open on demand and show what differs from the file
 if($c.RunLine.Text -notmatch 'This run: GuiSynthetic'){throw ('Run line: '+$c.RunLine.Text)}
 if($c.SettingsCard.Visibility -ne 'Collapsed'){throw 'Run settings must be collapsed on Setup'}
 if($c.Lights.Items.Count -ne 2 -or $c.RoleName.Text -notmatch 'AD \+ Cloud'){throw 'Prerequisite lights or role do not come from the probe'}
 Click $g 'BtnChange'
 if($c.SettingsCard.Visibility -ne 'Visible'){throw 'Change... did not open the run settings'}
 $c.F_Dc.Text='dc9.example.invalid'; Pump
 if($c.M_Dc.Visibility -ne 'Visible' -or $c.RunLineSub.Text -notmatch 'Modified for this run only'){throw 'A changed setting is not marked'}
 Click $g 'R_Dc'
 if($c.F_Dc.Text -ne '' -or $c.M_Dc.Visibility -ne 'Collapsed'){throw 'Reset did not restore the value of the file'}
 Click $g 'BtnDoneSettings'
 if($c.Row_AppId.Visibility -ne 'Collapsed'){throw 'Certificate fields shown with interactive sign-in'}
 # --- Task
 Click $g 'BtnNext'
 if($g.Page -ne 2 -or $c.BtnNext.IsEnabled){throw 'Task page: Continue must wait for a task'}
 Check $g 'T_Convert'
 if($c.SourceBox.Visibility -ne 'Visible' -or $c.Row_Identity.Visibility -ne 'Visible' -or $c.BtnNext.IsEnabled){throw 'New Convert: the object source (Single identity first) belongs to the Task page and needs an identity'}
 if($c.PhaseText.Text -notmatch 'transfer package'){throw 'Convert AD must announce ONE transfer package'}
 $c.F_Identity.Text='synthetic@example.invalid'; Pump
 Check $g 'S_Source_Ou'
 if($c.Row_Ou.Visibility -ne 'Visible' -or $c.Row_Identity.Visibility -ne 'Collapsed' -or $c.BtnNext.IsEnabled){throw 'OU source requires a DN and hides the identity'}
 $c.F_Ou.Text='OU=Selected,DC=example,DC=invalid'; Pump
 if(-not $c.BtnNext.IsEnabled -or $c.CmdLine.Text -notmatch 'SearchBase'){throw 'OU command not selected'}
 $selectTimer=New-Object Windows.Threading.DispatcherTimer
 $selectTimer.Interval=[timespan]::FromMilliseconds(100)
 $selectTimer.Add_Tick({
  foreach($window in @([Windows.Application]::Current.Windows)){
   if($window.Title -eq 'Pick an OU'){
    $window.FindName('Units').SelectedIndex=0
    $window.FindName('Select').RaiseEvent((New-Object Windows.RoutedEventArgs ([Windows.Controls.Button]::ClickEvent)))
   }
  }
 })
 $c.F_Ou.Text=''
 $selectTimer.Start()
 try {
  Click $g 'BtnPickOu'
  if(-not $g.OuLookup -or $c.Page1.IsEnabled -or $c.Page2.IsEnabled){throw 'OU browser did not start asynchronously with the inputs locked'}
  $deadline=[datetime]::UtcNow.AddSeconds(15)
  while($g.OuLookup -and [datetime]::UtcNow -lt $deadline){Pump 50}
  if($g.OuLookup -or $c.F_Ou.Text -ne 'OU=Selected,DC=example,DC=invalid'){throw 'OU selection dialog failed'}
  if(Get-Module ActiveDirectory,PRA.Directory){throw 'OU browser loaded directory modules into UI'}
 } finally {$selectTimer.Stop()}
 Check $g 'S_Source_Csv'
 $selectionCsv=Join-Path $Root 'selected-list.csv'
 [IO.File]::WriteAllText($selectionCsv,"Identity`r`nsynthetic@example.invalid")
 $c.F_Csv.Text=$selectionCsv; Pump
 if(-not $c.BtnNext.IsEnabled -or $c.CmdLine.Text -notmatch 'CsvPath'){throw 'CSV chooser did not validate the source'}
 Check $g 'S_Source_Single'
 # --- Continue a batch: batches of every environment are listed; one of another environment locks the Environment
 Check $g 'Mode_Continue'
 Click $g 'BtnReload'
 Check $g 'T_Convert'; Check $g 'Mode_Continue'
 if($c.BatchBox.Visibility -ne 'Visible' -or $c.BtnImport.Visibility -ne 'Visible'){throw 'Continue lists batches and offers Import package'}
 if($g.BatchRows.Count -lt 2){throw ('Batches not listed: '+$g.BatchRows.Count)}
 $labRow=@($g.BatchRows | Where-Object { $_.Environment -eq 'LabSynthetic' })[0]
 if(-not $labRow -or -not $labRow.Selectable){throw 'A batch of another environment must be listed and selectable'}
 $c.BatchList.SelectedItem=$labRow; Pump
 if($c.F_Env.Text -ne 'LabSynthetic' -or $c.F_Env.IsEnabled -or $c.EnvLock.Visibility -ne 'Visible'){throw 'Environment must lock to the batch'}
 $c.BatchList.SelectedItem=$null; Pump
 if($c.F_Env.Text -ne 'GuiSynthetic' -or -not $c.F_Env.IsEnabled){throw 'Environment must unlock when the batch is deselected'}
 Check $g 'Mode_New'
 # --- Verify: Preview first, then the confirmation word (any letter case), then Run
 $c.F_Identity.Text='synthetic@example.invalid'; Pump
 Click $g 'BtnNext'
 if($g.Page -ne 3 -or $c.BtnNext.IsEnabled -or $c.ConfirmBox.IsEnabled){throw 'Run must be locked before a Preview'}
 if($c.PlanList.Items.Count -lt 4){throw 'The plan is not shown before the Preview'}
 Click $g 'BtnPreview'
 if(-not $g.Run -or $g.Run.Request.Mode -ne 'Preview'){throw 'Preview did not start the child'}
 if($c.RunTitle.Text -notmatch 'AD and cloud, on this server' -or $c.RunTitle.Text -match 'Both part'){throw ('Phase Both must read "AD and cloud, on this server": '+$c.RunTitle.Text)}
 $g.Form.Close()
 if(-not $g.Form.IsVisible){throw 'Closing during an atomic action was not prevented'}
 Wait-Run $g
 if(-not $g.Pending){throw ('Preview not authorized: '+$c.SumText.Text+' '+$g.PreviewError)}
 if($c.VerList.Items.Count -ne 1){throw 'The grid is not populated by the Preview report'}
 if($g.Model.Steps.Count -ne 3 -or $g.Model.Steps[2].Status -ne 'Ok'){throw 'The plan and step events did not drive the steps'}
 $c.ConfirmBox.Text='CONVERTX'; Pump 350
 if($c.BtnNext.IsEnabled){throw 'A wrong confirmation word enabled Run'}
 $c.ConfirmBox.Text='convert'; Pump 350
 if(-not $c.BtnNext.IsEnabled){throw 'Lowercase confirmation did not enable Run'}
 $c.ConfirmBox.Text=' CoNvErT '; Pump 350
 if(-not $c.BtnNext.IsEnabled){throw 'Mixed-case confirmation with spaces did not enable Run'}
 $c.F_Identity.Text='other@example.invalid'; Pump
 if($g.Pending -or $c.BtnNext.IsEnabled -or $c.ConfirmBox.Text){throw 'Changing the object source preserved the authorization'}
 $c.F_Identity.Text='synthetic@example.invalid'; Pump
 Click $g 'BtnPreview'; Wait-Run $g
 $c.ConfirmBox.Text='CONVERT'; Pump 350
 if(-not $c.BtnNext.IsEnabled){throw 'A fresh Preview did not reauthorize Run'}
 [IO.File]::AppendAllText($Config,"`n# Changed input")
 Click $g 'BtnNext'
 if($g.Run -or $g.Pending){throw 'A changed configuration permitted Apply'}
 if(Test-Path -LiteralPath $marker){throw 'Apply started on changed input'}
 Click $g 'BtnReload'
 Check $g 'T_Convert'
 $c.F_Identity.Text='synthetic@example.invalid'; Pump
 if($g.Page -ne 3){ & (Get-Module PRA.Gui) { Show-PraGuiPage 3 } }
 # --- Apply with a setting changed for this run: an effective copy of the configuration is written, guarded and used
 # (this server does both sides, so a new batch is Phase Both by itself; the hand-over with a package is exercised by forcing the AD phase in Expert mode)
 Check $g 'S_ExpPhase_AD'
 $c.F_Dc.Text='dc9.example.invalid'; Pump
 Click $g 'BtnPreview'; Wait-Run $g
 if(-not $g.Pending){throw ('Preview with a changed setting not authorized: '+$g.PreviewError)}
 $args1=[IO.File]::ReadAllText((Join-Path $Root 'last-args.json'))|ConvertFrom-Json
 if(-not $args1.BaseConfigPath -or $args1.ConfigPath -eq $args1.BaseConfigPath -or -not (Test-Path -LiteralPath $args1.ConfigPath)){throw 'A changed setting must run with an effective copy and name its base file'}
 $effective=[IO.File]::ReadAllText($args1.ConfigPath)
 if($effective -notmatch 'dc9\.example\.invalid'){throw 'The effective configuration does not carry the changed value'}
 if([IO.File]::ReadAllText($Config) -match 'dc9\.example'){throw 'The configuration file was written'}
 $c.ConfirmBox.Text='convert'
 [IO.File]::AppendAllText($args1.ConfigPath,"`n# tampered")
 Click $g 'BtnNext'
 if($g.Run -or $g.Pending){throw 'A tampered effective configuration permitted Apply'}
 Click $g 'BtnPreview'; Wait-Run $g
 $c.ConfirmBox.Text='convert'
 Click $g 'BtnNext'
 if($c.RunTitle.Text -notmatch 'AD part'){throw ('A single phase keeps "AD part": '+$c.RunTitle.Text)}
 if(-not $g.Run -or $g.Run.Request.Mode -ne 'Apply' -or $g.Page -ne 4){throw 'Apply did not start the confirmed child on the Run page'}
 if($c.BtnNext.IsEnabled){throw 'Run button must be disabled while running'}
 Wait-Run $g
 if(-not (Test-Path -LiteralPath $marker)){throw 'Confirmed child did not receive Force'}
 if($g.Pending -or -not $g.LastRun.Valid){throw 'Apply incorrectly preserved Preview authorization or the result is invalid'}
 if($g.Model.Steps.Count -ne 3 -or @($g.Model.Steps | Where-Object Status -ne 'Ok').Count){throw 'Steps are not all done'}
 $c.StepList.SelectedIndex=2; Pump
 if($c.DetTitle.Text -notmatch 'Entra Connect' -or $c.DetObjList.Items.Count -ne 1){throw 'Step detail did not show the step and its object'}
 $c.DetObjList.SelectedIndex=0; Pump
 if($c.ObjCard.Visibility -ne 'Visible' -or $c.Journey.Items.Count -ne 3){throw 'Object journey card did not show'}
 Click $g 'BtnNext'
 if($g.Page -ne 5 -or $c.PackageBox.Visibility -ne 'Visible' -or $c.PkgName.Text -notmatch 'for-Cloud\.zip' -or $c.NextCmd.Text -notmatch 'Batch'){throw 'Next steps must show the transfer package and the command'}
 if(@($g.NextRows).Count -lt 3 -or ($c.NextSteps.Items[0].Text -notmatch 'the two files .*\.zip and .*\.zip\.sha256')){throw 'Next steps instructions do not name the zip and its sha256 file'}
 if(($g.NextRows | ForEach-Object Text) -match 'whole folder'){throw 'Instructions still say copy the whole folder'}
 # --- Check: read only, no confirmation, no Preview
 Click $g 'BtnNext'
 if($g.Page -ne 2){throw 'Start a new task did not go to Task'}
 Check $g 'T_Check'
 if($c.CheckPanel.Visibility -ne 'Visible'){throw 'Check panel'}
 $c.F_CheckUpn.Text='synthetic@example.invalid'; Pump
 Click $g 'BtnNext'
 if($g.Page -ne 3 -or $c.ConfirmCard.Visibility -ne 'Collapsed' -or $c.BtnPreview.Visibility -ne 'Collapsed' -or -not $c.BtnNext.IsEnabled){throw 'Check has no preview and no confirmation'}
 Click $g 'BtnNext'
 if(-not $g.Run -or $g.Run.Request.Action -ne 'Check' -or $g.Page -ne 4){throw 'Check did not start'}
 Wait-Run $g
 $checkArgs=[IO.File]::ReadAllText((Join-Path $Root 'last-args.json'))|ConvertFrom-Json
 if($checkArgs.Mode -ne 'Preview' -or $checkArgs.Force){throw 'Check must be read only, never Force'}
 # --- Continue from a transfer package of the Inbox: listed, verified, imported on the way to the verification page
 & (Get-Module PRA.Gui) { Show-PraGuiPage 2 }
 Check $g 'T_Convert'; Check $g 'Mode_Continue'
 # The package is checked by a child process (the window thread never hashes it): it is first "checking", then verified.
 $deadline=[datetime]::UtcNow.AddSeconds(60)
 do { Pump 100; $packageRow=@($g.BatchRows | Where-Object { $_.Package })[0] } while((-not $packageRow -or -not $packageRow.Selectable) -and [datetime]::UtcNow -lt $deadline)
 if(-not $packageRow -or -not $packageRow.Selectable -or $packageRow.State -notmatch 'verified'){throw 'The Inbox package is not listed as verified'}
 $c.BatchList.SelectedItem=$packageRow; Pump
 if(Test-Path -LiteralPath (Join-Path $Root ('Backups\Batch-'+$Packed)) ){throw 'The package was extracted before being chosen'}
 Click $g 'BtnNext'
 if(-not $g.PkgJob -and -not $g.PkgQueue.Count -and $g.Page -ne 3){throw 'Import did not start'}
 $deadline=[datetime]::UtcNow.AddSeconds(90)
 while(($g.PkgJob -or $g.PkgQueue.Count) -and [datetime]::UtcNow -lt $deadline){ Pump 100 }
 if($g.Page -ne 3 -or $g.SelectedBatch.Package -or -not (Test-Path -LiteralPath $g.SelectedBatch.Path)){throw ('The package was not imported on the way to the verification: '+$c.TaskError.Text)}
 if(-not $g.SelectedBatch.Path.Contains($Packed)){throw 'The imported batch is not the one of the package'}
 # --- Navigation and layout under a constrained work area
 & (Get-Module PRA.Gui) { Show-PraGuiPage 1 }
 & (Get-Module PRA.Gui) {param($window) Set-PraGuiWindowBounds -Window $window -WorkArea ([Windows.Rect]::new(0,0,1280,720))} $g.Form
 Pump; $g.Form.UpdateLayout()
 if($g.Form.ActualWidth -gt 1280 -or $g.Form.ActualHeight -gt 720){throw 'Constrained work-area clamp failed'}
 [Console]::WriteLine('WPF-SMOKE-PASS '+$PSVersionTable.PSEdition)
} finally {$g.Form.Close()}
'@
        $env:PRA_TEST_COMMON=$script:GuiCommon
        $tokens=@('-NoProfile','-NonInteractive','-STA','-File',$probe,'-Common',$script:GuiCommon,'-Gui',$script:GuiModule,'-Root',$runtime.Root,'-Config',$runtime.Config,'-Packed',$packed.Id)
        $info=New-Object Diagnostics.ProcessStartInfo
        $info.FileName=(Join-Path $PSHOME 'pwsh.exe');$info.Arguments=(@($tokens|ForEach-Object{ConvertTo-PraGuiNativeArgument $_})-join ' ')
        $info.UseShellExecute=$false;$info.CreateNoWindow=$true;$info.RedirectStandardOutput=$true;$info.RedirectStandardError=$true
        $process=[Diagnostics.Process]::Start($info)
        $out=$process.StandardOutput.ReadToEndAsync();$err=$process.StandardError.ReadToEndAsync()
        try {
            $process.WaitForExit(120000) | Should -BeTrue
            $process.ExitCode | Should -Be 0 -Because ($out.Result+$err.Result)
            $out.Result | Should -Match 'WPF-SMOKE-PASS'
        } finally { $process.Dispose() }
    }
}

Describe 'Console 3.0.0 - detection, effective configuration and files' {
    It 'looks for the sign-in certificate where the engine reads it (CurrentUser\My) and accepts a valid one found there' {
        $key=[Security.Cryptography.RSA]::Create(2048)
        $request=New-Object Security.Cryptography.X509Certificates.CertificateRequest('CN=PraGateSynthetic',$key,[Security.Cryptography.HashAlgorithmName]::SHA256,[Security.Cryptography.RSASignaturePadding]::Pkcs1)
        $made=$request.CreateSelfSigned([datetimeoffset]::UtcNow.AddDays(-1),[datetimeoffset]::UtcNow.AddDays(30))
        $pfx=$made.Export([Security.Cryptography.X509Certificates.X509ContentType]::Pfx,'gate')
        $certificate=New-Object Security.Cryptography.X509Certificates.X509Certificate2($pfx,'gate',[Security.Cryptography.X509Certificates.X509KeyStorageFlags]::PersistKeySet)
        $thumb=$certificate.Thumbprint
        $store=New-Object Security.Cryptography.X509Certificates.X509Store('My','CurrentUser')
        $store.Open('ReadWrite')
        try {
            $store.Add($certificate)
            $result=& (Get-Module PRA.Gui) { param($t) Get-PraGuiPrerequisite -Signin Cert -Thumbprint $t -SyncEnabled $false -Refresh } $thumb
            $light=$result.Lights | Where-Object Name -eq 'Sign-in: Certificate'
            $light.Status | Should -BeExactly 'Ok' -Because $light.Detail
            $light.Detail | Should -Match 'CurrentUser\\My'
        } finally { $store.Remove($certificate); $store.Close(); $certificate.Dispose(); $key.Dispose() }
        $gone=& (Get-Module PRA.Gui) { param($t) Get-PraGuiPrerequisite -Signin Cert -Thumbprint $t -SyncEnabled $false -Refresh } $thumb
        ($gone.Lights | Where-Object Name -eq 'Sign-in: Certificate').Status | Should -BeExactly 'Fail'
        ($gone.Lights | Where-Object Name -eq 'Sign-in: Certificate').Detail | Should -Match 'CurrentUser\\My'
    }
    It 'detects the lights and the role from what is installed (no import, no connection)' {
        $result=& (Get-Module PRA.Gui) { Get-PraGuiPrerequisite -Signin Cert -Thumbprint '0000000000000000000000000000000000000000' -SyncEnabled $false -Refresh }
        $result.Lights.Count | Should -Be 4 -Because 'RSAT, Cloud modules, Entra Connect sync and the sign-in: the two cloud modules share one light'
        ($result.Lights | Where-Object Name -eq 'Sign-in: Certificate').Status | Should -BeExactly 'Fail'
        ($result.Lights | Where-Object Name -eq 'Entra Connect sync').Status | Should -BeExactly 'NA' -Because 'a synchronisation that is not used is neutral grey, not a green check'
        $result.Role | Should -BeIn @('Both','AD','Cloud','None')
        ($result.Lights | Where-Object Name -eq 'Sign-in: Certificate').Detail | Should -Match 'CurrentUser\\My' -Because 'the sign-in of the engine reads the store of the account that runs the tool'
        $result.Cloud | Should -BeFalse -Because 'a missing certificate removes the cloud capability'
        $wam=& (Get-Module PRA.Gui) { Get-PraGuiPrerequisite -Signin Wam -SyncEnabled $false }
        ($wam.Lights | Where-Object Name -like 'Sign-in*').Name | Should -Be 'Sign-in: Interactive (WAM)'
        @($wam.Lights | Where-Object Name -eq 'Cloud modules').Count | Should -Be 1
        @($wam.Lights | Where-Object { $_.Name -in @('ExchangeOnlineManagement','Microsoft.Graph') }).Count | Should -Be 0
        Get-Module ActiveDirectory,ExchangeOnlineManagement,Microsoft.Graph.Authentication | Should -BeNullOrEmpty
    }
    It 'passes the base configuration to the engine and guards both configuration files' {
        $runtime=New-GuiTestRoot
        $request=New-PraGuiRequest -Phase AD -Identity 'a@example.invalid'
        $command=Get-PraGuiCommand $runtime.Root $runtime.Config $request -BaseConfigPath 'C:\Synthetic\base.psd1'
        $index=[Array]::IndexOf([string[]]$command.Tokens,'-BaseConfigPath')
        $index | Should -BeGreaterThan 0
        $command.Tokens[$index+1] | Should -BeExactly 'C:\Synthetic\base.psd1'
        (Get-PraGuiCommand $runtime.Root $runtime.Config $request).Tokens | Should -Not -Contain '-BaseConfigPath'
        $base=Join-Path $runtime.Root 'base.psd1'
        Write-GuiTestFile $base ([IO.File]::ReadAllText($runtime.Config))
        $before=Get-PraGuiGuard $runtime.Root $runtime.Config $request $base
        [IO.File]::AppendAllText($base,"`n# changed")
        Get-PraGuiGuard $runtime.Root $runtime.Config $request $base | Should -Not -Be $before
        $before=Get-PraGuiGuard $runtime.Root $runtime.Config $request $base
        [IO.File]::AppendAllText($runtime.Config,"`n# changed")
        Get-PraGuiGuard $runtime.Root $runtime.Config $request $base | Should -Not -Be $before
    }
    It 'lists a batch of another environment apart instead of calling it corrupt' {
        $runtime=New-GuiTestRoot
        $batch=New-GuiTestBatch $runtime
        $batch.Data.Environment='OtherSynthetic'
        Write-GuiTestJson $batch.Path $batch.Data
        $state=Read-PraGuiState $runtime.Root $runtime.Config
        $state.OtherEnvironment.Count | Should -Be 1
        $state.OtherEnvironment[0].Environment | Should -BeExactly 'OtherSynthetic'
        $state.OtherEnvironment[0].Valid | Should -BeTrue
        (Read-PraGuiBatch $batch.Path 'GuiSynthetic' -AnyEnvironment).Valid | Should -BeTrue
        (Read-PraGuiBatch $batch.Path 'GuiSynthetic').Valid | Should -BeFalse
    }
    It 'names the object of an event for the window and keeps a DN, a server or a bare ID out of the list of mailboxes' {
        $context=@{}
        Register-PraObjectName -Context $context -ObjectGuid 'AAAAAAAA-0000-0000-0000-000000000001' -Name 'adele.vance@contoso.com'
        Get-PraEventObjectName $context 'aaaaaaaa-0000-0000-0000-000000000001' | Should -BeExactly 'adele.vance@contoso.com'
        Get-PraEventObjectName $context 'user@contoso.com' | Should -BeExactly 'user@contoso.com'
        Get-PraEventObjectName $context 'CN=Batch,DC=example,DC=invalid' | Should -BeExactly ''
        Get-PraEventObjectName $context '11111111-1111-1111-1111-111111111111' | Should -BeExactly ''
        Get-PraEventObjectName $context '' | Should -BeExactly ''
        Get-PraEventObjectName @{} 'aaaaaaaa-0000-0000-0000-000000000001' | Should -BeExactly ''
    }
    It 'reads plan and progress events like the other kinds' {
        $path=Join-Path $script:GuiEvidence 'plan.events.jsonl'
        [IO.File]::WriteAllText($path,"{`"kind`":`"plan`",`"steps`":[{`"id`":`"s1`",`"label`":`"A`",`"count`":null}]}`n{`"kind`":`"progress`",`"stepId`":`"s1`",`"attempt`":2,`"maxAttempts`":13,`"nextInSeconds`":7,`"text`":`"wait`"}`n",(New-Object Text.UTF8Encoding($false)))
        $read=Read-PraGuiEvents $path
        $read.Errors | Should -BeNullOrEmpty
        $read.Events.Count | Should -Be 2
        $read.Events[1].nextInSeconds | Should -Be 7
    }
    It 'keeps the window code free of runtime compilation, of restyled implicit controls and of French text' {
        $code=[IO.File]::ReadAllText($script:GuiModule)
        $code | Should -Not -Match 'Add-Type\s+-TypeDefinition'
        $code | Should -Not -Match 'Style\]::new\(\$control\.GetType\(\)'
        $code | Should -Not -Match 'moteur|Métadonnées|Saisir|ligne\(s\)'
        $xaml=[IO.File]::ReadAllText((Join-Path (Split-Path $script:GuiModule -Parent) 'PRA.Gui.xaml'))
        $xaml | Should -Match 'capitals or not'
        $xaml | Should -Not -Match 'mockup|fake data|Demo:'
        $xaml | Should -Not -Match '<Style TargetType="(Button|TextBox|ComboBox|CheckBox|Expander|ProgressBar)"'
        $xaml | Should -Match 'Import package'
        $xaml | Should -Not -Match 'copy the whole folder|Copy folder name'
    }
}


Describe 'Release 2.3.0 - GUI cloud sign-in child, progressive output, confirmation and path comparison' -Tag 'Release230' {
    It 'launches <Action> <Phase> without -NonInteractive and flags the actions that can reach the cloud (NeedsCloudWindow=<Cloud>)' -TestCases @(
        @{Action='Convert';Phase='Both';Cloud=$true}
        @{Action='Convert';Phase='Cloud';Cloud=$true}
        @{Action='Recover';Phase='Both';Cloud=$true}
        @{Action='Recover';Phase='Cloud';Cloud=$true}
        @{Action='Check';Phase='Cloud';Cloud=$true}
        @{Action='Convert';Phase='AD';Cloud=$false}
        @{Action='Recover';Phase='AD';Cloud=$false}
        @{Action='Finalize';Phase='AD';Cloud=$false}
    ) {
        param($Action,$Phase,$Cloud)
        $type=Get-PraGuiBatchType $Action $Phase
        $r=New-PraGuiRequest -Action $Action -Phase $Phase -Batch $(if($type){'01234567'}else{''})
        $command=Get-PraGuiCommand -Root 'C:\Synthetic root' -ConfigPath 'C:\Synthetic root\config.psd1' -Request $r
        $command.Tokens | Should -Not -Contain '-NonInteractive'
        $command.Tokens | Should -Contain '-STA'
        $command.Tokens | Should -Contain '-NoProfile'
        $command.NeedsCloudWindow | Should -Be $Cloud
        $command.Display | Should -Not -Match 'NonInteractive'
    }
    It 'gives a cloud child a console, an AD-only child none, closes stdin and streams stdout while the child runs' -TestCases @(
        @{Phase='Both';HasWindow=$true},@{Phase='AD';HasWindow=$false}
    ) {
        param($Phase,$HasWindow)
        $runtime=New-GuiTestRoot
        $fixture=Join-Path $runtime.Root 'stream-fixture.ps1'
        Write-GuiTestFile $fixture @'
param($Action,$Mode,$ConfigPath,$Scope,$Phase,$Identity,$MaxObjects)
$ErrorActionPreference='Stop'
# Test-only helper: the child proves what console it really has.
Add-Type -Namespace PraGateNative -Name Con -MemberDefinition '[DllImport("kernel32.dll")] public static extern System.IntPtr GetConsoleWindow(); [DllImport("kernel32.dll")] public static extern uint GetConsoleProcessList(uint[] list, uint count);'
$list=New-Object 'uint32[]' 64
$attached=[PraGateNative.Con]::GetConsoleProcessList($list,64)
$window=[PraGateNative.Con]::GetConsoleWindow()
[Console]::Out.WriteLine('console-window='+($window -ne [IntPtr]::Zero)+';console-processes='+$attached)
[Console]::Out.WriteLine('line-one-before-sleep'); [Console]::Out.Flush()
Start-Sleep -Seconds 4
$all=[Console]::In.ReadToEnd()
[Console]::Out.WriteLine('stdin-redirected='+[Console]::IsInputRedirected+';stdin-length='+$all.Length)
[Console]::Out.WriteLine('line-two-after-sleep')
exit 0
'@
        $request=New-PraGuiRequest -Phase $Phase
        $events=Join-Path $runtime.Root ([guid]::NewGuid().ToString('N')+'.events.jsonl')
        $command=Get-PraGuiCommand $runtime.Root $runtime.Config $request -ScriptPath $fixture
        $child=Start-PraGuiChildProcess $command $runtime.Root $events
        try {
            $seen=''; $clock=[Diagnostics.Stopwatch]::StartNew(); $earlyWhileRunning=$false
            while ($clock.Elapsed.TotalSeconds -lt 30 -and -not $child.Process.HasExited) {
                $seen+=$child.Output.TakeText()
                if ($seen -match 'line-one-before-sleep' -and -not $child.Process.HasExited) { $earlyWhileRunning=$true; break }
                Start-Sleep -Milliseconds 100
            }
            $earlyWhileRunning | Should -BeTrue -Because 'the first stdout line must be readable while the child is still running'
            $child.Process.WaitForExit(30000) | Should -BeTrue
            $child.Process.ExitCode | Should -Be 0
            $full=$child.Output.Result
            $full | Should -Match 'line-one-before-sleep'
            $full | Should -Match 'line-two-after-sleep'
            $full | Should -Match 'stdin-redirected=True;stdin-length=0'
            # The child proves its console. A cloud child has a console WINDOW of its own and is the only process attached to it
            # (it does not share the console of the terminal that started the window); an AD-only child has no console window.
            if ($HasWindow) { $full | Should -Match 'console-window=True;console-processes=1(\r?\n|$)' }
            else { $full | Should -Match 'console-window=False;' }
            # The raw output is kept in files next to the event file, written while the child runs (no collector thread, no compiler).
            $base=$events -replace '\.events\.jsonl$',''
            [IO.File]::ReadAllText($base+'.stdout.txt') | Should -Match 'line-two-after-sleep'
            $child.Output.IsCompleted | Should -BeTrue
            $child.Errors.Result | Should -BeExactly ''
        } finally { $child.Process.Dispose() }
    }
    It 'starts the cloud child through CreateProcess with its own console and no runtime compilation' {
        $code=[IO.File]::ReadAllText($script:GuiModule)
        $code | Should -Not -Match 'Add-Type\s+-TypeDefinition'
        $code | Should -Not -Match 'public sealed class'
        $code | Should -Match 'Get-PraNativeProcessApi'
        $code | Should -Match '0x410'
        $code | Should -Not -Match 'fails at once'
        $common=[IO.File]::ReadAllText($script:GuiCommon)
        $common | Should -Not -Match 'Add-Type\s+-TypeDefinition'
    }
    It 'shows the value, not the formula guard apostrophe, in the preview grid' -TestCases @(
        @{Text="'=1+1";Shown='=1+1'},@{Text="'+SUM(A1)";Shown='+SUM(A1)'},@{Text="'-2";Shown='-2'},@{Text="'@cmd";Shown='@cmd'},
        @{Text="'`tx";Shown="`tx"},@{Text="O'Brien";Shown="O'Brien"},@{Text="'plain";Shown="'plain"},@{Text='';Shown=''}
    ) {
        param($Text,$Shown)
        & (Get-Module PRA.Gui) { param($t) Remove-PraGuiCsvGuard $t } $Text | Should -BeExactly $Shown
    }
    It 'flushes the last partial line and the hidden-lines counter at the end of the run, and only hides a short event text when it is the whole line' {
        $global:PraGuiLinesProbe=New-Object 'Collections.Generic.List[string]'
        Mock Add-PraGuiLine -ModuleName PRA.Gui { $global:PraGuiLinesProbe.Add($Text) }
        function New-FeedProbe([string]$Text) {
            $o=New-Object psobject
            Add-Member -InputObject $o -MemberType ScriptMethod -Name TakeText -Value ([scriptblock]::Create("'"+$Text.Replace("'","''")+"'"))
            $o
        }
        function Invoke-OutputProbe($Run,[switch]$Final) { if ($Final) { & (Get-Module PRA.Gui) { param($r) Add-PraGuiEngineOutput $r -Final } $Run } else { & (Get-Module PRA.Gui) { param($r) Add-PraGuiEngineOutput $r } $Run } }
        try {
            # 1. The last line has no end of line: it appears only with -Final.
            $run=@{ Output=(New-FeedProbe "first`r`nlast without newline"); Partial=''; Seen=(New-Object 'Collections.Generic.List[string]'); Hidden=0 }
            Invoke-OutputProbe $run
            ($global:PraGuiLinesProbe -join '|') | Should -BeExactly 'engine · first'
            $run.Output=(New-FeedProbe '')
            Invoke-OutputProbe $run -Final
            $global:PraGuiLinesProbe[-1] | Should -BeExactly 'engine · last without newline'
            # 2. More than 60 lines in one tick: the counter is flushed at the end.
            $global:PraGuiLinesProbe.Clear()
            $many=((1..70 | ForEach-Object { 'line '+$_ }) -join "`n")+"`n"
            $run=@{ Output=(New-FeedProbe $many); Partial=''; Seen=(New-Object 'Collections.Generic.List[string]'); Hidden=0 }
            Invoke-OutputProbe $run
            $run.Hidden | Should -Be 10
            $run.Output=(New-FeedProbe '')
            Invoke-OutputProbe $run -Final
            $run.Hidden | Should -Be 0
            @($global:PraGuiLinesProbe | Where-Object { $_ -like '*10 output line(s)*' }).Count | Should -Be 1
            # 3. A short event text hides only a line equal to it; a long one is found inside a console line.
            $global:PraGuiLinesProbe.Clear()
            $run=@{ Output=(New-FeedProbe "Done`r`nDone with warnings in the module`r`n[OK] A long event text that the engine also prints`r`n"); Partial=''; Seen=(New-Object 'Collections.Generic.List[string]'); Hidden=0 }
            $run.Seen.Add('Done'); $run.Seen.Add('A long event text that the engine also prints')
            Invoke-OutputProbe $run
            ($global:PraGuiLinesProbe -join '|') | Should -BeExactly 'engine · Done with warnings in the module'
        } finally { Remove-Variable PraGuiLinesProbe -Scope Global -ErrorAction SilentlyContinue }
    }
    It 'sees no change of a run setting when only the letter case differs from the configuration file, and still sees a real change' -Tag 'Release313h' {
        $result = & (Get-Module PRA.Gui) {
            $saved = $script:Gui
            try {
                $box = { param($text) [pscustomobject]@{ Text = $text } }
                $radio = { param($on) [pscustomobject]@{ IsChecked = $on } }
                $script:Gui = @{
                    Defaults = @{ Env = 'PROD'; Dc = 'dc01.example.invalid'; Tenant = 'contoso.onmicrosoft.com'; Org = 'Contoso.onmicrosoft.com'; AppId = 'AAAA'; Thumb = 'ABCDEF'; Repl = $false }
                    Controls = @{ F_Env = (& $box 'prod'); F_Dc = (& $box 'DC01.EXAMPLE.INVALID'); F_Tenant = (& $box 'CONTOSO.ONMICROSOFT.COM'); F_Org = (& $box 'contoso.onmicrosoft.com')
                        F_AppId = (& $box 'aaaa'); F_Thumb = (& $box 'abcdef'); F_Repl = (& $radio $false); S_Signin_Cert = (& $radio $true); S_Signin_Wam = (& $radio $false) } }
                $same = Get-PraGuiOverride
                $modifiedEnv = Test-PraGuiModified 'Env'
                $script:Gui.Controls.F_Env.Text = 'OTHER'
                $script:Gui.Controls.F_Thumb.Text = '123456'
                [pscustomobject]@{ SameCount = @($same.Keys).Count; ModifiedEnv = $modifiedEnv; Changed = (Get-PraGuiOverride); ChoiceSet = (Test-GuiOrdinal 'Cert' 'cert' -IgnoreCase) }
            } finally { $script:Gui = $saved }
        }
        $result.SameCount | Should -Be 0
        $result.ModifiedEnv | Should -BeFalse
        $result.Changed.Environment | Should -BeExactly 'OTHER'
        $result.Changed.Cloud.CertificateThumbprint | Should -BeExactly '123456'
        $result.ChoiceSet | Should -BeTrue
    }
    It 'accepts the typed confirmation in any letter case, ignoring surrounding spaces, and rejects any other word' -TestCases @(
        @{Typed='CONVERT';Action='Convert';Ok=$true},@{Typed='convert';Action='Convert';Ok=$true},@{Typed='  CoNvErT ';Action='Convert';Ok=$true}
        @{Typed='recover';Action='Recover';Ok=$true},@{Typed='Finalize';Action='Finalize';Ok=$true}
        @{Typed='RECOVER';Action='Convert';Ok=$false},@{Typed='CONVERTX';Action='Convert';Ok=$false},@{Typed='';Action='Convert';Ok=$false},@{Typed='CONVERT';Action='';Ok=$false}
    ) {
        param($Typed,$Action,$Ok)
        & (Get-Module PRA.Gui) { param($t,$a) Test-PraGuiConfirmation $t $a } $Typed $Action | Should -Be $Ok
    }
    It 'refuses the typed confirmation <Name> although the culture comparison would match it' -TestCases @(
        @{Name='CONVERT + U+0001';Typed=('CONVERT' + [string][char]1);Action='Convert'}
        @{Name='CONVERT + U+200B';Typed=('CONVERT' + [string][char]0x200B);Action='Convert'}
        @{Name='CON + U+200B + VERT';Typed=('CON' + [string][char]0x200B + 'VERT');Action='Convert'}
        @{Name='recover + U+00AD';Typed=('recover' + [string][char]0xAD);Action='Recover'}
        @{Name='FINALIZE + U+0008';Typed=('FINALIZE' + [string][char]8);Action='Finalize'}
    ) {
        param($Name,$Typed,$Action)
        & (Get-Module PRA.Gui) { param($t,$a) Test-PraGuiConfirmation $t $a } $Typed $Action | Should -BeFalse
    }
    It 'refuses a request value without an ordinal match, and keeps the official spelling of a case variant' {
        foreach ($suffix in [string][char]1, [string][char]0x200B) {
            { New-PraGuiRequest -Action ('Convert' + $suffix) } | Should -Throw '*outside the allowed set*'
            { New-PraGuiRequest -Mode ('Preview' + $suffix) } | Should -Throw '*outside the allowed set*'
            { New-PraGuiRequest -Phase ('AD' + $suffix) } | Should -Throw '*outside the allowed set*'
            { New-PraGuiRequest -Scope ('All' + $suffix) } | Should -Throw '*outside the allowed set*'
        }
        $request = New-PraGuiRequest -Action 'convert' -Mode 'preview' -Phase 'ad'
        $request.Action | Should -BeExactly 'Convert'
        $request.Mode | Should -BeExactly 'Preview'
        $request.Phase | Should -BeExactly 'AD'
    }
    It 'compares configuration paths as full Windows paths, ignoring case, a trailing slash and redundant segments' -TestCases @(
        @{A='C:\Users\Nico\config.psd1';B='c:\users\NICO\CONFIG.PSD1';Ok=$true}
        @{A='  C:\Users\Nico\config.psd1  ';B='C:\Users\Nico\config.psd1';Ok=$true}
        @{A='C:\Users\Nico\x\..\config.psd1';B='C:\Users\Nico\config.psd1';Ok=$true}
        @{A='C:\Users\Nico\folder\';B='c:\users\nico\FOLDER';Ok=$true}
        @{A='C:\Users\Nico\config.psd1';B='C:\Users\Nico\other.psd1';Ok=$false}
        @{A='';B='C:\Users\Nico\config.psd1';Ok=$false}
        @{A='C:\bad|path';B='C:\Users\Nico\config.psd1';Ok=$false}
    ) {
        param($A,$B,$Ok)
        & (Get-Module PRA.Gui) { param($x,$y) Test-PraGuiSamePath $x $y } $A $B | Should -Be $Ok
    }
    It 'keeps the confirmation tooltip, the status text and the refusal message in line with the case-insensitive rule' {
        $xaml=[IO.File]::ReadAllText((Join-Path (Split-Path $script:GuiModule -Parent) 'PRA.Gui.xaml'))
        $xaml | Should -Not -Match 'Saisir exactement'
        $xaml | Should -Match 'capitals or not'
        $code=[IO.File]::ReadAllText($script:GuiModule)
        $code | Should -Not -Match 'ConfigPathText\.Text\.Trim\(\) -cne'
        $code | Should -Not -Match 'ConfirmationText\.Text -c(eq|ne)'
        $code | Should -Not -Match 'saisir exactement|Confirmer exactement'
    }
}

Describe 'Child process launch hardening - only the three pipe ends reach the cloud child, and a failed start says why' {
    It 'gives the child the three pipe ends only: another inheritable handle of the window is not inherited and the streams still end' {
        $runtime=New-GuiTestRoot
        $fixture=Join-Path $runtime.Root 'leak-fixture.ps1'
        Write-GuiTestFile $fixture @'
param($Action,$Mode,$ConfigPath,$Scope,$Phase,$Identity,$MaxObjects)
$ErrorActionPreference='Stop'
Add-Type -Namespace PraLeak -Name Native -MemberDefinition '[DllImport("kernel32.dll", SetLastError=true)] public static extern bool WriteFile(System.IntPtr h, byte[] b, uint n, out uint w, System.IntPtr o);'
$written=[uint32]0
$ok=[PraLeak.Native]::WriteFile([IntPtr][long]$env:PRA_TEST_LEAK,[byte[]](65),1,[ref]$written,[IntPtr]::Zero)
[Console]::Out.WriteLine('leak-write='+$ok)
[Console]::Out.WriteLine('stdout-works=True')
exit 0
'@
        # An inheritable pipe end that is NOT one of the child's three: the former bInheritHandles = TRUE launch leaked it.
        $leak=New-Object IO.Pipes.AnonymousPipeServerStream([IO.Pipes.PipeDirection]::In,[IO.HandleInheritability]::Inheritable)
        $env:PRA_TEST_LEAK=[string]$leak.ClientSafePipeHandle.DangerousGetHandle().ToInt64()
        try {
            $request=New-PraGuiRequest -Phase Both
            $events=Join-Path $runtime.Root ([guid]::NewGuid().ToString('N')+'.events.jsonl')
            $command=Get-PraGuiCommand $runtime.Root $runtime.Config $request -ScriptPath $fixture
            $command.NeedsCloudWindow | Should -BeTrue
            $child=Start-PraGuiChildProcess $command $runtime.Root $events
            try {
                $child.Process.WaitForExit(60000) | Should -BeTrue
                $child.Output.IsCompleted | Should -BeTrue -Because 'a stray copy of a pipe end held by the child would keep the stream open'
                $child.Output.Result | Should -Match 'stdout-works=True'
                $child.Output.Result | Should -Match 'leak-write=False' -Because 'the child cannot write to a handle that was not in its handle list'
                # Both stream copies must have ended (they hold the .stdout/.stderr files open) before the evidence folder is removed.
                $deadline=[datetime]::UtcNow.AddSeconds(15)
                while(-not $child.Errors.IsCompleted -and [datetime]::UtcNow -lt $deadline){ Start-Sleep -Milliseconds 100 }
                $child.Errors.IsCompleted | Should -BeTrue -Because 'the copy of the standard error ends with the child'
                $leak.DisposeLocalCopyOfClientHandle()
                $buffer=New-Object byte[] 1
                $read=$leak.ReadAsync($buffer,0,1)
                $read.Wait(5000) | Should -BeTrue
                $read.Result | Should -Be 0 -Because 'no byte may arrive through a handle the child should not have inherited'
            } finally { $child.Process.Dispose() }
        } finally { Remove-Item Env:\PRA_TEST_LEAK -ErrorAction SilentlyContinue; $leak.Dispose() }
    }
    It 'puts the Win32 error code and its message in the error of a CreateProcess failure' {
        $runtime=New-GuiTestRoot
        $notProgram=Join-Path $runtime.Root 'not-a-program.exe'
        Write-GuiTestFile $notProgram 'this is text, not an executable'
        $command=[pscustomobject]@{ FilePath=$notProgram; Arguments=''; NeedsCloudWindow=$true; Tokens=@(); Display='' }
        $events=Join-Path $runtime.Root ([guid]::NewGuid().ToString('N')+'.events.jsonl')
        $failure=$null
        try { $null=Start-PraGuiChildProcess $command $runtime.Root $events } catch { $failure=$_.Exception.Message }
        $failure | Should -Match 'CreateProcess failed'
        $failure | Should -Match 'Win32 error (?<code>\d+): ' -Because 'the code and its system message are both in the error'
        $code=[int][regex]::Match($failure,'Win32 error (\d+):').Groups[1].Value
        $failure | Should -Match ([regex]::Escape((New-Object ComponentModel.Win32Exception $code).Message.Substring(0,8)))
        (Get-PraWin32ErrorText 5) | Should -Match '^5: '
    }
    It 'does not lose the error output and the exit code of a child that dies at start' {
        $runtime=New-GuiTestRoot
        $command=[pscustomobject]@{ FilePath=$env:ComSpec; Arguments='/d /c "echo early-failure-text 1>&2 & exit 7"'; NeedsCloudWindow=$true; Tokens=@(); Display='' }
        $events=Join-Path $runtime.Root ([guid]::NewGuid().ToString('N')+'.events.jsonl')
        $failure=''; $child=$null
        try { $child=Start-PraGuiChildProcess $command $runtime.Root $events } catch { $failure=$_.Exception.Message }
        if ($child) {
            # The window won the race and attached: the same facts are in the collectors.
            try {
                $child.Process.WaitForExit(30000) | Should -BeTrue
                $child.Process.ExitCode | Should -Be 7
                $child.Errors.Result | Should -Match 'early-failure-text'
            } finally { $child.Process.Dispose() }
        } else {
            $failure | Should -Match 'early-failure-text'
            $failure | Should -Match 'exit code 7'
        }
    }
}

Describe 'Console 3.0.0 - phase, replication option, identity preview, counters, backup, journey, Back after Apply' {
    It 'behaves as the owner asked (one window, synthetic probes, no engine run)' {
        $runtime=New-GuiTestRoot
        $probe=Join-Path $runtime.Root 'wpf-probe-2b.ps1'
        Write-GuiTestFile $probe @'
param($Common,$Gui,$Root,$Config)
$ErrorActionPreference='Stop'
Import-Module $Common -Force
Import-Module $Gui -Force
function Pump([int]$Milliseconds=60){
 $frame=New-Object Windows.Threading.DispatcherFrame
 $pump=New-Object Windows.Threading.DispatcherTimer
 $pump.Interval=[timespan]::FromMilliseconds($Milliseconds);$pump.Tag=$frame
 $pump.Add_Tick({param($s)$s.Tag.Continue=$false;$s.Stop()})
 $pump.Start();[Windows.Threading.Dispatcher]::PushFrame($frame)
}
function Click($Window,[string]$Name){ $Window.Controls[$Name].RaiseEvent((New-Object Windows.RoutedEventArgs ([Windows.Controls.Button]::ClickEvent))) }
function InGui([scriptblock]$Block,$Argument=$null){ & (Get-Module PRA.Gui) $Block $Argument }
$script:Role='Both'
$detect={ param($Request) [pscustomobject]@{ Lights=@([ordered]@{Name='RSAT ActiveDirectory';Status='Ok';Detail='synthetic'}); AD=$true; Cloud=($script:Role -ceq 'Both'); Role=$script:Role } }
$script:Mode='found'
$identity={ param($Identity)
  switch ($script:Mode) {
    'found' { [pscustomobject]@{Success=$true;Found=$true;Count=1;DisplayName='Alice Vance';UserPrincipalName='alice.vance@example.invalid';MailboxType='User mailbox'} }
    'missing' { [pscustomobject]@{Success=$true;Found=$false;Count=0} }
    'ambiguous' { [pscustomobject]@{Success=$true;Found=$false;Count=3} }
    default { throw 'Active Directory is not reachable.' } } }
$g=New-PraGuiWindow -Root $Root -ConfigPath $Config -Version 'Synthetic' -PrerequisiteProbe $detect -IdentityProbe $identity
$g.Form.Show()
try {
 $c=$g.Controls
 # --- A1: the configuration says Phase AD, the server can do both sides: the batch runs in one go, with no transfer package
 Click $g 'BtnNext'; $c.T_Convert.IsChecked=$true; Pump
 if($c.PhasePillText.Text -cne 'Phase: Both'){throw ('Phase pill: '+$c.PhasePillText.Text)}
 if($c.PhaseText.Text -notmatch 'no transfer package is needed'){throw 'The phase text does not say that no package is needed'}
 $c.T_Recover.IsChecked=$true; Pump
 if($c.PhasePillText.Text -cne 'Phase: Both' -or $c.PhaseText.Text -notmatch 'no transfer package'){throw 'Recover on a server that does both sides is not Phase Both'}
 $c.T_Convert.IsChecked=$true; Pump
 # Expert mode can still force a phase.
 $c.S_ExpPhase_AD.IsChecked=$true; Pump
 if($c.PhasePillText.Text -cne 'Phase: AD' -or $c.PhaseText.Text -notmatch 'transfer package'){throw 'Expert mode did not force the AD phase'}
 $c.S_ExpPhase_Auto.IsChecked=$true; Pump
 # A server that can do the AD side only: AD phase and a package.
 $script:Role='AD'; Click $g 'BtnRecheck'; Pump
 if($c.PhasePillText.Text -cne 'Phase: AD'){throw ('AD-only server: '+$c.PhasePillText.Text)}
 $script:Role='Both'; Click $g 'BtnRecheck'; Pump
 # --- D: the replication checkbox is an ordinary run setting (marker, reset, override, extra step)
 Click $g 'BtnNext'
 $before=@(InGui { Get-PraGuiPlanTitle 'Convert' 'Both' })
 if($before -contains 'Active Directory replication'){throw 'The replication step is listed while the option is off'}
 Click $g 'BtnBack'
 Click $g 'BtnChange'
 $c.F_Repl.IsChecked=$true; Pump
 if($c.M_Repl.Visibility -cne 'Visible'){throw 'The replication checkbox is not marked as modified'}
 $override=InGui { Get-PraGuiOverride }
 if(-not $override.Directory -or $override.Directory.ForceReplication -ne $true){throw 'The checkbox is not part of the overrides'}
 $after=@(InGui { Get-PraGuiPlanTitle 'Convert' 'Both' })
 if([array]::IndexOf($after,'Active Directory replication') -lt 0 -or [array]::IndexOf($after,'Active Directory replication') -ne ([array]::IndexOf($after,'Entra Connect synchronisation')-1)){throw 'The replication step is not just before the Entra Connect step'}
 if(@(InGui { Get-PraGuiPlanTitle 'Convert' 'Cloud' }) -contains 'Active Directory replication'){throw 'The cloud phase has no replication step'}
 $made=InGui { New-PraGuiRunConfig }
 if($made.Keys -cnotcontains 'Directory.ForceReplication' -or [IO.File]::ReadAllText($made.Path) -notmatch 'ForceReplication = \$true'){throw 'The effective configuration does not carry the replication option'}
 Click $g 'R_Repl'
 if($c.F_Repl.IsChecked -or $c.M_Repl.Visibility -cne 'Collapsed'){throw 'Reset did not restore the replication option'}
 Click $g 'BtnDoneSettings'
 # --- A11: identity preview under the field
 Click $g 'BtnNext'; $c.T_Convert.IsChecked=$true; Pump
 $c.F_Identity.Text='alice'; Pump
 Click $g 'BtnCheckIdentity'; Pump
 if($c.IdentityInfo.Text -notmatch 'Alice Vance' -or $c.IdentityInfo.Text -notmatch 'alice.vance@example.invalid' -or $c.IdentityInfo.Text -notmatch 'User mailbox'){throw ('Identity found: '+$c.IdentityInfo.Text)}
 $script:Mode='missing'; Click $g 'BtnCheckIdentity'; Pump
 if($c.IdentityInfo.Text -notmatch 'Not found'){throw ('Identity missing: '+$c.IdentityInfo.Text)}
 $script:Mode='ambiguous'; Click $g 'BtnCheckIdentity'; Pump
 if($c.IdentityInfo.Text -notmatch '3 accounts match'){throw ('Identity ambiguous: '+$c.IdentityInfo.Text)}
 $script:Mode='error'; Click $g 'BtnCheckIdentity'; Pump
 if($c.IdentityInfo.Text -notmatch 'Could not check: Active Directory is not reachable'){throw ('Identity error: '+$c.IdentityInfo.Text)}
 $c.F_Identity.Text='alice2'; Pump
 if($c.IdentityInfo.Text -ne ''){throw 'Typing again must clear the previous answer'}
 # --- A8: title of the verification
 $rows=@(
   [pscustomobject]@{Type='User';Status='Ok'}, [pscustomobject]@{Type='Shared';Status='Ok'})
 InGui { param($r) $g=$script:Gui; $g.Action='Convert'; $g.Previewed=$true; $g.VerRows.Clear(); foreach($x in $r){ $g.VerRows.Add((New-PraGuiRow @{Type=$x.Type;Status=$x.Status;Name='n';Upn='u';Result='r';Plain=''})) }; Update-PraGuiVerifyView } $rows
 if($c.SumTitle.Text -cne '2 mailboxes will be converted (1 user, 1 shared) · nothing blocking'){throw ('Verify title: '+$c.SumTitle.Text)}
 InGui { param($r) $g=$script:Gui; $g.VerRows.Clear(); $g.VerRows.Add((New-PraGuiRow @{Type='User';Status='Fail';Name='n';Upn='u';Result='r';Plain=''})); Update-PraGuiVerifyView } $rows
 if($c.SumTitle.Text -cne '1 mailbox will be converted (1 user) · 1 blocking'){throw ('Verify title (singular): '+$c.SumTitle.Text)}
 # --- A4 / A2 / A3: counters, backup path, whole-batch steps in the journey
 InGui {
   $g=$script:Gui
   Initialize-PraGuiRunModel @{Action='Convert';Phase='Both'}
   Set-PraGuiPlanFromEvent ([pscustomobject]@{steps=@([pscustomobject]@{id='s1';label='Active Directory connection';count=$null},[pscustomobject]@{id='s2';label='Targets and planned changes';count=$null},[pscustomobject]@{id='s3';label='Entra Connect synchronisation';count=$null})})
   Invoke-PraGuiCountEvent ([pscustomobject]@{count=2;stepIds=@('s2')})
   Invoke-PraGuiStepEvent ([pscustomobject]@{id='s2';index=2;title='Targets and planned changes';state='running'})
   Invoke-PraGuiItemEvent ([pscustomobject]@{stepId='s2';status='Ok';text='fine';identity='11111111-1111-1111-1111-111111111111';name='alice@example.invalid';detail='';backup='D:\PRA\Backups\Batch-x\Convert.json'})
 }
 $row=$g.Model.ById['s2']
 if($row.Counter -cne '1 / 2 objects' -or [Math]::Abs([double]$row.Progress-0.5) -gt 0.001){throw ('Running counter: '+$row.Counter+' '+$row.Progress)}
 if($g.Model.ById['s1'].Counter -cne ''){throw 'A batch-wide step must have no object counter'}
 InGui { Show-PraGuiObjectCard ($script:Gui.Model.Objects['s2'][0]) }
 if($c.CardBackup.Text -cne 'D:\PRA\Backups\Batch-x\Convert.json' -or -not $c.BtnCardOpen.IsEnabled -or -not $c.BtnCardCopy.IsEnabled){throw ('Backup of the card: '+$c.CardBackup.Text)}
 $wholeBatch=@($c.Journey.ItemsSource | Where-Object { $_.Caption -like 'Whole batch*' })
 if($wholeBatch.Count -ne 2){throw ('Whole-batch steps in the journey: '+$wholeBatch.Count)}
 # --- the wait of a step is shown in the detail pane: what, attempt, next check, and how long it may take
 InGui {
   Invoke-PraGuiStepEvent ([pscustomobject]@{id='s3';index=3;title='Entra Connect synchronisation';state='running'})
   Invoke-PraGuiProgressEvent ([pscustomobject]@{stepId='s3';current=30;total=900;attempt=3;maxAttempts=13;nextInSeconds=10;text='Entra Connect synchronisation cycle in progress on SRV-AADC01'})
   Show-PraGuiStepDetail $script:Gui.Model.ById['s3']
 }
 if($c.WaitBox.Visibility -cne 'Visible' -or $c.WaitTitle.Text -notmatch 'Waiting: Entra Connect synchronisation cycle' -or $c.WaitLine.Text -notmatch 'Attempt 3 of 13' -or $c.WaitLine.Text -notmatch 'next check in \d+ s' -or $c.WaitNormal.Text -notmatch 'This is normal: it can take up to 15 minutes'){throw ('Wait box: '+$c.WaitTitle.Text+' | '+$c.WaitLine.Text+' | '+$c.WaitNormal.Text)}
 InGui { Invoke-PraGuiStepEvent ([pscustomobject]@{id='s3';index=3;title='Entra Connect synchronisation';state='ok'}); Show-PraGuiStepDetail $script:Gui.Model.ById['s3'] }
 if($c.WaitBox.Visibility -cne 'Collapsed'){throw 'The wait box stays after the step ended'}
 # --- A5: after an Apply, Back never leads to the verification of the same operation
 InGui { $g=$script:Gui; $result=[pscustomobject]@{status='Success';success=1;pending=0;planned=0;skipped=0;batchId='abcd1234';nextSteps=@();transferPackage='';transferPackageKind='';logFile='x.log';htmlReport='x.html';globalReport='g.html'}; $g.LastResult=$result; $g.LastRun=[pscustomobject]@{Purpose='Run';Request=@{Action='Convert';Phase='Both';Mode='Apply'};Valid=$true;Result=$result;Seconds=1;StartedAt=[datetime]::Now;Base='';Issue='';ExitCode=0;Config=$null}; Show-PraGuiPage 4 }
 if($c.BtnBack.Visibility -cne 'Collapsed'){throw 'Back is offered on the Run page after an Apply'}
 if(InGui { Test-PraGuiPageReachable 3 }){throw 'Verify is reachable after an Apply'}
 if(InGui { Test-PraGuiPageReachable 2 }){throw 'Task is reachable after an Apply'}
 if(-not (InGui { Test-PraGuiPageReachable 5 })){throw 'What next is not reachable after an Apply'}
 # --- B / A12: the report button is next to the status on Next steps and opens the global report
 InGui { Update-PraGuiNext }
 if($c.BtnReport.Content -cne 'Open global report'){throw 'The report button does not name the global report'}
 if(-not [object]::ReferenceEquals($c.BtnReport.Parent.Parent,$c.NextPill.Parent.Parent)){throw 'Open report is not next to the status pill'}
 # --- A9: the preview button is back to the themed secondary style after a preview
 InGui { $g=$script:Gui; $g.LastRun=$null; $g.Previewed=$true; Show-PraGuiPage 3 }
 if($c.BtnPreview.ReadLocalValue([Windows.Controls.Button]::StyleProperty) -ne [Windows.DependencyProperty]::UnsetValue){throw 'Preview again has a local style (unthemed white button in the dark theme)'}
 [Console]::WriteLine('WPF-2B-PASS')
} finally {$g.Form.Close()}
'@
        $tokens=@('-NoProfile','-NonInteractive','-STA','-File',$probe,'-Common',$script:GuiCommon,'-Gui',$script:GuiModule,'-Root',$runtime.Root,'-Config',$runtime.Config)
        $info=New-Object Diagnostics.ProcessStartInfo
        $info.FileName=(Join-Path $PSHOME 'pwsh.exe');$info.Arguments=(@($tokens|ForEach-Object{ConvertTo-PraGuiNativeArgument $_})-join ' ')
        $info.UseShellExecute=$false;$info.CreateNoWindow=$true;$info.RedirectStandardOutput=$true;$info.RedirectStandardError=$true
        $process=[Diagnostics.Process]::Start($info)
        $out=$process.StandardOutput.ReadToEndAsync();$err=$process.StandardError.ReadToEndAsync()
        try {
            $process.WaitForExit(180000) | Should -BeTrue
            $process.ExitCode | Should -Be 0 -Because ($out.Result+$err.Result)
            $out.Result | Should -Match 'WPF-2B-PASS'
        } finally { $process.Dispose() }
    }
    It 'words the Recover tile with the transfer package, lights have a neutral not-applicable state, the report button sits in the status card' {
        $xaml=[IO.File]::ReadAllText((Join-Path $script:GuiProjectRoot 'module\PRA.Gui.xaml'))
        $xaml | Should -Match 'using the backup kept in the batch or in the transfer package'
        $xaml | Should -Match 'Value="NA"'
        $xaml | Should -Match 'x:Name="IdentityInfo"'
        $xaml | Should -Match 'x:Name="F_Repl"'
    }
}

Describe 'Console 3.0.0 - packages: configured Environment, Finalize package in the Inbox, checks off the window thread' {
    It 'refuses a package made for another Environment, offers "Complete a rollback" for a Finalize package of the Inbox, and imports without freezing' {
        $runtime=New-GuiTestRoot
        Write-GuiTestFile (Join-Path $runtime.Root 'module\PRA.Gui.Directory.ps1') @'
param($ConfigPath,$ResultPath,$Identity,$PackagePath,$Environment,$BackupFolder,[switch]$Import)
if($PackagePath){
 Import-Module $env:PRA_TEST_COMMON -Force
 Start-Sleep -Milliseconds 700
 try {
  if($Import){ $r=Import-PraTransferPackage -Path $PackagePath -BackupFolder $BackupFolder -Environment $Environment; $a=@{Success=$true;Mode='Import';Kind=$r.Kind;BatchId=$r.BatchId;Name=$r.Name;Folders=@($r.Folders);Created=@($r.Created);Existing=@($r.Existing)} }
  else { $i=Get-PraTransferPackage -Path $PackagePath -Environment $Environment; $a=@{Success=$true;Mode='Verify';Valid=[bool]$i.Valid;Error=[string]$i.Error;Kind=[string]$i.Kind;Environment=[string]$i.Environment;BatchId=[string]$i.BatchId;Name=[string]$i.Name;SizeBytes=[long]$i.SizeBytes;CreatedUtc=[string]$i.CreatedUtc;EntryCount=[int]$i.EntryCount} }
 } catch { $a=@{Success=$false;Error=$_.Exception.Message} }
 [IO.File]::WriteAllText($ResultPath,($a|ConvertTo-Json -Depth 5),(New-Object Text.UTF8Encoding($false)))
 exit 0
}
[IO.File]::WriteAllText($ResultPath,(@{Success=$true;Server='dc.synthetic.invalid';Units=@()}|ConvertTo-Json -Depth 4))
exit 0
'@
        $inbox=Join-Path $runtime.Root 'Backups\Inbox'
        # A package made in another environment (the lab), and a Finalize package of this environment.
        $lab=New-GuiTestBatch $runtime
        $null=New-PraTransferPackage -Kind Convert -Environment 'LabSynthetic' -BatchId $lab.Id -Folders @($lab.Folder) -OutboxFolder $inbox
        Remove-Item -LiteralPath $lab.Folder -Recurse -Force
        $finalize=New-GuiTestBatch $runtime -Operation RecoverFinalize
        $null=New-PraTransferPackage -Kind Finalize -Environment 'GuiSynthetic' -BatchId $finalize.Id -Folders @($finalize.Folder) -OutboxFolder $inbox
        Remove-Item -LiteralPath $finalize.Folder -Recurse -Force
        $probe=Join-Path $runtime.Root 'wpf-probe-2c.ps1'
        Write-GuiTestFile $probe @'
param($Common,$Gui,$Root,$Config,$LabId,$FinalizeId)
$ErrorActionPreference='Stop'
Import-Module $Common -Force
Import-Module $Gui -Force
function Pump([int]$Milliseconds=60){
 $frame=New-Object Windows.Threading.DispatcherFrame
 $pump=New-Object Windows.Threading.DispatcherTimer
 $pump.Interval=[timespan]::FromMilliseconds($Milliseconds);$pump.Tag=$frame
 $pump.Add_Tick({param($s)$s.Tag.Continue=$false;$s.Stop()})
 $pump.Start();[Windows.Threading.Dispatcher]::PushFrame($frame)
}
function Click($Window,[string]$Name){ $Window.Controls[$Name].RaiseEvent((New-Object Windows.RoutedEventArgs ([Windows.Controls.Button]::ClickEvent))) }
function WaitJobs($Window,[int]$Seconds=90){ $deadline=[datetime]::UtcNow.AddSeconds($Seconds); do { Pump 100 } while(($Window.PkgJob -or $Window.PkgQueue.Count) -and [datetime]::UtcNow -lt $deadline); if($Window.PkgJob -or $Window.PkgQueue.Count){throw 'Package jobs did not end'} }
$detect={ param($Request) [pscustomobject]@{ Lights=@([ordered]@{Name='RSAT ActiveDirectory';Status='Ok';Detail='synthetic'}); AD=$true; Cloud=$true; Role='Both' } }
$g=New-PraGuiWindow -Root $Root -ConfigPath $Config -Version 'Synthetic' -PrerequisiteProbe $detect
$g.Form.Show()
try {
 $c=$g.Controls
 # The packages of the Inbox are being checked by a child process: the constructor returned at once, nothing is verified on this thread.
 if(-not $g.PkgJob -and -not $g.PkgQueue.Count -and $g.PkgCache.Count -lt 2){throw 'The Inbox packages were not queued for a background check'}
 if($g.HasFinalize -and $g.PkgCache.Count -eq 0){throw 'HasFinalize was set before any check ended'}
 # M3: a Finalize package waiting in the Inbox makes the tile appear once it is verified.
 WaitJobs $g
 if(-not $g.HasFinalize -or $c.T_Finalize.Visibility -ne 'Visible'){throw 'A verified Finalize package of the Inbox did not make the Complete a rollback tile appear'}
 Click $g 'BtnNext'
 $c.T_Finalize.IsChecked=$true; Pump
 $row=@($g.BatchRows | Where-Object { $_.Package -and $_.Selectable })[0]
 if(-not $row -or -not $row.Selectable -or $row.State -notmatch 'verified'){throw 'The Finalize package is not listed as verified and selectable'}
 $c.BatchList.SelectedItem=$row; Pump
 if(Test-Path -LiteralPath (Join-Path $Root ('Backups\Finalize-'+$FinalizeId))){throw 'The package was extracted before being chosen'}
 Click $g 'BtnNext'
 if($g.PkgJob -eq $null -and $g.PkgQueue.Count -eq 0 -and $g.Page -eq 3){throw 'The import ran on the window thread'}
 if($c.Page1.IsEnabled){throw 'No busy state while the package is imported'}
 WaitJobs $g
 if($g.Page -ne 3 -or $g.SelectedBatch.Package -or -not ([string]$g.SelectedBatch.Path).Contains($FinalizeId)){throw ('The Finalize package was not imported on the way to Verify: '+$c.TaskError.Text)}
 if(@(Get-ChildItem -LiteralPath (Join-Path $Root 'Backups') -Directory -Force | Where-Object { $_.Name -like '.importing-*' }).Count){throw 'A staging folder was left behind'}
 # M1: a package made for another Environment is refused by the console, as by the command line.
 & (Get-Module PRA.Gui) { Show-PraGuiPage 2 }
 $c.T_Convert.IsChecked=$true; Pump; $c.Mode_Continue.IsChecked=$true; Pump; WaitJobs $g
 $labRow=@($g.BatchRows | Where-Object { $_.Package -and ([string]$_.Path) -like '*LabSynthetic*' })[0]
 if(-not $labRow){throw 'The package of another Environment is not listed'}
 if($labRow.Selectable -or $labRow.Level -ne 'Fail' -or $labRow.Sub -notmatch 'LabSynthetic' -or $labRow.Sub -notmatch 'GuiSynthetic'){throw ('The package of another Environment must be refused, naming both: '+$labRow.State+' / '+$labRow.Sub)}
 & (Get-Module PRA.Gui) { param($p) Start-PraGuiPackageImport $p { param($selected) } } ([string]$labRow.Path)
 WaitJobs $g
 if($c.TaskError.Text -notmatch 'Package refused' -or $c.TaskError.Text -notmatch 'Environment'){throw ('The import of a package of another Environment was not refused: '+$c.TaskError.Text)}
 if(Test-Path -LiteralPath (Join-Path $Root ('Backups\Batch-'+$LabId))){throw 'The refused package was extracted'}
 [Console]::WriteLine('WPF-2C-PASS')
} finally {$g.Form.Close()}
'@
        $env:PRA_TEST_COMMON=$script:GuiCommon
        $tokens=@('-NoProfile','-NonInteractive','-STA','-File',$probe,'-Common',$script:GuiCommon,'-Gui',$script:GuiModule,'-Root',$runtime.Root,'-Config',$runtime.Config,'-LabId',$lab.Id,'-FinalizeId',$finalize.Id)
        $info=New-Object Diagnostics.ProcessStartInfo
        $info.FileName=(Join-Path $PSHOME 'pwsh.exe');$info.Arguments=(@($tokens|ForEach-Object{ConvertTo-PraGuiNativeArgument $_})-join ' ')
        $info.UseShellExecute=$false;$info.CreateNoWindow=$true;$info.RedirectStandardOutput=$true;$info.RedirectStandardError=$true
        $process=[Diagnostics.Process]::Start($info)
        $out=$process.StandardOutput.ReadToEndAsync();$err=$process.StandardError.ReadToEndAsync()
        try {
            $process.WaitForExit(240000) | Should -BeTrue
            $process.ExitCode | Should -Be 0 -Because ($out.Result+$err.Result)
            $out.Result | Should -Match 'WPF-2C-PASS'
        } finally { $process.Dispose() }
    }
}

Describe 'Release 3.1.0 - Microsoft 365 reachability decides the phase (mocked probes, no network)' {
    It 'gives the verdict Ok, Partial or Fail from the answers of the two endpoints' {
        $verdict={ param($a,$b) Get-PraGuiNetworkVerdict @([pscustomobject]@{Host='login';Ok=$a},[pscustomobject]@{Host='outlook';Ok=$b}) }
        & (Get-Module PRA.Gui) $verdict $true $true | Should -BeExactly 'Ok'
        & (Get-Module PRA.Gui) $verdict $true $false | Should -BeExactly 'Partial'
        & (Get-Module PRA.Gui) $verdict $false $true | Should -BeExactly 'Partial'
        & (Get-Module PRA.Gui) $verdict $false $false | Should -BeExactly 'Fail'
    }
    It 'tests the two Microsoft 365 hosts over HTTPS through the default proxy, only in the default probe, with no runtime C#' {
        $source=[IO.File]::ReadAllText($script:GuiModule)
        $hosts=& (Get-Module PRA.Gui) { $script:GuiM365Hosts }
        $hosts | Should -Be @('login.microsoftonline.com','outlook.office365.com')
        $source | Should -Match 'Net\.Http\.HttpClientHandler'
        $source | Should -Not -Match 'Add-Type\s+(-TypeDefinition|-MemberDefinition)'
        $source | Should -Not -Match 'TcpClient|Test-NetConnection'
        ([regex]::Matches($source,'Start-PraGuiHttpsProbe')).Count | Should -Be 2 -Because 'the definition and the default probe of the window only'
    }
    It 'proposes Both, AD or Cloud from the programs and from the answer of Microsoft 365, without ever blocking the window' {
        $runtime=New-GuiTestRoot
        $probe=Join-Path $runtime.Root 'wpf-probe-net.ps1'
        Write-GuiTestFile $probe @'
param($Common,$Gui,$Root,$Config)
$ErrorActionPreference='Stop'
Import-Module $Common -Force
Import-Module $Gui -Force
function Pump([int]$Milliseconds=60){
 $frame=New-Object Windows.Threading.DispatcherFrame
 $pump=New-Object Windows.Threading.DispatcherTimer
 $pump.Interval=[timespan]::FromMilliseconds($Milliseconds);$pump.Tag=$frame
 $pump.Add_Tick({param($s)$s.Tag.Continue=$false;$s.Stop()})
 $pump.Start();[Windows.Threading.Dispatcher]::PushFrame($frame)
}
function Click($Window,[string]$Name){ $Window.Controls[$Name].RaiseEvent((New-Object Windows.RoutedEventArgs ([Windows.Controls.Button]::ClickEvent))) }
function Settle($Window,[int]$Seconds=10){ $end=[datetime]::UtcNow.AddSeconds($Seconds); while($Window.NetJob -and [datetime]::UtcNow -lt $end){ Pump 50 }; if($Window.NetJob){throw 'The Microsoft 365 check never ended'}; Pump 80 }
function Light($Window){ return ,@($Window.LightRows | Where-Object Name -ceq 'Microsoft 365 reachable')[0] }
$script:HasAd=$true
$detect={ param($Request) [pscustomobject]@{ Lights=@([ordered]@{Name='RSAT ActiveDirectory';Status=$(if($script:HasAd){'Ok'}else{'Fail'});Detail='synthetic'},[ordered]@{Name='ExchangeOnlineManagement';Status='Ok';Detail='synthetic'}); AD=$script:HasAd; Cloud=$true; Role=$(if($script:HasAd){'Both'}else{'Cloud'}) } }
$script:Mode=@{}
$script:Calls=New-Object 'Collections.Generic.List[string]'
$net={ param($HostName,$Seconds)
  $script:Calls.Add($HostName)
  switch ($script:Mode[$HostName]) {
    'ok' { [Threading.Tasks.Task]::FromResult([Net.Http.HttpResponseMessage]::new([Net.HttpStatusCode]::Unauthorized)) }
    'fail' { [Threading.Tasks.Task]::FromException([Net.Http.HttpRequestException]::new('No such host is known.')) }
    default { ([Threading.Tasks.TaskCompletionSource[object]]::new()).Task } } }
function New-NetWindow([bool]$Ad,[string]$Login,[string]$Outlook,[double]$Seconds=3){
  $script:HasAd=$Ad; $script:Mode=@{'login.microsoftonline.com'=$Login;'outlook.office365.com'=$Outlook}; $script:Calls.Clear()
  $window=New-PraGuiWindow -Root $Root -ConfigPath $Config -Version 'Synthetic' -PrerequisiteProbe $detect -NetworkProbe $net -NetworkSeconds $Seconds
  $window.Form.Show(); return $window
}
function Phase($Window,[string]$Tile){ Click $Window 'BtnNext'; $Window.Controls[$Tile].IsChecked=$true; Pump 80; return $Window.Controls.PhasePillText.Text }

# --- A: programs and both endpoints reach: Both, as before. The window is usable while the answer is awaited (the check is only pending, nothing waits).
$g=New-NetWindow $true 'ok' 'ok'
try {
 $c=$g.Controls
 if(-not $g.NetJob){throw 'The check did not start in the background'}
 if($c.RoleName.Text -cne 'Checking...' -or $c.BtnNext.IsEnabled){throw 'Both must not be proposed before the test ends'}
 if((Light $g).Status -cne 'Info'){throw ('No light while checking: '+(Light $g).Status+' of '+$g.LightRows.Count+' lights')}
 Settle $g
 if($c.RoleName.Text -cnotmatch 'AD \+ Cloud' -or (Light $g).Status -cne 'Ok' -or -not $c.BtnNext.IsEnabled){throw ('Reachable: '+$c.RoleName.Text+' / '+(Light $g).Status)}
 if($script:Calls.Count -ne 2 -or $script:Calls[0] -cne 'login.microsoftonline.com' -or $script:Calls[1] -cne 'outlook.office365.com'){throw 'The two endpoints are tested once each'}
 if((Phase $g 'T_Convert') -cne 'Phase: Both'){throw 'Phase must be Both when Microsoft 365 is reachable'}
 # Typing in a field does not test the network again; Check again does.
 & (Get-Module PRA.Gui) { Show-PraGuiPage 1 }
 $c.F_Env.Text='OtherEnv'; Pump 100
 if($script:Calls.Count -ne 2){throw 'A change of setting must not test the network again'}
 Click $g 'BtnRecheck'
 if(-not $g.NetJob -or $c.RoleName.Text -cne 'Checking...'){throw 'Check again must test again'}
 Settle $g
 if($script:Calls.Count -ne 4){throw 'Check again did not send the two requests'}
} finally { $g.Form.Close() }

# --- B: programs here, Microsoft 365 not reachable: AD, a clear light, the cloud task is refused, Expert mode can still force the phase.
$g=New-NetWindow $true 'fail' 'fail'
try {
 $c=$g.Controls
 Settle $g
 $light=Light $g
 if($c.RoleName.Text -cne 'AD' -or $light.Status -cne 'Warn'){throw ('Unreachable: '+$c.RoleName.Text+' / '+$light.Status)}
 if($light.Detail -cne 'Microsoft 365 not reachable from this server: the cloud part must run on another machine that reaches the Internet (two servers).'){throw ('Light text: '+$light.Detail)}
 if($c.RoleText.Text -cnotmatch 'two servers'){throw 'The role text does not explain'}
 if($g.Detect.Role -cne 'AD'){throw 'Role'}
 if((Phase $g 'T_Convert') -cne 'Phase: AD'){throw 'Phase must be AD when Microsoft 365 is not reachable'}
 if($c.PhaseText.Text -cnotmatch 'not reachable from this server'){throw 'The phase text does not say why'}
 if($c.BlockBox.Visibility -ne 'Collapsed'){throw 'The AD phase must not be blocked'}
 $c.T_Check.IsChecked=$true; Pump 80
 if($c.BlockBox.Visibility -ne 'Visible' -or $c.BlockText.Text -cnotmatch 'cannot do the cloud part yet: Microsoft 365 not reachable'){throw ('Check on an offline server: '+$c.BlockText.Text)}
 $c.T_Convert.IsChecked=$true; Pump 80
 $c.S_ExpPhase_Both.IsChecked=$true; Pump 80
 if($c.PhasePillText.Text -cne 'Phase: Both' -or $c.BlockBox.Visibility -ne 'Collapsed'){throw 'Expert mode must still be able to force the phase'}
} finally { $g.Form.Close() }

# --- C: only one endpoint answers: not reachable, the light names the one that does not answer
$g=New-NetWindow $true 'ok' 'fail'
try {
 Settle $g
 $light=Light $g
 if($g.Controls.RoleName.Text -cne 'AD' -or $light.Status -cne 'Warn' -or $light.Detail -cnotmatch '^Microsoft 365 not reachable from this server \(outlook\.office365\.com does not answer\): the cloud part must run on another machine'){throw ('Partial: '+$g.Controls.RoleName.Text+' / '+$light.Detail)}
 if($g.Detect.Net -cne 'Partial'){throw 'State Partial'}
} finally { $g.Form.Close() }

# --- D: no answer at all (time out): the window answers while waiting, then AD
$g=New-NetWindow $true 'hang' 'hang' 0.8
try {
 $watch=[Diagnostics.Stopwatch]::StartNew()
 Pump 150
 if(-not $g.NetJob -or $g.Controls.BtnNext.IsEnabled){throw 'The check must still be pending after 150 ms'}
 Settle $g
 if($watch.Elapsed.TotalSeconds -lt 0.6){throw 'The check ended before the time limit'}
 if($watch.Elapsed.TotalSeconds -gt 6){throw ('The check lasted too long: '+$watch.Elapsed)}
 if($g.Controls.RoleName.Text -cne 'AD' -or (Light $g).Status -cne 'Warn' -or $g.Detect.Net -cne 'Fail'){throw 'Time out must read as not reachable'}
 if(@($g.Lines | Where-Object { [string]$_.Text -cmatch 'no answer within' }).Count -lt 1){throw 'The time out is not written in the activity log'}
} finally { $g.Form.Close() }

# --- E: no RSAT: reachable gives Cloud, not reachable gives a red light and nothing to run
$g=New-NetWindow $false 'ok' 'ok'
try { Settle $g; if($g.Controls.RoleName.Text -cne 'Cloud' -or (Light $g).Status -cne 'Ok'){throw ('No RSAT, reachable: '+$g.Controls.RoleName.Text)} } finally { $g.Form.Close() }
$g=New-NetWindow $false 'fail' 'fail'
try {
 Settle $g
 $light=Light $g
 if($g.Controls.RoleName.Text -cne 'Nothing yet' -or $light.Status -cne 'Fail' -or $light.Detail -cnotmatch 'not reachable from this server: the cloud part cannot run here'){throw ('No RSAT, unreachable: '+$g.Controls.RoleName.Text+' / '+$light.Detail)}
 if($g.Controls.RoleText.Text -cnotmatch 'Microsoft 365 can be reached'){throw 'The role text does not explain'}
} finally { $g.Form.Close() }

# --- F: a probe that throws is a failure, not a crash; and without -NetworkProbe a probe-driven window never tests the network (existing behaviour)
$bad={ param($HostName,$Seconds) throw 'boom' }
$script:HasAd=$true
$g=New-PraGuiWindow -Root $Root -ConfigPath $Config -Version 'Synthetic' -PrerequisiteProbe $detect -NetworkProbe $bad -NetworkSeconds 1
$g.Form.Show()
try { Settle $g; if($g.Controls.RoleName.Text -cne 'AD' -or $g.Detect.Net -cne 'Fail'){throw 'A throwing probe must read as not reachable'} } finally { $g.Form.Close() }
$g=New-PraGuiWindow -Root $Root -ConfigPath $Config -Version 'Synthetic' -PrerequisiteProbe $detect
$g.Form.Show()
try { Pump 100; if($g.NetJob -or $g.Controls.RoleName.Text -cnotmatch 'AD \+ Cloud' -or @($g.LightRows | Where-Object Name -ceq 'Microsoft 365 reachable').Count){throw 'A probe-only window must not test the network'} } finally { $g.Form.Close() }
[Console]::WriteLine('NET-PHASE-PASS')
'@
        $tokens=@('-NoProfile','-NonInteractive','-STA','-File',$probe,'-Common',$script:GuiCommon,'-Gui',$script:GuiModule,'-Root',$runtime.Root,'-Config',$runtime.Config)
        $info=New-Object Diagnostics.ProcessStartInfo
        $info.FileName=(Join-Path $PSHOME 'pwsh.exe');$info.Arguments=(@($tokens|ForEach-Object{ConvertTo-PraGuiNativeArgument $_})-join ' ')
        $info.UseShellExecute=$false;$info.CreateNoWindow=$true;$info.RedirectStandardOutput=$true;$info.RedirectStandardError=$true
        $process=[Diagnostics.Process]::Start($info)
        $out=$process.StandardOutput.ReadToEndAsync();$err=$process.StandardError.ReadToEndAsync()
        try {
            $process.WaitForExit(120000) | Should -BeTrue
            $process.ExitCode | Should -Be 0 -Because ($out.Result+$err.Result)
            $out.Result | Should -Match 'NET-PHASE-PASS'
        } finally { $process.Dispose() }
    }
}

Describe 'Release 3.1.2 - the console says plainly why Microsoft 365 or Entra Connect cannot be used (mocked probes, no network)' -Tag 'Release312' {
    It 'puts a plain sentence before the technical message of a blocked connection, and leaves other errors as they are' {
        $why = { param($Exception) Get-PraGuiNetworkWhy $Exception }
        $blocked = [Net.Sockets.SocketException]::new(10013)
        $wrapped = [AggregateException]::new([Net.Http.HttpRequestException]::new($blocked.Message, $blocked))
        $text = & (Get-Module PRA.Gui) $why $wrapped
        $text | Should -BeExactly ('blocked on this server (firewall, proxy or security software): ' + $blocked.Message)
        $text | Should -Match ([regex]::Escape($blocked.Message)) -Because 'the technical detail is kept'
        (& (Get-Module PRA.Gui) $why ([AggregateException]::new([Net.Http.HttpRequestException]::new('x', [Net.Sockets.SocketException]::new(10061))))) | Should -Match '^refused by the network \(firewall or proxy\): '
        (& (Get-Module PRA.Gui) $why ([AggregateException]::new([Net.Http.HttpRequestException]::new('x', [Net.Sockets.SocketException]::new(11001))))) | Should -Match '^the name cannot be resolved \(DNS\): '
        (& (Get-Module PRA.Gui) $why ([AggregateException]::new([Net.Http.HttpRequestException]::new('No such host is known.')))) | Should -BeExactly 'No such host is known.'
    }
    It 'checks the Entra Connect server with the account (asynchronously), never blocks, and shows the plain reason in the Microsoft 365 log line' {
        $runtime = New-GuiTestRoot
        $syncConfig = Join-Path $runtime.Root 'sync.psd1'
        Write-GuiTestFile $syncConfig "@{Environment='GuiSynthetic'; Scope=@{Mode='Auto'}; Licensing=@{Enabled=`$false}; EntraConnect=@{Sync=`$true;Server='SRV-SYNC01'}; Execution=@{Phase='AD'}}"
        $probe = Join-Path $runtime.Root 'wpf-probe-sync.ps1'
        Write-GuiTestFile $probe @'
param($Common,$Gui,$Root,$Config,$SyncConfig)
$ErrorActionPreference='Stop'
Import-Module $Common -Force
Import-Module $Gui -Force
function Pump([int]$Milliseconds=60){
 $frame=New-Object Windows.Threading.DispatcherFrame
 $pump=New-Object Windows.Threading.DispatcherTimer
 $pump.Interval=[timespan]::FromMilliseconds($Milliseconds);$pump.Tag=$frame
 $pump.Add_Tick({param($s)$s.Tag.Continue=$false;$s.Stop()})
 $pump.Start();[Windows.Threading.Dispatcher]::PushFrame($frame)
}
function Click($Window,[string]$Name){ $Window.Controls[$Name].RaiseEvent((New-Object Windows.RoutedEventArgs ([Windows.Controls.Button]::ClickEvent))) }
function SettleSync($Window,[int]$Seconds=10){ $end=[datetime]::UtcNow.AddSeconds($Seconds); while($Window.SyncJob -and [datetime]::UtcNow -lt $end){ Pump 50 }; if($Window.SyncJob){throw 'The Entra Connect check never ended'}; Pump 80 }
function Settle($Window,[int]$Seconds=10){ $end=[datetime]::UtcNow.AddSeconds($Seconds); while($Window.NetJob -and [datetime]::UtcNow -lt $end){ Pump 50 }; if($Window.NetJob){throw 'The Microsoft 365 check never ended'}; Pump 80 }
function SyncLight($Window){ return ,@($Window.LightRows | Where-Object Name -ceq 'Entra Connect sync')[0] }
$detect={ param($Request) [pscustomobject]@{ Lights=@([ordered]@{Name='RSAT ActiveDirectory';Status='Ok';Detail='synthetic'},[ordered]@{Name='ExchangeOnlineManagement';Status='Ok';Detail='synthetic'},[ordered]@{Name='Entra Connect sync';Status='Ok';Detail='The synchronisation is started on SRV-SYNC01.'}); AD=$true; Cloud=$true; Role='Both' } }
$script:Calls=New-Object 'Collections.Generic.List[string]'
$script:Answer=$null; $script:Done=$false; $script:Boom=$false
$syncProbe={ param($Server,$Seconds)
  $script:Calls.Add($Server+'/'+$Seconds)
  if($script:Boom){ throw 'boom' }
  $handle=[pscustomobject]@{ Done=$false; Answer=$script:Answer }
  Add-Member -InputObject $handle -MemberType ScriptProperty -Name IsCompleted -Value { $this.Done }
  Add-Member -InputObject $handle -MemberType ScriptMethod -Name GetResult -Value { param([bool]$TimedOut) $this.Answer }
  $script:Handle=$handle
  $handle }
$denied=[pscustomobject]@{ Ok=$false; Kind='Denied'; Server='SRV-SYNC01'; Reason='this account has no right on SRV-SYNC01: it must be allowed to open a remote session there (member of Remote Management Users or Administrators) and to use Entra Connect (member of ADSyncOperators)'; Technical='Access is denied' }
$accepted=[pscustomobject]@{ Ok=$true; Kind='Ok'; Server='SRV-SYNC01'; Reason='SRV-SYNC01 accepts this account and Entra Connect answers'; Technical='' }
function New-SyncWindow($Answer,[string]$ConfigPath){
  $script:Answer=$Answer; $script:Calls.Clear(); $script:Boom=$false
  $window=New-PraGuiWindow -Root $Root -ConfigPath $ConfigPath -Version 'Synthetic' -PrerequisiteProbe $detect -SyncProbe $syncProbe -SyncSeconds 6
  $window.Form.Show(); return $window
}

# --- A: the check runs in the background (the window stays usable), then the light says why the sync will not be possible
$g=New-SyncWindow $denied $SyncConfig
try {
 $c=$g.Controls
 if(-not $g.SyncJob){throw 'The Entra Connect check did not start in the background'}
 if($script:Calls.Count -ne 1 -or $script:Calls[0] -cne 'SRV-SYNC01/6'){throw ('The check is made once, on the configured server: '+($script:Calls -join ','))}
 $light=SyncLight $g
 if($light.Status -cne 'Info' -or $light.Detail -cnotmatch 'Checking that this account can use the Entra Connect server SRV-SYNC01'){throw ('While checking: '+$light.Status+' / '+$light.Detail)}
 if(-not $c.BtnNext.IsEnabled){throw 'The window must stay usable while the Entra Connect check is pending'}
 Pump 150
 if(-not $g.SyncJob){throw 'The check must still be pending while the answer is not in'}
 $script:Handle.Done=$true
 SettleSync $g
 $light=SyncLight $g
 if($light.Status -cne 'Warn' -or $light.Detail -cnotmatch '^Entra Connect sync will not be possible: this account has no right on SRV-SYNC01: it must be allowed to open a remote session there \(member of Remote Management Users or Administrators\) and to use Entra Connect \(member of ADSyncOperators\)\. Either fix that, or set EntraConnect\.Sync to \$false in the configuration file and run the synchronisation yourself\.'){throw ('After the answer: '+$light.Status+' / '+$light.Detail)}
 if(@($g.Lines | Where-Object { [string]$_.Text -cmatch 'Entra Connect check from this server\. The synchronisation will not be possible: this account has no right' }).Count -ne 1){throw 'The answer is not written in the activity log'}
 if(-not $c.BtnNext.IsEnabled){throw 'A refused account must not block the window: the engine stops by itself before any change'}
 # Detecting again (a setting typed, a page change) does not ask the server again; Check again does.
 & (Get-Module PRA.Gui) { Invoke-PraGuiDetection }
 if($script:Calls.Count -ne 1 -or $g.SyncJob){throw 'A new detection must reuse the answer'}
 Click $g 'BtnRecheck'
 if($script:Calls.Count -ne 2 -or -not $g.SyncJob){throw 'Check again must ask the server again'}
 $script:Handle.Done=$true; SettleSync $g
} finally { $g.Form.Close() }

# --- B: the account is accepted
$g=New-SyncWindow $accepted $SyncConfig
try {
 $script:Handle.Done=$true; SettleSync $g
 $light=SyncLight $g
 if($light.Status -cne 'Ok' -or $light.Detail -cne 'SRV-SYNC01 accepts this account and Entra Connect answers.'){throw ('Accepted: '+$light.Status+' / '+$light.Detail)}
} finally { $g.Form.Close() }

# --- C: no answer in time (the handle never completes): not reachable, said plainly; a probe that throws is a failure, not a crash
$timedOut=[pscustomobject]@{ Ok=$false; Kind='Unreachable'; Server='SRV-SYNC01'; Reason='SRV-SYNC01 does not answer to PowerShell remoting (WinRM, port 5985) within 6 seconds: check the server name in EntraConnect.Server, the network and the firewall'; Technical='no answer within 6 seconds' }
$script:Answer=$timedOut; $script:Calls.Clear()
$g=New-PraGuiWindow -Root $Root -ConfigPath $SyncConfig -Version 'Synthetic' -PrerequisiteProbe $detect -SyncProbe $syncProbe -SyncSeconds 0.8
$g.Form.Show()
try {
 SettleSync $g
 $light=SyncLight $g
 if($light.Status -cne 'Warn' -or $light.Detail -cnotmatch 'Entra Connect sync will not be possible: SRV-SYNC01 does not answer to PowerShell remoting'){throw ('Time out: '+$light.Status+' / '+$light.Detail)}
} finally { $g.Form.Close() }
$script:Boom=$true
$g=New-PraGuiWindow -Root $Root -ConfigPath $SyncConfig -Version 'Synthetic' -PrerequisiteProbe $detect -SyncProbe $syncProbe -SyncSeconds 2
$g.Form.Show()
try {
 SettleSync $g
 $light=SyncLight $g
 if($light.Status -cne 'Warn' -or $light.Detail -cnotmatch 'the check could not start: boom'){throw ('Throwing probe: '+$light.Status+' / '+$light.Detail)}
} finally { $g.Form.Close() }

# --- D: synchronisation off in the configuration, or no probe given: no call at all, the light is the one of the detection
$script:Boom=$false
$g=New-SyncWindow $accepted $Config
try { Pump 150; if($script:Calls.Count -ne 0 -or $g.SyncJob){throw 'EntraConnect.Sync is off: nothing may be asked'} } finally { $g.Form.Close() }
$g=New-PraGuiWindow -Root $Root -ConfigPath $SyncConfig -Version 'Synthetic' -PrerequisiteProbe $detect
$g.Form.Show()
try { Pump 150; if($g.SyncJob -or (SyncLight $g).Detail -cne 'The synchronisation is started on SRV-SYNC01.'){throw 'A probe-only window must not ask the Entra Connect server'} } finally { $g.Form.Close() }

# --- E: a blocked connection to Microsoft 365 reads in plain words in the activity log, the technical message stays
$rawBlocked=[Net.Sockets.SocketException]::new(10013).Message
$net={ param($HostName,$Seconds) [Threading.Tasks.Task]::FromException([Net.Http.HttpRequestException]::new($rawBlocked,[Net.Sockets.SocketException]::new(10013))) }
$g=New-PraGuiWindow -Root $Root -ConfigPath $Config -Version 'Synthetic' -PrerequisiteProbe $detect -NetworkProbe $net -NetworkSeconds 3
$g.Form.Show()
try {
 Settle $g
 $line=@($g.Lines | Where-Object { [string]$_.Text -cmatch '^Microsoft 365 check from this server' })
 if($line.Count -ne 1 -or $line[0].Text -cnotmatch ('login\.microsoftonline\.com: not reachable \(blocked on this server \(firewall, proxy or security software\): '+[regex]::Escape($rawBlocked))){throw ('Blocked connection: '+($line | ForEach-Object Text))}
} finally { $g.Form.Close() }
[Console]::WriteLine('SYNC-LIGHT-PASS')
'@
        $tokens = @('-NoProfile', '-NonInteractive', '-STA', '-File', $probe, '-Common', $script:GuiCommon, '-Gui', $script:GuiModule, '-Root', $runtime.Root, '-Config', $runtime.Config, '-SyncConfig', $syncConfig)
        $info = New-Object Diagnostics.ProcessStartInfo
        $info.FileName = (Join-Path $PSHOME 'pwsh.exe'); $info.Arguments = (@($tokens | ForEach-Object { ConvertTo-PraGuiNativeArgument $_ }) -join ' ')
        $info.UseShellExecute = $false; $info.CreateNoWindow = $true; $info.RedirectStandardOutput = $true; $info.RedirectStandardError = $true
        $process = [Diagnostics.Process]::Start($info)
        $out = $process.StandardOutput.ReadToEndAsync(); $err = $process.StandardError.ReadToEndAsync()
        try {
            $process.WaitForExit(120000) | Should -BeTrue
            $process.ExitCode | Should -Be 0 -Because ($out.Result + $err.Result)
            $out.Result | Should -Match 'SYNC-LIGHT-PASS'
        } finally { $process.Dispose() }
    }
}

Describe 'Release 3.1.2 - the console finishes a Convert batch whose AD part is done without its sync or package (mocked probes, no engine)' -Tag 'Release312' {
    It 'refuses a batch with Convert -Phase AD unless the window finishes a batch, and builds the engine command of the finish' {
        { & (Get-Module PRA.Gui) { New-PraGuiRequest -Action Convert -Phase AD -Batch 'C:\x\Convert-1.json' } } | Should -Throw '*must not receive a batch*'
        { & (Get-Module PRA.Gui) { New-PraGuiRequest -Action Convert -Phase Both -Batch 'C:\x\Convert-1.json' -Finish $true } } | Should -Throw '*needs a Convert batch and the AD phase*'
        { & (Get-Module PRA.Gui) { New-PraGuiRequest -Action Recover -Phase AD -Batch 'C:\x\Convert-1.json' -Finish $true } } | Should -Throw '*needs a Convert batch and the AD phase*'
        $request = & (Get-Module PRA.Gui) { New-PraGuiRequest -Action Convert -Mode Apply -Phase AD -Batch 'C:\x\Convert-1.json' -Finish $true }
        $request.Phase | Should -BeExactly 'AD'
        $request.Batch | Should -BeExactly 'C:\x\Convert-1.json'
        $command = Get-PraGuiCommand -Root 'C:\x' -ConfigPath 'C:\x\c.psd1' -Request $request
        ($command.Tokens -join ' ') | Should -Match '-Action Convert -Mode Apply .*-Phase AD -Batch C:\\x\\Convert-1\.json'
        $command.NeedsCloudWindow | Should -BeFalse -Because 'finishing the AD side never signs in to the cloud'
        ($command.Tokens -join ' ') | Should -Not -Match '-Identity|-SearchBase|-CsvPath'
        (& (Get-Module PRA.Gui) { Get-PraGuiPlanTitle 'Convert' 'AD' 'C:\x\Convert-1.json' }) -join '|' | Should -BeExactly 'Loading the batch of the AD phase|Entra Connect synchronisation|Creating the transfer package'
        (& (Get-Module PRA.Gui) { Get-PraGuiPlanTitle 'Convert' 'AD' '' }).Count | Should -BeGreaterThan 4
    }
    It 'marks the batches to finish in Continue a batch, plans them as AD-side steps, and leaves the other batches to the cloud part' {
        $runtime = New-GuiTestRoot
        $outbox = Join-Path $runtime.Root 'Backups\Outbox'
        $syncFailed = New-GuiTestBatch -Runtime $runtime
        Write-GuiTestFile (Join-Path $syncFailed.Folder ('Journal-' + $syncFailed.Id + '.jsonl')) ("{`"RunId`":`"r`",`"Operation`":`"ADSync`",`"Status`":`"Started`"}`r`n{`"RunId`":`"r`",`"Operation`":`"ADSync`",`"Status`":`"Failed`"}`r`n")
        $done = New-GuiTestBatch -Runtime $runtime
        Write-GuiTestFile (Join-Path $done.Folder ('Journal-' + $done.Id + '.jsonl')) ("{`"RunId`":`"r`",`"Operation`":`"ADSync`",`"Status`":`"Started`"}`r`n{`"RunId`":`"r`",`"Operation`":`"ADSync`",`"Status`":`"Completed`"}`r`n")
        $orphan = New-GuiTestBatch -Runtime $runtime
        Write-GuiTestFile (Join-Path $orphan.Folder 'NOT-APPLIED.txt') 'Nothing was written to Active Directory by this batch.'
        $packaged = New-GuiTestBatch -Runtime $runtime
        Write-GuiTestFile (Join-Path $outbox ('PRA-GuiSynthetic-Convert-' + $packaged.Id.Substring(0, 8) + '-for-Cloud.zip')) 'x'
        $probe = Join-Path $runtime.Root 'wpf-probe-finish.ps1'
        Write-GuiTestFile $probe @'
param($Common,$Gui,$Root,$Config,$SyncFailedId,$DoneId,$PackagedId,$OrphanId)
$ErrorActionPreference='Stop'
Import-Module $Common -Force
Import-Module $Gui -Force
function Pump([int]$Milliseconds=60){
 $frame=New-Object Windows.Threading.DispatcherFrame
 $pump=New-Object Windows.Threading.DispatcherTimer
 $pump.Interval=[timespan]::FromMilliseconds($Milliseconds);$pump.Tag=$frame
 $pump.Add_Tick({param($s)$s.Tag.Continue=$false;$s.Stop()})
 $pump.Start();[Windows.Threading.Dispatcher]::PushFrame($frame)
}
function Click($Window,[string]$Name){ $Window.Controls[$Name].RaiseEvent((New-Object Windows.RoutedEventArgs ([Windows.Controls.Button]::ClickEvent))) }
function RowOf($Window,[string]$Id){ return ,@($Window.BatchRows | Where-Object { $_.BatchId -ceq $Id })[0] }
$script:HasCloud=$true
$detect={ param($Request) [pscustomobject]@{ Lights=@([ordered]@{Name='RSAT ActiveDirectory';Status='Ok';Detail='synthetic'}); AD=$true; Cloud=$script:HasCloud; Role=$(if($script:HasCloud){'Both'}else{'AD'}) } }
function New-FinishWindow([bool]$Cloud){
  $script:HasCloud=$Cloud
  $window=New-PraGuiWindow -Root $Root -ConfigPath $Config -Version 'Synthetic' -PrerequisiteProbe $detect
  $window.Form.Show()
  Click $window 'BtnNext'
  $window.Controls['T_Convert'].IsChecked=$true; Pump 80
  $window.Controls['Mode_Continue'].IsChecked=$true; Pump 80
  Click $window 'BtnReload'; Pump 80
  return $window
}

# --- A: a server that does both sides: only the batch whose sync failed is finished here; the others go on with the cloud part
$g=New-FinishWindow $true
try {
 $c=$g.Controls
 $failed=RowOf $g $SyncFailedId; $complete=RowOf $g $DoneId; $packaged=RowOf $g $PackagedId
 if(-not $failed -or -not $complete -or -not $packaged){throw ('Batches not listed: '+$g.BatchRows.Count)}
 if($failed.State -cne 'AD part done, sync did not run: finish it here' -or $failed.Level -cne 'Warn' -or -not $failed.Selectable -or -not $failed.Finish){throw ('Sync failed row: '+$failed.State+' / '+$failed.Level+' / '+$failed.Finish)}
 if($complete.State -cne 'AD part done, cloud part to do' -or $complete.Finish){throw ('Done row: '+$complete.State)}
 if($packaged.State -cne 'AD part done, cloud part to do' -or $packaged.Finish){throw ('Packaged row: '+$packaged.State)}
 if($c.BatchHelp.Text -cnotmatch 'finish it here'){throw 'The list help does not explain "finish it here"'}
 $orphanRow=RowOf $g $OrphanId
 if(-not $orphanRow -or $orphanRow.Selectable -or $orphanRow.Finish -or $orphanRow.State -cne 'Nothing was written to AD: not a batch to continue' -or $orphanRow.Level -cne 'Warn'){throw ('A folder marked not applied is not a batch to continue: '+$orphanRow.State)}
 $c.BatchList.SelectedItem=$failed; Pump 80
 if($c.PhasePillText.Text -cne 'Phase: AD'){throw ('Finish phase pill: '+$c.PhasePillText.Text)}
 if($c.PhaseText.Text -cnotmatch 'Active Directory is NOT changed again.*Entra Connect synchronisation again.*ONE transfer package'){throw ('Finish phase text: '+$c.PhaseText.Text)}
 if($c.CmdLine.Text -cnotmatch "'-Phase' 'AD'" -or $c.CmdLine.Text -cnotmatch "'-Batch' '[^']+\.json'" -or $c.CmdLine.Text -cmatch "'-Identity'|'-SearchBase'|'-CsvPath'"){throw ('Finish command: '+$c.CmdLine.Text)}
 if(-not $c.BtnNext.IsEnabled -or $c.BlockBox.Visibility -ne 'Collapsed'){throw 'A batch to finish must be startable'}
 $request=& (Get-Module PRA.Gui) { Get-PraGuiWindowRequest 'Preview' }
 if($request.Phase -cne 'AD' -or $request.Action -cne 'Convert' -or -not $request.Batch.EndsWith('.json') -or $request.MaxObjects -ne 0 -or $request.Identity -or $request.SearchBase -or $request.CsvPath){throw ('Finish request: '+($request | ConvertTo-Json -Compress))}
 Click $g 'BtnNext'
 if($g.Page -ne 3){throw 'Verify page not reached'}
 $titles=@($c.PlanList.Items | ForEach-Object Title)
 if(($titles -join '|') -cne 'Loading the batch of the AD phase|Entra Connect synchronisation|Creating the transfer package'){throw ('Finish plan: '+($titles -join '|'))}
 & (Get-Module PRA.Gui) { Show-PraGuiPage 2 }
 Pump 80
 $complete=RowOf $g $DoneId
 $c.BatchList.SelectedItem=$complete; Pump 80
 if($c.PhasePillText.Text -cne 'Phase: Cloud'){throw ('A completed batch continues in the cloud: '+$c.PhasePillText.Text)}
 $request=& (Get-Module PRA.Gui) { Get-PraGuiWindowRequest 'Preview' }
 if($request.Phase -cne 'Cloud'){throw 'A batch with its sync done is a cloud request'}
} finally { $g.Form.Close() }

# --- B: a server that cannot do the cloud part: a batch with no package is finished here; a packaged one is not
$g=New-FinishWindow $false
try {
 $c=$g.Controls
 $complete=RowOf $g $DoneId; $packaged=RowOf $g $PackagedId; $failed=RowOf $g $SyncFailedId
 if($complete.State -cne 'AD part done, no package yet: finish it here' -or -not $complete.Finish){throw ('AD-only server, no package: '+$complete.State)}
 if($packaged.Finish -or $packaged.State -cne 'AD part done, cloud part to do'){throw ('AD-only server, package present: '+$packaged.State+' / '+$packaged.Finish)}
 if($failed.State -cne 'AD part done, sync did not run: finish it here'){throw ('AD-only server, sync failed: '+$failed.State)}
 $c.BatchList.SelectedItem=$complete; Pump 80
 if($c.PhasePillText.Text -cne 'Phase: AD' -or $c.BlockBox.Visibility -ne 'Collapsed'){throw ('AD-only finish: '+$c.PhasePillText.Text+' / '+$c.BlockBox.Visibility)}
 $c.BatchList.SelectedItem=$packaged; Pump 80
 if($c.PhasePillText.Text -cne 'Phase: Cloud' -or $c.BlockBox.Visibility -ne 'Visible'){throw 'A packaged batch still waits for the cloud server (blocked here)'}
} finally { $g.Form.Close() }
[Console]::WriteLine('FINISH-PASS')
'@
        $tokens = @('-NoProfile', '-NonInteractive', '-STA', '-File', $probe, '-Common', $script:GuiCommon, '-Gui', $script:GuiModule, '-Root', $runtime.Root, '-Config', $runtime.Config,
            '-SyncFailedId', $syncFailed.Id, '-DoneId', $done.Id, '-PackagedId', $packaged.Id, '-OrphanId', $orphan.Id)
        $info = New-Object Diagnostics.ProcessStartInfo
        $info.FileName = (Join-Path $PSHOME 'pwsh.exe'); $info.Arguments = (@($tokens | ForEach-Object { ConvertTo-PraGuiNativeArgument $_ }) -join ' ')
        $info.UseShellExecute = $false; $info.CreateNoWindow = $true; $info.RedirectStandardOutput = $true; $info.RedirectStandardError = $true
        $process = [Diagnostics.Process]::Start($info)
        $out = $process.StandardOutput.ReadToEndAsync(); $err = $process.StandardError.ReadToEndAsync()
        try {
            $process.WaitForExit(120000) | Should -BeTrue
            $process.ExitCode | Should -Be 0 -Because ($out.Result + $err.Result)
            $out.Result | Should -Match 'FINISH-PASS'
        } finally { $process.Dispose() }
    }
}

Describe 'Release 3.1.2 - the Next steps page puts the sync first when it could not start after the AD changes' -Tag 'Release312' {
    It 'shows the reason and the sync before the copy of the package, and keeps the normal page when the sync ran' {
        $runtime = New-GuiTestRoot
        $package = Join-Path $runtime.Root 'PRA-GuiSynthetic-Convert-490cc62e-for-Cloud.zip'
        Write-GuiTestFile $package 'x'
        $probe = Join-Path $runtime.Root 'wpf-probe-next.ps1'
        Write-GuiTestFile $probe @'
param($Common,$Gui,$Root,$Config,$Package)
$ErrorActionPreference='Stop'
Import-Module $Common -Force
Import-Module $Gui -Force
$detect={ param($Request) [pscustomobject]@{ Lights=@([ordered]@{Name='RSAT ActiveDirectory';Status='Ok';Detail='synthetic'}); AD=$true; Cloud=$false; Role='AD' } }
$g=New-PraGuiWindow -Root $Root -ConfigPath $Config -Version 'Synthetic' -PrerequisiteProbe $detect
$g.Form.Show()
function Show-Next([string[]]$Steps){
  $result=[pscustomobject]@{ kind='result'; status='Pending'; exitCode=2; action='Convert'; mode='Apply'; phase='AD'; success=0; error=0; pending=2; skipped=0; planned=0; total=2; issues=@(); batchId='490cc62e'
    nextSteps=$Steps; transferPackage=$Package; transferPackageKind='Convert'; logFile=''; htmlReport=''; globalReport='' }
  $g.LastResult=$result
  $g.LastRun=[pscustomobject]@{ Result=$result; Request=[ordered]@{Action='Convert';Phase='AD'}; StartedAt=[datetime]::Now; Valid=$true; Issue=''; ExitCode=2; Base='' }
  & (Get-Module PRA.Gui) { Update-PraGuiNext }
}
try {
 $c=$g.Controls
 $copy='Copy these two files, together in the same folder, to the cloud server (anywhere): PRA-GuiSynthetic-Convert-490cc62e-for-Cloud.zip and PRA-GuiSynthetic-Convert-490cc62e-for-Cloud.zip.sha256. Then run there:'
 $command='.\Invoke-PraRemoteMailbox.ps1 -Action Convert -Phase Cloud -Mode Apply -Batch ''PRA-GuiSynthetic-Convert-490cc62e-for-Cloud.zip'''
 Show-Next @('AD is changed and verified. The Entra Connect sync did not run: this account has no right on SRV-AADC01.','Run a delta sync on SRV-AADC01 (Start-ADSyncSyncCycle -PolicyType Delta) or wait for the next automatic cycle (about 30 minutes).',$copy,$command)
 if($c.NextTitle.Text -cne 'The Active Directory part is done, but the sync did not start'){throw ('Title: '+$c.NextTitle.Text)}
 if($c.NextLead.Text -cnotmatch '^Run the sync first \(see the steps below\), then copy these two files to the cloud server, into the same folder: PRA-GuiSynthetic-Convert-490cc62e-for-Cloud\.zip and PRA-GuiSynthetic-Convert-490cc62e-for-Cloud\.zip\.sha256'){throw ('Lead: '+$c.NextLead.Text)}
 $rows=@($g.NextRows)
 if($rows.Count -ne 5){throw ('Steps: '+$rows.Count)}
 if($rows[0].Text -cnotmatch '^AD is changed and verified\. The Entra Connect sync did not run' -or $rows[0].N -cne '1'){throw ('Step 1: '+$rows[0].Text)}
 if($rows[1].Text -cnotmatch '^Run a delta sync on SRV-AADC01 \(Start-ADSyncSyncCycle -PolicyType Delta\)' -or $rows[1].N -cne '2'){throw ('Step 2: '+$rows[1].Text)}
 if($rows[2].Text -cnotmatch '^Copy the two files PRA-GuiSynthetic-Convert-490cc62e-for-Cloud\.zip and PRA-GuiSynthetic-Convert-490cc62e-for-Cloud\.zip\.sha256 to the cloud server' -or $rows[2].N -cne '3'){throw ('Step 3: '+$rows[2].Text)}
 if($c.NextCmdBox.Visibility -ne 'Visible' -or $c.NextCmd.Text -cne $command){throw 'The command for the cloud server must stay visible'}
 $first=@($g.TimelineRows)[0]
 if($first.Status -cne 'Wait' -or $first.Caption -cnotmatch 'the sync is still to run'){throw ('Timeline: '+$first.Status+' / '+$first.Caption)}
 Show-Next @($copy,$command)
 if($c.NextTitle.Text -cne 'The Active Directory part is done' -or @($g.NextRows).Count -ne 3 -or @($g.NextRows)[0].Text -cnotmatch '^Copy the two files '){throw ('Normal page: '+$c.NextTitle.Text+' / '+@($g.NextRows).Count)}
} finally { $g.Form.Close() }
[Console]::WriteLine('NEXT-PASS')
'@
        $tokens = @('-NoProfile', '-NonInteractive', '-STA', '-File', $probe, '-Common', $script:GuiCommon, '-Gui', $script:GuiModule, '-Root', $runtime.Root, '-Config', $runtime.Config, '-Package', $package)
        $info = New-Object Diagnostics.ProcessStartInfo
        $info.FileName = (Join-Path $PSHOME 'pwsh.exe'); $info.Arguments = (@($tokens | ForEach-Object { ConvertTo-PraGuiNativeArgument $_ }) -join ' ')
        $info.UseShellExecute = $false; $info.CreateNoWindow = $true; $info.RedirectStandardOutput = $true; $info.RedirectStandardError = $true
        $process = [Diagnostics.Process]::Start($info)
        $out = $process.StandardOutput.ReadToEndAsync(); $err = $process.StandardError.ReadToEndAsync()
        try {
            $process.WaitForExit(120000) | Should -BeTrue
            $process.ExitCode | Should -Be 0 -Because ($out.Result + $err.Result)
            $out.Result | Should -Match 'NEXT-PASS'
        } finally { $process.Dispose() }
    }
}

Describe 'Release 3.1.3 - the console takes the members of an AD group (mocked probe, no engine, no network)' -Tag 'Release313g' {
    It 'passes -Group only to Convert AD/Both, as data, and refuses it with another source' {
        foreach ($phase in @('AD', 'Both')) {
            $r = New-PraGuiRequest -Phase $phase -Group 'CN=PRA-Wave1,OU=Groups,DC=contoso,DC=com'
            $r.Group | Should -BeExactly 'CN=PRA-Wave1,OU=Groups,DC=contoso,DC=com'
            $c = Get-PraGuiCommand 'C:\Synthetic' 'C:\Synthetic\config.psd1' $r
            $c.Tokens | Should -Contain '-Group'
            $c.Tokens | Should -Contain 'CN=PRA-Wave1,OU=Groups,DC=contoso,DC=com'
        }
        (Get-PraGuiCommand 'C:\Synthetic' 'C:\Synthetic\config.psd1' (New-PraGuiRequest -Phase AD)).Tokens | Should -Not -Contain '-Group'
        { New-PraGuiRequest -Phase Cloud -Batch '01234567' -Group 'PRA-Wave1' } | Should -Throw
        { New-PraGuiRequest -Action Recover -Batch '01234567' -Group 'PRA-Wave1' } | Should -Throw
        { New-PraGuiRequest -Group 'PRA-Wave1' -SearchBase 'OU=Selected,DC=example,DC=invalid' } | Should -Throw
        { New-PraGuiRequest -Group 'PRA-Wave1' -CsvPath 'targets.csv' } | Should -Throw
        { New-PraGuiRequest -Group 'PRA-Wave1' -Identity 'one@example.invalid' } | Should -Throw
        { New-PraGuiRequest -Group "bad`nvalue" } | Should -Throw
    }
    It 'has the source, the field, the Check button and the answer line on the Task page' {
        $xaml = [IO.File]::ReadAllText((Join-Path $script:GuiProjectRoot 'module\PRA.Gui.xaml'))
        foreach ($name in @('S_Source_Group', 'Row_Group', 'F_Group', 'BtnCheckGroup', 'GroupInfo')) { $xaml | Should -Match ('x:Name="' + $name + '"') }
        $xaml | Should -Match 'Content="AD group"'
    }
    It 'behaves as the owner asked (one window, synthetic probe, no engine run)' {
        $runtime = New-GuiTestRoot
        $probe = Join-Path $runtime.Root 'wpf-probe-313g.ps1'
        Write-GuiTestFile $probe @'
param($Common,$Gui,$Root,$Config)
$ErrorActionPreference='Stop'
Import-Module $Common -Force
Import-Module $Gui -Force
function Pump([int]$Milliseconds=60){
 $frame=New-Object Windows.Threading.DispatcherFrame
 $pump=New-Object Windows.Threading.DispatcherTimer
 $pump.Interval=[timespan]::FromMilliseconds($Milliseconds);$pump.Tag=$frame
 $pump.Add_Tick({param($s)$s.Tag.Continue=$false;$s.Stop()})
 $pump.Start();[Windows.Threading.Dispatcher]::PushFrame($frame)
}
function Click($Window,[string]$Name){ $Window.Controls[$Name].RaiseEvent((New-Object Windows.RoutedEventArgs ([Windows.Controls.Button]::ClickEvent))) }
function Check($Window,[string]$Name){ $Window.Controls[$Name].IsChecked=$true; Pump 30 }
$detect={ param($Request) [pscustomobject]@{ Lights=@([ordered]@{Name='RSAT ActiveDirectory';Status='Ok';Detail='synthetic'}); AD=$true; Cloud=$false; Role='AD' } }
$script:Mode='found'
$group={ param($Group)
  switch ($script:Mode) {
    'found' { [pscustomobject]@{Success=$true;Name='PRA-Wave1';DistinguishedName='CN=PRA-Wave1,OU=Groups,DC=contoso,DC=com';Members=12} }
    'one' { [pscustomobject]@{Success=$true;Name='PRA-Wave1';DistinguishedName='CN=PRA-Wave1,OU=Groups,DC=contoso,DC=com';Members=1} }
    'missing' { [pscustomobject]@{Success=$false;Error="The group 'PRA-Wave9' was not found in Active Directory (checked on dc01.contoso.com). Give its name (sAMAccountName or CN) or its distinguished name."} }
    'ambiguous' { [pscustomobject]@{Success=$false;Error="2 groups are named 'PRA-Wave1': give the distinguished name of the one to use."} }
    default { throw 'Active Directory is not reachable.' } } }
$g=New-PraGuiWindow -Root $Root -ConfigPath $Config -Version 'Synthetic' -PrerequisiteProbe $detect -GroupProbe $group
$g.Form.Show()
try {
 $c=$g.Controls
 Click $g 'BtnNext'; Check $g 'T_Convert'
 if($c.Row_Group.Visibility -ne 'Collapsed'){throw 'The group row must be hidden until the source is chosen'}
 Check $g 'S_Source_Group'
 if($c.Row_Group.Visibility -ne 'Visible' -or $c.Row_Identity.Visibility -ne 'Collapsed' -or $c.Row_Ou.Visibility -ne 'Collapsed' -or $c.Row_Csv.Visibility -ne 'Collapsed'){throw 'The group source shows its own row only'}
 if($c.BtnNext.IsEnabled){throw 'An empty group field must not allow Continue'}
 $text=& (Get-Module PRA.Gui) { Get-PraGuiSourceText }
 if($text[0] -cne 'AD group'){throw ('Source title: '+$text[0])}
 # An empty field: the request says what to give.
 $message=''
 try { & (Get-Module PRA.Gui) { Get-PraGuiWindowRequest -Mode Preview } | Out-Null } catch { $message=$_.Exception.Message }
 if($message -cne 'Type the name or the distinguished name of the AD group.'){throw ('Empty group message: '+$message)}
 # --- the field, the command line preview, the request
 $c.F_Group.Text='CN=PRA-Wave1,OU=Groups,DC=contoso,DC=com'; Pump
 if(-not $c.BtnNext.IsEnabled){throw 'A group makes the task ready'}
 if($c.CmdLine.Text -cnotmatch "'-Group' 'CN=PRA-Wave1,OU=Groups,DC=contoso,DC=com'"){throw ('Command line preview: '+$c.CmdLine.Text)}
 if($c.CmdLine.Text -cmatch "'-Identity'|'-SearchBase'|'-CsvPath'"){throw 'Only -Group is passed'}
 $summary=& (Get-Module PRA.Gui) { Get-PraGuiSourceText }
 if($summary[1] -notmatch 'PRA-Wave1' -or $summary[1] -notmatch 'nested'){throw ('Source sentence: '+$summary[1])}
 # --- the Check button: found, one member, missing, ambiguous, error; typing again clears the answer
 Click $g 'BtnCheckGroup'; Pump
 if($c.GroupInfo.Text -notmatch 'PRA-Wave1' -or $c.GroupInfo.Text -notmatch 'OU=Groups' -or $c.GroupInfo.Text -notmatch '12 members, including nested groups'){throw ('Group found: '+$c.GroupInfo.Text)}
 $script:Mode='one'; Click $g 'BtnCheckGroup'; Pump
 if($c.GroupInfo.Text -notmatch '1 member, including nested groups'){throw ('Group one member: '+$c.GroupInfo.Text)}
 $script:Mode='missing'; Click $g 'BtnCheckGroup'; Pump
 if($c.GroupInfo.Text -notmatch 'was not found in Active Directory'){throw ('Group missing: '+$c.GroupInfo.Text)}
 $script:Mode='ambiguous'; Click $g 'BtnCheckGroup'; Pump
 if($c.GroupInfo.Text -notmatch '2 groups are named'){throw ('Group ambiguous: '+$c.GroupInfo.Text)}
 $script:Mode='error'; Click $g 'BtnCheckGroup'; Pump
 if($c.GroupInfo.Text -notmatch 'Could not check: Active Directory is not reachable'){throw ('Group error: '+$c.GroupInfo.Text)}
 $c.F_Group.Text='PRA-Wave1'; Pump
 if($c.GroupInfo.Text -ne ''){throw 'Typing again must clear the previous answer'}
 if($c.CmdLine.Text -cnotmatch "'-Group' 'PRA-Wave1'"){throw ('Command line preview (name): '+$c.CmdLine.Text)}
 # --- the request that the Preview will run
 $request=& (Get-Module PRA.Gui) { Get-PraGuiWindowRequest -Mode Preview }
 if($request.Group -cne 'PRA-Wave1' -or $request.Identity -or $request.SearchBase -or $request.CsvPath -or $request.Action -cne 'Convert'){throw ('Request: '+($request | ConvertTo-Json -Compress))}
 # --- back to another source: the group is not sent
 Check $g 'S_Source_Single'
 if($c.Row_Group.Visibility -ne 'Collapsed'){throw 'The group row must hide again'}
 Write-Output 'WPF-313G-PASS'
} finally { $g.Form.Close() }
'@
        $tokens = @('-NoProfile', '-NonInteractive', '-STA', '-File', $probe, '-Common', $script:GuiCommon, '-Gui', $script:GuiModule, '-Root', $runtime.Root, '-Config', $runtime.Config)
        $info = New-Object Diagnostics.ProcessStartInfo
        $info.FileName = (Join-Path $PSHOME 'pwsh.exe'); $info.Arguments = (@($tokens | ForEach-Object { ConvertTo-PraGuiNativeArgument $_ }) -join ' ')
        $info.UseShellExecute = $false; $info.CreateNoWindow = $true; $info.RedirectStandardOutput = $true; $info.RedirectStandardError = $true
        $process = [Diagnostics.Process]::Start($info)
        $out = $process.StandardOutput.ReadToEndAsync(); $err = $process.StandardError.ReadToEndAsync()
        try {
            $process.WaitForExit(180000) | Should -BeTrue
            $process.ExitCode | Should -Be 0 -Because ($out.Result + $err.Result)
            $out.Result | Should -Match 'WPF-313G-PASS'
        } finally { $process.Dispose() }
    }
}

Describe 'Release 3.1.3 - the group lookup answers an ambiguous name and an empty group, and the summary names the AD group (mocked probe, no engine, no network)' -Tag 'Release313i' {
    It 'shows the groups that share a name with their distinguished names, an empty group as a warning, and the source in the summary' {
        $runtime = New-GuiTestRoot
        $probe = Join-Path $runtime.Root 'wpf-probe-313i.ps1'
        Write-GuiTestFile $probe @'
param($Common,$Gui,$Root,$Config)
$ErrorActionPreference='Stop'
Import-Module $Common -Force
Import-Module $Gui -Force
function Pump([int]$Milliseconds=60){
 $frame=New-Object Windows.Threading.DispatcherFrame
 $pump=New-Object Windows.Threading.DispatcherTimer
 $pump.Interval=[timespan]::FromMilliseconds($Milliseconds);$pump.Tag=$frame
 $pump.Add_Tick({param($s)$s.Tag.Continue=$false;$s.Stop()})
 $pump.Start();[Windows.Threading.Dispatcher]::PushFrame($frame)
}
function Click($Window,[string]$Name){ $Window.Controls[$Name].RaiseEvent((New-Object Windows.RoutedEventArgs ([Windows.Controls.Button]::ClickEvent))) }
function Check($Window,[string]$Name){ $Window.Controls[$Name].IsChecked=$true; Pump 30 }
$detect={ param($Request) [pscustomobject]@{ Lights=@([ordered]@{Name='RSAT ActiveDirectory';Status='Ok';Detail='synthetic'}); AD=$true; Cloud=$false; Role='AD' } }
$script:Mode='ambiguous'
$group={ param($Group)
  switch ($script:Mode) {
    'ambiguous' { [pscustomobject]@{Success=$false;Error="2 groups are named 'PRA-Wave1': give the distinguished name of the one to use. They are: CN=PRA-Wave1,OU=GroupsA,DC=contoso,DC=com | CN=PRA-Wave1,OU=GroupsB,DC=contoso,DC=com."} }
    'many' { [pscustomobject]@{Success=$false;Error="7 groups are named 'PRA-Wave1': give the distinguished name of the one to use. They are: CN=PRA-Wave1,OU=A,DC=contoso,DC=com | CN=PRA-Wave1,OU=B,DC=contoso,DC=com | CN=PRA-Wave1,OU=C,DC=contoso,DC=com | CN=PRA-Wave1,OU=D,DC=contoso,DC=com | CN=PRA-Wave1,OU=E,DC=contoso,DC=com (and 2 more)."} }
    'empty' { [pscustomobject]@{Success=$true;Name='PRA-Empty';DistinguishedName='CN=PRA-Empty,OU=Groups,DC=contoso,DC=com';Members=0} }
    'found' { [pscustomobject]@{Success=$true;Name='PRA-Wave1';DistinguishedName='CN=PRA-Wave1,OU=Groups,DC=contoso,DC=com';Members=4} }
    default { throw 'Active Directory is not reachable.' } } }
$g=New-PraGuiWindow -Root $Root -ConfigPath $Config -Version 'Synthetic' -PrerequisiteProbe $detect -GroupProbe $group
$g.Form.Show()
try {
 $c=$g.Controls
 Click $g 'BtnNext'; Check $g 'T_Convert'; Check $g 'S_Source_Group'
 $c.F_Group.Text='PRA-Wave1'; Pump
 Click $g 'BtnCheckGroup'; Pump
 $lines=@($c.GroupInfo.Text -split "`n")
 if($lines[0] -cne "2 groups are named 'PRA-Wave1': give the distinguished name of the one to use"){throw ('Ambiguous first line: '+$c.GroupInfo.Text)}
 if($lines.Count -ne 3 -or $lines[1].Trim() -cne 'CN=PRA-Wave1,OU=GroupsA,DC=contoso,DC=com' -or $lines[2].Trim() -cne 'CN=PRA-Wave1,OU=GroupsB,DC=contoso,DC=com'){throw ('Ambiguous list: '+$c.GroupInfo.Text)}
 if($c.GroupInfo.Text -match 'Could not check'){throw 'An ambiguous name is an answer, not a failed check'}
 $caution=$g.Form.TryFindResource('PraCaution')
 if($null -eq $caution -or -not $c.GroupInfo.Foreground.Equals($caution)){throw 'The ambiguous answer must use the caution colour'}
 $script:Mode='many'; Click $g 'BtnCheckGroup'; Pump
 $lines=@($c.GroupInfo.Text -split "`n")
 if($lines.Count -ne 6 -or $lines[5].Trim() -cne 'CN=PRA-Wave1,OU=E,DC=contoso,DC=com (and 2 more)'){throw ('Many: '+$c.GroupInfo.Text)}
 $script:Mode='empty'; Click $g 'BtnCheckGroup'; Pump
 if($c.GroupInfo.Text -cne 'PRA-Empty · CN=PRA-Empty,OU=Groups,DC=contoso,DC=com · no member: nothing to convert'){throw ('Empty: '+$c.GroupInfo.Text)}
 if(-not $c.GroupInfo.Foreground.Equals($caution)){throw 'An empty group must use the caution colour'}
 $script:Mode='found'; Click $g 'BtnCheckGroup'; Pump
 if($c.GroupInfo.Text -notmatch '4 members, including nested groups'){throw ('Found: '+$c.GroupInfo.Text)}
 if($c.GroupInfo.Foreground.Equals($caution)){throw 'A group with members is not a caution'}
 $script:Mode='error'; Click $g 'BtnCheckGroup'; Pump
 if($c.GroupInfo.Text -notmatch '^Could not check: Active Directory is not reachable'){throw ('Error: '+$c.GroupInfo.Text)}
 $summary=& (Get-Module PRA.Gui) { Get-PraGuiSourceSummary }
 if($summary -cne 'AD group PRA-Wave1'){throw ('Summary (group): '+$summary)}
 Check $g 'S_Source_Single'; $c.F_Identity.Text='user1@contoso.com'; Pump
 $summary=& (Get-Module PRA.Gui) { Get-PraGuiSourceSummary }
 if($summary -cne 'Single identity (test) user1@contoso.com'){throw ('Summary (single): '+$summary)}
 Check $g 'S_Source_Scope'
 $summary=& (Get-Module PRA.Gui) { Get-PraGuiSourceSummary }
 if($summary -cne 'Configured scope'){throw ('Summary (scope): '+$summary)}
 Write-Output 'WPF-313I-PASS'
} finally { $g.Form.Close() }
'@
        $tokens = @('-NoProfile', '-NonInteractive', '-STA', '-File', $probe, '-Common', $script:GuiCommon, '-Gui', $script:GuiModule, '-Root', $runtime.Root, '-Config', $runtime.Config)
        $info = New-Object Diagnostics.ProcessStartInfo
        $info.FileName = (Join-Path $PSHOME 'pwsh.exe'); $info.Arguments = (@($tokens | ForEach-Object { ConvertTo-PraGuiNativeArgument $_ }) -join ' ')
        $info.UseShellExecute = $false; $info.CreateNoWindow = $true; $info.RedirectStandardOutput = $true; $info.RedirectStandardError = $true
        $process = [Diagnostics.Process]::Start($info)
        $out = $process.StandardOutput.ReadToEndAsync(); $err = $process.StandardError.ReadToEndAsync()
        try {
            $process.WaitForExit(180000) | Should -BeTrue
            $process.ExitCode | Should -Be 0 -Because ($out.Result + $err.Result)
            $out.Result | Should -Match 'WPF-313I-PASS'
        } finally { $process.Dispose() }
    }
}

AfterAll {
    if($script:GuiEvidence -and (Test-Path -LiteralPath $script:GuiEvidence)) {
        # A child of a test may still be closing its files for a moment: bounded retries, then the error is raised (never swallowed).
        for($attempt=1; $attempt -le 20; $attempt++) {
            try { Remove-Item -LiteralPath $script:GuiEvidence -Recurse -Force -ErrorAction Stop; break }
            catch { if($attempt -eq 20) { throw }; Start-Sleep -Milliseconds 500 }
        }
    }
}

Describe 'Release 3.2.0 - scale: the console reads a batch file again only when it changed, finds an object of an event without a scan, and reads its CSV files by their stamp (synthetic, no engine)' -Tag 'Release320c' {
    It 'keeps what it read of a batch while the file and its .sha256 file are unchanged, and reads again only the file that changed' {
        $runtime=New-GuiTestRoot
        $batches=@(1..3 | ForEach-Object { New-GuiTestBatch $runtime })
        $first=Read-PraGuiState $runtime.Root $runtime.Config
        $first.Batches.Count | Should -Be 3
        $second=Read-PraGuiState $runtime.Root $runtime.Config
        foreach ($item in $second.Batches) {
            $before=@($first.Batches | Where-Object Path -eq $item.Path)[0]
            [object]::ReferenceEquals($item.Data,$before.Data) | Should -BeTrue -Because 'the batch was not read again'
        }
        $changed=$batches[1]
        $data=$changed.Data.Clone(); $data.Records=@($data.Records[0],$data.Records[0]); $data.Environment='GuiSynthetic'
        Write-GuiTestJson $changed.Path $data
        $third=Read-PraGuiState $runtime.Root $runtime.Config
        foreach ($item in $third.Batches) {
            $before=@($second.Batches | Where-Object Path -eq $item.Path)[0]
            [object]::ReferenceEquals($item.Data,$before.Data) | Should -Be ($item.Path -ne $changed.Path)
        }
        @($third.Batches | Where-Object Path -eq $changed.Path)[0].Data.RecordCount | Should -Be 2
        [IO.File]::WriteAllText($batches[2].Path+'.sha256',('0'*64),$script:GuiEncoding)
        $fourth=Read-PraGuiState $runtime.Root $runtime.Config
        @($fourth.Batches | Where-Object Path -eq $batches[2].Path)[0].Status | Should -Match 'SHA-256 mismatch' -Because 'a changed .sha256 file is a change of the batch'
    }
    It 'keeps in the batch only what the window shows (the counts), so that a batch of thousands of objects costs little memory, and counts the shared mailboxes' {
        $runtime=New-GuiTestRoot
        $batch=New-GuiTestBatch $runtime
        $data=$batch.Data.Clone()
        $data.Records=@(1..2000 | ForEach-Object { @{ObjectGuid=[guid]::NewGuid().ToString();SamAccountName=('user'+$_);UserPrincipalName=('user'+$_+'@contoso.invalid');IsShared=(($_ % 4) -eq 0)} })
        Write-GuiTestJson $batch.Path $data
        $item=Read-PraGuiBatch $batch.Path 'GuiSynthetic'
        $item.Valid | Should -BeTrue
        $item.Data.RecordCount | Should -Be 2000
        $item.Data.SharedCount | Should -Be 500
        $item.Data.PSObject.Properties.Name | Should -Not -Contain 'Records'
        $item.Data.BatchId | Should -BeExactly $batch.Id
        (Read-PraGuiBatch $batch.Path 'OtherSynthetic').EnvMismatch | Should -BeTrue
        (Read-PraGuiBatch $batch.Path 'otherSYNTHETIC' -AnyEnvironment).Valid | Should -BeTrue
        (Read-PraGuiBatch $batch.Path 'guisynthetic').Valid | Should -BeTrue -Because 'the Environment is compared ignoring the letter case'
    }
    It 'finds the row of an object in a step by its name in any letter case, without scanning the rows of the step' {
        $result=& (Get-Module PRA.Gui) {
            $model=@{ Objects=@{}; ObjectIndex=@{} }
            $clock=[Diagnostics.Stopwatch]::StartNew()
            for ($i=1; $i -le 3000; $i++) { Add-PraGuiModelObject $model 's3' ('User'+$i+'@contoso.invalid') (New-PraGuiRow @{ Name=('User'+$i+'@contoso.invalid'); Result='ok' }) }
            $hits=0
            for ($i=1; $i -le 3000; $i++) { $row=Get-PraGuiModelObject $model 's3' ('USER'+$i+'@CONTOSO.INVALID'); if ($row -and $row.Result -ceq 'ok') { $hits++ } }
            $plain=@{ Objects=@{ s1=(New-Object 'Collections.ObjectModel.ObservableCollection[object]') } }
            $plain.Objects.s1.Add((New-PraGuiRow @{ Name='Only@contoso.invalid'; Result='x' }))
            @{ Rows=$model.Objects['s3'].Count; Hits=$hits; Seconds=$clock.Elapsed.TotalSeconds; Missing=(Get-PraGuiModelObject $model 's3' 'nobody@contoso.invalid'); NoStep=(Get-PraGuiModelObject $model 's9' 'x'); Scan=(Get-PraGuiModelObject $plain 's1' 'ONLY@contoso.invalid') }
        }
        $result.Rows | Should -Be 3000
        $result.Hits | Should -Be 3000
        $result.Missing | Should -BeNullOrEmpty
        $result.NoStep | Should -BeNullOrEmpty
        $result.Scan.Result | Should -BeExactly 'x' -Because 'a model built without the dictionary is still searched'
        $result.Seconds | Should -BeLessThan 60
    }
    It 'says how many rows its target CSV file has from the stamp of the file, and reads the file again when it changes' {
        $runtime=New-GuiTestRoot
        $csv=Join-Path $runtime.Root 'targets.csv'
        Write-GuiTestFile $csv ("Identity`r`n"+((1..50 | ForEach-Object { 'user'+$_+'@contoso.invalid' }) -join "`r`n"))
        $global:PraGuiCsv=$csv
        $text=& (Get-Module PRA.Gui) { Get-PraGuiCsvRowText $global:PraGuiCsv }
        $text | Should -BeExactly ' 50 rows.'
        & (Get-Module PRA.Gui) { $script:PraGuiCsvCache[$global:PraGuiCsv].Text=' kept from the first reading.' }
        (& (Get-Module PRA.Gui) { Get-PraGuiCsvRowText $global:PraGuiCsv }) | Should -BeExactly ' kept from the first reading.' -Because 'the file was not read again'
        Write-GuiTestFile $csv ("Identity`r`n"+((1..7 | ForEach-Object { 'user'+$_+'@contoso.invalid' }) -join "`r`n"))
        (& (Get-Module PRA.Gui) { Get-PraGuiCsvRowText $global:PraGuiCsv }) | Should -BeExactly ' 7 rows.'
        Write-GuiTestFile $csv "Wrong`r`nsynthetic@example.invalid"
        (& (Get-Module PRA.Gui) { Get-PraGuiCsvRowText $global:PraGuiCsv }) | Should -Match 'requires an Identity column'
        Remove-Variable PraGuiCsv -Scope Global
        $source=Get-Content -LiteralPath $script:GuiModule -Raw
        $source | Should -Match '\$c\.ConfirmBox\.Add_TextChanged\(\{ \$script:Gui\.ConfirmTimer\.Stop\(\); \$script:Gui\.ConfirmTimer\.Start\(\) \}\)' -Because 'a refresh follows a pause in the typing, not each key'
        $source | Should -Not -Match 'ConfirmBox\.Add_TextChanged\(\{ Update-PraGuiView \}\)'
    }
    It 'reads the per-run CSV of thousands of rows with the formula guard removed from the columns it shows, and the shared flag as a boolean' {
        $runtime=New-GuiTestRoot
        $path=Join-Path $runtime.Root 'run.csv'
        $lines=New-Object 'Collections.Generic.List[string]'
        $lines.Add('"ObjectGuid";"SamAccountName";"UserPrincipalName";"IsShared";"BackupPath";"Warnings";"FinalStatus";"Detail";"CloudDetail"')
        for ($i=1; $i -le 3000; $i++) { $lines.Add(('"{0}";"''=user{1}";"user{1}@contoso.invalid";"{2}";"B{1}";"";"Planned";"''-detail {1}";"''=kept"' -f [guid]::NewGuid(),$i,$(if ($i % 2) { 'True' } else { 'False' }))) }
        [IO.File]::WriteAllText($path,($lines -join "`r`n"),$script:GuiEncoding)
        $global:PraGuiReport=$path
        $clock=[Diagnostics.Stopwatch]::StartNew()
        $rows=@(& (Get-Module PRA.Gui) { Read-PraGuiReport $global:PraGuiReport })
        $seconds=$clock.Elapsed.TotalSeconds
        Remove-Variable PraGuiReport -Scope Global
        $rows.Count | Should -Be 3000
        $rows[0].SamAccountName | Should -BeExactly '=user1'
        $rows[0].Detail | Should -BeExactly '-detail 1'
        $rows[0].IsShared | Should -BeTrue
        $rows[1].IsShared | Should -BeFalse
        $rows[0].UserPrincipalName | Should -BeExactly 'user1@contoso.invalid'
        $rows[0].CloudDetail | Should -BeExactly "'=kept" -Because 'a column the window does not show keeps its guard'
        $seconds | Should -BeLessThan 60
    }
    It 'counts the rows of a preview once for a given list (a refresh follows each key typed in the confirmation box)' {
        $result=& (Get-Module PRA.Gui) {
            $saved=$script:Gui
            try {
                $rows=New-Object 'Collections.ObjectModel.ObservableCollection[object]'
                for ($i=1; $i -le 3000; $i++) { $rows.Add((New-PraGuiRow @{ Type=$(if ($i % 3 -eq 0) { 'Shared' } else { 'User' }); Status=$(if ($i % 10 -eq 0) { 'Warn' } elseif ($i % 50 -eq 0) { 'Fail' } else { 'Ok' }) })) }
                $script:Gui=@{ VerRows=$rows }
                $first=[pscustomobject]@{ }
                $tally=Get-PraGuiVerTally
                $first=[pscustomobject]@{ Count=$tally.Count; Shared=$tally.Shared; Warn=$tally.Warn; Failed=$tally.Failed }
                $script:Gui.VerTally.Warn=-1
                $second=Get-PraGuiVerTally
                $keptWarn=$second.Warn
                $rows.Add((New-PraGuiRow @{ Type='Shared'; Status='Fail' }))
                $third=Get-PraGuiVerTally
                @{ First=$first; Same=($keptWarn -eq -1); Third=$third }
            } finally { $script:Gui=$saved }
        }
        $result.First.Count | Should -Be 3000
        $result.First.Shared | Should -Be 1000
        $result.First.Warn | Should -Be 300
        $result.First.Failed | Should -Be 0 -Because 'a row that is a multiple of 50 is also a multiple of 10 and counts as a warning'
        $result.Same | Should -BeTrue
        $result.Third.Count | Should -Be 3001
        $result.Third.Shared | Should -Be 1001
        $result.Third.Failed | Should -Be 1
    }
}

Describe 'Release 3.2.0 - the console: the data files of the global report are not batches, an Apply with planned objects is not Done, a partial batch is labelled (synthetic, no engine)' -Tag 'Release320a' {
    It 'does not list PhaseData and PhaseEvents files as unreadable batches, and resolves a batch folder that holds them' {
        $runtime = New-GuiTestRoot
        $batch = New-GuiTestBatch -Runtime $runtime
        Write-GuiTestJson (Join-Path $batch.Folder 'PhaseData-20261116101010-AD-1a2b3c4d.json') @{ SchemaVersion = 1; Kind = 'PhaseData'; Environment = 'GuiSynthetic'; Objects = @() }
        Write-GuiTestFile (Join-Path $batch.Folder 'phasedata-20261116101011-cloud-1a2b3c4d.json') '{"Kind":"PhaseData"}'
        Write-GuiTestFile (Join-Path $batch.Folder 'PhaseEvents-20261116101010-AD-1a2b3c4d.json') '{"Step":"x"}'
        Write-GuiTestFile (Join-Path $batch.Folder 'PhaseEvents-20261116101010-AD-1a2b3c4d.jsonl') '{"Step":"x"}'
        $state = Read-PraGuiState $runtime.Root $runtime.Config
        @($state.Batches).Count | Should -Be 1 -Because (($state.Batches | ForEach-Object Label) -join "`n")
        @($state.Batches | Where-Object { -not $_.Valid }).Count | Should -Be 0
        $found = Resolve-PraGuiBatch $batch.Folder 'Convert' $state
        $found.Path | Should -BeExactly $batch.Path
        (Resolve-PraGuiBatch $batch.Id 'Convert' $state).Path | Should -BeExactly $batch.Path
    }
    It 'an Apply whose result is Planned, or has planned objects, is not a success; a Preview that plans is still valid' {
        $apply = New-PraGuiRequest -Phase AD -Mode Apply
        Test-PraGuiResult (New-GuiTestResult $apply) $apply 0 | Should -BeFalse -Because 'Planned is the status of a Preview'
        $mixed = New-GuiTestResult $apply -Planned 1 -Success 2; $mixed.status = 'Success'
        Test-PraGuiResult $mixed $apply 0 | Should -BeFalse -Because 'an object is still planned'
        Test-PraGuiResult (New-GuiTestResult $apply -Planned 0 -Success 2) $apply 0 | Should -BeTrue
        Test-PraGuiResult (New-GuiTestResult $apply -ExitCode 2 -Planned 0 -Pending 2) $apply 2 | Should -BeTrue
        $preview = New-PraGuiRequest -Phase AD -Mode Preview
        Test-PraGuiResult (New-GuiTestResult $preview) $preview 0 | Should -BeTrue
        $apply = New-PraGuiRequest -Phase AD -Mode 'APPLY'
        Test-PraGuiResult (New-GuiTestResult $apply) $apply 0 | Should -BeFalse -Because 'the mode is not case sensitive'
    }
    It 'labels a batch whose AD proof is partial with the number of objects converted, and nothing for a complete proof' {
        $runtime = New-GuiTestRoot
        $partial = New-GuiTestBatch -Runtime $runtime
        $records = @(1..3 | ForEach-Object { @{ ObjectGuid = [guid]::NewGuid().ToString(); Operation = 'Convert'; ADVerified = $true } })
        Write-GuiTestJson $partial.Proof @{ SchemaVersion = 2; Operation = 'Convert'; Kind = 'ADVerified'; Environment = 'GuiSynthetic'; Partial = $true; PlannedCount = 10; Records = $records }
        (& (Get-Module PRA.Gui) { param($path) Get-PraGuiPartialText $path } $partial.Proof) | Should -BeExactly 'Partial: 3 of 10 converted'
        $complete = New-GuiTestBatch -Runtime $runtime
        (& (Get-Module PRA.Gui) { param($path) Get-PraGuiPartialText $path } $complete.Proof) | Should -BeExactly ''
        (& (Get-Module PRA.Gui) { param($path) Get-PraGuiPartialText $path } (Join-Path $runtime.Root 'missing.json')) | Should -BeExactly ''
    }
}

Describe 'Release 3.2.0 - the console continues a partial batch, or a batch whose synchronisation is not confirmed, with the AD part first (synthetic, no engine)' -Tag 'Release320a' {
    It 'offers the AD part first for a partial batch, and for a batch without a good Entra Connect entry when the configuration asks for the synchronisation' {
        $runtime = New-GuiTestRoot
        $partial = New-GuiTestBatch -Runtime $runtime
        Write-GuiTestJson $partial.Proof @{ SchemaVersion = 2; Operation = 'Convert'; Kind = 'ADVerified'; Environment = 'GuiSynthetic'; Partial = $true; PlannedCount = 10; Records = @(@{ ObjectGuid = [guid]::NewGuid().ToString(); Operation = 'Convert'; ADVerified = $true }) }
        $plain = New-GuiTestBatch -Runtime $runtime
        $synced = New-GuiTestBatch -Runtime $runtime
        Write-GuiTestFile (Join-Path $synced.Folder ('Journal-' + $synced.Id + '.jsonl')) ("{`"RunId`":`"r`",`"Operation`":`"ADSync`",`"Status`":`"Started`"}`r`n{`"RunId`":`"r`",`"Operation`":`"ADSync`",`"Status`":`"Completed`"}`r`n")
        $items = @{}
        foreach ($name in 'partial', 'plain', 'synced') { $batch = Get-Variable $name -ValueOnly; $items[$name] = [pscustomobject]@{ Folder = $batch.Folder; BatchId = $batch.Id; Environment = 'GuiSynthetic' } }
        $reasons = & (Get-Module PRA.Gui) {
            param($Items, $Folder)
            $saved = $script:Gui
            try {
                $result = @{}
                foreach ($sync in $false, $true) {
                    $script:Gui = [pscustomobject]@{ State = [pscustomobject]@{ Config = @{ EntraConnect = @{ Sync = $sync }; Storage = @{ BackupFolder = $Folder } } }; Detect = $null }
                    foreach ($name in 'partial', 'plain', 'synced') { $result[$name + '-' + $sync] = [string](Get-PraGuiFinishReason $Items[$name]) }
                }
                $result
            }
            finally { $script:Gui = $saved }
        } $items (Join-Path $runtime.Root 'Backups')
        $reasons['partial-False'] | Should -BeExactly 'AD part partly done, sync not run: finish it here'
        $reasons['partial-True'] | Should -BeExactly 'AD part partly done, sync not run: finish it here'
        $reasons['plain-True'] | Should -BeExactly 'AD part done, sync not confirmed: finish it here'
        $reasons['plain-False'] | Should -Not -Match 'finish it here' -Because 'the configuration leaves the synchronisation to the operator'
        $reasons['synced-True'] | Should -Not -Match 'finish it here' -Because 'its journal has an Entra Connect entry that ended well'
    }
    It 'finishes a batch here only when it was converted on this server and this server can run the AD part: an imported batch, or a cloud-only server, goes on with the cloud part (partial, plain and sync-failed batches, Sync on and off)' {
        $runtime = New-GuiTestRoot
        $backups = Join-Path $runtime.Root 'Backups'
        $makeBatch = {
            param([string]$Kind, [bool]$Imported)
            $batch = New-GuiTestBatch -Runtime $runtime
            if ($Kind -eq 'partial') { Write-GuiTestJson $batch.Proof @{ SchemaVersion = 2; Operation = 'Convert'; Kind = 'ADVerified'; Environment = 'GuiSynthetic'; Partial = $true; PlannedCount = 10; Records = @(@{ ObjectGuid = [guid]::NewGuid().ToString(); Operation = 'Convert'; ADVerified = $true }) } }
            if ($Kind -eq 'failed') { Write-GuiTestFile (Join-Path $batch.Folder ('Journal-' + $batch.Id + '.jsonl')) ("{`"RunId`":`"r`",`"Operation`":`"ADSync`",`"Status`":`"Started`"}`r`n{`"RunId`":`"r`",`"Operation`":`"ADSync`",`"Status`":`"Failed`"}`r`n") }
            if ($Imported) { Write-GuiTestFile (Join-Path $backups ('Imported\' + $batch.Id + '.txt')) 'Convert-package 2026-11-17' }
            [pscustomobject]@{ Folder = $batch.Folder; BatchId = $batch.Id; Environment = 'GuiSynthetic' }
        }
        $items = @{}
        foreach ($kind in 'plain', 'partial', 'failed') { foreach ($imported in $false, $true) { $items[$kind + '-' + $imported] = & $makeBatch $kind $imported } }
        $inbox = & $makeBatch 'plain' $false
        $package = & (Get-Module PRA.Gui) { param($Item) Get-PraTransferPackageName -Kind Convert -Environment $Item.Environment -BatchId $Item.BatchId } $inbox
        Write-GuiTestFile (Join-Path $backups ('Inbox\' + $package)) 'synthetic package'
        $items['inbox'] = $inbox
        $reasons = & (Get-Module PRA.Gui) {
            param($Items, $Folder)
            $saved = $script:Gui
            try {
                $result = @{}
                foreach ($role in 'Cloud', 'AD', 'Both') {
                    foreach ($sync in $false, $true) {
                        $script:Gui = [pscustomobject]@{ State = [pscustomobject]@{ Config = @{ EntraConnect = @{ Sync = $sync }; Storage = @{ BackupFolder = $Folder } } }; Detect = [pscustomobject]@{ Role = $role; AD = ($role -ne 'Cloud'); Cloud = ($role -ne 'AD') } }
                        foreach ($name in $Items.Keys) { $result[$role + '-' + $sync + '-' + $name] = [string](Get-PraGuiFinishReason $Items[$name]) }
                    }
                }
                $result
            }
            finally { $script:Gui = $saved }
        } $items $backups
        foreach ($sync in $false, $true) {
            foreach ($kind in 'plain', 'partial', 'failed', 'inbox') {
                foreach ($role in 'Cloud', 'AD', 'Both') {
                    $name = if ($kind -eq 'inbox') { 'inbox' } else { $kind + '-True' }
                    $reasons[$role + '-' + $sync + '-' + $name] | Should -Not -Match 'finish it here' -Because ('imported batch, role ' + $role + ', sync ' + $sync + ', ' + $kind)
                }
            }
            foreach ($kind in 'partial', 'failed') {
                $reasons['Cloud-' + $sync + '-' + $kind + '-False'] | Should -Not -Match 'finish it here' -Because 'a cloud-only server has no AD part to finish'
                $reasons['AD-' + $sync + '-' + $kind + '-False'] | Should -Match 'finish it here' -Because 'a local batch of a server that has AD'
                $reasons['Both-' + $sync + '-' + $kind + '-False'] | Should -Match 'finish it here'
            }
            $reasons['Cloud-' + $sync + '-plain-False'] | Should -Not -Match 'finish it here'
            $reasons['AD-' + $sync + '-plain-False'] | Should -Match 'finish it here' -Because 'a server that only has AD and no package yet finishes its own batch'
        }
        $reasons['AD-True-plain-False'] | Should -BeExactly 'AD part done, sync not confirmed: finish it here'
        $reasons['Both-False-plain-False'] | Should -Not -Match 'finish it here' -Because 'a plain local batch with Sync off is left to the operator when the cloud part can run here'
        $reasons['Both-True-plain-False'] | Should -BeExactly 'AD part done, sync not confirmed: finish it here'
    }
}

Describe 'Release 3.2.0 - the console does not keep a failure to read a file, and Reload forgets what it kept (synthetic, no engine)' -Tag 'Release320c' {
    It 'a batch file that is locked is told but not kept: the next refresh reads it; an answer about the content (not a batch) is kept while the file is unchanged' {
        $runtime=New-GuiTestRoot
        $batch=New-GuiTestBatch $runtime
        $global:PraGuiLocked=$batch.Path
        $lock=[IO.File]::Open($batch.Path,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::None)
        try { $locked=& (Get-Module PRA.Gui) { Get-PraGuiBatchCore $global:PraGuiLocked } } finally { $lock.Dispose() }
        $locked.Error | Should -Not -BeNullOrEmpty
        $locked.Data | Should -BeNullOrEmpty
        (& (Get-Module PRA.Gui) { $script:PraGuiBatchCache.ContainsKey($global:PraGuiLocked) }) | Should -BeFalse -Because 'a lock that ends must not stick'
        $after=& (Get-Module PRA.Gui) { Get-PraGuiBatchCore $global:PraGuiLocked }
        $after.Error | Should -BeExactly ''
        $after.Data.RecordCount | Should -Be 1
        [object]::ReferenceEquals($after,(& (Get-Module PRA.Gui) { Get-PraGuiBatchCore $global:PraGuiLocked })) | Should -BeTrue
        $other=Join-Path $runtime.Root 'Backups\Batch-notabatch\Other-fixture.json'
        Write-GuiTestJson $other @{SchemaVersion=2;Operation='Other';Records=@()}
        $global:PraGuiLocked=$other
        $first=& (Get-Module PRA.Gui) { Get-PraGuiBatchCore $global:PraGuiLocked }
        $first.Error | Should -Match 'Not a Convert, Recover or RecoverFinalize package'
        [object]::ReferenceEquals($first,(& (Get-Module PRA.Gui) { Get-PraGuiBatchCore $global:PraGuiLocked })) | Should -BeTrue -Because 'the content of the unchanged file will not answer differently'
        Remove-Variable PraGuiLocked -Scope Global
    }
    It 'the sentence about a target CSV file is not kept when the file cannot be read (a lock), and is read again when the lock ends' {
        $runtime=New-GuiTestRoot
        $csv=Join-Path $runtime.Root 'targets-locked.csv'
        Write-GuiTestFile $csv ("Identity`r`n"+((1..3 | ForEach-Object { 'user'+$_+'@contoso.invalid' }) -join "`r`n"))
        $global:PraGuiCsv=$csv
        $lock=[IO.File]::Open($csv,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::None)
        try { $locked=& (Get-Module PRA.Gui) { Get-PraGuiCsvRowText $global:PraGuiCsv } } finally { $lock.Dispose() }
        $locked | Should -Not -Match '^ 3 rows\.$'
        $locked.Trim().Length | Should -BeGreaterThan 0
        (& (Get-Module PRA.Gui) { $script:PraGuiCsvCache.ContainsKey($global:PraGuiCsv) }) | Should -BeFalse
        (& (Get-Module PRA.Gui) { Get-PraGuiCsvRowText $global:PraGuiCsv }) | Should -BeExactly ' 3 rows.'
        Remove-Variable PraGuiCsv -Scope Global
    }
    It 'Reload clears the caches of batch files, CSV files and hashes, and the Reload button does it before it reads the state' {
        $runtime=New-GuiTestRoot
        $batch=New-GuiTestBatch $runtime
        $global:PraGuiLocked=$batch.Path
        $null=& (Get-Module PRA.Gui) { Get-PraGuiBatchCore $global:PraGuiLocked; $script:PraGuiCsvCache['x']=[pscustomobject]@{Stamp='s';Text='t'}; $script:PraGuiHashCache['y']=[pscustomobject]@{Stamp='s';Hash='h'} }
        (& (Get-Module PRA.Gui) { $script:PraGuiBatchCache.Count + $script:PraGuiCsvCache.Count + $script:PraGuiHashCache.Count }) | Should -BeGreaterThan 2
        & (Get-Module PRA.Gui) { Clear-PraGuiFileCache }
        (& (Get-Module PRA.Gui) { $script:PraGuiBatchCache.Count + $script:PraGuiCsvCache.Count + $script:PraGuiHashCache.Count }) | Should -Be 0
        Remove-Variable PraGuiLocked -Scope Global
        (Get-Content -LiteralPath $script:GuiModule -Raw) | Should -Match "'BtnReload' \{ if \(-not \`$g\.Run\) \{ Clear-PraGuiFileCache; Update-PraGuiState \} \}"
    }
}

Describe 'Release 3.2.0 - the console does not keep a checksum that it could not read (synthetic, no engine)' -Tag 'Release320c' {
    It 'a locked .sha256 file is told but not kept: the next refresh reads it again; a real mismatch is kept until the stamp changes' {
        $runtime=New-GuiTestRoot
        $batch=New-GuiTestBatch $runtime
        $global:PraGuiLocked=$batch.Path
        $lock=[IO.File]::Open($batch.Path+'.sha256',[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::None)
        try { $locked=& (Get-Module PRA.Gui) { Get-PraGuiBatchCoreProblem (Get-PraGuiBatchCore $global:PraGuiLocked) $global:PraGuiLocked } } finally { $lock.Dispose() }
        $locked | Should -Match '^The checksum cannot be read: '
        (& (Get-Module PRA.Gui) { (Get-PraGuiBatchCore $global:PraGuiLocked).Problem }) | Should -BeNullOrEmpty -Because 'a failure to read is not kept on the cached core'
        (& (Get-Module PRA.Gui) { Get-PraGuiBatchCoreProblem (Get-PraGuiBatchCore $global:PraGuiLocked) $global:PraGuiLocked }) | Should -BeExactly '' -Because 'the lock ended'
        [IO.File]::WriteAllText($batch.Path+'.sha256',('0'*64),$script:GuiEncoding)
        (& (Get-Module PRA.Gui) { Get-PraGuiBatchCoreProblem (Get-PraGuiBatchCore $global:PraGuiLocked) $global:PraGuiLocked }) | Should -BeExactly 'SHA-256 mismatch.'
        (& (Get-Module PRA.Gui) { (Get-PraGuiBatchCore $global:PraGuiLocked).Problem }) | Should -BeExactly 'SHA-256 mismatch.' -Because 'a real mismatch stays until the stamp changes'
        Remove-Variable PraGuiLocked -Scope Global
    }
}

Describe 'Release 3.2.0 - the console tells a finished batch from one that is still to do, a partial or pending one stands out, and a finished one never looks continuable (synthetic, no engine)' -Tag 'Release320d' {
    BeforeAll {
        function Write-GuiPhaseData {
            param([string]$Folder, [string]$Action, [string]$Side, [string]$Status, [int]$Pending = 0, [string]$HandOff = '', [string]$Stamp = '20261116101010', [string]$BatchId = '', [string]$Environment = 'GuiSynthetic')
            # The data of a run names the batch of the folder it is written in.
            if (-not $BatchId) { $BatchId = (Split-Path $Folder -Leaf) -replace '^(Batch|Finalize)-', ''; $BatchId = $BatchId.Substring(0, [Math]::Min(8, $BatchId.Length)) }
            $record = [ordered]@{ SchemaVersion = 2; Kind = 'PhaseData'; Environment = $Environment; BatchId = $BatchId; ToolVersion = '3.2.0'; Truncated = $false
                Phase = [ordered]@{ RunId = ('20261116_101010-' + [guid]::NewGuid().ToString('N')); Action = $Action; Phase = $Side; Mode = 'Apply'; Computer = 'SRV1'; Account = 'CONTOSO\admin'; Server = 'dc01'
                    StartedUtc = '2026-11-16T10:10:10.0000000Z'; EndedUtc = '2026-11-16T10:20:10.0000000Z'; Status = $Status; ExitCode = 0; HandOff = $HandOff; Overrides = @(); Settings = [ordered]@{ Environment = 'GuiSynthetic' }; Steps = @()
                    Counts = [ordered]@{ Success = 1; Error = 0; Pending = $Pending; Skipped = 0; Planned = 0 } }
                Omitted = [ordered]@{ Objects = 0; JourneyLines = 0; Texts = 0; EventLines = 0 }
                Objects = @([ordered]@{ ObjectGuid = [guid]::NewGuid().ToString(); Name = 'synthetic@example.invalid' }); Issues = @(); Warnings = @() }
            $path = Join-Path $Folder ('PhaseData-{0}-{1}-{2}.json' -f $Stamp, ($Side -replace '[^0-9A-Za-z]', ''), [guid]::NewGuid().ToString('N').Substring(0, 8))
            Write-GuiTestFile $path ($record | ConvertTo-Json -Depth 8 -Compress)
            Write-GuiTestFile ($path + '.sha256') ((Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant())
            $path
        }
        function Get-GuiRowOf {
            param($Rows, [string]$BatchId)
            foreach ($candidate in $Rows) { if ($candidate.BatchId -ceq $BatchId) { return , $candidate } }
        }
        function Get-GuiBatchRows {
            param($Runtime, [string]$Action, [string]$Mode)
            & (Get-Module PRA.Gui) {
                param($Root, $Config, $Action, $Mode)
                $saved = $script:Gui
                try {
                    $state = Read-PraGuiState $Root $Config
                    $script:Gui = @{ Action = $Action; Mode = $Mode; State = $state; Detect = $null }
                    @(Get-PraGuiBatchEntry)
                }
                finally { $script:Gui = $saved }
            } $Runtime.Root $Runtime.Config $Action $Mode
        }
    }

    It 'labels the batches of Continue a batch: finished, pending, stopped, partial and still to do, with the letter case of the phase data ignored; the ones that need attention come first, the finished ones last' {
        $runtime = New-GuiTestRoot
        $todo = New-GuiTestBatch -Runtime $runtime
        $finished = New-GuiTestBatch -Runtime $runtime
        $null = Write-GuiPhaseData $finished.Folder 'convert' 'cLoUd' 'SUCCESS'
        $both = New-GuiTestBatch -Runtime $runtime
        $null = Write-GuiPhaseData $both.Folder 'CONVERT' 'both' 'success'
        $pending = New-GuiTestBatch -Runtime $runtime
        $null = Write-GuiPhaseData $pending.Folder 'Convert' 'BOTH' 'pENDING' -Pending 3
        $stopped = New-GuiTestBatch -Runtime $runtime
        $null = Write-GuiPhaseData $stopped.Folder 'Convert' 'CLOUD' 'Failed'
        $adOnly = New-GuiTestBatch -Runtime $runtime
        $null = Write-GuiPhaseData $adOnly.Folder 'Convert' 'AD' 'Pending' -HandOff 'Convert'
        $garbage = New-GuiTestBatch -Runtime $runtime
        Write-GuiTestFile (Join-Path $garbage.Folder 'PhaseData-20261116101010-Cloud-1a2b3c4d.json') 'not json at all'
        $partial = New-GuiTestBatch -Runtime $runtime
        Write-GuiTestJson $partial.Proof @{ SchemaVersion = 2; Operation = 'Convert'; Kind = 'ADVerified'; Environment = 'GuiSynthetic'; Partial = $true; PlannedCount = 10; Records = @(1..3 | ForEach-Object { @{ ObjectGuid = [guid]::NewGuid().ToString(); Operation = 'Convert'; ADVerified = $true } }) }
        $null = Write-GuiPhaseData $partial.Folder 'Convert' 'Cloud' 'Success'
        $rows = Get-GuiBatchRows $runtime 'Convert' 'Continue'
        $row = { param($batch) Get-GuiRowOf $rows $batch.Id }
        $mark = [string][char]0xE73E
        foreach ($case in @($todo, $adOnly, $garbage)) {
            $r = & $row $case
            $r.State | Should -BeExactly 'AD part done, cloud part to do'
            $r.Group | Should -BeExactly 'To do'; $r.Level | Should -BeExactly 'Todo'; $r.Selectable | Should -BeTrue; $r.Finish | Should -BeFalse
        }
        foreach ($case in @($finished, $both)) {
            $r = & $row $case
            $r.State | Should -BeExactly 'Finished: cloud part done'
            $r.Group | Should -BeExactly 'Finished'; $r.Level | Should -BeExactly 'Ok'; $r.Selectable | Should -BeFalse -Because 'a finished batch cannot be continued'; $r.Finish | Should -BeFalse; $r.Mark | Should -BeExactly $mark
        }
        $r = & $row $pending
        $r.State | Should -BeExactly 'Cloud part pending: 3 objects not ready, run it again'
        $r.Level | Should -BeExactly 'Warn'; $r.Group | Should -BeExactly 'To do'; $r.Selectable | Should -BeTrue
        $r = & $row $stopped
        $r.State | Should -BeExactly 'Cloud part stopped: run it again'
        $r.Level | Should -BeExactly 'Warn'; $r.Selectable | Should -BeTrue
        $r = & $row $partial
        $r.State | Should -BeLike 'Partial: 3 of 10 converted * AD part*' -Because 'the cloud part of the objects that were converted does not make a partial batch finished'
        $r.Level | Should -BeExactly 'Warn'; $r.Group | Should -BeExactly 'To do'; $r.Selectable | Should -BeTrue
        $order = @($rows | ForEach-Object { $_.BatchId })
        $position = { param($batch) [array]::IndexOf($order, $batch.Id) }
        foreach ($attention in @($pending, $stopped, $partial)) { foreach ($plain in @($todo, $adOnly, $garbage)) { (& $position $attention) | Should -BeLessThan (& $position $plain) -Because 'a pending, stopped or partial batch comes before a batch that is simply to do' } }
        foreach ($done in @($finished, $both)) { foreach ($other in @($todo, $pending, $stopped, $partial, $adOnly, $garbage)) { (& $position $done) | Should -BeGreaterThan (& $position $other) -Because 'finished batches are last' } }
    }

    It 'labels the batches of a rollback: a finished conversion is still a batch to roll back, and says it is finished; a Recover whose cloud part is done says so and cannot be continued' {
        $runtime = New-GuiTestRoot
        $todo = New-GuiTestBatch -Runtime $runtime
        $finished = New-GuiTestBatch -Runtime $runtime
        $null = Write-GuiPhaseData $finished.Folder 'Convert' 'Cloud' 'Success'
        $rows = Get-GuiBatchRows $runtime 'Recover' 'New'
        $r = Get-GuiRowOf $rows $todo.Id
        $r.State | Should -BeExactly 'Can be rolled back'; $r.Selectable | Should -BeTrue; $r.Group | Should -BeExactly 'To do'
        $r = Get-GuiRowOf $rows $finished.Id
        $r.State | Should -BeExactly 'Finished · can be rolled back'; $r.Selectable | Should -BeTrue; $r.Group | Should -BeExactly 'Finished'
        $runtime = New-GuiTestRoot
        $plain = New-GuiTestBatch -Runtime $runtime -Operation 'Recover'
        $handed = New-GuiTestBatch -Runtime $runtime -Operation 'Recover'
        $null = Write-GuiPhaseData $handed.Folder 'RECOVER' 'cloud' 'Pending' -HandOff 'Finalize'
        $waiting = New-GuiTestBatch -Runtime $runtime -Operation 'Recover'
        $null = Write-GuiPhaseData $waiting.Folder 'Recover' 'Cloud' 'Pending' -Pending 2
        $rows = Get-GuiBatchRows $runtime 'Recover' 'Continue'
        $r = Get-GuiRowOf $rows $plain.Id
        $r.State | Should -BeExactly 'AD rollback done, cloud part to do'; $r.Level | Should -BeExactly 'Todo'; $r.Selectable | Should -BeTrue
        $r = Get-GuiRowOf $rows $handed.Id
        $r.State | Should -BeExactly 'Cloud part done: finalize on the AD server'; $r.Group | Should -BeExactly 'Finished'; $r.Selectable | Should -BeFalse
        $r = Get-GuiRowOf $rows $waiting.Id
        $r.State | Should -BeExactly 'Cloud part pending: 2 objects not ready, run it again'; $r.Level | Should -BeExactly 'Warn'; $r.Selectable | Should -BeTrue
    }

    It 'reads the progress of a batch from the last cloud-side run: a later failed run reopens a finished batch, a Finalize that succeeded is finished, and the header is read from the start of a large file only' {
        $runtime = New-GuiTestRoot
        $batch = New-GuiTestBatch -Runtime $runtime
        $progress = { param($folder, $operation) & (Get-Module PRA.Gui) { param($f, $o) Get-PraGuiBatchProgress $f $o } $folder $operation }
        (& $progress $batch.Folder 'Convert').Kind | Should -BeExactly 'None'
        $null = Write-GuiPhaseData $batch.Folder 'Convert' 'Cloud' 'Success' -Stamp '20261116101010'
        (& $progress $batch.Folder 'convert').Kind | Should -BeExactly 'Finished'
        $null = Write-GuiPhaseData $batch.Folder 'Convert' 'Cloud' 'Failed' -Stamp '20261116111111'
        (& $progress $batch.Folder 'Convert').Kind | Should -BeExactly 'Stopped' -Because 'the last run decides'
        $final = New-GuiTestBatch -Runtime $runtime -Operation 'RecoverFinalize'
        $null = Write-GuiPhaseData $final.Folder 'FINALIZE' 'finalize' 'SUCCESS'
        (& $progress $final.Folder 'RecoverFinalize').Kind | Should -BeExactly 'Finished'
        (& $progress (Join-Path $runtime.Root 'missing-folder') 'Convert').Kind | Should -BeExactly 'None'
        $large = New-GuiTestBatch -Runtime $runtime
        $path = Write-GuiPhaseData $large.Folder 'Convert' 'Cloud' 'Success'
        $text = [IO.File]::ReadAllText($path)
        $objects = ((1..30000 | ForEach-Object { '{"ObjectGuid":"' + [guid]::NewGuid().ToString() + '","Name":"synthetic' + $_ + '@example.invalid","Detail":"' + ('x' * 100) + '"}' }) -join ',')
        [IO.File]::WriteAllText($path, $text.Replace('"Objects":[', '"Objects":[' + $objects + ','), (New-Object Text.UTF8Encoding($false)))
        [IO.File]::WriteAllText($path + '.sha256', (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant(), (New-Object Text.UTF8Encoding($false)))
        ([IO.FileInfo]$path).Length | Should -BeGreaterThan 4MB
        $clock = [Diagnostics.Stopwatch]::StartNew()
        (& $progress $large.Folder 'Convert').Kind | Should -BeExactly 'Finished'
        $clock.Elapsed.TotalSeconds | Should -BeLessThan 5 -Because 'only the first bytes of the file are read, and the answer is kept while the file does not change'
    }

    It 'does not take a phase data file for a batch that it is not: another batch, another Environment, no checksum file or a checksum that does not match count as no phase data, and a file that cannot be opened just now is not remembered as unreadable' -Tag 'Release320f' {
        $runtime = New-GuiTestRoot
        $progress = { param($folder, $environment) & (Get-Module PRA.Gui) { param($f, $e) Get-PraGuiBatchProgress $f 'Convert' $e } $folder $environment }
        $other = New-GuiTestBatch -Runtime $runtime
        $null = Write-GuiPhaseData $other.Folder 'Convert' 'Cloud' 'Success' -BatchId 'FFFFFFFF'
        (& $progress $other.Folder 'GuiSynthetic').Kind | Should -BeExactly 'None' -Because 'the file names another batch'
        $null = Write-GuiPhaseData $other.Folder 'Convert' 'Cloud' 'Success' -Stamp '20261116121212' -BatchId $other.Id.ToUpperInvariant().Substring(0, 8)
        (& $progress $other.Folder 'GuiSynthetic').Kind | Should -BeExactly 'Finished' -Because 'the batch id is compared in any letter case'
        $env = New-GuiTestBatch -Runtime $runtime
        $null = Write-GuiPhaseData $env.Folder 'Convert' 'Cloud' 'Success' -Environment 'Another'
        (& $progress $env.Folder 'guisynthetic').Kind | Should -BeExactly 'None' -Because 'the file is for another Environment'
        (& $progress $env.Folder '').Kind | Should -BeExactly 'Finished' -Because 'an empty Environment is not compared'
        $sum = New-GuiTestBatch -Runtime $runtime
        $path = Write-GuiPhaseData $sum.Folder 'Convert' 'Cloud' 'Success'
        $good = [IO.File]::ReadAllText($path + '.sha256')
        Remove-Item -LiteralPath ($path + '.sha256') -Force
        (& $progress $sum.Folder 'GuiSynthetic').Kind | Should -BeExactly 'None' -Because 'no checksum file: the batch is not shown as finished'
        [IO.File]::WriteAllText($path + '.sha256', ('0' * 64))
        (& $progress $sum.Folder 'GuiSynthetic').Kind | Should -BeExactly 'None' -Because 'the checksum does not match the file'
        [IO.File]::WriteAllText($path + '.sha256', $good.ToUpperInvariant())
        (& $progress $sum.Folder 'GuiSynthetic').Kind | Should -BeExactly 'Finished' -Because 'a checksum file written afterwards is read at the next refresh, in any letter case'
        $busy = New-GuiTestBatch -Runtime $runtime
        $busyPath = Write-GuiPhaseData $busy.Folder 'Convert' 'Cloud' 'Success'
        $lock = [IO.File]::Open($busyPath, [IO.FileMode]::Open, [IO.FileAccess]::ReadWrite, [IO.FileShare]::None)
        try { (& $progress $busy.Folder 'GuiSynthetic').Kind | Should -BeExactly 'None' -Because 'the file is held by another process' }
        finally { $lock.Dispose() }
        (& $progress $busy.Folder 'GuiSynthetic').Kind | Should -BeExactly 'Finished' -Because 'the failed read was not kept'
    }

    It 'shows the sections in the window: To do is shown first for a list that continues a batch, Finished and All are one click away, a finished batch cannot be picked, and an empty section says why' {
        $runtime = New-GuiTestRoot
        $todo = New-GuiTestBatch -Runtime $runtime
        $pending = New-GuiTestBatch -Runtime $runtime
        $null = Write-GuiPhaseData $pending.Folder 'Convert' 'Cloud' 'Pending' -Pending 1
        $finished = New-GuiTestBatch -Runtime $runtime
        $null = Write-GuiPhaseData $finished.Folder 'Convert' 'Cloud' 'Success'
        $onlyFinished = New-GuiTestRoot
        $done = New-GuiTestBatch -Runtime $onlyFinished
        $null = Write-GuiPhaseData $done.Folder 'Convert' 'Cloud' 'Success'
        $probe = Join-Path $runtime.Root 'wpf-probe-sections.ps1'
        Write-GuiTestFile $probe @'
param($Common,$Gui,$Root,$Config,$OnlyRoot,$OnlyConfig,$TodoId,$PendingId,$FinishedId)
$ErrorActionPreference='Stop'
Import-Module $Common -Force
Import-Module $Gui -Force
function Pump([int]$Milliseconds=60){
 $frame=New-Object Windows.Threading.DispatcherFrame
 $pump=New-Object Windows.Threading.DispatcherTimer
 $pump.Interval=[timespan]::FromMilliseconds($Milliseconds);$pump.Tag=$frame
 $pump.Add_Tick({param($s)$s.Tag.Continue=$false;$s.Stop()})
 $pump.Start();[Windows.Threading.Dispatcher]::PushFrame($frame)
}
function Click($Window,[string]$Name){ $Window.Controls[$Name].RaiseEvent((New-Object Windows.RoutedEventArgs ([Windows.Controls.Button]::ClickEvent))) }
$detect={ param($Request) [pscustomobject]@{ Lights=@([ordered]@{Name='RSAT ActiveDirectory';Status='Ok';Detail='synthetic'}); AD=$true; Cloud=$true; Role='Both' } }
function New-SectionWindow($WindowRoot,$WindowConfig){
  $window=New-PraGuiWindow -Root $WindowRoot -ConfigPath $WindowConfig -Version 'Synthetic' -PrerequisiteProbe $detect
  $window.Form.Show()
  Click $window 'BtnNext'
  $window.Controls['T_Convert'].IsChecked=$true; Pump 80
  $window.Controls['Mode_Continue'].IsChecked=$true; Pump 80
  Click $window 'BtnReload'; Pump 80
  return $window
}
function Ids($Window){ return @($Window.BatchRows | ForEach-Object { $_.BatchId }) }
function RowOf($Window,[string]$Id){ return ,@($Window.BatchRows | Where-Object { $_.BatchId -ceq $Id })[0] }
$g=New-SectionWindow $Root $Config
try {
 $c=$g.Controls
 if($c.Bf_ToDo.Content -cne 'To do (2)' -or $c.Bf_Finished.Content -cne 'Finished (1)' -or $c.Bf_All.Content -cne 'All (3)'){throw ('Section counts: '+$c.Bf_ToDo.Content+' / '+$c.Bf_Finished.Content+' / '+$c.Bf_All.Content)}
 if(-not $c.Bf_ToDo.IsChecked -or $c.BatchFilterBar.Visibility -ne 'Visible'){throw 'To do is not the section in force'}
 $ids=@(Ids $g)
 if($ids.Count -ne 2 -or $ids -contains $FinishedId -or $ids[0] -cne $PendingId -or $ids[1] -cne $TodoId){throw ('To do section: '+($ids -join ','))}
 $pending=RowOf $g $PendingId
 if($pending.Level -cne 'Warn' -or $pending.State -cnotmatch '^Cloud part pending: 1 object not ready'){throw ('Pending row: '+$pending.State+' / '+$pending.Level)}
 $c.Bf_Finished.IsChecked=$true; Pump 80
 $ids=@(Ids $g)
 if($ids.Count -ne 1 -or $ids[0] -cne $FinishedId -or -not $c.Bf_Finished.IsChecked){throw ('Finished section: '+($ids -join ','))}
 $row=$g.BatchRows[0]
 if($row.Selectable -or $row.Group -cne 'Finished' -or $row.State -cne 'Finished: cloud part done'){throw ('Finished row: '+$row.State)}
 if($c.BtnNext.IsEnabled){throw 'A finished batch must not let the operator go on'}
 $c.Bf_All.IsChecked=$true; Pump 80
 $ids=@(Ids $g)
 if($ids.Count -ne 3 -or $ids[2] -cne $FinishedId){throw ('All section: '+($ids -join ','))}
 $c.BatchList.SelectedItem=(RowOf $g $TodoId); Pump 80
 if($null -eq $g.SelectedBatch -or $g.SelectedBatch.BatchId -cne $TodoId -or -not $c.BtnNext.IsEnabled){throw 'A batch that is to do can be picked'}
 $c.Mode_New.IsChecked=$true; Pump 80; $c.Mode_Continue.IsChecked=$true; Pump 80
 if(-not $c.Bf_ToDo.IsChecked -or @(Ids $g).Count -ne 2){throw 'Changing the mode puts the list back to To do'}
} finally { $g.Form.Close() }
$g=New-SectionWindow $OnlyRoot $OnlyConfig
try {
 $c=$g.Controls
 if($g.BatchRows.Count -ne 0 -or $c.BatchEmpty.Text -cnotmatch '^Nothing is left to do here: 1 finished and hidden\. Click Finished or All to see it\.$'){throw ('Only finished: '+$g.BatchRows.Count+' / '+$c.BatchEmpty.Text)}
 $c.Bf_Finished.IsChecked=$true; Pump 80
 if($g.BatchRows.Count -ne 1 -or $c.BatchEmpty.Text){throw 'The finished batch is listed in its section'}
} finally { $g.Form.Close() }
[Console]::WriteLine('SECTIONS-PASS')
'@
        $tokens = @('-NoProfile', '-NonInteractive', '-STA', '-File', $probe, '-Common', $script:GuiCommon, '-Gui', $script:GuiModule, '-Root', $runtime.Root, '-Config', $runtime.Config, '-OnlyRoot', $onlyFinished.Root, '-OnlyConfig', $onlyFinished.Config,
            '-TodoId', $todo.Id, '-PendingId', $pending.Id, '-FinishedId', $finished.Id)
        $info = New-Object Diagnostics.ProcessStartInfo
        $info.FileName = (Join-Path $PSHOME 'pwsh.exe'); $info.Arguments = (@($tokens | ForEach-Object { ConvertTo-PraGuiNativeArgument $_ }) -join ' ')
        $info.UseShellExecute = $false; $info.CreateNoWindow = $true; $info.RedirectStandardOutput = $true; $info.RedirectStandardError = $true
        $process = [Diagnostics.Process]::Start($info)
        $out = $process.StandardOutput.ReadToEndAsync(); $err = $process.StandardError.ReadToEndAsync()
        try {
            $process.WaitForExit(180000) | Should -BeTrue
            $process.ExitCode | Should -Be 0 -Because ($out.Result + $err.Result)
            $out.Result | Should -Match 'SECTIONS-PASS'
        } finally { $process.Dispose() }
    }
}

Describe 'Release 3.2.0 - the console: the retention override, the header of the activity log, the old files of logs\gui, the steps after a valid run, Ctrl+C and the time limit of the OU lookup (synthetic, no engine)' -Tag 'Release320e' {
    It 'the request, the command line and the guard carry -AcceptRetentionRisk for the AD part of a Recover only, whatever the letter case of the words' -TestCases @(
        @{Action='Recover';Phase='AD';Batch='01234567';Expected=$true}
        @{Action='recover';Phase='both';Batch='01234567';Expected=$true}
        @{Action='RECOVER';Phase='BOTH';Batch='01234567';Expected=$true}
        @{Action='Recover';Phase='Cloud';Batch='01234567';Expected=$false}
        @{Action='Convert';Phase='Both';Batch='';Expected=$false}
        @{Action='Finalize';Phase='AD';Batch='01234567';Expected=$false}
        @{Action='Check';Phase='Cloud';Batch='01234567';Expected=$false}
    ) {
        param($Action,$Phase,$Batch,$Expected)
        $request=New-PraGuiRequest -Action $Action -Phase $Phase -Batch $Batch -AcceptRetentionRisk $true
        [bool]$request.AcceptRetentionRisk | Should -Be $Expected
        $command=Get-PraGuiCommand -Root 'C:\Synthetic root' -ConfigPath 'C:\Synthetic root\config.psd1' -Request $request
        ($command.Tokens -contains '-AcceptRetentionRisk') | Should -Be $Expected
        ($command.Display -match '-AcceptRetentionRisk') | Should -Be $Expected
        $plain=New-PraGuiRequest -Action $Action -Phase $Phase -Batch $Batch
        [bool]$plain.AcceptRetentionRisk | Should -BeFalse
        (Get-PraGuiCommand -Root 'C:\Synthetic root' -ConfigPath 'C:\Synthetic root\config.psd1' -Request $plain).Tokens | Should -Not -Contain '-AcceptRetentionRisk'
    }
    It 'the switch changes the guard of the Preview: an Apply after the box was ticked or cleared needs a new Preview' {
        $runtime=New-GuiTestRoot
        $batch=New-GuiTestBatch $runtime
        $without=Get-PraGuiGuard $runtime.Root $runtime.Config (New-PraGuiRequest -Action Recover -Phase AD -Batch $batch.Path)
        $with=Get-PraGuiGuard $runtime.Root $runtime.Config (New-PraGuiRequest -Action Recover -Phase AD -Batch $batch.Path -AcceptRetentionRisk $true)
        $with | Should -Not -Be $without
        Get-PraGuiGuard $runtime.Root $runtime.Config (New-PraGuiRequest -Action Recover -Phase AD -Batch $batch.Path -AcceptRetentionRisk $true) | Should -Be $with
    }
    It 'the window has the checkbox on the Recover task, off by default, and the engine switch is documented in the entry script' {
        $xaml=Get-Content -LiteralPath (Join-Path $script:GuiProjectRoot 'module\PRA.Gui.xaml') -Raw
        $xaml | Should -Match 'x:Name="F_AcceptRetention"'
        $xaml | Should -Not -Match 'F_AcceptRetention"[^>]*IsChecked="True"'
        $gui=Get-Content -LiteralPath $script:GuiModule -Raw
        $gui | Should -Match 'F_AcceptRetention\.Add_Checked'
        $gui | Should -Match 'F_AcceptRetention\.IsChecked=\$false'
        (Get-Content -LiteralPath (Join-Path $script:GuiProjectRoot 'Invoke-PraRemoteMailbox.ps1') -Raw) | Should -Match '\[switch\]\$AcceptRetentionRisk'
    }
    It 'the header of the activity log says where the complete log is, and goes back to the plain title' {
        Add-Type -AssemblyName PresentationFramework,PresentationCore,WindowsBase
        & (Get-Module PRA.Gui) {
            $expander=[pscustomobject]@{ Header='Activity log' }
            $script:Gui=@{ Controls=@{ LogExpander=$expander } }
            try {
                Set-PraGuiLogHeader 'C:\Synthetic root\logs\run.log'
                $expander.Header | Should -BeOfType ([Windows.Controls.TextBlock])
                $expander.Header.Text | Should -BeExactly ('Activity log: the last {0} lines. The complete log is in C:\Synthetic root\logs\run.log' -f $script:PraGuiLogLines)
                Set-PraGuiLogHeader ''
                $expander.Header | Should -BeExactly 'Activity log'
            } finally { $script:Gui=$null }
        }
        $text=Get-Content -LiteralPath $script:GuiModule -Raw
        $text | Should -Match "Set-PraGuiLogHeader \(\`$base\+'\.stdout\.txt'\)"
        $text | Should -Match 'if \(\$logFile\) \{ Set-PraGuiLogHeader \$logFile \}'
    }
    It 'after a valid run a step that never started is Skip, the running one is Ok; after a failed run the running one is Fail and the others stay Pending' {
        & (Get-Module PRA.Gui) {
            foreach ($valid in @($true,$false)) {
                $rows=@('Ok','Running','Wait','Pending','Skip','Warn' | ForEach-Object { New-PraGuiRow @{ Status=$_; Note='n'; NoteBase='n'; NextAt=1; Progress=[double]0.5 } })
                Close-PraGuiRunStep -Step $rows -Valid $valid
                $states=@($rows | ForEach-Object { $_.Status }) -join ','
                if ($valid) { $states | Should -BeExactly 'Ok,Ok,Ok,Skip,Skip,Warn' }
                else { $states | Should -BeExactly 'Ok,Fail,Fail,Pending,Skip,Warn' }
                $rows[1].Progress | Should -Be 1
            }
        }
        Get-Content -LiteralPath $script:GuiModule -Raw | Should -Match 'Close-PraGuiRunStep -Step @\(\$g\.Model\.Steps\) -Valid \$valid'
    }
    It 'the window removes what it left in logs\gui more than 30 days ago, files and run folders, and nothing else' {
        $runtime=New-GuiTestRoot
        $gui=Join-Path $runtime.Root 'logs\gui'
        $old=(Get-Date).AddDays(-31); $recent=(Get-Date).AddDays(-29)
        $null=New-Item -ItemType Directory -Path (Join-Path $gui 'run-old'),(Join-Path $gui 'run-recent') -Force
        Write-GuiTestFile (Join-Path $gui 'run-old\effective.config.psd1') '@{ }'
        Write-GuiTestFile (Join-Path $gui 'run-recent\effective.config.psd1') '@{ }'
        foreach ($name in @('a-old.events.jsonl','a-old.stdout.txt','b-recent.stdout.txt','OU-OLD.json')) { Write-GuiTestFile (Join-Path $gui $name) 'x' }
        Write-GuiTestFile (Join-Path $runtime.Root 'logs\engine-old.log') 'engine log, never touched'
        Write-GuiTestFile (Join-Path $runtime.Root 'reports\report-old.html') 'report, never touched'
        foreach ($path in @((Join-Path $gui 'a-old.events.jsonl'),(Join-Path $gui 'a-old.stdout.txt'),(Join-Path $gui 'OU-OLD.json'),(Join-Path $gui 'run-old\effective.config.psd1'),(Join-Path $gui 'run-old'),(Join-Path $runtime.Root 'logs\engine-old.log'),(Join-Path $runtime.Root 'reports\report-old.html'))) { (Get-Item -LiteralPath $path).LastWriteTime=$old }
        foreach ($path in @((Join-Path $gui 'b-recent.stdout.txt'),(Join-Path $gui 'run-recent\effective.config.psd1'),(Join-Path $gui 'run-recent'))) { (Get-Item -LiteralPath $path).LastWriteTime=$recent }
        Remove-PraGuiOldLog -Root $runtime.Root | Should -Be 4
        @(Get-ChildItem -LiteralPath $gui -Force | ForEach-Object Name | Sort-Object) -join ',' | Should -BeExactly 'b-recent.stdout.txt,run-recent'
        Test-Path -LiteralPath (Join-Path $runtime.Root 'logs\engine-old.log') | Should -BeTrue
        Test-Path -LiteralPath (Join-Path $runtime.Root 'reports\report-old.html') | Should -BeTrue
        Remove-PraGuiOldLog -Root $runtime.Root | Should -Be 0
        Remove-PraGuiOldLog -Root (Join-Path $runtime.Root 'does-not-exist') | Should -Be 0
    }
    It 'a file of logs\gui that is held open is left, the others are removed, and nothing is thrown' {
        $runtime=New-GuiTestRoot
        $gui=Join-Path $runtime.Root 'logs\gui'
        foreach ($name in @('held.stdout.txt','free.stdout.txt')) { Write-GuiTestFile (Join-Path $gui $name) 'x'; (Get-Item -LiteralPath (Join-Path $gui $name)).LastWriteTime=(Get-Date).AddDays(-60) }
        $lock=[IO.File]::Open((Join-Path $gui 'held.stdout.txt'),[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::None)
        try { { Remove-PraGuiOldLog -Root $runtime.Root } | Should -Not -Throw } finally { $lock.Dispose() }
        @(Get-ChildItem -LiteralPath $gui | ForEach-Object Name) | Should -BeExactly @('held.stdout.txt')
    }
    It 'Show-PraGui prunes logs\gui and keeps Ctrl+C out of the window only while it is open, only when the input is a console, and gives the setting back' {
        $text=Get-Content -LiteralPath $script:GuiModule -Raw
        $body=[regex]::Match($text,'(?s)function Show-PraGui \{.*?\r?\n\}\r?\n').Value
        $body | Should -Match 'Remove-PraGuiOldLog -Root \$Root'
        $body | Should -Match '\[Console\]::IsInputRedirected'
        $body.IndexOf('TreatControlCAsInput=$true') | Should -BeGreaterThan 0
        $body.IndexOf('TreatControlCAsInput=$true') | Should -BeLessThan $body.IndexOf('ShowDialog()')
        $body.IndexOf('finally') | Should -BeGreaterThan $body.IndexOf('ShowDialog()')
        $body.Substring($body.IndexOf('finally')) | Should -Match 'TreatControlCAsInput=\$previousCtrlC'
        Get-Command -Module PRA.Gui -Name Remove-PraGuiOldLog | Should -Not -BeNullOrEmpty
    }
    It 'an OU lookup that does not answer within its time limit is stopped, says so, and frees the window; one that is within its time is left alone' {
        $info=New-Object Diagnostics.ProcessStartInfo
        $info.FileName=(Join-Path $PSHOME 'pwsh.exe'); $info.Arguments='-NoProfile -NonInteractive -Command Start-Sleep -Seconds 120'; $info.UseShellExecute=$false; $info.CreateNoWindow=$true
        $process=[Diagnostics.Process]::Start($info)
        $processId=$process.Id; $processStart=$process.StartTime
        $global:PraOuProcess=$process; $global:PraOuMessages=New-Object 'Collections.Generic.List[string]'
        try {
            Mock Show-PraGuiError { $global:PraOuMessages.Add($Message) } -ModuleName PRA.Gui
            Mock Set-PraGuiBusy { } -ModuleName PRA.Gui
            Mock Update-PraGuiView { } -ModuleName PRA.Gui
            Mock Sync-PraGuiTimer { } -ModuleName PRA.Gui
            & (Get-Module PRA.Gui) {
                $global:PraOuStopped=0
                $timer=[pscustomobject]@{}; Add-Member -InputObject $timer -MemberType ScriptMethod -Name Stop -Value { $global:PraOuStopped=[int]$global:PraOuStopped+1 }
                $script:Gui=@{ Timer=$timer; OuLookup=@{ Process=$global:PraOuProcess; Output=[pscustomobject]@{IsCompleted=$false}; Errors=[pscustomobject]@{IsCompleted=$false}; Path='none'; Base='none'; Clock=[Diagnostics.Stopwatch]::StartNew() } }
                try {
                    Complete-PraGuiOuLookup
                    $script:Gui.OuLookup | Should -Not -BeNullOrEmpty -Because 'the time limit is not reached'
                    $global:PraOuMessages.Count | Should -Be 0
                    $script:PraGuiOuLookupSeconds | Should -Be 60
                    $script:Gui.OuLookup.Clock=[Diagnostics.Stopwatch]::StartNew()
                    $keep=$script:PraGuiOuLookupSeconds; $script:PraGuiOuLookupSeconds=0
                    Start-Sleep -Milliseconds 30
                    Complete-PraGuiOuLookup
                    $script:PraGuiOuLookupSeconds=$keep
                    $script:Gui.OuLookup | Should -BeNullOrEmpty
                } finally { $script:Gui=$null }
            }
            $global:PraOuMessages.Count | Should -Be 1
            $global:PraOuMessages[0] | Should -Match 'Active Directory did not answer within 0 seconds'
            $global:PraOuMessages[0] | Should -Match 'type the distinguished name of the OU'
            $deadline=[datetime]::UtcNow.AddSeconds(10)
            while ((Get-Process -Id $processId -ErrorAction SilentlyContinue) -and [datetime]::UtcNow -lt $deadline) { Start-Sleep -Milliseconds 100 }
            $still=Get-Process -Id $processId -ErrorAction SilentlyContinue
            ($null -eq $still -or $still.StartTime -ne $processStart) | Should -BeTrue -Because 'the lookup process is stopped'
        } finally {
            $left=Get-Process -Id $processId -ErrorAction SilentlyContinue
            if ($left -and $left.StartTime -eq $processStart) { $left.Kill() }
            Remove-Variable PraOuProcess,PraOuMessages,PraOuStopped -Scope Global -ErrorAction SilentlyContinue
        }
        (Get-Content -LiteralPath $script:GuiModule -Raw) | Should -Match 'Clock=\[Diagnostics\.Stopwatch\]::StartNew\(\) \}\r?\n    Set-PraGuiBusy \$true\r?\n    Add-PraGuiLine ''Reading the OUs'
    }
}

Describe 'Release 3.2.0 - the console: the retention checkbox in the window (synthetic window, no engine)' -Tag 'Release320e' {
    It 'shows the checkbox for a Recover whose AD part runs on this server only, cleared at the start and whenever the task changes, and sends it to the request and to the command line' {
        $runtime = New-GuiTestRoot
        $batch = New-GuiTestBatch -Runtime $runtime
        $probe = Join-Path $runtime.Root 'wpf-probe-retention.ps1'
        Write-GuiTestFile $probe @'
param($Common,$Gui,$Root,$Config,$BatchPath)
$ErrorActionPreference='Stop'
Import-Module $Common -Force
Import-Module $Gui -Force
function Pump([int]$Milliseconds=60){
 $frame=New-Object Windows.Threading.DispatcherFrame
 $pump=New-Object Windows.Threading.DispatcherTimer
 $pump.Interval=[timespan]::FromMilliseconds($Milliseconds);$pump.Tag=$frame
 $pump.Add_Tick({param($s)$s.Tag.Continue=$false;$s.Stop()})
 $pump.Start();[Windows.Threading.Dispatcher]::PushFrame($frame)
}
function Click($Window,[string]$Name){ $Window.Controls[$Name].RaiseEvent((New-Object Windows.RoutedEventArgs ([Windows.Controls.Button]::ClickEvent))) }
$detect={ param($Request) [pscustomobject]@{ Lights=@([ordered]@{Name='RSAT ActiveDirectory';Status='Ok';Detail='synthetic'}); AD=$true; Cloud=$true; Role='Both' } }
$g=New-PraGuiWindow -Root $Root -ConfigPath $Config -Version 'Synthetic' -PrerequisiteProbe $detect
$g.Form.Show()
try {
 $c=$g.Controls
 Click $g 'BtnNext'
 $c.T_Convert.IsChecked=$true; Pump 80
 if($c.RetentionBox.Visibility -ne 'Collapsed'){throw 'A Convert has no retention check'}
 $c.T_Recover.IsChecked=$true; Pump 80
 if($c.RetentionBox.Visibility -ne 'Visible'){throw 'A Recover whose AD part runs here shows the box'}
 if($c.F_AcceptRetention.IsChecked){throw 'The box starts cleared'}
 if($c.RetentionHint.Text -notmatch 'checks that the retention policy holds them'){throw ('Hint: '+$c.RetentionHint.Text)}
 $c.F_AcceptRetention.IsChecked=$true; Pump 80
 $g.SelectedBatch=[pscustomobject]@{ Path=$BatchPath }
 $request=& (Get-Module PRA.Gui) { Get-PraGuiWindowRequest 'Apply' }
 if(-not $request.AcceptRetentionRisk -or $request.Phase -ne 'Both'){throw ('The request does not carry the box: '+($request|ConvertTo-Json -Compress))}
 $display=(& (Get-Module PRA.Gui) { param($r) (Get-PraGuiCommand $script:Gui.Root $script:Gui.ConfigPath $r).Display } $request)
 if($display -notmatch '-AcceptRetentionRisk'){throw ('The command line does not carry the box: '+$display)}
 $c.Mode_Continue.IsChecked=$true; Pump 80
 if($c.RetentionBox.Visibility -ne 'Collapsed' -or $c.F_AcceptRetention.IsChecked){throw 'The cloud part never checks the retention: the box goes away and is cleared'}
 $c.Mode_New.IsChecked=$true; Pump 80
 if($c.RetentionBox.Visibility -ne 'Visible' -or $c.F_AcceptRetention.IsChecked){throw 'Back on the AD part: the box is shown again, still cleared'}
 $c.F_AcceptRetention.IsChecked=$true; Pump 80
 $c.T_Convert.IsChecked=$true; Pump 80
 $c.T_Recover.IsChecked=$true; Pump 80
 if($c.F_AcceptRetention.IsChecked){throw 'Another task cleared the box: the acceptance is never carried to another run'}
} finally { $g.Form.Close() }
[Console]::WriteLine('RETENTION-PASS')
'@
        $tokens = @('-NoProfile', '-NonInteractive', '-STA', '-File', $probe, '-Common', $script:GuiCommon, '-Gui', $script:GuiModule, '-Root', $runtime.Root, '-Config', $runtime.Config, '-BatchPath', $batch.Path)
        $info = New-Object Diagnostics.ProcessStartInfo
        $info.FileName = (Join-Path $PSHOME 'pwsh.exe'); $info.Arguments = (@($tokens | ForEach-Object { ConvertTo-PraGuiNativeArgument $_ }) -join ' ')
        $info.UseShellExecute = $false; $info.CreateNoWindow = $true; $info.RedirectStandardOutput = $true; $info.RedirectStandardError = $true
        $process = [Diagnostics.Process]::Start($info)
        $out = $process.StandardOutput.ReadToEndAsync(); $err = $process.StandardError.ReadToEndAsync()
        try {
            $process.WaitForExit(180000) | Should -BeTrue
            $process.ExitCode | Should -Be 0 -Because ($out.Result + $err.Result)
            $out.Result | Should -Match 'RETENTION-PASS'
        } finally { $process.Dispose() }
    }
}

Describe 'Release 3.2.0 - the console shows whether the retention proof of the selected batch is found, and how old it is (synthetic, no engine)' -Tag 'Release320e', 'Release320i' {
    BeforeAll {
        function global:Get-G320GuiText {
            param($Case)
            $global:PraGuiProofCase = $Case
            try {
                & (Get-Module PRA.Gui) {
                    $case = $global:PraGuiProofCase
                    $config = [pscustomobject]@{ Environment = 'GUISYNTHETIC'; Storage = [pscustomobject]@{ BackupFolder = $case.Backup }; Retention = [pscustomobject]@{ ProofMaxAgeHours = $case.Hours; PolicyGuid = $(if ($case.ContainsKey('PolicyGuid')) { [string]$case.PolicyGuid } else { '' }); PolicyName = $(if ($case.ContainsKey('PolicyName')) { [string]$case.PolicyName } else { '' }) }; Cloud = [pscustomobject]@{ AppId = $(if ($case.Certificate) { 'app' } else { '' }) }; SharedMailbox = [pscustomobject]@{ KeepCloudSharedOnRecover = $(if ($case.ContainsKey('KeepShared')) { [bool]$case.KeepShared } else { $false }) } }
                    $script:Gui = @{ SelectedBatch = [pscustomobject]@{ BatchId = $case.Batch.Id; Path = $case.Batch.Path; Data = [pscustomobject]@{ TaggedRows = $case.Tagged } }; State = [pscustomobject]@{ Config = $config } }
                    try { Get-PraGuiRetentionProofText } finally { $script:Gui = $null }
                }
            } finally { Remove-Variable PraGuiProofCase -Scope Global -ErrorAction SilentlyContinue }
        }
    }
    AfterAll { Remove-Item -LiteralPath 'Function:\Get-G320GuiText' -ErrorAction SilentlyContinue }
    It 'says that no proof is usable (with the reason), that one is found and covers every mailbox (with its age), or that it does not cover every mailbox, for the objects that the Recover would check, and whether this server needs the proof or reads it only when Exchange Online cannot be reached' {
        $runtime = New-GuiTestRoot
        $batch = New-GuiTestBatch -Runtime $runtime
        $inbox = Join-Path $runtime.Root 'Backups\Inbox'
        $hash = (Get-FileHash -LiteralPath $batch.Path -Algorithm SHA256).Hash.ToLowerInvariant()
        $tagged = @([pscustomobject]@{ ObjectGuid = '00000000-0000-0000-0000-000000000001'; UserPrincipalName = 'a@example.invalid'; IsShared = $false; Retention = [pscustomobject]@{ Enabled = $true } }, [pscustomobject]@{ ObjectGuid = '00000000-0000-0000-0000-000000000002'; UserPrincipalName = 'b@example.invalid'; IsShared = $false; Retention = [pscustomobject]@{ Enabled = $true } })
        $case = @{ Batch = $batch; Backup = (Join-Path $runtime.Root 'Backups'); Inbox = $inbox; Hours = 24; Certificate = $false; Tagged = $tagged }
        (Get-G320GuiText $case) | Should -Match '^No valid retention proof for this batch \(no retention proof of this batch was found\)\. This server cannot sign in to Exchange Online without a person, so the run needs one: run Check with Expected state Retained on the cloud server \(\.\\Invoke-PraRemoteMailbox\.ps1 -Action Check -Batch [0-9a-f]{8} -Expect Retained\), then copy the two proof files \(RetentionProof-\.\.\.json and its \.sha256 file\) to the folder '
        $certificate = @{} + $case; $certificate.Certificate = $true
        (Get-G320GuiText $certificate) | Should -Match '^No valid retention proof for this batch \(no retention proof of this batch was found\)\. This server asks Exchange Online itself \(certificate sign-in\), so a proof matters only if Exchange Online cannot be reached: then run Check'
        $objects = @([pscustomobject]@{ ObjectGuid = '00000000-0000-0000-0000-000000000001'; Upn = 'a@example.invalid'; Verdict = 'Covered' }, [pscustomobject]@{ ObjectGuid = '00000000-0000-0000-0000-000000000002'; Upn = 'b@example.invalid'; Verdict = 'NotCovered' })
        $null = Write-PraRetentionProof -Folder $inbox -BatchId $batch.Id -SourceBackupHash $hash -Environment 'guisynthetic' -Object $objects
        (Get-G320GuiText $case) | Should -Match '^A retention proof was found \(\d+(\.\d)? hours old\) but it does not cover every mailbox: 1 of the 2 object\(s\) of this Recover are not covered in it\. The run cannot use it\. Only the newest proof counts, and an older one never completes it: run Check with Expected state Retained again on the cloud server \(\.\\Invoke-PraRemoteMailbox\.ps1 -Action Check -Batch [0-9a-f]{8} -Expect Retained\), then copy the two proof files to the folder .+ The run leaves out the objects that are already rolled back or were not converted, which only the run can tell: this is an estimate\.$'
        (Get-G320GuiText $certificate) | Should -Match 'It matters only if Exchange Online cannot be reached\. Only the newest proof counts, and an older one never completes it: .* The run leaves out the objects that are already rolled back or were not converted, which only the run can tell: this is an estimate\.$'
        Start-Sleep -Milliseconds 30
        $withoutMailbox = @([pscustomobject]@{ ObjectGuid = '00000000-0000-0000-0000-000000000001'; Upn = 'a@example.invalid'; Verdict = 'Covered' }, [pscustomobject]@{ ObjectGuid = '00000000-0000-0000-0000-000000000002'; Upn = 'b@example.invalid'; Verdict = 'NoMailbox' })
        $null = Write-PraRetentionProof -Folder $inbox -BatchId $batch.Id -SourceBackupHash $hash -Environment 'GuiSynthetic' -Object $withoutMailbox
        (Get-G320GuiText $case) | Should -Match '^A valid retention proof was found: \d+(\.\d)? hours old, 1 of 2 mailbox\(es\) covered, 1 without a mailbox in Exchange Online \(nothing to retain; the run warns about them\)\. This server cannot sign in to Exchange Online without a person: the run uses this proof\.$'
        (Get-G320GuiText $certificate) | Should -Match 'the run reads this proof only when Exchange Online cannot be reached\.$'
        $other = @{} + $case; $other.Tagged = @([pscustomobject]@{ ObjectGuid = '00000000-0000-0000-0000-000000000077'; UserPrincipalName = 'a@example.invalid'; IsShared = $false; Retention = [pscustomobject]@{ Enabled = $true } })
        (Get-G320GuiText $other) | Should -Match 'does not cover every mailbox: 1 of the 1 object\(s\) of this Recover are not covered in it' -Because 'the same objects as the engine judges, found by ObjectGuid'
        $untagged = @{} + $case; $untagged.Tagged = @()
        (Get-G320GuiText $untagged) | Should -Match '^No object of this batch carries the retention tag'
    }
    It 'the newest proof decides in the console too: an older complete proof does not complete a newer one that says NotCovered, and a damaged newest proof says to copy both files again with the folder' {
        $runtime = New-GuiTestRoot
        $batch = New-GuiTestBatch -Runtime $runtime
        $inbox = Join-Path $runtime.Root 'Backups\Inbox'
        $hash = (Get-FileHash -LiteralPath $batch.Path -Algorithm SHA256).Hash.ToLowerInvariant()
        $tagged = @([pscustomobject]@{ ObjectGuid = '00000000-0000-0000-0000-000000000001'; UserPrincipalName = 'a@example.invalid'; IsShared = $false; Retention = [pscustomobject]@{ Enabled = $true } })
        $case = @{ Batch = $batch; Backup = (Join-Path $runtime.Root 'Backups'); Inbox = $inbox; Hours = 24; Certificate = $false; Tagged = $tagged }
        $null = Write-PraRetentionProof -Folder $inbox -BatchId $batch.Id -SourceBackupHash $hash -Environment 'GuiSynthetic' -Object @([pscustomobject]@{ ObjectGuid = '00000000-0000-0000-0000-000000000001'; Upn = 'a@example.invalid'; Verdict = 'Covered' })
        (Get-G320GuiText $case) | Should -Match '^A valid retention proof was found'
        Start-Sleep -Milliseconds 30
        $newest = Write-PraRetentionProof -Folder $inbox -BatchId $batch.Id -SourceBackupHash $hash -Environment 'GuiSynthetic' -Object @([pscustomobject]@{ ObjectGuid = '00000000-0000-0000-0000-000000000001'; Upn = 'a@example.invalid'; Verdict = 'NotCovered' })
        (Get-G320GuiText $case) | Should -Match '^A retention proof was found \(\d+(\.\d)? hours old\) but it does not cover every mailbox: 1 of the 1 object\(s\) of this Recover are not covered in it\. The run cannot use it\. Only the newest proof counts, and an older one never completes it: run Check with Expected state Retained again'
        [IO.File]::AppendAllText($newest.Path, ' ')
        & (Get-Module PRA.Gui) { $script:PraGuiProofCache.Clear() }
        (Get-G320GuiText $case) | Should -Match '^The newest retention proof cannot be used \(.*RetentionProof-.*its SHA-256 does not match its \.sha256 file.*\)\. Copy both files, RetentionProof-\.\.\.json and its \.sha256 file, again from the Backups\\Outbox folder of the cloud server to the folder .*Inbox, together and after the copy has ended\. An older proof never stands in for it\. Delete the damaged copy at .*RetentionProof-.* \(and its \.sha256 file\) so that it is not read again\.$'
    }
    It 'a Retention.PolicyGuid that is not a GUID gives the command that reads the GUID, with the policy name when there is one and the list of policies when there is none' {
        $runtime = New-GuiTestRoot
        $batch = New-GuiTestBatch -Runtime $runtime
        $tagged = @([pscustomobject]@{ ObjectGuid = '00000000-0000-0000-0000-000000000001'; UserPrincipalName = 'a@example.invalid'; IsShared = $false; Retention = [pscustomobject]@{ Enabled = $true } })
        $case = @{ Batch = $batch; Backup = (Join-Path $runtime.Root 'Backups'); Hours = 24; Certificate = $false; Tagged = $tagged; PolicyGuid = 'not-a-guid'; PolicyName = '' }
        (Get-G320GuiText $case) | Should -Match ([regex]::Escape('Connect-IPPSSession; Get-RetentionCompliancePolicy | Format-Table Name,Guid'))
        $named = @{} + $case; $named.PolicyName = 'Policy-Synthetic'
        (Get-G320GuiText $named) | Should -Match ([regex]::Escape('Connect-IPPSSession; (Get-RetentionCompliancePolicy -Identity ''Policy-Synthetic'').Guid'))
    }
    It 'a proof made from another copy of the batch file is not valid for the console either, a lock does not stay in the cache, and a proof that cannot be looked for gets a command to see the folder' {
        $runtime = New-GuiTestRoot
        $batch = New-GuiTestBatch -Runtime $runtime
        $inbox = Join-Path $runtime.Root 'Backups\Inbox'
        $tagged = @([pscustomobject]@{ ObjectGuid = '00000000-0000-0000-0000-000000000001'; UserPrincipalName = 'a@example.invalid'; IsShared = $false; Retention = [pscustomobject]@{ Enabled = $true } })
        $case = @{ Batch = $batch; Backup = (Join-Path $runtime.Root 'Backups'); Inbox = $inbox; Hours = 24; Certificate = $false; Tagged = $tagged }
        $written = Write-PraRetentionProof -Folder $inbox -BatchId $batch.Id -SourceBackupHash 'ffff' -Environment 'GuiSynthetic' -Object @([pscustomobject]@{ ObjectGuid = '00000000-0000-0000-0000-000000000001'; Upn = 'a@example.invalid'; Verdict = 'Covered' })
        (Get-G320GuiText $case) | Should -Match 'another copy of the Convert batch file'
        & (Get-Module PRA.Gui) { $script:PraGuiProofCache.Clear() }
        $locked = [IO.File]::Open($written.Path, [IO.FileMode]::Open, [IO.FileAccess]::ReadWrite, [IO.FileShare]::None)
        try { (Get-G320GuiText $case) | Should -Match 'it cannot be read' } finally { $locked.Dispose() }
        (& (Get-Module PRA.Gui) { $script:PraGuiProofCache.Count }) | Should -Be 0 -Because 'a failure to read says nothing about the file and is not kept'
        (Get-G320GuiText $case) | Should -Match 'another copy of the Convert batch file'
        (& (Get-Module PRA.Gui) { $script:PraGuiProofCache.Count }) | Should -Be 1
        $unreadable = @{} + $case; $unreadable.Hours = 0
        (Get-G320GuiText $unreadable) | Should -Match '^The retention proof cannot be looked for: .* To see what these folders hold, run: Get-ChildItem -LiteralPath ''.*Inbox'' -Filter ''RetentionProof-\*''\. Then choose Refresh in the window\.$'
    }
    It 'keeps for the console every object of a Convert batch that carries the retention tag, with whether it is shared, and judges the objects like the run: a shared mailbox kept on purpose is left out, the others are estimated' {
        $runtime = New-GuiTestRoot
        $id = [guid]::NewGuid().ToString('N')
        $path = Join-Path $runtime.Root ('Backups\Batch-' + $id + '\Convert-fixture.json')
        $records = @(
            @{ ObjectGuid = '00000000-0000-0000-0000-000000000001'; UserPrincipalName = 'tagged@example.invalid'; IsShared = $false; Retention = @{ Enabled = $true; Attribute = 'extensionAttribute1'; Value = 'Converted' } }
            @{ ObjectGuid = '00000000-0000-0000-0000-000000000002'; UserPrincipalName = 'shared@example.invalid'; IsShared = $true; Retention = @{ Enabled = $true; Attribute = 'extensionAttribute1'; Value = 'Converted' } }
            @{ ObjectGuid = '00000000-0000-0000-0000-000000000003'; UserPrincipalName = 'plain@example.invalid'; IsShared = $false; Retention = @{ Enabled = $false } }
            @{ ObjectGuid = '00000000-0000-0000-0000-000000000004'; UserPrincipalName = 'old@example.invalid'; IsShared = $false })
        Write-GuiTestJson $path @{ SchemaVersion = 2; Operation = 'Convert'; Environment = 'GuiSynthetic'; BatchId = $id; SourceBackupHash = ''; Records = $records }
        $rows = @(& (Get-Module PRA.Gui) { param($p) (Get-PraGuiBatchCore -Path $p).Data.TaggedRows } $path)
        $rows.Count | Should -Be 2
        $rows[0].UserPrincipalName | Should -BeExactly 'tagged@example.invalid'
        $rows[1].IsShared | Should -BeTrue
        $inbox = Join-Path $runtime.Root 'Backups\Inbox'
        $hash = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant()
        $null = Write-PraRetentionProof -Folder $inbox -BatchId $id -SourceBackupHash $hash -Environment 'GuiSynthetic' -Object @([pscustomobject]@{ ObjectGuid = '00000000-0000-0000-0000-000000000001'; Upn = 'tagged@example.invalid'; Verdict = 'Covered' })
        $case = @{ Batch = @{ Id = $id; Path = $path }; Backup = (Join-Path $runtime.Root 'Backups'); Hours = 24; Certificate = $false; Tagged = $rows; KeepShared = $false }
        (Get-G320GuiText $case) | Should -Match '^A retention proof was found \(\d+(\.\d)? hours old\) but it does not cover every mailbox: 1 of the 2 object\(s\) of this Recover are not covered in it\.'
        $case.KeepShared = $true
        (Get-G320GuiText $case) | Should -Match '^A valid retention proof was found: \d+(\.\d)? hours old, 1 of 1 mailbox\(es\) covered\.' -Because 'the shared mailbox that the Recover keeps is not checked'
    }
    It 'shows the proof line only for the AD part of a Recover, in the window, and a proof file in a batch folder is a side file there, by the common function' {
        $xaml = Get-Content -LiteralPath (Join-Path $script:GuiProjectRoot 'module\PRA.Gui.xaml') -Raw
        $xaml | Should -Match 'x:Name="RetentionProofText"'
        $text = Get-Content -LiteralPath $script:GuiModule -Raw
        $text | Should -Match "Test-GuiOrdinal \(Get-PraGuiPhase\) 'AD' -IgnoreCase\)\) \{ Get-PraGuiRetentionProofText \}"
        (& (Get-Module PRA.Common) { Test-PraBatchSideFile 'RetentionProof-abcdef01-20261119101010000.json' }) | Should -BeTrue
        (& (Get-Module PRA.Common) { Test-PraBatchSideFile 'retentionproof-abcdef01-20261119101010000.json.sha256' }) | Should -BeTrue
        (& (Get-Module PRA.Common) { Test-PraBatchSideFile 'Convert-x.json' }) | Should -BeFalse
        (& (Get-Module PRA.Gui) { $null -eq (Get-Command Test-PraGuiBatchSideFile -ErrorAction SilentlyContinue) }) | Should -BeTrue
    }
}