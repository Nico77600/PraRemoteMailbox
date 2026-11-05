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
 $c.ConfirmBox.Text='CONVERTX'
 if($c.BtnNext.IsEnabled){throw 'A wrong confirmation word enabled Run'}
 $c.ConfirmBox.Text='convert'
 if(-not $c.BtnNext.IsEnabled){throw 'Lowercase confirmation did not enable Run'}
 $c.ConfirmBox.Text=' CoNvErT '
 if(-not $c.BtnNext.IsEnabled){throw 'Mixed-case confirmation with spaces did not enable Run'}
 $c.F_Identity.Text='other@example.invalid'; Pump
 if($g.Pending -or $c.BtnNext.IsEnabled -or $c.ConfirmBox.Text){throw 'Changing the object source preserved the authorization'}
 $c.F_Identity.Text='synthetic@example.invalid'; Pump
 Click $g 'BtnPreview'; Wait-Run $g
 $c.ConfirmBox.Text='CONVERT'
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
 if(@($g.NextRows).Count -lt 3 -or ($c.NextSteps.Items[0].Text -notmatch 'one file')){throw 'Next steps instructions are not the one-file instructions'}
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
        $result.Lights.Count | Should -Be 5
        ($result.Lights | Where-Object Name -eq 'Sign-in: Certificate').Status | Should -BeExactly 'Fail'
        ($result.Lights | Where-Object Name -eq 'Entra Connect sync').Status | Should -BeExactly 'NA' -Because 'a synchronisation that is not used is neutral grey, not a green check'
        $result.Role | Should -BeIn @('Both','AD','Cloud','None')
        ($result.Lights | Where-Object Name -eq 'Sign-in: Certificate').Detail | Should -Match 'CurrentUser\\My' -Because 'the sign-in of the engine reads the store of the account that runs the tool'
        $result.Cloud | Should -BeFalse -Because 'a missing certificate removes the cloud capability'
        $wam=& (Get-Module PRA.Gui) { Get-PraGuiPrerequisite -Signin Wam -SyncEnabled $false }
        ($wam.Lights | Where-Object Name -like 'Sign-in*').Name | Should -Be 'Sign-in: Interactive (WAM)'
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

Describe 'Console 3.0.0 lot 2b - phase, replication option, identity preview, counters, backup, journey, Back after Apply' {
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

Describe 'Console 3.0.0 lot 2c - packages: configured Environment, Finalize package in the Inbox, checks off the window thread' {
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

AfterAll {
    if($script:GuiEvidence -and (Test-Path -LiteralPath $script:GuiEvidence)) {
        # A child of a test may still be closing its files for a moment: bounded retries, then the error is raised (never swallowed).
        for($attempt=1; $attempt -le 20; $attempt++) {
            try { Remove-Item -LiteralPath $script:GuiEvidence -Recurse -Force -ErrorAction Stop; break }
            catch { if($attempt -eq 20) { throw }; Start-Sleep -Milliseconds 500 }
        }
    }
}
