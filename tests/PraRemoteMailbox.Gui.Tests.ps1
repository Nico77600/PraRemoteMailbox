#Requires -Version 5.1
# Synthetic only: no AD, Exchange, Graph, network or production configuration.
BeforeAll {
    $script:GuiProjectRoot=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
    $script:GuiModule=Join-Path $script:GuiProjectRoot 'module\PRA.Gui.psm1'
    $script:GuiCommon=Join-Path $script:GuiProjectRoot 'module\PRA.Common.psm1'
    Import-Module $script:GuiCommon -Force
    Import-Module $script:GuiModule -Force
    $script:GuiEvidence=Join-Path $PSScriptRoot ('evidence\gui-'+[guid]::NewGuid().ToString('N'))
    $null=New-Item -ItemType Directory -Path $script:GuiEvidence -Force
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
        $command.FilePath | Should -Match '\\WindowsPowerShell\\v1.0\\powershell.exe$'
        $command.Tokens | Should -Contain '-NoProfile'
        $command.Tokens | Should -Contain '-NonInteractive'
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
    It 'removes Core-only module paths and retains native modules' {
        $paths=Get-PraGuiNativeModulePath
        $paths | Should -Match '\\WindowsPowerShell\\v1.0\\Modules'
        $paths | Should -Match '\\WindowsPowerShell\\Modules'
        $paths | Should -Not -Match '(?i)\\PowerShell\\7(?:\\|;)'
        $paths | Should -Not -Match '(?i)\\Documents\\PowerShell\\Modules'
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
        $state.Batches[0].Status | Should -Match 'INVALIDE'
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
        $proof=[IO.File]::ReadAllText($convert.Proof)|ConvertFrom-Json
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
        $different=[IO.File]::ReadAllText($copy)|ConvertFrom-Json
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
        $proof=[IO.File]::ReadAllText($convert.Proof)|ConvertFrom-Json
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
                $result.edition | Should -BeExactly 'Desktop'
                $result.version | Should -Match '^5\.1\.'
                $result.apartment | Should -BeExactly 'STA'
            } finally { $child.Process.Dispose() }
        }
    }
    It 'copies smart apostrophes as literal data and executes Display safely in both PowerShell editions' {
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
        $engines=@((Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'),(Get-Command pwsh.exe -ErrorAction Stop).Source)
        foreach($engine in $engines){
            $eventFile=Join-Path $runtime.Root ([guid]::NewGuid().ToString('N')+'.events.jsonl')
            $info=New-Object Diagnostics.ProcessStartInfo
            $info.FileName=$engine
            $info.Arguments=(@(@('-NoProfile','-NonInteractive','-STA','-File',$driver,'-CommandFile',$commandFile)|ForEach-Object{ConvertTo-PraGuiNativeArgument $_})-join ' ')
            $info.UseShellExecute=$false;$info.CreateNoWindow=$true;$info.RedirectStandardOutput=$true;$info.RedirectStandardError=$true
            $info.EnvironmentVariables['PSModulePath']=Get-PraGuiNativeModulePath
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

Describe 'Actual WPF construction, event bindings and synthetic UI workflow in both engines' {
    It 'builds the real XAML and invokes bound handlers under STA in Desktop and Core without live imports' {
        $runtime=New-GuiTestRoot
        Write-GuiTestFile (Join-Path $runtime.Root 'Invoke-PraRemoteMailbox.ps1') @'
param($Action,$Mode,$ConfigPath,$Scope,$Phase,$Identity,$MaxObjects,$SearchBase,$CsvPath,[switch]$Force)
$ErrorActionPreference='Stop'
Start-Sleep -Milliseconds 600
if($Mode -eq 'Apply'){
 if(-not $Force){throw 'Synthetic Apply requires GUI-confirmed Force'}
 [IO.File]::WriteAllText((Join-Path $PSScriptRoot 'synthetic-apply-marker.txt'),'Apply confirmed')
}
$status=if($Mode -eq 'Apply'){'Success'}else{'Planned'}
if($SearchBase){[IO.File]::WriteAllText((Join-Path $PSScriptRoot 'selected-ou.txt'),$SearchBase)}
if($CsvPath){[IO.File]::WriteAllText((Join-Path $PSScriptRoot 'selected-csv.txt'),$CsvPath)}
$plannedCount=if($Mode -eq 'Apply'){0}else{1};$successCount=if($Mode -eq 'Apply'){1}else{0}
$row=[pscustomobject]@{ObjectGuid='11111111-1111-1111-1111-111111111111';SamAccountName='synthetic';UserPrincipalName='synthetic@example.invalid';Action=$Action;IsShared=$false;ADApplied=$false;ADVerified=$false;CloudStatus='N/A';FinalStatus='Planned';Detail='Synthetic only';BackupPath='';Warnings=''}
$row.FinalStatus=$status
$csv=Join-Path $PSScriptRoot 'synthetic.csv';$row|Export-Csv -LiteralPath $csv -Delimiter ';' -NoTypeInformation -Encoding UTF8
$phaseValue=if($Action -eq 'Finalize'){'Finalize'}elseif($Action -eq 'Check'){'Cloud'}else{$Phase}
$events=@(
 @{kind='start';title='Synthetic run';action=$Action;mode=$Mode;phase=$phaseValue}
 @{kind='step';index=1;total=1;title='Synthetic plan'}
 @{kind='item';status='Info';text='Synthetic target';identity=$Identity}
 @{kind='summary';title='Synthetic summary';status='Ok';values=@{Planned=$plannedCount;Success=$successCount}}
 @{kind='result';status=$status;exitCode=0;action=$Action;mode=$Mode;phase=$phaseValue;success=$successCount;error=0;pending=0;skipped=0;planned=$plannedCount;total=1;issues=@();nextSteps=@('Synthetic handoff');batchId='12345678';csvReport=$csv;logFile='';htmlReport='';backupFiles=@();stateFiles=@()}
)
$lines=@($events|ForEach-Object{$_|ConvertTo-Json -Depth 6 -Compress})-join "`n"
[IO.File]::WriteAllText($env:PRA_EVENT_FILE,$lines+"`n",(New-Object Text.UTF8Encoding($false)))
exit 0
'@
        $probe=Join-Path $runtime.Root 'wpf-probe.ps1'
        Write-GuiTestFile (Join-Path $runtime.Root 'module\PRA.Gui.Directory.ps1') @'
param($ConfigPath,$ResultPath)
Start-Sleep -Milliseconds 400
[IO.File]::WriteAllText($ResultPath,(@{Success=$true;Server='dc.synthetic.invalid';Units=@(@{Name='Selected';DistinguishedName='OU=Selected,DC=example,DC=invalid'})}|ConvertTo-Json -Depth 4))
exit 0
'@
        Write-GuiTestFile $probe @'
param($Common,$Gui,$Root,$Config)
$ErrorActionPreference='Stop'
Import-Module $Common -Force
Import-Module $Gui -Force
$marker=Join-Path $Root 'synthetic-apply-marker.txt'
if(Test-Path -LiteralPath $marker){Remove-Item -LiteralPath $marker -Force}
function Wait-SyntheticGuiRun($Window){
 $deadline=[datetime]::UtcNow.AddSeconds(20)
 while($Window.Run -and [datetime]::UtcNow -lt $deadline){
  $frame=New-Object Windows.Threading.DispatcherFrame
  $pump=New-Object Windows.Threading.DispatcherTimer
  $pump.Interval=[timespan]::FromMilliseconds(50)
  $pump.Tag=$frame
  $pump.Add_Tick({param($s,$e)$s.Tag.Continue=$false;$s.Stop()})
  $pump.Start();[Windows.Threading.Dispatcher]::PushFrame($frame)
 }
 if($Window.Run){throw 'Synthetic child timed out'}
}
function Pump-SyntheticLayout {
 $frame=New-Object Windows.Threading.DispatcherFrame
 $pump=New-Object Windows.Threading.DispatcherTimer
 $pump.Interval=[timespan]::FromMilliseconds(50);$pump.Tag=$frame
 $pump.Add_Tick({param($s)$s.Tag.Continue=$false;$s.Stop()})
 $pump.Start();[Windows.Threading.Dispatcher]::PushFrame($frame)
}
$g=New-PraGuiWindow -Root $Root -ConfigPath $Config -Version 'Synthetic'
if($g.Run -or $g.Pending -or $g.Controls.Apply.IsEnabled){throw 'Construction started/authorized an operation'}
if($g.Controls.PhaseChoice.SelectedItem.Content -ne 'AD'){throw 'Config default phase not used'}
if($g.HandlerNames.Count -lt 25){throw 'Missing handlers'}
if(Get-Module ActiveDirectory,ExchangeOnlineManagement,Microsoft.Graph.Authentication){throw 'Live module imported'}
if(-not $g.Form.Background){throw 'Outer Window margin has no theme background'}
$area=[Windows.SystemParameters]::WorkArea
if($g.Form.Width -gt $area.Width -or $g.Form.Height -gt $area.Height -or $g.Form.MinWidth -gt $area.Width -or $g.Form.MinHeight -gt $area.Height){throw 'Window exceeds actual work area'}
$g.Form.Show()
try {
 $g.Controls.IdentityText.Text='synthetic@example.invalid'
 $g.Controls.SourceChoice.SelectedIndex=1
 if($g.Controls.SourcePanel.Visibility -ne 'Visible' -or $g.Controls.IdentityText.Visibility -ne 'Collapsed' -or $g.Controls.Preview.IsEnabled){throw 'OU requires a DN and no stale identity'}
 $g.Controls.OuText.Text='OU=Selected,DC=example,DC=invalid'
 if(-not $g.Controls.Preview.IsEnabled -or $g.Controls.CommandText.Text -notmatch 'SearchBase'){throw 'OU command not selected'}
 $selectTimer=New-Object Windows.Threading.DispatcherTimer
 $selectTimer.Interval=[timespan]::FromMilliseconds(100)
 $selectTimer.Add_Tick({
  foreach($window in @([Windows.Application]::Current.Windows)){
   if($window.Title -eq 'Choisir une OU'){
    $window.FindName('Units').SelectedIndex=0
    $window.FindName('Select').RaiseEvent((New-Object Windows.RoutedEventArgs ([Windows.Controls.Button]::ClickEvent)))
   }
  }
 })
 $selectTimer.Start()
 try {
  $g.Controls.ChooseOu.RaiseEvent((New-Object Windows.RoutedEventArgs ([Windows.Controls.Button]::ClickEvent)))
  if(-not $g.OuLookup -or $g.Controls.Preview.IsEnabled){throw 'OU browser did not start asynchronously with operations locked'}
  $deadline=[datetime]::UtcNow.AddSeconds(15)
  while($g.OuLookup -and [datetime]::UtcNow -lt $deadline){Pump-SyntheticLayout}
  if($g.OuLookup -or $g.Controls.OuText.Text -ne 'OU=Selected,DC=example,DC=invalid'){throw 'OU selection dialog failed'}
  if(Get-Module ActiveDirectory,PRA.Directory){throw 'OU browser loaded directory modules into UI'}
 } finally {$selectTimer.Stop()}
 $g.Controls.SourceChoice.SelectedIndex=2
 $selectionCsv=Join-Path $Root 'selected-list.csv'
 [IO.File]::WriteAllText($selectionCsv,"Identity`r`nsynthetic@example.invalid")
 $g.Controls.CsvText.Text=$selectionCsv
 if(-not $g.Controls.Preview.IsEnabled -or $g.Controls.CommandText.Text -notmatch 'CsvPath'){throw 'CSV chooser did not validate the source'}
 $g.Controls.SourceChoice.SelectedIndex=0
 $g.Controls.ActionChoice.SelectedIndex=3
 if($g.Controls.Apply.IsEnabled -or $g.Controls.PhaseChoice.IsEnabled){throw 'Check UI contract'}
 if($g.Controls.SourcePanel.Visibility -ne 'Collapsed'){throw 'Source exposed in Check'}
 if($g.Controls.PhaseChoice.SelectedItem.Content -ne 'Cloud'){throw 'Check still displays an AD/Both phase'}
 $request=& (Get-Module PRA.Gui) {Get-PraGuiWindowRequest}
 if($request.Phase -ne 'Cloud'){throw 'Check native request mismatch'}
 $g.Controls.ActionChoice.SelectedIndex=0
 if($g.Controls.PhaseChoice.SelectedItem.Content -ne 'AD'){throw 'Previous execution phase was not restored'}
 $g.Controls.PhaseChoice.SelectedIndex=0
 $g.Controls.ActionChoice.SelectedIndex=3
 $g.Controls.ActionChoice.SelectedIndex=0
 if($g.Controls.PhaseChoice.SelectedItem.Content -ne 'Both'){throw 'Both phase was forgotten'}
 $g.Controls.PhaseChoice.SelectedIndex=2
 $g.Controls.BatchText.Text='01234567'
 $g.Controls.ActionChoice.SelectedIndex=2
 if($g.Controls.PhaseChoice.SelectedItem.Content -ne 'AD' -or $g.Controls.PhaseChoice.IsEnabled){throw 'Finalize must visibly be AD-only'}
 $request=& (Get-Module PRA.Gui) {Get-PraGuiWindowRequest}
 if($request.Phase -ne 'Finalize'){throw 'Finalize native request mismatch'}
 $command=Get-PraGuiCommand $Root $Config $request
 if($command.Tokens -contains '-Phase'){throw 'Finalize must not receive a CLI Phase parameter'}
 $g.Controls.ActionChoice.SelectedIndex=1
 if($g.Controls.PhaseChoice.SelectedItem.Content -ne 'Cloud'){throw 'Recover execution phase was forgotten'}
 if($g.Controls.OperationGuide.Text -notmatch 'si une restauration finale AD reste à faire' -or $g.Controls.OperationGuide.Text -notmatch 'aucune écriture AD'){throw 'Recover Cloud handoff is not conditional or incorrectly allows AD writes'}
 $overview=[IO.File]::ReadAllText((Join-Path (Split-Path $Gui -Parent) 'PRA.Gui.xaml'))
 if($overview -notmatch 'Finalize-… si une restauration finale AD reste à faire' -or $overview -notmatch "il n'écrit jamais dans AD"){throw 'Overview handoff guidance is inaccurate'}
 $g.Controls.ActionChoice.SelectedIndex=0
 $g.Controls.PhaseChoice.SelectedIndex=1
 $g.Controls.BatchText.Clear()
 $g.Controls.Preview.RaiseEvent((New-Object Windows.RoutedEventArgs ([Windows.Controls.Button]::ClickEvent)))
 if(-not $g.Run){throw 'Preview handler did not start child'}
 $g.Form.Close()
 if(-not $g.Form.IsVisible){throw 'Closing during atomic action was not prevented'}
 Wait-SyntheticGuiRun $g
 if(-not $g.Pending){throw ('Preview not authorized: '+$g.Controls.ResultText.Text+' '+$g.Controls.ValidationText.Text)}
 if($g.Controls.PreviewGrid.Items.Count -ne 1){throw 'CSV table not populated'}
 $g.Controls.SourceChoice.SelectedIndex=2
 if($g.Pending -or $g.Controls.Apply.IsEnabled){throw 'Source switch kept an old Preview'}
 $g.Controls.Preview.RaiseEvent((New-Object Windows.RoutedEventArgs ([Windows.Controls.Button]::ClickEvent)))
 Wait-SyntheticGuiRun $g
 if(-not (Test-Path -LiteralPath (Join-Path $Root 'selected-csv.txt'))){throw 'Selected CSV did not reach Desktop child'}
 [IO.File]::AppendAllText($selectionCsv,"`r`nother@example.invalid")
 $g.Controls.ConfirmationText.Text='CONVERT'
 if($g.Controls.Apply.IsEnabled -or $g.Pending){throw 'Changed selected CSV permitted Apply'}
 $g.Controls.SourceChoice.SelectedIndex=0
 $g.Controls.Preview.RaiseEvent((New-Object Windows.RoutedEventArgs ([Windows.Controls.Button]::ClickEvent)))
 Wait-SyntheticGuiRun $g
 $g.Controls.ConfirmationText.Text='convert'
 if($g.Controls.Apply.IsEnabled){throw 'Case-insensitive confirmation accepted'}
 $g.Controls.ConfirmationText.Text='CONVERT'
 if(-not $g.Controls.Apply.IsEnabled){throw 'Exact confirmation did not enable Apply'}
 [IO.File]::AppendAllText($Config,"`n# Changed input")
 $g.Controls.Apply.RaiseEvent((New-Object Windows.RoutedEventArgs ([Windows.Controls.Button]::ClickEvent)))
 if($g.Run -or $g.Pending){throw 'Changed configuration permitted Apply'}
 $g.Controls.Reload.RaiseEvent((New-Object Windows.RoutedEventArgs ([Windows.Controls.Button]::ClickEvent)))
 $g.Controls.ScopeChoice.SelectedIndex=2
 if($g.Pending -or $g.Controls.Apply.IsEnabled){throw 'Selection change preserved authorization'}
 $g.Controls.Preview.RaiseEvent((New-Object Windows.RoutedEventArgs ([Windows.Controls.Button]::ClickEvent)))
 Wait-SyntheticGuiRun $g
 $g.Controls.ConfirmationText.Text='CONVERT'
 if(-not $g.Controls.Apply.IsEnabled){throw 'Fresh Preview did not reauthorize Apply'}
 $g.Controls.Apply.RaiseEvent((New-Object Windows.RoutedEventArgs ([Windows.Controls.Button]::ClickEvent)))
 if(-not $g.Run -or $g.Run.Request.Mode -ne 'Apply'){throw 'Apply did not start the confirmed child'}
 if($g.Controls.CommandText.Text -notmatch "'Apply'" -or $g.Controls.CommandText.Text -notmatch "'-Force'"){throw 'Displayed command does not match active Apply'}
 Wait-SyntheticGuiRun $g
 if(-not (Test-Path -LiteralPath (Join-Path $Root 'synthetic-apply-marker.txt'))){throw 'Confirmed child did not receive Force'}
 if($g.Pending -or $g.Controls.Apply.IsEnabled){throw 'Apply incorrectly preserved Preview authorization'}
 if([Windows.Application].GetProperty('ThemeMode') -and -not $g.Theme.Fluent){throw 'Native Fluent theme missing'}
 if($g.Theme.Fluent){
  foreach($name in @('PhaseChoice','IdentityText','PreviewGrid','Preview')){
   if(-not $g.Controls[$name].Style.BasedOn){throw ('Native Fluent template masked: '+$name)}
  }
  $g.Controls.Pages.SelectedIndex=1
  $g.Controls.ActionChoice.SelectedIndex=1
  & (Get-Module PRA.Gui) {param($window) Set-PraGuiWindowBounds -Window $window -WorkArea ([Windows.Rect]::new(0,0,1280,720))} $g.Form
  Pump-SyntheticLayout
  $g.Form.UpdateLayout()
  if($g.Form.ActualWidth -gt 1280 -or $g.Form.ActualHeight -gt 720){throw 'Constrained work-area clamp failed'}
  if($g.Controls.BatchPanel.Visibility -ne 'Visible'){throw 'Recover batch controls missing'}
  $scroll=$g.Controls.OperationsScroll
  if($scroll.VerticalScrollBarVisibility -ne 'Auto' -or $scroll.ScrollableHeight -le 0){throw 'Recover controls are clipped instead of scrollable'}
  foreach($name in @('Preview','Apply','PreviewGrid')){
   $control=$g.Controls[$name];$control.BringIntoView();Pump-SyntheticLayout;$g.Form.UpdateLayout()
   $bounds=$control.TransformToAncestor($scroll).TransformBounds([Windows.Rect]::new(0,0,$control.ActualWidth,$control.ActualHeight))
   if($bounds.Top -lt -1 -or $bounds.Bottom -gt $scroll.ActualHeight+1){throw ('Constrained control is not reachable: '+$name)}
  }
  if($g.Run){throw 'Layout/selection changes launched an operation'}
 }
 [Console]::WriteLine('WPF-SMOKE-PASS '+$PSVersionTable.PSEdition)
} finally {$g.Form.Close()}
'@
        $engines=@((Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'))
        $core=Get-Command pwsh.exe -ErrorAction SilentlyContinue
        if(-not $core){throw 'Dual-engine GUI validation requires the already installed pwsh.exe.'}
        $engines+=$core.Source
        foreach($engine in $engines) {
            $tokens=@('-NoProfile','-NonInteractive','-STA','-File',$probe,'-Common',$script:GuiCommon,'-Gui',$script:GuiModule,'-Root',$runtime.Root,'-Config',$runtime.Config)
            $info=New-Object Diagnostics.ProcessStartInfo
            $info.FileName=$engine;$info.Arguments=(@($tokens|ForEach-Object{ConvertTo-PraGuiNativeArgument $_})-join ' ')
            $info.UseShellExecute=$false;$info.CreateNoWindow=$true;$info.RedirectStandardOutput=$true;$info.RedirectStandardError=$true
            $info.EnvironmentVariables['PSModulePath']=Get-PraGuiNativeModulePath
            $process=[Diagnostics.Process]::Start($info)
            $out=$process.StandardOutput.ReadToEndAsync();$err=$process.StandardError.ReadToEndAsync()
            try {
                $process.WaitForExit(40000) | Should -BeTrue
                $process.ExitCode | Should -Be 0 -Because ($out.Result+$err.Result)
                $out.Result | Should -Match 'WPF-SMOKE-PASS'
            } finally { $process.Dispose() }
        }
    }
}

AfterAll {
    if($script:GuiEvidence -and (Test-Path -LiteralPath $script:GuiEvidence)) {
        Remove-Item -LiteralPath $script:GuiEvidence -Recurse -Force
    }
}
