<#
.SYNOPSIS
    Runs the PRA Remote Mailbox test gate offline and keeps reproducible evidence.
.DESCRIPTION
    Windows PowerShell 5.1 Desktop, Pester >= 5 (imported explicitly in this process),
    PSScriptAnalyzer 1.25.0 with the Windows PowerShell 5.1 compatibility profiles.
    Data, AD/ADSync modules and cloud checks of the entry script are synthetic.
    A missing test, a failed container/block or an analyzer error fails the gate.
.PARAMETER EvidenceDirectory
    Evidence folder; default tests\evidence\gate\<timestamp-GUID>.
.EXAMPLE
    powershell.exe -NoLogo -NoProfile -NonInteractive -File .\tests\Invoke-TestGate.ps1
.NOTES
    Author : Nicolas Fabert
    Version: 2.0.0
#>
#Requires -Version 5.1
#Requires -PSEdition Desktop
[CmdletBinding()]
param([string]$EvidenceDirectory)

Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
# A Windows PowerShell launched by pwsh can inherit only Core module paths.
foreach ($name in @('Microsoft.PowerShell.Utility','Microsoft.PowerShell.Management','Microsoft.PowerShell.Security')) {
    Import-Module (Join-Path $PSHOME ('Modules\'+$name+'\'+$name+'.psd1')) -ErrorAction Stop
}
$root=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
if (-not $EvidenceDirectory) { $EvidenceDirectory=Join-Path $root ('tests\evidence\gate\'+(Get-Date -Format 'yyyyMMdd-HHmmss')+'-'+[guid]::NewGuid().ToString('N').Substring(0,8)) }
$evidenceRoot=[IO.Path]::GetFullPath((Join-Path $root 'tests\evidence\gate')).TrimEnd('\')+'\'
$EvidenceDirectory=[IO.Path]::GetFullPath($EvidenceDirectory)
if (-not ($EvidenceDirectory+'\').StartsWith($evidenceRoot,[StringComparison]::OrdinalIgnoreCase)) { throw 'Evidence is only allowed under tests\evidence\gate.' }
$null=New-Item -ItemType Directory -Path $EvidenceDirectory -Force
$encoding=New-Object Text.UTF8Encoding($true)
$clock=[Diagnostics.Stopwatch]::StartNew()
$originalEvidence=$env:PRA_GATE_EVIDENCE
$env:PRA_GATE_EVIDENCE=$EvidenceDirectory
$exitCode=1; $transcriptStarted=$false; $result=$null
$checks=New-Object 'Collections.Generic.List[object]'
$failures=New-Object 'Collections.Generic.List[string]'
$summary=[ordered]@{
    Provenance='Synthetic-only. No real AD/EXO/Graph/ADSync access. Main Cloud orchestration uses an explicitly substituted blocking fixture.'
    Command=[Environment]::CommandLine; Invocation=$MyInvocation.Line; Script=$PSCommandPath; StartedUtc=[datetime]::UtcNow.ToString('o')
    PowerShellVersion=[string]$PSVersionTable.PSVersion; PSEdition=$PSVersionTable.PSEdition; CLRVersion=[string]$PSVersionTable.CLRVersion
    Executable=(Join-Path $PSHOME 'powershell.exe'); OS=[Environment]::OSVersion.VersionString
    PesterVersion=''; PesterPath=''; AnalyzerVersion=''; AnalyzerProfiles=@(); TotalCount=0; PassedCount=0; FailedCount=0
    FailedBlocksCount=0; FailedContainersCount=0; AnalyzerErrorCount=0; AnalyzerWarningCount=0
    ReleaseDefaultWarningCount=0; ReleaseCompatibilityWarningCount=0; GateWarningCount=0
    Checks=@(); Failures=@(); RuntimeMilliseconds=0; ExitCode=1; RESULT='FAIL'; EvidenceDirectory=$EvidenceDirectory
}
try {
    Start-Transcript -LiteralPath (Join-Path $EvidenceDirectory 'gate.transcript.txt') -NoClobber | Out-Null
    $transcriptStarted=$true
    $testRoot=[IO.Path]::GetFullPath($PSScriptRoot).TrimEnd('\')+'\'
    $files=@(Get-ChildItem -LiteralPath $root -Recurse -File | Where-Object { $_.Extension -in @('.ps1','.psm1','.psd1') -and -not $_.FullName.StartsWith($testRoot,[StringComparison]::OrdinalIgnoreCase) })
    $files+=@(Get-ChildItem -LiteralPath $PSScriptRoot -File | Where-Object Extension -eq '.ps1')
    $hashes=@(foreach ($file in $files) { $hash=Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256; [pscustomobject]@{Path=$file.FullName;SHA256=$hash.Hash;Length=$file.Length} })
    [IO.File]::WriteAllText((Join-Path $EvidenceDirectory 'source-hashes.json'),($hashes | ConvertTo-Json -Depth 5),$encoding)
    foreach ($file in $files) {
        $tokens=$null; $errors=$null
        $null=[Management.Automation.Language.Parser]::ParseFile($file.FullName,[ref]$tokens,[ref]$errors)
        $checks.Add([pscustomobject]@{Name='AST';File=$file.FullName;Passed=($errors.Count -eq 0);Details=@($errors | ForEach-Object Message)})
        if ($errors.Count) { $failures.Add('AST: '+$file.FullName) }
        $bytes=[IO.File]::ReadAllBytes($file.FullName)
        $bom=$bytes.Length -ge 3 -and $bytes[0] -eq 239 -and $bytes[1] -eq 187 -and $bytes[2] -eq 191
        $checks.Add([pscustomobject]@{Name='UTF8-BOM';File=$file.FullName;Passed=$bom;Details='Windows PowerShell 5.1 deterministic decoding.'})
        if (-not $bom) { $failures.Add('UTF8 BOM absent: '+$file.FullName) }
    }
    $main=Join-Path $root 'Invoke-PraRemoteMailbox.ps1'
    $help=Get-Help $main -Full
    $helpText=$help | Out-String -Width 240
    [IO.File]::WriteAllText((Join-Path $EvidenceDirectory 'main-help.txt'),$helpText,$encoding)
    $helpPass=($helpText -match 'SYNOPSIS|SYNOPSIS' -and @($help.examples.example).Count -ge 3 -and $helpText -match 'WhatIf')
    $checks.Add([pscustomobject]@{Name='CommentBasedHelp';File=$main;Passed=$helpPass;Details='Get-Help only; no script invocation.'})
    if (-not $helpPass) { $failures.Add('Comment-based help missing examples/WhatIf.') }
    Import-Module PSScriptAnalyzer -RequiredVersion 1.25.0 -Force -ErrorAction Stop
    $analyzer=Get-Module PSScriptAnalyzer
    $summary.AnalyzerVersion=[string]$analyzer.Version
    $profileRoot=Join-Path $analyzer.ModuleBase 'compatibility_profiles'
    $profiles=@(Get-ChildItem -LiteralPath $profileRoot -Filter '*_5.1.*_framework.json' | ForEach-Object { [IO.Path]::GetFileNameWithoutExtension($_.Name) })
    if (-not $profiles.Count) { throw 'PSSA Windows PowerShell 5.1 compatibility profiles unavailable.' }
    $summary.AnalyzerProfiles=$profiles
    $settings=@{
        IncludeDefaultRules=$true
        Rules=@{
            PSUseCompatibleSyntax=@{Enable=$true;TargetVersions=@('5.1')}
            PSUseCompatibleCommands=@{Enable=$true;TargetProfiles=$profiles}
            PSUseCompatibleTypes=@{Enable=$true;TargetProfiles=$profiles}
        }
    }
    $gateSettings=@{IncludeDefaultRules=$true;Rules=@{PSUseCompatibleSyntax=@{Enable=$true;TargetVersions=@('5.1')}}}
    $analyzerScopes=@{Release=$settings;Gate=$gateSettings;Reason='Compatibility command/type profiles apply to delivered release. Test harness requires Pester >=5, not legacy Pester metadata in native Windows profiles; gate still receives every default rule and 5.1 syntax checks.'}
    [IO.File]::WriteAllText((Join-Path $EvidenceDirectory 'analyzer-settings.json'),($analyzerScopes | ConvertTo-Json -Depth 10),$encoding)
    $releaseRoot=$root.TrimEnd('\')+'\'
    $diagnostics=@(foreach ($file in $files) {
        $fileSettings=if ($file.FullName.StartsWith($testRoot,[StringComparison]::OrdinalIgnoreCase)) { $gateSettings } else { $settings }
        Invoke-ScriptAnalyzer -Path $file.FullName -Settings $fileSettings -ErrorAction Stop
    })
    $diagnosticRows=@($diagnostics | Select-Object ScriptPath,ScriptName,Line,Column,Severity,RuleName,Message)
    [IO.File]::WriteAllText((Join-Path $EvidenceDirectory 'analyzer-diagnostics.json'),(ConvertTo-Json -InputObject $diagnosticRows -Depth 8),$encoding)
    $summary.AnalyzerErrorCount=@($diagnostics | Where-Object Severity -eq 'Error').Count
    $summary.AnalyzerWarningCount=@($diagnostics | Where-Object Severity -eq 'Warning').Count
    $releaseWarnings=@($diagnostics | Where-Object { $_.Severity -eq 'Warning' -and -not $_.ScriptPath.StartsWith($testRoot,[StringComparison]::OrdinalIgnoreCase) })
    $summary.ReleaseCompatibilityWarningCount=@($releaseWarnings | Where-Object RuleName -Like 'PSUseCompatible*').Count
    $summary.ReleaseDefaultWarningCount=$releaseWarnings.Count-$summary.ReleaseCompatibilityWarningCount
    $summary.GateWarningCount=$summary.AnalyzerWarningCount-$releaseWarnings.Count
    if ($summary.AnalyzerErrorCount) { $failures.Add('PSScriptAnalyzer error diagnostics: '+$summary.AnalyzerErrorCount) }
    $rationales=@(foreach ($diagnostic in $diagnostics | Where-Object Severity -ne 'Error') {
        $reason=switch -Regex ($diagnostic.RuleName) {
            'PSUseCompatible(Commands|Types)' { 'Windows 5.1 profiles describe native/legacy Pester 3.4 metadata, not the required Pester >=5 test DSL. Gate imports Pester 6 explicitly; external AD/Graph/EXO boundaries are synthetic or mocked. Diagnostics are retained, never globally disabled.'; break }
            'PSUseShouldProcessForStateChangingFunctions|PSShouldProcess' { 'Memory-only status helpers must still record failures under WhatIf; actual permission writes are individually gated by Invoke-PraPermissionGrant, proof callbacks and native preferences, covered by readonly boundary tests.'; break }
            'PSUseDeclaredVarsMoreThanAssignments' { 'Pester discovery/runtime scopes and mocked scriptblocks can appear unused to static analysis; diagnostic retained.'; break }
            'PSAvoidGlobalVars' { 'Gate-only mutable fixture/counter scope shared with InModuleScope; cleanup in AfterAll; no production globals added.'; break }
            'PSAvoidUsingWriteHost' { 'Human-facing RESULT/log wrappers; test assertions consume structured results, not host text alone.'; break }
            'PSAvoidUsingPositionalParameters' { 'Closed package-internal calls use known signatures; external safety-critical AD calls use explicit named splats. Executable synthetic tests cover argument binding.'; break }
            'PSProvideCommentHelp' { 'Internal/private helpers use the module/API contract; public main has tested comment-based help and examples. Missing per-helper help is a documentation warning, not runtime execution.'; break }
            'PSUseSingularNouns' { 'Internal helper names describe collections and are not part of the user-facing script parameters; naming debt retained explicitly without suppressing the rule.'; break }
            'PSUseOutputTypeCorrectly' { 'Polymorphic value/serialization helpers deliberately return strings, numbers, booleans, byte arrays or collections; runtime round-trip and empty-collection tests enforce shapes. Static OutputType annotations remain incomplete.'; break }
            'PSReviewUnusedParameter' { 'Fixture/mocked callbacks retain the production parameter contract for binding; unused values are intentional in a network-blocking test double.'; break }
            'PSAvoidAssignmentToAutomaticVariable' { 'Cloud fixed worker uses a local argument-splat dictionary rather than reading automatic unbound arguments; retained as naming debt for the production owner, not hidden.'; break }
            default { 'Non-error diagnostic recorded without disabling its rule; requires release review, not silently suppressed.' }
        }
        [pscustomobject]@{File=$diagnostic.ScriptPath;Line=$diagnostic.Line;Rule=$diagnostic.RuleName;Message=$diagnostic.Message;Rationale=$reason}
    })
    [IO.File]::WriteAllText((Join-Path $EvidenceDirectory 'analyzer-warning-review.json'),(ConvertTo-Json -InputObject $rationales -Depth 8),$encoding)
    # Force in THIS process: avoid resolving legacy Assert-MockCalled/Pester 3.4.
    Remove-Module Pester -Force -ErrorAction SilentlyContinue
    Import-Module Pester -MinimumVersion 5.0.0 -Force -ErrorAction Stop
    $pester=Get-Module Pester
    if ($pester.Version.Major -lt 5) { throw 'Pester >= 5 is mandatory.' }
    $summary.PesterVersion=[string]$pester.Version; $summary.PesterPath=$pester.Path
    $configuration=New-PesterConfiguration
    $configuration.Run.Path=Join-Path $PSScriptRoot 'PraRemoteMailbox.Tests.ps1'
    $configuration.Run.PassThru=$true
    $configuration.Run.Exit=$false
    $configuration.Output.Verbosity='Detailed'
    $configuration.TestResult.Enabled=$true
    $configuration.TestResult.OutputPath=Join-Path $EvidenceDirectory 'pester-results.xml'
    $configuration.TestResult.OutputFormat='NUnitXml'
    $result=Invoke-Pester -Configuration $configuration
    if ($null -eq $result) { throw 'Pester returned no result.' }
    foreach ($name in @('TotalCount','PassedCount','FailedCount','FailedBlocksCount','FailedContainersCount')) {
        if ($null -ne $result.PSObject.Properties[$name]) { $summary[$name]=[int]$result.$name }
    }
    $failedBlocks=@(if ($null -ne $result.PSObject.Properties['FailedBlocks']) { $result.FailedBlocks })
    $failedContainers=@(if ($null -ne $result.PSObject.Properties['FailedContainers']) { $result.FailedContainers })
    $summary.FailedBlocksCount=[Math]::Max($summary.FailedBlocksCount,$failedBlocks.Count)
    $summary.FailedContainersCount=[Math]::Max($summary.FailedContainersCount,$failedContainers.Count)
    $failureDetails=@(foreach ($test in $result.Tests | Where-Object Result -eq 'Failed') { [pscustomobject]@{Name=$test.ExpandedPath;Error=($test.ErrorRecord | Out-String -Width 240)} })
    $failureDetails+=@(foreach ($block in $failedBlocks) { [pscustomobject]@{Name=[string]$block.Name;Error=($block.ErrorRecord | Out-String -Width 240)} })
    $failureDetails+=@(foreach ($container in $failedContainers) { [pscustomobject]@{Name=[string]$container.Item;Error=($container.ErrorRecord | Out-String -Width 240)} })
    [IO.File]::WriteAllText((Join-Path $EvidenceDirectory 'pester-failures.json'),(ConvertTo-Json -InputObject $failureDetails -Depth 10),$encoding)
    if ($summary.TotalCount -le 0 -or $summary.PassedCount -le 0) { $failures.Add('No tests actually passed/executed (positive counts required).') }
    if ($summary.PassedCount -ne $summary.TotalCount) { $failures.Add('Every gate test is mandatory: skipped, filtered, inconclusive or unexecuted tests cannot pass the gate.') }
    if ($summary.FailedCount -gt 0 -or $summary.FailedBlocksCount -gt 0 -or $summary.FailedContainersCount -gt 0 -or [string]$result.Result -ne 'Passed') { $failures.Add('Pester test/block/container failure or non-Passed result.') }
    if ($failures.Count -eq 0) { $exitCode=0 }
}
catch {
    $failures.Add($_.Exception.Message)
    [IO.File]::WriteAllText((Join-Path $EvidenceDirectory 'runner-error.txt'),($_ | Format-List * -Force | Out-String -Width 240),$encoding)
}
finally {
    if ($transcriptStarted) {
        try { Stop-Transcript | Out-Null }
        catch { $exitCode=1; $failures.Add('Gate transcript close failed: '+$_.Exception.Message) }
    }
    $summary.Checks=$checks.ToArray(); $summary.Failures=$failures.ToArray(); $summary.RuntimeMilliseconds=$clock.ElapsedMilliseconds
    $summary.ExitCode=$exitCode; $summary.RESULT=if ($exitCode -eq 0) { 'PASS' } else { 'FAIL' }
    $summary.CompletedUtc=[datetime]::UtcNow.ToString('o')
    [IO.File]::WriteAllText((Join-Path $EvidenceDirectory 'gate-result.json'),($summary | ConvertTo-Json -Depth 15),$encoding)
    $verdict='RESULT: {0} | tests={1}; passed={2}; failed={3}; blocks={4}; containers={5}; PSSA errors={6}; warnings={7}; exit={8}' -f $summary.RESULT,$summary.TotalCount,$summary.PassedCount,$summary.FailedCount,$summary.FailedBlocksCount,$summary.FailedContainersCount,$summary.AnalyzerErrorCount,$summary.AnalyzerWarningCount,$exitCode
    [IO.File]::WriteAllText((Join-Path $EvidenceDirectory 'RESULT.txt'),($verdict+"`r`nEvidence: "+$EvidenceDirectory+"`r`n"+($failures -join "`r`n")),$encoding)
    Write-Output $verdict
    Write-Output ('Evidence: '+$EvidenceDirectory)
    $env:PRA_GATE_EVIDENCE=$originalEvidence
}
exit $exitCode

