<#
.SYNOPSIS
    PRA Remote Mailbox - common module: console, log, configuration, audit and reports.

.DESCRIPTION
    Helper functions used by Invoke-PraRemoteMailbox.ps1 and by the other modules. The module never
    reads Active Directory and never connects to Microsoft 365. It is organised in regions, in the
    order of an execution:

        1. Console theme       icons, frames and colours (console colours)
        2. Console and log     Write-PraBanner, Write-PraStep, Write-PraItem, Write-PraLog, Write-PraSummary
        3. Configuration       Import-PraConfiguration (reads and checks the .psd1 file)
        4. Audit               Initialize-PraAudit (log file + PowerShell transcript)
        5. Results             Get-PraOutcome, Write-PraReport (CSV + HTML), Complete-PraRun

    The run state is one hashtable (the "context") created by the entry script and passed to every
    function. Its main keys are described in docs\PraRemoteMailbox-Guide.md, chapter "Inside the tool".

.NOTES
    Author  : Nicolas Fabert
    Version : 3.1.1
    History : see CHANGELOG.md
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

# SINGLE SOURCE of the tool version. Every runtime consumer reads it through Get-PraToolVersion (entry script,
# window, run context, report, audit). The literal comments "Version : x.y.z" of the file headers cannot be
# computed (the signature and the manifest hash the exact bytes): they are listed in the guide, annex D, and
# checked against this value by the tests. tools\New-PraPackage.ps1 reads the version from this line.
$script:ToolVersion = '3.1.1'
$script:TranscriptOwner = $null
$script:PraNativePath = $null
$script:PraNativeProcess = $null
# Columns of the CSV report, in this order (also the fields copied from each result row).
$script:RowFields = @('ObjectGuid','SamAccountName','UserPrincipalName','Action','IsShared','ADApplied','ADVerified',
    'GroupAction','BackupPath','LastOperation','CloudMailbox','CloudLicense','CloudStatus','CloudDetail','PreserveCloudMailbox',
    'PreserveLicense','DeprovisionConfirmed','PermDetail','PermMissing','FinalStatus','Detail','Warnings')
# Final statuses a row can have. 'AlreadyDone' is counted as a success.
$script:FinalStatuses = @('Planned','AlreadyDone','Success','Error','Pending','Skipped')

function ConvertFrom-PraJson {
    <#
    .SYNOPSIS
        The ONLY way the tool reads JSON (backups, proofs, manifests, journals, child-process answers).
    .DESCRIPTION
        ConvertFrom-Json of PowerShell 7 turns ISO 8601 strings (CapturedUtc, CreatedUtc, Utc) into [DateTime] unless told
        otherwise, which would break the byte-exact, string-based comparisons of the proofs and of the memory fingerprint.
        -DateKind String (PowerShell 7.5+) keeps every date as the string that was written, exactly as Windows PowerShell 5.1 did,
        so a file written by 2.x under Windows PowerShell 5.1 and a file written by 3.x are read the same way.
        A test refuses any other ConvertFrom-Json call in the package.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory, ValueFromPipeline)][AllowEmptyString()][string]$InputObject)
    begin { $parts = New-Object 'Collections.Generic.List[string]' }
    process { $parts.Add($InputObject) }
    end { ($parts -join "`n") | ConvertFrom-Json -DateKind String -ErrorAction Stop }
}

#region 0. Ordinal string comparison -----------------------------------------------------------
# PowerShell 7 runs on .NET with ICU: every CULTURE-sensitive string comparison ignores zero-weight characters. -eq, -ceq, -ne, -cne,
# -in, -cin, -contains, -like, -clike, switch, Group-Object, Select-Object -Unique, Sort-Object, Compare-Object, [string]::Compare,
# .StartsWith(string), .EndsWith(string), .IndexOf(string), .CompareTo and hashtables built on a culture comparer treat "a" and
# "a<U+0001>" (or "a<U+200B>") as EQUAL (the "c" operators only drop the case, never the culture). Windows PowerShell 5.1 (NLS) was strict.
# This tool is fail-closed: every comparison that guards integrity, identity or authorisation goes through these helpers or through an
# explicit [StringComparison]::Ordinal / OrdinalIgnoreCase (regular expressions are already ordinal). The experiment is in
# the guide, annex "Limitations" and the tests (OrdinalComparison).
function Test-PraOrdinalEqual {
    <# True when both values are the same sequence of UTF-16 code units (case-sensitive, culture-free). $null equals only $null. #>
    [OutputType([bool])]
    param([AllowNull()][object]$Left, [AllowNull()][object]$Right)
    if ($null -eq $Left -or $null -eq $Right) { return ($null -eq $Left -and $null -eq $Right) }
    return [string]::Equals([string]$Left, [string]$Right, [StringComparison]::Ordinal)
}

function Test-PraOrdinalIgnoreCaseEqual {
    <# Same, but ignoring the case (identities: UPN, sAMAccountName, SMTP, GUID text, hexadecimal hashes written in either case). #>
    [OutputType([bool])]
    param([AllowNull()][object]$Left, [AllowNull()][object]$Right)
    if ($null -eq $Left -or $null -eq $Right) { return ($null -eq $Left -and $null -eq $Right) }
    return [string]::Equals([string]$Left, [string]$Right, [StringComparison]::OrdinalIgnoreCase)
}

function Test-PraOrdinalIn {
    <# True when Value is one of the items of Set (ordinal, case-sensitive; -IgnoreCase for the ordinal case-insensitive comparison). Replaces -in/-cin/-contains/-notin. #>
    [OutputType([bool])]
    param([AllowNull()][object]$Value, [AllowNull()][AllowEmptyCollection()][object]$Set, [switch]$IgnoreCase)
    if ($null -eq $Set) { return $false }
    $comparison = if ($IgnoreCase) { [StringComparison]::OrdinalIgnoreCase } else { [StringComparison]::Ordinal }
    # Native path for a non-empty text (a PowerShell loop is about 70 times slower on a group with 20 000 members). The slow loop below keeps
    # the exact $null / empty-string semantics (a $null item never equals a text; the [string[]] cast would turn it into '').
    if ($null -ne $Value) {
        $text = [string]$Value
        if ($text.Length -gt 0) {
            $strings = $Set -as [string[]]
            if ($null -ne $strings) { return [Linq.Enumerable]::Contains($strings, $text, $(if ($IgnoreCase) { [StringComparer]::OrdinalIgnoreCase } else { [StringComparer]::Ordinal })) }
        }
    }
    foreach ($item in @($Set)) {
        if ($null -eq $item -or $null -eq $Value) { if ($null -eq $item -and $null -eq $Value) { return $true }; continue }
        if ([string]::Equals([string]$Value, [string]$item, $comparison)) { return $true }
    }
    return $false
}

function Test-PraOrdinalIgnoreCaseIn {
    <# Test-PraOrdinalIn -IgnoreCase, for conditions where a switch would read badly. #>
    [OutputType([bool])]
    param([AllowNull()][object]$Value, [AllowNull()][AllowEmptyCollection()][object]$Set)
    return (Test-PraOrdinalIn -Value $Value -Set $Set -IgnoreCase)
}

function Sort-PraOrdinal {
    <#
    .SYNOPSIS
        Sorts strings (or objects by one string property) by UTF-16 code unit: the culture-free, reproducible order that canonical forms
        and hashes need. Sort-Object uses the culture collation (ICU), which is neither stable across machines nor strict.
    .PARAMETER Property
        Name of the string property to sort by; without it the input items themselves are sorted.
    .PARAMETER IgnoreCase
        OrdinalIgnoreCase instead of Ordinal.
    .PARAMETER Unique
        Removes the duplicates (same comparison) and keeps the first of each.
    #>
    [CmdletBinding()]
    param([Parameter(ValueFromPipeline, Mandatory)][AllowNull()][object]$InputObject, [string]$Property, [switch]$Descending, [switch]$IgnoreCase, [switch]$Unique)
    begin { $items = New-Object 'Collections.Generic.List[object]' }
    process { $items.Add($InputObject) }
    end {
        $comparer = if ($IgnoreCase) { [StringComparer]::OrdinalIgnoreCase } else { [StringComparer]::Ordinal }
        $keys = New-Object 'string[]' $items.Count
        for ($i = 0; $i -lt $items.Count; $i++) {
            $value = if ($Property) { $item = $items[$i]; if ($null -eq $item) { $null } else { $member = $item.PSObject.Properties[$Property]; if ($null -ne $member) { $member.Value } else { $null } } } else { $items[$i] }
            $keys[$i] = if ($null -eq $value) { '' } else { [string]$value }
        }
        $array = $items.ToArray()
        [Array]::Sort([Array]$keys, [Array]$array, [Collections.IComparer]$comparer)
        if ($Descending) { [Array]::Reverse($keys); [Array]::Reverse($array) }
        if ($Unique) {
            $seen = New-Object 'Collections.Generic.HashSet[string]' -ArgumentList $comparer
            for ($i = 0; $i -lt $array.Length; $i++) { if ($seen.Add($keys[$i])) { $array[$i] } }
        } else { $array }
    }
}

function Get-PraOrdinalUnique {
    <# Distinct strings in first-seen order, compared ordinally (Select-Object -Unique / Sort-Object -Unique / Get-Unique use the culture comparison). #>
    [CmdletBinding()]
    param([Parameter(ValueFromPipeline, Mandatory)][AllowNull()][AllowEmptyString()][object]$InputObject, [switch]$IgnoreCase)
    begin { $seen = New-Object 'Collections.Generic.HashSet[string]' -ArgumentList $(if ($IgnoreCase) { [StringComparer]::OrdinalIgnoreCase } else { [StringComparer]::Ordinal }) }
    process { if ($null -ne $InputObject -and $seen.Add([string]$InputObject)) { [string]$InputObject } }
}

function Compare-PraX500Address {
    <#
    .SYNOPSIS
        Which of the expected X500 addresses a cloud mailbox carries (EmailAddresses / proxyAddresses): Present and Missing, in the order of Expected.
    .DESCRIPTION
        Read only. The whole value is compared, ordinal and ignoring case (Exchange Online may write the type prefix in lower case); the values are returned
        exactly as they are in Expected.
    #>
    [CmdletBinding()]
    param([AllowNull()][string[]]$Expected, [AllowNull()][string[]]$Actual)
    $actualSet = New-Object 'Collections.Generic.HashSet[string]' -ArgumentList ([StringComparer]::OrdinalIgnoreCase)
    foreach ($value in @($Actual)) { if ($null -ne $value) { [void]$actualSet.Add([string]$value) } }
    $present = New-Object 'Collections.Generic.List[string]'; $missing = New-Object 'Collections.Generic.List[string]'
    foreach ($value in @($Expected)) { if ($null -eq $value) { continue }; if ($actualSet.Contains([string]$value)) { $present.Add([string]$value) } else { $missing.Add([string]$value) } }
    return [pscustomobject]@{ Total = ($present.Count + $missing.Count); Present = [string[]]$present.ToArray(); Missing = [string[]]$missing.ToArray() }
}
#endregion

function Get-PraToolVersion {
    <# The tool version (single source: $script:ToolVersion of this module). #>
    [CmdletBinding()]
    [OutputType([string])]
    param()
    return $script:ToolVersion
}

#region 1. Console theme ----------------------------------------------------------------------
# The classic console (conhost) is the reference: colours are console
# colours (no ANSI sequences, so the transcript and the log stay clean text) and the default icons
# are characters present in the Consolas and Lucida Console fonts. Emoji are used only in Windows
# Terminal and VS Code. Force a style with the environment variable PRA_ICONS = Emoji|Symbols|Ascii.

function Get-PraIconSet {
    <# Icons of one console style. 'Symbols' uses only characters of the classic console fonts. #>
    param([Parameter(Mandatory)][ValidateSet('Emoji','Symbols','Ascii')][string]$Style)
    $u = { param([int]$Code) [char]::ConvertFromUtf32($Code) }
    switch ($Style) {
        'Emoji' {
            return @{
                Logo = & $u 0x1F6DF; Ok = & $u 0x2705; Warn = & $u 0x1F7E1; Fail = & $u 0x274C; Info = & $u 0x1F539
                Skip = & $u 0x23E9; Directory = & $u 0x1F3E2; Plan = & $u 0x1F50E; Backup = & $u 0x1F4BE; Write = & $u 0x270F
                Sync = & $u 0x1F504; Cloud = & $u 0x2601; Key = & $u 0x1F510; Batch = & $u 0x1F4E6; Config = & $u 0x1F4DD
                Report = & $u 0x1F4CA; Folder = & $u 0x1F4C1; Clock = & $u 0x23F3; Mail = & $u 0x1F4E8; Target = & $u 0x1F3AF
                Log = & $u 0x1F4C4; Done = & $u 0x1F389; People = & $u 0x1F465; Next = & $u 0x1F449; Mode = & $u 0x1F9ED
            }
        }
        'Symbols' {
            return @{
                Logo = & $u 0x2666; Ok = & $u 0x221A; Warn = & $u 0x25B2; Fail = & $u 0x00D7; Info = & $u 0x2022
                Skip = & $u 0x00BB; Directory = & $u 0x2302; Plan = & $u 0x25BA; Backup = & $u 0x25A0; Write = & $u 0x00B1
                Sync = & $u 0x2194; Cloud = & $u 0x263C; Key = & $u 0x00A7; Batch = & $u 0x25D9; Config = & $u 0x2261
                Report = & $u 0x2261; Folder = & $u 0x2302; Clock = & $u 0x25CB; Mail = '@'; Target = & $u 0x25D9
                Log = & $u 0x00B6; Done = & $u 0x221A; People = & $u 0x2192; Next = & $u 0x2192; Mode = & $u 0x25BA
            }
        }
        default {
            return @{
                Logo = '*'; Ok = '+'; Warn = '!'; Fail = 'x'; Info = '-'; Skip = '>'; Directory = '#'; Plan = '?'; Backup = '='
                Write = '~'; Sync = '<>'; Cloud = '@'; Key = '$'; Batch = '#'; Config = '='; Report = '='; Folder = '>'
                Clock = ':'; Mail = '@'; Target = 'o'; Log = '='; Done = '*'; People = '&'; Next = '>'; Mode = '>'
            }
        }
    }
}

function Get-PraFrameSet {
    <# Frame characters: rounded corners (Consolas), square corners for Lucida Console, ASCII otherwise. #>
    param([Parameter(Mandatory)][ValidateSet('Emoji','Symbols','Ascii')][string]$Style)
    if ((Test-PraOrdinalIgnoreCaseEqual $Style 'Ascii')) { return @{ TopLeft='+'; TopRight='+'; BottomLeft='+'; BottomRight='+'; Horizontal='-'; Vertical='|' } }
    return @{ TopLeft=[string][char]0x256D; TopRight=[string][char]0x256E; BottomLeft=[string][char]0x2570
        BottomRight=[string][char]0x256F; Horizontal=[string][char]0x2500; Vertical=[string][char]0x2502 }
}

$script:IconStyle = if ((Test-PraOrdinalIn $env:PRA_ICONS @('Emoji','Symbols','Ascii') -IgnoreCase)) { $env:PRA_ICONS }
    elseif ($env:WT_SESSION -or (Test-PraOrdinalIgnoreCaseEqual $env:TERM_PROGRAM 'vscode')) { 'Emoji' }
    else { 'Symbols' }
$script:Icons = Get-PraIconSet $script:IconStyle
$script:Frame = Get-PraFrameSet $script:IconStyle
# Emoji are two columns wide, symbols one: pad symbols so that the text stays aligned.
$script:IconPad = if ((Test-PraOrdinalIgnoreCaseEqual $script:IconStyle 'Emoji')) { ' ' } else { '  ' }
# Console colours of the theme. Accent = frames and step numbers.
$script:Theme = @{ Accent='Magenta'; AccentBack='DarkMagenta'; Dim='DarkGray'; Ok='Green'; Warn='Yellow'; Fail='Red'; Text='Gray'; Strong='White'; Info='Cyan' }

function Get-PraIcon {
    param([Parameter(Mandatory)][string]$Name)
    $icon = $script:Icons[$Name]
    if (-not $icon) { $icon = $script:Icons['Info'] }
    return $icon + $script:IconPad
}

function Write-PraHost {
    <#
    .SYNOPSIS
        Writes one console line made of coloured segments: @( @('text','Color'), @('text'), ... ).
        Console output only (the transcript records it); never the log file.
    #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingWriteHost','',Justification='Single console writer of the tool.')]
    param([Parameter(Mandatory)][object[]]$Segments, [string]$Color)
    # ONE Write-Host per line and one colour per line: the Windows PowerShell 5.1 transcript writes
    # every Write-Host -NoNewline piece on its own line, which would make the audit transcript unreadable.
    # The colour is -Color, or the first colour given in the segments.
    $text = (@($Segments | ForEach-Object { [string](@($_)[0]) })) -join ''
    if (-not $Color) {
        foreach ($segment in $Segments) { $parts = @($segment); if ($parts.Count -ge 2 -and $parts[1]) { $Color = [string]$parts[1]; break } }
    }
    # PRA_ANSI=1: the colour as an ANSI sequence (console captures for the documentation).
    if ((Test-PraOrdinalIgnoreCaseEqual $env:PRA_ANSI '1') -and $Color) {
        $codes = @{ Black=30; DarkBlue=34; DarkGreen=32; DarkCyan=36; DarkRed=31; DarkMagenta=35; DarkYellow=33; Gray=37; DarkGray=90; Blue=94; Green=92; Cyan=96; Red=91; Magenta=95; Yellow=93; White=97 }
        Write-Host ("{0}[{1}m{2}{0}[0m" -f [char]27, $codes[$Color], $text)
        return
    }
    if ($Color -and -not [Console]::IsOutputRedirected) { Write-Host $text -ForegroundColor $Color }
    else { Write-Host $text }
}
#endregion

#region 2. Console and log ----------------------------------------------------------------------

function Get-PraValue {
    <#
    .SYNOPSIS
        Reads a key or a property without mixing up "missing", $null, $false, 0 and empty collections.
    .PARAMETER Object
        Dictionary or object, possibly $null.
    .PARAMETER Name
        Key or property name.
    .PARAMETER Default
        Value returned only when the object or the member is missing.
    #>
    [CmdletBinding()]
    param([AllowNull()][object]$Object, [Parameter(Mandatory)][string]$Name, [AllowNull()][object]$Default = $null)
    if ($null -eq $Object) { return ,$Default }
    if ($Object -is [System.Collections.IDictionary]) {
        foreach ($entry in $Object.GetEnumerator()) { if ([string]::Equals([string]$entry.Key, $Name, [StringComparison]::OrdinalIgnoreCase)) { return ,($entry.Value) } }
    } else {
        $property = $Object.PSObject.Properties[$Name]
        if ($null -ne $property) { return ,($property.Value) }
    }
    return ,$Default
}

function Get-PraList {
    <# The items of a list-valued key or property as a flat sequence (Get-PraValue wraps its answer in one more array level, so @(Get-PraValue ...) would nest). Missing or $null gives nothing. #>
    [CmdletBinding()]
    param([AllowNull()][object]$Object, [Parameter(Mandatory)][string]$Name)
    $value = Get-PraValue $Object $Name $null
    if ($null -eq $value) { return }
    foreach ($item in $value) { if ($null -ne $item) { $item } }
}

function Format-PraDuration {
    <#
    .SYNOPSIS
        '4.2 s', '3 min 05 s', '1 h 02 min'.
    #>
    param([Parameter(Mandatory)][double]$Seconds)
    $t = [TimeSpan]::FromTicks([long]([Math]::Max(0.0, $Seconds) * 10000000))
    if ($t.TotalHours -ge 1) { return '{0} h {1:00} min' -f [int][Math]::Floor($t.TotalHours), $t.Minutes }
    if ($t.TotalMinutes -ge 1) { return '{0} min {1:00} s' -f $t.Minutes, $t.Seconds }
    return ('{0:0.0} s' -f $t.TotalSeconds).Replace(',', '.')
}

function Add-PraIssue {
    <#
    .SYNOPSIS
        Records a run error (reports, exit code) without any output. Used by Write-PraLog -Level Error.
    #>
    [CmdletBinding()]
    param([hashtable]$Context, [string]$Message, [string]$Source = 'Execution')
    $phase = [string](Get-PraValue $Context 'CurrentPhase' '')
    if (-not $phase) { $phase = [string](Get-PraValue $Context 'Phase' '') }
    [void]$Context.Issues.Add([pscustomobject]@{
        Timestamp = (Get-Date).ToString('o'); Phase = $phase; Source = $Source
        Operation = [string](Get-PraValue $Context 'CurrentOperation' '')
        Identity = [string](Get-PraValue $Context 'CurrentIdentity' ''); Message = $Message
    })
    $Context.ExitCode = 1
}

function Add-PraWarning {
    <#
    .SYNOPSIS
        Records a run warning (summary card, HTML report) without any output and without changing the
        exit code. Used by Write-PraLog -Level Warning and Write-PraItem -Status Warn.
    #>
    [CmdletBinding()]
    param([hashtable]$Context, [string]$Message)
    if (-not $Context.ContainsKey('WarningList')) { $Context['WarningList'] = New-Object 'Collections.Generic.List[object]' }
    [void]$Context['WarningList'].Add([pscustomobject]@{
        Timestamp = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss'); Phase = [string](Get-PraValue $Context 'CurrentPhase' ''); Message = $Message
    })
}

function Write-PraEvent {
    <# Optional JSONL channel to the window; CLI runs without PRA_EVENT_FILE are unchanged. #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][ValidateSet('start','step','item','summary','result','plan','progress','count')][string]$Kind, [hashtable]$Data = @{})
    if (-not $env:PRA_EVENT_FILE) { return }
    $record = [ordered]@{ time = [datetime]::UtcNow.ToString('o'); kind = $Kind }
    foreach ($key in $Data.Keys) { $record[$key] = $Data[$key] }
    $line = ($record | ConvertTo-Json -Compress -Depth 8) + "`n"
    for ($attempt = 1; $attempt -le 3; $attempt++) {
        try {
            [IO.File]::AppendAllText($env:PRA_EVENT_FILE, $line, (New-Object Text.UTF8Encoding($false)))
            return
        }
        catch [IO.IOException] {
            if ($attempt -eq 3) { throw }
            Start-Sleep -Milliseconds 50
        }
    }
}

function Get-PraStepId {
    <# Identifier of the step being run ('s1', 's2' ... = 's' + the 1-based index shown as x/total), or '' before the first step. #>
    param([hashtable]$Context)
    $index = [int](Get-PraValue $Context 'StepIndex' 0)
    if ($index -gt 0) { return 's' + $index.ToString([Globalization.CultureInfo]::InvariantCulture) }
    return ''
}

function Close-PraStepEvent {
    <#
    .SYNOPSIS
        Ends the step that is still running: one 'step' event with its final state (ok, warn when warnings were raised during it,
        fail when errors were recorded during it, or the state given). Nothing is written without PRA_EVENT_FILE.
    #>
    param([hashtable]$Context, [ValidateSet('', 'ok', 'warn', 'fail')][string]$State = '')
    $open = Get-PraValue $Context '_PraOpenStep' $null
    if ($null -eq $open) { return }
    $Context['_PraOpenStep'] = $null
    if (-not $State) {
        $issues = Get-PraValue $Context 'Issues' $null
        $issueCount = if ($null -ne $issues) { [int]$issues.Count } else { 0 }
        $State = if ($issueCount -gt [int]$open.IssueBase) { 'fail' } elseif ([int](Get-PraValue $Context 'Warnings' 0) -gt [int]$open.WarningBase) { 'warn' } else { 'ok' }
    }
    if ($open.ContainsKey('Log') -and $null -ne $open.Log) { $open.Log.State = $State; $open.Log.EndedUtc = [datetime]::UtcNow.ToString('o') }
    Write-PraEvent -Kind step -Data @{ index = $open.Index; total = $open.Total; title = $open.Title; id = $open.Id; state = $State
        startedUtc = $open.StartedUtc; endedUtc = [datetime]::UtcNow.ToString('o') }
}

function Write-PraProgress {
    <#
    .SYNOPSIS
        A wait the operator should see (Entra Connect cycle, grant verification, mailbox or deprovisioning polling): one 'progress' event.
        No console output; nothing is written without PRA_EVENT_FILE.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][hashtable]$Context, [Parameter(Mandatory)][AllowEmptyString()][string]$Text,
        [int]$Current = 0, [int]$Total = 0, [int]$Attempt = 0, [int]$MaxAttempts = 0, [int]$NextInSeconds = 0)
    Write-PraEvent -Kind progress -Data @{ stepId = (Get-PraStepId $Context); current = $Current; total = $Total; attempt = $Attempt
        maxAttempts = $MaxAttempts; nextInSeconds = $NextInSeconds; text = $Text }
}

function Write-PraLogFile {
    <# Appends one line to the log file. A log that cannot be written stops the run (audit). #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingWriteHost','',Justification='Last-resort console message when the log is broken.')]
    param([Parameter(Mandatory)][hashtable]$Context, [Parameter(Mandatory)][string]$Level, [AllowEmptyString()][string]$Message)
    if (-not $Context.LogFile) { return }
    $line = '{0} [{1,-6}] {2}' -f (Get-Date).ToString('yyyy-MM-dd HH:mm:ss.fff'), $Level, ($Message -replace '[\r\n]+', ' | ')
    try { [IO.File]::AppendAllText($Context.LogFile, $line + "`r`n", (New-Object Text.UTF8Encoding($false))) }
    catch {
        $failure = 'The log file cannot be written: {0}' -f $_.Exception.Message
        Add-PraIssue $Context $failure 'Log'
        Write-Host ('  [ERROR] ' + $failure) -ForegroundColor Red
        throw
    }
}

function Write-PraLog {
    <#
    .SYNOPSIS
        Writes a message to the log file and, depending on the level, to the console.
    .PARAMETER Level
        Info      console item (bullet) + log
        Success   console item (tick, green) + log
        Warning   console item (yellow) + log; counted in the warnings
        Error     console item (red) + log; recorded as a run error (exit code 1)
        Sub       indented console detail line + log
        Detail    log only (full values, technical traces)
        Debug     log only; also on the console with -Verbose
        Step      log only (step headers are drawn by Write-PraStep)
    .PARAMETER ForegroundColor
        Console colour of the text (presentation only: it never changes the level or the counters).
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][hashtable]$Context, [Parameter(Mandatory)][AllowEmptyString()][string]$Message,
        [ValidateSet('Info','Sub','Success','Warning','Error','Debug','Step','Detail')][string]$Level = 'Info',
        [ConsoleColor]$ForegroundColor)
    $logLevel = @{ Info='INFO'; Sub='INFO'; Success='OK'; Warning='WARN'; Error='ERROR'; Debug='DEBUG'; Step='STEP'; Detail='DETAIL' }[$Level]
    if ((Test-PraOrdinalIgnoreCaseEqual $Level 'Warning')) { $Context.Warnings = [int](Get-PraValue $Context 'Warnings' 0) + 1; Add-PraWarning $Context $Message }
    if ((Test-PraOrdinalIgnoreCaseEqual $Level 'Error')) { Add-PraIssue $Context $Message }
    Write-PraLogFile -Context $Context -Level $logLevel -Message $Message
    $text = $Message -replace '[\r\n]+', ' | '
    switch ($Level) {
        'Debug' {
            $verbose = [bool](Get-PraValue $Context 'VerboseEnabled' ((Test-PraOrdinalIgnoreCaseEqual $VerbosePreference 'Continue')))
            Write-Verbose $text -Verbose:$verbose
        }
        'Detail' { }
        'Step' { }
        'Sub' {
            $color = if ($PSBoundParameters.ContainsKey('ForegroundColor')) { [string]$ForegroundColor } else { $script:Theme.Dim }
            Write-PraHost @(,@(('         ' + $text), $color))
        }
        default {
            $status = @{ Info='Info'; Success='Ok'; Warning='Warn'; Error='Fail' }[$Level]
            $iconColor = @{ Info=$script:Theme.Info; Ok=$script:Theme.Ok; Warn=$script:Theme.Warn; Fail=$script:Theme.Fail }[$status]
            $textColor = if ($PSBoundParameters.ContainsKey('ForegroundColor')) { [string]$ForegroundColor }
                elseif ((Test-PraOrdinalIn $status @('Warn','Fail') -IgnoreCase)) { $iconColor } else { '' }
            Write-PraHost @('      ', (Get-PraIcon $status), $text) -Color $textColor
        }
    }
    if ((Test-PraOrdinalIn $Level @('Info','Sub','Success','Warning','Error') -IgnoreCase)) {
        Write-PraEvent -Kind item -Data @{ status = @{ Info='Info'; Sub='Sub'; Success='Ok'; Warning='Warn'; Error='Fail' }[$Level]
            text = $text; identity = [string](Get-PraValue $Context 'CurrentIdentity' ''); name = (Get-PraEventObjectName $Context ([string](Get-PraValue $Context 'CurrentIdentity' ''))); stepId = (Get-PraStepId $Context); detail = ''
            backup = (Get-PraEventBackup $Context ([string](Get-PraValue $Context 'CurrentIdentity' ''))) }
        Add-PraJourney -Context $Context -Status (@{ Info='Info'; Sub='Info'; Success='Ok'; Warning='Warn'; Error='Fail' }[$Level]) -Text $text
    }
}

function Register-PraObjectName {
    <# Remembers the readable name (UPN, else sAMAccountName) of an object ID, so that the events of the window can name the object (names only, no decision). #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][hashtable]$Context, [string]$ObjectGuid, [string]$Name)
    if (-not $ObjectGuid -or -not $Name) { return }
    if (-not $Context.ContainsKey('ObjectNames')) { $Context['ObjectNames'] = @{} }
    $Context['ObjectNames'][$ObjectGuid.ToLowerInvariant()] = $Name
}

function Register-PraObjectBackup {
    <# Remembers the backup file of an object (by ID, UPN and account name), or of the whole batch when no object is named, so that the item events can carry it. #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][hashtable]$Context, [string[]]$Identity = @(), [Parameter(Mandatory)][string]$Path)
    if (-not $Context.ContainsKey('ObjectBackups')) { $Context['ObjectBackups'] = @{} }
    $any = $false
    foreach ($key in $Identity) { if ($key) { $Context['ObjectBackups'][$key.ToLowerInvariant()] = $Path; $any = $true } }
    if (-not $any) { $Context['BatchBackup'] = $Path }
}

function Get-PraEventBackup {
    <# The backup path to show for the identity of an event: its own, else the one of the batch, else ''. #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][hashtable]$Context, [string]$Identity)
    $map = Get-PraValue $Context 'ObjectBackups' $null
    if ($Identity -and $map -is [hashtable] -and $map.ContainsKey($Identity.ToLowerInvariant())) { return [string]$map[$Identity.ToLowerInvariant()] }
    return [string](Get-PraValue $Context 'BatchBackup' '')
}

function Get-PraEventObjectName {
    <# The readable name of the identity of an event ('' when it is not a known object: a step-level message, a DN, a server). #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][hashtable]$Context, [string]$Identity)
    if (-not $Identity) { return '' }
    $names = Get-PraValue $Context 'ObjectNames' $null
    if ($names -is [hashtable] -and $names.ContainsKey($Identity.ToLowerInvariant())) { return [string]$names[$Identity.ToLowerInvariant()] }
    if ($Identity -match '\A[^\s@]+@[^\s@]+\z') { return $Identity }
    return ''
}

function Write-PraItem {    <#
    .SYNOPSIS
        One indented result line with a status icon, also written to the log.
    .PARAMETER Status
        Ok, Warn, Fail, Info or Skip. Fail does NOT record a run error: use Write-PraLog -Level Error for that.
    .PARAMETER Icon
        Optional icon name instead of the status icon (Directory, Backup, Cloud, Mail, ...).
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][hashtable]$Context, [ValidateSet('Ok','Warn','Fail','Info','Skip')][string]$Status = 'Info',
        [Parameter(Mandatory)][AllowEmptyString()][string]$Text, [string]$Icon, [string]$Detail = '')
    $color = @{ Ok=$script:Theme.Ok; Warn=$script:Theme.Warn; Fail=$script:Theme.Fail; Info=$script:Theme.Info; Skip=$script:Theme.Dim }[$Status]
    $textColor = if ((Test-PraOrdinalIn $Status @('Warn','Fail','Skip') -IgnoreCase)) { $color } else { '' }
    $symbol = if ($Icon) { Get-PraIcon $Icon } else { Get-PraIcon $Status }
    Write-PraHost @('      ', $symbol, $Text) -Color $textColor
    if ((Test-PraOrdinalIgnoreCaseEqual $Status 'Warn')) { $Context.Warnings = [int](Get-PraValue $Context 'Warnings' 0) + 1; Add-PraWarning $Context $Text }
    Write-PraLogFile -Context $Context -Level (@{ Ok='OK'; Warn='WARN'; Fail='FAIL'; Info='INFO'; Skip='SKIP' }[$Status]) -Message $Text
    Write-PraEvent -Kind item -Data @{ status = $Status; text = $Text; identity = [string](Get-PraValue $Context 'CurrentIdentity' ''); name = (Get-PraEventObjectName $Context ([string](Get-PraValue $Context 'CurrentIdentity' ''))); stepId = (Get-PraStepId $Context); detail = $Detail
        backup = (Get-PraEventBackup $Context ([string](Get-PraValue $Context 'CurrentIdentity' ''))) }
    Add-PraJourney -Context $Context -Status $Status -Text $Text
}

function Write-PraBanner {
    <#
    .SYNOPSIS
        Title card at the start of an execution:

          ╭────────────────────────────────────────────────────────────────────────────╮
          │  ♦  PRA Remote Mailbox                           v3.1.1 · Nicolas Fabert   │
          │     Hybrid Exchange disaster recovery · on-premises mailboxes → Exchange O │
          ╰────────────────────────────────────────────────────────────────────────────╯
               ►  Action     Convert · Preview (nothing is changed)
    .PARAMETER Details
        Ordered list of rows: key = label, value = @(IconName, Text) or plain text.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][hashtable]$Context, [Parameter(Mandatory)][string]$Title, [string]$Subtitle,
        [System.Collections.Specialized.OrderedDictionary]$Details)
    $F = $script:Frame; $T = $script:Theme; $width = 76
    $right = "v$($Context.Version) $([char]0x00B7) Nicolas Fabert"
    $left = "  $($script:Icons.Logo)  $Title"
    $iconWidth = if ((Test-PraOrdinalIgnoreCaseEqual $script:IconStyle 'Emoji')) { 2 } else { $script:Icons.Logo.Length }
    $visible = $left.Length - $script:Icons.Logo.Length + $iconWidth
    $gap = [Math]::Max(1, $width - $visible - $right.Length - 2)
    Write-Host ''
    Write-PraHost @(,@(('  ' + $F.TopLeft + ($F.Horizontal * $width) + $F.TopRight), $T.Accent))
    Write-PraHost @('  ', $F.Vertical, $left, (' ' * $gap), $right, '  ', $F.Vertical) -Color $T.Accent
    if ($Subtitle) {
        $sub = ('     ' + $Subtitle)
        if ($sub.Length -gt $width) { $sub = $sub.Substring(0, $width) }
        Write-PraHost @('  ', $F.Vertical, $sub.PadRight($width), $F.Vertical) -Color $T.Accent
    }
    Write-PraHost @(,@(('  ' + $F.BottomLeft + ($F.Horizontal * $width) + $F.BottomRight), $T.Accent))
    Write-PraLogFile -Context $Context -Level 'STEP' -Message ("=== $Title v$($Context.Version) - run $($Context.RunId) ===")
    $eventDetails = [ordered]@{}
    if ($Details) {
        foreach ($key in $Details.Keys) {
            $value = $Details[$key]
            $icon = '   '; $text = $value
            if ($value -is [array]) { $icon = Get-PraIcon $value[0]; $text = $value[1] }
            Write-PraHost @('     ', $icon, ('{0,-11}' -f $key), (' ' + $text))
            Write-PraLogFile -Context $Context -Level 'INFO' -Message ('{0}: {1}' -f $key, $text)
            $eventDetails[$key] = [string]$text
        }
    }
    Write-PraEvent -Kind start -Data @{ title = $Title; action = [string](Get-PraValue $Context 'Action' '')
        mode = [string](Get-PraValue $Context 'Mode' ''); phase = [string](Get-PraValue $Context 'Phase' '')
        version = [string]$Context.Version; runId = [string]$Context.RunId
        logFile = [string](Get-PraValue $Context 'LogFile' ''); details = $eventDetails }
}

function Write-PraStep {
    <#
    .SYNOPSIS
        Step header with a coloured number pill and an icon, e.g.

           3/7  ►  Reading the targets and planning the changes
    .DESCRIPTION
        The step number comes from $Context.StepIndex (incremented here) and the total from
        $Context.StepTotal (set by the entry script for the selected action and phase).
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][hashtable]$Context, [Parameter(Mandatory)][string]$Title, [string]$Icon = 'Plan', [switch]$Skipped)
    # The step that was running ends here (event state ok / warn / fail); a skipped step is announced and closed at once.
    Close-PraStepEvent -Context $Context
    $Context.StepIndex = [int](Get-PraValue $Context 'StepIndex' 0) + 1
    $Context.CurrentPhase = $Title
    $total = [int](Get-PraValue $Context 'StepTotal' 0)
    $number = if ($total -gt 0) { '{0}/{1}' -f $Context.StepIndex, $total } else { [string]$Context.StepIndex }
    Write-Host ''
    Write-PraHost @('  ', ('{0,5}' -f $number), '  ', (Get-PraIcon $Icon), $Title) -Color $script:Theme.Accent
    Write-PraLogFile -Context $Context -Level 'STEP' -Message ("[$number] $Title")
    $now = [datetime]::UtcNow.ToString('o')
    $issues = Get-PraValue $Context 'Issues' $null
    $stepId = Get-PraStepId $Context
    if (-not $Context.ContainsKey('StepLog')) { $Context['StepLog'] = New-Object 'Collections.Generic.List[object]' }
    $logEntry = [pscustomobject]@{ Index = [int]$Context.StepIndex; Title = $Title; State = $(if ($Skipped) { 'skipped' } else { 'running' }); StartedUtc = $now; EndedUtc = $(if ($Skipped) { $now } else { '' }) }
    [void]$Context['StepLog'].Add($logEntry)
    if ($Skipped) {
        Write-PraEvent -Kind step -Data @{ index = $Context.StepIndex; total = $total; title = $Title; id = $stepId; state = 'skipped'; startedUtc = $now; endedUtc = $now }
    }
    else {
        $Context['_PraOpenStep'] = @{ Index = $Context.StepIndex; Total = $total; Title = $Title; Id = $stepId; StartedUtc = $now; Log = $logEntry
            IssueBase = $(if ($null -ne $issues) { [int]$issues.Count } else { 0 }); WarningBase = [int](Get-PraValue $Context 'Warnings' 0) }
        Write-PraEvent -Kind step -Data @{ index = $Context.StepIndex; total = $total; title = $Title; id = $stepId; state = 'running'; startedUtc = $now; endedUtc = $null }
    }
}

function Write-PraSummary {
    <#
    .SYNOPSIS
        Final summary card:

          ╭─ √  Convert finished ──────────────────────────────────────────────────────╮
               √  Result     2 done · 0 pending · 0 errors
               ■  Batch      490cc62e  (Backups\Batch-490cc62e...)
          ╰────────────────────────────────────────────────────────────────────────────╯
    .PARAMETER Values
        Ordered list: key = label, value = @(IconName, Text) or plain text. A text can be an array
        (several lines under the same label).
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][hashtable]$Context, [Parameter(Mandatory)][string]$Title,
        [Parameter(Mandatory)][System.Collections.Specialized.OrderedDictionary]$Values, [ValidateSet('Ok','Warn','Fail')][string]$Status = 'Ok')
    $F = $script:Frame; $T = $script:Theme; $width = 76
    $color = @{ Ok=$T.Ok; Warn=$T.Warn; Fail=$T.Fail }[$Status]
    $icon = $script:Icons[@{ Ok='Done'; Warn='Warn'; Fail='Fail' }[$Status]]
    $iconWidth = if ((Test-PraOrdinalIgnoreCaseEqual $script:IconStyle 'Emoji')) { 2 } else { $icon.Length }
    $head = " $icon  $Title "
    $rest = [Math]::Max(2, $width - 1 - ($head.Length - $icon.Length + $iconWidth))
    Write-Host ''
    Write-PraHost @('  ', ($F.TopLeft + $F.Horizontal), $head, (($F.Horizontal * $rest) + $F.TopRight)) -Color $color
    foreach ($key in $Values.Keys) {
        $value = $Values[$key]
        $rowIcon = '   '; $text = $value
        if ($value -is [array] -and $value.Count -eq 2 -and $script:Icons.ContainsKey([string]$value[0])) { $rowIcon = Get-PraIcon $value[0]; $text = $value[1] }
        $first = $true
        foreach ($line in @($text)) {
            $label = if ($first) { '{0,-11}' -f $key } else { ' ' * 11 }
            $iconText = if ($first) { $rowIcon } else { '   ' }
            Write-PraHost @('     ', $iconText, $label, (' ' + $line))
            Write-PraLogFile -Context $Context -Level 'INFO' -Message ('Summary - {0}: {1}' -f $key, $line)
            $first = $false
        }
    }
    Write-PraHost @(,@(('  ' + $F.BottomLeft + ($F.Horizontal * $width) + $F.BottomRight), $color))
    $eventValues = [ordered]@{}
    foreach ($key in $Values.Keys) {
        $value = $Values[$key]
        $text = if ($value -is [array] -and $value.Count -eq 2 -and $script:Icons.ContainsKey([string]$value[0])) { $value[1] } else { $value }
        $eventValues[$key] = @(@($text) | ForEach-Object { [string]$_ })
    }
    Write-PraEvent -Kind summary -Data @{ title = $Title; status = $Status; values = $eventValues }
}
#endregion

#region 3. Configuration ----------------------------------------------------------------------

function Resolve-PraPath {
    <#
    .SYNOPSIS
        Full path of a file or folder; a relative path is relative to the tool folder.
    .DESCRIPTION
        Invalid characters (often a line break pasted with the path) are reported with their
        position and Unicode code instead of being removed silently.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][AllowEmptyString()][string]$Path, [string]$Name = 'Path', [Parameter(Mandatory)][string]$Root)
    $invalid = [IO.Path]::GetInvalidPathChars(); $count = 0; $positions = @()
    for ($i = 0; $i -lt $Path.Length; $i++) {
        if ([Array]::IndexOf($invalid, $Path[$i]) -ge 0) {
            $count++
            if ($positions.Count -lt 8) { $positions += ('{0}:U+{1:X4}' -f $i, [int][char]$Path[$i]) }
        }
    }
    if ($count) {
        throw ('Invalid path in {0}: length={1}, invalid characters={2}, positions (0-based UTF-16)={3}, others={4}. Retype the value (a pasted line break is the usual cause).' -f $Name, $Path.Length, $count, ($positions -join ', '), ($count - $positions.Count))
    }
    if ([IO.Path]::IsPathRooted($Path)) { return [IO.Path]::GetFullPath($Path) }
    return [IO.Path]::GetFullPath((Join-Path $Root $Path))
}

function Add-PraNativeImport {
    <# One kernel32 import, emitted with Reflection.Emit: DllImport with SetLastError = true (the Win32 error is kept for Marshal.GetLastWin32Error / Get-PraWin32ErrorText). #>
    param([Parameter(Mandatory)][Reflection.Emit.TypeBuilder]$Type, [Parameter(Mandatory)][string]$Name, [string]$EntryPoint = '', [Parameter(Mandatory)][Type]$Return, [Parameter(Mandatory)][Type[]]$Parameters)
    if (-not $EntryPoint) { $EntryPoint = $Name }
    $method = $Type.DefineMethod($Name, 'Public,Static,PinvokeImpl,HideBySig', $Return, $Parameters)
    $method.SetImplementationFlags([Reflection.MethodImplAttributes]::PreserveSig)
    $import = [Runtime.InteropServices.DllImportAttribute]
    $attribute = New-Object Reflection.Emit.CustomAttributeBuilder($import.GetConstructor([Type[]]@([string])), [object[]]@('kernel32.dll'),
        [Reflection.FieldInfo[]]@($import.GetField('EntryPoint'), $import.GetField('CharSet'), $import.GetField('SetLastError')),
        [object[]]@($EntryPoint, [Runtime.InteropServices.CharSet]::Unicode, $true))
    $method.SetCustomAttribute($attribute)
}

function Get-PraWin32ErrorText {
    <# '<code>: <system message>' for a Win32 error code (Marshal.GetLastWin32Error after a native call). #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][int]$Code)
    return ('{0}: {1}' -f $Code, (New-Object ComponentModel.Win32Exception($Code)).Message)
}

function Get-PraNativePathApi {
    <# Two kernel32 calls (open a handle, read its final path) bound in memory with Reflection.Emit (static AssemblyBuilder.DefineDynamicAssembly, one-argument DefineDynamicModule and CreateType: the same calls in every PowerShell edition): no compiler, temporary file, DLL or cache. #>
    if ($script:PraNativePath) { return $script:PraNativePath }
    $assembly = [Reflection.Emit.AssemblyBuilder]::DefineDynamicAssembly((New-Object Reflection.AssemblyName 'PraNativePath'), [Reflection.Emit.AssemblyBuilderAccess]::Run)
    $type = $assembly.DefineDynamicModule('PraNativePath').DefineType('Api', 'Public,Class,Sealed,Abstract')
    Add-PraNativeImport -Type $type -Name 'CreateFileW' -Return ([Microsoft.Win32.SafeHandles.SafeFileHandle]) -Parameters ([Type[]]@([string], [uint32], [uint32], [IntPtr], [uint32], [uint32], [IntPtr]))
    Add-PraNativeImport -Type $type -Name 'GetFinalPathNameByHandleW' -Return ([uint32]) -Parameters ([Type[]]@([Microsoft.Win32.SafeHandles.SafeFileHandle], [Text.StringBuilder], [uint32], [uint32]))
    $script:PraNativePath = $type.CreateType()
    return $script:PraNativePath
}

function Get-PraNativeProcessApi {
    <#
    CreateProcessW and its structures, bound in memory with Reflection.Emit exactly like Get-PraNativePathApi (no compiler, temporary file, DLL or cache). Used by the
    window to start the engine child with its own console while its three standard streams stay redirected. Every import keeps the Win32 error (SetLastError = true).
    Returns a table: Api (the static class), StartupInfo (STARTUPINFOW), StartupInfoEx (STARTUPINFOEXW: StartupInfo + lpAttributeList),
    ProcessInformation. Api methods: CreateProcessW (STARTUPINFOW), CreateProcessEx (the same native CreateProcessW with a STARTUPINFOEXW, for a handle list),
    InitializeProcThreadAttributeList, UpdateProcThreadAttribute, DeleteProcThreadAttributeList, GetExitCodeProcess, CloseHandle.
    #>
    if ($script:PraNativeProcess) { return $script:PraNativeProcess }
    $assembly = [Reflection.Emit.AssemblyBuilder]::DefineDynamicAssembly((New-Object Reflection.AssemblyName 'PraNativeProcess'), [Reflection.Emit.AssemblyBuilderAccess]::Run)
    $module = $assembly.DefineDynamicModule('PraNativeProcess')
    $startup = $module.DefineType('PraStartupInfo', 'Public,SequentialLayout,Sealed', [ValueType])
    foreach ($field in @(@('cb', [uint32]), @('lpReserved', [IntPtr]), @('lpDesktop', [IntPtr]), @('lpTitle', [IntPtr]), @('dwX', [uint32]), @('dwY', [uint32]),
            @('dwXSize', [uint32]), @('dwYSize', [uint32]), @('dwXCountChars', [uint32]), @('dwYCountChars', [uint32]), @('dwFillAttribute', [uint32]),
            @('dwFlags', [uint32]), @('wShowWindow', [uint16]), @('cbReserved2', [uint16]), @('lpReserved2', [IntPtr]),
            @('hStdInput', [IntPtr]), @('hStdOutput', [IntPtr]), @('hStdError', [IntPtr]))) { [void]$startup.DefineField($field[0], $field[1], 'Public') }
    $startupType = $startup.CreateType()
    $startupEx = $module.DefineType('PraStartupInfoEx', 'Public,SequentialLayout,Sealed', [ValueType])
    [void]$startupEx.DefineField('StartupInfo', $startupType, 'Public'); [void]$startupEx.DefineField('lpAttributeList', [IntPtr], 'Public')
    $startupExType = $startupEx.CreateType()
    $information = $module.DefineType('PraProcessInformation', 'Public,SequentialLayout,Sealed', [ValueType])
    foreach ($field in @(@('hProcess', [IntPtr]), @('hThread', [IntPtr]), @('dwProcessId', [uint32]), @('dwThreadId', [uint32]))) { [void]$information.DefineField($field[0], $field[1], 'Public') }
    $informationType = $information.CreateType()
    $type = $module.DefineType('Api', 'Public,Class,Sealed,Abstract')
    $createParameters = @([string], [Text.StringBuilder], [IntPtr], [IntPtr], [bool], [uint32], [IntPtr], [string])
    Add-PraNativeImport -Type $type -Name 'CreateProcessW' -Return ([bool]) -Parameters ([Type[]]($createParameters + @($startupType.MakeByRefType(), $informationType.MakeByRefType())))
    Add-PraNativeImport -Type $type -Name 'CreateProcessEx' -EntryPoint 'CreateProcessW' -Return ([bool]) -Parameters ([Type[]]($createParameters + @($startupExType.MakeByRefType(), $informationType.MakeByRefType())))
    Add-PraNativeImport -Type $type -Name 'InitializeProcThreadAttributeList' -Return ([bool]) -Parameters ([Type[]]@([IntPtr], [int], [int], [IntPtr].MakeByRefType()))
    Add-PraNativeImport -Type $type -Name 'UpdateProcThreadAttribute' -Return ([bool]) -Parameters ([Type[]]@([IntPtr], [uint32], [IntPtr], [IntPtr], [IntPtr], [IntPtr], [IntPtr]))
    Add-PraNativeImport -Type $type -Name 'DeleteProcThreadAttributeList' -Return ([void]) -Parameters ([Type[]]@([IntPtr]))
    Add-PraNativeImport -Type $type -Name 'GetExitCodeProcess' -Return ([bool]) -Parameters ([Type[]]@([IntPtr], [uint32].MakeByRefType()))
    Add-PraNativeImport -Type $type -Name 'CloseHandle' -Return ([bool]) -Parameters ([Type[]]@([IntPtr]))
    $script:PraNativeProcess = @{ Api = $type.CreateType(); StartupInfo = $startupType; StartupInfoEx = $startupExType; ProcessInformation = $informationType }
    return $script:PraNativeProcess
}

function Read-PraCsvText {
    <#
    .SYNOPSIS
        Text of a CSV file written by a person: a byte order mark (UTF-8, UTF-16) is honoured, a BOM-less file is read as strict
        UTF-8, and a file that is not valid UTF-8 (Excel "CSV", Notepad "ANSI") is read with the system ANSI code page.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path)
    $bytes = [IO.File]::ReadAllBytes($Path)
    if ($bytes.Length -ge 3 -and $bytes[0] -eq 0xEF -and $bytes[1] -eq 0xBB -and $bytes[2] -eq 0xBF) { return [Text.Encoding]::UTF8.GetString($bytes, 3, $bytes.Length - 3) }
    if ($bytes.Length -ge 2 -and $bytes[0] -eq 0xFF -and $bytes[1] -eq 0xFE) { return [Text.Encoding]::Unicode.GetString($bytes, 2, $bytes.Length - 2) }
    if ($bytes.Length -ge 2 -and $bytes[0] -eq 0xFE -and $bytes[1] -eq 0xFF) { return [Text.Encoding]::BigEndianUnicode.GetString($bytes, 2, $bytes.Length - 2) }
    try { return (New-Object Text.UTF8Encoding($false, $true)).GetString($bytes) }
    catch [Text.DecoderFallbackException] {
        try { $ansi = [Text.Encoding]::GetEncoding([Globalization.CultureInfo]::CurrentCulture.TextInfo.ANSICodePage) }
        catch { $ansi = [Text.Encoding]::GetEncoding(1252) }
        return $ansi.GetString($bytes)
    }
}

function Get-PraPhysicalPath {
    <#
    .SYNOPSIS
        Physical location of a path as the filesystem resolves it (junctions, symbolic links, SUBST and mapped drives,
        8.3 names, \\?\ prefixes), even when its last folders do not exist yet.
    .DESCRIPTION
        The deepest existing ancestor is opened and its final path read from the handle; the missing folders are
        appended unchanged. Anything that cannot be resolved throws: a path is never assumed to be elsewhere.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path)
    $full = [IO.Path]::GetFullPath($Path)
    if ($full -match '^\\\\[?.]\\') {
        if (@($full.Split('\') | Select-Object -Skip 3 | Where-Object { [string]::Equals($_, '.', [StringComparison]::Ordinal) -or [string]::Equals($_, '..', [StringComparison]::Ordinal) }).Count) { throw "Path $Path uses a device namespace with relative segments; it cannot be resolved safely." }
    }
    $existing = $full.TrimEnd('\')
    if ($existing -match '^[A-Za-z]:$' -or $existing -match '^\\\\[?.]\\[A-Za-z]:$') { $existing += '\' }
    $missing = New-Object Collections.Generic.List[string]
    while (-not ([IO.Directory]::Exists($existing) -or [IO.File]::Exists($existing))) {
        $parent = [IO.Path]::GetDirectoryName($existing)
        if (-not $parent) { throw "Path $Path cannot be resolved: neither it nor any parent exists, so its physical location is unknown." }
        $missing.Insert(0, [IO.Path]::GetFileName($existing))
        $existing = $parent
    }
    $native = if ($existing -match '^\\\\[?.]\\') { $existing }
              elseif ($existing.StartsWith('\\', [StringComparison]::Ordinal)) { '\\?\UNC\' + $existing.Substring(2) }
              else { '\\?\' + $existing }
    $api = Get-PraNativePathApi
    $handle = $api::CreateFileW($native, [uint32]0, [uint32]7, [IntPtr]::Zero, [uint32]3, [uint32]0x02000000, [IntPtr]::Zero)
    try {
        if ($handle.IsInvalid) { throw "Path $Path cannot be resolved: the filesystem refused to open $existing." }
        $buffer = New-Object Text.StringBuilder 1024
        $length = $api::GetFinalPathNameByHandleW($handle, $buffer, [uint32]$buffer.Capacity, [uint32]0)
        if ($length -gt $buffer.Capacity) {
            $buffer = New-Object Text.StringBuilder ([int]$length + 1)
            $length = $api::GetFinalPathNameByHandleW($handle, $buffer, [uint32]$buffer.Capacity, [uint32]0)
        }
        if ($length -eq 0 -or $length -gt $buffer.Capacity) { throw "Path $Path cannot be resolved: the final path of $existing is unavailable." }
        $physical = $buffer.ToString()
    }
    finally { if ($handle) { $handle.Dispose() } }
    if ($physical.StartsWith('\\?\UNC\', [StringComparison]::OrdinalIgnoreCase)) { $physical = '\\' + $physical.Substring(8) }
    elseif ($physical -match '^\\\\\?\\[A-Za-z]:\\') { $physical = $physical.Substring(4) }
    elseif ($physical.StartsWith('\\?\', [StringComparison]::Ordinal)) { throw "Path $Path cannot be resolved to a drive or share path ($physical); refusing the ambiguous namespace." }
    foreach ($name in $missing) { $physical = $physical.TrimEnd('\') + '\' + $name }
    return $physical
}

function Assert-PraOutputFolder {
    <#
    .SYNOPSIS
        Refuses an output folder inside the authenticated package other than its own canonical folder.
    .DESCRIPTION
        The package integrity check treats every file of the package as stable except the generated root
        folders Backups, logs and reports (exact case). A backup, log or report folder anywhere else inside
        the package would make the next start fail, so it is refused here, before any file is created. The
        test uses the physical location of the package and of the folder (Get-PraPhysicalPath), so a \\?\ prefix,
        an 8.3 name, a junction, SUBST or a legacy alias such as 'Documents and Settings' cannot hide the package;
        a path that cannot be resolved is refused. The returned path is the one to use: the physical path when
        it is inside the package, otherwise the configured folder unchanged.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path, [Parameter(Mandatory)][string]$Name, [Parameter(Mandatory)][string]$Canonical, [Parameter(Mandatory)][string]$Root)
    $rootFull = [IO.Path]::GetFullPath($Root).TrimEnd('\')
    $full = [IO.Path]::GetFullPath($Path)
    if ($full.Length -gt [IO.Path]::GetPathRoot($full).Length) { $full = $full.TrimEnd('\') }
    $lexical = [string]::Equals($full, $rootFull, [StringComparison]::OrdinalIgnoreCase) -or $full.StartsWith($rootFull + '\', [StringComparison]::OrdinalIgnoreCase)
    if ($lexical) {
        $relative = $full.Substring($rootFull.Length).TrimStart('\')
        $first = if ($relative) { $relative.Split('\')[0] } else { '' }
        if (-not [string]::Equals($first, $Canonical, [StringComparison]::Ordinal)) {
            throw "Configuration: $Name ($full) is inside the signed package and is not the $Canonical folder. Use '.\$Canonical' (a sub-folder of it is accepted) or a folder outside the package; any other folder inside the package would break package integrity."
        }
        $current = $rootFull
        foreach ($segment in $relative.Split('\')) {
            $current = $current + '\' + $segment
            if (-not (Test-Path -LiteralPath $current)) { break }
            if ((Get-Item -LiteralPath $current -Force).Attributes -band [IO.FileAttributes]::ReparsePoint) {
                throw "Configuration: $Name goes through a reparse point inside the package ($current); the integrity check refuses it."
            }
        }
    }
    try {
        $physicalRoot = (Get-PraPhysicalPath $rootFull).TrimEnd('\')
        $physical = (Get-PraPhysicalPath $full).TrimEnd('\')
    }
    catch { throw "Configuration: $Name ($full) cannot be checked against the signed package, so it is refused: $($_.Exception.Message)" }
    $inside = [string]::Equals($physical, $physicalRoot, [StringComparison]::OrdinalIgnoreCase) -or $physical.StartsWith($physicalRoot + '\', [StringComparison]::OrdinalIgnoreCase)
    if (-not $inside) {
        if ($lexical) { throw "Configuration: $Name ($full) is inside the signed package but resolves outside it ($physical); the location is ambiguous and is refused." }
        return $full
    }
    $relative = $physical.Substring($physicalRoot.Length).TrimStart('\')
    $first = if ($relative) { $relative.Split('\')[0] } else { '' }
    if (-not [string]::Equals($first, $Canonical, [StringComparison]::Ordinal)) {
        throw "Configuration: $Name ($full) resolves to $physical, inside the signed package, and is not the $Canonical folder. Use '.\$Canonical' (a sub-folder of it is accepted) or a folder outside the package; any other folder inside the package would break package integrity."
    }
    $current = $physicalRoot
    foreach ($segment in $relative.Split('\')) {
        $current = $current + '\' + $segment
        if (-not (Test-Path -LiteralPath $current)) { break }
        if ((Get-Item -LiteralPath $current -Force).Attributes -band [IO.FileAttributes]::ReparsePoint) {
            throw "Configuration: $Name goes through a reparse point inside the package ($current); the integrity check refuses it."
        }
    }
    return $physical
}
function New-PraPrivateDirectorySecurity {
    <#
    .SYNOPSIS
        ACL of every folder that can hold AD values or run evidence: full control for the current account, SYSTEM and
        Administrators only, no inherited permission. Shared by the backups, logs and reports folders.
    #>
    [CmdletBinding()]
    [OutputType([Security.AccessControl.DirectorySecurity])]
    param()
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent().User
    $acl = New-Object Security.AccessControl.DirectorySecurity
    $acl.SetAccessRuleProtection($true, $false)
    $acl.SetOwner($identity)
    foreach ($sid in @($identity.Value, 'S-1-5-18', 'S-1-5-32-544') | Get-PraOrdinalUnique -IgnoreCase) {
        $rule = New-Object Security.AccessControl.FileSystemAccessRule(
            (New-Object Security.Principal.SecurityIdentifier($sid)),
            [Security.AccessControl.FileSystemRights]::FullControl,
            ([Security.AccessControl.InheritanceFlags]'ContainerInherit,ObjectInherit'),
            [Security.AccessControl.PropagationFlags]::None, [Security.AccessControl.AccessControlType]::Allow)
        [void]$acl.AddAccessRule($rule)
    }
    return $acl
}

function Initialize-PraPrivateFolder {
    <#
    .SYNOPSIS
        Makes sure a log or report folder exists. A missing folder is created WITH the private ACL of the backups (no
        window where files inherit broader rights); an existing folder is left exactly as the administrator set it.
    .DESCRIPTION
        Not subject to -WhatIf / -Confirm: the audit trail of a Preview must be written too.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path)
    if (Test-Path -LiteralPath $Path -PathType Container) { return }
    if (Test-Path -LiteralPath $Path) { throw "A file exists where the folder is expected: $Path" }
    # Missing parent folders are created with NORMAL inheritance (the administrator's choice); only the leaf gets the private ACL,
    # in one step (no moment where files inherit broader rights).
    $parent = [IO.Path]::GetDirectoryName([IO.Path]::GetFullPath($Path))
    if ($parent) { [void][IO.Directory]::CreateDirectory($parent) }
    $info = New-Object IO.DirectoryInfo $Path
    [IO.FileSystemAclExtensions]::Create($info, (New-PraPrivateDirectorySecurity))
    if (-not ([IO.FileSystemAclExtensions]::GetAccessControl($info)).AreAccessRulesProtected) { throw "Folder ACL is not protected: $Path" }
}

function Merge-PraConfiguration {
    <# Adds the missing keys from the defaults and checks the type of every known key. #>
    param([hashtable]$Values, [hashtable]$Defaults, [string]$Prefix = '')
    foreach ($key in $Defaults.Keys) {
        if (-not $Values.ContainsKey($key)) { $Values[$key] = $Defaults[$key]; continue }
        $value = $Values[$key]; $default = $Defaults[$key]
        if ($default -is [hashtable]) {
            if ($value -isnot [hashtable]) { throw "Configuration: $Prefix$key must be a section @{ ... }." }
            Merge-PraConfiguration $value $default "$Prefix$key."
        }
        elseif ($default -is [bool] -and $value -isnot [bool]) { throw "Configuration: $Prefix$key must be `$true or `$false." }
        elseif ($default -is [string] -and $value -isnot [string]) { throw "Configuration: $Prefix$key must be text between quotes." }
        elseif ($default -is [int] -and $value -isnot [int]) { throw "Configuration: $Prefix$key must be a whole number." }
        elseif ($default -is [array] -and $value -isnot [array]) { throw "Configuration: $Prefix$key must be a list @( ... )." }
    }
    foreach ($key in @($Values.Keys)) {
        if (-not $Defaults.ContainsKey($key)) { throw "Configuration: unknown setting $Prefix$key (check the spelling, see the guide chapter 6)." }
    }
}

function Get-PraDefaultConfiguration {
    <#
    Default values of every setting (the reference list of the valid keys). They are the same values as the shipped
    config\PraRemoteMailbox.config.psd1 (checked by the tests): a key left out of a configuration behaves as the
    shipped file says, not differently.
    #>
    return @{
        Environment = 'PROD'
        DomainController = ''
        Scope = @{ Mode='OU'; SearchBase=''; GroupDN=''; CsvPath=''; IncludeShared=$true; IncludeRoom=$false; IncludeEquip=$false; ExcludeSamAccountNames=@() }
        Remote = @{ RecipientType=1; HandleArchives=$true; ClearMailboxGuid=$true }
        Routing = @{ AutoDetect=$true; RoutingDomain='' }
        Licensing = @{ Enabled=$true; GroupDN='' }
        SharedMailbox = @{
            Enabled=$true; RemoteRecipientType=97; PermissionSource='AD'; CsvPath=''; CustomAttribute='extensionAttribute1'
            CaptureSendOnBehalf=$true; GrantFullAccess=$true; GrantSendAs=$true; GrantSendOnBehalf=$true; AutoMapping=$true
            KeepCloudSharedOnRecover=$false; DeferOnPremRestore=$false; ExcludeTrusteeSamAccountNames=@()
        }
        Directory = @{ ForceReplication=$false; ReplicationTargets=@(); ReplicationVerifyAttempts=6; ReplicationVerifyDelaySeconds=10 }
        EntraConnect = @{ Sync=$true; Server=''; PolicyType='Delta'; TimeoutMinutes=15 }
        Cloud = @{
            TenantId=''; Organization=''; AppId=''; CertificateThumbprint=''; UserPrincipalName=''
            CheckMailbox=$true; CheckLicense=$true; MailboxCheckVia='Exo'; RequiredSkuPartNumber=''
        }
        Exo = @{ MinModuleVersion='3.10.0'; UseSubprocess=$false; DisableWAM=$false; GrantVerifyAttempts=13; GrantVerifyDelaySeconds=10 }
        Polling = @{ IntervalMinutes=1; TimeoutMinutes=60 }
        Retention = @{ Enabled=$true; PolicyName='PRA-Converted-Retention'; PolicyGuid=''; UseComplianceSession=$false; Tag=@{ Enabled=$true; Attribute='extensionAttribute1'; Value='Converted' } }
        Execution = @{ Phase='Both' }
        Storage = @{ BackupFolder='.\Backups'; ForbiddenBackupRoots=@() }
        Logging = @{ Folder='.\logs' }
        Report = @{ Enabled=$true; Folder='.\reports' }
    }
}

function Get-PraTargetOverride {
    <# Run-specific targeting; the original data file is never rewritten. #>
    [CmdletBinding()]
    param([string]$SearchBase = '', [string]$CsvPath = '', [string]$Identity = '')
    foreach ($value in @($SearchBase,$CsvPath)) {
        if ($value -match '[\x00-\x1f]' -or ($value -and [string]::IsNullOrWhiteSpace($value))) { throw 'Target OU/CSV contains an empty value or a control character.' }
    }
    if ($SearchBase -and $CsvPath) { throw 'Choose one source: SearchBase (OU) or CsvPath, not both.' }
    if ($Identity -and ($SearchBase -or $CsvPath)) { throw 'Identity cannot be combined with a selected OU or CSV.' }
    if ($SearchBase) { return @{ Mode='OU'; SearchBase=$SearchBase.Trim(); CsvPath=''; GroupDN='' } }
    if ($CsvPath) { return @{ Mode='Csv'; CsvPath=$CsvPath.Trim(); SearchBase=''; GroupDN='' } }
    return @{}
}

function Read-PraTargetCsv {
    <# Same local validation in the window and the engine; directory eligibility is checked later. #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path)
    $text = Read-PraCsvText -Path $Path
    if ([string]::IsNullOrWhiteSpace($text)) { throw "The target CSV file is empty: $Path" }
    $header = ($text -split '\r?\n',2)[0]
    $delimiter = if ($header -match '(?i)(^|,)\s*"?Identity"?\s*(,|$)') { ',' }
        elseif ($header -match '(?i)(^|;)\s*"?Identity"?\s*(;|$)') { ';' }
        else { throw 'The target CSV requires an Identity column (UPN, sAMAccountName, DN or GUID).' }
    $rows = @(ConvertFrom-Csv -InputObject $text -Delimiter $delimiter -ErrorAction Stop)
    if (-not $rows.Count) { throw "The target CSV file has no objects: $Path" }
    foreach ($row in $rows) {
        $identity = [string](Get-PraValue $row 'Identity' '')
        if ([string]::IsNullOrWhiteSpace($identity) -or $identity -match '[\x00-\x1f]') { throw 'A line of the target CSV file has no valid Identity: batch refused.' }
        [pscustomobject]@{ Identity=$identity.Trim() }
    }
}

function Import-PraConfiguration {
    <#
    .SYNOPSIS
        Reads the configuration file, adds the default values, checks every value and resolves the paths.
    .PARAMETER Path
        The .psd1 configuration file.
    .PARAMETER Root
        Tool folder: relative paths in the file are relative to it.
    .OUTPUTS
        Hashtable. Paths (Storage.BackupFolder, Logging.Folder, Report.Folder, Scope.CsvPath,
        SharedMailbox.CsvPath, Storage.ForbiddenBackupRoots) are returned as full paths.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path, [Parameter(Mandatory)][string]$Root, [hashtable]$ScopeOverride = @{})
    $file = Resolve-PraPath $Path 'ConfigPath' $Root
    if (-not (Test-Path -LiteralPath $file -PathType Leaf)) { throw "Configuration file not found: $file" }
    $config = Import-PowerShellDataFile -LiteralPath $file -ErrorAction Stop
    Merge-PraConfiguration $config (Get-PraDefaultConfiguration)
    foreach ($key in $ScopeOverride.Keys) {
        if (-not (Test-PraOrdinalIn $key @('Mode','SearchBase','CsvPath','GroupDN')) -or $ScopeOverride[$key] -isnot [string]) { throw 'Unsupported target scope override.' }
        $config.Scope[$key] = $ScopeOverride[$key]
    }

    if ($config.Environment -notmatch '^[A-Za-z0-9_.-]{1,64}\z') { throw 'Configuration: Environment must be 1 to 64 letters, digits, dot, dash or underscore (it is used in file names).' }
    if ($config.DomainController -and $config.DomainController -notmatch '^[A-Za-z0-9.-]+\z') { throw 'Configuration: DomainController must be a host name.' }
    $scope = $config.Scope
    if (-not (Test-PraOrdinalIn $scope.Mode @('Auto','OU','Group','Csv'))) { throw 'Configuration: Scope.Mode must be Auto, OU, Group or Csv.' }
    if ((Test-PraOrdinalIgnoreCaseEqual $scope.Mode 'OU') -and -not $scope.SearchBase) { throw 'Configuration: Scope.Mode = OU requires Scope.SearchBase (a search of the whole domain needs Mode = Auto).' }
    if ((Test-PraOrdinalIgnoreCaseEqual $scope.Mode 'Group') -and -not $scope.GroupDN) { throw 'Configuration: Scope.Mode = Group requires Scope.GroupDN.' }
    if ((Test-PraOrdinalIgnoreCaseEqual $scope.Mode 'Csv') -and -not $scope.CsvPath) { throw 'Configuration: Scope.Mode = Csv requires Scope.CsvPath.' }
    if ((-not (Test-PraOrdinalIn ($config.Remote.RecipientType) @(1,3) -IgnoreCase))) { throw 'Configuration: Remote.RecipientType must be 1 (provision a mailbox) or 3 (mailbox + archive).' }
    if ($config.Routing.RoutingDomain -and $config.Routing.RoutingDomain -notmatch '^[A-Za-z0-9.-]+\.[A-Za-z]{2,}\z') { throw 'Configuration: Routing.RoutingDomain must be a domain name (tenant.mail.onmicrosoft.com).' }
    if ($config.Licensing.Enabled -and -not $config.Licensing.GroupDN) { throw 'Configuration: Licensing.Enabled requires Licensing.GroupDN.' }
    $shared = $config.SharedMailbox
    if ((-not (Test-PraOrdinalIn $shared.RemoteRecipientType @(97,99,100,102) -IgnoreCase))) { throw 'Configuration: SharedMailbox.RemoteRecipientType must be 97 or 99 (100/102 are accepted only to read old backups).' }
    if (-not (Test-PraOrdinalIn $shared.PermissionSource @('AD','Csv','CustomAttribute','None'))) { throw 'Configuration: SharedMailbox.PermissionSource must be AD, Csv, CustomAttribute or None.' }
    if ((Test-PraOrdinalIgnoreCaseEqual $shared.PermissionSource 'Csv') -and -not $shared.CsvPath) { throw 'Configuration: SharedMailbox.PermissionSource = Csv requires SharedMailbox.CsvPath.' }
    if ($shared.CustomAttribute -notmatch '^extensionAttribute([1-9]|1[0-5])\z') { throw 'Configuration: SharedMailbox.CustomAttribute must be extensionAttribute1 to extensionAttribute15.' }
    $replication = $config.Directory
    if ($replication.ReplicationVerifyAttempts -lt 1 -or $replication.ReplicationVerifyAttempts -gt 30 -or $replication.ReplicationVerifyDelaySeconds -lt 1 -or $replication.ReplicationVerifyDelaySeconds -gt 60) {
        throw 'Configuration: Directory.ReplicationVerifyAttempts must be 1..30 and Directory.ReplicationVerifyDelaySeconds 1..60.'
    }
    foreach ($replicationTarget in @($replication.ReplicationTargets)) {
        if ([string]$replicationTarget -notmatch '^[A-Za-z0-9.-]+\z') { throw 'Configuration: Directory.ReplicationTargets must be a list of domain controller host names.' }
    }
    $sync = $config.EntraConnect
    if (-not (Test-PraOrdinalIn $sync.PolicyType @('Delta','Initial'))) { throw 'Configuration: EntraConnect.PolicyType must be Delta or Initial.' }
    if ($sync.TimeoutMinutes -lt 1 -or $sync.TimeoutMinutes -gt 240) { throw 'Configuration: EntraConnect.TimeoutMinutes must be between 1 and 240.' }
    if ($sync.Server -and $sync.Server -notmatch '^[A-Za-z0-9.-]+\z') { throw 'Configuration: EntraConnect.Server must be a host name (empty = this server).' }
    $cloud = $config.Cloud
    if (-not (Test-PraOrdinalIn $cloud.MailboxCheckVia @('Graph','Exo'))) { throw 'Configuration: Cloud.MailboxCheckVia must be Exo or Graph.' }
    if ([bool]$cloud.AppId -ne [bool]$cloud.CertificateThumbprint) { throw 'Configuration: Cloud.AppId and Cloud.CertificateThumbprint go together (both set = certificate sign-in, both empty = interactive sign-in).' }
    if ($cloud.AppId) {
        # Certificate (app-only) sign-in cannot work without the tenant: refuse it at load, not in the middle of a run.
        if (-not $cloud.Organization) { throw 'Configuration: Cloud.AppId (certificate sign-in) requires Cloud.Organization, the initial domain of the tenant (tenant.onmicrosoft.com).' }
        $tenantGuid = [guid]::Empty
        if (-not [guid]::TryParse([string]$cloud.TenantId, [ref]$tenantGuid) -or $tenantGuid -eq [guid]::Empty) { throw 'Configuration: Cloud.AppId (certificate sign-in) requires Cloud.TenantId, the GUID of the tenant.' }
    }
    $exo = $config.Exo
    if ($exo.GrantVerifyAttempts -lt 1 -or $exo.GrantVerifyAttempts -gt 60 -or $exo.GrantVerifyDelaySeconds -lt 1 -or $exo.GrantVerifyDelaySeconds -gt 30) {
        throw 'Configuration: Exo.GrantVerifyAttempts must be 1..60 and Exo.GrantVerifyDelaySeconds 1..30.'
    }
    try { $null = [version]$exo.MinModuleVersion } catch { throw 'Configuration: Exo.MinModuleVersion must be a version number (3.10.0).' }
    if ($config.Polling.IntervalMinutes -lt 1 -or $config.Polling.TimeoutMinutes -lt 1) { throw 'Configuration: Polling.IntervalMinutes and Polling.TimeoutMinutes must be at least 1.' }
    $retention = $config.Retention
    if ($retention.Tag.Attribute -notmatch '^extensionAttribute([1-9]|1[0-5])\z') { throw 'Configuration: Retention.Tag.Attribute must be extensionAttribute1 to extensionAttribute15.' }
    if ($retention.Enabled -and $retention.Tag.Enabled -and -not $retention.Tag.Value) { throw 'Configuration: Retention.Tag.Value is empty.' }
    if (-not (Test-PraOrdinalIn $config.Execution.Phase @('Both','AD','Cloud'))) { throw 'Configuration: Execution.Phase must be Both, AD or Cloud.' }

    $config.Storage.BackupFolder = Resolve-PraPath $config.Storage.BackupFolder 'Storage.BackupFolder' $Root
    $config.Storage.ForbiddenBackupRoots = @(foreach ($forbidden in $config.Storage.ForbiddenBackupRoots) { (Resolve-PraPath ([string]$forbidden) 'Storage.ForbiddenBackupRoots' $Root).TrimEnd('\') + '\' })
    $config.Logging.Folder = Resolve-PraPath $config.Logging.Folder 'Logging.Folder' $Root
    $config.Report.Folder = Resolve-PraPath $config.Report.Folder 'Report.Folder' $Root
    $config.Storage.BackupFolder = Assert-PraOutputFolder $config.Storage.BackupFolder 'Storage.BackupFolder' 'Backups' $Root
    $config.Logging.Folder = Assert-PraOutputFolder $config.Logging.Folder 'Logging.Folder' 'logs' $Root
    $config.Report.Folder = Assert-PraOutputFolder $config.Report.Folder 'Report.Folder' 'reports' $Root
    foreach ($section in @('Scope','SharedMailbox')) {
        if ($config[$section].CsvPath) { $config[$section].CsvPath = Resolve-PraPath $config[$section].CsvPath ($section + '.CsvPath') $Root }
    }
    $config['_Path'] = $file
    return $config
}
#endregion

#region 4. Audit ------------------------------------------------------------------------------

function Get-PraArtifactStem {
    <# Unique, file-name safe prefix of the log, transcript and report files of this run. #>
    [CmdletBinding()]
    param([hashtable]$Context)
    $id = ([string]$Context.RunId -replace '[^a-zA-Z0-9_.-]', '_')
    if ($id.Length -gt 80) { $id = $id.Substring(0, 80) }
    return ('PRA_{0}_{1}' -f $id, [guid]::NewGuid().ToString('N').Substring(0, 8))
}

function Wait-PraTranscriptFile {
    <#
    .SYNOPSIS
        Waits until the transcript file really exists and is not empty.
    .DESCRIPTION
        Windows PowerShell 5.1 can return from Start-Transcript before the file is created. The first
        console output starts it; this function waits for it (up to 5 s) instead of creating a
        replacement file. A missing or empty transcript stops the run (no audit, no processing).
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$LiteralPath, [ValidateRange(1,60000)][int]$TimeoutMilliseconds = 5000)
    $clock = [Diagnostics.Stopwatch]::StartNew()
    do {
        if (Test-Path -LiteralPath $LiteralPath -PathType Leaf -ErrorAction Stop) {
            if ((Get-Item -LiteralPath $LiteralPath -ErrorAction Stop).Length -gt 0) { return }
        }
        if ($clock.ElapsedMilliseconds -ge $TimeoutMilliseconds) { break }
        Start-Sleep -Milliseconds 50
    } while ($true)
    throw "The transcript file is missing or empty after ${TimeoutMilliseconds} ms: $LiteralPath. No audit, no processing."
}

function Initialize-PraAudit {
    <#
    .SYNOPSIS
        Creates the log file of the run and starts the PowerShell transcript. Any failure stops the run.
    .DESCRIPTION
        Both files are created in $Context.LogFolder with a unique name; an existing file is never
        overwritten and a transcript started by someone else is left untouched. When reports are
        enabled, the report folder is also checked (a probe file is created and deleted).
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][hashtable]$Context)
    $Context.LogFile = ''
    try {
        if ($null -ne $script:TranscriptOwner) { throw 'A transcript of this module is already running.' }
        $stem = Get-PraArtifactStem $Context
        $Context['_PraArtifactStem'] = $stem
        $Context.CurrentOperation = 'Create-Log'
        Initialize-PraPrivateFolder -Path $Context.LogFolder
        $logPath = Join-Path $Context.LogFolder ($stem + '.log')
        $null = New-Item -ItemType File -Path $logPath -WhatIf:$false -Confirm:$false -ErrorAction Stop
        $Context.LogFile = $logPath
        $transcript = Join-Path $Context.LogFolder ($stem + '.transcript.txt')
        $Context.TranscriptPath = $transcript
        $Context.CurrentOperation = 'Start-Transcript'; $Context['_PraTranscriptCreated'] = $false
        # Never Stop-Transcript first and never -Append: a transcript started by someone else stays intact.
        Start-Transcript -Path $transcript -NoClobber -WhatIf:$false -Confirm:$false -ErrorAction Stop | Out-Null
        $Context.TranscriptStarted = $true; $script:TranscriptOwner = $Context
        # The first host output makes Windows PowerShell 5.1 create the file.
        Write-PraLog -Context $Context -Message ("Audit: host=$($Host.Name) PowerShell=$($PSVersionTable.PSVersion) transcript=$transcript") -Level Debug
        Write-Host ''
        $Context.CurrentOperation = 'Wait-TranscriptFile'
        Wait-PraTranscriptFile -LiteralPath $transcript
        $Context['_PraTranscriptCreated'] = $true
        $Context.CurrentOperation = 'Check-ReportFolder'
        if (-not $Context.NoReport) {
            Initialize-PraPrivateFolder -Path $Context.ReportFolder
            $probe = Join-Path $Context.ReportFolder ($stem + '.probe'); $created = $false
            try {
                $null = New-Item -ItemType File -Path $probe -WhatIf:$false -Confirm:$false -ErrorAction Stop; $created = $true
                Set-Content -LiteralPath $probe -Value 'PRA audit probe' -Encoding UTF8 -WhatIf:$false -Confirm:$false -ErrorAction Stop
            } finally { if ($created) { Remove-Item -LiteralPath $probe -WhatIf:$false -Confirm:$false -ErrorAction Stop } }
        }
        Write-PraLog $Context ('Audit started: run {0}, version {1}, account {2}, computer {3}' -f $Context.RunId, $Context.Version, [Security.Principal.WindowsIdentity]::GetCurrent().Name, $env:COMPUTERNAME) -Level Detail
    } catch {
        Write-PraLog $Context ('Audit could not start: {0}' -f $_.Exception.Message) -Level Error
        throw
    }
}
#endregion

#region 5. Results ----------------------------------------------------------------------------

function Get-PraOutcome {
    <#
    .SYNOPSIS
        Result rows (one per object + one per run error not attached to an object), counters and exit code.
    .DESCRIPTION
        Exit code: 0 = done, 1 = failed (any error), 2 = done but at least one object is Pending
        (a next step is needed, e.g. the cloud phase or Finalize).
    #>
    [CmdletBinding()]
    param([hashtable]$Context)
    $rows = New-Object 'System.Collections.Generic.List[object]'
    $errorIdentities = @{}
    foreach ($row in $Context.Rows.ToArray()) {
        $copy = [ordered]@{}
        # Same lookup as Get-PraValue (missing and $null both give $null), inlined: this loop runs 22 times per row on very large runs.
        foreach ($field in $script:RowFields) {
            $value = $null
            if ($row -is [System.Collections.IDictionary]) { foreach ($entry in $row.GetEnumerator()) { if ([string]::Equals([string]$entry.Key, $field, [StringComparison]::OrdinalIgnoreCase)) { $value = $entry.Value; break } } }
            elseif ($null -ne $row) { $property = $row.PSObject.Properties[$field]; if ($null -ne $property) { $value = $property.Value } }
            $copy[$field] = $value
        }
        $copy.PermMissing = $copy.PermMissing -join '; '
        if (-not (Test-PraOrdinalIn $copy.FinalStatus $script:FinalStatuses)) {
            $copy.Detail = 'Final status missing or invalid: {0}. {1}' -f $copy.FinalStatus, $copy.Detail; $copy.FinalStatus = 'Error'
        }
        if (Test-PraOrdinalEqual $copy.FinalStatus 'Error') {
            foreach ($field in @('ObjectGuid','SamAccountName','UserPrincipalName')) { if ($copy[$field]) { $errorIdentities[[string]$copy[$field]] = $true } }
        }
        [void]$rows.Add([pscustomobject]$copy)
    }
    foreach ($issue in $Context.Issues.ToArray()) {
        $identity = [string](Get-PraValue $issue 'Identity' '')
        $source = [string](Get-PraValue $issue 'Source' 'Execution')
        if ((Test-PraOrdinalEqual $source 'Execution') -and $identity -and $errorIdentities.ContainsKey($identity)) { continue }
        $failure = [ordered]@{}
        foreach ($field in $script:RowFields) { $failure[$field] = $null }
        $failure.Action = $Context.Action; $failure.UserPrincipalName = $identity
        $failure.FinalStatus = 'Error'; $failure.LastOperation = Get-PraValue $issue 'Operation' ''
        $failure.Detail = '[Run/{0}] {1}' -f $source, (Get-PraValue $issue 'Message' ([string]$issue))
        [void]$rows.Add([pscustomobject]$failure)
    }
    $counts = @{ Success = 0; Error = 0; Pending = 0; Skipped = 0; Planned = 0 }
    foreach ($row in $rows) {
        $key = [string]$row.FinalStatus
        if (Test-PraOrdinalEqual $key 'AlreadyDone') { $key = 'Success' }
        $counts[$key]++
    }
    $requested = [string](Get-PraValue $Context 'ResultStatus' '')
    $code = 0; $status = 'Success'
    if ($counts.Error -gt 0 -or $Context.Issues.Count -gt 0 -or [int]$Context.ExitCode -eq 1 -or $Context.CloudConnectFailed -or (Test-PraOrdinalIgnoreCaseEqual $requested 'Failed')) {
        $code = 1; $status = 'Failed'
    } elseif ($counts.Pending -gt 0) { $code = 2; $status = 'Pending' }
    elseif ((-not (Test-PraOrdinalIgnoreCaseEqual $Context.Mode 'Apply')) -and $counts.Planned -gt 0) { $status = 'Planned' }
    return [pscustomobject]@{ Rows = $rows.ToArray(); Counts = $counts; Status = $status; ExitCode = $code }
}

function ConvertTo-PraHtmlText {
    param([AllowNull()][object]$Value)
    if ($null -eq $Value) { return '' }
    return [Net.WebUtility]::HtmlEncode([string]$Value)
}

$script:ReportChunkRows = 20000
$script:ReportChunkChars = 4000000
$script:JsonEscape = New-Object Text.RegularExpressions.Regex('["\\\u0000-\u001f\u007f-\u009f\u2028\u2029<>&]')
$script:JsonEscapeEvaluator = [Text.RegularExpressions.MatchEvaluator]{
    param($m)
    # On the character CODE, never on the string: PowerShell string comparison (switch, -eq, -ceq) is culture-aware and, with the ICU
    # collation of .NET on PowerShell 7, ignores control characters (U+0001 -eq U+0008), which would write \b for U+0001.
    $code = [int][char]$m.Value
    switch ($code) {
        34 { '\"' } 92 { '\\' } 10 { '\n' } 13 { '\r' } 9 { '\t' } 8 { '\b' } 12 { '\f' }
        default { '\u' + $code.ToString('x4') }
    }
}

function ConvertTo-PraJsonString {
    <#
    .SYNOPSIS
        JSON string literal of a text. Quotes, backslashes, control characters, the HTML-significant characters
        < > & and the line separators U+2028/U+2029 are escaped, so the result is safe in a script element.
    #>
    [CmdletBinding()]
    param([AllowNull()][object]$Value)
    if ($null -eq $Value) { return 'null' }
    $Text = [string]$Value
    if ($script:JsonEscape.IsMatch($Text)) { return '"' + $script:JsonEscape.Replace($Text, $script:JsonEscapeEvaluator) + '"' }
    return '"' + $Text + '"'
}

function Get-PraReportScalar {
    <#
    .SYNOPSIS
        Keeps strings, booleans and finite numbers as they are and converts any other value to its text.
    #>
    [CmdletBinding()]
    param([AllowNull()][object]$Value)
    if ($null -eq $Value -or $Value -is [string] -or $Value -is [bool]) { return $Value }
    if ($Value -is [int] -or $Value -is [long]) { return $Value }
    if (($Value -is [double] -or $Value -is [single]) -and -not ([double]::IsNaN([double]$Value) -or [double]::IsInfinity([double]$Value))) { return $Value }
    if ($Value -is [decimal]) { return $Value }
    return [string]$Value
}

function ConvertTo-PraJsonScalar {
    [CmdletBinding()]
    param([AllowNull()][object]$Value)
    if ($null -eq $Value) { return 'null' }
    if ($Value -is [string]) { return (ConvertTo-PraJsonString $Value) }
    if ($Value -is [bool]) { if ($Value) { return 'true' } else { return 'false' } }
    if ($Value -is [double] -or $Value -is [single]) { return ([double]$Value).ToString('R', [Globalization.CultureInfo]::InvariantCulture) }
    return ([IFormattable]$Value).ToString($null, [Globalization.CultureInfo]::InvariantCulture)
}

function Write-PraReportChunks {
    <#
    .SYNOPSIS
        Writes items as gzip+base64 chunks of dictionary-indexed columns (script elements of type
        application/x-pra-chunk). Each chunk holds at most ChunkRows items and about ChunkChars characters of the
        long text fields, so memory stays bounded whatever the number of items. Dictionary index 0 is null.
        Returns the number of chunks.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][IO.TextWriter]$Writer, [Parameter(Mandatory)][string]$Kind,
        [AllowEmptyCollection()][object[]]$Items, [Parameter(Mandatory)][string[]]$Fields, [string[]]$SizeFields = @(),
        [int]$ChunkRows = $script:ReportChunkRows, [int]$ChunkChars = $script:ReportChunkChars
    )
    $dictionaries = @(for ($f = 0; $f -lt $Fields.Count; $f++) { ,(New-Object 'Collections.Generic.Dictionary[object,int]') })
    $utf8 = New-Object Text.UTF8Encoding($false)
    $jsonEscape = $script:JsonEscape; $jsonEvaluator = $script:JsonEscapeEvaluator
    $position = 0; $chunks = 0
    while ($position -lt $Items.Count) {
        $end = $position; $chars = 0
        while ($end -lt $Items.Count -and ($end - $position) -lt $ChunkRows) {
            $item = $Items[$end]
            foreach ($sizeField in $SizeFields) { $text = $item.$sizeField; if ($text -is [string]) { $chars += $text.Length } }
            if ($chars -gt $ChunkChars -and $end -gt $position) { break }
            $end++
        }
        $count = $end - $position
        $slice = New-Object object[] $count
        [Array]::Copy($Items, $position, $slice, 0, $count)
        $json = New-Object Text.StringBuilder
        $indexes = New-Object Text.StringBuilder
        [void]$json.Append('{"n":').Append($count).Append(',"d":[')
        for ($f = 0; $f -lt $Fields.Count; $f++) {
            $name = $Fields[$f]; $dictionary = $dictionaries[$f]
            $column = New-Object int[] $count
            $added = New-Object 'Collections.Generic.List[string]'
            if ($chunks -eq 0) { $added.Add('null') }
            $k = 0
            for ($i = 0; $i -lt $count; $i++) {
                $value = $slice[$i].$name
                if ($null -eq $value) { continue }
                if ($value -isnot [string] -and $value -isnot [bool]) { $value = Get-PraReportScalar $value }
                if ($dictionary.TryGetValue($value, [ref]$k)) { $column[$i] = $k }
                else {
                    $k = $dictionary.Count + 1
                    $dictionary.Add($value, $k)
                    if ($value -is [string]) {
                        if ($jsonEscape.IsMatch($value)) { $added.Add('"' + $jsonEscape.Replace($value, $jsonEvaluator) + '"') } else { $added.Add('"' + $value + '"') }
                    } elseif ($value -is [bool]) { if ($value) { $added.Add('true') } else { $added.Add('false') } }
                    else { $added.Add((ConvertTo-PraJsonScalar $value)) }
                    $column[$i] = $k
                }
            }
            if ($f) { [void]$json.Append(',') ; [void]$indexes.Append(',') }
            [void]$json.Append('[').Append([string]::Join(',', $added)).Append(']')
            [void]$indexes.Append('[').Append([string]::Join(',', $column)).Append(']')
        }
        [void]$json.Append('],"c":[').Append($indexes.ToString()).Append(']}')
        $memory = New-Object IO.MemoryStream
        $gzip = New-Object IO.Compression.GZipStream($memory, [IO.Compression.CompressionMode]::Compress, $true)
        try { $bytes = $utf8.GetBytes($json.ToString()); $gzip.Write($bytes, 0, $bytes.Length) } finally { $gzip.Dispose() }
        $Writer.Write('<script type="application/x-pra-chunk" data-kind="' + $Kind + '" data-seq="' + $chunks + '">')
        $Writer.Write([Convert]::ToBase64String($memory.ToArray()))
        $Writer.Write("</script>`r`n")
        $memory.Dispose()
        $chunks++; $position = $end
    }
    return $chunks
}

function Write-PraReportHtml {
    <#
    .SYNOPSIS
        Streams the HTML report (templates\Report.template.html) to a writer. The header, the tiles and the next
        steps are HTML-encoded markup; the object rows (the 22 fields of the CSV), the run errors and the warnings are
        written by Write-PraReportChunks. Used by Write-PraReport (file) and Get-PraReportHtml (string).
    #>
    [CmdletBinding()]
    param([hashtable]$Context, $Outcome, [Parameter(Mandatory)][IO.TextWriter]$Writer,
        [int]$ChunkRows = $script:ReportChunkRows, [int]$ChunkChars = $script:ReportChunkChars)
    $templatePath = Join-Path $Context.Root 'templates\Report.template.html'
    $template = if (Test-Path -LiteralPath $templatePath -PathType Leaf) { [IO.File]::ReadAllText($templatePath, [Text.Encoding]::UTF8) }
        else { '<!doctype html><html><head><meta charset="utf-8"><title>{{TITLE}}</title></head><body><h1>{{TITLE}}</h1><p>{{SUBTITLE}}</p>{{TILES}}{{NEXT}}<p>{{DATA_NOTICE}} Template missing: only the CSV file holds the rows.</p></body></html>' }
    $c = $Outcome.Counts
    $warningList = @(@(Get-PraValue $Context 'WarningList' @()) | ForEach-Object { $_ } | Where-Object { $null -ne $_ })
    $issueList = @($Context.Issues.ToArray())
    $statusClass = @{ Success='ok'; Planned='info'; Pending='warn'; Failed='fail' }[$Outcome.Status]
    $tiles = New-Object Text.StringBuilder
    foreach ($tile in @(
            @('Result', $Outcome.Status, $statusClass), @('Objects', $Outcome.Rows.Count, ''), @('Done', $c.Success, 'ok'),
            @('Pending', $c.Pending, $(if ($c.Pending) { 'warn' } else { '' })), @('Errors', $c.Error, $(if ($c.Error) { 'fail' } else { '' })),
            @('Warnings', $warningList.Count, $(if ($warningList.Count) { 'warn' } else { '' })),
            @('Planned', $c.Planned, $(if ($c.Planned) { 'info' } else { '' })), @('Skipped', $c.Skipped, ''))) {
        [void]$tiles.AppendFormat('<div class="tile {2}"><div class="tile-label">{0}</div><div class="tile-value">{1}</div></div>', (ConvertTo-PraHtmlText $tile[0]), (ConvertTo-PraHtmlText $tile[1]), $tile[2])
    }
    $modeText = if ((Test-PraOrdinalIgnoreCaseEqual $Context.Mode 'Apply')) { 'Apply' } else { 'Preview - nothing changed' }
    $meta = [ordered]@{
        'Action' = ('{0} · phase {1} · {2}' -f $Context.Action, $Context.Phase, $modeText)
        'Environment' = [string](Get-PraValue $Context.Config 'Environment' '')
        'Batch' = [string](Get-PraValue $Context 'BatchId' '')
        'Domain controller' = [string]$Context.Server
        'Computer / account' = ('{0} · {1}\{2}' -f $env:COMPUTERNAME, $env:USERDOMAIN, $env:USERNAME)
        'Started' = ([datetime]$Context.StartTime).ToString('yyyy-MM-dd HH:mm:ss')
        'Duration' = (Format-PraDuration ((Get-Date) - [datetime]$Context.StartTime).TotalSeconds)
        'Run ID' = [string]$Context.RunId
        'Run settings changed' = ((@(Get-PraList $Context 'ConfigOverrides') | ForEach-Object { [string]$_ }) -join '; ')
    }
    $metaHtml = New-Object Text.StringBuilder
    foreach ($key in $meta.Keys) { if ($meta[$key]) { [void]$metaHtml.AppendFormat('<div><span>{0}</span>{1}</div>', (ConvertTo-PraHtmlText $key), (ConvertTo-PraHtmlText $meta[$key])) } }
    $next = @(@(Get-PraValue $Context 'NextSteps' @()) | ForEach-Object { $_ } | Where-Object { $_ })
    $nextHtml = ''
    if ($next.Count) { $nextHtml = '<section class="card next"><h2>Next step</h2>' + (($next | ForEach-Object { '<pre>' + (ConvertTo-PraHtmlText $_) + '</pre>' }) -join '') + '</section>' }
    $notice = '{0} object row(s), {1} run error(s) and {2} warning(s) are stored in this file.' -f $Outcome.Rows.Count, $issueList.Count, $warningList.Count
    $values = @{
        '{{TITLE}}' = ConvertTo-PraHtmlText ('PRA Remote Mailbox - {0}' -f $Context.Action)
        '{{SUBTITLE}}' = ConvertTo-PraHtmlText ('{0} · {1}' -f $modeText, ([datetime]$Context.StartTime).ToString('yyyy-MM-dd HH:mm'))
        '{{VERSION}}' = ConvertTo-PraHtmlText $Context.Version
        '{{META}}' = $metaHtml.ToString(); '{{TILES}}' = $tiles.ToString(); '{{NEXT}}' = $nextHtml
        '{{DATA_NOTICE}}' = ConvertTo-PraHtmlText $notice
        '{{ROWS_TABLE}}' = ''; '{{ISSUES}}' = ''; '{{WARNINGS}}' = ''
    }
    foreach ($key in $values.Keys) { $template = $template.Replace($key, $values[$key]) }
    $marker = '{{DATA}}'
    $at = $template.LastIndexOf($marker, [StringComparison]::Ordinal)
    if ($at -lt 0) { $Writer.Write($template); return }
    $Writer.Write($template.Substring(0, $at))

    $issueItems = foreach ($issue in $issueList) {
        [pscustomobject]@{ Timestamp = [string](Get-PraValue $issue 'Timestamp' ''); Phase = [string](Get-PraValue $issue 'Phase' ''); Operation = [string](Get-PraValue $issue 'Operation' '')
            Identity = [string](Get-PraValue $issue 'Identity' ''); Source = [string](Get-PraValue $issue 'Source' ''); Message = [string](Get-PraValue $issue 'Message' ([string]$issue)) }
    }
    $warningItems = foreach ($warning in $warningList) {
        [pscustomobject]@{ Timestamp = [string](Get-PraValue $warning 'Timestamp' ''); Phase = [string](Get-PraValue $warning 'Phase' ''); Message = [string](Get-PraValue $warning 'Message' ([string]$warning)) }
    }
    $issueFields = @('Timestamp','Phase','Operation','Identity','Source','Message'); $warningFields = @('Timestamp','Phase','Message')
    $rowItems = [object[]]@($Outcome.Rows)
    $rowChunks = Write-PraReportChunks -Writer $Writer -Kind 'rows' -Items $rowItems -Fields $script:RowFields -SizeFields @('Detail','CloudDetail','PermDetail','Warnings') -ChunkRows $ChunkRows -ChunkChars $ChunkChars
    $issueChunks = Write-PraReportChunks -Writer $Writer -Kind 'issues' -Items ([object[]]@($issueItems)) -Fields $issueFields -SizeFields @('Message') -ChunkRows $ChunkRows -ChunkChars $ChunkChars
    $warningChunks = Write-PraReportChunks -Writer $Writer -Kind 'warnings' -Items ([object[]]@($warningItems)) -Fields $warningFields -SizeFields @('Message') -ChunkRows $ChunkRows -ChunkChars $ChunkChars
    $statuses = ($script:FinalStatuses | ForEach-Object { ConvertTo-PraJsonString $_ }) -join ','
    $fieldsJson = ($script:RowFields | ForEach-Object { ConvertTo-PraJsonString $_ }) -join ','
    $json = '{{"format":1,"statuses":[{0}],"rows":{{"count":{1},"fields":[{2}]}},"issues":{{"count":{3},"fields":[{4}],"titles":["Time","Step","Operation","Object","Source","Message"]}},"warnings":{{"count":{5},"fields":[{6}],"titles":["Time","Step","Message"]}},"chunks":{{"rows":{7},"issues":{8},"warnings":{9}}}}}' -f
        $statuses, $rowItems.Count, $fieldsJson, $issueList.Count, (($issueFields | ForEach-Object { ConvertTo-PraJsonString $_ }) -join ','), $warningList.Count, (($warningFields | ForEach-Object { ConvertTo-PraJsonString $_ }) -join ','), $rowChunks, $issueChunks, $warningChunks
    $Writer.Write('<script type="application/json" id="pra-meta">' + $json + "</script>`r`n")
    $Writer.Write($template.Substring($at + $marker.Length))
}

function Get-PraReportHtml {
    <#
    .SYNOPSIS
        Returns the HTML report as one string (small reports, tests). It uses the same writer as the report file,
        so there is a single serializer; production code streams to the file instead (Write-PraReport).
    #>
    [CmdletBinding()]
    param([hashtable]$Context, $Outcome)
    $writer = New-Object IO.StringWriter
    try { Write-PraReportHtml -Context $Context -Outcome $Outcome -Writer $writer; return $writer.ToString() } finally { $writer.Dispose() }
}
function ConvertTo-PraCsvCell {
    <#
    .SYNOPSIS
        Neutralises a spreadsheet formula in one text cell: a value that starts with = + - @ TAB or CR gets a leading
        apostrophe (same rule as the CSV export of the HTML report). Values that do not start so are unchanged.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param([AllowNull()][AllowEmptyString()][string]$Value)
    if ($null -ne $Value -and $Value -match '^[=+\-@\t\r]') { return "'" + $Value }
    return $Value
}

function ConvertTo-PraCsvRow {
    <# Copy of a result row whose text values are safe to open in a spreadsheet (booleans and numbers are kept as they are). #>
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Row)
    $copy = [ordered]@{}
    foreach ($property in $Row.PSObject.Properties) {
        $copy[$property.Name] = if ($property.Value -is [string]) { ConvertTo-PraCsvCell $property.Value } else { $property.Value }
    }
    return [pscustomobject]$copy
}

function Write-PraReport {
    <#
    .SYNOPSIS
        Writes the CSV and HTML reports (also when there are zero rows). A failed format is recorded as
        a run error; the other format is still written, then refreshed to include that error.
    #>
    [CmdletBinding()]
    param([hashtable]$Context, [hashtable]$Reports)
    for ($attempt = 0; $attempt -lt 2; $attempt++) {
        $issueCount = $Context.Issues.Count
        foreach ($format in @('Csv','Html')) {
            if (-not $Reports[$format] -or $Reports[($format + 'Failed')]) { continue }
            try {
                $outcome = Get-PraOutcome $Context
                if ((Test-PraOrdinalIgnoreCaseEqual $format 'Csv')) {
                    if ($outcome.Rows.Count) { $outcome.Rows | ForEach-Object { ConvertTo-PraCsvRow $_ } | Export-Csv -LiteralPath $Reports.Csv -NoTypeInformation -Delimiter ';' -Encoding utf8BOM -WhatIf:$false -Confirm:$false -ErrorAction Stop }
                    else { Set-Content -LiteralPath $Reports.Csv -Value ('"' + ($script:RowFields -join '";"') + '"') -Encoding utf8BOM -WhatIf:$false -Confirm:$false -ErrorAction Stop }
                } else {
                    $stream = [IO.File]::Open($Reports.Html, [IO.FileMode]::Create, [IO.FileAccess]::Write, [IO.FileShare]::None)
                    $writer = New-Object IO.StreamWriter($stream, (New-Object Text.UTF8Encoding($true)), 65536)
                    try { Write-PraReportHtml -Context $Context -Outcome $outcome -Writer $writer } finally { $writer.Dispose() }
                }
                if (-not (Test-Path -LiteralPath $Reports[$format] -PathType Leaf) -or (Get-Item -LiteralPath $Reports[$format]).Length -eq 0) { throw 'Report missing or empty after writing.' }
            } catch { $Reports[($format + 'Failed')] = $true; Add-PraIssue $Context ('{0} report: {1}' -f $format, $_.Exception.Message) 'Report' }
        }
        if ($Context.Issues.Count -eq $issueCount) { break }
    }
}

function Complete-PraRun {
    <#
    .SYNOPSIS
        Ends every run: reports, summary card, transcript, verdict. Returns one result object (no exit).
    .DESCRIPTION
        Always called from the finally block of the entry script, also after an error. The verdict
        'RESULT: PASS' or 'RESULT: FAIL' is the last line of the log and of the transcript; it is
        added after the transcript is stopped so that a failure to stop it is still reported.
    .OUTPUTS
        PSCustomObject: RunId, Status (Success, Planned, Pending, Failed), ExitCode, counters,
        BatchId, NextSteps, file paths and Issues.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][hashtable]$Context)
    $reports = @{ Csv = ''; Html = ''; CsvFailed = $false; HtmlFailed = $false }
    $paths = @{ LogFile = ''; TranscriptPath = ''; BackupFiles = @(); StateFiles = @() }
    $safeLog = {
        param($message, $level = 'Detail')
        try { Write-PraLog $Context $message -Level $level }
        catch { $console = $Context.Clone(); $console.LogFile = ''; Write-PraLog $console $message -Level $level }
    }
    $ownsTranscript = [object]::ReferenceEquals($script:TranscriptOwner, $Context)
    if (([int]$Context.ExitCode -ne 0 -or $Context.CloudConnectFailed -or (Test-PraOrdinalIgnoreCaseEqual (Get-PraValue $Context 'ResultStatus' '') 'Failed')) -and $Context.Issues.Count -eq 0) {
        Add-PraIssue $Context 'Failure reported by the run (exit code / cloud connection).' 'Run'
    }
    foreach ($key in @('LogFile','TranscriptPath','BackupFiles','StateFiles')) {
        $candidates = Get-PraValue $Context $key
        if ((Test-PraOrdinalIn $key @('LogFile','TranscriptPath') -IgnoreCase)) { $candidates = [string]$candidates }
        if ((Test-PraOrdinalIgnoreCaseEqual $key 'TranscriptPath') -and -not (Get-PraValue $Context '_PraTranscriptCreated' $false)) { $candidates = '' }
        foreach ($path in $candidates) {
            try {
                if (-not $path -or -not (Test-Path -LiteralPath $path -PathType Leaf)) { throw 'file not found' }
                $file = Get-Item -LiteralPath $path -ErrorAction Stop
                if ($file.Length -eq 0 -and (-not (Test-PraOrdinalIgnoreCaseEqual $key 'StateFiles'))) { throw 'empty file' }
                if ((Test-PraOrdinalIn $key @('BackupFiles','StateFiles') -IgnoreCase)) { $paths[$key] += $file.FullName } else { $paths[$key] = $file.FullName }
            } catch { Add-PraIssue $Context ('Audit file {0} unavailable: {1}' -f $key, $_.Exception.Message) 'Audit' }
        }
    }
    if (-not $Context.NoReport) {
        try {
            Initialize-PraPrivateFolder -Path $Context.ReportFolder
            $stem = [string](Get-PraValue $Context '_PraArtifactStem' '')
            if (-not $stem) { $stem = Get-PraArtifactStem $Context }
            foreach ($format in @('Csv','Html')) {
                try {
                    $path = Join-Path $Context.ReportFolder ($stem + '.' + $format.ToLowerInvariant())
                    $null = New-Item -ItemType File -Path $path -WhatIf:$false -Confirm:$false -ErrorAction Stop
                    $reports[$format] = $path
                } catch { $reports[($format + 'Failed')] = $true; Add-PraIssue $Context ('{0} report cannot be created: {1}' -f $format, $_.Exception.Message) 'Report' }
            }
        } catch { Add-PraIssue $Context ('Report folder: {0}' -f $_.Exception.Message) 'Report' }
        Write-PraReport $Context $reports
    }
    # The run that ends the chain also writes the global report: every object from the first server to the last (see region 9).
    $globalReport = @{ Html = ''; Csv = '' }
    if (-not $Context.NoReport -and (Test-PraGlobalReportWanted $Context)) {
        $globalReport = Write-PraGlobalReport -Context $Context
        if ($globalReport.Html) { $Context.NextSteps = @(('Global report (every object, from the first server to this one): ' + $globalReport.Html)) + @(@(Get-PraValue $Context 'NextSteps' @()) | ForEach-Object { $_ } | Where-Object { $_ }) }
    }

    # Summary card.
    $outcome = Get-PraOutcome $Context
    # The last step ends with the run: fail when the run failed, otherwise ok or warn.
    Close-PraStepEvent -Context $Context -State $(if ($outcome.ExitCode -eq 1) { 'fail' } else { '' })
    $c = $outcome.Counts
    $isApply = (Test-PraOrdinalIgnoreCaseEqual $Context.Mode 'Apply')
    $title = switch ($outcome.Status) {
        'Failed' { '{0} stopped - see the errors below' -f $Context.Action }
        'Pending' { '{0} done - next step required' -f $Context.Action }
        'Planned' { '{0} preview - nothing was changed' -f $Context.Action }
        default { '{0} finished' -f $Context.Action }
    }
    $status = @{ Failed='Fail'; Pending='Warn'; Planned='Ok'; Success='Ok' }[$outcome.Status]
    $objects = if ($isApply -or $c.Success -or $c.Pending) { '{0} done {4} {1} pending {4} {2} error(s) {4} {3} skipped' -f $c.Success, $c.Pending, $c.Error, $c.Skipped, [char]0x00B7 }
        else { '{0} planned {3} {1} error(s) {3} {2} skipped' -f $c.Planned, $c.Error, $c.Skipped, [char]0x00B7 }
    $values = [ordered]@{ 'Result' = @('Target', $objects) }
    $batch = [string](Get-PraValue $Context 'BatchId' '')
    if ($batch) { $values['Batch'] = @('Batch', $batch) }
    $issueLines = @($Context.Issues.ToArray() | Select-Object -Last 2 | ForEach-Object {
            $message = [string](Get-PraValue $_ 'Message' ([string]$_))
            if ($message.Length -gt 240) { $message = $message.Substring(0, 237) + '...' }
            $message })
    if ($issueLines.Count) {
        if ($Context.Issues.Count -gt 2) { $issueLines = @(('{0} error(s) in total, see the log and the report' -f $Context.Issues.Count)) + $issueLines }
        $values['Error'] = @('Fail', $issueLines)
    }
    $warningList = @(@(Get-PraValue $Context 'WarningList' @()) | ForEach-Object { $_ } | Where-Object { $null -ne $_ })
    if ($warningList.Count) {
        $warningLines = @($warningList | Select-Object -Last 2 | ForEach-Object {
                $message = [string](Get-PraValue $_ 'Message' ([string]$_))
                if ($message.Length -gt 240) { $message = $message.Substring(0, 237) + '...' }
                $message })
        if ($warningList.Count -gt 2) { $warningLines = @(('{0} warning(s) in total, see the log and the report' -f $warningList.Count)) + $warningLines }
        $values['Warning'] = @('Warn', $warningLines)
        # Warnings never change the exit code; they only colour the card of a successful run.
        if ((Test-PraOrdinalIgnoreCaseEqual $status 'Ok')) { $status = 'Warn'; $title += (' {0} {1} warning(s)' -f [char]0x00B7, $warningList.Count) }
    }
    if ($paths.BackupFiles.Count) { $values['Backup'] = @('Backup', @($paths.BackupFiles)) }
    if ($reports.Html -and -not $reports.HtmlFailed) { $values['Report'] = @('Report', $reports.Html) }
    if ($globalReport.Html) { $values['Global report'] = @('Report', $globalReport.Html) }
    if ($paths.LogFile) { $values['Log'] = @('Log', $paths.LogFile) }
    $values['Duration'] = @('Clock', (Format-PraDuration ((Get-Date) - [datetime]$Context.StartTime).TotalSeconds))
    # Replication that was not confirmed on a domain controller: the instruction stays even when the run failed afterwards (a failed synchronisation, for instance).
    $unconfirmed = @(Get-PraList $Context 'ReplicationUnconfirmed')
    if ($unconfirmed.Count) {
        $replicationNote = 'Active Directory replication was NOT confirmed on: {0}. The Entra Connect synchronisation may not have seen the change: run it again later on the Entra Connect server (Start-ADSyncSyncCycle -PolicyType Delta) before relying on the cloud.' -f ($unconfirmed -join ', ')
        if (-not (Test-PraOrdinalIn $replicationNote @(Get-PraList $Context 'NextSteps'))) { $Context.NextSteps = @($replicationNote) + @(Get-PraList $Context 'NextSteps') }
    }
    $next = @(@(Get-PraValue $Context 'NextSteps' @()) | ForEach-Object { $_ } | Where-Object { $_ })
    if (($outcome.ExitCode -ne 1 -or $unconfirmed.Count) -and $next.Count) { $values['Next'] = @('Next', $next) }
    try { Write-PraSummary -Context $Context -Title $title -Values $values -Status $status }
    catch { & $safeLog ('Summary unavailable: ' + $_.Exception.Message) }
    foreach ($key in @('BackupFiles','StateFiles')) { foreach ($path in $paths[$key]) { & $safeLog ('{0}: {1}' -f $key, $path) } }
    & $safeLog ('Status {0}; total {1}; done {2}; errors {3}; pending {4}; skipped {5}; planned {6}.' -f $outcome.Status, $outcome.Rows.Count, $c.Success, $c.Error, $c.Pending, $c.Skipped, $c.Planned)

    # Stop our own transcript (never someone else's), then write the verdict.
    if ($ownsTranscript) {
        try { Stop-Transcript -ErrorAction Stop | Out-Null }
        catch { Add-PraIssue $Context ('Transcript could not be stopped: {0}' -f $_.Exception.Message) 'Audit' }
        finally { $Context.TranscriptStarted = $false; $script:TranscriptOwner = $null }
    }
    Write-PraReport $Context $reports
    $outcome = Get-PraOutcome $Context
    $verdict = if ($outcome.ExitCode -eq 1) { 'RESULT: FAIL' } else { 'RESULT: PASS' }
    try { if ($ownsTranscript -and $paths.TranscriptPath) { Add-Content -LiteralPath $paths.TranscriptPath -Value $verdict -Encoding UTF8 -WhatIf:$false -Confirm:$false -ErrorAction Stop } }
    catch { Add-PraIssue $Context ('Transcript verdict: {0}' -f $_.Exception.Message) 'Audit'; Write-PraReport $Context $reports }
    $outcome = Get-PraOutcome $Context; $beforeVerdict = $Context.Issues.Count
    $verdict = if ($outcome.ExitCode -eq 1) { 'RESULT: FAIL' } else { 'RESULT: PASS' }
    try { Write-PraLogFile -Context $Context -Level 'INFO' -Message $verdict } catch { $null = $_ }
    Write-PraHost @(,@(('  ' + $verdict), $script:Theme.Dim))
    Write-Host ''
    if ($Context.Issues.Count -ne $beforeVerdict) {
        try { if ($ownsTranscript -and $paths.TranscriptPath) { Add-Content -LiteralPath $paths.TranscriptPath -Value 'RESULT: FAIL' -Encoding UTF8 -WhatIf:$false -Confirm:$false -ErrorAction Stop } }
        catch { Add-PraIssue $Context ('Transcript verdict: {0}' -f $_.Exception.Message) 'Audit' }
        Write-PraReport $Context $reports
    }
    $outcome = Get-PraOutcome $Context
    $Context.ExitCode = $outcome.ExitCode; $Context.ResultStatus = $outcome.Status
    $result = [pscustomobject][ordered]@{
        RunId = $Context.RunId; Version = $Context.Version; Action = $Context.Action; Mode = $Context.Mode; Phase = $Context.Phase
        Status = $outcome.Status; ExitCode = $outcome.ExitCode; SuccessCount = $outcome.Counts.Success; ErrorCount = $outcome.Counts.Error
        PendingCount = $outcome.Counts.Pending; SkippedCount = $outcome.Counts.Skipped; PlannedCount = $outcome.Counts.Planned
        TotalCount = $outcome.Rows.Count; Duration = ((Get-Date) - [datetime]$Context.StartTime)
        BatchId = [string](Get-PraValue $Context 'BatchId' ''); NextSteps = [string[]]@(@(Get-PraValue $Context 'NextSteps' @()) | ForEach-Object { $_ } | Where-Object { $_ })
        Server = $Context.Server; BackupFiles = [string[]]$paths.BackupFiles; StateFiles = [string[]]$paths.StateFiles
        LogFile = $paths.LogFile; TranscriptPath = $paths.TranscriptPath
        CsvReport = $(if (-not $reports.CsvFailed) { $reports.Csv } else { '' })
        HtmlReport = $(if (-not $reports.HtmlFailed) { $reports.Html } else { '' }); Issues = [object[]]$Context.Issues.ToArray()
        WarningCount = @(@(Get-PraValue $Context 'WarningList' @()) | ForEach-Object { $_ } | Where-Object { $null -ne $_ }).Count
        Warnings = [object[]]@(@(Get-PraValue $Context 'WarningList' @()) | ForEach-Object { $_ } | Where-Object { $null -ne $_ })
        GlobalHtmlReport = [string]$globalReport.Html; GlobalCsvReport = [string]$globalReport.Csv
        TransferPackage = [string](Get-PraValue $Context 'TransferPackage' ''); TransferPackageKind = [string](Get-PraValue $Context 'TransferPackageKind' '')
        ConfigOverrides = [string[]]@(@(Get-PraValue $Context 'ConfigOverrides' @()) | ForEach-Object { $_ } | Where-Object { $_ })
    }
    Write-PraEvent -Kind result -Data @{ status = $result.Status; exitCode = $result.ExitCode
        action = $result.Action; mode = $result.Mode; phase = $result.Phase
        success = $result.SuccessCount; error = $result.ErrorCount; pending = $result.PendingCount
        skipped = $result.SkippedCount; planned = $result.PlannedCount; total = $result.TotalCount
        seconds = [int]$result.Duration.TotalSeconds; batchId = $result.BatchId; nextSteps = @($result.NextSteps)
        logFile = $result.LogFile; csvReport = $result.CsvReport; htmlReport = $result.HtmlReport; globalReport = $result.GlobalHtmlReport; globalCsvReport = $result.GlobalCsvReport
        warnings = $result.WarningCount; backupFiles = @($result.BackupFiles); stateFiles = @($result.StateFiles)
        issues = @($result.Issues | ForEach-Object { [string](Get-PraValue $_ 'Message' ([string]$_)) })
        transferPackage = $result.TransferPackage; transferPackageKind = $result.TransferPackageKind; configOverrides = @($result.ConfigOverrides) }
    return $result
}
#endregion

#region 7. Transfer package ------------------------------------------------------------------------
# One ZIP carries everything the other server needs at a hand-off (AD -> Cloud: Convert, Recover; Cloud -> AD: Finalize). The ZIP is read as hostile
# input: its sidecar hash, its manifest and the hash of EVERY entry are verified before the first byte is written to disk; names are whitelisted
# (folder/file, no separator tricks), sizes are bounded (zip bomb), and an existing folder is accepted only when it is identical.
Add-Type -AssemblyName System.IO.Compression

$script:PraTransferKinds = @{
    Convert  = @{ Direction = 'ToCloud'; Target = 'Cloud'; Prefix = 'Batch-' }
    Recover  = @{ Direction = 'ToCloud'; Target = 'Cloud'; Prefix = 'Batch-' }
    Finalize = @{ Direction = 'ToAD'; Target = 'AD'; Prefix = 'Finalize-' }
}
$script:PraTransferLimits = @{ MaxEntries = [int]2000; MaxEntryBytes = [long]268435456; MaxTotalBytes = [long]536870912; MaxManifestBytes = [long]1048576 }

function Remove-PraStaleStaging {
    <# Sweeps the staging folders ('.importing-*') that a killed import left in the backup folder (older than 15 minutes: never an import in progress). #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Root)
    if (-not [IO.Directory]::Exists($Root)) { return }
    foreach ($stale in [IO.Directory]::GetDirectories($Root, '.importing-*')) {
        try { if (([datetime]::UtcNow - [IO.Directory]::GetCreationTimeUtc($stale)).TotalMinutes -gt 15) { [IO.Directory]::Delete($stale, $true) } } catch { $null = $_ }
    }
}

function Get-PraStreamSha256 {
    <# SHA-256 (lower case hexadecimal) of the rest of a stream. #>
    param([Parameter(Mandatory)][IO.Stream]$Stream)
    $sha = [Security.Cryptography.SHA256]::Create()
    try { return ([BitConverter]::ToString($sha.ComputeHash($Stream))).Replace('-', '').ToLowerInvariant() }
    finally { $sha.Dispose() }
}

function Get-PraTransferPackageName {
    <# PRA-<Environment>-<Kind>-<first 8 characters of the batch ID>-for-<Cloud|AD>.zip #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Kind, [Parameter(Mandatory)][string]$Environment, [Parameter(Mandatory)][string]$BatchId)
    if (-not (Test-PraOrdinalIn $Kind @($script:PraTransferKinds.Keys))) { throw "Transfer package: unknown kind '$Kind'." }
    if ($Environment -notmatch '\A[A-Za-z0-9_.-]{1,64}\z') { throw 'Transfer package: Environment is not a valid file name part.' }
    if ($BatchId -notmatch '\A[0-9a-fA-F]{8,32}\z') { throw 'Transfer package: the batch ID must be 8 to 32 hexadecimal characters.' }
    return 'PRA-{0}-{1}-{2}-for-{3}.zip' -f $Environment, $Kind, $BatchId.Substring(0, 8).ToLowerInvariant(), $script:PraTransferKinds[$Kind].Target
}

function Test-PraTransferEntryName {
    <# '' when the entry name is acceptable ('transfer.json' or '<folder>/<file>'), otherwise the reason it is refused. #>
    param([AllowEmptyString()][string]$Name)
    if ([string]::IsNullOrEmpty($Name)) { return 'empty name' }
    if ($Name.Length -gt 240) { return 'name too long' }
    foreach ($character in $Name.ToCharArray()) { if ([int]$character -lt 32 -or [int]$character -eq 127) { return 'control character' } }
    if ([string]::Equals($Name, 'transfer.json', [StringComparison]::Ordinal)) { return '' }
    if ($Name.Contains('\')) { return 'backslash' }
    if ($Name.Contains('..')) { return 'parent folder (..)' }
    if ($Name.Contains(':')) { return 'drive or stream separator' }
    $match = [regex]::Match($Name, '\A(?<folder>(?:Batch|Finalize)-[A-Za-z0-9._-]{1,100})/(?<file>[A-Za-z0-9._-]{1,120})\z', [Text.RegularExpressions.RegexOptions]::CultureInvariant)
    if (-not $match.Success) { return 'not a <folder>/<file> name made of letters, digits, dot, dash and underscore' }
    $reserved = @('CON', 'PRN', 'AUX', 'NUL', 'COM1', 'COM2', 'COM3', 'COM4', 'COM5', 'COM6', 'COM7', 'COM8', 'COM9', 'LPT1', 'LPT2', 'LPT3', 'LPT4', 'LPT5', 'LPT6', 'LPT7', 'LPT8', 'LPT9')
    foreach ($part in @($match.Groups['folder'].Value, $match.Groups['file'].Value)) {
        if ($part.EndsWith('.', [StringComparison]::Ordinal)) { return 'trailing dot' }
        if (Test-PraOrdinalIn ($part.Split('.')[0]) $reserved -IgnoreCase) { return 'reserved device name' }
    }
    return ''
}

function Get-PraSafeText {
    <# A name or message from untrusted input, limited to printable ASCII and 80 characters, for an error message. #>
    param([AllowEmptyString()][string]$Text)
    $clean = [regex]::Replace($Text, '[^\x20-\x7E]', '?')
    if ($clean.Length -gt 80) { $clean = $clean.Substring(0, 80) + '...' }
    return $clean
}

function Read-PraBoundedEntry {
    <# The bytes of a ZIP entry, never more than the declared length (a lying header is a bomb) and never more than $Maximum. #>
    param([Parameter(Mandatory)]$Entry, [Parameter(Mandatory)][long]$Maximum)
    $memory = New-Object IO.MemoryStream
    $source = $Entry.Open()
    try {
        $buffer = New-Object byte[] 65536
        while (($read = $source.Read($buffer, 0, $buffer.Length)) -gt 0) {
            if ($memory.Length + $read -gt $Maximum -or $memory.Length + $read -gt $Entry.Length) { throw 'Transfer package: an entry is larger than its declared size.' }
            $memory.Write($buffer, 0, $read)
        }
        return $memory.ToArray()
    }
    finally { $source.Dispose(); $memory.Dispose() }
}

function Invoke-PraTransferPackage {
    <#
    .SYNOPSIS
        Verifies a transfer package (always) and extracts it (-Extract). Throws on the first problem. The ZIP stays open with
        FileShare.Read for the whole call, so it cannot change between the verification and the extraction.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path, [string]$Environment = '', [string]$BackupFolder = '', [switch]$Extract, [switch]$SkipSidecar, [string]$ExpectedKind = '')
    $limits = $script:PraTransferLimits
    $full = [IO.Path]::GetFullPath($Path)
    if (-not [IO.File]::Exists($full)) { throw "Transfer package: file not found: $full" }
    $stream = New-Object IO.FileStream($full, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
    $zip = $null
    $created = New-Object 'Collections.Generic.List[string]'
    try {
        $zipHash = Get-PraStreamSha256 $stream
        if (-not $SkipSidecar) {
            $sidecar = $full + '.sha256'
            if (-not [IO.File]::Exists($sidecar)) { throw 'Transfer package: the .sha256 file next to the package is missing.' }
            $token = ([IO.File]::ReadAllText($sidecar).Trim() -split '\s+')[0]
            if ($token -notmatch '\A[0-9a-fA-F]{64}\z' -or -not [string]::Equals($token, $zipHash, [StringComparison]::OrdinalIgnoreCase)) {
                throw 'Transfer package: the SHA-256 of the package does not match its .sha256 file (the file was changed or damaged).'
            }
        }
        [void]$stream.Seek(0, [IO.SeekOrigin]::Begin)
        try { $zip = New-Object IO.Compression.ZipArchive($stream, [IO.Compression.ZipArchiveMode]::Read, $true) }
        catch { throw "Transfer package: not a readable ZIP archive ($($_.Exception.Message))." }
        $entries = @($zip.Entries)
        if ($entries.Count -gt ($limits.MaxEntries + 1)) { throw 'Transfer package: too many entries.' }
        $names = New-Object 'Collections.Generic.HashSet[string]' -ArgumentList ([StringComparer]::OrdinalIgnoreCase)
        $total = [long]0; $manifestEntry = $null
        $files = New-Object 'Collections.Generic.List[object]'
        foreach ($entry in $entries) {
            $name = [string]$entry.FullName
            $problem = Test-PraTransferEntryName $name
            if ($problem) { throw ("Transfer package: refused entry '{0}' ({1})." -f (Get-PraSafeText $name), $problem) }
            if (-not $names.Add($name)) { throw ("Transfer package: duplicate entry '{0}'." -f (Get-PraSafeText $name)) }
            $isManifest = [string]::Equals($name, 'transfer.json', [StringComparison]::Ordinal)
            $maximum = if ($isManifest) { $limits.MaxManifestBytes } else { $limits.MaxEntryBytes }
            if ($entry.Length -lt 0 -or $entry.Length -gt $maximum) { throw ("Transfer package: entry '{0}' is too large." -f (Get-PraSafeText $name)) }
            $total += $entry.Length
            if ($total -gt $limits.MaxTotalBytes) { throw 'Transfer package: the content is too large (zip bomb protection).' }
            if ($isManifest) { $manifestEntry = $entry } else { $files.Add($entry) }
        }
        if ($null -eq $manifestEntry) { throw 'Transfer package: transfer.json is missing.' }
        if (-not $files.Count) { throw 'Transfer package: no file in the package.' }
        try {
            $strict = New-Object Text.UTF8Encoding($false, $true)
            $manifest = $strict.GetString((Read-PraBoundedEntry $manifestEntry $limits.MaxManifestBytes)).TrimStart([char]0xFEFF) | ConvertFrom-PraJson
        } catch { throw "Transfer package: transfer.json is not valid ($($_.Exception.Message))." }
        $schema = Get-PraValue $manifest 'SchemaVersion' $null
        if (($schema -isnot [int] -and $schema -isnot [long]) -or [int]$schema -ne 1) { throw 'Transfer package: unsupported transfer.json SchemaVersion.' }
        $kind = [string](Get-PraValue $manifest 'Kind' '')
        if (-not (Test-PraOrdinalIn $kind @($script:PraTransferKinds.Keys))) { throw 'Transfer package: unknown package kind.' }
        if ($ExpectedKind -and -not (Test-PraOrdinalEqual $kind $ExpectedKind)) { throw ("Transfer package: this is a {0} package, a {1} package is needed here." -f $kind, (Get-PraSafeText $ExpectedKind)) }
        $packageEnvironment = [string](Get-PraValue $manifest 'Environment' '')
        if ($packageEnvironment -notmatch '\A[A-Za-z0-9_.-]{1,64}\z') { throw 'Transfer package: invalid Environment in transfer.json.' }
        if ($Environment -and -not (Test-PraOrdinalEqual $packageEnvironment $Environment)) {
            throw ("Transfer package: it was made for Environment '{0}', this configuration is '{1}': refused." -f $packageEnvironment, (Get-PraSafeText $Environment))
        }
        $batchId = [string](Get-PraValue $manifest 'BatchId' '')
        if ($batchId -notmatch '\A[0-9a-fA-F]{8,32}\z') { throw 'Transfer package: invalid BatchId in transfer.json.' }
        $createdUtc = [string](Get-PraValue $manifest 'CreatedUtc' '')
        $toolVersion = [string](Get-PraValue $manifest 'ToolVersion' '')
        if (-not $createdUtc -or $createdUtc.Length -gt 64 -or $toolVersion.Length -gt 64) { throw 'Transfer package: invalid CreatedUtc or ToolVersion in transfer.json.' }
        $nextCommand = [string](Get-PraValue $manifest 'NextCommand' '')
        if ($nextCommand.Length -gt 1000) { throw 'Transfer package: invalid NextCommand in transfer.json.' }
        $listed = Get-PraValue $manifest 'Entries' @()
        $listed = @($listed)
        if (-not $listed.Count) { throw 'Transfer package: transfer.json lists no entry.' }
        $expected = New-Object 'Collections.Generic.Dictionary[string,object]' -ArgumentList ([StringComparer]::OrdinalIgnoreCase)
        foreach ($item in $listed) {
            $itemName = [string](Get-PraValue $item 'Name' '')
            $itemSize = Get-PraValue $item 'Size' $null
            $itemHash = [string](Get-PraValue $item 'Sha256' '')
            $problem = Test-PraTransferEntryName $itemName
            if ($problem -or [string]::Equals($itemName, 'transfer.json', [StringComparison]::Ordinal)) { throw ("Transfer package: transfer.json lists a refused name '{0}'." -f (Get-PraSafeText $itemName)) }
            if (($itemSize -isnot [int] -and $itemSize -isnot [long]) -or [long]$itemSize -lt 0 -or $itemHash -notmatch '\A[0-9a-fA-F]{64}\z') { throw ("Transfer package: transfer.json has an invalid size or hash for '{0}'." -f (Get-PraSafeText $itemName)) }
            if ($expected.ContainsKey($itemName)) { throw ("Transfer package: transfer.json lists '{0}' twice." -f (Get-PraSafeText $itemName)) }
            $expected[$itemName] = @{ Size = [long]$itemSize; Sha256 = $itemHash.ToLowerInvariant() }
        }
        foreach ($entry in $files) {
            $name = [string]$entry.FullName
            if (-not $expected.ContainsKey($name)) { throw ("Transfer package: unexpected entry '{0}' (not listed in transfer.json)." -f (Get-PraSafeText $name)) }
            if ([long]$expected[$name].Size -ne [long]$entry.Length) { throw ("Transfer package: the size of '{0}' differs from transfer.json." -f (Get-PraSafeText $name)) }
        }
        if ($expected.Count -ne $files.Count) { throw 'Transfer package: an entry listed in transfer.json is missing from the package.' }
        $prefix = $script:PraTransferKinds[$kind].Prefix
        $folders = @($files | ForEach-Object { ([string]$_.FullName).Split('/')[0] } | Get-PraOrdinalUnique | Sort-PraOrdinal)
        foreach ($folder in $folders) { if (-not $folder.StartsWith($prefix, [StringComparison]::Ordinal)) { throw ("Transfer package: a {0} package holds {1}* folders only." -f $kind, $prefix) } }
        if (-not (Test-PraOrdinalIn ($prefix + $batchId) $folders -IgnoreCase)) { throw 'Transfer package: the folder of the batch named in transfer.json is not in the package.' }
        # Content: hash of every entry, from the stream, with a hard bound on the bytes actually produced. Nothing is written yet.
        $buffer = New-Object byte[] 1048576
        foreach ($entry in $files) {
            $name = [string]$entry.FullName
            $hasher = [Security.Cryptography.IncrementalHash]::CreateHash([Security.Cryptography.HashAlgorithmName]::SHA256)
            $source = $entry.Open()
            try {
                $count = [long]0
                while (($read = $source.Read($buffer, 0, $buffer.Length)) -gt 0) {
                    $count += $read
                    if ($count -gt $entry.Length) { throw ("Transfer package: '{0}' is larger than its declared size (zip bomb protection)." -f (Get-PraSafeText $name)) }
                    $hasher.AppendData($buffer, 0, $read)
                }
                if ($count -ne $entry.Length) { throw ("Transfer package: '{0}' is shorter than its declared size." -f (Get-PraSafeText $name)) }
                $actual = ([BitConverter]::ToString($hasher.GetHashAndReset())).Replace('-', '').ToLowerInvariant()
            }
            finally { $source.Dispose(); $hasher.Dispose() }
            if (-not [string]::Equals($actual, [string]$expected[$name].Sha256, [StringComparison]::Ordinal)) { throw ("Transfer package: the content of '{0}' does not match its SHA-256 in transfer.json (tampered or damaged)." -f (Get-PraSafeText $name)) }
        }
        $info = [pscustomobject][ordered]@{
            Path = $full; Name = [IO.Path]::GetFileName($full); Valid = $true; Error = ''; Kind = $kind; Environment = $packageEnvironment
            CreatedUtc = $createdUtc; ToolVersion = $toolVersion; BatchId = $batchId; SizeBytes = [long]$stream.Length; EntryCount = [int]$files.Count
            Sha256 = $zipHash; Direction = [string]$script:PraTransferKinds[$kind].Direction; Folders = [string[]]$folders; NextCommand = $nextCommand
        }
        if (-not $Extract) { return $info }

        # Extraction. Every target folder is decided BEFORE anything is created: an existing folder must be identical.
        if (-not $BackupFolder) { throw 'Transfer package: the backup folder is required to import.' }
        $root = [IO.Path]::GetFullPath($BackupFolder).TrimEnd('\')
        if (-not [IO.Directory]::Exists($root)) { Initialize-PraPrivateFolder -Path $root }
        $existing = New-Object 'Collections.Generic.List[string]'
        $toCreate = New-Object 'Collections.Generic.List[string]'
        foreach ($folder in $folders) {
            $target = [IO.Path]::GetFullPath([IO.Path]::Combine($root, $folder))
            if (-not $target.StartsWith($root + '\', [StringComparison]::OrdinalIgnoreCase)) { throw 'Transfer package: a folder would leave the backup folder.' }
            if ([IO.File]::Exists($target)) { throw ("Transfer package: a file exists where the folder {0} is expected." -f $folder) }
            if (-not [IO.Directory]::Exists($target)) { $toCreate.Add($folder); continue }
            $directory = New-Object IO.DirectoryInfo $target
            if ($directory.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw ("Transfer package: the folder {0} is a reparse point." -f $folder) }
            $inFolder = @($files | Where-Object { ([string]$_.FullName).StartsWith($folder + '/', [StringComparison]::Ordinal) })
            $onDisk = @([IO.Directory]::GetFiles($target))
            if ([IO.Directory]::GetDirectories($target).Length -or $onDisk.Count -ne $inFolder.Count) {
                throw ("Transfer package: the folder {0} already exists and is different from the package: refused (nothing was changed)." -f $folder)
            }
            foreach ($entry in $inFolder) {
                $diskPath = [IO.Path]::Combine($target, ([string]$entry.FullName).Substring($folder.Length + 1))
                if (-not [IO.File]::Exists($diskPath)) { throw ("Transfer package: the folder {0} already exists and is different from the package: refused (nothing was changed)." -f $folder) }
                $diskStream = [IO.File]::Open($diskPath, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
                try {
                    $diskHash = if ($diskStream.Length -eq [long]$entry.Length) { Get-PraStreamSha256 $diskStream } else { '' }
                } finally { $diskStream.Dispose() }
                if (-not [string]::Equals($diskHash, [string]$expected[[string]$entry.FullName].Sha256, [StringComparison]::Ordinal)) {
                    throw ("Transfer package: the folder {0} already exists and is different from the package: refused (nothing was changed)." -f $folder)
                }
            }
            $existing.Add($target)
        }
        $createdPaths = New-Object 'Collections.Generic.List[string]'
        $stagingRoot = ''
        try {
            # Everything is written in a private staging folder next to the final ones, then each folder is renamed into place (same volume: one atomic
            # step). A process killed while extracting leaves only a stale '.importing-*' folder (swept by the next import), never a half-filled batch folder.
            if ($toCreate.Count) {
                Remove-PraStaleStaging -Root $root
                $stagingRoot = [IO.Path]::Combine($root, '.importing-' + [guid]::NewGuid().ToString('N'))
                [void][IO.FileSystemAclExtensions]::Create((New-Object IO.DirectoryInfo $stagingRoot), (New-PraPrivateDirectorySecurity))
            }
            foreach ($folder in $toCreate) {
                $target = [IO.Path]::GetFullPath([IO.Path]::Combine($stagingRoot, $folder))
                $directoryInfo = New-Object IO.DirectoryInfo $target
                [void][IO.FileSystemAclExtensions]::Create($directoryInfo, (New-PraPrivateDirectorySecurity))
                if (-not ([IO.FileSystemAclExtensions]::GetAccessControl($directoryInfo)).AreAccessRulesProtected) { throw "Transfer package: folder ACL is not protected: $target" }
                foreach ($entry in @($files | Where-Object { ([string]$_.FullName).StartsWith($folder + '/', [StringComparison]::Ordinal) })) {
                    $diskPath = [IO.Path]::Combine($target, ([string]$entry.FullName).Substring($folder.Length + 1))
                    $hasher = [Security.Cryptography.IncrementalHash]::CreateHash([Security.Cryptography.HashAlgorithmName]::SHA256)
                    $source = $entry.Open()
                    $destination = New-Object IO.FileStream($diskPath, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
                    try {
                        $count = [long]0
                        while (($read = $source.Read($buffer, 0, $buffer.Length)) -gt 0) {
                            $count += $read
                            if ($count -gt $entry.Length) { throw 'Transfer package: an entry grew while it was extracted.' }
                            $hasher.AppendData($buffer, 0, $read); $destination.Write($buffer, 0, $read)
                        }
                        $destination.Flush($true)
                        $written = ([BitConverter]::ToString($hasher.GetHashAndReset())).Replace('-', '').ToLowerInvariant()
                    }
                    finally { $destination.Dispose(); $source.Dispose(); $hasher.Dispose() }
                    $wanted = [string]$expected[[string]$entry.FullName].Sha256
                    if ($count -ne $entry.Length -or -not [string]::Equals($written, $wanted, [StringComparison]::Ordinal)) { throw ("Transfer package: '{0}' changed while it was extracted." -f (Get-PraSafeText ([string]$entry.FullName))) }
                    # Second, independent check: the bytes that are really on disk.
                    $check = [IO.File]::Open($diskPath, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
                    try { $onDiskHash = Get-PraStreamSha256 $check } finally { $check.Dispose() }
                    if (-not [string]::Equals($onDiskHash, $wanted, [StringComparison]::Ordinal)) { throw ("Transfer package: the file {0} written to disk does not match its SHA-256." -f (Get-PraSafeText ([string]$entry.FullName))) }
                }
            }
            foreach ($folder in $toCreate) {
                $finalPath = [IO.Path]::GetFullPath([IO.Path]::Combine($root, $folder))
                [IO.Directory]::Move([IO.Path]::Combine($stagingRoot, $folder), $finalPath)
                $created.Add($finalPath); $createdPaths.Add($finalPath)
            }
        }
        catch {
            $failure = $_
            foreach ($path in $created) { try { [IO.Directory]::Delete($path, $true) } catch { $null = $_ } }
            throw $failure
        }
        finally { if ($stagingRoot -and [IO.Directory]::Exists($stagingRoot)) { try { [IO.Directory]::Delete($stagingRoot, $true) } catch { $null = $_ } } }
        $info | Add-Member -NotePropertyName Created -NotePropertyValue ([string[]]$createdPaths.ToArray()) -PassThru |
            Add-Member -NotePropertyName Existing -NotePropertyValue ([string[]]$existing.ToArray()) -PassThru |
            Add-Member -NotePropertyName FolderPaths -NotePropertyValue ([string[]]@($folders | ForEach-Object { [IO.Path]::Combine($root, $_) })) -PassThru
    }
    finally {
        if ($null -ne $zip) { $zip.Dispose() }
        $stream.Dispose()
    }
}

function Get-PraTransferPackage {
    <#
    .SYNOPSIS
        Read-only check of a transfer package (nothing is written, nothing is thrown for a bad package).
    .OUTPUTS
        Path, Name, Valid, Error, Kind, Environment, CreatedUtc, ToolVersion, BatchId, SizeBytes, EntryCount, Sha256, Direction ('ToCloud' or 'ToAD'),
        Folders, NextCommand. Valid is $true only when the sidecar, the manifest, the Environment (when given) and every entry hash are verified.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path, [string]$Environment = '')
    $result = [pscustomobject][ordered]@{
        Path = $Path; Name = ''; Valid = $false; Error = ''; Kind = ''; Environment = ''; CreatedUtc = ''; ToolVersion = ''; BatchId = ''
        SizeBytes = [long]0; EntryCount = 0; Sha256 = ''; Direction = ''; Folders = [string[]]@(); NextCommand = ''
    }
    try {
        $result.Path = [IO.Path]::GetFullPath($Path); $result.Name = [IO.Path]::GetFileName($result.Path)
        if ([IO.File]::Exists($result.Path)) { $result.SizeBytes = ([IO.FileInfo]$result.Path).Length }
        return (Invoke-PraTransferPackage -Path $Path -Environment $Environment)
    }
    catch { $result.Error = $_.Exception.Message; return $result }
}

function Import-PraTransferPackage {
    <#
    .SYNOPSIS
        Verifies a transfer package and extracts its folders, as private folders with their original names, under the backup folder.
    .DESCRIPTION
        Throws when anything is wrong. A folder that already exists with identical content is accepted (Existing); a different one is refused
        and nothing is written. Returns Kind, BatchId, Folders (full paths), Created, Existing.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path, [Parameter(Mandatory)][string]$BackupFolder, [Parameter(Mandatory)][string]$Environment, [string]$ExpectedKind = '')
    $info = Invoke-PraTransferPackage -Path $Path -Environment $Environment -BackupFolder $BackupFolder -Extract -ExpectedKind $ExpectedKind
    return [pscustomobject][ordered]@{
        Kind = $info.Kind; BatchId = $info.BatchId; Folders = [string[]]$info.FolderPaths; Created = [string[]]$info.Created; Existing = [string[]]$info.Existing
        Name = $info.Name; Direction = $info.Direction; Sha256 = $info.Sha256
    }
}

function New-PraTransferPackage {
    <#
    .SYNOPSIS
        Writes the transfer package of a hand-off (and its .sha256) in the Outbox folder, then verifies it with the same code that imports it.
    .PARAMETER Folders
        Full paths of the folders to pack (Batch-* or Finalize-*; flat folders, every file is packed).
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Kind, [Parameter(Mandatory)][string]$Environment, [Parameter(Mandatory)][string]$BatchId,
        [Parameter(Mandatory)][string[]]$Folders, [Parameter(Mandatory)][string]$OutboxFolder, [string]$NextCommand = '', [string]$ToolVersion = '')
    $name = Get-PraTransferPackageName -Kind $Kind -Environment $Environment -BatchId $BatchId
    $limits = $script:PraTransferLimits
    $items = New-Object 'Collections.Generic.List[object]'
    foreach ($folder in $Folders) {
        $folderPath = [IO.Path]::GetFullPath($folder).TrimEnd('\')
        $folderName = [IO.Path]::GetFileName($folderPath)
        if (-not [IO.Directory]::Exists($folderPath)) { throw "Transfer package: folder not found: $folderPath" }
        if ([IO.Directory]::GetDirectories($folderPath).Length) { throw "Transfer package: the folder $folderName contains a sub-folder." }
        foreach ($file in [IO.Directory]::GetFiles($folderPath)) {
            $entryName = $folderName + '/' + [IO.Path]::GetFileName($file)
            $problem = Test-PraTransferEntryName $entryName
            if ($problem -or [string]::Equals($entryName, 'transfer.json', [StringComparison]::Ordinal)) { throw ("Transfer package: the file '{0}' cannot be packed ({1})." -f (Get-PraSafeText $entryName), $problem) }
            $stream = [IO.File]::Open($file, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
            try { $items.Add([pscustomobject]@{ Name = $entryName; Path = $file; Size = [long]$stream.Length; Sha256 = (Get-PraStreamSha256 $stream) }) }
            finally { $stream.Dispose() }
        }
    }
    if (-not $items.Count) { throw 'Transfer package: the folders hold no file.' }
    if ($items.Count -gt $limits.MaxEntries) { throw 'Transfer package: too many files.' }
    $ordered = @($items | Sort-PraOrdinal -Property Name)
    $names = New-Object 'Collections.Generic.HashSet[string]' -ArgumentList ([StringComparer]::OrdinalIgnoreCase)
    foreach ($item in $ordered) { if (-not $names.Add($item.Name)) { throw ("Transfer package: duplicate file name '{0}'." -f $item.Name) } }
    $manifest = [ordered]@{
        SchemaVersion = 1; Kind = $Kind; Environment = $Environment; CreatedUtc = [DateTime]::UtcNow.ToString('o'); ToolVersion = $ToolVersion
        BatchId = $BatchId.ToLowerInvariant(); Entries = @($ordered | ForEach-Object { [ordered]@{ Name = $_.Name; Size = $_.Size; Sha256 = $_.Sha256 } }); NextCommand = $NextCommand
    }
    Initialize-PraPrivateFolder -Path $OutboxFolder
    $final = Join-Path ([IO.Path]::GetFullPath($OutboxFolder)) $name
    foreach ($stale in [IO.Directory]::GetFiles([IO.Path]::GetFullPath($OutboxFolder), '*.tmp')) {
        try { if (([datetime]::UtcNow - [IO.File]::GetLastWriteTimeUtc($stale)).TotalHours -gt 24) { [IO.File]::Delete($stale) } } catch { $null = $_ }
    }
    $temporary = $final + '.' + [guid]::NewGuid().ToString('N').Substring(0, 8) + '.tmp'
    if ([IO.File]::Exists($final) -or [IO.File]::Exists($final + '.sha256')) { throw "Transfer package: $name already exists in the Outbox folder." }
    $stamp = [DateTimeOffset]::new(2000, 1, 1, 0, 0, 0, [TimeSpan]::Zero)
    $file = New-Object IO.FileStream($temporary, [IO.FileMode]::CreateNew, [IO.FileAccess]::ReadWrite, [IO.FileShare]::None)
    try {
        $zip = New-Object IO.Compression.ZipArchive($file, [IO.Compression.ZipArchiveMode]::Create, $true)
        try {
            $entry = $zip.CreateEntry('transfer.json', [IO.Compression.CompressionLevel]::Optimal); $entry.LastWriteTime = $stamp
            $target = $entry.Open()
            try { $bytes = (New-Object Text.UTF8Encoding($false)).GetBytes(($manifest | ConvertTo-Json -Depth 6)); $target.Write($bytes, 0, $bytes.Length) } finally { $target.Dispose() }
            foreach ($item in $ordered) {
                $entry = $zip.CreateEntry($item.Name, [IO.Compression.CompressionLevel]::Optimal); $entry.LastWriteTime = $stamp
                $target = $entry.Open()
                $source = [IO.File]::Open($item.Path, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
                try { $source.CopyTo($target) } finally { $source.Dispose(); $target.Dispose() }
            }
        }
        finally { $zip.Dispose() }
        $file.Flush($true)
    }
    catch { $file.Dispose(); try { [IO.File]::Delete($temporary) } catch { $null = $_ }; throw }
    $file.Dispose()
    try {
        # The package is verified with the importer's own code before it is published.
        $check = Invoke-PraTransferPackage -Path $temporary -Environment $Environment -SkipSidecar
        [IO.File]::Move($temporary, $final)
    }
    catch { try { [IO.File]::Delete($temporary) } catch { $null = $_ }; throw }
    $hash = $check.Sha256
    $sidecarStream = New-Object IO.FileStream(($final + '.sha256'), [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
    try { $bytes = (New-Object Text.UTF8Encoding($false)).GetBytes($hash); $sidecarStream.Write($bytes, 0, $bytes.Length); $sidecarStream.Flush($true) } finally { $sidecarStream.Dispose() }
    $verified = Invoke-PraTransferPackage -Path $final -Environment $Environment
    return [pscustomobject][ordered]@{ Path = $final; Name = $name; Sidecar = ($final + '.sha256'); Kind = $Kind; Direction = $verified.Direction; BatchId = $verified.BatchId
        SizeBytes = $verified.SizeBytes; EntryCount = $verified.EntryCount; Sha256 = $verified.Sha256; Verified = $true }
}
#endregion

#region 8. Effective run configuration -------------------------------------------------------------
# The window never edits the .psd1: it asks for a generated copy (base + the run settings that changed) in the private folder of the run. The engine
# loads that copy with the same Import-PraConfiguration, so every validation applies; its hash is part of the Preview guard of the window.

function ConvertTo-PraDataLiteral {
    <# A configuration value as a PowerShell data-file literal. Strings are single-quoted (the apostrophe and the typographic quotes are doubled). #>
    param([AllowNull()]$Value, [int]$Indent = 0)
    $pad = ' ' * ($Indent + 4); $close = ' ' * $Indent
    if ($Value -is [bool]) { return $(if ($Value) { '$true' } else { '$false' }) }
    if ($Value -is [int] -or $Value -is [long]) { return ([long]$Value).ToString([Globalization.CultureInfo]::InvariantCulture) }
    if ($Value -is [string]) {
        if ($Value -match '[\x00-\x1f\x7f]') { throw 'Configuration value with a control character.' }
        $escaped = $Value.Replace("'", "''")
        foreach ($code in @(0x2018, 0x2019, 0x201A, 0x201B)) { $quote = [string][char]$code; $escaped = $escaped.Replace($quote, $quote + $quote) }
        return "'" + $escaped + "'"
    }
    if ($Value -is [Collections.IDictionary]) {
        $keys = @($Value.Keys | ForEach-Object { [string]$_ } | Sort-PraOrdinal)
        if (-not $keys.Count) { return '@{}' }
        $lines = foreach ($key in $keys) {
            if ($key -notmatch '\A[A-Za-z][A-Za-z0-9_]{0,63}\z') { throw "Configuration key '$key' is not valid." }
            $pad + $key + ' = ' + (ConvertTo-PraDataLiteral $Value[$key] ($Indent + 4))
        }
        return "@{`r`n" + ($lines -join "`r`n") + "`r`n" + $close + '}'
    }
    if ($Value -is [Collections.IEnumerable]) {
        $items = @($Value | ForEach-Object { ConvertTo-PraDataLiteral $_ ($Indent + 4) })
        if (-not $items.Count) { return '@()' }
        return '@(' + ($items -join ', ') + ')'
    }
    throw ('Configuration value of an unsupported type: ' + $(if ($null -eq $Value) { 'null' } else { $Value.GetType().Name }))
}

function Get-PraConfigurationFlat {
    <# Dotted key -> text, for every leaf of a configuration (lists are joined with ', '); '_Path' is not a setting. #>
    param([Parameter(Mandatory)][Collections.IDictionary]$Configuration, [string]$Prefix = '')
    foreach ($key in @($Configuration.Keys | ForEach-Object { [string]$_ } | Sort-PraOrdinal)) {
        if ($key.StartsWith('_', [StringComparison]::Ordinal)) { continue }
        $value = $Configuration[$key]
        if ($value -is [Collections.IDictionary]) { Get-PraConfigurationFlat -Configuration $value -Prefix ($Prefix + $key + '.') }
        elseif ($value -is [Collections.IEnumerable] -and $value -isnot [string]) { [pscustomobject]@{ Key = $Prefix + $key; Value = (@($value | ForEach-Object { [string]$_ }) -join ', ') } }
        else { [pscustomobject]@{ Key = $Prefix + $key; Value = [string]$value } }
    }
}

function Get-PraConfigurationDifference {
    <# What the run changes compared with the configuration file: one object (Key, Base, Effective, Text = 'Key: base -> effective') per setting whose value differs. #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][Collections.IDictionary]$Base, [Parameter(Mandatory)][Collections.IDictionary]$Effective)
    $baseFlat = @{}
    foreach ($row in @(Get-PraConfigurationFlat -Configuration $Base)) { $baseFlat[$row.Key] = $row.Value }
    foreach ($row in @(Get-PraConfigurationFlat -Configuration $Effective)) {
        $before = if ($baseFlat.ContainsKey($row.Key)) { [string]$baseFlat[$row.Key] } else { '' }
        if (-not (Test-PraOrdinalEqual $before $row.Value)) {
            $beforeText = if ($before) { $before } else { '(empty)' }; $afterText = if ($row.Value) { $row.Value } else { '(empty)' }
            [pscustomobject][ordered]@{ Key = $row.Key; Base = $before; Effective = $row.Value; Text = ('{0}: {1} -> {2}' -f $row.Key, $beforeText, $afterText) }
        }
    }
}

function Get-PraOverrideKey {
    <# Dotted names of the leaves of an overrides table. #>
    param([Collections.IDictionary]$Overrides, [string]$Prefix = '')
    foreach ($key in @($Overrides.Keys | ForEach-Object { [string]$_ } | Sort-PraOrdinal)) {
        $value = $Overrides[$key]
        if ($value -is [Collections.IDictionary]) { Get-PraOverrideKey -Overrides $value -Prefix ($Prefix + $key + '.') } else { $Prefix + $key }
    }
}

function Set-PraConfigurationOverride {
    param([hashtable]$Target, [Collections.IDictionary]$Overrides, [string]$Prefix = '')
    foreach ($key in @($Overrides.Keys)) {
        if (-not $Target.ContainsKey($key)) { throw "Configuration override: unknown setting $Prefix$key." }
        $value = $Overrides[$key]
        if ($Target[$key] -is [hashtable]) {
            if ($value -isnot [Collections.IDictionary]) { throw "Configuration override: $Prefix$key is a section @{ ... }." }
            Set-PraConfigurationOverride -Target $Target[$key] -Overrides $value -Prefix ($Prefix + $key + '.')
        }
        elseif ($value -is [Collections.IDictionary]) { throw "Configuration override: $Prefix$key is not a section." }
        else { $Target[$key] = $value }
    }
}

function New-PraEffectiveConfiguration {
    <#
    .SYNOPSIS
        Writes the configuration of ONE run: the base file with the given overrides, as a new .psd1 in a private folder of the run.
    .DESCRIPTION
        The base file is only read. Unknown keys and wrong types are refused (same rules as the configuration file), the generated file is loaded again with
        Import-PraConfiguration before it is accepted, and its file ACL is private (current account, SYSTEM, Administrators). The destination must not exist.
    .OUTPUTS
        Path, Hash (SHA-256, lower case), Keys (dotted names of the overridden settings).
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$BasePath, [Parameter(Mandatory)][string]$Root, [Parameter(Mandatory)][Collections.IDictionary]$Overrides, [Parameter(Mandatory)][string]$Destination)
    $baseFile = Resolve-PraPath $BasePath 'BasePath' $Root
    if (-not [IO.File]::Exists($baseFile)) { throw "Configuration file not found: $baseFile" }
    $config = Import-PowerShellDataFile -LiteralPath $baseFile -ErrorAction Stop
    Merge-PraConfiguration $config (Get-PraDefaultConfiguration)
    Set-PraConfigurationOverride -Target $config -Overrides $Overrides
    Merge-PraConfiguration $config (Get-PraDefaultConfiguration)
    $text = "# Generated effective configuration for one run - never edit - the base file is unchanged.`r`n# Base: $($baseFile -replace '[\x00-\x1f]', '?')`r`n" + (ConvertTo-PraDataLiteral $config) + "`r`n"
    $target = [IO.Path]::GetFullPath($Destination)
    if ([IO.File]::Exists($target)) { throw "The effective configuration already exists: $target" }
    $stream = New-Object IO.FileStream($target, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
    try {
        $bytes = [byte[]](239, 187, 191) + (New-Object Text.UTF8Encoding($false)).GetBytes($text)
        $stream.Write($bytes, 0, $bytes.Length); $stream.Flush($true)
    }
    finally { $stream.Dispose() }
    try {
        $identity = [Security.Principal.WindowsIdentity]::GetCurrent().User
        $acl = New-Object Security.AccessControl.FileSecurity
        $acl.SetAccessRuleProtection($true, $false)
        foreach ($sid in @($identity.Value, 'S-1-5-18', 'S-1-5-32-544') | Get-PraOrdinalUnique -IgnoreCase) {
            [void]$acl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule((New-Object Security.Principal.SecurityIdentifier($sid)), [Security.AccessControl.FileSystemRights]::FullControl, [Security.AccessControl.AccessControlType]::Allow)))
        }
        [IO.FileSystemAclExtensions]::SetAccessControl((New-Object IO.FileInfo $target), $acl)
        $loaded = Import-PraConfiguration -Path $target -Root $Root
        $expected = $config.Environment
        if (-not (Test-PraOrdinalEqual $loaded.Environment $expected)) { throw 'The effective configuration does not round-trip.' }
        $hashStream = [IO.File]::Open($target, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
        try { $hash = Get-PraStreamSha256 $hashStream } finally { $hashStream.Dispose() }
    }
    catch { $failure = $_; try { [IO.File]::Delete($target) } catch { $null = $_ }; throw $failure }
    return [pscustomobject][ordered]@{ Path = $target; Hash = $hash; Keys = [string[]]@(Get-PraOverrideKey -Overrides $Overrides) }
}
#endregion

#region 9. Phase data and global report -------------------------------------------------------------
# With two servers each one writes its own report. So that the LAST server can follow every object from end to end, each side keeps what it did in a
# small machine-readable file (PhaseData-*.json + .sha256) in the batch folder it creates; the file travels in the transfer package with the batch
# (listed in transfer.json with its SHA-256 like every entry, so a changed file is refused at import). It is DATA FOR A REPORT: nothing in the engine
# decides anything from it. It is read as untrusted input (size, schema, checksum, Environment) and every value is HTML-encoded when it is shown.
$script:PraPhaseLimits = @{ MaxBytes = [long]67108864; MaxText = 2000; MaxStepText = 300; MaxStepsPerObject = 40; MaxJourney = 200000; MaxObjects = 200000; MaxFiles = 24; MaxIssues = 500; DetailedObjects = 2000 }
$script:PraPhaseFilter = 'PhaseData-*.json'
$script:PraNotAvailable = 'not available (folder from an older version or copied manually)'
# Display only: a Pending phase (or stage) that a later phase of the same report took over is shown as handed over; the verdict logic reads the raw status.
$script:PraHandedOver = 'Handed over'

function Limit-PraText {
    <# A text for a report: control characters replaced by a space, at most $Max characters. #>
    [CmdletBinding()]
    [OutputType([string])]
    param([AllowNull()][object]$Value, [int]$Max = 2000)
    if ($null -eq $Value) { return '' }
    $text = [regex]::Replace([string]$Value, '[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]', ' ')
    if ($text.Length -gt $Max) { return $text.Substring(0, [Math]::Max(0, $Max - 3)) + '...' }
    return $text
}

function Add-PraJourney {
    <#
    .SYNOPSIS
        Remembers one line of the journey of an object (time, step, status, text) when the current identity is a known object.
        Memory only; bounded; used by the phase data and the global report.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][hashtable]$Context, [Parameter(Mandatory)][string]$Status, [AllowEmptyString()][string]$Text)
    $identity = [string](Get-PraValue $Context 'CurrentIdentity' '')
    if (-not $identity) { return }
    $name = Get-PraEventObjectName $Context $identity
    if (-not $name) { return }
    if (-not $Context.ContainsKey('Journey')) { $Context['Journey'] = New-Object 'Collections.Generic.List[object]' }
    $list = $Context['Journey']
    if ($list.Count -ge $script:PraPhaseLimits.MaxJourney) { return }
    [void]$list.Add([pscustomobject]@{ Time = [datetime]::UtcNow.ToString('o'); Name = $name; Step = (Limit-PraText (Get-PraValue $Context 'CurrentPhase' '') 200)
            Status = $Status; Text = (Limit-PraText $Text $script:PraPhaseLimits.MaxStepText) })
}

function Get-PraPhaseSetting {
    <# The settings of the run that matter to a reader of the report (no secret, no token, no path of a private file). #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][hashtable]$Context)
    $config = Get-PraValue $Context 'Config' @{}
    $settings = [ordered]@{}
    $settings['Environment'] = [string](Get-PraValue $config 'Environment' '')
    $settings['Domain controller'] = [string](Get-PraValue $Context 'Server' '')
    $settings['Scope mode'] = [string](Get-PraValue (Get-PraValue $config 'Scope' @{}) 'Mode' '')
    $settings['Tenant'] = [string](Get-PraValue (Get-PraValue $config 'Cloud' @{}) 'Organization' '')
    $settings['Licence group'] = [string]([bool](Get-PraValue (Get-PraValue $config 'Licensing' @{}) 'Enabled' $false))
    $settings['Entra Connect sync'] = [string]([bool](Get-PraValue (Get-PraValue $config 'EntraConnect' @{}) 'Sync' $false))
    $settings['Entra Connect policy'] = [string](Get-PraValue (Get-PraValue $config 'EntraConnect' @{}) 'PolicyType' '')
    $settings['AD replication before the sync'] = [string]([bool](Get-PraValue (Get-PraValue $config 'Directory' @{}) 'ForceReplication' $false))
    return $settings
}

function New-PraPhaseRecord {
    <#
    .SYNOPSIS
        What this run did, as data: the run (server, operator, times, mode, tool version, run settings changed, steps), one entry per object (identity,
        type, final status, steps with status, time and message, warnings, backup) and the errors and warnings. Memory only.
    #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions','',Justification='In-memory constructor of report data, no change to any target or file.')]
    [CmdletBinding()]
    param([Parameter(Mandatory)][hashtable]$Context, [string]$HandOff = '', [switch]$NoSteps)
    $limits = $script:PraPhaseLimits
    $outcome = Get-PraOutcome $Context
    $byName = New-Object 'Collections.Generic.Dictionary[string,object]' -ArgumentList ([StringComparer]::OrdinalIgnoreCase)
    if (-not $NoSteps) {
        foreach ($entry in @(Get-PraList $Context 'Journey')) {
            if ($null -eq $entry) { continue }
            if (-not $byName.ContainsKey($entry.Name)) { $byName[$entry.Name] = New-Object 'Collections.Generic.List[object]' }
            if ($byName[$entry.Name].Count -lt $limits.MaxStepsPerObject) { [void]$byName[$entry.Name].Add($entry) }
        }
    }
    $objects = New-Object 'Collections.Generic.List[object]'
    foreach ($row in $Context.Rows.ToArray()) {
        if ($objects.Count -ge $limits.MaxObjects) { break }
        $guid = [string](Get-PraValue $row 'ObjectGuid' ''); $upn = [string](Get-PraValue $row 'UserPrincipalName' ''); $sam = [string](Get-PraValue $row 'SamAccountName' '')
        $name = if ($upn) { $upn } elseif ($sam) { $sam } else { $guid }
        $steps = New-Object 'Collections.Generic.List[object]'
        if (-not $NoSteps) {
            $found = $null
            if ($byName.TryGetValue($name, [ref]$found)) { foreach ($entry in $found) { [void]$steps.Add([ordered]@{ Time = $entry.Time; Step = $entry.Step; Status = $entry.Status; Text = $entry.Text }) } }
            if (-not $steps.Count) {
                # No event named this object: the steps are read from its result row.
                $now = [datetime]::UtcNow.ToString('o')
                if ([string](Get-PraValue $row 'BackupPath' '')) { [void]$steps.Add([ordered]@{ Time = $now; Step = 'Backup'; Status = 'Ok'; Text = 'Backup written' }) }
                if ((Get-PraValue $row 'ADApplied' $null) -eq $true) { [void]$steps.Add([ordered]@{ Time = $now; Step = 'Active Directory'; Status = 'Ok'; Text = 'Attributes changed' }) }
                if ((Get-PraValue $row 'ADVerified' $null) -eq $true) { [void]$steps.Add([ordered]@{ Time = $now; Step = 'Active Directory'; Status = 'Ok'; Text = 'Read back and verified' }) }
                $cloud = [string](Get-PraValue $row 'CloudStatus' '')
                if ($cloud -and -not (Test-PraOrdinalEqual $cloud 'N/A')) {
                    $cloudState = if (Test-PraOrdinalEqual $cloud 'Success') { 'Ok' } elseif (Test-PraOrdinalEqual $cloud 'Error') { 'Fail' } elseif (Test-PraOrdinalEqual $cloud 'Pending') { 'Warn' } else { 'Info' }
                    [void]$steps.Add([ordered]@{ Time = $now; Step = 'Exchange Online'; Status = $cloudState; Text = (Limit-PraText (('{0} {1}' -f $cloud, (Get-PraValue $row 'CloudDetail' '')).Trim()) $limits.MaxStepText) })
                }
            }
        }
        [void]$objects.Add([ordered]@{
                ObjectGuid = $guid; Name = (Limit-PraText $name 300); SamAccountName = (Limit-PraText $sam 300); UserPrincipalName = (Limit-PraText $upn 300)
                IsShared = [bool](Get-PraValue $row 'IsShared' $false); Action = [string](Get-PraValue $row 'Action' ''); FinalStatus = [string](Get-PraValue $row 'FinalStatus' '')
                CloudStatus = [string](Get-PraValue $row 'CloudStatus' ''); ADApplied = (Get-PraValue $row 'ADApplied' $null); ADVerified = (Get-PraValue $row 'ADVerified' $null)
                BackupPath = (Limit-PraText (Get-PraValue $row 'BackupPath' '') 500); Detail = (Limit-PraText (Get-PraValue $row 'Detail' '') $limits.MaxText)
                CloudDetail = (Limit-PraText (Get-PraValue $row 'CloudDetail' '') $limits.MaxText); Warnings = (Limit-PraText (Get-PraValue $row 'Warnings' '') $limits.MaxText)
                Steps = $steps.ToArray()
            })
    }
    $stepLog = @(@(Get-PraList $Context 'StepLog') | ForEach-Object { if ($null -ne $_) { [ordered]@{ Index = [int]$_.Index; Title = (Limit-PraText $_.Title 200); State = [string]$_.State; StartedUtc = [string]$_.StartedUtc; EndedUtc = [string]$_.EndedUtc } } })
    $issues = @($Context.Issues.ToArray() | Select-Object -First $limits.MaxIssues | ForEach-Object {
            [ordered]@{ Timestamp = [string](Get-PraValue $_ 'Timestamp' ''); Phase = (Limit-PraText (Get-PraValue $_ 'Phase' '') 200); Operation = (Limit-PraText (Get-PraValue $_ 'Operation' '') 200)
                Identity = (Limit-PraText (Get-PraValue $_ 'Identity' '') 300); Source = (Limit-PraText (Get-PraValue $_ 'Source' '') 100); Message = (Limit-PraText (Get-PraValue $_ 'Message' ([string]$_)) 1000) } })
    $warnings = @(@(Get-PraList $Context 'WarningList') | Select-Object -First $limits.MaxIssues | ForEach-Object {
            [ordered]@{ Timestamp = [string](Get-PraValue $_ 'Timestamp' ''); Phase = (Limit-PraText (Get-PraValue $_ 'Phase' '') 200); Message = (Limit-PraText (Get-PraValue $_ 'Message' ([string]$_)) 1000) } })
    $counts = $outcome.Counts
    $overrides = @(@(Get-PraList $Context 'ConfigOverrides') | ForEach-Object { if ($_) { Limit-PraText $_ 500 } })
    $runId = [string](Get-PraValue $Context 'RunId' '')
    return [ordered]@{
        SchemaVersion = 1; Kind = 'PhaseData'; Environment = [string](Get-PraValue (Get-PraValue $Context 'Config' @{}) 'Environment' ''); BatchId = [string](Get-PraValue $Context 'BatchId' '')
        ToolVersion = [string](Get-PraValue $Context 'Version' ''); Truncated = [bool]$NoSteps
        Phase = [ordered]@{
            RunId = $runId; Action = [string](Get-PraValue $Context 'Action' ''); Phase = [string](Get-PraValue $Context 'Phase' ''); Mode = [string](Get-PraValue $Context 'Mode' '')
            Computer = [string]$env:COMPUTERNAME; Account = ('{0}\{1}' -f $env:USERDOMAIN, $env:USERNAME); Server = [string](Get-PraValue $Context 'Server' '')
            StartedUtc = ([datetime](Get-PraValue $Context 'StartTime' ([datetime]::Now))).ToUniversalTime().ToString('o'); EndedUtc = [datetime]::UtcNow.ToString('o')
            Status = [string]$outcome.Status; ExitCode = [int]$outcome.ExitCode; HandOff = $HandOff; Overrides = $overrides; Settings = (Get-PraPhaseSetting $Context); Steps = $stepLog
            Counts = [ordered]@{ Success = [int]$counts.Success; Error = [int]$counts.Error; Pending = [int]$counts.Pending; Skipped = [int]$counts.Skipped; Planned = [int]$counts.Planned }
        }
        Objects = $objects.ToArray(); Issues = $issues; Warnings = $warnings
    }
}

function Save-PraPhaseData {
    <#
    .SYNOPSIS
        Writes what this run did, as PhaseData-<time>-<phase>-<run>.json and its .sha256, in a batch folder this run created (private folder: the files inherit
        its ACL). Never overwrites. The file is dropped to the steps-less form when it would be larger than the limit.
    .OUTPUTS
        The path of the file.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][hashtable]$Context, [Parameter(Mandatory)][string]$Folder, [string]$HandOff = '')
    if (-not [IO.Directory]::Exists($Folder)) { throw "Phase data: folder not found: $Folder" }
    $json = (New-PraPhaseRecord -Context $Context -HandOff $HandOff) | ConvertTo-Json -Depth 8 -Compress
    if ($json.Length -gt $script:PraPhaseLimits.MaxBytes / 4) { $json = (New-PraPhaseRecord -Context $Context -HandOff $HandOff -NoSteps) | ConvertTo-Json -Depth 8 -Compress }
    $bytes = (New-Object Text.UTF8Encoding($false)).GetBytes($json)
    if ($bytes.LongLength -gt $script:PraPhaseLimits.MaxBytes) { throw 'Phase data: the file would be larger than the limit.' }
    $runId = [string](Get-PraValue $Context 'RunId' '')
    $short = ($runId -replace '\A[^-]*-', '' -replace '[^0-9A-Za-z]', '')
    if ($short.Length -gt 8) { $short = $short.Substring(0, 8) }
    if (-not $short) { $short = [guid]::NewGuid().ToString('N').Substring(0, 8) }
    $side = ([string](Get-PraValue $Context 'Phase' '') -replace '[^0-9A-Za-z]', '')
    if (-not $side) { $side = 'Run' }
    $path = Join-Path $Folder ('PhaseData-{0}-{1}-{2}.json' -f [datetime]::UtcNow.ToString('yyyyMMddHHmmss', [Globalization.CultureInfo]::InvariantCulture), $side, $short)
    $stream = New-Object IO.FileStream($path, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
    try { $stream.Write($bytes, 0, $bytes.Length); $stream.Flush($true) } finally { $stream.Dispose() }
    $hash = New-Object IO.FileStream($path, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
    try { $digest = Get-PraStreamSha256 $hash } finally { $hash.Dispose() }
    $sidecar = New-Object IO.FileStream(($path + '.sha256'), [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
    try { $text = (New-Object Text.UTF8Encoding($false)).GetBytes($digest); $sidecar.Write($text, 0, $text.Length); $sidecar.Flush($true) } finally { $sidecar.Dispose() }
    return $path
}

function Copy-PraPhaseData {
    <# Copies the PhaseData files (and their .sha256) of the source folders into a folder this run created, so that they travel with it. A file already there is left alone. #>
    [CmdletBinding()]
    param([string[]]$SourceFolder = @(), [Parameter(Mandatory)][string]$Destination)
    $copied = 0
    foreach ($source in @($SourceFolder | Where-Object { $_ } | Get-PraOrdinalUnique -IgnoreCase)) {
        if (-not [IO.Directory]::Exists($source)) { continue }
        foreach ($file in [IO.Directory]::GetFiles($source, $script:PraPhaseFilter)) {
            foreach ($candidate in @($file, ($file + '.sha256'))) {
                if (-not [IO.File]::Exists($candidate)) { continue }
                $target = Join-Path $Destination ([IO.Path]::GetFileName($candidate))
                if ([IO.File]::Exists($target)) { continue }
                [IO.File]::Copy($candidate, $target, $false)
            }
            $copied++
        }
    }
    return $copied
}

function Read-PraPhaseData {
    <#
    .SYNOPSIS
        Reads the PhaseData files of some folders as untrusted input: size, .sha256, schema, Kind and Environment are checked; a file that fails is reported
        in Problems and ignored (the global report then says the side is not available), never trusted.
    .OUTPUTS
        Phases (validated records, as read) and Problems (texts).
    #>
    [CmdletBinding()]
    param([string[]]$Folder = @(), [string]$Environment = '')
    $limits = $script:PraPhaseLimits
    $phases = New-Object 'Collections.Generic.List[object]'
    $problems = New-Object 'Collections.Generic.List[string]'
    $seen = New-Object 'Collections.Generic.HashSet[string]' -ArgumentList ([StringComparer]::Ordinal)
    $total = 0
    foreach ($directory in @($Folder | Where-Object { $_ } | Get-PraOrdinalUnique -IgnoreCase)) {
        if (-not [IO.Directory]::Exists($directory)) { continue }
        $files = [string[]][IO.Directory]::GetFiles($directory, $script:PraPhaseFilter)
        [Array]::Sort([Array]$files, [Collections.IComparer][StringComparer]::Ordinal)
        foreach ($file in $files) {
            $leaf = Get-PraSafeText ([IO.Path]::GetFileName($file))
            $total++
            if ($total -gt $limits.MaxFiles) { $problems.Add('Phase data: too many files, the rest is ignored.'); break }
            try {
                $length = ([IO.FileInfo]$file).Length
                if ($length -lt 2 -or $length -gt $limits.MaxBytes) { throw 'the size is not acceptable' }
                $sidecar = $file + '.sha256'
                if (-not [IO.File]::Exists($sidecar)) { throw 'the .sha256 file is missing' }
                $stream = New-Object IO.FileStream($file, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
                try { $digest = Get-PraStreamSha256 $stream } finally { $stream.Dispose() }
                $token = ([IO.File]::ReadAllText($sidecar).Trim() -split '\s+')[0]
                if ($token -notmatch '\A[0-9a-fA-F]{64}\z' -or -not (Test-PraOrdinalIgnoreCaseEqual $token $digest)) { throw 'the checksum does not match (the file was changed)' }
                $record = [IO.File]::ReadAllText($file, [Text.Encoding]::UTF8) | ConvertFrom-PraJson
                $schema = Get-PraValue $record 'SchemaVersion' $null
                if (($schema -isnot [int] -and $schema -isnot [long]) -or [int]$schema -ne 1) { throw 'unsupported schema' }
                if (-not (Test-PraOrdinalEqual (Get-PraValue $record 'Kind' '') 'PhaseData')) { throw 'not phase data' }
                if ($Environment -and -not (Test-PraOrdinalEqual (Get-PraValue $record 'Environment' '') $Environment)) { throw 'another Environment' }
                $phase = Get-PraValue $record 'Phase' $null
                $runId = [string](Get-PraValue $phase 'RunId' '')
                if ($null -eq $phase -or -not $runId -or -not [string](Get-PraValue $phase 'Action' '') -or -not [string](Get-PraValue $phase 'StartedUtc' '')) { throw 'incomplete' }
                if ($seen.Add($runId + '|' + [string](Get-PraValue $phase 'Phase' ''))) { $phases.Add($record) }
            }
            catch { $problems.Add(('Phase data {0}: {1}.' -f $leaf, $_.Exception.Message)) }
        }
    }
    return [pscustomobject]@{ Phases = $phases.ToArray(); Problems = $problems.ToArray() }
}

function Get-PraPhaseLabel {
    <# 'Convert · AD', 'Recover · Cloud', 'Finalize · AD', 'Convert · AD + Cloud' from a phase header. #>
    param($Phase)
    $action = [string](Get-PraValue $Phase 'Action' ''); $side = [string](Get-PraValue $Phase 'Phase' '')
    $sideText = if (Test-PraOrdinalEqual $side 'Both') { 'AD + Cloud' } elseif (Test-PraOrdinalEqual $side 'Finalize') { 'AD' } else { $side }
    return ('{0} {1} {2}' -f $action, [char]0x00B7, $sideText)
}

function Format-PraUtcText {
    <# 'yyyy-MM-dd HH:mm:ss UTC' from an ISO 8601 text; the text itself when it cannot be read. #>
    param([AllowNull()][string]$Iso)
    if (-not $Iso) { return '' }
    $parsed = [datetimeoffset]::MinValue
    if ([datetimeoffset]::TryParse($Iso, [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::AssumeUniversal, [ref]$parsed)) {
        return $parsed.UtcDateTime.ToString('yyyy-MM-dd HH:mm:ss', [Globalization.CultureInfo]::InvariantCulture) + ' UTC'
    }
    return (Limit-PraText $Iso 40)
}

function Get-PraPhaseDuration {
    param($Phase)
    $a = [datetimeoffset]::MinValue; $b = [datetimeoffset]::MinValue
    if ([datetimeoffset]::TryParse([string](Get-PraValue $Phase 'StartedUtc' ''), [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::AssumeUniversal, [ref]$a) -and
        [datetimeoffset]::TryParse([string](Get-PraValue $Phase 'EndedUtc' ''), [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::AssumeUniversal, [ref]$b)) { return (Format-PraDuration (($b - $a).TotalSeconds)) }
    return ''
}

function Get-PraGlobalModel {
    <#
    .SYNOPSIS
        The data of the global report: the phases of the batch (earlier phases read from the PhaseData files of $Context.PhaseFolders, then this run),
        and one entry per object with its stage in each phase, its journey across the servers and its verdict.
    .DESCRIPTION
        Verdict: failed when any phase failed it; otherwise pending when its last stage is Pending (it is expected on a later side, or it was
        filtered out there); skipped; done with warnings when a warning was raised; otherwise done. A side that was not carried is listed as not available.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][hashtable]$Context)
    $environment = [string](Get-PraValue (Get-PraValue $Context 'Config' @{}) 'Environment' '')
    $history = Read-PraPhaseData -Folder @(Get-PraList $Context 'PhaseFolders') -Environment $environment
    $currentJson = (New-PraPhaseRecord -Context $Context) | ConvertTo-Json -Depth 8 -Compress
    $current = $currentJson | ConvertFrom-PraJson
    $action = [string](Get-PraValue $Context 'Action' '')
    $mainActions = if (Test-PraOrdinalIn $action @('Recover', 'Finalize')) { @('Recover', 'Finalize') } else { @($action) }
    $all = New-Object 'Collections.Generic.List[object]'
    foreach ($record in $history.Phases) { if (-not (Test-PraOrdinalEqual (Get-PraValue (Get-PraValue $record 'Phase' $null) 'RunId' '') (Get-PraValue (Get-PraValue $current 'Phase' $null) 'RunId' ''))) { $all.Add($record) } }
    $all.Add($current)
    # Sort by start time (ISO 8601, UTC): a record without the property sorts by its own phase header.
    $keys = New-Object 'string[]' $all.Count; $items = $all.ToArray()
    # Earlier operations first, then the sides in their order (AD, Cloud, Finalize); the start time only breaks a tie, so a clock that is off between the two servers cannot reorder the chain.
    for ($i = 0; $i -lt $items.Length; $i++) {
        $header = Get-PraValue $items[$i] 'Phase' $null
        $main = Test-PraOrdinalIn ([string](Get-PraValue $header 'Action' '')) $mainActions
        $side = [string](Get-PraValue $header 'Phase' '')
        $rank = if (Test-PraOrdinalEqual $side 'Finalize') { 3 } elseif (Test-PraOrdinalEqual $side 'Cloud') { 2 } else { 1 }
        $keys[$i] = ('{0}{1}|{2}' -f $(if ($main) { 1 } else { 0 }), $rank, [string](Get-PraValue $header 'StartedUtc' ''))
    }
    [Array]::Sort([Array]$keys, [Array]$items, [Collections.IComparer][StringComparer]::Ordinal)
    $phases = New-Object 'Collections.Generic.List[object]'
    foreach ($record in $items) {
        $header = Get-PraValue $record 'Phase' $null
        $isMain = Test-PraOrdinalIn ([string](Get-PraValue $header 'Action' '')) $mainActions
        $phases.Add([pscustomobject]@{ Label = (Get-PraPhaseLabel $header); Role = $(if ($isMain) { 'Main' } else { 'History' }); Available = $true; Note = ''; Header = $header; Record = $record; HandedOverTo = ''; StatusDisplay = ''
                IsCurrent = (Test-PraOrdinalEqual (Get-PraValue $header 'RunId' '') (Get-PraValue (Get-PraValue $current 'Phase' $null) 'RunId' '')) })
    }
    # Sides that should have run before this one and are not there.
    $required = @()
    $currentPhase = [string](Get-PraValue $Context 'Phase' '')
    if (Test-PraOrdinalEqual $action 'Convert') { if (Test-PraOrdinalEqual $currentPhase 'Cloud') { $required = @(, @('Convert', 'AD')) } }
    elseif (Test-PraOrdinalEqual $action 'Recover') { if (Test-PraOrdinalEqual $currentPhase 'Cloud') { $required = @(, @('Recover', 'AD')) } }
    elseif (Test-PraOrdinalEqual $action 'Finalize') { $required = @(@('Recover', 'AD'), @('Recover', 'Cloud')) }
    $missing = New-Object 'Collections.Generic.List[object]'
    foreach ($pair in $required) {
        $found = @($phases | Where-Object { (Test-PraOrdinalEqual $_.Role 'Main') -and (Test-PraOrdinalEqual (Get-PraValue $_.Header 'Action' '') $pair[0]) -and (Test-PraOrdinalIn (Get-PraValue $_.Header 'Phase' '') @($pair[1], 'Both')) }).Count
        if (-not $found) { $missing.Add([pscustomobject]@{ Label = ('{0} {1} {2}' -f $pair[0], [char]0x00B7, $pair[1]); Role = 'Main'; Available = $false; Note = $script:PraNotAvailable; Header = $null; Record = $null; IsCurrent = $false; HandedOverTo = ''; StatusDisplay = '' }) }
    }
    $ordered = New-Object 'Collections.Generic.List[object]'
    foreach ($entry in $missing) { $ordered.Add($entry) }
    foreach ($entry in $phases) { $ordered.Add($entry) }
    # A Pending phase that a later phase of the same operation took over reads "Handed over"; without a later phase it stays Pending.
    for ($i = 0; $i -lt $ordered.Count; $i++) {
        $entry = $ordered[$i]
        if (-not $entry.Available) { continue }
        $entry.StatusDisplay = [string](Get-PraValue $entry.Header 'Status' '')
        if (-not (Test-PraOrdinalEqual $entry.StatusDisplay 'Pending')) { continue }
        for ($j = $i + 1; $j -lt $ordered.Count; $j++) {
            if ($ordered[$j].Available -and (Test-PraOrdinalEqual $ordered[$j].Role $entry.Role)) { $entry.HandedOverTo = $ordered[$j].Label; $entry.StatusDisplay = $script:PraHandedOver; break }
        }
    }
    # Objects.
    $mainPhases = @($ordered | Where-Object { (Test-PraOrdinalEqual $_.Role 'Main') -and $_.Available })
    $byKey = New-Object 'Collections.Generic.Dictionary[string,object]' -ArgumentList ([StringComparer]::Ordinal)
    $objects = New-Object 'Collections.Generic.List[object]'
    foreach ($phase in $mainPhases) {
        foreach ($item in @(Get-PraList $phase.Record 'Objects')) {
            $guid = [string](Get-PraValue $item 'ObjectGuid' ''); $name = [string](Get-PraValue $item 'Name' '')
            $key = if ($guid) { $guid.ToLowerInvariant() } else { $name.ToLowerInvariant() }
            if (-not $key) { continue }
            $entry = $null
            if (-not $byKey.TryGetValue($key, [ref]$entry)) {
                $entry = [pscustomobject]@{ Key = $key; ObjectGuid = $guid; Name = $name; Sam = [string](Get-PraValue $item 'SamAccountName' ''); Upn = [string](Get-PraValue $item 'UserPrincipalName' '')
                    IsShared = [bool](Get-PraValue $item 'IsShared' $false); Stages = (New-Object 'Collections.Generic.List[object]'); Verdict = ''; Note = ''; Backup = '' }
                $byKey[$key] = $entry; $objects.Add($entry)
            }
            $backup = [string](Get-PraValue $item 'BackupPath' '')
            if ($backup -and -not $entry.Backup) { $entry.Backup = $backup }
            [void]$entry.Stages.Add([pscustomobject]@{ Phase = $phase; Present = $true; HandedOverTo = ''; StatusDisplay = ''; Status = [string](Get-PraValue $item 'FinalStatus' ''); Detail = [string](Get-PraValue $item 'Detail' ''); Warnings = [string](Get-PraValue $item 'Warnings' '')
                    Steps = @(Get-PraList $item 'Steps') })
        }
    }
    $verdicts = @{ Done = 0; Warn = 0; Failed = 0; Pending = 0; Skipped = 0 }
    foreach ($entry in $objects) {
        # One stage per main phase, in order; a phase that does not list the object leaves an explicit gap.
        $staged = New-Object 'Collections.Generic.List[object]'
        foreach ($phase in $mainPhases) {
            $stage = @($entry.Stages | Where-Object { [object]::ReferenceEquals($_.Phase, $phase) })
            if ($stage.Count) { $staged.Add($stage[0]) } else { $staged.Add([pscustomobject]@{ Phase = $phase; Present = $false; HandedOverTo = ''; StatusDisplay = ''; Status = ''; Detail = ''; Warnings = ''; Steps = @() }) }
        }
        $entry.Stages = $staged
        # Display only: a Pending stage that a later phase lists for this object reads "Handed over" (it is Pending when no later phase lists it).
        for ($i = 0; $i -lt $staged.Count; $i++) {
            $stage = $staged[$i]
            if (-not $stage.Present) { continue }
            $stage.StatusDisplay = $stage.Status
            if (-not (Test-PraOrdinalEqual $stage.Status 'Pending')) { continue }
            for ($j = $i + 1; $j -lt $staged.Count; $j++) {
                if ($staged[$j].Present) { $stage.HandedOverTo = $staged[$j].Phase.Label; $stage.StatusDisplay = $script:PraHandedOver; break }
            }
        }
        $present = @($staged | Where-Object { $_.Present })
        $last = $present[$present.Count - 1]
        $failedAnywhere = @($present | Where-Object { Test-PraOrdinalEqual $_.Status 'Error' }).Count -gt 0
        $warned = @($present | Where-Object { $_.Warnings.Trim() -or @($_.Steps | Where-Object { Test-PraOrdinalEqual (Get-PraValue $_ 'Status' '') 'Warn' }).Count }).Count -gt 0
        $lastStage = $staged[$staged.Count - 1]
        if ($failedAnywhere) { $entry.Verdict = 'failed' }
        elseif (Test-PraOrdinalEqual $last.Status 'Pending') {
            $entry.Verdict = 'pending'
            if (-not $lastStage.Present -and $present.Count -lt $staged.Count) { $entry.Note = 'Not in the results of ' + $lastStage.Phase.Label + ': filtered out there or not processed.' }
            else { $entry.Note = 'Waiting for the next step.' }
        }
        elseif (Test-PraOrdinalIn $last.Status @('Skipped', 'Planned')) { $entry.Verdict = 'skipped' }
        elseif ($warned) { $entry.Verdict = 'done with warnings' }
        else { $entry.Verdict = 'done' }
        if ((Test-PraOrdinalEqual $entry.Verdict 'failed')) { $verdicts.Failed++ } elseif ((Test-PraOrdinalEqual $entry.Verdict 'pending')) { $verdicts.Pending++ } elseif ((Test-PraOrdinalEqual $entry.Verdict 'skipped')) { $verdicts.Skipped++ }
        elseif ((Test-PraOrdinalEqual $entry.Verdict 'done with warnings')) { $verdicts.Warn++ } else { $verdicts.Done++ }
    }
    return [pscustomobject]@{
        Phases = $ordered.ToArray(); Objects = $objects.ToArray(); Counts = $verdicts; Problems = $history.Problems; Environment = $environment
        Missing = @($missing | ForEach-Object { $_.Label }); Version = [string](Get-PraValue $Context 'Version' ''); BatchId = [string](Get-PraValue $Context 'BatchId' '')
        Action = $action; Current = $current
    }
}

$script:PraGlobalCss = @'
:root{color-scheme:light dark;--bg:#f7f4ef;--surface:#fff;--soft:#f5f5f5;--border:#dedede;--text:#242424;--muted:#5c5c5c;--accent:#b11f4b;--accent-2:#9a1a41;--accent-fg:#fff;--highlight:rgba(177,31,75,.12);--ok:#16a34a;--warn:#b45309;--fail:#dc2626;--info:#0078d4}
@media (prefers-color-scheme:dark){:root{--bg:#3d3b3a;--surface:#292929;--soft:#2e2e2e;--border:#474747;--text:#dedede;--muted:#a0a0a0;--accent:#fd8ea1;--accent-2:#fb7b91;--accent-fg:#1a1a1a;--highlight:rgba(253,142,161,.12);--ok:#4ade80;--warn:#fbbf24;--fail:#f87171;--info:#4da6ff}}
*{box-sizing:border-box}body{margin:0;padding:28px 32px;background:var(--bg);color:var(--text);font:14px "Segoe UI",Aptos,Calibri,sans-serif}
header{position:relative;overflow:hidden;border:1px solid var(--border);border-top:4px solid var(--accent);border-radius:16px;padding:24px;margin-bottom:20px;background:var(--surface)}
.origin{color:var(--accent);font-size:11px;letter-spacing:.1em;text-transform:uppercase;font-weight:700}h1{font-size:28px;font-weight:650;margin:8px 0 6px}h2{font-size:16px;font-weight:600;margin:0 0 12px}.subtitle{color:var(--muted);margin:0}
.tiles{display:grid;grid-template-columns:repeat(auto-fill,minmax(150px,1fr));gap:14px;margin:0 0 20px}.tile{padding:14px 16px;border:1px solid var(--border);border-radius:16px;background:var(--surface)}
.tile-label{font-size:12px;font-weight:600;color:var(--muted)}.tile-value{font-size:26px;font-weight:650;margin-top:6px}.tile.ok .tile-value{color:var(--ok)}.tile.warn .tile-value{color:var(--warn)}.tile.fail .tile-value{color:var(--fail)}
.card{background:var(--surface);border:1px solid var(--border);border-radius:16px;padding:20px;margin-bottom:20px;overflow-x:auto}.card.warn{border-left:4px solid var(--warn)}.card.fail{border-left:4px solid var(--fail)}
table{border-collapse:collapse;width:100%;font-size:13px}th{text-align:left;font-size:11px;letter-spacing:.05em;text-transform:uppercase;color:var(--accent);padding:6px 10px;border-bottom:1px solid var(--border)}td{padding:6px 10px;border-bottom:1px solid var(--border);vertical-align:top;word-break:break-word}
.pill{display:inline-block;padding:1px 10px;border-radius:999px;font-weight:600;font-size:12px;background:var(--soft)}.pill.ok{color:var(--ok)}.pill.warn{color:var(--warn)}.pill.fail{color:var(--fail)}.pill.muted{color:var(--muted)}
details{border-top:1px solid var(--border);padding:8px 0}summary{cursor:pointer;font-weight:600}.muted{color:var(--muted)}.mono{font-family:Consolas,"Cascadia Mono",monospace;font-size:12px}ul.plain{margin:6px 0 0;padding-left:18px}
.missing{color:var(--warn);font-weight:600}
'@

function Get-PraStatusClass {
    <# Style class of a status or verdict text (display only). #>
    param([string]$Status)
    if (Test-PraOrdinalIn $Status @('Ok', 'Success', 'AlreadyDone', 'done', $script:PraHandedOver) -IgnoreCase) { return 'ok' }
    if (Test-PraOrdinalIn $Status @('Warn', 'Pending', 'pending', 'done with warnings', 'warn') -IgnoreCase) { return 'warn' }
    if (Test-PraOrdinalIn $Status @('Fail', 'Error', 'failed', 'fail') -IgnoreCase) { return 'fail' }
    return 'muted'
}

function Write-PraGlobalReportHtml {
    <#
    .SYNOPSIS
        Writes the global report (one page, no script, no external resource): the batch timeline across the servers, the run settings that differed
        from the configuration file, one entry per object with its journey from one side to the other and its verdict, and the errors and warnings of each side.
        Every value is HTML-encoded.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Model, [Parameter(Mandatory)][IO.TextWriter]$Writer)
    $h = { param($Value) ConvertTo-PraHtmlText $Value }
    $counts = $Model.Counts
    $total = $Model.Objects.Count
    $overall = if ($counts.Failed -gt 0) { 'Failed' } elseif ($counts.Pending -gt 0) { 'Pending' } else { 'Success' }
    $overallClass = if ($counts.Failed -gt 0) { 'fail' } elseif ($counts.Pending -gt 0) { 'warn' } else { 'ok' }
    $sb = New-Object Text.StringBuilder
    [void]$sb.Append('<!doctype html><html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>').Append((& $h ('PRA Remote Mailbox - global report - ' + $Model.Action))).Append('</title><style>').Append($script:PraGlobalCss).Append('</style></head><body>')
    [void]$sb.Append('<header><div class="origin">PRA Remote Mailbox ').Append([char]0x00B7).Append(' global report</div><h1>').Append((& $h ('{0} across the servers' -f $(if (Test-PraOrdinalIn $Model.Action @('Recover', 'Finalize')) { 'Recover and Finalize' } else { $Model.Action })))).Append('</h1><p class="subtitle">')
    [void]$sb.Append((& $h ('Environment {0} {1} batch {2} {1} tool v{3}' -f $Model.Environment, [char]0x00B7, $Model.BatchId, $Model.Version))).Append('</p></header>')
    [void]$sb.Append('<div class="tiles">')
    foreach ($tile in @(@('Result', $overall, $overallClass), @('Objects', $total, ''), @('Done', $counts.Done, 'ok'), @('Done with warnings', $counts.Warn, $(if ($counts.Warn) { 'warn' } else { '' })),
            @('Failed', $counts.Failed, $(if ($counts.Failed) { 'fail' } else { '' })), @('Pending', $counts.Pending, $(if ($counts.Pending) { 'warn' } else { '' })), @('Skipped', $counts.Skipped, ''))) {
        [void]$sb.Append('<div class="tile ').Append($tile[2]).Append('"><div class="tile-label">').Append((& $h $tile[0])).Append('</div><div class="tile-value">').Append((& $h $tile[1])).Append('</div></div>')
    }
    [void]$sb.Append('</div>')
    if ($Model.Missing.Count) {
        [void]$sb.Append('<section class="card warn"><h2>Side not available</h2>')
        foreach ($label in $Model.Missing) { [void]$sb.Append('<p class="missing">').Append((& $h ('{0}: {1}' -f $label, $script:PraNotAvailable))).Append('</p>') }
        [void]$sb.Append('<p class="muted">The objects below are reported from the sides that were carried. The verdicts do not include the missing side.</p></section>')
    }
    foreach ($problem in $Model.Problems) { [void]$sb.Append('<section class="card warn"><p class="missing">').Append((& $h $problem)).Append('</p></section>') }
    # Timeline.
    [void]$sb.Append('<section class="card"><h2>Batch timeline</h2><table><thead><tr><th>Phase</th><th>Server</th><th>Operator</th><th>Started</th><th>Ended</th><th>Duration</th><th>Status</th><th>Mode</th><th>Tool</th></tr></thead><tbody>')
    foreach ($phase in $Model.Phases) {
        if (-not $phase.Available) {
            [void]$sb.Append('<tr><td>').Append((& $h $phase.Label)).Append('</td><td colspan="8" class="missing">').Append((& $h $phase.Note)).Append('</td></tr>'); continue
        }
        $p = $phase.Header
        $role = if ((Test-PraOrdinalEqual $phase.Role 'History')) { ' (earlier operation)' } else { '' }
        $status = [string](Get-PraValue $p 'Status' '')
        $shown = if ($phase.HandedOverTo) { $phase.StatusDisplay } else { $status }
        $rawTitle = if ($phase.HandedOverTo) { ' title="' + (& $h ('{0} (handed over to {1})' -f $status, $phase.HandedOverTo)) + '"' } else { '' }
        [void]$sb.Append('<tr><td>').Append((& $h ($phase.Label + $role))).Append('</td><td>').Append((& $h ((@((Get-PraValue $p 'Computer' ''), (Get-PraValue $p 'Server' '')) | Where-Object { $_ }) -join ' / '))).Append('</td><td>').Append((& $h (Get-PraValue $p 'Account' ''))).Append('</td><td>')
        [void]$sb.Append((& $h (Format-PraUtcText (Get-PraValue $p 'StartedUtc' '')))).Append('</td><td>').Append((& $h (Format-PraUtcText (Get-PraValue $p 'EndedUtc' '')))).Append('</td><td>').Append((& $h (Get-PraPhaseDuration $p))).Append('</td><td><span class="pill ').Append((Get-PraStatusClass $shown)).Append('"').Append($rawTitle).Append('>')
        [void]$sb.Append((& $h $shown)).Append('</span></td><td>').Append((& $h (Get-PraValue $p 'Mode' ''))).Append('</td><td>').Append((& $h (Get-PraValue $phase.Record 'ToolVersion' ''))).Append('</td></tr>')
    }
    [void]$sb.Append('</tbody></table></section>')
    # Run settings per phase.
    [void]$sb.Append('<section class="card"><h2>Run settings changed from the configuration file</h2>')
    $anyOverride = $false
    foreach ($phase in $Model.Phases) {
        if (-not $phase.Available) { continue }
        $items = @(Get-PraList $phase.Header 'Overrides' | Where-Object { $_ })
        if ($items.Count) {
            $anyOverride = $true
            [void]$sb.Append('<p><strong>').Append((& $h $phase.Label)).Append('</strong></p><ul class="plain">')
            foreach ($item in $items) { [void]$sb.Append('<li class="mono">').Append((& $h $item)).Append('</li>') }
            [void]$sb.Append('</ul>')
        }
    }
    if (-not $anyOverride) { [void]$sb.Append('<p class="muted">None: every phase used the settings of the configuration file.</p>') }
    foreach ($phase in $Model.Phases) {
        if (-not $phase.Available) { continue }
        $settings = Get-PraValue $phase.Header 'Settings' $null
        if ($null -eq $settings) { continue }
        [void]$sb.Append('<details><summary>Settings used ').Append([char]0x00B7).Append(' ').Append((& $h $phase.Label)).Append('</summary><ul class="plain">')
        foreach ($property in $settings.PSObject.Properties) { [void]$sb.Append('<li><span class="muted">').Append((& $h $property.Name)).Append(':</span> ').Append((& $h $property.Value)).Append('</li>') }
        [void]$sb.Append('</ul></details>')
    }
    [void]$sb.Append('</section>')
    # Objects.
    [void]$sb.Append('<section class="card"><h2>Objects, end to end</h2>')
    $detailed = $total -le $script:PraPhaseLimits.DetailedObjects
    if (-not $detailed) { [void]$sb.Append('<p class="muted">').Append((& $h ('More than {0} objects: the journey is written for the objects that are not simply done; the CSV file lists every object.' -f $script:PraPhaseLimits.DetailedObjects))).Append('</p>') }
    [void]$sb.Append('<table><thead><tr><th>Object</th><th>Type</th><th>Verdict</th>')
    $mainPhases = @($Model.Phases | Where-Object { (Test-PraOrdinalEqual $_.Role 'Main') -and $_.Available })
    foreach ($phase in $mainPhases) { [void]$sb.Append('<th>').Append((& $h $phase.Label)).Append('</th>') }
    [void]$sb.Append('</tr></thead><tbody>')
    foreach ($entry in $Model.Objects) {
        $class = Get-PraStatusClass $entry.Verdict
        [void]$sb.Append('<tr><td>').Append((& $h $entry.Name)).Append('</td><td>').Append($(if ($entry.IsShared) { 'Shared mailbox' } else { 'User mailbox' })).Append('</td><td><span class="pill ').Append($class).Append('">').Append((& $h $entry.Verdict)).Append('</span></td>')
        foreach ($stage in $entry.Stages) {
            if ($stage.Present) { [void]$sb.Append('<td><span class="pill ').Append((Get-PraStatusClass $stage.StatusDisplay)).Append('">').Append((& $h $stage.StatusDisplay)).Append('</span></td>') }
            else { [void]$sb.Append('<td class="muted">not in this phase</td>') }
        }
        [void]$sb.Append('</tr>')
        if ($detailed -or (-not (Test-PraOrdinalEqual $entry.Verdict 'done'))) {
            [void]$sb.Append('<tr><td colspan="').Append(3 + $mainPhases.Count).Append('"><details><summary>Journey of ').Append((& $h $entry.Name)).Append('</summary>')
            if ($entry.Note) { [void]$sb.Append('<p class="missing">').Append((& $h $entry.Note)).Append('</p>') }
            if ($entry.Backup) { [void]$sb.Append('<p class="muted">Backup: <span class="mono">').Append((& $h $entry.Backup)).Append('</span></p>') }
            [void]$sb.Append('<table><thead><tr><th>Side</th><th>Step</th><th>Status</th><th>Time</th><th>Message</th></tr></thead><tbody>')
            foreach ($stage in $entry.Stages) {
                if (-not $stage.Present) { [void]$sb.Append('<tr><td>').Append((& $h $stage.Phase.Label)).Append('</td><td colspan="4" class="muted">This object is not in the results of this phase.</td></tr>'); continue }
                foreach ($step in @($stage.Steps)) {
                    $stepStatus = [string](Get-PraValue $step 'Status' '')
                    [void]$sb.Append('<tr><td>').Append((& $h $stage.Phase.Label)).Append('</td><td>').Append((& $h (Get-PraValue $step 'Step' ''))).Append('</td><td><span class="pill ').Append((Get-PraStatusClass $stepStatus)).Append('">').Append((& $h $stepStatus)).Append('</span></td><td>')
                    [void]$sb.Append((& $h (Format-PraUtcText (Get-PraValue $step 'Time' '')))).Append('</td><td>').Append((& $h (Get-PraValue $step 'Text' ''))).Append('</td></tr>')
                }
                $message = (('{0} {1}' -f $stage.Detail, $stage.Warnings)).Trim()
                $resultText = if ($stage.HandedOverTo) { '{0} (handed over to {1})' -f $stage.Status, $stage.HandedOverTo } else { $stage.Status }
                [void]$sb.Append('<tr><td>').Append((& $h $stage.Phase.Label)).Append('</td><td><strong>Result of this phase</strong></td><td><span class="pill ').Append((Get-PraStatusClass $stage.StatusDisplay)).Append('">').Append((& $h $resultText)).Append('</span></td><td></td><td>').Append((& $h $message)).Append('</td></tr>')
            }
            [void]$sb.Append('</tbody></table></details></td></tr>')
        }
    }
    if (-not $Model.Objects.Count) { [void]$sb.Append('<tr><td colspan="').Append(3 + $mainPhases.Count).Append('" class="muted">No object.</td></tr>') }
    [void]$sb.Append('</tbody></table></section>')
    # Errors and warnings.
    foreach ($phase in $Model.Phases) {
        if (-not $phase.Available) { continue }
        $issues = @(Get-PraList $phase.Record 'Issues'); $warnings = @(Get-PraList $phase.Record 'Warnings')
        if (-not $issues.Count -and -not $warnings.Count) { continue }
        [void]$sb.Append('<section class="card ').Append($(if ($issues.Count) { 'fail' } else { 'warn' })).Append('"><h2>').Append((& $h ('Errors and warnings ' + [char]0x00B7 + ' ' + $phase.Label))).Append('</h2><table><thead><tr><th>Kind</th><th>Time</th><th>Step</th><th>Object</th><th>Message</th></tr></thead><tbody>')
        foreach ($issue in ($issues | Select-Object -First 200)) { [void]$sb.Append('<tr><td><span class="pill fail">error</span></td><td>').Append((& $h (Get-PraValue $issue 'Timestamp' ''))).Append('</td><td>').Append((& $h (Get-PraValue $issue 'Phase' ''))).Append('</td><td>').Append((& $h (Get-PraValue $issue 'Identity' ''))).Append('</td><td>').Append((& $h (Get-PraValue $issue 'Message' ''))).Append('</td></tr>') }
        foreach ($warning in ($warnings | Select-Object -First 200)) { [void]$sb.Append('<tr><td><span class="pill warn">warning</span></td><td>').Append((& $h (Get-PraValue $warning 'Timestamp' ''))).Append('</td><td>').Append((& $h (Get-PraValue $warning 'Phase' ''))).Append('</td><td></td><td>').Append((& $h (Get-PraValue $warning 'Message' ''))).Append('</td></tr>') }
        [void]$sb.Append('</tbody></table></section>')
    }
    [void]$sb.Append('<p class="muted">Generated by PRA Remote Mailbox v').Append((& $h $Model.Version)).Append('. This report holds names and statuses only: no secret, no token.</p></body></html>')
    $Writer.Write($sb.ToString())
}

function Write-PraGlobalReportCsv {
    <# One line per object: verdict, the status of each side and the journey as text (formula guard on every text cell). Semicolon, UTF-8 with BOM. #>
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Model, [Parameter(Mandatory)][string]$Path)
    $rows = foreach ($entry in $Model.Objects) {
        $row = [ordered]@{ ObjectGuid = $entry.ObjectGuid; Name = $entry.Name; SamAccountName = $entry.Sam; UserPrincipalName = $entry.Upn; Type = $(if ($entry.IsShared) { 'Shared' } else { 'User' }); Verdict = $entry.Verdict }
        $sides = New-Object 'Collections.Generic.List[string]'
        foreach ($stage in $entry.Stages) { if ($stage.Present) { $sides.Add($stage.Phase.Label + ': ' + $stage.StatusDisplay) } else { $sides.Add($stage.Phase.Label + ': -') } }
        $row['Sides'] = $sides -join ' | '
        $row['Note'] = $entry.Note
        $row['BackupPath'] = $entry.Backup
        $journey = New-Object 'Collections.Generic.List[string]'
        foreach ($stage in $entry.Stages) {
            if (-not $stage.Present) { continue }
            foreach ($step in @($stage.Steps)) { $journey.Add(('{0} / {1}: {2} {3} - {4}' -f $stage.Phase.Label, (Get-PraValue $step 'Step' ''), (Get-PraValue $step 'Status' ''), (Format-PraUtcText (Get-PraValue $step 'Time' '')), (Get-PraValue $step 'Text' ''))) }
            $journey.Add(('{0} / result: {1} - {2}' -f $stage.Phase.Label, $(if ($stage.HandedOverTo) { '{0} (handed over to {1})' -f $stage.Status, $stage.HandedOverTo } else { $stage.Status }), (('{0} {1}' -f $stage.Detail, $stage.Warnings).Trim())))
        }
        $row['Journey'] = $journey -join ' | '
        $row['RunSettings'] = (@($Model.Phases | Where-Object { $_.Available } | ForEach-Object { $label = $_.Label; @(Get-PraList $_.Header 'Overrides') | Where-Object { $_ } | ForEach-Object { $label + ': ' + $_ } }) -join ' | ')
        ConvertTo-PraCsvRow ([pscustomobject]$row)
    }
    $fields = @('ObjectGuid', 'Name', 'SamAccountName', 'UserPrincipalName', 'Type', 'Verdict', 'Sides', 'Note', 'BackupPath', 'Journey', 'RunSettings')
    if (@($rows).Count) { $rows | Export-Csv -LiteralPath $Path -NoTypeInformation -Delimiter ';' -Encoding utf8BOM -WhatIf:$false -Confirm:$false -ErrorAction Stop }
    else { Set-Content -LiteralPath $Path -Value ('"' + ($fields -join '";"') + '"') -Encoding utf8BOM -WhatIf:$false -Confirm:$false -ErrorAction Stop }
}

function Test-PraGlobalReportWanted {
    <# True for the run that ends the chain: an Apply of Convert, Recover or Finalize that hands nothing over to another server. #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][hashtable]$Context)
    if (-not (Get-PraValue $Context 'AllowMutation' $false)) { return $false }
    if (-not (Test-PraOrdinalIn ([string](Get-PraValue $Context 'Action' '')) @('Convert', 'Recover', 'Finalize'))) { return $false }
    if ([string](Get-PraValue $Context 'HandOff' '')) { return $false }
    return ($Context.Rows.Count -gt 0)
}

function Write-PraGlobalReport {
    <# Writes the global HTML and CSV report of this run into the report folder. Returns Html and Csv (empty when a file could not be written: a warning says why). #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][hashtable]$Context)
    $result = @{ Html = ''; Csv = '' }
    try {
        $model = Get-PraGlobalModel -Context $Context
        Initialize-PraPrivateFolder -Path $Context.ReportFolder
        $stem = [string](Get-PraValue $Context '_PraArtifactStem' '')
        if (-not $stem) { $stem = Get-PraArtifactStem $Context }
        $html = Join-Path $Context.ReportFolder ($stem + '.global.html'); $csv = Join-Path $Context.ReportFolder ($stem + '.global.csv')
        $stream = [IO.File]::Open($html, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
        $writer = New-Object IO.StreamWriter($stream, (New-Object Text.UTF8Encoding($true)), 65536)
        try { Write-PraGlobalReportHtml -Model $model -Writer $writer } finally { $writer.Dispose() }
        $result.Html = $html
        Write-PraGlobalReportCsv -Model $model -Path $csv
        $result.Csv = $csv
        $Context['GlobalModel'] = $model
    }
    catch { Write-PraLog -Context $Context -Message ('The global report could not be written: {0}' -f $_.Exception.Message) -Level Warning }
    return $result
}
#endregion

Export-ModuleMember -Function Register-PraObjectName, Get-PraList, Register-PraObjectBackup, Save-PraPhaseData, Copy-PraPhaseData, Read-PraPhaseData, New-PraPhaseRecord, Get-PraGlobalModel, Write-PraGlobalReport, Write-PraGlobalReportHtml, Write-PraGlobalReportCsv, Test-PraGlobalReportWanted, Limit-PraText, Get-PraEventObjectName, Test-PraOrdinalEqual, Test-PraOrdinalIgnoreCaseEqual, Test-PraOrdinalIn, Test-PraOrdinalIgnoreCaseIn, Sort-PraOrdinal, Get-PraOrdinalUnique, Compare-PraX500Address, ConvertFrom-PraJson, Get-PraNativeProcessApi, Read-PraCsvText, Get-PraToolVersion, New-PraPrivateDirectorySecurity, Initialize-PraPrivateFolder, ConvertTo-PraCsvCell, Get-PraValue, Format-PraDuration, Add-PraIssue, Write-PraLog, Write-PraItem, Write-PraBanner, Write-PraStep,
    Write-PraSummary, Write-PraHost, Resolve-PraPath, Import-PraConfiguration, Initialize-PraAudit, Get-PraOutcome, Complete-PraRun, Write-PraEvent, Get-PraWin32ErrorText, Get-PraTargetOverride, Read-PraTargetCsv, Write-PraProgress, Get-PraTransferPackageName, Get-PraTransferPackage, Import-PraTransferPackage, New-PraTransferPackage, New-PraEffectiveConfiguration, Get-PraConfigurationDifference

# SIG # Begin signature block
# MIImKgYJKoZIhvcNAQcCoIImGzCCJhcCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCAxMY1tqmcWWwep
# bKQQvUQ6pnkHC9UPnfx9iP/13u3oMKCCDW8wggZyMIIEWqADAgECAghkM1HTxzif
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
# wZislcdCZuS6MYIYETCCGA0CAQEwgYwweDELMAkGA1UEBhMCVVMxDjAMBgNVBAgM
# BVRleGFzMRAwDgYDVQQHDAdIb3VzdG9uMREwDwYDVQQKDAhTU0wgQ29ycDE0MDIG
# A1UEAwwrU1NMLmNvbSBDb2RlIFNpZ25pbmcgSW50ZXJtZWRpYXRlIENBIFJTQSBS
# MQIQBof4ljXihJpmCqqt2mhAWzANBglghkgBZQMEAgEFAKCBhDAYBgorBgEEAYI3
# AgEMMQowCKACgAChAoAAMBkGCSqGSIb3DQEJAzEMBgorBgEEAYI3AgEEMBwGCisG
# AQQBgjcCAQsxDjAMBgorBgEEAYI3AgEVMC8GCSqGSIb3DQEJBDEiBCDteqCZczrj
# lqMpxNPst0YtLd7/1FteMdxAeeEg0RyTtTANBgkqhkiG9w0BAQEFAASCAgBfN97d
# aFxz943GPy7rNXXwh+mbIlO/IshGCfg+qrbCIfXy6THRF2IdHaUEgKNqqPFmYZfc
# LRgBCdrmmGpm4J3rAP6TkxMt97rSYRPshvSsGhS/JxcYazBOrPPZZR14ySZAF1tb
# cUSrexl+OterhN7mm6bXEXVyuWRIIEBFyDWtuaSpH7kzeZRmEMdHmSgNS/prwiQx
# xwbU1ANuqbwOZV++5Sz0c6kxEWItVgHXDFnR8Qno7INriwFn23fnbxBQYjrhaYkz
# LLVo3h8bzkKfkaBQhc6JXn28W50FYBw0brgo5x8U1D2Um2UpPEerPy1VN38AAEfi
# M9PKGkh771nN5s4dBsnDw+EdjX/9SW9aD/QQ0e5prE6mrDfgen5KmegiuK9kvo+F
# 4UliSXQbOiV4J11kYGuyAdmRevOl74qICEyKCipLozevXSribmnyFcrNeViHQyOC
# VWFjnCRVToXdvciC7tnzzsXk2a8Pqft7bFAUmHPbjxpr4iB/vslBtqpWo/j3nzm1
# ctIz4TJ4Aur/APhzH/fmpmK6SyjtNL0LwETfZr8QVHKESeC5XTy7o37hJL/vQNPK
# /x9gG5wPJQfgvKCYoO8HqUfzIbaaNqK2UfeHkWI4WwhtwJqvfypITIoj0krvbjGs
# L/BliMreYlrDUvT9hJ0PA6ec2krc0kv6HK4/OaGCFM4wghTKBgorBgEEAYI3AwMB
# MYIUujCCFLYGCSqGSIb3DQEHAqCCFKcwghSjAgEDMQ0wCwYJYIZIAWUDBAIBMIGJ
# BgsqhkiG9w0BCRABBKB6BHgwdgIBAQYMKwYBBAGCqTABAwYBMDEwDQYJYIZIAWUD
# BAIBBQAEIItYfeuEk+bRe3UyZauT5+5LBIsA8ybhshZLZP2MGyh+AggNGqiZBvS8
# uRgPMjAyNjExMDkxNTMzMjNaMAMCAQECEDktB9+cDTosK6vP6LLry/WgghGnMIIE
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
# wzSPOzGCAlYwggJSAgEBMIGGMHIxCzAJBgNVBAYTAlVTMQ4wDAYDVQQIDAVUZXhh
# czEQMA4GA1UEBwwHSG91c3RvbjERMA8GA1UECgwIU1NMIENvcnAxLjAsBgNVBAMM
# JVNTTC5jb20gVGltZXN0YW1waW5nIElzc3VpbmcgUlNBIENBIDICEFRD+De9Wu4Y
# AYRyuFzajuMwCwYJYIZIAWUDBAIBoIIBYDAaBgkqhkiG9w0BCQMxDQYLKoZIhvcN
# AQkQAQQwHAYJKoZIhvcNAQkFMQ8XDTI2MTEwOTE1MzMyM1owKAYJKoZIhvcNAQk0
# MRswGTALBglghkgBZQMEAgGhCgYIKoZIzj0EAwIwLwYJKoZIhvcNAQkEMSIEIOO2
# f/P+VPUQ3y/jWOHjVcDdm/jlnc35VzUfgI6J3gweMIHIBgsqhkiG9w0BCRACLzGB
# uDCBtTCBsjCBrwQgV0/qF6r6XnxqK5sIyZixc15FCzhzykTmokygkw5j87AwgYow
# dqR0MHIxCzAJBgNVBAYTAlVTMQ4wDAYDVQQIDAVUZXhhczEQMA4GA1UEBwwHSG91
# c3RvbjERMA8GA1UECgwIU1NMIENvcnAxLjAsBgNVBAMMJVNTTC5jb20gVGltZXN0
# YW1waW5nIElzc3VpbmcgUlNBIENBIDICEFRD+De9Wu4YAYRyuFzajuMwCgYIKoZI
# zj0EAwIERzBFAiBMelxdFQpgYo33Dr4EV7ud9MNyehZ46tuSrPAuhkrNewIhAKS8
# DBqE4jaPTxGcaMGd1STbkh9mTgNnqS5uSAj1OYCe
# SIG # End signature block
