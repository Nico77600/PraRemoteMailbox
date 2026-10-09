<#
.SYNOPSIS
    PRA Remote Mailbox - common module: console, log, configuration, audit and reports.

.DESCRIPTION
    Helper functions used by Invoke-PraRemoteMailbox.ps1 and by the other modules. The module never
    reads Active Directory and never connects to Microsoft 365. It is organised in regions, in the
    order of an execution:

        1. Console theme       icons, frames and colours (Windows PowerShell 5.1 console colours)
        2. Console and log     Write-PraBanner, Write-PraStep, Write-PraItem, Write-PraLog, Write-PraSummary
        3. Configuration       Import-PraConfiguration (reads and checks the .psd1 file)
        4. Audit               Initialize-PraAudit (log file + PowerShell transcript)
        5. Results             Get-PraOutcome, Write-PraReport (CSV + HTML), Complete-PraRun

    The run state is one hashtable (the "context") created by the entry script and passed to every
    function. Its main keys are described in docs\PraRemoteMailbox-Guide.md, chapter "Inside the tool".

.NOTES
    Author  : Nicolas Fabert
    Version : 2.1.0
    History : see CHANGELOG.md
#>
#Requires -Version 5.1
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$script:ToolVersion = '2.1.0'
$script:TranscriptOwner = $null
# Columns of the CSV report, in this order (also the fields copied from each result row).
$script:RowFields = @('ObjectGuid','SamAccountName','UserPrincipalName','Action','IsShared','ADApplied','ADVerified',
    'GroupAction','BackupPath','LastOperation','CloudMailbox','CloudLicense','CloudStatus','CloudDetail','PreserveCloudMailbox',
    'PreserveLicense','DeprovisionConfirmed','PermDetail','PermMissing','FinalStatus','Detail','Warnings')
# Final statuses a row can have. 'AlreadyDone' is counted as a success.
$script:FinalStatuses = @('Planned','AlreadyDone','Success','Error','Pending','Skipped')

#region 1. Console theme ----------------------------------------------------------------------
# Windows PowerShell 5.1 and the classic console (conhost) are the reference: colours are console
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
    if ($Style -eq 'Ascii') { return @{ TopLeft='+'; TopRight='+'; BottomLeft='+'; BottomRight='+'; Horizontal='-'; Vertical='|' } }
    return @{ TopLeft=[string][char]0x256D; TopRight=[string][char]0x256E; BottomLeft=[string][char]0x2570
        BottomRight=[string][char]0x256F; Horizontal=[string][char]0x2500; Vertical=[string][char]0x2502 }
}

$script:IconStyle = if ($env:PRA_ICONS -in @('Emoji','Symbols','Ascii')) { $env:PRA_ICONS }
    elseif ($env:WT_SESSION -or $env:TERM_PROGRAM -eq 'vscode') { 'Emoji' }
    else { 'Symbols' }
$script:Icons = Get-PraIconSet $script:IconStyle
$script:Frame = Get-PraFrameSet $script:IconStyle
# Emoji are two columns wide, symbols one: pad symbols so that the text stays aligned.
$script:IconPad = if ($script:IconStyle -eq 'Emoji') { ' ' } else { '  ' }
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
    if ($env:PRA_ANSI -eq '1' -and $Color) {
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
        foreach ($entry in $Object.GetEnumerator()) { if ($entry.Key -eq $Name) { return ,($entry.Value) } }
    } else {
        $property = $Object.PSObject.Properties[$Name]
        if ($null -ne $property) { return ,($property.Value) }
    }
    return ,$Default
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
    param([Parameter(Mandatory)][ValidateSet('start','step','item','summary','result')][string]$Kind, [hashtable]$Data = @{})
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
    if ($Level -eq 'Warning') { $Context.Warnings = [int](Get-PraValue $Context 'Warnings' 0) + 1; Add-PraWarning $Context $Message }
    if ($Level -eq 'Error') { Add-PraIssue $Context $Message }
    Write-PraLogFile -Context $Context -Level $logLevel -Message $Message
    $text = $Message -replace '[\r\n]+', ' | '
    switch ($Level) {
        'Debug' {
            $verbose = [bool](Get-PraValue $Context 'VerboseEnabled' ($VerbosePreference -eq 'Continue'))
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
                elseif ($status -in @('Warn','Fail')) { $iconColor } else { '' }
            Write-PraHost @('      ', (Get-PraIcon $status), $text) -Color $textColor
        }
    }
    if ($Level -in @('Info','Sub','Success','Warning','Error')) {
        Write-PraEvent -Kind item -Data @{ status = @{ Info='Info'; Sub='Sub'; Success='Ok'; Warning='Warn'; Error='Fail' }[$Level]
            text = $text; identity = [string](Get-PraValue $Context 'CurrentIdentity' '') }
    }
}

function Write-PraItem {
    <#
    .SYNOPSIS
        One indented result line with a status icon, also written to the log.
    .PARAMETER Status
        Ok, Warn, Fail, Info or Skip. Fail does NOT record a run error: use Write-PraLog -Level Error for that.
    .PARAMETER Icon
        Optional icon name instead of the status icon (Directory, Backup, Cloud, Mail, ...).
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][hashtable]$Context, [ValidateSet('Ok','Warn','Fail','Info','Skip')][string]$Status = 'Info',
        [Parameter(Mandatory)][AllowEmptyString()][string]$Text, [string]$Icon)
    $color = @{ Ok=$script:Theme.Ok; Warn=$script:Theme.Warn; Fail=$script:Theme.Fail; Info=$script:Theme.Info; Skip=$script:Theme.Dim }[$Status]
    $textColor = if ($Status -in @('Warn','Fail','Skip')) { $color } else { '' }
    $symbol = if ($Icon) { Get-PraIcon $Icon } else { Get-PraIcon $Status }
    Write-PraHost @('      ', $symbol, $Text) -Color $textColor
    if ($Status -eq 'Warn') { $Context.Warnings = [int](Get-PraValue $Context 'Warnings' 0) + 1; Add-PraWarning $Context $Text }
    Write-PraLogFile -Context $Context -Level (@{ Ok='OK'; Warn='WARN'; Fail='FAIL'; Info='INFO'; Skip='SKIP' }[$Status]) -Message $Text
    Write-PraEvent -Kind item -Data @{ status = $Status; text = $Text; identity = [string](Get-PraValue $Context 'CurrentIdentity' '') }
}

function Write-PraBanner {
    <#
    .SYNOPSIS
        Title card at the start of an execution:

          ╭────────────────────────────────────────────────────────────────────────────╮
          │  ♦  PRA Remote Mailbox                           v2.1.0 · Nicolas Fabert   │
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
    $iconWidth = if ($script:IconStyle -eq 'Emoji') { 2 } else { $script:Icons.Logo.Length }
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
    param([Parameter(Mandatory)][hashtable]$Context, [Parameter(Mandatory)][string]$Title, [string]$Icon = 'Plan')
    $Context.StepIndex = [int](Get-PraValue $Context 'StepIndex' 0) + 1
    $Context.CurrentPhase = $Title
    $total = [int](Get-PraValue $Context 'StepTotal' 0)
    $number = if ($total -gt 0) { '{0}/{1}' -f $Context.StepIndex, $total } else { [string]$Context.StepIndex }
    Write-Host ''
    Write-PraHost @('  ', ('{0,5}' -f $number), '  ', (Get-PraIcon $Icon), $Title) -Color $script:Theme.Accent
    Write-PraLogFile -Context $Context -Level 'STEP' -Message ("[$number] $Title")
    Write-PraEvent -Kind step -Data @{ index = $Context.StepIndex; total = $total; title = $Title }
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
    $iconWidth = if ($script:IconStyle -eq 'Emoji') { 2 } else { $icon.Length }
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
        if ($Path[$i] -in $invalid) {
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
    <# Default values of every setting (the reference list of the valid keys). #>
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
        EntraConnect = @{ Sync=$true; Server=''; PolicyType='Delta'; TimeoutMinutes=15 }
        Cloud = @{
            TenantId=''; Organization=''; AppId=''; CertificateThumbprint=''; UserPrincipalName=''
            CheckMailbox=$true; CheckLicense=$true; MailboxCheckVia='Exo'; RequiredSkuPartNumber=''
        }
        Exo = @{ MinModuleVersion='3.10.0'; UseSubprocess=$false; DisableWAM=$false; GrantVerifyAttempts=13; GrantVerifyDelaySeconds=10 }
        Polling = @{ IntervalMinutes=5; TimeoutMinutes=60 }
        Retention = @{ Enabled=$true; PolicyName=''; PolicyGuid=''; UseComplianceSession=$false; Tag=@{ Enabled=$true; Attribute='extensionAttribute1'; Value='Converted' } }
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
    $text = [IO.File]::ReadAllText($Path, [Text.Encoding]::UTF8)
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
        if ($key -notin @('Mode','SearchBase','CsvPath','GroupDN') -or $ScopeOverride[$key] -isnot [string]) { throw 'Unsupported target scope override.' }
        $config.Scope[$key] = $ScopeOverride[$key]
    }

    if ($config.Environment -notmatch '^[A-Za-z0-9_.-]{1,64}$') { throw 'Configuration: Environment must be 1 to 64 letters, digits, dot, dash or underscore (it is used in file names).' }
    if ($config.DomainController -and $config.DomainController -notmatch '^[A-Za-z0-9.-]+$') { throw 'Configuration: DomainController must be a host name.' }
    $scope = $config.Scope
    if ($scope.Mode -notin @('Auto','OU','Group','Csv')) { throw 'Configuration: Scope.Mode must be Auto, OU, Group or Csv.' }
    if ($scope.Mode -eq 'OU' -and -not $scope.SearchBase) { throw 'Configuration: Scope.Mode = OU requires Scope.SearchBase (a search of the whole domain needs Mode = Auto).' }
    if ($scope.Mode -eq 'Group' -and -not $scope.GroupDN) { throw 'Configuration: Scope.Mode = Group requires Scope.GroupDN.' }
    if ($scope.Mode -eq 'Csv' -and -not $scope.CsvPath) { throw 'Configuration: Scope.Mode = Csv requires Scope.CsvPath.' }
    if ($config.Remote.RecipientType -notin @(1,3)) { throw 'Configuration: Remote.RecipientType must be 1 (provision a mailbox) or 3 (mailbox + archive).' }
    if ($config.Routing.RoutingDomain -and $config.Routing.RoutingDomain -notmatch '^[A-Za-z0-9.-]+\.[A-Za-z]{2,}$') { throw 'Configuration: Routing.RoutingDomain must be a domain name (tenant.mail.onmicrosoft.com).' }
    if ($config.Licensing.Enabled -and -not $config.Licensing.GroupDN) { throw 'Configuration: Licensing.Enabled requires Licensing.GroupDN.' }
    $shared = $config.SharedMailbox
    if ($shared.RemoteRecipientType -notin @(97,99,100,102)) { throw 'Configuration: SharedMailbox.RemoteRecipientType must be 97 or 99 (100/102 are accepted only to read old backups).' }
    if ($shared.PermissionSource -notin @('AD','Csv','CustomAttribute','None')) { throw 'Configuration: SharedMailbox.PermissionSource must be AD, Csv, CustomAttribute or None.' }
    if ($shared.PermissionSource -eq 'Csv' -and -not $shared.CsvPath) { throw 'Configuration: SharedMailbox.PermissionSource = Csv requires SharedMailbox.CsvPath.' }
    if ($shared.CustomAttribute -notmatch '^extensionAttribute([1-9]|1[0-5])$') { throw 'Configuration: SharedMailbox.CustomAttribute must be extensionAttribute1 to extensionAttribute15.' }
    $sync = $config.EntraConnect
    if ($sync.PolicyType -notin @('Delta','Initial')) { throw 'Configuration: EntraConnect.PolicyType must be Delta or Initial.' }
    if ($sync.TimeoutMinutes -lt 1 -or $sync.TimeoutMinutes -gt 240) { throw 'Configuration: EntraConnect.TimeoutMinutes must be between 1 and 240.' }
    if ($sync.Server -and $sync.Server -notmatch '^[A-Za-z0-9.-]+$') { throw 'Configuration: EntraConnect.Server must be a host name (empty = this server).' }
    $cloud = $config.Cloud
    if ($cloud.MailboxCheckVia -notin @('Graph','Exo')) { throw 'Configuration: Cloud.MailboxCheckVia must be Exo or Graph.' }
    if ([bool]$cloud.AppId -ne [bool]$cloud.CertificateThumbprint) { throw 'Configuration: Cloud.AppId and Cloud.CertificateThumbprint go together (both set = certificate sign-in, both empty = interactive sign-in).' }
    $exo = $config.Exo
    if ($exo.GrantVerifyAttempts -lt 1 -or $exo.GrantVerifyAttempts -gt 60 -or $exo.GrantVerifyDelaySeconds -lt 1 -or $exo.GrantVerifyDelaySeconds -gt 30) {
        throw 'Configuration: Exo.GrantVerifyAttempts must be 1..60 and Exo.GrantVerifyDelaySeconds 1..30.'
    }
    try { $null = [version]$exo.MinModuleVersion } catch { throw 'Configuration: Exo.MinModuleVersion must be a version number (3.10.0).' }
    if ($config.Polling.IntervalMinutes -lt 1 -or $config.Polling.TimeoutMinutes -lt 1) { throw 'Configuration: Polling.IntervalMinutes and Polling.TimeoutMinutes must be at least 1.' }
    $retention = $config.Retention
    if ($retention.Tag.Attribute -notmatch '^extensionAttribute([1-9]|1[0-5])$') { throw 'Configuration: Retention.Tag.Attribute must be extensionAttribute1 to extensionAttribute15.' }
    if ($retention.Enabled -and $retention.Tag.Enabled -and -not $retention.Tag.Value) { throw 'Configuration: Retention.Tag.Value is empty.' }
    if ($config.Execution.Phase -notin @('Both','AD','Cloud')) { throw 'Configuration: Execution.Phase must be Both, AD or Cloud.' }

    $config.Storage.BackupFolder = Resolve-PraPath $config.Storage.BackupFolder 'Storage.BackupFolder' $Root
    $config.Storage.ForbiddenBackupRoots = @(foreach ($forbidden in $config.Storage.ForbiddenBackupRoots) { (Resolve-PraPath ([string]$forbidden) 'Storage.ForbiddenBackupRoots' $Root).TrimEnd('\') + '\' })
    $config.Logging.Folder = Resolve-PraPath $config.Logging.Folder 'Logging.Folder' $Root
    $config.Report.Folder = Resolve-PraPath $config.Report.Folder 'Report.Folder' $Root
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
        $null = New-Item -ItemType Directory -Path $Context.LogFolder -Force -WhatIf:$false -Confirm:$false -ErrorAction Stop
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
            $null = New-Item -ItemType Directory -Path $Context.ReportFolder -Force -WhatIf:$false -Confirm:$false -ErrorAction Stop
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
        foreach ($field in $script:RowFields) { $copy[$field] = Get-PraValue $row $field }
        $copy.PermMissing = $copy.PermMissing -join '; '
        if ($copy.FinalStatus -notin $script:FinalStatuses) {
            $copy.Detail = 'Final status missing or invalid: {0}. {1}' -f $copy.FinalStatus, $copy.Detail; $copy.FinalStatus = 'Error'
        }
        if ($copy.FinalStatus -eq 'Error') {
            foreach ($field in @('ObjectGuid','SamAccountName','UserPrincipalName')) { if ($copy[$field]) { $errorIdentities[[string]$copy[$field]] = $true } }
        }
        [void]$rows.Add([pscustomobject]$copy)
    }
    foreach ($issue in $Context.Issues.ToArray()) {
        $identity = [string](Get-PraValue $issue 'Identity' '')
        $source = [string](Get-PraValue $issue 'Source' 'Execution')
        if ($source -eq 'Execution' -and $identity -and $errorIdentities.ContainsKey($identity)) { continue }
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
        if ($key -eq 'AlreadyDone') { $key = 'Success' }
        $counts[$key]++
    }
    $requested = [string](Get-PraValue $Context 'ResultStatus' '')
    $code = 0; $status = 'Success'
    if ($counts.Error -gt 0 -or $Context.Issues.Count -gt 0 -or [int]$Context.ExitCode -eq 1 -or $Context.CloudConnectFailed -or $requested -eq 'Failed') {
        $code = 1; $status = 'Failed'
    } elseif ($counts.Pending -gt 0) { $code = 2; $status = 'Pending' }
    elseif ($Context.Mode -ne 'Apply' -and $counts.Planned -gt 0) { $status = 'Planned' }
    return [pscustomobject]@{ Rows = $rows.ToArray(); Counts = $counts; Status = $status; ExitCode = $code }
}

function ConvertTo-PraHtmlText {
    param([AllowNull()][object]$Value)
    if ($null -eq $Value) { return '' }
    return [Net.WebUtility]::HtmlEncode([string]$Value)
}

function Get-PraReportHtml {
    <#
    .SYNOPSIS
        Builds the HTML report from templates\Report.template.html. Every value is HTML-encoded.
    #>
    [CmdletBinding()]
    param([hashtable]$Context, $Outcome)
    $templatePath = Join-Path $Context.Root 'templates\Report.template.html'
    $template = if (Test-Path -LiteralPath $templatePath -PathType Leaf) { [IO.File]::ReadAllText($templatePath, [Text.Encoding]::UTF8) }
        else { '<!doctype html><html><head><meta charset="utf-8"><title>{{TITLE}}</title></head><body><h1>{{TITLE}}</h1><p>{{SUBTITLE}}</p>{{TILES}}{{WARNINGS}}{{ROWS_TABLE}}{{ISSUES}}</body></html>' }
    $c = $Outcome.Counts
    $warningList = @(@(Get-PraValue $Context 'WarningList' @()) | ForEach-Object { $_ } | Where-Object { $null -ne $_ })
    $statusClass = @{ Success='ok'; Planned='info'; Pending='warn'; Failed='fail' }[$Outcome.Status]
    $tiles = New-Object Text.StringBuilder
    foreach ($tile in @(
            @('Result', $Outcome.Status, $statusClass), @('Objects', $Outcome.Rows.Count, ''), @('Done', $c.Success, 'ok'),
            @('Pending', $c.Pending, $(if ($c.Pending) { 'warn' } else { '' })), @('Errors', $c.Error, $(if ($c.Error) { 'fail' } else { '' })),
            @('Warnings', $warningList.Count, $(if ($warningList.Count) { 'warn' } else { '' })),
            @('Planned', $c.Planned, $(if ($c.Planned) { 'info' } else { '' })), @('Skipped', $c.Skipped, ''))) {
        [void]$tiles.AppendFormat('<div class="tile {2}"><div class="tile-label">{0}</div><div class="tile-value">{1}</div></div>', (ConvertTo-PraHtmlText $tile[0]), (ConvertTo-PraHtmlText $tile[1]), $tile[2])
    }
    $table = New-Object Text.StringBuilder
    [void]$table.Append('<table id="rows"><thead><tr><th>Object</th><th>Type</th><th>Status</th><th>Active Directory</th><th>Licence group</th><th>Exchange Online</th><th>Permissions</th><th>Detail</th></tr></thead><tbody>')
    foreach ($row in $Outcome.Rows) {
        $status = [string]$row.FinalStatus
        $ad = if ($row.ADVerified -eq $true) { 'verified' + $(if ($row.ADApplied -eq $true) { ' (changed)' } else { ' (no change)' }) } elseif ($row.ADVerified -eq $false) { 'NOT verified' } else { '-' }
        $cloud = if ([string]$row.CloudStatus -and [string]$row.CloudStatus -ne 'N/A') { [string]$row.CloudStatus + $(if ($row.DeprovisionConfirmed -eq $true) { ' (deprovisioned)' } else { '' }) } else { '-' }
        $detail = (@([string]$row.CloudDetail, [string]$row.Detail) | Where-Object { $_ }) -join ' | '
        $rowWarning = [string](Get-PraValue $row 'Warnings' '')
        $detailHtml = $(if ($rowWarning) { '<div class="row-warn">&#9650; ' + (ConvertTo-PraHtmlText $rowWarning) + '</div>' } else { '' }) + (ConvertTo-PraHtmlText $detail)
        [void]$table.AppendFormat('<tr class="st-{0}{10}"><td><strong>{1}</strong><br><small>{2}</small></td><td>{3}</td><td><span class="badge {0}">{4}</span></td><td>{5}</td><td>{6}</td><td>{7}</td><td>{8}</td><td class="detail">{9}</td></tr>',
            $status.ToLowerInvariant(), (ConvertTo-PraHtmlText $row.SamAccountName), (ConvertTo-PraHtmlText $row.UserPrincipalName),
            $(if ($row.IsShared -eq $true) { 'Shared' } elseif ($row.SamAccountName) { 'User' } else { '-' }), (ConvertTo-PraHtmlText $status),
            (ConvertTo-PraHtmlText $ad), (ConvertTo-PraHtmlText $(if ($row.GroupAction) { $row.GroupAction } else { '-' })), (ConvertTo-PraHtmlText $cloud),
            (ConvertTo-PraHtmlText $(if ($row.PermDetail) { $row.PermDetail } else { '-' })), $detailHtml, $(if ($rowWarning) { ' has-warn' } else { '' }))
    }
    [void]$table.Append('</tbody></table>')
    # Every column of the CSV, for the technical review.
    [void]$table.Append('<details class="raw"><summary>All columns (same as the CSV)</summary><div class="scroll"><table class="raw"><thead><tr>')
    foreach ($field in $script:RowFields) { [void]$table.AppendFormat('<th>{0}</th>', (ConvertTo-PraHtmlText $field)) }
    [void]$table.Append('</tr></thead><tbody>')
    foreach ($row in $Outcome.Rows) {
        [void]$table.Append('<tr>')
        foreach ($field in $script:RowFields) { [void]$table.AppendFormat('<td>{0}</td>', (ConvertTo-PraHtmlText (Get-PraValue $row $field ''))) }
        [void]$table.Append('</tr>')
    }
    [void]$table.Append('</tbody></table></div></details>')
    $issues = New-Object Text.StringBuilder
    $warningsHtml = New-Object Text.StringBuilder
    if ($warningList.Count) {
        [void]$warningsHtml.Append('<section class="card warnings"><h2>&#9650; Warnings</h2><table><thead><tr><th>Time</th><th>Step</th><th>Message</th></tr></thead><tbody>')
        foreach ($warning in $warningList) {
            [void]$warningsHtml.AppendFormat('<tr><td>{0}</td><td>{1}</td><td>{2}</td></tr>', (ConvertTo-PraHtmlText (Get-PraValue $warning 'Timestamp' '')),
                (ConvertTo-PraHtmlText (Get-PraValue $warning 'Phase' '')), (ConvertTo-PraHtmlText (Get-PraValue $warning 'Message' ([string]$warning))))
        }
        [void]$warningsHtml.Append('</tbody></table></section>')
    }
    if ($Context.Issues.Count) {
        [void]$issues.Append('<section class="card"><h2>Run errors</h2><table><thead><tr><th>Time</th><th>Step</th><th>Operation</th><th>Object</th><th>Source</th><th>Message</th></tr></thead><tbody>')
        foreach ($issue in $Context.Issues.ToArray()) {
            [void]$issues.AppendFormat('<tr><td>{0}</td><td>{1}</td><td>{2}</td><td>{3}</td><td>{4}</td><td>{5}</td></tr>',
                (ConvertTo-PraHtmlText (Get-PraValue $issue 'Timestamp' '')), (ConvertTo-PraHtmlText (Get-PraValue $issue 'Phase' '')),
                (ConvertTo-PraHtmlText (Get-PraValue $issue 'Operation' '')), (ConvertTo-PraHtmlText (Get-PraValue $issue 'Identity' '')),
                (ConvertTo-PraHtmlText (Get-PraValue $issue 'Source' '')), (ConvertTo-PraHtmlText (Get-PraValue $issue 'Message' ([string]$issue))))
        }
        [void]$issues.Append('</tbody></table></section>')
    }
    $modeText = if ($Context.Mode -eq 'Apply') { 'Apply' } else { 'Preview - nothing changed' }
    $meta = [ordered]@{
        'Action' = ('{0} · phase {1} · {2}' -f $Context.Action, $Context.Phase, $modeText)
        'Environment' = [string](Get-PraValue $Context.Config 'Environment' '')
        'Batch' = [string](Get-PraValue $Context 'BatchId' '')
        'Domain controller' = [string]$Context.Server
        'Computer / account' = ('{0} · {1}\{2}' -f $env:COMPUTERNAME, $env:USERDOMAIN, $env:USERNAME)
        'Started' = ([datetime]$Context.StartTime).ToString('yyyy-MM-dd HH:mm:ss')
        'Duration' = (Format-PraDuration ((Get-Date) - [datetime]$Context.StartTime).TotalSeconds)
        'Run ID' = [string]$Context.RunId
    }
    $metaHtml = New-Object Text.StringBuilder
    foreach ($key in $meta.Keys) { if ($meta[$key]) { [void]$metaHtml.AppendFormat('<div><span>{0}</span>{1}</div>', (ConvertTo-PraHtmlText $key), (ConvertTo-PraHtmlText $meta[$key])) } }
    $next = @(@(Get-PraValue $Context 'NextSteps' @()) | ForEach-Object { $_ } | Where-Object { $_ })
    $nextHtml = ''
    if ($next.Count) { $nextHtml = '<section class="card next"><h2>Next step</h2>' + (($next | ForEach-Object { '<pre>' + (ConvertTo-PraHtmlText $_) + '</pre>' }) -join '') + '</section>' }
    $values = @{
        '{{TITLE}}' = ConvertTo-PraHtmlText ('PRA Remote Mailbox - {0}' -f $Context.Action)
        '{{SUBTITLE}}' = ConvertTo-PraHtmlText ('{0} · {1}' -f $modeText, ([datetime]$Context.StartTime).ToString('yyyy-MM-dd HH:mm'))
        '{{VERSION}}' = ConvertTo-PraHtmlText $Context.Version
        '{{META}}' = $metaHtml.ToString(); '{{TILES}}' = $tiles.ToString(); '{{NEXT}}' = $nextHtml
        '{{ROWS_TABLE}}' = $table.ToString(); '{{ISSUES}}' = $issues.ToString(); '{{WARNINGS}}' = $warningsHtml.ToString()
    }
    foreach ($key in $values.Keys) { $template = $template.Replace($key, $values[$key]) }
    return $template
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
                if ($format -eq 'Csv') {
                    if ($outcome.Rows.Count) { $outcome.Rows | Export-Csv -LiteralPath $Reports.Csv -NoTypeInformation -Delimiter ';' -Encoding UTF8 -WhatIf:$false -Confirm:$false -ErrorAction Stop }
                    else { Set-Content -LiteralPath $Reports.Csv -Value ('"' + ($script:RowFields -join '";"') + '"') -Encoding UTF8 -WhatIf:$false -Confirm:$false -ErrorAction Stop }
                } else {
                    [IO.File]::WriteAllText($Reports.Html, (Get-PraReportHtml -Context $Context -Outcome $outcome), (New-Object Text.UTF8Encoding($true)))
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
    if (([int]$Context.ExitCode -ne 0 -or $Context.CloudConnectFailed -or (Get-PraValue $Context 'ResultStatus' '') -eq 'Failed') -and $Context.Issues.Count -eq 0) {
        Add-PraIssue $Context 'Failure reported by the run (exit code / cloud connection).' 'Run'
    }
    foreach ($key in @('LogFile','TranscriptPath','BackupFiles','StateFiles')) {
        $candidates = Get-PraValue $Context $key
        if ($key -in @('LogFile','TranscriptPath')) { $candidates = [string]$candidates }
        if ($key -eq 'TranscriptPath' -and -not (Get-PraValue $Context '_PraTranscriptCreated' $false)) { $candidates = '' }
        foreach ($path in $candidates) {
            try {
                if (-not $path -or -not (Test-Path -LiteralPath $path -PathType Leaf)) { throw 'file not found' }
                $file = Get-Item -LiteralPath $path -ErrorAction Stop
                if ($file.Length -eq 0 -and $key -ne 'StateFiles') { throw 'empty file' }
                if ($key -in @('BackupFiles','StateFiles')) { $paths[$key] += $file.FullName } else { $paths[$key] = $file.FullName }
            } catch { Add-PraIssue $Context ('Audit file {0} unavailable: {1}' -f $key, $_.Exception.Message) 'Audit' }
        }
    }
    if (-not $Context.NoReport) {
        try {
            $null = New-Item -ItemType Directory -Path $Context.ReportFolder -Force -WhatIf:$false -Confirm:$false -ErrorAction Stop
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

    # Summary card.
    $outcome = Get-PraOutcome $Context
    $c = $outcome.Counts
    $isApply = $Context.Mode -eq 'Apply'
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
        if ($status -eq 'Ok') { $status = 'Warn'; $title += (' {0} {1} warning(s)' -f [char]0x00B7, $warningList.Count) }
    }
    if ($paths.BackupFiles.Count) { $values['Backup'] = @('Backup', @($paths.BackupFiles)) }
    if ($reports.Html -and -not $reports.HtmlFailed) { $values['Report'] = @('Report', $reports.Html) }
    if ($paths.LogFile) { $values['Log'] = @('Log', $paths.LogFile) }
    $values['Duration'] = @('Clock', (Format-PraDuration ((Get-Date) - [datetime]$Context.StartTime).TotalSeconds))
    $next = @(@(Get-PraValue $Context 'NextSteps' @()) | ForEach-Object { $_ } | Where-Object { $_ })
    if ($outcome.ExitCode -ne 1 -and $next.Count) { $values['Next'] = @('Next', $next) }
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
    }
    Write-PraEvent -Kind result -Data @{ status = $result.Status; exitCode = $result.ExitCode
        action = $result.Action; mode = $result.Mode; phase = $result.Phase
        success = $result.SuccessCount; error = $result.ErrorCount; pending = $result.PendingCount
        skipped = $result.SkippedCount; planned = $result.PlannedCount; total = $result.TotalCount
        seconds = [int]$result.Duration.TotalSeconds; batchId = $result.BatchId; nextSteps = @($result.NextSteps)
        logFile = $result.LogFile; csvReport = $result.CsvReport; htmlReport = $result.HtmlReport
        warnings = $result.WarningCount; backupFiles = @($result.BackupFiles); stateFiles = @($result.StateFiles)
        issues = @($result.Issues | ForEach-Object { [string](Get-PraValue $_ 'Message' ([string]$_)) }) }
    return $result
}
#endregion

Export-ModuleMember -Function Get-PraValue, Format-PraDuration, Add-PraIssue, Write-PraLog, Write-PraItem, Write-PraBanner, Write-PraStep,
    Write-PraSummary, Write-PraHost, Resolve-PraPath, Import-PraConfiguration, Initialize-PraAudit, Get-PraOutcome, Complete-PraRun, Write-PraEvent, Get-PraTargetOverride, Read-PraTargetCsv
