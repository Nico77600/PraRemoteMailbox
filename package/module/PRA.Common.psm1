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
    Version : 2.2.0
    History : see CHANGELOG.md
#>
#Requires -Version 5.1
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
    if ([string]$signature.Status -cne 'Valid' -or $null -eq $signature.SignerCertificate -or
        $signature.SignerCertificate.Thumbprint -cne '0F28E442889F17B5F4D251E8F96E7CC6E2C9C6D6' -or
        $null -eq $signature.TimeStamperCertificate) {
        throw 'Package integrity: verifier must have the trusted, timestamped owner signature.'
    }
    & $verifier -Root $PackageRoot
} ([IO.Path]::GetDirectoryName($PSScriptRoot))
# <<< PRA package integrity bootstrap

$script:ToolVersion = '2.2.0'
$script:TranscriptOwner = $null
$script:PraNativePath = $null
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
          │  ♦  PRA Remote Mailbox                           v2.2.0 · Nicolas Fabert   │
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

function Get-PraNativePathApi {
    <# Two kernel32 calls (open a handle, read its final path) bound in memory with Reflection.Emit (static AssemblyBuilder.DefineDynamicAssembly, one-argument DefineDynamicModule and CreateType: the same calls in Windows PowerShell 5.1 and PowerShell 7): no compiler, temporary file, DLL or cache. #>
    if ($script:PraNativePath) { return $script:PraNativePath }
    $assembly = [Reflection.Emit.AssemblyBuilder]::DefineDynamicAssembly((New-Object Reflection.AssemblyName 'PraNativePath'), [Reflection.Emit.AssemblyBuilderAccess]::Run)
    $type = $assembly.DefineDynamicModule('PraNativePath').DefineType('Api', 'Public,Class,Sealed,Abstract')
    $flags = [Reflection.MethodImplAttributes]::PreserveSig
    $open = $type.DefinePInvokeMethod('CreateFileW', 'kernel32.dll', 'Public,Static,PinvokeImpl', [Reflection.CallingConventions]::Standard,
        [Microsoft.Win32.SafeHandles.SafeFileHandle], [Type[]]@([string], [uint32], [uint32], [IntPtr], [uint32], [uint32], [IntPtr]),
        [Runtime.InteropServices.CallingConvention]::Winapi, [Runtime.InteropServices.CharSet]::Unicode)
    $open.SetImplementationFlags($flags)
    $final = $type.DefinePInvokeMethod('GetFinalPathNameByHandleW', 'kernel32.dll', 'Public,Static,PinvokeImpl', [Reflection.CallingConventions]::Standard,
        [uint32], [Type[]]@([Microsoft.Win32.SafeHandles.SafeFileHandle], [Text.StringBuilder], [uint32], [uint32]),
        [Runtime.InteropServices.CallingConvention]::Winapi, [Runtime.InteropServices.CharSet]::Unicode)
    $final.SetImplementationFlags($flags)
    $script:PraNativePath = $type.CreateType()
    return $script:PraNativePath
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
        if (@($full.Split('\') | Select-Object -Skip 3 | Where-Object { $_ -eq '.' -or $_ -eq '..' }).Count) { throw "Path $Path uses a device namespace with relative segments; it cannot be resolved safely." }
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
              elseif ($existing.StartsWith('\\')) { '\\?\UNC\' + $existing.Substring(2) }
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
    elseif ($physical.StartsWith('\\?\')) { throw "Path $Path cannot be resolved to a drive or share path ($physical); refusing the ambiguous namespace." }
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
    $lexical = $full -ieq $rootFull -or $full.StartsWith($rootFull + '\', [StringComparison]::OrdinalIgnoreCase)
    if ($lexical) {
        $relative = $full.Substring($rootFull.Length).TrimStart('\')
        $first = if ($relative) { $relative.Split('\')[0] } else { '' }
        if ($first -cne $Canonical) {
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
    $inside = $physical -ieq $physicalRoot -or $physical.StartsWith($physicalRoot + '\', [StringComparison]::OrdinalIgnoreCase)
    if (-not $inside) {
        if ($lexical) { throw "Configuration: $Name ($full) is inside the signed package but resolves outside it ($physical); the location is ambiguous and is refused." }
        return $full
    }
    $relative = $physical.Substring($physicalRoot.Length).TrimStart('\')
    $first = if ($relative) { $relative.Split('\')[0] } else { '' }
    if ($first -cne $Canonical) {
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
        # Same lookup as Get-PraValue (missing and $null both give $null), inlined: this loop runs 22 times per row on very large runs.
        foreach ($field in $script:RowFields) {
            $value = $null
            if ($row -is [System.Collections.IDictionary]) { foreach ($entry in $row.GetEnumerator()) { if ($entry.Key -eq $field) { $value = $entry.Value; break } } }
            elseif ($null -ne $row) { $property = $row.PSObject.Properties[$field]; if ($null -ne $property) { $value = $property.Value } }
            $copy[$field] = $value
        }
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

$script:ReportChunkRows = 20000
$script:ReportChunkChars = 4000000
$script:JsonEscape = New-Object Text.RegularExpressions.Regex('["\\\u0000-\u001f\u007f-\u009f\u2028\u2029<>&]')
$script:JsonEscapeEvaluator = [Text.RegularExpressions.MatchEvaluator]{
    param($m)
    switch ($m.Value) {
        '"' { '\"' } '\' { '\\' } "`n" { '\n' } "`r" { '\r' } "`t" { '\t' } "`b" { '\b' } "`f" { '\f' }
        default { '\u' + ([int][char]$m.Value).ToString('x4') }
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

# SIG # Begin signature block
# MIIghgYJKoZIhvcNAQcCoIIgdzCCIHMCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCAwcYk12WSytR7d
# EtGwZf/WQGmLpRLOo3JA1Z3Y7A1q9KCCDW8wggZyMIIEWqADAgECAghkM1HTxzif
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
# wZislcdCZuS6MYISbTCCEmkCAQEwgYwweDELMAkGA1UEBhMCVVMxDjAMBgNVBAgM
# BVRleGFzMRAwDgYDVQQHDAdIb3VzdG9uMREwDwYDVQQKDAhTU0wgQ29ycDE0MDIG
# A1UEAwwrU1NMLmNvbSBDb2RlIFNpZ25pbmcgSW50ZXJtZWRpYXRlIENBIFJTQSBS
# MQIQBof4ljXihJpmCqqt2mhAWzANBglghkgBZQMEAgEFAKCBhDAYBgorBgEEAYI3
# AgEMMQowCKACgAChAoAAMBkGCSqGSIb3DQEJAzEMBgorBgEEAYI3AgEEMBwGCisG
# AQQBgjcCAQsxDjAMBgorBgEEAYI3AgEVMC8GCSqGSIb3DQEJBDEiBCDhTJ/wvXuA
# jiKtTQXYWmczRsfoVuDDT5fb7srrzC5SJDANBgkqhkiG9w0BAQEFAASCAgBdIcmO
# KGBqQL1ohgOvbien16tKGsndEv/JiLrZNU86jrTmNAkIK3nilYmwGKCx0wAZHXq/
# joS1VPnCGezm1lqvJyOgpEJvEwE4XoIqTewgW7X2N21/KJPdHLf1ODmu9KYZCKC9
# 9g1lnMeUMmgbewAigG+6DnsVcKYHgjBQtCAMTkEheaCgmfQQSRMizDvujbFUizQg
# LhIrTQfi7OJooH6yKwH/J1aLP/s2ONO1q+hAqwVXOO2GWyie7XZR4sd+utHbnJ2P
# SiUPrRf0Xqdq+kzWdUhwiBlVmA7QxTkH2Q1F2rNcE0mvCfSyQz8kSI2BAp9KG2JC
# +hZ5LIDIsWP+Zb2ryZQDEVmuVTCIe441tBsEflZg6XUSYZ+imUm40EfYpzsWSvEQ
# w2/il1Lp+BYEUTo1CrRsbt9FVvpb1dPgeVpTAhP341M64ny26DH9bG/XPvB5tNlF
# jaeD1j1t6q/zQQmdY8bv/v52uFBimt+2XXlI+oyEFKNtbNNRdF55PAcxshR7d8G3
# 2A2YikTFe/17l5jE9ebMfJ9rkrkUT8WiGxdYLKlpa0N7qo8F6jGknoKvfSVQ414F
# 4E7sblacW2YmrQlItJuBgkxCe1nbWfU5mmAjlqmdVIPWlWsZtEj+BSLy6yeGLlgo
# SqnD4MK+BUEx9UWkyvc9oD4KjmQFekx0lFCHTaGCDyowgg8mBgorBgEEAYI3AwMB
# MYIPFjCCDxIGCSqGSIb3DQEHAqCCDwMwgg7/AgEDMQ0wCwYJYIZIAWUDBAIBMIGJ
# BgsqhkiG9w0BCRABBKB6BHgwdgIBAQYMKwYBBAGCqTABAwYBMDEwDQYJYIZIAWUD
# BAIBBQAEIILWa6WE9OSfWm8RDM7wlTeUU7Kn82w9r5+edx5ml6chAghk1kPd6MXd
# 0BgPMjAyNjEwMTUyMTIzMDBaMAMCAQECEA+LtX+62FBNxpOJANoEKbagggwAMIIE
# /DCCAuSgAwIBAgIQH2sWYtIuG2xd8cDBoGAOODANBgkqhkiG9w0BAQsFADBzMQsw
# CQYDVQQGEwJVUzEOMAwGA1UECAwFVGV4YXMxEDAOBgNVBAcMB0hvdXN0b24xETAP
# BgNVBAoMCFNTTCBDb3JwMS8wLQYDVQQDDCZTU0wuY29tIFRpbWVzdGFtcGluZyBJ
# c3N1aW5nIFJTQSBDQSBSMTAeFw0yNTAyMTgxNjMyMDJaFw0zNDExMTIxODUwMDVa
# MG4xCzAJBgNVBAYTAlVTMQ4wDAYDVQQIDAVUZXhhczEQMA4GA1UEBwwHSG91c3Rv
# bjERMA8GA1UECgwIU1NMIENvcnAxKjAoBgNVBAMMIVNTTC5jb20gVGltZXN0YW1w
# aW5nIFVuaXQgMjAyNSBFMTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABBv7UVHH
# b+ZVluxPXlfE3M6tg0Xnq8dic+O3vPOCRpalUM1vO9A+GRzSVVjyygHhYrBw62XL
# Fh1kv7e+yRd/aTajggFaMIIBVjAfBgNVHSMEGDAWgBQMnRAljpqnG5mHQ88IfuG9
# gZD0zzBRBggrBgEFBQcBAQRFMEMwQQYIKwYBBQUHMAKGNWh0dHA6Ly9jZXJ0LnNz
# bC5jb20vU1NMLmNvbS10aW1lU3RhbXBpbmctSS1SU0EtUjEuY2VyMFEGA1UdIARK
# MEgwPAYMKwYBBAGCqTABAwYBMCwwKgYIKwYBBQUHAgEWHmh0dHBzOi8vd3d3LnNz
# bC5jb20vcmVwb3NpdG9yeTAIBgZngQwBBAIwFgYDVR0lAQH/BAwwCgYIKwYBBQUH
# AwgwRgYDVR0fBD8wPTA7oDmgN4Y1aHR0cDovL2NybHMuc3NsLmNvbS9TU0wuY29t
# LXRpbWVTdGFtcGluZy1JLVJTQS1SMS5jcmwwHQYDVR0OBBYEFM582cAEgMUkEGoJ
# 6hyrJT0R/ajSMA4GA1UdDwEB/wQEAwIHgDANBgkqhkiG9w0BAQsFAAOCAgEAgHN1
# JIW9ZlNip07FfY9r1LJwLKTl1h/y9r1BjDgHMEz7U7J7mAy32JxA1KLyjCCJqNku
# RfhDHGFEfZtjTOru7AQMDSDiUDvCCc3jaz5py9jGvwIe5npkLbXqXhA+SqCzG719
# USigwhHkYr7v8NiXoaY0Xu03p0BiZZreZlpngmGB9+86N94FqIFx2I5Z5iuu7d4j
# 7aAOZBNxfU9jFDIIGDtWfWeCpF0Q8rLE/3DHDlzJKs5Il3i/VoOl7rTU938oSrxM
# www6GDBlKX8rGHxvkjgIb9MXkVglJSDHsNAZDeCS/inaxKHA+ChuB8K4OxIxa6k1
# e+eHBypakAY3wuN7w7PlPmhN6k5IdqZn3HZHs2VjoR841Z9wmVPFdGDdkBZ7XOmb
# 5OZUaKufsvtER0VbY2DkzaqAaItt1kc+I+FUz7PiVz2PUzpegkftRRxvrPyIL08b
# lJTnbMQ0XrqDN0rEfuTLv4XhhnKyJaXhxCUdjO/cRumMzZ35QTUMItBWy1xGp0iy
# oFVnAya2pPsVMuAI+sy1zxlOS9l5iSxvKJ8gpnpOgjqYTa7u1eyZo+4JlcGoiiR1
# 7LthMTrF1q62tO5xOpI8txUZ6gtKGtkJV6wdj+vZLcwKZ2M93GqVpOo6UBlGjx1s
# KsVZ7AIUzJZli4NJ0M2KYcrfNnlebkYKpDnSqWwwggb8MIIE5KADAgECAhBtUhhw
# h+gjTYVgANCAj5NWMA0GCSqGSIb3DQEBCwUAMHwxCzAJBgNVBAYTAlVTMQ4wDAYD
# VQQIDAVUZXhhczEQMA4GA1UEBwwHSG91c3RvbjEYMBYGA1UECgwPU1NMIENvcnBv
# cmF0aW9uMTEwLwYDVQQDDChTU0wuY29tIFJvb3QgQ2VydGlmaWNhdGlvbiBBdXRo
# b3JpdHkgUlNBMB4XDTE5MTExMzE4NTAwNVoXDTM0MTExMjE4NTAwNVowczELMAkG
# A1UEBhMCVVMxDjAMBgNVBAgMBVRleGFzMRAwDgYDVQQHDAdIb3VzdG9uMREwDwYD
# VQQKDAhTU0wgQ29ycDEvMC0GA1UEAwwmU1NMLmNvbSBUaW1lc3RhbXBpbmcgSXNz
# dWluZyBSU0EgQ0EgUjEwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQCu
# URAT0vk8IKAghd7JUBxkyeH9xek0/wp/MUjoclrFXqhh/fGH91Fc+7fm0MHCE7A+
# wmOiqBj9ODrJAYGq3rm33jCnHSsCBNWAQYyoauLq8IjqsS1JlXL29qDNMMdwZ8UN
# zQS7vWZMDJ40JSGNphMGTIA2qn2bohGtgRc4p1395ESypUOaGvJ3t0FNL3BuKmb6
# YctMcQUF2sqooMzd89h0E6ujdvBDo6ZwNnWoxj7YmfWjSXg33A5GuY9ym4QZM5OE
# Vgo8ebz/B+gyhyCLNNhh4Mb/4xvCTCMVmNYrBviGgdPZYrym8Zb84TQCmSuX0JlL
# La6WK1aO6qlwISbb9bVGh866ekKblC/XRP20gAu1CjvcYciUgNTrGFg8f8AJgQPO
# Cc1/CCdaJSYwhJpSdheKOnQgESgNmYZPhFOC6IKaMAUXk5U1tjTcFCgFvvArXtK4
# azAWUOO1Y3fdldIBL6LjkzLUCYJNkFXqhsBVcPMuB0nUDWvLJfPimstjJ8lF4S6E
# CxWnlWi7OElVwTnt1GtRqeY9ydvvGLntU+FecK7DbqHDUd366UreMkSBtzevAc9a
# qoZPnjVMjvFqV1pYOjzmTiVHZtAc80bAfFe5LLfJzPI6DntNyqobpwTevQpHqPDN
# 9qqNO83r3kaw8A9j+HZiSw2AX5cGdQP0kG0vhzfgBwIDAQABo4IBgTCCAX0wEgYD
# VR0TAQH/BAgwBgEB/wIBADAfBgNVHSMEGDAWgBTdBAkHovV6fVJTEpKV7jiAJQ2m
# WTCBgwYIKwYBBQUHAQEEdzB1MFEGCCsGAQUFBzAChkVodHRwOi8vd3d3LnNzbC5j
# b20vcmVwb3NpdG9yeS9TU0xjb21Sb290Q2VydGlmaWNhdGlvbkF1dGhvcml0eVJT
# QS5jcnQwIAYIKwYBBQUHMAGGFGh0dHA6Ly9vY3Nwcy5zc2wuY29tMD8GA1UdIAQ4
# MDYwNAYEVR0gADAsMCoGCCsGAQUFBwIBFh5odHRwczovL3d3dy5zc2wuY29tL3Jl
# cG9zaXRvcnkwEwYDVR0lBAwwCgYIKwYBBQUHAwgwOwYDVR0fBDQwMjAwoC6gLIYq
# aHR0cDovL2NybHMuc3NsLmNvbS9zc2wuY29tLXJzYS1Sb290Q0EuY3JsMB0GA1Ud
# DgQWBBQMnRAljpqnG5mHQ88IfuG9gZD0zzAOBgNVHQ8BAf8EBAMCAYYwDQYJKoZI
# hvcNAQELBQADggIBAJIZdQ2mWkLPGQfZ8vyU+sCb8BXpRJZaL3Ez3VDlE3uZk3cP
# xPtybVfLuqaci0W6SB22JTMttCiQMnIVOsXWnIuAbD/aFTcUkTLBI3xys+wEajzX
# aXJYWACDS47BRjDtYlDW14gLJxf8W6DQoH3jHDGGy8kGJFOlDKG7/YrK7UGfHtBA
# EDVe6lyZ+FtCsrk7dD/IiL/+Q3Q6SFASJLQ2XI89ihFugdYL77CiDNXrI2MFspQG
# swXEAGpHuaQDTHUp/LdR3TyrIsLlnzoLskUGswF/KF8+kpWUiKJNC4rPWtNrxlbX
# YRGgdEdx8SMjUTDClldcrknlFxbqHsVmr9xkT2QtFmG+dEq1v5fsIK0vHaHrWjMM
# maJ9i+4qGJSD0stYfQ6v0PddT7EpGxGd867Ada6FZyHwbuQSadMb0K0P0OC2r7rw
# qBUe0BaMqTa6LWzWItgBjGcObXeMxmbQqlEz2YtAcErkZvh0WABDDE4U8GyV/32F
# daAvJgTfe9MiL2nSBioYe/g5mHUSWAay/Ip1RQmQCvmF9sNfqlhJwkjy/1U1ibUk
# TIUBX3HgymyQvqQTZLLys6pL2tCdWcjI9YuLw30rgZm8+K387L7ycUvqrmQ3ZJlu
# jHl3r1hgV76s3WwMPgKk1bAEFMj+rRXimSC+Ev30hXZdqyMdl/il5Ksd0vhGMYIC
# WTCCAlUCAQEwgYcwczELMAkGA1UEBhMCVVMxDjAMBgNVBAgMBVRleGFzMRAwDgYD
# VQQHDAdIb3VzdG9uMREwDwYDVQQKDAhTU0wgQ29ycDEvMC0GA1UEAwwmU1NMLmNv
# bSBUaW1lc3RhbXBpbmcgSXNzdWluZyBSU0EgQ0EgUjECEB9rFmLSLhtsXfHAwaBg
# DjgwCwYJYIZIAWUDBAIBoIIBYTAaBgkqhkiG9w0BCQMxDQYLKoZIhvcNAQkQAQQw
# HAYJKoZIhvcNAQkFMQ8XDTI2MTAxNTIxMjMwMFowKAYJKoZIhvcNAQk0MRswGTAL
# BglghkgBZQMEAgGhCgYIKoZIzj0EAwIwLwYJKoZIhvcNAQkEMSIEIHUDDr9rfXfv
# mNBjs65F5hfCoU1Bbm+RNJw5ipkU+wLoMIHJBgsqhkiG9w0BCRACLzGBuTCBtjCB
# szCBsAQgVCr5oWqNci5mEUl4iumUwYqaruWmXLNEolSa+Wx5x4swgYswd6R1MHMx
# CzAJBgNVBAYTAlVTMQ4wDAYDVQQIDAVUZXhhczEQMA4GA1UEBwwHSG91c3RvbjER
# MA8GA1UECgwIU1NMIENvcnAxLzAtBgNVBAMMJlNTTC5jb20gVGltZXN0YW1waW5n
# IElzc3VpbmcgUlNBIENBIFIxAhAfaxZi0i4bbF3xwMGgYA44MAoGCCqGSM49BAMC
# BEgwRgIhAME1sSMkGGh+DDAaB7053RYxbCJ4cHnTafJRXC34WHFdAiEAqd+tIzlg
# Ebn2H+JOgr+4PpygEiVuFdXRGP3FCRySdYk=
# SIG # End signature block
