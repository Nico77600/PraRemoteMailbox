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
    Version : 3.1.4
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
$script:ToolVersion = '3.1.4'
$script:TranscriptOwner = $null
$script:PraNativePath = $null
$script:PraNativeProcess = $null
$script:PraEventWriteWarned = $false
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
        -DateKind String (PowerShell 7.5+) keeps every date as the string that was written,
        so a file written by any version of the tool is read the same way.
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
# "a<U+0001>" (or "a<U+200B>") as EQUAL (the "c" operators only drop the case, never the culture).
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

function Resolve-PraOfficialValue {
    <# The official spelling of Value among Set (ordinal, ignoring the case), or $null when Value is none of them. #>
    [OutputType([string])]
    param([AllowNull()][object]$Value, [Parameter(Mandatory)][object[]]$Set)
    if ($null -eq $Value) { return $null }
    foreach ($item in $Set) { if ([string]::Equals([string]$Value, [string]$item, [StringComparison]::OrdinalIgnoreCase)) { return [string]$item } }
    return $null
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

function Get-PraOrdinalSorted {
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

$script:PraRecordIndexCache = New-Object 'Runtime.CompilerServices.ConditionalWeakTable[object,object]'

function New-PraRecordIndex {
    <# The records of a list by ObjectGuid (ordinal, ignoring the case): ByGuid finds one record without scanning the list, Duplicates holds the GUIDs that more than one record carries (the first record is kept). #>
    [CmdletBinding()]
    param([AllowNull()][AllowEmptyCollection()][object]$Record)
    $map = New-Object 'Collections.Generic.Dictionary[string,object]' ([StringComparer]::OrdinalIgnoreCase)
    $duplicates = New-Object 'Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    $count = 0
    foreach ($item in @($Record)) {
        if ($null -eq $item) { continue }
        $count++
        $key = [string]$item.ObjectGuid
        if ($map.ContainsKey($key)) { [void]$duplicates.Add($key); continue }
        $map.Add($key, $item)
    }
    return [pscustomobject]@{ ByGuid = $map; Duplicates = $duplicates; Count = $count }
}

function Get-PraRecordIndex {
    <# New-PraRecordIndex of a records array, built once: the same array (and the same number of records) gives the same index. A value that is not an array is indexed each time. #>
    [CmdletBinding()]
    param([AllowNull()][AllowEmptyCollection()][object]$Record)
    if ($Record -is [object[]]) {
        $cached = $null
        if ($script:PraRecordIndexCache.TryGetValue($Record, [ref]$cached) -and $cached.Count -eq $Record.Length) { return $cached }
        $index = New-PraRecordIndex -Record $Record
        $script:PraRecordIndexCache.AddOrUpdate($Record, $index)
        return $index
    }
    return (New-PraRecordIndex -Record $Record)
}

function Find-PraRecord {
    <# The record of an index (New-PraRecordIndex, Get-PraRecordIndex) for a GUID in any letter case; $null when there is none. #>
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Index, [AllowNull()][AllowEmptyString()][string]$Guid)
    $found = $null
    if ($Guid -and $Index.ByGuid.TryGetValue($Guid, [ref]$found)) { return $found }
    return $null
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

# Minimum versions of the cloud modules. The Microsoft Graph modules are used in ONE version for all of them (two versions of the same module cannot share a session).
$script:PraMinGraphVersion = '2.41.1'
$script:PraMinExoVersion = '3.10.1'

function Get-PraCloudModuleReport {
    <#
    .SYNOPSIS
        What the cloud part needs from this server, in plain words: ExchangeOnlineManagement at the minimum version or later, and ONE version of Microsoft.Graph.Authentication
        and Microsoft.Graph.Users (the same for both, minimum version or later). Reads the installed modules only; nothing is imported or connected.
    .DESCRIPTION
        Graph: the highest version that exists for BOTH modules and is at least the minimum. If a Microsoft Graph module is already loaded in this session, only that
        version is acceptable (another one cannot be loaded next to it). A set that does not exist, or a conflicting loaded version, gives a message with the versions
        found, the minimum and the exact Install-Module command. Used by the entry script (Preview and Apply, before any write), by the cloud module (the versions
        it imports) and by the window (the lights).
    .PARAMETER Available
        The installed modules (Get-Module -ListAvailable); read here when not given.
    .PARAMETER Loaded
        The modules already loaded in this session (Get-Module); read here when not given.
    .OUTPUTS
        Ok, Messages (one per problem), Graph (Ok, Version, Message) and Exo (Ok, Version, Message).
    #>
    [CmdletBinding()]
    param([string]$MinGraph = $script:PraMinGraphVersion, [string]$MinExo = $script:PraMinExoVersion, [object[]]$Available, [object[]]$Loaded)
    if (-not $PSBoundParameters.ContainsKey('Available')) {
        $Available = @(Get-Module -ListAvailable -Name 'Microsoft.Graph.Authentication', 'Microsoft.Graph.Users', 'ExchangeOnlineManagement' -SkipEditionCheck -ErrorAction SilentlyContinue)
    }
    if (-not $PSBoundParameters.ContainsKey('Loaded')) { $Loaded = @(Get-Module -Name 'Microsoft.Graph.*' -ErrorAction SilentlyContinue) }
    # The built-in minimum is the floor: a lower value in the configuration does not lower it.
    if ([version]$MinExo -lt [version]$script:PraMinExoVersion) { $MinExo = $script:PraMinExoVersion }
    $minGraphVersion = [version]$MinGraph; $minExoVersion = [version]$MinExo
    $versionsOf = {
        param([object[]]$Modules, [string]$Name)
        $found = New-Object 'Collections.Generic.List[version]'
        foreach ($module in @($Modules)) {
            if ($null -eq $module -or -not (Test-PraOrdinalIgnoreCaseEqual ([string]$module.Name) $Name)) { continue }
            $version = [version]$module.Version
            if (-not $found.Contains($version)) { $found.Add($version) }
        }
        $found.Sort(); $found.Reverse()
        return , $found
    }
    $texts = { param($List) if ($List.Count) { ($List | ForEach-Object { $_.ToString() }) -join ', ' } else { 'not installed' } }
    # Microsoft Graph.
    $auth = & $versionsOf $Available 'Microsoft.Graph.Authentication'
    $users = & $versionsOf $Available 'Microsoft.Graph.Users'
    $coherent = New-Object 'Collections.Generic.List[version]'
    foreach ($version in $auth) { if ($version -ge $minGraphVersion -and $users.Contains($version)) { $coherent.Add($version) } }
    # One Install-Module per module: PowerShellGet refuses -MinimumVersion when several names are given.
    $graphCommand = 'Install-Module Microsoft.Graph.Authentication -MinimumVersion {0} -Scope CurrentUser; Install-Module Microsoft.Graph.Users -MinimumVersion {0} -Scope CurrentUser' -f $MinGraph
    $scopeHint = 'to install for every user, use -Scope AllUsers in a window opened as administrator'
    $graph = [ordered]@{ Ok = $false; Version = ''; Message = '' }
    $loadedVersions = New-Object 'Collections.Generic.List[version]'
    foreach ($module in @($Loaded)) {
        if ($null -eq $module -or -not ([string]$module.Name).StartsWith('Microsoft.Graph.', [StringComparison]::OrdinalIgnoreCase)) { continue }
        if (-not $loadedVersions.Contains([version]$module.Version)) { $loadedVersions.Add([version]$module.Version) }
    }
    if ($loadedVersions.Count -gt 1) {
        $graph.Message = 'Microsoft Graph: several versions are loaded in this PowerShell session ({0}). Close this window and start the tool in a new PowerShell 7 window.' -f (& $texts $loadedVersions)
    }
    elseif ($loadedVersions.Count -eq 1 -and -not $coherent.Contains($loadedVersions[0])) {
        $graph.Message = 'Microsoft Graph {0} is already loaded in this PowerShell session, but the tool needs Microsoft.Graph.Authentication and Microsoft.Graph.Users in one same version {1} or later (found: Authentication {2}; Users {3}). Close this window, install the modules if needed ({4}) and start the tool in a new PowerShell 7 window.' -f
            $loadedVersions[0], $MinGraph, (& $texts $auth), (& $texts $users), $graphCommand
    }
    elseif ($loadedVersions.Count -eq 1) { $graph.Ok = $true; $graph.Version = $loadedVersions[0].ToString() }
    elseif ($coherent.Count) { $graph.Ok = $true; $graph.Version = $coherent[0].ToString() }
    else {
        # Versions are listed only for a module that is installed; a missing one is said so.
        $present = @(); $absent = @()
        foreach ($pair in @(@('Microsoft.Graph.Authentication', $auth), @('Microsoft.Graph.Users', $users))) {
            if ($pair[1].Count) { $present += ('{0} {1}' -f $pair[0], (& $texts $pair[1])) } else { $absent += ('{0} is not installed' -f $pair[0]) }
        }
        $inventory = (@($(if ($present.Count) { 'found ' + ($present -join '; ') } else { @() })) + $absent) -join '; '
        $graph.Message = 'Microsoft Graph: {0}. The tool needs both in one same version {1} or later. Run: {2} (one command per module, the same version for both; {3}).' -f $inventory, $MinGraph, $graphCommand, $scopeHint
    }
    # Exchange Online.
    $exoVersions = & $versionsOf $Available 'ExchangeOnlineManagement'
    $exo = [ordered]@{ Ok = $false; Version = ''; Message = '' }
    if ($exoVersions.Count -and $exoVersions[0] -ge $minExoVersion) { $exo.Ok = $true; $exo.Version = $exoVersions[0].ToString() }
    else {
        $exo.Message = 'ExchangeOnlineManagement: {0}; the tool needs {1} or later. Run: Install-Module ExchangeOnlineManagement -MinimumVersion {1} -Scope CurrentUser ({2}).' -f $(if ($exoVersions.Count) { 'found ' + (& $texts $exoVersions) } else { 'not installed' }), $MinExo, $scopeHint
    }
    $messages = @(@($graph.Message, $exo.Message) | Where-Object { $_ })
    return [pscustomobject]@{ Ok = ($graph.Ok -and $exo.Ok); Messages = $messages; Graph = [pscustomobject]$graph; Exo = [pscustomobject]$exo }
}

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
        if ($Object.Contains($Name)) { return ,($Object[$Name]) }
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

function ConvertTo-PraImmutableId {
    <# The onPremisesImmutableId that a GUID gives: the base64 text of its 16 bytes in Active Directory byte order. A GUID (object, text or 16 bytes) only; $null for anything else, the empty GUID included. #>
    [CmdletBinding()]
    [OutputType([string])]
    param([AllowNull()][object]$Value)
    if ($null -eq $Value) { return $null }
    if ($Value -isnot [guid] -and $Value -isnot [byte[]] -and $Value -is [System.Collections.IEnumerable] -and $Value -isnot [string]) {
        $items = @($Value | Where-Object { $null -ne $_ })
        if ($items.Count -eq 1) { return (ConvertTo-PraImmutableId -Value $items[0]) }
        if ($items.Count -eq 16 -and -not @($items | Where-Object { $_ -isnot [byte] }).Count) { return (ConvertTo-PraImmutableId -Value ([byte[]]$items)) }
        return $null
    }
    $guid = [guid]::Empty
    if ($Value -is [guid]) { $guid = $Value }
    elseif ($Value -is [byte[]]) { if ($Value.Length -ne 16) { return $null }; $guid = [guid]::new([byte[]]$Value) }
    elseif (-not [guid]::TryParse([string]$Value, [ref]$guid)) { return $null }
    if ($guid -eq [guid]::Empty) { return $null }
    return [Convert]::ToBase64String($guid.ToByteArray())
}

function Get-PraSourceAnchor {
    <#
    .SYNOPSIS
        The source anchors of one Active Directory record, as the onPremisesImmutableId texts the Entra ID account may carry.
    .DESCRIPTION
        A record written by this version holds SourceAnchor (ObjectGuid and ConsistencyGuid, both base64); the Entra ID account is the right one when it carries either.
        A record without it (backup, transfer package or batch of an older version) has only its ObjectGuid: the anchor is derived from it (Recorded = $false).
        A record without a usable GUID has no anchor (Usable = $false). The texts are base64 and are compared exactly.
    #>
    [CmdletBinding()]
    param([AllowNull()][object]$Record)
    $candidates = New-Object 'Collections.Generic.List[string]'
    $stored = Get-PraValue $Record 'SourceAnchor' $null
    $recorded = $false
    if ($null -ne $stored) {
        foreach ($name in @('ConsistencyGuid', 'ObjectGuid')) {
            $text = [string](Get-PraValue $stored $name '')
            if ($text -cmatch '^[A-Za-z0-9+/]{22}==\z' -and -not $candidates.Contains($text)) { $candidates.Add($text); $recorded = $true }
        }
    }
    if (-not $recorded) {
        $derived = ConvertTo-PraImmutableId -Value (Get-PraValue $Record 'ObjectGuid' $null)
        if ($derived) { $candidates.Add($derived) }
    }
    return [pscustomobject]@{ Candidates = [string[]]$candidates.ToArray(); Recorded = $recorded; Usable = ($candidates.Count -gt 0) }
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

function ConvertTo-PraPlainMessage {
    <#
    .SYNOPSIS
        The text of an error without its stack: the lines "at Namespace.Type.Method(...)", "at <ScriptBlock>, file: line N" and "--- End of ... stack trace ---" are removed.
        The card, the console and the report show this text; the log keeps the whole detail. The empty parts that Exchange Online puts between its separators ("||You can't use...")
        are removed too, so that no stray pipe is shown.
    #>
    [CmdletBinding()]
    param([AllowNull()][AllowEmptyString()][string]$Text)
    if ([string]::IsNullOrEmpty($Text)) { return '' }
    $frame = '^\s*(at\s+(<[^>\r\n]+>|[^\s(,]+\([^\r\n]*|[^\s,]+,\s+[^\r\n]*?\bline\s+\d+[^\r\n]*)|---\s*End of [^\r\n]*---)\s*$'
    $kept = @([regex]::Split($Text, '\r?\n') | Where-Object { $_ -notmatch $frame })
    $plain = ($kept -join [Environment]::NewLine).TrimEnd()
    $plain = [regex]::Replace($plain, '\|(?:[ \t]*\|)+', '|')
    $plain = [regex]::Replace($plain, '(?m)^[ \t]*\|[ \t]*|(?<=:[ \t]+)\|[ \t]*', '')
    return ([regex]::Replace($plain, '(?m)[ \t]*\|[ \t]*(?=\r?$)', ''))
}

function Test-PraOwnEntryProcess {
    <#
    .SYNOPSIS
        True when this PowerShell process was started for one script or one command (pwsh -File, -Command or -EncodedCommand, without -NoExit): the console's child
        process, a scheduled task, a batch file. False for an interactive session where the operator typed the command: its window must never be closed by the run.
    .PARAMETER Arguments
        The command line of the process (the first item is the program); the process's own when not given.
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param([string[]]$Arguments = [Environment]::GetCommandLineArgs())
    $own = $false
    for ($i = 1; $i -lt $Arguments.Count; $i++) {
        $argument = [string]$Arguments[$i]
        if ($argument.Length -lt 2 -or -not ($argument.StartsWith('-', [StringComparison]::Ordinal) -or $argument.StartsWith('/', [StringComparison]::Ordinal))) { continue }
        $name = $argument.TrimStart('-', '/')
        if (Test-PraOrdinalIn $name @('noexit', 'noe') -IgnoreCase) { return $false }
        if (Test-PraOrdinalIn $name @('file', 'f', 'command', 'c', 'commandwithargs', 'cwa', 'encodedcommand', 'e', 'ec') -IgnoreCase) { $own = $true }
    }
    return $own
}

function Write-PraEvent {
    <# Optional JSONL channel to the window; CLI runs without PRA_EVENT_FILE are unchanged. A line that cannot be written (another program holds the file) never stops the run: it is tried three times, the first failure of the run is said once on the console. #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][ValidateSet('start','step','item','summary','result','plan','progress','count')][string]$Kind, [hashtable]$Data = @{})
    if (-not $env:PRA_EVENT_FILE) { return }
    $record = [ordered]@{ time = [datetime]::UtcNow.ToString('o'); kind = $Kind }
    foreach ($key in $Data.Keys) { $record[$key] = $Data[$key] }
    $line = ($record | ConvertTo-Json -Compress -Depth 8) + "`n"
    $reason = ''
    for ($attempt = 1; $attempt -le 3; $attempt++) {
        try {
            [IO.File]::AppendAllText($env:PRA_EVENT_FILE, $line, (New-Object Text.UTF8Encoding($false)))
            return
        }
        catch {
            $reason = [string]$_.Exception.Message
            if ($attempt -lt 3) { Start-Sleep -Milliseconds 50 }
        }
    }
    if (-not $script:PraEventWriteWarned) {
        $script:PraEventWriteWarned = $true
        try { Write-PraHost @('      ', (Get-PraIcon 'Warn'), ('The progress file of the window cannot be written ({0}): the run goes on, the window may miss some events.' -f $reason)) -Color $script:Theme.Warn } catch { $null = $_ }
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
    <# Appends one line (or, with -Lines, a block of lines in one write) to the log file. A log that cannot be written stops the run (audit). #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingWriteHost','',Justification='Last-resort console message when the log is broken.')]
    param([Parameter(Mandatory)][hashtable]$Context, [Parameter(Mandatory)][string]$Level, [AllowEmptyString()][string]$Message, [string[]]$Lines)
    if (-not $Context.LogFile) { return }
    if ($PSBoundParameters.ContainsKey('Lines')) {
        $block = New-Object Text.StringBuilder
        foreach ($entry in $Lines) { [void]$block.Append(('{0} [{1,-6}] {2}' -f (Get-Date).ToString('yyyy-MM-dd HH:mm:ss.fff'), $Level, ($entry -replace '[\r\n]+', ' | '))).Append("`r`n") }
        $text = $block.ToString()
    }
    else { $text = ('{0} [{1,-6}] {2}' -f (Get-Date).ToString('yyyy-MM-dd HH:mm:ss.fff'), $Level, ($Message -replace '[\r\n]+', ' | ')) + "`r`n" }
    try { [IO.File]::AppendAllText($Context.LogFile, $text, (New-Object Text.UTF8Encoding($false))) }
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
    .PARAMETER Lines
        Several Detail lines written to the log in one write (the lines of one object, for example). Detail only.
    .PARAMETER ForegroundColor
        Console colour of the text (presentation only: it never changes the level or the counters).
    #>
    [CmdletBinding(DefaultParameterSetName = 'One')]
    param([Parameter(Mandatory, Position = 0)][hashtable]$Context, [Parameter(Mandatory, Position = 1, ParameterSetName = 'One')][AllowEmptyString()][string]$Message,
        [Parameter(Mandatory, ParameterSetName = 'Block')][AllowEmptyString()][string[]]$Lines,
        [Parameter(Position = 2)][ValidateSet('Info','Sub','Success','Warning','Error','Debug','Step','Detail')][string]$Level = 'Info',
        [ConsoleColor]$ForegroundColor)
    if ([string]::Equals($PSCmdlet.ParameterSetName, 'Block', [StringComparison]::Ordinal)) {
        if (-not (Test-PraOrdinalIgnoreCaseEqual $Level 'Detail')) { throw 'Write-PraLog -Lines is for the Detail level only.' }
        Write-PraLogFile -Context $Context -Level 'DETAIL' -Lines $Lines
        return
    }
    $logLevel = @{ Info='INFO'; Sub='INFO'; Success='OK'; Warning='WARN'; Error='ERROR'; Debug='DEBUG'; Step='STEP'; Detail='DETAIL' }[$Level]
    if ((Test-PraOrdinalIgnoreCaseEqual $Level 'Warning')) { $Context.Warnings = [int](Get-PraValue $Context 'Warnings' 0) + 1; Add-PraWarning $Context $Message }
    if ((Test-PraOrdinalIgnoreCaseEqual $Level 'Error')) { Add-PraIssue $Context $Message }
    Write-PraLogFile -Context $Context -Level $logLevel -Message $Message
    # The Detail and Step levels go to the log only: their plain text is not needed.
    $text = if ((Test-PraOrdinalIgnoreCaseEqual $Level 'Detail') -or (Test-PraOrdinalIgnoreCaseEqual $Level 'Step')) { '' } else { (ConvertTo-PraPlainMessage $Message) -replace '[\r\n]+', ' | ' }
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
          │  ♦  PRA Remote Mailbox                           v3.1.4 · Nicolas Fabert   │
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
    if ($existing -match '^[A-Za-z]:\z' -or $existing -match '^\\\\[?.]\\[A-Za-z]:\z') { $existing += '\' }
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
        if (-not [string]::Equals($first, $Canonical, [StringComparison]::OrdinalIgnoreCase)) {
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
    # A folder that does not exist yet is created with the canonical spelling, whatever case the configuration wrote.
    if ($first -and [string]::Equals($first, $Canonical, [StringComparison]::OrdinalIgnoreCase) -and -not [string]::Equals($first, $Canonical, [StringComparison]::Ordinal) -and
        -not (Test-Path -LiteralPath ($physicalRoot + '\' + $first))) {
        $physical = $physicalRoot + '\' + $Canonical + $relative.Substring($first.Length)
        $relative = $physical.Substring($physicalRoot.Length).TrimStart('\')
        $first = $Canonical
    }
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
    $info = $null
    try {
        $parent = [IO.Path]::GetDirectoryName([IO.Path]::GetFullPath($Path))
        if ($parent) { [void][IO.Directory]::CreateDirectory($parent) }
        $info = New-Object IO.DirectoryInfo $Path
        [IO.FileSystemAclExtensions]::Create($info, (New-PraPrivateDirectorySecurity))
    }
    catch { throw ('The folder {0} cannot be created: {1}' -f $Path, $(if ($_.Exception.InnerException) { $_.Exception.InnerException.Message } else { $_.Exception.Message })) }
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
            IdentityCheck='Anchor'; RetryBudgetObjectSeconds=180; RetryBudgetRunMinutes=30
        }
        Exo = @{ MinModuleVersion='3.10.1'; UseSubprocess=$false; DisableWAM=$false; GrantVerifyAttempts=13; GrantVerifyDelaySeconds=10 }
        Polling = @{ IntervalMinutes=1; TimeoutMinutes=60 }
        Retention = @{ Enabled=$true; PolicyName='PRA-Converted-Retention'; PolicyGuid=''; UseComplianceSession=$false; CheckBeforeRecover=$true; ProofMaxAgeHours=24; Tag=@{ Enabled=$true; Attribute='extensionAttribute1'; Value='Converted' } }
        Execution = @{ Phase='Both' }
        Storage = @{ BackupFolder='.\Backups'; ForbiddenBackupRoots=@() }
        Logging = @{ Folder='.\logs' }
        Report = @{ Enabled=$true; Folder='.\reports' }
    }
}

function Get-PraTargetOverride {
    <# Run-specific targeting; the original data file is never rewritten. #>
    [CmdletBinding()]
    param([string]$SearchBase = '', [string]$CsvPath = '', [string]$Identity = '', [string]$Group = '')
    foreach ($value in @($SearchBase,$CsvPath,$Group)) {
        if ($value -match '[\x00-\x1f]' -or ($value -and [string]::IsNullOrWhiteSpace($value))) { throw 'Target OU/CSV/group contains an empty value or a control character.' }
    }
    if (@(@($SearchBase, $CsvPath, $Group) | Where-Object { $_ }).Count -gt 1) { throw 'Choose one source: -SearchBase (OU), -CsvPath or -Group, not several.' }
    if ($Identity -and ($SearchBase -or $CsvPath -or $Group)) { throw 'Identity cannot be combined with a selected OU, CSV or group.' }
    if ($SearchBase) { return @{ Mode='OU'; SearchBase=$SearchBase.Trim(); CsvPath=''; GroupDN='' } }
    if ($CsvPath) { return @{ Mode='Csv'; CsvPath=$CsvPath.Trim(); SearchBase=''; GroupDN='' } }
    if ($Group) { return @{ Mode='Group'; GroupDN=$Group.Trim(); SearchBase=''; CsvPath='' } }
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

function Test-PraScopeConfiguration {
    <#
    .SYNOPSIS
        Checks that the configuration says which mailboxes a CONVERSION takes (Scope.Mode with its SearchBase, GroupDN or CsvPath), and says plainly what to fill in when it does not.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][hashtable]$Config)
    $scope = $Config.Scope
    $how = 'Fill it in the configuration file, or give -Identity (one account), -CsvPath (a CSV file with an Identity column), -SearchBase (an OU) or -Group (an AD group) for this run' + $(if (Test-PraOrdinalIgnoreCaseEqual $scope.Mode 'Auto') { '.' } else { ', or set Scope.Mode = Auto to take every mailbox of the domain.' })
    if ((Test-PraOrdinalIgnoreCaseEqual $scope.Mode 'OU') -and -not $scope.SearchBase) { throw ('Configuration: Scope.Mode = OU requires Scope.SearchBase: no OU is set, so the tool does not know which mailboxes to convert. ' + $how) }
    if ((Test-PraOrdinalIgnoreCaseEqual $scope.Mode 'Group') -and -not $scope.GroupDN) { throw ('Configuration: Scope.Mode = Group requires Scope.GroupDN: no group is set, so the tool does not know which mailboxes to convert. ' + $how) }
    if ((Test-PraOrdinalIgnoreCaseEqual $scope.Mode 'Csv') -and -not $scope.CsvPath) { throw ('Configuration: Scope.Mode = Csv requires Scope.CsvPath: no CSV file is set, so the tool does not know which mailboxes to convert. ' + $how) }
}

function Get-PraConfigurationValueError {
    <# The refusal of a configuration value that is not one of the accepted words: the key, the accepted words, the value found and the file. #>
    param([string]$File, [string]$Key, [string]$Accepted, [AllowNull()][object]$Value)
    $shown = if ($null -eq $Value -or [string]::IsNullOrWhiteSpace([string]$Value)) { 'empty' } else { "'$Value'" }
    return ('Configuration: {0} must be {1}: the value is {2} in {3}.' -f $Key, $Accepted, $shown, $File)
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
    param([Parameter(Mandatory)][string]$Path, [Parameter(Mandatory)][string]$Root, [hashtable]$ScopeOverride = @{}, [switch]$DeferScopeCheck)
    $file = Resolve-PraPath $Path 'ConfigPath' $Root
    if (-not (Test-Path -LiteralPath $file -PathType Leaf)) { throw "Configuration file not found: $file" }
    $config = Import-PowerShellDataFile -LiteralPath $file -ErrorAction Stop
    Merge-PraConfiguration $config (Get-PraDefaultConfiguration)
    foreach ($key in $ScopeOverride.Keys) {
        $overrideKey = Resolve-PraOfficialValue $key @('Mode','SearchBase','CsvPath','GroupDN')
        if ($null -eq $overrideKey -or $ScopeOverride[$key] -isnot [string]) { throw 'Unsupported target scope override.' }
        $config.Scope[$overrideKey] = $ScopeOverride[$key]
    }

    if ($config.Environment -notmatch '^[A-Za-z0-9_.-]{1,64}\z') { throw 'Configuration: Environment must be 1 to 64 letters, digits, dot, dash or underscore (it is used in file names).' }
    if ($config.DomainController -and $config.DomainController -notmatch '^[A-Za-z0-9.-]+\z') { throw 'Configuration: DomainController must be a host name.' }
    $scope = $config.Scope
    $badValue = $scope.Mode
    $scope.Mode = Resolve-PraOfficialValue $scope.Mode @('Auto','OU','Group','Csv')
    if ($null -eq $scope.Mode) { throw (Get-PraConfigurationValueError $file 'Scope.Mode' 'Auto, OU, Group or Csv' $badValue) }
    # The mailboxes to convert are only needed by a conversion (Convert, phase AD or Both): the entry script checks them then (Test-PraScopeConfiguration). A Check, a cloud
    # phase, a Recover or a Finalize on a server without that setting must not fail on it; -DeferScopeCheck leaves the check to the caller.
    if (-not $DeferScopeCheck) { Test-PraScopeConfiguration -Config $config }
    if ((-not (Test-PraOrdinalIn ($config.Remote.RecipientType) @(1,3) -IgnoreCase))) { throw 'Configuration: Remote.RecipientType must be 1 (provision a mailbox) or 3 (mailbox + archive).' }
    if ($config.Routing.RoutingDomain -and $config.Routing.RoutingDomain -notmatch '^[A-Za-z0-9.-]+\.[A-Za-z]{2,}\z') { throw 'Configuration: Routing.RoutingDomain must be a domain name (tenant.mail.onmicrosoft.com).' }
    if ($config.Licensing.Enabled -and -not $config.Licensing.GroupDN) { throw 'Configuration: Licensing.Enabled requires Licensing.GroupDN.' }
    $shared = $config.SharedMailbox
    if ((-not (Test-PraOrdinalIn $shared.RemoteRecipientType @(97,99,100,102) -IgnoreCase))) { throw 'Configuration: SharedMailbox.RemoteRecipientType must be 97 or 99 (100/102 are accepted only to read old backups).' }
    $badValue = $shared.PermissionSource
    $shared.PermissionSource = Resolve-PraOfficialValue $shared.PermissionSource @('AD','Csv','CustomAttribute','None')
    if ($null -eq $shared.PermissionSource) { throw (Get-PraConfigurationValueError $file 'SharedMailbox.PermissionSource' 'AD, Csv, CustomAttribute or None' $badValue) }
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
    $badValue = $sync.PolicyType
    $sync.PolicyType = Resolve-PraOfficialValue $sync.PolicyType @('Delta','Initial')
    if ($null -eq $sync.PolicyType) { throw (Get-PraConfigurationValueError $file 'EntraConnect.PolicyType' 'Delta or Initial' $badValue) }
    if ($sync.TimeoutMinutes -lt 1 -or $sync.TimeoutMinutes -gt 240) { throw 'Configuration: EntraConnect.TimeoutMinutes must be between 1 and 240.' }
    if ($sync.Server -and $sync.Server -notmatch '^[A-Za-z0-9.-]+\z') { throw 'Configuration: EntraConnect.Server must be a host name (empty = this server).' }
    $cloud = $config.Cloud
    $badValue = $cloud.MailboxCheckVia
    $cloud.MailboxCheckVia = Resolve-PraOfficialValue $cloud.MailboxCheckVia @('Graph','Exo')
    if ($null -eq $cloud.MailboxCheckVia) { throw (Get-PraConfigurationValueError $file 'Cloud.MailboxCheckVia' 'Exo or Graph' $badValue) }
    $badValue = $cloud.IdentityCheck
    $cloud.IdentityCheck = Resolve-PraOfficialValue $cloud.IdentityCheck @('Anchor','Off')
    if ($null -eq $cloud.IdentityCheck) { throw (Get-PraConfigurationValueError $file 'Cloud.IdentityCheck' 'Anchor or Off' $badValue) }
    if ($cloud.RetryBudgetObjectSeconds -lt 0 -or $cloud.RetryBudgetObjectSeconds -gt 3600 -or $cloud.RetryBudgetRunMinutes -lt 0 -or $cloud.RetryBudgetRunMinutes -gt 720) {
        throw 'Configuration: Cloud.RetryBudgetObjectSeconds must be 0..3600 and Cloud.RetryBudgetRunMinutes 0..720 (0 = no retry).'
    }
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
    try { $null = [version]$exo.MinModuleVersion } catch { throw 'Configuration: Exo.MinModuleVersion must be a version number (3.10.1).' }
    if ($config.Polling.IntervalMinutes -lt 1 -or $config.Polling.TimeoutMinutes -lt 1) { throw 'Configuration: Polling.IntervalMinutes and Polling.TimeoutMinutes must be at least 1.' }
    $retention = $config.Retention
    if ($retention.Tag.Attribute -notmatch '^extensionAttribute([1-9]|1[0-5])\z') { throw 'Configuration: Retention.Tag.Attribute must be extensionAttribute1 to extensionAttribute15.' }
    if ($retention.Enabled -and $retention.Tag.Enabled -and -not $retention.Tag.Value) { throw 'Configuration: Retention.Tag.Value is empty.' }
    if ($retention.ProofMaxAgeHours -lt 1 -or $retention.ProofMaxAgeHours -gt 720) { throw 'Configuration: Retention.ProofMaxAgeHours must be between 1 and 720.' }
    $badValue = $config.Execution.Phase
    $config.Execution.Phase = Resolve-PraOfficialValue $config.Execution.Phase @('Both','AD','Cloud')
    if ($null -eq $config.Execution.Phase) { throw (Get-PraConfigurationValueError $file 'Execution.Phase' 'Both, AD or Cloud' $badValue) }

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
    $Context['AuditAttempted'] = $true
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
    # Errors of the run itself (an object that could not be read), apart from the objects found not in the expected state.
    $runErrors = 0
    # A run refused before any change (Entra Connect check, cloud modules, domain controller refusing the account) touched no object: only its error is a result row.
    $untouched = [bool](Get-PraValue $Context 'NoChangeMade' $false)
    # In an Apply whose batch exists (its backup is written), an object still Planned when the run ends is not done: it is Pending, never counted as a success or as skipped.
    $appliesChanges = (Test-PraOrdinalIgnoreCaseEqual ([string](Get-PraValue $Context 'Mode' '')) 'Apply') -and (Test-PraOrdinalIn ([string](Get-PraValue $Context 'Action' '')) @('Convert', 'Recover', 'Finalize') -IgnoreCase) -and
        ([bool](Get-PraValue $Context 'ChangesStarted' $false) -or -not [string]::IsNullOrEmpty([string](Get-PraValue $Context 'BatchId' '')))
    foreach ($row in $(if ($untouched) { @() } else { $Context.Rows.ToArray() })) {
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
        elseif ($appliesChanges -and (Test-PraOrdinalEqual $copy.FinalStatus 'Planned')) {
            $copy.FinalStatus = 'Pending'
            if (-not $copy.Detail) { $copy.Detail = 'not finished: the run ended before this object was done; the next steps say how to go on' }
        }
        if (Test-PraOrdinalEqual $copy.FinalStatus 'Error') {
            foreach ($field in @('ObjectGuid','SamAccountName','UserPrincipalName')) { if ($copy[$field]) { $errorIdentities[[string]$copy[$field]] = $true } }
            if ([bool](Get-PraValue $row 'RunError' $false)) { $runErrors++ }
        }
        [void]$rows.Add([pscustomobject]$copy)
    }
    foreach ($issue in $Context.Issues.ToArray()) {
        $identity = [string](Get-PraValue $issue 'Identity' '')
        $source = [string](Get-PraValue $issue 'Source' 'Execution')
        # The error of an object is its row: the cloud error and the stop that follow it are the same failure, not two more.
        if ((Test-PraOrdinalIn $source @('Execution', 'Cloud')) -and $identity -and $errorIdentities.ContainsKey($identity)) { continue }
        $failure = [ordered]@{}
        foreach ($field in $script:RowFields) { $failure[$field] = $null }
        $failure.Action = $Context.Action
        $failure.UserPrincipalName = if ($identity -or -not $untouched) { $identity } elseif ([string](Get-PraValue $Context 'BatchId' '')) { '(batch {0})' -f (Get-PraValue $Context 'BatchId' '') } else { '(run)' }
        $failure.FinalStatus = 'Error'; $failure.LastOperation = Get-PraValue $issue 'Operation' ''
        $failure.Detail = '[Run/{0}] {1}' -f $source, (Get-PraValue $issue 'Message' ([string]$issue))
        [void]$rows.Add([pscustomobject]$failure); $runErrors++
    }
    $counts = @{ Success = 0; Error = 0; Pending = 0; Skipped = 0; Planned = 0; RunError = $runErrors }
    foreach ($row in $rows) {
        $key = [string]$row.FinalStatus
        if (Test-PraOrdinalEqual $key 'AlreadyDone') { $key = 'Success' }
        $counts[$key]++
    }
    # The members of a selected group that are not converted have no row: they are skipped objects of the run.
    $counts.Skipped += @(Get-PraList $Context 'SkippedMembers').Count
    $requested =[string](Get-PraValue $Context 'ResultStatus' '')
    $code = 0; $status = 'Success'
    # An operator who answered no to the confirmation cancelled the run: nothing was written and no error is counted (exit code 1, the work was not done).
    if ([bool](Get-PraValue $Context 'Cancelled' $false) -and $counts.Error -eq 0 -and $Context.Issues.Count -eq 0 -and -not $Context.CloudConnectFailed) { $code = 1; $status = 'Cancelled' }
    elseif ($counts.Error -gt 0 -or $Context.Issues.Count -gt 0 -or [int]$Context.ExitCode -eq 1 -or $Context.CloudConnectFailed -or (Test-PraOrdinalIgnoreCaseEqual $requested 'Failed')) {
        $code = 1; $status = 'Failed'
    } elseif ($counts.Pending -gt 0) { $code = 2; $status = 'Pending' }
    elseif ((-not (Test-PraOrdinalIgnoreCaseEqual $Context.Mode 'Apply')) -and $counts.Planned -gt 0) { $status = 'Planned' }
    return [pscustomobject]@{ Rows = $rows.ToArray(); Counts = $counts; Status = $status; ExitCode = $code }
}

function Get-PraVerdict {
    <# The verdict line of a run: the last line of the log and of the transcript. #>
    param($Outcome)
    if ((Test-PraOrdinalEqual ([string]$Outcome.Status) 'Cancelled')) { return 'RESULT: CANCELLED' }
    if ($Outcome.ExitCode -eq 1) { return 'RESULT: FAIL' }
    if ($Outcome.ExitCode -eq 2) { return 'RESULT: PENDING' }
    return 'RESULT: PASS'
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
                $k = $dictionary[$value]
                if ($null -ne $k) { $column[$i] = $k }
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
    $statusClass = @{ Success='ok'; Planned='info'; Pending='warn'; Cancelled='warn'; Failed='fail' }[$Outcome.Status]
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
        'Objects' = [string](Get-PraValue $Context 'ObjectsText' '')
        'Skipped members' = $(if (@(Get-PraList $Context 'SkippedMembers').Count) { '{0} member(s) not converted: {1}' -f @(Get-PraList $Context 'SkippedMembers').Count, (@(Get-PraList $Context 'SkippedMembers') -join '; ') } else { '' })
        'Batch' = [string](Get-PraValue $Context 'BatchId' '')
        'Domain controller' = [string]$Context.Server
        'Computer / account' = ('{0} · {1}\{2}' -f $env:COMPUTERNAME, $env:USERDOMAIN, $env:USERNAME)
        'Started' = ([datetime]$Context.StartTime).ToString('yyyy-MM-dd HH:mm:ss')
        'Duration' = (Format-PraDuration ((Get-Date) - [datetime]$Context.StartTime).TotalSeconds)
        'Run ID' = [string]$Context.RunId
        'Run settings changed' = ((@(Get-PraList $Context 'ConfigOverrides') | ForEach-Object { [string]$_ }) -join '; ')
        'Retention proof accepted' = $(if ((Get-PraPhaseSetting -Context $Context).Contains('Retention proof accepted')) { (Get-PraPhaseSetting -Context $Context)['Retention proof accepted'] } else { '' })
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
    # One pass over the template: a value that holds a marker is written as it is, never replaced again. The place of the data is found before any value is put in.
    $marker = '{{DATA}}'
    $at = $template.LastIndexOf($marker, [StringComparison]::Ordinal)
    $pattern = New-Object Text.RegularExpressions.Regex('\{\{[A-Z_]+\}\}', [Text.RegularExpressions.RegexOptions]::CultureInvariant)
    $evaluator = [Text.RegularExpressions.MatchEvaluator]({ param($Match) if ($values.ContainsKey($Match.Value)) { [string]$values[$Match.Value] } else { $Match.Value } }).GetNewClosure()
    if ($at -lt 0) { $Writer.Write($pattern.Replace($template, $evaluator)); return }
    $tail = $pattern.Replace($template.Substring($at + $marker.Length), $evaluator)
    $Writer.Write($pattern.Replace($template.Substring(0, $at), $evaluator))

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
    $Writer.Write($tail)
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
        'RESULT: PASS', 'RESULT: PENDING' (exit code 2, a next step is required), 'RESULT: CANCELLED' (the operator answered no to the confirmation; exit code 1,
        nothing was written) or 'RESULT: FAIL' is the last line of the log and of the transcript; it is
        added after the transcript is stopped so that a failure to stop it is still reported.
    .OUTPUTS
        PSCustomObject: RunId, Status (Success, Planned, Pending, Cancelled, Failed), ExitCode, counters,
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
    if (([int]$Context.ExitCode -ne 0 -or $Context.CloudConnectFailed -or (Test-PraOrdinalIgnoreCaseEqual (Get-PraValue $Context 'ResultStatus' '') 'Failed')) -and $Context.Issues.Count -eq 0 -and -not [bool](Get-PraValue $Context 'Cancelled' $false)) {
        Add-PraIssue $Context 'Failure reported by the run (exit code / cloud connection).' 'Run'
    }
    # No stack line reaches the card, the console or the report: the log holds the whole detail.
    foreach ($entry in @($Context.Issues.ToArray()) + @(@(Get-PraValue $Context 'WarningList' @()) | ForEach-Object { $_ })) {
        if ($entry -is [pscustomobject] -and $entry.PSObject.Properties['Message']) {
            $plain = ConvertTo-PraPlainMessage ([string]$entry.Message)
            if (-not [string]::Equals($plain, [string]$entry.Message, [StringComparison]::Ordinal)) { $entry.Message = $plain }
        }
    }
    foreach ($key in @('LogFile','TranscriptPath','BackupFiles','StateFiles')) {
        $candidates = Get-PraValue $Context $key
        if ((Test-PraOrdinalIn $key @('LogFile','TranscriptPath') -IgnoreCase)) { $candidates = [string]$candidates }
        if ((Test-PraOrdinalIgnoreCaseEqual $key 'TranscriptPath') -and -not (Get-PraValue $Context '_PraTranscriptCreated' $false)) { $candidates = '' }
        foreach ($path in $candidates) {
            # An empty log or transcript path means the audit never started: that cause is already an issue of the run.
            if (-not $path -and (Test-PraOrdinalIn $key @('LogFile','TranscriptPath') -IgnoreCase) -and @($Context.Issues.ToArray() | Where-Object { (Test-PraOrdinalIgnoreCaseEqual ([string](Get-PraValue $_ 'Source' '')) 'Audit') -or ([string](Get-PraValue $_ 'Message' '')).StartsWith('Audit ', [StringComparison]::OrdinalIgnoreCase) }).Count) { continue }
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
    $globalReport = @{ Html = ''; Csv = ''; EventsCsv = ''; IssuesCsv = '' }
    if (-not $Context.NoReport -and (Test-PraGlobalReportWanted $Context)) {
        $globalReport = Write-PraGlobalReport -Context $Context
        if ($globalReport.Html) {
            $globalLines = @(('Global report (every object, from the first server to this one): ' + $globalReport.Html))
            if ($globalReport.Csv -and $globalReport.EventsCsv -and $globalReport.IssuesCsv) { $globalLines += ('Global report data, one file per kind (CSV): objects {0}, journey lines {1}, errors and warnings {2}' -f $globalReport.Csv, $globalReport.EventsCsv, $globalReport.IssuesCsv) }
            $Context.NextSteps = $globalLines + @(@(Get-PraValue $Context 'NextSteps' @()) | ForEach-Object { $_ } | Where-Object { $_ })
        }
    }

    # Summary card.
    $outcome = Get-PraOutcome $Context
    # The last step ends with the run: fail when the run failed, otherwise ok or warn.
    Close-PraStepEvent -Context $Context -State $(if ($outcome.ExitCode -eq 1) { 'fail' } else { '' })
    $c = $outcome.Counts
    $isApply = (Test-PraOrdinalIgnoreCaseEqual $Context.Mode 'Apply')
    # A Preview (not a Check, which has its own words) changes nothing: its objects are "ready" or "planned", never "done".
    $isPreviewRun = (-not $isApply) -and (-not (Test-PraOrdinalIgnoreCaseEqual $Context.Action 'Check'))
    $isCheckRun = (Test-PraOrdinalIgnoreCaseEqual $Context.Action 'Check')
    # A Check that ran to the end and found differences is finished; it "stopped" only when a run error prevented it.
    $checkRanToEnd = $isCheckRun -and (Test-PraOrdinalEqual $outcome.Status 'Failed') -and [bool](Get-PraValue $Context 'CheckFinished' $false) -and $c.RunError -eq 0 -and $c.Error -gt 0
    $title = switch ($outcome.Status) {
        'Failed' { if ($checkRanToEnd) { 'Check finished - {0} object(s) not in the expected state' -f $c.Error } else { '{0} stopped - see the errors below' -f $Context.Action } }
        'Pending' { '{0} done - next step required' -f $Context.Action }
        'Cancelled' { '{0} cancelled - nothing was written' -f $Context.Action }
        default { if ($isPreviewRun) { '{0} preview finished - nothing was changed' -f $Context.Action } else { '{0} finished' -f $Context.Action } }
    }
    $status = @{ Failed='Fail'; Pending='Warn'; Cancelled='Warn'; Planned='Ok'; Success='Ok' }[$outcome.Status]
    # A Check counts "not as expected" only for objects that were read and compared; a run error is an error.
    $objects = if ($isCheckRun) { '{0} as expected {3} {1} not as expected {3} {4}{2} skipped' -f $c.Success, ($c.Error - $c.RunError), $c.Skipped, [char]0x00B7, $(if ($c.RunError) { '{0} error(s) {1} ' -f $c.RunError, [char]0x00B7 } else { '' }) }
        elseif ($isPreviewRun) { '{0} ready {5} {1} planned {5} {4}{2} error(s) {5} {3} skipped' -f $c.Success, $c.Planned, $c.Error, $c.Skipped, $(if ($c.Pending) { '{0} pending {1} ' -f $c.Pending, [char]0x00B7 } else { '' }), [char]0x00B7 }
        elseif ($isApply -or $c.Success -or $c.Pending) { '{0} done {4} {1} pending {4} {2} error(s) {4} {3} skipped' -f $c.Success, $c.Pending, $c.Error, $c.Skipped, [char]0x00B7 }
        else { '{0} planned {3} {1} error(s) {3} {2} skipped' -f $c.Planned, $c.Error, $c.Skipped, [char]0x00B7 }
    $values = [ordered]@{ 'Result' = @('Target', $objects) }
    $batch = [string](Get-PraValue $Context 'BatchId' '')
    if ($batch) { $values['Batch'] = @('Batch', $batch) }
    $objectsText = [string](Get-PraValue $Context 'ObjectsText' '')
    if ($objectsText) { $values['Objects'] = @('Target', $objectsText) }
    # The errors of the objects come first (at most 5, then how many more), the stop of the run is the last line.
    $issueTexts = @($Context.Issues.ToArray() | ForEach-Object { [string](Get-PraValue $_ 'Message' ([string]$_)) })
    $stopAt = -1
    for ($i = $issueTexts.Count - 1; $i -ge 0; $i--) { if ($issueTexts[$i].StartsWith("Stopped at step '", [StringComparison]::Ordinal)) { $stopAt = $i; break } }
    $objectTexts = @(for ($i = 0; $i -lt $issueTexts.Count; $i++) { if ($i -ne [int]$stopAt) { $issueTexts[$i] } })
    $issueLines = @($objectTexts | Select-Object -First 5)
    if ($objectTexts.Count -gt 5) { $issueLines += ('... and {0} more, see the report' -f ($objectTexts.Count - 5)) }
    if ($stopAt -ge 0) { $issueLines += $issueTexts[$stopAt] }
    $issueLines = @($issueLines | ForEach-Object { if ($_.Length -gt 240) { $_.Substring(0, 237) + '...' } else { $_ } })
    if ($issueLines.Count) {
        # The same count as the Result line: an object that failed and the stop that follows its error are one error, not two.
        if ($Context.Issues.Count -gt 2) { $issueLines = @(('{0} error(s) in total, see the log and the report' -f $(if ($isCheckRun) { $c.RunError } else { $c.Error }))) + $issueLines }
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
    $showNext = ($outcome.ExitCode -ne 1 -or $unconfirmed.Count -or [bool](Get-PraValue $Context 'NoChangeMade' $false) -or [bool](Get-PraValue $Context 'NextOnFailure' $false))
    # A failed run always ends with a next step: the one the run set, else the fallback given by the entry script.
    if ($outcome.ExitCode -eq 1 -and (-not $showNext -or -not $next.Count)) {
        $fallback = @(@(Get-PraValue $Context 'FallbackNext' @()) | ForEach-Object { $_ } | Where-Object { $_ })
        if ($fallback.Count) { $next = $fallback; $Context.NextSteps = $fallback; $showNext = $true }
    }
    if ($showNext -and $next.Count) { $values['Next'] = @('Next', $next) }
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
    $verdict = Get-PraVerdict $outcome
    try { if ($ownsTranscript -and $paths.TranscriptPath) { Add-Content -LiteralPath $paths.TranscriptPath -Value $verdict -Encoding UTF8 -WhatIf:$false -Confirm:$false -ErrorAction Stop } }
    catch { Add-PraIssue $Context ('Transcript verdict: {0}' -f $_.Exception.Message) 'Audit'; Write-PraReport $Context $reports }
    $outcome = Get-PraOutcome $Context; $beforeVerdict = $Context.Issues.Count
    $verdict = Get-PraVerdict $outcome
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
        GlobalHtmlReport = [string]$globalReport.Html; GlobalCsvReport = [string]$globalReport.Csv; GlobalEventsCsvReport = [string]$globalReport.EventsCsv; GlobalIssuesCsvReport = [string]$globalReport.IssuesCsv
        TransferPackage = [string](Get-PraValue $Context 'TransferPackage' ''); TransferPackageKind = [string](Get-PraValue $Context 'TransferPackageKind' '')
        ConfigOverrides = [string[]]@(@(Get-PraValue $Context 'ConfigOverrides' @()) | ForEach-Object { $_ } | Where-Object { $_ })
    }
    Write-PraEvent -Kind result -Data @{ status = $result.Status; exitCode = $result.ExitCode
        action = $result.Action; mode = $result.Mode; phase = $result.Phase
        success = $result.SuccessCount; error = $result.ErrorCount; pending = $result.PendingCount
        skipped = $result.SkippedCount; planned = $result.PlannedCount; total = $result.TotalCount
        seconds = [int]$result.Duration.TotalSeconds; batchId = $result.BatchId; nextSteps = @($result.NextSteps)
        logFile = $result.LogFile; csvReport = $result.CsvReport; htmlReport = $result.HtmlReport; globalReport = $result.GlobalHtmlReport; globalCsvReport = $result.GlobalCsvReport; globalEventsCsvReport = $result.GlobalEventsCsvReport; globalIssuesCsvReport = $result.GlobalIssuesCsvReport
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
$script:PraTransferLimits = @{ MaxEntries = [int]2000; MaxEntryBytes = [long]2147483648; MaxTotalBytes = [long]4294967296; MaxManifestBytes = [long]1048576 }

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
    $match = [regex]::Match($Name, '\A(?<folder>(?i:Batch|Finalize)-[A-Za-z0-9._-]{1,100})/(?<file>[A-Za-z0-9._-]{1,120})\z', [Text.RegularExpressions.RegexOptions]::CultureInvariant)
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
            if (-not [IO.File]::Exists($sidecar)) {
                $packageName = [IO.Path]::GetFileName($full)
                $writer = if ($packageName.EndsWith('-for-Cloud.zip', [StringComparison]::OrdinalIgnoreCase)) { 'AD' } elseif ($packageName.EndsWith('-for-AD.zip', [StringComparison]::OrdinalIgnoreCase)) { 'cloud' } else { '' }
                throw ('Transfer package: the .sha256 file next to the package is missing. Copy {0}.sha256 from the Outbox folder of the {1}server that wrote the package, into the same folder as the .zip, then run again.' -f $packageName, $(if ($writer) { $writer + ' ' } else { '' }))
            }
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
        if ($Environment -and -not (Test-PraOrdinalIgnoreCaseEqual $packageEnvironment $Environment)) {
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
        $folders = @($files | ForEach-Object { ([string]$_.FullName).Split('/')[0] } | Get-PraOrdinalUnique | Get-PraOrdinalSorted)
        if (@($folders | Get-PraOrdinalUnique -IgnoreCase).Count -ne $folders.Count) { throw 'Transfer package: two folders have the same name apart from letter case.' }
        foreach ($folder in $folders) { if (-not $folder.StartsWith($prefix, [StringComparison]::OrdinalIgnoreCase)) { throw ("Transfer package: a {0} package holds {1}* folders only." -f $kind, $prefix) } }
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

        # Extraction. Every target folder is decided before anything is created: an existing folder must be identical.
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
            # The folder may hold more than the package: the side files that a later run writes there (proof, journal, global report data) are kept as they are.
            $listedNames = New-Object 'Collections.Generic.HashSet[string]' -ArgumentList ([StringComparer]::OrdinalIgnoreCase)
            foreach ($entry in $inFolder) { [void]$listedNames.Add(([string]$entry.FullName).Substring($folder.Length + 1)) }
            $unlisted = @([IO.Directory]::GetFiles($target) | Where-Object { $leaf = [IO.Path]::GetFileName($_); -not $listedNames.Contains($leaf) -and (-not (Test-PraBatchSideFile $leaf) -or ([IO.File]::GetAttributes($_) -band [IO.FileAttributes]::ReparsePoint)) })
            if ([IO.Directory]::GetDirectories($target).Length -or $unlisted.Count) {
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

function Test-PraBatchSideFile {
    <# True for the files of a batch folder that are not a batch file, by name: the proof (State-), the journal, the data of the global report (PhaseData-, PhaseEvents-) and any checksum file. #>
    param([Parameter(Mandatory)][string]$Name)
    if ($Name.EndsWith('.sha256', [StringComparison]::OrdinalIgnoreCase)) { return $true }
    foreach ($prefix in @('State-', 'Journal-', 'PhaseData-', 'PhaseEvents-', 'RetentionProof-')) { if ($Name.StartsWith($prefix, [StringComparison]::OrdinalIgnoreCase)) { return $true } }
    return $false
}

function Get-PraRetentionProofName {
    <# RetentionProof-<batch ID>-<UTC time>.json: the retention proof that a Check -Expect Retained writes for a Convert batch (the batch ID is the full ID of that batch). #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$BatchId, [Parameter(Mandatory)][datetime]$CreatedUtc)
    if ($BatchId -notmatch '\A[0-9a-fA-F]{8,32}\z') { throw 'Retention proof: the batch ID must be 8 to 32 hexadecimal characters.' }
    return 'RetentionProof-{0}-{1}.json' -f $BatchId.ToLowerInvariant(), $CreatedUtc.ToString('yyyyMMddHHmmssfff', [Globalization.CultureInfo]::InvariantCulture)
}

function Write-PraRetentionProof {
    <#
    .SYNOPSIS
        Writes the retention proof of a Convert batch in a folder (with its .sha256 file): what the retention check found, per object, at this time.
    .DESCRIPTION
        -Object: ObjectGuid, Upn and Verdict (Covered, NotCovered, NoMailbox or NotChecked; anything else is NotChecked). Each entry says its Verdict, and Covered and NoMailbox as booleans that agree with it
        (Covered true only for Covered, NoMailbox true only for NoMailbox). The file is never replaced: its name carries the time.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Folder, [Parameter(Mandatory)][string]$BatchId, [string]$SourceBackupHash = '', [Parameter(Mandatory)][string]$Environment,
        [string[]]$PolicyGuid = @(), [AllowEmptyCollection()][object[]]$Object = @())
    $created = [DateTime]::UtcNow
    $entries = New-Object 'Collections.Generic.List[object]'
    $coveredCount = 0
    foreach ($item in $Object) {
        $verdict = [string]$item.Verdict
        $known = @('Covered', 'NotCovered', 'NoMailbox', 'NotChecked') | Where-Object { Test-PraOrdinalIgnoreCaseEqual $_ $verdict } | Select-Object -First 1
        if (-not $known) { $known = 'NotChecked' }
        $covered = Test-PraOrdinalEqual $known 'Covered'
        if ($covered) { $coveredCount++ }
        $entries.Add([ordered]@{ ObjectGuid = [string]$item.ObjectGuid; Upn = [string]$item.Upn; Verdict = $known; Covered = $covered; NoMailbox = (Test-PraOrdinalEqual $known 'NoMailbox') })
    }
    $record = [ordered]@{
        SchemaVersion = 1; Kind = 'RetentionProof'; BatchId = $BatchId.ToLowerInvariant(); SourceBackupHash = $SourceBackupHash; Environment = $Environment
        CreatedUtc = $created.ToString('o'); PolicyGuid = [string[]]@($PolicyGuid | Where-Object { $_ }); ObjectCount = $entries.Count; CoveredCount = $coveredCount; Objects = $entries.ToArray()
    }
    Initialize-PraPrivateFolder -Path $Folder
    $path = Join-Path ([IO.Path]::GetFullPath($Folder)) (Get-PraRetentionProofName -BatchId $BatchId -CreatedUtc $created)
    $stream = New-Object IO.FileStream($path, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
    try { $bytes = (New-Object Text.UTF8Encoding($false)).GetBytes(($record | ConvertTo-Json -Depth 6)); $stream.Write($bytes, 0, $bytes.Length); $stream.Flush($true) } finally { $stream.Dispose() }
    $hash = Write-PraFileChecksum -Path $path
    return [pscustomobject][ordered]@{ Path = $path; Sidecar = ($path + '.sha256'); Sha256 = $hash; ObjectCount = $entries.Count; CoveredCount = $coveredCount; CreatedUtc = $created }
}

function Read-PraRetentionProofFile {
    <#
    .SYNOPSIS
        Reads one retention proof file: its checksum file must be there and match, and the content must be a retention proof of the right shape. Never throws.
    .DESCRIPTION
        The file is read once (at most 64 MB); the SHA-256 and the content are those same bytes. Every entry must have a Verdict (Covered, NotCovered, NotChecked or NoMailbox), a boolean Covered and a boolean NoMailbox that agree with it, an ObjectGuid that is
        a GUID when it has one, and no entry may repeat an object (by ObjectGuid, or by UPN): otherwise the proof is not valid and Reason says which entry.
    .OUTPUTS
        Valid, Transient (the file could not be read: not a statement about its content), Reason, Path, Sha256, BatchId, Environment, CreatedUtc (UTC), SourceBackupHash, PolicyGuid, ObjectCount, CoveredCount, NoMailboxCount and Objects (Guid, HasGuid, Upn, Verdict, Covered, NoMailbox).
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path)
    $result = [pscustomobject][ordered]@{ Valid = $false; Transient = $false; Reason = ''; Path = $Path; Sha256 = ''; BatchId = ''; Environment = ''; CreatedUtc = [datetime]::MinValue; SourceBackupHash = ''; PolicyGuid = [string[]]@(); ObjectCount = 0; CoveredCount = 0; NoMailboxCount = 0; Objects = @() }
    try {
        $sidecar = $Path + '.sha256'
        if (-not [IO.File]::Exists($sidecar)) { $result.Reason = 'its .sha256 file is missing'; return $result }
        $limit = 64MB
        $stream = [IO.File]::Open($Path, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
        try {
            $length = $stream.Length
            if ($length -lt 2 -or $length -gt $limit) { $result.Reason = 'its size is not acceptable (a retention proof is at most 64 MB)'; return $result }
            $bytes = New-Object byte[] ([int]$length)
            $got = 0
            while ($got -lt $bytes.Length) { $count = $stream.Read($bytes, $got, $bytes.Length - $got); if ($count -le 0) { break }; $got += $count }
            if ($got -ne $bytes.Length) { $result.Reason = 'it changed while it was being read'; $result.Transient = $true; return $result }
        }
        finally { $stream.Dispose() }
        $actual = [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($bytes)).ToLowerInvariant()
        $token = ([IO.File]::ReadAllText($sidecar).Trim() -split '\s+')[0]
        if ($token -notmatch '\A[0-9a-fA-F]{64}\z' -or -not (Test-PraOrdinalIgnoreCaseEqual $token $actual)) { $result.Reason = 'its SHA-256 does not match its .sha256 file (the file was changed or damaged)'; return $result }
        $result.Sha256 = $actual
        $content = (New-Object Text.UTF8Encoding($false)).GetString($bytes).TrimStart([char]0xFEFF)
        $data = $content | ConvertFrom-PraJson
        if (-not (Test-PraOrdinalEqual ([string](Get-PraValue $data 'Kind' '')) 'RetentionProof') -or [int](Get-PraValue $data 'SchemaVersion' 0) -ne 1) { $result.Reason = 'it is not a retention proof of this version'; return $result }
        $created = [datetime]::MinValue
        if (-not [datetime]::TryParse([string](Get-PraValue $data 'CreatedUtc' ''), [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::RoundtripKind, [ref]$created)) { $result.Reason = 'its time is not readable'; return $result }
        $objects = @($(if ($null -ne $data.PSObject.Properties['Objects']) { $data.Objects }) | Where-Object { $null -ne $_ })
        $entries = New-Object 'Collections.Generic.List[object]'
        $seenGuid = New-Object 'Collections.Generic.HashSet[guid]'
        $seenUpn = New-Object 'Collections.Generic.HashSet[string]' -ArgumentList ([StringComparer]::OrdinalIgnoreCase)
        $covered = 0; $noMailbox = 0; $position = 0
        foreach ($entry in $objects) {
            $position++
            $guidText = [string](Get-PraValue $entry 'ObjectGuid' ''); $upn = [string](Get-PraValue $entry 'Upn' '')
            $guid = [guid]::Empty
            if ($guidText -and (-not [guid]::TryParse($guidText, [ref]$guid) -or $guid -eq [guid]::Empty)) { $result.Reason = ('entry {0} has an ObjectGuid that is not a GUID' -f $position); return $result }
            if (-not $guidText -and -not $upn) { $result.Reason = ('entry {0} names no object (no ObjectGuid and no Upn)' -f $position); return $result }
            $isCovered = Get-PraValue $entry 'Covered' $null; $isNoMailbox = Get-PraValue $entry 'NoMailbox' $null
            if ($isCovered -isnot [bool] -or $isNoMailbox -isnot [bool]) { $result.Reason = ('entry {0} does not say true or false for Covered and NoMailbox' -f $position); return $result }
            if ($isCovered -and $isNoMailbox) { $result.Reason = ('entry {0} says both Covered and NoMailbox' -f $position); return $result }
            $verdict = [string](Get-PraValue $entry 'Verdict' '')
            if (-not $verdict) { $result.Reason = ('entry {0} has no Verdict (a proof written by an earlier build is not accepted)' -f $position); return $result }
            if (-not (Test-PraOrdinalIn $verdict @('Covered', 'NotCovered', 'NotChecked', 'NoMailbox'))) { $result.Reason = ('entry {0} has an unknown Verdict' -f $position); return $result }
            if (((Test-PraOrdinalEqual $verdict 'Covered') -xor $isCovered) -or ((Test-PraOrdinalEqual $verdict 'NoMailbox') -xor $isNoMailbox)) { $result.Reason = ('entry {0}: its Verdict {1} does not agree with its Covered and NoMailbox' -f $position, $verdict); return $result }
            if ($guidText -and -not $seenGuid.Add($guid)) { $result.Reason = ('the object {0} is in the proof more than once (entry {1})' -f $guid, $position); return $result }
            if ($upn -and -not $seenUpn.Add($upn)) { $result.Reason = ('the UPN {0} is in the proof more than once (entry {1})' -f $upn, $position); return $result }
            if ($isCovered) { $covered++ }
            if ($isNoMailbox) { $noMailbox++ }
            $entries.Add([pscustomobject]@{ Guid = $guid; HasGuid = [bool]$guidText; Upn = $upn; Verdict = $verdict; Covered = [bool]$isCovered; NoMailbox = [bool]$isNoMailbox })
        }
        $result.BatchId = [string](Get-PraValue $data 'BatchId' ''); $result.Environment = [string](Get-PraValue $data 'Environment' ''); $result.SourceBackupHash = [string](Get-PraValue $data 'SourceBackupHash' '')
        $result.CreatedUtc = $created.ToUniversalTime(); $result.PolicyGuid = [string[]]@(if ($null -ne $data.PSObject.Properties['PolicyGuid']) { $data.PolicyGuid })
        $result.Objects = $entries.ToArray(); $result.ObjectCount = $entries.Count; $result.CoveredCount = $covered; $result.NoMailboxCount = $noMailbox
        $result.Valid = $true
    }
    catch { $result.Reason = 'it cannot be read (' + (([string]$_.Exception.Message) -replace '\s+', ' ') + ')'; $result.Transient = $true }
    return $result
}

function Test-PraRetentionCheckRecord {
    <# True when a Recover checks the retention of the object of this record: the record carries the retention tag and the cloud mailbox is not kept on purpose (-PreserveCloudMailbox). The gate of the run and the console use this one rule. #>
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Record, [bool]$PreserveCloudMailbox = $false)
    return ((-not $PreserveCloudMailbox) -and [bool](Get-PraValue (Get-PraValue $Record 'Retention' $null) 'Enabled' $false))
}

function Get-PraRetentionProofIndex {
    <# The entries of one valid proof by ObjectGuid, by UPN for the entries that have no ObjectGuid, and by UPN. #>
    param([Parameter(Mandatory)]$Read)
    $byGuid = New-Object 'Collections.Generic.Dictionary[guid,object]'
    $byUpnWithoutGuid = New-Object 'Collections.Generic.Dictionary[string,object]' -ArgumentList ([StringComparer]::OrdinalIgnoreCase)
    $byUpn = New-Object 'Collections.Generic.Dictionary[string,object]' -ArgumentList ([StringComparer]::OrdinalIgnoreCase)
    foreach ($entry in $Read.Objects) {
        if ($entry.HasGuid) { $byGuid[$entry.Guid] = $entry } elseif ($entry.Upn) { $byUpnWithoutGuid[$entry.Upn] = $entry }
        if ($entry.Upn) { $byUpn[$entry.Upn] = $entry }
    }
    return [pscustomobject]@{ Read = $Read; ByGuid = $byGuid; ByUpnWithoutGuid = $byUpnWithoutGuid; ByUpn = $byUpn }
}

function Find-PraRetentionProofEntry {
    <# The entry of an index for an object of a Recover: by ObjectGuid; the UPN counts only for an entry that has no ObjectGuid (a row without ObjectGuid is found by its UPN). $null when the proof does not list the object. #>
    param([Parameter(Mandatory)]$Index, [Parameter(Mandatory)]$Item)
    $entry = $null
    $itemUpn = [string](Get-PraValue $Item 'UserPrincipalName' ''); $itemGuidText = [string](Get-PraValue $Item 'ObjectGuid' '')
    $itemGuid = [guid]::Empty
    if ($itemGuidText -and [guid]::TryParse($itemGuidText, [ref]$itemGuid) -and $itemGuid -ne [guid]::Empty) {
        if (-not $Index.ByGuid.TryGetValue($itemGuid, [ref]$entry)) { $entry = $null; if ($itemUpn) { [void]$Index.ByUpnWithoutGuid.TryGetValue($itemUpn, [ref]$entry) } }
    }
    elseif ($itemUpn) { [void]$Index.ByUpn.TryGetValue($itemUpn, [ref]$entry) }
    return $entry
}

function Get-PraRetentionProofDecision {
    <#
    .SYNOPSIS
        What the valid proofs of a batch say about the objects of a Recover: for each object, the newest proof that lists it with a definitive verdict (Covered, NoMailbox or NotCovered) decides; NotChecked leaves the decision to an older proof.
    .PARAMETER Read
        The valid proofs, newest first.
    .OUTPUTS
        Complete (every object is Covered or NoMailbox), Missing (UPN, else ObjectGuid, of the objects without a covering verdict), Blocked (objects whose newest definitive verdict is NotCovered: Upn, ObjectGuid, Proof), NoMailbox (Upn, ObjectGuid),
        Used (the proofs that decided at least one object, newest first) and Notes (a newer proof that changes the answer of an older one).
    #>
    param([Parameter(Mandatory)][object[]]$Read, [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Row)
    $indexes = @($Read | ForEach-Object { Get-PraRetentionProofIndex -Read $_ })
    $missing = New-Object 'Collections.Generic.List[string]'; $blocked = New-Object 'Collections.Generic.List[object]'; $without = New-Object 'Collections.Generic.List[object]'
    $used = New-Object 'Collections.Generic.HashSet[int]'
    $changes = New-Object 'Collections.Generic.Dictionary[string,int]' -ArgumentList ([StringComparer]::Ordinal)
    foreach ($item in $Row) {
        $itemUpn = [string](Get-PraValue $item 'UserPrincipalName' ''); $itemGuidText = [string](Get-PraValue $item 'ObjectGuid' '')
        $label = $(if ($itemUpn) { $itemUpn } else { $itemGuidText })
        $decidedAt = -1; $decidedVerdict = ''; $deferredAt = New-Object 'Collections.Generic.List[int]'
        for ($i = 0; $i -lt $indexes.Count; $i++) {
            $entry = Find-PraRetentionProofEntry -Index $indexes[$i] -Item $item
            if ($null -eq $entry) { continue }
            if (Test-PraOrdinalEqual $entry.Verdict 'NotChecked') { $deferredAt.Add($i); continue }
            if ($decidedAt -lt 0) { $decidedAt = $i; $decidedVerdict = [string]$entry.Verdict; continue }
            if ((Test-PraOrdinalEqual $decidedVerdict 'NotCovered') -xor (Test-PraOrdinalEqual $entry.Verdict 'NotCovered')) {
                $key = 'override|{0}|{1}' -f $decidedAt, $i; $changes[$key] = 1 + $(if ($changes.ContainsKey($key)) { $changes[$key] } else { 0 })
            }
            break
        }
        if ($decidedAt -lt 0) { $missing.Add($label); continue }
        [void]$used.Add($decidedAt)
        foreach ($deferred in $deferredAt) { if ($deferred -lt $decidedAt) { $key = 'defer|{0}|{1}' -f $deferred, $decidedAt; $changes[$key] = 1 + $(if ($changes.ContainsKey($key)) { $changes[$key] } else { 0 }) } }
        if (Test-PraOrdinalEqual $decidedVerdict 'NotCovered') { $blocked.Add([pscustomobject]@{ Upn = $itemUpn; ObjectGuid = $itemGuidText; Proof = [IO.Path]::GetFileName([string]$indexes[$decidedAt].Read.Path) }); $missing.Add($label); continue }
        if (Test-PraOrdinalEqual $decidedVerdict 'NoMailbox') { $without.Add([pscustomobject]@{ ObjectGuid = $itemGuidText; Upn = $itemUpn }) }
    }
    $notes = New-Object 'Collections.Generic.List[string]'
    foreach ($pair in $changes.GetEnumerator()) {
        $part = $pair.Key.Split('|'); $first = [IO.Path]::GetFileName([string]$indexes[[int]$part[1]].Read.Path); $second = [IO.Path]::GetFileName([string]$indexes[[int]$part[2]].Read.Path)
        if (Test-PraOrdinalEqual $part[0] 'override') { $notes.Add(('The newer retention proof {0} gives another answer than {1} for {2} object(s) of this Recover: the newer one decides.' -f $first, $second, $pair.Value)) }
        else { $notes.Add(('The retention proof {0} did not check {1} object(s) of this Recover: the answer of {2} is used for them.' -f $first, $pair.Value, $second)) }
    }
    $order = [int[]]@($used); [Array]::Sort($order)
    $usedProofs = @($order | ForEach-Object { $indexes[$_].Read })
    $answer = [pscustomobject]@{ Complete = ($missing.Count -eq 0); Missing = [string[]]$missing.ToArray(); Blocked = $blocked.ToArray(); NoMailbox = $without.ToArray(); Used = $usedProofs; Notes = [string[]]$notes.ToArray(); Reason = '' }
    if (-not $answer.Complete) { $answer.Reason = '{0} of the {1} object(s) of this Recover are not covered in it' -f $missing.Count, @($Row).Count }
    return $answer
}

function Get-PraRetentionProof {
    <#
    .SYNOPSIS
        The retention proof that lets a Recover go on when Exchange Online cannot be asked: the proofs of the Convert batch, in these folders, that are intact, of this batch and Environment, not older than -MaxAgeHours, and what they say about each object.
    .DESCRIPTION
        Read only. -Row (objects with ObjectGuid and UserPrincipalName): the objects of the Recover. For each object the newest usable proof that lists it with a definitive verdict (Covered, NoMailbox, NotCovered) decides; a NotChecked
        verdict leaves it to an older proof; an object whose newest definitive verdict is NotCovered blocks, whatever older proofs said. Complete is true when every object is Covered (or NoMailbox: nothing to retain); Missing lists the
        UPNs that are not, and Blocked those that a proof says are not held. Without -Row, Complete says that every object of the newest usable proof is covered. An object is found by its ObjectGuid; its UPN counts only for a proof entry that
        has no ObjectGuid, so the same UPN with another ObjectGuid is not covered. -SourceBackupHash (the hash of the Convert batch file) and -PolicyGuid (Retention.PolicyGuid, when the configuration sets one) must agree with the proof;
        a -PolicyGuid that is not a GUID refuses every proof (PolicyGuidInvalid). A file that is not usable is skipped; Reason tells why the newest candidate was refused or what is not covered.
    .OUTPUTS
        Found (a usable proof exists), Complete, Reason, Path, Sha256, CreatedUtc, AgeHours, ObjectCount, CoveredCount (of the newest usable proof), NoMailbox (objects that a proof says have no mailbox), Missing, Blocked, PolicyGuid,
        Proofs (the proofs that decided an object: Path, Sha256, CreatedUtc, PolicyGuid, ObjectCount), Notes (a newer proof that changes the answer of an older one), FutureDated, PolicyGuidInvalid, Candidates (files looked at).
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][AllowEmptyCollection()][string[]]$Folder, [Parameter(Mandatory)][string]$BatchId, [Parameter(Mandatory)][string]$Environment,
        [ValidateRange(1, 720)][int]$MaxAgeHours = 24, [AllowEmptyCollection()][object[]]$Row, [hashtable]$Cache, [string]$SourceBackupHash = '', [string]$PolicyGuid = '')
    $result = [pscustomobject][ordered]@{ Found = $false; Complete = $false; Reason = ''; Path = ''; Sha256 = ''; CreatedUtc = [datetime]::MinValue; AgeHours = [double]0; ObjectCount = 0; CoveredCount = 0; NoMailbox = @(); Missing = [string[]]@(); Blocked = @(); PolicyGuid = [string[]]@(); Proofs = @(); Notes = [string[]]@(); FutureDated = $false; PolicyGuidInvalid = $false; Candidates = 0 }
    $wantedPolicy = [guid]::Empty
    if ($PolicyGuid -and (-not [guid]::TryParse($PolicyGuid, [ref]$wantedPolicy) -or $wantedPolicy -eq [guid]::Empty)) {
        $result.PolicyGuidInvalid = $true
        $result.Reason = 'Retention.PolicyGuid of this configuration ({0}) is not a GUID, so no proof can be matched to the policy' -f $PolicyGuid
        return $result
    }
    $id = $BatchId.ToLowerInvariant()
    $files = New-Object 'Collections.Generic.List[string]'
    $seen = New-Object 'Collections.Generic.HashSet[string]' -ArgumentList ([StringComparer]::OrdinalIgnoreCase)
    foreach ($directory in $Folder) {
        if (-not $directory -or -not [IO.Directory]::Exists($directory)) { continue }
        foreach ($file in [IO.Directory]::GetFiles($directory, 'RetentionProof-' + $id + '-*.json')) { if ($seen.Add([IO.Path]::GetFullPath($file))) { $files.Add($file) } }
    }
    $result.Candidates = $files.Count
    if (-not $files.Count) { $result.Reason = 'no retention proof of this batch was found'; return $result }
    $now = [DateTime]::UtcNow
    $withRows = $PSBoundParameters.ContainsKey('Row') -and $null -ne $Row
    $byTime = @($files | ForEach-Object { [pscustomobject]@{ Name = [IO.Path]::GetFileName($_); Path = $_ } } | Get-PraOrdinalSorted -Property Name -Descending)
    $valid = New-Object 'Collections.Generic.List[object]'; $firstReason = ''
    foreach ($candidate in $byTime) {
        $file = [string]$candidate.Path
        $stamp = ''
        if ($null -ne $Cache) {
            $info = New-Object IO.FileInfo $file; $sidecarText = ''
            try { $sidecarText = [IO.File]::ReadAllText($file + '.sha256').Trim() } catch { $sidecarText = '' }
            $stamp = '{0}|{1}|{2}|{3}|{4}' -f $file, $info.Length, $info.LastWriteTimeUtc.Ticks, (New-Object IO.FileInfo ($file + '.sha256')).LastWriteTimeUtc.Ticks, $sidecarText
        }
        $read = $null
        if ($stamp -and $Cache.ContainsKey($stamp)) { $read = $Cache[$stamp] } else { $read = Read-PraRetentionProofFile -Path $file; if ($stamp -and -not $read.Transient) { $Cache[$stamp] = $read } }
        $why = ''
        if (-not $read.Valid) { $why = $read.Reason }
        elseif (-not (Test-PraOrdinalIgnoreCaseEqual $read.BatchId $id)) { $why = 'it was made for another batch' }
        elseif (-not (Test-PraOrdinalIgnoreCaseEqual $read.Environment $Environment)) { $why = ('it was made for the Environment {0}, this configuration is {1}' -f $read.Environment, $Environment) }
        elseif ($SourceBackupHash -and -not (Test-PraOrdinalIgnoreCaseEqual $read.SourceBackupHash $SourceBackupHash)) { $why = 'it was made from another copy of the Convert batch file (its SourceBackupHash is not the hash of this batch file)' }
        elseif ($PolicyGuid -and -not (@($read.PolicyGuid | Where-Object { $parsed = [guid]::Empty; [guid]::TryParse([string]$_, [ref]$parsed) -and $parsed.Equals($wantedPolicy) }).Count)) { $why = 'it was made for another retention policy (its PolicyGuid is not Retention.PolicyGuid of this configuration)' }
        elseif ($read.CreatedUtc -gt $now.AddMinutes(5)) { $why = 'its time is in the future (the clocks of the two servers differ by more than 5 minutes)'; $result.FutureDated = $true }
        elseif (($now - $read.CreatedUtc).TotalHours -gt $MaxAgeHours) { $why = ('it is {0} hours old, the limit is {1} (Retention.ProofMaxAgeHours)' -f ($now - $read.CreatedUtc).TotalHours.ToString('0.#', [Globalization.CultureInfo]::InvariantCulture), $MaxAgeHours) }
        if ($why) { if (-not $firstReason) { $firstReason = ('{0}: {1}' -f [IO.Path]::GetFileName($file), $why) }; continue }
        $valid.Add($read)
    }
    if (-not $valid.Count) { $result.Reason = $firstReason; return $result }
    $newest = $valid[0]
    $result.Found = $true; $result.Path = $newest.Path; $result.Sha256 = $newest.Sha256; $result.CreatedUtc = $newest.CreatedUtc; $result.AgeHours = [Math]::Max(0.0, ($now - $newest.CreatedUtc).TotalHours)
    $result.ObjectCount = $newest.ObjectCount; $result.CoveredCount = $newest.CoveredCount; $result.PolicyGuid = $newest.PolicyGuid
    $summary = { param($Proof) [pscustomobject]@{ Path = [string]$Proof.Path; Sha256 = [string]$Proof.Sha256; CreatedUtc = $Proof.CreatedUtc; PolicyGuid = [string[]]@($Proof.PolicyGuid); ObjectCount = [int]$Proof.ObjectCount } }
    if ($withRows) {
        $decision = Get-PraRetentionProofDecision -Read $valid.ToArray() -Row $Row
        $result.Complete = $decision.Complete; $result.Missing = $decision.Missing; $result.Blocked = @($decision.Blocked); $result.NoMailbox = @($decision.NoMailbox); $result.Notes = $decision.Notes; $result.Reason = $decision.Reason
        $result.Proofs = @($decision.Used | ForEach-Object { & $summary $_ })
        return $result
    }
    $open = @($newest.Objects | Where-Object { -not ($_.Covered -or $_.NoMailbox) })
    $result.Complete = ($newest.ObjectCount -gt 0 -and $open.Count -eq 0)
    if (-not $result.Complete) { $result.Reason = '{0} of the {1} object(s) of the proof are not covered' -f ($newest.ObjectCount - $newest.CoveredCount - $newest.NoMailboxCount), $newest.ObjectCount }
    $result.NoMailbox = @($newest.Objects | Where-Object { $_.NoMailbox } | ForEach-Object { [pscustomobject]@{ ObjectGuid = $(if ($_.HasGuid) { $_.Guid.ToString() } else { '' }); Upn = $_.Upn } })
    $result.Proofs = @(& $summary $newest)
    return $result
}

function Get-PraConvertCloudDone {
    <#
    .SYNOPSIS
        The objects whose cloud part of the Convert is recorded as complete: from the PhaseData files of the Convert batch folder (checksum, Kind, Environment and batch are checked; a file that fails is ignored).
    .OUTPUTS
        Known (at least one cloud phase of the Convert was read) and Done (a set of ObjectGuid, any letter case).
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Folder, [Parameter(Mandatory)][string]$BatchId, [string]$Environment = '')
    $done = New-Object 'Collections.Generic.HashSet[string]' -ArgumentList ([StringComparer]::OrdinalIgnoreCase)
    $known = $false
    if ($Folder -and [IO.Directory]::Exists($Folder)) {
        $files = [string[]][IO.Directory]::GetFiles($Folder, $script:PraPhaseFilter)
        [Array]::Sort([Array]$files, [Collections.IComparer][StringComparer]::Ordinal)
        if ($files.Length -gt $script:PraPhaseLimits.MaxFiles) { $files = [string[]]@($files[($files.Length - $script:PraPhaseLimits.MaxFiles)..($files.Length - 1)]) }
        foreach ($file in $files) {
            try {
                $length = ([IO.FileInfo]$file).Length
                if ($length -lt 2 -or $length -gt $script:PraPhaseLimits.MaxBytes -or -not [IO.File]::Exists($file + '.sha256')) { continue }
                $bytes = [IO.File]::ReadAllBytes($file)
                $digest = [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($bytes)).ToLowerInvariant()
                $token = ([IO.File]::ReadAllText($file + '.sha256').Trim() -split '\s+')[0]
                if ($token -notmatch '\A[0-9a-fA-F]{64}\z' -or -not (Test-PraOrdinalIgnoreCaseEqual $token $digest)) { continue }
                $record = (New-Object Text.UTF8Encoding($false)).GetString($bytes) | ConvertFrom-PraJson
                if (-not (Test-PraOrdinalEqual ([string](Get-PraValue $record 'Kind' '')) 'PhaseData')) { continue }
                if ($Environment -and -not (Test-PraOrdinalIgnoreCaseEqual ([string](Get-PraValue $record 'Environment' '')) $Environment)) { continue }
                if (-not (Test-PraOrdinalIgnoreCaseEqual ([string](Get-PraValue $record 'BatchId' '')) $BatchId)) { continue }
                $phase = Get-PraValue $record 'Phase' $null
                if (-not (Test-PraOrdinalEqual ([string](Get-PraValue $phase 'Action' '')) 'Convert') -or -not (Test-PraOrdinalIgnoreCaseEqual ([string](Get-PraValue $phase 'Mode' '')) 'Apply') -or
                    -not (Test-PraOrdinalIn ([string](Get-PraValue $phase 'Phase' '')) @('Cloud', 'Both') -IgnoreCase)) { continue }
                $known = $true
                $listed = Get-PraValue $record 'Objects' @()
                foreach ($object in @($listed)) { if (Test-PraOrdinalEqual ([string](Get-PraValue $object 'CloudStatus' '')) 'Success') { [void]$done.Add([string](Get-PraValue $object 'ObjectGuid' '')) } }
            }
            catch { $null = $_ }
        }
    }
    return [pscustomobject]@{ Known = $known; Done = $done }
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
        Throws when anything is wrong. A folder that already exists is accepted (Existing) when every file of the package is in it unchanged and
        the only other files are side files (Test-PraBatchSideFile: proof, journal, global report data, checksums), which are never replaced; any other difference is refused
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
    $ordered = @($items | Get-PraOrdinalSorted -Property Name)
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
        $keys = @($Value.Keys | ForEach-Object { [string]$_ } | Get-PraOrdinalSorted)
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
    foreach ($key in @($Configuration.Keys | ForEach-Object { [string]$_ } | Get-PraOrdinalSorted)) {
        if ($key.StartsWith('_', [StringComparison]::Ordinal)) { continue }
        $value = $Configuration[$key]
        if ($value -is [Collections.IDictionary]) { Get-PraConfigurationFlat -Configuration $value -Prefix ($Prefix + $key + '.') }
        elseif ($value -is [Collections.IEnumerable] -and $value -isnot [string]) { [pscustomobject]@{ Key = $Prefix + $key; Value = (@($value | ForEach-Object { [string]$_ }) -join ', ') } }
        else { [pscustomobject]@{ Key = $Prefix + $key; Value = [string]$value } }
    }
}

function Get-PraConfigurationDifference {
    <# What the run changes compared with the configuration file: one object (Key, Base, Effective, Text = 'Key: base -> effective') per setting whose value differs (the letter case is not a difference). #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][Collections.IDictionary]$Base, [Parameter(Mandatory)][Collections.IDictionary]$Effective)
    $baseFlat = @{}
    foreach ($row in @(Get-PraConfigurationFlat -Configuration $Base)) { $baseFlat[$row.Key] = $row.Value }
    foreach ($row in @(Get-PraConfigurationFlat -Configuration $Effective)) {
        $before = if ($baseFlat.ContainsKey($row.Key)) { [string]$baseFlat[$row.Key] } else { '' }
        if (-not (Test-PraOrdinalIgnoreCaseEqual $before $row.Value)) {
            $beforeText = if ($before) { $before } else { '(empty)' }; $afterText = if ($row.Value) { $row.Value } else { '(empty)' }
            [pscustomobject][ordered]@{ Key = $row.Key; Base = $before; Effective = $row.Value; Text = ('{0}: {1} -> {2}' -f $row.Key, $beforeText, $afterText) }
        }
    }
}

function Get-PraOverrideKey {
    <# Dotted names of the leaves of an overrides table. #>
    param([Collections.IDictionary]$Overrides, [string]$Prefix = '')
    foreach ($key in @($Overrides.Keys | ForEach-Object { [string]$_ } | Get-PraOrdinalSorted)) {
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
        $loaded = Import-PraConfiguration -Path $target -Root $Root -DeferScopeCheck
        $expected = $config.Environment
        if (-not (Test-PraOrdinalIgnoreCaseEqual $loaded.Environment $expected)) { throw 'The effective configuration does not round-trip.' }
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
# The journey lines, errors and warnings of a phase are not in that file: they are written one JSON object per line to PhaseEvents-<same stem>.jsonl (+ .sha256) next to it, whose
# SHA-256 the PhaseData header carries, so the PhaseData file holds the header and one entry per object whatever the number of events. Nothing is cut silently: what a limit leaves
# out is counted in the header (Omitted) and the global report says so.
# MaxFileBytes: the largest PhaseData file the writer writes; MaxBytes: the largest PhaseData file the reader accepts, and all the files read for one report together;
# MaxEventsBytes: the largest events file and all the events files read for one report together; MaxLineChars: the longest line the reader accepts; MaxFiles: the newest PhaseData files read.
$script:PraPhaseLimits = @{ MaxBytes = [long]268435456; MaxFileBytes = [long]67108864; MaxEventsBytes = [long]100663296; MaxLineChars = 65536; MaxText = 2000; MaxStepText = 300; MaxJourney = 1000000; MaxObjects = 200000; MaxFiles = 200 }
$script:PraPhaseFilter = 'PhaseData-*.json'
$script:PraEventsPrefix = 'PhaseEvents-'
$script:PraTextCut = [long]0
$script:PraNotAvailable = 'not available (folder from an older version or copied manually)'
# Display only: a Pending phase (or stage) that a later phase of the same report took over is shown as handed over; the verdict logic reads the raw status.
$script:PraHandedOver = 'Handed over'

function Limit-PraText {
    <# A text for a report: control characters replaced by a space, at most $Max characters (a longer text ends with '...' and is counted in $script:PraTextCut). #>
    [CmdletBinding()]
    [OutputType([string])]
    param([AllowNull()][object]$Value, [int]$Max = 2000)
    if ($null -eq $Value) { return '' }
    $text = [regex]::Replace([string]$Value, '[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]', ' ')
    if ($text.Length -gt $Max) { $script:PraTextCut++; return $text.Substring(0, [Math]::Max(0, $Max - 3)) + '...' }
    return $text
}

function Add-PraJourney {
    <#
    .SYNOPSIS
        Remembers one line of the journey of an object (time, step, status, text) when the current identity is a known object.
        Memory only. A line above MaxJourney is not kept and a text cut to MaxStepText is not complete: both are counted in the context (JourneyDropped, JourneyTextCut) and the phase data says so.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][hashtable]$Context, [Parameter(Mandatory)][string]$Status, [AllowEmptyString()][string]$Text)
    $identity = [string](Get-PraValue $Context 'CurrentIdentity' '')
    if (-not $identity) { return }
    $name = Get-PraEventObjectName $Context $identity
    if (-not $name) { return }
    if (-not $Context.ContainsKey('Journey')) { $Context['Journey'] = New-Object 'Collections.Generic.List[object]' }
    $list = $Context['Journey']
    if ($list.Count -ge $script:PraPhaseLimits.MaxJourney) { $Context['JourneyDropped'] = [long](Get-PraValue $Context 'JourneyDropped' 0) + 1; return }
    $cut = $script:PraTextCut
    [void]$list.Add([pscustomobject]@{ Time = [datetime]::UtcNow.ToString('o'); Name = $name; Step = (Limit-PraText (Get-PraValue $Context 'CurrentPhase' '') 200)
            Status = $Status; Text = (Limit-PraText $Text $script:PraPhaseLimits.MaxStepText) })
    if ($script:PraTextCut -gt $cut) { $Context['JourneyTextCut'] = [long](Get-PraValue $Context 'JourneyTextCut' 0) + 1 }
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
    $settings['Retention check before Recover'] = [string]([bool](Get-PraValue (Get-PraValue $config 'Retention' @{}) 'CheckBeforeRecover' $true))
    $accepted = Get-PraValue $Context 'RetentionProofAccepted' $null
    if ($null -ne $accepted -and @($accepted).Count) {
        $settings['Retention proof accepted'] = (@($accepted | ForEach-Object { '{0} (SHA-256 {1}, created {2} UTC, policy {3}, {4} object(s))' -f [IO.Path]::GetFileName([string]$_.Path), $_.Sha256, ([datetime]$_.CreatedUtc).ToString('yyyy-MM-dd HH:mm:ss', [Globalization.CultureInfo]::InvariantCulture), $(if (@($_.PolicyGuid).Count) { @($_.PolicyGuid) -join ', ' } else { '(none recorded)' }), $_.ObjectCount }) -join '; ')
    }
    return $settings
}

function New-PraPhaseRecord {
    <#
    .SYNOPSIS
        What this run did, as data: the run (server, operator, times, mode, tool version, run settings changed, steps, log file), one entry per object (identity, type, final
        status, steps with status, time and message, warnings, backup), the errors and the warnings, the journey lines that name no object, and what a limit left out (Omitted).
        Memory only: Save-PraPhaseData writes the steps, the errors, the warnings and the other lines to the events file.
    #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions','',Justification='In-memory constructor of report data, no change to any target or file.')]
    [CmdletBinding()]
    param([Parameter(Mandatory)][hashtable]$Context, [string]$HandOff = '')
    $limits = $script:PraPhaseLimits
    $cutBefore = $script:PraTextCut
    $outcome = Get-PraOutcome $Context
    $byName = New-Object 'Collections.Generic.Dictionary[string,object]' -ArgumentList ([StringComparer]::OrdinalIgnoreCase)
    if ($Context.ContainsKey('Journey') -and $null -ne $Context['Journey']) {
        foreach ($entry in $Context['Journey']) {
            if ($null -eq $entry) { continue }
            $list = $byName[[string]$entry.Name]
            if ($null -eq $list) { $list = New-Object 'Collections.Generic.List[object]'; $byName[[string]$entry.Name] = $list }
            [void]$list.Add($entry)
        }
    }
    $used = New-Object 'Collections.Generic.HashSet[string]' -ArgumentList ([StringComparer]::OrdinalIgnoreCase)
    $objects = New-Object 'Collections.Generic.List[object]'
    $omittedObjects = 0
    foreach ($row in $Context.Rows.ToArray()) {
        if ($objects.Count -ge $limits.MaxObjects) { $omittedObjects++; continue }
        $guid = [string](Get-PraValue $row 'ObjectGuid' ''); $upn = [string](Get-PraValue $row 'UserPrincipalName' ''); $sam = [string](Get-PraValue $row 'SamAccountName' '')
        $name = if ($upn) { $upn } elseif ($sam) { $sam } else { $guid }
        $steps = New-Object 'Collections.Generic.List[object]'
        $found = $byName[$name]
        if ($null -ne $found) { [void]$used.Add($name); $steps.AddRange($found) }
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
        [void]$objects.Add([ordered]@{
                ObjectGuid = $guid; Name = (Limit-PraText $name 300); SamAccountName = (Limit-PraText $sam 300); UserPrincipalName = (Limit-PraText $upn 300)
                IsShared = [bool](Get-PraValue $row 'IsShared' $false); Action = [string](Get-PraValue $row 'Action' ''); FinalStatus = [string](Get-PraValue $row 'FinalStatus' '')
                CloudStatus = [string](Get-PraValue $row 'CloudStatus' ''); ADApplied = (Get-PraValue $row 'ADApplied' $null); ADVerified = (Get-PraValue $row 'ADVerified' $null)
                BackupPath = (Limit-PraText (Get-PraValue $row 'BackupPath' '') 500); Detail = (Limit-PraText (Get-PraValue $row 'Detail' '') $limits.MaxText)
                CloudDetail = (Limit-PraText (Get-PraValue $row 'CloudDetail' '') $limits.MaxText); Warnings = (Limit-PraText (Get-PraValue $row 'Warnings' '') $limits.MaxText)
                Steps = $steps.ToArray()
            })
    }
    $unattached = New-Object 'Collections.Generic.List[object]'
    foreach ($pair in $byName.GetEnumerator()) { if (-not $used.Contains([string]$pair.Key)) { $unattached.AddRange($pair.Value) } }
    $stepLog = @(@(Get-PraList $Context 'StepLog') | ForEach-Object { if ($null -ne $_) { [ordered]@{ Index = [int]$_.Index; Title = (Limit-PraText $_.Title 200); State = [string]$_.State; StartedUtc = [string]$_.StartedUtc; EndedUtc = [string]$_.EndedUtc } } })
    $issues = @($Context.Issues.ToArray() | ForEach-Object {
            [ordered]@{ Timestamp = [string](Get-PraValue $_ 'Timestamp' ''); Phase = (Limit-PraText (Get-PraValue $_ 'Phase' '') 200); Operation = (Limit-PraText (Get-PraValue $_ 'Operation' '') 200)
                Identity = (Limit-PraText (Get-PraValue $_ 'Identity' '') 300); Source = (Limit-PraText (Get-PraValue $_ 'Source' '') 100); Message = (Limit-PraText (Get-PraValue $_ 'Message' ([string]$_)) 1000) } })
    $warnings = @(@(Get-PraList $Context 'WarningList') | ForEach-Object {
            [ordered]@{ Timestamp = [string](Get-PraValue $_ 'Timestamp' ''); Phase = (Limit-PraText (Get-PraValue $_ 'Phase' '') 200); Message = (Limit-PraText (Get-PraValue $_ 'Message' ([string]$_)) 1000) } })
    $counts = $outcome.Counts
    $overrides = @(@(Get-PraList $Context 'ConfigOverrides') | ForEach-Object { if ($_) { Limit-PraText $_ 500 } })
    $runId = [string](Get-PraValue $Context 'RunId' '')
    $omitted = [ordered]@{ Objects = [long]$omittedObjects; ObjectsBySize = [long]0; JourneyLines = [long](Get-PraValue $Context 'JourneyDropped' 0); Texts = ([long](Get-PraValue $Context 'JourneyTextCut' 0) + ($script:PraTextCut - $cutBefore)); EventLines = [long]0 }
    return [ordered]@{
        SchemaVersion = 2; Kind = 'PhaseData'; Environment = [string](Get-PraValue (Get-PraValue $Context 'Config' @{}) 'Environment' ''); BatchId = [string](Get-PraValue $Context 'BatchId' '')
        ToolVersion = [string](Get-PraValue $Context 'Version' ''); Truncated = [bool]($omitted.Objects -or $omitted.JourneyLines -or $omitted.Texts)
        Phase = [ordered]@{
            RunId = $runId; Action = [string](Get-PraValue $Context 'Action' ''); Phase = [string](Get-PraValue $Context 'Phase' ''); Mode = [string](Get-PraValue $Context 'Mode' '')
            Computer = [string]$env:COMPUTERNAME; Account = ('{0}\{1}' -f $env:USERDOMAIN, $env:USERNAME); Server = [string](Get-PraValue $Context 'Server' '')
            LogFile = (Limit-PraText ([IO.Path]::GetFileName([string](Get-PraValue $Context 'LogFile' ''))) 200)
            StartedUtc = ([datetime](Get-PraValue $Context 'StartTime' ([datetime]::Now))).ToUniversalTime().ToString('o'); EndedUtc = [datetime]::UtcNow.ToString('o')
            Status = [string]$outcome.Status; ExitCode = [int]$outcome.ExitCode; HandOff = $HandOff; Overrides = $overrides; Settings = (Get-PraPhaseSetting $Context); Steps = $stepLog
            Counts = [ordered]@{ Success = [int]$counts.Success; Error = [int]$counts.Error; Pending = [int]$counts.Pending; Skipped = [int]$counts.Skipped; Planned = [int]$counts.Planned }
        }
        Omitted = $omitted
        Limits = [ordered]@{ MaxObjects = [long]$limits.MaxObjects; MaxFileBytes = [long]$limits.MaxFileBytes; MaxJourney = [long]$limits.MaxJourney; MaxStepText = [long]$limits.MaxStepText; MaxText = [long]$limits.MaxText; MaxEventsBytes = [long]$limits.MaxEventsBytes }
        Objects = $objects.ToArray(); Issues = $issues; Warnings = $warnings; Unattached = $unattached.ToArray()
    }
}

function Write-PraPhaseEventFile {
    <#
    .SYNOPSIS
        Writes the steps of every object, the journey lines that name no object, the errors and the warnings of a phase record to a JSON-lines file (one object per line, UTF-8
        without a byte order mark). A line that would take the file above MaxEventsBytes is not written and is counted.
    .OUTPUTS
        Count (lines written), Bytes and Dropped (lines left out).
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Record, [Parameter(Mandatory)][string]$Path)
    $limits = $script:PraPhaseLimits
    $utf8 = New-Object Text.UTF8Encoding($false)
    $escape = $script:JsonEscape; $evaluator = $script:JsonEscapeEvaluator
    $quote = { param([string]$Text) if ($escape.IsMatch($Text)) { '"' + $escape.Replace($Text, $evaluator) + '"' } else { '"' + $Text + '"' } }
    $state = @{ Count = 0; Bytes = [long]0; Dropped = [long]0 }
    $stream = New-Object IO.FileStream($Path, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
    $writer = New-Object IO.StreamWriter($stream, $utf8, 1048576)
    try {
        $emit = {
            param([string]$Line)
            $size = $utf8.GetByteCount($Line) + 1
            if ($state.Bytes + $size -gt $limits.MaxEventsBytes) { $state.Dropped++; return }
            $writer.Write($Line); $writer.Write("`n"); $state.Bytes += $size; $state.Count++
        }
        # The steps of an object carry its place in the list of objects (I): two objects can have no GUID or the same one, the place always tells them apart.
        $place = 0
        foreach ($object in @($Record.Objects)) {
            $key = (& $quote ([string]$object.ObjectGuid)) + ',"I":' + $place
            $place++
            foreach ($step in @($object.Steps)) {
                $time = [string]$step.Time; $name = [string]$step.Step; $status = [string]$step.Status; $text = [string]$step.Text
                if ($escape.IsMatch($time + $name + $status + $text)) { & $emit ('{"K":"E","G":' + $key + ',"Time":' + (& $quote $time) + ',"Step":' + (& $quote $name) + ',"Status":' + (& $quote $status) + ',"Text":' + (& $quote $text) + '}') }
                else { & $emit ('{"K":"E","G":' + $key + ',"Time":"' + $time + '","Step":"' + $name + '","Status":"' + $status + '","Text":"' + $text + '"}') }
            }
        }
        foreach ($step in @($Record.Unattached)) {
            & $emit ('{"K":"E","G":"","Name":' + (& $quote ([string]$step.Name)) + ',"Time":' + (& $quote ([string]$step.Time)) + ',"Step":' + (& $quote ([string]$step.Step)) + ',"Status":' + (& $quote ([string]$step.Status)) + ',"Text":' + (& $quote ([string]$step.Text)) + '}')
        }
        foreach ($issue in @($Record.Issues)) {
            & $emit ('{"K":"I","Timestamp":' + (& $quote ([string]$issue.Timestamp)) + ',"Phase":' + (& $quote ([string]$issue.Phase)) + ',"Operation":' + (& $quote ([string]$issue.Operation)) + ',"Identity":' + (& $quote ([string]$issue.Identity)) +
                ',"Source":' + (& $quote ([string]$issue.Source)) + ',"Message":' + (& $quote ([string]$issue.Message)) + '}')
        }
        foreach ($warning in @($Record.Warnings)) {
            & $emit ('{"K":"W","Timestamp":' + (& $quote ([string]$warning.Timestamp)) + ',"Phase":' + (& $quote ([string]$warning.Phase)) + ',"Message":' + (& $quote ([string]$warning.Message)) + '}')
        }
        $writer.Flush(); $stream.Flush($true)
    }
    finally { $writer.Dispose() }
    return [pscustomobject]@{ Count = [int]$state.Count; Bytes = [long]$state.Bytes; Dropped = [long]$state.Dropped }
}

function Write-PraFileChecksum {
    <# Writes <Path>.sha256 (the SHA-256 of the file, lower case hexadecimal, no line break) and returns the hash. Never overwrites. #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path)
    $hash = New-Object IO.FileStream($Path, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
    try { $digest = Get-PraStreamSha256 $hash } finally { $hash.Dispose() }
    $sidecar = New-Object IO.FileStream(($Path + '.sha256'), [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
    try { $text = (New-Object Text.UTF8Encoding($false)).GetBytes($digest); $sidecar.Write($text, 0, $text.Length); $sidecar.Flush($true) } finally { $sidecar.Dispose() }
    return $digest
}

function Limit-PraPhaseObject {
    <#
    .SYNOPSIS
        Keeps the PhaseData file of a record within MaxFileBytes: the objects that would not fit are left out, from the end, and counted in Omitted.Objects. Their steps stay in the
        events file as lines that name the object. A record that fits is not changed.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Record, [Parameter(Mandatory)][string]$EventsName)
    $objects = @($Record.Objects)
    if (-not $objects.Count) { return }
    $utf8 = New-Object Text.UTF8Encoding($false)
    $flat = @(foreach ($object in $objects) { $copy = [ordered]@{}; foreach ($key in $object.Keys) { if (-not (Test-PraOrdinalEqual $key 'Steps')) { $copy[$key] = $object[$key] } }; $copy })
    $shell = [ordered]@{}
    foreach ($key in $Record.Keys) { if (-not (Test-PraOrdinalIn $key @('Objects', 'Issues', 'Warnings', 'Unattached'))) { $shell[$key] = $Record[$key] } }
    $shell['Events'] = [ordered]@{ File = $EventsName; Count = [int]::MaxValue; Bytes = [long]::MaxValue; Sha256 = ('0' * 64) }
    $shell['Issues'] = @(); $shell['Warnings'] = @()
    $budget = [long]$script:PraPhaseLimits.MaxFileBytes - 4096 - $utf8.GetByteCount(($shell | ConvertTo-Json -Depth 8 -Compress))
    $size = $utf8.GetByteCount((ConvertTo-Json -InputObject $flat -Depth 8 -Compress))
    $keep = $flat.Count
    while ($size -gt $budget -and $keep -gt 0) {
        $keep = [Math]::Max(0, [Math]::Min($keep - 1, [int][Math]::Floor($keep * ([Math]::Max(0, $budget) / [double]$size) * 0.98)))
        $size = if ($keep) { $utf8.GetByteCount((ConvertTo-Json -InputObject @($flat[0..($keep - 1)]) -Depth 8 -Compress)) } else { 2 }
    }
    if ($keep -ge $flat.Count) { return }
    $lines = New-Object 'Collections.Generic.List[object]'
    foreach ($line in @($Record.Unattached)) { $lines.Add($line) }
    for ($place = $keep; $place -lt $objects.Count; $place++) {
        foreach ($step in @($objects[$place].Steps)) { $lines.Add([ordered]@{ Name = [string]$objects[$place].Name; Time = [string]$step.Time; Step = [string]$step.Step; Status = [string]$step.Status; Text = [string]$step.Text }) }
    }
    $Record['Unattached'] = $lines.ToArray()
    $Record['Objects'] = if ($keep) { [object[]]@($objects[0..($keep - 1)]) } else { [object[]]@() }
    $Record.Omitted.Objects = [long]$Record.Omitted.Objects + ($objects.Count - $keep)
    $Record.Omitted.ObjectsBySize = [long]$Record.Omitted.ObjectsBySize + ($objects.Count - $keep)
}

function Save-PraPhaseData {
    <#
    .SYNOPSIS
        Writes what this run did in a batch folder this run created (private folder: the files inherit its ACL): PhaseEvents-<time>-<phase>-<run>.jsonl (the steps of every object,
        the errors and the warnings) and its .sha256, then PhaseData-<time>-<phase>-<run>.json (the header and one entry per object, with the SHA-256 of the events file) and its
        .sha256. Never overwrites. What a limit leaves out is counted in the header (Omitted).
    .OUTPUTS
        The path of the PhaseData file.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][hashtable]$Context, [Parameter(Mandatory)][string]$Folder, [string]$HandOff = '')
    if (-not [IO.Directory]::Exists($Folder)) { throw "Phase data: folder not found: $Folder" }
    $record = New-PraPhaseRecord -Context $Context -HandOff $HandOff
    $runId = [string](Get-PraValue $Context 'RunId' '')
    $short = ($runId -replace '\A[^-]*-', '' -replace '[^0-9A-Za-z]', '')
    if ($short.Length -gt 8) { $short = $short.Substring(0, 8) }
    if (-not $short) { $short = [guid]::NewGuid().ToString('N').Substring(0, 8) }
    $side = ([string](Get-PraValue $Context 'Phase' '') -replace '[^0-9A-Za-z]', '')
    if (-not $side) { $side = 'Run' }
    # The time in the name orders the files: a second save in the same second takes the next second, so that its files never meet the first ones.
    $moment = [datetime]::UtcNow
    $path = ''; $eventsPath = ''
    for ($attempt = 0; $attempt -lt 1000; $attempt++) {
        $stem = '{0}-{1}-{2}' -f $moment.AddSeconds($attempt).ToString('yyyyMMddHHmmss', [Globalization.CultureInfo]::InvariantCulture), $side, $short
        $path = Join-Path $Folder ('PhaseData-' + $stem + '.json')
        $eventsPath = Join-Path $Folder ($script:PraEventsPrefix + $stem + '.jsonl')
        if (-not ([IO.File]::Exists($path) -or [IO.File]::Exists($path + '.sha256') -or [IO.File]::Exists($eventsPath) -or [IO.File]::Exists($eventsPath + '.sha256'))) { break }
    }
    if ([IO.File]::Exists($path) -or [IO.File]::Exists($eventsPath)) { throw "Phase data: no free file name in $Folder." }
    try {
        Limit-PraPhaseObject -Record $record -EventsName ([IO.Path]::GetFileName($eventsPath))
        $events = Write-PraPhaseEventFile -Record $record -Path $eventsPath
        $digest = Write-PraFileChecksum -Path $eventsPath
        foreach ($object in $record.Objects) { $object.Remove('Steps') }
        $record.Remove('Unattached')
        $record.Issues = @(); $record.Warnings = @()
        $record.Omitted.EventLines = [long]$events.Dropped
        $record.Truncated = [bool]($record.Omitted.Objects -or $record.Omitted.JourneyLines -or $record.Omitted.Texts -or $record.Omitted.EventLines)
        $record['Events'] = [ordered]@{ File = [IO.Path]::GetFileName($eventsPath); Count = [int]$events.Count; Bytes = [long]$events.Bytes; Sha256 = $digest }
        $bytes = (New-Object Text.UTF8Encoding($false)).GetBytes(($record | ConvertTo-Json -Depth 8 -Compress))
        if ($bytes.LongLength -gt $script:PraPhaseLimits.MaxFileBytes) { throw 'Phase data: the file would be larger than the limit.' }
        $stream = New-Object IO.FileStream($path, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
        try { $stream.Write($bytes, 0, $bytes.Length); $stream.Flush($true) } finally { $stream.Dispose() }
        $null = Write-PraFileChecksum -Path $path
    }
    catch {
        $failure = $_
        foreach ($leftover in @($eventsPath, ($eventsPath + '.sha256'), $path, ($path + '.sha256'))) { try { [IO.File]::Delete($leftover) } catch { $null = $_ } }
        throw $failure
    }
    return $path
}

function Copy-PraPhaseFile {
    <# Copies one PhaseData file with its events file and their .sha256 files into a folder. A file already there is left alone. #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path, [Parameter(Mandatory)][string]$Destination)
    $leaf = [IO.Path]::GetFileName($Path)
    $events = Join-Path ([IO.Path]::GetDirectoryName($Path)) ($script:PraEventsPrefix + $leaf.Substring(10, $leaf.Length - 15) + '.jsonl')
    foreach ($candidate in @($Path, ($Path + '.sha256'), $events, ($events + '.sha256'))) {
        if (-not [IO.File]::Exists($candidate)) { continue }
        $target = Join-Path $Destination ([IO.Path]::GetFileName($candidate))
        if ([IO.File]::Exists($target)) { continue }
        [IO.File]::Copy($candidate, $target, $false)
    }
}

function Copy-PraPhaseData {
    <# Copies the PhaseData files and the events file of each (and their .sha256) of the source folders into a folder this run created, so that they travel with it. A file already there is left alone. Returns the number of phases found. #>
    [CmdletBinding()]
    param([string[]]$SourceFolder = @(), [Parameter(Mandatory)][string]$Destination)
    $copied = 0
    foreach ($source in @($SourceFolder | Where-Object { $_ } | Get-PraOrdinalUnique -IgnoreCase)) {
        if (-not [IO.Directory]::Exists($source)) { continue }
        foreach ($file in [IO.Directory]::GetFiles($source, $script:PraPhaseFilter)) {
            Copy-PraPhaseFile -Path $file -Destination $Destination
            $copied++
        }
    }
    return $copied
}

function Read-PraEventLine {
    <# The objects of a JSON-lines file, read in batches of lines (one JSON array per batch; line by line when a batch cannot be read). Skipped counts the lines that are longer than MaxLineChars or are not a JSON object. #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path)
    $maxChars = $script:PraPhaseLimits.MaxLineChars
    $items = New-Object 'Collections.Generic.List[object]'
    $batch = New-Object 'Collections.Generic.List[string]'
    $state = @{ Skipped = 0 }
    $flush = {
        $parsed = $null
        try { $parsed = @(('[' + [string]::Join(',', $batch) + ']') | ConvertFrom-PraJson); if ($parsed.Count -ne $batch.Count) { $parsed = $null } } catch { $parsed = $null }
        if ($null -eq $parsed) {
            $parsed = New-Object 'Collections.Generic.List[object]'
            foreach ($single in $batch) {
                try { $one = @($single | ConvertFrom-PraJson); if ($one.Count -eq 1) { $parsed.Add($one[0]) } else { $state.Skipped++ } } catch { $state.Skipped++ }
            }
        }
        foreach ($item in $parsed) { if ($item -is [pscustomobject]) { $items.Add($item) } else { $state.Skipped++ } }
        $batch.Clear()
    }
    foreach ($line in [IO.File]::ReadLines($Path, [Text.Encoding]::UTF8)) {
        if (-not $line) { continue }
        if ($line.Length -gt $maxChars -or $line[0] -ne [char]'{' -or $line[$line.Length - 1] -ne [char]'}') { $state.Skipped++; continue }
        $batch.Add($line)
        if ($batch.Count -ge 2000) { & $flush }
    }
    if ($batch.Count) { & $flush }
    return [pscustomobject]@{ Items = $items; Skipped = [int]$state.Skipped }
}

function Add-PraPhaseEvent {
    <#
    .SYNOPSIS
        Reads the events file of a validated PhaseData record (size, .sha256, the SHA-256 in the header, then the lines) and puts the steps on the objects of the record and the errors
        and the warnings on the record. The lines that name no object are kept in Unattached.
    .OUTPUTS
        '' when the file was used (lines that could not be read are counted in EventLinesSkipped), otherwise why it cannot be used: the record then has no steps, errors or warnings.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Record, [Parameter(Mandatory)][string]$DataFile, [Parameter(Mandatory)][hashtable]$Budget)
    $limits = $script:PraPhaseLimits
    $leaf = [IO.Path]::GetFileName($DataFile)
    $path = Join-Path ([IO.Path]::GetDirectoryName($DataFile)) ($script:PraEventsPrefix + $leaf.Substring(10, $leaf.Length - 15) + '.jsonl')
    try {
        if (-not [IO.File]::Exists($path)) { throw 'the events file is missing' }
        $length = ([IO.FileInfo]$path).Length
        if ($length -gt $limits.MaxEventsBytes) { throw ('the events file is larger than {0} MB' -f [long]($limits.MaxEventsBytes / 1MB)) }
        if (($Budget.Bytes + $length) -gt $limits.MaxEventsBytes) { throw ('the events files read before it already use {0} MB of the {1} MB allowed for one report' -f [long]($Budget.Bytes / 1MB), [long]($limits.MaxEventsBytes / 1MB)) }
        $Budget.Bytes += $length
        $sidecar = $path + '.sha256'
        if (-not [IO.File]::Exists($sidecar)) { throw 'the .sha256 file of the events file is missing' }
        $stream = New-Object IO.FileStream($path, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
        try { $digest = Get-PraStreamSha256 $stream } finally { $stream.Dispose() }
        $token = ([IO.File]::ReadAllText($sidecar).Trim() -split '\s+')[0]
        $declared = [string](Get-PraValue (Get-PraValue $Record 'Events' $null) 'Sha256' '')
        if ($token -notmatch '\A[0-9a-fA-F]{64}\z' -or -not (Test-PraOrdinalIgnoreCaseEqual $token $digest) -or -not (Test-PraOrdinalIgnoreCaseEqual $declared $digest)) { throw 'the checksum of the events file does not match (the file was changed)' }
        $read = Read-PraEventLine -Path $path
        $byGuid = New-Object 'Collections.Generic.Dictionary[string,object]' -ArgumentList ([StringComparer]::OrdinalIgnoreCase)
        $byPlace = New-Object 'Collections.Generic.Dictionary[int,object]'
        $known = New-Object 'Collections.Generic.HashSet[string]' -ArgumentList ([StringComparer]::OrdinalIgnoreCase)
        $objects = @(Get-PraList $Record 'Objects')
        foreach ($object in $objects) { [void]$known.Add([string](Get-PraValue $object 'ObjectGuid' '')) }
        $unattached = New-Object 'Collections.Generic.List[object]'
        $issues = New-Object 'Collections.Generic.List[object]'
        $warnings = New-Object 'Collections.Generic.List[object]'
        $skipped = $read.Skipped
        foreach ($item in $read.Items) {
            $kind = [string](Get-PraValue $item 'K' '')
            $code = if ($kind.Length -eq 1) { [int][char]$kind } else { 0 }
            if ($code -eq 69) {
                $guid = if ($null -ne $item.PSObject.Properties['G']) { [string]$item.G } else { '' }
                $placeValue = if ($null -ne $item.PSObject.Properties['I']) { $item.I } else { $null }
                if ($placeValue -is [int] -or $placeValue -is [long]) {
                    # The place in the list of objects tells the object; the GUID is only a check that the line is for it.
                    $place = [long]$placeValue
                    if ($place -ge 0 -and $place -lt $objects.Count -and (Test-PraOrdinalIgnoreCaseEqual $guid ([string](Get-PraValue $objects[$place] 'ObjectGuid' '')))) {
                        $list = $byPlace[[int]$place]
                        if ($null -eq $list) { $list = New-Object 'Collections.Generic.List[object]'; $byPlace[[int]$place] = $list }
                        $list.Add($item)
                    }
                    else { $unattached.Add($item) }
                }
                elseif ($guid -and $known.Contains($guid)) {
                    $list = $byGuid[$guid]
                    if ($null -eq $list) { $list = New-Object 'Collections.Generic.List[object]'; $byGuid[$guid] = $list }
                    $list.Add($item)
                }
                else { $unattached.Add($item) }
            }
            elseif ($code -eq 73) { $issues.Add($item) }
            elseif ($code -eq 87) { $warnings.Add($item) }
            else { $skipped++ }
        }
        for ($place = 0; $place -lt $objects.Count; $place++) {
            $list = $byPlace[$place]
            if ($null -eq $list) { $list = $byGuid[[string](Get-PraValue $objects[$place] 'ObjectGuid' '')] }
            if ($null -ne $list) { Add-Member -InputObject $objects[$place] -NotePropertyName Steps -NotePropertyValue $list.ToArray() -Force }
        }
        Add-Member -InputObject $Record -NotePropertyName Issues -NotePropertyValue $issues.ToArray() -Force
        Add-Member -InputObject $Record -NotePropertyName Warnings -NotePropertyValue $warnings.ToArray() -Force
        Add-Member -InputObject $Record -NotePropertyName Unattached -NotePropertyValue $unattached.ToArray() -Force
        Add-Member -InputObject $Record -NotePropertyName EventLinesSkipped -NotePropertyValue ([int]$skipped) -Force
    }
    catch { return [string]$_.Exception.Message }
    return ''
}

function Get-PraRerunCommand {
    <# The command that runs this run again: the command line of the entry script when it gave the context a way to write one, otherwise the action, phase and batch of the context. #>
    param([hashtable]$Context)
    $action = [string](Get-PraValue $Context 'Action' ''); $phase = [string](Get-PraValue $Context 'Phase' ''); $batch = [string](Get-PraValue $Context 'BatchId' '')
    $hook = Get-PraValue $Context 'CommandLineFor' $null
    if ($hook -is [scriptblock]) { return [string](& $hook $action $phase $batch) }
    $parts = @('.\Invoke-PraRemoteMailbox.ps1', "-Action $action")
    if ($phase) { $parts += "-Phase $phase" }
    $parts += '-Mode Apply'
    if ($batch) { $parts += "-Batch $batch" }
    return ($parts -join ' ')
}

function Read-PraPhaseData {
    <#
    .SYNOPSIS
        Reads the PhaseData files of some folders (and the events file of each) as untrusted input: size, .sha256, schema, Kind and Environment are checked; a file that fails is
        reported in Problems and ignored (the global report then says the side is not available), never trusted. An events file that fails is not used: the phase is read without
        its steps, errors and warnings and the record says why (EventsProblem). At most MaxFiles files of a folder are read, the newest first.
    .OUTPUTS
        Phases (validated records, as read) and Problems (texts).
    #>
    [CmdletBinding()]
    param([string[]]$Folder = @(), [string]$Environment = '', [hashtable]$Context, [string]$SkipRunId = '')
    $limits = $script:PraPhaseLimits
    $phases = New-Object 'Collections.Generic.List[object]'
    $problems = New-Object 'Collections.Generic.List[string]'
    $seen = New-Object 'Collections.Generic.HashSet[string]' -ArgumentList ([StringComparer]::Ordinal)
    $budget = [long]0
    $eventsBudget = @{ Bytes = [long]0 }
    foreach ($directory in @($Folder | Where-Object { $_ } | Get-PraOrdinalUnique -IgnoreCase)) {
        if (-not [IO.Directory]::Exists($directory)) { continue }
        $files = [string[]][IO.Directory]::GetFiles($directory, $script:PraPhaseFilter)
        [Array]::Sort([Array]$files, [Collections.IComparer][StringComparer]::Ordinal)
        if ($files.Length -gt $limits.MaxFiles) {
            $problems.Add(('Phase data: {0} older file(s) of the folder {1} were not read (the newest {2} are read for one report). To report on them, move the newer PhaseData files (with their PhaseEvents and .sha256 files) out of the batch folder, then run the same command again{3}' -f ($files.Length - $limits.MaxFiles), (Get-PraSafeText ([IO.Path]::GetFileName($directory.TrimEnd('\')))), $limits.MaxFiles, $(if ($null -ne $Context) { ': ' + (Get-PraRerunCommand $Context) } else { '' })))
            $files = [string[]]@($files[($files.Length - $limits.MaxFiles)..($files.Length - 1)])
        }
        foreach ($file in $files) {
            $leaf = Get-PraSafeText ([IO.Path]::GetFileName($file))
            try {
                $length = ([IO.FileInfo]$file).Length
                # One file is read up to the limit of the whole report, whatever size the writer keeps.
                if ($length -lt 2 -or $length -gt $limits.MaxBytes) { throw ('the size is not acceptable (at most {0} MB for one file)' -f [long]($limits.MaxBytes / 1MB)) }
                if (($budget + $length) -gt $limits.MaxBytes) {
                    throw ('not read: the files read before it already use {0} MB of the {1} MB allowed for one report. Move the PhaseData files of other batches out of the batch folder (a batch folder holds only the files of its own batch), then run the same command again: {2}' -f [long]($budget / 1MB), [long]($limits.MaxBytes / 1MB), (Get-PraRerunCommand $Context))
                }
                $budget += $length
                $sidecar = $file + '.sha256'
                if (-not [IO.File]::Exists($sidecar)) { throw 'the .sha256 file is missing' }
                $stream = New-Object IO.FileStream($file, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
                try { $digest = Get-PraStreamSha256 $stream } finally { $stream.Dispose() }
                $token = ([IO.File]::ReadAllText($sidecar).Trim() -split '\s+')[0]
                if ($token -notmatch '\A[0-9a-fA-F]{64}\z' -or -not (Test-PraOrdinalIgnoreCaseEqual $token $digest)) { throw 'the checksum does not match (the file was changed)' }
                $record = [IO.File]::ReadAllText($file, [Text.Encoding]::UTF8) | ConvertFrom-PraJson
                $schema = Get-PraValue $record 'SchemaVersion' $null
                if ($schema -isnot [int] -and $schema -isnot [long]) { throw 'unsupported schema' }
                $version = [int]$schema
                if ($version -ne 1 -and $version -ne 2) { throw 'unsupported schema' }
                if (-not (Test-PraOrdinalEqual (Get-PraValue $record 'Kind' '') 'PhaseData')) { throw 'not phase data' }
                if ($Environment -and -not (Test-PraOrdinalIgnoreCaseEqual (Get-PraValue $record 'Environment' '') $Environment)) { throw 'another Environment' }
                $phase = Get-PraValue $record 'Phase' $null
                $runId = [string](Get-PraValue $phase 'RunId' '')
                if ($null -eq $phase -or -not $runId -or -not [string](Get-PraValue $phase 'Action' '') -or -not [string](Get-PraValue $phase 'StartedUtc' '')) { throw 'incomplete' }
                if ($SkipRunId -and (Test-PraOrdinalEqual $runId $SkipRunId)) { continue }
                if ($seen.Add($runId + '|' + [string](Get-PraValue $phase 'Phase' ''))) {
                    $reason = ''
                    if ($version -eq 2) { $reason = Add-PraPhaseEvent -Record $record -DataFile $file -Budget $eventsBudget }
                    elseif ((Get-PraValue $record 'Truncated' $false) -eq $true) { $reason = 'the steps of this phase were left out when it was saved (the file was too large)' }
                    Add-Member -InputObject $record -NotePropertyName EventsProblem -NotePropertyValue $reason -Force
                    $phases.Add($record)
                }
            }
            catch {
                $why = [string]$_.Exception.Message
                if ($why -notmatch 'run the same command again') {
                    $again = if ($null -ne $Context) { ' then run the same command again: ' + (Get-PraRerunCommand $Context) } else { ' then run the same command again' }
                    $step = if ($why -match 'checksum|\.sha256') { ' Copy the file and its .sha256 file again from the server that wrote them (they are in the transfer package), or move both out of the batch folder,' }
                        elseif ($why -match 'unsupported schema') { ' The file was written by another version of this tool: move it out of the batch folder,' }
                        else { ' Move the file out of the batch folder,' }
                    $why = $why + '.' + $step + $again
                }
                $problems.Add(('Phase data {0}: {1}' -f $leaf, $why))
            }
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
    if ($Iso.Length -ge 20 -and $Iso[$Iso.Length - 1] -eq [char]'Z' -and $Iso[4] -eq [char]'-' -and $Iso[10] -eq [char]'T' -and $Iso[13] -eq [char]':') { return $Iso.Substring(0, 10) + ' ' + $Iso.Substring(11, 8) + ' UTC' }
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

function Get-PraGlobalStep {
    <# The steps of a phase record entry as uniform objects: Time as UTC text, Step, Status, Text. #>
    [CmdletBinding()]
    param([AllowNull()]$Item)
    $raw = Get-PraValue $Item 'Steps' $null
    if ($null -eq $raw) { return }
    foreach ($step in $raw) {
        if ($null -eq $step) { continue }
        try { [pscustomobject]@{ Time = (Format-PraUtcText ([string]$step.Time)); Step = [string]$step.Step; Status = [string]$step.Status; Text = [string]$step.Text } }
        catch { [pscustomobject]@{ Time = (Format-PraUtcText ([string](Get-PraValue $step 'Time' ''))); Step = [string](Get-PraValue $step 'Step' ''); Status = [string](Get-PraValue $step 'Status' ''); Text = [string](Get-PraValue $step 'Text' '') } }
    }
}

function Get-PraGlobalModel {
    <#
    .SYNOPSIS
        The data of the global report: the phases of the batch (earlier phases read from the PhaseData files of $Context.PhaseFolders, then this run),
        and one entry per object with its stage in each phase, its journey across the servers and its verdict.
    .DESCRIPTION
        Verdict: failed when any phase failed it (the cloud error of a stage that did both sides is replaced by a later stage that covers the cloud side); otherwise pending when its last stage is Pending (it is expected on a later side, or it was
        filtered out there); skipped; done with warnings when a warning was raised; otherwise done. A side that was not carried is listed as not available.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][hashtable]$Context)
    $environment = [string](Get-PraValue (Get-PraValue $Context 'Config' @{}) 'Environment' '')
    $history = Read-PraPhaseData -Folder @(Get-PraList $Context 'PhaseFolders') -Environment $environment -Context $Context -SkipRunId ([string](Get-PraValue $Context 'RunId' ''))
    $current = New-PraPhaseRecord -Context $Context
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
    # A side that ran twice (a synchronisation redone with -Phase AD -Batch, a cloud phase repeated) is ONE stage of each object: the last run gives the status,
    # the steps of the earlier run stay in front of it. Both runs stay in the timeline.
    $stagePhases = New-Object 'Collections.Generic.List[object]'
    $lastByLabel = New-Object 'Collections.Generic.Dictionary[string,object]' -ArgumentList ([StringComparer]::Ordinal)
    $positionByLabel = New-Object 'Collections.Generic.Dictionary[string,int]' -ArgumentList ([StringComparer]::Ordinal)
    foreach ($phase in $mainPhases) {
        $position = 0
        if ($positionByLabel.TryGetValue([string]$phase.Label, [ref]$position)) { $stagePhases[$position] = $phase } else { $positionByLabel[[string]$phase.Label] = $stagePhases.Count; $stagePhases.Add($phase) }
        $lastByLabel[[string]$phase.Label] = $phase
    }
    $byKey = New-Object 'Collections.Generic.Dictionary[string,object]' -ArgumentList ([StringComparer]::Ordinal)
    $objects = New-Object 'Collections.Generic.List[object]'
    foreach ($phase in $mainPhases) {
        $stagePhase = $lastByLabel[[string]$phase.Label]
        foreach ($item in @(Get-PraList $phase.Record 'Objects')) {
            $guid = [string](Get-PraValue $item 'ObjectGuid' ''); $name = [string](Get-PraValue $item 'Name' '')
            $key = if ($guid) { $guid.ToLowerInvariant() } else { $name.ToLowerInvariant() }
            if (-not $key) { continue }
            $entry = $byKey[$key]
            if ($null -eq $entry) {
                $entry = [pscustomobject]@{ Key = $key; ObjectGuid = $guid; Name = $name; Sam = [string](Get-PraValue $item 'SamAccountName' ''); Upn = [string](Get-PraValue $item 'UserPrincipalName' '')
                    IsShared = [bool](Get-PraValue $item 'IsShared' $false); Stages = (New-Object 'Collections.Generic.List[object]'); Verdict = ''; Note = ''; Backup = ''; Journey = @() }
                $byKey[$key] = $entry; $objects.Add($entry)
            }
            $backup = [string](Get-PraValue $item 'BackupPath' '')
            if ($backup -and -not $entry.Backup) { $entry.Backup = $backup }
            $stage = $null
            foreach ($candidate in $entry.Stages) { if ([object]::ReferenceEquals($candidate.Phase, $stagePhase)) { $stage = $candidate; break } }
            if ($null -ne $stage) {
                $earlierResult = [pscustomobject]@{ Time = ''; Step = 'Earlier run'; Status = 'Info'; Text = (Limit-PraText (('{0} - {1}' -f $stage.Status, $stage.Detail).Trim(' ', '-')) 300) }
                $warnings = (@($stage.Warnings, [string](Get-PraValue $item 'Warnings' '')) | Where-Object { $_ } | Get-PraOrdinalUnique) -join ' | '
                $stage.Status = [string](Get-PraValue $item 'FinalStatus' ''); $stage.Detail = [string](Get-PraValue $item 'Detail' ''); $stage.Warnings = $warnings; $stage.ADVerified = ((Get-PraValue $item 'ADVerified' $null) -eq $true)
                $stage.Steps = @(@($stage.Steps) + @($earlierResult) + @(Get-PraGlobalStep $item))
                continue
            }
            [void]$entry.Stages.Add([pscustomobject]@{ Phase = $stagePhase; Present = $true; HandedOverTo = ''; StatusDisplay = ''; Status = [string](Get-PraValue $item 'FinalStatus' ''); Detail = [string](Get-PraValue $item 'Detail' ''); Warnings = [string](Get-PraValue $item 'Warnings' '')
                    ADVerified = ((Get-PraValue $item 'ADVerified' $null) -eq $true); Superseded = $false; Steps = @(Get-PraGlobalStep $item) })
        }
    }
    $verdicts = @{ Done = 0; Warn = 0; Failed = 0; Pending = 0; Skipped = 0 }
    $position = 0
    foreach ($entry in $objects) {
        # One stage per main phase, in order; a phase that does not list the object leaves an explicit gap.
        $staged = New-Object 'Collections.Generic.List[object]'
        foreach ($phase in $stagePhases) {
            $stage = $null
            foreach ($candidate in $entry.Stages) { if ([object]::ReferenceEquals($candidate.Phase, $phase)) { $stage = $candidate; break } }
            if ($null -ne $stage) { $staged.Add($stage) } else { $staged.Add([pscustomobject]@{ Phase = $phase; Present = $false; HandedOverTo = ''; StatusDisplay = ''; Status = ''; Detail = ''; Warnings = ''; ADVerified = $false; Superseded = $false; Steps = @() }) }
        }
        $entry.Stages = $staged
        # An error of the cloud part of a stage that did both sides (its AD part was verified) is not final when a later stage of the same operation covers the cloud side for this object:
        # that stage replaces the cloud result, and the earlier error stays in its journey as an "Earlier run" line.
        for ($i = 0; $i -lt $staged.Count; $i++) {
            $stage = $staged[$i]
            if (-not $stage.Present -or -not (Test-PraOrdinalEqual $stage.Status 'Error') -or -not $stage.ADVerified -or -not (Test-PraOrdinalEqual ([string](Get-PraValue $stage.Phase.Header 'Phase' '')) 'Both')) { continue }
            for ($j = $i + 1; $j -lt $staged.Count; $j++) {
                $later = $staged[$j]
                if (-not $later.Present -or -not (Test-PraOrdinalEqual ([string](Get-PraValue $later.Phase.Header 'Action' '')) ([string](Get-PraValue $stage.Phase.Header 'Action' ''))) -or
                    -not (Test-PraOrdinalIn ([string](Get-PraValue $later.Phase.Header 'Phase' '')) @('Cloud', 'Both'))) { continue }
                $stage.Superseded = $true
                $later.Steps = @([pscustomobject]@{ Time = ''; Step = 'Earlier run'; Status = 'Info'; Text = (Limit-PraText (('{0} - {1}' -f $stage.Status, $stage.Detail).Trim(' ', '-')) 300) }) + @($later.Steps)
                break
            }
        }
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
        $present = New-Object 'Collections.Generic.List[object]'
        $failedAnywhere = $false; $warned = $false
        foreach ($stage in $staged) {
            if (-not $stage.Present) { continue }
            $present.Add($stage)
            if (-not $stage.Superseded -and [string]::Equals($stage.Status, 'Error', [StringComparison]::Ordinal)) { $failedAnywhere = $true }
            if (-not $warned) {
                if ($stage.Warnings.Trim()) { $warned = $true }
                else { foreach ($step in $stage.Steps) { if ([string]::Equals($step.Status, 'Warn', [StringComparison]::Ordinal)) { $warned = $true; break } } }
            }
        }
        $last = $present[$present.Count - 1]
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
        $entry.Journey = @(Get-PraGlobalJourney -Entry $entry -Index $position)
        $position++
    }
    # What a limit left out (counted by the phase that wrote it), the journey lines that name no object, and every error and warning of every phase.
    $omittedList = New-Object 'Collections.Generic.List[object]'
    $unattachedList = New-Object 'Collections.Generic.List[object]'
    $issueList = New-Object 'Collections.Generic.List[object]'
    $number = { param($Value) ([long]$Value).ToString('N0', [Globalization.CultureInfo]::InvariantCulture) }
    foreach ($entry in $ordered) {
        if (-not $entry.Available) { continue }
        $header = $entry.Header; $record = $entry.Record
        $omit = Get-PraValue $record 'Omitted' $null
        $limit = Get-PraValue $record 'Limits' $null
        $limitOf = { param($Name) $value = Get-PraValue $limit $Name $null; if ($null -eq $value) { $script:PraPhaseLimits[$Name] } else { $value } }
        $eventsLimit = [long](& $limitOf 'MaxEventsBytes')
        $eventsLimitText = if ($eventsLimit -ge 1MB) { '{0} MB' -f (& $number ($eventsLimit / 1MB)) } else { '{0} bytes' -f (& $number $eventsLimit) }
        $sentences = New-Object 'Collections.Generic.List[string]'
        $bySize = [long](Get-PraValue $omit 'ObjectsBySize' 0)
        $byCount = [long](Get-PraValue $omit 'Objects' 0) - $bySize
        if ($byCount -gt 0) { $sentences.Add(('{0} object(s) are not in this phase data (more than {1} objects in one phase)' -f (& $number $byCount), (& $number (& $limitOf 'MaxObjects')))) }
        if ($bySize -gt 0) { $sentences.Add(('{0} object(s) are not in this phase data (the file would pass {1} MB); their journey lines are in the events file' -f (& $number $bySize), (& $number ([long](& $limitOf 'MaxFileBytes') / 1MB)))) }
        if ([long](Get-PraValue $omit 'JourneyLines' 0) -gt 0) { $sentences.Add(('{0} journey line(s) were not kept (more than {1} lines in one phase)' -f (& $number (Get-PraValue $omit 'JourneyLines' 0)), (& $number (& $limitOf 'MaxJourney')))) }
        if ([long](Get-PraValue $omit 'Texts' 0) -gt 0) { $sentences.Add(('{0} text(s) were cut to their first characters (they end with "...")' -f (& $number (Get-PraValue $omit 'Texts' 0)))) }
        if ([long](Get-PraValue $omit 'EventLines' 0) -gt 0) { $sentences.Add(('{0} line(s) were not written to the events file of this phase (it would pass {1})' -f (& $number (Get-PraValue $omit 'EventLines' 0)), $eventsLimitText)) }
        if ([int](Get-PraValue $record 'EventLinesSkipped' 0) -gt 0) { $sentences.Add(('{0} line(s) of the events file could not be read and were skipped' -f (& $number (Get-PraValue $record 'EventLinesSkipped' 0)))) }
        $eventsProblem = [string](Get-PraValue $record 'EventsProblem' '')
        if ($eventsProblem) { $sentences.Add(('the steps, errors and warnings of this phase are not available: {0}' -f $eventsProblem)) }
        if ($sentences.Count) {
            $omittedList.Add([pscustomobject]@{ Label = [string]$entry.Label; Computer = [string](Get-PraValue $header 'Computer' ''); LogFile = [string](Get-PraValue $header 'LogFile' ''); Items = $sentences.ToArray() })
        }
        foreach ($line in @(Get-PraList $record 'Unattached')) { $unattachedList.Add([pscustomobject]@{ Phase = [string]$entry.Label; Item = $line }) }
        foreach ($issue in @(Get-PraList $record 'Issues')) {
            $issueList.Add([pscustomobject]@{ Phase = [string]$entry.Label; Kind = 'error'; Time = [string](Get-PraValue $issue 'Timestamp' ''); Step = [string](Get-PraValue $issue 'Phase' ''); Object = [string](Get-PraValue $issue 'Identity' ''); Message = [string](Get-PraValue $issue 'Message' '') })
        }
        foreach ($warning in @(Get-PraList $record 'Warnings')) {
            $issueList.Add([pscustomobject]@{ Phase = [string]$entry.Label; Kind = 'warning'; Time = [string](Get-PraValue $warning 'Timestamp' ''); Step = [string](Get-PraValue $warning 'Phase' ''); Object = ''; Message = [string](Get-PraValue $warning 'Message' '') })
        }
    }
    return [pscustomobject]@{
        Phases = $ordered.ToArray(); Objects = $objects.ToArray(); Counts = $verdicts; Problems = $history.Problems; Environment = $environment
        Missing = @($missing | ForEach-Object { $_.Label }); Version = [string](Get-PraValue $Context 'Version' ''); BatchId = [string](Get-PraValue $Context 'BatchId' '')
        Action = $action; Current = $current; Omitted = $omittedList.ToArray(); Unattached = $unattachedList.ToArray(); Issues = $issueList.ToArray()
    }
}

function Get-PraGlobalJourney {
    <# The journey lines of one object of the global model, in the order of its stages: the steps of each phase, then the result of the phase; a phase that does not list the object gets one line saying so. #>
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Entry, [AllowNull()][object]$Index = $null)
    foreach ($stage in $Entry.Stages) {
        $label = [string]$stage.Phase.Label
        if (-not $stage.Present) { [pscustomobject]@{ Object = $Index; Phase = $label; Step = ''; Status = ''; Time = ''; Text = 'This object is not in the results of this phase.' }; continue }
        foreach ($step in @($stage.Steps)) {
            [pscustomobject]@{ Object = $Index; Phase = $label; Step = $step.Step; Status = $step.Status; Time = $step.Time; Text = $step.Text }
        }
        $message = (('{0} {1}' -f $stage.Detail, $stage.Warnings)).Trim()
        $resultText = if ($stage.HandedOverTo) { '{0} (handed over to {1})' -f $stage.Status, $stage.HandedOverTo } else { [string]$stage.Status }
        [pscustomobject]@{ Object = $Index; Phase = $label; Step = 'Result of this phase'; Status = [string]$stage.StatusDisplay; Time = ''; Text = (('{0} - {1}' -f $resultText, $message).Trim(' ', '-')) }
    }
}

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
        Writes the global report: one self-contained page (templates\GlobalReport.template.html), no external resource. The summary (tiles, side not available, what a limit left
        out, batch timeline, run settings) is HTML-encoded markup that reads without script. The objects (one row each), their journey lines, the errors and warnings and the journey
        lines that name no object are written by Write-PraReportChunks and read by the script of the page: no object, no line and no error or warning is left out of the page,
        whatever their number.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Model, [Parameter(Mandatory)][IO.TextWriter]$Writer, [string]$TemplateFolder = '', [string]$ObjectsCsvName = '', [string]$EventsCsvName = '', [string]$IssuesCsvName = '',
        [int]$ChunkRows = $script:ReportChunkRows, [int]$ChunkChars = $script:ReportChunkChars)
    $h = { param($Value) ConvertTo-PraHtmlText $Value }
    $dot = [char]0x00B7
    $counts = $Model.Counts
    $objects = $Model.Objects
    $total = $objects.Count
    $overall = if ($counts.Failed -gt 0) { 'Failed' } elseif ($counts.Pending -gt 0) { 'Pending' } else { 'Success' }
    $overallClass = if ($counts.Failed -gt 0) { 'fail' } elseif ($counts.Pending -gt 0) { 'warn' } else { 'ok' }

    # Journey lines: one row per line, grouped by object (the index of the object in the objects list), then the lines that name no object.
    $eventItems = New-Object 'Collections.Generic.List[object]'
    $objectItems = New-Object 'Collections.Generic.List[object]'
    for ($index = 0; $index -lt $total; $index++) {
        $entry = $objects[$index]
        $eventItems.AddRange($entry.Journey)
        $stages = (@($entry.Stages | ForEach-Object { '{0}: {1}' -f $_.Phase.Label, $(if ($_.Present) { $_.StatusDisplay } else { '-' }) }) -join ' | ')
        $objectItems.Add([pscustomobject]@{ Name = $entry.Name; ObjectGuid = $entry.ObjectGuid; Sam = $entry.Sam; Upn = $entry.Upn; Type = $(if ($entry.IsShared) { 'Shared mailbox' } else { 'User mailbox' })
                Verdict = $entry.Verdict; Stages = $stages; Note = $entry.Note; Backup = $entry.Backup; Events = $entry.Journey.Count })
    }
    foreach ($pair in $Model.Unattached) {
        $item = $pair.Item
        $who = [string](Get-PraValue $item 'Name' '')
        $eventItems.Add([pscustomobject]@{ Object = $null; Phase = $pair.Phase; Step = [string](Get-PraValue $item 'Step' ''); Status = [string](Get-PraValue $item 'Status' ''); Time = (Format-PraUtcText ([string](Get-PraValue $item 'Time' ''))); Text = ($(if ($who) { $who + ': ' } else { '' }) + [string](Get-PraValue $item 'Text' '')) })
    }
    $issueItems = [object[]]@($Model.Issues)
    $errorCount = @($issueItems | Where-Object { Test-PraOrdinalEqual $_.Kind 'error' }).Count
    $warningCount = $issueItems.Count - $errorCount
    $objectFields = @('Name', 'ObjectGuid', 'Sam', 'Upn', 'Type', 'Verdict', 'Stages', 'Note', 'Backup', 'Events')
    $eventFields = @('Object', 'Phase', 'Step', 'Status', 'Time', 'Text')
    $issueFields = @('Phase', 'Kind', 'Time', 'Step', 'Object', 'Message')

    $tiles = New-Object Text.StringBuilder
    foreach ($tile in @(@('Result', $overall, $overallClass), @('Objects', $total, ''), @('Done', $counts.Done, 'ok'), @('Done with warnings', $counts.Warn, $(if ($counts.Warn) { 'warn' } else { '' })),
            @('Failed', $counts.Failed, $(if ($counts.Failed) { 'fail' } else { '' })), @('Pending', $counts.Pending, $(if ($counts.Pending) { 'warn' } else { '' })), @('Skipped', $counts.Skipped, ''), @('Journey lines', $eventItems.Count, ''))) {
        [void]$tiles.Append('<div class="tile ').Append($tile[2]).Append('"><div class="tile-label">').Append((& $h $tile[0])).Append('</div><div class="tile-value">').Append((& $h $tile[1])).Append('</div></div>')
    }

    $sb = New-Object Text.StringBuilder
    if ($Model.Missing.Count) {
        [void]$sb.Append('<section class="card warn"><h2>Side not available</h2>')
        foreach ($label in $Model.Missing) { [void]$sb.Append('<p class="missing">').Append((& $h ('{0}: {1}' -f $label, $script:PraNotAvailable))).Append('</p>') }
        [void]$sb.Append('<p class="muted">The objects below are reported from the sides that were carried. The verdicts do not include the missing side.</p></section>')
    }
    foreach ($problem in $Model.Problems) { [void]$sb.Append('<section class="card warn"><p class="missing">').Append((& $h $problem)).Append('</p></section>') }
    if (@($Model.Omitted).Count) {
        [void]$sb.Append('<section class="card warn" id="omitted"><h2>Not everything was kept</h2><p>What follows was left out of the data that the phases carried. Everything else is in this report.</p><div class="scroll"><table class="summary-table"><thead><tr><th>Phase</th><th>Left out</th><th>The complete data</th></tr></thead><tbody>')
        foreach ($omit in $Model.Omitted) {
            $where = if ($omit.LogFile) { 'the log of that run: {0}{1}' -f $omit.LogFile, $(if ($omit.Computer) { ' (on ' + $omit.Computer + ')' } else { '' }) } else { 'the log of that run' }
            [void]$sb.Append('<tr><td>').Append((& $h $omit.Label)).Append('</td><td>').Append((($omit.Items | ForEach-Object { & $h $_ }) -join '<br>')).Append('</td><td>').Append((& $h $where)).Append('</td></tr>')
        }
        [void]$sb.Append('</tbody></table></div></section>')
    }
    if ($issueItems.Count) {
        [void]$sb.Append('<section class="card ').Append($(if ($errorCount) { 'fail' } else { 'warn' })).Append('" id="issue-counts"><h2>Errors and warnings</h2><div class="scroll"><table class="summary-table"><thead><tr><th>Phase</th><th>Errors</th><th>Warnings</th></tr></thead><tbody>')
        $perPhase = New-Object 'Collections.Generic.Dictionary[string,int[]]' -ArgumentList ([StringComparer]::Ordinal)
        foreach ($issue in $issueItems) {
            $pair = $null
            if (-not $perPhase.TryGetValue($issue.Phase, [ref]$pair)) { $pair = [int[]]@(0, 0); $perPhase[$issue.Phase] = $pair }
            if (Test-PraOrdinalEqual $issue.Kind 'error') { $pair[0]++ } else { $pair[1]++ }
        }
        foreach ($phaseLabel in $perPhase.Keys) { [void]$sb.Append('<tr><td>').Append((& $h $phaseLabel)).Append('</td><td>').Append($perPhase[$phaseLabel][0]).Append('</td><td>').Append($perPhase[$phaseLabel][1]).Append('</td></tr>') }
        [void]$sb.Append('</tbody></table></div><p class="muted">Every error and warning is listed in the table at the end of this page')
        if ($IssuesCsvName) { [void]$sb.Append(' and in ').Append((& $h $IssuesCsvName)) }
        [void]$sb.Append('.</p></section>')
    }
    $noticesHtml = $sb.ToString(); [void]$sb.Clear()

    # Timeline.
    [void]$sb.Append('<section class="card"><h2>Batch timeline</h2><div class="scroll"><table class="summary-table"><thead><tr><th>Phase</th><th>Server</th><th>Operator</th><th>Started</th><th>Ended</th><th>Duration</th><th>Status</th><th>Mode</th><th>Tool</th></tr></thead><tbody>')
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
    [void]$sb.Append('</tbody></table></div></section>')
    $timelineHtml = $sb.ToString(); [void]$sb.Clear()

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
        $pairs = if ($settings -is [Collections.IDictionary]) { @($settings.Keys | ForEach-Object { , @([string]$_, $settings[$_]) }) } else { @($settings.PSObject.Properties | ForEach-Object { , @($_.Name, $_.Value) }) }
        [void]$sb.Append('<details><summary>Settings used ').Append($dot).Append(' ').Append((& $h $phase.Label)).Append('</summary><ul class="plain">')
        foreach ($pair in $pairs) { [void]$sb.Append('<li><span class="muted">').Append((& $h $pair[0])).Append(':</span> ').Append((& $h $pair[1])).Append('</li>') }
        [void]$sb.Append('</ul></details>')
    }
    [void]$sb.Append('</section>')
    $settingsHtml = $sb.ToString()

    $notice = '{0} object(s), {1} journey line(s), {2} error(s) and {3} warning(s) are stored in this file.' -f $total, $eventItems.Count, $errorCount, $warningCount
    if ($ObjectsCsvName -and $EventsCsvName -and $IssuesCsvName) { $notice += ' The files {0}, {1} and {2} hold every object, every journey line and every error and warning.' -f $ObjectsCsvName, $EventsCsvName, $IssuesCsvName }
    if (-not $TemplateFolder) { $TemplateFolder = Join-Path ([IO.Path]::GetDirectoryName($PSScriptRoot)) 'templates' }
    $templatePath = Join-Path $TemplateFolder 'GlobalReport.template.html'
    $template = if (Test-Path -LiteralPath $templatePath -PathType Leaf) { [IO.File]::ReadAllText($templatePath, [Text.Encoding]::UTF8) }
        else { '<!doctype html><html><head><meta charset="utf-8"><title>{{TITLE}}</title></head><body><h1>{{HEADING}}</h1><p>{{SUBTITLE}}</p>{{TILES}}{{NOTICES}}{{TIMELINE}}{{SETTINGS}}<p>{{DATA_NOTICE}} Template missing: only the CSV files hold the objects, the journey lines and the errors and warnings.</p></body></html>' }
    $heading = '{0} across the servers' -f $(if (Test-PraOrdinalIn $Model.Action @('Recover', 'Finalize')) { 'Recover and Finalize' } else { $Model.Action })
    $values = @{
        '{{TITLE}}' = (& $h ('PRA Remote Mailbox - global report - ' + $Model.Action))
        '{{HEADING}}' = (& $h $heading)
        '{{SUBTITLE}}' = (& $h ('Environment {0} {1} batch {2} {1} tool v{3}' -f $Model.Environment, $dot, $Model.BatchId, $Model.Version))
        '{{VERSION}}' = (& $h $Model.Version)
        '{{TILES}}' = $tiles.ToString(); '{{NOTICES}}' = $noticesHtml; '{{TIMELINE}}' = $timelineHtml; '{{SETTINGS}}' = $settingsHtml
        '{{DATA_NOTICE}}' = (& $h $notice)
    }
    # One pass over the template: a value that holds a marker is written as it is, never replaced again. The place of the data is found before any value is put in.
    $marker = '{{DATA}}'
    $at = $template.LastIndexOf($marker, [StringComparison]::Ordinal)
    $pattern = New-Object Text.RegularExpressions.Regex('\{\{[A-Z_]+\}\}', [Text.RegularExpressions.RegexOptions]::CultureInvariant)
    $evaluator = [Text.RegularExpressions.MatchEvaluator]({ param($Match) if ($values.ContainsKey($Match.Value)) { [string]$values[$Match.Value] } else { $Match.Value } }).GetNewClosure()
    if ($at -lt 0) { $Writer.Write($pattern.Replace($template, $evaluator)); return }
    $tail = $pattern.Replace($template.Substring($at + $marker.Length), $evaluator)
    $Writer.Write($pattern.Replace($template.Substring(0, $at), $evaluator))
    $objectChunks = Write-PraReportChunks -Writer $Writer -Kind 'objects' -Items ([object[]]$objectItems.ToArray()) -Fields $objectFields -SizeFields @('Stages', 'Note') -ChunkRows $ChunkRows -ChunkChars $ChunkChars
    $eventChunks = Write-PraReportChunks -Writer $Writer -Kind 'events' -Items ([object[]]$eventItems.ToArray()) -Fields $eventFields -SizeFields @('Text') -ChunkRows $ChunkRows -ChunkChars $ChunkChars
    $issueChunks = Write-PraReportChunks -Writer $Writer -Kind 'issues' -Items $issueItems -Fields $issueFields -SizeFields @('Message') -ChunkRows $ChunkRows -ChunkChars $ChunkChars
    $fieldsJson = { param($fields) ($fields | ForEach-Object { ConvertTo-PraJsonString $_ }) -join ',' }
    $json = '{{"format":1,"objects":{{"count":{0},"fields":[{1}]}},"events":{{"count":{2},"fields":[{3}]}},"issues":{{"count":{4},"fields":[{5}]}},"chunks":{{"objects":{6},"events":{7},"issues":{8}}}}}' -f
        $total, (& $fieldsJson $objectFields), $eventItems.Count, (& $fieldsJson $eventFields), $issueItems.Count, (& $fieldsJson $issueFields), $objectChunks, $eventChunks, $issueChunks
    $Writer.Write('<script type="application/json" id="pra-meta">' + $json + "</script>`r`n")
    $Writer.Write($tail)
}

function Write-PraCsvFile {
    <# Writes rows (arrays of text in the order of Fields) as a semicolon-separated CSV, UTF-8 with a byte order mark, every cell quoted, a text that starts like a formula with an apostrophe in front of it. #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path, [Parameter(Mandatory)][string[]]$Fields, [AllowEmptyCollection()][Collections.Generic.List[string[]]]$Rows)
    $stream = New-Object IO.FileStream($Path, [IO.FileMode]::Create, [IO.FileAccess]::Write, [IO.FileShare]::None)
    $writer = New-Object IO.StreamWriter($stream, (New-Object Text.UTF8Encoding($true)), 65536)
    try {
        $writer.Write('"' + ($Fields -join '";"') + "`"`r`n")
        foreach ($row in $Rows) {
            $cells = $row -replace '\A([=+\-@\t\r])', '''$1' -replace '"', '""'
            $writer.Write('"' + [string]::Join('";"', $cells) + "`"`r`n")
        }
    }
    finally { $writer.Dispose() }
}

function Write-PraGlobalReportCsv {
    <# One line per object: verdict, the status of each side, the number of journey lines and the run settings (formula guard on every text cell). The journey lines are in the events file (Write-PraGlobalEventsCsv). Semicolon, UTF-8 with BOM. #>
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Model, [Parameter(Mandatory)][string]$Path)
    $runSettings = (@($Model.Phases | Where-Object { $_.Available } | ForEach-Object { $label = $_.Label; @(Get-PraList $_.Header 'Overrides') | Where-Object { $_ } | ForEach-Object { $label + ': ' + $_ } }) -join ' | ')
    $rows = New-Object 'Collections.Generic.List[string[]]'
    foreach ($entry in $Model.Objects) {
        $sides = (@($entry.Stages | ForEach-Object { if ($_.Present) { $_.Phase.Label + ': ' + $_.StatusDisplay } else { $_.Phase.Label + ': -' } }) -join ' | ')
        $rows.Add([string[]]@($entry.ObjectGuid, $entry.Name, $entry.Sam, $entry.Upn, $(if ($entry.IsShared) { 'Shared' } else { 'User' }), $entry.Verdict, $sides, $entry.Note, $entry.Backup, [string]$entry.Journey.Count, $runSettings))
    }
    Write-PraCsvFile -Path $Path -Fields @('ObjectGuid', 'Name', 'SamAccountName', 'UserPrincipalName', 'Type', 'Verdict', 'Sides', 'Note', 'BackupPath', 'EventCount', 'RunSettings') -Rows $rows
}

function Write-PraGlobalEventsCsv {
    <# One line per journey line, none left out: the journey of every object, then the lines that name no object (ObjectGuid and Name empty or as the line names it). Same rules as the objects file. #>
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Model, [Parameter(Mandatory)][string]$Path)
    $rows = New-Object 'Collections.Generic.List[string[]]'
    foreach ($entry in $Model.Objects) {
        foreach ($line in $entry.Journey) { $rows.Add([string[]]@($entry.ObjectGuid, $entry.Name, $line.Phase, $line.Step, $line.Status, $line.Time, $line.Text)) }
    }
    foreach ($pair in $Model.Unattached) {
        $item = $pair.Item
        $rows.Add([string[]]@('', [string](Get-PraValue $item 'Name' ''), $pair.Phase, [string](Get-PraValue $item 'Step' ''), [string](Get-PraValue $item 'Status' ''), (Format-PraUtcText ([string](Get-PraValue $item 'Time' ''))), [string](Get-PraValue $item 'Text' '')))
    }
    Write-PraCsvFile -Path $Path -Fields @('ObjectGuid', 'Name', 'Phase', 'Step', 'Status', 'Time', 'Text') -Rows $rows
}

function Write-PraGlobalIssuesCsv {
    <# One line per error or warning of every phase, none left out. Same rules as the objects file. #>
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Model, [Parameter(Mandatory)][string]$Path)
    $rows = New-Object 'Collections.Generic.List[string[]]'
    foreach ($issue in $Model.Issues) { $rows.Add([string[]]@($issue.Phase, $issue.Kind, $issue.Time, $issue.Step, $issue.Object, $issue.Message)) }
    Write-PraCsvFile -Path $Path -Fields @('Phase', 'Kind', 'Time', 'Step', 'Object', 'Message') -Rows $rows
}

function Test-PraGlobalReportWanted {
    <# True for the run that ends the chain: an Apply of Convert, Recover or Finalize that hands nothing over to another server. #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][hashtable]$Context)
    if (-not (Get-PraValue $Context 'AllowMutation' $false)) { return $false }
    if (-not (Test-PraOrdinalIn ([string](Get-PraValue $Context 'Action' '')) @('Convert', 'Recover', 'Finalize'))) { return $false }
    if ([string](Get-PraValue $Context 'HandOff' '')) { return $false }
    if ([bool](Get-PraValue $Context 'NoChangeMade' $false)) { return $false }
    return ($Context.Rows.Count -gt 0)
}

function Write-PraGlobalReport {
    <# Writes the global report of this run into the report folder: the HTML page and three CSV files (objects, journey lines, errors and warnings). Returns Html, Csv, EventsCsv and IssuesCsv (empty when a file could not be written: a warning says why). #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][hashtable]$Context)
    $result = @{ Html = ''; Csv = ''; EventsCsv = ''; IssuesCsv = '' }
    try {
        $model = Get-PraGlobalModel -Context $Context
        Initialize-PraPrivateFolder -Path $Context.ReportFolder
        $stem = [string](Get-PraValue $Context '_PraArtifactStem' '')
        if (-not $stem) { $stem = Get-PraArtifactStem $Context }
        $html = Join-Path $Context.ReportFolder ($stem + '.global.html'); $csv = Join-Path $Context.ReportFolder ($stem + '.global.csv')
        $eventsCsv = Join-Path $Context.ReportFolder ($stem + '.global.events.csv'); $issuesCsv = Join-Path $Context.ReportFolder ($stem + '.global.issues.csv')
        $templates = ''
        $root = [string](Get-PraValue $Context 'Root' '')
        if ($root -and (Test-Path -LiteralPath (Join-Path $root 'templates\GlobalReport.template.html') -PathType Leaf)) { $templates = Join-Path $root 'templates' }
        $stream = [IO.File]::Open($html, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
        $writer = New-Object IO.StreamWriter($stream, (New-Object Text.UTF8Encoding($true)), 65536)
        try { Write-PraGlobalReportHtml -Model $model -Writer $writer -TemplateFolder $templates -ObjectsCsvName ([IO.Path]::GetFileName($csv)) -EventsCsvName ([IO.Path]::GetFileName($eventsCsv)) -IssuesCsvName ([IO.Path]::GetFileName($issuesCsv)) } finally { $writer.Dispose() }
        $result.Html = $html
        Write-PraGlobalReportCsv -Model $model -Path $csv
        $result.Csv = $csv
        Write-PraGlobalEventsCsv -Model $model -Path $eventsCsv
        $result.EventsCsv = $eventsCsv
        Write-PraGlobalIssuesCsv -Model $model -Path $issuesCsv
        $result.IssuesCsv = $issuesCsv
        $Context['GlobalModel'] = $model
    }
    catch { Write-PraLog -Context $Context -Message ('The global report could not be written: {0}' -f $_.Exception.Message) -Level Warning }
    return $result
}
#endregion

Export-ModuleMember -Function Register-PraObjectName, Get-PraList, ConvertTo-PraImmutableId, Get-PraSourceAnchor, Register-PraObjectBackup, Save-PraPhaseData, Copy-PraPhaseData, Copy-PraPhaseFile, Read-PraPhaseData, New-PraPhaseRecord, Get-PraGlobalModel, Write-PraGlobalReport, Write-PraGlobalReportHtml, Write-PraGlobalReportCsv, Write-PraGlobalEventsCsv, Write-PraGlobalIssuesCsv, Get-PraGlobalJourney, Test-PraBatchSideFile, Write-PraRetentionProof, Get-PraRetentionProof, Test-PraRetentionCheckRecord, Get-PraConvertCloudDone, Test-PraGlobalReportWanted, Limit-PraText, Get-PraEventObjectName, Test-PraOrdinalEqual, Test-PraOrdinalIgnoreCaseEqual, Test-PraOrdinalIn, Test-PraOrdinalIgnoreCaseIn, Get-PraOrdinalSorted, Get-PraOrdinalUnique, New-PraRecordIndex, Get-PraRecordIndex, Find-PraRecord, Compare-PraX500Address, ConvertFrom-PraJson, Get-PraNativeProcessApi, Read-PraCsvText, Get-PraToolVersion, Get-PraCloudModuleReport, New-PraPrivateDirectorySecurity, Initialize-PraPrivateFolder, ConvertTo-PraCsvCell, Get-PraValue, Format-PraDuration, Add-PraIssue, Write-PraLog, Write-PraItem, Write-PraBanner, Write-PraStep,
    Write-PraSummary, Write-PraHost, Resolve-PraPath, Import-PraConfiguration, Test-PraScopeConfiguration, Initialize-PraAudit, Get-PraOutcome, Complete-PraRun, Write-PraEvent, Get-PraWin32ErrorText, Test-PraOwnEntryProcess, Get-PraTargetOverride, Read-PraTargetCsv, Write-PraProgress, Get-PraTransferPackageName, Get-PraTransferPackage, Import-PraTransferPackage, New-PraTransferPackage, New-PraEffectiveConfiguration, Get-PraConfigurationDifference

# SIG # Begin signature block
# MIImKgYJKoZIhvcNAQcCoIImGzCCJhcCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCCvJhRiprdR7SOO
# E9idbgfgQurBt8gsCGFyqHUyFghEhaCCDW8wggZyMIIEWqADAgECAghkM1HTxzif
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
# AQQBgjcCAQsxDjAMBgorBgEEAYI3AgEVMC8GCSqGSIb3DQEJBDEiBCDMMohAfHeF
# 6KMJM6TTbAtok+eL/RYsLC5xiyCdfdhfEzANBgkqhkiG9w0BAQEFAASCAgBn3t21
# EGU0FZaE228TXzUrItna/eH5FrPm0KF9tbsDOqOmxajQzvJ23mYli2elTFH1WJts
# oYcF7dvFCpMA8SRl1kfX5CnSo6vo7err3y1G+ugv4KLdS5cYv/wEKMGDRMz9ROw1
# 6C6pwN8qMn2nU0R58DAJU1bjouUnay5FjyZZ0hbhXy2RY2+i1Bd44QthPJxbFVdm
# RZ45yzF9AJLPNGYByEJ69fPr+OLrZ1xjS6dz08lTaqpSWImABxJHRhXSL2K3NzzQ
# Q6AvYAmkyl61aJzFEjFhjWsvSEXwj9sVZfpYYnKG9oRafVq1bFgNesmuv4agq4eH
# fl0z4Byjy74LdSjz5aC6Cb1mQEg/fqIxV9gDzE9cDY03BSDut4mQEUtn2ARbqMm9
# nNlIs1DDrLJDZ7Zn8peRMDibds72PNOQW21vKv/PlzQ1nKedO4Qcq+icRqI0Pp/4
# 5S1MjrPdcPqVa1g16oM+oBUdZ1LaFs2hVQZq9hgJIQXZq3NNyFTUFzAMdb3I4A0N
# HhnR7wHiXfjzST9LpNC+hvmt0+6yzX8SxTkPBXGukakxc6YoAi66GF5Hl8S2rGsq
# 5zMsGBmT5px+L6KT8oyFmu4VcrnaRgHtKcCmBjYgdQl4GpaHfEA2kGMgfSGON9Mz
# sdRd4vbdQzN+Bq1MRmTSoIJMkZ0wDkub5E8LAKGCFM4wghTKBgorBgEEAYI3AwMB
# MYIUujCCFLYGCSqGSIb3DQEHAqCCFKcwghSjAgEDMQ0wCwYJYIZIAWUDBAIBMIGJ
# BgsqhkiG9w0BCRABBKB6BHgwdgIBAQYMKwYBBAGCqTABAwYBMDEwDQYJYIZIAWUD
# BAIBBQAEIIEgEAwZls2KUHQWERm+Zpavqe14pq44sPBPMDsjq2+jAggnDvZ/iHhQ
# qhgPMjAyNjExMTMxMjEyMzNaMAMCAQECEDm9zLsfd/GtxWBhQlsQK+SgghGnMIIE
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
# AQkQAQQwHAYJKoZIhvcNAQkFMQ8XDTI2MTExMzEyMTIzM1owKAYJKoZIhvcNAQk0
# MRswGTALBglghkgBZQMEAgGhCgYIKoZIzj0EAwIwLwYJKoZIhvcNAQkEMSIEIL1x
# 1k1q1+QY69wjVGpdtTDZIr77zMVvcUbHKsf4IkJHMIHIBgsqhkiG9w0BCRACLzGB
# uDCBtTCBsjCBrwQgV0/qF6r6XnxqK5sIyZixc15FCzhzykTmokygkw5j87AwgYow
# dqR0MHIxCzAJBgNVBAYTAlVTMQ4wDAYDVQQIDAVUZXhhczEQMA4GA1UEBwwHSG91
# c3RvbjERMA8GA1UECgwIU1NMIENvcnAxLjAsBgNVBAMMJVNTTC5jb20gVGltZXN0
# YW1waW5nIElzc3VpbmcgUlNBIENBIDICEFRD+De9Wu4YAYRyuFzajuMwCgYIKoZI
# zj0EAwIERzBFAiAygtmRn4BpBCn+ikiRvGYOhWnMIfk16MHTpVpOkNhF6gIhAPGf
# XFy7YyDNoHNu+baUU9wILQqZecQ12eZXW3WRAJN0
# SIG # End signature block
