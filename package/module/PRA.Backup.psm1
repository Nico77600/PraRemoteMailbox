#Requires -Version 5.1
#Requires -PSEdition Desktop
<#
.SYNOPSIS
    PRA Remote Mailbox - data-only CLIXML codec of the AD captures (backup part 2 of 2).

.DESCRIPTION
    Every backup has two parts: the typed JSON records (what Recover restores) and a CLIXML file
    with EVERY value returned by AD for each object (audit, manual recovery, attributes the tool
    does not manage). This module writes and re-reads that CLIXML as a stream, with a closed format:
    no native AD object is kept or deserialised, no value is converted to text as a fallback, and an
    unsupported type stops the backup (nothing is written to AD).

      ConvertTo-PraRawSnapshot   ADUser -> closed, lossless description of every attribute
      Write-PraRawCapture        writes the snapshots of a batch (new file only, never overwritten)
      Test-PraRawCapture         streams the file to the end and checks it against the JSON records
                                 (and, just after writing, against the snapshots in memory)

    Old backups (schema 1 and 2) contain a native CLIXML: only the object identities are checked,
    the graph is never inflated.

.NOTES
    Author  : Nicolas Fabert
    Version : 2.2.0 (format PraDataOnlyClixml-v1, unchanged since 1.3.3)
#>
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

# Closed, data-only codec. No directory reads, CLR property walks, or native graph serializer.
# DTO: {ObjectGUID; DistinguishedName; CapturedUtc; Attributes=[ordered] name -> descriptor}.
# Descriptor always has {Kind; Type; Value=string|null; Items=object[]}.
# Wire: Objs/Obj/MS snapshots; Attributes is DCT name -> LST of preorder descriptor nodes
# {Depth=I32; Kind=S; Type=S; Value=S|Nil; Count=I32}. XML depth is constant, not graph depth.
# IEEE754 bytes and decimal bits preserve negative zero, NaN payloads and decimal scale.
$script:PraRawFormat = 'PraDataOnlyClixml-v1'
$script:PraRawNamespace = 'http://schemas.microsoft.com/powershell/2004/04'
$script:PraRawDepth = 16
$script:PraRawNodes = 1000000
$script:PraRawCulture = [Globalization.CultureInfo]::InvariantCulture
$script:PraRawEscape = [regex]'[_\x00-\x1f\x7f-\x9f\uD800-\uDFFF￾￿]'
$script:PraRawUnescape = [regex]'_x([0-9a-fA-F]{4})_'

function Get-PraRawMember {
    param([AllowNull()]$Object,[string]$Name)
    if ($null -eq $Object) { return $null }
    if ($Object -is [Collections.IDictionary]) {
        if ($Object.Contains($Name)) { return ,$Object[$Name] }
        return $null
    }
    $property = $Object.PSObject.Properties[$Name]
    if ($null -ne $property) { return ,$property.Value }
    return $null
}

function Test-PraRawCollectionType {
    param([string]$Name)
    return ($Name -cmatch '^System\.[A-Za-z0-9_.+`\[\], =-]+\[\]$' -or
        $Name -cin @('System.Collections.ArrayList','System.Collections.Specialized.StringCollection',
            'Microsoft.ActiveDirectory.Management.ADPropertyValueCollection') -or
        $Name -cmatch '^System\.Collections\.(Generic\.List|ObjectModel\.(ReadOnlyCollection|Collection))`1\[\[')
}

function ConvertTo-PraRawDescriptor {
    param([AllowNull()]$Value,[string]$Attribute,[string]$ObjectGuid,[int]$Depth,[hashtable]$Budget)
    $Budget.Left--
    if ($Depth -gt $script:PraRawDepth -or $Budget.Left -lt 0) {
        throw "Raw capture: collection limit/cycle, attribute=$Attribute GUID=$ObjectGuid."
    }
    $result = [ordered]@{ Kind='Null'; Type=''; Value=$null; Items=[object[]]@() }
    if ($null -eq $Value) { return ,$result }
    $type = $Value.GetType(); $name = $type.FullName
    $result.Kind = 'Scalar'; $result.Type = $type.Name
    switch -CaseSensitive ($name) {
        'System.String' { $result.Value = $Value; return ,$result }
        'System.Boolean' { $result.Value = if ($Value) { 'true' } else { 'false' }; return ,$result }
        'System.Char' { $result.Value = ([uint16][char]$Value).ToString($script:PraRawCulture); return ,$result }
        { $_ -cin @('System.SByte','System.Byte','System.Int16','System.UInt16','System.Int32',
                'System.UInt32','System.Int64','System.UInt64') } {
            $result.Value = $Value.ToString($script:PraRawCulture); return ,$result
        }
        { $_ -cin @('System.Single','System.Double') } {
            $bytes = [BitConverter]::GetBytes($Value)
            if (-not [BitConverter]::IsLittleEndian) { [array]::Reverse($bytes) }
            $result.Value = [Convert]::ToBase64String($bytes); return ,$result
        }
        'System.Decimal' {
            $parts = [Collections.Generic.List[string]]::new()
            foreach ($part in [decimal]::GetBits($Value)) { $parts.Add($part.ToString($script:PraRawCulture)) }
            $result.Value = $parts -join '|'; return ,$result
        }
        'System.DateTime' { $result.Value = $Value.ToBinary().ToString($script:PraRawCulture); return ,$result }
        'System.DateTimeOffset' {
            $result.Value = $Value.Ticks.ToString($script:PraRawCulture) + '|' + $Value.Offset.Ticks.ToString($script:PraRawCulture)
            return ,$result
        }
        'System.TimeSpan' { $result.Value = $Value.Ticks.ToString($script:PraRawCulture); return ,$result }
        'System.Guid' { $result.Value = $Value.ToString('D'); return ,$result }
        'System.Security.Principal.SecurityIdentifier' {
            $bytes = [byte[]]::new($Value.BinaryLength); $Value.GetBinaryForm($bytes,0)
            $result.Type = 'SID'; $result.Value = [Convert]::ToBase64String($bytes); return ,$result
        }
        'System.Byte[]' {
            $result.Kind = 'Binary'; $result.Type = 'Byte[]'
            $result.Value = [Convert]::ToBase64String($Value); return ,$result
        }
    }
    # ActiveDirectorySecurity derives from ObjectSecurity, NOT GenericSecurityDescriptor.
    if ($Value -is [Security.AccessControl.ObjectSecurity]) {
        $result.Kind = 'SecurityDescriptor'; $result.Type = $name
        $result.Value = [Convert]::ToBase64String($Value.GetSecurityDescriptorBinaryForm())
        return ,$result
    }
    if ($Value -is [Security.AccessControl.GenericSecurityDescriptor]) {
        $bytes = [byte[]]::new($Value.BinaryLength); $Value.GetBinaryForm($bytes,0)
        $result.Kind = 'SecurityDescriptor'; $result.Type = $name
        $result.Value = [Convert]::ToBase64String($bytes); return ,$result
    }
    $collection = $false
    if ($type.IsArray) {
        $collection = $Value.Rank -eq 1 -and $Value.GetLowerBound(0) -eq 0
    } elseif ((Test-PraRawCollectionType $name) -and
        $type.Assembly.GetName().Name -cin @('mscorlib','System','Microsoft.ActiveDirectory.Management')) {
        $collection = $true
    }
    if (-not $collection) { throw "Raw capture: unsupported attribute=$Attribute type=$name GUID=$ObjectGuid; no fallback."
    }
    $result.Kind = 'Collection'; $result.Type = $name
    $items = [Collections.Generic.List[object]]::new()
    foreach ($item in $Value) {
        $items.Add((ConvertTo-PraRawDescriptor -Value $item -Attribute $Attribute -ObjectGuid $ObjectGuid -Depth ($Depth+1) -Budget $Budget))
    }
    $result.Items = $items.ToArray()
    return ,$result
}

function ConvertTo-PraRawSnapshot {
    <# .SYNOPSIS
    Detaches every returned user property into a closed lossless DTO; no native object is retained.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)]$User,[Parameter(Mandatory)][string]$CapturedUtc)
    $identity = Get-PraRawMember $User 'ObjectGUID'; $guid = [guid]::Empty
    if (($identity -isnot [guid] -and $identity -isnot [string]) -or
        -not [guid]::TryParse([string]$identity,[ref]$guid) -or $guid -eq [guid]::Empty) {
        throw 'Raw capture: invalid attribute=ObjectGUID, GUID unavailable.'
    }
    $key = $guid.ToString('D'); $attributes = [ordered]@{}
    $dictionary = $User -is [Collections.IDictionary]
    # Native ADUser exposes CLR tracking metadata alongside its returned directory properties.
    # Its property bag is authoritative; ordinary objects/dictionaries retain every member.
    $names = if ($dictionary) { $User.Keys }
        elseif ($User.GetType().FullName -ceq 'Microsoft.ActiveDirectory.Management.ADUser') { $User.PropertyNames }
        else { $User.PSObject.Properties.Name }
    foreach ($name in $names) {
        if ($name -isnot [string] -or [string]::IsNullOrEmpty($name) -or $attributes.Contains($name)) {
            throw "Raw capture: invalid/duplicate attribute name, GUID=$key."
        }
        $value = $null
        try {
            # Direct assignment preserves null/empty/nested arrays and reads each getter once.
            if ($name -ieq 'ObjectGUID') { $value = $identity }
            elseif ($dictionary) { $value = $User[$name] }
            else {
                $property = $User.PSObject.Properties[$name]
                if ($null -eq $property) { throw 'Declared property is not readable.' }
                $value = $property.Value
            }
            $attributes[$name] = ConvertTo-PraRawDescriptor -Value $value -Attribute $name -ObjectGuid $key -Depth 0 -Budget @{Left=$script:PraRawNodes}
        } catch {
            $typeName = '<unreadable>'
            if ($null -ne $value) { $typeName = $value.GetType().FullName }
            throw "Raw capture failed: attribute=$name type=$typeName GUID=$key. $($_.Exception.Message)"
        }
    }
    $dn = $attributes['DistinguishedName']
    if ($null -eq $dn -or $dn.Kind -cne 'Scalar' -or $dn.Type -cne 'String') {
        throw "Raw capture: DistinguishedName must be a captured string, GUID=$key."
    }
    $snapshot = [pscustomobject][ordered]@{ ObjectGUID=$key; DistinguishedName=$dn.Value; CapturedUtc=$CapturedUtc; Attributes=$attributes }
    Assert-PraRawSnapshot $snapshot
    return $snapshot
}

function Assert-PraRawScalar {
    param([string]$Kind,[string]$Type,[AllowNull()]$Value)
    if ($Kind -ceq 'Null') {
        if ($Type -cne '' -or $null -ne $Value) { throw 'Raw: invalid null descriptor.' }
        return
    }
    if ($Kind -ceq 'Collection') {
        if ($null -ne $Value -or -not (Test-PraRawCollectionType $Type)) { throw 'Raw: invalid collection descriptor.' }
        return
    }
    if ($Value -isnot [string]) { throw 'Raw: descriptor Value must be a string.' }
    if ($Kind -ceq 'Binary' -or $Kind -ceq 'SecurityDescriptor' -or
        ($Kind -ceq 'Scalar' -and $Type -cin @('Single','Double','SID'))) {
        $bytes = [Convert]::FromBase64String($Value)
        if ([Convert]::ToBase64String($bytes) -cne $Value) { throw 'Raw: noncanonical Base64.' }
        if ($Kind -ceq 'Binary') {
            if ($Type -cne 'Byte[]') { throw 'Raw: invalid binary type.' }
        } elseif ($Kind -ceq 'SecurityDescriptor') {
            if ($Type -notmatch '^System\.(Security\.AccessControl|DirectoryServices)\.[A-Za-z]+(Security|SecurityDescriptor)$') {
                throw 'Raw: invalid security descriptor type.'
            }
            $security = [Security.AccessControl.RawSecurityDescriptor]::new($bytes,0)
            $copy = [byte[]]::new($security.BinaryLength); $security.GetBinaryForm($copy,0)
            if ([Convert]::ToBase64String($copy) -cne $Value) { throw 'Raw: security descriptor binary mismatch.' }
        } elseif ($Type -ceq 'SID') {
            $sid = [Security.Principal.SecurityIdentifier]::new($bytes,0)
            $copy = [byte[]]::new($sid.BinaryLength); $sid.GetBinaryForm($copy,0)
            if ([Convert]::ToBase64String($copy) -cne $Value) { throw 'Raw: SID binary mismatch.' }
        } elseif (($Type -ceq 'Single' -and $bytes.Length -ne 4) -or ($Type -ceq 'Double' -and $bytes.Length -ne 8)) {
            throw 'Raw: invalid IEEE754 width.'
        }
        return
    }
    if ($Kind -cne 'Scalar') { throw 'Raw: unknown descriptor kind.' }
    $canonical = $Value
    switch -CaseSensitive ($Type) {
        'String' { return }
        'Boolean' { if ($Value -cnotin @('true','false')) { throw 'Raw: invalid Boolean.' }; return }
        'Char' { $canonical = ([uint16]::Parse($Value,$script:PraRawCulture)).ToString($script:PraRawCulture) }
        'SByte' { $canonical = ([sbyte]::Parse($Value,$script:PraRawCulture)).ToString($script:PraRawCulture) }
        'Byte' { $canonical = ([byte]::Parse($Value,$script:PraRawCulture)).ToString($script:PraRawCulture) }
        'Int16' { $canonical = ([int16]::Parse($Value,$script:PraRawCulture)).ToString($script:PraRawCulture) }
        'UInt16' { $canonical = ([uint16]::Parse($Value,$script:PraRawCulture)).ToString($script:PraRawCulture) }
        'Int32' { $canonical = ([int32]::Parse($Value,$script:PraRawCulture)).ToString($script:PraRawCulture) }
        'UInt32' { $canonical = ([uint32]::Parse($Value,$script:PraRawCulture)).ToString($script:PraRawCulture) }
        'Int64' { $canonical = ([int64]::Parse($Value,$script:PraRawCulture)).ToString($script:PraRawCulture) }
        'UInt64' { $canonical = ([uint64]::Parse($Value,$script:PraRawCulture)).ToString($script:PraRawCulture) }
        'Guid' { $canonical = ([guid]::Parse($Value)).ToString('D') }
        'TimeSpan' { $canonical = ([timespan]::FromTicks([int64]::Parse($Value,$script:PraRawCulture))).Ticks.ToString($script:PraRawCulture) }
        'DateTime' {
            $binary = [int64]::Parse($Value,$script:PraRawCulture); $null = [datetime]::FromBinary($binary)
            $canonical = $binary.ToString($script:PraRawCulture)
        }
        'DateTimeOffset' {
            $parts = $Value.Split('|')
            if ($parts.Count -ne 2) { throw 'Raw: invalid DateTimeOffset.' }
            $date = [datetimeoffset]::new([int64]::Parse($parts[0],$script:PraRawCulture),[timespan]::FromTicks([int64]::Parse($parts[1],$script:PraRawCulture)))
            $canonical = $date.Ticks.ToString($script:PraRawCulture) + '|' + $date.Offset.Ticks.ToString($script:PraRawCulture)
        }
        'Decimal' {
            $parts = $Value.Split('|')
            if ($parts.Count -ne 4) { throw 'Raw: invalid Decimal.' }
            $bits = [int[]]::new(4); $text = [string[]]::new(4)
            for ($i=0; $i -lt 4; $i++) {
                $bits[$i] = [int32]::Parse($parts[$i],$script:PraRawCulture); $text[$i] = $bits[$i].ToString($script:PraRawCulture)
            }
            $null = [decimal]::new($bits); $canonical = $text -join '|'
        }
        default { throw "Raw: unknown scalar type '$Type'." }
    }
    if ($canonical -cne $Value) { throw "Raw: noncanonical $Type value." }
}

function Assert-PraRawDescriptor {
    param($Descriptor,[int]$Depth=0,[hashtable]$Budget=@{Left=$script:PraRawNodes})
    $Budget.Left--
    if ($Depth -gt $script:PraRawDepth -or $Budget.Left -lt 0) { throw 'Raw: descriptor depth/node limit or cycle.' }
    if ($Descriptor -isnot [Collections.IDictionary] -or $Descriptor.Count -ne 4) { throw 'Raw: invalid descriptor shape.' }
    foreach ($field in @('Kind','Type','Value','Items')) {
        if (-not $Descriptor.Contains($field)) { throw "Raw: missing descriptor field $field." }
    }
    if ($Descriptor.Kind -isnot [string] -or $Descriptor.Type -isnot [string] -or $Descriptor.Items -isnot [object[]]) {
        throw 'Raw: invalid descriptor field type.'
    }
    Assert-PraRawScalar $Descriptor.Kind $Descriptor.Type $Descriptor.Value
    if ($Descriptor.Kind -cne 'Collection' -and $Descriptor.Items.Count -ne 0) { throw 'Raw: scalar has children.' }
    foreach ($item in $Descriptor.Items) { Assert-PraRawDescriptor $item ($Depth+1) $Budget }
}

function Assert-PraRawSnapshot {
    param($Snapshot)
    if ($Snapshot -isnot [pscustomobject] -or @($Snapshot.PSObject.Properties).Count -ne 4) { throw 'Raw: invalid snapshot shape.' }
    foreach ($field in @('ObjectGUID','DistinguishedName','CapturedUtc')) {
        if ((Get-PraRawMember $Snapshot $field) -isnot [string]) { throw "Raw: invalid snapshot $field." }
    }
    $guid = [guid]::Parse($Snapshot.ObjectGUID)
    if ($guid -eq [guid]::Empty -or $guid.ToString('D') -cne $Snapshot.ObjectGUID) { throw 'Raw: invalid snapshot GUID.' }
    if ([string]::IsNullOrWhiteSpace($Snapshot.CapturedUtc)) { throw 'Raw: empty CapturedUtc.' }
    $null = [datetimeoffset]::Parse($Snapshot.CapturedUtc,$script:PraRawCulture)
    if ($Snapshot.Attributes -isnot [Collections.Specialized.OrderedDictionary]) { throw 'Raw: Attributes must be an ordered dictionary.' }
    foreach ($name in $Snapshot.Attributes.Keys) {
        if ($name -isnot [string] -or [string]::IsNullOrEmpty($name)) { throw 'Raw: invalid attribute name.' }
        try { Assert-PraRawDescriptor $Snapshot.Attributes[$name] }
        catch { throw "Raw: attribute=$name GUID=$($Snapshot.ObjectGUID). $($_.Exception.Message)" }
    }
    $id = $Snapshot.Attributes['ObjectGUID']; $dn = $Snapshot.Attributes['DistinguishedName']
    if ($null -eq $id -or $id.Kind -cne 'Scalar' -or $id.Type -cnotin @('Guid','String') -or
        ([guid]::Parse($id.Value)).ToString('D') -cne $Snapshot.ObjectGUID) { throw 'Raw: metadata/attribute ObjectGUID mismatch.' }
    if ($null -eq $dn -or $dn.Kind -cne 'Scalar' -or $dn.Type -cne 'String' -or $dn.Value -cne $Snapshot.DistinguishedName) {
        throw 'Raw: metadata/attribute DistinguishedName mismatch.'
    }
}

function Write-PraRawString {
    param([Xml.XmlWriter]$Writer,[AllowEmptyString()][string]$Value)
    if ($Value.Length -eq 0) { return }
    if (-not $script:PraRawEscape.IsMatch($Value)) { $Writer.WriteString($Value); return }
    # Escaping every underscore avoids _xHHHH_ ambiguity across buffer boundaries.
    # Encode UTF-16 surrogate code units too, including isolated surrogates, without XML loss.
    for ($offset=0; $offset -lt $Value.Length; $offset+=4096) {
        $chunk = $Value.Substring($offset,[Math]::Min(4096,$Value.Length-$offset))
        $escaped = $script:PraRawEscape.Replace($chunk,[Text.RegularExpressions.MatchEvaluator]{
            param($match)
            return ('_x{0:X4}_' -f [int][char]$match.Value[0])
        })
        $Writer.WriteString($escaped)
    }
}

function Write-PraRawElement {
    param([hashtable]$State,[string]$Tag,[AllowEmptyString()][string]$Name,[AllowNull()]$Value)
    $State.Writer.WriteStartElement($Tag,$script:PraRawNamespace)
    if ($Name) { $State.Writer.WriteStartAttribute('N'); Write-PraRawString $State.Writer $Name; $State.Writer.WriteEndAttribute() }
    if ($Tag -cne 'Nil') { Write-PraRawString $State.Writer $Value }
    $State.Writer.WriteEndElement()
}

function Write-PraRawObjectStart {
    param([hashtable]$State,[string]$Name='')
    $State.Writer.WriteStartElement('Obj',$script:PraRawNamespace)
    $State.Writer.WriteAttributeString('RefId',$State.RefId.ToString($script:PraRawCulture)); $State.RefId++
    if ($Name) { $State.Writer.WriteStartAttribute('N'); Write-PraRawString $State.Writer $Name; $State.Writer.WriteEndAttribute() }
}

function Write-PraRawNode {
    param([hashtable]$State,$Descriptor,[int]$Depth)
    Write-PraRawObjectStart $State
    $State.Writer.WriteStartElement('MS',$script:PraRawNamespace)
    Write-PraRawElement $State 'I32' 'Depth' $Depth.ToString($script:PraRawCulture)
    Write-PraRawElement $State 'S' 'Kind' $Descriptor.Kind
    Write-PraRawElement $State 'S' 'Type' $Descriptor.Type
    $tag = if ($null -eq $Descriptor.Value) { 'Nil' } else { 'S' }
    Write-PraRawElement $State $tag 'Value' $Descriptor.Value
    Write-PraRawElement $State 'I32' 'Count' $Descriptor.Items.Count.ToString($script:PraRawCulture)
    $State.Writer.WriteEndElement(); $State.Writer.WriteEndElement()
    foreach ($item in $Descriptor.Items) { Write-PraRawNode $State $item ($Depth+1) }
}

function Write-PraRawProgress {
    param($Context,$Snapshot,[int64]$Bytes,[string]$Stage)
    $name = $Snapshot.DistinguishedName
    $sam = $Snapshot.Attributes['SamAccountName']
    if ($null -ne $sam -and $sam.Kind -ceq 'Scalar' -and $sam.Type -ceq 'String') { $name = $sam.Value }
    if ($name.Length -gt 128) { $name = $name.Substring(0,128) }
    $name = [regex]::Replace($name,'[\p{Cc}\p{Cf}\p{Zl}\p{Zp}]','?')
    $process = [Diagnostics.Process]::GetCurrentProcess()
    try { $private = [Math]::Round($process.PrivateMemorySize64 / 1MB,1).ToString($script:PraRawCulture) }
    finally { $process.Dispose() }
    Write-PraLog -Context $Context -Message "RAW $Stage | GUID=$($Snapshot.ObjectGUID) | name=$name | attributes=$($Snapshot.Attributes.Count) | privateMiB=$private | bytes=$Bytes" -Level Debug
}

function Write-PraRawCapture {
    <# .SYNOPSIS
    Creates an exclusive CLIXML stream in the caller's already-private directory. Never overwrites.
    #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions','',Justification='Mandatory immutable backup artifact; target mutation and private-directory approval belong to the caller.')]
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Context,[Parameter(Mandatory)][string]$LiteralPath,
        [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Snapshots)
    if ($Snapshots.Count -eq 0) { throw 'Raw: empty snapshot sequence.' }
    $seen = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    foreach ($snapshot in $Snapshots) {
        Assert-PraRawSnapshot $snapshot
        if (-not $seen.Add($snapshot.ObjectGUID)) { throw 'Raw: duplicate snapshot GUID before write.' }
    }
    $path = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($LiteralPath)
    if (-not [IO.Directory]::Exists([IO.Path]::GetDirectoryName($path))) { throw 'Raw: private parent directory must already exist.' }
    $stream = [IO.FileStream]::new($path,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None,65536)
    $writer = $null
    try {
        $settings = [Xml.XmlWriterSettings]::new(); $settings.Encoding = [Text.UTF8Encoding]::new($true)
        $settings.CloseOutput = $false; $settings.Indent = $false; $settings.CheckCharacters = $true
        $writer = [Xml.XmlWriter]::Create($stream,$settings)
        $state = @{Writer=$writer; RefId=[int64]0}
        $writer.WriteStartDocument(); $writer.WriteStartElement('Objs',$script:PraRawNamespace)
        $writer.WriteAttributeString('Version','1.1.0.1')
        foreach ($snapshot in $Snapshots) {
            Write-PraRawProgress $Context $snapshot $stream.Position 'WRITE BEGIN'
            Write-PraRawObjectStart $state; $writer.WriteStartElement('MS',$script:PraRawNamespace)
            foreach ($field in @('RawFormat','ObjectGUID','DistinguishedName','CapturedUtc')) {
                $value = if ($field -ceq 'RawFormat') { $script:PraRawFormat } else { $snapshot.$field }
                Write-PraRawElement $state 'S' $field $value
            }
            Write-PraRawObjectStart $state 'Attributes'; $writer.WriteStartElement('DCT',$script:PraRawNamespace)
            foreach ($name in $snapshot.Attributes.Keys) {
                $writer.WriteStartElement('En',$script:PraRawNamespace)
                Write-PraRawElement $state 'S' 'Key' $name
                Write-PraRawObjectStart $state 'Value'; $writer.WriteStartElement('LST',$script:PraRawNamespace)
                Write-PraRawNode $state $snapshot.Attributes[$name] 0
                $writer.WriteEndElement(); $writer.WriteEndElement(); $writer.WriteEndElement()
            }
            $writer.WriteEndElement(); $writer.WriteEndElement(); $writer.WriteEndElement(); $writer.WriteEndElement()
            $writer.Flush()
            Write-PraRawProgress $Context $snapshot $stream.Position 'WRITE END'
        }
        $writer.WriteEndElement(); $writer.WriteEndDocument(); $writer.Flush(); $stream.Flush($true)
    } finally {
        try { if ($null -ne $writer) { $writer.Dispose() } } finally { $stream.Dispose() }
    }
}

function ConvertFrom-PraRawString {
    param([AllowEmptyString()][string]$Value)
    if ($Value.IndexOf('_x',[StringComparison]::Ordinal) -lt 0) { return $Value }
    return $script:PraRawUnescape.Replace($Value,[Text.RegularExpressions.MatchEvaluator]{
        param($match)
        return [string][char][Convert]::ToInt32($match.Groups[1].Value,16)
    })
}

function Assert-PraRawXmlStart {
    param([Xml.XmlReader]$Reader,[string]$Tag,[string[]]$Attributes=@())
    $null = $Reader.MoveToContent()
    if ($Reader.NodeType -ne [Xml.XmlNodeType]::Element -or $Reader.LocalName -cne $Tag -or $Reader.NamespaceURI -cne $script:PraRawNamespace) {
        throw "Raw XML: expected $Tag, found $($Reader.NodeType)/$($Reader.LocalName)."
    }
    if ($Reader.MoveToFirstAttribute()) {
        do {
            if ($Reader.Name -ceq 'xmlns' -and $Tag -ceq 'Objs' -and $Reader.Value -ceq $script:PraRawNamespace) { continue }
            if ($Reader.NamespaceURI -cne '' -or $Reader.Name -cnotin $Attributes) { throw "Raw XML: unexpected attribute $($Reader.Name)." }
        } while ($Reader.MoveToNextAttribute())
        $null = $Reader.MoveToElement()
    }
}

function Read-PraRawStart {
    param([Xml.XmlReader]$Reader,[string]$Tag)
    Assert-PraRawXmlStart $Reader $Tag
    if ($Reader.IsEmptyElement) { throw "Raw XML: empty $Tag container." }
    $Reader.ReadStartElement()
}

function Read-PraRawEnd {
    param([Xml.XmlReader]$Reader,[string]$Tag)
    $null = $Reader.MoveToContent()
    if ($Reader.NodeType -ne [Xml.XmlNodeType]::EndElement -or $Reader.LocalName -cne $Tag -or $Reader.NamespaceURI -cne $script:PraRawNamespace) {
        throw "Raw XML: expected closing $Tag."
    }
    $Reader.ReadEndElement()
}

function Read-PraRawObjectStart {
    param([hashtable]$State,[string]$Name='')
    $reader = $State.Reader
    Assert-PraRawXmlStart $reader 'Obj' @('RefId','N')
    if ($reader.GetAttribute('RefId') -cne $State.RefId.ToString($script:PraRawCulture) -or
        (ConvertFrom-PraRawString ([string]$reader.GetAttribute('N'))) -cne $Name -or $reader.IsEmptyElement) {
        throw 'Raw XML: object identity/name/sequence invalid; shared references are forbidden.'
    }
    $State.RefId++; $reader.ReadStartElement()
}

function Read-PraRawElement {
    param([Xml.XmlReader]$Reader,[string]$Tag,[string]$Name)
    Assert-PraRawXmlStart $Reader $Tag @('N')
    if ((ConvertFrom-PraRawString ([string]$Reader.GetAttribute('N'))) -cne $Name) { throw "Raw XML: expected member $Name." }
    if ($Tag -ceq 'Nil') {
        if ($Reader.ReadElementContentAsString() -cne '') { throw 'Raw XML: nonempty Nil.' }
        return $null
    }
    # One intrinsic scalar only; never materialize a snapshot XML string or the whole file.
    $value = $Reader.ReadElementContentAsString()
    if ($Tag -ceq 'S') { return (ConvertFrom-PraRawString $value) }
    $number = [int]::Parse($value,$script:PraRawCulture)
    if ($number.ToString($script:PraRawCulture) -cne $value) { throw 'Raw XML: noncanonical Int32.' }
    return $number
}

function Read-PraRawNode {
    param([hashtable]$State,[int]$Depth,[hashtable]$Budget)
    $Budget.Left--
    if ($Depth -gt $script:PraRawDepth -or $Budget.Left -lt 0) { throw 'Raw XML: descriptor depth/node limit.' }
    $reader = $State.Reader
    Read-PraRawObjectStart $State; Read-PraRawStart $reader 'MS'
    if ((Read-PraRawElement $reader 'I32' 'Depth') -ne $Depth) { throw 'Raw XML: invalid descriptor preorder depth.' }
    $kind = Read-PraRawElement $reader 'S' 'Kind'; $type = Read-PraRawElement $reader 'S' 'Type'
    $null = $reader.MoveToContent(); $tag = $reader.LocalName
    if ($tag -cnotin @('S','Nil')) { throw 'Raw XML: invalid descriptor value type.' }
    $value = Read-PraRawElement $reader $tag 'Value'; $count = Read-PraRawElement $reader 'I32' 'Count'
    if ($count -lt 0 -or $count -gt $Budget.Left -or ($kind -cne 'Collection' -and $count -ne 0)) { throw 'Raw XML: invalid item cardinality.' }
    Read-PraRawEnd $reader 'MS'; Read-PraRawEnd $reader 'Obj'
    $items = [Collections.Generic.List[object]]::new()
    for ($i=0; $i -lt $count; $i++) { $items.Add((Read-PraRawNode $State ($Depth+1) $Budget)) }
    return ,([ordered]@{Kind=$kind; Type=$type; Value=$value; Items=[object[]]$items.ToArray()})
}

function Read-PraRawSnapshot {
    param([hashtable]$State)
    $reader = $State.Reader
    Read-PraRawObjectStart $State; Read-PraRawStart $reader 'MS'
    if ((Read-PraRawElement $reader 'S' 'RawFormat') -cne $script:PraRawFormat) { throw 'Raw XML: format marker mismatch.' }
    $guid = Read-PraRawElement $reader 'S' 'ObjectGUID'; $dn = Read-PraRawElement $reader 'S' 'DistinguishedName'
    $utc = Read-PraRawElement $reader 'S' 'CapturedUtc'
    Read-PraRawObjectStart $State 'Attributes'; Read-PraRawStart $reader 'DCT'
    $attributes = [ordered]@{}
    while ($reader.MoveToContent() -eq [Xml.XmlNodeType]::Element) {
        Read-PraRawStart $reader 'En'; $name = Read-PraRawElement $reader 'S' 'Key'
        if ([string]::IsNullOrEmpty($name) -or $attributes.Contains($name)) { throw 'Raw XML: duplicate/empty attribute name.' }
        Read-PraRawObjectStart $State 'Value'; Read-PraRawStart $reader 'LST'
        $attributes[$name] = Read-PraRawNode $State 0 @{Left=$script:PraRawNodes}
        Read-PraRawEnd $reader 'LST'; Read-PraRawEnd $reader 'Obj'; Read-PraRawEnd $reader 'En'
    }
    Read-PraRawEnd $reader 'DCT'; Read-PraRawEnd $reader 'Obj'; Read-PraRawEnd $reader 'MS'; Read-PraRawEnd $reader 'Obj'
    $snapshot = [pscustomobject][ordered]@{ObjectGUID=$guid; DistinguishedName=$dn; CapturedUtc=$utc; Attributes=$attributes}
    Assert-PraRawSnapshot $snapshot
    return $snapshot
}

function Assert-PraRawDescriptorEqual {
    param($Left,$Right,[string]$Name)
    foreach ($field in @('Kind','Type','Value')) {
        if (-not [object]::Equals($Left[$field],$Right[$field])) { throw "Raw: creation roundtrip mismatch, attribute=$Name field=$field." }
    }
    if ($Left.Items.Count -ne $Right.Items.Count) { throw "Raw: creation roundtrip item count mismatch, attribute=$Name." }
    for ($i=0; $i -lt $Left.Items.Count; $i++) { Assert-PraRawDescriptorEqual $Left.Items[$i] $Right.Items[$i] $Name }
}

function Assert-PraRawExpected {
    param($Actual,$Expected)
    foreach ($field in @('ObjectGUID','DistinguishedName','CapturedUtc')) {
        if (-not [object]::Equals($Actual.$field,$Expected.$field)) { throw "Raw: creation roundtrip metadata mismatch, $field." }
    }
    if ($Actual.Attributes.Count -ne $Expected.Attributes.Count) { throw 'Raw: creation roundtrip attribute count mismatch.' }
    $names = @($Expected.Attributes.Keys); $index = 0
    foreach ($name in $Actual.Attributes.Keys) {
        if ($name -cne $names[$index]) { throw 'Raw: creation roundtrip attribute name/order mismatch.' }
        Assert-PraRawDescriptorEqual $Actual.Attributes[$name] $Expected.Attributes[$name] $name
        $index++
    }
}

function Assert-PraRawRecord {
    param($Snapshot,$Record)
    foreach ($field in @('DistinguishedName','CapturedUtc')) {
        $value = Get-PraRawMember $Record $field
        if ($null -ne $value -and -not [object]::Equals($value,$Snapshot.$field)) { throw "Raw/JSON: $field mismatch, GUID=$($Snapshot.ObjectGUID)." }
    }
    $states = Get-PraRawMember $Record 'Attributes'
    if ($null -eq $states) { return }
    $entries = if ($states -is [Collections.IDictionary]) { $states.GetEnumerator() } else { $states.PSObject.Properties }
    foreach ($entry in $entries) {
        $name = if ($states -is [Collections.IDictionary]) { $entry.Key } else { $entry.Name }
        if (-not $Snapshot.Attributes.Contains($name)) { throw "Raw/JSON: attribute not captured, $name." }
        $state = $entry.Value; $descriptor = $Snapshot.Attributes[$name]
        $present = $descriptor.Kind -cne 'Null' -and
            -not ($descriptor.Kind -ceq 'Collection' -and $descriptor.Items.Count -eq 0) -and
            -not ($descriptor.Kind -ceq 'Binary' -and $descriptor.Value.Length -eq 0) -and
            -not ($descriptor.Kind -ceq 'Scalar' -and $descriptor.Type -ceq 'String' -and $descriptor.Value.Length -eq 0)
        $storedPresent = Get-PraRawMember $state 'Present'
        if ($storedPresent -isnot [bool] -or $storedPresent -ne $present) { throw "Raw/JSON: presence mismatch, attribute=$name." }
        $stored = Get-PraRawMember $state 'Value'; $kind = Get-PraRawMember $state 'Kind'
        if (-not $present) {
            if ($null -ne $stored) { throw "Raw/JSON: absent value mismatch, attribute=$name." }
            continue
        }
        if ($kind -ceq 'MultiString') {
            $values = [Collections.Generic.List[string]]::new()
            $items = if ($descriptor.Kind -ceq 'Collection') { $descriptor.Items } else { ,$descriptor }
            foreach ($item in $items) {
                if ($item.Kind -cne 'Scalar' -or $item.Type -cne 'String') { throw "Raw/JSON: MultiString type mismatch, $name." }
                $values.Add($item.Value)
            }
            $actual = @($values | Sort-Object -CaseSensitive); $expected = @($stored | Sort-Object -CaseSensitive)
            if ($actual.Count -ne $expected.Count) { throw "Raw/JSON: MultiString count mismatch, $name." }
            for ($i=0; $i -lt $actual.Count; $i++) {
                if (-not [object]::Equals($actual[$i],$expected[$i])) { throw "Raw/JSON: MultiString value mismatch, $name." }
            }
            continue
        }
        $scalar = $descriptor
        if ($scalar.Kind -ceq 'Collection' -and $scalar.Items.Count -eq 1) { $scalar = $scalar.Items[0] }
        $actual = $null
        switch -CaseSensitive ($kind) {
            'Bytes' { if ($descriptor.Kind -ceq 'Binary') { $actual = $descriptor.Value } }
            'String' { if ($scalar.Kind -ceq 'Scalar' -and $scalar.Type -ceq 'String') { $actual = $scalar.Value } }
            'Bool' { if ($scalar.Kind -ceq 'Scalar' -and $scalar.Type -ceq 'Boolean') { $actual = $scalar.Value -ceq 'true' } }
            { $_ -cin @('Int','Long') } {
                if ($scalar.Kind -ceq 'Scalar' -and $scalar.Type -cin @('SByte','Byte','Int16','UInt16','Int32','UInt32','Int64','UInt64','String')) {
                    $actual = ([int64]::Parse($scalar.Value,$script:PraRawCulture)).ToString($script:PraRawCulture)
                    if ($kind -ceq 'Int') { $null = [int32]::Parse($actual,$script:PraRawCulture) }
                }
            }
            default { throw "Raw/JSON: unknown restoration kind, attribute=$name." }
        }
        if ($null -eq $actual -or -not [object]::Equals($actual,$stored)) { throw "Raw/JSON: typed value mismatch, attribute=$name." }
    }
    $usn = Get-PraRawMember $Record 'CapturedUsnChanged'
    if ($null -ne $usn) {
        $descriptor = $Snapshot.Attributes['uSNChanged']
        if ($null -eq $descriptor -or $descriptor.Kind -cne 'Scalar' -or $descriptor.Value -cne $usn) { throw 'Raw/JSON: uSNChanged mismatch.' }
    }
}

function Skip-PraLegacyValue {
    param([Xml.XmlReader]$Reader)
    $null = $Reader.MoveToContent(); $depth = $Reader.Depth
    if ($Reader.NodeType -ne [Xml.XmlNodeType]::Element) { throw 'Legacy CLIXML: expected value.' }
    $allowed = @('Obj','Ref','TN','TNRef','T','ToString','Props','MS','LST','IE','QUE','STK','DCT','En',
        'Nil','S','C','B','SB','By','I16','U16','I32','U32','I64','U64','Sg','Db','D','DT','TS','G','URI','Version','BA','SS','XD','SBK')
    while ($true) {
        if ($Reader.Depth -gt 256) { throw 'Legacy CLIXML: XML depth exceeds 256; no graph inflation fallback.' }
        if ($Reader.NodeType -eq [Xml.XmlNodeType]::Element) {
            if ($Reader.NamespaceURI -cne $script:PraRawNamespace -or $Reader.LocalName -cnotin $allowed) { throw 'Legacy CLIXML: unsupported XML node.' }
            if ($Reader.LocalName -ceq 'BA') {
                $buffer = [byte[]]::new(4096)
                while ($Reader.ReadElementContentAsBase64($buffer,0,$buffer.Length) -gt 0) { }
                if ($Reader.Depth -le $depth) { return }
                continue
            }
            if ($Reader.Depth -eq $depth -and $Reader.IsEmptyElement) { $null = $Reader.Read(); return }
        } elseif ($Reader.NodeType -eq [Xml.XmlNodeType]::EndElement -and $Reader.Depth -eq $depth) {
            $null = $Reader.Read(); return
        }
        if (-not $Reader.Read()) { throw 'Legacy CLIXML: truncated value.' }
    }
}

function Add-PraRawIdentity {
    param([hashtable]$State,[string]$Guid)
    $key = ([guid]::Parse($Guid)).ToString('D')
    if ($key -ceq [guid]::Empty.ToString('D') -or -not $State.Records.ContainsKey($key) -or -not $State.Seen.Add($key)) {
        throw "Raw/JSON: unexpected/duplicate logical user GUID=$key."
    }
    $State.Guids.Add($key)
}

function Read-PraLegacyReference {
    param([hashtable]$State)
    $reader = $State.Reader
    Assert-PraRawXmlStart $reader 'Ref' @('RefId','N')
    $id = $reader.GetAttribute('RefId')
    if ($null -eq $id -or -not $State.Identities.ContainsKey($id)) {
        throw 'Legacy CLIXML: identity reference cannot be proven without graph inflation; rejected.'
    }
    if (-not $reader.IsEmptyElement) { throw 'Legacy CLIXML: nonempty identity reference.' }
    $null = $reader.Read()
    return $State.Identities[$id]
}

function Read-PraLegacyObject {
    param([hashtable]$State,[bool]$AllowWrapper)
    $reader = $State.Reader
    Assert-PraRawXmlStart $reader 'Obj' @('RefId','N')
    $refId = $reader.GetAttribute('RefId')
    if ($null -eq $refId -or $refId -cnotmatch '^(0|[1-9][0-9]*)$' -or $reader.IsEmptyElement) { throw 'Legacy CLIXML: invalid logical object.' }
    $reader.ReadStartElement(); $guid = $null; $wrapper = $false; $members = $false
    while ($reader.MoveToContent() -eq [Xml.XmlNodeType]::Element) {
        switch -CaseSensitive ($reader.LocalName) {
            { $_ -cin @('TN','TNRef','ToString') } { Skip-PraLegacyValue $reader }
            'LST' {
                if (-not $AllowWrapper -or $wrapper -or $members) { throw 'Legacy CLIXML: ambiguous/nested user wrapper.' }
                $wrapper = $true; Read-PraRawStart $reader 'LST'
                while ($reader.MoveToContent() -eq [Xml.XmlNodeType]::Element) {
                    if ($reader.LocalName -ceq 'Ref') { Add-PraRawIdentity $State (Read-PraLegacyReference $State) }
                    elseif ($reader.LocalName -ceq 'Obj') { $null = Read-PraLegacyObject $State $false }
                    else { throw 'Legacy CLIXML: non-object logical user in wrapper.' }
                }
                Read-PraRawEnd $reader 'LST'
            }
            { $_ -cin @('Props','MS') } {
                if ($wrapper) { throw 'Legacy CLIXML: wrapper also has user properties.' }
                $members = $true; $container = $reader.LocalName
                Assert-PraRawXmlStart $reader $container
                if ($reader.IsEmptyElement) { $reader.ReadStartElement(); continue }
                $reader.ReadStartElement()
                while ($reader.MoveToContent() -eq [Xml.XmlNodeType]::Element) {
                    $name = ConvertFrom-PraRawString ([string]$reader.GetAttribute('N'))
                    if ($name -ieq 'ObjectGUID') {
                        if ($null -ne $guid) { throw 'Legacy CLIXML: duplicate direct ObjectGUID.' }
                        if ($reader.LocalName -ceq 'G') {
                            Assert-PraRawXmlStart $reader 'G' @('N')
                            $guid = ([guid]::Parse($reader.ReadElementContentAsString())).ToString('D')
                        } elseif ($reader.LocalName -ceq 'Ref') { $guid = Read-PraLegacyReference $State }
                        else { throw 'Legacy CLIXML: identity is not a direct typed GUID or provable reference; rejected.' }
                    } else { Skip-PraLegacyValue $reader }
                }
                Read-PraRawEnd $reader $container
            }
            default { throw 'Legacy CLIXML: unrecognized logical user/wrapper structure.' }
        }
    }
    Read-PraRawEnd $reader 'Obj'
    if (-not $wrapper) {
        if ($null -eq $guid) { throw 'Legacy CLIXML: logical user has no direct ObjectGUID; nested ACL GUIDs do not count.' }
        if ($State.Identities.ContainsKey($refId)) { throw 'Legacy CLIXML: ambiguous logical RefId.' }
        $State.Identities[$refId] = $guid
        Add-PraRawIdentity $State $guid
    }
    return $wrapper
}

function Test-PraRawCapture {
    <# .SYNOPSIS
    Streams to EOF, validates the closed codec or legacy logical identities, returns only a receipt.
    .DESCRIPTION
    ExpectedSnapshots adds lossless creation-time comparison. Records.Attributes is independently
    compared to the typed restoration JSON. Legacy never deserializes or inflates a native graph.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Context,[Parameter(Mandatory)][string]$LiteralPath,
        [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Records,
        [Parameter(Mandatory)][AllowEmptyString()][string]$RawFormat,
        [AllowEmptyCollection()][object[]]$ExpectedSnapshots)
    if ($RawFormat -cnotin @('',$script:PraRawFormat)) { throw "Raw: unsupported format '$RawFormat'." }
    if ($Records.Count -eq 0) { throw 'Raw: empty Records.' }
    $recordMap = @{}; $expectedMap = @{}
    foreach ($record in $Records) {
        $key = ([guid]::Parse([string](Get-PraRawMember $record 'ObjectGUID'))).ToString('D')
        if ($key -ceq [guid]::Empty.ToString('D') -or $recordMap.ContainsKey($key)) { throw 'Raw: invalid/duplicate JSON GUID.' }
        $recordMap[$key] = $record
    }
    $compare = $PSBoundParameters.ContainsKey('ExpectedSnapshots')
    if ($compare) {
        if ($RawFormat -ceq '' -or $ExpectedSnapshots.Count -ne $Records.Count) { throw 'Raw: ExpectedSnapshots format/cardinality mismatch.' }
        foreach ($snapshot in $ExpectedSnapshots) {
            Assert-PraRawSnapshot $snapshot
            if ($expectedMap.ContainsKey($snapshot.ObjectGUID) -or -not $recordMap.ContainsKey($snapshot.ObjectGUID)) { throw 'Raw: duplicate/unexpected expected GUID.' }
            $expectedMap[$snapshot.ObjectGUID] = $snapshot
        }
    }
    $path = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($LiteralPath)
    $stream = [IO.FileStream]::new($path,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read,65536)
    $reader = $null
    try {
        $settings = [Xml.XmlReaderSettings]::new(); $settings.DtdProcessing = [Xml.DtdProcessing]::Prohibit
        $settings.XmlResolver = $null; $settings.CloseInput = $false; $settings.IgnoreWhitespace = $false
        $settings.CheckCharacters = $true; $settings.ConformanceLevel = [Xml.ConformanceLevel]::Document
        $reader = [Xml.XmlReader]::Create($stream,$settings)
        Assert-PraRawXmlStart $reader 'Objs' @('Version')
        if ($reader.GetAttribute('Version') -cne '1.1.0.1' -or $reader.IsEmptyElement) { throw 'Raw: invalid/empty CLIXML root.' }
        $reader.ReadStartElement()
        $state = @{Reader=$reader; RefId=[int64]0; Records=$recordMap; Guids=[Collections.Generic.List[string]]::new();
            Seen=[Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal); Identities=@{}}
        $wrapper = $false; $topCount = 0
        while ($reader.MoveToContent() -eq [Xml.XmlNodeType]::Element) {
            if ($RawFormat -ceq $script:PraRawFormat) {
                $snapshot = Read-PraRawSnapshot $state
                Add-PraRawIdentity $state $snapshot.ObjectGUID
                Assert-PraRawRecord $snapshot $recordMap[$snapshot.ObjectGUID]
                if ($compare) { Assert-PraRawExpected $snapshot $expectedMap[$snapshot.ObjectGUID] }
                Write-PraRawProgress $Context $snapshot $stream.Position 'READ VERIFIED'
                $snapshot = $null
            } else {
                if ($wrapper) { throw 'Legacy CLIXML: wrapper mixed with root sequence.' }
                if ($reader.LocalName -ceq 'Ref') { Add-PraRawIdentity $state (Read-PraLegacyReference $state) }
                else { $wrapper = Read-PraLegacyObject $state ($topCount -eq 0) }
                $topCount++
            }
        }
        Read-PraRawEnd $reader 'Objs'
        # Reading past the root is essential: reject a truncated/malformed trailing document.
        $null = $reader.MoveToContent()
        if (-not $reader.EOF) { throw 'Raw: trailing XML content.' }
        if ($state.Guids.Count -ne $Records.Count) { throw 'Raw/JSON: logical user count mismatch.' }
        return [pscustomobject]@{Count=$state.Guids.Count; ObjectGuids=[string[]]$state.Guids.ToArray();
            Format=$RawFormat; Bytes=[int64]$stream.Length}
    } finally {
        try { if ($null -ne $reader) { $reader.Dispose() } } finally { $stream.Dispose() }
    }
}

Export-ModuleMember -Function ConvertTo-PraRawSnapshot,Write-PraRawCapture,Test-PraRawCapture

# SIG # Begin signature block
# MIIghgYJKoZIhvcNAQcCoIIgdzCCIHMCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCBg1436t7I8BK3A
# vBE8oE2z5dhzZURSP3+b7zd6V08y2aCCDW8wggZyMIIEWqADAgECAghkM1HTxzif
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
# AQQBgjcCAQsxDjAMBgorBgEEAYI3AgEVMC8GCSqGSIb3DQEJBDEiBCDn8w1u79fq
# RgZi1oiwfplz2kor7AtDtBHZ2zP3pbER/zANBgkqhkiG9w0BAQEFAASCAgBgwv89
# GD4VCS8ngAMZOlOkYtovjrsYhITiZFYpYUpfnII2o2yzpP5ZPUpJxavDko/mOkLP
# iwJG1NpmjZO7kTZCfmB1XHIjXupebHPV83ZPoL4O8CW6Zres5Sy9XwsQ56KQgiyl
# 5v8sCtLuCTyXYW5sTguorRIB1JsYR9S4gqrXNnls4W+WF+lj77PB7YNUZN81BPky
# FoSbDSdjGF+nQaDOviHHKLBb79Eul3Yjbsh85NMxvTlfy1BWpYJlZKsVd9A03gNW
# XULGy1WwxFlCNA8+kx0LgJygayqL8m1lhmZgK/kaVpT0nGPw3MbyqLJG9kfnl8RR
# 2mxdZ/uRS2CvuHAdKXiPw8/GbRXcC+G3sbQCTLPRoXs6C2C0N8jQvIPN/J56ltt2
# Id/QTrcGFCP+XMon0OT1YlxwcJAA3ajplZv8IOT/BNKq5y/fpPSGGAVgV10dHdFU
# btQIHQI4xHpFzKSX9jchQbPo+H0mBdy02rKNyvlMSyGaZymRrguNpfaEv8rcAD38
# VL/TgVY085eNayM5/cEWrrW5X8nCGn3aWavkQE5QGSQ8A/CT3X+kH9tJ/i1exPRq
# /fIOhzpPABFLe3IsuZTz6YaZetIpenhJ42nzVEX8hhBpUv9yGF7zi5KRYdIoucXx
# MiQlxVSap0m6POUjADCTj+tpQVhc1xk3yH4HC6GCDyowgg8mBgorBgEEAYI3AwMB
# MYIPFjCCDxIGCSqGSIb3DQEHAqCCDwMwgg7/AgEDMQ0wCwYJYIZIAWUDBAIBMIGJ
# BgsqhkiG9w0BCRABBKB6BHgwdgIBAQYMKwYBBAGCqTABAwYBMDEwDQYJYIZIAWUD
# BAIBBQAEIES79wxrMjSBsHfQ/Y9w9eP+GSDg0LfGcDTzl+p7I7PBAggfOMFh4A1M
# VxgPMjAyNjEwMTUyMTIzMDZaMAMCAQECEAcp0UEVAQcEdy9EUxkP4HSgggwAMIIE
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
# HAYJKoZIhvcNAQkFMQ8XDTI2MTAxNTIxMjMwNlowKAYJKoZIhvcNAQk0MRswGTAL
# BglghkgBZQMEAgGhCgYIKoZIzj0EAwIwLwYJKoZIhvcNAQkEMSIEIASkEtuiPSNp
# S1AAsyiPgJftMQq3TruDMaxlM7le+xbxMIHJBgsqhkiG9w0BCRACLzGBuTCBtjCB
# szCBsAQgVCr5oWqNci5mEUl4iumUwYqaruWmXLNEolSa+Wx5x4swgYswd6R1MHMx
# CzAJBgNVBAYTAlVTMQ4wDAYDVQQIDAVUZXhhczEQMA4GA1UEBwwHSG91c3RvbjER
# MA8GA1UECgwIU1NMIENvcnAxLzAtBgNVBAMMJlNTTC5jb20gVGltZXN0YW1waW5n
# IElzc3VpbmcgUlNBIENBIFIxAhAfaxZi0i4bbF3xwMGgYA44MAoGCCqGSM49BAMC
# BEgwRgIhAO0b3IeoiG2PfDI5ICIV+rQ2N318gQVC6y1kUL9GY4iAAiEA04f2VzCx
# URKtCd9/ddG7j7YEeEmyQJBWD+xvw2XO9Zw=
# SIG # End signature block
