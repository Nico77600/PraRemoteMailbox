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
    Version : 2.1.0 (format PraDataOnlyClixml-v1, unchanged since 1.3.3)
#>
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

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
