#Requires -Version 7.5
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
    Version : 3.1.4 (format PraDataOnlyClixml-v1)
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
    if (-not [string]::Equals([string]$signature.Status, 'Valid', [StringComparison]::Ordinal) -or $null -eq $signature.SignerCertificate -or
        -not [string]::Equals([string]$signature.SignerCertificate.Thumbprint, '0F28E442889F17B5F4D251E8F96E7CC6E2C9C6D6', [StringComparison]::Ordinal) -or
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
# Closed vocabularies of the codec. On .NET with ICU every culture-sensitive comparison (the PowerShell comparison operators, switch, ...) ignores
# zero-weight characters, so "Binary<U+0001>" would equal "Binary". Wire and JSON values are therefore compared with explicit ORDINAL comparers only:
# [string]::Equals(a, b, [StringComparison]::Ordinal) or the ordinal sets below. A value accepted by a set IS one of the literals, byte for byte.
$script:PraRawCollectionTypes = [Collections.Generic.HashSet[string]]::new([string[]]@('System.Collections.ArrayList',
    'System.Collections.Specialized.StringCollection','Microsoft.ActiveDirectory.Management.ADPropertyValueCollection'), [StringComparer]::Ordinal)
$script:PraRawClrTypes = [Collections.Generic.Dictionary[string,string]]::new([StringComparer]::Ordinal)
foreach ($pair in @('System.String=String','System.Boolean=Boolean','System.Char=Char','System.SByte=Integer','System.Byte=Integer','System.Int16=Integer',
    'System.UInt16=Integer','System.Int32=Integer','System.UInt32=Integer','System.Int64=Integer','System.UInt64=Integer','System.Single=Float',
    'System.Double=Float','System.Decimal=Decimal','System.DateTime=DateTime','System.DateTimeOffset=DateTimeOffset','System.TimeSpan=TimeSpan',
    'System.Guid=Guid','System.Security.Principal.SecurityIdentifier=Sid','System.Byte[]=Bytes')) {
    $script:PraRawClrTypes.Add($pair.Substring(0, $pair.IndexOf('=', [StringComparison]::Ordinal)), $pair.Substring($pair.IndexOf('=', [StringComparison]::Ordinal) + 1))
}
$script:PraRawBinaryScalarTypes = [Collections.Generic.HashSet[string]]::new([string[]]@('Single','Double','SID'), [StringComparer]::Ordinal)
$script:PraRawScalarTypes = [Collections.Generic.HashSet[string]]::new([string[]]@('String','Boolean','Char','SByte','Byte','Int16','UInt16','Int32','UInt32',
    'Int64','UInt64','Guid','TimeSpan','DateTime','DateTimeOffset','Decimal'), [StringComparer]::Ordinal)
$script:PraRawIntegerTypes = [Collections.Generic.HashSet[string]]::new([string[]]@('SByte','Byte','Int16','UInt16','Int32','UInt32','Int64','UInt64','String'), [StringComparer]::Ordinal)
$script:PraRawRestoreKinds = [Collections.Generic.HashSet[string]]::new([string[]]@('Bytes','String','Bool','Int','Long'), [StringComparer]::Ordinal)
$script:PraLegacyElementNames = [Collections.Generic.HashSet[string]]::new([string[]]@('Obj','Ref','TN','TNRef','T','ToString','Props','MS','LST','IE','QUE','STK','DCT','En',
    'Nil','S','C','B','SB','By','I16','U16','I32','U32','I64','U64','Sg','Db','D','DT','TS','G','URI','Version','BA','SS','XD','SBK'), [StringComparer]::Ordinal)
$script:PraLegacySkipNames = [Collections.Generic.HashSet[string]]::new([string[]]@('TN','TNRef','ToString'), [StringComparer]::Ordinal)
$script:PraLegacyMemberNames = [Collections.Generic.HashSet[string]]::new([string[]]@('Props','MS'), [StringComparer]::Ordinal)

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
    return ($Name -cmatch '^System\.[A-Za-z0-9_.+`\[\], =-]+\[\]\z' -or
        $script:PraRawCollectionTypes.Contains($Name) -or
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
    # The CLR full name is mapped to a closed token through an ordinal dictionary; the switch only ever sees our own tokens.
    $clrToken = $null
    $null = $script:PraRawClrTypes.TryGetValue([string]$name, [ref]$clrToken)
    switch -CaseSensitive ($clrToken) {
        'String' { $result.Value = $Value; return ,$result }
        'Boolean' { $result.Value = if ($Value) { 'true' } else { 'false' }; return ,$result }
        'Char' { $result.Value = ([uint16][char]$Value).ToString($script:PraRawCulture); return ,$result }
        'Integer' {
            $result.Value = $Value.ToString($script:PraRawCulture); return ,$result
        }
        'Float' {
            $bytes = [BitConverter]::GetBytes($Value)
            if (-not [BitConverter]::IsLittleEndian) { [array]::Reverse($bytes) }
            $result.Value = [Convert]::ToBase64String($bytes); return ,$result
        }
        'Decimal' {
            $parts = [Collections.Generic.List[string]]::new()
            foreach ($part in [decimal]::GetBits($Value)) { $parts.Add($part.ToString($script:PraRawCulture)) }
            $result.Value = $parts -join '|'; return ,$result
        }
        'DateTime' { $result.Value = $Value.ToBinary().ToString($script:PraRawCulture); return ,$result }
        'DateTimeOffset' {
            $result.Value = $Value.Ticks.ToString($script:PraRawCulture) + '|' + $Value.Offset.Ticks.ToString($script:PraRawCulture)
            return ,$result
        }
        'TimeSpan' { $result.Value = $Value.Ticks.ToString($script:PraRawCulture); return ,$result }
        'Guid' { $result.Value = $Value.ToString('D'); return ,$result }
        'Sid' {
            $bytes = [byte[]]::new($Value.BinaryLength); $Value.GetBinaryForm($bytes,0)
            $result.Type = 'SID'; $result.Value = [Convert]::ToBase64String($bytes); return ,$result
        }
        'Bytes' {
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
    } elseif (Test-PraRawCollectionType $name) {
        # The closed list of full type names is the filter. There is no assembly list on purpose: the same type lives in
        # mscorlib / System under Windows PowerShell 5.1 and in System.Private.CoreLib / System.Collections.* under .NET.
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
        elseif ([string]::Equals($User.GetType().FullName, 'Microsoft.ActiveDirectory.Management.ADUser', [StringComparison]::Ordinal)) { $User.PropertyNames }
        else { $User.PSObject.Properties.Name }
    foreach ($name in $names) {
        if ($name -isnot [string] -or [string]::IsNullOrEmpty($name) -or $attributes.Contains($name)) {
            throw "Raw capture: invalid/duplicate attribute name, GUID=$key."
        }
        $value = $null
        try {
            # Direct assignment preserves null/empty/nested arrays and reads each getter once.
            if ([string]::Equals($name, 'ObjectGUID', [StringComparison]::OrdinalIgnoreCase)) { $value = $identity }
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
    if ($null -eq $dn -or -not [string]::Equals($dn.Kind, 'Scalar', [StringComparison]::Ordinal) -or -not [string]::Equals($dn.Type, 'String', [StringComparison]::Ordinal)) {
        throw "Raw capture: DistinguishedName must be a captured string, GUID=$key."
    }
    $snapshot = [pscustomobject][ordered]@{ ObjectGUID=$key; DistinguishedName=$dn.Value; CapturedUtc=$CapturedUtc; Attributes=$attributes }
    Assert-PraRawSnapshot $snapshot
    return $snapshot
}

function Assert-PraRawScalar {
    param([string]$Kind,[string]$Type,[AllowNull()]$Value)
    if ([string]::Equals($Kind, 'Null', [StringComparison]::Ordinal)) {
        if (-not [string]::Equals($Type, '', [StringComparison]::Ordinal) -or $null -ne $Value) { throw 'Raw: invalid null descriptor.' }
        return
    }
    if ([string]::Equals($Kind, 'Collection', [StringComparison]::Ordinal)) {
        if ($null -ne $Value -or -not (Test-PraRawCollectionType $Type)) { throw 'Raw: invalid collection descriptor.' }
        return
    }
    if ($Value -isnot [string]) { throw 'Raw: descriptor Value must be a string.' }
    if ([string]::Equals($Kind, 'Binary', [StringComparison]::Ordinal) -or [string]::Equals($Kind, 'SecurityDescriptor', [StringComparison]::Ordinal) -or
        ([string]::Equals($Kind, 'Scalar', [StringComparison]::Ordinal) -and $script:PraRawBinaryScalarTypes.Contains($Type))) {
        $bytes = [Convert]::FromBase64String($Value)
        if (-not [string]::Equals([Convert]::ToBase64String($bytes), $Value, [StringComparison]::Ordinal)) { throw 'Raw: noncanonical Base64.' }
        if ([string]::Equals($Kind, 'Binary', [StringComparison]::Ordinal)) {
            if (-not [string]::Equals($Type, 'Byte[]', [StringComparison]::Ordinal)) { throw 'Raw: invalid binary type.' }
        } elseif ([string]::Equals($Kind, 'SecurityDescriptor', [StringComparison]::Ordinal)) {
            if ($Type -notmatch '^System\.(Security\.AccessControl|DirectoryServices)\.[A-Za-z]+(Security|SecurityDescriptor)\z') {
                throw 'Raw: invalid security descriptor type.'
            }
            $security = [Security.AccessControl.RawSecurityDescriptor]::new($bytes,0)
            $copy = [byte[]]::new($security.BinaryLength); $security.GetBinaryForm($copy,0)
            if (-not [string]::Equals([Convert]::ToBase64String($copy), $Value, [StringComparison]::Ordinal)) { throw 'Raw: security descriptor binary mismatch.' }
        } elseif ([string]::Equals($Type, 'SID', [StringComparison]::Ordinal)) {
            $sid = [Security.Principal.SecurityIdentifier]::new($bytes,0)
            $copy = [byte[]]::new($sid.BinaryLength); $sid.GetBinaryForm($copy,0)
            if (-not [string]::Equals([Convert]::ToBase64String($copy), $Value, [StringComparison]::Ordinal)) { throw 'Raw: SID binary mismatch.' }
        } elseif (([string]::Equals($Type, 'Single', [StringComparison]::Ordinal) -and $bytes.Length -ne 4) -or ([string]::Equals($Type, 'Double', [StringComparison]::Ordinal) -and $bytes.Length -ne 8)) {
            throw 'Raw: invalid IEEE754 width.'
        }
        return
    }
    if (-not [string]::Equals($Kind, 'Scalar', [StringComparison]::Ordinal)) { throw 'Raw: unknown descriptor kind.' }
    $canonical = $Value
    # Ordinal membership first: after it, $Type is exactly one of the literals below, so the switch cannot match a look-alike.
    if (-not $script:PraRawScalarTypes.Contains($Type)) { throw "Raw: unknown scalar type '$Type'." }
    switch -CaseSensitive ($Type) {
        'String' { return }
        'Boolean' { if (-not ([string]::Equals($Value, 'true', [StringComparison]::Ordinal) -or [string]::Equals($Value, 'false', [StringComparison]::Ordinal))) { throw 'Raw: invalid Boolean.' }; return }
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
    if (-not [string]::Equals($canonical, $Value, [StringComparison]::Ordinal)) { throw "Raw: noncanonical $Type value." }
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
    if (-not [string]::Equals($Descriptor.Kind, 'Collection', [StringComparison]::Ordinal) -and $Descriptor.Items.Count -ne 0) { throw 'Raw: scalar has children.' }
    foreach ($item in $Descriptor.Items) { Assert-PraRawDescriptor $item ($Depth+1) $Budget }
}

function Assert-PraRawSnapshot {
    param($Snapshot)
    if ($Snapshot -isnot [pscustomobject] -or @($Snapshot.PSObject.Properties).Count -ne 4) { throw 'Raw: invalid snapshot shape.' }
    foreach ($field in @('ObjectGUID','DistinguishedName','CapturedUtc')) {
        if ((Get-PraRawMember $Snapshot $field) -isnot [string]) { throw "Raw: invalid snapshot $field." }
    }
    $guid = [guid]::Parse($Snapshot.ObjectGUID)
    if ($guid -eq [guid]::Empty -or -not [string]::Equals($guid.ToString('D'), $Snapshot.ObjectGUID, [StringComparison]::Ordinal)) { throw 'Raw: invalid snapshot GUID.' }
    if ([string]::IsNullOrWhiteSpace($Snapshot.CapturedUtc)) { throw 'Raw: empty CapturedUtc.' }
    $null = [datetimeoffset]::Parse($Snapshot.CapturedUtc,$script:PraRawCulture)
    if ($Snapshot.Attributes -isnot [Collections.Specialized.OrderedDictionary]) { throw 'Raw: Attributes must be an ordered dictionary.' }
    foreach ($name in $Snapshot.Attributes.Keys) {
        if ($name -isnot [string] -or [string]::IsNullOrEmpty($name)) { throw 'Raw: invalid attribute name.' }
        try { Assert-PraRawDescriptor $Snapshot.Attributes[$name] }
        catch { throw "Raw: attribute=$name GUID=$($Snapshot.ObjectGUID). $($_.Exception.Message)" }
    }
    $id = $Snapshot.Attributes['ObjectGUID']; $dn = $Snapshot.Attributes['DistinguishedName']
    if ($null -eq $id -or -not [string]::Equals($id.Kind, 'Scalar', [StringComparison]::Ordinal) -or
        -not ([string]::Equals($id.Type, 'Guid', [StringComparison]::Ordinal) -or [string]::Equals($id.Type, 'String', [StringComparison]::Ordinal)) -or
        -not [string]::Equals(([guid]::Parse($id.Value)).ToString('D'), $Snapshot.ObjectGUID, [StringComparison]::Ordinal)) { throw 'Raw: metadata/attribute ObjectGUID mismatch.' }
    if ($null -eq $dn -or -not [string]::Equals($dn.Kind, 'Scalar', [StringComparison]::Ordinal) -or -not [string]::Equals($dn.Type, 'String', [StringComparison]::Ordinal) -or
        -not [string]::Equals($dn.Value, $Snapshot.DistinguishedName, [StringComparison]::Ordinal)) {
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
    if (-not [string]::Equals($Tag, 'Nil', [StringComparison]::Ordinal)) { Write-PraRawString $State.Writer $Value }
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
    if ($null -ne $sam -and [string]::Equals($sam.Kind, 'Scalar', [StringComparison]::Ordinal) -and [string]::Equals($sam.Type, 'String', [StringComparison]::Ordinal)) { $name = $sam.Value }
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
                $value = if ([string]::Equals($field, 'RawFormat', [StringComparison]::Ordinal)) { $script:PraRawFormat } else { $snapshot.$field }
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
    if ($Reader.NodeType -ne [Xml.XmlNodeType]::Element -or -not [string]::Equals($Reader.LocalName, $Tag, [StringComparison]::Ordinal) -or
        -not [string]::Equals($Reader.NamespaceURI, $script:PraRawNamespace, [StringComparison]::Ordinal)) {
        throw "Raw XML: expected $Tag, found $($Reader.NodeType)/$($Reader.LocalName)."
    }
    if ($Reader.MoveToFirstAttribute()) {
        do {
            if ([string]::Equals($Reader.Name, 'xmlns', [StringComparison]::Ordinal) -and [string]::Equals($Tag, 'Objs', [StringComparison]::Ordinal) -and
                [string]::Equals($Reader.Value, $script:PraRawNamespace, [StringComparison]::Ordinal)) { continue }
            if (-not [string]::Equals($Reader.NamespaceURI, '', [StringComparison]::Ordinal) -or [Array]::IndexOf($Attributes, $Reader.Name) -lt 0) { throw "Raw XML: unexpected attribute $($Reader.Name)." }
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
    if ($Reader.NodeType -ne [Xml.XmlNodeType]::EndElement -or -not [string]::Equals($Reader.LocalName, $Tag, [StringComparison]::Ordinal) -or
        -not [string]::Equals($Reader.NamespaceURI, $script:PraRawNamespace, [StringComparison]::Ordinal)) {
        throw "Raw XML: expected closing $Tag."
    }
    $Reader.ReadEndElement()
}

function Read-PraRawObjectStart {
    param([hashtable]$State,[string]$Name='')
    $reader = $State.Reader
    Assert-PraRawXmlStart $reader 'Obj' @('RefId','N')
    if (-not [string]::Equals($reader.GetAttribute('RefId'), $State.RefId.ToString($script:PraRawCulture), [StringComparison]::Ordinal) -or
        -not [string]::Equals((ConvertFrom-PraRawString ([string]$reader.GetAttribute('N'))), $Name, [StringComparison]::Ordinal) -or $reader.IsEmptyElement) {
        throw 'Raw XML: object identity/name/sequence invalid; shared references are forbidden.'
    }
    $State.RefId++; $reader.ReadStartElement()
}

function Read-PraRawElement {
    param([Xml.XmlReader]$Reader,[string]$Tag,[string]$Name)
    Assert-PraRawXmlStart $Reader $Tag @('N')
    if (-not [string]::Equals((ConvertFrom-PraRawString ([string]$Reader.GetAttribute('N'))), $Name, [StringComparison]::Ordinal)) { throw "Raw XML: expected member $Name." }
    if ([string]::Equals($Tag, 'Nil', [StringComparison]::Ordinal)) {
        if (-not [string]::Equals($Reader.ReadElementContentAsString(), '', [StringComparison]::Ordinal)) { throw 'Raw XML: nonempty Nil.' }
        return $null
    }
    # One intrinsic scalar only; never materialize a snapshot XML string or the whole file.
    $value = $Reader.ReadElementContentAsString()
    if ([string]::Equals($Tag, 'S', [StringComparison]::Ordinal)) { return (ConvertFrom-PraRawString $value) }
    $number = [int]::Parse($value,$script:PraRawCulture)
    if (-not [string]::Equals($number.ToString($script:PraRawCulture), $value, [StringComparison]::Ordinal)) { throw 'Raw XML: noncanonical Int32.' }
    return $number
}

function Read-PraRawNode {
    param([hashtable]$State,[int]$Depth,[hashtable]$Budget)
    $Budget.Left--
    if ($Depth -gt $script:PraRawDepth -or $Budget.Left -lt 0) { throw 'Raw XML: descriptor depth/node limit.' }
    $reader = $State.Reader
    Read-PraRawObjectStart $State; Read-PraRawStart $reader 'MS'
    if ((-not (Test-PraOrdinalIgnoreCaseEqual (Read-PraRawElement $reader 'I32' 'Depth') $Depth))) { throw 'Raw XML: invalid descriptor preorder depth.' }
    $kind = Read-PraRawElement $reader 'S' 'Kind'; $type = Read-PraRawElement $reader 'S' 'Type'
    $null = $reader.MoveToContent(); $tag = $reader.LocalName
    if (-not ([string]::Equals($tag, 'S', [StringComparison]::Ordinal) -or [string]::Equals($tag, 'Nil', [StringComparison]::Ordinal))) { throw 'Raw XML: invalid descriptor value type.' }
    $value = Read-PraRawElement $reader $tag 'Value'; $count = Read-PraRawElement $reader 'I32' 'Count'
    if ($count -lt 0 -or $count -gt $Budget.Left -or (-not [string]::Equals($kind, 'Collection', [StringComparison]::Ordinal) -and $count -ne 0)) { throw 'Raw XML: invalid item cardinality.' }
    Read-PraRawEnd $reader 'MS'; Read-PraRawEnd $reader 'Obj'
    $items = [Collections.Generic.List[object]]::new()
    for ($i=0; $i -lt $count; $i++) { $items.Add((Read-PraRawNode $State ($Depth+1) $Budget)) }
    return ,([ordered]@{Kind=$kind; Type=$type; Value=$value; Items=[object[]]$items.ToArray()})
}

function Read-PraRawSnapshot {
    param([hashtable]$State)
    $reader = $State.Reader
    Read-PraRawObjectStart $State; Read-PraRawStart $reader 'MS'
    if (-not [string]::Equals((Read-PraRawElement $reader 'S' 'RawFormat'), $script:PraRawFormat, [StringComparison]::Ordinal)) { throw 'Raw XML: format marker mismatch.' }
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
        if (-not [string]::Equals($name, $names[$index], [StringComparison]::Ordinal)) { throw 'Raw: creation roundtrip attribute name/order mismatch.' }
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
        $present = -not [string]::Equals($descriptor.Kind, 'Null', [StringComparison]::Ordinal) -and
            -not ([string]::Equals($descriptor.Kind, 'Collection', [StringComparison]::Ordinal) -and $descriptor.Items.Count -eq 0) -and
            -not ([string]::Equals($descriptor.Kind, 'Binary', [StringComparison]::Ordinal) -and $descriptor.Value.Length -eq 0) -and
            -not ([string]::Equals($descriptor.Kind, 'Scalar', [StringComparison]::Ordinal) -and [string]::Equals($descriptor.Type, 'String', [StringComparison]::Ordinal) -and $descriptor.Value.Length -eq 0)
        $storedPresent = Get-PraRawMember $state 'Present'
        if ($storedPresent -isnot [bool] -or (-not (Test-PraOrdinalIgnoreCaseEqual $storedPresent $present))) { throw "Raw/JSON: presence mismatch, attribute=$name." }
        $stored = Get-PraRawMember $state 'Value'; $kind = Get-PraRawMember $state 'Kind'
        if (-not $present) {
            if ($null -ne $stored) { throw "Raw/JSON: absent value mismatch, attribute=$name." }
            continue
        }
        if ([string]::Equals($kind, 'MultiString', [StringComparison]::Ordinal)) {
            $values = [Collections.Generic.List[string]]::new()
            $items = if ([string]::Equals($descriptor.Kind, 'Collection', [StringComparison]::Ordinal)) { $descriptor.Items } else { ,$descriptor }
            foreach ($item in $items) {
                if (-not [string]::Equals($item.Kind, 'Scalar', [StringComparison]::Ordinal) -or -not [string]::Equals($item.Type, 'String', [StringComparison]::Ordinal)) { throw "Raw/JSON: MultiString type mismatch, $name." }
                $values.Add($item.Value)
            }
            # Ordinal order on both sides (Sort-Object uses the culture collation, which ties look-alike strings in an arbitrary order).
            $actual = $values.ToArray(); [Array]::Sort($actual, [StringComparer]::Ordinal)
            $expected = @($stored); $expectedKeys = [string[]]@($expected | ForEach-Object { [string]$_ }); [Array]::Sort([Array]$expectedKeys, [Array]$expected, [Collections.IComparer][StringComparer]::Ordinal)
            if ($actual.Count -ne $expected.Count) { throw "Raw/JSON: MultiString count mismatch, $name." }
            for ($i=0; $i -lt $actual.Count; $i++) {
                if (-not [object]::Equals($actual[$i],$expected[$i])) { throw "Raw/JSON: MultiString value mismatch, $name." }
            }
            continue
        }
        $scalar = $descriptor
        if ([string]::Equals($scalar.Kind, 'Collection', [StringComparison]::Ordinal) -and $scalar.Items.Count -eq 1) { $scalar = $scalar.Items[0] }
        $actual = $null
        # Ordinal membership first: after it, $kind is exactly one of the literals below, so the switch cannot match a look-alike.
        if ($null -eq $kind -or -not $script:PraRawRestoreKinds.Contains([string]$kind)) { throw "Raw/JSON: unknown restoration kind, attribute=$name." }
        switch -CaseSensitive ($kind) {
            'Bytes' { if ([string]::Equals($descriptor.Kind, 'Binary', [StringComparison]::Ordinal)) { $actual = $descriptor.Value } }
            'String' { if ([string]::Equals($scalar.Kind, 'Scalar', [StringComparison]::Ordinal) -and [string]::Equals($scalar.Type, 'String', [StringComparison]::Ordinal)) { $actual = $scalar.Value } }
            'Bool' { if ([string]::Equals($scalar.Kind, 'Scalar', [StringComparison]::Ordinal) -and [string]::Equals($scalar.Type, 'Boolean', [StringComparison]::Ordinal)) { $actual = [string]::Equals($scalar.Value, 'true', [StringComparison]::Ordinal) } }
            { [string]::Equals($_, 'Int', [StringComparison]::Ordinal) -or [string]::Equals($_, 'Long', [StringComparison]::Ordinal) } {
                if ([string]::Equals($scalar.Kind, 'Scalar', [StringComparison]::Ordinal) -and $script:PraRawIntegerTypes.Contains($scalar.Type)) {
                    $actual = ([int64]::Parse($scalar.Value,$script:PraRawCulture)).ToString($script:PraRawCulture)
                    if ([string]::Equals($kind, 'Int', [StringComparison]::Ordinal)) { $null = [int32]::Parse($actual,$script:PraRawCulture) }
                }
            }
            default { throw "Raw/JSON: unknown restoration kind, attribute=$name." }
        }
        if ($null -eq $actual -or -not [object]::Equals($actual,$stored)) { throw "Raw/JSON: typed value mismatch, attribute=$name." }
    }
    $usn = Get-PraRawMember $Record 'CapturedUsnChanged'
    if ($null -ne $usn) {
        $descriptor = $Snapshot.Attributes['uSNChanged']
        if ($null -eq $descriptor -or -not [string]::Equals($descriptor.Kind, 'Scalar', [StringComparison]::Ordinal) -or -not [string]::Equals($descriptor.Value, $usn, [StringComparison]::Ordinal)) { throw 'Raw/JSON: uSNChanged mismatch.' }
    }
}

function Skip-PraLegacyValue {
    param([Xml.XmlReader]$Reader)
    $null = $Reader.MoveToContent(); $depth = $Reader.Depth
    if ($Reader.NodeType -ne [Xml.XmlNodeType]::Element) { throw 'Legacy CLIXML: expected value.' }
    while ($true) {
        if ($Reader.Depth -gt 256) { throw 'Legacy CLIXML: XML depth exceeds 256; no graph inflation fallback.' }
        if ($Reader.NodeType -eq [Xml.XmlNodeType]::Element) {
            if (-not [string]::Equals($Reader.NamespaceURI, $script:PraRawNamespace, [StringComparison]::Ordinal) -or -not $script:PraLegacyElementNames.Contains($Reader.LocalName)) { throw 'Legacy CLIXML: unsupported XML node.' }
            if ([string]::Equals($Reader.LocalName, 'BA', [StringComparison]::Ordinal)) {
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
    if ([string]::Equals($key, [guid]::Empty.ToString('D'), [StringComparison]::Ordinal) -or -not $State.Records.ContainsKey($key) -or -not $State.Seen.Add($key)) {
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
    if ($null -eq $refId -or $refId -cnotmatch '^(0|[1-9][0-9]*)\z' -or $reader.IsEmptyElement) { throw 'Legacy CLIXML: invalid logical object.' }
    $reader.ReadStartElement(); $guid = $null; $wrapper = $false; $members = $false
    while ($reader.MoveToContent() -eq [Xml.XmlNodeType]::Element) {
        # The element name is mapped to a closed token with ordinal comparers; the switch only ever sees our own tokens.
        $localName = $reader.LocalName
        $legacyToken = if ($script:PraLegacySkipNames.Contains($localName)) { 'Skip' }
            elseif ([string]::Equals($localName, 'LST', [StringComparison]::Ordinal)) { 'LST' }
            elseif ($script:PraLegacyMemberNames.Contains($localName)) { 'Members' }
            else { '' }
        switch -CaseSensitive ($legacyToken) {
            'Skip' { Skip-PraLegacyValue $reader }
            'LST' {
                if (-not $AllowWrapper -or $wrapper -or $members) { throw 'Legacy CLIXML: ambiguous/nested user wrapper.' }
                $wrapper = $true; Read-PraRawStart $reader 'LST'
                while ($reader.MoveToContent() -eq [Xml.XmlNodeType]::Element) {
                    if ([string]::Equals($reader.LocalName, 'Ref', [StringComparison]::Ordinal)) { Add-PraRawIdentity $State (Read-PraLegacyReference $State) }
                    elseif ([string]::Equals($reader.LocalName, 'Obj', [StringComparison]::Ordinal)) { $null = Read-PraLegacyObject $State $false }
                    else { throw 'Legacy CLIXML: non-object logical user in wrapper.' }
                }
                Read-PraRawEnd $reader 'LST'
            }
            'Members' {
                if ($wrapper) { throw 'Legacy CLIXML: wrapper also has user properties.' }
                $members = $true; $container = $reader.LocalName
                Assert-PraRawXmlStart $reader $container
                if ($reader.IsEmptyElement) { $reader.ReadStartElement(); continue }
                $reader.ReadStartElement()
                while ($reader.MoveToContent() -eq [Xml.XmlNodeType]::Element) {
                    $name = ConvertFrom-PraRawString ([string]$reader.GetAttribute('N'))
                    if ([string]::Equals($name, 'ObjectGUID', [StringComparison]::OrdinalIgnoreCase)) {
                        if ($null -ne $guid) { throw 'Legacy CLIXML: duplicate direct ObjectGUID.' }
                        if ([string]::Equals($reader.LocalName, 'G', [StringComparison]::Ordinal)) {
                            Assert-PraRawXmlStart $reader 'G' @('N')
                            $guid = ([guid]::Parse($reader.ReadElementContentAsString())).ToString('D')
                        } elseif ([string]::Equals($reader.LocalName, 'Ref', [StringComparison]::Ordinal)) { $guid = Read-PraLegacyReference $State }
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
    if (-not ([string]::Equals($RawFormat, '', [StringComparison]::Ordinal) -or [string]::Equals($RawFormat, $script:PraRawFormat, [StringComparison]::Ordinal))) { throw "Raw: unsupported format '$RawFormat'." }
    if ($Records.Count -eq 0) { throw 'Raw: empty Records.' }
    $recordMap = @{}; $expectedMap = @{}
    foreach ($record in $Records) {
        $key = ([guid]::Parse([string](Get-PraRawMember $record 'ObjectGUID'))).ToString('D')
        if ([string]::Equals($key, [guid]::Empty.ToString('D'), [StringComparison]::Ordinal) -or $recordMap.ContainsKey($key)) { throw 'Raw: invalid/duplicate JSON GUID.' }
        $recordMap[$key] = $record
    }
    $compare = $PSBoundParameters.ContainsKey('ExpectedSnapshots')
    if ($compare) {
        if ([string]::Equals($RawFormat, '', [StringComparison]::Ordinal) -or $ExpectedSnapshots.Count -ne $Records.Count) { throw 'Raw: ExpectedSnapshots format/cardinality mismatch.' }
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
        if (-not [string]::Equals($reader.GetAttribute('Version'), '1.1.0.1', [StringComparison]::Ordinal) -or $reader.IsEmptyElement) { throw 'Raw: invalid/empty CLIXML root.' }
        $reader.ReadStartElement()
        $state = @{Reader=$reader; RefId=[int64]0; Records=$recordMap; Guids=[Collections.Generic.List[string]]::new();
            Seen=[Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal); Identities=@{}}
        $wrapper = $false; $topCount = 0
        while ($reader.MoveToContent() -eq [Xml.XmlNodeType]::Element) {
            if ([string]::Equals($RawFormat, $script:PraRawFormat, [StringComparison]::Ordinal)) {
                $snapshot = Read-PraRawSnapshot $state
                Add-PraRawIdentity $state $snapshot.ObjectGUID
                Assert-PraRawRecord $snapshot $recordMap[$snapshot.ObjectGUID]
                if ($compare) { Assert-PraRawExpected $snapshot $expectedMap[$snapshot.ObjectGUID] }
                Write-PraRawProgress $Context $snapshot $stream.Position 'READ VERIFIED'
                $snapshot = $null
            } else {
                if ($wrapper) { throw 'Legacy CLIXML: wrapper mixed with root sequence.' }
                if ([string]::Equals($reader.LocalName, 'Ref', [StringComparison]::Ordinal)) { Add-PraRawIdentity $state (Read-PraLegacyReference $state) }
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
# MIImKgYJKoZIhvcNAQcCoIImGzCCJhcCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCD8v96a9WvJQeA2
# rrvwOOGFWPnyof4FvixtCQ3iFsbQh6CCDW8wggZyMIIEWqADAgECAghkM1HTxzif
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
# AQQBgjcCAQsxDjAMBgorBgEEAYI3AgEVMC8GCSqGSIb3DQEJBDEiBCBLkiFpsxd1
# gSgKF5cN6D7gwh0BKRfU4NJDelg1o+uMwDANBgkqhkiG9w0BAQEFAASCAgCBvL1W
# fmFlUz1tbhrJbrp4V7j0Pz/auA95j3ILER/YN4IYS8eZmEexttb854ZSMGhc347W
# LCCXd+PwFwLbO6X41X+oOoiLzJmxpU01jwB38X0ST0fefkeD9femz2lJvHhGznsh
# OIJwlu089caIraY7tDw1hcuY8f2RfWt4RfafuskRbu8GLnVZgv6UNfpDqoFBh3+m
# BSxk+N6i/QtbW1xb2Ct5KfnZI27tPeVGmaeYBVTGzBeZbfK3IqKXiBAXFE3I73Xe
# 1ZGd+B5ztxUQtbV6pbavLGFNgSEDkL0ojFnkoqZOuZ7VgeIUmNsdktMm2rBT+NKG
# 7vijNX2u1dIYFGIAmfTY/BLwlGEx4utre8Lj6mZcX+ITisr5bdtNcjfn3ABWlcV1
# GESNwDMd32CUWrE3AvwPLX42NhwB64h4C8P5c1G/LeZWqAtyniQa051AICBzs5mV
# Fe4qcXTyfE7aCq9tCny1Ah/7JBA/i8yur7lUmnFHlAdiz1i7+Pgt5H2BB2+JlcoX
# rf0kUBxKQoP5FcxFwH56GhBzSXTN9QA5GrmxVDZ27wPfvUJ3ay/ArCOHqTp/VNJx
# tadc+FQsxi1u5Vnw8b25F5BbENtiTqE9+z0K+H3chvqEhQD7SfjOk4eCE8lIETic
# Gb/R6eikuwfu5UrCY/vTjZdkXb/eG1QbsaiOp6GCFM4wghTKBgorBgEEAYI3AwMB
# MYIUujCCFLYGCSqGSIb3DQEHAqCCFKcwghSjAgEDMQ0wCwYJYIZIAWUDBAIBMIGJ
# BgsqhkiG9w0BCRABBKB6BHgwdgIBAQYMKwYBBAGCqTABAwYBMDEwDQYJYIZIAWUD
# BAIBBQAEIGMqiXZBL4wSGIbIE+bBnkREAtvYIaIzgWpQuBQjoMMuAggGinebGPr7
# vxgPMjAyNjExMTMxMjEyMzlaMAMCAQECEBeevHMbvRqzME2MSZoZmJKgghGnMIIE
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
# AQkQAQQwHAYJKoZIhvcNAQkFMQ8XDTI2MTExMzEyMTIzOVowKAYJKoZIhvcNAQk0
# MRswGTALBglghkgBZQMEAgGhCgYIKoZIzj0EAwIwLwYJKoZIhvcNAQkEMSIEIGCm
# c414KAd+eoDcAoO+T2olzxc2bdE+ge1499H5WiR6MIHIBgsqhkiG9w0BCRACLzGB
# uDCBtTCBsjCBrwQgV0/qF6r6XnxqK5sIyZixc15FCzhzykTmokygkw5j87AwgYow
# dqR0MHIxCzAJBgNVBAYTAlVTMQ4wDAYDVQQIDAVUZXhhczEQMA4GA1UEBwwHSG91
# c3RvbjERMA8GA1UECgwIU1NMIENvcnAxLjAsBgNVBAMMJVNTTC5jb20gVGltZXN0
# YW1waW5nIElzc3VpbmcgUlNBIENBIDICEFRD+De9Wu4YAYRyuFzajuMwCgYIKoZI
# zj0EAwIERzBFAiEAnCv/arK/uDvSo8E/4syxSK5WXugrv/Nj4Cl/3NkJ53cCIGCx
# KyN0FKk96ruZHnBETVJ9GS90zfJjoxuv1N+2oyNx
# SIG # End signature block
