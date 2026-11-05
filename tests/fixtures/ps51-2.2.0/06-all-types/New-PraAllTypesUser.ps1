#Requires -Version 5.1
<#
.SYNOPSIS
    INPUT of fixture set 06-all-types: builds the synthetic user whose raw capture is all-types.clixml.
.DESCRIPTION
    This file is the single source of truth for the input, dot-sourced by both tools\New-LegacyFixtures.ps1
    (Windows PowerShell 5.1, which wrote all-types.clixml with the production PRA.Backup codec) and
    tests\PraLegacyFixtures.Tests.ps1 (any edition, which rebuilds the same snapshot and compares the codec
    output byte for byte with the frozen file).
    It is edition neutral and self-contained: no harness, no directory access. The data is synthetic (contoso.com).
    Do not edit it without regenerating the fixtures: its values are part of the frozen expectation.
.NOTES
    Not part of the runtime package.
#>

function New-PraAllTypesDescriptor {
    <# Local System.DirectoryServices security descriptor (never directory-bound); fixed owner, SIDs and ACEs. #>
    param([switch]$Mailbox, [int]$AclCount = 12)
    Add-Type -AssemblyName System.DirectoryServices
    $descriptor = New-Object DirectoryServices.ActiveDirectorySecurity
    $descriptor.SetOwner((New-Object Security.Principal.SecurityIdentifier('S-1-5-18')))
    $descriptor.SetAccessRuleProtection($true, $false)
    $sendAs = [guid]'ab721a54-1e2f-11d0-9819-00aa0040529b'
    $sids = @('S-1-5-21-100-200-300-2001', 'S-1-5-21-100-200-300-2002', 'S-1-5-21-100-200-300-2003', 'S-1-5-21-100-200-300-3001', 'S-1-5-18',
        'S-1-5-21-100-200-300-512', 'S-1-5-21-100-200-300-518', 'S-1-5-21-100-200-300-519', 'S-1-5-32-544', 'S-1-5-21-100-200-300-2004')
    for ($i = 0; $i -lt $AclCount; $i++) {
        $sid = New-Object Security.Principal.SecurityIdentifier($sids[$i % $sids.Count])
        $rights = [DirectoryServices.ActiveDirectoryRights]::ReadProperty
        $objectType = [guid]('90000000-0000-0000-0000-{0:000000000000}' -f ($i + 1))
        if ($Mailbox) { $rights = [DirectoryServices.ActiveDirectoryRights]::CreateChild }
        elseif ($i -lt $sids.Count) { $rights = [DirectoryServices.ActiveDirectoryRights]::ExtendedRight; $objectType = $sendAs }
        $rule = New-Object DirectoryServices.ActiveDirectoryAccessRule($sid, $rights, [Security.AccessControl.AccessControlType]::Allow, $objectType)
        [void]$descriptor.AddAccessRule($rule)
    }
    $denied = New-Object DirectoryServices.ActiveDirectoryAccessRule((New-Object Security.Principal.SecurityIdentifier('S-1-5-21-100-200-300-3999')),
        [DirectoryServices.ActiveDirectoryRights]::ExtendedRight, [Security.AccessControl.AccessControlType]::Deny, $sendAs)
    [void]$descriptor.AddAccessRule($denied)
    return $descriptor
}

function New-PraAllTypesUser {
    <# One synthetic user carrying every scalar, collection, binary and native-security shape the codec supports. #>
    $native = New-PraAllTypesDescriptor
    $mailbox = New-PraAllTypesDescriptor -Mailbox
    $sid = New-Object Security.Principal.SecurityIdentifier('S-1-5-21-100-200-300-3001')
    $user = [pscustomobject][ordered]@{
        ObjectGUID = [guid]'00000000-0000-0000-0000-000000000001'
        DistinguishedName = 'CN=User1,OU=Tests,DC=contoso,DC=com'; SamAccountName = 'user1'
        UserPrincipalName = 'user1@contoso.com'; DisplayName = 'Synthetic User 1'; Name = 'User1'; objectClass = 'user'
        mail = 'user1@contoso.com'; mailNickname = 'user1'; uSNChanged = [long]100; memberOf = @(); publicDelegates = @()
        nTSecurityDescriptor = $native; msExchMailboxSecurityDescriptor = $mailbox.GetSecurityDescriptorBinaryForm(); msExchArchiveGUID = $null
        homeMDB = 'CN=Database1,CN=Databases,DC=contoso,DC=com'; homeMTA = 'CN=OriginalMTA,DC=contoso,DC=com'
        msExchHomeServerName = '/o=Synthetic/ou=Gate/cn=Servers/cn=Original'; msExchMailboxGuid = [byte[]](0, 1, 2, 127, 128, 254, 255, 1)
        mDBUseDefaults = $false; msExchRecipientDisplayType = 0; msExchRecipientTypeDetails = [long]1; msExchRemoteRecipientType = $null
        targetAddress = $null; proxyAddresses = [string[]]@('SMTP:user1@contoso.com', 'smtp:alias1@contoso.com', 'X500:/o=Synthetic/ou=Gate/cn=User')
        extensionAttribute1 = 'OriginalTag-1'
    }
    $extras = [ordered]@{
        EmptyString = ''; Whitespace = '  '; NullValue = $null; FalseValue = $false; Zero = [int]0
        ByteMax = [byte]255; SByteMin = [sbyte]-128; Int16Min = [int16]-32768; UInt16Max = [uint16]65535
        Int32Min = [int32]::MinValue; UInt32Max = [uint32]::MaxValue; Int64Min = [int64]::MinValue; UInt64Max = [uint64]::MaxValue
        SingleValue = [single]-1.25; DoubleValue = [double]::NaN; DecimalValue = [decimal]::Parse('1.2300', [Globalization.CultureInfo]::InvariantCulture)
        DateValue = [datetime]::SpecifyKind([datetime]'2026-09-07T01:02:03', [DateTimeKind]::Utc)
        OffsetValue = [datetimeoffset]::Parse('2026-09-07T01:02:03+02:00', [Globalization.CultureInfo]::InvariantCulture)
        SpanValue = [timespan]::FromTicks(-123456789); GuidValue = [guid]'00112233-4455-6677-8899-aabbccddeeff'; SidValue = $sid; CharValue = [char]0
        ControlString = (' literal_x0041_ & < > ' + [char]0 + "`r`n`t" + [char]0xD800)
        EmptyBytes = [byte[]]@(); EmptyArray = [string[]]@(); Duplicates = [string[]]@('same', 'same', 'last')
        Nested = [object[]]@('first', $null, [object[]]@(), [object[]]@('nested', 'nested'), [byte[]](0, 255))
    }
    foreach ($name in $extras.Keys) { $user | Add-Member -NotePropertyName $name -NotePropertyValue $extras[$name] }
    return $user
}

$script:PraAllTypesCapturedUtc = '2026-09-07T01:02:03.0000000Z'
