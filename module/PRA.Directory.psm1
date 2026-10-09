#Requires -Version 5.1
#Requires -PSEdition Desktop
<#
.SYNOPSIS
    PRA Remote Mailbox - Active Directory engine: targets, plans, backups, AD writes, proofs, sync.

.DESCRIPTION
    Every AD read and write of the tool is in this module. Regions, in the order of an execution:

        1. Receipts and files      validated backups kept in memory, SHA-256, immutable files, journal
        2. Directory reads         DC connection, users, groups, targets of the scope
        3. Attribute states        typed values stored in the backups, comparison, display
        4. Shared permissions      FullAccess / SendAs / SendOnBehalf read from AD, CSV or a group
        5. Plans                   New-PraPlan: what will change for one object (read only)
        6. Backups and proofs      Save-PraBatch, Import-PraBackup, Import-PraProof
        7. Writes                  Invoke-PraAdPreview, Invoke-PraAdBatch (the only AD writes)
        8. Entra Connect           Invoke-PraSync (local or remote delta cycle)

    Safety contract (unchanged since 1.3.0):
      - every target is read and planned before the first write;
      - a complete backup (typed JSON + data-only CLIXML + SHA-256) of the whole batch is written,
        closed and re-read before the first write;
      - before each write the current AD state is compared with the backup (uSNChanged, DN, values);
      - the first error stops the batch: no next object, no sync, no cloud write, no automatic rollback;
      - after the writes, a State file (AD proof) records what was verified; the cloud phase and
        Finalize rely on it.

.NOTES
    Author  : Nicolas Fabert
    Version : 2.1.0
#>
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

Import-Module (Join-Path $PSScriptRoot 'PRA.Backup.psm1') -ErrorAction Stop
# Validated receipts and permission caches are attached to the run context; they are released with it.
$script:ReceiptRegistries = New-Object 'Runtime.CompilerServices.ConditionalWeakTable[object,object]'
$script:PermissionCaches = New-Object 'Runtime.CompilerServices.ConditionalWeakTable[object,object]'
# Attributes managed by the tool and their stored type. The typed JSON is what Recover restores;
# the CLIXML keeps every value returned by AD (audit, manual recovery).
$script:AttributeKinds = [ordered]@{
    homeMDB='String'; homeMTA='String'; msExchHomeServerName='String'; msExchMailboxGuid='Bytes'
    mDBUseDefaults='Bool'; msExchRecipientDisplayType='Int'; msExchRecipientTypeDetails='Long'
    msExchRemoteRecipientType='Long'; targetAddress='String'; proxyAddresses='MultiString'
}
# Display names of msExchRecipientTypeDetails values (console only).
$script:RecipientTypeNames = @{
    '1'='UserMailbox'; '4'='SharedMailbox'; '16'='RoomMailbox'; '32'='EquipmentMailbox'; '128'='MailUser'
    '2147483648'='RemoteUserMailbox'; '8589934592'='RemoteRoomMailbox'; '17179869184'='RemoteEquipmentMailbox'; '34359738368'='RemoteSharedMailbox'
}

#region 1. Receipts and files ----------------------------------------------------------------

function Write-PraMemoryStage {
    <# Log only: stage of a backup and private memory of the process (large batches). #>
    [CmdletBinding()]
    param([hashtable]$Context, [string]$Stage, [string]$Identity = '', [string]$Detail = '')
    $process = [Diagnostics.Process]::GetCurrentProcess()
    try { $privateMiB = [math]::Round(($process.PrivateMemorySize64 / 1MB), 1) } finally { $process.Dispose() }
    Write-PraLog -Context $Context -Message ("BACKUP/AD | $Stage | GUID=$Identity | $Detail | PrivateMiB=$privateMiB | Process64Bit=$([Environment]::Is64BitProcess)") -Level Debug
}

function Get-PraReceiptRegistry {
    <# Validated backups ("receipts") of this run. #>
    [CmdletBinding()]
    param([hashtable]$Context)
    $registry = $null
    if (-not $script:ReceiptRegistries.TryGetValue($Context, [ref]$registry)) {
        $registry = New-Object 'Collections.Generic.List[object]'
        $script:ReceiptRegistries.Add($Context, $registry)
    }
    return ,$registry
}

function Write-PraDataFingerprint {
    <#
    .SYNOPSIS
        Structural SHA-256 of closed JSON data (strings, numbers, arrays, dictionaries, note properties).
        Used to detect a change of a validated backup in memory. Any other type is refused.
    #>
    [CmdletBinding()]
    param([hashtable]$State, [AllowNull()]$Value, [int]$Depth = 0)
    if ($Depth -gt 64) { throw 'Receipt data too deep or cyclic.' }
    $State.Nodes++
    if ($State.Nodes -gt 10000000) { throw 'Receipt data too large.' }
    $writer = $State.Writer
    if ($null -eq $Value) { $writer.Write([byte]0); return }
    if ($Value -is [string]) {
        $writer.Write([byte]1); $writer.Write([int]$Value.Length)
        for ($offset = 0; $offset -lt $Value.Length; $offset += 1024) {
            $count = [math]::Min(1024, $Value.Length - $offset)
            $Value.CopyTo($offset, $State.Characters, 0, $count)
            [Buffer]::BlockCopy($State.Characters, 0, $State.Bytes, 0, ($count * 2))
            $writer.Write($State.Bytes, 0, ($count * 2))
        }
        return
    }
    if ($Value -is [bool]) { $writer.Write([byte]2); $writer.Write([bool]$Value); return }
    if ($Value -is [int]) { $writer.Write([byte]3); $writer.Write([int]$Value); return }
    if ($Value -is [long]) { $writer.Write([byte]4); $writer.Write([long]$Value); return }
    if ($Value -is [double]) { $writer.Write([byte]5); $writer.Write([double]$Value); return }
    if ($Value -is [decimal]) { $writer.Write([byte]6); foreach ($bits in [decimal]::GetBits($Value)) { $writer.Write([int]$bits) }; return }
    if ($Value -is [array]) {
        if ($Value.Rank -ne 1) { throw 'Unsupported array in a receipt.' }
        $writer.Write([byte]7); $writer.Write([int]$Value.Length)
        foreach ($item in $Value) { Write-PraDataFingerprint -State $State -Value $item -Depth ($Depth + 1) }
        return
    }
    if ($Value -is [hashtable] -or $Value -is [Collections.Specialized.OrderedDictionary]) {
        $writer.Write([byte]8); $writer.Write([int]$Value.Count)
        foreach ($entry in $Value.GetEnumerator()) {
            if ($entry.Key -isnot [string]) { throw 'Non-text key in a receipt.' }
            Write-PraDataFingerprint -State $State -Value $entry.Key -Depth ($Depth + 1)
            Write-PraDataFingerprint -State $State -Value $entry.Value -Depth ($Depth + 1)
        }
        return
    }
    if ($Value.PSObject.BaseObject -is [Management.Automation.PSCustomObject]) {
        $properties = @($Value.PSObject.Properties)
        $writer.Write([byte]9); $writer.Write([int]$properties.Count)
        foreach ($property in $properties) {
            if ($property.MemberType -ne [Management.Automation.PSMemberTypes]::NoteProperty) { throw 'Executable property not allowed in a receipt.' }
            Write-PraDataFingerprint -State $State -Value ([string]$property.Name) -Depth ($Depth + 1)
            Write-PraDataFingerprint -State $State -Value $property.Value -Depth ($Depth + 1)
        }
        return
    }
    throw "Type not allowed in a receipt (data only): $($Value.GetType().FullName)"
}

function Get-PraDataFingerprint {
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Data)
    $hash = [Security.Cryptography.SHA256]::Create()
    $crypto = New-Object Security.Cryptography.CryptoStream([IO.Stream]::Null, $hash, [Security.Cryptography.CryptoStreamMode]::Write)
    $writer = New-Object IO.BinaryWriter($crypto, (New-Object Text.UTF8Encoding($false)), $true)
    try {
        $state = @{ Writer=$writer; Characters=(New-Object char[] 1024); Bytes=(New-Object byte[] 2048); Nodes=0L }
        Write-PraDataFingerprint -State $state -Value $Data
        $writer.Flush(); $crypto.FlushFinalBlock()
        return ([BitConverter]::ToString($hash.Hash)).Replace('-', '').ToLowerInvariant()
    }
    finally { $writer.Dispose(); $crypto.Dispose(); $hash.Dispose() }
}

function Add-PraValidatedReceipt {
    <# Remembers a backup validated in this run, with its hashes and a fingerprint of its content. #>
    [CmdletBinding()]
    param([hashtable]$Context, $Receipt, [string]$RawPath = '', [string]$RawHash = '')
    $guids = New-Object 'Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    foreach ($record in $Receipt.Data.Records) { [void]$guids.Add([string]$record.ObjectGuid) }
    $entry = [pscustomobject]@{
        Receipt=$Receipt; Data=$Receipt.Data; Path=[string]$Receipt.Path; Hash=[string]$Receipt.Hash
        RawPath=$RawPath; RawHash=$RawHash; Environment=[string]$Receipt.Data.Environment
        SchemaVersion=[int](Get-PraValue $Receipt.Data 'SchemaVersion' 1); RawFormat=[string](Get-PraValue $Receipt.Data 'RawFormat' '')
        Operation=[string]$Receipt.Data.Operation; Legacy=[bool]$Receipt.Legacy; Guids=$guids
        DataFingerprint=(Get-PraDataFingerprint -Data $Receipt.Data)
    }
    $registry = Get-PraReceiptRegistry -Context $Context
    $registry.Add($entry)
}

function Get-PraReceiptEntry {
    [CmdletBinding()]
    param([hashtable]$Context, $Receipt)
    $registry = Get-PraReceiptRegistry -Context $Context
    foreach ($entry in $registry) { if ([object]::ReferenceEquals($entry.Receipt, $Receipt)) { return $entry } }
    throw 'Backup not validated in this run: a complete validation is required.'
}

function Assert-PraReceiptIntegrity {
    <# The backup is unchanged in memory and on disk (JSON, .sha256, CLIXML) since its validation. #>
    [CmdletBinding()]
    param([hashtable]$Context, $Entry)
    $receipt = $Entry.Receipt
    if ($Entry.Environment -cne $Context.Config.Environment -or $receipt.Path -cne $Entry.Path -or
        $receipt.Data.Environment -cne $Entry.Environment -or $receipt.Data.Operation -cne $Entry.Operation -or
        [int](Get-PraValue $receipt.Data 'SchemaVersion' 1) -ne $Entry.SchemaVersion -or
        [string](Get-PraValue $receipt.Data 'RawFormat' '') -cne $Entry.RawFormat -or
        $receipt.Legacy -isnot [bool] -or $receipt.Legacy -ne $Entry.Legacy -or
        $receipt.Hash -cne $Entry.Hash -or -not [object]::ReferenceEquals($receipt.Data, $Entry.Data)) {
        throw 'Backup receipt changed, or it belongs to another context.'
    }
    if ((Get-PraDataFingerprint -Data $receipt.Data) -cne $Entry.DataFingerprint) { throw 'Backup content changed in memory since its validation.' }
    if ((Get-PraHash -Path $Entry.Path) -cne $Entry.Hash) { throw 'Backup JSON file changed since its validation.' }
    if ($Entry.SchemaVersion -ge 2) {
        $sidecar = (Get-Content -LiteralPath ($Entry.Path + '.sha256') -Raw -ErrorAction Stop).Trim()
        if ($sidecar -cne $Entry.Hash) { throw 'Backup .sha256 file changed since its validation.' }
        if ($receipt.Data.RawHash -cne $Entry.RawHash -or
            [IO.Path]::GetFileName($Entry.RawPath) -cne $receipt.Data.RawFile -or
            (Get-PraHash -Path $Entry.RawPath) -cne $Entry.RawHash) { throw 'Backup CLIXML file changed since its validation.' }
    }
}

function ConvertTo-PraLdapValue {
    <#
    .SYNOPSIS
        Escapes a value for an LDAP filter (RFC 4515).
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][AllowEmptyString()][string]$Value)
    $Value.Replace('\', '\5c').Replace('*', '\2a').Replace('(', '\28').Replace(')', '\29').Replace([string][char]0, '\00')
}

function Get-PraHash {
    <#
    .SYNOPSIS
        SHA-256 of a file, lower case.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path)
    $hash = [Security.Cryptography.SHA256]::Create()
    $stream = [IO.File]::OpenRead($Path)
    try { return ([BitConverter]::ToString($hash.ComputeHash($stream))).Replace('-', '').ToLowerInvariant() }
    finally { $stream.Dispose(); $hash.Dispose() }
}

function Write-PraImmutableFile {
    <#
    .SYNOPSIS
        Creates a new file (never overwrites), writes it, flushes it to disk and closes it.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path, [Parameter(Mandatory)][AllowEmptyString()][string]$Text)
    $stream = New-Object IO.FileStream($Path, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
    $writer = $null
    try {
        $writer = New-Object IO.StreamWriter($stream, (New-Object Text.UTF8Encoding($false)), 16384, $true)
        $writer.Write($Text); $writer.Flush(); $stream.Flush($true)
    }
    finally { if ($null -ne $writer) { $writer.Dispose() }; $stream.Dispose() }
}

function New-PraPrivateDirectory {
    <#
    .SYNOPSIS
        Creates a backup folder readable only by the current account, SYSTEM and Administrators
        (no inherited permission). The folder must not exist.
    #>
    [CmdletBinding(SupportsShouldProcess = $true)]
    param([Parameter(Mandatory)][string]$Path)
    if (-not $PSCmdlet.ShouldProcess($Path, 'Create a private backup folder')) { throw 'Backup folder creation refused.' }
    if (Test-Path -LiteralPath $Path) { throw "Backup folder already exists: $Path" }
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent().User
    $acl = New-Object Security.AccessControl.DirectorySecurity
    $acl.SetAccessRuleProtection($true, $false)
    $acl.SetOwner($identity)
    foreach ($sid in @($identity.Value, 'S-1-5-18', 'S-1-5-32-544') | Select-Object -Unique) {
        $rule = New-Object Security.AccessControl.FileSystemAccessRule(
            (New-Object Security.Principal.SecurityIdentifier($sid)),
            [Security.AccessControl.FileSystemRights]::FullControl,
            ([Security.AccessControl.InheritanceFlags]'ContainerInherit,ObjectInherit'),
            [Security.AccessControl.PropagationFlags]::None, [Security.AccessControl.AccessControlType]::Allow)
        [void]$acl.AddAccessRule($rule)
    }
    # The folder is created with its restrictive ACL: no moment where files inherit broader rights.
    [void][IO.Directory]::CreateDirectory($Path, $acl)
    $actual = [IO.Directory]::GetAccessControl($Path)
    if (-not $actual.AreAccessRulesProtected) { throw "Backup folder ACL is not protected: $Path" }
}

function Write-PraJournal {
    <#
    .SYNOPSIS
        Appends one JSON line to the journal of the batch (Started / Applied / Verified / Failed).
    #>
    [CmdletBinding()]
    param([hashtable]$Context, [string]$Target, [string]$Operation, [string]$Status, [string]$Detail = '')
    if (-not $Context.JournalPath) { throw 'The batch journal is not open: no write is allowed.' }
    $entry = [ordered]@{ RunId=$Context.RunId; Utc=[DateTime]::UtcNow.ToString('o'); Target=$Target; Operation=$Operation; Status=$Status; Detail=$Detail }
    $bytes = (New-Object Text.UTF8Encoding($false)).GetBytes(($entry | ConvertTo-Json -Depth 8 -Compress) + "`r`n")
    $stream = New-Object IO.FileStream($Context.JournalPath, [IO.FileMode]::Append, [IO.FileAccess]::Write, [IO.FileShare]::Read)
    try { $stream.Write($bytes, 0, $bytes.Length); $stream.Flush($true) }
    finally { $stream.Dispose() }
}
#endregion

#region 2. Directory reads --------------------------------------------------------------------

function Invoke-PraRead {
    <# Runs one AD read, logs it (debug) and logs any failure with its details. #>
    [CmdletBinding()]
    param([hashtable]$Context, [string]$Operation, [string]$Identity, [scriptblock]$Read)
    $Context.CurrentOperation = $Operation; $Context.CurrentIdentity = $Identity
    Write-PraLog -Context $Context -Message "AD BEGIN | $Operation | DC=$($Context.Server) | Identity=$Identity" -Level Debug
    $clock = [Diagnostics.Stopwatch]::StartNew()
    try {
        $result = @(& $Read)
        Write-PraLog -Context $Context -Message "AD END | $Operation | results=$($result.Count) | duration=$($clock.ElapsedMilliseconds)ms" -Level Debug
        return $result
    }
    catch {
        Write-PraLog -Context $Context -Message "AD read failed | $Operation | DC=$($Context.Server) | Identity=$Identity | $($_.Exception.GetType().FullName) | $($_.Exception.Message) | ErrorId=$($_.FullyQualifiedErrorId) | Category=$($_.CategoryInfo.Category)" -Level Error
        Write-PraLog -Context $Context -Message "$($_.InvocationInfo.PositionMessage)`n$($_.ScriptStackTrace)" -Level Debug
        throw
    }
}

function Initialize-PraDirectory {
    <#
    .SYNOPSIS
        Loads the ActiveDirectory module and fixes ONE writable domain controller for the whole run
        (DomainController in the configuration, or discovered). Optionally checks Scope.SearchBase.
    #>
    [CmdletBinding()]
    param([hashtable]$Context, [switch]$ValidateScope)
    Initialize-PraPermissionCache -Context $Context
    if (-not [Environment]::Is64BitProcess) { Write-PraLog -Context $Context -Message '32-bit PowerShell: less memory for large batches. Use the 64-bit Windows PowerShell 5.1.' -Level Warning }
    # No AD: drive (it would connect to a default domain controller, not the one of the run).
    $env:ADPS_LoadDefaultDrive = 0
    Import-Module ActiveDirectory -ErrorAction Stop -Verbose:$false -WarningAction SilentlyContinue
    if ([string]::IsNullOrWhiteSpace($Context.Server)) {
        $dc = Get-ADDomainController -Discover -Writable -ErrorAction Stop
        $names = @($dc.HostName | Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) })
        if ($names.Count -ne 1) { throw 'Domain controller discovery: no name or several names returned.' }
        $Context.Server = [string]$names[0]
    }
    $server = $Context.Server
    $dc = @(Invoke-PraRead $Context 'Get-ADDomainController' $server { Get-ADDomainController -Identity $server -Server $server -ErrorAction Stop })
    if ($dc.Count -ne 1 -or (Get-PraValue $dc[0] 'IsReadOnly' $true)) { throw "Writable domain controller not confirmed: $server" }
    $root = @(Invoke-PraRead $Context 'Get-ADRootDSE' $server { Get-ADRootDSE -Server $server -ErrorAction Stop })
    if ($root.Count -ne 1 -or -not (Get-PraValue $root[0] 'defaultNamingContext' '')) { throw 'AD domain partition not found.' }
    $Context.NamingContext = [string]$root[0].defaultNamingContext
    Write-PraItem -Context $Context -Status Ok -Icon Directory -Text ("{0} {1} {2} {1} account {3}" -f $server, [char]0x00B7, $Context.NamingContext, [Security.Principal.WindowsIdentity]::GetCurrent().Name)
    if ($ValidateScope -and $Context.Config.Scope.SearchBase) {
        $base = [string]$Context.Config.Scope.SearchBase
        Assert-PraDomain $Context $base
        $null = Invoke-PraRead $Context 'Get-ADObject/SearchBase' $base { Get-ADObject -Identity $base -Server $server -ErrorAction Stop }
    }
}

function Assert-PraDomain {
    <# The object belongs to the domain of the fixed domain controller (no implicit DC change). #>
    [CmdletBinding()]
    param([hashtable]$Context, [string]$DistinguishedName)
    if (-not ($DistinguishedName.EndsWith(',' + $Context.NamingContext, [StringComparison]::OrdinalIgnoreCase) -or
            $DistinguishedName.Equals($Context.NamingContext, [StringComparison]::OrdinalIgnoreCase))) {
        throw "Object outside the domain of the domain controller: '$DistinguishedName' (domain '$($Context.NamingContext)'). The domain controller is never changed implicitly."
    }
}

function Get-PraUser {
    <#
    .SYNOPSIS
        Reads one user by UPN (exact LDAP filter), sAMAccountName, DN or GUID. Exactly one result is required.
    .PARAMETER Capture
        Also reads every attribute ('*') and the security descriptors (backup).
    #>
    [CmdletBinding()]
    param([hashtable]$Context, [Parameter(Mandatory)][string]$Identity, [string[]]$ExtraProperties = @(), [switch]$Capture)
    $properties = @('memberOf','uSNChanged','DisplayName','mail','mailNickname','msExchArchiveGUID') + @($script:AttributeKinds.Keys) + $ExtraProperties
    if ($Capture) { $properties += @('*','msExchMailboxSecurityDescriptor','nTSecurityDescriptor','publicDelegates') }
    $properties = @($properties | Select-Object -Unique)
    $server = $Context.Server
    if ($Identity -match '@' -and $Identity -notmatch '^(CN|OU|DC)=') {
        # -Identity does not search the UPN: use an exact, escaped LDAP filter.
        $filter = '(userPrincipalName=' + (ConvertTo-PraLdapValue $Identity) + ')'
        $users = @(Invoke-PraRead $Context 'Get-ADUser/UPN' $Identity { Get-ADUser -LDAPFilter $filter -Properties $properties -Server $server -ErrorAction Stop })
    }
    else { $users = @(Invoke-PraRead $Context 'Get-ADUser/Identity' $Identity { Get-ADUser -Identity $Identity -Properties $properties -Server $server -ErrorAction Stop }) }
    if ($users.Count -ne 1) { throw "AD object '$Identity' not found or not unique: $($users.Count) result(s) on $server." }
    $user = $users[0]
    $guid = [guid](Get-PraValue $user 'ObjectGUID' ([guid]::Empty))
    if ($guid -eq [guid]::Empty) { throw "AD object without GUID: $Identity" }
    Assert-PraDomain $Context ([string]$user.DistinguishedName)
    Write-PraLog -Context $Context -Message "AD RESOLVED | GUID=$guid | DN=$($user.DistinguishedName) | UPN=$($user.UserPrincipalName)" -Level Debug
    return $user
}

function Get-PraUsn {
    <# uSNChanged of an object (version of the object on its domain controller). #>
    [CmdletBinding()]
    param($User)
    $value = Get-PraValue $User 'uSNChanged' $null
    if ($null -eq $value -or [string]$value -notmatch '^[0-9]+$' -or [int64]$value -le 0) { throw 'uSNChanged missing or invalid: the AD version of the object cannot be proven.' }
    return ([int64]$value).ToString([Globalization.CultureInfo]::InvariantCulture)
}

function Get-PraGroup {
    [CmdletBinding()]
    param([hashtable]$Context, [Parameter(Mandatory)][string]$Identity, [switch]$WithoutMembers)
    $server = $Context.Server
    $parameters = @{ Identity=$Identity; Server=$server; ErrorAction='Stop' }
    if (-not $WithoutMembers) { $parameters.Properties = @('member') }
    $groups = @(Invoke-PraRead $Context 'Get-ADGroup' $Identity { Get-ADGroup @parameters })
    if ($groups.Count -ne 1) { throw "Group not found or not unique: $Identity" }
    Assert-PraDomain $Context ([string]$groups[0].DistinguishedName)
    if ([guid]$groups[0].ObjectGUID -eq [guid]::Empty) { throw "Group without GUID: $Identity" }
    return $groups[0]
}

function Get-PraTarget {
    <#
    .SYNOPSIS
        Objects to convert: -Identity, or the configured scope (Auto/OU, Group, Csv), filtered by
        mailbox type, exclusions and -MaxObjects. Sorted by sAMAccountName.
    .DESCRIPTION
        Only on-premises mailboxes are eligible (homeMDB set, msExchRecipientTypeDetails 1, 4, 16 or 32).
        System mailboxes (HealthMailbox*, SystemMailbox*, "Microsoft Exchange*") are always excluded.
        An explicit target (Identity or CSV line) that is not eligible stops the run.
    #>
    [CmdletBinding()]
    param([hashtable]$Context, [string]$Identity, [string]$MailboxScope = 'All', [int]$MaxObjects = 0)
    $scope = $Context.Config.Scope; $server = $Context.Server
    $types = @(1)
    if ($Identity) { $types = @(1, 4, 16, 32) }
    elseif ($MailboxScope -eq 'UsersOnly') { $types = @(1) }
    elseif ($MailboxScope -eq 'SharedOnly') { $types = @(4) }
    else {
        if ($scope.IncludeShared) { $types += 4 }
        if ($scope.IncludeRoom) { $types += 16 }
        if ($scope.IncludeEquip) { $types += 32 }
    }
    $users = New-Object 'Collections.Generic.List[object]'
    $explicit = $false
    if ($Identity) { $explicit = $true; $users.Add((Get-PraUser $Context $Identity)) }
    elseif ($scope.Mode -eq 'Csv') {
        $explicit = $true
        $entries = @(Read-PraTargetCsv -Path $scope.CsvPath)
        foreach ($entry in $entries) {
            $id = [string](Get-PraValue $entry 'Identity' '')
            if ([string]::IsNullOrWhiteSpace($id)) { throw 'A line of the target CSV file has no Identity: batch refused.' }
            $users.Add((Get-PraUser $Context $id.Trim()))
        }
    }
    elseif ($scope.Mode -eq 'Group') {
        $group = Get-PraGroup $Context $scope.GroupDN
        $members = @(Invoke-PraRead $Context 'Get-ADGroupMember/Scope' $group.DistinguishedName {
                Get-ADGroupMember -Identity $group.ObjectGUID -Recursive -Server $server -ErrorAction Stop })
        foreach ($member in $members | Where-Object objectClass -eq 'user') { $users.Add((Get-PraUser $Context ([string]$member.DistinguishedName))) }
    }
    else {
        $filter = '(&(homeMDB=*)(|' + (($types | ForEach-Object { "(msExchRecipientTypeDetails=$_)" }) -join '') + '))'
        $parameters = @{ LDAPFilter=$filter; Properties=@('homeMDB','msExchRecipientTypeDetails','DisplayName'); Server=$server; ErrorAction='Stop' }
        if ($scope.SearchBase) { $parameters.SearchBase = $scope.SearchBase }
        foreach ($user in @(Invoke-PraRead $Context 'Get-ADUser/Scope' ([string]$scope.SearchBase) { Get-ADUser @parameters })) { $users.Add($user) }
    }
    $seen = @{}; $selected = New-Object 'Collections.Generic.List[object]'
    foreach ($user in $users) {
        $id = ([guid]$user.ObjectGUID).ToString()
        if ($seen.ContainsKey($id)) { throw "The same object is listed twice (GUID $id). Fix the scope first." }
        $seen[$id] = $true
        $eligible = (Get-PraValue $user 'homeMDB' '') -and ((Get-PraValue $user 'msExchRecipientTypeDetails' 0) -in $types)
        $excluded = $user.SamAccountName -like 'HealthMailbox*' -or $user.SamAccountName -like 'SystemMailbox*' -or
            (Get-PraValue $user 'DisplayName' '') -like 'Microsoft Exchange*' -or $user.SamAccountName -in $scope.ExcludeSamAccountNames
        if (-not $eligible -or $excluded) {
            if ($explicit) { throw "Explicit target not eligible (not an on-premises mailbox of an accepted type) or excluded: $($user.SamAccountName). Nothing converted." }
            continue
        }
        $selected.Add($user)
    }
    $ordered = @($selected | Sort-Object SamAccountName, ObjectGUID)
    if ($MaxObjects -gt 0) { $ordered = @($ordered | Select-Object -First $MaxObjects) }
    return $ordered
}
#endregion

#region 3. Attribute states -------------------------------------------------------------------

function Get-PraAttributeState {
    <#
    .SYNOPSIS
        Typed state of the managed attributes: @{ Present; Kind; Value } per attribute.
        A property that was not read is an error (never taken as "absent").
    #>
    [CmdletBinding()]
    param($User, [Collections.IDictionary]$Kinds)
    $states = [ordered]@{}
    foreach ($name in $Kinds.Keys) {
        if ($null -eq $User.PSObject.Properties[$name]) { throw "AD attribute not read: $name (GUID $($User.ObjectGUID))." }
        $raw = $User.$name; $present = $null -ne $raw; $value = $null
        if ($present -and $raw -is [string] -and $raw.Length -eq 0) { $present = $false }
        if ($present -and $raw -is [Collections.ICollection] -and $raw.Count -eq 0) { $present = $false }
        if ($present) {
            switch ($Kinds[$name]) {
                String { $value = [string]$raw }
                MultiString { $value = [string[]]@($raw | Sort-Object -CaseSensitive) }
                Bytes { $value = [Convert]::ToBase64String([byte[]]$raw) }
                Bool { $value = [bool]$raw }
                Int { $value = ([int]$raw).ToString([Globalization.CultureInfo]::InvariantCulture) }
                Long { $value = ([int64]$raw).ToString([Globalization.CultureInfo]::InvariantCulture) }
            }
        }
        $states[$name] = [ordered]@{ Present=[bool]$present; Kind=[string]$Kinds[$name]; Value=$value }
    }
    return $states
}

function ConvertFrom-PraStoredValue {
    <# Value to write with Set-ADUser -Replace, from a stored typed state. #>
    [CmdletBinding()]
    param($State)
    if (-not $State.Present) { return $null }
    switch ($State.Kind) {
        String { return [string]$State.Value }
        MultiString { return ,([string[]]@($State.Value)) }
        Bytes { return ,([Convert]::FromBase64String([string]$State.Value)) }
        Bool { return [bool]$State.Value }
        Int { return [int]::Parse([string]$State.Value, [Globalization.CultureInfo]::InvariantCulture) }
        Long { return [int64]::Parse([string]$State.Value, [Globalization.CultureInfo]::InvariantCulture) }
        default { throw "Unknown stored type: $($State.Kind)" }
    }
}

function Test-PraStateEqual {
    <#
    .SYNOPSIS
        Two typed states are equal (case-sensitive; multi-valued attributes compared as sorted sets).
    #>
    [CmdletBinding()]
    param($Left, $Right)
    if ([bool]$Left.Present -ne [bool]$Right.Present -or $Left.Kind -ne $Right.Kind) { return $false }
    if (-not $Left.Present) { return $true }
    if ($Left.Kind -eq 'MultiString') {
        $a = @($Left.Value | Sort-Object -CaseSensitive); $b = @($Right.Value | Sort-Object -CaseSensitive)
        if ($a.Count -ne $b.Count) { return $false }
        for ($i = 0; $i -lt $a.Count; $i++) { if ([string]$a[$i] -cne [string]$b[$i]) { return $false } }
        return $true
    }
    return ([string]$Left.Value -ceq [string]$Right.Value)
}

function ConvertTo-PraLogText {
    <# Escapes control characters, quotes and backslashes of an AD value (the value is never cut). #>
    [CmdletBinding()]
    param([AllowEmptyString()][string]$Value)
    return [regex]::Replace($Value, '[\p{Cc}\p{Cf}\p{Zl}\p{Zp}\\"]', [Text.RegularExpressions.MatchEvaluator]{
            param($match)
            switch ($match.Value) {
                "`r" { '\r'; break }
                "`n" { '\n'; break }
                "`t" { '\t'; break }
                '\' { '\\'; break }
                '"' { '\"'; break }
                default { '\u{0:x4}' -f [int][char]$match.Value[0] }
            }
        })
}

function Format-PraAttributeValue {
    <#
    .SYNOPSIS
        Full, readable value(s) of a typed state for the log: <absent>, false and 0 stay distinct;
        a multi-valued attribute returns one line per value.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)]$State)
    if ($State.Present -isnot [bool]) { throw 'Display: presence of the attribute not captured.' }
    if (-not $State.Present) { return '<absent>' }
    switch ($State.Kind) {
        String { return ('"' + (ConvertTo-PraLogText -Value ([string]$State.Value)) + '"') }
        Bool { if ($State.Value) { return 'true' } else { return 'false' } }
        Int { return [string]$State.Value }
        Long { return [string]$State.Value }
        MultiString {
            $values = @($State.Value)
            if (-not $values.Count) { return '[] (0 values)' }
            for ($index = 0; $index -lt $values.Count; $index++) {
                '[{0}/{1}] "{2}"' -f ($index + 1), $values.Count, (ConvertTo-PraLogText -Value ([string]$values[$index]))
            }
            return
        }
        Bytes {
            $bytes = [Convert]::FromBase64String([string]$State.Value)
            $base64 = [Convert]::ToBase64String($bytes)
            if ($bytes.Length -eq 16) { return ('GUID={0} ; Base64={1} (16 bytes)' -f ([guid]::new($bytes)).ToString(), $base64) }
            return ('Base64={0} ({1} bytes)' -f $base64, $bytes.Length)
        }
        default { throw "Display: unknown type '$($State.Kind)'." }
    }
}

function Format-PraShortValue {
    <# Short value for the console: DN reduced to its first part, GUID for 16-byte values, (none) for absent. #>
    param([Parameter(Mandatory)]$State)
    if (-not $State.Present) { return '(none)' }
    switch ($State.Kind) {
        Bool { if ($State.Value) { return 'true' } else { return 'false' } }
        Bytes {
            $bytes = [Convert]::FromBase64String([string]$State.Value)
            if ($bytes.Length -eq 16) { return ([guid]::new($bytes)).ToString() }
            return ('{0} bytes' -f $bytes.Length)
        }
        MultiString { return ('{0} value(s)' -f @($State.Value).Count) }
        default {
            $text = ConvertTo-PraLogText -Value ([string]$State.Value)
            if ($text -match '^(CN|OU)=[^,]+,.+,DC=') { $text = ($text -split ',')[0] + ',...' }
            if ($text.StartsWith('/o=')) { $text = '...' + $text.Substring($text.LastIndexOf('/')) }
            return $text
        }
    }
}

function Write-PraAdDelta {
    <#
    .SYNOPSIS
        Shows what changes for one object: BEFORE / PLANNED, or VERIFIED after a successful AD re-read.
    .DESCRIPTION
        Console: one header line per object, then only the attributes that change (green = added,
        yellow = changed, red = removed) and the licence group. Log: every managed attribute with all
        its values BEFORE and PLANNED (or VERIFIED). Colours describe changes, not errors.
        VERIFIED is refused unless the object was really verified in Apply mode.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][hashtable]$Context, [Parameter(Mandatory)]$Plan, [ValidateSet('Planned','Verified')][string]$Stage = 'Planned')
    if ($Stage -eq 'Verified' -and ($Context.Mode -ne 'Apply' -or -not $Context.AllowMutation -or
            $Context.Action -eq 'Check' -or $WhatIfPreference -or $Plan.Row.ADVerified -ne $true)) {
        throw 'VERIFIED display refused: no successful AD verification in Apply mode.'
    }
    $afterLabel = if ($Stage -eq 'Verified') { 'VERIFIED' } else { 'PLANNED' }
    $heading = if ($Stage -eq 'Verified') { 'AD VERIFIED' } else { 'AD PLAN - planned values, not applied' }
    $record = $Plan.Record
    Write-PraLog -Context $Context -Message ("$heading | $(ConvertTo-PraLogText -Value $record.SamAccountName) | $($Plan.Operation) | Mode=$($Context.Mode) | GUID=$($record.ObjectGuid)") -Level Detail
    $palette = @{ ADD='Green'; CHANGE='Yellow'; REMOVE='Red'; UNCHANGED='DarkGray' }
    $consoleLines = New-Object 'Collections.Generic.List[object]'
    $unchanged = 0
    foreach ($name in $Plan.Kinds.Keys) {
        $before = $record.Attributes[$name]; $after = $Plan.Desired[$name]
        $change = if (Test-PraStateEqual -Left $before -Right $after) { 'UNCHANGED' } elseif (-not $before.Present) { 'ADD' } elseif (-not $after.Present) { 'REMOVE' } else { 'CHANGE' }
        Write-PraLog -Context $Context -Message "ATTRIBUTE | $name | $change | Type=$($Plan.Kinds[$name])" -Level Detail
        foreach ($value in @(Format-PraAttributeValue -State $before)) { Write-PraLog -Context $Context -Message "  $name | BEFORE : $value" -Level Detail }
        foreach ($value in @(Format-PraAttributeValue -State $after)) { Write-PraLog -Context $Context -Message "  $name | $afterLabel : $value" -Level Detail }
        if ($change -eq 'UNCHANGED') { $unchanged++; continue }
        if ($Plan.Kinds[$name] -eq 'MultiString' -and $before.Present -and $after.Present) {
            $old = @($before.Value); $new = @($after.Value)
            foreach ($value in $new | Where-Object { $_ -cnotin $old }) { $consoleLines.Add(@($name, ('+ ' + (ConvertTo-PraLogText -Value $value)), 'Green')) }
            foreach ($value in $old | Where-Object { $_ -cnotin $new }) { $consoleLines.Add(@($name, ('- ' + (ConvertTo-PraLogText -Value $value)), 'Red')) }
        }
        else { $consoleLines.Add(@($name, ('{0}  {1}  {2}' -f (Format-PraShortValue $before), [char]0x2192, (Format-PraShortValue $after)), $palette[$change])) }
    }
    $group = $record.Licensing
    if ($group.Enabled) {
        $change = if ($group.WasMember -eq $group.DesiredMember) { 'UNCHANGED' } elseif ($group.DesiredMember) { 'ADD' } else { 'REMOVE' }
        $beforeText = if ($group.WasMember) { 'Member' } else { 'Not member' }
        $afterText = if ($group.DesiredMember) { 'Member' } else { 'Not member' }
        Write-PraLog -Context $Context -Message "LICENCE GROUP | $(ConvertTo-PraLogText -Value $group.GroupDN) | $change" -Level Detail
        Write-PraLog -Context $Context -Message "  Licence group | BEFORE : $beforeText" -Level Detail
        Write-PraLog -Context $Context -Message "  Licence group | $afterLabel : $afterText" -Level Detail
        if ($change -ne 'UNCHANGED') {
            $groupName = (($group.GroupDN -split ',')[0] -replace '^CN=', '')
            $consoleLines.Add(@(('licence group ' + $groupName), ('{0}  {1}  {2}' -f $beforeText.ToLowerInvariant(), [char]0x2192, $afterText.ToLowerInvariant()), $palette[$change]))
        }
    }
    else { Write-PraLog -Context $Context -Message 'LICENCE GROUP | not managed for this operation' -Level Detail }
    $shared = $record.SharedPermissions
    $permissionText = ''
    if ($record.IsShared -and $Plan.Operation -eq 'Convert') {
        $permissionText = ' {0} {1} FullAccess {0} {2} SendAs {0} {3} SendOnBehalf' -f [char]0x00B7, @($shared.FullAccess).Count, @($shared.SendAs).Count, @($shared.SendOnBehalf).Count
    }

    # Console.
    $beforeType = [string]$record.Attributes['msExchRecipientTypeDetails'].Value
    $afterType = [string]$Plan.Desired['msExchRecipientTypeDetails'].Value
    $typeText = if ($script:RecipientTypeNames.ContainsKey($beforeType)) { $script:RecipientTypeNames[$beforeType] } else { $beforeType }
    if ($afterType -ne $beforeType) { $typeText += (' {0} ' -f [char]0x2192) + $(if ($script:RecipientTypeNames.ContainsKey($afterType)) { $script:RecipientTypeNames[$afterType] } else { $afterType }) }
    if ($Stage -eq 'Verified') {
        $groupAction = [string](Get-PraValue $Plan.Row 'GroupAction' '')
        $statusText = switch ([string]$Plan.Row.FinalStatus) { 'Pending' { 'next: Exchange Online deprovisioning check' } 'AlreadyDone' { 'already in the expected state' } default { 'done' } }
        $text = '{0}  {1}  {2} AD verified, {3} attribute(s) changed{4} {2} {5}' -f $record.SamAccountName, $typeText, [char]0x00B7, ($Plan.Kinds.Count - $unchanged), $(if ($groupAction -in @('Added','Removed')) { ', licence group ' + $groupAction.ToLowerInvariant() } else { '' }), $statusText
        Write-PraItem -Context $Context -Status Ok -Text $text
        return
    }
    $operationText = switch ($Plan.Operation) { 'Deprovision' { 'deprovision in Exchange Online first' } 'AlreadyRecovered' { 'already restored' } 'RestoreTag' { 'restore the retention tag' } default { $Plan.Operation.ToLowerInvariant() } }
    Write-Host ''
    Write-PraHost @(@('      '), @(($record.SamAccountName + '  '), 'White'), @(([string]$record.UserPrincipalName + '  '), 'DarkGray'), @($typeText, 'Cyan'), @(('  ' + [char]0x00B7 + ' ' + $operationText + $permissionText), 'DarkGray'))
    foreach ($line in $consoleLines) { Write-PraHost @('         ', ('{0,-28} ' -f $line[0]), $line[1]) -Color $line[2] }
    if (-not $consoleLines.Count) { Write-PraHost @(@('         '), @('no change: the object is already in the expected state', 'DarkGray')) }
    elseif ($unchanged) { Write-PraHost @(@('         '), @(('{0} other managed attribute(s) unchanged (full values in the log)' -f $unchanged), 'DarkGray')) }
    if ($permissionText) {
        # Who will get access in Exchange Online: a few names on screen, the complete list in the log.
        foreach ($right in @('FullAccess', 'SendAs', 'SendOnBehalf')) {
            $value = Get-PraValue $shared $right @()
            $holders = @(@($value) | Where-Object { $_ })
            Write-PraLog -Context $Context -Message ("PERMISSIONS | {0} | {1} ({2}) | {3}" -f $record.SamAccountName, $right, $holders.Count, $(if ($holders.Count) { $holders -join ', ' } else { '(none)' })) -Level Detail
            if (-not $holders.Count) { continue }
            $names = @($holders | Select-Object -First 3) -join ', '
            if ($holders.Count -gt 3) { $names += (' + {0} more (full list in the log)' -f ($holders.Count - 3)) }
            Write-PraHost @('         ', ('{0,-28} ' -f ($right + ' to')), $names) -Color 'Gray'
        }
        $ignoredEntries = Get-PraValue (Get-PraValue $Context '_PraIgnoredTrustees' @{}) ([string]$record.ObjectGuid) @()
        $ignoredEntries = @($ignoredEntries | Where-Object { $_ })
        if ($ignoredEntries.Count) {
            # A warning, not an error: the account no longer exists, so nothing can be granted to it.
            Write-PraLog -Context $Context -Level Warning -Message ('{0}: {1} permission entr{2} ignored, account unknown in AD (deleted, or from another domain): {3}' -f
                $record.SamAccountName, $ignoredEntries.Count, $(if ($ignoredEntries.Count -gt 1) { 'ies' } else { 'y' }), ($ignoredEntries -join '; '))
        }
    }
}

function Get-PraRoutingAddress {
    <#
    .SYNOPSIS
        Routing address of the remote mailbox (targetAddress): an existing proxy address in
        Routing.RoutingDomain (AutoDetect), otherwise <alias>@RoutingDomain.
    #>
    [CmdletBinding()]
    param([hashtable]$Context, $User)
    $domain = $Context.Config.Routing.RoutingDomain
    $proxies = @($User.proxyAddresses)
    $primary = @($proxies | Where-Object { $_ -cmatch '^SMTP:' } | Select-Object -First 1)
    $address = if ($primary.Count) { $primary[0].Substring(5) } else { [string](Get-PraValue $User 'mail' '') }
    $local = if ($address) { ($address -split '@', 2)[0] } else { [string](Get-PraValue $User 'mailNickname' '') }
    if ($Context.Config.Routing.AutoDetect) {
        $existing = @($proxies | Where-Object { $_ -imatch '^smtp:.+@.+\.mail\.onmicrosoft\.com$' } | ForEach-Object { $_.Substring(5) })
        $match = @($existing | Where-Object { ($_ -split '@', 2)[0] -ieq $local -and $_ -imatch "@$([regex]::Escape($domain))$" })
        if (-not $match.Count) { $match = @($existing | Where-Object { $_ -imatch "@$([regex]::Escape($domain))$" }) }
        if ($match.Count -eq 1) { return [string]$match[0] }
        if ($match.Count -gt 1) { throw "Several routing addresses possible for $($User.SamAccountName): keep one proxy address in $domain." }
    }
    if (-not $local -or $local -match '[\s@]' -or $domain -notmatch '^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$') { throw "No valid routing address for $($User.SamAccountName) (check Routing.RoutingDomain and the mail alias)." }
    return "$local@$domain"
}
#endregion

#region 4. Shared permissions ------------------------------------------------------------------

function Initialize-PraPermissionCache {
    <#
    .SYNOPSIS
        Clears the cache of expanded permission groups of this run (never touches AD or receipts).
    #>
    [CmdletBinding()]
    param([hashtable]$Context)
    [void]$script:PermissionCaches.Remove($Context)
}

function Get-PraPermissionCache {
    <# Bounded cache (groups, trustees) shared by the shared mailboxes of one batch. #>
    [CmdletBinding()]
    param([hashtable]$Context)
    $policy = (@($Context.Config.SharedMailbox.ExcludeTrusteeSamAccountNames | Sort-Object) -join "`n")
    $cache = $null
    if ($script:PermissionCaches.TryGetValue($Context, [ref]$cache)) {
        if ($cache.Server -ieq $Context.Server -and $cache.Policy -ceq $policy) { return $cache }
        [void]$script:PermissionCaches.Remove($Context)
    }
    $cache = @{ Server=[string]$Context.Server; Policy=$policy; Entries=@{}; Order=(New-Object 'Collections.Generic.Queue[string]'); UpnCount=0; MaxEntries=512; MaxUpns=100000; CharacterCount=0L; MaxCharacters=8000000L }
    $script:PermissionCaches.Add($Context, $cache)
    return $cache
}

function Add-PraPermissionCache {
    [CmdletBinding()]
    param([hashtable]$Context, [string]$Key, [AllowEmptyCollection()][string[]]$Upns)
    $cache = Get-PraPermissionCache -Context $Context
    if ($cache.Entries.ContainsKey($Key)) { return }
    $characters = 0L; foreach ($upn in $Upns) { $characters += $upn.Length }
    # The limits only reduce re-use; they never limit the permissions that are backed up.
    if ($Upns.Count -gt $cache.MaxUpns -or $characters -gt $cache.MaxCharacters) { return }
    while ($cache.Entries.Count -ge $cache.MaxEntries -or ($cache.UpnCount + $Upns.Count) -gt $cache.MaxUpns -or ($cache.CharacterCount + $characters) -gt $cache.MaxCharacters) {
        $oldKey = $cache.Order.Dequeue(); $old = $cache.Entries[$oldKey]
        $cache.UpnCount -= $old.Upns.Count; $cache.CharacterCount -= $old.Characters; $cache.Entries.Remove($oldKey)
    }
    $cache.Entries[$Key] = @{ Upns=[string[]]$Upns; Characters=$characters; CapturedUtc=[DateTime]::UtcNow.ToString('o') }
    $cache.Order.Enqueue($Key); $cache.UpnCount += $Upns.Count; $cache.CharacterCount += $characters
}

function Expand-PraTrustee {
    <# UPN(s) of a trustee: the user itself, or the members of a group (recursive), minus the exclusions. #>
    [CmdletBinding()]
    param([hashtable]$Context, $Object)
    $excluded = @($Context.Config.SharedMailbox.ExcludeTrusteeSamAccountNames)
    if ((Get-PraValue $Object 'sAMAccountName' '') -in $excluded) { return }
    if ($Object.objectClass -eq 'user') {
        $upn = [string](Get-PraValue $Object 'userPrincipalName' '')
        if (-not $upn) { throw "Trustee without UPN: $($Object.DistinguishedName)" }
        return $upn
    }
    if ($Object.objectClass -ne 'group') { throw "Unsupported trustee type: $($Object.objectClass)" }
    $cache = Get-PraPermissionCache -Context $Context
    $key = 'group:' + ([string]$Object.DistinguishedName).ToLowerInvariant()
    if ($cache.Entries.ContainsKey($key)) {
        Write-PraLog -Context $Context -Message ("PERMISSIONS CACHE | $($Object.DistinguishedName) | UPN=$($cache.Entries[$key].Upns.Count) | captured=$($cache.Entries[$key].CapturedUtc)") -Level Debug
        return $cache.Entries[$key].Upns
    }
    $Context.CurrentOperation = 'Expand-PermissionGroup'; $Context.CurrentIdentity = [string]$Object.DistinguishedName
    $seen = New-Object 'Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    $upns = New-Object 'Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    Write-PraLog -Context $Context -Message ("PERMISSIONS GROUP BEGIN | DC=$($Context.Server) | $($Object.DistinguishedName)") -Level Debug
    # Members are streamed: the whole member list of a large group is never kept in memory.
    Get-ADGroupMember -Identity $Object.DistinguishedName -Recursive -Server $Context.Server -ErrorAction Stop | ForEach-Object {
        $member = $_
        if ($member.objectClass -eq 'user' -and $seen.Add([string]$member.DistinguishedName)) {
            $memberKey = 'user:' + ([string]$member.DistinguishedName).ToLowerInvariant()
            if ($cache.Entries.ContainsKey($memberKey)) {
                foreach ($upn in $cache.Entries[$memberKey].Upns) { [void]$upns.Add($upn) }
            }
            else {
                $user = Get-ADUser -Identity $member.DistinguishedName -Properties userPrincipalName, sAMAccountName -Server $Context.Server -ErrorAction Stop
                $memberUpns = @()
                if ($user.SamAccountName -notin $excluded) {
                    if (-not $user.UserPrincipalName) { throw "Trustee without UPN: $($member.DistinguishedName)" }
                    $memberUpns = @([string]$user.UserPrincipalName); [void]$upns.Add([string]$user.UserPrincipalName)
                }
                Add-PraPermissionCache -Context $Context -Key $memberKey -Upns $memberUpns
            }
        }
    }
    $result = [string[]]@($upns | Sort-Object)
    # An enumeration error never reaches this point: a partial expansion is never cached.
    Add-PraPermissionCache -Context $Context -Key $key -Upns $result
    Write-PraLog -Context $Context -Message ("PERMISSIONS GROUP END | unique members=$($seen.Count) | unique UPN=$($result.Count)") -Level Debug
    return $result
}

function Resolve-PraAclTrustee {
    <#
    .SYNOPSIS
        UPN(s) behind the SID of an ACE. Well-known and administrative accounts/groups are ignored.
    .DESCRIPTION
        A SID that no AD object carries any more (deleted account, or an account of another domain) cannot
        receive a permission in Exchange Online: it is added to -Unknown and ignored. The caller reports it
        as a warning (console, log, report). Unknown SIDs are not cached, so every mailbox reports them.
    #>
    [CmdletBinding()]
    param([hashtable]$Context, $Reference, [Collections.Generic.List[string]]$Unknown)
    $sid = if ($Reference -is [Security.Principal.SecurityIdentifier]) { $Reference } else { $Reference.Translate([Security.Principal.SecurityIdentifier]) }
    # BUILTIN, NT AUTHORITY and Domain/Enterprise/Schema Admins are never reproduced.
    if ($sid.Value -match '^S-1-5-32-' -or $sid.Value -match '^S-1-5-[0-9]+$' -or
        $sid.Value -match '^S-1-5-21-[0-9]+-[0-9]+-[0-9]+-(512|518|519)$') { return }
    $name = [string]$Reference
    foreach ($pattern in @('NT AUTHORITY\*','BUILTIN\*','*\Domain Admins','*\Enterprise Admins','*\Schema Admins','*\Organization Management','*\Exchange Trusted Subsystem','*\Exchange Servers','*\Exchange Windows Permissions','*\Managed Availability Servers','*\Delegated Setup')) {
        if ($name -like $pattern) { return }
    }
    $cache = Get-PraPermissionCache -Context $Context
    $key = 'sid:' + $sid.Value
    if ($cache.Entries.ContainsKey($key)) { return $cache.Entries[$key].Upns }
    $Context.CurrentOperation = 'Resolve-PermissionTrustee'; $Context.CurrentIdentity = $sid.Value
    Write-PraLog -Context $Context -Message ("PERMISSIONS TRUSTEE | DC=$($Context.Server) | SID=$($sid.Value)") -Level Debug
    $objects = @(Get-ADObject -Filter "objectSid -eq '$($sid.Value)'" -Properties objectClass, userPrincipalName, sAMAccountName -Server $Context.Server -ErrorAction Stop)
    if ($objects.Count -eq 0) {
        if ($null -eq $Unknown) { throw "Permission trustee not found in AD: $($sid.Value)" }
        Write-PraLog -Context $Context -Message ("PERMISSIONS TRUSTEE | SID=$($sid.Value) | not found in AD (deleted account or another domain): ignored") -Level Detail
        if (-not $Unknown.Contains($sid.Value)) { $Unknown.Add($sid.Value) }
        return
    }
    if ($objects.Count -ne 1) { throw "Permission trustee not unique in AD: $($sid.Value)" }
    $excludedGroups = @('Domain Admins','Enterprise Admins','Schema Admins','Organization Management','Exchange Trusted Subsystem','Exchange Servers','Exchange Windows Permissions','Managed Availability Servers','Delegated Setup')
    if ($objects[0].objectClass -eq 'group' -and ((Get-PraValue $objects[0] 'sAMAccountName' '') -in $excludedGroups -or (Get-PraValue $objects[0] 'Name' '') -in $excludedGroups)) {
        Add-PraPermissionCache -Context $Context -Key $key -Upns @()
        return
    }
    $result = [string[]]@(Expand-PraTrustee -Context $Context -Object $objects[0])
    Add-PraPermissionCache -Context $Context -Key $key -Upns $result
    return $result
}

function Get-PraSharedPermission {
    <#
    .SYNOPSIS
        FullAccess, SendAs and SendOnBehalf holders (UPN) of a shared mailbox, read without Exchange.
    .DESCRIPTION
        PermissionSource = AD              SendAs: extended-right ACEs of nTSecurityDescriptor;
                                           FullAccess: ACEs with mask 0x1 of msExchMailboxSecurityDescriptor
        PermissionSource = Csv             one line Shared,Group in SharedMailbox.CsvPath: group members get both rights
        PermissionSource = CustomAttribute the group whose <CustomAttribute> = name of the shared mailbox
        PermissionSource = None            no FullAccess/SendAs
        SendOnBehalf always comes from publicDelegates (CaptureSendOnBehalf). Groups are expanded recursively.
    #>
    [CmdletBinding()]
    param([hashtable]$Context, $User)
    $settings = $Context.Config.SharedMailbox
    $Context.CurrentOperation = 'CaptureSharedPermissions/' + $settings.PermissionSource; $Context.CurrentIdentity = [string]$User.DistinguishedName
    $full = New-Object 'Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    $send = New-Object 'Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    $behalf = New-Object 'Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    # SIDs of the ACEs that no AD object carries any more: ignored, reported as a warning (Write-PraAdDelta).
    $unknownSendAs = New-Object 'Collections.Generic.List[string]'; $unknownFullAccess = New-Object 'Collections.Generic.List[string]'
    if (-not $Context.ContainsKey('_PraIgnoredTrustees')) { $Context['_PraIgnoredTrustees'] = @{} }
    [void]$Context['_PraIgnoredTrustees'].Remove(([guid]$User.ObjectGUID).ToString())
    if (-not $settings.Enabled) { return @{ FullAccess=@(); SendAs=@(); SendOnBehalf=@() } }
    Write-PraLog -Context $Context -Message "Shared mailbox permissions | DC=$($Context.Server) | $($User.DistinguishedName) | source=$($settings.PermissionSource)" -Level Debug
    switch ($settings.PermissionSource) {
        AD {
            # Descriptor read through Get-ADUser -Server, never through the AD: drive.
            $security = Get-PraValue $User 'nTSecurityDescriptor' $null
            if ($null -eq $security) { throw 'nTSecurityDescriptor cannot be read: SendAs capture incomplete (check the read rights of the account).' }
            $sendRules = if ($security -is [Security.AccessControl.ObjectSecurity]) { $security.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier]) } else { $security.Access }
            foreach ($ace in $sendRules) {
                if ($ace.AccessControlType -eq 'Allow' -and -not $ace.IsInherited -and
                    $ace.ActiveDirectoryRights -match 'ExtendedRight' -and [string]$ace.ObjectType -ieq 'ab721a54-1e2f-11d0-9819-00aa0040529b') {
                    foreach ($upn in @(Resolve-PraAclTrustee -Context $Context -Reference $ace.IdentityReference -Unknown $unknownSendAs)) { [void]$send.Add($upn) }
                }
            }
            if ($null -eq $User.PSObject.Properties['msExchMailboxSecurityDescriptor']) { throw 'msExchMailboxSecurityDescriptor not read.' }
            $mailboxSecurity = $User.msExchMailboxSecurityDescriptor
            if ($mailboxSecurity -is [byte[]]) {
                $descriptor = New-Object DirectoryServices.ActiveDirectorySecurity
                $descriptor.SetSecurityDescriptorBinaryForm($mailboxSecurity); $mailboxSecurity = $descriptor
            }
            if ($null -ne $mailboxSecurity) {
                $fullRules = if ($mailboxSecurity -is [Security.AccessControl.ObjectSecurity]) { $mailboxSecurity.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier]) } else { $mailboxSecurity.Access }
                foreach ($ace in $fullRules) {
                    if ($ace.AccessControlType -eq 'Allow' -and -not $ace.IsInherited -and (([int]$ace.ActiveDirectoryRights -band 1) -eq 1)) {
                        foreach ($upn in @(Resolve-PraAclTrustee -Context $Context -Reference $ace.IdentityReference -Unknown $unknownFullAccess)) { [void]$full.Add($upn) }
                    }
                }
            }
        }
        Csv {
            $names = @((Get-PraValue $User 'mailNickname' ''), $User.SamAccountName, (Get-PraValue $User 'DisplayName' ''), (Get-PraValue $User 'Name' ''))
            $permissionRows = @(Import-Csv -LiteralPath $settings.CsvPath -ErrorAction Stop | Where-Object { $_.Shared -in $names })
            if ($permissionRows.Count -ne 1 -or -not $permissionRows[0].Group) { throw "Permission CSV: no line (or several lines) Shared/Group for $($User.SamAccountName)." }
            $group = Get-PraGroup $Context $permissionRows[0].Group -WithoutMembers
            foreach ($upn in @(Expand-PraTrustee -Context $Context -Object $group)) { [void]$full.Add($upn); [void]$send.Add($upn) }
        }
        CustomAttribute {
            $attr = [string]$settings.CustomAttribute
            if ($attr -notmatch '^extensionAttribute([1-9]|1[0-5])$') { throw 'SharedMailbox.CustomAttribute is invalid.' }
            $filters = @(@((Get-PraValue $User 'mailNickname' ''), $User.SamAccountName, (Get-PraValue $User 'DisplayName' '')) | Where-Object { $_ } | Select-Object -Unique | ForEach-Object { "($attr=$(ConvertTo-PraLdapValue $_))" })
            $groups = @(Get-ADGroup -LDAPFilter ('(|' + ($filters -join '') + ')') -Server $Context.Server -ErrorAction Stop)
            if ($groups.Count -ne 1) { throw "Permission group not found or not unique for $($User.SamAccountName) ($attr)." }
            foreach ($upn in @(Expand-PraTrustee -Context $Context -Object $groups[0])) { [void]$full.Add($upn); [void]$send.Add($upn) }
        }
        None { }
        default { throw 'SharedMailbox.PermissionSource is invalid.' }
    }
    if ($settings.CaptureSendOnBehalf) {
        if ($null -eq $User.PSObject.Properties['publicDelegates']) { throw 'publicDelegates not read.' }
        $seenDelegates = New-Object 'Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
        foreach ($dn in @($User.publicDelegates)) {
            if (-not $dn -or -not $seenDelegates.Add([string]$dn)) { continue }
            $cache = Get-PraPermissionCache -Context $Context
            $key = 'delegate:' + ([string]$dn).ToLowerInvariant()
            if ($cache.Entries.ContainsKey($key)) { $upns = $cache.Entries[$key].Upns }
            else {
                $Context.CurrentOperation = 'Resolve-PublicDelegate'; $Context.CurrentIdentity = [string]$dn
                $delegate = Get-ADObject -Identity $dn -Properties objectClass, userPrincipalName, sAMAccountName -Server $Context.Server -ErrorAction Stop
                $upns = [string[]]@(Expand-PraTrustee -Context $Context -Object $delegate)
                Add-PraPermissionCache -Context $Context -Key $key -Upns $upns
            }
            foreach ($upn in $upns) { [void]$behalf.Add($upn) }
        }
    }
    Write-PraMemoryStage -Context $Context -Stage 'PERMISSIONS CAPTURED' -Identity ([string]$User.ObjectGUID) -Detail ("FullAccess=$($full.Count) SendAs=$($send.Count) SendOnBehalf=$($behalf.Count)")
    $ignored = @(@($unknownFullAccess | ForEach-Object { "FullAccess $_" }) + @($unknownSendAs | ForEach-Object { "SendAs $_" }))
    if ($ignored.Count) { $Context['_PraIgnoredTrustees'][([guid]$User.ObjectGUID).ToString()] = [string[]]$ignored }
    return @{ FullAccess=@($full | Sort-Object); SendAs=@($send | Sort-Object); SendOnBehalf=@($behalf | Sort-Object) }
}
#endregion

#region 5. Plans -------------------------------------------------------------------------------

function New-PraRow {
    <#
    .SYNOPSIS
        Result row of one object (CSV/HTML report, cloud phase). Memory only.
    #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions','',Justification='In-memory constructor, no change to any target or file.')]
    [CmdletBinding()]
    param([hashtable]$Context, $Record)
    [pscustomobject]@{
        ObjectGuid=[string](Get-PraValue $Record 'ObjectGuid' ''); SamAccountName=[string](Get-PraValue $Record 'SamAccountName' '')
        UserPrincipalName=[string](Get-PraValue $Record 'UserPrincipalName' ''); Action=$Context.Action
        IsShared=[bool](Get-PraValue $Record 'IsShared' $false); ADApplied=$null; ADVerified=$null; GroupAction=''
        BackupPath=''; LastOperation=''; CloudMailbox=$null; CloudLicense=$null; CloudStatus='N/A'; CloudDetail=''
        FinalStatus='Skipped'; Detail=''; SharedFullAccess=@(); SharedSendAs=@(); SharedSendOnBehalf=@(); PermMissing=@(); PermDetail=''; Warnings=''
        BackupRec=$Record; DeproPending=$false; RestoreDeferred=$false
        PreserveCloudMailbox=$false; PreserveLicense=$false; DeprovisionConfirmed=$false
    }
}

function New-PraPlan {
    <#
    .SYNOPSIS
        Reads one object (all attributes, security descriptors) and computes its target state. Read only.
    .PARAMETER Operation
        Convert      on-premises mailbox -> remote mailbox (targetAddress, remote types, Exchange
                     attributes cleared, routing proxy, retention tag, licence group or shared permissions)
        Recover      original attributes and licence group membership from the Convert backup
        Deprovision  shared mailbox: MailUser with msExchRemoteRecipientType 8, so that Exchange Online
                     removes the cloud shared mailbox before the on-premises attributes come back
        RestoreTag   original value of the retention tag only
    .PARAMETER SourceRecord
        Record of the Convert backup (Recover, Deprovision, RestoreTag).
    .PARAMETER RestoreRetention
        Recover: also restore the original retention tag (Finalize step).
    .OUTPUTS
        Plan: User (light), RawSnapshot (full capture), Record (backup record), Kinds, Desired, Row, Operation.
    #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions','',Justification='Reads and in-memory preparation only; writes are in Invoke-PraAdWrite.')]
    [CmdletBinding()]
    param([hashtable]$Context, [string]$Identity, [ValidateSet('Convert','Recover','Deprovision','RestoreTag')][string]$Operation, $SourceRecord = $null, [switch]$RestoreRetention)
    $Context.CurrentOperation = $Operation; $Context.CurrentIdentity = $Identity
    $config = $Context.Config
    if ($null -ne $SourceRecord) { Assert-PraDomain $Context ([string]$SourceRecord.DistinguishedName) }
    $tag = if ($Operation -eq 'Convert') { $config.Retention.Tag } else { Get-PraValue $SourceRecord 'Retention' $null }
    $tagEnabled = if ($Operation -eq 'Convert') { $config.Retention.Enabled -and $tag.Enabled } else { [bool](Get-PraValue $tag 'Enabled' $false) }
    $tagAttr = if ($tagEnabled) { [string]$tag.Attribute } else { '' }
    if ($tagAttr -and $tagAttr -notmatch '^extensionAttribute([1-9]|1[0-5])$') { throw "Retention tag attribute not allowed: $tagAttr" }
    if ($Operation -eq 'RestoreTag' -and -not $tagEnabled) { throw 'The original value of the retention tag is not in the backup: tag clean-up refused.' }
    $kinds = [ordered]@{}; foreach ($name in $script:AttributeKinds.Keys) { $kinds[$name] = $script:AttributeKinds[$name] }
    if ($tagAttr) { $kinds[$tagAttr] = 'String' }
    $user = Get-PraUser $Context $Identity -ExtraProperties @($kinds.Keys) -Capture
    $before = Get-PraAttributeState $user $kinds
    $shared = if ($Operation -eq 'Convert') { [int64]$user.msExchRecipientTypeDetails -eq 4 } else { [bool]$SourceRecord.IsShared }
    $desired = [ordered]@{}; foreach ($name in $before.Keys) { $desired[$name] = $before[$name] }
    $permissions = @{ FullAccess=@(); SendAs=@(); SendOnBehalf=@() }
    $licensing = [ordered]@{ Enabled=$false; GroupGuid=''; GroupDN=''; WasMember=$false; DesiredMember=$false }
    $routing = ''; $alreadyRecovered = $false
    if ($Operation -eq 'Convert') {
        if (-not $user.homeMDB -or [int64]$user.msExchRecipientTypeDetails -notin @(1, 4, 16, 32)) { throw "Not an on-premises mailbox (homeMDB / msExchRecipientTypeDetails): $Identity" }
        $routing = Get-PraRoutingAddress $Context $user
        $rrt = if ($shared) { [int64]$config.SharedMailbox.RemoteRecipientType } else { [int64]$config.Remote.RecipientType }
        if ($shared -and $rrt -in @(100, 102)) { throw "SharedMailbox.RemoteRecipientType=$rrt means an already migrated mailbox (Migrated+Shared): first provisioning refused before any change: $Identity" }
        if ($config.Remote.HandleArchives -and (Get-PraValue $user 'msExchArchiveGUID' $null)) { $rrt = $rrt -bor 2 }
        $desired.targetAddress = @{ Present=$true; Kind='String'; Value="SMTP:$routing" }
        $desired.msExchRecipientDisplayType = @{ Present=$true; Kind='Int'; Value='-2147483642' }
        $details = if ($shared) { '34359738368' } else { '2147483648' }
        $desired.msExchRecipientTypeDetails = @{ Present=$true; Kind='Long'; Value=$details }
        $desired.msExchRemoteRecipientType = @{ Present=$true; Kind='Long'; Value=[string]$rrt }
        foreach ($name in @('homeMDB','homeMTA','msExchHomeServerName','mDBUseDefaults')) { $desired[$name] = @{ Present=$false; Kind=$kinds[$name]; Value=$null } }
        if ($config.Remote.ClearMailboxGuid) { $desired.msExchMailboxGuid = @{ Present=$false; Kind='Bytes'; Value=$null } }
        $proxies = @($user.proxyAddresses)
        if (-not @($proxies | Where-Object { $_ -ieq "smtp:$routing" }).Count) { $proxies += "smtp:$routing" }
        $desired.proxyAddresses = @{ Present=$true; Kind='MultiString'; Value=[string[]]$proxies }
        if ($tagEnabled) { $desired[$tagAttr] = @{ Present=$true; Kind='String'; Value=[string]$tag.Value } }
        if ($shared) { $permissions = Get-PraSharedPermission $Context $user }
        elseif ($config.Licensing.Enabled) {
            $group = Get-PraGroup $Context $config.Licensing.GroupDN
            $licensing.Enabled = $true; $licensing.GroupGuid = ([guid]$group.ObjectGUID).ToString(); $licensing.GroupDN = [string]$group.DistinguishedName
            $licensing.WasMember = ([string]$user.DistinguishedName -in @($group.member)); $licensing.DesiredMember = $true
        }
    }
    elseif ($Operation -eq 'Deprovision') {
        if (-not $shared) { throw 'Deprovision is for shared mailboxes only.' }
        $remoteState = ([int64]$user.msExchRecipientTypeDetails -eq 34359738368)
        $pendingState = ([int64]$user.msExchRecipientTypeDetails -eq 128 -and [int64]$user.msExchRemoteRecipientType -eq 8)
        if (-not $remoteState -and -not $pendingState) {
            $alreadyRecovered = $true
            foreach ($name in $script:AttributeKinds.Keys) { if (-not (Test-PraStateEqual $before[$name] $SourceRecord.Attributes.$name)) { $alreadyRecovered = $false } }
            if (-not $alreadyRecovered) { throw 'Shared mailbox in an unexpected state: neither RemoteSharedMailbox, nor MailUser with RRT 8, nor its original state.' }
        }
        if (-not $alreadyRecovered) {
            if (-not (Get-PraValue $user 'targetAddress' '')) { throw 'targetAddress missing: a clean deprovisioning is not guaranteed.' }
            $desired.msExchRemoteRecipientType = @{ Present=$true; Kind='Long'; Value='8' }
            $desired.msExchRecipientDisplayType = @{ Present=$true; Kind='Int'; Value='6' }
            $desired.msExchRecipientTypeDetails = @{ Present=$true; Kind='Long'; Value='128' }
            foreach ($name in @('homeMDB','msExchHomeServerName','mDBUseDefaults','msExchMailboxGuid')) { $desired[$name] = @{ Present=$false; Kind=$kinds[$name]; Value=$null } }
        }
    }
    elseif ($Operation -eq 'Recover') {
        foreach ($name in $script:AttributeKinds.Keys) { $desired[$name] = $SourceRecord.Attributes.$name }
        $sourceGroup = Get-PraValue $SourceRecord 'Licensing' $null
        if ($null -ne $sourceGroup -and $sourceGroup.Enabled) {
            $group = Get-PraGroup $Context $sourceGroup.GroupGuid
            $licensing.Enabled = $true; $licensing.GroupGuid = ([guid]$group.ObjectGUID).ToString(); $licensing.GroupDN = [string]$group.DistinguishedName
            $licensing.WasMember = ([string]$user.DistinguishedName -in @($group.member)); $licensing.DesiredMember = [bool]$sourceGroup.WasMember
        }
        elseif ([bool](Get-PraValue $SourceRecord 'AddedToLicenseGroup' $false)) {
            throw 'Old backup without the GUID of the licence group: removal refused (a group with the same DN may have been re-created). Have the backup migrated before restoring this batch.'
        }
    }
    if ($Operation -eq 'RestoreTag' -or ($Operation -eq 'Recover' -and $RestoreRetention -and $tagEnabled)) {
        $original = $SourceRecord.Attributes.$tagAttr
        if (-not (Test-PraStateEqual $before[$tagAttr] $original) -and
            (-not $before[$tagAttr].Present -or [string]$before[$tagAttr].Value -cne [string]$tag.Value)) {
            throw "Retention tag $tagAttr changed by someone else: restore refused."
        }
        $desired[$tagAttr] = $original
    }
    $sourceLicensing = Get-PraValue $SourceRecord 'Licensing' $null
    $preserveMailbox = $shared -and $Operation -eq 'Recover' -and [bool](Get-PraValue $Context 'KeepCloudShared' $false)
    $preserveLicense = ($Operation -eq 'Recover') -and [bool](Get-PraValue $sourceLicensing 'Enabled' $false) -and [bool](Get-PraValue $sourceLicensing 'WasMember' $false)
    $record = [ordered]@{
        ObjectGuid=([guid]$user.ObjectGUID).ToString(); DistinguishedName=[string]$user.DistinguishedName
        SamAccountName=[string]$user.SamAccountName; UserPrincipalName=[string]$user.UserPrincipalName; DisplayName=[string](Get-PraValue $user 'DisplayName' $user.SamAccountName)
        CapturedUtc=[DateTime]::UtcNow.ToString('o'); CapturedUsnChanged=(Get-PraUsn $user); IsShared=$shared; RequestedOperation=$Operation
        Attributes=$before; PlannedAttributes=$desired; Licensing=$licensing
        Retention=[ordered]@{ Enabled=[bool]$tagEnabled; Attribute=$tagAttr; Value=$(if ($tagEnabled) { [string]$tag.Value } else { '' }) }
        SharedPermissions=$permissions; PreserveCloudMailbox=[bool]$preserveMailbox; PreserveLicense=[bool]$preserveLicense
    }
    $row = New-PraRow $Context $record
    if ($null -ne $SourceRecord) { $row.BackupRec = $SourceRecord } else { $row.BackupRec = [pscustomobject]$record }
    $row.PreserveCloudMailbox = [bool]$preserveMailbox; $row.PreserveLicense = [bool]$preserveLicense
    $ignoredEntries = Get-PraValue (Get-PraValue $Context '_PraIgnoredTrustees' @{}) $record.ObjectGuid @()
    $ignoredEntries = @($ignoredEntries | Where-Object { $_ })
    if ($shared -and $Operation -eq 'Convert' -and $ignoredEntries.Count) { $row.Warnings = 'Permission entries ignored (account unknown in AD): ' + ($ignoredEntries -join '; ') }
    $row.IsShared = $shared; $row.SharedFullAccess = @($permissions.FullAccess); $row.SharedSendAs = @($permissions.SendAs); $row.SharedSendOnBehalf = @($permissions.SendOnBehalf)
    $row.DeproPending = ($Operation -eq 'Deprovision' -and -not $alreadyRecovered); $row.Detail = "Operation=$Operation ; routing=$routing"; $row.LastOperation = 'Prepared'
    $plannedOperation = if ($alreadyRecovered) { 'AlreadyRecovered' } else { $Operation }
    $record.RequestedOperation = $plannedOperation
    $Context.CurrentOperation = 'Project-ADSnapshot'; $Context.CurrentIdentity = $record.ObjectGuid
    Write-PraMemoryStage -Context $Context -Stage 'PROJECTION BEGIN' -Identity $record.ObjectGuid -Detail $record.SamAccountName
    $rawSnapshot = ConvertTo-PraRawSnapshot -User $user -CapturedUtc $record.CapturedUtc
    $lightUser = [pscustomobject]@{ ObjectGUID=[guid]$record.ObjectGuid; DistinguishedName=$record.DistinguishedName; uSNChanged=[int64]$record.CapturedUsnChanged }
    Write-PraMemoryStage -Context $Context -Stage 'PROJECTION END' -Identity $record.ObjectGuid -Detail ("attributes=$($rawSnapshot.Attributes.Count) FullAccess=$(@($permissions.FullAccess).Count) SendAs=$(@($permissions.SendAs).Count) SendOnBehalf=$(@($permissions.SendOnBehalf).Count)")
    return [pscustomobject]@{ User=$lightUser; RawSnapshot=$rawSnapshot; Record=$record; Kinds=$kinds; Desired=$desired; Row=$row; Operation=$plannedOperation; ExpectedUsnChanged=$record.CapturedUsnChanged; Previewed=$false }
}
#endregion

#region 6. Backups and proofs -------------------------------------------------------------------

function Assert-PraStoredRecord {
    <# One record of a backup file is complete and correctly typed (never trusted blindly). #>
    [CmdletBinding()]
    param($Record, [switch]$Legacy, [switch]$Planned)
    $attributeStates = if ($Planned) { $Record.PlannedAttributes } else { $Record.Attributes }
    if ([guid]$Record.ObjectGuid -eq [guid]::Empty) { throw 'Backup: empty GUID.' }
    foreach ($name in @('DistinguishedName','SamAccountName','UserPrincipalName')) {
        if ((Get-PraValue $Record $name $null) -isnot [string] -or [string]::IsNullOrWhiteSpace($Record.$name)) { throw "Backup: $name missing or invalid." }
    }
    $kinds = [ordered]@{}; foreach ($name in $script:AttributeKinds.Keys) { $kinds[$name] = $script:AttributeKinds[$name] }
    $retention = Get-PraValue $Record 'Retention' $null
    if ($null -ne $retention -and $retention.Enabled) {
        if ($retention.Attribute -notmatch '^extensionAttribute([1-9]|1[0-5])$' -or $retention.Value -isnot [string]) { throw 'Backup: invalid retention tag metadata.' }
        $kinds[$retention.Attribute] = 'String'
    }
    foreach ($name in $kinds.Keys) {
        $state = Get-PraValue $attributeStates $name $null
        if ($null -eq $state -or (Get-PraValue $state 'Present' $null) -isnot [bool] -or $state.Kind -cne $kinds[$name]) { throw "Backup incomplete or wrong type: $name" }
        if (-not $state.Present) {
            if ($null -ne $state.Value) { throw "Backup: $name is absent but has a value." }
            continue
        }
        switch ($state.Kind) {
            Bool { if ($state.Value -isnot [bool]) { throw "Backup: invalid boolean $name" } }
            MultiString {
                if ($state.Value -isnot [array] -or @($state.Value).Count -eq 0) { throw "Backup: invalid list $name" }
                foreach ($value in $state.Value) { if ($value -isnot [string] -or -not $value) { throw "Backup: invalid text in $name" } }
            }
            default { if ($state.Value -isnot [string] -or -not $state.Value) { throw "Backup: invalid value $name" } }
        }
        $null = ConvertFrom-PraStoredValue $state
    }
    if (-not $Legacy) {
        if ($Record.CapturedUsnChanged -isnot [string] -or $Record.CapturedUsnChanged -notmatch '^[1-9][0-9]*$') { throw 'Backup: original uSNChanged missing or invalid.' }
        $null = [int64]::Parse($Record.CapturedUsnChanged, [Globalization.CultureInfo]::InvariantCulture)
        if ($Record.RequestedOperation -notin @('Convert','Recover','Deprovision','RestoreTag','AlreadyRecovered')) { throw 'Backup: invalid planned operation.' }
        if ($Record.PreserveCloudMailbox -isnot [bool] -or $Record.PreserveLicense -isnot [bool]) { throw 'Backup: invalid cloud post-conditions.' }
        if ($Record.PreserveCloudMailbox -and (-not $Record.IsShared -or $Record.RequestedOperation -ne 'Recover')) { throw 'Backup: keeping the cloud mailbox does not match the operation or the type.' }
        if ($Record.IsShared -isnot [bool] -or $Record.Licensing.Enabled -isnot [bool] -or $Record.Licensing.WasMember -isnot [bool] -or $Record.Licensing.DesiredMember -isnot [bool]) { throw 'Backup: invalid licence group or type state.' }
        if ($Record.Licensing.Enabled -and [guid]$Record.Licensing.GroupGuid -eq [guid]::Empty) { throw 'Backup: licence group GUID missing.' }
    }
    else {
        if ((Get-PraValue $Record 'AddedToLicenseGroup' $null) -isnot [bool]) { throw 'Old backup: licence group state not captured.' }
    }
}

function Import-PraBackup {
    <#
    .SYNOPSIS
        Reads and fully validates a backup (JSON, .sha256, CLIXML) and returns its receipt.
        Schema 3 (current), 2 and 1 (old versions, read with their restrictions) are accepted.
    #>
    [CmdletBinding()]
    param([hashtable]$Context, [Parameter(Mandatory)][string]$Path)
    $pathResolved = (Get-Item -LiteralPath $Path -ErrorAction Stop).FullName
    $registry = Get-PraReceiptRegistry -Context $Context
    foreach ($entry in $registry) {
        if ($entry.Path -ieq $pathResolved) {
            Assert-PraReceiptIntegrity -Context $Context -Entry $entry
            Write-PraLog -Context $Context -Message ("BACKUP INTEGRITY | already validated | $pathResolved | hashes re-read") -Level Debug
            return $entry.Receipt
        }
    }
    $Context.CurrentOperation = 'Read-BackupJson'
    $hashBeforeRead = Get-PraHash -Path $pathResolved
    $data = Get-Content -LiteralPath $pathResolved -Raw -Encoding UTF8 -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
    if ($data.Environment -cne $Context.Config.Environment) { throw "Backup of another Environment: '$($data.Environment)' (configuration: '$($Context.Config.Environment)')." }
    $version = Get-PraValue $data 'SchemaVersion' 1
    if ($version -notin @(1, 2, 3)) { throw "Backup schema not supported: $version" }
    if ($version -eq 3 -and (Get-PraValue $data 'RawFormat' '') -cne 'PraDataOnlyClixml-v1') { throw 'Backup capture format not supported.' }
    if ($data.Operation -notin @('Convert','Recover','Finalize','Retention')) { throw "This file is not an AD backup: $($data.Operation)" }
    $records = @($data.Records)
    if (-not $records.Count -or $null -eq $records[0]) { throw 'Backup without any record.' }
    $seen = @{}
    foreach ($record in $records) {
        Assert-PraStoredRecord $record -Legacy:($version -eq 1)
        if ($version -ge 2) { Assert-PraStoredRecord $record -Planned }
        $key = ([guid]$record.ObjectGuid).ToString()
        if ($seen.ContainsKey($key)) { throw "Same GUID twice in the backup: $key" }; $seen[$key] = $true
    }
    $hash = Get-PraHash $pathResolved
    if ($hash -cne $hashBeforeRead) { throw 'Backup JSON changed while it was read.' }
    $rawPath = ''; $rawHash = ''
    if ($version -ge 2) {
        $storedHash = (Get-Content -LiteralPath ($pathResolved + '.sha256') -Raw -ErrorAction Stop).Trim()
        if ($storedHash -cne $hash) { throw 'Backup SHA-256 does not match its .sha256 file.' }
        if ([IO.Path]::GetFileName($data.RawFile) -cne $data.RawFile) { throw 'Backup CLIXML path is not in the batch folder.' }
        $rawPath = Join-Path (Split-Path $pathResolved -Parent) $data.RawFile
        $rawHash = Get-PraHash -Path $rawPath
        if ($rawHash -cne $data.RawHash) { throw 'Backup CLIXML SHA-256 mismatch.' }
        $format = if ($version -eq 3) { [string]$data.RawFormat } else { '' }
        $Context.CurrentOperation = 'Validate-RawCapture'
        Write-PraMemoryStage -Context $Context -Stage 'RAW VALIDATE BEGIN' -Detail ("schema=$version objects=$($records.Count) file=$rawPath")
        $null = Test-PraRawCapture -Context $Context -LiteralPath $rawPath -Records $records -RawFormat $format
        # A change during the read never yields a receipt for different content.
        if ((Get-PraHash -Path $rawPath) -cne $rawHash) { throw 'Backup CLIXML changed during its validation.' }
        Write-PraMemoryStage -Context $Context -Stage 'RAW VALIDATE END' -Detail ("bytes=$((Get-Item -LiteralPath $rawPath -ErrorAction Stop).Length)")
    }
    else { Write-PraLog -Context $Context -Message 'Schema 1 backup (version 1.2.x): no proof of the original retention tag nor of the AD phase. Missing values are never invented.' -Level Warning }
    if ((Get-PraHash -Path $pathResolved) -cne $hash) { throw 'Backup JSON changed during its validation.' }
    $receipt = [pscustomobject]@{ Data=$data; Path=$pathResolved; Hash=$hash; Legacy=($version -eq 1) }
    Add-PraValidatedReceipt -Context $Context -Receipt $receipt -RawPath $rawPath -RawHash $rawHash
    return $receipt
}

function Assert-PraRecordMatchesPlan {
    <# The re-read backup record holds exactly the planned record (metadata, values, group, tag, permissions). #>
    [CmdletBinding()]
    param($Stored, [Collections.IDictionary]$Expected)
    foreach ($name in @('ObjectGuid','DistinguishedName','SamAccountName','UserPrincipalName','DisplayName','CapturedUtc','CapturedUsnChanged','IsShared','RequestedOperation','PreserveCloudMailbox','PreserveLicense')) {
        if ((Get-PraValue $Stored $name $null) -cne $Expected[$name]) { throw "Backup re-read: $name not preserved." }
    }
    foreach ($section in @('Attributes','PlannedAttributes')) {
        $actualNames = @($Stored.$section.PSObject.Properties.Name)
        if ($actualNames.Count -ne $Expected[$section].Count) { throw "Backup re-read: missing or extra attributes in $section." }
        foreach ($name in $Expected[$section].Keys) {
            $state = Get-PraValue $Stored.$section $name $null
            if ($null -eq $state -or -not (Test-PraStateEqual -Left $Expected[$section][$name] -Right $state)) { throw "Backup re-read: value not preserved $section/$name." }
        }
    }
    foreach ($section in @('Licensing','Retention')) {
        foreach ($name in $Expected[$section].Keys) {
            if ((Get-PraValue $Stored.$section $name $null) -cne $Expected[$section][$name]) { throw "Backup re-read: state not preserved $section/$name." }
        }
    }
    foreach ($right in @('FullAccess','SendAs','SendOnBehalf')) {
        $actual = Get-PraValue $Stored.SharedPermissions $right $null
        $wanted = @($Expected.SharedPermissions[$right])
        if ($null -eq $actual -or @($actual).Count -ne $wanted.Count) { throw "Backup re-read: incomplete permissions $right." }
        for ($index = 0; $index -lt $wanted.Count; $index++) {
            if ([string]$actual[$index] -cne [string]$wanted[$index]) { throw "Backup re-read: permission not preserved $right index=$index." }
        }
    }
}

function Save-PraBatch {
    <#
    .SYNOPSIS
        Writes the backup of the whole batch BEFORE any write: private folder Batch-<id> with
        <Operation>-<Environment>-<date>-<id>.json (typed records), .clixml (every AD value),
        .sha256, then re-reads and compares everything with the plans. Also opens the batch journal.
    #>
    [CmdletBinding()]
    param([hashtable]$Context, [Parameter(Mandatory)][object[]]$Plans, [string]$Operation)
    if (-not $Plans.Count) { throw 'Empty backup batch.' }
    $Context.CurrentOperation = 'Capture/Persist/Verify'; $Context.CurrentIdentity = 'Batch'
    $id = [guid]::NewGuid().ToString('N')
    $directory = Join-Path $Context.BackupFolder ('Batch-' + $id)
    $base = "$Operation-$($Context.Config.Environment)-$(Get-Date -Format 'yyyyMMdd_HHmmss')-$($id.Substring(0, 8))"
    $rawPath = Join-Path $directory ($base + '.clixml')
    $path = Join-Path $directory ($base + '.json')
    if ($rawPath.Length -ge 248) { throw 'Backup path too long for Windows PowerShell 5.1: use a shorter Storage.BackupFolder.' }
    New-PraPrivateDirectory $directory
    Write-PraLog -Context $Context -Message "BACKUP BEGIN | $($Plans.Count) object(s) | $path" -Level Detail
    $snapshots = @($Plans | ForEach-Object { $_.RawSnapshot })
    $Context.CurrentOperation = 'Write-RawCapture'
    Write-PraMemoryStage -Context $Context -Stage 'RAW WRITE BEGIN' -Detail ("objects=$($snapshots.Count) file=$rawPath")
    Write-PraRawCapture -Context $Context -LiteralPath $rawPath -Snapshots $snapshots
    Write-PraMemoryStage -Context $Context -Stage 'RAW WRITE END' -Detail ("bytes=$((Get-Item -LiteralPath $rawPath -ErrorAction Stop).Length)")
    $data = [ordered]@{
        SchemaVersion=3; RawFormat='PraDataOnlyClixml-v1'; Operation=$Operation; RunId=$Context.RunId; BatchId=$id; Environment=$Context.Config.Environment
        Server=$Context.Server; NamingContext=$Context.NamingContext; CreatedUtc=[DateTime]::UtcNow.ToString('o')
        RawFile=[IO.Path]::GetFileName($rawPath); RawHash=(Get-PraHash $rawPath)
        SourceBackupHash=$Context.SourceBackupHash; Records=@($Plans | ForEach-Object { $_.Record })
    }
    $Context.CurrentOperation = 'Write-BackupJson'
    $json = $data | ConvertTo-Json -Depth 30
    Write-PraImmutableFile $path $json
    $json = $null
    Write-PraImmutableFile ($path + '.sha256') (Get-PraHash $path)
    $Context.CurrentOperation = 'Validate-BackupAgainstPlan'
    $null = Test-PraRawCapture -Context $Context -LiteralPath $rawPath -Records $data.Records -RawFormat $data.RawFormat -ExpectedSnapshots $snapshots
    $receipt = Import-PraBackup $Context $path
    # A valid JSON is not necessarily complete: compare it with the plans in memory.
    for ($i = 0; $i -lt $Plans.Count; $i++) {
        $record = $receipt.Data.Records[$i]
        if ($record.ObjectGuid -cne $Plans[$i].Record.ObjectGuid) { throw 'Backup order or identity differs from the plan.' }
        Assert-PraRecordMatchesPlan -Stored $record -Expected $Plans[$i].Record
    }
    $Context.BackupFiles.Add($path)
    $Context.JournalPath = Join-Path $directory ('Journal-' + $id + '.jsonl')
    Write-PraImmutableFile $Context.JournalPath ''
    $Context.StateFiles.Add($Context.JournalPath)
    foreach ($plan in $Plans) { $plan.Row.BackupPath = $path }
    Write-PraJournal $Context '*' 'Backup' 'Verified' $path
    Write-PraLog -Context $Context -Message "BACKUP VERIFIED | $path | SHA256=$($receipt.Hash) | JSON + CLIXML re-read" -Level Detail
    Write-PraItem -Context $Context -Status Ok -Icon Backup -Text ("Backup of {0} object(s) written and re-read {1} batch {2}" -f $Plans.Count, [char]0x00B7, $id.Substring(0, 8))
    Write-PraLog -Context $Context -Message $directory -Level Sub
    return $receipt
}

function Assert-PraReceipt {
    <#
    .SYNOPSIS
        The object is covered by the validated backup, and the backup is unchanged.
    #>
    [CmdletBinding()]
    param([hashtable]$Context, $Receipt, [string]$ObjectGuid)
    $entry = Get-PraReceiptEntry -Context $Context -Receipt $Receipt
    if (-not $entry.Guids.Contains($ObjectGuid)) { throw "Object not covered by the validated backup: $ObjectGuid" }
    Assert-PraReceiptIntegrity -Context $Context -Entry $entry
}

function Assert-PraCurrentState {
    <# Re-reads the object: same version (uSNChanged), same DN, expected values and group membership. #>
    [CmdletBinding()]
    param([hashtable]$Context, $Plan, [Collections.IDictionary]$Expected, [bool]$ExpectedMember, [switch]$AcceptNewVersion)
    $user = Get-PraUser $Context $Plan.Record.ObjectGuid -ExtraProperties @($Plan.Kinds.Keys)
    $version = Get-PraUsn $user
    if (-not $AcceptNewVersion -and $version -cne $Plan.ExpectedUsnChanged) { throw 'uSNChanged changed: the object was modified since it was planned or last verified.' }
    if ([string]$user.DistinguishedName -cne $Plan.Record.DistinguishedName) { throw 'The DN changed since the capture: plan the batch again.' }
    $actual = Get-PraAttributeState $user $Plan.Kinds
    foreach ($name in $Expected.Keys) {
        if (-not (Test-PraStateEqual $Expected[$name] $actual[$name])) { throw "AD state differs from the expected state | GUID=$($Plan.Record.ObjectGuid) | attribute=$name | DC=$($Context.Server)" }
    }
    if ($Plan.Record.Licensing.Enabled) {
        $group = Get-PraGroup $Context $Plan.Record.Licensing.GroupGuid
        if ($group.DistinguishedName -cne $Plan.Record.Licensing.GroupDN -or
            ([string]$user.DistinguishedName -in @($group.member)) -ne $ExpectedMember) { throw 'Licence group membership differs from the backup/plan.' }
    }
    if ($AcceptNewVersion) { $Plan.ExpectedUsnChanged = $version }
}
#endregion

#region 7. Writes ------------------------------------------------------------------------------

function Invoke-PraAdWrite {
    <#
    .SYNOPSIS
        One AD write (Set-ADUser, Add-ADGroupMember or Remove-ADGroupMember) with every guard:
        no previous error, Apply mode, ShouldProcess, validated backup covering the object,
        operator approval, current state re-read AFTER the approval, journal Started/Applied.
    #>
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Low')]
    param([hashtable]$Context, $Receipt, $Plan, [string]$Operation, [scriptblock]$Write)
    if ([bool](Get-PraValue $Context 'OperationFailed' $false) -or $Context.Issues.Count -gt 0 -or @($Context.Rows | Where-Object FinalStatus -eq 'Error').Count -gt 0) { throw 'Safety stop: no AD write after an error in this run.' }
    if (-not $Context.AllowMutation -or $Context.Mode -ne 'Apply' -or $Context.Action -eq 'Check' -or $WhatIfPreference) { throw 'Safety stop: AD writes are not allowed in this mode.' }
    if (-not $PSCmdlet.ShouldProcess($Plan.Record.ObjectGuid, $Operation)) { throw 'AD write not authorised (ShouldProcess).' }
    Assert-PraReceipt $Context $Receipt $Plan.Record.ObjectGuid
    if (-not (& $Context.Approval $Plan.Record.DistinguishedName $Operation)) { throw "Operation refused: $Operation. Batch stopped." }
    # An interactive confirmation can take time: re-check the object and the backup AFTER it.
    $expected = if ($Operation -eq 'Set-ADUser') { $Plan.Record.Attributes } else { $Plan.Desired }
    Assert-PraCurrentState $Context $Plan $expected $Plan.Record.Licensing.WasMember
    Assert-PraReceipt $Context $Receipt $Plan.Record.ObjectGuid
    $Context.CurrentOperation = $Operation; $Context.CurrentIdentity = $Plan.Record.ObjectGuid
    $Plan.Row.LastOperation = $Operation; $Plan.Row.Detail += " | attempt=$Operation"
    Write-PraJournal $Context $Plan.Record.ObjectGuid $Operation 'Started'
    Write-PraLog -Context $Context -Message "AD WRITE BEGIN | $Operation | DC=$($Context.Server) | GUID=$($Plan.Record.ObjectGuid) | backup=$($Receipt.Path)" -Level Detail
    # Any exception goes up to Invoke-PraAdBatch: no next object, no sync.
    & $Write | Out-Null
    $Plan.Row.ADApplied = $true
    Write-PraJournal $Context $Plan.Record.ObjectGuid $Operation 'Applied'
}

function Invoke-PraAdPreview {
    <#
    .SYNOPSIS
        Adds the planned objects to the results and shows their planned changes (before the
        confirmation). Invoke-PraAdBatch does not show them again.
    #>
    [CmdletBinding()]
    param([hashtable]$Context, [AllowEmptyCollection()][object[]]$Plans)
    foreach ($plan in $Plans) {
        if (-not $Context.Rows.Contains($plan.Row)) { $Context.Rows.Add($plan.Row) }
        Write-PraAdDelta -Context $Context -Plan $plan -Stage Planned
        $plan.Previewed = $true
    }
}

function Invoke-PraAdBatch {
    <#
    .SYNOPSIS
        Applies a batch of plans: backup of the whole batch, then for each object Set-ADUser and the
        licence group change, each followed by an AD re-read; finally the State file (AD proof).
    .DESCRIPTION
        Preview (or -WhatIf): the rows are marked Planned and nothing is written (no backup either).
        The first error stops the batch; previous objects keep their changes (no automatic rollback):
        the journal and the backup say exactly what was done.
    .OUTPUTS
        The receipt of the batch backup, with a StatePath property; $null in Preview.
    #>
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Low')]
    param([hashtable]$Context, [AllowEmptyCollection()][object[]]$Plans, [ValidateSet('Convert','Recover','Finalize','Retention')][string]$Operation)
    $Context.LastVerifiedReceipt = $null
    if ([bool](Get-PraValue $Context 'OperationFailed' $false) -or $Context.Issues.Count -gt 0 -or @($Context.Rows | Where-Object FinalStatus -eq 'Error').Count -gt 0) { throw 'No new batch after an error in this run.' }
    if (-not $Plans.Count) { Write-PraItem -Context $Context -Status Skip -Text 'Nothing to do.'; return $null }
    foreach ($plan in $Plans) { if (-not $Context.Rows.Contains($plan.Row)) { $Context.Rows.Add($plan.Row) } }
    try {
        foreach ($plan in $Plans) { if (-not [bool](Get-PraValue $plan 'Previewed' $false)) { Write-PraAdDelta -Context $Context -Plan $plan -Stage Planned } }
        if (-not $Context.AllowMutation -or $Context.Mode -ne 'Apply' -or $Context.Action -eq 'Check' -or $WhatIfPreference) {
            foreach ($plan in $Plans) {
                $plan.Row.FinalStatus = 'Planned'; $plan.Row.ADApplied = $false; $plan.Row.LastOperation = 'PreparedOnly'
                Write-PraLog -Context $Context -Message "$($plan.Record.SamAccountName) | $($plan.Operation) | Planned | nothing written" -Level Detail
            }
            Write-PraItem -Context $Context -Status Skip -Text ("Preview: no backup and no AD change ({0} object(s) planned)." -f $Plans.Count)
            return $null
        }
        if (-not $PSCmdlet.ShouldProcess("$($Plans.Count) object(s)", 'Apply a backed-up and verified AD batch')) { throw 'AD batch refused.' }
        $receipt = Save-PraBatch $Context $Plans $Operation
        foreach ($plan in $Plans) {
            try {
                $before = $plan.Record.Attributes; $groupState = $plan.Record.Licensing
                Assert-PraCurrentState $Context $plan $before $groupState.WasMember
                $replace = @{}; $clear = New-Object 'Collections.Generic.List[string]'
                foreach ($name in $plan.Kinds.Keys) {
                    if (Test-PraStateEqual $before[$name] $plan.Desired[$name]) { continue }
                    if ($plan.Desired[$name].Present) { $replace[$name] = ConvertFrom-PraStoredValue $plan.Desired[$name] } else { $clear.Add($name) }
                }
                $changed = $replace.Count -gt 0 -or $clear.Count -gt 0
                if ($changed) {
                    $parameters = @{ Identity=[guid]$plan.Record.ObjectGuid; Server=$Context.Server; ErrorAction='Stop'; Confirm=$false }
                    if ($replace.Count) { $parameters.Replace = $replace }; if ($clear.Count) { $parameters.Clear = $clear.ToArray() }
                    Invoke-PraAdWrite $Context $receipt $plan 'Set-ADUser' { Set-ADUser @parameters }
                    Assert-PraCurrentState $Context $plan $plan.Desired $groupState.WasMember -AcceptNewVersion
                    Write-PraJournal $Context $plan.Record.ObjectGuid 'Set-ADUser' 'Verified'
                }
                if ($groupState.Enabled -and $groupState.WasMember -ne $groupState.DesiredMember) {
                    # Re-read before each new write: the group must not have changed.
                    Assert-PraCurrentState $Context $plan $plan.Desired $groupState.WasMember
                    $parameters = @{ Identity=[guid]$groupState.GroupGuid; Members=[guid]$plan.Record.ObjectGuid; Server=$Context.Server; ErrorAction='Stop'; Confirm=$false }
                    if ($groupState.DesiredMember) { Invoke-PraAdWrite $Context $receipt $plan 'Add-ADGroupMember' { Add-ADGroupMember @parameters }; $plan.Row.GroupAction = 'Added' }
                    else { Invoke-PraAdWrite $Context $receipt $plan 'Remove-ADGroupMember' { Remove-ADGroupMember @parameters }; $plan.Row.GroupAction = 'Removed' }
                    $changed = $true
                }
                else { $plan.Row.GroupAction = if ($groupState.Enabled) { 'Preserved' } else { 'N/A' } }
                Assert-PraCurrentState $Context $plan $plan.Desired $groupState.DesiredMember
                $plan.Row.ADVerified = $true; $plan.Row.ADApplied = $changed; $plan.Row.LastOperation = 'ADVerified'
                $plan.Row.FinalStatus = if ($plan.Row.DeproPending) { 'Pending' } elseif ($changed) { 'Success' } else { 'AlreadyDone' }
                Write-PraJournal $Context $plan.Record.ObjectGuid $plan.Operation 'Verified'
                Write-PraLog -Context $Context -Message "AD VERIFIED | $($plan.Record.SamAccountName) | $($plan.Row.FinalStatus)" -Level Detail
                Write-PraAdDelta -Context $Context -Plan $plan -Stage Verified
            }
            catch {
                $plan.Row.FinalStatus = 'Error'; $plan.Row.ADVerified = $false
                $plan.Row.Detail += " | FAILED: $($_.Exception.Message) | The object may be partly changed: see the journal and the backup."
                try { Write-PraJournal $Context $plan.Record.ObjectGuid $plan.Row.LastOperation 'FailedOrIndeterminate' $_.Exception.Message }
                catch { Write-PraLog -Context $Context -Message 'The journal cannot be written any more; the original backups are separate files.' -Level Error }
                throw
            }
        }
        $state = [ordered]@{
            SchemaVersion=2; Operation=$Operation; Kind='ADVerified'; Environment=$Context.Config.Environment; RunId=$Context.RunId
            BackupFile=[IO.Path]::GetFileName($receipt.Path); BackupHash=$receipt.Hash; SourceBackupHash=$Context.SourceBackupHash
            CreatedUtc=[DateTime]::UtcNow.ToString('o')
            Records=@($Plans | ForEach-Object { [ordered]@{ ObjectGuid=$_.Record.ObjectGuid; Operation=$_.Operation; ADVerified=$true; VerifiedUsnChanged=$_.ExpectedUsnChanged } })
        }
        $statePath = Join-Path (Split-Path $receipt.Path -Parent) ('State-' + $receipt.Data.BatchId + '.json')
        Write-PraImmutableFile $statePath ($state | ConvertTo-Json -Depth 12)
        Write-PraImmutableFile ($statePath + '.sha256') (Get-PraHash $statePath)
        $Context.StateFiles.Add($statePath)
        $receipt | Add-Member -NotePropertyName StatePath -NotePropertyValue $statePath
        $Context.LastVerifiedReceipt = $receipt
        return $receipt
    }
    catch {
        $Context.OperationFailed = $true; $Context.LastVerifiedReceipt = $null
        $failure = $_
        try { Write-PraLog -Context $Context -Message "AD batch stopped: $($failure.Exception.Message). No further write in this run." -Level Error }
        catch { $Context.Issues.Add([pscustomobject]@{ Message=$failure.Exception.Message; Source='ADBatch' }) }
        throw $failure
    }
    finally { Initialize-PraPermissionCache -Context $Context }
}

function Import-PraProof {
    <#
    .SYNOPSIS
        Reads and checks a State file (AD proof of a batch) against its backup and its Convert source.
    .PARAMETER Source
        Receipt of the original Convert backup.
    .PARAMETER Operation
        Convert, Recover, Finalize or Retention: operation expected in the proof.
    #>
    [CmdletBinding()]
    param([hashtable]$Context, [string]$Path, $Source, [string]$Operation)
    $data = Get-Content -LiteralPath $Path -Raw -Encoding UTF8 -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
    $hash = Get-PraHash $Path
    if ((Get-Content -LiteralPath ($Path + '.sha256') -Raw -ErrorAction Stop).Trim() -cne $hash) { throw 'AD proof (State file): SHA-256 mismatch.' }
    if ($data.SchemaVersion -ne 2 -or $data.Kind -ne 'ADVerified' -or $data.Environment -cne $Context.Config.Environment -or $data.Operation -cne $Operation) { throw "AD proof (State file) does not match: operation $($data.Operation) instead of $Operation, or another Environment." }
    if ([IO.Path]::GetFileName($data.BackupFile) -cne $data.BackupFile) { throw 'AD proof: invalid backup path.' }
    $receipt = Import-PraBackup $Context (Join-Path (Split-Path $Path -Parent) $data.BackupFile)
    if ($receipt.Hash -cne $data.BackupHash -or $receipt.Data.Operation -cne $Operation -or $receipt.Data.RunId -cne $data.RunId -or $receipt.Data.SourceBackupHash -cne $data.SourceBackupHash) { throw 'AD proof does not match its backup, operation or source.' }
    if (@($data.Records).Count -ne @($receipt.Data.Records).Count) { throw 'AD proof incomplete compared with its backup.' }
    $expectedSource = if ($Operation -eq 'Convert') { $data.BackupHash } else { $data.SourceBackupHash }
    if ($expectedSource -cne $Source.Hash) { throw 'AD proof built from another Convert batch.' }
    $seen = @{}
    foreach ($record in @($data.Records)) {
        if ($record.ADVerified -isnot [bool] -or -not $record.ADVerified -or $record.ObjectGuid -notin @($Source.Data.Records.ObjectGuid) -or $seen.ContainsKey($record.ObjectGuid)) { throw 'AD proof: invalid or duplicated object.' }
        $captured = @($receipt.Data.Records | Where-Object ObjectGuid -eq $record.ObjectGuid)
        $allowed = switch ($Operation) { Convert { @('Convert') } Recover { @('Recover','Deprovision','AlreadyRecovered') } Finalize { @('Recover','RestoreTag','AlreadyRecovered') } Retention { @('RestoreTag') } default { @() } }
        if ($captured.Count -ne 1 -or $record.Operation -notin $allowed -or $record.Operation -cne $captured[0].RequestedOperation -or
            $record.VerifiedUsnChanged -isnot [string] -or $record.VerifiedUsnChanged -notmatch '^[1-9][0-9]*$') { throw 'AD proof: operation or version does not match the backup.' }
        $null = [int64]::Parse($record.VerifiedUsnChanged, [Globalization.CultureInfo]::InvariantCulture)
        $seen[$record.ObjectGuid] = $true
    }
    if (-not $seen.Count) { throw 'AD proof is empty.' }
    return [pscustomobject]@{ Data=$data; Path=$Path; Hash=$hash; Receipt=$receipt }
}

function Assert-PraFollowupState {
    <#
    .SYNOPSIS
        Before the final restore (Finalize or inline): the object is still exactly as the AD proof left it.
        uSNChanged is local to one domain controller: the DC of the proof must be used.
    #>
    [CmdletBinding()]
    param([hashtable]$Context, $Plan, $Proof)
    if ($Context.Server -ine $Proof.Receipt.Data.Server) { throw "Finalize: use the domain controller of the proof '$($Proof.Receipt.Data.Server)' (uSNChanged cannot be compared between DCs); set DomainController in the configuration." }
    $verified = @($Proof.Data.Records | Where-Object ObjectGuid -eq $Plan.Record.ObjectGuid)
    $captured = @($Proof.Receipt.Data.Records | Where-Object ObjectGuid -eq $Plan.Record.ObjectGuid)
    if ($verified.Count -ne 1 -or $captured.Count -ne 1) { throw 'Finalize: object not in the AD proof.' }
    $previous = $captured[0]
    if ($previous.Licensing.Enabled) {
        $group = Get-PraGroup $Context $previous.Licensing.GroupGuid
        if ($group.DistinguishedName -cne $previous.Licensing.GroupDN -or
            ([string]$Plan.User.DistinguishedName -in @($group.member)) -ne $previous.Licensing.DesiredMember) { throw 'Finalize: licence group membership differs from the AD proof.' }
    }
    # Already finished (replay): only the complete original state is accepted, it needs no write.
    $original = $Plan.Row.BackupRec
    $complete = $true
    foreach ($name in $Plan.Kinds.Keys) {
        $sourceState = Get-PraValue $original.Attributes $name $null
        if ($null -eq $sourceState -or -not (Test-PraStateEqual $Plan.Record.Attributes[$name] $sourceState)) { $complete = $false }
    }
    if ($complete -and (-not $Plan.Record.Licensing.Enabled -or $Plan.Record.Licensing.WasMember -eq $Plan.Record.Licensing.DesiredMember)) { return }
    if ((Get-PraUsn $Plan.User) -cne $verified[0].VerifiedUsnChanged -or $Plan.User.DistinguishedName -cne $previous.DistinguishedName) {
        throw 'Finalize: the AD proof is out of date (version or DN changed). Nothing is overwritten: run the AD phase and the cloud check again.'
    }
    foreach ($name in $Plan.Kinds.Keys) {
        $expected = Get-PraValue $previous.PlannedAttributes $name $null
        if ($null -eq $expected -or -not (Test-PraStateEqual $Plan.Record.Attributes[$name] $expected)) { throw "Finalize: $name differs from the AD proof." }
    }
}
#endregion

#region 8. Entra Connect -----------------------------------------------------------------------

# Runs one synchronisation cycle and waits for its end. Self-contained: also sent to a remote server.
$script:PraSyncCycle = {
    param([string]$PolicyType, [int]$TimeoutMinutes)
    $ErrorActionPreference = 'Stop'
    Import-Module ADSync -ErrorAction Stop
    $deadline = [DateTime]::UtcNow.AddMinutes($TimeoutMinutes)
    $clock = [Diagnostics.Stopwatch]::StartNew()
    while ((Get-ADSyncScheduler -ErrorAction Stop).SyncCycleInProgress) {
        if ([DateTime]::UtcNow -gt $deadline) { throw 'Timeout: a synchronisation cycle was already running.' }
        Start-Sleep -Seconds 5
    }
    $result = Start-ADSyncSyncCycle -PolicyType $PolicyType -ErrorAction Stop
    if ([string]$result.Result -ne 'Success') { throw "Entra Connect refused the cycle: $($result.Result)" }
    Start-Sleep -Seconds 10
    while ((Get-ADSyncScheduler -ErrorAction Stop).SyncCycleInProgress) {
        if ([DateTime]::UtcNow -gt $deadline) { throw 'Timeout: the synchronisation cycle did not end in time; the cloud part is not started.' }
        Start-Sleep -Seconds 5
    }
    [pscustomobject]@{ Result = [string]$result.Result; Seconds = [int]$clock.Elapsed.TotalSeconds; Computer = $env:COMPUTERNAME }
}

function Invoke-PraSync {
    <#
    .SYNOPSIS
        After a verified AD batch (Apply): runs one Entra Connect cycle (EntraConnect.PolicyType) and
        waits for its end, on this server (ADSync module) or on EntraConnect.Server (PowerShell remoting).
    .DESCRIPTION
        EntraConnect.Sync = $false: nothing is run; a warning reminds the operator to synchronise
        before the cloud part. The sync is refused if the batch is not proven in this run.
    #>
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Low')]
    param([hashtable]$Context)
    if (-not $Context.AllowMutation -or $Context.Mode -ne 'Apply' -or $Context.Action -notin @('Convert','Recover','Finalize') -or $WhatIfPreference) { return }
    $settings = $Context.Config.EntraConnect
    if (-not $settings.Sync) {
        Write-PraItem -Context $Context -Status Warn -Text 'EntraConnect.Sync = $false: run a delta synchronisation on the Entra Connect server now (Start-ADSyncSyncCycle -PolicyType Delta) or wait for the scheduled one.'
        return
    }
    if (-not $PSCmdlet.ShouldProcess($(if ($settings.Server) { $settings.Server } else { $env:COMPUTERNAME }), 'Start an Entra Connect synchronisation cycle')) { return }
    if (-not @($Context.Rows | Where-Object { (Get-PraValue $_ 'ADApplied' $null) -eq $true }).Count) {
        Write-PraItem -Context $Context -Status Skip -Text 'No AD change in this run: no synchronisation needed.'
        return
    }
    $receipt = Get-PraValue $Context 'LastVerifiedReceipt' $null
    if ($null -eq $receipt -or $receipt.Data.RunId -cne $Context.RunId) { throw 'Synchronisation refused: no verified AD batch in this run.' }
    if ([bool](Get-PraValue $Context 'OperationFailed' $false) -or $Context.Issues.Count -gt 0 -or @($Context.Rows | Where-Object FinalStatus -eq 'Error').Count -gt 0) { throw 'Synchronisation refused after an error in this run.' }
    $source = if ($receipt.Data.Operation -eq 'Convert') { $receipt } else { Get-PraValue $Context 'Source' $null }
    if ($null -eq $source) { throw 'Synchronisation refused: the Convert source of the batch is unknown.' }
    $null = Import-PraProof $Context $receipt.StatePath $source $receipt.Data.Operation
    if (-not $Context.JournalPath -or -not (Test-Path -LiteralPath $Context.JournalPath -PathType Leaf)) { throw 'Synchronisation refused: the batch journal is missing.' }
    $target = if ($settings.Server) { $settings.Server } else { $env:COMPUTERNAME }
    $Context.CurrentOperation = 'Start-ADSyncSyncCycle'; $Context.CurrentIdentity = $target
    if (-not (& $Context.Approval $target 'Start-ADSyncSyncCycle')) { throw 'Synchronisation refused.' }
    Write-PraJournal $Context '*' 'ADSync' 'Started' $target
    Write-PraItem -Context $Context -Status Info -Icon Sync -Text ("{0} cycle started on {1}, waiting for its end (max {2} min)..." -f $settings.PolicyType, $target, $settings.TimeoutMinutes)
    if ($settings.Server) {
        $result = Invoke-Command -ComputerName $settings.Server -ScriptBlock $script:PraSyncCycle -ArgumentList $settings.PolicyType, $settings.TimeoutMinutes -ErrorAction Stop
    }
    else { $result = & $script:PraSyncCycle $settings.PolicyType $settings.TimeoutMinutes }
    Write-PraJournal $Context '*' 'ADSync' 'Completed' $target
    Write-PraItem -Context $Context -Status Ok -Icon Sync -Text ("Entra Connect cycle finished on {0} in {1} s (Exchange Online may still need a few minutes)" -f $target, (Get-PraValue $result 'Seconds' 0))
}
#endregion

Export-ModuleMember -Function ConvertTo-PraLdapValue, Get-PraHash, Write-PraImmutableFile, New-PraPrivateDirectory, Write-PraJournal,
    Initialize-PraDirectory, Get-PraUser, Get-PraTarget, New-PraRow, New-PraPlan, Import-PraBackup, Invoke-PraAdPreview, Invoke-PraAdBatch,
    Import-PraProof, Invoke-PraSync, Assert-PraReceipt, Test-PraStateEqual, Assert-PraFollowupState, Initialize-PraPermissionCache
