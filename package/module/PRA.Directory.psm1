#Requires -Version 7.5
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
    Version : 3.0.0
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
# Bounds of the list of X500 addresses expected in Exchange Online (record field ExpectedX500): count and length of one value.
$script:MaxExpectedX500 = 2000
$script:MaxExpectedX500Length = 2048
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
        foreach ($item in $Value) {
            # Permission lists dominate large receipts. Keep the same wire bytes and limits
            # without creating an advanced-function invocation for every individual string.
            if ($item -is [string]) {
                if ($Depth -ge 64) { throw 'Receipt data too deep or cyclic.' }
                $State.Nodes++
                if ($State.Nodes -gt 10000000) { throw 'Receipt data too large.' }
                $writer.Write([byte]1); $writer.Write([int]$item.Length)
                for ($offset = 0; $offset -lt $item.Length; $offset += 1024) {
                    $count = [math]::Min(1024, $item.Length - $offset)
                    $item.CopyTo($offset, $State.Characters, 0, $count)
                    [Buffer]::BlockCopy($State.Characters, 0, $State.Bytes, 0, ($count * 2))
                    $writer.Write($State.Bytes, 0, ($count * 2))
                }
            }
            else { Write-PraDataFingerprint -State $State -Value $item -Depth ($Depth + 1) }
        }
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
    if (-not (Test-PraOrdinalEqual $Entry.Environment $Context.Config.Environment) -or -not (Test-PraOrdinalEqual $receipt.Path $Entry.Path) -or
        -not (Test-PraOrdinalEqual $receipt.Data.Environment $Entry.Environment) -or -not (Test-PraOrdinalEqual $receipt.Data.Operation $Entry.Operation) -or
        [int](Get-PraValue $receipt.Data 'SchemaVersion' 1) -ne $Entry.SchemaVersion -or
        -not (Test-PraOrdinalEqual ([string](Get-PraValue $receipt.Data 'RawFormat' '')) $Entry.RawFormat) -or
        $receipt.Legacy -isnot [bool] -or (-not (Test-PraOrdinalIgnoreCaseEqual $receipt.Legacy $Entry.Legacy)) -or
        -not (Test-PraOrdinalEqual $receipt.Hash $Entry.Hash) -or -not [object]::ReferenceEquals($receipt.Data, $Entry.Data)) {
        throw 'Backup receipt changed, or it belongs to another context.'
    }
    if (-not (Test-PraOrdinalEqual (Get-PraDataFingerprint -Data $receipt.Data) $Entry.DataFingerprint)) { throw 'Backup content changed in memory since its validation.' }
    if (-not (Test-PraOrdinalEqual (Get-PraHash -Path $Entry.Path) $Entry.Hash)) { throw 'Backup JSON file changed since its validation.' }
    if ($Entry.SchemaVersion -ge 2) {
        $sidecar = (Get-Content -LiteralPath ($Entry.Path + '.sha256') -Raw -ErrorAction Stop).Trim()
        if (-not (Test-PraOrdinalEqual $sidecar $Entry.Hash)) { throw 'Backup .sha256 file changed since its validation.' }
        if (-not (Test-PraOrdinalEqual $receipt.Data.RawHash $Entry.RawHash) -or
            -not (Test-PraOrdinalEqual ([IO.Path]::GetFileName($Entry.RawPath)) $receipt.Data.RawFile) -or
            -not (Test-PraOrdinalEqual (Get-PraHash -Path $Entry.RawPath) $Entry.RawHash)) { throw 'Backup CLIXML file changed since its validation.' }
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
    .PARAMETER Root
        The configured Storage.BackupFolder. As with 2.x, every folder that has to be created from Root (included) down to
        Path is born private, so a missing Storage.BackupFolder is private too; folders above Root keep the inheritance of
        their own parent. Without Root only the last folder gets the private ACL.
    #>
    [CmdletBinding(SupportsShouldProcess = $true)]
    param([Parameter(Mandatory)][string]$Path, [string]$Root = '')
    if (-not $PSCmdlet.ShouldProcess($Path, 'Create a private backup folder')) { throw 'Backup folder creation refused.' }
    if (Test-Path -LiteralPath $Path) { throw "Backup folder already exists: $Path" }
    # One ACL for backups, logs and reports (PRA.Common: New-PraPrivateDirectorySecurity).
    $acl = New-PraPrivateDirectorySecurity
    # Each folder is created with its restrictive ACL: no moment where files inherit broader rights.
    # The folders to create are the missing ones from the leaf up to Root (included); a missing parent above Root keeps the
    # inheritance of its own parent. Without Root (or outside Root) only the leaf gets the private ACL.
    $full = [IO.Path]::GetFullPath($Path).TrimEnd('\')
    $boundary = $full
    if ($Root) {
        $rootFull = [IO.Path]::GetFullPath($Root).TrimEnd('\')
        if ($full.StartsWith($rootFull + '\', [StringComparison]::OrdinalIgnoreCase)) { $boundary = $rootFull }
    }
    $toCreate = New-Object 'Collections.Generic.List[string]'
    $cursor = $full
    while ($cursor -and -not [IO.Directory]::Exists($cursor)) {
        $toCreate.Insert(0, $cursor)
        if ([string]::Equals($cursor, $boundary, [StringComparison]::OrdinalIgnoreCase)) { break }
        $cursor = [IO.Path]::GetDirectoryName($cursor)
    }
    $parent = [IO.Path]::GetDirectoryName($toCreate[0])
    if ($parent) { [void][IO.Directory]::CreateDirectory($parent) }
    foreach ($folder in $toCreate) {
        $info = New-Object IO.DirectoryInfo $folder
        [IO.FileSystemAclExtensions]::Create($info, $acl)
        $actual = [IO.FileSystemAclExtensions]::GetAccessControl($info)
        if (-not $actual.AreAccessRulesProtected) { throw "Backup folder ACL is not protected: $folder" }
    }
}

function Write-PraJournal {
    <#
    .SYNOPSIS
        Appends one JSON line to the journal of the batch. Statuses used: Started, Applied, Verified, FailedOrIndeterminate
        (AD writes), Failed (cloud write), Initialized (cloud journal opened), Completed (Entra Connect cycle).
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
    if (-not [Environment]::Is64BitProcess) { Write-PraLog -Context $Context -Message '32-bit PowerShell: less memory for large batches. Use the 64-bit PowerShell 7.' -Level Warning }
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
    $properties = @('memberOf','uSNChanged','DisplayName','mail','mailNickname','msExchArchiveGUID','legacyExchangeDN') + @($script:AttributeKinds.Keys) + $ExtraProperties
    if ($Capture) { $properties += @('*','msExchMailboxSecurityDescriptor','nTSecurityDescriptor','publicDelegates') }
    $properties = @($properties | Get-PraOrdinalUnique -IgnoreCase)
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
        With -Identity the mailbox scope (-MailboxScope, the entry script's -Scope) is IGNORED: the one named
        object is accepted whatever its type (user, shared, room or equipment mailbox).
    #>
    [CmdletBinding()]
    param([hashtable]$Context, [string]$Identity, [string]$MailboxScope = 'All', [int]$MaxObjects = 0)
    $scope = $Context.Config.Scope; $server = $Context.Server
    $types = @(1)
    if ($Identity) { $types = @(1, 4, 16, 32) }
    elseif ((Test-PraOrdinalIgnoreCaseEqual $MailboxScope 'UsersOnly')) { $types = @(1) }
    elseif ((Test-PraOrdinalIgnoreCaseEqual $MailboxScope 'SharedOnly')) { $types = @(4) }
    else {
        if ($scope.IncludeShared) { $types += 4 }
        if ($scope.IncludeRoom) { $types += 16 }
        if ($scope.IncludeEquip) { $types += 32 }
    }
    $users = New-Object 'Collections.Generic.List[object]'
    $explicit = $false
    if ($Identity) { $explicit = $true; $users.Add((Get-PraUser $Context $Identity)) }
    elseif (Test-PraOrdinalIgnoreCaseEqual $scope.Mode 'Csv') {
        $explicit = $true
        $entries = @(Read-PraTargetCsv -Path $scope.CsvPath)
        foreach ($entry in $entries) {
            $id = [string](Get-PraValue $entry 'Identity' '')
            if ([string]::IsNullOrWhiteSpace($id)) { throw 'A line of the target CSV file has no Identity: batch refused.' }
            $users.Add((Get-PraUser $Context $id.Trim()))
        }
    }
    elseif (Test-PraOrdinalIgnoreCaseEqual $scope.Mode 'Group') {
        $group = Get-PraGroup $Context $scope.GroupDN
        $members = @(Invoke-PraRead $Context 'Get-ADGroupMember/Scope' $group.DistinguishedName {
                Get-ADGroupMember -Identity $group.ObjectGUID -Recursive -Server $server -ErrorAction Stop })
        foreach ($member in $members | Where-Object { Test-PraOrdinalIgnoreCaseEqual $_.objectClass 'user' }) { $users.Add((Get-PraUser $Context ([string]$member.DistinguishedName))) }
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
        $eligible = (Get-PraValue $user 'homeMDB' '') -and ([Linq.Enumerable]::Contains([long[]]@($types), [long](Get-PraValue $user 'msExchRecipientTypeDetails' 0)))
        $samName = [string]$user.SamAccountName
        $excluded = $samName.StartsWith('HealthMailbox', [StringComparison]::OrdinalIgnoreCase) -or $samName.StartsWith('SystemMailbox', [StringComparison]::OrdinalIgnoreCase) -or
            ([string](Get-PraValue $user 'DisplayName' '')).StartsWith('Microsoft Exchange', [StringComparison]::OrdinalIgnoreCase) -or (Test-PraOrdinalIn -IgnoreCase $user.SamAccountName $scope.ExcludeSamAccountNames)
        if (-not $eligible -or $excluded) {
            if ($explicit) { throw "Explicit target not eligible (not an on-premises mailbox of an accepted type) or excluded: $($user.SamAccountName). Nothing converted." }
            continue
        }
        $selected.Add($user)
    }
    # Canonical, culture-free order (Sort-Object uses the ICU collation): sAMAccountName upper-cased, then the GUID, compared by code unit.
    $orderedItems = $selected.ToArray()
    $orderKeys = [string[]]@($orderedItems | ForEach-Object { ([string]$_.SamAccountName).ToUpperInvariant() + [string][char]0 + ([guid]$_.ObjectGUID).ToString() })
    [Array]::Sort([Array]$orderKeys, [Array]$orderedItems, [Collections.IComparer][StringComparer]::Ordinal)
    $ordered = @($orderedItems)
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
                MultiString { $value = [string[]]@($raw | Sort-PraOrdinal) }
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

function Resolve-PraKind {
    <# Official spelling of a stored attribute type, by ordinal comparison ($null when unknown): a switch over the stored text itself would be culture-sensitive (ICU ignores zero-weight characters). #>
    param([AllowNull()]$Kind)
    foreach ($known in 'String', 'MultiString', 'Bytes', 'Bool', 'Int', 'Long') { if ([string]::Equals([string]$Kind, $known, [StringComparison]::Ordinal)) { return $known } }
    return $null
}

function ConvertFrom-PraStoredValue {
    <# Value to write with Set-ADUser -Replace, from a stored typed state. #>
    [CmdletBinding()]
    param($State)
    if (-not $State.Present) { return $null }
    switch (Resolve-PraKind $State.Kind) {
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
    if ([bool]$Left.Present -ne [bool]$Right.Present -or -not (Test-PraOrdinalEqual $Left.Kind $Right.Kind)) { return $false }
    if (-not $Left.Present) { return $true }
    if (Test-PraOrdinalEqual $Left.Kind 'MultiString') {
        $a = @($Left.Value | Sort-PraOrdinal); $b = @($Right.Value | Sort-PraOrdinal)
        if ($a.Count -ne $b.Count) { return $false }
        for ($i = 0; $i -lt $a.Count; $i++) { if (-not (Test-PraOrdinalEqual ([string]$a[$i]) ([string]$b[$i]))) { return $false } }
        return $true
    }
    return (Test-PraOrdinalEqual ([string]$Left.Value) ([string]$Right.Value))
}

function ConvertTo-PraLogText {
    <# Escapes control characters, quotes and backslashes of an AD value (the value is never cut). #>
    [CmdletBinding()]
    param([AllowEmptyString()][string]$Value)
    return [regex]::Replace($Value, '[\p{Cc}\p{Cf}\p{Zl}\p{Zp}\\"]', [Text.RegularExpressions.MatchEvaluator]{
            param($match)
            # On the character CODE, never on the string (ICU string comparison ignores control characters: U+0001 -eq U+0008).
            $code = [int][char]$match.Value[0]
            switch ($code) {
                13 { '\r'; break }
                10 { '\n'; break }
                9 { '\t'; break }
                92 { '\\'; break }
                34 { '\"'; break }
                default { '\u{0:x4}' -f $code }
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
    switch (Resolve-PraKind $State.Kind) {
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
    switch (Resolve-PraKind $State.Kind) {
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
            if ($text.StartsWith('/o=', [StringComparison]::Ordinal)) { $text = '...' + $text.Substring($text.LastIndexOf('/', [StringComparison]::Ordinal)) }
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
    if ((Test-PraOrdinalIgnoreCaseEqual $Stage 'Verified') -and ((-not (Test-PraOrdinalIgnoreCaseEqual $Context.Mode 'Apply')) -or -not $Context.AllowMutation -or
            (Test-PraOrdinalIgnoreCaseEqual $Context.Action 'Check') -or $WhatIfPreference -or $Plan.Row.ADVerified -ne $true)) {
        throw 'VERIFIED display refused: no successful AD verification in Apply mode.'
    }
    $afterLabel = if ((Test-PraOrdinalIgnoreCaseEqual $Stage 'Verified')) { 'VERIFIED' } else { 'PLANNED' }
    $heading = if ((Test-PraOrdinalIgnoreCaseEqual $Stage 'Verified')) { 'AD VERIFIED' } else { 'AD PLAN - planned values, not applied' }
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
        if ((Test-PraOrdinalIgnoreCaseEqual $change 'UNCHANGED')) { $unchanged++; continue }
        if ((Test-PraOrdinalIgnoreCaseEqual ($Plan.Kinds[$name]) 'MultiString') -and $before.Present -and $after.Present) {
            $old = @($before.Value); $new = @($after.Value)
            foreach ($value in $new | Where-Object { -not (Test-PraOrdinalIn $_ $old) }) { $consoleLines.Add(@($name, ('+ ' + (ConvertTo-PraLogText -Value $value)), 'Green')) }
            foreach ($value in $old | Where-Object { -not (Test-PraOrdinalIn $_ $new) }) { $consoleLines.Add(@($name, ('- ' + (ConvertTo-PraLogText -Value $value)), 'Red')) }
        }
        else { $consoleLines.Add(@($name, ('{0}  {1}  {2}' -f (Format-PraShortValue $before), [char]0x2192, (Format-PraShortValue $after)), $palette[$change])) }
    }
    $group = $record.Licensing
    if ($group.Enabled) {
        $change = if ((Test-PraOrdinalIgnoreCaseEqual $group.WasMember $group.DesiredMember)) { 'UNCHANGED' } elseif ($group.DesiredMember) { 'ADD' } else { 'REMOVE' }
        $beforeText = if ($group.WasMember) { 'Member' } else { 'Not member' }
        $afterText = if ($group.DesiredMember) { 'Member' } else { 'Not member' }
        Write-PraLog -Context $Context -Message "LICENCE GROUP | $(ConvertTo-PraLogText -Value $group.GroupDN) | $change" -Level Detail
        Write-PraLog -Context $Context -Message "  Licence group | BEFORE : $beforeText" -Level Detail
        Write-PraLog -Context $Context -Message "  Licence group | $afterLabel : $afterText" -Level Detail
        if ((-not (Test-PraOrdinalIgnoreCaseEqual $change 'UNCHANGED'))) {
            $groupName = (($group.GroupDN -split ',')[0] -replace '^CN=', '')
            $consoleLines.Add(@(('licence group ' + $groupName), ('{0}  {1}  {2}' -f $beforeText.ToLowerInvariant(), [char]0x2192, $afterText.ToLowerInvariant()), $palette[$change]))
        }
    }
    else { Write-PraLog -Context $Context -Message 'LICENCE GROUP | not managed for this operation' -Level Detail }
    $shared = $record.SharedPermissions
    $permissionText = ''
    if ($record.IsShared -and (Test-PraOrdinalIgnoreCaseEqual $Plan.Operation 'Convert')) {
        $permissionText = ' {0} {1} FullAccess {0} {2} SendAs {0} {3} SendOnBehalf' -f [char]0x00B7, @($shared.FullAccess).Count, @($shared.SendAs).Count, @($shared.SendOnBehalf).Count
    }

    # Console.
    $beforeType = [string]$record.Attributes['msExchRecipientTypeDetails'].Value
    $afterType = [string]$Plan.Desired['msExchRecipientTypeDetails'].Value
    $typeText = if ($script:RecipientTypeNames.ContainsKey($beforeType)) { $script:RecipientTypeNames[$beforeType] } else { $beforeType }
    if ((-not (Test-PraOrdinalIgnoreCaseEqual $afterType $beforeType))) { $typeText += (' {0} ' -f [char]0x2192) + $(if ($script:RecipientTypeNames.ContainsKey($afterType)) { $script:RecipientTypeNames[$afterType] } else { $afterType }) }
    if ((Test-PraOrdinalIgnoreCaseEqual $Stage 'Verified')) {
        $groupAction = [string](Get-PraValue $Plan.Row 'GroupAction' '')
        $statusText = switch ([string]$Plan.Row.FinalStatus) { 'Pending' { 'next: Exchange Online deprovisioning check' } 'AlreadyDone' { 'already in the expected state' } default { 'done' } }
        $text = '{0}  {1}  {2} AD verified, {3} attribute(s) changed{4} {2} {5}' -f $record.SamAccountName, $typeText, [char]0x00B7, ($Plan.Kinds.Count - $unchanged), $(if ((Test-PraOrdinalIn $groupAction @('Added','Removed') -IgnoreCase)) { ', licence group ' + $groupAction.ToLowerInvariant() } else { '' }), $statusText
        Write-PraItem -Context $Context -Status Ok -Text $text
        return
    }
    $operationText = switch ($Plan.Operation) { 'Deprovision' { 'deprovision in Exchange Online first' } 'AlreadyRecovered' { 'already restored' } 'RestoreTag' { 'restore the retention tag' } default { $Plan.Operation.ToLowerInvariant() } }
    Write-Host ''
    Write-PraHost @(@('      '), @(($record.SamAccountName + '  '), 'White'), @(([string]$record.UserPrincipalName + '  '), 'DarkGray'), @($typeText, 'Cyan'), @(('  ' + [char]0x00B7 + ' ' + $operationText + $permissionText), 'DarkGray'))
    foreach ($line in $consoleLines) { Write-PraHost @('         ', ('{0,-28} ' -f $line[0]), $line[1]) -Color $line[2] }
    $keptCloud = @(if ($record.Contains('KeptX500')) { $record['KeptX500'] | Where-Object { $_ } })
    if ($keptCloud.Count) {
        foreach ($value in $keptCloud) { Write-PraLog -Context $Context -Message ("  proxyAddresses | KEPT X500 (written back by Entra Connect) : {0}" -f (ConvertTo-PraLogText -Value $value)) -Level Detail }
        Write-PraItem -Context $Context -Status Info -Text ('{0}: {1} cloud X500 address(es) kept (written back by Entra Connect; replies to messages sent from the cloud keep working)' -f $record.SamAccountName, $keptCloud.Count)
    }
    if ((Test-PraOrdinalIgnoreCaseEqual $Plan.Operation 'Convert')) {
        # The cloud phase proves these addresses in Exchange Online (a reply to an old message is addressed by legacyExchangeDN); here the operator only sees how many.
        $verifyX500 = @(if ($record.Contains('ExpectedX500')) { $record['ExpectedX500'] | Where-Object { $_ } })
        foreach ($value in $verifyX500) { Write-PraLog -Context $Context -Message ("  X500 to verify in Exchange Online : {0}" -f (ConvertTo-PraLogText -Value $value)) -Level Detail }
        Write-PraItem -Context $Context -Status Info -Text ('{0}: X500 to verify after the conversion: {1}{2}' -f $record.SamAccountName, $verifyX500.Count, $(if ($verifyX500.Count) { '' } else { ' (no legacyExchangeDN and no X500 address on premises)' }))
    }
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
        $match = @($existing | Where-Object { (Test-PraOrdinalIgnoreCaseEqual (($_ -split '@', 2)[0]) $local) -and $_ -imatch "@$([regex]::Escape($domain))\z" })
        if (-not $match.Count) { $match = @($existing | Where-Object { $_ -imatch "@$([regex]::Escape($domain))\z" }) }
        if ($match.Count -eq 1) { return [string]$match[0] }
        if ($match.Count -gt 1) { throw "Several routing addresses possible for $($User.SamAccountName): keep one proxy address in $domain." }
    }
    if (-not $local -or $local -match '[\s@]' -or $domain -notmatch '^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$') { throw "No valid routing address for $($User.SamAccountName) (check Routing.RoutingDomain and the mail alias)." }
    return "$local@$domain"
}

function Test-PraX500Address {
    <# True for a proxy address of type X500 (the type prefix is compared ordinal, ignoring case; the rest of the value is never touched). #>
    [OutputType([bool])]
    param([AllowNull()][string]$Value)
    return (-not [string]::IsNullOrEmpty($Value)) -and $Value.StartsWith('X500:', [StringComparison]::OrdinalIgnoreCase)
}

function Get-PraX500Difference {
    <#
    .SYNOPSIS
        Compares two stored proxyAddresses states, X500 entries on one side and every other entry on the other.
    .DESCRIPTION
        While an object is a remote mailbox, Entra Connect (Exchange hybrid writeback) adds an X500 address of the cloud mailbox to proxyAddresses.
        Added   = X500 entries of Current that are not in Reference (ordinal, ignoring case, on the whole value)
        Removed = X500 entries of Reference that are not in Current
        OtherEqual = every entry that is not X500 is identical (sorted ordinal sets): the only difference left, if any, is X500.
    #>
    [CmdletBinding()]
    param($Current, $Reference)
    $now = if ($null -ne $Current -and [bool]$Current.Present) { @([string[]]@($Current.Value)) } else { @() }
    $was = if ($null -ne $Reference -and [bool]$Reference.Present) { @([string[]]@($Reference.Value)) } else { @() }
    $nowX = @($now | Where-Object { Test-PraX500Address $_ }); $wasX = @($was | Where-Object { Test-PraX500Address $_ })
    $added = New-Object 'Collections.Generic.List[string]'
    foreach ($value in $nowX) { if (-not (Test-PraOrdinalIn $value $wasX -IgnoreCase) -and -not (Test-PraOrdinalIn $value $added.ToArray() -IgnoreCase)) { $added.Add([string]$value) } }
    $removed = @($wasX | Where-Object { -not (Test-PraOrdinalIn $_ $nowX -IgnoreCase) })
    $a = @($now | Where-Object { -not (Test-PraX500Address $_) } | Sort-PraOrdinal); $b = @($was | Where-Object { -not (Test-PraX500Address $_) } | Sort-PraOrdinal)
    $same = ($a.Count -eq $b.Count)
    if ($same) { for ($i = 0; $i -lt $a.Count; $i++) { if (-not (Test-PraOrdinalEqual ([string]$a[$i]) ([string]$b[$i]))) { $same = $false; break } } }
    return [pscustomobject]@{ OtherEqual = $same; Added = [string[]]$added.ToArray(); Removed = [string[]]@($removed) }
}

function Get-PraExpectedX500 {
    <#
    .SYNOPSIS
        X500 addresses that the cloud mailbox must carry so that a reply to an old message, a meeting update or a cached Outlook entry (all addressed by
        legacyExchangeDN, internally IMCEAEX) still reaches it: X500:<legacyExchangeDN> when it is not empty, then every X500 entry of the on-premises proxyAddresses.
    .DESCRIPTION
        Read only. Duplicates are removed (ordinal, ignoring case, on the whole value); the first spelling is kept, byte for byte. The prefix of the
        legacyExchangeDN is written X500: (the type prefix of the other entries keeps whatever case it has on premises).
    #>
    [OutputType([string[]])]
    param([AllowNull()][AllowEmptyString()][string]$LegacyExchangeDN, [AllowNull()][string[]]$ProxyAddresses)
    $seen = New-Object 'Collections.Generic.HashSet[string]' -ArgumentList ([StringComparer]::OrdinalIgnoreCase)
    $list = New-Object 'Collections.Generic.List[string]'
    if (-not [string]::IsNullOrWhiteSpace($LegacyExchangeDN)) { $value = 'X500:' + $LegacyExchangeDN; if ($seen.Add($value)) { $list.Add($value) } }
    foreach ($address in @($ProxyAddresses)) { if (Test-PraX500Address $address) { if ($seen.Add([string]$address)) { $list.Add([string]$address) } } }
    if ($list.Count -gt $script:MaxExpectedX500) { throw "Too many X500 addresses to verify ($($list.Count), limit $($script:MaxExpectedX500)): conversion refused before any change." }
    foreach ($value in $list) { if ($value.Length -gt $script:MaxExpectedX500Length) { throw "X500 address too long to verify ($($value.Length) characters, limit $($script:MaxExpectedX500Length)): conversion refused before any change." } }
    return [string[]]$list.ToArray()
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
    $policy = (@($Context.Config.SharedMailbox.ExcludeTrusteeSamAccountNames | Sort-PraOrdinal) -join "`n")
    $cache = $null
    if ($script:PermissionCaches.TryGetValue($Context, [ref]$cache)) {
        if ((Test-PraOrdinalIgnoreCaseEqual $cache.Server $Context.Server) -and (Test-PraOrdinalEqual $cache.Policy $policy)) { return $cache }
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
    if (Test-PraOrdinalIn -IgnoreCase (Get-PraValue $Object 'sAMAccountName' '') $excluded) { return }
    if (Test-PraOrdinalIgnoreCaseEqual $Object.objectClass 'user') {
        $upn = [string](Get-PraValue $Object 'userPrincipalName' '')
        if (-not $upn) { throw "Trustee without UPN: $($Object.DistinguishedName)" }
        return $upn
    }
    if (-not (Test-PraOrdinalIgnoreCaseEqual $Object.objectClass 'group')) { throw "Unsupported trustee type: $($Object.objectClass)" }
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
        if ((Test-PraOrdinalIgnoreCaseEqual $member.objectClass 'user') -and $seen.Add([string]$member.DistinguishedName)) {
            $memberKey = 'user:' + ([string]$member.DistinguishedName).ToLowerInvariant()
            if ($cache.Entries.ContainsKey($memberKey)) {
                foreach ($upn in $cache.Entries[$memberKey].Upns) { [void]$upns.Add($upn) }
            }
            else {
                $user = Get-ADUser -Identity $member.DistinguishedName -Properties userPrincipalName, sAMAccountName -Server $Context.Server -ErrorAction Stop
                $memberUpns = @()
                if (-not (Test-PraOrdinalIn -IgnoreCase $user.SamAccountName $excluded)) {
                    if (-not $user.UserPrincipalName) { throw "Trustee without UPN: $($member.DistinguishedName)" }
                    $memberUpns = @([string]$user.UserPrincipalName); [void]$upns.Add([string]$user.UserPrincipalName)
                }
                Add-PraPermissionCache -Context $Context -Key $memberKey -Upns $memberUpns
            }
        }
    }
    $result = [string[]]@($upns | Sort-PraOrdinal -IgnoreCase)
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
    # Named accounts and groups (Organization Management, Exchange Trusted Subsystem, ...) are filtered by name once the SID is
    # resolved to its AD object (see $excludedGroups below); the ACE reference is a SID here, so a name pattern could never match.
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
    if ((Test-PraOrdinalIgnoreCaseEqual $objects[0].objectClass 'group') -and ((Test-PraOrdinalIn -IgnoreCase (Get-PraValue $objects[0] 'sAMAccountName' '') $excludedGroups) -or (Test-PraOrdinalIn -IgnoreCase (Get-PraValue $objects[0] 'Name' '') $excludedGroups))) {
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
    # The configured text is mapped to its official spelling by ordinal comparison before the switch (culture-sensitive string matching ignores zero-weight characters).
    $permissionSource = $null
    foreach ($knownSource in 'AD', 'Csv', 'CustomAttribute', 'None') { if (Test-PraOrdinalIgnoreCaseEqual $settings.PermissionSource $knownSource) { $permissionSource = $knownSource; break } }
    switch ($permissionSource) {
        AD {
            # Descriptor read through Get-ADUser -Server, never through the AD: drive.
            $security = Get-PraValue $User 'nTSecurityDescriptor' $null
            if ($null -eq $security) { throw 'nTSecurityDescriptor cannot be read: SendAs capture incomplete (check the read rights of the account).' }
            $sendRules = if ($security -is [Security.AccessControl.ObjectSecurity]) { $security.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier]) } else { $security.Access }
            foreach ($ace in $sendRules) {
                if ((Test-PraOrdinalIgnoreCaseEqual $ace.AccessControlType 'Allow') -and -not $ace.IsInherited -and
                    $ace.ActiveDirectoryRights -match 'ExtendedRight' -and (Test-PraOrdinalIgnoreCaseEqual ([string]$ace.ObjectType) 'ab721a54-1e2f-11d0-9819-00aa0040529b')) {
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
                    if ((Test-PraOrdinalIgnoreCaseEqual $ace.AccessControlType 'Allow') -and -not $ace.IsInherited -and (([int]$ace.ActiveDirectoryRights -band 1) -eq 1)) {
                        foreach ($upn in @(Resolve-PraAclTrustee -Context $Context -Reference $ace.IdentityReference -Unknown $unknownFullAccess)) { [void]$full.Add($upn) }
                    }
                }
            }
        }
        Csv {
            # An empty name (no mailNickname, no DisplayName) must never match an empty Shared cell: filter it out.
            $names = @((Get-PraValue $User 'mailNickname' ''), $User.SamAccountName, (Get-PraValue $User 'DisplayName' ''), (Get-PraValue $User 'Name' '')) |
                Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) }
            # Text with BOM detection and an ANSI fallback (a CSV saved by Excel or Notepad "ANSI" is not UTF-8; Get-Content -Encoding UTF8
            # would turn its accents into replacement characters and the shared mailbox name would no longer match).
            # Delimiter read from the header (comma or semicolon), like the target CSV: Import-Csv alone uses the regional list separator.
            $csvText = Read-PraCsvText -Path $settings.CsvPath
            if ([string]::IsNullOrWhiteSpace($csvText)) { throw "Permission CSV is empty: $($settings.CsvPath)" }
            $csvHeader = ($csvText -split '\r?\n', 2)[0]
            $csvDelimiter = if ($csvHeader -match '(?i)(^|,)\s*"?Shared"?\s*(,|$)') { ',' }
                elseif ($csvHeader -match '(?i)(^|;)\s*"?Shared"?\s*(;|$)') { ';' }
                else { throw 'Permission CSV: the columns Shared and Group are required (comma or semicolon separated).' }
            $permissionRows = @(ConvertFrom-Csv -InputObject $csvText -Delimiter $csvDelimiter -ErrorAction Stop |
                Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_.Shared) -and (Test-PraOrdinalIn -IgnoreCase ([string]$_.Shared).Trim() $names) })
            if ($permissionRows.Count -ne 1 -or -not $permissionRows[0].Group) { throw "Permission CSV: no line (or several lines) Shared/Group for $($User.SamAccountName)." }
            $group = Get-PraGroup $Context $permissionRows[0].Group -WithoutMembers
            foreach ($upn in @(Expand-PraTrustee -Context $Context -Object $group)) { [void]$full.Add($upn); [void]$send.Add($upn) }
        }
        CustomAttribute {
            $attr = [string]$settings.CustomAttribute
            if ($attr -notmatch '^extensionAttribute([1-9]|1[0-5])$') { throw 'SharedMailbox.CustomAttribute is invalid.' }
            $filters = @(@((Get-PraValue $User 'mailNickname' ''), $User.SamAccountName, (Get-PraValue $User 'DisplayName' '')) | Where-Object { $_ } | Get-PraOrdinalUnique | ForEach-Object { "($attr=$(ConvertTo-PraLdapValue $_))" })
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
    return @{ FullAccess=@($full | Sort-PraOrdinal -IgnoreCase); SendAs=@($send | Sort-PraOrdinal -IgnoreCase); SendOnBehalf=@($behalf | Sort-PraOrdinal -IgnoreCase) }
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
    $readable = [string](Get-PraValue $Record 'UserPrincipalName' ''); if (-not $readable) { $readable = [string](Get-PraValue $Record 'SamAccountName' '') }
    Register-PraObjectName -Context $Context -ObjectGuid ([string](Get-PraValue $Record 'ObjectGuid' '')) -Name $readable
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
    $tag = if ((Test-PraOrdinalIgnoreCaseEqual $Operation 'Convert')) { $config.Retention.Tag } else { Get-PraValue $SourceRecord 'Retention' $null }
    $tagEnabled = if ((Test-PraOrdinalIgnoreCaseEqual $Operation 'Convert')) { $config.Retention.Enabled -and $tag.Enabled } else { [bool](Get-PraValue $tag 'Enabled' $false) }
    $tagAttr = if ($tagEnabled) { [string]$tag.Attribute } else { '' }
    if ($tagAttr -and $tagAttr -notmatch '^extensionAttribute([1-9]|1[0-5])$') { throw "Retention tag attribute not allowed: $tagAttr" }
    if ((Test-PraOrdinalIgnoreCaseEqual $Operation 'RestoreTag') -and -not $tagEnabled) { throw 'The original value of the retention tag is not in the backup: tag clean-up refused.' }
    $kinds = [ordered]@{}; foreach ($name in $script:AttributeKinds.Keys) { $kinds[$name] = $script:AttributeKinds[$name] }
    if ($tagAttr) { $kinds[$tagAttr] = 'String' }
    $user = Get-PraUser $Context $Identity -ExtraProperties @($kinds.Keys) -Capture
    $before = Get-PraAttributeState $user $kinds
    $shared = if ((Test-PraOrdinalIgnoreCaseEqual $Operation 'Convert')) { [int64]$user.msExchRecipientTypeDetails -eq 4 } else { [bool]$SourceRecord.IsShared }
    $desired = [ordered]@{}; foreach ($name in $before.Keys) { $desired[$name] = $before[$name] }
    $permissions = @{ FullAccess=@(); SendAs=@(); SendOnBehalf=@() }
    $licensing = [ordered]@{ Enabled=$false; GroupGuid=''; GroupDN=''; WasMember=$false; DesiredMember=$false }
    $routing = ''; $alreadyRecovered = $false; $keptX500 = @(); $expectedX500 = @()
    if ((Test-PraOrdinalIgnoreCaseEqual $Operation 'Convert')) {
        if (-not $user.homeMDB -or [int64]$user.msExchRecipientTypeDetails -notin @(1, 4, 16, 32)) { throw "Not an on-premises mailbox (homeMDB / msExchRecipientTypeDetails): $Identity" }
        $routing = Get-PraRoutingAddress $Context $user
        # X500 addresses the cloud mailbox must carry (read only: legacyExchangeDN is never written, restored or modified; the control runs in the cloud phase).
        $expectedX500 = @(Get-PraExpectedX500 -LegacyExchangeDN ([string](Get-PraValue $user 'legacyExchangeDN' '')) -ProxyAddresses @($user.proxyAddresses))
        $rrt = if ($shared) { [int64]$config.SharedMailbox.RemoteRecipientType } else { [int64]$config.Remote.RecipientType }
        if ($shared -and (Test-PraOrdinalIn $rrt @(100, 102) -IgnoreCase)) { throw "SharedMailbox.RemoteRecipientType=$rrt means an already migrated mailbox (Migrated+Shared): first provisioning refused before any change: $Identity" }
        if ($config.Remote.HandleArchives -and (Get-PraValue $user 'msExchArchiveGUID' $null)) { $rrt = $rrt -bor 2 }
        $desired.targetAddress = @{ Present=$true; Kind='String'; Value="SMTP:$routing" }
        $desired.msExchRecipientDisplayType = @{ Present=$true; Kind='Int'; Value='-2147483642' }
        $details = if ($shared) { '34359738368' } else { '2147483648' }
        $desired.msExchRecipientTypeDetails = @{ Present=$true; Kind='Long'; Value=$details }
        $desired.msExchRemoteRecipientType = @{ Present=$true; Kind='Long'; Value=[string]$rrt }
        foreach ($name in @('homeMDB','homeMTA','msExchHomeServerName','mDBUseDefaults')) { $desired[$name] = @{ Present=$false; Kind=$kinds[$name]; Value=$null } }
        if ($config.Remote.ClearMailboxGuid) { $desired.msExchMailboxGuid = @{ Present=$false; Kind='Bytes'; Value=$null } }
        $proxies = @($user.proxyAddresses)
        if (-not @($proxies | Where-Object { Test-PraOrdinalIgnoreCaseEqual $_ "smtp:$routing" }).Count) { $proxies += "smtp:$routing" }
        $desired.proxyAddresses = @{ Present=$true; Kind='MultiString'; Value=[string[]]$proxies }
        if ($tagEnabled) { $desired[$tagAttr] = @{ Present=$true; Kind='String'; Value=[string]$tag.Value } }
        if ($shared) { $permissions = Get-PraSharedPermission $Context $user }
        elseif ($config.Licensing.Enabled) {
            $group = Get-PraGroup $Context $config.Licensing.GroupDN
            $licensing.Enabled = $true; $licensing.GroupGuid = ([guid]$group.ObjectGUID).ToString(); $licensing.GroupDN = [string]$group.DistinguishedName
            $licensing.WasMember = (Test-PraOrdinalIn -IgnoreCase ([string]$user.DistinguishedName) @($group.member)); $licensing.DesiredMember = $true
        }
    }
    elseif ((Test-PraOrdinalIgnoreCaseEqual $Operation 'Deprovision')) {
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
    elseif ((Test-PraOrdinalIgnoreCaseEqual $Operation 'Recover')) {
        foreach ($name in $script:AttributeKinds.Keys) { $desired[$name] = $SourceRecord.Attributes.$name }
        # Cloud X500 kept on purpose. While the object was a remote mailbox, Entra Connect wrote an X500 address of the cloud mailbox into proxyAddresses
        # (legacyExchangeDN of the cloud recipient). Restoring the list exactly as captured would remove it, and a reply to a message sent from the cloud
        # during the disaster (or a cached Outlook address) would bounce after the rollback. So the restored list is the original one plus every X500
        # entry that is on the object now and was not in the original: nothing else is kept (the routing smtp address added by Convert is still removed),
        # no X500 is ever invented, and the value is kept byte for byte. Computed here, at plan time, so that the final restore of a Finalize sees the
        # writeback that happened since the AD phase.
        $originalProxies = $SourceRecord.Attributes.proxyAddresses
        $x500 = Get-PraX500Difference $before.proxyAddresses $originalProxies
        if ($x500.Added.Count) {
            $originalValues = if ([bool]$originalProxies.Present) { @([string[]]@($originalProxies.Value)) } else { @() }
            $keptX500 = @($x500.Added)
            $desired.proxyAddresses = @{ Present=$true; Kind='MultiString'; Value=[string[]]@(@($originalValues) + @($keptX500) | Sort-PraOrdinal) }
        }
        $sourceGroup = Get-PraValue $SourceRecord 'Licensing' $null
        if ($null -ne $sourceGroup -and $sourceGroup.Enabled) {
            $group = Get-PraGroup $Context $sourceGroup.GroupGuid
            $licensing.Enabled = $true; $licensing.GroupGuid = ([guid]$group.ObjectGUID).ToString(); $licensing.GroupDN = [string]$group.DistinguishedName
            $licensing.WasMember = (Test-PraOrdinalIn -IgnoreCase ([string]$user.DistinguishedName) @($group.member)); $licensing.DesiredMember = [bool]$sourceGroup.WasMember
        }
        elseif ([bool](Get-PraValue $SourceRecord 'AddedToLicenseGroup' $false)) {
            throw 'Old backup without the GUID of the licence group: removal refused (a group with the same DN may have been re-created). Have the backup migrated before restoring this batch.'
        }
    }
    if ((Test-PraOrdinalIgnoreCaseEqual $Operation 'RestoreTag') -or ((Test-PraOrdinalIgnoreCaseEqual $Operation 'Recover') -and $RestoreRetention -and $tagEnabled)) {
        $original = $SourceRecord.Attributes.$tagAttr
        if (-not (Test-PraStateEqual $before[$tagAttr] $original) -and
            (-not $before[$tagAttr].Present -or -not (Test-PraOrdinalEqual ([string]$before[$tagAttr].Value) ([string]$tag.Value)))) {
            throw "Retention tag $tagAttr changed by someone else: restore refused."
        }
        $desired[$tagAttr] = $original
    }
    $sourceLicensing = Get-PraValue $SourceRecord 'Licensing' $null
    $preserveMailbox = $shared -and (Test-PraOrdinalIgnoreCaseEqual $Operation 'Recover') -and [bool](Get-PraValue $Context 'KeepCloudShared' $false)
    $preserveLicense = ((Test-PraOrdinalIgnoreCaseEqual $Operation 'Recover')) -and [bool](Get-PraValue $sourceLicensing 'Enabled' $false) -and [bool](Get-PraValue $sourceLicensing 'WasMember' $false)
    $record = [ordered]@{
        ObjectGuid=([guid]$user.ObjectGUID).ToString(); DistinguishedName=[string]$user.DistinguishedName
        SamAccountName=[string]$user.SamAccountName; UserPrincipalName=[string]$user.UserPrincipalName; DisplayName=[string](Get-PraValue $user 'DisplayName' $user.SamAccountName)
        CapturedUtc=[DateTime]::UtcNow.ToString('o'); CapturedUsnChanged=(Get-PraUsn $user); IsShared=$shared; RequestedOperation=$Operation
        Attributes=$before; PlannedAttributes=$desired; Licensing=$licensing
        Retention=[ordered]@{ Enabled=[bool]$tagEnabled; Attribute=$tagAttr; Value=$(if ($tagEnabled) { [string]$tag.Value } else { '' }) }
        SharedPermissions=$permissions; PreserveCloudMailbox=[bool]$preserveMailbox; PreserveLicense=[bool]$preserveLicense
        KeptX500=[string[]]@($keptX500); ExpectedX500=[string[]]@($expectedX500)
    }
    $row = New-PraRow $Context $record
    if ($null -ne $SourceRecord) { $row.BackupRec = $SourceRecord } else { $row.BackupRec = [pscustomobject]$record }
    $row.PreserveCloudMailbox = [bool]$preserveMailbox; $row.PreserveLicense = [bool]$preserveLicense
    $ignoredEntries = Get-PraValue (Get-PraValue $Context '_PraIgnoredTrustees' @{}) $record.ObjectGuid @()
    $ignoredEntries = @($ignoredEntries | Where-Object { $_ })
    if ($shared -and (Test-PraOrdinalIgnoreCaseEqual $Operation 'Convert') -and $ignoredEntries.Count) { $row.Warnings = 'Permission entries ignored (account unknown in AD): ' + ($ignoredEntries -join '; ') }
    $row.IsShared = $shared; $row.SharedFullAccess = @($permissions.FullAccess); $row.SharedSendAs = @($permissions.SendAs); $row.SharedSendOnBehalf = @($permissions.SendOnBehalf)
    $row.DeproPending = ((Test-PraOrdinalIgnoreCaseEqual $Operation 'Deprovision') -and -not $alreadyRecovered); $row.Detail = "Operation=$Operation ; routing=$routing" + $(if ($keptX500.Count) { " ; $($keptX500.Count) cloud X500 address(es) kept" } else { '' }); $row.LastOperation = 'Prepared'
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
        if ($null -eq $state -or (Get-PraValue $state 'Present' $null) -isnot [bool] -or -not (Test-PraOrdinalEqual $state.Kind $kinds[$name])) { throw "Backup incomplete or wrong type: $name" }
        if (-not $state.Present) {
            if ($null -ne $state.Value) { throw "Backup: $name is absent but has a value." }
            continue
        }
        switch (Resolve-PraKind $state.Kind) {
            Bool { if ($state.Value -isnot [bool]) { throw "Backup: invalid boolean $name" } }
            MultiString {
                if ($state.Value -isnot [array] -or @($state.Value).Count -eq 0) { throw "Backup: invalid list $name" }
                foreach ($value in $state.Value) { if ($value -isnot [string] -or -not $value) { throw "Backup: invalid text in $name" } }
            }
            default { if ($state.Value -isnot [string] -or -not $state.Value) { throw "Backup: invalid value $name" } }
        }
        $null = ConvertFrom-PraStoredValue $state
    }
    # Cloud X500 addresses kept by a Recover (absent in a batch written before 3.0.0: none).
    $keptStored = Get-PraValue $Record 'KeptX500' $null
    if ($null -ne $keptStored) { foreach ($value in @($keptStored)) { if ($value -isnot [string] -or -not (Test-PraX500Address $value)) { throw 'Backup: invalid list of kept X500 addresses.' } } }
    # X500 addresses expected in Exchange Online (absent in a batch written before 3.1.0: the control is skipped).
    $expectedStored = Get-PraValue $Record 'ExpectedX500' $null
    if ($null -ne $expectedStored) {
        if ($expectedStored -isnot [string] -and $expectedStored -isnot [array]) { throw 'Backup: invalid list of expected X500 addresses.' }
        if (@($expectedStored).Count -gt $script:MaxExpectedX500) { throw 'Backup: too many expected X500 addresses.' }
        foreach ($value in @($expectedStored)) { if ($value -isnot [string] -or -not (Test-PraX500Address $value) -or $value.Length -gt $script:MaxExpectedX500Length) { throw 'Backup: invalid list of expected X500 addresses.' } }
    }
    if (-not $Legacy) {
        if ($Record.CapturedUsnChanged -isnot [string] -or $Record.CapturedUsnChanged -notmatch '^[1-9][0-9]*$') { throw 'Backup: original uSNChanged missing or invalid.' }
        $null = [int64]::Parse($Record.CapturedUsnChanged, [Globalization.CultureInfo]::InvariantCulture)
        if (-not (Test-PraOrdinalIn $Record.RequestedOperation @('Convert','Recover','Deprovision','RestoreTag','AlreadyRecovered'))) { throw 'Backup: invalid planned operation.' }
        if ($Record.PreserveCloudMailbox -isnot [bool] -or $Record.PreserveLicense -isnot [bool]) { throw 'Backup: invalid cloud post-conditions.' }
        if ($Record.PreserveCloudMailbox -and (-not $Record.IsShared -or -not (Test-PraOrdinalEqual $Record.RequestedOperation 'Recover'))) { throw 'Backup: keeping the cloud mailbox does not match the operation or the type.' }
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
        if (Test-PraOrdinalIgnoreCaseEqual $entry.Path $pathResolved) {
            Assert-PraReceiptIntegrity -Context $Context -Entry $entry
            Write-PraLog -Context $Context -Message ("BACKUP INTEGRITY | already validated | $pathResolved | hashes re-read") -Level Debug
            return $entry.Receipt
        }
    }
    $Context.CurrentOperation = 'Read-BackupJson'
    $hashBeforeRead = Get-PraHash -Path $pathResolved
    $data = Get-Content -LiteralPath $pathResolved -Raw -Encoding UTF8 -ErrorAction Stop | ConvertFrom-PraJson
    if (-not (Test-PraOrdinalEqual $data.Environment $Context.Config.Environment)) { throw "Backup of another Environment: '$($data.Environment)' (configuration: '$($Context.Config.Environment)')." }
    $version = Get-PraValue $data 'SchemaVersion' 1
    if ((-not (Test-PraOrdinalIn $version @(1, 2, 3) -IgnoreCase))) { throw "Backup schema not supported: $version" }
    $version = [int]$version   # numeric comparisons below need an integer, not the raw JSON value
    if ($version -eq 3 -and -not (Test-PraOrdinalEqual (Get-PraValue $data 'RawFormat' '') 'PraDataOnlyClixml-v1')) { throw 'Backup capture format not supported.' }
    if (-not (Test-PraOrdinalIn $data.Operation @('Convert','Recover','Finalize','Retention'))) { throw "This file is not an AD backup: $($data.Operation)" }
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
    if (-not (Test-PraOrdinalEqual $hash $hashBeforeRead)) { throw 'Backup JSON changed while it was read.' }
    $rawPath = ''; $rawHash = ''
    if ($version -ge 2) {
        $storedHash = (Get-Content -LiteralPath ($pathResolved + '.sha256') -Raw -ErrorAction Stop).Trim()
        if (-not (Test-PraOrdinalEqual $storedHash $hash)) { throw 'Backup SHA-256 does not match its .sha256 file.' }
        if (-not (Test-PraOrdinalEqual ([IO.Path]::GetFileName($data.RawFile)) $data.RawFile)) { throw 'Backup CLIXML path is not in the batch folder.' }
        $rawPath = Join-Path (Split-Path $pathResolved -Parent) $data.RawFile
        $rawHash = Get-PraHash -Path $rawPath
        if (-not (Test-PraOrdinalEqual $rawHash $data.RawHash)) { throw 'Backup CLIXML SHA-256 mismatch.' }
        $format = if ($version -eq 3) { [string]$data.RawFormat } else { '' }
        $Context.CurrentOperation = 'Validate-RawCapture'
        Write-PraMemoryStage -Context $Context -Stage 'RAW VALIDATE BEGIN' -Detail ("schema=$version objects=$($records.Count) file=$rawPath")
        $null = Test-PraRawCapture -Context $Context -LiteralPath $rawPath -Records $records -RawFormat $format
        # A change during the read never yields a receipt for different content.
        if (-not (Test-PraOrdinalEqual (Get-PraHash -Path $rawPath) $rawHash)) { throw 'Backup CLIXML changed during its validation.' }
        Write-PraMemoryStage -Context $Context -Stage 'RAW VALIDATE END' -Detail ("bytes=$((Get-Item -LiteralPath $rawPath -ErrorAction Stop).Length)")
    }
    else { Write-PraLog -Context $Context -Message 'Schema 1 backup (version 1.2.x): no proof of the original retention tag nor of the AD phase. Missing values are never invented.' -Level Warning }
    if (-not (Test-PraOrdinalEqual (Get-PraHash -Path $pathResolved) $hash)) { throw 'Backup JSON changed during its validation.' }
    $receipt = [pscustomobject]@{ Data=$data; Path=$pathResolved; Hash=$hash; Legacy=($version -eq 1) }
    Add-PraValidatedReceipt -Context $Context -Receipt $receipt -RawPath $rawPath -RawHash $rawHash
    return $receipt
}

function Assert-PraRecordMatchesPlan {
    <# The re-read backup record holds exactly the planned record (metadata, values, group, tag, permissions). #>
    [CmdletBinding()]
    param($Stored, [Collections.IDictionary]$Expected)
    foreach ($name in @('ObjectGuid','DistinguishedName','SamAccountName','UserPrincipalName','DisplayName','CapturedUtc','CapturedUsnChanged','IsShared','RequestedOperation','PreserveCloudMailbox','PreserveLicense')) {
        if (-not (Test-PraOrdinalEqual (Get-PraValue $Stored $name $null) $Expected[$name])) { throw "Backup re-read: $name not preserved." }
    }
    if ($Expected.Contains('KeptX500')) {
        $storedKept = @(if ($null -ne $Stored.PSObject.Properties['KeptX500']) { $Stored.KeptX500 | Where-Object { $null -ne $_ } }); $wantedKept = @($Expected['KeptX500'])
        if ($storedKept.Count -ne $wantedKept.Count) { throw 'Backup re-read: kept X500 addresses not preserved.' }
        for ($index = 0; $index -lt $wantedKept.Count; $index++) { if (-not (Test-PraOrdinalEqual ([string]$storedKept[$index]) ([string]$wantedKept[$index]))) { throw 'Backup re-read: kept X500 addresses not preserved.' } }
    }
    if ($Expected.Contains('ExpectedX500')) {
        $storedExpected = @(if ($null -ne $Stored.PSObject.Properties['ExpectedX500']) { $Stored.ExpectedX500 | Where-Object { $null -ne $_ } }); $wantedExpected = @($Expected['ExpectedX500'])
        if ($storedExpected.Count -ne $wantedExpected.Count) { throw 'Backup re-read: expected X500 addresses not preserved.' }
        for ($index = 0; $index -lt $wantedExpected.Count; $index++) { if (-not (Test-PraOrdinalEqual ([string]$storedExpected[$index]) ([string]$wantedExpected[$index]))) { throw 'Backup re-read: expected X500 addresses not preserved.' } }
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
            if (-not (Test-PraOrdinalEqual (Get-PraValue $Stored.$section $name $null) $Expected[$section][$name])) { throw "Backup re-read: state not preserved $section/$name." }
        }
    }
    foreach ($right in @('FullAccess','SendAs','SendOnBehalf')) {
        $actual = Get-PraValue $Stored.SharedPermissions $right $null
        $wanted = @($Expected.SharedPermissions[$right])
        if ($null -eq $actual -or @($actual).Count -ne $wanted.Count) { throw "Backup re-read: incomplete permissions $right." }
        for ($index = 0; $index -lt $wanted.Count; $index++) {
            if (-not (Test-PraOrdinalEqual ([string]$actual[$index]) ([string]$wanted[$index]))) { throw "Backup re-read: permission not preserved $right index=$index." }
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
    if ($rawPath.Length -ge 248) { throw 'Backup path too long: use a shorter Storage.BackupFolder (the paths of one batch must stay under 248 characters, as they were with 2.x).' }
    New-PraPrivateDirectory $directory -Root $Context.BackupFolder
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
        if (-not (Test-PraOrdinalEqual $record.ObjectGuid $Plans[$i].Record.ObjectGuid)) { throw 'Backup order or identity differs from the plan.' }
        Assert-PraRecordMatchesPlan -Stored $record -Expected $Plans[$i].Record
    }
    $Context.BackupFiles.Add($path)
    $Context.JournalPath = Join-Path $directory ('Journal-' + $id + '.jsonl')
    Write-PraImmutableFile $Context.JournalPath ''
    $Context.StateFiles.Add($Context.JournalPath)
    foreach ($plan in $Plans) {
        $plan.Row.BackupPath = $path
        Register-PraObjectBackup -Context $Context -Identity @([string]$plan.Row.ObjectGuid, [string]$plan.Row.UserPrincipalName, [string]$plan.Row.SamAccountName) -Path $path
    }
    Register-PraObjectBackup -Context $Context -Path $path
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
    if (-not $AcceptNewVersion -and -not (Test-PraOrdinalEqual $version $Plan.ExpectedUsnChanged)) { throw 'uSNChanged changed: the object was modified since it was planned or last verified.' }
    if (-not (Test-PraOrdinalEqual ([string]$user.DistinguishedName) $Plan.Record.DistinguishedName)) { throw 'The DN changed since the capture: plan the batch again.' }
    $actual = Get-PraAttributeState $user $Plan.Kinds
    foreach ($name in $Expected.Keys) {
        if (-not (Test-PraStateEqual $Expected[$name] $actual[$name])) { throw "AD state differs from the expected state | GUID=$($Plan.Record.ObjectGuid) | attribute=$name | DC=$($Context.Server)" }
    }
    if ($Plan.Record.Licensing.Enabled) {
        $group = Get-PraGroup $Context $Plan.Record.Licensing.GroupGuid
        if (-not (Test-PraOrdinalEqual $group.DistinguishedName $Plan.Record.Licensing.GroupDN) -or
            (-not (Test-PraOrdinalIgnoreCaseEqual (Test-PraOrdinalIn -IgnoreCase ([string]$user.DistinguishedName) @($group.member)) $ExpectedMember))) { throw 'Licence group membership differs from the backup/plan.' }
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
    if (-not $Context.AllowMutation -or (-not (Test-PraOrdinalIgnoreCaseEqual $Context.Mode 'Apply')) -or (Test-PraOrdinalIgnoreCaseEqual $Context.Action 'Check') -or $WhatIfPreference) { throw 'Safety stop: AD writes are not allowed in this mode.' }
    if (-not $PSCmdlet.ShouldProcess($Plan.Record.ObjectGuid, $Operation)) { throw 'AD write not authorised (ShouldProcess).' }
    Assert-PraReceipt $Context $Receipt $Plan.Record.ObjectGuid
    if (-not (& $Context.Approval $Plan.Record.DistinguishedName $Operation)) { throw "Operation refused: $Operation. Batch stopped." }
    # An interactive confirmation can take time: re-check the object and the backup AFTER it.
    $expected = if ((Test-PraOrdinalIgnoreCaseEqual $Operation 'Set-ADUser')) { $Plan.Record.Attributes } else { $Plan.Desired }
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
        if (-not $Context.AllowMutation -or (-not (Test-PraOrdinalIgnoreCaseEqual $Context.Mode 'Apply')) -or (Test-PraOrdinalIgnoreCaseEqual $Context.Action 'Check') -or $WhatIfPreference) {
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
                if ($groupState.Enabled -and (-not (Test-PraOrdinalIgnoreCaseEqual $groupState.WasMember $groupState.DesiredMember))) {
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
    $data = Get-Content -LiteralPath $Path -Raw -Encoding UTF8 -ErrorAction Stop | ConvertFrom-PraJson
    $hash = Get-PraHash $Path
    if (-not (Test-PraOrdinalEqual (Get-Content -LiteralPath ($Path + '.sha256') -Raw -ErrorAction Stop).Trim() $hash)) { throw 'AD proof (State file): SHA-256 mismatch.' }
    if ($data.SchemaVersion -ne 2 -or -not (Test-PraOrdinalEqual $data.Kind 'ADVerified') -or -not (Test-PraOrdinalEqual $data.Environment $Context.Config.Environment) -or -not (Test-PraOrdinalEqual $data.Operation $Operation)) { throw "AD proof (State file) does not match: operation $($data.Operation) instead of $Operation, or another Environment." }
    if (-not (Test-PraOrdinalEqual ([IO.Path]::GetFileName($data.BackupFile)) $data.BackupFile)) { throw 'AD proof: invalid backup path.' }
    $receipt = Import-PraBackup $Context (Join-Path (Split-Path $Path -Parent) $data.BackupFile)
    if (-not (Test-PraOrdinalEqual $receipt.Hash $data.BackupHash) -or -not (Test-PraOrdinalEqual $receipt.Data.Operation $Operation) -or -not (Test-PraOrdinalEqual $receipt.Data.RunId $data.RunId) -or -not (Test-PraOrdinalEqual $receipt.Data.SourceBackupHash $data.SourceBackupHash)) { throw 'AD proof does not match its backup, operation or source.' }
    if (@($data.Records).Count -ne @($receipt.Data.Records).Count) { throw 'AD proof incomplete compared with its backup.' }
    $expectedSource = if ((Test-PraOrdinalIgnoreCaseEqual $Operation 'Convert')) { $data.BackupHash } else { $data.SourceBackupHash }
    if (-not (Test-PraOrdinalEqual $expectedSource $Source.Hash)) { throw 'AD proof built from another Convert batch.' }
    $seen = @{}
    foreach ($record in @($data.Records)) {
        if ($record.ADVerified -isnot [bool] -or -not $record.ADVerified -or -not (Test-PraOrdinalIn -IgnoreCase $record.ObjectGuid @($Source.Data.Records.ObjectGuid)) -or $seen.ContainsKey($record.ObjectGuid)) { throw 'AD proof: invalid or duplicated object.' }
        $captured = @($receipt.Data.Records | Where-Object { Test-PraOrdinalIgnoreCaseEqual $_.ObjectGuid $record.ObjectGuid })
        $allowed = switch ($Operation) { Convert { @('Convert') } Recover { @('Recover','Deprovision','AlreadyRecovered') } Finalize { @('Recover','RestoreTag','AlreadyRecovered') } Retention { @('RestoreTag') } default { @() } }
        if ($captured.Count -ne 1 -or -not (Test-PraOrdinalIn $record.Operation $allowed) -or -not (Test-PraOrdinalEqual $record.Operation $captured[0].RequestedOperation) -or
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
    if (-not (Test-PraOrdinalIgnoreCaseEqual $Context.Server $Proof.Receipt.Data.Server)) { throw "Finalize: use the domain controller of the proof '$($Proof.Receipt.Data.Server)' (uSNChanged cannot be compared between DCs); set DomainController in the configuration." }
    $verified = @($Proof.Data.Records | Where-Object { Test-PraOrdinalIgnoreCaseEqual $_.ObjectGuid $Plan.Record.ObjectGuid })
    $captured = @($Proof.Receipt.Data.Records | Where-Object { Test-PraOrdinalIgnoreCaseEqual $_.ObjectGuid $Plan.Record.ObjectGuid })
    if ($verified.Count -ne 1 -or $captured.Count -ne 1) { throw 'Finalize: object not in the AD proof.' }
    $previous = $captured[0]
    if ($previous.Licensing.Enabled) {
        $group = Get-PraGroup $Context $previous.Licensing.GroupGuid
        if (-not (Test-PraOrdinalEqual $group.DistinguishedName $previous.Licensing.GroupDN) -or
            (-not (Test-PraOrdinalIgnoreCaseEqual (Test-PraOrdinalIn -IgnoreCase ([string]$Plan.User.DistinguishedName) @($group.member)) ($previous.Licensing.DesiredMember)))) { throw 'Finalize: licence group membership differs from the AD proof.' }
    }
    # Already finished (replay): only the complete original state is accepted, it needs no write.
    $original = $Plan.Row.BackupRec
    $complete = $true
    foreach ($name in $Plan.Kinds.Keys) {
        $sourceState = Get-PraValue $original.Attributes $name $null
        if ($null -eq $sourceState -or -not (Test-PraStateEqual $Plan.Record.Attributes[$name] $sourceState)) {
            # A cloud X500 kept on purpose is not a difference from the original list.
            if ($null -ne $sourceState -and (Test-PraOrdinalEqual $name 'proxyAddresses')) {
                $kept = Get-PraX500Difference $Plan.Record.Attributes[$name] $sourceState
                if ($kept.OtherEqual -and -not $kept.Removed.Count) { continue }
            }
            $complete = $false
        }
    }
    if ($complete -and (-not $Plan.Record.Licensing.Enabled -or (Test-PraOrdinalIgnoreCaseEqual ($Plan.Record.Licensing.WasMember) ($Plan.Record.Licensing.DesiredMember)))) { return }
    # The version (uSNChanged) proves that nothing touched the object since the AD proof. One legitimate writer exists: Entra Connect (Exchange hybrid
    # writeback) adds the X500 address of the cloud mailbox to proxyAddresses and sets msDS-ExternalDirectoryObjectId while the object is a remote
    # mailbox. That alone moves the version. It is accepted ONLY when the DN is the same, the X500 entries of proxyAddresses are the only difference
    # from the planned list of the proof (every other address identical), and every other managed attribute (and the licence group, above) is
    # as the proof left it; at least one X500 entry must have been added or removed. Any other change still refuses the restore. Limit: an attribute
    # that the tool does not manage cannot be told apart from msDS-ExternalDirectoryObjectId by the version alone, so in that one situation it is not
    # detected (the managed attributes, the licence group, the DN and the non-X500 addresses are).
    $versionKept = (Test-PraOrdinalEqual (Get-PraUsn $Plan.User) $verified[0].VerifiedUsnChanged)
    $sameDn = (Test-PraOrdinalEqual $Plan.User.DistinguishedName $previous.DistinguishedName)
    $writeback = $false
    if (-not $versionKept -and $sameDn) {
        $plannedProxies = Get-PraValue $previous.PlannedAttributes 'proxyAddresses' $null
        if ($null -ne $plannedProxies) {
            $x500 = Get-PraX500Difference $Plan.Record.Attributes['proxyAddresses'] $plannedProxies
            $writeback = ($x500.OtherEqual -and ($x500.Added.Count + $x500.Removed.Count) -gt 0)
        }
    }
    if ((-not $versionKept -and -not $writeback) -or -not $sameDn) {
        throw 'Finalize: the AD proof is out of date (version or DN changed). Nothing is overwritten: run the AD phase and the cloud check again.'
    }
    foreach ($name in $Plan.Kinds.Keys) {
        $expected = Get-PraValue $previous.PlannedAttributes $name $null
        if ($writeback -and (Test-PraOrdinalEqual $name 'proxyAddresses')) { continue }
        if ($null -eq $expected -or -not (Test-PraStateEqual $Plan.Record.Attributes[$name] $expected)) { throw "Finalize: $name differs from the AD proof." }
    }
    if ($writeback) {
        $Plan.Row.Detail += ' | Entra Connect writeback since the AD proof accepted (X500 address of the cloud mailbox)'
        Write-PraLog -Context $Context -Message ("FINALIZE | {0} | the version changed after the AD proof by an Entra Connect writeback (X500 entries of proxyAddresses only): accepted, the X500 list is recomputed" -f $Plan.Record.SamAccountName) -Level Detail
    }
}
#endregion

#region 7b. Active Directory replication ----
function Invoke-PraAdReplication {
    <#
    .SYNOPSIS
        Optional (Directory.ForceReplication, -ForceAdReplication, OFF by default): before the Entra Connect synchronisation, pushes each object changed in this
        run from the domain controller that was written to the other writable domain controllers (Sync-ADObject), then reads the changed attributes back on each
        of them. Nothing is silent: an unreachable or not converged domain controller, or an access denied, is a warning that names it.
    .DESCRIPTION
        Apply only (a Preview never replicates). The synchronisation always runs afterwards; when replication was not confirmed everywhere, the Next steps say that the
        synchronisation may not see the change and how to run it again later. Directory.ReplicationTargets restricts the destinations (for example the
        domain controllers the Entra Connect connector reads). Bounded: Directory.ReplicationVerifyAttempts reads, Directory.ReplicationVerifyDelaySeconds apart.
    #>
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Low')]
    param([hashtable]$Context, [AllowEmptyCollection()][object[]]$Plans)
    $settings = Get-PraValue $Context.Config 'Directory' @{}
    if (-not [bool](Get-PraValue $settings 'ForceReplication' $false)) { return }
    if (-not $Context.AllowMutation -or (-not (Test-PraOrdinalIgnoreCaseEqual $Context.Mode 'Apply')) -or $WhatIfPreference) { return }
    $changed = @($Plans | Where-Object { (Get-PraValue $_.Row 'ADApplied' $null) -eq $true })
    if (-not $changed.Count) { Write-PraItem -Context $Context -Status Skip -Icon Directory -Text 'No Active Directory change in this run: nothing to replicate.'; return }
    $source = [string]$Context.Server
    $attempts = [int](Get-PraValue $settings 'ReplicationVerifyAttempts' 6); $delay = [int](Get-PraValue $settings 'ReplicationVerifyDelaySeconds' 10)
    $unconfirmed = New-Object 'Collections.Generic.List[string]'
    $Context.CurrentOperation = 'Replicate-ADObject'; $Context.CurrentIdentity = ''
    $targets = @(@(Get-PraList $settings 'ReplicationTargets') | Where-Object { $_ } | Get-PraOrdinalUnique -IgnoreCase | Where-Object { -not (Test-PraOrdinalIgnoreCaseEqual $_ $source) })
    if (-not $targets.Count) {
        try {
            $controllers = @(Invoke-PraRead $Context 'Get-ADDomainController/All' $source { Get-ADDomainController -Filter * -Server $source -ErrorAction Stop })
            $targets = @($controllers | Where-Object { -not [bool](Get-PraValue $_ 'IsReadOnly' $false) } | ForEach-Object { [string](Get-PraValue $_ 'HostName' '') } |
                    Where-Object { $_ -and -not (Test-PraOrdinalIgnoreCaseEqual $_ $source) } | Get-PraOrdinalUnique -IgnoreCase)
        }
        catch {
            Write-PraLog -Context $Context -Message ("Active Directory replication: the list of domain controllers cannot be read from {0} ({1}). The Entra Connect synchronisation may not see the change." -f $source, $_.Exception.Message) -Level Warning
            $Context['ReplicationUnconfirmed'] = @($source); return
        }
    }
    if (-not $targets.Count) {
        $restricted = @(Get-PraList $settings 'ReplicationTargets').Count -gt 0
        Write-PraItem -Context $Context -Status Info -Icon Directory -Text $(if ($restricted) { 'Directory.ReplicationTargets leaves no destination (it only names {0}): nothing to replicate.' -f $source } else { '{0} is the only writable domain controller: nothing to replicate.' -f $source })
        return
    }
    Write-PraItem -Context $Context -Status Info -Icon Directory -Text ("Replicating {0} changed object(s) from {1} to {2} domain controller(s): {3}" -f $changed.Count, $source, $targets.Count, ($targets -join ', '))
    # The licence group change (member added or removed) lives on the GROUP object: it is pushed and read back like the users.
    $groupPlans = @($changed | Where-Object { Test-PraOrdinalIn ([string](Get-PraValue $_.Row 'GroupAction' '')) @('Added', 'Removed') })
    $groupDns = @($groupPlans | ForEach-Object { [string]$_.Record.Licensing.GroupDN } | Get-PraOrdinalUnique)
    $destinationNumber = 0
    foreach ($destination in $targets) {
        $destinationNumber++
        $failed = New-Object 'Collections.Generic.List[string]'
        if (-not $PSCmdlet.ShouldProcess($destination, 'Replicate the changed objects (Sync-ADObject)')) { $unconfirmed.Add($destination); continue }
        if (-not (& $Context.Approval $destination 'Sync-ADObject')) { Write-PraLog -Context $Context -Message ("Replication to {0} was not approved: the synchronisation may not see the change there." -f $destination) -Level Warning; $unconfirmed.Add($destination); continue }
        foreach ($plan in $changed) {
            $Context.CurrentOperation = 'Sync-ADObject'; $Context.CurrentIdentity = [string]$plan.Record.ObjectGuid
            try {
                Write-PraLog -Context $Context -Message ("AD REPLICATE | {0} -> {1} | {2}" -f $source, $destination, $plan.Record.ObjectGuid) -Level Detail
                Sync-ADObject -Object ([string]$plan.Record.DistinguishedName) -Source $source -Destination $destination -ErrorAction Stop | Out-Null
            }
            catch {
                $failed.Add([string]$plan.Record.ObjectGuid)
                $reason = $_.Exception.Message
                if ($_.Exception -is [UnauthorizedAccessException] -or $reason -match '(?i)denied|insufficient access|not authori') {
                    $reason = "access denied: the account needs the right to replicate a single object between domain controllers (the extended right Replication Synchronization on the domain naming context, normally held by Domain Admins). $reason"
                }
                Write-PraLog -Context $Context -Message ("Replication to {0} failed for {1}: {2}" -f $destination, $(if ($plan.Row.UserPrincipalName) { $plan.Row.UserPrincipalName } else { $plan.Row.SamAccountName }), $reason) -Level Warning
            }
        }
        foreach ($groupDn in $groupDns) {
            $Context.CurrentOperation = 'Sync-ADObject'; $Context.CurrentIdentity = ''
            try {
                Write-PraLog -Context $Context -Message ("AD REPLICATE | {0} -> {1} | licence group {2}" -f $source, $destination, $groupDn) -Level Detail
                Sync-ADObject -Object $groupDn -Source $source -Destination $destination -ErrorAction Stop | Out-Null
            }
            catch {
                foreach ($member in @($groupPlans | Where-Object { Test-PraOrdinalEqual ([string]$_.Record.Licensing.GroupDN) $groupDn })) { if (-not $failed.Contains([string]$member.Record.ObjectGuid)) { $failed.Add([string]$member.Record.ObjectGuid) } }
                Write-PraLog -Context $Context -Message ("Replication of the licence group to {0} failed: {1}" -f $destination, $_.Exception.Message) -Level Warning
            }
        }
        # Read the changed attributes back on the destination.
        $pending = @($changed | Where-Object { -not $failed.Contains([string]$_.Record.ObjectGuid) })
        for ($attempt = 1; $attempt -le $attempts -and $pending.Count; $attempt++) {
            $stillPending = New-Object 'Collections.Generic.List[object]'
            foreach ($plan in $pending) {
                $Context.CurrentOperation = 'Verify-ADReplication'; $Context.CurrentIdentity = [string]$plan.Record.ObjectGuid
                $match = $false
                try {
                    $names = @($plan.Kinds.Keys)
                    $user = @(Get-ADUser -Identity ([guid]$plan.Record.ObjectGuid) -Properties $names -Server $destination -ErrorAction Stop)
                    if ($user.Count -eq 1) {
                        $actual = Get-PraAttributeState $user[0] $plan.Kinds
                        $match = $true
                        foreach ($name in $names) { if (-not (Test-PraStateEqual $plan.Desired[$name] $actual[$name])) { $match = $false; break } }
                        if ($match -and (Test-PraOrdinalIn ([string](Get-PraValue $plan.Row 'GroupAction' '')) @('Added', 'Removed'))) {
                            $group = @(Get-ADGroup -Identity ([guid]$plan.Record.Licensing.GroupGuid) -Properties member -Server $destination -ErrorAction Stop)
                            $isMember = ($group.Count -eq 1) -and (Test-PraOrdinalIn -IgnoreCase ([string]$plan.Record.DistinguishedName) @($group[0].member))
                            $match = ($isMember -eq [bool]$plan.Record.Licensing.DesiredMember)
                        }
                    }
                }
                catch { Write-PraLog -Context $Context -Message ("AD REPLICATION READ | {0} | {1} | {2}" -f $destination, $plan.Record.ObjectGuid, $_.Exception.Message) -Level Detail }
                if (-not $match) { $stillPending.Add($plan) }
            }
            $pending = [object[]]$stillPending.ToArray()
            $Context.CurrentIdentity = ''
            Write-PraProgress -Context $Context -Text ("Active Directory replication to {0} ({1} / {2} object(s) confirmed)" -f $destination, ($changed.Count - $failed.Count - $pending.Count), $changed.Count) -Current ($destinationNumber - 1) -Total $targets.Count -Attempt $attempt -MaxAttempts $attempts -NextInSeconds $(if ($pending.Count -and $attempt -lt $attempts) { $delay } else { 0 })
            if ($pending.Count -and $attempt -lt $attempts) { Start-Sleep -Seconds $delay }
        }
        foreach ($plan in $pending) { $failed.Add([string]$plan.Record.ObjectGuid) }
        foreach ($plan in $changed) {
            $Context.CurrentOperation = 'Verify-ADReplication'; $Context.CurrentIdentity = [string]$plan.Record.ObjectGuid
            if ($failed.Contains([string]$plan.Record.ObjectGuid)) {
                Write-PraItem -Context $Context -Status Warn -Icon Directory -Text ("Not confirmed on {0}: the Entra Connect synchronisation may not see the change." -f $destination)
            }
            else { Write-PraItem -Context $Context -Status Ok -Icon Directory -Text ("Replicated to {0} and read back" -f $destination) }
        }
        $Context.CurrentIdentity = ''
        if ($failed.Count) { $unconfirmed.Add($destination) }
    }
    $Context['ReplicationUnconfirmed'] = $unconfirmed.ToArray()
    if ($unconfirmed.Count) {
        Write-PraLog -Context $Context -Message ("Active Directory replication was NOT confirmed on: {0}. The synchronisation runs anyway but may not see the change." -f ($unconfirmed -join ', ')) -Level Warning
    }
    else { Write-PraItem -Context $Context -Status Ok -Icon Directory -Text ("Every changed object is on {0} domain controller(s) before the synchronisation." -f $targets.Count) }
}
#endregion

#region 8. Entra Connect -----------------------------------------------------------------------

# Runs one synchronisation cycle and waits for its end. Self-contained: also sent to a remote server.
$script:PraSyncCycle = {
    param([string]$PolicyType, [int]$TimeoutMinutes, [scriptblock]$OnPoll)
    $ErrorActionPreference = 'Stop'
    # ADSync is a Windows PowerShell (.NET Framework) module: PowerShell 7 loads it through the Windows PowerShell
    # compatibility session. On EntraConnect.Server this block runs in the Windows PowerShell 5.1 endpoint, which has no such switch.
    $import = @{ Name = 'ADSync'; ErrorAction = 'Stop' }
    if ([string]::Equals([string]$PSVersionTable.PSEdition, 'Core', [StringComparison]::Ordinal)) { $import.UseWindowsPowerShell = $true }
    Import-Module @import
    $deadline = [DateTime]::UtcNow.AddMinutes($TimeoutMinutes)
    $clock = [Diagnostics.Stopwatch]::StartNew()
    $polls = 0; $maxPolls = [int][Math]::Ceiling($TimeoutMinutes * 60 / 5.0)
    while ((Get-ADSyncScheduler -ErrorAction Stop).SyncCycleInProgress) {
        if ([DateTime]::UtcNow -gt $deadline) { throw 'Timeout: a synchronisation cycle was already running.' }
        $polls++
        if ($null -ne $OnPoll) { $null = & $OnPoll 'A synchronisation cycle is already running: waiting for it to end' $polls $maxPolls ([int]$clock.Elapsed.TotalSeconds) }
        Start-Sleep -Seconds 5
    }
    $result = Start-ADSyncSyncCycle -PolicyType $PolicyType -ErrorAction Stop
    if (-not [string]::Equals([string]$result.Result, 'Success', [StringComparison]::OrdinalIgnoreCase)) { throw "Entra Connect refused the cycle: $($result.Result)" }
    Start-Sleep -Seconds 10
    $polls = 0
    while ((Get-ADSyncScheduler -ErrorAction Stop).SyncCycleInProgress) {
        if ([DateTime]::UtcNow -gt $deadline) { throw 'Timeout: the synchronisation cycle did not end in time; the cloud part is not started.' }
        $polls++
        if ($null -ne $OnPoll) { $null = & $OnPoll 'Entra Connect synchronisation cycle in progress' $polls $maxPolls ([int]$clock.Elapsed.TotalSeconds) }
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
    if (-not $Context.AllowMutation -or (-not (Test-PraOrdinalIgnoreCaseEqual $Context.Mode 'Apply')) -or (-not (Test-PraOrdinalIn $Context.Action @('Convert','Recover','Finalize') -IgnoreCase)) -or $WhatIfPreference) { return }
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
    if ($null -eq $receipt -or -not (Test-PraOrdinalEqual $receipt.Data.RunId $Context.RunId)) { throw 'Synchronisation refused: no verified AD batch in this run.' }
    if ([bool](Get-PraValue $Context 'OperationFailed' $false) -or $Context.Issues.Count -gt 0 -or @($Context.Rows | Where-Object FinalStatus -eq 'Error').Count -gt 0) { throw 'Synchronisation refused after an error in this run.' }
    $source = if (Test-PraOrdinalEqual $receipt.Data.Operation 'Convert') { $receipt } else { Get-PraValue $Context 'Source' $null }
    if ($null -eq $source) { throw 'Synchronisation refused: the Convert source of the batch is unknown.' }
    $null = Import-PraProof $Context $receipt.StatePath $source $receipt.Data.Operation
    if (-not $Context.JournalPath -or -not (Test-Path -LiteralPath $Context.JournalPath -PathType Leaf)) { throw 'Synchronisation refused: the batch journal is missing.' }
    $target = if ($settings.Server) { $settings.Server } else { $env:COMPUTERNAME }
    $Context.CurrentOperation = 'Start-ADSyncSyncCycle'; $Context.CurrentIdentity = $target
    if (-not (& $Context.Approval $target 'Start-ADSyncSyncCycle')) { throw 'Synchronisation refused.' }
    Write-PraJournal $Context '*' 'ADSync' 'Started' $target
    Write-PraItem -Context $Context -Status Info -Icon Sync -Text ("{0} cycle started on {1}, waiting for its end (max {2} min)..." -f $settings.PolicyType, $target, $settings.TimeoutMinutes)
    Write-PraProgress -Context $Context -Text ('Waiting for the Entra Connect {0} cycle to finish on {1} (up to {2} min)' -f $settings.PolicyType, $target, $settings.TimeoutMinutes) -Current 0 -Total ([int]$settings.TimeoutMinutes * 60)
    $timeoutSeconds = [int]$settings.TimeoutMinutes * 60
    if ($settings.Server) {
        # The cycle runs on the Entra Connect server as a job: this side reports a wait (attempt, next check) every 5 s until it ends.
        $job = Invoke-Command -ComputerName $settings.Server -ScriptBlock $script:PraSyncCycle -ArgumentList $settings.PolicyType, $settings.TimeoutMinutes -AsJob -ErrorAction Stop
        try {
            $clock = [Diagnostics.Stopwatch]::StartNew(); $poll = 0
            while ($null -eq (Wait-Job -Job $job -Timeout 5)) {
                $poll++
                Write-PraProgress -Context $Context -Text ('Entra Connect synchronisation cycle in progress on {0}' -f $target) -Current ([int]$clock.Elapsed.TotalSeconds) -Total $timeoutSeconds -Attempt $poll -MaxAttempts ([int][Math]::Ceiling($timeoutSeconds / 5.0)) -NextInSeconds 5
            }
            $result = Receive-Job -Job $job -ErrorAction Stop
        }
        finally { Remove-Job -Job $job -Force -ErrorAction SilentlyContinue }
    }
    else {
        $report = { param($Text, $Attempt, $MaxAttempts, $Elapsed) Write-PraProgress -Context $Context -Text $Text -Current $Elapsed -Total $timeoutSeconds -Attempt $Attempt -MaxAttempts $MaxAttempts -NextInSeconds 5 }.GetNewClosure()
        $result = & $script:PraSyncCycle $settings.PolicyType $settings.TimeoutMinutes $report
    }
    Write-PraJournal $Context '*' 'ADSync' 'Completed' $target
    Write-PraProgress -Context $Context -Text ('Entra Connect cycle finished on {0}' -f $target) -Current ([int](Get-PraValue $result 'Seconds' 0)) -Total ([int]$settings.TimeoutMinutes * 60)
    Write-PraItem -Context $Context -Status Ok -Icon Sync -Text ("Entra Connect cycle finished on {0} in {1} s (Exchange Online may still need a few minutes)" -f $target, (Get-PraValue $result 'Seconds' 0))
}
#endregion

Export-ModuleMember -Function ConvertTo-PraLdapValue, Get-PraHash, Write-PraImmutableFile, New-PraPrivateDirectory, Write-PraJournal,
    Initialize-PraDirectory, Get-PraUser, Get-PraExpectedX500, Get-PraTarget, New-PraRow, New-PraPlan, Import-PraBackup, Invoke-PraAdPreview, Invoke-PraAdBatch,
    Import-PraProof, Invoke-PraSync, Invoke-PraAdReplication, Assert-PraReceipt, Test-PraStateEqual, Assert-PraFollowupState, Initialize-PraPermissionCache

# SIG # Begin signature block
# MIImKAYJKoZIhvcNAQcCoIImGTCCJhUCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCBDCeIJDs3qkhVe
# z1CqvgQDLN8jr/Rm/lGczmNARzv1CaCCDW8wggZyMIIEWqADAgECAghkM1HTxzif
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
# wZislcdCZuS6MYIYDzCCGAsCAQEwgYwweDELMAkGA1UEBhMCVVMxDjAMBgNVBAgM
# BVRleGFzMRAwDgYDVQQHDAdIb3VzdG9uMREwDwYDVQQKDAhTU0wgQ29ycDE0MDIG
# A1UEAwwrU1NMLmNvbSBDb2RlIFNpZ25pbmcgSW50ZXJtZWRpYXRlIENBIFJTQSBS
# MQIQBof4ljXihJpmCqqt2mhAWzANBglghkgBZQMEAgEFAKCBhDAYBgorBgEEAYI3
# AgEMMQowCKACgAChAoAAMBkGCSqGSIb3DQEJAzEMBgorBgEEAYI3AgEEMBwGCisG
# AQQBgjcCAQsxDjAMBgorBgEEAYI3AgEVMC8GCSqGSIb3DQEJBDEiBCBsTEC7DeXn
# 3avmi42IDFa22szqBVz410kCF7EASb1w4jANBgkqhkiG9w0BAQEFAASCAgBRX260
# H0x2pijivJdGV+lur8ryYwngQGP9tvlMrqdMHNQ1ZnjS06BB08LbE42EB1/d93SQ
# xUccbSkfsQ8jiCRVt5Ri/OSEQ++Y5sVxv7d8nhsChgvfHzgXl7RR8CC8+F3d+/Q1
# au2AYLvMhgC2DUF9cDKkOd7SZZb49iw4dwp9SmV+bpWzQ58Dsgqjxl6W9XHGX99b
# PEagkqDGBWK46lNP1XArapHMVOXv6HDNzsm5dctULUVIWVuutyZzjkbBHcYQq93H
# j1YrWp1xT0OzxaQYg1KLEUY6klhZsWJfd2pr7Z0/8y56QDUjj0PReJehriZy7t/a
# Og3RaFjVIiltseGXRy7HKPp3GQgj+N94aGJ0CgvlARiVjya7UiCvaee3p42ffHLX
# +JMGmfaBxMvHgvr05tdI3qr0MOT7Nz/KUri4cNOVRQVwffUgfQr5bDAXBLGpNsV2
# FIEJoqR0N/ZvlKdbHQtCanlmBwprCj2ikZyWQwOFI8FI4N0Vmz9rIhtsvYq9QiQk
# qPtt2Qr/iZ/zczuSqLF2q86tvzk0vCGDirfTVZrOyMGskDgwUWn8KiAjG2dVuvFX
# hanpG2Ikw+wKq1jTzJDP9RTAfikL8Q04JXk9pV7XcPl4r85LOXLh9+0QDHlwzNrk
# /zkWf/kM39Aq/Bw/T/mOzFfEeZNYNe1vV9k97aGCFMwwghTIBgorBgEEAYI3AwMB
# MYIUuDCCFLQGCSqGSIb3DQEHAqCCFKUwghShAgEDMQ0wCwYJYIZIAWUDBAIBMIGI
# BgsqhkiG9w0BCRABBKB5BHcwdQIBAQYMKwYBBAGCqTABAwYBMDEwDQYJYIZIAWUD
# BAIBBQAEIDKfWrJ5O8xYOP08+q0tqa7kU8+COO5FwYknm7IfwNWaAgdAN5/Do924
# GA8yMDI2MTEwNTA4MDcyMlowAwIBAQIQc6dFpkrjh3tDOljRjI+3Y6CCEacwggTz
# MIIC26ADAgECAhBUQ/g3vVruGAGEcrhc2o7jMA0GCSqGSIb3DQEBCwUAMHIxCzAJ
# BgNVBAYTAlVTMQ4wDAYDVQQIDAVUZXhhczEQMA4GA1UEBwwHSG91c3RvbjERMA8G
# A1UECgwIU1NMIENvcnAxLjAsBgNVBAMMJVNTTC5jb20gVGltZXN0YW1waW5nIElz
# c3VpbmcgUlNBIENBIDIwHhcNMjYwNjEyMTcyMjQ2WhcNMzYwNjA5MTcyMjQ1WjBu
# MQswCQYDVQQGEwJVUzEOMAwGA1UECAwFVGV4YXMxEDAOBgNVBAcMB0hvdXN0b24x
# ETAPBgNVBAoMCFNTTCBDb3JwMSowKAYDVQQDDCFTU0wuY29tIFRpbWVzdGFtcGlu
# ZyBVbml0IDIwMjYgRTEwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAToJYu4ZhMu
# SJI48ws2yQ4G2FewiFFIDjp945DC9ItwNo2Hq/FTMEoTHUp0UFEWzs4eucf8rRUD
# oxsNAgWlSDQ9o4IBUjCCAU4wHwYDVR0jBBgwFoAUcJplwUOAo/zpsWSJbvEwnAkh
# yXwwTQYIKwYBBQUHAQEEQTA/MD0GCCsGAQUFBzAChjFodHRwOi8vY2VydC5zc2wu
# Y29tL1NTTC5jb20tdGltZVN0YW1waW5nLUktUjIuY2VyMFEGA1UdIARKMEgwPAYM
# KwYBBAGCqTABAwYBMCwwKgYIKwYBBQUHAgEWHmh0dHBzOi8vd3d3LnNzbC5jb20v
# cmVwb3NpdG9yeTAIBgZngQwBBAIwFgYDVR0lAQH/BAwwCgYIKwYBBQUHAwgwQgYD
# VR0fBDswOTA3oDWgM4YxaHR0cDovL2NybHMuc3NsLmNvbS9TU0wuY29tLXRpbWVT
# dGFtcGluZy1JLVIyLmNybDAdBgNVHQ4EFgQUJ6wDVrooaroXO4M9QH95qCTswzww
# DgYDVR0PAQH/BAQDAgeAMA0GCSqGSIb3DQEBCwUAA4ICAQBPdm7O/AOewhlNcGf6
# GOa4FeDMHXZ9tjFP25h7pm+G+ltlYpzINCBpwROQ/DyTrJ6qdgJjIVnTreUw8SoC
# EAPacwbrXhmHs+0db0Nap+yCK/Fs9gF4363tTGCRhPd7GltYx08SoG1ZXIc68twq
# 8zGAlZ8mMA3BWTBUN+TL+Ptx/bz6KKY3w8pztL+7z8t6dFGdXZbZh+dxGeTP0J+z
# mdEPNpmC6IeuunYbHCCc1BIfgYGMc6Xc/MuydVsahkqLhkSOBe6mziYYY4rv4YHY
# cCVCf45L3jhweqWQfSASW3ZZ7OgI1GkQumH2prG4GeNISpdZZ+ATrIYHA7S7Eo2q
# lZVMeYDCvpK8E+h/G5tci4Sf2K9HgIs64DFRKsnjVkGD+qobSgmMXoaREpvGrtzJ
# ZKQRlgmGYoKDYeDl9cdqA7GLBuafkk9nW+FYKtuTe/91PHaC9Mrn56sLkf3+tNyW
# NQjvvrJ3at+GN+Sm/ICxu1ezgPueufDyL3Civn5921FIkFXGrMubKQV+2gvRSnZD
# 763IoJR2uJt1yesHgcpLez63cCN1xsDToMIvwaJ9CL18vTJEFE2UDijoE/5Kvvnk
# xoI2NRFhkO8PLEkcEFPtyqNkjCyJHyz7rzrSegVsEG12B7YjDsI8L/VDfUjbuFWi
# VLsHTJqje/xfYy1bLeaxmVdNwTCCBd0wggPFoAMCAQICCHssm9MWgDKZMA0GCSqG
# SIb3DQEBCwUAMHwxCzAJBgNVBAYTAlVTMQ4wDAYDVQQIDAVUZXhhczEQMA4GA1UE
# BwwHSG91c3RvbjEYMBYGA1UECgwPU1NMIENvcnBvcmF0aW9uMTEwLwYDVQQDDChT
# U0wuY29tIFJvb3QgQ2VydGlmaWNhdGlvbiBBdXRob3JpdHkgUlNBMB4XDTE2MDIx
# MjE3MzkzOVoXDTQxMDIxMjE3MzkzOVowfDELMAkGA1UEBhMCVVMxDjAMBgNVBAgM
# BVRleGFzMRAwDgYDVQQHDAdIb3VzdG9uMRgwFgYDVQQKDA9TU0wgQ29ycG9yYXRp
# b24xMTAvBgNVBAMMKFNTTC5jb20gUm9vdCBDZXJ0aWZpY2F0aW9uIEF1dGhvcml0
# eSBSU0EwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQD5D92jK33L0Cr+
# 7GeFpucuG7p34eP1r6Ts+kpdkcRXR2sYd2t28v2T5D0PwhaeC2bDVpSeF4OFzlbv
# 8hb9AGL1IglU6GUXTkG54E9Gl6obyLhuYl5psV/bKgJ+/GzK80HY7dDo/D9hSO2w
# AxQdEA5LGeC7TuyGZf82815nAgudhlVh/Xo47f7iGQC3b6FQYnV0PKD6yCWStG56
# Isf4HqHjst2RMasrHQT/pUoEN+mFpDMr/eLWVTR8GaRKaMeyqNO3yqGTiOvBl7yM
# +R3ZIoQkdMcEPWqpKZPM67hb4f5fJao0WMjBI1SdG5gRwzicfj2GbKUPQIZ8AvRc
# Ak8oy65xnw86yDP+ESU16vy6xWA92XwY1bKp03V4A3IiyjrDH+8s5S6p+p4stlFG
# /a8D1upgaOqFFjZrhekewLPdxCTcgCqBQW2UPsjgyYFBAJ5ev3/FCJiiGCxCQLP5
# bzgnS06A9D2BR+CIfOoczrV1XFEuHCt/GnIo5wC10XTG1+SfrQeTtlM1Nfw35MP2
# XRa+IXPekgr4oGNqvJaSaj74vGVVm971DYkmBPwlGqYlacvCbcp84llfl6zr7y7I
# vNcbWTwrzPIZyJNrJ2MZz/zpJvjKcZt/k/40Z4ROmev8s3gJM3C6ZqZ27Rtz6xql
# DcQiEyCUVgpOLGxOsf3PnAm6ojPthwIDAQABo2MwYTAdBgNVHQ4EFgQU3QQJB6L1
# en1SUxKSle44gCUNplkwDwYDVR0TAQH/BAUwAwEB/zAfBgNVHSMEGDAWgBTdBAkH
# ovV6fVJTEpKV7jiAJQ2mWTAOBgNVHQ8BAf8EBAMCAYYwDQYJKoZIhvcNAQELBQAD
# ggIBACAYEZQp+yadHB4ecGHxlXKTcSStaJNYjjKvG7NwA/wlK3SFkD14avS5i6WX
# O7UYkbsep/lAW5H5VZmvHhHQXB2nZuOxlAcMMjmm6huwedgdnHBE44rdxPmVH4o4
# Qz8BhaVHpz1GsrzlImj3e5zYLD4KIcgtM6y/xYGZMXTBdXHFvrHwI0X0nWv8GWOd
# o7wExhgLJbtTiQ+zgFDeRe5Ef6uUeGSY0/Yo3YfYcGV0+w65E+unD2GpMpbM3rvt
# Y0wYu6lA96BUbiCIcXUY6nq0NHLgIyd3XLaQ6oYlQKvvMw/Ln4K+oiD79rUtGubC
# hbF0D/vIZQKkUgFH3Ukiwb/Y62usft7sYzMVtyMIj8YPjUFa3Y7FuY/lRT9427rS
# G0Cx/nFNP+CBorpetOwV4JPdCB9+4VWZCyHek54K++ajSb02MP7nd7KgdZe1LYGI
# F2Ug99qQAJ/JUswyyjV89T0P2CvX9SZsyQY0lhbqcFkaMnl5C7aIfw9SSD2/bNii
# RC7RTrdyWNOJE5X+RKv414sbbpy8LKBb1WoAr1834dX6EAuYnIbnJo/O8OxuilcL
# gONOssCgY2GQulVoN3RqtpLbn6GGIrZlJw7stp9CYORnwrXaQQvE04thG7z6H5Er
# 10QHXroprNnF6e9TSFrrgPEoWCHNsAZV+yc/U5BwqQQeVye5MIIGyzCCBLOgAwIB
# AgIQUp27wriJh/WDgOCw66IGNjANBgkqhkiG9w0BAQsFADB8MQswCQYDVQQGEwJV
# UzEOMAwGA1UECAwFVGV4YXMxEDAOBgNVBAcMB0hvdXN0b24xGDAWBgNVBAoMD1NT
# TCBDb3Jwb3JhdGlvbjExMC8GA1UEAwwoU1NMLmNvbSBSb290IENlcnRpZmljYXRp
# b24gQXV0aG9yaXR5IFJTQTAeFw0yNjA2MTIxNjQyMTVaFw00MTAyMTIxNzM5Mzla
# MHIxCzAJBgNVBAYTAlVTMQ4wDAYDVQQIDAVUZXhhczEQMA4GA1UEBwwHSG91c3Rv
# bjERMA8GA1UECgwIU1NMIENvcnAxLjAsBgNVBAMMJVNTTC5jb20gVGltZXN0YW1w
# aW5nIElzc3VpbmcgUlNBIENBIDIwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIK
# AoICAQCfL6vmc02QvDFGmzYHeVpQY1T3Lu9aInnTXfJ/SJfPrltB3Br1uOPyX9KR
# 5eocap9KHYWhp77zQTyYMR/3egjCOzLYJfZxeYrGq0XwckZgHh/rJGEoQPnTCRs7
# KwvTYhd/78RmdrjiN9+GFXPg5T+TnbFD8+ciD+4WFzZaT5Jz8IeoCv6VhWQ/PsvL
# lGoH1/VEoav0kLftbUuBV0cLnR00h2xrdBc+GW1hm5tHeekTgFt+LSOhRbmfk7Rr
# LB43jlH9hUvEDRgaWnU4dV9WeyperxuGfDUtziSMnpc6BeU6XD9rzN7ntO9t25mX
# d6F7BOa87QCTL+eo5YNL0g8/F3F0bq+msFtK4eXE0A0EBsdOIWCR9mZ/R1liVP8C
# dkigXECrQcgs+iV/g6BaARPvpKJZKWbZdhEhfBWOl6obSmW9fBEhAHNKIQmPtB5A
# WcK8fHiBAwg283f7Ib/WvGERtqMa97S1M/eVfg884dUATRAmnhnM8jVhgmSFVGuJ
# VXFVFTgWyDgE/A/oj5guYdvW1nhEvA4U0uH+AlgOA+UKEKjE6iAXFeDA9lmsPIRF
# gHRp457FbQ4ppw3hFG71yoXYoq78BvkAvt5gMtUZQ+sQTJhsgwClUqql5tzT+MNC
# eIL7euRq5ECOBVzybWKn8JCAbUPDhn26VVEBj1VHplrbouxNtQIDAQABo4IBUTCC
# AU0wEgYDVR0TAQH/BAgwBgEB/wIBADAfBgNVHSMEGDAWgBTdBAkHovV6fVJTEpKV
# 7jiAJQ2mWTBNBggrBgEFBQcBAQRBMD8wPQYIKwYBBQUHMAKGMWh0dHA6Ly9jZXJ0
# LnNzbC5jb20vU1NMY29tLVJvb3RDQS1SU0EtNDA5Ni1SMS5jZXIwPwYDVR0gBDgw
# NjA0BgRVHSAAMCwwKgYIKwYBBQUHAgEWHmh0dHBzOi8vd3d3LnNzbC5jb20vcmVw
# b3NpdG9yeTATBgNVHSUEDDAKBggrBgEFBQcDCDBCBgNVHR8EOzA5MDegNaAzhjFo
# dHRwOi8vY3Jscy5zc2wuY29tL1NTTGNvbS1Sb290Q0EtUlNBLTQwOTYtUjEuY3Js
# MB0GA1UdDgQWBBRwmmXBQ4Cj/OmxZIlu8TCcCSHJfDAOBgNVHQ8BAf8EBAMCAYYw
# DQYJKoZIhvcNAQELBQADggIBAGUUW80x6YDqIGIFijnogpCNaFa5Bpgq6jiql/Qo
# k0REC3WDP4ewDZIvfED9X4QDxJE80/1K9fSKz7mYOymli+krJgapg/fpgVbSZsXU
# XRm1fG6YJRQ79lXmYE0oN/lDg9jtBvR5YB6lRzSs0mv8y+flmJd8k/ENvbGZyDxp
# EPrnb+ev46uTZQE/QTjeIl0jgsXtWzb1HdIZEthk7EzXkMjhB5uwpGXQoOV/g6Zg
# YIpzu6ZPGJuRm03ULUpaCd/2Np1T8nCfJJpgQGDHr+/4VULpIY43OJjtNy8j0xX6
# pjEdQ+U6boBpA/Z1LhuNZeebzqV0JtSTG04AK6ZJ9P3vTvsk2JVrs9nUgGR3/Y8T
# UALyCztT79iTUE31dE8iLXmT+4DXEX2h557koaPKIYqSohPtbxCSBRPnN4KKcUqR
# wpp9kxxE5JVile2a1CoYZHaDi49ionQrWGazqAlese3/finwz0+tXyg1Z7RmXUSs
# My1ed1SDeqEkvikDdlSWjvDmUzmaX4DuKOv/caTa/hBGgN4TZKGZNd0eC2qjwv99
# PXX2ZhwRPJwTY1gZFewGXc3SvMOwdGvw/dOumuqFGtfTiJLQ/t5D6UPGBLfKEafc
# 7NYaEO30Z/bHWp7T+p2EUBU6RfHMxnPhRq3rGwB/NfT7+bwYQpbk6PD8dj6Qu9XD
# NI87MYICVTCCAlECAQEwgYYwcjELMAkGA1UEBhMCVVMxDjAMBgNVBAgMBVRleGFz
# MRAwDgYDVQQHDAdIb3VzdG9uMREwDwYDVQQKDAhTU0wgQ29ycDEuMCwGA1UEAwwl
# U1NMLmNvbSBUaW1lc3RhbXBpbmcgSXNzdWluZyBSU0EgQ0EgMgIQVEP4N71a7hgB
# hHK4XNqO4zALBglghkgBZQMEAgGgggFgMBoGCSqGSIb3DQEJAzENBgsqhkiG9w0B
# CRABBDAcBgkqhkiG9w0BCQUxDxcNMjYxMTA1MDgwNzIyWjAoBgkqhkiG9w0BCTQx
# GzAZMAsGCWCGSAFlAwQCAaEKBggqhkjOPQQDAjAvBgkqhkiG9w0BCQQxIgQgQPXe
# /gUdhmcVd/vBdDPH4DrSeHfEQ5VKc5RqfCy3IO4wgcgGCyqGSIb3DQEJEAIvMYG4
# MIG1MIGyMIGvBCBXT+oXqvpefGormwjJmLFzXkULOHPKROaiTKCTDmPzsDCBijB2
# pHQwcjELMAkGA1UEBhMCVVMxDjAMBgNVBAgMBVRleGFzMRAwDgYDVQQHDAdIb3Vz
# dG9uMREwDwYDVQQKDAhTU0wgQ29ycDEuMCwGA1UEAwwlU1NMLmNvbSBUaW1lc3Rh
# bXBpbmcgSXNzdWluZyBSU0EgQ0EgMgIQVEP4N71a7hgBhHK4XNqO4zAKBggqhkjO
# PQQDAgRGMEQCIC1Kgzl3YZgUBrS5rd9GfapXOXycCHhjoeIZA7IjamkFAiACTXz9
# ZkxOvL7NK5SVkoyQFA0x5RcxHgyfFJdInpUYdA==
# SIG # End signature block
