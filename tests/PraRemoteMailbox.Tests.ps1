<#
.SYNOPSIS
    PRA Remote Mailbox test gate (Pester 5+): synthetic data only, no real directory or tenant.
.DESCRIPTION
    The only external modules allowed are fake modules created under the Windows TEMP folder.
    The entry script is copied unchanged; its Cloud module is replaced by a declared synthetic
    barrier, so that the AD orchestration is tested on its own.
    Unit tests run the real Directory functions in InModuleScope.
    No legacy Assert-MockCalled: counters are mutable objects.
.NOTES
    Author : Nicolas Fabert
    Version: 3.1.3
    Run it through tests\Invoke-TestGate.ps1 (evidence, PSScriptAnalyzer, mandatory tests).
#>
#Requires -Version 7.5

BeforeAll {
    $global:PraGate = @{
        Release = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
        Root = Join-Path ([IO.Path]::GetTempPath()) ('PG-' + [guid]::NewGuid().ToString('N').Substring(0,8))
        OriginalModulePath = $env:PSModulePath
        OriginalNonet = $env:PRA_GATE_NONET
        OriginalState = $env:PRA_GATE_STATE
        Runtime = $null
    }
    $global:PraGate.Source = Join-Path $global:PraGate.Release 'package'
    $null = New-Item -ItemType Directory -Path $global:PraGate.Root -Force
    . (Join-Path $PSScriptRoot 'IntegrityFixture.ps1')
    $global:PraGate.Package = Join-Path $global:PraGate.Root 'package-fixture'
    New-PraIntegrityFixture -SourcePackage $global:PraGate.Source -Destination $global:PraGate.Package -Changelog (Join-Path $global:PraGate.Release 'CHANGELOG.md')
    $env:PRA_GATE_NONET = 'SYNTHETIC-NO-NETWORK'
    $global:PraGate.AdSource = @'
# SYNTHETIC fixture. No AD management assembly, provider, network or remoting.
# System.DirectoryServices security descriptors below are created locally; never directory-bound.
Set-StrictMode -Version Latest
if ($env:PRA_GATE_NONET -cne 'SYNTHETIC-NO-NETWORK') { throw 'Synthetic interlock absent.' }
$global:PraGateAd = [Management.Automation.PSSerializer]::Deserialize([IO.File]::ReadAllText($env:PRA_GATE_STATE))
$script:GateBackupChecks=@{}
$script:GateNativeCaptureCount=0
function Write-GateEvent {
    param([string]$Operation, [object]$Identity = '', [string]$Server = '', [object]$Detail = '')
    $event = [ordered]@{ Operation=$Operation; Identity=[string]$Identity; Server=$Server; Detail=$Detail; Synthetic=$true; Utc=[datetime]::UtcNow.ToString('o') }
    [IO.File]::AppendAllText($global:PraGateAd.EventPath, (($event | ConvertTo-Json -Depth 10 -Compress) + "`r`n"))
}
function Assert-GateServer {
    param([string]$Server)
    if ($Server -cne $global:PraGateAd.Server) { throw "Synthetic DC mismatch: '$Server'" }
}
function New-GateNativeDescriptor {
    param([switch]$Mailbox,[int]$AclCount=100)
    Add-Type -AssemblyName System.DirectoryServices
    $descriptor=New-Object DirectoryServices.ActiveDirectorySecurity
    $descriptor.SetOwner((New-Object Security.Principal.SecurityIdentifier('S-1-5-18')))
    $descriptor.SetAccessRuleProtection($true,$false)
    $sendAs=[guid]'ab721a54-1e2f-11d0-9819-00aa0040529b'
    $sids=@('S-1-5-21-100-200-300-2001','S-1-5-21-100-200-300-2002','S-1-5-21-100-200-300-2003','S-1-5-21-100-200-300-3001','S-1-5-18','S-1-5-21-100-200-300-512','S-1-5-21-100-200-300-518','S-1-5-21-100-200-300-519','S-1-5-32-544','S-1-5-21-100-200-300-2004')
    for ($i=0;$i -lt $AclCount;$i++) {
        $sid=New-Object Security.Principal.SecurityIdentifier($sids[$i % $sids.Count])
        $rights=[DirectoryServices.ActiveDirectoryRights]::ReadProperty
        $objectType=[guid]('90000000-0000-0000-0000-{0:000000000000}' -f ($i+1))
        if ($Mailbox) { $rights=[DirectoryServices.ActiveDirectoryRights]::CreateChild }
        elseif ($i -lt $sids.Count) { $rights=[DirectoryServices.ActiveDirectoryRights]::ExtendedRight; $objectType=$sendAs }
        $rule=New-Object DirectoryServices.ActiveDirectoryAccessRule($sid,$rights,[Security.AccessControl.AccessControlType]::Allow,$objectType)
        [void]$descriptor.AddAccessRule($rule)
    }
    $denied=New-Object DirectoryServices.ActiveDirectoryAccessRule((New-Object Security.Principal.SecurityIdentifier('S-1-5-21-100-200-300-3999')),[DirectoryServices.ActiveDirectoryRights]::ExtendedRight,[Security.AccessControl.AccessControlType]::Deny,$sendAs)
    [void]$descriptor.AddAccessRule($denied)
    if ($global:PraGateAd.ContainsKey('OrphanSid') -and $global:PraGateAd.OrphanSid) {
        # ACE of an account that no AD object carries any more (deleted account).
        $orphan=New-Object Security.Principal.SecurityIdentifier($global:PraGateAd.OrphanSid)
        $orphanRights=if ($Mailbox) { [DirectoryServices.ActiveDirectoryRights]::CreateChild } else { [DirectoryServices.ActiveDirectoryRights]::ExtendedRight }
        $orphanType=if ($Mailbox) { [guid]'90000000-0000-0000-0000-000000009999' } else { $sendAs }
        [void]$descriptor.AddAccessRule((New-Object DirectoryServices.ActiveDirectoryAccessRule($orphan,$orphanRights,[Security.AccessControl.AccessControlType]::Allow,$orphanType)))
    }
    return $descriptor
}
function Copy-GateUser {
    param($User,[switch]$Capture)
    # Ordinary fixture state ONLY is cloned. Native security objects are injected AFTER cloning.
    $copy=[Management.Automation.PSSerializer]::Deserialize([Management.Automation.PSSerializer]::Serialize($User,30))
    if ($Capture -and $global:PraGateAd.ContainsKey('NativeShared') -and $global:PraGateAd.NativeShared -and $copy.objectClass -eq 'user' -and $copy.SamAccountName -like 'user*') {
        $script:GateNativeCaptureCount++
        if ($global:PraGateAd.Case -eq 'ThirteenthCaptureFailure' -and $script:GateNativeCaptureCount -eq 13) { throw 'SYNTHETIC: thirteenth raw capture refused.' }
        $copy.nTSecurityDescriptor=New-GateNativeDescriptor -AclCount $global:PraGateAd.AclCount
        $mailbox=New-GateNativeDescriptor -Mailbox -AclCount $global:PraGateAd.AclCount
        $copy.msExchMailboxSecurityDescriptor=$mailbox
        Write-GateEvent 'NativeSecurityDescriptor' $copy.ObjectGUID $global:PraGateAd.Server @{NtBase64=[Convert]::ToBase64String($copy.nTSecurityDescriptor.GetSecurityDescriptorBinaryForm());MailboxBase64=[Convert]::ToBase64String($mailbox.GetSecurityDescriptorBinaryForm());AceCount=$copy.nTSecurityDescriptor.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier]).Count;IdentityType='System.Security.Principal.SecurityIdentifier'}
    }
    return $copy
}
function Get-GateSha {
    param([string]$Path)
    $sha=[Security.Cryptography.SHA256]::Create(); $stream=[IO.File]::OpenRead($Path)
    try { ([BitConverter]::ToString($sha.ComputeHash($stream))).Replace('-','').ToLowerInvariant() }
    finally { $stream.Dispose(); $sha.Dispose() }
}
function Assert-GateBackupBarrier {
    if ($global:PraGateAd.ContainsKey('RequireProductReadbacks') -and $global:PraGateAd.RequireProductReadbacks) {
        if ($global:PraGate.Counters.Readbacks -lt 1 -or @($global:PraGateAd.ExpectedGuids | Where-Object { $_ -notin $global:PraGate.Counters.ReadbackIds }).Count) { throw 'GATE: product has not reread all target backups before mutation.' }
        Write-GateEvent 'ProductReadbackBeforeMutation' '*' $global:PraGateAd.Server @{Readbacks=$global:PraGate.Counters.Readbacks;AllTargets=$global:PraGate.Counters.ReadbackIds}
    }
    $files = @(Get-ChildItem -LiteralPath $global:PraGateAd.BackupFolder -Recurse -File -Filter '*.json' | Where-Object Name -Match '^(Convert|Recover|Finalize)-')
    if (-not $files.Count) { throw 'GATE: mutation before backup.' }
    $verified = $false
    foreach ($file in $files) {
        $json = [IO.File]::ReadAllText($file.FullName) | ConvertFrom-Json -DateKind String
        if ($json.SchemaVersion -ne 3 -or $json.RawFormat -cne 'PraDataOnlyClixml-v1' -or $json.Operation -notin @('Convert','Recover','Finalize')) { continue }
        $ids = @($json.Records | ForEach-Object { [string]$_.ObjectGuid })
        if (@($global:PraGateAd.ExpectedGuids | Where-Object { $_ -notin $ids }).Count) { continue }
        if ([IO.File]::ReadAllText($file.FullName+'.sha256').Trim() -cne (Get-GateSha $file.FullName)) { throw 'GATE: JSON hash invalid.' }
        $rawPath=Join-Path $file.DirectoryName $json.RawFile
        if ($json.RawHash -cne (Get-GateSha $rawPath)) { throw 'GATE: CLIXML hash invalid.' }
        # Test-only memoization avoids charging repeated fixture decoding to the product's memory probe.
        # Every mutation still independently streams both hashes; the first mutation fully validates all targets.
        if ($script:GateBackupChecks.ContainsKey($file.FullName)) {
            $cached=$script:GateBackupChecks[$file.FullName]
            if ($cached.JsonHash -cne (Get-GateSha $file.FullName) -or $cached.RawHash -cne $json.RawHash) { throw 'GATE: previously validated fixture changed.' }
            $verified=$true; $detail=$cached.Detail.Clone(); $detail.ValidationReused=$true
            Write-GateEvent 'BackupBarrier' '*' $global:PraGateAd.Server $detail
            continue
        }
        $codec=Get-Module PRA.Backup -All | Select-Object -First 1
        if ($null -eq $codec) { throw 'GATE: real streaming codec module missing.' }
        $checked=& $codec { param($p,$r,$f) Test-PraRawCapture -Context @{LogFile='';VerboseEnabled=$false} -LiteralPath $p -Records $r -RawFormat $f } $rawPath @($json.Records) $json.RawFormat
        if ($checked.Count -ne $global:PraGateAd.ExpectedGuids.Count -or $checked.Bytes -ne (Get-Item -LiteralPath $rawPath).Length -or $checked.Format -cne 'PraDataOnlyClixml-v1') { throw 'GATE: streaming capture count/bytes/format inconsistent.' }
        # Only this explicitly bounded gate fixture is imported, never a native user graph.
        if ($checked.Count -gt 13 -or $checked.Bytes -gt 8MB) { throw 'GATE: bounded fixture exceeded.' }
        $raw=@(Import-Clixml -LiteralPath $rawPath)
        if ($raw.Count -ne $global:PraGateAd.ExpectedGuids.Count) { throw 'GATE: not all targets in CLIXML.' }
        foreach ($id in $global:PraGateAd.ExpectedGuids) {
            $record=@($json.Records | Where-Object ObjectGuid -eq $id)
            $original=@($global:PraGateAd.Originals | Where-Object ObjectGUID -eq $id)
            $rawUser=@($raw | Where-Object ObjectGUID -eq $id)
            if ($record.Count -ne 1 -or $rawUser.Count -ne 1) { throw 'GATE: target not captured exactly once.' }
            if ($json.Operation -eq 'Convert') {
                if ($record[0].Attributes.extensionAttribute1.Value -cne $original[0].extensionAttribute1) { throw 'GATE: original retention tag lost.' }
                if ($record[0].Attributes.msExchMailboxGuid.Value -cne [Convert]::ToBase64String([byte[]]$original[0].msExchMailboxGuid)) { throw 'GATE: original mailbox GUID lost.' }
                if ($record[0].Attributes.mDBUseDefaults.Present -ne $true -or $record[0].Attributes.mDBUseDefaults.Value -isnot [bool] -or $record[0].Attributes.mDBUseDefaults.Value -ne $false) { throw 'GATE: original false Bool lost.' }
                if ($record[0].Attributes.homeMDB.Value -cne $original[0].homeMDB) { throw 'GATE: original AD attributes lost.' }
                if ($rawUser[0].Attributes['extensionAttribute1'][0].Value -cne $original[0].extensionAttribute1 -or $rawUser[0].Attributes['homeMDB'][0].Value -cne $original[0].homeMDB -or $rawUser[0].Attributes['mDBUseDefaults'][0].Value -cne 'false') { throw 'GATE: original CLIXML attributes lost.' }
                if ($rawUser[0].Attributes['msExchMailboxGuid'][0].Value -cne [Convert]::ToBase64String([byte[]]$original[0].msExchMailboxGuid)) { throw 'GATE: original CLIXML mailbox GUID lost.' }
            }
        }
        $verified=$true
        $detail=@{AllTargets=$ids;JsonRead=$true;CliXmlRead=$true;ShaRead=$true;Path=$file.FullName;ValidatorModule=$codec.Path;ValidatedCount=$checked.Count;ValidatedBytes=$checked.Bytes;RawFormat=$checked.Format;ValidatedGuids=$checked.ObjectGuids;ValidationReused=$false}
        $script:GateBackupChecks[$file.FullName]=@{JsonHash=(Get-GateSha $file.FullName);RawHash=$json.RawHash;Detail=$detail}
        Write-GateEvent 'BackupBarrier' '*' $global:PraGateAd.Server $detail
    }
    if (-not $verified) { throw 'GATE: no complete validated backup before mutation.' }
}
if (-not ('GateSynthetic.ADServerDownException' -as [type])) { Add-Type -TypeDefinition 'namespace GateSynthetic { public class ADServerDownException : System.Exception { public ADServerDownException(string message) : base(message) { } } }' }
function Get-ADDomainController {
    [CmdletBinding()]
    param([switch]$Discover,[switch]$Writable,[string]$Identity,[string]$Server)
    if (-not $Discover) { Assert-GateServer $Server }
    # The domain controller does not answer (the text is in another language than English: the type tells).
    if ($global:PraGateAd.Case -eq 'AdServerDown' -and -not $Discover) { throw [GateSynthetic.ADServerDownException]::new('Impossible de contacter le serveur. Cela peut etre parce que ce serveur n''existe pas.') }
    Write-GateEvent 'Get-ADDomainController' $Identity $Server @{Discover=[bool]$Discover; HostNameType='System.String'}
    [pscustomobject]@{ HostName=[string]$global:PraGateAd.Server; IsReadOnly=$false }
}
function Get-ADRootDSE {
    [CmdletBinding()]
    param([string]$Server)
    Assert-GateServer $Server
    Write-GateEvent 'Get-ADRootDSE' '' $Server
    [pscustomobject]@{ defaultNamingContext='DC=gate,DC=invalid' }
}
function Get-ADUser {
    [CmdletBinding()]
    param([object]$Identity,[string]$LDAPFilter,[string[]]$Properties,[string]$Server,[string]$SearchBase)
    Assert-GateServer $Server
    Write-GateEvent 'Get-ADUser' $Identity $Server @{LDAPFilter=$LDAPFilter; Properties=$Properties; SearchBase=$SearchBase}
    if ($global:PraGateAd.Case -eq 'MissingUser') { return }
    if ($global:PraGateAd.Case -eq 'AmbiguousUser') { foreach ($user in $global:PraGateAd.Users) { Copy-GateUser $user -Capture:('*' -in $Properties) }; return }
    if ($global:PraGateAd.ContainsKey('TrusteeUsers') -and $Identity) {
        foreach ($trustee in $global:PraGateAd.TrusteeUsers) {
            if ([string]$Identity -in @($trustee.DistinguishedName,$trustee.SamAccountName)) {
                if ($global:PraGateAd.ContainsKey('FailTrustee') -and $global:PraGateAd.FailTrustee -eq $trustee.SamAccountName) { throw 'SYNTHETIC: partial group trustee unavailable.' }
                Copy-GateUser $trustee; return
            }
        }
    }
    foreach ($user in $global:PraGateAd.Users) {
        $match=$false
        if ($Identity) { $match=([string]$Identity -in @([string]$user.ObjectGUID,$user.SamAccountName,$user.DistinguishedName)) }
        elseif ($LDAPFilter -like '(userPrincipalName=*') {
            $encoded=$user.UserPrincipalName.Replace('\','\5c').Replace('*','\2a').Replace('(','\28').Replace(')','\29').Replace([string][char]0,'\00')
            $match=$LDAPFilter -ieq ('(userPrincipalName='+$encoded+')')
        } else { $match=[bool]$user.homeMDB }
        if ($match) { Copy-GateUser $user -Capture:('*' -in $Properties) }
    }
}
function Get-ADGroup {
    [CmdletBinding()]
    param([object]$Identity,[string[]]$Properties,[string]$Server,[string]$LDAPFilter)
    Assert-GateServer $Server
    Write-GateEvent 'Get-ADGroup' $Identity $Server
    if ($global:PraGateAd.Case -eq 'GroupFailure') { throw 'SYNTHETIC: group preflight refused.' }
    Copy-GateUser $global:PraGateAd.Group
}
function Get-ADGroupMember {
    [CmdletBinding()]
    param([object]$Identity,[switch]$Recursive,[string]$Server)
    Assert-GateServer $Server
    Write-GateEvent 'Get-ADGroupMember' $Identity $Server
    if ($global:PraGateAd.ContainsKey('PermissionGroups') -and @($global:PraGateAd.PermissionGroups | Where-Object DistinguishedName -eq ([string]$Identity)).Count) {
        foreach ($user in $global:PraGateAd.TrusteeUsers) { [pscustomobject]@{objectClass='user';DistinguishedName=$user.DistinguishedName;SamAccountName=$user.SamAccountName} }
        # Duplicate members from recursive group expansion must not duplicate returned grants.
        foreach ($user in @($global:PraGateAd.TrusteeUsers[0],$global:PraGateAd.TrusteeUsers[-1])) { [pscustomobject]@{objectClass='user';DistinguishedName=$user.DistinguishedName;SamAccountName=$user.SamAccountName} }
        if ($global:PraGateAd.ContainsKey('FailGroupEnumeration') -and $global:PraGateAd.FailGroupEnumeration) { throw 'SYNTHETIC: group enumeration failed after partial output.' }
        return
    }
    foreach ($user in $global:PraGateAd.Users) { Copy-GateUser $user }
}
function Get-ADObject {
    [CmdletBinding()]
    param([object]$Identity,[string]$Filter,[string[]]$Properties,[string]$Server)
    Assert-GateServer $Server
    Write-GateEvent 'Get-ADObject' $Identity $Server @{Filter=$Filter;Properties=$Properties}
    if ($global:PraGateAd.ContainsKey('PermissionGroups')) {
        foreach ($object in @($global:PraGateAd.PermissionGroups)+@($global:PraGateAd.TrusteeUsers)) {
            if (($Identity -and [string]$Identity -eq $object.DistinguishedName) -or ($Filter -and $Filter -eq "objectSid -eq '$($object.objectSid)'")) { Copy-GateUser $object; return }
        }
        if ($Filter -and $global:PraGateAd.ContainsKey('OrphanSid') -and $Filter -eq "objectSid -eq '$($global:PraGateAd.OrphanSid)'") { return }
        if ($Filter) { throw 'SYNTHETIC: trustee outside fixed fixture.' }
    }
    [pscustomobject]@{ DistinguishedName=[string]$Identity; objectClass='organizationalUnit' }
}
function Get-ADOrganizationalUnit {
    [CmdletBinding()]
    param([string]$Filter,[string]$Server,[string]$SearchBase,[string]$SearchScope)
    Assert-GateServer $Server
    Write-GateEvent 'Get-ADOrganizationalUnit' '*' $Server @{SearchBase=$SearchBase;SearchScope=$SearchScope}
    if ($SearchBase -cne 'DC=gate,DC=invalid' -or $SearchScope -cne 'Subtree') { throw 'Synthetic OU search scope mismatch.' }
    @([pscustomobject]@{Name='Users';DistinguishedName='OU=Users,DC=gate,DC=invalid'},[pscustomobject]@{Name='Shared';DistinguishedName='OU=Shared,DC=gate,DC=invalid'})
}
function Set-ADUser {
    [CmdletBinding(SupportsShouldProcess)]
    param([object]$Identity,[hashtable]$Replace,[string[]]$Clear,[string]$Server)
    Assert-GateServer $Server
    Assert-GateBackupBarrier
    # A refusal of the domain controller, in another language than English: the engine must still tell it from any other error.
    if ($global:PraGateAd.Case -eq 'AccessDenied') { throw [UnauthorizedAccessException]::new('Droits d''acces insuffisants pour executer l''operation.') }
    Write-GateEvent 'Set-ADUser' $Identity $Server @{Replace=$Replace;Clear=$Clear}
    $user=@($global:PraGateAd.Users | Where-Object ObjectGUID -eq ([string]$Identity))[0]
    if ($null -ne $Replace) { foreach ($key in $Replace.Keys) { $user.$key=$Replace[$key] } }
    foreach ($key in $Clear) { $user.$key=$null }
    $user.uSNChanged=[long]$user.uSNChanged+1
}
function Add-ADGroupMember {
    [CmdletBinding(SupportsShouldProcess)]
    param([object]$Identity,[object[]]$Members,[string]$Server)
    Assert-GateServer $Server
    Assert-GateBackupBarrier
    Write-GateEvent 'Add-ADGroupMember' ([string]$Members[0]) $Server
    if ($global:PraGateAd.Case -eq 'SecondMutationFailure') { throw 'SYNTHETIC: second mutation fails after Set-ADUser.' }
    foreach ($id in $Members) {
        $user=@($global:PraGateAd.Users | Where-Object ObjectGUID -eq ([string]$id))[0]
        $global:PraGateAd.Group.member=@($global:PraGateAd.Group.member)+$user.DistinguishedName
        if ($global:PraGateAd.Case -eq 'SecondPostVerifyFailure' -and $user.SamAccountName -eq 'user2') {
            # Synthetic concurrent edit AFTER the successful group write, before final readback.
            $user.targetAddress='SMTP:postverify-divergence@gate.invalid'
            Write-GateEvent 'SyntheticPostVerifyDivergence' $id $Server $user.targetAddress
        }
    }
}
function Remove-ADGroupMember {
    [CmdletBinding(SupportsShouldProcess)]
    param([object]$Identity,[object[]]$Members,[string]$Server)
    Assert-GateServer $Server
    Assert-GateBackupBarrier
    Write-GateEvent 'Remove-ADGroupMember' ([string]$Members[0]) $Server
    if ($global:PraGateAd.Case -eq 'SecondRemovalFailure') { throw 'SYNTHETIC: second removal mutation fails after Set-ADUser.' }
    foreach ($id in $Members) {
        $user=@($global:PraGateAd.Users | Where-Object ObjectGUID -eq ([string]$id))[0]
        $global:PraGateAd.Group.member=@($global:PraGateAd.Group.member | Where-Object { $_ -cne $user.DistinguishedName })
    }
}
Write-GateEvent 'Import-SyntheticAD' '' '' $PSCommandPath
Export-ModuleMember -Function Get-ADDomainController,Get-ADRootDSE,Get-ADUser,Get-ADGroup,Get-ADGroupMember,Get-ADObject,Get-ADOrganizationalUnit,Set-ADUser,Add-ADGroupMember,Remove-ADGroupMember
'@
    $global:PraGate.CloudSource = @'
# SYNTHETIC orchestration barrier, NOT the production Cloud implementation.
if ($env:PRA_GATE_NONET -cne 'SYNTHETIC-NO-NETWORK') { throw 'Synthetic interlock absent.' }
function Initialize-PraCloudPreflight {
    [CmdletBinding()]
    param([hashtable]$Context,[object[]]$Rows)
    $state=[Management.Automation.PSSerializer]::Deserialize([IO.File]::ReadAllText($env:PRA_GATE_STATE))
    # Readonly fixture: enforce real Row contracts and prove preflight precedes every AD mutation.
    if (@($Rows).Count -ne $state.ExpectedGuids.Count) { throw 'SYNTHETIC: preflight did not receive actual target rows.' }
    foreach ($row in $Rows) {
        if (-not $row.UserPrincipalName -or $row.ObjectGuid -notin $state.ExpectedGuids -or $row.ADVerified) { throw 'SYNTHETIC: invalid pre-AD row.' }
    }
    $event=@{Operation='CloudPreflight-SyntheticBarrier';Synthetic=$true;Rows=@($Rows | Select-Object ObjectGuid,UserPrincipalName,ADVerified);Config=@{UserPrincipalName=$Context.Config.Cloud.UserPrincipalName;DisableWAM=$Context.Config.Exo.DisableWAM;GrantVerifyAttempts=$Context.Config.Exo.GrantVerifyAttempts;GrantVerifyDelaySeconds=$Context.Config.Exo.GrantVerifyDelaySeconds}}
    [IO.File]::AppendAllText($state.EventPath,(($event | ConvertTo-Json -Depth 8 -Compress)+"`r`n"))
    $Context['_GatePreflightAttempted']=$true
    if ($state.Case -eq 'CloudPreflightFailure') { throw 'SYNTHETIC: cloud preflight refused before AD.' }
}
function Invoke-PraCloudPhase {
    [CmdletBinding()]
    param([hashtable]$Context,[object[]]$Rows,[string]$Act)
    $state=[Management.Automation.PSSerializer]::Deserialize([IO.File]::ReadAllText($env:PRA_GATE_STATE))
    [IO.File]::AppendAllText($state.EventPath,('{"Operation":"CloudPhase-SyntheticBarrier","Synthetic":true}'+"`r`n"))
    $seen=@(foreach ($row in $Rows) { [ordered]@{ Upn=[string]$row.UserPrincipalName; ExpectedX500=@(Get-PraList $row.BackupRec 'ExpectedX500'); Note=[string](Get-PraValue $row.BackupRec 'ExpectedX500Note' '') } })
    [IO.File]::AppendAllText($state.EventPath,((@{Operation='CloudRows-SyntheticBarrier';Synthetic=$true;Rows=$seen} | ConvertTo-Json -Depth 8 -Compress)+"`r`n"))
    if ($state.Case -eq 'CloudX500Missing') {
        # What the real cloud phase does for an object whose X500 address is not in Exchange Online: a warning item, the object listed for the Next steps, the conversion done.
        foreach ($row in $Rows) { $row.CloudStatus='Success'; $row.CloudMailbox=$true; $row.CloudLicense=$true; $row.FinalStatus='Success'; $row.CloudDetail='SYNTHETIC: mailbox ready.' }
        $Context.CurrentIdentity=[string]$Rows[0].ObjectGuid
        Write-PraItem -Context $Context -Status Warn -Text ($Rows[0].UserPrincipalName+': X500 missing in Exchange Online: X500:/o=Synthetic/cn=old. Replies to old messages and meeting updates to this mailbox can bounce (IMCEAEX NDR).')
        $Context['X500Missing']=New-Object 'Collections.Generic.List[string]'; [void]$Context['X500Missing'].Add([string]$Rows[0].UserPrincipalName)
    } elseif ($state.Case -eq 'CloudConcurrentChange') {
        # Model a third-party edit during polling, not a cmdlet call by the product.
        $global:PraGateAd.Users[0].homeMDB='CN=ThirdParty,DC=gate,DC=invalid'
        $global:PraGateAd.Users[0].uSNChanged=[long]$global:PraGateAd.Users[0].uSNChanged+1
        [IO.File]::AppendAllText($state.EventPath,('{"Operation":"SyntheticConcurrentEdit","Synthetic":true}'+"`r`n"))
        foreach ($row in $Rows) { $row.CloudStatus='Success'; $row.CloudMailbox=$true; $row.CloudLicense=$true; $row.DeprovisionConfirmed=$true; $row.FinalStatus='Success'; $row.CloudDetail='SYNTHETIC cloud confirmation followed by concurrent AD edit.' }
    } elseif ($state.Case -eq 'CloudConfirmed13') {
        foreach ($row in $Rows) { $row.CloudStatus='Success'; $row.CloudMailbox=$false; $row.CloudLicense=$false; $row.DeprovisionConfirmed=$true; $row.FinalStatus='Success'; $row.CloudDetail='SYNTHETIC: explicitly confirmed absent shared mailbox, no connection.' }
    } elseif ($state.Case -eq 'CloudNetworkFailure') {
        # What the real cloud phase does when Microsoft 365 does not answer: a run error on each row, in plain words.
        $Context.NetworkFailure=$true; $Context.CurrentPhase='Cloud'; $Context.CurrentOperation='CloudCheck'
        foreach ($row in $Rows) {
            $row.CloudStatus='Error'; $row.FinalStatus='Error'; $row.CloudDetail='SYNTHETIC: connection attempt failed (graph.example.invalid:443)'
            Add-Member -InputObject $row -NotePropertyName RunError -NotePropertyValue $true -Force
            $Context.CurrentIdentity=[string]$row.ObjectGuid
            $text=[string]$row.UserPrincipalName+': Microsoft 365 did not answer (network): graph.example.invalid:443. Run again.'
            [void]$Context.Issues.Add([pscustomobject]@{ Timestamp=(Get-Date).ToString('o'); Phase='Cloud'; Source='Cloud'; Operation='CloudCheck'; Identity=[string]$row.ObjectGuid; Message=$text })
            Write-PraItem -Context $Context -Status Fail -Text $text
        }
    } elseif ($state.Case -eq 'CloudConnectFailure') {
        # What the real cloud phase does when it cannot sign in: the same error on each row, and the sign-in as the operation that stopped.
        $Context.NetworkFailure=$true; $Context.CloudConnectFailed=$true; $Context.CurrentPhase='Cloud'; $Context.CurrentOperation='Connect-MgGraph'
        foreach ($row in $Rows) {
            $row.CloudStatus='Error'; $row.FinalStatus='Error'; $row.CloudDetail='SYNTHETIC: connection attempt failed (graph.example.invalid:443)'
            Add-Member -InputObject $row -NotePropertyName RunError -NotePropertyValue $true -Force
            $Context.CurrentIdentity=[string]$row.ObjectGuid
            $text=[string]$row.UserPrincipalName+': Microsoft 365 did not answer (network): graph.example.invalid:443. Run again.'
            [void]$Context.Issues.Add([pscustomobject]@{ Timestamp=(Get-Date).ToString('o'); Phase='Cloud'; Source='Cloud'; Operation='Connect-MgGraph'; Identity=[string]$row.ObjectGuid; Message=$text })
            Write-PraItem -Context $Context -Status Fail -Text $text
        }
    } elseif ($state.Case -eq 'CloudWaitTimeout') {
        # What the real cloud phase does when the objects are still not in the expected state after the wait: a cloud error on each row (not a run error) and their number.
        $Context.CurrentPhase='Cloud'; $Context.CurrentOperation='CloudCheck'; $Context.CloudNotReached=0
        foreach ($row in $Rows) {
            $row.CloudStatus='Error'; $row.FinalStatus='Error'; $row.CloudDetail='SYNTHETIC: expected state not reached.'
            $Context.CloudNotReached=[int]$Context.CloudNotReached+1
            $Context.CurrentIdentity=[string]$row.ObjectGuid
            $text=[string]$row.UserPrincipalName+': still not in the expected state after waiting 3 min: no mailbox in Exchange Online yet.'
            [void]$Context.Issues.Add([pscustomobject]@{ Timestamp=(Get-Date).ToString('o'); Phase='Cloud'; Source='Cloud'; Operation='CloudCheck'; Identity=[string]$row.ObjectGuid; Message=$text })
            Write-PraItem -Context $Context -Status Fail -Text $text
        }
    } elseif ($state.Case -eq 'CloudOtherFailure') {
        # A cloud failure that is not a network failure: an error on each row.
        $Context.CurrentPhase='Cloud'; $Context.CurrentOperation='CloudCheck'
        foreach ($row in $Rows) {
            $row.CloudStatus='Error'; $row.FinalStatus='Error'; $row.CloudDetail='SYNTHETIC: the answer is not valid.'
            Add-Member -InputObject $row -NotePropertyName RunError -NotePropertyValue $true -Force
            $Context.CurrentIdentity=[string]$row.ObjectGuid
            $text=[string]$row.UserPrincipalName+': SYNTHETIC: the answer is not valid.'
            [void]$Context.Issues.Add([pscustomobject]@{ Timestamp=(Get-Date).ToString('o'); Phase='Cloud'; Source='Cloud'; Operation='CloudCheck'; Identity=[string]$row.ObjectGuid; Message=$text })
            Write-PraItem -Context $Context -Status Fail -Text $text
        }
    } elseif ($state.Case -eq 'CloudFirstFails') {
        # The check of the first object fails, the others are read afterwards: the loop ends on the last object.
        $Context.CurrentPhase='Cloud'
        $failed=$false
        foreach ($row in $Rows) {
            if (-not $failed) {
                $failed=$true
                $row.CloudStatus='Error'; $row.FinalStatus='Error'; $row.CloudDetail='SYNTHETIC: the session check failed.'
                $text=[string]$row.UserPrincipalName+': Exchange Online session: connection state ''Disconnected'', expected Connected.'
                [void]$Context.Issues.Add([pscustomobject]@{ Timestamp=(Get-Date).ToString('o'); Phase='Cloud'; Source='Cloud'; Operation='CloudCheck'; Identity=[string]$row.ObjectGuid; Message=$text })
                Write-PraItem -Context $Context -Status Fail -Text $text
            } else { $row.CloudStatus='Planned'; $row.FinalStatus='Planned'; $row.CloudDetail='SYNTHETIC: ready.' }
            $Context.CurrentIdentity=[string]$row.ObjectGuid; $Context.CurrentOperation='X500Check'
        }
    } elseif ($state.Case -eq 'CloudNotYet' -and -not $Context.AllowMutation -and $Context.Action -in @('Convert','Recover')) {
        foreach ($row in $Rows) { $row.CloudStatus='Pending'; $row.FinalStatus='Planned'; $row.CloudDetail='SYNTHETIC: not yet in the expected state.'; $Context.NotYetExpected=[int](Get-PraValue $Context 'NotYetExpected' 0)+1 }
    } elseif ($state.Case -eq 'CheckNotExpected' -and $Context.Action -eq 'Check') {
        foreach ($row in $Rows) {
            $row.CloudStatus='Error'; $row.FinalStatus='Error'; $row.CloudDetail='SYNTHETIC: MBX:EXO type='
            [void]$Context.Issues.Add([pscustomobject]@{ Timestamp=(Get-Date).ToString('o'); Phase='Cloud'; Source='Cloud'; Operation='CloudCheck'; Identity=[string]$row.UserPrincipalName; Message=([string]$row.UserPrincipalName+': not in the expected state: no mailbox in Exchange Online yet (SYNTHETIC).') })
        }
    } elseif ($Context.Action -eq 'Check') {
        foreach ($row in $Rows) { $row.CloudStatus='Success'; $row.CloudMailbox=$true; $row.CloudLicense=$true; $row.FinalStatus='Success'; $row.CloudDetail='SYNTHETIC: read-only check satisfied.' }
    } elseif (-not $Context.AllowMutation -and $Context.Action -in @('Convert','Recover')) {
        foreach ($row in $Rows) { $row.CloudStatus='Planned'; $row.FinalStatus='Planned'; $row.CloudDetail='SYNTHETIC: preview, no cloud connection performed.' }
    } else {
        foreach ($row in $Rows) { $row.CloudStatus='Pending'; $row.FinalStatus='Pending'; $row.CloudDetail='SYNTHETIC: no cloud connection performed.' }
    }
}
function Invoke-PraRetentionCheck { [CmdletBinding()]param([hashtable]$Context,[object[]]$Rows) Invoke-PraCloudPhase -Context $Context -Rows $Rows -Act 'ReadOnly' }
function Close-PraCloudSession {
    [CmdletBinding()]param([hashtable]$Context)
    if ($Context.ContainsKey('_GatePreflightAttempted')) {
        $state=[Management.Automation.PSSerializer]::Deserialize([IO.File]::ReadAllText($env:PRA_GATE_STATE))
        [IO.File]::AppendAllText($state.EventPath,('{"Operation":"CloudClose-SyntheticBarrier","Synthetic":true}'+"`r`n"))
        [void]$Context.Remove('_GatePreflightAttempted')
    }
}
Export-ModuleMember -Function Initialize-PraCloudPreflight,Invoke-PraCloudPhase,Invoke-PraRetentionCheck,Close-PraCloudSession
'@
    $global:PraGate.SyncSource = @'
if ($env:PRA_GATE_NONET -cne 'SYNTHETIC-NO-NETWORK') { throw 'Synthetic interlock absent.' }
function Get-ADSyncScheduler { [CmdletBinding()]param() throw 'SYNTHETIC BLOCK: ADSync scheduler.' }
function Start-ADSyncSyncCycle {
    [CmdletBinding()]param([string]$PolicyType)
    $state=[Management.Automation.PSSerializer]::Deserialize([IO.File]::ReadAllText($env:PRA_GATE_STATE))
    [IO.File]::AppendAllText($state.EventPath,('{"Operation":"Start-ADSyncSyncCycle","Synthetic":true}'+"`r`n"))
    throw 'SYNTHETIC BLOCK: ADSync cannot run.'
}
Export-ModuleMember -Function Get-ADSyncScheduler,Start-ADSyncSyncCycle
'@
    function global:New-GateUser {
        param([int]$Index=1)
        [pscustomobject][ordered]@{
            ObjectGUID=[guid]('00000000-0000-0000-0000-{0:000000000000}' -f $Index)
            DistinguishedName="CN=User$Index,OU=Tests,DC=gate,DC=invalid"; SamAccountName="user$Index"
            UserPrincipalName="user$Index@gate.invalid"; DisplayName="Synthetic User $Index"; Name="User$Index"; objectClass='user'
            mail="user$Index@gate.invalid"; mailNickname="user$Index"; legacyExchangeDN="/o=Synthetic/ou=Gate/cn=Recipients/cn=user$Index"; uSNChanged=[long]100; memberOf=@(); publicDelegates=@()
            nTSecurityDescriptor=$null; msExchMailboxSecurityDescriptor=$null; msExchArchiveGUID=$null
            homeMDB="CN=Database$Index,CN=Databases,DC=gate,DC=invalid"; homeMTA='CN=OriginalMTA,DC=gate,DC=invalid'
            msExchHomeServerName='/o=Synthetic/ou=Gate/cn=Servers/cn=Original'; msExchMailboxGuid=[byte[]](0,1,2,127,128,254,255,$Index)
            mDBUseDefaults=$false; msExchRecipientDisplayType=0; msExchRecipientTypeDetails=[long]1; msExchRemoteRecipientType=$null
            targetAddress=$null; proxyAddresses=[string[]]@("SMTP:user$Index@gate.invalid","smtp:alias$Index@gate.invalid",'X500:/o=Synthetic/ou=Gate/cn=User')
            extensionAttribute1="OriginalTag-$Index"
        }
    }
    function global:New-GateRuntime {
        param([string]$Name='case',[string]$Case='Normal',[switch]$Preexisting,[switch]$Shared13,[ValidateRange(3,500)][int]$TrusteeCount=8,[ValidateRange(100,120)][int]$AclCount=100)
        $caseName=$Name
        $root=Join-Path $global:PraGate.Root ([guid]::NewGuid().ToString('N').Substring(0,6))
        $modules=Join-Path $root 'modules'; $package=Join-Path $root 'package'
        foreach ($path in @($root,$modules,$package,(Join-Path $package 'module'),(Join-Path $package 'templates'),(Join-Path $root 'backups'),(Join-Path $root 'logs'),(Join-Path $root 'reports'))) { $null=New-Item -ItemType Directory -Path $path -Force }
        foreach ($name in @('ActiveDirectory','ADSync')) { $null=New-Item -ItemType Directory -Path (Join-Path $modules $name) -Force }
        foreach ($pair in @(@('Microsoft.Graph.Authentication','2.41.1'),@('Microsoft.Graph.Users','2.41.1'),@('ExchangeOnlineManagement','3.10.1'))) {
            $moduleFolder=Join-Path $modules $pair[0]; $null=New-Item -ItemType Directory -Path $moduleFolder -Force
            [IO.File]::WriteAllText((Join-Path $moduleFolder ($pair[0]+'.psd1')),"@{ ModuleVersion='$($pair[1])'; GUID='$([guid]::NewGuid())'; Author='SYNTHETIC'; Description='Synthetic fixture: a module version for the detection, never loaded.' }",(New-Object Text.UTF8Encoding($true)))
        }
        [IO.File]::WriteAllText((Join-Path $modules 'ActiveDirectory\ActiveDirectory.psm1'),$global:PraGate.AdSource,(New-Object Text.UTF8Encoding($true)))
        [IO.File]::WriteAllText((Join-Path $modules 'ADSync\ADSync.psm1'),$global:PraGate.SyncSource,(New-Object Text.UTF8Encoding($true)))
        Copy-Item -Path (Join-Path $global:PraGate.Package '*') -Destination $package -Recurse -Force
        [IO.File]::WriteAllText((Join-Path $package 'module\PRA.Cloud.psm1'),$global:PraGate.CloudSource,(New-Object Text.UTF8Encoding($true)))
        Set-PraFixtureHash -Root $package -Relative 'module\PRA.Cloud.psm1'
        $users=@((New-GateUser 1),(New-GateUser 2))
        if ($Shared13) {
            $users=@(1..13 | ForEach-Object { New-GateUser $_ })
            foreach ($user in $users) {
                $user.msExchRecipientTypeDetails=[long]4
                $user.publicDelegates=@('CN=Permission1,OU=Tests,DC=gate,DC=invalid','CN=Permission1,OU=Tests,DC=gate,DC=invalid','CN=Permission2,OU=Tests,DC=gate,DC=invalid','CN=Trustee1,OU=Tests,DC=gate,DC=invalid','CN=Permission3,OU=Tests,DC=gate,DC=invalid')
            }
        }
        if ($Case -eq 'MissingUpn') { $users[0].UserPrincipalName='' }
        if ($Case -eq 'AlreadyConverted') { $users[0].homeMDB=$null; $users[0].msExchRecipientTypeDetails=[long]2147483648 }
        $group=[pscustomobject]@{ ObjectGUID=[guid]'10000000-0000-0000-0000-000000000001'; DistinguishedName='CN=License,OU=Tests,DC=gate,DC=invalid'; objectClass='group'; member=@() }
        if ($Preexisting) { $group.member=@($users | ForEach-Object DistinguishedName) }
        $state=@{ Case=$Case; Users=$users; Originals=([Management.Automation.PSSerializer]::Deserialize([Management.Automation.PSSerializer]::Serialize($users,30))); Group=$group; Server='dc01.gate.invalid'; BackupFolder=(Join-Path $root 'backups'); ExpectedGuids=@($users | ForEach-Object { [string]$_.ObjectGUID }); EventPath=(Join-Path $root 'events.jsonl') }
        if ($Shared13) {
            $state.NativeShared=$true; $state.AclCount=$AclCount
            $state.PermissionGroups=@(1..3 | ForEach-Object { [pscustomobject]@{ObjectGUID=[guid]('20000000-0000-0000-0000-{0:000000000000}' -f $_);DistinguishedName="CN=Permission$_,OU=Tests,DC=gate,DC=invalid";SamAccountName="permission$_";objectClass='group';objectSid=('S-1-5-21-100-200-300-'+(2000+$_))} })
            $state.PermissionGroups+=@([pscustomobject]@{ObjectGUID=[guid]'20000000-0000-0000-0000-000000000004';DistinguishedName='CN=Organization Management,OU=Tests,DC=gate,DC=invalid';SamAccountName='Organization Management';Name='Organization Management';objectClass='group';objectSid='S-1-5-21-100-200-300-2004'})
            $state.TrusteeUsers=@(1..$TrusteeCount | ForEach-Object { [pscustomobject]@{DistinguishedName="CN=Trustee$_,OU=Tests,DC=gate,DC=invalid";SamAccountName="trustee$_";UserPrincipalName="trustee$_@gate.invalid";objectClass='user';objectSid=('S-1-5-21-100-200-300-'+(3000+$_))} })
        }
        $statePath=Join-Path $root 'state.clixml'
        [IO.File]::WriteAllText($statePath,[Management.Automation.PSSerializer]::Serialize($state,35))
        $config=@"
@{
 Environment='SYNTHETIC_GATE'; DomainController=''
 Scope=@{Mode='Auto';SearchBase='OU=Tests,DC=gate,DC=invalid';GroupDN='';CsvPath='';IncludeShared=`$false;IncludeRoom=`$false;IncludeEquip=`$false;ExcludeSamAccountNames=@()}
 Routing=@{AutoDetect=`$false;RoutingDomain='synthetic.mail.onmicrosoft.com'}
 Licensing=@{Enabled=`$true;GroupDN='CN=License,OU=Tests,DC=gate,DC=invalid'}
 SharedMailbox=@{Enabled=`$true;PermissionSource='None';CaptureSendOnBehalf=`$false}
 EntraConnect=@{Sync=`$false;Server='';PolicyType='Delta';TimeoutMinutes=1}
 Retention=@{Enabled=`$true;Tag=@{Enabled=`$true;Attribute='extensionAttribute1';Value='Converted'}}
 Execution=@{Phase='Both'}
 Storage=@{BackupFolder='$($state.BackupFolder)';ForbiddenBackupRoots=@()}
 Logging=@{Folder='$(Join-Path $root 'logs')'}
 Report=@{Enabled=`$true;Folder='$(Join-Path $root 'reports')'}
}
"@
        if ($Shared13) {
            $config=$config.Replace('IncludeShared=$false','IncludeShared=$true').Replace("PermissionSource='None';CaptureSendOnBehalf=`$false","PermissionSource='AD';CaptureSendOnBehalf=`$true;ExcludeTrusteeSamAccountNames=@('permission3','trustee$TrusteeCount')")
        }
        $configPath=Join-Path $root 'Gate.psd1'; [IO.File]::WriteAllText($configPath,$config)
        [pscustomobject]@{ Root=$root; CaseName=$caseName; Modules=$modules; Package=$package; StatePath=$statePath; State=$state; ConfigPath=$configPath; EventPath=$state.EventPath; OutputPath=(Join-Path $root 'stdout.txt'); ErrorPath=(Join-Path $root 'stderr.txt') }
    }
    function global:New-GateContext {
        param($Runtime,[string]$Mode='Apply',[string]$Action='Convert')
        $config=Import-PowerShellDataFile -LiteralPath $Runtime.ConfigPath
        $config.Remote=@{RecipientType=1;HandleArchives=$true;ClearMailboxGuid=$true}
        $config.SharedMailbox.RemoteRecipientType=97
        if (-not $config.SharedMailbox.ContainsKey('ExcludeTrusteeSamAccountNames')) { $config.SharedMailbox.ExcludeTrusteeSamAccountNames=@() }
        $config.EntraConnect=@{Sync=$false;Server='';PolicyType='Delta';TimeoutMinutes=1}
        @{
            Root=$Runtime.Package; RunId=[guid]::NewGuid().ToString('N'); Version='gate'; StartTime=Get-Date; Action=$Action; Mode=$Mode; Phase='AD'
            CurrentPhase='Test'; CurrentOperation=''; CurrentIdentity=''; StepIndex=0; Warnings=0; Config=$config
            Issues=(New-Object 'Collections.Generic.List[object]'); Rows=(New-Object 'Collections.Generic.List[object]')
            BackupFiles=(New-Object 'Collections.Generic.List[string]'); StateFiles=(New-Object 'Collections.Generic.List[string]')
            BackupFolder=$Runtime.State.BackupFolder; LogFolder=(Join-Path $Runtime.Root 'logs'); ReportFolder=(Join-Path $Runtime.Root 'reports')
            LogFile=''; TranscriptPath=''; TranscriptStarted=$false; NoReport=$false; Server=$Runtime.State.Server; NamingContext='DC=gate,DC=invalid'
            AllowMutation=($Mode -eq 'Apply' -and $Action -ne 'Check'); Approval={param($Target,$Operation) $true}
            SourceBackupHash=''; Source=$null; Proof=$null; JournalPath=''; ExitCode=0; ResultStatus=''; CloudConnectFailed=$false
        }
    }
    function global:Get-GateEvents {
        param($Runtime)
        if (Test-Path -LiteralPath $Runtime.EventPath) { foreach ($line in [IO.File]::ReadAllLines($Runtime.EventPath)) { if ($line) { $line | ConvertFrom-Json -DateKind String } } }
    }
    function global:Set-GateConfigText {
        param($Runtime,[Parameter(Mandatory)][scriptblock]$Transform)
        $text=[IO.File]::ReadAllText($Runtime.ConfigPath)
        $updated=& $Transform $text
        [IO.File]::WriteAllText($Runtime.ConfigPath,[string]$updated,(New-Object Text.UTF8Encoding($true)))
    }
    function global:Get-GateWrites {
        param($Runtime)
        @(Get-GateEvents $Runtime | Where-Object Operation -Match '^(Set-|Add-|Remove-|Start-ADSync)')
    }
    function global:Save-GateDeltaEvidence {
        param([string]$Name,[hashtable]$Context,$Runtime,[object[]]$HostRecords=@(),[object]$Detail=$null)
        if (-not $env:PRA_GATE_EVIDENCE) { return }
        $log=if ($Context.LogFile -and (Test-Path -LiteralPath $Context.LogFile)) { [IO.File]::ReadAllText($Context.LogFile) } else { '' }
        $record=[ordered]@{
            Synthetic=$true; Name=$Name; Runtime=$Runtime.Root; Mode=$Context.Mode; Warnings=$Context.Warnings
            Issues=@($Context.Issues.ToArray()); HostRecords=$HostRecords; Log=$log; Events=@(Get-GateEvents $Runtime); Detail=$Detail
        }
        $path=Join-Path $env:PRA_GATE_EVIDENCE ((Split-Path $Runtime.Root -Leaf)+'-'+$Name+'.delta.json')
        [IO.File]::WriteAllText($path,($record | ConvertTo-Json -Depth 25),(New-Object Text.UTF8Encoding($true)))
    }
    function global:Invoke-GateProcess {
        param($Runtime,[hashtable]$Arguments,[switch]$Desktop,[switch]$ExplicitArguments,[ValidateRange(10,240)][int]$TimeoutSeconds=60,[ValidateRange(256,512)][int]$MemoryLimitMB=512)
        $paramsPath=Join-Path $Runtime.Root ('args-'+[guid]::NewGuid().ToString('N')+'.clixml')
        [IO.File]::WriteAllText($paramsPath,[Management.Automation.PSSerializer]::Serialize($Arguments,10))
        $argumentText='@parameters'
        if ($ExplicitArguments) {
            # Only data literals are emitted, never caller-supplied PowerShell expressions.
            # Single quotes (including embedded CR/LF/NUL) preserve the exact UTF-16 value.
            $parts=@(foreach ($key in @($Arguments.Keys | Sort-Object)) {
                if ($key -cnotmatch '^[A-Za-z][A-Za-z0-9]*$') { throw 'Synthetic explicit argument name refused.' }
                $value=$Arguments[$key]
                if ($value -is [string]) {
                    $escaped=$value.Replace("'","''")
                    # Windows PowerShell also recognizes these smart single quotes.
                    foreach ($code in @(0x2018,0x2019,0x201A,0x201B)) {
                        $quote=[string][char]$code
                        $escaped=$escaped.Replace($quote,($quote+$quote))
                    }
                    '-'+$key+" '"+$escaped+"'"
                }
                elseif ($value -is [bool] -or $value -is [Management.Automation.SwitchParameter]) { '-'+$key+':$'+([bool]$value).ToString().ToLowerInvariant() }
                elseif ($value -is [int]) { '-'+$key+' '+$value.ToString([Globalization.CultureInfo]::InvariantCulture) }
                else { throw ('Synthetic explicit argument type refused: '+$key) }
            })
            $argumentText=$parts -join ' '
        }
        $command=@"
`$ErrorActionPreference='Stop'
[Console]::OutputEncoding=New-Object Text.UTF8Encoding(`$false)
foreach (`$name in @('Microsoft.PowerShell.Utility','Microsoft.PowerShell.Management','Microsoft.PowerShell.Security')) { Import-Module (Join-Path `$PSHOME ('Modules\'+`$name+'\'+`$name+'.psd1')) -ErrorAction Stop }
`$env:PRA_GATE_NONET='SYNTHETIC-NO-NETWORK'
`$env:PRA_GATE_STATE='$($Runtime.StatePath.Replace("'","''"))'
`$env:PSModulePath='$($Runtime.Modules.Replace("'","''"))'+';'+(Join-Path `$PSHOME 'Modules')
function global:Invoke-WebRequest { throw 'SYNTHETIC BLOCK: network' }
function global:Invoke-RestMethod { throw 'SYNTHETIC BLOCK: network' }
function global:New-PSSession { throw 'SYNTHETIC BLOCK: remoting' }
# Remoting is blocked unless the state file scripts it (RemoteSync: Ok, Denied, Unreachable, OkThenFail, RawFail, RawFailOther): then a fake job answers for EntraConnect.Server, nothing leaves the process.
function global:Invoke-Command { [CmdletBinding()] param([string]`$ComputerName,[scriptblock]`$ScriptBlock,[object[]]`$ArgumentList,`$SessionOption,[switch]`$AsJob)
    `$mode = if (`$global:PraGateAd.ContainsKey('RemoteSync')) { [string]`$global:PraGateAd.RemoteSync } else { 'Blocked' }
    if (`$mode -ceq 'Blocked') { throw 'SYNTHETIC BLOCK: remoting' }
    [pscustomobject]@{ State='Completed'; Mode=`$mode; IsCycle=`$ScriptBlock.ToString().Contains('Start-ADSyncSyncCycle'); Computer=`$ComputerName } }
function global:Wait-Job { [CmdletBinding()] param(`$Job,`$Timeout) `$Job }
function global:Stop-Job { [CmdletBinding()] param(`$Job) }
function global:Remove-Job { [CmdletBinding()] param(`$Job,[switch]`$Force) }
function global:Receive-Job { [CmdletBinding()] param(`$Job,[switch]`$Keep)
    if (`$Job.Mode -ceq 'RawFailOther' -and `$Job.IsCycle) { throw 'System.InvalidOperationException: The sync engine returned an unexpected result. at Microsoft.MetadirectoryServices.Scheduler.Scheduler.StartSyncCycle(String overridePolicy) at SchedulerUtils.StartSyncCycle(String policy)' }
    if (`$Job.Mode -ceq 'RawFail' -and `$Job.IsCycle) { throw 'System.InvalidOperationException: Scheduler is already suspended via global parameters. at Microsoft.MetadirectoryServices.Scheduler.Scheduler.StartSyncCycle(String overridePolicy, Boolean interactiveMode) at SchedulerUtils.StartSyncCycle(String policy)' }
    if (`$Job.Mode -ceq 'Denied' -or (`$Job.Mode -ceq 'OkThenFail' -and `$Job.IsCycle)) { throw ('Connecting to remote server ' + `$Job.Computer + ' failed with the following error message : Access is denied. For more information, see the about_Remote_Troubleshooting Help topic.') }
    if (`$Job.Mode -ceq 'Unreachable') { throw 'The WinRM client cannot process the request because the server name cannot be resolved.' }
    if (`$Job.IsCycle) { [pscustomobject]@{ Result='Success'; Seconds=1; Computer=`$Job.Computer } } else { [pscustomobject]@{ Computer=`$Job.Computer; CycleEnabled=`$true } } }
function global:Connect-ExchangeOnline { throw 'SYNTHETIC BLOCK: EXO' }
function global:Connect-MgGraph { throw 'SYNTHETIC BLOCK: Graph' }
Import-Module ActiveDirectory -Force -Global -ErrorAction Stop
if ((Get-Command Get-ADUser).Module.Path -notlike '$($Runtime.Modules.Replace("'","''"))*') { throw 'Non-synthetic AD module refused.' }
[IO.File]::WriteAllText('$(Join-Path $Runtime.Root 'child-runtime.json')',(@{Version=`$PSVersionTable.PSVersion.ToString();Edition=`$PSVersionTable.PSEdition;PSHOME=`$PSHOME;PSModulePath=`$env:PSModulePath;ADModule=(Get-Command Get-ADUser).Module.Path;Synthetic=`$true} | ConvertTo-Json),(New-Object Text.UTF8Encoding(`$true)))
`$parameters=[Management.Automation.PSSerializer]::Deserialize([IO.File]::ReadAllText('$($paramsPath.Replace("'","''"))'))
`$global:LASTEXITCODE=99
`$summary=@(& '$((Join-Path $Runtime.Package 'Invoke-PraRemoteMailbox.ps1').Replace("'","''"))' $argumentText -PassThru)
`$code=`$LASTEXITCODE
if (`$summary.Count -ne 1 -or `$null -eq `$summary[0].PSObject.Properties['ExitCode'] -or [int]`$summary[0].ExitCode -ne `$code) { throw 'Main did not return one coherent result and exit code.' }
[IO.File]::WriteAllText('$(Join-Path $Runtime.Root 'main-result.json')',(`$summary[0] | ConvertTo-Json -Depth 15),(New-Object Text.UTF8Encoding(`$true)))
`$summary[0]
exit `$code
"@
        $encoded=[Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($command))
        # PowerShell 7.5+ is the engine. -Desktop starts Windows PowerShell 5.1 only to prove that the engine refuses it.
        $exe=Join-Path $PSHOME 'pwsh.exe'
        if ($Desktop) { $exe=Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe' }
        $clock=[Diagnostics.Stopwatch]::StartNew()
        $start=New-Object Diagnostics.ProcessStartInfo
        $start.FileName=$exe; $start.Arguments='-NoLogo -NoProfile -NonInteractive -EncodedCommand '+$encoded
        $start.UseShellExecute=$false; $start.CreateNoWindow=$true; $start.RedirectStandardOutput=$true; $start.RedirectStandardError=$true
        $start.StandardOutputEncoding=New-Object Text.UTF8Encoding($false); $start.StandardErrorEncoding=New-Object Text.UTF8Encoding($false)
        $process=New-Object Diagnostics.Process; $process.StartInfo=$start
        $peakPrivate=0L; $peakWorkingSet=0L; $samples=0; $stopped=''
        try {
            if (-not $process.Start()) { throw 'Synthetic main process failed to start.' }
            $stdout=$process.StandardOutput.ReadToEndAsync(); $stderr=$process.StandardError.ReadToEndAsync()
            while (-not $process.WaitForExit(25)) {
                $process.Refresh(); $samples++; $peakPrivate=[Math]::Max($peakPrivate,$process.PrivateMemorySize64); $peakWorkingSet=[Math]::Max($peakWorkingSet,$process.PeakWorkingSet64)
                if ($peakPrivate -gt ($MemoryLimitMB*1MB)) { $stopped='PrivateMemory watchdog'; break }
                if ($clock.Elapsed.TotalSeconds -gt $TimeoutSeconds) { $stopped='Timeout watchdog'; break }
            }
            if ($stopped) { $process.Kill(); $process.WaitForExit() }
            $code=$process.ExitCode
            $out=$stdout.GetAwaiter().GetResult(); $err=$stderr.GetAwaiter().GetResult()
        } finally { $process.Dispose() }
        [IO.File]::WriteAllText($Runtime.OutputPath,$out,(New-Object Text.UTF8Encoding($true)))
        [IO.File]::WriteAllText($Runtime.ErrorPath,$err,(New-Object Text.UTF8Encoding($true)))
        $summaryPath=Join-Path $Runtime.Root 'main-result.json'
        $mainSummary=if (Test-Path -LiteralPath $summaryPath) { [IO.File]::ReadAllText($summaryPath) | ConvertFrom-Json -DateKind String } else { $null }
        $sourceHashes=@(foreach ($file in @((Join-Path $Runtime.Package 'Invoke-PraRemoteMailbox.ps1'),(Join-Path $Runtime.Package 'module\PRA.Directory.psm1'),(Join-Path $Runtime.Package 'module\PRA.Common.psm1'),(Join-Path $Runtime.Package 'module\PRA.Backup.psm1'))) { Get-FileHash -LiteralPath $file -Algorithm SHA256 | Select-Object Path,Hash })
        $childRuntimePath=Join-Path $Runtime.Root 'child-runtime.json'
        $childRuntime=if (Test-Path -LiteralPath $childRuntimePath) { [IO.File]::ReadAllText($childRuntimePath) | ConvertFrom-Json -DateKind String } else { $null }
        $record=[ordered]@{ Synthetic=$true; ChildRuntime=$childRuntime; CaseName=$Runtime.CaseName; ExplicitArguments=[bool]$ExplicitArguments; AdProvenance='TEMP ActiveDirectory.psm1; local System.DirectoryServices security descriptors only; no AD management assembly/provider'; CloudProvenance='TEMP synthetic orchestration barrier, not production Cloud'; SourceHashes=$sourceHashes; Executable=$exe; Command=$command; Arguments=$Arguments; RuntimeMilliseconds=$clock.ElapsedMilliseconds; PeakPrivateBytes=$peakPrivate; PeakWorkingSetBytes=$peakWorkingSet; MemorySamples=$samples; MemoryLimitBytes=($MemoryLimitMB*1MB); TimeoutSeconds=$TimeoutSeconds; WatchdogStopped=$stopped; ExitCode=$code; MainResult=$mainSummary; Stdout=$out; Stderr=$err; Events=@(Get-GateEvents $Runtime) }
        if ($env:PRA_GATE_EVIDENCE) {
            $caseId=(Split-Path $Runtime.Root -Leaf)+'-'+([IO.Path]::GetFileNameWithoutExtension($paramsPath).Substring(5,6))
            $path=Join-Path $env:PRA_GATE_EVIDENCE ($caseId+'.process.json')
            [IO.File]::WriteAllText($path,($record | ConvertTo-Json -Depth 30),(New-Object Text.UTF8Encoding($true)))
            $artifactRoot=Join-Path $env:PRA_GATE_EVIDENCE ($caseId+'-synthetic-artifacts')
            $null=New-Item -ItemType Directory -Path $artifactRoot -Force
            foreach ($name in @('backups','logs','reports','main-result.json','events.jsonl','engine.events.jsonl')) {
                $sourcePath=Join-Path $Runtime.Root $name
                if (Test-Path -LiteralPath $sourcePath) { Copy-Item -LiteralPath $sourcePath -Destination $artifactRoot -Recurse -Force }
            }
        }
        if ($stopped) { throw ('SYNTHETIC controlled stop: '+$stopped+'; peakPrivateBytes='+$peakPrivate+'; timeoutSeconds='+$TimeoutSeconds) }
        [pscustomobject]@{ExitCode=$code;Output=$out;Error=$err;Runtime=$Runtime;Events=$record.Events;MainResult=$mainSummary;PeakPrivateBytes=$peakPrivate;PeakWorkingSetBytes=$peakWorkingSet;MemorySamples=$samples;RuntimeMilliseconds=$clock.ElapsedMilliseconds;WatchdogStopped=$stopped}
    }
    function global:New-GateSourceBundles {
        param($Context,[switch]$ApplySnapshots)
        $plans=@(New-PraPlan $Context 'user1' 'Convert'; New-PraPlan $Context 'user2' 'Convert')
        $directory=Get-Module PRA.Directory
        $source=if ($ApplySnapshots) { Invoke-PraAdBatch $Context $plans 'Convert' } else { & $directory { param($c,$p) Save-PraBatch $c $p 'Convert' } $Context $plans }
        $Context.SourceBackupHash=$source.Hash; $Context.Source=$source; $Context.Action='Recover'
        $recoverPlans=@(foreach ($record in $source.Data.Records) { New-PraPlan $Context $record.ObjectGuid 'Recover' $record })
        $recover=if ($ApplySnapshots) { Invoke-PraAdBatch $Context $recoverPlans 'Recover' } else { & $directory { param($c,$p) Save-PraBatch $c $p 'Recover' } $Context $recoverPlans }
        if ($ApplySnapshots) { $proofPath=$recover.StatePath }
        else {
            $proofPath=Join-Path (Split-Path $recover.Path -Parent) ('State-' + $recover.Data.BatchId + '.json')
            $proof=[ordered]@{SchemaVersion=2;Operation='Recover';Kind='ADVerified';Environment=$Context.Config.Environment;RunId=$Context.RunId;BackupFile=[IO.Path]::GetFileName($recover.Path);BackupHash=$recover.Hash;SourceBackupHash=$source.Hash;Records=@($recoverPlans | ForEach-Object { @{ObjectGuid=$_.Record.ObjectGuid;Operation='Recover';ADVerified=$true;VerifiedUsnChanged=[string]$_.User.uSNChanged} })}
            Write-PraImmutableFile $proofPath ($proof | ConvertTo-Json -Depth 20)
            Write-PraImmutableFile ($proofPath+'.sha256') (Get-PraHash $proofPath)
        }
        foreach ($path in @($source.Path,($source.Path+'.sha256'),(Join-Path (Split-Path $source.Path -Parent) $source.Data.RawFile))) { Copy-Item -LiteralPath $path -Destination (Split-Path $recover.Path -Parent) }
        $manifestPath=Join-Path (Split-Path $recover.Path -Parent) 'Synthetic-Finalize.json'
        $manifest=[ordered]@{SchemaVersion=2;Operation='RecoverFinalize';Environment=$Context.Config.Environment;SourceBackupFile=[IO.Path]::GetFileName($source.Path);SourceBackupHash=$source.Hash;StateFile=[IO.Path]::GetFileName($proofPath);StateHash=(Get-PraHash $proofPath);Items=@($plans | ForEach-Object { @{ObjectGuid=$_.Record.ObjectGuid;RestoreShared=$false;RestoreTag=$true;CloudConfirmed=$true;DeprovisionConfirmed=$true} })}
        Write-PraImmutableFile $manifestPath ($manifest | ConvertTo-Json -Depth 20)
        Write-PraImmutableFile ($manifestPath+'.sha256') (Get-PraHash $manifestPath)
        [pscustomobject]@{Source=$source.Path;Recover=$recover.Path;State=$proofPath;Manifest=$manifestPath;Plans=$plans}
    }
    function global:Get-GateCodec {
        Get-Module PRA.Backup -All | Select-Object -First 1
    }
    function global:Get-GateExpectedNodes {
        param($Descriptor,[int]$Depth=0)
        [pscustomobject]@{Depth=$Depth;Kind=$Descriptor.Kind;Type=$Descriptor.Type;Value=$Descriptor.Value;Count=$Descriptor.Items.Count}
        foreach ($item in $Descriptor.Items) { Get-GateExpectedNodes $item ($Depth+1) }
    }
    function global:Assert-GateWireSnapshot {
        param($Wire,$Snapshot)
        $Wire.RawFormat | Should -BeExactly 'PraDataOnlyClixml-v1'
        $Wire.ObjectGUID | Should -BeExactly $Snapshot.ObjectGUID
        $Wire.DistinguishedName | Should -BeExactly $Snapshot.DistinguishedName
        $Wire.CapturedUtc | Should -BeExactly $Snapshot.CapturedUtc
        $Wire.Attributes.Count | Should -Be $Snapshot.Attributes.Count
        foreach ($name in $Snapshot.Attributes.Keys) {
            $actual=@($Wire.Attributes[$name]); $expected=@(Get-GateExpectedNodes $Snapshot.Attributes[$name])
            $actual.Count | Should -Be $expected.Count -Because $name
            for ($i=0;$i -lt $expected.Count;$i++) {
                foreach ($field in @('Depth','Kind','Type','Value','Count')) { $actual[$i].$field | Should -BeExactly $expected[$i].$field -Because ($name+'/'+$i+'/'+$field) }
            }
        }
    }
    function global:Save-GateOomEvidence {
        param([string]$Name,$Runtime,[object]$Statistics,[string[]]$ArtifactPaths=@())
        if (-not $env:PRA_GATE_EVIDENCE) { return }
        $artifacts=@(foreach ($path in $ArtifactPaths) {
            if (Test-Path -LiteralPath $path -PathType Leaf) {
                $file=Get-Item -LiteralPath $path
                [pscustomobject]@{Path=$file.FullName;Bytes=$file.Length;SHA256=(Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash}
            }
        })
        $record=[ordered]@{Synthetic=$true;Name=$Name;Runtime=$Runtime.Root;Statistics=$Statistics;Artifacts=$artifacts;SourceHashes=@(foreach ($moduleName in @('PRA.Backup.psm1','PRA.Directory.psm1')) { Get-FileHash -LiteralPath (Join-Path $global:PraGate.Package ('module\'+$moduleName)) -Algorithm SHA256 | Select-Object Path,Hash })}
        [IO.File]::WriteAllText((Join-Path $env:PRA_GATE_EVIDENCE ((Split-Path $Runtime.Root -Leaf)+'-'+$Name+'.oom.json')),($record | ConvertTo-Json -Depth 12),(New-Object Text.UTF8Encoding($true)))
    }
    Import-Module (Join-Path $global:PraGate.Package 'module\PRA.Common.psm1') -Force -Global
    Import-Module (Join-Path $global:PraGate.Package 'module\PRA.Backup.psm1') -Force -Global
    Import-Module (Join-Path $global:PraGate.Package 'module\PRA.Directory.psm1') -Force -Global
}

Describe 'Runtime disclaimer' -Tag 'Disclaimer' {
    It 'keeps public script help identical to the root runtime readme disclaimer' {
        $readme = [IO.File]::ReadAllText((Join-Path $global:PraGate.Source 'README.md')).Replace("`r`n", "`n")
        $sections = [regex]::Matches($readme, '(?ms)^## Disclaimer\n\n(?<Text>.*?)(?=^## |\z)')
        $sections.Count | Should -Be 1
        $canonical = $sections[0].Groups['Text'].Value.TrimEnd([char[]]"`n")
        $canonical | Should -Not -BeNullOrEmpty

        $entry = Join-Path $global:PraGate.Source 'Invoke-PraRemoteMailbox.ps1'
        $notes = ((Get-Help $entry -Full).alertSet.alert.Text -join "`n").Replace("`r`n", "`n")
        $disclaimers = [regex]::Matches($notes, '(?ms)^Disclaimer:\n(?<Text>.*?)(?=\n\nRequires -Version|\z)')
        $disclaimers.Count | Should -Be 1
        $disclaimers[0].Groups['Text'].Value.TrimEnd([char[]]"`n") | Should -BeExactly $canonical
    }
}

Describe 'Directory internal invariants - synthetic modules only' {
    BeforeEach {
        $global:PraGate.Runtime=New-GateRuntime -Name 'unit'
        $env:PRA_GATE_STATE=$global:PraGate.Runtime.StatePath
        $env:PSModulePath=$global:PraGate.Runtime.Modules+';'+(Join-Path $PSHOME 'Modules')
        Import-Module ActiveDirectory -Force -Global
        $global:PraGate.Context=New-GateContext $global:PraGate.Runtime
        $global:PraGate.Context.LogFile=Join-Path $global:PraGate.Runtime.Root 'logs\unit.log'
        $global:PraGate.Counters=@{Readbacks=0;Writes=0;FaultReached=0}
    }
    It 'uses an intact string HostName for every DC-bound read' {
        $global:PraGate.Context.Server=''
        Initialize-PraDirectory $global:PraGate.Context -ValidateScope
        $global:PraGate.Context.Server | Should -BeExactly 'dc01.gate.invalid'
        $global:PraGate.Context.Server | Should -BeOfType ([string])
        @(Get-GateEvents $global:PraGate.Runtime | Where-Object { $_.Server -and $_.Server -cne 'dc01.gate.invalid' }).Count | Should -Be 0
    }
    It 'serializes false Bool, binary and multi-valued attributes without conflating absence' {
        InModuleScope PRA.Directory {
            $user=New-GateUser
            $state=Get-PraAttributeState $user $script:AttributeKinds
            $roundtrip=($state | ConvertTo-Json -Depth 10 | ConvertFrom-Json -DateKind String)
            $roundtrip.mDBUseDefaults.Present | Should -BeTrue
            $roundtrip.mDBUseDefaults.Value | Should -BeOfType ([bool])
            (ConvertFrom-PraStoredValue $roundtrip.mDBUseDefaults) | Should -BeFalse
            $bytes=ConvertFrom-PraStoredValue $roundtrip.msExchMailboxGuid
            $bytes.GetType().FullName | Should -Be 'System.Byte[]'
            [Convert]::ToBase64String($bytes) | Should -Be ([Convert]::ToBase64String($user.msExchMailboxGuid))
            $values=ConvertFrom-PraStoredValue $roundtrip.proxyAddresses
            $values.Count | Should -Be 3
            ($values | Sort-Object) -join '|' | Should -Be (($user.proxyAddresses | Sort-Object) -join '|')
            $roundtrip.targetAddress.Present | Should -BeFalse
        }
    }
    It 'refuses an unknown/unprojected attribute instead of treating it as absent' {
        InModuleScope PRA.Directory {
            $user=New-GateUser; $user.PSObject.Properties.Remove('homeMDB')
            { Get-PraAttributeState $user $script:AttributeKinds } | Should -Throw '*AD attribute not read*'
        }
        @(Get-GateWrites $global:PraGate.Runtime).Count | Should -Be 0
    }
    It 'escapes all LDAP metacharacters without writing' {
        $identity='a*(x)\'+[char]0+'@gate.invalid'
        ConvertTo-PraLdapValue $identity | Should -BeExactly 'a\2a\28x\29\5c\00@gate.invalid'
        $global:PraGateAd.Users[0].UserPrincipalName=$identity
        $user=Get-PraUser $global:PraGate.Context $identity
        $user.SamAccountName | Should -Be 'user1'
        $call=@(Get-GateEvents $global:PraGate.Runtime | Where-Object Operation -eq 'Get-ADUser')[-1]
        $call.Detail.LDAPFilter | Should -BeExactly '(userPrincipalName=a\2a\28x\29\5c\00@gate.invalid)'
        @(Get-GateWrites $global:PraGate.Runtime).Count | Should -Be 0
    }
    It 'refuses missing or ambiguous identity before any write' -ForEach @(@{Case='MissingUser'},@{Case='AmbiguousUser'}) {
        $global:PraGateAd.Case=$Case
        { Get-PraUser $global:PraGate.Context 'absent@gate.invalid' } | Should -Throw '*not found or not unique*'
        @(Get-GateWrites $global:PraGate.Runtime).Count | Should -Be 0
    }
    It 'refuses a licensing group preflight failure before any write' {
        $global:PraGateAd.Case='GroupFailure'
        { New-PraPlan $global:PraGate.Context 'user1' 'Convert' } | Should -Throw '*group preflight*'
        @(Get-GateWrites $global:PraGate.Runtime).Count | Should -Be 0
    }
    It 'accepts RemoteRecipientType=<Rrt> for a new shared Convert plan and prepares the expected desired value' -ForEach @(@{Rrt=97},@{Rrt=99}) {
        $global:PraGateAd.Users[0].msExchRecipientTypeDetails=[long]4
        $global:PraGate.Context.Config.SharedMailbox.RemoteRecipientType=$Rrt
        $plan=New-PraPlan $global:PraGate.Context 'user1' 'Convert'
        $plan.Desired.msExchRemoteRecipientType.Value | Should -BeExactly ([string]$Rrt)
        @(Get-GateWrites $global:PraGate.Runtime).Count | Should -Be 0
    }
    It 'keeps the archive bit (-bor 2) on top of a first-provisioning RemoteRecipientType=97' {
        $global:PraGateAd.Users[0].msExchRecipientTypeDetails=[long]4
        $global:PraGateAd.Users[0].msExchArchiveGUID=[guid]'30000000-0000-0000-0000-000000000001'
        $global:PraGate.Context.Config.SharedMailbox.RemoteRecipientType=97
        $plan=New-PraPlan $global:PraGate.Context 'user1' 'Convert'
        $plan.Desired.msExchRemoteRecipientType.Value | Should -BeExactly '99'
        @(Get-GateWrites $global:PraGate.Runtime).Count | Should -Be 0
    }
    It 'refuses RemoteRecipientType=<Rrt> (Migrated+Shared) for a new shared Convert plan before any write' -ForEach @(@{Rrt=100},@{Rrt=102}) {
        $global:PraGateAd.Users[0].msExchRecipientTypeDetails=[long]4
        $global:PraGate.Context.Config.SharedMailbox.RemoteRecipientType=$Rrt
        { New-PraPlan $global:PraGate.Context 'user1' 'Convert' } | Should -Throw '*already migrated mailbox*'
        @(Get-GateWrites $global:PraGate.Runtime).Count | Should -Be 0
    }
    It 'does not apply the new-shared RemoteRecipientType=<Rrt> guard to a non-shared Convert plan' -ForEach @(@{Rrt=100},@{Rrt=102}) {
        $global:PraGate.Context.Config.SharedMailbox.RemoteRecipientType=$Rrt
        $plan=New-PraPlan $global:PraGate.Context 'user1' 'Convert'
        $plan.Desired.msExchRemoteRecipientType.Value | Should -BeExactly '1'
        @(Get-GateWrites $global:PraGate.Runtime).Count | Should -Be 0
    }
    It 'refuses missing UPN when persisting the batch and performs zero writes' {
        $global:PraGateAd.Users[0].UserPrincipalName=''
        $plans=@(New-PraPlan $global:PraGate.Context 'user1' 'Convert'; New-PraPlan $global:PraGate.Context 'user2' 'Convert')
        { Invoke-PraAdBatch $global:PraGate.Context $plans 'Convert' } | Should -Throw '*UserPrincipalName*'
        @(Get-GateWrites $global:PraGate.Runtime).Count | Should -Be 0
    }
    It 'rereads complete JSON, CLIXML and SHA for all targets BEFORE the first mutation' {
        InModuleScope PRA.Directory {
            $script:GateActualImport=(Get-Command Import-PraBackup).ScriptBlock
            $script:GateActualRawTest=(Get-Command Test-PraRawCapture).ScriptBlock
            $global:PraGateAd.RequireProductReadbacks=$true
            $global:PraGate.Counters.RawValidations=New-Object 'Collections.Generic.List[object]'
            Mock Test-PraRawCapture {
                param($Context,$LiteralPath,$Records,$RawFormat,$ExpectedSnapshots)
                $arguments=@{Context=$Context;LiteralPath=$LiteralPath;Records=$Records;RawFormat=$RawFormat}
                if ($PSBoundParameters.ContainsKey('ExpectedSnapshots')) { $arguments.ExpectedSnapshots=$ExpectedSnapshots }
                $checked=& $script:GateActualRawTest @arguments
                $global:PraGate.Counters.RawValidations.Add([pscustomobject]@{Count=$checked.Count;Bytes=$checked.Bytes;Format=$checked.Format;Expected=$arguments.ContainsKey('ExpectedSnapshots');Writes=@(Get-GateWrites $global:PraGate.Runtime).Count})
                $checked
            }
            $global:PraGate.Counters.ReadbackIds=@()
            Mock Import-PraBackup {
                param($Context,$Path)
                $result=& $script:GateActualImport $Context $Path
                $global:PraGate.Counters.Readbacks++
                $global:PraGate.Counters.ReadbackIds=@($result.Data.Records | ForEach-Object ObjectGuid)
                return $result
            }
            $plans=@(New-PraPlan $global:PraGate.Context 'user1' 'Convert';New-PraPlan $global:PraGate.Context 'user2' 'Convert')
            $receipt=Invoke-PraAdBatch $global:PraGate.Context $plans 'Convert'
            $receipt.Data.Records.Count | Should -Be 2
            $global:PraGate.Counters.Readbacks | Should -Be 1 -Because 'one complete import registers the receipt; each mutation rehashes it without reparsing raw'
            $global:PraGate.Counters.RawValidations.Count | Should -Be 2
            @($global:PraGate.Counters.RawValidations | Where-Object { $_.Count -ne 2 -or $_.Bytes -le 0 -or $_.Format -cne 'PraDataOnlyClixml-v1' -or $_.Writes -ne 0 }).Count | Should -Be 0
            @($global:PraGate.Counters.RawValidations | Where-Object Expected).Count | Should -Be 1
        }
        $events=@(Get-GateEvents $global:PraGate.Runtime)
        $firstWrite=@($events | Where-Object Operation -eq 'Set-ADUser')[0]
        $barriers=@($events | Where-Object { $_.Operation -eq 'BackupBarrier' -and $_.Utc -le $firstWrite.Utc })
        $barriers.Count | Should -BeGreaterThan 0
        $barriers[0].Detail.AllTargets.Count | Should -Be 2
        $barriers[0].Detail.JsonRead | Should -BeTrue
        $barriers[0].Detail.CliXmlRead | Should -BeTrue
        $barriers[0].Detail.ShaRead | Should -BeTrue
        @(Get-GateWrites $global:PraGate.Runtime).Count | Should -Be 4
    }
    It 'renders every planned target before mutations and verified values only after the final successful readback' -Tag 'Delta' {
        $global:PraGate.DeltaTrace=New-Object 'Collections.Generic.List[object]'
        $global:PraGate.FinalReadbacks=@{}
        InModuleScope PRA.Directory {
            $script:GateActualCurrentState=(Get-Command Assert-PraCurrentState).ScriptBlock
            $script:GateActualDelta=(Get-Command Write-PraAdDelta).ScriptBlock
            Mock Assert-PraCurrentState {
                param($Context,$Plan,$Expected,$ExpectedMember,$AcceptNewVersion)
                & $script:GateActualCurrentState -Context $Context -Plan $Plan -Expected $Expected -ExpectedMember $ExpectedMember -AcceptNewVersion:$AcceptNewVersion
                if ($ExpectedMember -eq $true -and -not $AcceptNewVersion -and [object]::ReferenceEquals($Expected,$Plan.Desired)) {
                    $global:PraGate.FinalReadbacks[$Plan.Record.ObjectGuid]=$true
                }
            }
            Mock Write-PraAdDelta {
                param($Context,$Plan,$Stage)
                $readback=$global:PraGate.FinalReadbacks.ContainsKey($Plan.Record.ObjectGuid)
                $global:PraGate.DeltaTrace.Add([pscustomobject]@{Stage=$Stage;ObjectGuid=$Plan.Record.ObjectGuid;FinalReadback=$readback;RowVerified=$Plan.Row.ADVerified;MutationCount=@(Get-GateWrites $global:PraGate.Runtime).Count})
                if ($Stage -eq 'Verified') {
                    $readback | Should -BeTrue -Because 'the final attributes AND desired group readback must already have succeeded'
                    $Plan.Row.ADVerified | Should -BeTrue
                }
                & $script:GateActualDelta -Context $Context -Plan $Plan -Stage $Stage
            }
            $plans=@(New-PraPlan $global:PraGate.Context 'user1' 'Convert';New-PraPlan $global:PraGate.Context 'user2' 'Convert')
            $null=Invoke-PraAdBatch $global:PraGate.Context $plans 'Convert'
        }
        Save-GateDeltaEvidence 'stage-order' $global:PraGate.Context $global:PraGate.Runtime -Detail $global:PraGate.DeltaTrace.ToArray()
        $planned=@($global:PraGate.DeltaTrace | Where-Object Stage -eq 'Planned')
        $verified=@($global:PraGate.DeltaTrace | Where-Object Stage -eq 'Verified')
        $planned.Count | Should -Be 2
        @($planned | Where-Object MutationCount -ne 0).Count | Should -Be 0
        $verified.Count | Should -Be 2
        @($verified | Where-Object { -not $_.FinalReadback -or -not $_.RowVerified }).Count | Should -Be 0
        $verified[0].MutationCount | Should -Be 2
        $verified[1].MutationCount | Should -Be 4
    }
    It 'refuses backup fault <Fault> with zero target writes' -Tag 'Delta' -ForEach @(@{Fault='Write'},@{Fault='JsonRead'},@{Fault='CliXmlRead'},@{Fault='CliXmlDeserialize'},@{Fault='ShaWrite'},@{Fault='ShaRead'},@{Fault='ShaMismatch'}) {
        $global:PraGate.Fault=$Fault
        InModuleScope PRA.Directory {
            $plans=@(New-PraPlan $global:PraGate.Context 'user1' 'Convert';New-PraPlan $global:PraGate.Context 'user2' 'Convert')
            $script:GateActualImmutable=(Get-Command Write-PraImmutableFile).ScriptBlock
            $script:GateActualHash=(Get-Command Get-PraHash).ScriptBlock
            # Pester 6 rejects unmatched filters; every partial mock has an explicit real fallback.
            Mock Write-PraImmutableFile { param($Path,$Text) & $script:GateActualImmutable $Path $Text }
            Mock Get-PraHash { param($Path) & $script:GateActualHash $Path }
            Mock Get-Content { param($LiteralPath) [IO.File]::ReadAllText($LiteralPath) }
            switch ($global:PraGate.Fault) {
                'Write' { Mock Write-PraImmutableFile { $global:PraGate.Counters.FaultReached++; throw 'SYNTHETIC: write refused' } }
                'JsonRead' { Mock Get-Content { $global:PraGate.Counters.FaultReached++; throw 'SYNTHETIC: JSON read refused' } -ParameterFilter { $LiteralPath -like '*.json' } }
                'CliXmlRead' { Mock Get-PraHash { $global:PraGate.Counters.FaultReached++; throw 'SYNTHETIC: CLIXML read refused' } -ParameterFilter { $Path -like '*.clixml' } }
                'CliXmlDeserialize' { Mock Write-PraRawCapture { param($Context,$LiteralPath,$Snapshots) $global:PraGate.Counters.FaultReached++; [IO.File]::WriteAllText($LiteralPath,'deliberately invalid CLIXML, with a matching SHA') } }
                'ShaWrite' { Mock Write-PraImmutableFile { $global:PraGate.Counters.FaultReached++; throw 'SYNTHETIC: SHA write refused' } -ParameterFilter { $Path -like '*.sha256' } }
                'ShaRead' { Mock Get-Content { $global:PraGate.Counters.FaultReached++; throw 'SYNTHETIC: SHA read refused' } -ParameterFilter { $LiteralPath -like '*.sha256' } }
                'ShaMismatch' { Mock Get-Content { $global:PraGate.Counters.FaultReached++; 'corrupted-hash' } -ParameterFilter { $LiteralPath -like '*.sha256' } }
            }
            $failure={ Invoke-PraAdBatch $global:PraGate.Context $plans 'Convert' } | Should -Throw -PassThru
            $global:PraGate.Counters.FaultReached | Should -BeGreaterThan 0 -Because $failure.Exception.Message
        }
        Save-GateDeltaEvidence ('backup-'+$Fault) $global:PraGate.Context $global:PraGate.Runtime
        [IO.File]::ReadAllText($global:PraGate.Context.LogFile) | Should -Not -Match '(?m)^.*\] AD VERIFIED \|'
        @(Get-GateWrites $global:PraGate.Runtime).Count | Should -Be 0
    }
    It 'blocks a changed backup receipt immediately before the next mutation' {
        InModuleScope PRA.Directory {
            $plans=@(New-PraPlan $global:PraGate.Context 'user1' 'Convert';New-PraPlan $global:PraGate.Context 'user2' 'Convert')
            Mock Assert-PraReceipt { throw 'SYNTHETIC: receipt read refused' }
            { Invoke-PraAdBatch $global:PraGate.Context $plans 'Convert' } | Should -Throw '*receipt read refused*'
        }
        @(Get-GateWrites $global:PraGate.Runtime).Count | Should -Be 0
    }
    It 'preserves original tag, GUID and attrs after Set succeeds and Add fails; stops the batch' {
        $global:PraGateAd.Case='SecondMutationFailure'
        $plans=@(New-PraPlan $global:PraGate.Context 'user1' 'Convert';New-PraPlan $global:PraGate.Context 'user2' 'Convert')
        { Invoke-PraAdBatch $global:PraGate.Context $plans 'Convert' } | Should -Throw '*second mutation*'
        $writes=@(Get-GateWrites $global:PraGate.Runtime)
        ($writes.Operation -join ',') | Should -Be 'Set-ADUser,Add-ADGroupMember'
        @($writes | Where-Object Identity -eq ([string]$global:PraGateAd.Users[1].ObjectGUID)).Count | Should -Be 0
        $backup=Import-PraBackup $global:PraGate.Context $global:PraGate.Context.BackupFiles[0]
        $backup.Data.Records[0].Attributes.extensionAttribute1.Value | Should -Be 'OriginalTag-1'
        $backup.Data.Records[0].Attributes.msExchMailboxGuid.Value | Should -Be ([Convert]::ToBase64String((New-GateUser).msExchMailboxGuid))
        $backup.Data.Records[0].Attributes.homeMDB.Value | Should -Be (New-GateUser).homeMDB
        $plans[0].Row.FinalStatus | Should -Be 'Error'
        $plans[0].Row.ADVerified | Should -BeFalse
        $plans[1].Row.LastOperation | Should -Be 'Prepared'
    }
    It 'revokes a previous successful receipt after a later partial failure, blocking sync and another batch' {
        $context=$global:PraGate.Context
        $convert=@(New-PraPlan $context 'user1' 'Convert';New-PraPlan $context 'user2' 'Convert')
        $source=Invoke-PraAdBatch $context $convert 'Convert'
        $context.LastVerifiedReceipt | Should -Not -BeNullOrEmpty
        $context.Action='Recover'; $context.Source=$source; $context.SourceBackupHash=$source.Hash
        $recover=@(foreach ($record in $source.Data.Records) { New-PraPlan $context $record.ObjectGuid 'Recover' $record })
        $global:PraGateAd.Case='SecondRemovalFailure'
        { Invoke-PraAdBatch $context $recover 'Recover' } | Should -Throw '*second removal mutation*'
        $context.OperationFailed | Should -BeTrue
        $context.LastVerifiedReceipt | Should -BeNullOrEmpty
        $writes=@(Get-GateWrites $global:PraGate.Runtime).Count
        $writes | Should -Be 6
        $context.Config.EntraConnect.Sync=$true
        { Invoke-PraSync $context } | Should -Throw '*Synchronisation refused*'
        { Invoke-PraAdBatch $context @($recover[1]) 'Recover' } | Should -Throw '*No new batch after an error*'
        @(Get-GateWrites $global:PraGate.Runtime).Count | Should -Be $writes
    }
    It 'tags a mixed user/shared batch while licensing only the user and preserving original membership and tags for Recover' -Tag 'NativeCloud136' {
        $context=$global:PraGate.Context
        $global:PraGateAd.Users[1].msExchRecipientTypeDetails=[long]4
        $plans=@(New-PraPlan $context 'user1' 'Convert';New-PraPlan $context 'user2' 'Convert')
        $plans[0].Desired.msExchRemoteRecipientType.Value | Should -BeExactly '1'
        $plans[1].Desired.msExchRemoteRecipientType.Value | Should -BeExactly '97'
        foreach ($plan in $plans) { $plan.Desired.extensionAttribute1.Value | Should -BeExactly 'Converted' }
        $source=Invoke-PraAdBatch $context $plans 'Convert'
        $saved=Import-PraBackup $context $source.Path
        $saved.Data.Records[0].Licensing.WasMember | Should -BeFalse
        foreach ($index in 0..1) {
            $saved.Data.Records[$index].Attributes.extensionAttribute1.Value | Should -BeExactly ('OriginalTag-'+($index+1))
            $global:PraGateAd.Users[$index].extensionAttribute1 | Should -BeExactly 'Converted'
        }
        $adds=@(Get-GateWrites $global:PraGate.Runtime | Where-Object Operation -eq 'Add-ADGroupMember')
        $adds.Count | Should -Be 1
        $adds[0].Identity | Should -BeExactly ([string]$plans[0].Record.ObjectGuid)
        $global:PraGateAd.Group.member.Count | Should -Be 1
        $global:PraGateAd.Group.member[0] | Should -BeExactly $global:PraGateAd.Users[0].DistinguishedName
        $context.Action='Recover'; $context.Source=$source; $context.SourceBackupHash=$source.Hash
        $recover=@(foreach ($record in $saved.Data.Records) { New-PraPlan $context $record.ObjectGuid 'Recover' $record -RestoreRetention })
        $null=Invoke-PraAdBatch $context $recover 'Recover'
        $removes=@(Get-GateWrites $global:PraGate.Runtime | Where-Object Operation -eq 'Remove-ADGroupMember')
        $removes.Count | Should -Be 1
        $removes[0].Identity | Should -BeExactly ([string]$plans[0].Record.ObjectGuid)
        $global:PraGateAd.Group.member.Count | Should -Be 0
        foreach ($index in 0..1) { $global:PraGateAd.Users[$index].extensionAttribute1 | Should -BeExactly ('OriginalTag-'+($index+1)) }
    }
    It 'preserves preexisting licensing membership through Convert and Recover' {
        $global:PraGateAd.Group.member=@($global:PraGateAd.Users | ForEach-Object DistinguishedName)
        $plans=@(New-PraPlan $global:PraGate.Context 'user1' 'Convert';New-PraPlan $global:PraGate.Context 'user2' 'Convert')
        $source=Invoke-PraAdBatch $global:PraGate.Context $plans 'Convert'
        @($source.Data.Records | Where-Object { -not $_.Licensing.WasMember }).Count | Should -Be 0
        $global:PraGate.Context.Action='Recover'; $global:PraGate.Context.SourceBackupHash=$source.Hash
        $restore=@(foreach ($record in $source.Data.Records) { New-PraPlan $global:PraGate.Context $record.ObjectGuid 'Recover' $record -RestoreRetention })
        $null=Invoke-PraAdBatch $global:PraGate.Context $restore 'Recover'
        @(Get-GateWrites $global:PraGate.Runtime | Where-Object Operation -Match '^(Add|Remove)-').Count | Should -Be 0
        $global:PraGateAd.Group.member.Count | Should -Be 2
        $global:PraGateAd.Users[0].mDBUseDefaults | Should -BeFalse
        $global:PraGateAd.Users[0].extensionAttribute1 | Should -Be 'OriginalTag-1'
    }
    It 'Recover keeps the cloud X500 written back by Entra Connect (user and shared), once, and still removes any other added address' -Tag 'Lot2d' {
        $context=$global:PraGate.Context
        $global:PraGateAd.Users[1].msExchRecipientTypeDetails=[long]4
        $convert=@(New-PraPlan $context 'user1' 'Convert';New-PraPlan $context 'user2' 'Convert')
        $source=Invoke-PraAdBatch $context $convert 'Convert'
        $cloudOne='X500:/o=ExchangeLabs/ou=Exchange Administrative Group (FYDIBOHF23SPDLT)/cn=Recipients/cn=aaaa1111-user1'
        $cloudTwo='X500:/o=ExchangeLabs/ou=Exchange Administrative Group (FYDIBOHF23SPDLT)/cn=Recipients/cn=bbbb2222-user2'
        # The writeback: user1 gets one X500, user2 gets one X500 plus a case variant of its ORIGINAL X500 and a foreign smtp address (the latter two are not cloud X500).
        $global:PraGateAd.Users[0].proxyAddresses=[string[]]@($global:PraGateAd.Users[0].proxyAddresses)+$cloudOne
        $global:PraGateAd.Users[1].proxyAddresses=[string[]]@($global:PraGateAd.Users[1].proxyAddresses)+$cloudTwo+'x500:/o=synthetic/ou=gate/cn=user'+'smtp:someone.else@gate.invalid'
        $context.Action='Recover'; $context.Source=$source; $context.SourceBackupHash=$source.Hash
        $recover=@(foreach ($record in $source.Data.Records) { New-PraPlan $context $record.ObjectGuid 'Recover' $record -RestoreRetention })
        @($recover[0].Record.KeptX500) | Should -BeExactly @($cloudOne)
        @($recover[1].Record.KeptX500) | Should -BeExactly @($cloudTwo)
        $recover[0].Row.Detail | Should -Match '1 cloud X500 address\(es\) kept'
        $receipt=Invoke-PraAdBatch $context $recover 'Recover'
        $original=@(1,2 | ForEach-Object { @((New-GateUser $_).proxyAddresses) })
        $final1=@($global:PraGateAd.Users[0].proxyAddresses | Sort-Object { $_ } -CaseSensitive)
        $expected1=@(@((New-GateUser 1).proxyAddresses)+$cloudOne | Sort-Object { $_ } -CaseSensitive)
        ($final1 -join '|') | Should -BeExactly ($expected1 -join '|')
        $expected2=@(@((New-GateUser 2).proxyAddresses)+$cloudTwo | Sort-Object { $_ } -CaseSensitive)
        (@($global:PraGateAd.Users[1].proxyAddresses | Sort-Object { $_ } -CaseSensitive) -join '|') | Should -BeExactly ($expected2 -join '|')
        @($global:PraGateAd.Users[1].proxyAddresses | Where-Object { $_ -ceq 'smtp:someone.else@gate.invalid' }).Count | Should -Be 0
        @($global:PraGateAd.Users[1].proxyAddresses | Where-Object { $_ -match '^x500:/o=synthetic' -and $_ -cne 'X500:/o=Synthetic/ou=Gate/cn=User' }).Count | Should -Be 0
        # The batch records the kept list, and a re-read of the backup matches it.
        $saved=Import-PraBackup $context $receipt.Path
        @($saved.Data.Records[0].KeptX500) | Should -BeExactly @($cloudOne)
        @($saved.Data.Records[1].KeptX500) | Should -BeExactly @($cloudTwo)
    }
    It 'nothing is kept when no X500 was added, and an X500 that is already original is not duplicated' -Tag 'Lot2d' {
        $context=$global:PraGate.Context
        $convert=@(New-PraPlan $context 'user1' 'Convert';New-PraPlan $context 'user2' 'Convert')
        $source=Invoke-PraAdBatch $context $convert 'Convert'
        $context.Action='Recover'; $context.Source=$source; $context.SourceBackupHash=$source.Hash
        $plan=New-PraPlan $context $source.Data.Records[0].ObjectGuid 'Recover' $source.Data.Records[0]
        @($plan.Record.KeptX500).Count | Should -Be 0
        (@($plan.Desired.proxyAddresses.Value | Sort-Object { $_ } -CaseSensitive) -join '|') | Should -BeExactly ((@((New-GateUser 1).proxyAddresses) | Sort-Object { $_ } -CaseSensitive) -join '|')
        $plan.Row.Detail | Should -Not -Match 'X500'
    }
    It 'a record written before 3.0.0 (no KeptX500) is read, and a kept list that is not X500 is refused' -Tag 'Lot2d' {
        InModuleScope PRA.Directory {
            $plan=New-PraPlan $global:PraGate.Context 'user1' 'Convert'
            $record=($plan.Record | ConvertTo-Json -Depth 20 | ConvertFrom-Json -DateKind String)
            $record.PSObject.Properties.Remove('KeptX500')
            { Assert-PraStoredRecord $record } | Should -Not -Throw
            $record | Add-Member -NotePropertyName KeptX500 -NotePropertyValue @('smtp:not.x500@gate.invalid')
            { Assert-PraStoredRecord $record } | Should -Throw '*kept X500*'
        }
    }
    It 'Finalize accepts a writeback that only added X500 entries since the AD proof, and refuses anything else' -Tag 'Lot2d' -ForEach @(
        @{Case='X500Only'; Throws=''}, @{Case='X500PlusOtherAddress'; Throws='*AD proof is out of date*'},
        @{Case='X500PlusAttribute'; Throws='*homeMDB differs from the AD proof*'}, @{Case='VersionOnly'; Throws='*AD proof is out of date*'}
    ) {
        $global:PraGate.Change=$Case; $global:PraGate.Expect=$Throws
        InModuleScope PRA.Directory {
            $context=$global:PraGate.Context
            $convert=@(New-PraPlan $context 'user1' 'Convert';New-PraPlan $context 'user2' 'Convert')
            $source=Invoke-PraAdBatch $context $convert 'Convert'
            $context.Action='Recover'; $context.Source=$source; $context.SourceBackupHash=$source.Hash
            $restore=@(foreach ($record in $source.Data.Records) { New-PraPlan $context $record.ObjectGuid 'Recover' $record })
            $receipt=Invoke-PraAdBatch $context $restore 'Recover'
            $proof=Import-PraProof $context $receipt.StatePath $source 'Recover'
            $user=$global:PraGateAd.Users[0]
            $cloud='X500:/o=ExchangeLabs/ou=Exchange Administrative Group (FYDIBOHF23SPDLT)/cn=Recipients/cn=cccc3333-user1'
            if ($global:PraGate.Change -ne 'VersionOnly') { $user.proxyAddresses=[string[]]@($user.proxyAddresses)+$cloud }
            if ($global:PraGate.Change -eq 'X500PlusOtherAddress') { $user.proxyAddresses=[string[]]@($user.proxyAddresses)+'smtp:added.by.someone@gate.invalid' }
            if ($global:PraGate.Change -eq 'X500PlusAttribute') { $user.homeMDB='CN=ThirdParty,DC=gate,DC=invalid' }
            $user.uSNChanged=[long]$user.uSNChanged+3
            $writesBefore=@(Get-GateWrites $global:PraGate.Runtime).Count
            $followup=New-PraPlan $context 'user1' 'RestoreTag' $source.Data.Records[0]
            if ($global:PraGate.Expect) { { Assert-PraFollowupState $context $followup $proof } | Should -Throw $global:PraGate.Expect }
            else {
                { Assert-PraFollowupState $context $followup $proof } | Should -Not -Throw
                $followup.Row.Detail | Should -Match 'writeback'
                # The final restore of the tag keeps the X500 (the proxyAddresses of a RestoreTag plan are the current ones).
                $null=Invoke-PraAdBatch $context @($followup) 'Finalize'
                @($user.proxyAddresses | Where-Object { $_ -ceq $cloud }).Count | Should -Be 1
                $user.extensionAttribute1 | Should -BeExactly 'OriginalTag-1'
            }
            if ($global:PraGate.Expect) { @(Get-GateWrites $global:PraGate.Runtime).Count | Should -Be $writesBefore }
        }
    }
    It 'rechecks uSNChanged after approval and refuses a concurrent edit before the first write' {
        $plans=@(New-PraPlan $global:PraGate.Context 'user1' 'Convert';New-PraPlan $global:PraGate.Context 'user2' 'Convert')
        $global:PraGate.Context.Approval={ param($Target,$Operation) $global:PraGateAd.Users[0].uSNChanged++; $true }
        { Invoke-PraAdBatch $global:PraGate.Context $plans 'Convert' } | Should -Throw '*uSNChanged*'
        @(Get-GateWrites $global:PraGate.Runtime).Count | Should -Be 0
    }
    It 'blocks stale followup proof after <Change>, without another mutation' -ForEach @(@{Change='AttributeDuringPoll'},@{Change='NewCycleSameAttributes'}) {
        $global:PraGate.Change=$Change
        InModuleScope PRA.Directory {
            $context=$global:PraGate.Context
            $convert=@(New-PraPlan $context 'user1' 'Convert';New-PraPlan $context 'user2' 'Convert')
            $source=Invoke-PraAdBatch $context $convert 'Convert'
            $context.Action='Recover'; $context.Source=$source; $context.SourceBackupHash=$source.Hash
            $restore=@(foreach ($record in $source.Data.Records) { New-PraPlan $context $record.ObjectGuid 'Recover' $record })
            $receipt=Invoke-PraAdBatch $context $restore 'Recover'
            $proof=Import-PraProof $context $receipt.StatePath $source 'Recover'
            $before=@(Get-GateWrites $global:PraGate.Runtime).Count
            if ($global:PraGate.Change -eq 'AttributeDuringPoll') { $global:PraGateAd.Users[0].homeMDB='CN=ThirdParty,DC=gate,DC=invalid' }
            $global:PraGateAd.Users[0].uSNChanged=[long]$global:PraGateAd.Users[0].uSNChanged+2
            $followup=New-PraPlan $context 'user1' 'RestoreTag' $source.Data.Records[0]
            { Assert-PraFollowupState $context $followup $proof; Invoke-PraAdBatch $context @($followup) 'Finalize' } | Should -Throw '*AD proof is out of date*'
            @(Get-GateWrites $global:PraGate.Runtime).Count | Should -Be $before
            $global:PraGateAd.Users[0].extensionAttribute1 | Should -Be 'Converted'
        }
    }
    It 'refuses a legacy backup missing a required original attribute' {
        InModuleScope PRA.Directory {
            $plan=New-PraPlan $global:PraGate.Context 'user1' 'Convert'
            $record=($plan.Record | ConvertTo-Json -Depth 20 | ConvertFrom-Json -DateKind String)
            $record | Add-Member -NotePropertyName AddedToLicenseGroup -NotePropertyValue $false
            $record.Attributes.PSObject.Properties.Remove('msExchMailboxGuid')
            { Assert-PraStoredRecord $record -Legacy } | Should -Throw '*msExchMailboxGuid*'
        }
        @(Get-GateWrites $global:PraGate.Runtime).Count | Should -Be 0
    }
    It 'refuses a legacy group removal without the original group GUID' {
        $plan=New-PraPlan $global:PraGate.Context 'user1' 'Convert'
        $record=$plan.Record | ConvertTo-Json -Depth 20 | ConvertFrom-Json -DateKind String
        $record.PSObject.Properties.Remove('Licensing')
        $record | Add-Member -NotePropertyName AddedToLicenseGroup -NotePropertyValue $true
        $record | Add-Member -NotePropertyName LicenseGroupDN -NotePropertyValue 'CN=RecreatedGroup,DC=gate,DC=invalid'
        { New-PraPlan $global:PraGate.Context 'user1' 'Recover' $record } | Should -Throw '*GUID of the licence group*'
        @(Get-GateWrites $global:PraGate.Runtime).Count | Should -Be 0
    }
    It 'blocks autonomous sync with contradictory readonly mode/action/WhatIf guards' -ForEach @(
        @{SyncMode='Preview';SyncAction='Convert';NativeWhatIf=$false},@{SyncMode='Preview';SyncAction='Recover';NativeWhatIf=$false},
        @{SyncMode='Apply';SyncAction='Check';NativeWhatIf=$false},@{SyncMode='Apply';SyncAction='Convert';NativeWhatIf=$true}
    ) {
        $global:PraGate.Context.Mode=$SyncMode; $global:PraGate.Context.Action=$SyncAction; $global:PraGate.Context.AllowMutation=$true
        $global:PraGate.TestWhatIf=$NativeWhatIf
        InModuleScope PRA.Directory {
            Mock Import-PraProof { $global:PraGate.Counters.Writes++; throw 'SYNTHETIC: sync guard unexpectedly passed' }
            $WhatIfPreference=$global:PraGate.TestWhatIf
            try { Invoke-PraSync $global:PraGate.Context } finally { $WhatIfPreference=$false }
            $global:PraGate.Counters.Writes | Should -Be 0
        }
        @(Get-GateWrites $global:PraGate.Runtime).Count | Should -Be 0
    }
    It 'skips Entra Connect when Apply produced no AD change in this run' {
        $context=$global:PraGate.Context
        $context.Config.EntraConnect.Sync=$true
        $row=New-PraRow $context ([pscustomobject]@{ObjectGuid='00000000-0000-0000-0000-000000000001';SamAccountName='user1';UserPrincipalName='user1@gate.invalid';IsShared=$false})
        $row.ADVerified=$true; $row.ADApplied=$false; $row.FinalStatus='AlreadyDone'
        $context.Rows.Add($row)
        InModuleScope PRA.Directory {
            Mock Import-PraProof { throw 'SYNTHETIC: proof import should not run when no AD change was applied' }
            $records=@(Invoke-PraSync $global:PraGate.Context -Confirm:$false 6>&1)
            ($records | ForEach-Object { $_.MessageData.Message } | Out-String) | Should -Match 'No AD change in this run: no synchronisation needed'
        }
        $context.Issues.Count | Should -Be 0
        @($context.Rows.ToArray() | Where-Object { $_.ADApplied -eq $true }).Count | Should -Be 0
        @($context.Rows.ToArray() | Where-Object { $_.FinalStatus -eq 'Error' }).Count | Should -Be 0
        @($context.Rows.ToArray() | Where-Object { $_.PSObject.Properties['ADSyncStarted'] }).Count | Should -Be 0
        @(Get-GateWrites $global:PraGate.Runtime).Count | Should -Be 0
    }
    It 'performs no mutation or backup despite contradictory AllowMutation in readonly modes' -ForEach @(@{Mode='Preview';NativeWhatIf=$false},@{Mode='Preview';NativeWhatIf=$false},@{Mode='Apply';NativeWhatIf=$true}) {
        $context=New-GateContext $global:PraGate.Runtime -Mode $Mode
        $context.AllowMutation=$true
        $plans=@(New-PraPlan $context 'user1' 'Convert';New-PraPlan $context 'user2' 'Convert')
        $receipt=Invoke-PraAdBatch $context $plans 'Convert' -WhatIf:$NativeWhatIf
        $receipt | Should -BeNullOrEmpty
        @(Get-GateWrites $global:PraGate.Runtime).Count | Should -Be 0
        $context.BackupFiles.Count | Should -Be 0
    }
}

Describe 'ScopeOU native selection - subtree-aware synthetic fixture only' -Tag 'ScopeOU' {
    BeforeEach {
        $global:PraGate.Runtime=New-GateRuntime -Name 'scope-ou'
        $runtime=$global:PraGate.Runtime
        # Replace Get-ADUser in THIS temporary runtime only. The historical fixture
        # intentionally remains unchanged for all other Describe blocks.
        $scopeReader=@'
function Get-ADUser {
    [CmdletBinding()]
    param([object]$Identity,[string]$LDAPFilter,[string[]]$Properties,[string]$Server,
        [string]$SearchBase,[ValidateSet('Base','OneLevel','Subtree')][string]$SearchScope='Subtree')
    Assert-GateServer $Server
    Write-GateEvent 'Get-ADUser' $Identity $Server @{LDAPFilter=$LDAPFilter;Properties=$Properties;SearchBase=$SearchBase;SearchScope=$SearchScope;ExplicitSearchScope=$PSBoundParameters.ContainsKey('SearchScope')}
    if ($Identity -or -not $SearchBase -or $LDAPFilter -notmatch '^\(&\(homeMDB=\*\)\(\|(?:\(msExchRecipientTypeDetails=\d+\))+\)\)$') {
        throw 'SYNTHETIC ScopeOU: unsupported query; never use a real directory.'
    }
    $types=@([regex]::Matches($LDAPFilter,'msExchRecipientTypeDetails=(\d+)') | ForEach-Object { [long]$_.Groups[1].Value })
    foreach ($user in $global:PraGateAd.Users) {
        $dn=[string]$user.DistinguishedName
        $inside=switch ($SearchScope) {
            Base { $dn.Equals($SearchBase,[StringComparison]::OrdinalIgnoreCase) }
            OneLevel { $dn.Substring($dn.IndexOf(',')+1).Equals($SearchBase,[StringComparison]::OrdinalIgnoreCase) }
            Subtree { $dn.EndsWith(','+$SearchBase,[StringComparison]::OrdinalIgnoreCase) -or $dn.Equals($SearchBase,[StringComparison]::OrdinalIgnoreCase) }
        }
        if ($inside -and $user.homeMDB -and $user.msExchRecipientTypeDetails -in $types) { Copy-GateUser $user }
    }
}
'@
        $start=$global:PraGate.AdSource.IndexOf('function Get-ADUser {',[StringComparison]::Ordinal)
        $end=$global:PraGate.AdSource.IndexOf('function Get-ADGroup {',$start,[StringComparison]::Ordinal)
        if ($start -lt 0 -or $end -le $start) { throw 'ScopeOU fixture splice boundary missing.' }
        $source=$global:PraGate.AdSource.Substring(0,$start)+$scopeReader+"`r`n"+$global:PraGate.AdSource.Substring($end)
        $adModulePath=Join-Path $runtime.Modules 'ActiveDirectory\ActiveDirectory.psm1'
        [IO.File]::WriteAllText($adModulePath,$source,(New-Object Text.UTF8Encoding($true)))
        $env:PRA_GATE_STATE=$runtime.StatePath
        $env:PSModulePath=$runtime.Modules+';'+(Join-Path $PSHOME 'Modules')
        # Initialize-PraDirectory in the preceding Describe imports AD into the
        # Directory module's own session state. A global -Force import alone does
        # NOT replace that local binding. Reload the unchanged production module
        # to discard that state, then bind the exact physical synthetic module.
        Remove-Module PRA.Directory -Force -ErrorAction SilentlyContinue
        Get-Module ActiveDirectory -All | Remove-Module -Force -ErrorAction Stop
        Import-Module $adModulePath -Force -Global -ErrorAction Stop
        Import-Module (Join-Path $global:PraGate.Package 'module\PRA.Directory.psm1') -Force -Global -ErrorAction Stop
        $directory=Get-Module PRA.Directory
        (Get-Command Get-ADUser).Module.Path | Should -BeExactly $adModulePath
        (& $directory { (Get-Command Get-ADUser).Module.Path }) | Should -BeExactly $adModulePath -Because 'the product module, not only the test scope, must resolve the subtree-aware fixture'
        (& $directory { (Get-Command Get-ADUser).Parameters.ContainsKey('SearchScope') }) | Should -BeTrue
        $global:PraGate.Context=New-GateContext $runtime -Mode Preview
        $scope=$global:PraGate.Context.Config.Scope
        $scope.Mode='OU'; $scope.SearchBase='OU=Pilot,OU=Tests,DC=gate,DC=invalid'
        $scope.IncludeShared=$true; $scope.IncludeRoom=$false; $scope.IncludeEquip=$false
        $scope.CsvPath=''; $scope.GroupDN=''
        $global:PraGateAd.Users=@(1..4 | ForEach-Object { New-GateUser $_ })
        foreach ($user in $global:PraGateAd.Users) { $user.DistinguishedName='CN='+$user.SamAccountName+','+$scope.SearchBase }
        $global:PraGateAd.Users[2].msExchRecipientTypeDetails=[long]4
        $global:PraGateAd.Users[3].msExchRecipientTypeDetails=[long]4
        $global:PraGate.ScopeExpected=@($global:PraGateAd.Users | ForEach-Object { [string]$_.ObjectGUID } | Sort-Object)
    }
    AfterEach {
        @(Get-GateWrites $global:PraGate.Runtime).Count | Should -Be 0
        @(Get-GateEvents $global:PraGate.Runtime | Where-Object { $_.Server -and $_.Server -cne 'dc01.gate.invalid' }).Count | Should -Be 0
    }
    It 'selects exactly the four expected GUIDs: two user and two shared mailboxes without CSV or Identity' {
        $selected=@(Get-PraTarget -Context $global:PraGate.Context)
        $selected.Count | Should -Be 4
        (@($selected | ForEach-Object { [string]$_.ObjectGUID } | Sort-Object) -join '|') | Should -BeExactly ($global:PraGate.ScopeExpected -join '|')
        @($selected | Where-Object msExchRecipientTypeDetails -eq 1).Count | Should -Be 2
        @($selected | Where-Object msExchRecipientTypeDetails -eq 4).Count | Should -Be 2
        $queries=@(Get-GateEvents $global:PraGate.Runtime | Where-Object Operation -eq 'Get-ADUser')
        $queries.Count | Should -Be 1
        $queries[0].Identity | Should -BeNullOrEmpty
        $queries[0].Detail.SearchBase | Should -BeExactly $global:PraGate.Context.Config.Scope.SearchBase
        $queries[0].Detail.LDAPFilter | Should -BeExactly '(&(homeMDB=*)(|(msExchRecipientTypeDetails=1)(msExchRecipientTypeDetails=4)))'
        (Get-Command Get-ADUser).Module.Path | Should -BeExactly (Join-Path $global:PraGate.Runtime.Modules 'ActiveDirectory\ActiveDirectory.psm1')
    }
    It 'excludes eligible accounts outside SearchBase, including a sibling with a misleading OU suffix' {
        $outside=New-GateUser 5
        $lookalike=New-GateUser 6
        $lookalike.DistinguishedName='CN=user6,OU=NotPilot,OU=Tests,DC=gate,DC=invalid'
        $global:PraGateAd.Users+=@($outside,$lookalike)
        $selected=@(Get-PraTarget -Context $global:PraGate.Context)
        $selected.Count | Should -Be 4
        (@($selected | ForEach-Object { [string]$_.ObjectGUID } | Sort-Object) -join '|') | Should -BeExactly ($global:PraGate.ScopeExpected -join '|')
    }
    It 'includes a nested eligible account because the native AD query defaults implicitly to Subtree' {
        $nested=New-GateUser 5
        $nested.DistinguishedName='CN=user5,OU=Nested,'+$global:PraGate.Context.Config.Scope.SearchBase
        $global:PraGateAd.Users+=@($nested)
        $selected=@(Get-PraTarget -Context $global:PraGate.Context)
        $selected.Count | Should -Be 5
        @($selected | Where-Object ObjectGUID -eq $nested.ObjectGUID).Count | Should -Be 1
        $query=@(Get-GateEvents $global:PraGate.Runtime | Where-Object Operation -eq 'Get-ADUser')[0]
        $query.Detail.SearchScope | Should -BeExactly 'Subtree'
        $query.Detail.ExplicitSearchScope | Should -BeFalse
        # This inclusion is why the external exact-OU guard must reject a child OU.
    }
    It 'silently ignores an ineligible extra account (<Reason>); four results are not an exact-OU guard' -ForEach @(
        @{Reason='NoHomeMDB'},@{Reason='RemoteMailbox'},@{Reason='RoomMailbox'},@{Reason='EquipmentMailbox'}
    ) {
        $extra=New-GateUser 5
        $extra.DistinguishedName='CN=user5,'+$global:PraGate.Context.Config.Scope.SearchBase
        switch ($Reason) {
            NoHomeMDB { $extra.homeMDB=$null }
            RemoteMailbox { $extra.msExchRecipientTypeDetails=[long]2147483648; $extra.msExchRemoteRecipientType=[long]1 }
            RoomMailbox { $extra.msExchRecipientTypeDetails=[long]16 }
            EquipmentMailbox { $extra.msExchRecipientTypeDetails=[long]32 }
        }
        $global:PraGateAd.Users+=@($extra)
        $global:PraGateAd.Users.Count | Should -Be 5
        $selected=@(Get-PraTarget -Context $global:PraGate.Context)
        $selected.Count | Should -Be 4
        (@($selected | ForEach-Object { [string]$_.ObjectGUID } | Sort-Object) -join '|') | Should -BeExactly ($global:PraGate.ScopeExpected -join '|')
    }
    It 'applies the product exclusions in OU mode without proving that the dedicated OU contains only four accounts' -ForEach @(
        @{Exclusion='HealthMailbox'},@{Exclusion='SystemMailbox'},@{Exclusion='ExchangeDisplayName'},@{Exclusion='ConfiguredSam'}
    ) {
        $extra=New-GateUser 5
        $extra.DistinguishedName='CN=user5,'+$global:PraGate.Context.Config.Scope.SearchBase
        switch ($Exclusion) {
            HealthMailbox { $extra.SamAccountName='HealthMailbox-extra' }
            SystemMailbox { $extra.SamAccountName='SystemMailbox-extra' }
            ExchangeDisplayName { $extra.DisplayName='Microsoft Exchange Extra' }
            ConfiguredSam { $global:PraGate.Context.Config.Scope.ExcludeSamAccountNames=@('user5') }
        }
        $global:PraGateAd.Users+=@($extra)
        $selected=@(Get-PraTarget -Context $global:PraGate.Context)
        $selected.Count | Should -Be 4
        @($selected | Where-Object ObjectGUID -eq $extra.ObjectGUID).Count | Should -Be 0
    }
    It 'documents MaxObjects=4 truncation rather than changing production into an exact-set guard (<Order>)' -ForEach @(
        @{Order='BeforeExpected';Sam='aaa-extra'},@{Order='AfterExpected';Sam='zzz-extra'}
    ) {
        $extra=New-GateUser 5
        $extra.SamAccountName=$Sam
        $extra.DistinguishedName='CN='+$Sam+','+$global:PraGate.Context.Config.Scope.SearchBase
        $global:PraGateAd.Users+=@($extra)
        $all=@(Get-PraTarget -Context $global:PraGate.Context)
        $limited=@(Get-PraTarget -Context $global:PraGate.Context -MaxObjects 4)
        $all.Count | Should -Be 5
        $limited.Count | Should -Be 4
        ($limited.SamAccountName -join '|') | Should -BeExactly (($all | Select-Object -First 4).SamAccountName -join '|')
        if ($Order -eq 'BeforeExpected') {
            @($limited | Where-Object ObjectGUID -eq $extra.ObjectGUID).Count | Should -Be 1
            @($global:PraGate.ScopeExpected | Where-Object { $_ -notin @($limited.ObjectGUID | ForEach-Object { [string]$_ }) }).Count | Should -Be 1
        } else {
            (@($limited | ForEach-Object { [string]$_.ObjectGUID } | Sort-Object) -join '|') | Should -BeExactly ($global:PraGate.ScopeExpected -join '|')
        }
        # Both results have Count=4. Neither establishes the unbounded OU set.
    }
    It 'still refuses duplicate GUIDs before MaxObjects truncation' {
        $global:PraGateAd.Users+=@($global:PraGateAd.Users[0])
        { Get-PraTarget -Context $global:PraGate.Context -MaxObjects 4 } | Should -Throw '*same object is listed twice*'
    }
}

Describe 'OOM data-only raw codec and historical compatibility' -Tag 'OOM' {
    BeforeEach {
        $global:PraGate.Runtime=New-GateRuntime -Name 'oom-codec'
        $env:PRA_GATE_STATE=$global:PraGate.Runtime.StatePath
        $env:PSModulePath=$global:PraGate.Runtime.Modules+';'+(Join-Path $PSHOME 'Modules')
        Import-Module ActiveDirectory -Force -Global
        $global:PraGate.Context=New-GateContext $global:PraGate.Runtime
        $global:PraGate.Context.LogFile=Join-Path $global:PraGate.Runtime.Root 'logs\oom.log'
    }
    It 'uses real streaming writer/reader and forbids raw native graph deserialization' {
        $codec=Get-GateCodec
        $codec.Path | Should -BeExactly (Join-Path $global:PraGate.Package 'module\PRA.Backup.psm1')
        $text=[IO.File]::ReadAllText($codec.Path)
        $text | Should -Match 'XmlWriter'
        $text | Should -Match 'XmlReader'
        $text | Should -Match 'CreateNew'
        $text | Should -Not -Match 'PSSerializer|Import-Clixml|ReadAllText|ReadAllBytes'
        $directoryText=[IO.File]::ReadAllText((Join-Path $global:PraGate.Package 'module\PRA.Directory.psm1'))
        $directoryText | Should -Not -Match 'PSSerializer|Import-Clixml|ReadAllText'
        $runtime=$global:PraGate.Runtime
        (Get-FileHash (Join-Path $runtime.Package 'module\PRA.Backup.psm1')).Hash | Should -Be (Get-FileHash $codec.Path).Hash
    }
    It 'preserves every supported scalar, collection, binary and local native security byte with independent wire assertions' {
        $user=New-GateUser
        $native=& (Get-Command Get-ADUser).Module { New-GateNativeDescriptor }
        $user.nTSecurityDescriptor=$native
        $user.msExchMailboxSecurityDescriptor=$native.GetSecurityDescriptorBinaryForm()
        $sid=New-Object Security.Principal.SecurityIdentifier('S-1-5-21-100-200-300-3001')
        $sidBytes=New-Object byte[] $sid.BinaryLength; $sid.GetBinaryForm($sidBytes,0)
        $extras=[ordered]@{
            EmptyString='';Whitespace='  ';NullValue=$null;FalseValue=$false;Zero=[int]0
            ByteMax=[byte]255;SByteMin=[sbyte]-128;Int16Min=[int16]-32768;UInt16Max=[uint16]65535
            Int32Min=[int32]::MinValue;UInt32Max=[uint32]::MaxValue;Int64Min=[int64]::MinValue;UInt64Max=[uint64]::MaxValue
            SingleValue=[single]-1.25;DoubleValue=[double]::NaN;DecimalValue=[decimal]::Parse('1.2300',[Globalization.CultureInfo]::InvariantCulture)
            DateValue=[datetime]::SpecifyKind([datetime]'2026-09-07T01:02:03',[DateTimeKind]::Utc)
            OffsetValue=[datetimeoffset]::Parse('2026-09-07T01:02:03+02:00',[Globalization.CultureInfo]::InvariantCulture)
            SpanValue=[timespan]::FromTicks(-123456789);GuidValue=[guid]'00112233-4455-6677-8899-aabbccddeeff';SidValue=$sid;CharValue=[char]0
            ControlString=(' literal_x0041_ & < > '+[char]0+"`r`n`t"+[char]0xD800)
            EmptyBytes=[byte[]]@();EmptyArray=[string[]]@();Duplicates=[string[]]@('same','same','last')
            Nested=[object[]]@('first',$null,[object[]]@(),[object[]]@('nested','nested'),[byte[]](0,255))
        }
        foreach ($name in $extras.Keys) { $user | Add-Member -NotePropertyName $name -NotePropertyValue $extras[$name] }
        $utc='2026-09-07T01:02:03.0000000Z'
        $snapshot=ConvertTo-PraRawSnapshot -User $user -CapturedUtc $utc
        $snapshot.ObjectGUID | Should -BeOfType ([string])
        $snapshot.Attributes.Count | Should -Be @($user.PSObject.Properties).Count
        $snapshot.Attributes['nTSecurityDescriptor'].Kind | Should -BeExactly 'SecurityDescriptor'
        $snapshot.Attributes['nTSecurityDescriptor'].Value | Should -BeExactly ([Convert]::ToBase64String($native.GetSecurityDescriptorBinaryForm()))
        $snapshot.Attributes['SidValue'].Value | Should -BeExactly ([Convert]::ToBase64String($sidBytes))
        $snapshot.Attributes['FalseValue'].Value | Should -BeExactly 'false'
        $snapshot.Attributes['Zero'].Value | Should -BeExactly '0'
        $snapshot.Attributes['NullValue'].Kind | Should -BeExactly 'Null'
        $snapshot.Attributes['EmptyArray'].Kind | Should -BeExactly 'Collection'
        $snapshot.Attributes['EmptyBytes'].Kind | Should -BeExactly 'Binary'
        $snapshot.Attributes['UInt64Max'].Value | Should -BeExactly '18446744073709551615'
        $snapshot.Attributes['Int64Min'].Value | Should -BeExactly '-9223372036854775808'
        $snapshot.Attributes['SingleValue'].Value | Should -BeExactly ([Convert]::ToBase64String([BitConverter]::GetBytes($extras.SingleValue)))
        $snapshot.Attributes['DoubleValue'].Value | Should -BeExactly ([Convert]::ToBase64String([BitConverter]::GetBytes($extras.DoubleValue)))
        $snapshot.Attributes['DecimalValue'].Value | Should -BeExactly (([decimal]::GetBits($extras.DecimalValue)) -join '|')
        $snapshot.Attributes['DateValue'].Value | Should -BeExactly ($extras.DateValue.ToBinary().ToString([Globalization.CultureInfo]::InvariantCulture))
        $snapshot.Attributes['OffsetValue'].Value | Should -BeExactly ($extras.OffsetValue.Ticks.ToString()+'|'+$extras.OffsetValue.Offset.Ticks)
        $snapshot.Attributes['SpanValue'].Value | Should -BeExactly '-123456789'
        $snapshot.Attributes['GuidValue'].Value | Should -BeExactly '00112233-4455-6677-8899-aabbccddeeff'
        $snapshot.Attributes['CharValue'].Value | Should -BeExactly '0'
        foreach ($expected in @(
            @{Name='ByteMax';Type='Byte';Value='255'},@{Name='SByteMin';Type='SByte';Value='-128'},
            @{Name='Int16Min';Type='Int16';Value='-32768'},@{Name='UInt16Max';Type='UInt16';Value='65535'},
            @{Name='Int32Min';Type='Int32';Value='-2147483648'},@{Name='UInt32Max';Type='UInt32';Value='4294967295'}
        )) {
            $snapshot.Attributes[$expected.Name].Type | Should -BeExactly $expected.Type
            $snapshot.Attributes[$expected.Name].Value | Should -BeExactly $expected.Value
        }
        $snapshot.Attributes['Duplicates'].Items.Count | Should -Be 3
        ($snapshot.Attributes['Duplicates'].Items.Value -join '|') | Should -BeExactly 'same|same|last'
        $snapshot.Attributes['Nested'].Items.Count | Should -Be 5
        $snapshot.Attributes['Nested'].Items[1].Kind | Should -BeExactly 'Null'
        $snapshot.Attributes['Nested'].Items[2].Kind | Should -BeExactly 'Collection'
        $snapshot.Attributes['Nested'].Items[2].Items.Count | Should -Be 0
        $snapshot.Attributes['Nested'].Items[4].Kind | Should -BeExactly 'Binary'
        $path=Join-Path $global:PraGate.Runtime.Root 'all-types.clixml'
        @(Write-PraRawCapture -Context $global:PraGate.Context -LiteralPath $path -Snapshots @($snapshot)).Count | Should -Be 0
        $checked=Test-PraRawCapture -Context $global:PraGate.Context -LiteralPath $path -Records @(@{ObjectGuid=$snapshot.ObjectGUID}) -RawFormat 'PraDataOnlyClixml-v1' -ExpectedSnapshots @($snapshot)
        $checked.Count | Should -Be 1
        $checked.Bytes | Should -Be (Get-Item -LiteralPath $path).Length
        $wire=@(Import-Clixml -LiteralPath $path)
        $wire.Count | Should -Be 1
        Assert-GateWireSnapshot $wire[0] $snapshot
        $wire[0].Attributes['ControlString'][0].Value | Should -BeExactly $extras.ControlString
        $wire[0].Attributes['Whitespace'][0].Value | Should -BeExactly '  '
        $before=(Get-FileHash $path).Hash
        { Write-PraRawCapture -Context $global:PraGate.Context -LiteralPath $path -Snapshots @($snapshot) } | Should -Throw
        (Get-FileHash $path).Hash | Should -BeExactly $before
        Save-GateOomEvidence 'all-types' $global:PraGate.Runtime @{Snapshots=$checked.Count;Attributes=$snapshot.Attributes.Count;Bytes=$checked.Bytes;NativeAceCount=$native.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier]).Count;WireCompared=$true;NativeBinaryExact=$true} @($path)
    }
    It 'captures the declared native ADUser properties without walking adapter metadata' -Tag 'NativeAdapter' {
        # Compile an isolated synthetic type even when PSSA has loaded the real AD type metadata.
        # No AD assembly reference, provider or directory access; instantiate this assembly's type only.
        $source=@'
namespace Microsoft.ActiveDirectory.Management {
    public sealed class ADUser {
        private readonly System.Collections.Generic.SortedDictionary<string, object> names =
            new System.Collections.Generic.SortedDictionary<string, object>();
        public static int MetadataReads;
        public System.Guid ObjectGUID { get; set; }
        public string DistinguishedName { get; set; }
        public string UnmanagedForensics { get; set; }
        public object targetAddress { get; set; }
        public bool mDBUseDefaults { get; set; }
        public byte[] msExchMailboxGuid { get; set; }
        public object Opaque { get; set; }
        public System.Collections.ICollection PropertyNames { get { return names.Keys; } }
        public System.Collections.Generic.ICollection<string> AddedProperties { get { MetadataReads++; throw new System.InvalidOperationException("Adapter metadata read"); } }
        public System.Collections.Generic.ICollection<string> RemovedProperties { get { MetadataReads++; throw new System.InvalidOperationException("Adapter metadata read"); } }
        public System.Collections.Generic.ICollection<string> ModifiedProperties { get { MetadataReads++; throw new System.InvalidOperationException("Adapter metadata read"); } }
        public int PropertyCount { get { MetadataReads++; return names.Count; } }
        public void Declare(string name) { names.Add(name, null); }
    }
}
'@
        # CodeDom does not compile on .NET: Add-Type (Roslyn) builds the synthetic native-shape type in a dynamic assembly.
        $type=Add-Type -TypeDefinition $source -PassThru | Where-Object FullName -ceq 'Microsoft.ActiveDirectory.Management.ADUser'
        $type | Should -Not -BeNullOrEmpty
        $type.Assembly.GetName().Name | Should -Not -Be 'Microsoft.ActiveDirectory.Management'
        $user=[Activator]::CreateInstance($type)
        $user.ObjectGUID=[guid]'00000000-0000-0000-0000-000000000001'
        $user.DistinguishedName='CN=NativeShape,OU=Tests,DC=gate,DC=invalid'
        $user.UnmanagedForensics='keep this attribute'
        $user.msExchMailboxGuid=[byte[]](0,1,127,255)
        $names=@('ObjectGUID','DistinguishedName','UnmanagedForensics','targetAddress','mDBUseDefaults','msExchMailboxGuid')
        foreach ($name in $names) { $user.Declare($name) }
        $metadataReads=$type.GetField('MetadataReads'); $metadataReads.SetValue($null,0)
        $snapshot=ConvertTo-PraRawSnapshot -User $user -CapturedUtc '2026-09-08T00:00:00.0000000Z'
        $snapshot.Attributes.Count | Should -Be $names.Count
        foreach ($name in $names) { $snapshot.Attributes.Contains($name) | Should -BeTrue }
        foreach ($name in @('PropertyNames','AddedProperties','RemovedProperties','ModifiedProperties','PropertyCount')) {
            $snapshot.Attributes.Contains($name) | Should -BeFalse
        }
        $snapshot.Attributes['UnmanagedForensics'].Value | Should -BeExactly 'keep this attribute'
        $snapshot.Attributes['targetAddress'].Kind | Should -BeExactly 'Null'
        $snapshot.Attributes['mDBUseDefaults'].Value | Should -BeExactly 'false'
        $snapshot.Attributes['msExchMailboxGuid'].Value | Should -BeExactly 'AAF//w=='
        $metadataReads.GetValue($null) | Should -Be 0
        $path=Join-Path $global:PraGate.Runtime.Root 'native-adapter.clixml'
        Write-PraRawCapture -Context $global:PraGate.Context -LiteralPath $path -Snapshots @($snapshot)
        $checked=Test-PraRawCapture -Context $global:PraGate.Context -LiteralPath $path -Records @(@{ObjectGuid=$snapshot.ObjectGUID}) -RawFormat 'PraDataOnlyClixml-v1' -ExpectedSnapshots @($snapshot)
        $checked.Count | Should -Be 1
        $user.Declare('Opaque'); $user.Opaque=[uri]'https://gate.invalid/'
        { ConvertTo-PraRawSnapshot -User $user -CapturedUtc '2026-09-08T00:00:00.0000000Z' } | Should -Throw '*attribute=Opaque*'
        $user.Opaque=$null; $user.Declare('NotReturned')
        { ConvertTo-PraRawSnapshot -User $user -CapturedUtc '2026-09-08T00:00:00.0000000Z' } | Should -Throw '*attribute=NotReturned*'
        @(Get-GateWrites $global:PraGate.Runtime).Count | Should -Be 0
    }
    It 'does not discard metadata-like names from an ordinary <Shape>' -Tag 'NativeAdapter' -ForEach @(@{Shape='Object'},@{Shape='Dictionary'}) {
        $values=[ordered]@{ObjectGUID=[guid]'00000000-0000-0000-0000-000000000001';DistinguishedName='CN=Plain,DC=gate,DC=invalid';PropertyNames='forensic value';PropertyCount=42}
        $user=if ($Shape -eq 'Object') { [pscustomobject]$values } else { $values }
        $snapshot=ConvertTo-PraRawSnapshot -User $user -CapturedUtc '2026-09-08T00:00:00.0000000Z'
        $snapshot.Attributes.Count | Should -Be 4
        $snapshot.Attributes['PropertyNames'].Value | Should -BeExactly 'forensic value'
        $snapshot.Attributes['PropertyCount'].Value | Should -BeExactly '42'
    }
    It 'rejects an unsupported complex attribute without walking its getter or using a ToString fallback' {
        if (-not ('PraGateOpaqueValue' -as [type])) {
            Add-Type -TypeDefinition 'public sealed class PraGateOpaqueValue { public static int GetterCalls; public static int StringCalls; public PraGateOpaqueValue Child { get { GetterCalls++; return this; } } public static string LastStringStack; public static System.Collections.Generic.List<string> StringStacks=new System.Collections.Generic.List<string>(); public static int BinderCalls; public static int UnexpectedCalls; public override string ToString() { StringCalls++; var frames=new System.Diagnostics.StackTrace().GetFrames(); /* The engine''s own parameter binder converts the value to text when a command is bound to it. Every frame between ToString and the binder is a PSObject method (the JIT may inline some of them, so their number is not fixed); a ToString called from anything else is not accepted. */ bool binder=false; int j=1; while(j<frames.Length){var m=frames[j].GetMethod(); if(m.DeclaringType!=null && m.DeclaringType.FullName=="System.Management.Automation.PSObject"){j++;continue;} break;} if(j>1 && j<frames.Length){var bind=frames[j].GetMethod(); binder=bind.DeclaringType!=null && bind.DeclaringType.FullName=="System.Management.Automation.ParameterBinderBase" && bind.Name=="BindParameter";} if(binder){BinderCalls++;}else{UnexpectedCalls++;} var text=new System.Text.StringBuilder(); for(int i=0;i<System.Math.Min(8,frames.Length);i++){var method=frames[i].GetMethod(); text.AppendLine((method.DeclaringType==null?"<dynamic>":method.DeclaringType.FullName)+"."+method.Name);} LastStringStack=text.ToString(); if(StringStacks.Count<8){StringStacks.Add(LastStringStack);} return "opaque"; } }'
        }
        [PraGateOpaqueValue]::GetterCalls=0; [PraGateOpaqueValue]::StringCalls=0; [PraGateOpaqueValue]::BinderCalls=0; [PraGateOpaqueValue]::UnexpectedCalls=0; [PraGateOpaqueValue]::LastStringStack=''; [PraGateOpaqueValue]::StringStacks.Clear()
        $user=New-GateUser; $user | Add-Member -NotePropertyName Opaque -NotePropertyValue (New-Object PraGateOpaqueValue)
        $fixtureStringCalls=[PraGateOpaqueValue]::StringCalls; $fixtureStringStack=[PraGateOpaqueValue]::LastStringStack
        # PowerShell transcription can stringify New-Object/Add-Member output during arrangement.
        # Compare a no-op invocation, then reset at the actual product boundary.
        [PraGateOpaqueValue]::GetterCalls=0; [PraGateOpaqueValue]::StringCalls=0; [PraGateOpaqueValue]::BinderCalls=0; [PraGateOpaqueValue]::UnexpectedCalls=0; [PraGateOpaqueValue]::LastStringStack=''; [PraGateOpaqueValue]::StringStacks.Clear()
        & { param($InputValue) $null=$InputValue } $user
        $noopStringCalls=[PraGateOpaqueValue]::StringCalls; $noopGetterCalls=[PraGateOpaqueValue]::GetterCalls
        $noopBinderCalls=[PraGateOpaqueValue]::BinderCalls; $noopUnexpectedCalls=[PraGateOpaqueValue]::UnexpectedCalls; $noopStack=[PraGateOpaqueValue]::LastStringStack
        [PraGateOpaqueValue]::GetterCalls=0; [PraGateOpaqueValue]::StringCalls=0; [PraGateOpaqueValue]::BinderCalls=0; [PraGateOpaqueValue]::UnexpectedCalls=0; [PraGateOpaqueValue]::LastStringStack=''; [PraGateOpaqueValue]::StringStacks.Clear()
        { ConvertTo-PraRawSnapshot -User $user -CapturedUtc '2026-09-07T00:00:00.0000000Z' } | Should -Throw '*attribute=Opaque*'
        $observed=@{FixtureToStringCalls=$fixtureStringCalls;FixtureToStringStack=$fixtureStringStack;NoopGetterCalls=$noopGetterCalls;NoopToStringCalls=$noopStringCalls;NoopBinderCalls=$noopBinderCalls;NoopUnexpectedCalls=$noopUnexpectedCalls;NoopStack=$noopStack;ProductGetterCalls=[PraGateOpaqueValue]::GetterCalls;ProductToStringCalls=[PraGateOpaqueValue]::StringCalls;ProductBinderCalls=[PraGateOpaqueValue]::BinderCalls;ProductUnexpectedCalls=[PraGateOpaqueValue]::UnexpectedCalls;ProductStack=[PraGateOpaqueValue]::LastStringStack;ProductStacks=[PraGateOpaqueValue]::StringStacks.ToArray()}
        [PraGateOpaqueValue]::GetterCalls=0; [PraGateOpaqueValue]::StringCalls=0; [PraGateOpaqueValue]::BinderCalls=0; [PraGateOpaqueValue]::UnexpectedCalls=0; [PraGateOpaqueValue]::LastStringStack=''; [PraGateOpaqueValue]::StringStacks.Clear()
        [void]([string]$user.Opaque)
        $observed.ExplicitCastToStringCalls=[PraGateOpaqueValue]::StringCalls; $observed.ExplicitCastBinderCalls=[PraGateOpaqueValue]::BinderCalls; $observed.ExplicitCastUnexpectedCalls=[PraGateOpaqueValue]::UnexpectedCalls; $observed.ExplicitCastStack=[PraGateOpaqueValue]::LastStringStack
        Save-GateOomEvidence 'opaque-call-boundary' $global:PraGate.Runtime $observed
        $observed.ProductGetterCalls | Should -Be 0
        $observed.ProductUnexpectedCalls | Should -Be 0 -Because 'no fallback ToString is permitted; only the exact engine binder frame sequence is classified separately'
        $observed.ProductToStringCalls | Should -Be $observed.ProductBinderCalls
        $observed.NoopUnexpectedCalls | Should -Be 0
        $observed.ExplicitCastUnexpectedCalls | Should -BeGreaterThan 0 -Because 'the classifier must detect an actual explicit string conversion'
        @(Get-GateWrites $global:PraGate.Runtime).Count | Should -Be 0
    }
    It 'accepts safe schema <Version> historical ordinary fixtures without native deserialization' -ForEach @(@{Version=1},@{Version=2}) {
        $context=$global:PraGate.Context; $runtime=$global:PraGate.Runtime
        $plan=New-PraPlan $context 'user1' 'Convert'
        $record=$plan.Record | ConvertTo-Json -Depth 30 | ConvertFrom-Json -DateKind String
        if ($Version -eq 1) { $record | Add-Member AddedToLicenseGroup $false }
        $raw=Join-Path $runtime.Root 'historical.clixml'
        # This legacy graph is an ordinary bounded fake, never an ActiveDirectorySecurity.
        [IO.File]::WriteAllText($raw,[Management.Automation.PSSerializer]::Serialize(@((New-GateUser)),30))
        $path=Join-Path $runtime.Root 'historical.json'
        $data=[ordered]@{SchemaVersion=$Version;Operation='Convert';Environment=$context.Config.Environment;Records=@($record);RawFile='historical.clixml';RawHash=(Get-PraHash $raw)}
        [IO.File]::WriteAllText($path,($data | ConvertTo-Json -Depth 30))
        [IO.File]::WriteAllText(($path+'.sha256'),(Get-PraHash $path))
        $receipt=Import-PraBackup $context $path
        $receipt.Data.SchemaVersion | Should -Be $Version
        $receipt.Data.Records[0].Attributes.msExchMailboxGuid.Value | Should -BeExactly $record.Attributes.msExchMailboxGuid.Value
        $receipt.Legacy | Should -Be ($Version -eq 1)
        @(Get-GateWrites $runtime).Count | Should -Be 0
    }
    It 'recognizes legacy shape <Shape> only with a direct provable user GUID' -ForEach @(
        @{Shape='Direct';Accept=$true},@{Shape='ArrayWrapper';Accept=$true},@{Shape='NestedGuidOnly';Accept=$false},@{Shape='UnresolvedRef';Accept=$false}
    ) {
        $id='00000000-0000-0000-0000-000000000001'
        $nested='<Obj N="Acl"><MS><G N="ObjectGUID">99999999-9999-9999-9999-999999999999</G></MS></Obj>'
        $body='<Obj RefId="0"><MS><G N="ObjectGUID">'+$id+'</G>'+$nested+'</MS></Obj>'
        switch ($Shape) {
            'ArrayWrapper' { $body='<Obj RefId="3"><LST>'+$body+'</LST></Obj>' }
            'NestedGuidOnly' { $body='<Obj RefId="0"><MS>'+$nested+'</MS></Obj>' }
            'UnresolvedRef' { $body='<Obj RefId="0"><MS><Ref N="ObjectGUID" RefId="876" />'+$nested+'</MS></Obj>' }
        }
        $path=Join-Path $global:PraGate.Runtime.Root ($Shape+'.clixml')
        [IO.File]::WriteAllText($path,('<Objs Version="1.1.0.1" xmlns="http://schemas.microsoft.com/powershell/2004/04">'+$body+'</Objs>'))
        $invoke={ Test-PraRawCapture -Context $global:PraGate.Context -LiteralPath $path -Records @(@{ObjectGuid=$id}) -RawFormat '' }
        if ($Accept) { $checked=& $invoke; $checked.Count | Should -Be 1; $checked.ObjectGuids[0] | Should -BeExactly $id }
        else { $invoke | Should -Throw }
    }
    It 'rejects malformed raw stream <Fault> and compares unmanaged attributes against the expected snapshots' -ForEach @(
        @{Fault='Truncated'},@{Fault='ExtraRoot'},@{Fault='Dtd'},@{Fault='WrongMarkerCase'},@{Fault='UnknownKind'},@{Fault='UnmanagedValue'}
    ) {
        $context=$global:PraGate.Context
        $user=New-GateUser; $user | Add-Member -NotePropertyName UnmanagedForensics -NotePropertyValue 'original-forensics'
        $snapshot=ConvertTo-PraRawSnapshot -User $user -CapturedUtc '2026-09-07T00:00:00.0000000Z'
        $path=Join-Path $global:PraGate.Runtime.Root ($Fault+'.clixml')
        Write-PraRawCapture -Context $context -LiteralPath $path -Snapshots @($snapshot)
        $records=@(@{ObjectGuid=$snapshot.ObjectGUID})
        if ($Fault -eq 'Truncated') {
            $stream=[IO.File]::Open($path,[IO.FileMode]::Open,[IO.FileAccess]::Write)
            try { $stream.SetLength($stream.Length-20) } finally { $stream.Dispose() }
        } elseif ($Fault -eq 'ExtraRoot') { [IO.File]::AppendAllText($path,'<Objs />') }
        elseif ($Fault -eq 'Dtd') { [IO.File]::WriteAllText($path,'<!DOCTYPE Objs [<!ENTITY blocked SYSTEM "file:///C:/PRA-GATE-NONEXISTENT">]><Objs xmlns="http://schemas.microsoft.com/powershell/2004/04" Version="1.1.0.1">&blocked;</Objs>') }
        else {
            # A tiny already data-only test document; no legacy/native object graph is loaded.
            (Get-Item -LiteralPath $path).Length | Should -BeLessThan 64KB
            $document=New-Object Xml.XmlDocument; $document.XmlResolver=$null; $document.Load($path)
            $namespace=New-Object Xml.XmlNamespaceManager($document.NameTable); $namespace.AddNamespace('p','http://schemas.microsoft.com/powershell/2004/04')
            switch ($Fault) {
                'WrongMarkerCase' { $document.SelectSingleNode('//p:S[@N="RawFormat"]',$namespace).InnerText='pradataonlyclixml-v1' }
                'UnknownKind' { $document.SelectSingleNode('//p:S[@N="Kind"]',$namespace).InnerText='Unrecognized' }
                'UnmanagedValue' { $document.SelectSingleNode('//p:En[p:S[@N="Key"]="UnmanagedForensics"]//p:S[@N="Value"]',$namespace).InnerText='tampered-forensics' }
            }
            $document.Save($path)
        }
        if ($Fault -eq 'UnmanagedValue') {
            # Records-only validation cannot know this unmanaged value; exact plan comparison must.
            (Test-PraRawCapture -Context $context -LiteralPath $path -Records $records -RawFormat 'PraDataOnlyClixml-v1').Count | Should -Be 1
        }
        { Test-PraRawCapture -Context $context -LiteralPath $path -Records $records -RawFormat 'PraDataOnlyClixml-v1' -ExpectedSnapshots @($snapshot) } | Should -Throw
        @(Get-GateWrites $global:PraGate.Runtime).Count | Should -Be 0
    }
    It 'rejects schema 3 marker <Marker> even with a correct JSON hash' -ForEach @(@{Marker='pradataonlyclixml-v1'},@{Marker='PraDataOnlyClixml-v2'},@{Marker=''}) {
        $context=$global:PraGate.Context
        $plan=New-PraPlan $context 'user1' 'Convert'
        $receipt=& (Get-Module PRA.Directory) { param($c,$p) Save-PraBatch $c @($p) 'Convert' } $context $plan
        $data=[IO.File]::ReadAllText($receipt.Path) | ConvertFrom-Json -DateKind String; $data.RawFormat=$Marker
        [IO.File]::WriteAllText($receipt.Path,($data | ConvertTo-Json -Depth 30))
        [IO.File]::WriteAllText(($receipt.Path+'.sha256'),(Get-PraHash $receipt.Path))
        $fresh=New-GateContext $global:PraGate.Runtime
        { Import-PraBackup $fresh $receipt.Path } | Should -Throw '*Format*'
        @(Get-GateWrites $global:PraGate.Runtime).Count | Should -Be 0
    }
}

Describe 'Receipt fingerprint string-array compatibility and limits' -Tag 'OOM' {
    BeforeAll {
        $fingerprintModule=Get-Module PRA.Directory
        function Write-GateFingerprintReference {
            param([IO.BinaryWriter]$Writer,[AllowNull()]$Value)
            if ($null -eq $Value) { $Writer.Write([byte]0); return }
            if ($Value -is [array]) {
                $Writer.Write([byte]7); $Writer.Write([int]$Value.Length)
                foreach ($item in $Value) { Write-GateFingerprintReference -Writer $Writer -Value $item }
                return
            }
            if ($Value -is [string]) {
                $Writer.Write([byte]1); $Writer.Write([int]$Value.Length)
                foreach ($character in $Value.ToCharArray()) { $Writer.Write([uint16]$character) }
                return
            }
            if ($Value -is [bool]) { $Writer.Write([byte]2); $Writer.Write([bool]$Value); return }
            if ($Value -is [int]) { $Writer.Write([byte]3); $Writer.Write([int]$Value); return }
            throw 'Unsupported value in the independent fingerprint test reference.'
        }
    }
    It 'preserves exact UTF-16 wire bytes and node counts for <Case>' -ForEach @(
        @{Case='Strings';Nodes=10;Data=[string[]]@('','duplicate','duplicate',('x'*1023),('x'*1024),('x'*1025),('x'*2049),([string][char]0xD800),([string][char]0x00E9+[char]0+[char]0x6F22))},
        @{Case='Mixed';Nodes=5;Data=[object[]]@('same',$null,[int]42,$false)},
        @{Case='Nested';Nodes=9;Data=[object[]]@([string[]]@('first','last'),[object[]]@([string[]]@('inner'),$null),'end')}
    ) {
        $expectedStream=New-Object IO.MemoryStream
        $expectedWriter=New-Object IO.BinaryWriter($expectedStream)
        $actualStream=New-Object IO.MemoryStream
        $actualWriter=New-Object IO.BinaryWriter($actualStream)
        try {
            Write-GateFingerprintReference -Writer $expectedWriter -Value $Data
            $state=@{Writer=$actualWriter;Characters=(New-Object char[] 1024);Bytes=(New-Object byte[] 2048);Nodes=0L}
            & $fingerprintModule { param($s,$v) Write-PraDataFingerprint -State $s -Value $v } $state $Data
            $expectedWriter.Flush(); $actualWriter.Flush()
            [Convert]::ToBase64String($actualStream.ToArray()) | Should -BeExactly ([Convert]::ToBase64String($expectedStream.ToArray()))
            $state.Nodes | Should -Be $Nodes
        }
        finally { $expectedWriter.Dispose(); $expectedStream.Dispose(); $actualWriter.Dispose(); $actualStream.Dispose() }
    }
    It 'preserves <Case> errors, partial bytes and node accounting' -ForEach @(
        @{Case='Depth64';Depth=63;InitialNodes=0L;Nodes=3L;ExpectedError='';Written=2},
        @{Case='Depth65';Depth=64;InitialNodes=0L;Nodes=1L;ExpectedError='*Receipt data too deep or cyclic*';Written=0},
        @{Case='NodeLimit';Depth=0;InitialNodes=9999998L;Nodes=10000001L;ExpectedError='*Receipt data too large*';Written=1}
    ) {
        $expectedStream=New-Object IO.MemoryStream
        $expectedWriter=New-Object IO.BinaryWriter($expectedStream)
        $actualStream=New-Object IO.MemoryStream
        $actualWriter=New-Object IO.BinaryWriter($actualStream)
        try {
            $values=[string[]]@('first','last')
            $expectedWriter.Write([byte]7); $expectedWriter.Write([int]2)
            for ($index=0;$index -lt $Written;$index++) { Write-GateFingerprintReference -Writer $expectedWriter -Value $values[$index] }
            $state=@{Writer=$actualWriter;Characters=(New-Object char[] 1024);Bytes=(New-Object byte[] 2048);Nodes=$InitialNodes}
            $invoke={ & $fingerprintModule { param($s,$v,$d) Write-PraDataFingerprint -State $s -Value $v -Depth $d } $state $values $Depth }
            if ($ExpectedError) { $invoke | Should -Throw $ExpectedError }
            else { & $invoke }
            $expectedWriter.Flush(); $actualWriter.Flush()
            [Convert]::ToBase64String($actualStream.ToArray()) | Should -BeExactly ([Convert]::ToBase64String($expectedStream.ToArray()))
            $state.Nodes | Should -Be $Nodes
        }
        finally { $expectedWriter.Dispose(); $expectedStream.Dispose(); $actualWriter.Dispose(); $actualStream.Dispose() }
    }
}

Describe 'OOM permission cache, receipt identity and thirteen shared snapshots' -Tag 'OOM' {
    BeforeEach {
        $global:PraGate.Runtime=New-GateRuntime -Name 'oom-shared' -Shared13
        $env:PRA_GATE_STATE=$global:PraGate.Runtime.StatePath
        $env:PSModulePath=$global:PraGate.Runtime.Modules+';'+(Join-Path $PSHOME 'Modules')
        Import-Module ActiveDirectory -Force -Global
        $global:PraGate.Context=New-GateContext $global:PraGate.Runtime
        $global:PraGate.Context.LogFile=Join-Path $global:PraGate.Runtime.Root 'logs\oom-shared.log'
    }
    It 'captures all thirteen shared native ACL snapshots with equivalent de-duplicated rights and fewer repeated group reads' {
        $context=$global:PraGate.Context; $runtime=$global:PraGate.Runtime
        $plans=@(1..13 | ForEach-Object { New-PraPlan $context ('user'+$_) 'Convert' })
        $plans.Count | Should -Be 13
        $expected=@($global:PraGateAd.TrusteeUsers | Where-Object SamAccountName -ne 'trustee8' | ForEach-Object UserPrincipalName | Sort-Object)
        foreach ($plan in $plans) {
            $plan.Record.IsShared | Should -BeTrue
            @($plan.User.PSObject.Properties.Name).Count | Should -Be 3
            foreach ($right in @('FullAccess','SendAs','SendOnBehalf')) {
                @($plan.Record.SharedPermissions[$right]).Count | Should -Be $expected.Count
                (@($plan.Record.SharedPermissions[$right]) | Sort-Object) -join '|' | Should -BeExactly ($expected -join '|')
            }
            $captured=@(Get-GateEvents $runtime | Where-Object { $_.Operation -eq 'NativeSecurityDescriptor' -and $_.Identity -eq $plan.Record.ObjectGuid })[0]
            $plan.RawSnapshot.Attributes['nTSecurityDescriptor'].Value | Should -BeExactly $captured.Detail.NtBase64
            $plan.RawSnapshot.Attributes['msExchMailboxSecurityDescriptor'].Value | Should -BeExactly $captured.Detail.MailboxBase64
            $captured.Detail.AceCount | Should -BeGreaterOrEqual 100
            $captured.Detail.IdentityType | Should -BeExactly 'System.Security.Principal.SecurityIdentifier'
        }
        $events=@(Get-GateEvents $runtime)
        $groupCalls=@($events | Where-Object Operation -eq 'Get-ADGroupMember')
        $distinctGroups=@($groupCalls.Identity | Sort-Object -Unique)
        $groupCalls.Count | Should -Be $distinctGroups.Count
        $groupCalls.Count | Should -BeLessThan 13
        $memberReads=@($events | Where-Object { $_.Operation -eq 'Get-ADUser' -and $_.Identity -like 'CN=Trustee*' })
        $memberReads.Count | Should -Be $global:PraGateAd.TrusteeUsers.Count
        @($events | Where-Object { $_.Operation -eq 'Get-ADUser' -and '*' -in $_.Detail.Properties }).Count | Should -Be 13
        @(Get-GateWrites $runtime).Count | Should -Be 0
        InModuleScope PRA.Directory {
            $cache=Get-PraPermissionCache $global:PraGate.Context
            $cache.MaxEntries | Should -Be 512; $cache.MaxUpns | Should -Be 100000; $cache.MaxCharacters | Should -Be 8000000
            $script:PermissionCaches.GetType().FullName | Should -Match 'ConditionalWeakTable'
            foreach ($entry in $cache.Entries.Values) {
                @($entry.Upns | Where-Object { $_ -isnot [string] }).Count | Should -Be 0
                $entry.Keys | Should -Not -Contain 'Object'
            }
            $global:PraGate.Context.Keys | Should -Not -Contain 'PermissionCache'
        }
        Save-GateOomEvidence '13-shared-capture' $runtime @{Snapshots=$plans.Count;GroupExpansionReads=$groupCalls.Count;DistinctGroups=$distinctGroups.Count;MemberUserReads=$memberReads.Count;UniqueUpnsPerRight=$expected.Count;NativeAclBytesExact=$true;ADWrites=0}
    }
    It 'ignores the permission entries of an account no longer in AD and reports them as one warning per mailbox' {
        $context=$global:PraGate.Context
        $global:PraGateAd.OrphanSid='S-1-5-21-100-200-300-9999'
        $plan=New-PraPlan $context 'user1' 'Convert'
        $expected=@($global:PraGateAd.TrusteeUsers | Where-Object SamAccountName -ne 'trustee8' | ForEach-Object UserPrincipalName | Sort-Object)
        foreach ($right in @('FullAccess','SendAs')) { (@($plan.Record.SharedPermissions[$right]) | Sort-Object) -join '|' | Should -BeExactly ($expected -join '|') }
        $plan.Row.Warnings | Should -Match 'FullAccess S-1-5-21-100-200-300-9999'
        $plan.Row.Warnings | Should -Match 'SendAs S-1-5-21-100-200-300-9999'
        & (Get-Module PRA.Directory) { param($c,$p) Write-PraAdDelta -Context $c -Plan $p } $context $plan
        $context.Warnings | Should -Be 1
        $context.WarningList.Count | Should -Be 1
        $context.WarningList[0].Message | Should -Match 'user1: 2 permission entries ignored'
        $context.Issues.Count | Should -Be 0
        [IO.File]::ReadAllText($context.LogFile) | Should -Match '\[WARN  \] user1: 2 permission entries ignored'
        @(Get-GateWrites $global:PraGate.Runtime).Count | Should -Be 0
    }
    It 'limits full reads to capture and never uses permission cache for fresh licensing or AD preconditions' {
        $context=$global:PraGate.Context
        $null=New-PraPlan $context 'user2' 'Convert'
        $global:PraGateAd.Users[0].msExchRecipientTypeDetails=[long]1
        $first=New-PraPlan $context 'user1' 'Convert'
        $before=@(Get-GateEvents $global:PraGate.Runtime | Where-Object Operation -eq 'Get-ADGroup').Count
        $global:PraGateAd.Group.member=@($global:PraGateAd.Users[0].DistinguishedName)
        $second=New-PraPlan $context 'user1' 'Convert'
        $first.Record.Licensing.WasMember | Should -BeFalse
        $second.Record.Licensing.WasMember | Should -BeTrue
        @(Get-GateEvents $global:PraGate.Runtime | Where-Object Operation -eq 'Get-ADGroup').Count | Should -BeGreaterThan $before
        $null=Get-PraUser $context 'user1'
        $last=@(Get-GateEvents $global:PraGate.Runtime | Where-Object Operation -eq 'Get-ADUser')[-1]
        $last.Detail.Properties | Should -Not -Contain '*'
        $last.Detail.Properties | Should -Not -Contain 'nTSecurityDescriptor'
        $global:PraGateAd.Users[0].uSNChanged++
        { & (Get-Module PRA.Directory) { param($c,$p) Assert-PraCurrentState $c $p $p.Record.Attributes $p.Record.Licensing.WasMember } $context $second } | Should -Throw '*uSNChanged*'
        @(Get-GateWrites $global:PraGate.Runtime).Count | Should -Be 0
    }
    It 'invalidates permissions for context identity, DC, exclusion policy and directory reinitialization' -ForEach @(@{Change='Context'},@{Change='DC'},@{Change='Policy'},@{Change='Initialize'}) {
        $context=$global:PraGate.Context
        $null=New-PraPlan $context 'user1' 'Convert'
        $before=@(Get-GateEvents $global:PraGate.Runtime | Where-Object Operation -eq 'Get-ADGroupMember').Count
        switch ($Change) {
            'Context' { $context=New-GateContext $global:PraGate.Runtime }
            'DC' { $context.Server='dc02.gate.invalid'; $global:PraGateAd.Server=$context.Server }
            'Policy' { $context.Config.SharedMailbox.ExcludeTrusteeSamAccountNames+=@('trustee1') }
            'Initialize' { Initialize-PraDirectory $context }
        }
        $plan=New-PraPlan $context 'user2' 'Convert'
        @(Get-GateEvents $global:PraGate.Runtime | Where-Object Operation -eq 'Get-ADGroupMember').Count | Should -BeGreaterThan $before
        if ($Change -eq 'Policy') { $plan.Record.SharedPermissions.FullAccess | Should -Not -Contain 'trustee1@gate.invalid' }
        @(Get-GateWrites $global:PraGate.Runtime).Count | Should -Be 0
    }
    It 'never caches partial group success after <Fault>, while individually completed users may be reused' -ForEach @(@{Fault='MemberRead'},@{Fault='Enumeration'}) {
        $context=$global:PraGate.Context
        if ($Fault -eq 'MemberRead') { $global:PraGateAd.FailTrustee='trustee3' }
        else { $global:PraGateAd.FailGroupEnumeration=$true }
        { New-PraPlan $context 'user1' 'Convert' } | Should -Throw '*SYNTHETIC*'
        InModuleScope PRA.Directory {
            $cache=Get-PraPermissionCache $global:PraGate.Context
            @($cache.Entries.Keys | Where-Object { $_ -like 'group:*' }).Count | Should -Be 0
        }
        $before=@(Get-GateEvents $global:PraGate.Runtime | Where-Object Operation -eq 'Get-ADGroupMember').Count
        $global:PraGateAd.FailTrustee=''; $global:PraGateAd.FailGroupEnumeration=$false
        $plan=New-PraPlan $context 'user1' 'Convert'
        $plan.Record.SharedPermissions.FullAccess.Count | Should -Be 7
        @(Get-GateEvents $global:PraGate.Runtime | Where-Object Operation -eq 'Get-ADGroupMember').Count | Should -BeGreaterThan $before
        @(Get-GateWrites $global:PraGate.Runtime).Count | Should -Be 0
    }
    It 'evicts or bypasses cache cap <Cap> without truncating any right' -ForEach @(@{Cap='Entries'},@{Cap='UPNs'},@{Cap='Characters'}) {
        $global:PraGate.Cap=$Cap
        InModuleScope PRA.Directory {
            $cache=Get-PraPermissionCache $global:PraGate.Context
            switch ($global:PraGate.Cap) { 'Entries' { $cache.MaxEntries=2 }; 'UPNs' { $cache.MaxUpns=2 }; 'Characters' { $cache.MaxCharacters=10L } }
        }
        foreach ($index in 1..2) {
            $plan=New-PraPlan $global:PraGate.Context ('user'+$index) 'Convert'
            foreach ($right in @('FullAccess','SendAs','SendOnBehalf')) {
                $plan.Record.SharedPermissions[$right].Count | Should -Be 7
                $plan.Record.SharedPermissions[$right] | Should -Contain 'trustee7@gate.invalid'
                $plan.Record.SharedPermissions[$right] | Should -Not -Contain 'trustee8@gate.invalid'
            }
        }
        InModuleScope PRA.Directory {
            $cache=Get-PraPermissionCache $global:PraGate.Context
            $cache.Entries.Count | Should -BeLessOrEqual $cache.MaxEntries
            $cache.UpnCount | Should -BeLessOrEqual $cache.MaxUpns
            $cache.CharacterCount | Should -BeLessOrEqual $cache.MaxCharacters
        }
        @(Get-GateWrites $global:PraGate.Runtime).Count | Should -Be 0
    }
    It 'requires all thirteen snapshots to validate before FIRST Set and preserves schema 2 state through Convert and Recover' {
        $context=$global:PraGate.Context; $runtime=$global:PraGate.Runtime
        $plans=@(1..13 | ForEach-Object { New-PraPlan $context ('user'+$_) 'Convert' })
        $source=Invoke-PraAdBatch $context $plans 'Convert'
        $source.Data.SchemaVersion | Should -Be 3
        $source.Data.RawFormat | Should -BeExactly 'PraDataOnlyClixml-v1'
        $source.Data.Records.Count | Should -Be 13
        $state=[IO.File]::ReadAllText($source.StatePath) | ConvertFrom-Json -DateKind String
        $state.SchemaVersion | Should -Be 2
        $events=@(Get-GateEvents $runtime)
        $first=@($events | Where-Object Operation -eq 'Set-ADUser')[0]
        $barriers=@($events | Where-Object { $_.Operation -eq 'BackupBarrier' -and $_.Utc -le $first.Utc })
        $barriers.Count | Should -BeGreaterThan 0
        $barriers[0].Detail.ValidatedCount | Should -Be 13
        $barriers[0].Detail.ValidatedGuids.Count | Should -Be 13
        $barriers[0].Detail.ValidatedBytes | Should -BeGreaterThan 0
        $barriers[0].Detail.RawFormat | Should -BeExactly 'PraDataOnlyClixml-v1'
        @(Get-GateWrites $runtime).Count | Should -Be 13 -Because 'shared mailboxes are not added to the licensing group'
        InModuleScope PRA.Directory {
            $cache=$null; $script:PermissionCaches.TryGetValue($global:PraGate.Context,[ref]$cache) | Should -BeFalse
        }
        $context.Action='Recover'; $context.Source=$source; $context.SourceBackupHash=$source.Hash
        $recover=@(foreach ($record in $source.Data.Records) { New-PraPlan $context $record.ObjectGuid 'Recover' $record -RestoreRetention })
        $receipt=Invoke-PraAdBatch $context $recover 'Recover'
        $receipt.Data.SchemaVersion | Should -Be 3
        $receipt.Data.RawFormat | Should -BeExactly 'PraDataOnlyClixml-v1'
        ([IO.File]::ReadAllText($receipt.StatePath) | ConvertFrom-Json -DateKind String).SchemaVersion | Should -Be 2
        @(Get-GateWrites $runtime).Count | Should -Be 26
        foreach ($user in $global:PraGateAd.Users) {
            $original=@($global:PraGateAd.Originals | Where-Object ObjectGUID -eq $user.ObjectGUID)[0]
            $user.homeMDB | Should -BeExactly $original.homeMDB
            $user.extensionAttribute1 | Should -BeExactly $original.extensionAttribute1
            [Convert]::ToBase64String($user.msExchMailboxGuid) | Should -BeExactly ([Convert]::ToBase64String($original.msExchMailboxGuid))
        }
        Save-GateOomEvidence '13-convert-recover' $runtime @{Targets=13;BeforeFirstSet=$barriers[0].Detail.ValidatedCount;ConvertWrites=13;TotalWrites=26;BackupSchema=3;StateSchema=2} @($source.Path,$source.StatePath,$receipt.Path,$receipt.StatePath)
    }
    It 'rejects the thirteenth corrupted raw snapshot with zero AD/cloud/sync mutations and clears batch caches' {
        InModuleScope PRA.Directory {
            $context=$global:PraGate.Context
            $plans=@(1..13 | ForEach-Object { New-PraPlan $context ('user'+$_) 'Convert' })
            $script:GateRealRawWrite=(Get-Command Write-PraRawCapture).ScriptBlock
            Mock Write-PraRawCapture {
                param($Context,$LiteralPath,$Snapshots)
                $Snapshots.Count | Should -Be 13
                $last=$Snapshots[12]
                $last.Attributes['homeMDB'].Value='CN=Corrupted13,DC=gate,DC=invalid'
                & $script:GateRealRawWrite -Context $Context -LiteralPath $LiteralPath -Snapshots $Snapshots
            }
            { Invoke-PraAdBatch $context $plans 'Convert' } | Should -Throw
            $cache=$null; $script:PermissionCaches.TryGetValue($context,[ref]$cache) | Should -BeFalse
        }
        @(Get-GateWrites $global:PraGate.Runtime).Count | Should -Be 0
        @(Get-GateEvents $global:PraGate.Runtime | Where-Object Operation -Match 'CloudPhase|ADSync').Count | Should -Be 0
    }
    It 'rejects disk-only corruption of the thirteenth unmanaged raw value before every mutation boundary' {
        InModuleScope PRA.Directory {
            $context=$global:PraGate.Context
            foreach ($user in $global:PraGateAd.Users) { $user | Add-Member -NotePropertyName Description -NotePropertyValue ('ForensicOriginal-'+$user.SamAccountName) }
            $plans=@(1..13 | ForEach-Object { New-PraPlan $context ('user'+$_) 'Convert' })
            $global:PraGate.DiskCorruptReached=0
            $script:GateRealDiskRawWrite=(Get-Command Write-PraRawCapture).ScriptBlock
            Mock Write-PraRawCapture {
                param($Context,$LiteralPath,$Snapshots)
                & $script:GateRealDiskRawWrite -Context $Context -LiteralPath $LiteralPath -Snapshots $Snapshots
                $Snapshots[12].Attributes['Description'].Value | Should -BeExactly 'ForensicOriginal-user13'
                (Get-Item -LiteralPath $LiteralPath).Length | Should -BeLessThan 8MB
                $document=New-Object Xml.XmlDocument; $document.XmlResolver=$null; $document.Load($LiteralPath)
                $namespace=New-Object Xml.XmlNamespaceManager($document.NameTable); $namespace.AddNamespace('p','http://schemas.microsoft.com/powershell/2004/04')
                $node=$document.SelectSingleNode('/p:Objs/p:Obj[13]/p:MS//p:En[p:S[@N="Key"]="Description"]//p:S[@N="Value"]',$namespace)
                $node.InnerText | Should -BeExactly 'ForensicOriginal-user13'
                $node.InnerText='ForensicTampered-user13'; $document.Save($LiteralPath)
                $Snapshots[12].Attributes['Description'].Value | Should -BeExactly 'ForensicOriginal-user13'
                $global:PraGate.DiskCorruptReached++
            }
            { Invoke-PraAdBatch $context $plans 'Convert' } | Should -Throw
            $global:PraGate.DiskCorruptReached | Should -Be 1
            $plans[12].RawSnapshot.Attributes['Description'].Value | Should -BeExactly 'ForensicOriginal-user13'
            $jsonPath=@(Get-ChildItem -LiteralPath $context.BackupFolder -Recurse -File -Filter 'Convert-*.json')[0].FullName
            $json=[IO.File]::ReadAllText($jsonPath) | ConvertFrom-Json -DateKind String
            $rawPath=Join-Path (Split-Path $jsonPath -Parent) $json.RawFile
            (Get-PraHash $rawPath) | Should -BeExactly $json.RawHash -Because 'hash was computed AFTER disk corruption; ExpectedSnapshots alone must reject forensic loss'
            (Test-PraRawCapture -Context $context -LiteralPath $rawPath -Records @($json.Records) -RawFormat $json.RawFormat).Count | Should -Be 13
            @(Get-GateWrites $global:PraGate.Runtime).Count | Should -Be 0
            @(Get-GateEvents $global:PraGate.Runtime | Where-Object Operation -Match 'CloudPhase|ADSync').Count | Should -Be 0
            Save-GateOomEvidence 'thirteenth-disk-only-corruption' $global:PraGate.Runtime @{Targets=13;TamperedIndex=13;ExpectedDtoUnchanged=$true;HashMatchesTamperedDisk=$true;RecordOnlyCount=13;Writes=0} @($jsonPath,$rawPath)
        }
    }
    It 'rejects in-place validated receipt mutation <Field> without expanding an arbitrary getter' -ForEach @(
        @{Field='Attribute'},@{Field='SendAs'},@{Field='SendAsElement'},@{Field='Server'},@{Field='RunId'},@{Field='SourceBackupHash'},@{Field='Legacy'},@{Field='Opaque'}
    ) {
        $context=$global:PraGate.Context
        $plan=New-PraPlan $context 'user1' 'Convert'
        $receipt=& (Get-Module PRA.Directory) { param($c,$p) Save-PraBatch $c @($p) 'Convert' } $context $plan
        switch ($Field) {
            'Attribute' { $receipt.Data.Records[0].Attributes.homeMDB.Value='CN=Injected,DC=gate,DC=invalid' }
            'SendAs' { $receipt.Data.Records[0].SharedPermissions.SendAs=@('injected@gate.invalid') }
            'SendAsElement' { $receipt.Data.Records[0].SharedPermissions.SendAs[0]='injected@gate.invalid' }
            'Server' { $receipt.Data.Server='dc-other.gate.invalid' }
            'RunId' { $receipt.Data.RunId='injected-run-id' }
            'SourceBackupHash' { $receipt.Data.SourceBackupHash=('a'*64) }
            'Legacy' { $receipt.Legacy=$true }
            'Opaque' {
                if (-not ('PraGateReceiptOpaque' -as [type])) { Add-Type -TypeDefinition 'public sealed class PraGateReceiptOpaque { public static int GetterCalls; public static int StringCalls; public PraGateReceiptOpaque Child { get { GetterCalls++; return this; } } public static string LastStringStack; public static System.Collections.Generic.List<string> StringStacks=new System.Collections.Generic.List<string>(); public static int BinderCalls; public static int UnexpectedCalls; public override string ToString() { StringCalls++; var frames=new System.Diagnostics.StackTrace().GetFrames(); /* The engine''s own parameter binder converts the value to text when a command is bound to it. Every frame between ToString and the binder is a PSObject method (the JIT may inline some of them, so their number is not fixed); a ToString called from anything else is not accepted. */ bool binder=false; int j=1; while(j<frames.Length){var m=frames[j].GetMethod(); if(m.DeclaringType!=null && m.DeclaringType.FullName=="System.Management.Automation.PSObject"){j++;continue;} break;} if(j>1 && j<frames.Length){var bind=frames[j].GetMethod(); binder=bind.DeclaringType!=null && bind.DeclaringType.FullName=="System.Management.Automation.ParameterBinderBase" && bind.Name=="BindParameter";} if(binder){BinderCalls++;}else{UnexpectedCalls++;} var text=new System.Text.StringBuilder(); for(int i=0;i<System.Math.Min(8,frames.Length);i++){var method=frames[i].GetMethod(); text.AppendLine((method.DeclaringType==null?"<dynamic>":method.DeclaringType.FullName)+"."+method.Name);} LastStringStack=text.ToString(); if(StringStacks.Count<8){StringStacks.Add(LastStringStack);} return "opaque"; } }' }
                [PraGateReceiptOpaque]::GetterCalls=0; [PraGateReceiptOpaque]::StringCalls=0; [PraGateReceiptOpaque]::BinderCalls=0; [PraGateReceiptOpaque]::UnexpectedCalls=0; [PraGateReceiptOpaque]::LastStringStack=''; [PraGateReceiptOpaque]::StringStacks.Clear()
                $receipt.Data.Records[0].Attributes.homeMDB.Value=New-Object PraGateReceiptOpaque
            }
        }
        if ($Field -eq 'Opaque') {
            $fixtureStringCalls=[PraGateReceiptOpaque]::StringCalls; $fixtureStringStack=[PraGateReceiptOpaque]::LastStringStack
            [PraGateReceiptOpaque]::GetterCalls=0; [PraGateReceiptOpaque]::StringCalls=0; [PraGateReceiptOpaque]::BinderCalls=0; [PraGateReceiptOpaque]::UnexpectedCalls=0; [PraGateReceiptOpaque]::LastStringStack=''; [PraGateReceiptOpaque]::StringStacks.Clear()
            & { param($InputValue) $null=$InputValue } $receipt
            $noopStringCalls=[PraGateReceiptOpaque]::StringCalls; $noopGetterCalls=[PraGateReceiptOpaque]::GetterCalls
            $noopBinderCalls=[PraGateReceiptOpaque]::BinderCalls; $noopUnexpectedCalls=[PraGateReceiptOpaque]::UnexpectedCalls; $noopStack=[PraGateReceiptOpaque]::LastStringStack
            [PraGateReceiptOpaque]::GetterCalls=0; [PraGateReceiptOpaque]::StringCalls=0; [PraGateReceiptOpaque]::BinderCalls=0; [PraGateReceiptOpaque]::UnexpectedCalls=0; [PraGateReceiptOpaque]::LastStringStack=''; [PraGateReceiptOpaque]::StringStacks.Clear()
        }
        { Assert-PraReceipt $context $receipt $plan.Record.ObjectGuid } | Should -Throw
        { Import-PraBackup $context $receipt.Path } | Should -Throw
        if ($Field -eq 'Opaque') {
            $observed=@{FixtureToStringCalls=$fixtureStringCalls;FixtureToStringStack=$fixtureStringStack;NoopGetterCalls=$noopGetterCalls;NoopToStringCalls=$noopStringCalls;NoopBinderCalls=$noopBinderCalls;NoopUnexpectedCalls=$noopUnexpectedCalls;NoopStack=$noopStack;ProductGetterCalls=[PraGateReceiptOpaque]::GetterCalls;ProductToStringCalls=[PraGateReceiptOpaque]::StringCalls;ProductBinderCalls=[PraGateReceiptOpaque]::BinderCalls;ProductUnexpectedCalls=[PraGateReceiptOpaque]::UnexpectedCalls;ProductStack=[PraGateReceiptOpaque]::LastStringStack;ProductStacks=[PraGateReceiptOpaque]::StringStacks.ToArray()}
            [PraGateReceiptOpaque]::GetterCalls=0; [PraGateReceiptOpaque]::StringCalls=0; [PraGateReceiptOpaque]::BinderCalls=0; [PraGateReceiptOpaque]::UnexpectedCalls=0; [PraGateReceiptOpaque]::LastStringStack=''; [PraGateReceiptOpaque]::StringStacks.Clear()
            [void]([string]$receipt.Data.Records[0].Attributes.homeMDB.Value)
            $observed.ExplicitCastToStringCalls=[PraGateReceiptOpaque]::StringCalls; $observed.ExplicitCastBinderCalls=[PraGateReceiptOpaque]::BinderCalls; $observed.ExplicitCastUnexpectedCalls=[PraGateReceiptOpaque]::UnexpectedCalls; $observed.ExplicitCastStack=[PraGateReceiptOpaque]::LastStringStack
            Save-GateOomEvidence 'opaque-receipt-call-boundary' $global:PraGate.Runtime $observed
            $observed.ProductGetterCalls | Should -Be 0
            $observed.ProductUnexpectedCalls | Should -Be 0
            $observed.ProductToStringCalls | Should -Be $observed.ProductBinderCalls
            $observed.NoopUnexpectedCalls | Should -Be 0
            $observed.ExplicitCastUnexpectedCalls | Should -BeGreaterThan 0
        }
        @(Get-GateWrites $global:PraGate.Runtime).Count | Should -Be 0
    }
    It 'rejects copied receipts and same-valued foreign contexts, without raw re-import on genuine receipt checks' {
        $context=$global:PraGate.Context
        $plan=New-PraPlan $context 'user1' 'Convert'
        $receipt=& (Get-Module PRA.Directory) { param($c,$p) Save-PraBatch $c @($p) 'Convert' } $context $plan
        $fake=[pscustomobject]@{Data=$receipt.Data;Path=$receipt.Path;Hash=$receipt.Hash;Legacy=$receipt.Legacy}
        { Assert-PraReceipt $context $fake $plan.Record.ObjectGuid } | Should -Throw '*not validated in this run*'
        $foreign=$context.Clone()
        { Assert-PraReceipt $foreign $receipt $plan.Record.ObjectGuid } | Should -Throw '*not validated in this run*'
        $global:PraGate.Receipt=$receipt; $global:PraGate.Plan=$plan; $global:PraGate.ReceiptCounts=@{Imports=0;RawTests=0;JsonHashes=0;RawHashes=0}
        InModuleScope PRA.Directory {
            $script:GateRealHash=(Get-Command Get-PraHash).ScriptBlock
            Mock Import-PraBackup { $global:PraGate.ReceiptCounts.Imports++; throw 'SYNTHETIC: redundant import' }
            Mock Test-PraRawCapture { $global:PraGate.ReceiptCounts.RawTests++; throw 'SYNTHETIC: redundant raw parsing' }
            Mock Get-PraHash {
                param($Path)
                if ($Path -like '*.clixml') { $global:PraGate.ReceiptCounts.RawHashes++ }
                elseif ($Path -like '*.json') { $global:PraGate.ReceiptCounts.JsonHashes++ }
                & $script:GateRealHash $Path
            }
            foreach ($i in 1..3) { Assert-PraReceipt $global:PraGate.Context $global:PraGate.Receipt $global:PraGate.Plan.Record.ObjectGuid }
        }
        $global:PraGate.ReceiptCounts.Imports | Should -Be 0
        $global:PraGate.ReceiptCounts.RawTests | Should -Be 0
        $global:PraGate.ReceiptCounts.JsonHashes | Should -Be 3
        $global:PraGate.ReceiptCounts.RawHashes | Should -Be 3
        Save-GateOomEvidence 'registered-receipt' $global:PraGate.Runtime $global:PraGate.ReceiptCounts @($receipt.Path)
    }
    It 'blocks genuine file tampering after Approval before any mutation for <Artifact>' -ForEach @(@{Artifact='Json'},@{Artifact='Raw'},@{Artifact='Sidecar'}) {
        $context=$global:PraGate.Context
        $plans=@(1..13 | ForEach-Object { New-PraPlan $context ('user'+$_) 'Convert' })
        $global:PraGate.TamperArtifact=$Artifact
        $context.Approval={
            param($Target,$Operation)
            $path=$global:PraGate.Context.BackupFiles[0]
            if ($global:PraGate.TamperArtifact -eq 'Raw') { $data=[IO.File]::ReadAllText($path) | ConvertFrom-Json -DateKind String; $path=Join-Path (Split-Path $path -Parent) $data.RawFile }
            elseif ($global:PraGate.TamperArtifact -eq 'Sidecar') { $path+='.sha256' }
            [IO.File]::AppendAllText($path,'x'); $true
        }
        { Invoke-PraAdBatch $context $plans 'Convert' } | Should -Throw '*changed since its validation*'
        @(Get-GateWrites $global:PraGate.Runtime).Count | Should -Be 0
    }
    It 'rechecks a cached receipt when importing a proof and rejects subsequently changed raw bytes' {
        $context=$global:PraGate.Context; $runtime=$global:PraGate.Runtime
        $plans=@(1..13 | ForEach-Object { New-PraPlan $context ('user'+$_) 'Convert' })
        $receipt=& (Get-Module PRA.Directory) { param($c,$p) Save-PraBatch $c $p 'Convert' } $context $plans
        $path=Join-Path (Split-Path $receipt.Path -Parent) 'synthetic-proof.json'
        $data=[ordered]@{SchemaVersion=2;Kind='ADVerified';Environment=$context.Config.Environment;Operation='Convert';RunId=$receipt.Data.RunId;BackupFile=[IO.Path]::GetFileName($receipt.Path);BackupHash=$receipt.Hash;SourceBackupHash='';Records=@($receipt.Data.Records | ForEach-Object { @{ObjectGuid=$_.ObjectGuid;ADVerified=$true;Operation='Convert';VerifiedUsnChanged='101'} })}
        Write-PraImmutableFile $path ($data | ConvertTo-Json -Depth 12)
        Write-PraImmutableFile ($path+'.sha256') (Get-PraHash $path)
        $proof=Import-PraProof $context $path $receipt 'Convert'
        [object]::ReferenceEquals($proof.Receipt,$receipt) | Should -BeTrue
        $raw=Join-Path (Split-Path $receipt.Path -Parent) $receipt.Data.RawFile
        [IO.File]::AppendAllText($raw,' ')
        { Import-PraProof $context $path $receipt 'Convert' } | Should -Throw '*changed since its validation*'
        @(Get-GateWrites $runtime).Count | Should -Be 0
    }
    It 'rejects a changed cached backup path instead of returning a previously validated receipt' {
        $context=$global:PraGate.Context
        $plan=New-PraPlan $context 'user1' 'Convert'
        $receipt=& (Get-Module PRA.Directory) { param($c,$p) Save-PraBatch $c @($p) 'Convert' } $context $plan
        $cached=Import-PraBackup $context $receipt.Path
        [object]::ReferenceEquals($cached,$receipt) | Should -BeTrue
        [IO.File]::AppendAllText($receipt.Path,' ')
        { Import-PraBackup $context $receipt.Path } | Should -Throw '*changed since its validation*'
        @(Get-GateWrites $global:PraGate.Runtime).Count | Should -Be 0
    }
}

Describe 'AD delta formatter and dynamic projection' -Tag 'Delta' {
    BeforeEach {
        $global:PraGate.Runtime=New-GateRuntime -Name 'delta-unit'
        $env:PRA_GATE_STATE=$global:PraGate.Runtime.StatePath
        $env:PSModulePath=$global:PraGate.Runtime.Modules+';'+(Join-Path $PSHOME 'Modules')
        Import-Module ActiveDirectory -Force -Global
        $global:PraGate.Context=New-GateContext $global:PraGate.Runtime -Mode Preview
        $global:PraGate.Context.LogFile=Join-Path $global:PraGate.Runtime.Root 'logs\delta.log'
    }
    It 'keeps the formatter and delta writer private to Directory' {
        $exports=(Get-Module PRA.Directory).ExportedFunctions.Keys
        $exports | Should -Not -Contain 'Format-PraAttributeValue'
        $exports | Should -Not -Contain 'Write-PraAdDelta'
        InModuleScope PRA.Directory {
            (Get-Command Format-PraAttributeValue -ErrorAction Stop).ModuleName | Should -Be 'PRA.Directory'
            (Get-Command Write-PraAdDelta -ErrorAction Stop).ModuleName | Should -Be 'PRA.Directory'
        }
    }
    It 'formats <Name> without conflating absence, false and zero or rounding integers' -ForEach @(
        @{Name='absent Bool';State=@{Present=$false;Kind='Bool';Value=$false};Expected='<absent>'}
        @{Name='false Bool';State=@{Present=$true;Kind='Bool';Value=$false};Expected='false'}
        @{Name='true Bool';State=@{Present=$true;Kind='Bool';Value=$true};Expected='true'}
        @{Name='zero Int';State=@{Present=$true;Kind='Int';Value='0'};Expected='0'}
        @{Name='minimum Int';State=@{Present=$true;Kind='Int';Value='-2147483648'};Expected='-2147483648'}
        @{Name='maximum Long';State=@{Present=$true;Kind='Long';Value='9223372036854775807'};Expected='9223372036854775807'}
        @{Name='minimum Long';State=@{Present=$true;Kind='Long';Value='-9223372036854775808'};Expected='-9223372036854775808'}
        @{Name='empty present String';State=@{Present=$true;Kind='String';Value=''};Expected='""'}
    ) {
        $directory=Get-Module PRA.Directory
        $formatted=@(& $directory { param($s) Format-PraAttributeValue -State $s } $State)
        $formatted.Count | Should -Be 1
        $formatted[0] | Should -BeOfType ([string])
        $formatted[0] | Should -BeExactly $Expected
        @(Get-GateWrites $global:PraGate.Runtime).Count | Should -Be 0
    }
    It 'renders a 16-byte mailbox GUID in readable and lossless Base64 forms' {
        $guid=[guid]'00112233-4455-6677-8899-aabbccddeeff'
        $base64=[Convert]::ToBase64String($guid.ToByteArray())
        $state=@{Present=$true;Kind='Bytes';Value=$base64}
        $formatted=@(& (Get-Module PRA.Directory) { param($s) Format-PraAttributeValue -State $s } $state)
        $text=$formatted -join "`n"
        Save-GateDeltaEvidence 'guid' $global:PraGate.Context $global:PraGate.Runtime -Detail @{State=$state;Formatted=$formatted}
        $text | Should -Match ([regex]::Escape($guid.ToString()))
        $text | Should -Match ([regex]::Escape($base64))
        $text | Should -Match 'Base64'
        @($formatted | Where-Object { $_ -isnot [string] }).Count | Should -Be 0
    }
    It 'preserves non-GUID byte arrays entirely in Base64' {
        $base64=[Convert]::ToBase64String([byte[]](0,1,2,127,128,254,255,1))
        $formatted=@(& (Get-Module PRA.Directory) { param($v) Format-PraAttributeValue -State @{Present=$true;Kind='Bytes';Value=$v} } $base64)
        ($formatted -join "`n") | Should -Match ([regex]::Escape($base64))
    }
    It 'shows every multivalue on a separate line, including the full long final value' {
        $values=@(1..24 | ForEach-Object { 'smtp:alias{0:00}@gate.invalid' -f $_ })
        $values+=('X500:/o=Synthetic/ou=Gate/cn='+('LongPart' * 65)+'/cn=FINAL-VALUE')
        $state=@{Present=$true;Kind='MultiString';Value=[string[]]$values}
        $formatted=@(& (Get-Module PRA.Directory) { param($s) Format-PraAttributeValue -State $s } $state)
        Save-GateDeltaEvidence 'multivalues' $global:PraGate.Context $global:PraGate.Runtime -Detail @{State=$state;Formatted=$formatted}
        foreach ($value in $values) {
            $matching=@($formatted | Where-Object { $_ -cmatch [regex]::Escape('"'+$value+'"') })
            $matching.Count | Should -Be 1
            @($values | Where-Object { $matching[0].Contains($_) }).Count | Should -Be 1 -Because 'one element per line, not a joined or truncated collection'
        }
        ($formatted -join "`n") | Should -Not -Match '\.\.\.|\u2026|System\.(Object|String)\[\]'
    }
    It 'quotes strings and escapes LF, CR, tab and ESC without injecting log or console lines' {
        $value='start"quoted"\path'+"`nLF`rCR`tTAB"+[char]27+'[31mEND'
        $state=@{Present=$true;Kind='String';Value=$value}
        $formatted=@(& (Get-Module PRA.Directory) { param($s) Format-PraAttributeValue -State $s } $state)
        $formatted.Count | Should -Be 1
        $text=$formatted[0]
        $text | Should -Match '^".*"$'
        $text | Should -Match '\\"quoted\\"'
        $text | Should -Match '\\\\path'
        $text | Should -Match '\\(n|u000[aA])LF'
        $text | Should -Match '\\(r|u000[dD])CR'
        $text | Should -Match '\\(t|u0009)TAB'
        $text | Should -Match '\\(u001[bB]|x1[bB]|e)\[31mEND'
        $text | Should -Not -Match '[\x00-\x1f\x7f]'
        $hostRecords=@(Write-PraLog -Context $global:PraGate.Context -Message $text -Level Sub 6>&1)
        $log=[IO.File]::ReadAllText($global:PraGate.Context.LogFile)
        Save-GateDeltaEvidence 'escaped-controls' $global:PraGate.Context $global:PraGate.Runtime -HostRecords @($hostRecords | ForEach-Object MessageData) -Detail @{State=$state;Formatted=$formatted}
        $hostRecords.Count | Should -Be 1
        $hostRecords[0].MessageData.Message | Should -Match ([regex]::Escape($text))
        $hostRecords[0].MessageData.Message | Should -Not -Match '[\x00-\x1f\x7f]'
        @([IO.File]::ReadAllLines($global:PraGate.Context.LogFile)).Count | Should -Be 1
        $log | Should -Not -Match '[\x00-\x09\x0b\x0c\x0e-\x1f\x7f]'
        $global:PraGate.Context.Warnings | Should -Be 0
        $global:PraGate.Context.Issues.Count | Should -Be 0
    }
    It 'projects a newly configured retention attribute and renders every planned attribute' {
        $context=$global:PraGate.Context
        $context.Config.Retention.Tag.Attribute='extensionAttribute15'
        foreach ($user in $global:PraGateAd.Users) { $user | Add-Member -NotePropertyName extensionAttribute15 -NotePropertyValue ('OriginalExtra-'+$user.SamAccountName) }
        $context.Config.Remote.ClearMailboxGuid=$false
        $plan=New-PraPlan $context 'user1' 'Convert'
        $plan.Kinds.Keys | Should -Contain 'extensionAttribute15'
        $plan.Record.Attributes.extensionAttribute15.Value | Should -BeExactly 'OriginalExtra-user1'
        $read=@(Get-GateEvents $global:PraGate.Runtime | Where-Object Operation -eq 'Get-ADUser')[-1]
        $read.Detail.Properties | Should -Contain 'extensionAttribute15'
        $read.Detail.Properties | Should -Contain '*' -Because 'plan preparation alone performs the complete raw capture'
        $plan.RawSnapshot.Attributes['extensionAttribute15'].Value | Should -BeExactly 'OriginalExtra-user1'
        @($plan.User.PSObject.Properties.Name).Count | Should -Be 3
        $plan.User.PSObject.Properties.Name | Should -Not -Contain 'nTSecurityDescriptor'
        $records=@(& (Get-Module PRA.Directory) { param($c,$p) Write-PraAdDelta -Context $c -Plan $p -Stage Planned } $context $plan 6>&1)
        $hostRecords=@($records | Where-Object { $_ -is [Management.Automation.InformationRecord] } | ForEach-Object MessageData)
        $text=($hostRecords | ForEach-Object Message) -join "`n"
        $log=[IO.File]::ReadAllText($context.LogFile)
        Save-GateDeltaEvidence 'dynamic-projection' $context $global:PraGate.Runtime -HostRecords $hostRecords -Detail @{Kinds=@($plan.Kinds.Keys);Before=$plan.Record.Attributes;Desired=$plan.Desired;Licensing=$plan.Record.Licensing}
        foreach ($name in $plan.Kinds.Keys) {
            $beforeValues=@(& (Get-Module PRA.Directory) { param($s) Format-PraAttributeValue -State $s } $plan.Record.Attributes[$name])
            $afterValues=@(& (Get-Module PRA.Directory) { param($s) Format-PraAttributeValue -State $s } $plan.Desired[$name])
            foreach ($value in $beforeValues) { $log | Should -Match ([regex]::Escape($name+' | BEFORE : '+$value)) }
            foreach ($value in $afterValues) { $log | Should -Match ([regex]::Escape($name+' | PLANNED : '+$value)) }
        }
        foreach ($expected in @(
            @{Name='targetAddress';Change='ADD';Color='Green';Console=$true},@{Name='extensionAttribute15';Change='CHANGE';Color='Yellow';Console=$true},
            @{Name='homeMDB';Change='REMOVE';Color='Red';Console=$true},@{Name='msExchMailboxGuid';Change='UNCHANGED';Color='Gray';Console=$false}
        )) {
            @([regex]::Matches($log,[regex]::Escape('ATTRIBUTE | '+$expected.Name+' | '+$expected.Change+' |'))).Count | Should -Be 1
            $console=@($hostRecords | Where-Object { $_.Message -match [regex]::Escape($expected.Name) })
            if ($expected.Console) {
                $console.Count | Should -BeGreaterThan 0
            } else { $console.Count | Should -Be 0 }
        }
        foreach ($visible in @('BEFORE','PLANNED','OriginalExtra-user1','Converted','proxyAddresses','CN=License,OU=Tests,DC=gate,DC=invalid','ADD','CHANGE','REMOVE','UNCHANGED')) {
            $log | Should -Match ([regex]::Escape($visible))
        }
        $text | Should -Not -Match 'VERIFIED'
        $text | Should -Not -Match '[]'
        $log | Should -Not -Match '[]'
        $context.Warnings | Should -Be 0
        $context.Issues.Count | Should -Be 0
        @(Get-GateWrites $global:PraGate.Runtime).Count | Should -Be 0
    }
    It 'renders licensing <WasMember> to <DesiredMember> as <Change> without changing severity' -ForEach @(
        @{WasMember=$false;DesiredMember=$true;Change='ADD';Color='Green';BeforeText='Not member';AfterText='Member'}
        @{WasMember=$true;DesiredMember=$false;Change='REMOVE';Color='Red';BeforeText='Member';AfterText='Not member'}
        @{WasMember=$true;DesiredMember=$true;Change='UNCHANGED';Color='Gray';BeforeText='Member';AfterText='Member'}
        @{WasMember=$false;DesiredMember=$false;Change='UNCHANGED';Color='Gray';BeforeText='Not member';AfterText='Not member'}
    ) {
        $context=$global:PraGate.Context
        $plan=New-PraPlan $context 'user1' 'Convert'
        $plan.Record.Licensing.WasMember=$WasMember; $plan.Record.Licensing.DesiredMember=$DesiredMember
        $records=@(& (Get-Module PRA.Directory) { param($c,$p) Write-PraAdDelta -Context $c -Plan $p -Stage Planned } $context $plan 6>&1)
        $hostRecords=@($records | ForEach-Object MessageData)
        Save-GateDeltaEvidence ('group-'+$WasMember+'-'+$DesiredMember) $context $global:PraGate.Runtime -HostRecords $hostRecords -Detail $plan.Record.Licensing
        $log=[IO.File]::ReadAllText($context.LogFile)
        $log | Should -Match ([regex]::Escape('LICENCE GROUP | CN=License,OU=Tests,DC=gate,DC=invalid | '+$Change))
        $log | Should -Match ([regex]::Escape('Licence group | BEFORE : '+$BeforeText))
        $log | Should -Match ([regex]::Escape('Licence group | PLANNED : '+$AfterText))
        $console=@($hostRecords | Where-Object Message -Match 'licence group License')
        if ($Change -eq 'UNCHANGED') { $console.Count | Should -Be 0 }
        else {
            $console.Count | Should -Be 1
            $console[0].Message | Should -Match ($BeforeText.ToLowerInvariant()+'.*'+$AfterText.ToLowerInvariant())
        }
        $context.Warnings | Should -Be 0
        $context.Issues.Count | Should -Be 0
        @(Get-GateWrites $global:PraGate.Runtime).Count | Should -Be 0
    }
}

Describe 'Human-facing logger colors do not change severity' -Tag 'Delta' {
    BeforeEach {
        $global:PraGate.Runtime=New-GateRuntime -Name 'logger-color'
        $global:PraGate.Context=New-GateContext $global:PraGate.Runtime -Mode Preview
        $global:PraGate.Context.LogFile=Join-Path $global:PraGate.Runtime.Root 'logs\color.log'
    }
    It 'uses cyan for Info and supports a ConsoleColor override without changing counters' {
        $context=$global:PraGate.Context
        (Get-Command Write-PraLog).Parameters['ForegroundColor'].ParameterType | Should -Be ([ConsoleColor])
        $records=@(Write-PraLog -Context $context -Message 'Default Info' -Level Info 6>&1)
        ($records[0].MessageData.Message -join '') | Should -Match 'Default Info'
        $override=@(Write-PraLog -Context $context -Message 'Expected removal, not an error' -Level Sub -ForegroundColor Red 6>&1)
        ($override[0].MessageData.Message -join '') | Should -Match 'Expected removal, not an error'
        $context.Warnings | Should -Be 0
        $context.Issues.Count | Should -Be 0
        $context.ExitCode | Should -Be 0
        $context.StepIndex | Should -Be 0
        Save-GateDeltaEvidence 'info-sub-override' $context $global:PraGate.Runtime -HostRecords @(@($records+$override) | ForEach-Object MessageData)
        [IO.File]::ReadAllText($context.LogFile) | Should -Not -Match '[\x1b]'
    }
    It 'retains <Level> semantics when only its foreground color is overridden' -ForEach @(
        @{Level='Warning';Color='Magenta';Warnings=1;Issues=0;Steps=0;ExitCode=0}
        @{Level='Error';Color='Green';Warnings=0;Issues=1;Steps=0;ExitCode=1}
        @{Level='Step';Color='Gray';Warnings=0;Issues=0;Steps=0;ExitCode=0}
        @{Level='Success';Color='DarkCyan';Warnings=0;Issues=0;Steps=0;ExitCode=0}
    ) {
        $context=$global:PraGate.Context
        $records=@(Write-PraLog -Context $context -Message ('Colored '+$Level) -Level $Level -ForegroundColor ([ConsoleColor]$Color) 6>&1)
        if ($Level -eq 'Step') { $records.Count | Should -Be 0 }
        else {
            $records.Count | Should -Be 1
            ($records[0].MessageData.Message -join '') | Should -Match ([regex]::Escape('Colored '+$Level))
        }
        $context.Warnings | Should -Be $Warnings
        $context.Issues.Count | Should -Be $Issues
        $context.StepIndex | Should -Be $Steps
        $context.ExitCode | Should -Be $ExitCode
        Save-GateDeltaEvidence ('severity-'+$Level) $context $global:PraGate.Runtime -HostRecords @($records | ForEach-Object MessageData)
    }
    It 'renders a step header and records it without changing counters' {
        $context=$global:PraGate.Context
        $records=@(Write-PraStep -Context $context -Title 'Gate step banner' -Icon Plan 6>&1)
        $hostRecords=@($records | ForEach-Object MessageData)
        Save-GateDeltaEvidence 'step-banner' $context $global:PraGate.Runtime -HostRecords $hostRecords
        @($hostRecords | Where-Object Message -Match 'Gate step banner').Count | Should -Be 1
        $context.StepIndex | Should -Be 1
        $context.CurrentPhase | Should -Be 'Gate step banner'
        $context.Warnings | Should -Be 0
        $context.Issues.Count | Should -Be 0
        [IO.File]::ReadAllText($context.LogFile) | Should -Match '\[1\] Gate step banner'
        [IO.File]::ReadAllText($context.LogFile) | Should -Not -Match '[\x1b]'
    }
}

Describe 'Common value and report contracts' {
    It 'reads dictionaries containing real Keys and Values entries without member-name collisions' {
        $dictionary=@{Found=$true;Type='MailUser';Keys=@('id');Values='synthetic'}
        Get-PraValue $dictionary 'Found' $false | Should -BeTrue
        Get-PraValue $dictionary 'Type' '' | Should -Be 'MailUser'
        $keys=Get-PraValue $dictionary 'Keys' @()
        $keys.Count | Should -Be 1
        $keys[0] | Should -Be 'id'
    }
    It 'retains false, null, zero and empty arrays without inventing members' {
        $object=@{False=$false;Zero=0;Null=$null;Empty=@()}
        (Get-PraValue $object 'False' $true) | Should -BeFalse
        (Get-PraValue $object 'Zero' 42) | Should -Be 0
        (Get-PraValue $object 'Null' 'fallback') | Should -BeNullOrEmpty
        $empty=Get-PraValue $object 'Empty' @('phantom')
        $empty.GetType().FullName | Should -Be 'System.Object[]'
        $empty.Count | Should -Be 0
        InModuleScope PRA.Directory {
            $context=New-GateContext $global:PraGate.Runtime
            $row=New-PraRow $context ([pscustomobject]@{ObjectGuid='';SamAccountName='';UserPrincipalName='';IsShared=$false})
            $row.IsShared | Should -BeFalse
            $row.SharedFullAccess.Count | Should -Be 0
            $row.PermMissing.Count | Should -Be 0
        }
    }
    It 'keeps report totals consistent without phantom empty-membership cells' {
        InModuleScope PRA.Common {
            $context=New-GateContext $global:PraGate.Runtime -Mode Preview
            $row=New-PraRow $context ([pscustomobject]@{SamAccountName='synthetic';IsShared=$false})
            $row.FinalStatus='Planned'; $context.Rows.Add($row)
            $outcome=Get-PraOutcome $context
            $outcome.Rows.Count | Should -Be 1
            $outcome.Counts.Planned | Should -Be 1
            $outcome.Counts.Error | Should -Be 0
            $outcome.Rows[0].PermMissing | Should -BeExactly ''
            $html=Get-PraReportHtml -Context $context -Outcome $outcome
            $html | Should -Match '<script type="application/x-pra-chunk" data-kind="rows" data-seq="0">'
            $html | Should -Match '"rows":\{"count":1,'
            $html | Should -Match '"fields":\[[^\]]*"PermMissing"'
            $html | Should -Not -Match '<table id="rows">'
            $html | Should -Not -Match 'System.Object\[\]|phantom'
        }
    }
    It 'shows run warnings in the tiles, a warnings card and the row of the object, without changing the exit code' {
        InModuleScope PRA.Common {
            $context=New-GateContext $global:PraGate.Runtime -Mode Preview
            $row=New-PraRow $context ([pscustomobject]@{SamAccountName='shared1';IsShared=$true})
            $row.FinalStatus='Planned'; $row.Warnings='Permission entries ignored (account unknown in AD): FullAccess S-1-5-21-1-2-3-9999'; $context.Rows.Add($row)
            Write-PraLog -Context $context -Level Warning -Message 'shared1: 1 permission entry ignored, account unknown in AD (deleted, or from another domain): FullAccess S-1-5-21-1-2-3-9999'
            $outcome=Get-PraOutcome $context
            $outcome.ExitCode | Should -Be 0
            $outcome.Rows[0].Warnings | Should -Match 'FullAccess S-1-5-21-1-2-3-9999'
            $html=Get-PraReportHtml -Context $context -Outcome $outcome
            $html | Should -Match '<div class="tile-label">Warnings</div><div class="tile-value">1</div>'
            $html | Should -Match '<section class="card warnings" id="warnings-card" hidden>'
            $html | Should -Match '"warnings":\{"count":1,'
            $html | Should -Match '"fields":\[[^\]]*"Warnings"'
            $html | Should -Match '<script type="application/x-pra-chunk" data-kind="warnings" data-seq="0">'
        }
    }
}

Describe 'AuditTranscript - delayed native file contract and ownership' -Tag 'AuditTranscript' {
    BeforeEach {
        $global:PraGate.Runtime=New-GateRuntime -Name 'audit-transcript'
        $env:PRA_GATE_STATE=$global:PraGate.Runtime.StatePath
        $env:PSModulePath=$global:PraGate.Runtime.Modules+';'+(Join-Path $PSHOME 'Modules')
        $global:PraGate.Context=New-GateContext $global:PraGate.Runtime -Mode Preview
        $global:PraGate.Audit=@{
            CreateOn='Host'; Fault=''; Starts=0; Stops=0; Sleeps=0; Hosts=0; Path=''; Result=$null
            Trace=(New-Object 'Collections.Generic.List[object]')
        }
        InModuleScope PRA.Common {
            $script:TranscriptOwner=$null
            # Never touch the real transcript owned by Invoke-TestGate in this Pester process.
            # The double models ONLY the native writer; the product must not manufacture a file.
            Mock Start-Transcript {
                param($Path,$NoClobber,$Append,$WhatIf,$Confirm)
                $audit=$global:PraGate.Audit
                $audit.Starts++; $audit.Path=$Path
                $audit.Trace.Add([pscustomobject]@{Operation='Start';Path=$Path;Exists=[IO.File]::Exists($Path);NoClobber=[bool]$NoClobber;Append=[bool]$Append;WhatIf=[bool]$WhatIf})
                [bool]$NoClobber | Should -BeTrue
                [bool]$Append | Should -BeFalse
                $PSBoundParameters.ContainsKey('WhatIf') | Should -BeTrue
                [bool]$WhatIf | Should -BeFalse
                [bool]$Confirm | Should -BeFalse
                if ($audit.Fault -eq 'Unauthorized') { throw [UnauthorizedAccessException]::new('SYNTHETIC: transcript access denied') }
                if ([IO.File]::Exists($Path)) { throw 'SYNTHETIC: NoClobber refuses existing transcript' }
                if ($audit.CreateOn -eq 'Empty') { [IO.File]::WriteAllBytes($Path,[byte[]]@()) }
                'SYNTHETIC: Start succeeded; native file may still be absent.'
            }
            Mock Stop-Transcript {
                $global:PraGate.Audit.Stops++
                $global:PraGate.Audit.Trace.Add([pscustomobject]@{Operation='Stop';OwnsContext=[object]::ReferenceEquals($script:TranscriptOwner,$global:PraGate.Context)})
                [object]::ReferenceEquals($script:TranscriptOwner,$global:PraGate.Context) | Should -BeTrue
                if ($global:PraGate.Audit.Fault -eq 'Stop') { throw 'SYNTHETIC: transcript close refused' }
                'SYNTHETIC: owned transcript stopped.'
            }
            Mock Write-Host {
                param($Object)
                $audit=$global:PraGate.Audit; $context=$global:PraGate.Context
                $audit.Hosts++
                $audit.Trace.Add([pscustomobject]@{Operation='Host';Text=($Object -join ' ');Started=$context.TranscriptStarted;Created=[bool](Get-PraValue $context '_PraTranscriptCreated' $false);Exists=($audit.Path -and [IO.File]::Exists($audit.Path));Issues=$context.Issues.Count})
                if ($audit.CreateOn -eq 'Host' -and $context.TranscriptStarted -and $audit.Path -and -not [IO.File]::Exists($audit.Path)) {
                    [IO.File]::WriteAllText($audit.Path,"SYNTHETIC native transcript header after first host output`r`n")
                }
            }
            Mock Start-Sleep {
                param($Milliseconds)
                $audit=$global:PraGate.Audit; $context=$global:PraGate.Context
                $audit.Sleeps++
                $audit.Trace.Add([pscustomobject]@{Operation='PollSleep';Milliseconds=$Milliseconds;Created=[bool](Get-PraValue $context '_PraTranscriptCreated' $false);Exists=($audit.Path -and [IO.File]::Exists($audit.Path))})
                $Milliseconds | Should -Be 50
                if ($audit.CreateOn -eq 'Poll2' -and $audit.Sleeps -eq 2) {
                    [IO.File]::WriteAllText($audit.Path,"SYNTHETIC native transcript header after two polls`r`n")
                }
                [Threading.Thread]::Sleep([int]$Milliseconds)
            }
        }
    }
    AfterEach {
        try {
            if ($env:PRA_GATE_EVIDENCE) {
                $context=$global:PraGate.Context; $runtime=$global:PraGate.Runtime
                $artifacts=@(foreach ($file in Get-ChildItem -LiteralPath $context.LogFolder -File) {
                    [pscustomobject]@{Path=$file.FullName;Length=$file.Length;SHA256=(Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256).Hash;Content=[IO.File]::ReadAllText($file.FullName);Bytes=[Convert]::ToBase64String([IO.File]::ReadAllBytes($file.FullName))}
                })
                $record=[ordered]@{
                    Synthetic=$true; Boundary='Common Start/Stop-Transcript and host output mocked; no native transcript in unit tests'
                    Runtime=$runtime.Root; CreateOn=$global:PraGate.Audit.CreateOn; Fault=$global:PraGate.Audit.Fault
                    Starts=$global:PraGate.Audit.Starts; Stops=$global:PraGate.Audit.Stops; Sleeps=$global:PraGate.Audit.Sleeps
                    TranscriptStarted=$context.TranscriptStarted; TranscriptCreated=[bool]$context['_PraTranscriptCreated']
                    Trace=$global:PraGate.Audit.Trace.ToArray(); Result=$global:PraGate.Audit.Result; Issues=$context.Issues.ToArray()
                    Artifacts=$artifacts; Events=@(Get-GateEvents $runtime)
                }
                [IO.File]::WriteAllText((Join-Path $env:PRA_GATE_EVIDENCE ((Split-Path $runtime.Root -Leaf)+'.audit.json')),($record | ConvertTo-Json -Depth 20),(New-Object Text.UTF8Encoding($true)))
            }
            @(Get-GateEvents $global:PraGate.Runtime).Count | Should -Be 0 -Because 'audit units must never reach AD, ADSync, EXO or the synthetic cloud phase'
        } finally {
            # Reset only module bookkeeping, even if an assertion failed. NEVER call native Stop here.
            InModuleScope PRA.Common { $script:TranscriptOwner=$null }
        }
    }
    It 'keeps the bounded transcript wait helper private to Common' {
        (Get-Module PRA.Common).ExportedFunctions.Keys | Should -Not -Contain 'Wait-PraTranscriptFile'
        InModuleScope PRA.Common {
            (Get-Command Wait-PraTranscriptFile -ErrorAction Stop).ModuleName | Should -Be 'PRA.Common'
            $functionAst=(Get-Command Wait-PraTranscriptFile).ScriptBlock.Ast
            $timeout=@($functionAst.FindAll({ param($node) $node -is [Management.Automation.Language.ParameterAst] -and $node.Name.VariablePath.UserPath -eq 'TimeoutMilliseconds' },$true))
            $timeout.Count | Should -Be 1
            $timeout[0].DefaultValue.SafeGetValue() | Should -Be 5000
        }
    }
    It 'accepts successful Start with no file until <CreateOn>, then finalizes PASS with the actual path' -ForEach @(@{CreateOn='Host'},@{CreateOn='Poll2'}) {
        $global:PraGate.Audit.CreateOn=$CreateOn
        InModuleScope PRA.Common {
            $context=$global:PraGate.Context; $audit=$global:PraGate.Audit
            { Initialize-PraAudit $context } | Should -Not -Throw
            $audit.Starts | Should -Be 1
            $audit.Stops | Should -Be 0 -Because 'Initialize must not stop any transcript'
            @($audit.Trace | Where-Object Operation -eq 'Start')[0].Exists | Should -BeFalse
            $firstHost=@($audit.Trace | Where-Object Operation -eq 'Host')[0]
            $firstHost.Started | Should -BeTrue
            $firstHost.Created | Should -BeFalse
            $firstHost.Exists | Should -BeFalse
            $firstHost.Issues | Should -Be 0
            $firstHost.Text | Should -Not -Match 'Audit initialis|RESULT:|absent|indisponible'
            if ($audit.CreateOn -eq 'Poll2') {
                $audit.Sleeps | Should -Be 2
                @($audit.Trace | Where-Object { $_.Operation -eq 'PollSleep' -and $_.Created }).Count | Should -Be 0
            }
            $context.TranscriptStarted | Should -BeTrue
            $context['_PraTranscriptCreated'] | Should -BeTrue
            [object]::ReferenceEquals($script:TranscriptOwner,$context) | Should -BeTrue
            $context.Issues.Count | Should -Be 0
            $context.ExitCode | Should -Be 0
            [IO.File]::ReadAllText($context.LogFile) | Should -Not -Match 'absent|Initialisation audit :'
            $result=Complete-PraRun $context; $audit.Result=$result
            $result.ExitCode | Should -Be 0
            $result.ErrorCount | Should -Be 0
            @($result.Issues).Count | Should -Be 0
            $result.TranscriptPath | Should -BeExactly $context.TranscriptPath
            [IO.File]::ReadAllText($result.TranscriptPath) | Should -Match '(?m)^RESULT: PASS\r?$'
            $audit.Stops | Should -Be 1
            $context.TranscriptStarted | Should -BeFalse
            $script:TranscriptOwner | Should -BeNullOrEmpty
        }
    }
    It 'times out read-only on a <State> path without manufacturing or changing transcript bytes' -ForEach @(@{State='Missing'},@{State='Empty'},@{State='Directory'}) {
        $global:PraGate.Audit.CreateOn='Never'
        $path=Join-Path $global:PraGate.Context.LogFolder ('wait['+$State+'].transcript.txt')
        $global:PraGate.Audit.Path=$path
        if ($State -eq 'Empty') { [IO.File]::WriteAllBytes($path,[byte[]]@()) }
        if ($State -eq 'Directory') { $null=New-Item -ItemType Directory -Path $path }
        InModuleScope PRA.Common {
            $clock=[Diagnostics.Stopwatch]::StartNew()
            { Wait-PraTranscriptFile -LiteralPath $global:PraGate.Audit.Path -TimeoutMilliseconds 100 } | Should -Throw '*transcript*'
            $clock.ElapsedMilliseconds | Should -BeLessThan 2000
            $global:PraGate.Audit.Starts | Should -Be 0
            $global:PraGate.Audit.Stops | Should -Be 0
        }
        if ($State -eq 'Empty') {
            (Get-Item -LiteralPath $path).Length | Should -Be 0
            [Convert]::ToBase64String([IO.File]::ReadAllBytes($path)) | Should -BeExactly ''
        } elseif ($State -eq 'Directory') { [IO.Directory]::Exists($path) | Should -BeTrue }
        else { Test-Path -LiteralPath $path | Should -BeFalse }
    }
    It 'accepts a nonempty literal path without sleeps or writes' {
        $path=Join-Path $global:PraGate.Context.LogFolder 'ready[1].transcript.txt'
        [IO.File]::WriteAllBytes($path,[byte[]](0,1,127,128,254,255))
        $before=[Convert]::ToBase64String([IO.File]::ReadAllBytes($path))
        $global:PraGate.Audit.Path=$path
        InModuleScope PRA.Common {
            { Wait-PraTranscriptFile -LiteralPath $global:PraGate.Audit.Path -TimeoutMilliseconds 100 } | Should -Not -Throw
            $global:PraGate.Audit.Sleeps | Should -Be 0
            $global:PraGate.Audit.Starts | Should -Be 0
            $global:PraGate.Audit.Stops | Should -Be 0
        }
        [Convert]::ToBase64String([IO.File]::ReadAllBytes($path)) | Should -BeExactly $before
    }
    It 'fails closed when successful Start leaves a <CreateOn> file, stopping only its own transcript at completion' -ForEach @(@{CreateOn='Never'},@{CreateOn='Empty'}) {
        $global:PraGate.Audit.CreateOn=$CreateOn
        InModuleScope PRA.Common {
            $context=$global:PraGate.Context; $audit=$global:PraGate.Audit
            # Inject the timeout at the helper boundary: do not pay the default 5 s per failure.
            Mock Wait-PraTranscriptFile {
                param($LiteralPath)
                $LiteralPath | Should -BeExactly $global:PraGate.Context.TranscriptPath
                $global:PraGate.Context.TranscriptStarted | Should -BeTrue
                $global:PraGate.Context['_PraTranscriptCreated'] | Should -BeFalse
                [object]::ReferenceEquals($script:TranscriptOwner,$global:PraGate.Context) | Should -BeTrue
                throw [TimeoutException]::new('SYNTHETIC: transcript wait timeout')
            }
            { Initialize-PraAudit $context } | Should -Throw '*transcript wait timeout*'
            $context.Issues.Count | Should -BeGreaterThan 0
            $context.ExitCode | Should -Be 1
            $context['_PraTranscriptCreated'] | Should -BeFalse
            $context.TranscriptStarted | Should -BeTrue
            $audit.Starts | Should -Be 1
            $audit.Stops | Should -Be 0
            [IO.File]::ReadAllText($context.LogFile) | Should -Not -Match 'Audit initialis'
            @(Get-ChildItem -LiteralPath $context.ReportFolder -File).Count | Should -Be 0
            $result=Complete-PraRun $context; $audit.Result=$result
            $result.ExitCode | Should -Be 1
            $result.TranscriptPath | Should -BeNullOrEmpty -Because 'a failed audit must not advertise an absent or empty transcript'
            $audit.Stops | Should -Be 1
            $context.TranscriptStarted | Should -BeFalse
            $script:TranscriptOwner | Should -BeNullOrEmpty
            if ($audit.CreateOn -eq 'Empty') { (Get-Item -LiteralPath $context.TranscriptPath).Length | Should -Be 0 }
            else { Test-Path -LiteralPath $context.TranscriptPath | Should -BeFalse }
        }
    }
    It 'propagates Start UnauthorizedAccess without taking ownership or stopping a foreign transcript' {
        $global:PraGate.Audit.Fault='Unauthorized'
        InModuleScope PRA.Common {
            $context=$global:PraGate.Context
            { Initialize-PraAudit $context } | Should -Throw '*transcript access denied*'
            $context.TranscriptStarted | Should -BeFalse
            [bool](Get-PraValue $context '_PraTranscriptCreated' $false) | Should -BeFalse
            $script:TranscriptOwner | Should -BeNullOrEmpty
            $global:PraGate.Audit.Starts | Should -Be 1
            $global:PraGate.Audit.Stops | Should -Be 0
            $result=Complete-PraRun $context; $global:PraGate.Audit.Result=$result
            $result.ExitCode | Should -Be 1
            $result.TranscriptPath | Should -BeNullOrEmpty
            Test-Path -LiteralPath $context.TranscriptPath | Should -BeFalse
            $global:PraGate.Audit.Stops | Should -Be 0
        }
    }
    It 'ignores a preset transcript path and leaves that existing file intact' {
        $context=$global:PraGate.Context
        $preset=Join-Path $context.LogFolder 'foreign-existing.transcript.txt'
        [IO.File]::WriteAllBytes($preset,[byte[]](0,10,13,127,128,254,255))
        $context.TranscriptPath=$preset
        $global:PraGate.Audit.Preset=$preset
        $before=[Convert]::ToBase64String([IO.File]::ReadAllBytes($preset))
        InModuleScope PRA.Common {
            $context=$global:PraGate.Context
            { Initialize-PraAudit $context } | Should -Not -Throw
            $context.TranscriptPath | Should -Not -BeExactly $global:PraGate.Audit.Preset
            Test-Path -LiteralPath $context.TranscriptPath -PathType Leaf | Should -BeTrue
            $result=Complete-PraRun $context; $global:PraGate.Audit.Result=$result
            $result.ExitCode | Should -Be 0
            $global:PraGate.Audit.Stops | Should -Be 1
        }
        [Convert]::ToBase64String([IO.File]::ReadAllBytes($preset)) | Should -BeExactly $before
    }
    It 'does not stop or append an owned transcript when another context completes with copied flags' {
        InModuleScope PRA.Common {
            $context=$global:PraGate.Context
            Initialize-PraAudit $context
            $before=[Convert]::ToBase64String([IO.File]::ReadAllBytes($context.TranscriptPath))
            $foreign=New-GateContext $global:PraGate.Runtime -Mode Preview
            $foreign.NoReport=$true
            $foreign.LogFile=Join-Path $foreign.LogFolder 'other-context.log'
            [IO.File]::WriteAllText($foreign.LogFile,'SYNTHETIC: independent context log')
            $foreign.TranscriptPath=$context.TranscriptPath; $foreign.TranscriptStarted=$true; $foreign['_PraTranscriptCreated']=$true
            $null=Complete-PraRun $foreign
            $global:PraGate.Audit.Stops | Should -Be 0
            [object]::ReferenceEquals($script:TranscriptOwner,$context) | Should -BeTrue
            $context.TranscriptStarted | Should -BeTrue
            [Convert]::ToBase64String([IO.File]::ReadAllBytes($context.TranscriptPath)) | Should -BeExactly $before
            $result=Complete-PraRun $context; $global:PraGate.Audit.Result=$result
            $result.ExitCode | Should -Be 0
            $global:PraGate.Audit.Stops | Should -Be 1
            [IO.File]::ReadAllText($result.TranscriptPath) | Should -Match 'RESULT: PASS'
        }
    }
    It 'refuses a second start from <Caller> without overwriting the first audit or losing ownership' -ForEach @(@{Caller='SameContext'},@{Caller='OtherContext'}) {
        $global:PraGate.Audit.Caller=$Caller
        InModuleScope PRA.Common {
            $context=$global:PraGate.Context
            Initialize-PraAudit $context
            $transcriptPath=$context.TranscriptPath; $logPath=$context.LogFile
            $transcriptBefore=[Convert]::ToBase64String([IO.File]::ReadAllBytes($transcriptPath))
            $logBefore=[Convert]::ToBase64String([IO.File]::ReadAllBytes($logPath))
            $second=if ($global:PraGate.Audit.Caller -eq 'SameContext') { $context } else { New-GateContext $global:PraGate.Runtime -Mode Preview }
            { Initialize-PraAudit $second } | Should -Throw '*transcript of this module is already running*'
            $global:PraGate.Audit.Starts | Should -Be 1
            $global:PraGate.Audit.Stops | Should -Be 0
            [object]::ReferenceEquals($script:TranscriptOwner,$context) | Should -BeTrue
            $context.TranscriptStarted | Should -BeTrue
            [Convert]::ToBase64String([IO.File]::ReadAllBytes($transcriptPath)) | Should -BeExactly $transcriptBefore
            [Convert]::ToBase64String([IO.File]::ReadAllBytes($logPath)) | Should -BeExactly $logBefore
        }
    }
    It 'still creates log and transcript under native WhatIf with NoReport=<NoReport>, without AD or sync' -ForEach @(@{NoReport=$false},@{NoReport=$true}) {
        $global:PraGate.Context.NoReport=$NoReport
        InModuleScope PRA.Common {
            $context=$global:PraGate.Context
            # Contradictory Apply/AllowMutation must not make audit creation depend on ShouldProcess.
            $context.Mode='Apply'; $context.AllowMutation=$true
            $WhatIfPreference=$true
            try {
                Initialize-PraAudit $context
                $result=Complete-PraRun $context; $global:PraGate.Audit.Result=$result
            } finally { $WhatIfPreference=$false }
            $result.ExitCode | Should -Be 0
            [IO.File]::ReadAllText($result.LogFile) | Should -Match 'RESULT: PASS'
            [IO.File]::ReadAllText($result.TranscriptPath) | Should -Match 'RESULT: PASS'
            $global:PraGate.Audit.Starts | Should -Be 1
            $global:PraGate.Audit.Stops | Should -Be 1
            if ($context.NoReport) {
                $result.CsvReport | Should -BeNullOrEmpty
                $result.HtmlReport | Should -BeNullOrEmpty
                @(Get-ChildItem -LiteralPath $context.ReportFolder -File).Count | Should -Be 0
            } else {
                (Get-Item -LiteralPath $result.CsvReport).Length | Should -BeGreaterThan 0
                (Get-Item -LiteralPath $result.HtmlReport).Length | Should -BeGreaterThan 0
            }
        }
    }
    It 'records an owned Stop failure as FAIL rather than appending a misleading PASS' {
        InModuleScope PRA.Common {
            $context=$global:PraGate.Context
            Initialize-PraAudit $context
            $global:PraGate.Audit.Fault='Stop'
            $result=Complete-PraRun $context; $global:PraGate.Audit.Result=$result
            $result.ExitCode | Should -Be 1
            ($result.Issues.Message -join ' ') | Should -Match 'transcript close refused'
            $text=[IO.File]::ReadAllText($result.TranscriptPath)
            $text | Should -Match 'RESULT: FAIL'
            $text | Should -Not -Match 'RESULT: PASS'
            $global:PraGate.Audit.Stops | Should -Be 1
            $context.TranscriptStarted | Should -BeFalse
            $script:TranscriptOwner | Should -BeNullOrEmpty
        }
    }
}

Describe 'Production Cloud internals - mocked external boundaries, no network' {
    BeforeAll {
        $global:PraGate.CloudNetworkPath=Join-Path $global:PraGate.Root 'PraGateCloudNetwork.psm1'
        $networkSource=@'
if ($env:PRA_GATE_NONET -cne 'SYNTHETIC-NO-NETWORK') { throw 'Synthetic interlock absent.' }
function Get-EXOMailbox { [CmdletBinding()]param($Filter,$Properties,$ResultSize,[switch]$InactiveMailboxOnly) throw 'SYNTHETIC BLOCK: EXO mailbox' }
function Get-EXORecipient { [CmdletBinding()]param($UserPrincipalName,$Filter,$Properties,$ResultSize) throw 'SYNTHETIC BLOCK: EXO recipient' }
function Get-MgUser { [CmdletBinding()]param($UserId,$Property) throw 'SYNTHETIC BLOCK: Graph user' }
function Get-MgUserLicenseDetail { [CmdletBinding()]param($UserId,[switch]$All) throw 'SYNTHETIC BLOCK: Graph license' }
function Get-MgContext { [CmdletBinding()]param() [pscustomobject]@{TenantId='20000000-0000-0000-0000-000000000002';ContextScope='Process'} }
function Get-ConnectionInformation { [CmdletBinding()]param() [pscustomobject]@{TenantID='20000000-0000-0000-0000-000000000002';State='Connected';TokenStatus='Active';ConnectionId='30000000-0000-0000-0000-000000000003';ModuleName=$global:PraGate.CloudNetworkPath} }
Export-ModuleMember -Function Get-EXOMailbox,Get-EXORecipient,Get-MgUser,Get-MgUserLicenseDetail,Get-ConnectionInformation,Get-MgContext
'@
        [IO.File]::WriteAllText($global:PraGate.CloudNetworkPath,$networkSource,(New-Object Text.UTF8Encoding($true)))
        Import-Module $global:PraGate.CloudNetworkPath -Global -Force
        Import-Module (Join-Path $global:PraGate.Package 'module\PRA.Cloud.psm1') -Force -Global
    }
    BeforeEach {
        $global:PraGate.Runtime=New-GateRuntime -Name 'cloud-unit'
        $global:PraGate.CloudContext=New-GateContext $global:PraGate.Runtime -Mode Preview -Action Recover
        $global:PraGate.CloudContext.Phase='Cloud'; $global:PraGate.CloudContext.Once=$true
        $global:PraGate.CloudContext.CheckScope='Both'; $global:PraGate.CloudContext.IntervalMinutes=0; $global:PraGate.CloudContext.TimeoutMinutes=0
        $global:PraGate.CloudContext.Config.Cloud=@{CheckMailbox=$true;CheckLicense=$false;MailboxCheckVia='Exo';RequiredSkuPartNumber='';TenantId='20000000-0000-0000-0000-000000000002'}
        $global:PraGate.CloudContext.Config.SharedMailbox.GrantFullAccess=$false
        $global:PraGate.CloudRow=New-PraRow $global:PraGate.CloudContext ([pscustomobject]@{ObjectGuid='00000000-0000-0000-0000-000000000001';UserPrincipalName='user1@gate.invalid';IsShared=$false})
        $global:PraGate.CloudCalls=@{Writes=0;Connected=0}
    }
    It 'does not interpret an EXO query error as mailbox absence' {
        InModuleScope PRA.Cloud {
            Mock Connect-PraCloudSession { param($Context) $Context['_PraCloudSession']=@{Graph=$false;Exo=$true;Subprocess=$false;Binding=@{TenantId='20000000-0000-0000-0000-000000000002';ConnectionId='30000000-0000-0000-0000-000000000003';ModuleLocation=$global:PraGate.CloudNetworkPath;ModulePath=$global:PraGate.CloudNetworkPath}} }
            Mock Close-PraCloudSession { }
            Mock Get-EXOMailbox { throw 'SYNTHETIC: unavailable, unknown state' }
            Invoke-PraCloudPhase $global:PraGate.CloudContext @($global:PraGate.CloudRow) 'Recover'
            $global:PraGate.CloudRow.CloudStatus | Should -Be 'Error'
            $global:PraGate.CloudRow.CloudMailbox | Should -Not -BeTrue
            $global:PraGate.CloudContext.Issues.Count | Should -BeGreaterThan 0
        }
    }
    It 'requires absent mailbox AND an exactly known MailUser recipient for Recover' -ForEach @(@{Type='Absent';Expected='Pending'},@{Type='Unknown';Expected='Error'},@{Type='MailContact';Expected='Pending'},@{Type='MailUser';Expected='Success'}) {
        $global:PraGate.RecipientType=$Type; $global:PraGate.ExpectedCloudStatus=$Expected
        InModuleScope PRA.Cloud {
            Mock Connect-PraCloudSession { param($Context) $Context['_PraCloudSession']=@{Graph=$false;Exo=$true;Subprocess=$false;Binding=@{TenantId='20000000-0000-0000-0000-000000000002';ConnectionId='30000000-0000-0000-0000-000000000003';ModuleLocation=$global:PraGate.CloudNetworkPath;ModulePath=$global:PraGate.CloudNetworkPath}} }
            Mock Close-PraCloudSession { }
            Mock Get-EXOMailbox { }
            Mock Get-EXORecipient {
                switch ($global:PraGate.RecipientType) {
                    'Absent' { return }
                    'Unknown' { return [pscustomobject]@{UserPrincipalName='user1@gate.invalid'} }
                    default { return [pscustomobject]@{RecipientTypeDetails=$global:PraGate.RecipientType;UserPrincipalName='user1@gate.invalid';PrimarySmtpAddress='user1@gate.invalid';ExternalDirectoryObjectId='40000000-0000-0000-0000-000000000004'} }
                }
            }
            Invoke-PraCloudPhase $global:PraGate.CloudContext @($global:PraGate.CloudRow) 'Recover'
            $global:PraGate.CloudRow.CloudStatus | Should -Be $global:PraGate.ExpectedCloudStatus
            if ($global:PraGate.ExpectedCloudStatus -eq 'Pending') { $global:PraGate.CloudRow.FinalStatus | Should -Be 'Planned'; $global:PraGate.CloudRow.CloudMailbox | Should -Not -BeTrue } elseif ($global:PraGate.ExpectedCloudStatus -eq 'Error') { $global:PraGate.CloudRow.FinalStatus | Should -Be 'Error'; $global:PraGate.CloudRow.CloudMailbox | Should -Not -BeTrue }
        }
    }
    It 'uses the dedicated UPN selector without unsupported Recipient filter or output properties' {
        InModuleScope PRA.Cloud {
            Mock Connect-PraCloudSession { param($Context) $Context['_PraCloudSession']=@{Graph=$false;Exo=$true;Subprocess=$false;Binding=@{TenantId='20000000-0000-0000-0000-000000000002';ConnectionId='30000000-0000-0000-0000-000000000003';ModuleLocation=$global:PraGate.CloudNetworkPath;ModulePath=$global:PraGate.CloudNetworkPath}} }
            Mock Close-PraCloudSession { }
            Mock Get-EXOMailbox { }
            Mock Get-EXORecipient {
                param($UserPrincipalName,$Filter,$Properties,$ResultSize)
                if ('UserPrincipalName' -in @($Properties)) { throw 'InvalidProperties = UserPrincipalName' }
                if ($Filter) { throw 'Invalid filter clause: UserPrincipalName is not a Recipient filter property' }
                $UserPrincipalName | Should -Be 'user1@gate.invalid'
                $ResultSize | Should -Be 'Unlimited'
                [pscustomobject]@{
                    RecipientTypeDetails='MailUser'
                    PrimarySmtpAddress='mail-alias@gate.invalid'
                    ExternalDirectoryObjectId='00000000-0000-0000-0000-000000000001'
                    Guid='00000000-0000-0000-0000-000000000001'
                    DistinguishedName='CN=synthetic-recipient'
                }
            }
            Invoke-PraCloudPhase $global:PraGate.CloudContext @($global:PraGate.CloudRow) 'Recover'
            $global:PraGate.CloudRow.CloudStatus | Should -Be 'Success'
            $global:PraGate.CloudRow.DeprovisionConfirmed | Should -BeTrue
            $global:PraGate.CloudContext.Issues.Count | Should -Be 0
            Should -Invoke Get-EXORecipient -Times 1 -Exactly
        }
    }
    It 'honors KeepCloudShared but never confirms deprovision or authorizes tag cleanup' {
        $global:PraGate.CloudRow.IsShared=$true; $global:PraGate.CloudRow.PreserveCloudMailbox=$true
        $global:PraGate.CloudRow.DeprovisionConfirmed=$true
        InModuleScope PRA.Cloud {
            Mock Connect-PraCloudSession { param($Context) $Context['_PraCloudSession']=@{Graph=$false;Exo=$true;Subprocess=$false;Binding=@{TenantId='20000000-0000-0000-0000-000000000002';ConnectionId='30000000-0000-0000-0000-000000000003';ModuleLocation=$global:PraGate.CloudNetworkPath;ModulePath=$global:PraGate.CloudNetworkPath}} }
            Mock Close-PraCloudSession { }
            Mock Get-EXOMailbox { [pscustomobject]@{RecipientTypeDetails='SharedMailbox'} }
            Mock Get-EXORecipient { $global:PraGate.CloudCalls.Writes++; throw 'Kept shared must not be checked as an absent MailUser.' }
            Invoke-PraCloudPhase $global:PraGate.CloudContext @($global:PraGate.CloudRow) 'Recover'
            $global:PraGate.CloudRow.CloudStatus | Should -Be 'Success'
            $global:PraGate.CloudRow.CloudMailbox | Should -BeTrue
            $global:PraGate.CloudRow.DeprovisionConfirmed | Should -BeFalse
            $global:PraGate.CloudCalls.Writes | Should -Be 0
        }
    }
    It 'preserves preexisting licensing while requiring the configured SKU during Recover' -ForEach @(@{Sku='SYNTHETICSKU';Status='Success'},@{Sku='OTHER';Status='Pending'}) {
        $global:PraGate.CloudSku=$Sku; $global:PraGate.ExpectedCloudStatus=$Status
        $global:PraGate.CloudContext.Config.Cloud.CheckLicense=$true
        $global:PraGate.CloudContext.Config.Cloud.RequiredSkuPartNumber='SYNTHETICSKU'
        $global:PraGate.CloudRow.PreserveLicense=$true; $global:PraGate.CloudRow.DeprovisionConfirmed=$true
        InModuleScope PRA.Cloud {
            Mock Connect-PraCloudSession { param($Context) $Context['_PraCloudSession']=@{Graph=$true;Exo=$true;Subprocess=$false;GraphContext=@{TenantId='20000000-0000-0000-0000-000000000002';ContextScope='Process'};Binding=@{TenantId='20000000-0000-0000-0000-000000000002';ConnectionId='30000000-0000-0000-0000-000000000003';ModuleLocation=$global:PraGate.CloudNetworkPath;ModulePath=$global:PraGate.CloudNetworkPath}} }
            Mock Close-PraCloudSession { }
            Mock Get-EXOMailbox { }
            Mock Get-EXORecipient { [pscustomobject]@{RecipientTypeDetails='MailUser';UserPrincipalName='user1@gate.invalid';PrimarySmtpAddress='user1@gate.invalid';ExternalDirectoryObjectId='40000000-0000-0000-0000-000000000004'} }
            Mock Get-MgUser { [pscustomobject]@{assignedPlans=@([pscustomobject]@{Service='exchange';CapabilityStatus='Enabled'});assignedLicenses=@([pscustomobject]@{SkuId='10000000-0000-0000-0000-000000000000'})} }
            Mock Get-MgUserLicenseDetail { [pscustomobject]@{SkuPartNumber=$global:PraGate.CloudSku;ServicePlans=@()} }
            Invoke-PraCloudPhase $global:PraGate.CloudContext @($global:PraGate.CloudRow) 'Recover'
            $global:PraGate.CloudRow.CloudStatus | Should -Be $global:PraGate.ExpectedCloudStatus
            if ($global:PraGate.ExpectedCloudStatus -eq 'Success') { $global:PraGate.CloudRow.DeprovisionConfirmed | Should -BeTrue } else { $global:PraGate.CloudRow.FinalStatus | Should -Be 'Planned'; $global:PraGate.CloudRow.DeprovisionConfirmed | Should -BeFalse }
        }
    }
    It 'refuses unprojected Graph licensing state instead of assuming no license' {
        InModuleScope PRA.Cloud {
            $global:PraGate.CloudContext['_PraCloudSession']=@{Graph=$true;Exo=$false;Subprocess=$false;GraphContext=@{TenantId='20000000-0000-0000-0000-000000000002';ContextScope='Process'}}
            Mock Get-MgUser { [pscustomobject]@{assignedPlans=@()} }
            { Get-PraGraphFact $global:PraGate.CloudContext 'user1@gate.invalid' $false $true } | Should -Throw '*assignedLicenses*'
        }
    }
    It 'preserves explicit empty Graph collections without phantom plans/licenses' {
        InModuleScope PRA.Cloud {
            $global:PraGate.CloudContext['_PraCloudSession']=@{Graph=$true;Exo=$false;Subprocess=$false;GraphContext=@{TenantId='20000000-0000-0000-0000-000000000002';ContextScope='Process'}}
            Mock Get-MgUser { [pscustomobject]@{assignedPlans=@();assignedLicenses=@();provisionedPlans=@()} }
            Mock Get-MgUserLicenseDetail { }
            $facts=Get-PraGraphFact $global:PraGate.CloudContext 'user1@gate.invalid' $true $true
            $facts.LicenseCount | Should -Be 0
            $facts.Enabled | Should -BeFalse
            $facts.Provisioned | Should -BeFalse
        }
    }
    It 'blocks cloud permission writes in Preview, WhatIf, Recover or Finalize' -ForEach @(
        @{Mode='Preview';Action='Convert';Phase='Cloud';WhatIf=$false},@{Mode='Preview';Action='Convert';Phase='Cloud';WhatIf=$false},
        @{Mode='Apply';Action='Convert';Phase='Cloud';WhatIf=$true},@{Mode='Apply';Action='Recover';Phase='Cloud';WhatIf=$false},
        @{Mode='Apply';Action='Convert';Phase='Finalize';WhatIf=$false}
    ) {
        $global:PraGate.CloudContext.Mode=$Mode; $global:PraGate.CloudContext.Action=$Action; $global:PraGate.CloudContext.Phase=$Phase
        $global:PraGate.CloudContext.AllowMutation=$true; $global:PraGate.TestWhatIf=$WhatIf
        InModuleScope PRA.Cloud {
            Mock Invoke-PraExo { $global:PraGate.CloudCalls.Writes++; throw 'Mutation boundary unexpectedly reached.' }
            $WhatIfPreference=$global:PraGate.TestWhatIf
            try { { Invoke-PraPermissionGrant $global:PraGate.CloudContext $global:PraGate.CloudRow @{Upn='shared@gate.invalid';Trustee='user@gate.invalid';Right='FullAccess'} } | Should -Throw }
            finally { $WhatIfPreference=$false }
            $global:PraGate.CloudCalls.Writes | Should -Be 0
        }
    }
    AfterAll { Remove-Module PRA.Cloud,PraGateCloudNetwork -Force -ErrorAction SilentlyContinue }
}

Describe 'Native Cloud worker 1.3.6 - physical synthetic EXO provenance' -Tag 'NativeCloud136' {
    BeforeAll {
        # A real local module file supplies command metadata. No security guard/worker is mocked.
        $global:PraGate.NativeModulePath=Join-Path $global:PraGate.Root 'native-exo\PraGateNativeExo.psm1'
        $null=New-Item -ItemType Directory -Path (Split-Path $global:PraGate.NativeModulePath -Parent) -Force
        $nativeSource=@'
# SYNTHETIC EXO/Graph shapes only. No authentication library, HTTP client or AD provider.
Set-StrictMode -Version Latest
function Assert-NativeFixture {
    if ($env:PRA_GATE_NONET -cne 'SYNTHETIC-NO-NETWORK') { throw 'SYNTHETIC interlock absent.' }
}
function Get-ConnectionInformation {
    [CmdletBinding()]param()
    Assert-NativeFixture
    $s=$global:PraGate.Native; $s.ConnectionReads++
    if ($s.ConnectLifecycle -and $s.ExoConnect -le $s.ExoClose) { return }
    if ($s.Case -eq 'NoSession') { return }
    $tenant=$(if($s.SessionTenant){$s.SessionTenant}else{$s.Tenant}); $location=$global:PraGate.NativeModulePath; $id='30000000-0000-0000-0000-000000000003'
    if ($s.Case -eq 'ModuleBase') { $location=Split-Path $location -Parent }
    if ($s.Case -eq 'WrongTenant' -or ($s.Case -eq 'ChangedTenant' -and $s.Pauses.Count -gt 0)) { $tenant='90000000-0000-0000-0000-000000000009' }
    if ($s.Case -eq 'WrongProvenance') { $location=Join-Path $s.Root 'unloaded\PraGateNativeExo.psm1' }
    if ($s.Case -eq 'ModuleNameOnly') { $location='PraGateNativeExo' }
    if ($s.Case -eq 'ChangedSession' -and $s.Pauses.Count -gt 0) { $id='30000000-0000-0000-0000-000000000099' }
    $state='Connected'; $token='Active'
    if ($s.Case -eq 'Disconnected') { $state='Disconnected' }
    if ($s.Case -eq 'DisconnectedOnce' -and $s.ConnectionReads -le 1) { $state='Disconnected' }
    if ($s.Case -eq 'Expired') { $token='Expired' }
    [pscustomobject]@{TenantID=$tenant;State=$state;TokenStatus=$token;ModuleName=$location;ConnectionId=$id;UserPrincipalName='operator@gate.invalid';AppId=$s.SessionAppId}
    if ($s.Case -eq 'MultipleSessions') { [pscustomobject]@{TenantID=$tenant;State=$state;TokenStatus=$token;ModuleName=$location;ConnectionId='other';UserPrincipalName='operator@gate.invalid';AppId=$s.SessionAppId} }
}
function Get-EXORecipient {
    [CmdletBinding()]param($UserPrincipalName,$Filter,$Properties,$ResultSize)
    Assert-NativeFixture
    $s=$global:PraGate.Native
    if ($Filter) { throw 'SYNTHETIC: no unsupported Recipient filter.' }
    if ('UserPrincipalName' -in @($Properties)) { throw 'SYNTHETIC: unsupported Recipient output property.' }
    if ($UserPrincipalName -notin @($s.Target,$s.Trustee)) { throw 'SYNTHETIC: recipient outside fixture scope.' }
    [void]$s.RecipientSelectors.Add([string]$UserPrincipalName)
    $target=$UserPrincipalName -eq $s.Target
    if ($s.Case -in @('RecipientNotFound','RecipientNotFoundThrown','RecipientNotFoundOther') -and $target) {
        # Shape of the real answer (lab, Recover check): HTTP 404 + ManagementObjectNotFoundException.
        $object=if ($s.Case -eq 'RecipientNotFoundOther') { 'other@gate.invalid' } else { $UserPrincipalName }
        $m="Error executing request. The operation couldn't be performed because object '$object' couldn't be found on 'GATEDC01.prod.outlook.com'."
        $payload=@{error=@{code='NotFound';message=$m;details=@(@{code='Context';message=('Ex6F9304|Microsoft.Exchange.Configuration.Tasks.ManagementObjectNotFoundException|'+$m);target=''});innererror=@{message=$m;type='Microsoft.Exchange.Admin.OData.Core.ODataServiceException'}}}
        $text='Error while querying REST service. HttpStatusCode=404 ErrorMessage='+($payload | ConvertTo-Json -Depth 6 -Compress)
        if ($s.Case -eq 'RecipientNotFoundThrown') { throw $text }
        Write-Error -Message $text
        return
    }
    $oid=if ($target) { $s.TargetId } else { $s.TrusteeId }
    if ($s.Case -eq 'ChangedPrincipal' -and -not $target -and $s.Pauses.Count -gt 0) { $oid='40000000-0000-0000-0000-000000000099' }
    $smtp=if ($target) { 'shared-smtp@gate.invalid' } else { 'trustee-smtp@gate.invalid' }
    [pscustomobject]@{RecipientTypeDetails=$(if($target){'SharedMailbox'}else{'UserMailbox'});PrimarySmtpAddress=$smtp;ExternalDirectoryObjectId=$oid;Guid=$oid;DistinguishedName=('CN='+$oid);Identity=$oid}
}
function Get-EXOMailbox {
    [CmdletBinding()]param($Filter,$Properties,$ResultSize,[switch]$InactiveMailboxOnly)
    Assert-NativeFixture
    [pscustomobject]@{RecipientTypeDetails='SharedMailbox';PrimarySmtpAddress='shared-smtp@gate.invalid';ExternalDirectoryObjectId=$global:PraGate.Native.TargetId}
}
function New-NativeAcl {
    param([string]$Right,[string]$Principal,[switch]$Deny)
    $s=$global:PraGate.Native
    $rights=@($Right)
    if ($s.EnumRights) { $rights=@([Enum]::Parse(('PraGateNativeRight' -as [type]),$Right)) }
    $entry=[ordered]@{Identity=$s.TargetId;AccessRights=$rights;IsInherited=$false}
    if ($Right -eq 'FullAccess') {
        $entry.User=$Principal
        $entry.Deny=if ($s.BoolDeny) { [bool]$Deny } else { [Management.Automation.SwitchParameter][bool]$Deny }
    } else { $entry.Trustee=$Principal; $entry.AccessControlType=if($Deny){'Deny'}else{'Allow'} }
    [pscustomobject]$entry
}
function Get-NativeAcl {
    param([string]$Identity,[string]$Principal,[string]$Right)
    Assert-NativeFixture
    $s=$global:PraGate.Native
    if ($Identity -notin @($s.Target,$s.TargetId,'shared-smtp@gate.invalid')) { throw 'SYNTHETIC: ACL outside target scope.' }
    $filtered=-not [string]::IsNullOrEmpty($Principal)
    if ($filtered) { $s.FilteredReads++ } else { $s.GlobalReads++; if($s.Writes -gt 0){$s.PostAddReads++} }
    if ($s.Case -eq 'GlobalReadError' -and -not $filtered) { throw 'SYNTHETIC ACL AccessDenied global' }
    if ($s.Case -eq 'LateReadError' -and $s.Pauses.Count -gt 0) { throw 'SYNTHETIC ACL AccessDenied during verification' }
    if ($s.Case -eq 'EmptyGlobal' -and -not $filtered) { return }
    if ($s.Case -eq 'MalformedGlobal' -and -not $filtered) { [pscustomobject]@{Identity=$s.TargetId;User='NT AUTHORITY\SELF'};return }
    if ($s.Case -eq 'GlobalDeny' -and -not $filtered) { New-NativeAcl $Right 'unrelated-group@gate.invalid' -Deny; New-NativeAcl $Right 'NT AUTHORITY\SELF';return }
    $visible=$s.Present -or ($s.Writes -gt 0 -and $s.Pauses.Count -ge $s.VisibleAfter)
    if ($filtered) {
        if ($s.Case -in @('ExactNotFound','Generic404','AccessDenied404','WrongNotFoundUser','WrongNotFoundTarget','MalformedNotFound') -and -not $visible) {
            # Like the real EXO cmdlet (seen in the lab): a non-terminating error, so -ErrorAction decides.
            $code='NotFound';$message='No permissions were found for the user:'+$s.Trustee
            if ($s.Case -eq 'Generic404') { Write-Error -Message 'SYNTHETIC HTTP 404 NotFound unknown error'; return }
            if ($s.Case -eq 'MalformedNotFound') { Write-Error -Message 'SYNTHETIC {"error":{"code":"NotFound","message":'; return }
            if ($s.Case -eq 'AccessDenied404') { $code='AccessDenied' }
            if ($s.Case -eq 'WrongNotFoundUser') { $message='No permissions were found for the user:other@gate.invalid' }
            if ($s.Case -eq 'WrongNotFoundTarget') { $message='Mailbox not found' }
            $payload=@{error=@{code=$code;message=$message;innererror=@{message=$message;type='Microsoft.Exchange.Admin.OData.Core.ODataServiceException'}}}
            Write-Error -Message ('An error occurred while processing this request.. '+($payload | ConvertTo-Json -Depth 5 -Compress)+'. An error was read from the payload.')
            return
        }
        if ($s.Case -eq 'FilteredMismatch') { New-NativeAcl $Right 'unrelated@gate.invalid';return }
        if ($s.Case -eq 'FilteredOnly') { New-NativeAcl $Right 'trustee-smtp@gate.invalid';return }
        if ($s.Case -eq 'GlobalOnly') { return }
        if ($visible) { New-NativeAcl $Right 'trustee-smtp@gate.invalid' }
        return
    }
    $self=New-NativeAcl $Right 'NT AUTHORITY\SELF'
    if ($s.Case -eq 'AmbiguousDeny' -and $Right -eq 'FullAccess') { $self.Deny='False' }
    if ($s.Case -eq 'MalformedRights') { $self.AccessRights=@(42) }
    if ($s.Case -eq 'MismatchedMailbox') { $self.Identity='other-mailbox@gate.invalid' }
    $self
    if (($visible -and $s.Case -ne 'FilteredOnly') -or $s.Case -eq 'GlobalOnly') { New-NativeAcl $Right 'trustee-smtp@gate.invalid' }
}
function Get-EXOMailboxPermission {
    [CmdletBinding()]param($Identity,$User,$ResultSize)
    if ($User) { [void]$global:PraGate.Native.FilteredErrorActions.Add([string]$ErrorActionPreference) }
    Get-NativeAcl -Identity $Identity -Principal $User -Right FullAccess
}
function Get-EXORecipientPermission {
    [CmdletBinding()]param($Identity,$Trustee,$ResultSize)
    Get-NativeAcl -Identity $Identity -Principal $Trustee -Right SendAs
}
function Add-MailboxPermission {
    [CmdletBinding(SupportsShouldProcess)]param($Identity,$User,$AccessRights,[bool]$AutoMapping,$InheritanceType)
    Assert-NativeFixture
    $s=$global:PraGate.Native
    if ($Identity -notin @($s.Target,$s.TargetId,'shared-smtp@gate.invalid') -or $User -ne $s.Trustee -or [string]$AccessRights -ne 'FullAccess') { throw 'SYNTHETIC: unexpected grant scope.' }
    $s.Writes++;$s.AutoMapping=$AutoMapping
    if ($s.Case -eq 'AmbiguousWrite') { throw 'SYNTHETIC: Add result indeterminate' }
}
function Add-RecipientPermission {
    [CmdletBinding(SupportsShouldProcess)]param($Identity,$Trustee,$AccessRights)
    Assert-NativeFixture
    $s=$global:PraGate.Native
    if ($Identity -notin @($s.Target,$s.TargetId,'shared-smtp@gate.invalid') -or $Trustee -ne $s.Trustee -or [string]$AccessRights -ne 'SendAs') { throw 'SYNTHETIC: unexpected grant scope.' }
    $s.Writes++
    if ($s.Case -eq 'AmbiguousWrite') { throw 'SYNTHETIC: Add result indeterminate' }
}
function Set-Mailbox { [CmdletBinding(SupportsShouldProcess)]param($Identity,$GrantSendOnBehalfTo) throw 'SYNTHETIC: unexpected SendOnBehalf grant.' }
function Connect-ExchangeOnline { [CmdletBinding()]param($UserPrincipalName,[switch]$DisableWAM,[switch]$ShowBanner,$AppId,$CertificateThumbprint,$Organization) Assert-NativeFixture; [void]$global:PraGate.Native.ConnectionOrder.Add('Connect-ExchangeOnline');$global:PraGate.Native.ExoConnect++;$global:PraGate.Native.ConnectUpn=$UserPrincipalName;$global:PraGate.Native.DisableWAM=[bool]$DisableWAM }
function Disconnect-ExchangeOnline { [CmdletBinding(SupportsShouldProcess)]param($ConnectionId) Assert-NativeFixture;if($ConnectionId -ne '30000000-0000-0000-0000-000000000003'){throw 'SYNTHETIC: non-owned disconnect refused.'};$global:PraGate.Native.ExoClose++ }
function Connect-MgGraph {
    [CmdletBinding()]param($TenantId,$Scopes,[switch]$NoWelcome,$ContextScope,$ClientId,$CertificateThumbprint)
    Assert-NativeFixture;$s=$global:PraGate.Native
    [void]$s.ConnectionOrder.Add('Connect-MgGraph')
    if ($s.Case -eq 'GraphConnectFailure') { throw 'SYNTHETIC: Graph connection failed before any context was created.' }
    if ($s.Case -eq 'GraphAssemblyConflict') { throw "Method 'GetTokenAsync' in type 'Microsoft.Graph.PowerShell.Authentication.Core.Utilities.UserProvidedTokenCredential' from assembly 'Microsoft.Graph.Authentication.Core, Version=2.38.1.0' does not have an implementation." }
    $s.GraphConnect++
}
function Disconnect-MgGraph { [CmdletBinding()]param() Assert-NativeFixture;$global:PraGate.Native.GraphClose++ }
function Get-MgContext {
    [CmdletBinding()]param()
    Assert-NativeFixture;$s=$global:PraGate.Native
    if($s.Case -eq 'GraphPreexistingContext'){return [pscustomobject]@{TenantId='90000000-0000-0000-0000-000000000009';ContextScope='Process';Account='unrelated@gate.invalid'}}
    if($s.GraphConnect -le $s.GraphClose){return}
    $tenant=$s.Tenant
    if($s.Case -eq 'GraphWrongTenant'){$tenant='90000000-0000-0000-0000-000000000009'}
    [pscustomobject]@{TenantId=$tenant;ContextScope='Process'}
}
function Get-MgUser {
    [CmdletBinding()]param($UserId,$Property)
    Assert-NativeFixture;$s=$global:PraGate.Native
    [void]$s.GraphSelectors.Add([string]$UserId)
    $oid=if($UserId -eq $s.Target){$s.TargetId}else{$s.TrusteeId}
    if($s.Case -eq 'GraphMismatchedIdentity'){$oid='90000000-0000-0000-0000-000000000009'}
    [pscustomobject]@{Id=$oid;UserPrincipalName=$UserId}
}
Export-ModuleMember -Function Get-ConnectionInformation,Get-EXORecipient,Get-EXOMailbox,Get-EXOMailboxPermission,Get-EXORecipientPermission,Add-MailboxPermission,Add-RecipientPermission,Set-Mailbox,Connect-ExchangeOnline,Disconnect-ExchangeOnline,Connect-MgGraph,Disconnect-MgGraph,Get-MgContext,Get-MgUser
'@
        [IO.File]::WriteAllText($global:PraGate.NativeModulePath,$nativeSource,(New-Object Text.UTF8Encoding($true)))
        if (-not ('PraGateNativeRight' -as [type])) { Add-Type -TypeDefinition 'public enum PraGateNativeRight { FullAccess=1, SendAs=2 }' }
        Import-Module $global:PraGate.NativeModulePath -Global -Force
        Import-Module (Join-Path $global:PraGate.Package 'module\PRA.Cloud.psm1') -Global -Force
    }
    BeforeEach {
        $global:PraGate.Runtime=New-GateRuntime -Name 'native-cloud'
        $global:PraGate.Native=@{
            Root=$global:PraGate.Runtime.Root;Case='Normal';Tenant='20000000-0000-0000-0000-000000000002'
            Target='shared@gate.invalid';Trustee='trustee@gate.invalid';TargetId='40000000-0000-0000-0000-000000000004';TrusteeId='50000000-0000-0000-0000-000000000005'
            Present=$false;BoolDeny=$false;EnumRights=$true;VisibleAfter=0;Writes=0;GlobalReads=0;FilteredReads=0;PostAddReads=0;ConnectionReads=0;AutoMapping=$false;ConnectLifecycle=$false
            ExoConnect=0;ExoClose=0;GraphConnect=0;GraphClose=0;ConnectUpn='';DisableWAM=$false;Organization='tenant.onmicrosoft.com';SessionTenant='';SessionAppId='';ConnectionOrder=(New-Object 'Collections.Generic.List[string]')
            Pauses=(New-Object 'Collections.Generic.List[int]');RecipientSelectors=(New-Object 'Collections.Generic.List[string]');GraphSelectors=(New-Object 'Collections.Generic.List[string]');Journal=(New-Object 'Collections.Generic.List[string]')
            FilteredErrorActions=(New-Object 'Collections.Generic.List[string]')
        }
        $global:PraGate.NativeParams=@{Upn=$global:PraGate.Native.Target;Trustee=$global:PraGate.Native.Trustee;Right='FullAccess';AutoMapping=$true;TenantId=$global:PraGate.Native.Tenant;GrantVerifyAttempts=13;GrantVerifyDelaySeconds=10}
        $global:PraGate.NativePermit=@{AllowMutation=$true;Approved=$true;Authorized=$true;JournalStarted=$true;Target=$global:PraGate.Native.Target;Trustee=$global:PraGate.Native.Trustee;Right='FullAccess';Action='Convert';Mode='Apply';Phase='Both'}
        $global:PraGate.NativeBinding=@{TenantId=$global:PraGate.Native.Tenant;ConnectionId='30000000-0000-0000-0000-000000000003';ModuleLocation=$global:PraGate.NativeModulePath;ModulePath=$global:PraGate.NativeModulePath}
        InModuleScope PRA.Cloud {
            Mock Start-Sleep { param($Seconds) [void]$global:PraGate.Native.Pauses.Add([int]$Seconds) }
        }
    }
    It 'normalizes native SwitchParameter/enum and bool Deny with idempotent <Right> grants' -ForEach @(@{Right='FullAccess';Bool=$false},@{Right='FullAccess';Bool=$true},@{Right='SendAs';Bool=$false}) {
        $global:PraGate.Native.Present=$true;$global:PraGate.Native.BoolDeny=$Bool
        $global:PraGate.NativeParams.Right=$Right;$global:PraGate.NativePermit.Right=$Right
        InModuleScope PRA.Cloud {
            $result=& $script:PraExoWorker 'Grant' $global:PraGate.NativeParams $global:PraGate.NativePermit $global:PraGate.NativeBinding { [void]$global:PraGate.Native.Journal.Add('Applied') }
            $result.Verified | Should -BeTrue
            $result.Mutated | Should -BeFalse
        }
        $global:PraGate.Native.Writes | Should -Be 0
        $global:PraGate.Native.GlobalReads | Should -BeGreaterThan 0
        $global:PraGate.Native.FilteredReads | Should -BeGreaterThan 0
        $global:PraGate.Native.RecipientSelectors | Should -Contain 'trustee@gate.invalid'
    }
    It 'accepts exact structured FullAccess NotFound only after a valid global absence and adds once' {
        $Right='FullAccess'
        $global:PraGate.Native.Case='ExactNotFound';$global:PraGate.NativeParams.Right=$Right;$global:PraGate.NativePermit.Right=$Right
        InModuleScope PRA.Cloud {
            $result=& $script:PraExoWorker 'Grant' $global:PraGate.NativeParams $global:PraGate.NativePermit $global:PraGate.NativeBinding { [void]$global:PraGate.Native.Journal.Add('Applied') }
            $result.Verified | Should -BeTrue
            $result.Mutated | Should -BeTrue
        }
        $global:PraGate.Native.Writes | Should -Be 1
        $global:PraGate.Native.GlobalReads | Should -BeGreaterThan 1
        $global:PraGate.Native.Pauses.Count | Should -Be 0
        # With -ErrorAction Stop, Windows PowerShell 5.1 writes a TerminatingError line in the transcript
        # even when the error is expected and handled: the filtered read must never use Stop.
        $global:PraGate.Native.FilteredErrorActions.Count | Should -BeGreaterThan 0
        $global:PraGate.Native.FilteredErrorActions | Should -Not -Contain 'Stop'
    }
    It 'reads the exact Exchange Online 404 of a recipient as absent (<Case>)' -ForEach @(@{Case='RecipientNotFound'},@{Case='RecipientNotFoundThrown'}) {
        $global:PraGate.Native.Case=$Case
        InModuleScope PRA.Cloud {
            $result=& $script:PraExoWorker 'Recipient' $global:PraGate.NativeParams $global:PraGate.NativePermit $global:PraGate.NativeBinding $null
            $result.Found | Should -BeFalse
        }
        $global:PraGate.Native.RecipientSelectors | Should -Contain 'shared@gate.invalid'
    }
    It 'refuses a recipient 404 that names another object' {
        $global:PraGate.Native.Case='RecipientNotFoundOther'
        InModuleScope PRA.Cloud { { & $script:PraExoWorker 'Recipient' $global:PraGate.NativeParams $global:PraGate.NativePermit $global:PraGate.NativeBinding $null } | Should -Throw "*other@gate.invalid*" }
        $global:PraGate.Native.Writes | Should -Be 0
    }
    It 'refuses unknown absence, malformed or contradictory ACL <Case> for <Right> without Add' -ForEach @(
        @{Case='Generic404';Right='FullAccess'},@{Case='AccessDenied404';Right='FullAccess'},@{Case='WrongNotFoundUser';Right='FullAccess'},@{Case='WrongNotFoundTarget';Right='FullAccess'},@{Case='MalformedNotFound';Right='FullAccess'},
        @{Case='GlobalReadError';Right='FullAccess'},@{Case='EmptyGlobal';Right='FullAccess'},@{Case='MalformedGlobal';Right='FullAccess'},@{Case='GlobalDeny';Right='FullAccess'},@{Case='AmbiguousDeny';Right='FullAccess'},@{Case='MalformedRights';Right='FullAccess'},@{Case='MismatchedMailbox';Right='FullAccess'},@{Case='FilteredMismatch';Right='FullAccess'},@{Case='FilteredOnly';Right='FullAccess'},@{Case='GlobalOnly';Right='FullAccess'},
        @{Case='Generic404';Right='SendAs'},@{Case='EmptyGlobal';Right='SendAs'},@{Case='MalformedGlobal';Right='SendAs'},@{Case='GlobalDeny';Right='SendAs'},@{Case='FilteredMismatch';Right='SendAs'}
    ) {
        $global:PraGate.Native.Case=$Case;$global:PraGate.NativeParams.Right=$Right;$global:PraGate.NativePermit.Right=$Right
        InModuleScope PRA.Cloud { { & $script:PraExoWorker 'Grant' $global:PraGate.NativeParams $global:PraGate.NativePermit $global:PraGate.NativeBinding { [void]$global:PraGate.Native.Journal.Add('Applied') } } | Should -Throw }
        $global:PraGate.Native.Writes | Should -Be 0
        $global:PraGate.Native.Pauses.Count | Should -Be 0
    }
    It 'accepts an app-only EXO session reporting Organization as TenantID and rejects AppId drift' {
        $global:PraGate.Native.Present=$true
        $global:PraGate.Native.SessionTenant=$global:PraGate.Native.Organization
        $global:PraGate.Native.SessionAppId='11111111-1111-1111-1111-111111111111'
        $global:PraGate.NativeBinding.Organization=$global:PraGate.Native.Organization
        $global:PraGate.NativeBinding.AppId=$global:PraGate.Native.SessionAppId
        InModuleScope PRA.Cloud {
            $result=& $script:PraExoWorker 'Grant' $global:PraGate.NativeParams $global:PraGate.NativePermit $global:PraGate.NativeBinding { [void]$global:PraGate.Native.Journal.Add('Applied') }
            $result.Verified | Should -BeTrue
            $result.Mutated | Should -BeFalse
        }
        $global:PraGate.Native.Writes | Should -Be 0
        $global:PraGate.Native.SessionAppId='22222222-2222-2222-2222-222222222222'
        InModuleScope PRA.Cloud { { & $script:PraExoWorker 'Grant' $global:PraGate.NativeParams $global:PraGate.NativePermit $global:PraGate.NativeBinding { [void]$global:PraGate.Native.Journal.Add('Applied') } } | Should -Throw '*wrong application ID (22222222-2222-2222-2222-222222222222), expected 11111111-1111-1111-1111-111111111111*' }
        $global:PraGate.Native.Writes | Should -Be 0
    }
    It 'rejects unusable tenant/session/provenance <Case> before Add' -ForEach @(@{Case='NoSession'},@{Case='MultipleSessions'},@{Case='WrongTenant'},@{Case='WrongProvenance'},@{Case='ModuleNameOnly'},@{Case='Disconnected'},@{Case='Expired'}) {
        $global:PraGate.Native.Case=$Case
        InModuleScope PRA.Cloud { { & $script:PraExoWorker 'Grant' $global:PraGate.NativeParams $global:PraGate.NativePermit $global:PraGate.NativeBinding { [void]$global:PraGate.Native.Journal.Add('Applied') } } | Should -Throw }
        $global:PraGate.Native.Writes | Should -Be 0
    }
    It 'names only the check that failed: <Case>' -Tag 'Release313i' -ForEach @(
        @{Case='WrongTenant'; Message="Exchange Online session: wrong tenant (90000000-0000-0000-0000-000000000009), expected *."; Not='*connection state*'; Pauses=0},
        @{Case='Disconnected'; Message="Exchange Online session: connection state 'Disconnected', expected Connected."; Not='*wrong tenant*'; Pauses=1},
        @{Case='Expired'; Message="Exchange Online session: token status 'Expired', expected Active."; Not='*wrong tenant*'; Pauses=1}) {
        $global:PraGate.Native.Case=$Case
        $text = InModuleScope PRA.Cloud {
            try { & $script:PraExoWorker 'Grant' $global:PraGate.NativeParams $global:PraGate.NativePermit $global:PraGate.NativeBinding { [void]$global:PraGate.Native.Journal.Add('Applied') }; '' } catch { $_.Exception.Message }
        }
        $text | Should -BeLike $Message
        $text | Should -Not -BeLike $Not
        $text | Should -Not -BeLike '*token*connection ID*module path*'
        $global:PraGate.Native.Writes | Should -Be 0
        $global:PraGate.Native.Pauses.Count | Should -Be $Pauses
    }
    It 'reads the connection again once after a short pause when its state is not right yet, and goes on when the second read is right' -Tag 'Release313i' {
        $global:PraGate.Native.Case='DisconnectedOnce'; $global:PraGate.Native.Present=$true
        InModuleScope PRA.Cloud {
            $result=& $script:PraExoWorker 'Grant' $global:PraGate.NativeParams $global:PraGate.NativePermit $global:PraGate.NativeBinding { [void]$global:PraGate.Native.Journal.Add('Applied') }
            $result.Verified | Should -BeTrue
        }
        $global:PraGate.Native.Pauses.Count | Should -Be 1
        $global:PraGate.Native.Pauses[0] | Should -Be 2
        $global:PraGate.Native.ConnectionReads | Should -BeGreaterOrEqual 2
    }
    It 'accepts the exact loaded ModuleBase rather than requiring ModuleName to be a module name' {
        $global:PraGate.Native.Case='ModuleBase';$global:PraGate.NativeBinding.ModuleLocation=Split-Path $global:PraGate.NativeModulePath -Parent
        InModuleScope PRA.Cloud {
            $result=& $script:PraExoWorker 'Grant' $global:PraGate.NativeParams $global:PraGate.NativePermit $global:PraGate.NativeBinding { [void]$global:PraGate.Native.Journal.Add('Applied') }
            $result.Verified | Should -BeTrue
        }
        $global:PraGate.Native.Writes | Should -Be 1
    }
    It 'waits for delayed <Right> visibility with exactly 13 reads and twelve 10-second pauses, never repeating Add' -ForEach @(@{Right='FullAccess'},@{Right='SendAs'}) {
        $global:PraGate.Native.VisibleAfter=12;$global:PraGate.NativeParams.Right=$Right;$global:PraGate.NativePermit.Right=$Right
        InModuleScope PRA.Cloud {
            $result=& $script:PraExoWorker 'Grant' $global:PraGate.NativeParams $global:PraGate.NativePermit $global:PraGate.NativeBinding { [void]$global:PraGate.Native.Journal.Add('Applied') }
            $result.Verified | Should -BeTrue
            $result.Mutated | Should -BeTrue
        }
        $global:PraGate.Native.Writes | Should -Be 1
        $global:PraGate.Native.PostAddReads | Should -Be 13
        $global:PraGate.Native.Pauses.Count | Should -Be 12
        @($global:PraGate.Native.Pauses | Where-Object { $_ -ne 10 }).Count | Should -Be 0
    }
    It 'reports added-but-unverified on bounded timeout without repeating Add' {
        $global:PraGate.Native.VisibleAfter=99
        InModuleScope PRA.Cloud {
            $result=& $script:PraExoWorker 'Grant' $global:PraGate.NativeParams $global:PraGate.NativePermit $global:PraGate.NativeBinding { [void]$global:PraGate.Native.Journal.Add('Applied') }
            $result.Verified | Should -BeFalse
            $result.Mutated | Should -BeTrue
            $result.Error | Should -Match 'not verified after 13 reads'
        }
        $global:PraGate.Native.Writes | Should -Be 1
        $global:PraGate.Native.PostAddReads | Should -Be 13
        $global:PraGate.Native.Pauses.Count | Should -Be 12
    }
    It 'stops immediately on <Case> during verification without retrying Add' -ForEach @(@{Case='ChangedTenant'},@{Case='ChangedSession'},@{Case='ChangedPrincipal'},@{Case='LateReadError'},@{Case='AmbiguousWrite'}) {
        $global:PraGate.Native.Case=$Case;$global:PraGate.Native.VisibleAfter=12
        InModuleScope PRA.Cloud {
            if ($global:PraGate.Native.Case -eq 'AmbiguousWrite') {
                { & $script:PraExoWorker 'Grant' $global:PraGate.NativeParams $global:PraGate.NativePermit $global:PraGate.NativeBinding { [void]$global:PraGate.Native.Journal.Add('Applied') } } | Should -Throw '*indeterminate*'
            } else {
                $result=& $script:PraExoWorker 'Grant' $global:PraGate.NativeParams $global:PraGate.NativePermit $global:PraGate.NativeBinding { [void]$global:PraGate.Native.Journal.Add('Applied') }
                $result.Verified | Should -BeFalse
                $result.Mutated | Should -BeTrue
                $result.Error | Should -Not -BeNullOrEmpty
            }
        }
        $global:PraGate.Native.Writes | Should -Be 1
        $global:PraGate.Native.Pauses.Count | Should -BeLessOrEqual 1
        $global:PraGate.Native.PostAddReads | Should -BeLessOrEqual 2
    }
    Context 'Public preflight and authorized grant integration' {
        BeforeEach {
            $context=New-GateContext $global:PraGate.Runtime
            $context.Phase='Both'
            $context.Config.Cloud=@{TenantId=$global:PraGate.Native.Tenant;UserPrincipalName='operator@gate.invalid';CheckMailbox=$true;CheckLicense=$true;MailboxCheckVia='Exo';AppId='';CertificateThumbprint=''}
            $context.Config.Exo=@{MinModuleVersion='3.10.0';UseSubprocess=$false;DisableWAM=$true;GrantVerifyAttempts=13;GrantVerifyDelaySeconds=10}
            $context.Config.SharedMailbox.PermissionSource='AD';$context.Config.SharedMailbox.GrantFullAccess=$true;$context.Config.SharedMailbox.GrantSendAs=$true
            $global:PraGate.NativeContext=$context
            $global:PraGate.NativeRow=New-PraRow $context ([pscustomobject]@{ObjectGuid='00000000-0000-0000-0000-000000000001';UserPrincipalName=$global:PraGate.Native.Target;IsShared=$true})
            $global:PraGate.NativeRow.SharedFullAccess=@($global:PraGate.Native.Trustee);$global:PraGate.NativeRow.SharedSendAs=@($global:PraGate.Native.Trustee)
            $global:PraGate.NativeUserRow=New-PraRow $context ([pscustomobject]@{ObjectGuid='00000000-0000-0000-0000-000000000002';UserPrincipalName=$global:PraGate.Native.Trustee;IsShared=$false})
            InModuleScope PRA.Cloud {
                # Only external module discovery/import is replaced. Exact loaded fixture metadata
                # remains real for every Session/Get-Command provenance guard in the native worker.
                $script:GateNativeGetModule=Get-Command Get-Module -CommandType Cmdlet
                Mock Get-PraCloudModuleReport { [pscustomobject]@{ Ok=$true; Messages=@(); Graph=[pscustomobject]@{Ok=$true;Version='2.41.1';Message=''}; Exo=[pscustomobject]@{Ok=$true;Version='3.10.1';Message=''} } }
                Mock Get-Module {
                    param($Name,[switch]$ListAvailable)
                    if ($ListAvailable) {
                        if ($Name -ne 'ExchangeOnlineManagement') { throw 'SYNTHETIC: unexpected module discovery.' }
                        return [pscustomobject]@{Name='ExchangeOnlineManagement';Version=[version]'3.10.0'}
                    }
                    & $script:GateNativeGetModule
                }
                Mock Import-Module {
                    param($Name,$MinimumVersion)
                    if ($Name -notin @('ExchangeOnlineManagement','Microsoft.Graph.Authentication','Microsoft.Graph.Users')) { throw 'SYNTHETIC: unexpected external module import.' }
                    [void]$global:PraGate.Native.ConnectionOrder.Add('Import-'+$Name)
                }
            }
        }
        It 'preflights resolved UPNs with readonly EXO and Graph, no AD proof or write, and honors operator UPN/DisableWAM' {
            $global:PraGate.Native.ConnectLifecycle=$true
            $context=$global:PraGate.NativeContext
            $context.AssertCloudAuthorization={throw 'Readonly preflight must not demand AD proof.'}
            $context.JournalMutation={throw 'Readonly preflight must not write a mutation journal.'}
            Initialize-PraCloudPreflight -Context $context -Rows @($global:PraGate.NativeRow,$global:PraGate.NativeUserRow)
            $context['_PraCloudSession'].Preflight | Should -BeTrue
            $global:PraGate.NativeRow.ADVerified | Should -BeFalse
            $global:PraGate.Native.Writes | Should -Be 0
            $global:PraGate.Native.GlobalReads | Should -Be 0 -Because 'future ACL/provisioning is not asserted before AD'
            $global:PraGate.Native.ExoConnect | Should -Be 1
            $global:PraGate.Native.GraphConnect | Should -Be 1
            $global:PraGate.Native.ConnectUpn | Should -BeExactly 'operator@gate.invalid'
            $global:PraGate.Native.DisableWAM | Should -BeTrue
            $global:PraGate.Native.GraphSelectors | Should -Contain 'trustee@gate.invalid'
            $global:PraGate.Native.GraphSelectors | Should -Not -Contain $global:PraGate.NativeUserRow.ObjectGuid
            Close-PraCloudSession $context
            Close-PraCloudSession $context
            $global:PraGate.Native.ExoClose | Should -Be 1
            $global:PraGate.Native.GraphClose | Should -Be 1
        }
        It 'imports and connects Graph before importing and connecting EXO in the native public preflight' {
            $global:PraGate.Native.ConnectLifecycle=$true
            $context=$global:PraGate.NativeContext
            try {
                Initialize-PraCloudPreflight -Context $context -Rows @($global:PraGate.NativeRow,$global:PraGate.NativeUserRow)
                ($global:PraGate.Native.ConnectionOrder -join ',') | Should -BeExactly 'Import-Microsoft.Graph.Authentication,Import-Microsoft.Graph.Users,Connect-MgGraph,Import-ExchangeOnlineManagement,Connect-ExchangeOnline'
                $context['_PraCloudSession'].Preflight | Should -BeTrue
                $global:PraGate.Native.Writes | Should -Be 0
            } finally { Close-PraCloudSession $context }
            $global:PraGate.Native.ExoClose | Should -Be 1
            $global:PraGate.Native.GraphClose | Should -Be 1
        }
        It 'stops Graph <Case> before EXO without creating connections or disconnecting unrelated sessions' -ForEach @(
            @{Case='GraphConnectFailure';Message='*Graph connection failed before any context was created*'},
            @{Case='GraphAssemblyConflict';Message='*could not load an assembly*new PowerShell 7 window*GetTokenAsync*'},
            @{Case='GraphPreexistingContext';Message='*Graph session already exists*'}
        ) {
            $global:PraGate.Native.ConnectLifecycle=$true;$global:PraGate.Native.Case=$Case
            $context=$global:PraGate.NativeContext
            { Initialize-PraCloudPreflight -Context $context -Rows @($global:PraGate.NativeRow,$global:PraGate.NativeUserRow) } | Should -Throw $Message
            Close-PraCloudSession $context
            $global:PraGate.Native.Writes | Should -Be 0
            $global:PraGate.Native.ExoConnect | Should -Be 0
            $global:PraGate.Native.ExoClose | Should -Be 0
            $global:PraGate.Native.GraphConnect | Should -Be 0
            $global:PraGate.Native.GraphClose | Should -Be 0
            $global:PraGate.Native.ConnectionReads | Should -Be 0
            $global:PraGate.Native.ConnectionOrder | Should -Not -Contain 'Import-ExchangeOnlineManagement'
            $global:PraGate.Native.ConnectionOrder | Should -Not -Contain 'Connect-ExchangeOnline'
            $context.CloudConnectFailed | Should -BeTrue
            $expectedOrder='Import-Microsoft.Graph.Authentication,Import-Microsoft.Graph.Users'
            if($Case -in @('GraphConnectFailure','GraphAssemblyConflict')){$expectedOrder+=',Connect-MgGraph'}
            ($global:PraGate.Native.ConnectionOrder -join ',') | Should -BeExactly $expectedOrder
        }
        It 'cleans up owned sessions after native preflight <Case> and never writes' -ForEach @(@{Case='WrongTenant';Message='*tenant*'},@{Case='WrongProvenance';Message='*Module of the Exchange Online session*'},@{Case='GraphWrongTenant';Message='*Graph session missing*'},@{Case='GraphMismatchedIdentity';Message='*Graph and Exchange Online identities differ*'}) {
            $global:PraGate.Native.ConnectLifecycle=$true;$global:PraGate.Native.Case=$Case
            { Initialize-PraCloudPreflight -Context $global:PraGate.NativeContext -Rows @($global:PraGate.NativeRow,$global:PraGate.NativeUserRow) } | Should -Throw $Message
            $global:PraGate.Native.Writes | Should -Be 0
            $expectedExo=if($Case -eq 'GraphWrongTenant'){0}else{1}
            $global:PraGate.Native.ExoConnect | Should -Be $expectedExo
            $global:PraGate.Native.ExoClose | Should -Be $expectedExo
            $global:PraGate.Native.GraphConnect | Should -Be 1
            $global:PraGate.Native.GraphClose | Should -Be 1
            $global:PraGate.NativeContext.CloudConnectFailed | Should -BeTrue
        }
        It 'preflights a Recover (phase Both) with the same sessions, no trustee request and no identity pinning' {
            $global:PraGate.Native.ConnectLifecycle=$true
            $context=$global:PraGate.NativeContext
            $context.Action='Recover'
            try {
                Initialize-PraCloudPreflight -Context $context -Rows @($global:PraGate.NativeRow,$global:PraGate.NativeUserRow)
                $context['_PraCloudSession'].Preflight | Should -BeTrue
                # A deprovisioned user becomes a MailUser: its identity is not pinned for the cloud phase of the Recover.
                $context['_PraCloudSession'].Identities.Count | Should -Be 0
                $global:PraGate.Native.Writes | Should -Be 0
                $global:PraGate.Native.ExoConnect | Should -Be 1
                $global:PraGate.Native.GraphConnect | Should -Be 1
                $global:PraGate.Native.ConnectUpn | Should -BeExactly 'operator@gate.invalid'
                ($global:PraGate.Native.ConnectionOrder -join ',') | Should -BeExactly 'Import-Microsoft.Graph.Authentication,Import-Microsoft.Graph.Users,Connect-MgGraph,Import-ExchangeOnlineManagement,Connect-ExchangeOnline'
            } finally { Close-PraCloudSession $context }
            $global:PraGate.Native.ExoClose | Should -Be 1
            $global:PraGate.Native.GraphClose | Should -Be 1
        }
        It 'refuses the pre-check for anything but Convert or Recover, Apply, phase Both' -ForEach @(
            @{Action='Finalize';Mode='Apply';Phase='Both'},@{Action='Check';Mode='Apply';Phase='Both'},@{Action='Recover';Mode='Preview';Phase='Both'},@{Action='Recover';Mode='Apply';Phase='AD'}
        ) {
            $context=$global:PraGate.NativeContext
            $context.Action=$Action;$context.Mode=$Mode;$context.Phase=$Phase;$context.AllowMutation=($Mode -eq 'Apply')
            { Initialize-PraCloudPreflight -Context $context -Rows @($global:PraGate.NativeUserRow) } | Should -Throw '*only for Convert or Recover, Apply, phase Both*'
            $global:PraGate.Native.ExoConnect | Should -Be 0
            $global:PraGate.Native.GraphConnect | Should -Be 0
        }
        It 'keeps proof, individual approval and Started/Applied/Verified journal bound to the exact grant' {
            $context=$global:PraGate.NativeContext
            $context['_PraCloudSession']=@{Graph=$false;Exo=$true;Subprocess=$false;Binding=$global:PraGate.NativeBinding;Identities=@{}}
            $global:PraGate.NativeRow.ADVerified=$true
            $global:PraGate.Native.GrantEvents=New-Object 'Collections.Generic.List[object]'
            $context.Approval={param($Target,$Operation) [void]$global:PraGate.Native.GrantEvents.Add(@{Status='Approval';Target=$Target;Operation=$Operation});$true}
            $context.AssertCloudAuthorization={param($Row) $Row.ObjectGuid | Should -BeExactly '00000000-0000-0000-0000-000000000001';[void]$global:PraGate.Native.GrantEvents.Add(@{Status='Proof';Target=$Row.UserPrincipalName;Operation='proof'})}
            $context.JournalMutation={param($Target,$Operation,$Status,$Detail) [void]$global:PraGate.Native.GrantEvents.Add(@{Status=$Status;Target=$Target;Operation=$Operation;Detail=$Detail;Writes=$global:PraGate.Native.Writes})}
            InModuleScope PRA.Cloud { Invoke-PraPermissionGrant $global:PraGate.NativeContext $global:PraGate.NativeRow $global:PraGate.NativeParams }
            ($global:PraGate.Native.GrantEvents.Status -join ',') | Should -BeExactly 'Approval,Proof,Started,Applied,Verified'
            foreach($event in $global:PraGate.Native.GrantEvents){$event.Target | Should -BeExactly 'shared@gate.invalid'}
            foreach($event in @($global:PraGate.Native.GrantEvents | Where-Object Status -in @('Started','Applied','Verified'))){$event.Operation | Should -BeExactly 'Grant FullAccess to trustee@gate.invalid'}
            @($global:PraGate.Native.GrantEvents | Where-Object Status -eq 'Started')[0].Writes | Should -Be 0
            @($global:PraGate.Native.GrantEvents | Where-Object Status -eq 'Applied')[0].Writes | Should -Be 1
            $global:PraGate.Native.Writes | Should -Be 1
            $global:PraGate.Native.AutoMapping | Should -BeTrue
        }
    }
    AfterAll { Remove-Module PRA.Cloud,PraGateNativeExo -Force -ErrorAction SilentlyContinue }
}

Describe 'Actual main cloud authority closures - offline scope regression' -Tag 'CloudAuthorityClosure' {
    BeforeAll {
        # Parse, never execute the product main. Keep its CURRENT constructor and grant unchanged.
        $tokens=$null; $parseErrors=$null
        $mainAst=[Management.Automation.Language.Parser]::ParseFile((Join-Path $global:PraGate.Source 'Invoke-PraRemoteMailbox.ps1'),[ref]$tokens,[ref]$parseErrors)
        if ($parseErrors.Count) { throw 'Current main has parse errors.' }
        $authorityAst=$mainAst.Find({param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq 'Initialize-PraCloudAuthority'},$true)
        if ($null -eq $authorityAst) { throw 'Actual cloud authority constructor absent.' }
        $factoryBody=@'
param([hashtable]$InputContext,[switch]$ParentFunction,[switch]$RebindAfterCapture)
Set-StrictMode -Version Latest
__ACTUAL_AUTHORITY__
function New-ParentFunctionAuthority {
    $context=$InputContext
    Initialize-PraCloudAuthority
    $saved=$context
    if ($RebindAfterCapture) { $context=@{AllowMutation=$true;OperationFailed=$false} }
    return $saved
}
if ($ParentFunction) { New-ParentFunctionAuthority }
else {
    $context=$InputContext
    Initialize-PraCloudAuthority
    $saved=$context
    if ($RebindAfterCapture) { $context=@{AllowMutation=$true;OperationFailed=$false} }
    $saved
}
'@
        $global:PraGate.AuthorityFactory=Join-Path $global:PraGate.Root 'ActualCloudAuthority.ps1'
        [IO.File]::WriteAllText($global:PraGate.AuthorityFactory,$factoryBody.Replace('__ACTUAL_AUTHORITY__',$authorityAst.Extent.Text),(New-Object Text.UTF8Encoding($true)))
        $cloudAst=[Management.Automation.Language.Parser]::ParseFile((Join-Path $global:PraGate.Package 'module\PRA.Cloud.psm1'),[ref]$tokens,[ref]$parseErrors)
        if ($parseErrors.Count) { throw 'Current Cloud module has parse errors.' }
        $grantAst=$cloudAst.Find({param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq 'Invoke-PraPermissionGrant'},$true)
        # Only the grant guard is loaded. No real Cloud transport/connectors exist in this module.
        $offlineDispatch=@'
function Invoke-PraExo {
    param($Context,$Operation,$Params,$Permit,$OnApplied)
    if ($Operation -ne 'Grant' -or -not $Permit.JournalStarted -or -not $Permit.Authorized) { throw 'Synthetic dispatch requires a complete native permit.' }
    $Context.GateDispatchCount++
    & $OnApplied
    @{Verified=$true;Mutated=$true}
}
Export-ModuleMember -Function Invoke-PraPermissionGrant
'@
        $global:PraGate.AuthorityModulePath=Join-Path $global:PraGate.Root 'PraGateAuthorityGrant.psm1'
        [IO.File]::WriteAllText($global:PraGate.AuthorityModulePath,($grantAst.Extent.Text+"`r`n"+$offlineDispatch),(New-Object Text.UTF8Encoding($true)))
        Import-Module $global:PraGate.AuthorityModulePath -Global -Force
    }
    BeforeEach {
        $global:PraGate.Runtime=New-GateRuntime -Name 'actual-cloud-authority'
        $env:PRA_GATE_STATE=$global:PraGate.Runtime.StatePath
        $env:PSModulePath=$global:PraGate.Runtime.Modules+';'+(Join-Path $PSHOME 'Modules')
        Import-Module ActiveDirectory -Force -Global
        $context=New-GateContext $global:PraGate.Runtime
        $plan=New-PraPlan $context 'user1' 'Convert'
        # Existing native backup fixture, no AD mutation: produce a real validated schema-3 receipt.
        $receipt=& (Get-Module PRA.Directory) {param($c,$p) Save-PraBatch $c @($p) 'Convert'} $context $plan
        $proofPath=Join-Path (Split-Path $receipt.Path -Parent) 'synthetic-authority-proof.json'
        $data=[ordered]@{SchemaVersion=2;Kind='ADVerified';Environment=$context.Config.Environment;Operation='Convert';RunId=$receipt.Data.RunId;BackupFile=[IO.Path]::GetFileName($receipt.Path);BackupHash=$receipt.Hash;SourceBackupHash='';Records=@(@{ObjectGuid=$plan.Record.ObjectGuid;ADVerified=$true;Operation='Convert';VerifiedUsnChanged='101'})}
        Write-PraImmutableFile $proofPath ($data | ConvertTo-Json -Depth 12)
        Write-PraImmutableFile ($proofPath+'.sha256') (Get-PraHash $proofPath)
        $context.Source=$receipt; $context.Proof=Import-PraProof $context $proofPath $receipt 'Convert'
        $context.Phase='Cloud'; $context.OperationFailed=$false; $context.GateDispatchCount=0
        $context.JournalPath=Join-Path $global:PraGate.Runtime.Root 'CloudOperations.jsonl'
        Write-PraImmutableFile $context.JournalPath ''
        $plan.Row.ADVerified=$true
        $global:PraGate.AuthorityContext=$context; $global:PraGate.AuthorityRow=$plan.Row
        $global:PraGate.AuthorityParams=@{Upn=$plan.Row.UserPrincipalName;Trustee='trustee@gate.invalid';Right='FullAccess';AutoMapping=$true}
        $global:PraGate.AuthorityOldGlobal=Get-Variable context -Scope Global -ErrorAction SilentlyContinue
        $null=& $global:PraGate.AuthorityFactory -InputContext $context
    }
    It 'captures the same live context in both callbacks from parent <Scope>' -ForEach @(@{Scope='Script'},@{Scope='Function'}) {
        $context=$global:PraGate.AuthorityContext
        $returned=& $global:PraGate.AuthorityFactory -InputContext $context -ParentFunction:($Scope -eq 'Function')
        [object]::ReferenceEquals($returned,$context) | Should -BeTrue
        $heldProof=& $context.AssertCloudAuthorization.Module { $capturedContext }
        $heldJournal=& $context.JournalMutation.Module { $capturedContext }
        [object]::ReferenceEquals($heldProof,$context) | Should -BeTrue
        [object]::ReferenceEquals($heldJournal,$context) | Should -BeTrue
        Invoke-PraPermissionGrant $context $global:PraGate.AuthorityRow $global:PraGate.AuthorityParams
        $context.GateDispatchCount | Should -Be 1
        $journal=@([IO.File]::ReadAllLines($context.JournalPath) | ForEach-Object { $_ | ConvertFrom-Json -DateKind String })
        ($journal.Status -join ',') | Should -BeExactly 'Started,Applied,Verified'
        @($journal | Where-Object RunId -ne $context.RunId).Count | Should -Be 0
    }
    It 'keeps captured reference after reassignment in parent <Scope>' -ForEach @(@{Scope='Script'},@{Scope='Function'}) {
        $context=$global:PraGate.AuthorityContext
        $returned=& $global:PraGate.AuthorityFactory -InputContext $context -ParentFunction:($Scope -eq 'Function') -RebindAfterCapture
        [object]::ReferenceEquals($returned,$context) | Should -BeTrue
        $context.OperationFailed=$true
        { Invoke-PraPermissionGrant $context $global:PraGate.AuthorityRow $global:PraGate.AuthorityParams } | Should -Throw '*Cloud write refused*'
        $context.GateDispatchCount | Should -Be 0
        [IO.File]::ReadAllText($context.JournalPath) | Should -BeExactly ''
    }
    It 'ignores a global homonym created before construction and replaced afterward' {
        $context=$global:PraGate.AuthorityContext
        $global:context=@{AllowMutation=$false;OperationFailed=$true}
        $null=& $global:PraGate.AuthorityFactory -InputContext $context
        Invoke-PraPermissionGrant $context $global:PraGate.AuthorityRow $global:PraGate.AuthorityParams
        $context.GateDispatchCount | Should -Be 1
        $global:context=@{AllowMutation=$true;OperationFailed=$false;Issues=@();Proof=$context.Proof;Source=$context.Source}
        $context.OperationFailed=$true
        { Invoke-PraPermissionGrant $context $global:PraGate.AuthorityRow $global:PraGate.AuthorityParams } | Should -Throw '*Cloud write refused*'
        $context.GateDispatchCount | Should -Be 1
    }
    It 'revokes the existing callback when <Field> changes after construction' -ForEach @(@{Field='AllowMutation'},@{Field='OperationFailed'},@{Field='Issues'},@{Field='Proof'}) {
        $context=$global:PraGate.AuthorityContext
        switch ($Field) {
            AllowMutation { $context.AllowMutation=$false }
            OperationFailed { $context.OperationFailed=$true }
            Issues { $context.Issues.Add('Synthetic subsequent failure') }
            Proof { $context.Proof=$null }
        }
        # Direct callback also exercises its own guard where the native grant would reject earlier.
        { & $context.AssertCloudAuthorization $global:PraGate.AuthorityRow } | Should -Throw '*Cloud write refused*'
        $context.GateDispatchCount | Should -Be 0
        [IO.File]::ReadAllText($context.JournalPath) | Should -BeExactly ''
    }
    It 'observes revocation during individual approval before proof or Started' {
        $context=$global:PraGate.AuthorityContext
        $context.Approval={param($Target,$Operation) $global:PraGate.AuthorityContext.OperationFailed=$true; $true}
        { Invoke-PraPermissionGrant $context $global:PraGate.AuthorityRow $global:PraGate.AuthorityParams } | Should -Throw '*Cloud write refused*'
        $context.GateDispatchCount | Should -Be 0
        [IO.File]::ReadAllText($context.JournalPath) | Should -BeExactly ''
    }
    It 'resolves native <Command> through the actual closure module' -ForEach @(@{Command='Import-PraProof'},@{Command='Assert-PraReceipt'},@{Command='Write-PraJournal'}) {
        $context=$global:PraGate.AuthorityContext
        $resolved=& $context.AssertCloudAuthorization.Module {param($name) Get-Command $name -ErrorAction Stop} $Command
        $resolved.ModuleName | Should -BeExactly 'PRA.Directory'
        $resolved.Module.Path | Should -BeExactly (Join-Path $global:PraGate.Package 'module\PRA.Directory.psm1')
    }
    It 'retains native proof and receipt rejection for <Case> before Started' -ForEach @(
        @{Case='StateHash';Message='*AD proof (State file): SHA-256 mismatch*'},
        @{Case='RawHash';Message='*Backup CLIXML file changed*'},
        @{Case='UnregisteredReceipt';Message='*not validated in this run*'},
        @{Case='UncoveredTarget';Message='*verified AD phase*'},
        @{Case='ADVerifiedFalse';Message='*verified AD proof*required*'}
    ) {
        $context=$global:PraGate.AuthorityContext; $row=$global:PraGate.AuthorityRow
        switch ($Case) {
            StateHash { [IO.File]::AppendAllText($context.Proof.Path,' ') }
            RawHash { [IO.File]::AppendAllText((Join-Path (Split-Path $context.Source.Path -Parent) $context.Source.Data.RawFile),' ') }
            UnregisteredReceipt { $real=$context.Source; $context.Source=[pscustomobject]@{Data=$real.Data;Path=$real.Path;Hash=$real.Hash;Legacy=$real.Legacy} }
            UncoveredTarget { $row.ObjectGuid='00000000-0000-0000-0000-000000000099' }
            ADVerifiedFalse { $row.ADVerified=$false }
        }
        { Invoke-PraPermissionGrant $context $row $global:PraGate.AuthorityParams } | Should -Throw $Message
        $context.GateDispatchCount | Should -Be 0
        [IO.File]::ReadAllText($context.JournalPath) | Should -BeExactly ''
    }
    AfterEach {
        @(Get-GateWrites $global:PraGate.Runtime).Count | Should -Be 0
        if ($null -eq $global:PraGate.AuthorityOldGlobal) { Remove-Variable context -Scope Global -ErrorAction SilentlyContinue }
        else { Set-Variable context -Scope Global -Value $global:PraGate.AuthorityOldGlobal.Value }
    }
    AfterAll { Remove-Module PraGateAuthorityGrant -Force -ErrorAction SilentlyContinue }
}

Describe 'Batch resolution diagnostics - complete synthetic main invocations' -Tag 'RecoverPath' {
    BeforeEach {
        $runtime=New-GateRuntime -Name 'batch-resolution'
        $env:PRA_GATE_STATE=$runtime.StatePath
        $env:PSModulePath=$runtime.Modules+';'+(Join-Path $PSHOME 'Modules')
        Remove-Module PRA.Directory -Force -ErrorAction SilentlyContinue
        Get-Module ActiveDirectory -All | Remove-Module -Force -ErrorAction Stop
        Import-Module (Join-Path $runtime.Modules 'ActiveDirectory\ActiveDirectory.psm1') -Force -Global
        Import-Module (Join-Path $global:PraGate.Package 'module\PRA.Directory.psm1') -Force -Global
        $context=New-GateContext $runtime
        $context.BackupFolder=$runtime.State.BackupFolder
        $bundles=New-GateSourceBundles $context
        $source=Import-PraBackup $context $bundles.Source
        $sourceId=[string]$source.Data.BatchId
        Remove-Item -LiteralPath $runtime.EventPath -Force -ErrorAction SilentlyContinue
    }
    AfterEach {
        $after=Import-PraBackup $context $bundles.Source
        $after.Hash | Should -BeExactly $source.Hash
    }
    It 'serializes explicit ConfigPath and Batch values as data, including smart quotes and command-looking text' {
        $runtime.CaseName='batch-explicit-literals'
        $quotes=-join (@(0x2018,0x2019,0x201A,0x201B) | ForEach-Object { [char]$_ })
        $literalConfig=Join-Path $runtime.Root ("operator's "+$quotes+';exit 73;.psd1')
        Copy-Item -LiteralPath $runtime.ConfigPath -Destination $literalConfig
        { Invoke-GateProcess $runtime @{'ConfigPath;exit73'='not-code'} -ExplicitArguments } | Should -Throw '*argument name refused*'
        { Invoke-GateProcess $runtime @{ConfigPath=@('not','a','string')} -ExplicitArguments } | Should -Throw '*argument type refused*'
        $run=Invoke-GateProcess $runtime @{Action='Recover';Mode='Apply';Phase='AD';Force=$true;Confirm=$false;ConfigPath=$literalConfig;Batch=$bundles.Source} -ExplicitArguments
        $run.ExitCode | Should -Be 2 -Because 'a phase AD that ends with a package is done, next step required'
        $run.MainResult.ErrorCount | Should -Be 0
        $run.MainResult.TotalCount | Should -Be 2
        @($run.Events | Where-Object Operation -eq 'Get-ADUser').Count | Should -BeGreaterThan 0
    }
    It 'resolves Recover -Batch by absolute JSON path and by unique short batch ID' -ForEach @(
        @{Kind='Path';Invocation='Explicit'},@{Kind='Path';Invocation='SplatClixml'},@{Kind='ShortId';Invocation='Explicit'},@{Kind='ShortId';Invocation='SplatClixml'}
    ) {
        $runtime.CaseName='batch-valid-'+$Kind+'-'+$Invocation
        $batchValue=if ($Kind -eq 'ShortId') { $sourceId.Substring(0,8) } else { $bundles.Source }
        $run=Invoke-GateProcess $runtime @{Action='Recover';Mode='Apply';Phase='AD';Force=$true;ConfigPath=$runtime.ConfigPath;Batch=$batchValue} -ExplicitArguments:($Invocation -eq 'Explicit')
        $run.WatchdogStopped | Should -BeNullOrEmpty
        $run.ExitCode | Should -Be 2
        $run.MainResult.ErrorCount | Should -Be 0
        $run.MainResult.BackupFiles.Count | Should -Be 1
        $saved=Import-PraBackup $context $run.MainResult.BackupFiles[0]
        $saved.Data.SourceBackupHash | Should -BeExactly $source.Hash
        $saved.Path.StartsWith($runtime.State.BackupFolder+'\',[StringComparison]::OrdinalIgnoreCase) | Should -BeTrue
    }
    It 'resolves Recover -Phase Cloud from the Recover batch and finds the Convert source by hash' {
        $runtime.CaseName='batch-recover-cloud'
        $run=Invoke-GateProcess $runtime @{Action='Recover';Mode='Apply';Phase='Cloud';Force=$true;ConfigPath=$runtime.ConfigPath;Batch=$bundles.Recover}
        $run.ExitCode | Should -Be 1
        ($run.MainResult.Issues.Message -join ' ') | Should -Match 'Cloud deprovisioning or AD proof not confirmed'
        $run.MainResult.PendingCount | Should -Be 2
        @($run.Events | Where-Object Operation -eq 'CloudPhase-SyntheticBarrier').Count | Should -Be 1
        @(Get-GateWrites $runtime).Count | Should -Be 0
    }
    It 'rejects an unknown short batch ID before AD, cloud or sync work' {
        $runtime.CaseName='batch-unknown-id'
        $run=Invoke-GateProcess $runtime @{Action='Recover';Mode='Apply';Phase='AD';Force=$true;ConfigPath=$runtime.ConfigPath;Batch='deadbeef'}
        $run.ExitCode | Should -Be 1
        ($run.MainResult.Issues.Message -join ' ') | Should -Match 'not found under'
        @($run.Events | Where-Object Operation -ne 'Import-SyntheticAD').Count | Should -Be 0
        @(Get-GateWrites $runtime).Count | Should -Be 0
    }
    It 'rejects an ambiguous short batch ID before AD, cloud or sync work' {
        $runtime.CaseName='batch-ambiguous-id'
        $sourceFolder=Split-Path $bundles.Source -Parent
        $short=$sourceId.Substring(0,8)
        $clone=Join-Path (Split-Path $sourceFolder -Parent) ('Batch-'+$short+'ffffffffffffffffffffffff')
        Copy-Item -LiteralPath $sourceFolder -Destination $clone -Recurse
        $cloneJson=Join-Path $clone ([IO.Path]::GetFileName($bundles.Source))
        Add-Content -LiteralPath $cloneJson -Value ' ' -Encoding UTF8
        $run=Invoke-GateProcess $runtime @{Action='Recover';Mode='Apply';Phase='AD';Force=$true;ConfigPath=$runtime.ConfigPath;Batch=$short}
        $run.ExitCode | Should -Be 1
        ($run.MainResult.Issues.Message -join ' ') | Should -Match 'ambiguous'
        @($run.Events | Where-Object Operation -ne 'Import-SyntheticAD').Count | Should -Be 0
        @(Get-GateWrites $runtime).Count | Should -Be 0
    }
    It 'refuses -Mode Apply without -Force in a non-interactive process before any backup or write' {
        $runtime.CaseName='batch-apply-without-force'
        $run=Invoke-GateProcess $runtime @{Action='Recover';Mode='Apply';Phase='AD';ConfigPath=$runtime.ConfigPath;Batch=$sourceId.Substring(0,8)}
        $run.ExitCode | Should -Be 1
        ($run.MainResult.Issues.Message -join ' ') | Should -Match 'Apply needs a confirmation'
        @($run.MainResult.BackupFiles).Count | Should -Be 0
        @(Get-GateWrites $runtime).Count | Should -Be 0
    }
}

Describe 'Whole main in an isolated PowerShell 7 process' {
    It 'runs readonly Cloud preflight on actual planned rows before AD, then closes on AD failure' -Tag 'NativeCloud136' {
        $runtime=New-GateRuntime -Name 'main-preflight-before-ad' -Case SecondMutationFailure
        $run=Invoke-GateProcess $runtime @{Action='Convert';Mode='Apply';Phase='Both';Force=$true;ConfigPath=$runtime.ConfigPath}
        $run.ExitCode | Should -Be 1
        $operations=@($run.Events.Operation)
        @($run.Events | Where-Object Operation -eq 'CloudPreflight-SyntheticBarrier').Count | Should -Be 1
        [array]::IndexOf($operations,'CloudPreflight-SyntheticBarrier') | Should -BeLessThan ([array]::IndexOf($operations,'Set-ADUser'))
        @($run.Events | Where-Object Operation -eq 'CloudClose-SyntheticBarrier').Count | Should -Be 1
        ($run.MainResult.Issues.Message -join ' ') | Should -Match 'second mutation'
        $preflight=@($run.Events | Where-Object Operation -eq 'CloudPreflight-SyntheticBarrier')[0]
        $preflight.Rows.Count | Should -Be 2
        @($preflight.Rows | Where-Object ADVerified).Count | Should -Be 0
        $preflight.Config.GrantVerifyAttempts | Should -Be 13
        $preflight.Config.GrantVerifyDelaySeconds | Should -Be 10
    }
    It 'fails Cloud preflight with zero AD writes and closes attempted sessions' -Tag 'NativeCloud136' {
        $runtime=New-GateRuntime -Name 'main-preflight-refused' -Case CloudPreflightFailure
        $run=Invoke-GateProcess $runtime @{Action='Convert';Mode='Apply';Phase='Both';Force=$true;ConfigPath=$runtime.ConfigPath}
        $run.ExitCode | Should -Be 1
        ($run.MainResult.Issues.Message -join ' ') | Should -Match 'cloud preflight refused before AD'
        @(Get-GateWrites $runtime).Count | Should -Be 0
        @($run.Events | Where-Object Operation -eq 'CloudPreflight-SyntheticBarrier').Count | Should -Be 1
        @($run.Events | Where-Object Operation -eq 'CloudClose-SyntheticBarrier').Count | Should -Be 1
        @($run.Events | Where-Object Operation -eq 'CloudPhase-SyntheticBarrier').Count | Should -Be 0
    }
    It 'applies thirteen shared mailboxes with fixed ACL100 and UPN500 under a bounded private-memory watchdog' -Tag 'OOM','OOMMemory' {
        $runtime=New-GateRuntime -Name 'oom-main-fixed-volume' -Shared13 -TrusteeCount 500 -AclCount 100
        Set-GateConfigText $runtime { param($t) $t.Replace('Report=@{Enabled=$true;', 'Report=@{Enabled=$false;') }
        $run=Invoke-GateProcess $runtime @{Action='Convert';Mode='Apply';Phase='AD';Force=$true;ConfigPath=$runtime.ConfigPath} -TimeoutSeconds 180 -MemoryLimitMB 512
        $run.ExitCode | Should -Be 2 -Because ('bounded synthetic child evidence '+(Split-Path $runtime.Root -Leaf))
        $run.MainResult.TotalCount | Should -Be 13
        $run.MemorySamples | Should -BeGreaterThan 0
        $run.PeakPrivateBytes | Should -BeGreaterThan 0
        $run.PeakPrivateBytes | Should -BeLessThan 512MB
        $run.RuntimeMilliseconds | Should -BeLessThan 180000
        $run.WatchdogStopped | Should -BeExactly ''
        @(Get-GateWrites $runtime).Count | Should -Be 13
        $first=@($run.Events | Where-Object Operation -eq 'Set-ADUser')[0]
        $barrier=@($run.Events | Where-Object { $_.Operation -eq 'BackupBarrier' -and $_.Utc -le $first.Utc })[0]
        $barrier.Detail.ValidatedCount | Should -Be 13
        $barrier.Detail.ValidatedGuids.Count | Should -Be 13
        $barrier.Detail.ValidatorModule | Should -BeLike '*\module\PRA.Backup.psm1'
        $backup=[IO.File]::ReadAllText($barrier.Detail.Path) | ConvertFrom-Json -DateKind String
        $backup.SchemaVersion | Should -Be 3
        foreach ($record in $backup.Records) {
            foreach ($right in @('FullAccess','SendAs','SendOnBehalf')) {
                $record.SharedPermissions.$right.Count | Should -Be 499
                $record.SharedPermissions.$right | Should -Contain 'trustee499@gate.invalid'
                $record.SharedPermissions.$right | Should -Not -Contain 'trustee500@gate.invalid'
            }
        }
        $groupCalls=@($run.Events | Where-Object Operation -eq 'Get-ADGroupMember')
        $groupCalls.Count | Should -Be @($groupCalls.Identity | Sort-Object -Unique).Count
        $groupCalls.Count | Should -BeLessThan 13
        $memberReads=@($run.Events | Where-Object { $_.Operation -eq 'Get-ADUser' -and $_.Identity -like 'CN=Trustee*' })
        $memberReads.Count | Should -Be 500
        $discovery=@($run.Events | Where-Object { $_.Operation -eq 'Get-ADUser' -and -not $_.Identity })
        $discovery.Count | Should -BeGreaterThan 0
        foreach ($call in $discovery) { $call.Detail.Properties | Should -Not -Contain '*'; $call.Detail.Properties | Should -Not -Contain 'nTSecurityDescriptor' }
        Save-GateOomEvidence 'fixed-13-acl100-upn500-memory' $runtime @{Targets=13;AclPerDescriptor=100;InputUpns=500;UniqueGrantedUpns=499;PrivateMemoryPeakBytes=$run.PeakPrivateBytes;PeakWorkingSetBytes=$run.PeakWorkingSetBytes;RawBytes=$barrier.Detail.ValidatedBytes;JsonBytes=(Get-Item -LiteralPath $barrier.Detail.Path).Length;WatchdogLimitBytes=512MB;MemorySamples=$run.MemorySamples;ElapsedMilliseconds=$run.RuntimeMilliseconds;GroupExpansions=$groupCalls.Count;TrusteeReads=$memberReads.Count;ADWrites=13;ChildExitCode=$run.ExitCode} @($barrier.Detail.Path,(Join-Path (Split-Path $barrier.Detail.Path -Parent) $backup.RawFile))
    }
    It 'refuses the thirteenth raw capture in the actual main before all AD, cloud and sync mutation boundaries' -Tag 'OOM' {
        $runtime=New-GateRuntime -Name 'oom-main-capture13-refused' -Shared13 -Case ThirteenthCaptureFailure
        $run=Invoke-GateProcess $runtime @{Action='Convert';Mode='Apply';Phase='Both';Force=$true;ConfigPath=$runtime.ConfigPath} -TimeoutSeconds 120
        $run.ExitCode | Should -Be 1
        ($run.MainResult.Issues.Message -join ' ') | Should -Match 'thirteenth raw capture'
        @($run.Events | Where-Object Operation -eq 'NativeSecurityDescriptor').Count | Should -Be 12
        @(Get-GateWrites $runtime).Count | Should -Be 0
        @($run.Events | Where-Object Operation -Match 'CloudPhase|ADSync').Count | Should -Be 0
    }
    It 'runs thirteen-shared Recover AD then Cloud and copies schema 3 raw bundles into a schema 2 Finalize manifest' -Tag 'OOM' {
        $runtime=New-GateRuntime -Name 'oom-main-recover-cloud-bundle' -Shared13 -Case CloudConfirmed13
        $env:PRA_GATE_STATE=$runtime.StatePath; $env:PSModulePath=$runtime.Modules+';'+(Join-Path $PSHOME 'Modules')
        Import-Module ActiveDirectory -Force -Global
        $context=New-GateContext $runtime
        $plans=@(1..13 | ForEach-Object { New-PraPlan $context ('user'+$_) 'Convert' })
        $source=Invoke-PraAdBatch $context $plans 'Convert'
        # Persist only the ordinary mutable fake directory; descriptors were injected into read copies.
        [IO.File]::WriteAllText($runtime.StatePath,[Management.Automation.PSSerializer]::Serialize($global:PraGateAd,35))
        $recover=Invoke-GateProcess $runtime @{Action='Recover';Mode='Apply';Phase='AD';Force=$true;ConfigPath=$runtime.ConfigPath;Batch=$source.Path} -TimeoutSeconds 120
        $recover.ExitCode | Should -Be 2
        $recover.MainResult.TotalCount | Should -Be 13
        @(Get-GateWrites $runtime).Count | Should -Be 26
        $recoverPath=@(Get-ChildItem -LiteralPath $runtime.State.BackupFolder -Recurse -File -Filter 'Recover-*.json')[0].FullName
        $recoverData=[IO.File]::ReadAllText($recoverPath) | ConvertFrom-Json -DateKind String
        $recoverData.SchemaVersion | Should -Be 3
        $statePath=Join-Path (Split-Path $recoverPath -Parent) ('State-'+$recoverData.BatchId+'.json')
        $state=[IO.File]::ReadAllText($statePath) | ConvertFrom-Json -DateKind String
        $state.SchemaVersion | Should -Be 2
        $state.Records.Count | Should -Be 13
        $before=@(Get-GateWrites $runtime).Count
        $cloud=Invoke-GateProcess $runtime @{Action='Recover';Mode='Apply';Phase='Cloud';Force=$true;ConfigPath=$runtime.ConfigPath;Batch=$recoverPath} -TimeoutSeconds 120
        $cloud.ExitCode | Should -Be 2
        @($cloud.Events | Where-Object Operation -eq 'CloudPhase-SyntheticBarrier').Count | Should -Be 1
        @(Get-GateWrites $runtime).Count | Should -Be $before
        $manifestFile=@(Get-ChildItem -LiteralPath $runtime.State.BackupFolder -Recurse -File -Filter 'Finalize-*.json' | Where-Object { ([IO.File]::ReadAllText($_.FullName) | ConvertFrom-Json -DateKind String).Operation -eq 'RecoverFinalize' })[0]
        $manifest=[IO.File]::ReadAllText($manifestFile.FullName) | ConvertFrom-Json -DateKind String
        $manifest.SchemaVersion | Should -Be 2
        $manifest.Items.Count | Should -Be 13
        foreach ($receiptPath in @($source.Path,$recoverPath)) {
            $copied=Join-Path $manifestFile.DirectoryName ([IO.Path]::GetFileName($receiptPath))
            (Get-FileHash $copied).Hash | Should -BeExactly (Get-FileHash $receiptPath).Hash
            $data=[IO.File]::ReadAllText($copied) | ConvertFrom-Json -DateKind String
            $data.SchemaVersion | Should -Be 3
            $data.RawFormat | Should -BeExactly 'PraDataOnlyClixml-v1'
            $raw=Join-Path $manifestFile.DirectoryName $data.RawFile
            (Get-PraHash $raw) | Should -BeExactly $data.RawHash
            $checked=Test-PraRawCapture -Context $context -LiteralPath $raw -Records @($data.Records) -RawFormat $data.RawFormat
            $checked.Count | Should -Be 13
        }
        Save-GateOomEvidence 'recover-cloud-bundle3-manifest2' $runtime @{Targets=13;RecoverExit=$recover.ExitCode;CloudExit=$cloud.ExitCode;BackupSchema=3;StateSchema=2;ManifestSchema=2;WritesBeforeCloud=$before;WritesAfterCloud=@(Get-GateWrites $runtime).Count} @($source.Path,$recoverPath,$statePath,$manifestFile.FullName)
    }
    It 'fails audit before any AD read, sync or cloud work when Logging.Folder is a file path, with Report.Enabled=<ReportEnabled>' -Tag 'AuditTranscript' -ForEach @(@{ReportEnabled=$false},@{ReportEnabled=$true}) {
        $runtime=New-GateRuntime -Name ('main-audit-logfile-'+$ReportEnabled)
        $path=Join-Path $runtime.Root 'logs\foreign-existing.log-target'
        [IO.File]::WriteAllBytes($path,[byte[]](0,10,13,127,128,254,255))
        $before=[Convert]::ToBase64String([IO.File]::ReadAllBytes($path))
        Set-GateConfigText $runtime { param($t) ([regex]::Replace($t, "(?m)^\s*Logging=@\{Folder='[^']+'\}", (" Logging=@{Folder='"+$path.Replace("'","''")+"'}"))).Replace('Report=@{Enabled=$true;', ('Report=@{Enabled=$'+$ReportEnabled.ToString().ToLowerInvariant()+';')) }
        $run=Invoke-GateProcess $runtime @{Action='Convert';Mode='Apply';Phase='Both';Force=$true;ConfigPath=$runtime.ConfigPath}
        $run.ExitCode | Should -Be 1
        $run.MainResult.ExitCode | Should -Be 1
        $run.MainResult.ErrorCount | Should -BeGreaterThan 0
        $run.MainResult.TranscriptPath | Should -BeNullOrEmpty
        $run.Output | Should -Match 'RESULT: FAIL'
        $run.Output | Should -Not -Match 'RESULT: PASS'
        @($run.Events | Where-Object Operation -ne 'Import-SyntheticAD').Count | Should -Be 0
        @($run.Events | Where-Object Operation -eq 'Import-SyntheticAD').Count | Should -BeGreaterThan 0
        [Convert]::ToBase64String([IO.File]::ReadAllBytes($path)) | Should -BeExactly $before
        ($run.MainResult.Issues.Message -join ' ') | Should -Match 'Audit|log file|Report folder'
        if (-not $ReportEnabled) {
            $run.MainResult.CsvReport | Should -BeNullOrEmpty
            $run.MainResult.HtmlReport | Should -BeNullOrEmpty
        }
    }
    It 'rejects Windows PowerShell 5.1 before any AD read or write, with fake modules still installed' -Tag 'GuiIntegration' {
        $runtime=New-GateRuntime -Name 'main-desktop-rejected'
        $run=Invoke-GateProcess $runtime @{Action='Convert';Mode='Preview';Phase='AD';Force=$true;ConfigPath=$runtime.ConfigPath} -Desktop
        $run.ExitCode | Should -Not -Be 0
        ($run.Output+$run.Error) | Should -Match '7\.5'
        @($run.Events | Where-Object Operation -Match '^(Get-AD|Set-|Add-|Remove-|CloudPhase|Start-ADSync)').Count | Should -Be 0
    }
    It 'exposes debug details only with native Verbose, while always preserving them in the log' -ForEach @(@{EnableVerbose=$false},@{EnableVerbose=$true}) {
        $runtime=New-GateRuntime -Name ('main-verbose-'+$EnableVerbose)
        $arguments=@{Action='Convert';Mode='Preview';Phase='AD';Force=$true;ConfigPath=$runtime.ConfigPath}
        if ($EnableVerbose) { $arguments.Verbose=$true }
        $run=Invoke-GateProcess $runtime $arguments
        $run.ExitCode | Should -Be 0
        $log=Get-Content -LiteralPath $run.MainResult.LogFile -Raw
        $log | Should -Match 'AD RESOLVED'
        if ($EnableVerbose) { ($run.Output+$run.Error) | Should -Match 'AD RESOLVED' }
        else { ($run.Output+$run.Error) | Should -Not -Match 'AD RESOLVED' }
        @(Get-GateWrites $runtime).Count | Should -Be 0
    }
    It 'applies two synthetic targets with a full pre-mutation backup barrier' -Tag 'Delta' {
        $runtime=New-GateRuntime -Name 'main-apply'
        $run=Invoke-GateProcess $runtime @{Action='Convert';Mode='Apply';Phase='AD';Force=$true;ConfigPath=$runtime.ConfigPath}
        $run.ExitCode | Should -Be 2 -Because ('the synthetic process must return the expected code (a phase AD that ends with a package: next step required); evidence case '+(Split-Path $runtime.Root -Leaf))
        $run.Output | Should -Match 'RESULT: PENDING'
        ($run.MainResult.NextSteps -join ' ') | Should -Match '-Phase Cloud'
        ($run.MainResult.NextSteps -join ' ') | Should -Not -Match '-ConfigPath'
        @(Get-GateWrites $runtime).Count | Should -Be 4
        @($run.Events | Where-Object Operation -eq 'BackupBarrier').Count | Should -BeGreaterOrEqual 4
        @($run.Events | Where-Object Operation -eq 'Import-SyntheticAD').Count | Should -BeGreaterThan 0
        @($run.Events | Where-Object { $_.PSObject.Properties['Server'] -and $_.Server -and $_.Server -cne 'dc01.gate.invalid' }).Count | Should -Be 0
        $log=[IO.File]::ReadAllText($run.MainResult.LogFile)
        $log | Should -Match 'BEFORE'
        $log | Should -Match 'PLANNED'
        $log | Should -Match 'VERIFIED'
        $log.IndexOf('PLANNED') | Should -BeLessThan ($log.IndexOf('AD WRITE BEGIN'))
        $log.IndexOf('] AD VERIFIED |') | Should -BeGreaterThan ($log.IndexOf('AD WRITE BEGIN'))
        ($run.Output+$run.Error) | Should -Match 'AD verified'
        $log | Should -Not -Match '[\x1b]'
        @(Import-Csv -LiteralPath $run.MainResult.CsvReport -Delimiter ';' | Where-Object ADVerified -ne 'True').Count | Should -Be 0
    }
    It 'stops globally after a second mutation fails; no next user, cloud or sync' -Tag 'Delta' {
        $runtime=New-GateRuntime -Name 'main-partial' -Case SecondMutationFailure
        $run=Invoke-GateProcess $runtime @{Action='Convert';Mode='Apply';Phase='Both';Force=$true;ConfigPath=$runtime.ConfigPath}
        $run.ExitCode | Should -Be 1 -Because ('the synthetic process must return the expected code; evidence case '+(Split-Path $runtime.Root -Leaf))
        $run.Output | Should -Match 'RESULT: FAIL'
        $writes=@(Get-GateWrites $runtime)
        ($writes.Operation -join ',') | Should -Be 'Set-ADUser,Add-ADGroupMember'
        @($run.Events | Where-Object Operation -Match 'CloudPhase|ADSync').Count | Should -Be 0
        $backupPath=@($run.Events | Where-Object Operation -eq 'BackupBarrier')[0].Detail.Path
        $backup=[IO.File]::ReadAllText($backupPath) | ConvertFrom-Json -DateKind String
        $backup.Records.Count | Should -Be 2
        $backup.Records[0].Attributes.extensionAttribute1.Value | Should -Be 'OriginalTag-1'
        $backup.Records[0].Attributes.msExchMailboxGuid.Value | Should -Be ([Convert]::ToBase64String((New-GateUser).msExchMailboxGuid))
        $backup.Records[1].Attributes.homeMDB.Value | Should -Be (New-GateUser 2).homeMDB
        $journal=@(Get-ChildItem -LiteralPath (Split-Path $backupPath -Parent) -Filter '*.jsonl')[0]
        [IO.File]::ReadAllText($journal.FullName) | Should -Match 'FailedOrIndeterminate'
        ($run.Output+$run.Error) | Should -Not -Match 'AD verified'
        [IO.File]::ReadAllText($run.MainResult.LogFile) | Should -Not -Match '(?m)^.*\] AD VERIFIED \|'
    }
    It 'refuses group, missing user, missing UPN and ambiguous identity with exit 1 and zero writes' -Tag 'Delta' -ForEach @(@{Case='GroupFailure';Identity='user1'},@{Case='MissingUser';Identity='absent@gate.invalid'},@{Case='MissingUpn';Identity='user1'},@{Case='AmbiguousUser';Identity='ambiguous@gate.invalid'}) {
        $runtime=New-GateRuntime -Name ('main-'+$Case) -Case $Case
        $run=Invoke-GateProcess $runtime @{Action='Convert';Mode='Apply';Phase='AD';Force=$true;Identity=$Identity;ConfigPath=$runtime.ConfigPath}
        $run.ExitCode | Should -Be 1 -Because ('the synthetic process must return the expected code; evidence case '+(Split-Path $runtime.Root -Leaf))
        $run.Output | Should -Match 'RESULT: FAIL'
        @(Get-GateWrites $runtime).Count | Should -Be 0
        ($run.Output+$run.Error) | Should -Not -Match 'AD verified'
        [IO.File]::ReadAllText($run.MainResult.LogFile) | Should -Not -Match '(?m)^.*\] AD VERIFIED \|'
    }
    It 'keeps Convert Preview and native WhatIf write-free' -Tag 'Delta' -ForEach @(@{Mode='Preview';WhatIf=$false},@{Mode='Preview';WhatIf=$false},@{Mode='Apply';WhatIf=$true}) {
        $runtime=New-GateRuntime -Name ('main-readonly-'+$Mode)
        $arguments=@{Action='Convert';Mode=$Mode;Phase='Both';Force=$true;ConfigPath=$runtime.ConfigPath}
        if ($WhatIf) { $arguments.WhatIf=$true }
        $run=Invoke-GateProcess $runtime $arguments
        $run.ExitCode | Should -Be 0 -Because ('the synthetic process must return the expected code; evidence case '+(Split-Path $runtime.Root -Leaf))
        $run.Output | Should -Match 'RESULT: PASS'
        @(Get-GateWrites $runtime).Count | Should -Be 0
        @($run.Events | Where-Object Operation -Match 'CloudPhase|ADSync').Count | Should -Be 0
        @(Get-ChildItem -LiteralPath (Join-Path $runtime.Root 'reports') -Filter '*.csv').Count | Should -Be 1
        @(Get-ChildItem -LiteralPath (Join-Path $runtime.Root 'reports') -Filter '*.html').Count | Should -Be 1
        $csv=@(Import-Csv -LiteralPath $run.MainResult.CsvReport -Delimiter ';')
        $csv.Count | Should -Be 2
        $csv[0].PSObject.Properties.Name | Should -Contain 'FinalStatus'
        $csv[0].SamAccountName | Should -Be 'user1'
        $run.MainResult.TotalCount | Should -Be 2
        @(Get-ChildItem -LiteralPath (Join-Path $runtime.Root 'logs') -Filter '*.transcript.txt').Count | Should -Be 1
        $run.MainResult.TranscriptPath | Should -Not -BeNullOrEmpty
        Test-Path -LiteralPath $run.MainResult.TranscriptPath -PathType Leaf | Should -BeTrue
        $transcript=[IO.File]::ReadAllText($run.MainResult.TranscriptPath)
        $transcript | Should -Match '(?m)^RESULT: PASS\r?$'
        $transcript | Should -Not -Match 'RESULT: FAIL|transcript.*missing|transcript.*absent'
        $arguments.ContainsKey('Verbose') | Should -BeFalse
        $run.MainResult.ErrorCount | Should -Be 0
        @($run.MainResult.Issues).Count | Should -Be 0
        $log=[IO.File]::ReadAllText($run.MainResult.LogFile)
        foreach ($visible in @('BEFORE','PLANNED','extensionAttribute1','OriginalTag-1','OriginalTag-2','Converted',
            'proxyAddresses','SMTP:user1@gate.invalid','smtp:alias1@gate.invalid','X500:/o=Synthetic/ou=Gate/cn=User',
            'smtp:user1@synthetic.mail.onmicrosoft.com','CN=License,OU=Tests,DC=gate,DC=invalid','false',
            'Licence group | BEFORE : Not member','Licence group | PLANNED : Member')) {
            $log | Should -Match ([regex]::Escape($visible))
        }
        ($run.Output+$run.Error) | Should -Not -Match 'AD verified'
        $log | Should -Not -Match '(?m)^.*\] AD VERIFIED \|'
        $log | Should -Not -Match '[]|⚠'
        $run.MainResult.PlannedCount | Should -Be 2
    }
    It 'does not label the failed second target verified after a final AD readback divergence' -Tag 'Delta' {
        $runtime=New-GateRuntime -Name 'main-postverify-failed' -Case SecondPostVerifyFailure
        $run=Invoke-GateProcess $runtime @{Action='Convert';Mode='Apply';Phase='Both';Force=$true;ConfigPath=$runtime.ConfigPath}
        $run.ExitCode | Should -Be 1
        $run.Output | Should -Match 'RESULT: FAIL'
        @($run.Events | Where-Object Operation -eq 'SyntheticPostVerifyDivergence').Count | Should -Be 1
        @(Get-GateWrites $runtime).Count | Should -Be 4
        @($run.Events | Where-Object Operation -Match 'CloudPhase|ADSync').Count | Should -Be 0
        ($run.MainResult.Issues.Message -join ' ') | Should -Match 'AD state differs.*targetAddress'
        $rows=@(Import-Csv -LiteralPath $run.MainResult.CsvReport -Delimiter ';')
        @($rows | Where-Object { $_.SamAccountName -eq 'user1' -and $_.ADVerified -eq 'True' }).Count | Should -Be 1
        @($rows | Where-Object { $_.SamAccountName -eq 'user2' -and $_.FinalStatus -eq 'Error' -and $_.ADVerified -eq 'False' }).Count | Should -Be 1
        $log=[IO.File]::ReadAllText($run.MainResult.LogFile)
        $log | Should -Match 'VERIFIED'
        $verifiedHeaders=@([regex]::Matches($log,'\] AD VERIFIED \| [^\r\n]+'))
        $verifiedHeaders.Count | Should -BeGreaterThan 0
        @($verifiedHeaders | Where-Object { $_.Value -match 'user2' }).Count | Should -Be 0
        @($verifiedHeaders | Where-Object { $_.Value -notmatch 'user1' }).Count | Should -Be 0
        $activeBlock=''
        foreach ($line in ($log -split '\r?\n')) {
            if ($line -match '\] AD VERIFIED \||AD PLAN - planned values, not applied \|') { $activeBlock=$line }
            if ($line -match '\] AD VERIFIED|\| VERIFIED :') { $activeBlock | Should -Match '\] AD VERIFIED \| user1 \|' }
        }
    }
    It 'keeps Recover AD, Cloud and Finalize write-free in Preview and WhatIf' -ForEach @(
        @{Phase='AD';Mode='Preview';WhatIf=$false},@{Phase='AD';Mode='Preview';WhatIf=$false},@{Phase='AD';Mode='Apply';WhatIf=$true},
        @{Phase='Cloud';Mode='Preview';WhatIf=$false},@{Phase='Cloud';Mode='Preview';WhatIf=$false},@{Phase='Cloud';Mode='Apply';WhatIf=$true},
        @{Phase='Finalize';Mode='Preview';WhatIf=$false},@{Phase='Finalize';Mode='Preview';WhatIf=$false},@{Phase='Finalize';Mode='Apply';WhatIf=$true}
    ) {
        $runtime=New-GateRuntime -Name ('main-recover-'+$Phase+'-'+$Mode)
        $env:PRA_GATE_STATE=$runtime.StatePath; $env:PSModulePath=$runtime.Modules+';'+(Join-Path $PSHOME 'Modules')
        Import-Module ActiveDirectory -Force -Global
        $context=New-GateContext $runtime
        $bundles=New-GateSourceBundles $context
        if ($Phase -eq 'Finalize') { $arguments=@{Action='Finalize';Mode=$Mode;Force=$true;ConfigPath=$runtime.ConfigPath;Batch=$bundles.Manifest} }
        elseif ($Phase -eq 'Cloud') { $arguments=@{Action='Recover';Mode=$Mode;Phase='Cloud';Force=$true;ConfigPath=$runtime.ConfigPath;Batch=$bundles.Recover} }
        else { $arguments=@{Action='Recover';Mode=$Mode;Phase='AD';Force=$true;ConfigPath=$runtime.ConfigPath;Batch=$bundles.Source} }
        if ($WhatIf) { $arguments.WhatIf=$true }
        $run=Invoke-GateProcess $runtime $arguments
        $run.ExitCode | Should -Be 0 -Because ('the synthetic process must return the expected code; evidence case '+(Split-Path $runtime.Root -Leaf))
        $run.Output | Should -Match 'RESULT: PASS'
        @(Get-GateWrites $runtime).Count | Should -Be 0
    }
    It 'rejects a Finalize manifest replay from an earlier cycle with identical attrs but a newer USN' {
        $runtime=New-GateRuntime -Name 'main-stale-finalize'
        $env:PRA_GATE_STATE=$runtime.StatePath; $env:PSModulePath=$runtime.Modules+';'+(Join-Path $PSHOME 'Modules')
        Import-Module ActiveDirectory -Force -Global
        $context=New-GateContext $runtime
        $bundles=New-GateSourceBundles $context -ApplySnapshots
        $global:PraGateAd.Users[0].uSNChanged=[long]$global:PraGateAd.Users[0].uSNChanged+2
        [IO.File]::WriteAllText($runtime.StatePath,[Management.Automation.PSSerializer]::Serialize($global:PraGateAd,35))
        $before=@(Get-GateWrites $runtime).Count
        $run=Invoke-GateProcess $runtime @{Action='Finalize';Mode='Apply';Force=$true;ConfigPath=$runtime.ConfigPath;Batch=$bundles.Manifest}
        $run.ExitCode | Should -Be 1
        ($run.MainResult.Issues.Message -join ' ') | Should -Match 'AD proof is out of date'
        @(Get-GateWrites $runtime).Count | Should -Be $before
    }
    It 'blocks automatic post-cloud cleanup when AD changed during the synthetic polling phase' {
        $runtime=New-GateRuntime -Name 'main-cloud-concurrent' -Case CloudConcurrentChange
        $env:PRA_GATE_STATE=$runtime.StatePath; $env:PSModulePath=$runtime.Modules+';'+(Join-Path $PSHOME 'Modules')
        Import-Module ActiveDirectory -Force -Global
        $context=New-GateContext $runtime
        $bundles=New-GateSourceBundles $context
        $module=Get-Module PRA.Directory
        foreach ($plan in $bundles.Plans) {
            $user=@($runtime.State.Users | Where-Object ObjectGUID -eq $plan.Record.ObjectGuid)[0]
            foreach ($key in $plan.Kinds.Keys) { $user.$key=& $module { param($state) ConvertFrom-PraStoredValue $state } $plan.Desired[$key] }
            $user.uSNChanged=[long]101
        }
        $runtime.State.Group.member=@($runtime.State.Users | ForEach-Object DistinguishedName)
        [IO.File]::WriteAllText($runtime.StatePath,[Management.Automation.PSSerializer]::Serialize($runtime.State,35))
        $run=Invoke-GateProcess $runtime @{Action='Recover';Mode='Apply';Phase='Both';Force=$true;ConfigPath=$runtime.ConfigPath;Batch=$bundles.Source}
        $run.ExitCode | Should -Be 1
        @($run.Events | Where-Object Operation -eq 'SyntheticConcurrentEdit').Count | Should -Be 1
        $writes=@(Get-GateWrites $runtime)
        ($writes.Operation -join ',') | Should -Be 'Set-ADUser,Remove-ADGroupMember,Set-ADUser,Remove-ADGroupMember'
        ($run.MainResult.Issues.Message -join ' ') | Should -Match 'AD proof is out of date'
        @($run.Events | Where-Object Operation -Match 'ADSync').Count | Should -Be 0
    }
    It 'treats Check Apply as read-only' {
        $runtime=New-GateRuntime -Name 'main-cloudcheck'
        $run=Invoke-GateProcess $runtime @{Action='Check';Mode='Apply';Identity='user1@gate.invalid';Force=$true;ConfigPath=$runtime.ConfigPath}
        $run.ExitCode | Should -Be 0 -Because ('the synthetic process must return the expected code; evidence case '+(Split-Path $runtime.Root -Leaf))
        @(Get-GateWrites $runtime).Count | Should -Be 0
        @($run.Events | Where-Object Operation -eq 'CloudPhase-SyntheticBarrier').Count | Should -Be 1
    }
}

Describe 'Split cloud recovery never restores AD implicitly' -Tag 'GuiIntegration' {
    It 'packages confirmed cleanup with RSAT present and DeferOnPremRestore false, then Finalize restores the tags on the AD host' {
        $runtime=New-GateRuntime -Name 'gui-split-recover' -Case CloudConfirmed13
        $env:PRA_GATE_STATE=$runtime.StatePath
        $env:PSModulePath=$runtime.Modules+';'+(Join-Path $PSHOME 'Modules')
        Get-Module ActiveDirectory -All | Remove-Module -Force
        Import-Module ActiveDirectory -Force -Global
        Import-Module (Join-Path $global:PraGate.Package 'module\PRA.Directory.psm1') -Force -Global
        $context=New-GateContext $runtime
        $bundles=New-GateSourceBundles $context -ApplySnapshots
        [IO.File]::WriteAllText($runtime.StatePath,[Management.Automation.PSSerializer]::Serialize($global:PraGateAd,35))
        $before=@(Get-GateWrites $runtime).Count
        $config=Import-PraConfiguration -Path $runtime.ConfigPath -Root $runtime.Package
        $beforeEvents=@(Get-GateEvents $runtime).Count
        Import-Module (Join-Path $global:PraGate.Package 'module\PRA.Gui.psm1') -Force
        $guiState=Read-PraGuiState -Root $runtime.Package -ConfigPath $runtime.ConfigPath
        (Read-PraGuiBatch -Path $bundles.Source -Environment $config.Environment).Valid | Should -BeTrue
        (Read-PraGuiBatch -Path $bundles.Recover -Environment $config.Environment).Valid | Should -BeTrue
        $convertData=[IO.File]::ReadAllText($bundles.Source) | ConvertFrom-Json -DateKind String
        (Resolve-PraGuiBatch -Value $convertData.BatchId.Substring(0,8) -Operation Convert -State $guiState).Valid | Should -BeTrue
        $guiCloudRequest=New-PraGuiRequest -Action Recover -Phase Cloud -Batch $bundles.Recover
        Get-PraGuiGuard -Root $runtime.Package -ConfigPath $runtime.ConfigPath -Request $guiCloudRequest | Should -Match '^[0-9a-fA-F]{64}$'
        $config.SharedMailbox.DeferOnPremRestore | Should -BeFalse
        @(Get-Module -ListAvailable ActiveDirectory).Count | Should -BeGreaterThan 0
        $cloud=Invoke-GateProcess $runtime @{Action='Recover';Mode='Apply';Phase='Cloud';Force=$true;ConfigPath=$runtime.ConfigPath;Batch=$bundles.Recover}
        $cloud.ExitCode | Should -Be 2
        $cloud.MainResult.PendingCount | Should -Be 2
        @(Get-GateWrites $runtime).Count | Should -Be $before
        @($cloud.Events | Select-Object -Skip $beforeEvents | Where-Object Operation -Match 'Get-ADUser|ADSync').Count | Should -Be 0
        $manifest=@(Get-ChildItem -LiteralPath $runtime.State.BackupFolder -Recurse -File -Filter 'Finalize-*.json' |
            Where-Object { ([IO.File]::ReadAllText($_.FullName) | ConvertFrom-Json -DateKind String).Operation -eq 'RecoverFinalize' })[0]
        (Read-PraGuiBatch -Path $manifest.FullName -Environment $config.Environment).Valid | Should -BeTrue
        $guiFinalizeRequest=New-PraGuiRequest -Action Finalize -Batch $manifest.FullName
        Get-PraGuiGuard -Root $runtime.Package -ConfigPath $runtime.ConfigPath -Request $guiFinalizeRequest | Should -Match '^[0-9a-fA-F]{64}$'
        $cloud.MainResult.NextSteps -join ' ' | Should -Match 'Action Finalize'
        $beforeFinalizeEvents=@(Get-GateEvents $runtime).Count
        $finalize=Invoke-GateProcess $runtime @{Action='Finalize';Mode='Apply';Force=$true;ConfigPath=$runtime.ConfigPath;Batch=$manifest.FullName}
        $finalize.ExitCode | Should -Be 0
        $finalize.MainResult.SuccessCount | Should -Be 2
        @(Get-GateWrites $runtime).Count | Should -BeGreaterThan $before
        $restores=@($finalize.Events | Select-Object -Skip $beforeFinalizeEvents | Where-Object Operation -eq 'Set-ADUser')
        $restores.Count | Should -Be 2
        $restores[0].Detail.Replace.extensionAttribute1 | Should -BeExactly 'OriginalTag-1'
        $restores[1].Detail.Replace.extensionAttribute1 | Should -BeExactly 'OriginalTag-2'
        $rows=@(Import-Csv -LiteralPath $finalize.MainResult.CsvReport -Delimiter ';')
        @($rows | Where-Object { $_.ADVerified -eq 'True' -and $_.FinalStatus -eq 'Success' }).Count | Should -Be 2
    }
}

Describe 'Runtime output folders versus the authenticated package' -Tag 'Integrity' {
    BeforeAll {
        function global:Get-GatePackageFiles($Runtime) { @(Get-ChildItem -LiteralPath $Runtime.Package -Recurse -Force | ForEach-Object { $_.FullName.Substring($Runtime.Package.Length) } | Sort-Object) }
        function global:Set-GateOutputFolders($Runtime,[string]$Backup,[string]$Log,[string]$Report) {
            Set-GateConfigText $Runtime {
                param($t)
                $t=[regex]::Replace($t,"BackupFolder='[^']*'",[Text.RegularExpressions.MatchEvaluator]{ "BackupFolder='$Backup'" })
                $t=[regex]::Replace($t,"Logging=@\{Folder='[^']*'\}",[Text.RegularExpressions.MatchEvaluator]{ "Logging=@{Folder='$Log'}" })
                [regex]::Replace($t,'(Report=@\{Enabled=\$true;Folder=)''[^'']*''',[Text.RegularExpressions.MatchEvaluator]{ param($m) $m.Groups[1].Value+"'$Report'" })
            }.GetNewClosure()
        }
    }
    AfterAll { foreach ($name in 'Get-GatePackageFiles','Set-GateOutputFolders') { Remove-Item -LiteralPath ('Function:\'+$name) -ErrorAction SilentlyContinue } }
    It 'refuses every non-canonical in-package destination before any file exists (<Name>)' -ForEach @(
        @{Name='custom log folder';Backup='.\Backups';Log='.\audit';Report='.\reports'}
        @{Name='custom report folder';Backup='.\Backups';Log='.\logs';Report='.\module\out'}
        @{Name='backup folder beside the code';Backup='.\config';Log='.\logs';Report='.\reports'}
        @{Name='folder overlapping templates';Backup='.\Backups';Log='.\templates\logs';Report='.\reports'}
        @{Name='package root itself';Backup='.\Backups';Log='.\logs';Report='.'}
        @{Name='wrong case of the canonical folder';Backup='.\backups';Log='.\logs';Report='.\reports'}
        @{Name='canonical folder of another setting';Backup='.\logs';Log='.\logs';Report='.\reports'}
        @{Name='parent segments back into the code';Backup='.\Backups\..\module';Log='.\logs';Report='.\reports'}
    ) {
        $runtime=New-GateRuntime -Name ('outputs-'+($Name -replace '\W','-'))
        Set-GateOutputFolders $runtime $Backup $Log $Report
        $before=Get-GatePackageFiles $runtime
        { Import-PraConfiguration -Path $runtime.ConfigPath -Root $runtime.Package } | Should -Throw '*inside the signed package*'
        Import-Module (Join-Path $runtime.Package 'module\PRA.Gui.psm1') -Force
        $state=Read-PraGuiState -Root $runtime.Package -ConfigPath $runtime.ConfigPath
        $state.ConfigError | Should -Match 'inside the signed package'
        $run=Invoke-GateProcess $runtime @{Action='Convert';Mode='Preview';Phase='Both';ConfigPath=$runtime.ConfigPath}
        $run.ExitCode | Should -Not -Be 0
        (@($run.MainResult.Issues | ForEach-Object { [string]$_.Message }) -join ' ') | Should -Match 'inside the signed package'
        # The failed start still audits itself in the canonical folders; nothing may appear anywhere else.
        @(Get-GatePackageFiles $runtime | Where-Object { $_ -notin $before -and $_ -cnotmatch '^\\(Backups|logs|reports)(\\|$)' }) | Should -BeNullOrEmpty
    }
    It 'accepts the canonical folders, their sub-folders and folders outside the package, and later runs keep working' {
        $runtime=New-GateRuntime -Name 'outputs-valid'
        $external=Join-Path $runtime.Root 'external-out'
        Set-GateOutputFolders $runtime '.\Backups\site-a' '.\logs' $external
        $config=Import-PraConfiguration -Path $runtime.ConfigPath -Root $runtime.Package
        $config.Report.Folder | Should -BeExactly $external
        $config.Logging.Folder | Should -BeExactly (Join-Path $runtime.Package 'logs')
        $run=Invoke-GateProcess $runtime @{Action='Convert';Mode='Preview';Phase='Both';ConfigPath=$runtime.ConfigPath}
        $run.ExitCode | Should -Be 0
        (Test-Path -LiteralPath (Join-Path $runtime.Package 'logs')) | Should -BeTrue
        @(Get-ChildItem -LiteralPath $external -File).Count | Should -BeGreaterThan 0
        { Import-Module (Join-Path $runtime.Package 'module\PRA.Cloud.psm1') -Force } | Should -Not -Throw
        $again=Invoke-GateProcess $runtime @{Action='Convert';Mode='Preview';Phase='Both';ConfigPath=$runtime.ConfigPath}
        $again.ExitCode | Should -Be 0
    }
    It 'refuses a canonical folder that is a reparse point inside the package' {
        $runtime=New-GateRuntime -Name 'outputs-reparse'
        $target=Join-Path $runtime.Root 'junction-target'; $null=New-Item -ItemType Directory -Path $target
        Set-GateOutputFolders $runtime '.\Backups' '.\logs' '.\reports'
        $link=Join-Path $runtime.Package 'logs'
        $null=New-Item -ItemType Junction -Path $link -Target $target -ErrorAction Stop
        try { { Import-PraConfiguration -Path $runtime.ConfigPath -Root $runtime.Package } | Should -Throw '*reparse point*' }
        finally { [IO.Directory]::Delete($link) }
    }
    It 'refuses the protected folders through a device prefix or a junction alias, also for a missing child, before any file exists (<Name>)' -ForEach @(
        @{Name='device prefix, code folder';Kind='Device';Child='module'}
        @{Name='device prefix, missing child of the code folder';Kind='Device';Child='module\not-yet'}
        @{Name='device prefix, config folder';Kind='Device';Child='config'}
        @{Name='junction alias, code folder';Kind='Alias';Child='module'}
        @{Name='junction alias, missing child of the code folder';Kind='Alias';Child='module\not-yet\deeper'}
        @{Name='junction alias, package root';Kind='Alias';Child=''}
        @{Name='junction alias, sibling name of the canonical folder';Kind='Alias';Child='logs-x'}
    ) {
        $runtime=New-GateRuntime -Name ('outputs-alias-'+($Name -replace '\W','-'))
        $base=$runtime.Package
        if ($Kind -eq 'Alias') {
            $base=Join-Path $runtime.Root 'package-alias'
            $null=New-Item -ItemType Junction -Path $base -Target $runtime.Package -ErrorAction Stop
        }
        else { $base='\\?\'+$runtime.Package }
        try {
            $destination=if ($Child) { $base+'\'+$Child } else { $base }
            Set-GateOutputFolders $runtime '.\Backups' $destination '.\reports'
            $before=Get-GatePackageFiles $runtime
            { Import-PraConfiguration -Path $runtime.ConfigPath -Root $runtime.Package } | Should -Throw '*inside the signed package*'
            Import-Module (Join-Path $runtime.Package 'module\PRA.Gui.psm1') -Force
            (Read-PraGuiState -Root $runtime.Package -ConfigPath $runtime.ConfigPath).ConfigError | Should -Match 'inside the signed package'
            $run=Invoke-GateProcess $runtime @{Action='Convert';Mode='Preview';Phase='Both';ConfigPath=$runtime.ConfigPath}
            $run.ExitCode | Should -Not -Be 0
            @(Get-GatePackageFiles $runtime | Where-Object { $_ -notin $before -and $_ -cnotmatch '^\\(Backups|logs|reports)(\\|$)' }) | Should -BeNullOrEmpty
        }
        finally { if ($Kind -eq 'Alias') { [IO.Directory]::Delete($base) } }
    }
    It 'resolves the canonical folders through a device prefix or a junction alias to the physical package path and keeps ordinary external folders' {
        $runtime=New-GateRuntime -Name 'outputs-alias-valid'
        $alias=Join-Path $runtime.Root 'package-alias'
        $null=New-Item -ItemType Junction -Path $alias -Target $runtime.Package -ErrorAction Stop
        try {
            $external=Join-Path $runtime.Root 'external-out'
            Set-GateOutputFolders $runtime ('\\?\'+$runtime.Package+'\Backups\site-a') ($alias+'\logs') $external
            $config=Import-PraConfiguration -Path $runtime.ConfigPath -Root $runtime.Package
            $config.Storage.BackupFolder | Should -BeExactly (Join-Path $runtime.Package 'Backups\site-a')
            $config.Logging.Folder | Should -BeExactly (Join-Path $runtime.Package 'logs')
            $config.Report.Folder | Should -BeExactly $external
        }
        finally { [IO.Directory]::Delete($alias) }
    }
    It 'loads and checks real configurations in a child <Engine> process: canonical and external folders are accepted, aliases and unresolved paths are refused' -ForEach @(
        @{Engine='PowerShell 7';Exe=(Join-Path $PSHOME 'pwsh.exe');Major=7}
    ) {
        $Exe | Should -Not -BeNullOrEmpty
        $runtime=New-GateRuntime -Name ('outputs-engine-'+$Major)
        $alias=Join-Path $runtime.Root 'package-alias'
        $null=New-Item -ItemType Junction -Path $alias -Target $runtime.Package -ErrorAction Stop
        $external=Join-Path $runtime.Root 'external-out'
        try {
            $cases=[ordered]@{
                valid=@('.\Backups\site-a','.\logs',$external)
                volumeRoot=@('.\Backups','.\logs',([IO.Path]::GetPathRoot($runtime.Package)))
                device=@(('\\?\'+$runtime.Package+'\Backups'),'.\logs','.\reports')
                aliasCanonical=@('.\Backups',($alias+'\logs'),'.\reports')
                deviceCode=@('.\Backups',('\\?\'+$runtime.Package+'\module'),'.\reports')
                aliasCode=@('.\Backups','.\logs',($alias+'\module\not-yet'))
                unknownVolume=@('.\Backups','.\logs','\\?\Volume{00000000-0000-0000-0000-000000000000}\out')
                deviceDots=@('.\Backups','.\logs',('\\?\'+$runtime.Package+'\Backups\..\module'))
            }
            $list=@()
            foreach ($key in $cases.Keys) {
                Set-GateOutputFolders $runtime $cases[$key][0] $cases[$key][1] $cases[$key][2]
                $path=Join-Path $runtime.Root ('case-'+$key+'.psd1'); Copy-Item -LiteralPath $runtime.ConfigPath -Destination $path
                $list+=$path
            }
            $before=Get-GatePackageFiles $runtime
            $script=@"
`$ErrorActionPreference='Stop'
Import-Module '$($runtime.Package.Replace("'","''"))\module\PRA.Common.psm1' -Force
`$results=[ordered]@{ Version=`$PSVersionTable.PSVersion.ToString(); Cases=[ordered]@{} }
foreach (`$file in @('$(($list | ForEach-Object { $_.Replace("'","''") }) -join "','")')) {
    `$name=[IO.Path]::GetFileNameWithoutExtension(`$file).Substring(5)
    try { `$c=Import-PraConfiguration -Path `$file -Root '$($runtime.Package.Replace("'","''"))'; `$results.Cases[`$name]=@{Ok=`$true;Backup=`$c.Storage.BackupFolder;Log=`$c.Logging.Folder;Report=`$c.Report.Folder} }
    catch { `$results.Cases[`$name]=@{Ok=`$false;Error=`$_.Exception.Message} }
}
`$results.Init=& (Get-Module PRA.Common) {
    `$first=`$script:PraNativePath; `$null=Get-PraPhysicalPath '$($runtime.Package.Replace("'","''"))\module'; `$null=Get-PraPhysicalPath '$($external.Replace("'","''"))\missing'
    @{Created=(`$null -ne `$first); Cached=([object]::ReferenceEquals(`$first,`$script:PraNativePath)); Type=`$first.FullName; Methods=@(`$first.GetMethods() | Where-Object DeclaringType -eq `$first | ForEach-Object Name | Sort-Object)}
}
[IO.File]::WriteAllText('$((Join-Path $runtime.Root 'engine.json').Replace("'","''"))',(`$results | ConvertTo-Json -Depth 6),(New-Object Text.UTF8Encoding(`$false)))
"@
            $scriptPath=Join-Path $runtime.Root 'engine.ps1'
            [IO.File]::WriteAllText($scriptPath,$script,(New-Object Text.UTF8Encoding($true)))
            $output=& $Exe -NoProfile -NonInteractive -File $scriptPath 2>&1
            $LASTEXITCODE | Should -Be 0 -Because ([string]($output -join ' '))
            $r=[IO.File]::ReadAllText((Join-Path $runtime.Root 'engine.json')) | ConvertFrom-Json -DateKind String
            [int]($r.Version.Split('.')[0]) | Should -Be $Major
            $r.Init.Created | Should -BeTrue
            $r.Init.Cached | Should -BeTrue
            $r.Init.Methods | Should -Contain 'CreateFileW'
            $r.Init.Methods | Should -Contain 'GetFinalPathNameByHandleW'
            $r.Cases.valid.Ok | Should -BeTrue
            $r.Cases.valid.Backup | Should -BeExactly (Join-Path $runtime.Package 'Backups\site-a')
            $r.Cases.valid.Log | Should -BeExactly (Join-Path $runtime.Package 'logs')
            $r.Cases.valid.Report | Should -BeExactly $external
            $r.Cases.volumeRoot.Ok | Should -BeTrue
            $r.Cases.volumeRoot.Report | Should -BeExactly ([IO.Path]::GetPathRoot($runtime.Package))
            $r.Cases.device.Ok | Should -BeTrue
            $r.Cases.device.Backup | Should -BeExactly (Join-Path $runtime.Package 'Backups')
            $r.Cases.aliasCanonical.Ok | Should -BeTrue
            $r.Cases.aliasCanonical.Log | Should -BeExactly (Join-Path $runtime.Package 'logs')
            $r.Cases.deviceCode.Ok | Should -BeFalse
            $r.Cases.deviceCode.Error | Should -Match 'inside the signed package'
            $r.Cases.aliasCode.Ok | Should -BeFalse
            $r.Cases.aliasCode.Error | Should -Match 'inside the signed package'
            $r.Cases.unknownVolume.Ok | Should -BeFalse
            $r.Cases.unknownVolume.Error | Should -Match 'cannot be checked against the signed package'
            $r.Cases.deviceDots.Ok | Should -BeFalse
            $r.Cases.deviceDots.Error | Should -Match 'cannot be checked against the signed package'
            @(Get-GatePackageFiles $runtime) | Should -Be $before
        }
        finally { [IO.Directory]::Delete($alias) }
    }
    It 'refuses a destination whose physical location cannot be resolved instead of treating it as external (<Name>)' -ForEach @(
        @{Name='unknown volume namespace';Path='\\?\Volume{00000000-0000-0000-0000-000000000000}\out'}
        @{Name='device namespace with parent segments';Path='\\?\C:\a\..\b'}
    ) {
        $runtime=New-GateRuntime -Name ('outputs-unresolved-'+($Name -replace '\W','-'))
        Set-GateOutputFolders $runtime '.\Backups' '.\logs' $Path
        $before=Get-GatePackageFiles $runtime
        { Import-PraConfiguration -Path $runtime.ConfigPath -Root $runtime.Package } | Should -Throw '*cannot be checked against the signed package*'
        @(Get-GatePackageFiles $runtime) | Should -Be $before
    }
    # Behaviour difference of .NET (PowerShell 7) versus .NET Framework (2.x): GetFullPath normalises the dots of a \\.\ device path and
    # Directory.Exists answers for the volume root \\.\C:\, so the path IS resolved now instead of being unresolvable. It is then checked
    # exactly like the \\?\ forms: an external folder is accepted, a folder that leads into the signed package is refused.
    It 'resolves a device-namespace path with a current-folder segment after normalisation: external is accepted, the package is still refused' {
        $runtime=New-GateRuntime -Name 'outputs-device-dot'
        $external=Join-Path $runtime.Root 'external-dot'
        Set-GateOutputFolders $runtime '.\Backups' '.\logs' ('\\.\'+$external.Replace('\','\.\'))
        { Import-PraConfiguration -Path $runtime.ConfigPath -Root $runtime.Package } | Should -Not -Throw
        Set-GateOutputFolders $runtime '.\Backups' '.\logs' ('\\.\'+$runtime.Package+'\module\.\x')
        { Import-PraConfiguration -Path $runtime.ConfigPath -Root $runtime.Package } | Should -Throw '*inside the signed package*'
    }
}

Describe 'Direct OU and CSV targeting' -Tag 'Targeting' {
    It 'applies OU/CSV overrides before scope validation without rewriting the configuration' {
        $runtime=New-GateRuntime -Name 'scope-overrides'
        Set-GateConfigText $runtime { param($t) $t.Replace("Mode='Auto';SearchBase='OU=Tests,DC=gate,DC=invalid'","Mode='OU';SearchBase=''") }
        $hash=(Get-FileHash $runtime.ConfigPath).Hash
        $override=Get-PraTargetOverride -SearchBase 'OU=Selected,DC=gate,DC=invalid'
        $cfg=Import-PraConfiguration $runtime.ConfigPath $runtime.Package -ScopeOverride $override
        $cfg.Scope.Mode | Should -BeExactly 'OU'
        $cfg.Scope.SearchBase | Should -BeExactly 'OU=Selected,DC=gate,DC=invalid'
        $override=Get-PraTargetOverride -CsvPath '.\selection.csv'
        $cfg=Import-PraConfiguration $runtime.ConfigPath $runtime.Package -ScopeOverride $override
        $cfg.Scope.Mode | Should -BeExactly 'Csv'
        $cfg.Scope.SearchBase | Should -BeNullOrEmpty
        (Get-FileHash $runtime.ConfigPath).Hash | Should -BeExactly $hash
        { Get-PraTargetOverride -SearchBase 'OU=A' -CsvPath 'targets.csv' } | Should -Throw
        { Get-PraTargetOverride -SearchBase 'OU=A' -Identity user1 } | Should -Throw
    }
    It 'reads comma and semicolon CSVs with literal identities and refuses incomplete lists' {
        $runtime=New-GateRuntime -Name 'csv-validation'
        $path=Join-Path $runtime.Root 'targets.csv'
        foreach ($delimiter in @(',',';')) {
            [IO.File]::WriteAllText($path,('"Identity"'+$delimiter+'"Name"'+"`r`n"+'"user1@gate.invalid"'+$delimiter+'"One"'+"`r`n"+'"user2@gate.invalid"'+$delimiter+'"Two"'),(New-Object Text.UTF8Encoding($true)))
            $rows=@(Read-PraTargetCsv $path)
            $rows.Count | Should -Be 2
            $rows[1].Identity | Should -BeExactly 'user2@gate.invalid'
        }
        foreach ($bad in @('',"Identity`r`n","Wrong`r`nuser1","Identity;Name`r`n;missing")) {
            [IO.File]::WriteAllText($path,$bad)
            { Read-PraTargetCsv $path } | Should -Throw
        }
    }
    It 'routes a selected mixed user/shared CSV through the real entry and target selector' {
        $runtime=New-GateRuntime -Name 'csv-mixed-mailboxes'
        $runtime.State.Users[1].msExchRecipientTypeDetails=[long]4
        [IO.File]::WriteAllText($runtime.StatePath,[Management.Automation.PSSerializer]::Serialize($runtime.State,35))
        Set-GateConfigText $runtime { param($t) $t.Replace('IncludeShared=$false','IncludeShared=$true') }
        $path=Join-Path $runtime.Root 'targets.csv'
        [IO.File]::WriteAllText($path,"Identity;Name`r`nuser1@gate.invalid;User`r`nuser2@gate.invalid;Shared")
        $configHash=(Get-FileHash $runtime.ConfigPath).Hash
        $run=Invoke-GateProcess $runtime @{Action='Convert';Mode='Preview';Phase='AD';CsvPath=$path;ConfigPath=$runtime.ConfigPath}
        $run.ExitCode | Should -Be 0
        $run.MainResult.PlannedCount | Should -Be 2
        $rows=@(Import-Csv $run.MainResult.CsvReport -Delimiter ';')
        @($rows | Where-Object IsShared -eq 'True').Count | Should -Be 1
        @($rows | Where-Object IsShared -eq 'False').Count | Should -Be 1
        ($run.MainResult.NextSteps -join ' ') | Should -Match 'CsvPath'
        (Get-FileHash $runtime.ConfigPath).Hash | Should -BeExactly $configHash
        @(Get-GateWrites $runtime).Count | Should -Be 0
    }
    It 'rejects OU/CSV selection in Cloud, Recover and conflicting selectors before directory access' -ForEach @(
        @{Action='Convert';Phase='Cloud';Params=@{SearchBase='OU=Wrong,DC=gate,DC=invalid';Batch='deadbeef'}},
        @{Action='Recover';Phase='AD';Params=@{CsvPath='targets.csv';Batch='deadbeef'}},
        @{Action='Convert';Phase='AD';Params=@{SearchBase='OU=Wrong,DC=gate,DC=invalid';Identity='user1'}}
    ) {
        $runtime=New-GateRuntime -Name 'invalid-source'
        $arguments=@{Action=$Action;Phase=$Phase;Mode='Apply';Force=$true;ConfigPath=$runtime.ConfigPath}
        foreach ($key in $Params.Keys) { $arguments[$key]=$Params[$key] }
        $run=Invoke-GateProcess $runtime $arguments
        $run.ExitCode | Should -Be 1
        @($run.Events | Where-Object Operation -Match '^(Get-AD|Set-|Add-|Remove-|CloudPhase|Start-ADSync)').Count | Should -Be 0
    }
    It 'previews a selected OU and a single shared identity without consulting the cloud' -ForEach @(@{Source='OU'},@{Source='Shared'}) {
        $runtime=New-GateRuntime -Name 'ou-or-shared'
        $arguments=@{Action='Convert';Phase='AD';Mode='Preview';ConfigPath=$runtime.ConfigPath}
        if ($Source -eq 'OU') { $arguments.SearchBase='OU=Selected,DC=gate,DC=invalid' }
        else {
            $runtime.State.Users[1].msExchRecipientTypeDetails=[long]4
            [IO.File]::WriteAllText($runtime.StatePath,[Management.Automation.PSSerializer]::Serialize($runtime.State,35))
            $arguments.Identity='user2@gate.invalid'
        }
        $run=Invoke-GateProcess $runtime $arguments
        $run.ExitCode | Should -Be 0
        if ($Source -eq 'OU') {
            @($run.Events | Where-Object { $_.Operation -eq 'Get-ADUser' -and $_.Detail.SearchBase -eq $arguments.SearchBase }).Count | Should -BeGreaterThan 0
        }
        else { $run.MainResult.PlannedCount | Should -Be 1 }
        @(Get-GateWrites $runtime).Count | Should -Be 0
        @($run.Events | Where-Object Operation -eq 'CloudPhase-SyntheticBarrier').Count | Should -Be 0
    }
    It 'reads OU choices on the fixed synthetic DC using the real PowerShell 7 helper without writes' {
        $runtime=New-GateRuntime -Name 'ou-readonly-child'
        $resultPath=Join-Path $runtime.Root 'ou.json'
        $code=@"
`$env:PRA_GATE_NONET='SYNTHETIC-NO-NETWORK'
`$env:PRA_GATE_STATE='$($runtime.StatePath)'
`$env:PSModulePath='$($runtime.Modules);$(Join-Path $PSHOME 'Modules')'
Import-Module '$($runtime.Modules)\ActiveDirectory\ActiveDirectory.psm1' -Force -Global
& '$($runtime.Package)\module\PRA.Gui.Directory.ps1' -ConfigPath '$($runtime.ConfigPath)' -ResultPath '$resultPath'
exit `$LASTEXITCODE
"@
        $info=New-Object Diagnostics.ProcessStartInfo
        $info.FileName=Join-Path $PSHOME 'pwsh.exe'
        $info.Arguments='-NoProfile -NonInteractive -EncodedCommand '+[Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($code))
        $info.UseShellExecute=$false; $info.CreateNoWindow=$true; $info.RedirectStandardOutput=$true; $info.RedirectStandardError=$true
        $p=[Diagnostics.Process]::Start($info)
        try {
            $out=$p.StandardOutput.ReadToEndAsync(); $err=$p.StandardError.ReadToEndAsync()
            $p.WaitForExit(30000) | Should -BeTrue
            $p.ExitCode | Should -Be 0 -Because ($out.Result+$err.Result)
            $data=[IO.File]::ReadAllText($resultPath) | ConvertFrom-Json -DateKind String
            $data.Success | Should -BeTrue
            $data.Server | Should -BeExactly $runtime.State.Server
            $data.Units.Count | Should -Be 2
            @(Get-GateWrites $runtime).Count | Should -Be 0
        } finally { $p.Dispose() }
    }
}

Describe 'GUI entry routing uses no directory or cloud module' -Tag 'GuiRouting' {
    It 'routes -Gui before the directory imports using <Engine>, and refuses mixed operation parameters' -ForEach @(
        @{Engine='pwsh.exe'}
    ) {
        $runtime=New-GateRuntime -Name 'gui-entry-routing'
        $stub=@'
function Show-PraGui {
    param([string]$Root,[string]$ConfigPath,[string]$Version)
    [IO.File]::WriteAllText((Join-Path $Root 'opened.json'),(@{
        Root=$Root;ConfigPath=$ConfigPath;Version=$Version;Edition=$PSVersionTable.PSEdition
        DirectoryLoaded=@(Get-Module PRA.Directory,ActiveDirectory,PRA.Cloud).Count
    } | ConvertTo-Json))
}
Export-ModuleMember -Function Show-PraGui
'@
        [IO.File]::WriteAllText((Join-Path $runtime.Package 'module\PRA.Gui.psm1'),$stub,(New-Object Text.UTF8Encoding($true)))
        Set-PraFixtureHash -Root $runtime.Package -Relative 'module\PRA.Gui.psm1'
        $entry=Join-Path $runtime.Package 'Invoke-PraRemoteMailbox.ps1'
        $exe=(Get-Command $Engine -CommandType Application -ErrorAction Stop).Source
        foreach ($mixed in @($false,$true)) {
            $info=New-Object Diagnostics.ProcessStartInfo
            $info.FileName=$exe
            $info.Arguments='-NoLogo -NoProfile -NonInteractive -STA -File "'+$entry+'" -Gui -ConfigPath "'+$runtime.ConfigPath+'"'
            if ($mixed) { $info.Arguments+=' -Action Convert' }
            $info.UseShellExecute=$false; $info.CreateNoWindow=$true
            $info.RedirectStandardOutput=$true; $info.RedirectStandardError=$true
            $process=[Diagnostics.Process]::Start($info)
            try {
                $out=$process.StandardOutput.ReadToEndAsync(); $err=$process.StandardError.ReadToEndAsync()
                $process.WaitForExit(30000) | Should -BeTrue
                $output=$out.GetAwaiter().GetResult()+$err.GetAwaiter().GetResult()
                $marker=Join-Path $runtime.Package 'opened.json'
                if ($mixed) {
                    $process.ExitCode | Should -Not -Be 0
                    Test-Path -LiteralPath $marker | Should -BeFalse
                }
                else {
                    $process.ExitCode | Should -Be 0 -Because $output
                    $opened=[IO.File]::ReadAllText($marker) | ConvertFrom-Json -DateKind String
                    $opened.Version | Should -BeExactly (Get-PraToolVersion)
                    $opened.DirectoryLoaded | Should -Be 0
                    $opened.ConfigPath | Should -BeExactly $runtime.ConfigPath
                    Remove-Item -LiteralPath $marker -Force
                }
            }
            finally { $process.Dispose() }
        }
        @(Get-GateWrites $runtime).Count | Should -Be 0
    }
}

Describe 'GUI events mirror the existing engine without extra mutations' -Tag 'GuiEvents' {
    BeforeEach {
        $oldEventPath=$env:PRA_EVENT_FILE
        $runtime=New-GateRuntime -Name 'gui-event-channel'
        $env:PRA_EVENT_FILE=Join-Path $runtime.Root 'gui.events.jsonl'
    }
    AfterEach { $env:PRA_EVENT_FILE=$oldEventPath }

    It 'does nothing on the pipeline and creates no event file for an ordinary CLI run' {
        $env:PRA_EVENT_FILE=''
        @(Write-PraEvent -Kind item -Data @{text='not emitted'}).Count | Should -Be 0
        Test-Path (Join-Path $runtime.Root 'gui.events.jsonl') | Should -BeFalse
    }
    It 'emits a complete UTF8 line with literal Unicode and newlines, without contaminating the pipeline' {
        $text='message '+[char]0x00E9+"`n"+"'; exit 73; #"
        @(Write-PraEvent -Kind item -Data @{text=$text;status='Info';identity='user@gate.invalid'}).Count | Should -Be 0
        $bytes=[IO.File]::ReadAllBytes($env:PRA_EVENT_FILE)
        $bytes[-1] | Should -Be 10
        $bytes[0] | Should -Be 123
        $event=[IO.File]::ReadAllText($env:PRA_EVENT_FILE) | ConvertFrom-Json -DateKind String
        $event.kind | Should -BeExactly 'item'
        $event.text | Should -BeExactly $text
        $event.identity | Should -BeExactly 'user@gate.invalid'
    }
    It 'surfaces an unavailable event channel rather than pretending the window received the event' {
        $env:PRA_EVENT_FILE=Join-Path $runtime.Root 'missing\events.jsonl'
        { Write-PraEvent -Kind item -Data @{text='not delivered'} } | Should -Throw
    }
    It 'reports the actual Preview result and phase, preserving the native result and write-free behavior' {
        $run=Invoke-GateProcess $runtime @{Action='Convert';Phase='AD';Mode='Preview';ConfigPath=$runtime.ConfigPath}
        $run.ExitCode | Should -Be 0
        $events=@(Get-Content -LiteralPath $env:PRA_EVENT_FILE -Encoding UTF8 | ForEach-Object { $_ | ConvertFrom-Json -DateKind String })
        @($events | Where-Object kind -eq 'start').Count | Should -Be 1
        @($events | Where-Object kind -eq 'step').Count | Should -BeGreaterThan 0
        @($events | Where-Object kind -eq 'summary').Count | Should -Be 1
        @($events | Where-Object kind -eq 'result').Count | Should -Be 1
        $result=@($events | Where-Object kind -eq 'result')[0]
        $result.phase | Should -BeExactly 'AD'
        $result.action | Should -BeExactly 'Convert'
        $result.mode | Should -BeExactly 'Preview'
        $result.exitCode | Should -Be $run.ExitCode
        $result.total | Should -Be $run.MainResult.TotalCount
        $result.planned | Should -Be 2
        $result.csvReport | Should -BeExactly $run.MainResult.CsvReport
        Import-Module (Join-Path $global:PraGate.Package 'module\PRA.Gui.psm1') -Force
        $request=New-PraGuiRequest -Action Convert -Phase AD
        Test-PraGuiPreview -Result $result -Request $request -NativeExitCode $run.ExitCode | Should -BeTrue
        @(Get-GateWrites $runtime).Count | Should -Be 0
    }
    It 'reports a failed run as failed, including its issue and native exit code' {
        $run=Invoke-GateProcess $runtime @{Action='Recover';Phase='AD';Mode='Preview';Batch='deadbeef';ConfigPath=$runtime.ConfigPath}
        $run.ExitCode | Should -Be 1
        $result=@(Get-Content -LiteralPath $env:PRA_EVENT_FILE -Encoding UTF8 | ForEach-Object { $_ | ConvertFrom-Json -DateKind String } |
            Where-Object kind -eq 'result')[0]
        $result.exitCode | Should -Be 1
        $result.status | Should -BeExactly 'Failed'
        $result.issues -join ' ' | Should -Match 'not found'
        Import-Module (Join-Path $global:PraGate.Package 'module\PRA.Gui.psm1') -Force
        $request=New-PraGuiRequest -Action Recover -Phase AD -Batch deadbeef
        Test-PraGuiPreview -Result $result -Request $request -NativeExitCode $run.ExitCode | Should -BeFalse
        @(Get-GateWrites $runtime).Count | Should -Be 0
    }
}

Describe 'Culture-neutral test gate help validation' {
    BeforeAll {
        $gatePath=Join-Path $global:PraGate.Release 'tests\Invoke-TestGate.ps1'
        $gateAst=[Management.Automation.Language.Parser]::ParseFile($gatePath,[ref]$null,[ref]$null)
        $helpAssignment=$gateAst.Find({
            param($node)
            $node -is [Management.Automation.Language.AssignmentStatementAst] -and
                $node.Left -is [Management.Automation.Language.VariableExpressionAst] -and
                $node.Left.VariablePath.UserPath -eq 'helpPass'
        },$true)
        if ($null -eq $helpAssignment) { throw 'The gate help validation assignment is missing.' }
        $helpValidation=[scriptblock]::Create($helpAssignment.Right.Extent.Text)
    }
    It 'accepts actual structured help independently of the displayed culture <Culture>' -ForEach @(
        @{Culture='fr-FR'},@{Culture='en-US'}
    ) {
        $thread=[Threading.Thread]::CurrentThread
        $originalCulture=$thread.CurrentUICulture
        try {
            $thread.CurrentUICulture=[Globalization.CultureInfo]::GetCultureInfo($Culture)
            $help=Get-Help (Join-Path $global:PraGate.Source 'Invoke-PraRemoteMailbox.ps1') -Full
            $helpText='Localized headings are deliberately not part of the help contract.'
            (& $helpValidation) | Should -BeTrue
        }
        finally { $thread.CurrentUICulture=$originalCulture }
    }
    It 'still rejects missing help metadata <Missing>' -ForEach @(
        @{Missing='Synopsis'},@{Missing='Examples'},@{Missing='WhatIf'}
    ) {
        $help=@{
            Synopsis='An authored synopsis.'
            examples=@{example=@('example 1','example 2','example 3')}
            parameters=@{parameter=@(@{name='Action'},@{name='WhatIf'})}
        }
        switch ($Missing) {
            Synopsis { $help.Synopsis='' }
            Examples { $help.examples.example=@('example 1','example 2') }
            WhatIf { $help.parameters.parameter=@(@{name='Action'}) }
        }
        $helpText='SYNOPSIS WhatIf: formatted text cannot substitute for missing structured metadata.'
        (& $helpValidation) | Should -BeFalse
    }
}

Describe 'Scripts start with pwsh.exe -File (scheduled task)' {
    It 'never reads $PSScriptRoot in a param() default (kept from 2.x, where it was empty in Windows PowerShell 5.1 with -File)' {
        $files = @(Join-Path $global:PraGate.Source 'Invoke-PraRemoteMailbox.ps1') + @(Get-ChildItem -LiteralPath (Join-Path $global:PraGate.Release 'tools') -Filter '*.ps1' | ForEach-Object FullName)
        $found = @(foreach ($file in $files) {
            $ast = [System.Management.Automation.Language.Parser]::ParseFile($file, [ref]$null, [ref]$null)
            foreach ($block in @($ast.FindAll({ param($node) $node -is [System.Management.Automation.Language.ParamBlockAst] }, $true))) {
                foreach ($parameter in $block.Parameters) {
                    if ($parameter.DefaultValue -and $parameter.DefaultValue.Extent.Text -match 'PSScriptRoot|PSCommandPath|MyInvocation') { '{0}: {1}' -f (Split-Path $file -Leaf), $parameter.Name.Extent.Text }
                }
            }
        })
        $found | Should -BeNullOrEmpty
    }
    It 'resolves the default configuration path in the script body' {
        $text = [IO.File]::ReadAllText((Join-Path $global:PraGate.Source 'Invoke-PraRemoteMailbox.ps1'))
        $text | Should -Match "if \(-not \`$ConfigPath\) \{ \`$ConfigPath = Join-Path \`$PSScriptRoot 'config\\PraRemoteMailbox\.config\.psd1' \}"
    }
}
Describe 'Release 2.3.0 - entry casing, Recover pre-check, journal order and next steps' -Tag 'Release230' {
    BeforeEach {
        $runtime=New-GateRuntime -Name 'release230'
        $env:PRA_GATE_STATE=$runtime.StatePath
        $env:PSModulePath=$runtime.Modules+';'+(Join-Path $PSHOME 'Modules')
        Remove-Module PRA.Directory -Force -ErrorAction SilentlyContinue
        Get-Module ActiveDirectory -All | Remove-Module -Force -ErrorAction Stop
        Import-Module (Join-Path $runtime.Modules 'ActiveDirectory\ActiveDirectory.psm1') -Force -Global
        Import-Module (Join-Path $global:PraGate.Package 'module\PRA.Directory.psm1') -Force -Global
        $context=New-GateContext $runtime
        $context.BackupFolder=$runtime.State.BackupFolder
        $bundles=New-GateSourceBundles $context
        Remove-Item -LiteralPath $runtime.EventPath -Force -ErrorAction SilentlyContinue
    }
    It 'accepts Recover -Phase Cloud -Mode Apply typed as <Action>/<Phase>/<Mode>: the proof is compared with its official spelling' -ForEach @(
        @{Action='recover';Phase='cloud';Mode='apply'},@{Action='RECOVER';Phase='CLOUD';Mode='APPLY'},@{Action='rEcOvEr';Phase='cLoUd';Mode='aPpLy'}
    ) {
        $run=Invoke-GateProcess $runtime @{Action=$Action;Mode=$Mode;Phase=$Phase;Force=$true;ConfigPath=$runtime.ConfigPath;Batch=$bundles.Recover}
        $messages=($run.MainResult.Issues.Message -join ' ')
        # The proof was accepted (the synthetic cloud then confirms nothing); a case mismatch would stop at the proof.
        $messages | Should -Match 'Cloud deprovisioning or AD proof not confirmed'
        $messages | Should -Not -Match 'does not match'
        $run.MainResult.Action | Should -BeExactly 'Recover'
        $run.MainResult.Phase | Should -BeExactly 'Cloud'
        $run.MainResult.Mode | Should -BeExactly 'Apply'
        @($run.Events | Where-Object Operation -eq 'CloudPhase-SyntheticBarrier').Count | Should -Be 1
        @(Get-GateWrites $runtime).Count | Should -Be 0
    }
    It 'accepts Convert -Phase Cloud -Mode Apply typed as <Action>/<Phase>/<Mode> with an AD-verified Convert batch' -ForEach @(
        @{Action='convert';Phase='cloud';Mode='apply'},@{Action='CONVERT';Phase='CLOUD';Mode='APPLY'}
    ) {
        $fresh=New-GateContext $runtime
        $plans=@(New-PraPlan $fresh 'user1' 'Convert'; New-PraPlan $fresh 'user2' 'Convert')
        $source=Invoke-PraAdBatch $fresh $plans 'Convert'
        [IO.File]::WriteAllText($runtime.StatePath,[Management.Automation.PSSerializer]::Serialize($global:PraGateAd,35))
        Remove-Item -LiteralPath $runtime.EventPath -Force -ErrorAction SilentlyContinue
        $run=Invoke-GateProcess $runtime @{Action=$Action;Mode=$Mode;Phase=$Phase;Force=$true;ConfigPath=$runtime.ConfigPath;Batch=$source.Path}
        (@($run.MainResult.Issues | ForEach-Object { [string]$_.Message }) -join ' ') | Should -Not -Match 'does not match|AD proof'
        $run.ExitCode | Should -BeIn @(0,2)
        $run.MainResult.Action | Should -BeExactly 'Convert'
        $run.MainResult.Phase | Should -BeExactly 'Cloud'
        $run.MainResult.Mode | Should -BeExactly 'Apply'
        @($run.Events | Where-Object Operation -eq 'CloudPhase-SyntheticBarrier').Count | Should -Be 1
    }
    It 'canonicalizes every ValidateSet parameter of the entry (Action, Mode, Phase, Scope, Expect) and reports the tool version' {
        $run=Invoke-GateProcess $runtime @{Action='cHECK';Mode='pREVIEW';Identity='user1@gate.invalid';Scope='uSERSonly';Expect='rETAINED';ConfigPath=$runtime.ConfigPath}
        $run.ExitCode | Should -Be 0
        $run.MainResult.Action | Should -BeExactly 'Check'
        $run.MainResult.Mode | Should -BeExactly 'Preview'
        $run.MainResult.Version | Should -BeExactly (Get-PraToolVersion)
        $run.MainResult.Version | Should -Match '^\d+\.\d+\.\d+$'
    }
    It 'ships the canonicalization loop at the entry, before the GUI branch and the engine imports' {
        $text=[IO.File]::ReadAllText((Join-Path $global:PraGate.Source 'Invoke-PraRemoteMailbox.ps1'))
        $loop=$text.IndexOf('ValidateSetAttribute')
        $loop | Should -BeGreaterThan 0
        $loop | Should -BeLessThan $text.IndexOf('if ($Gui) {')
        $loop | Should -BeLessThan $text.IndexOf("Import-Module (Join-Path `$PSScriptRoot 'PraRemoteMailbox.psd1')")
        # The strict downstream comparison of the proof is still case-sensitive.
        [IO.File]::ReadAllText((Join-Path $global:PraGate.Source 'module\PRA.Directory.psm1')) | Should -Match 'Test-PraOrdinalEqual \$data\.Operation \$Operation'
    }
    It 'runs the readonly cloud pre-check on the planned rows BEFORE the first AD write of Recover -Phase Both' {
        $module=Get-Module PRA.Directory
        foreach ($plan in $bundles.Plans) {
            $user=@($runtime.State.Users | Where-Object ObjectGUID -eq $plan.Record.ObjectGuid)[0]
            foreach ($key in $plan.Kinds.Keys) { $user.$key=& $module { param($state) ConvertFrom-PraStoredValue $state } $plan.Desired[$key] }
            $user.uSNChanged=[long]101
        }
        $runtime.State.Group.member=@($runtime.State.Users | ForEach-Object DistinguishedName)
        [IO.File]::WriteAllText($runtime.StatePath,[Management.Automation.PSSerializer]::Serialize($runtime.State,35))
        $run=Invoke-GateProcess $runtime @{Action='Recover';Mode='Apply';Phase='Both';Force=$true;ConfigPath=$runtime.ConfigPath;Batch=$bundles.Source}
        $operations=@($run.Events.Operation)
        @($run.Events | Where-Object Operation -eq 'CloudPreflight-SyntheticBarrier').Count | Should -Be 1
        @(Get-GateWrites $runtime).Count | Should -BeGreaterThan 0
        [array]::IndexOf($operations,'CloudPreflight-SyntheticBarrier') | Should -BeLessThan ([array]::IndexOf($operations,'Set-ADUser'))
        $preflight=@($run.Events | Where-Object Operation -eq 'CloudPreflight-SyntheticBarrier')[0]
        $preflight.Rows.Count | Should -Be 2
        @($preflight.Rows | Where-Object ADVerified).Count | Should -Be 0
        $run.Output | Should -Match 'Exchange Online pre-check'
    }
    It 'stops Recover -Phase Both with zero AD writes and no backup when the cloud pre-check is refused' {
        $module=Get-Module PRA.Directory
        foreach ($plan in $bundles.Plans) {
            $user=@($runtime.State.Users | Where-Object ObjectGUID -eq $plan.Record.ObjectGuid)[0]
            foreach ($key in $plan.Kinds.Keys) { $user.$key=& $module { param($state) ConvertFrom-PraStoredValue $state } $plan.Desired[$key] }
            $user.uSNChanged=[long]101
        }
        $runtime.State.Group.member=@($runtime.State.Users | ForEach-Object DistinguishedName)
        $runtime.State.Case='CloudPreflightFailure'
        [IO.File]::WriteAllText($runtime.StatePath,[Management.Automation.PSSerializer]::Serialize($runtime.State,35))
        $before=@(Get-ChildItem -LiteralPath $runtime.State.BackupFolder -Recurse -File).Count
        $run=Invoke-GateProcess $runtime @{Action='Recover';Mode='Apply';Phase='Both';Force=$true;ConfigPath=$runtime.ConfigPath;Batch=$bundles.Source}
        $run.ExitCode | Should -Be 1
        ($run.MainResult.Issues.Message -join ' ') | Should -Match 'cloud preflight refused before AD'
        @(Get-GateWrites $runtime).Count | Should -Be 0
        @($run.MainResult.BackupFiles).Count | Should -Be 0
        @(Get-ChildItem -LiteralPath $runtime.State.BackupFolder -Recurse -File).Count | Should -Be $before
        @($run.Events | Where-Object Operation -eq 'CloudPreflight-SyntheticBarrier').Count | Should -Be 1
        @($run.Events | Where-Object Operation -eq 'CloudClose-SyntheticBarrier').Count | Should -Be 1
        @($run.Events | Where-Object Operation -eq 'CloudPhase-SyntheticBarrier').Count | Should -Be 0
    }
    It 'does not run any cloud pre-check for a Recover -Phase Both Preview' {
        $run=Invoke-GateProcess $runtime @{Action='Recover';Mode='Preview';Phase='Both';ConfigPath=$runtime.ConfigPath;Batch=$bundles.Source}
        @($run.Events | Where-Object Operation -eq 'CloudPreflight-SyntheticBarrier').Count | Should -Be 0
        @(Get-GateWrites $runtime).Count | Should -Be 0
    }
    It 'creates the cloud journal folder only after the confirmation (an unconfirmed cloud Apply leaves no folder)' {
        $fresh=New-GateContext $runtime
        $plans=@(New-PraPlan $fresh 'user1' 'Convert'; New-PraPlan $fresh 'user2' 'Convert')
        $source=Invoke-PraAdBatch $fresh $plans 'Convert'
        [IO.File]::WriteAllText($runtime.StatePath,[Management.Automation.PSSerializer]::Serialize($global:PraGateAd,35))
        $refused=Invoke-GateProcess $runtime @{Action='Convert';Mode='Apply';Phase='Cloud';ConfigPath=$runtime.ConfigPath;Batch=$source.Path}
        $refused.ExitCode | Should -Be 1
        ($refused.MainResult.Issues.Message -join ' ') | Should -Match 'Apply needs a confirmation'
        @(Get-ChildItem -LiteralPath $runtime.State.BackupFolder -Directory -Filter '*-cloud').Count | Should -Be 0
        $confirmed=Invoke-GateProcess $runtime @{Action='Convert';Mode='Apply';Phase='Cloud';Force=$true;ConfigPath=$runtime.ConfigPath;Batch=$source.Path}
        $confirmed.ExitCode | Should -BeIn @(0,2)
        $journals=@(Get-ChildItem -LiteralPath $runtime.State.BackupFolder -Directory -Filter '*-cloud')
        $journals.Count | Should -Be 1
        Test-Path -LiteralPath (Join-Path $journals[0].FullName 'CloudOperations.jsonl') | Should -BeTrue
    }
    It 'quotes every free-text value of the next-step command as data (apostrophes and typographic quotes in -ConfigPath)' {
        $quotes=-join (@(0x2018,0x2019,0x201A,0x201B) | ForEach-Object { [char]$_ })
        $literalConfig=Join-Path $runtime.Root ("operator's "+$quotes+'.psd1')
        Copy-Item -LiteralPath $runtime.ConfigPath -Destination $literalConfig
        $run=Invoke-GateProcess $runtime @{Action='Convert';Mode='Preview';Phase='AD';ConfigPath=$literalConfig} -ExplicitArguments
        $run.ExitCode | Should -Be 0
        $next=@($run.MainResult.NextSteps | Where-Object { $_ -match '-ConfigPath' })
        $next.Count | Should -Be 1
        $escaped=("operator's "+$quotes+'.psd1').Replace("'","''")
        foreach ($code in @(0x2018,0x2019,0x201A,0x201B)) { $quote=[string][char]$code; $escaped=$escaped.Replace($quote,$quote+$quote) }
        $next[0] | Should -BeLike ("*-ConfigPath '*"+$escaped+"'")
        # The suggested command parses back to exactly the original path.
        $tokens=$null;$errors=$null
        $ast=[Management.Automation.Language.Parser]::ParseInput($next[0],[ref]$tokens,[ref]$errors)
        $errors.Count | Should -Be 0
        $literal=$ast.Find({ param($n) $n -is [Management.Automation.Language.StringConstantExpressionAst] -and $n.Value -like '*.psd1' },$true)
        $literal.Value | Should -BeExactly $literalConfig
    }
}

Describe 'Release 2.3.0 - Confirm-PraApply, command line quoting and the single version source (entry functions)' -Tag 'Release230' {
    BeforeAll {
        function global:Get-EntryFunctionText([string]$Name) {
            $ast=[Management.Automation.Language.Parser]::ParseFile((Join-Path $global:PraGate.Source 'Invoke-PraRemoteMailbox.ps1'),[ref]$null,[ref]$null)
            $node=$ast.Find({ param($n) $n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq $Name },$true)
            if (-not $node) { throw "Entry function not found: $Name" }
            $node.Extent.Text
        }
    }
    AfterAll { Remove-Item -LiteralPath 'Function:\Get-EntryFunctionText' -ErrorAction SilentlyContinue }
    It 'asks once and, on yes, lets the run continue with no further prompt' {
        try {
            $caller=New-Object psobject
            $answer=$true
            $asked=New-Object 'Collections.Generic.List[string]'
            $caller | Add-Member ScriptMethod ShouldContinue ({ param($Query,$Caption) [void]$asked.Add([string]$Query); $answer }.GetNewClosure())
            $Force=$false; $script:ConfirmBound=$false
            $context=@{ AllowMutation=$true; CurrentOperation=''; CurrentIdentity=''; ConfirmPreference='High'; LogFile=''; Warnings=0; Issues=(New-Object 'Collections.Generic.List[object]') }
            . ([scriptblock]::Create((Get-EntryFunctionText 'Confirm-PraApply')))
            Confirm-PraApply 'Convert the 2 object(s)?'
            $asked.Count | Should -Be 1
            $asked[0] | Should -Be 'Convert the 2 object(s)?'
            $context.AllowMutation | Should -BeTrue
            $context.ConfirmPreference | Should -BeExactly 'None'
        } finally { Remove-Variable -Name ConfirmPreference -Scope Script -ErrorAction SilentlyContinue }
    }
    It 'cancels without any write when the operator answers no' {
        try {
            $caller=New-Object psobject
            $answer=$false
            $asked=New-Object 'Collections.Generic.List[string]'
            $caller | Add-Member ScriptMethod ShouldContinue ({ param($Query,$Caption) [void]$asked.Add([string]$Query); $answer }.GetNewClosure())
            $Force=$false; $script:ConfirmBound=$false
            $context=@{ AllowMutation=$true; CurrentOperation=''; CurrentIdentity=''; ConfirmPreference='High'; LogFile=''; Warnings=0; Issues=(New-Object 'Collections.Generic.List[object]') }
            . ([scriptblock]::Create((Get-EntryFunctionText 'Confirm-PraApply')))
            { Confirm-PraApply 'Roll back?' } | Should -Throw '*Cancelled by the operator*'
            $asked.Count | Should -Be 1
            $context.AllowMutation | Should -BeFalse
            $context.ConfirmPreference | Should -BeExactly 'High'
        } finally { Remove-Variable -Name ConfirmPreference -Scope Script -ErrorAction SilentlyContinue }
    }
    It 'a cancel and a console that cannot ask both mark the run as one that changed nothing' -Tag 'Release313j' {
        try {
            $caller=New-Object psobject
            $caller | Add-Member ScriptMethod ShouldContinue ({ param($Query,$Caption) $false }.GetNewClosure())
            $Force=$false; $script:ConfirmBound=$false
            $context=@{ AllowMutation=$true; CurrentOperation=''; CurrentIdentity=''; ConfirmPreference='High'; LogFile=''; Warnings=0; Issues=(New-Object 'Collections.Generic.List[object]') }
            . ([scriptblock]::Create((Get-EntryFunctionText 'Confirm-PraApply')))
            { Confirm-PraApply 'Roll back?' } | Should -Throw '*Cancelled by the operator*'
            $context.NoChangeMade | Should -BeTrue
            $unavailable=New-Object psobject
            $unavailable | Add-Member ScriptMethod ShouldContinue ({ param($Query,$Caption) throw 'no console' }.GetNewClosure())
            $caller=$unavailable
            $context=@{ AllowMutation=$true; CurrentOperation=''; CurrentIdentity=''; ConfirmPreference='High'; LogFile=''; Warnings=0; Issues=(New-Object 'Collections.Generic.List[object]') }
            { Confirm-PraApply 'Roll back?' } | Should -Throw '*cannot ask for one*'
            $context.NoChangeMade | Should -BeTrue
            $context.ConfirmationUnavailable | Should -BeTrue
        } finally { Remove-Variable -Name ConfirmPreference -Scope Script -ErrorAction SilentlyContinue }
    }
    It 'never asks with <Name> (documented behaviour, including -Confirm:$false)' -ForEach @(@{Name='-Force';ForceOn=$true;Bound=$false},@{Name='an explicit -Confirm';ForceOn=$false;Bound=$true}) {
        try {
            $caller=New-Object psobject
            $asked=New-Object 'Collections.Generic.List[string]'
            $caller | Add-Member ScriptMethod ShouldContinue ({ param($Query,$Caption) [void]$asked.Add([string]$Query); $true }.GetNewClosure())
            $Force=$ForceOn; $script:ConfirmBound=$Bound
            $context=@{ AllowMutation=$true; CurrentOperation=''; CurrentIdentity=''; ConfirmPreference='High'; LogFile=''; Warnings=0; Issues=(New-Object 'Collections.Generic.List[object]') }
            . ([scriptblock]::Create((Get-EntryFunctionText 'Confirm-PraApply')))
            Confirm-PraApply 'Question'
            $asked.Count | Should -Be 0
            $context.AllowMutation | Should -BeTrue
        } finally { Remove-Variable -Name ConfirmPreference -Scope Script -ErrorAction SilentlyContinue }
    }
    It 'documents the -Confirm:$false behaviour in the help of the entry script' {
        $help=Get-Help (Join-Path $global:PraGate.Source 'Invoke-PraRemoteMailbox.ps1') -Parameter Force
        ($help | Out-String) | Should -Match 'Confirm:\$false'
        $scope=Get-Help (Join-Path $global:PraGate.Source 'Invoke-PraRemoteMailbox.ps1') -Parameter Scope
        ($scope | Out-String) | Should -Match 'Identity ignores -Scope'
    }
    It 'quotes apostrophes, typographic quotes and spaces in every free-text option of the suggested command line' {
        $quotes=-join (@(0x2018,0x2019,0x201A,0x201B) | ForEach-Object { [char]$_ })
        . ([scriptblock]::Create((Get-EntryFunctionText 'ConvertTo-PraLiteral')))
        . ([scriptblock]::Create((Get-EntryFunctionText 'Get-PraCommandLine')))
        $Identity="o'brien@gate.invalid"; $Scope='SharedOnly'; $MaxObjects=5; $BaseConfigPath=''
        $SearchBase="OU=O'Neil,DC=gate,DC=invalid"; $CsvPath="C:\lists\o'x $quotes.csv"; $ConfigPath="C:\cfg\it's.psd1"; $script:ConfigPathBound=$true
        $line=Get-PraCommandLine -ActionName Convert -PhaseName AD -KeepFilters
        $line | Should -BeLike "*-Identity 'o''brien@gate.invalid'*"
        $line | Should -BeLike "*-SearchBase 'OU=O''Neil,DC=gate,DC=invalid'*"
        $line | Should -BeLike "*-ConfigPath 'C:\cfg\it''s.psd1'"
        $line | Should -Match ([regex]::Escape("o''x "+$quotes.Substring(0,1)+$quotes.Substring(0,1)))
        $batch=Get-PraCommandLine -ActionName Recover -PhaseName Cloud -BatchId "C:\x y\it's\batch.json"
        $batch | Should -BeLike "*-Batch 'C:\x y\it''s\batch.json'*"
        $plain=Get-PraCommandLine -ActionName Recover -BatchId '0a1b2c3d' -OtherServer
        $plain | Should -BeLike '*-Batch 0a1b2c3d'
        $plain | Should -Not -Match "-Batch '"
        # Every suggested line is a valid PowerShell statement.
        $errors=$null
        [void][Management.Automation.Language.Parser]::ParseInput($line,[ref]$null,[ref]$errors)
        $errors.Count | Should -Be 0
    }
    It 'has ONE version source: ToolVersion of the common module, used by the entry, the builder and every header comment' {
        $version=Get-PraToolVersion
        $version | Should -Match '^\d+\.\d+\.\d+$'
        # External anchors: the version is not only compared with the files that quote it. It must be the release that this tree is
        # (update this literal with the release) and the newest heading of the change log.
        $version | Should -BeExactly '3.1.3'
        $heading=[regex]::Match([IO.File]::ReadAllText((Join-Path $global:PraGate.Release 'CHANGELOG.md')),'(?m)^## (\d+\.\d+\.\d+)\b')
        $heading.Success | Should -BeTrue
        $heading.Groups[1].Value | Should -BeExactly $version -Because 'the first "## x.y.z" heading of CHANGELOG.md is the version of the tree'
        $entry=[IO.File]::ReadAllText((Join-Path $global:PraGate.Source 'Invoke-PraRemoteMailbox.ps1'))
        $entry | Should -Not -Match "Version\s*=\s*'\d+\.\d+\.\d+'"
        $entry | Should -Not -Match "-Version\s+'\d"
        $entry | Should -Match 'Version = \(Get-PraToolVersion\)'
        $entry | Should -Match '-Version \(Get-PraToolVersion\)'
        [IO.File]::ReadAllText((Join-Path $global:PraGate.Release 'tools\New-PraPackage.ps1')) | Should -Match 'ToolVersion'
        $literals=@(
            'package\Invoke-PraRemoteMailbox.ps1','package\PraRemoteMailbox.psm1','package\module\PRA.Common.psm1','package\module\PRA.Directory.psm1','package\module\PRA.Backup.psm1','package\module\PRA.Cloud.psm1'
            'package\module\PRA.Gui.psm1','package\module\PRA.Gui.Directory.ps1','package\config\PraRemoteMailbox.config.psd1','package\templates\Report.template.html'
            'tools\New-PraPackage.ps1','tools\Build-Documentation.ps1','tests\Invoke-TestGate.ps1','tests\IntegrityFixture.ps1'
            'tests\PackageIntegrity.Tests.ps1','tests\PraRemoteMailbox.Tests.ps1','tests\PraReport.Tests.ps1','tests\PraDocumentation.Tests.ps1','tools\New-DocumentationImages.ps1'
        )
        foreach ($relative in $literals) {
            $text=[IO.File]::ReadAllText((Join-Path $global:PraGate.Release $relative))
            $found=[regex]::Match($text,'(?m)^\s*#?\s*Version\s*:\s*(\d+\.\d+\.\d+)')
            $found.Success | Should -BeTrue -Because $relative
            $found.Groups[1].Value | Should -BeExactly $version -Because $relative
        }
        [IO.File]::ReadAllText((Join-Path $global:PraGate.Release 'CHANGELOG.md')) | Should -Match ('(?m)^## '+[regex]::Escape($version)+' ')
        [IO.File]::ReadAllText((Join-Path $global:PraGate.Release 'README.md')) | Should -Match ('\*\*Version:\*\* '+[regex]::Escape($version)+',')
        [IO.File]::ReadAllText((Join-Path $global:PraGate.Source 'PackageIntegrity.psd1')) | Should -Match ('# PRA Remote Mailbox '+[regex]::Escape($version)+' - authenticated package integrity manifest')
        [IO.File]::ReadAllText((Join-Path $global:PraGate.Source 'module\PRA.Common.psm1')) | Should -Match ('v'+[regex]::Escape($version)+' . Nicolas Fabert')
        ([IO.File]::ReadAllText((Join-Path $global:PraGate.Source 'docs\PraRemoteMailbox-Guide.md')) -split "`n" | Select-Object -First 8) -join "`n" | Should -Match ('(?m)^version:\s*'+[regex]::Escape($version))
    }
}

Describe 'Release 2.3.0 - configuration coherence and validation' -Tag 'Release230' {
    AfterAll { Remove-Item -LiteralPath 'Function:\Get-ConfigLeaves' -ErrorAction SilentlyContinue }
    BeforeAll {
        function global:Get-ConfigLeaves($Table,[string]$Prefix='') {
            foreach ($key in $Table.Keys) {
                if ($Table[$key] -is [hashtable]) { Get-ConfigLeaves $Table[$key] ($Prefix+$key+'.') }
                else { [pscustomobject]@{ Path=$Prefix+$key; Value=(@($Table[$key]) -join '|') } }
            }
        }
    }
    It 'keeps the code defaults equal to the shipped configuration file (only the explicitly documented differences)' {
        $shipped=Import-PowerShellDataFile -LiteralPath (Join-Path $global:PraGate.Source 'config\PraRemoteMailbox.config.psd1')
        $defaults=InModuleScope PRA.Common { Get-PraDefaultConfiguration }
        $shippedLeaves=@{}; foreach ($leaf in Get-ConfigLeaves $shipped) { $shippedLeaves[$leaf.Path]=$leaf.Value }
        $differences=foreach ($leaf in Get-ConfigLeaves $defaults) {
            if (-not $shippedLeaves.ContainsKey($leaf.Path)) { $leaf.Path+' missing from the shipped file'; continue }
            if ($shippedLeaves[$leaf.Path] -cne $leaf.Value) { '{0}: code={1} shipped={2}' -f $leaf.Path,$leaf.Value,$shippedLeaves[$leaf.Path] }
        }
        # The builder empties environment values and the shipped list names the Administrator account as an example.
        @($differences | Where-Object { $_ -notmatch '^SharedMailbox\.ExcludeTrusteeSamAccountNames:' }) | Should -BeNullOrEmpty
        $defaults.Exo.DisableWAM | Should -BeFalse
        $shipped.Exo.DisableWAM | Should -BeFalse
        $defaults.Cloud.MailboxCheckVia | Should -BeExactly 'Exo'
        $defaults.Polling.IntervalMinutes | Should -Be $shipped.Polling.IntervalMinutes
        $defaults.Retention.PolicyName | Should -BeExactly $shipped.Retention.PolicyName
    }
    It 'requires Cloud.Organization and a GUID Cloud.TenantId as soon as Cloud.AppId is set' {
        $runtime=New-GateRuntime -Name 'cloud-appid'
        $withCloud={ param($cloud) Set-GateConfigText $runtime ({ param($t) $t.Replace("Execution=@{Phase='Both'}","Execution=@{Phase='Both'}`r`n Cloud=@{$cloud}") }.GetNewClosure()) }
        $guid='11111111-2222-3333-4444-555555555555'
        & $withCloud "AppId='app';CertificateThumbprint='ABCDEF'"
        { Import-PraConfiguration -Path $runtime.ConfigPath -Root $runtime.Package } | Should -Throw '*Cloud.Organization*'
        $runtime=New-GateRuntime -Name 'cloud-appid-tenant'
        $withCloud={ param($cloud) Set-GateConfigText $runtime ({ param($t) $t.Replace("Execution=@{Phase='Both'}","Execution=@{Phase='Both'}`r`n Cloud=@{$cloud}") }.GetNewClosure()) }
        foreach ($tenant in @('',"TenantId='not-a-guid';","TenantId='00000000-0000-0000-0000-000000000000';")) {
            Set-GateConfigText $runtime { param($t) [regex]::Replace($t,'(?s) Cloud=@\{.*?\}\r?\n','') }
            & $withCloud ($tenant+"Organization='contoso.onmicrosoft.com';AppId='app';CertificateThumbprint='ABCDEF'")
            { Import-PraConfiguration -Path $runtime.ConfigPath -Root $runtime.Package } | Should -Throw '*Cloud.TenantId*'
        }
        Set-GateConfigText $runtime { param($t) [regex]::Replace($t,'(?s) Cloud=@\{.*?\}\r?\n','') }
        & $withCloud ("TenantId='$guid';Organization='contoso.onmicrosoft.com';AppId='app';CertificateThumbprint='ABCDEF'")
        $config=Import-PraConfiguration -Path $runtime.ConfigPath -Root $runtime.Package
        $config.Cloud.TenantId | Should -BeExactly $guid
        # Interactive sign-in (no AppId) still needs none of them at load time.
        Set-GateConfigText $runtime { param($t) [regex]::Replace($t,'(?s) Cloud=@\{.*?\}\r?\n','') }
        (Import-PraConfiguration -Path $runtime.ConfigPath -Root $runtime.Package).Cloud.AppId | Should -BeExactly ''
    }
    It 'refuses unknown keys and wrong types at load: <Name>' -ForEach @(
        @{Name='unknown top-level key';Add="Typo=1";Message='*unknown setting Typo*'}
        @{Name='unknown nested key';Add="Cloud=@{TenantIdentifier='x'}";Message='*unknown setting Cloud.TenantIdentifier*'}
        @{Name='text where a number is expected';Add="Polling=@{IntervalMinutes='5'}";Message='*Polling.IntervalMinutes must be a whole number*'}
        @{Name='text where a boolean is expected';Add="Retention=@{Enabled='yes'}";Message='*Retention.Enabled must be*true*false*'}
        @{Name='number where text is expected';Add="Environment=7";Message='*Environment must be text*'}
        @{Name='text where a list is expected';Add="Scope=@{ExcludeSamAccountNames='a'}";Message='*Scope.ExcludeSamAccountNames must be a list*'}
        @{Name='text where a section is expected';Add="Exo='x'";Message='*Exo must be a section*'}
    ) {
        $runtime=New-GateRuntime -Name 'config-types'
        if ($Add -like 'Environment=*') { Set-GateConfigText $runtime { param($t) $t.Replace("Environment='SYNTHETIC_GATE'",'Environment=7') } }
        elseif ($Add -like 'Scope=*') { Set-GateConfigText $runtime { param($t) $t.Replace('ExcludeSamAccountNames=@()',"ExcludeSamAccountNames='a'") } }
        elseif ($Add -like 'Retention=*') { Set-GateConfigText $runtime { param($t) $t.Replace('Retention=@{Enabled=$true;',"Retention=@{Enabled='yes';") } }
        else { $line=$Add; Set-GateConfigText $runtime ({ param($t) $t.Replace("Execution=@{Phase='Both'}","Execution=@{Phase='Both'}`r`n $line") }.GetNewClosure()) }
        { Import-PraConfiguration -Path $runtime.ConfigPath -Root $runtime.Package } | Should -Throw $Message
    }
}

Describe 'Release 2.3.0 - report CSV, shared permission CSV and private output folders' -Tag 'Release230' {
    It 'neutralizes spreadsheet formulas in the server CSV exactly as the HTML export does' {
        $runtime=New-GateRuntime -Name 'csv-formulas'
        InModuleScope PRA.Common -Parameters @{ Runtime=$runtime } {
            foreach ($case in @(@('=1+1',"'=1+1"),@('+SUM(A1)',"'+SUM(A1)"),@('-2+3',"'-2+3"),@('@cmd',"'@cmd"),("`tx","'`tx"),("`rx","'`rx"),@('plain','plain'),@('a=b','a=b'),@('','') )) {
                ConvertTo-PraCsvCell $case[0] | Should -BeExactly $case[1]
            }
            ConvertTo-PraCsvCell $null | Should -BeNullOrEmpty
            $context=New-GateContext $Runtime -Mode Preview
            $row=New-PraRow $context ([pscustomobject]@{SamAccountName='=HYPERLINK("http://x")';UserPrincipalName='user@gate.invalid';IsShared=$false})
            $row.FinalStatus='Planned'; $row.Detail='+cmd|calc'; $context.Rows.Add($row)
            $path=Join-Path ([IO.Path]::GetTempPath()) ('pra-csv-'+[guid]::NewGuid().ToString('N')+'.csv')
            try {
                Write-PraReport $context @{ Csv=$path; Html='' }
                $rows=@(Import-Csv -LiteralPath $path -Delimiter ';' -Encoding UTF8)
                $rows.Count | Should -Be 1
                $rows[0].SamAccountName | Should -BeExactly "'=HYPERLINK(""http://x"")"
                $rows[0].Detail | Should -BeExactly "'+cmd|calc"
                $rows[0].UserPrincipalName | Should -BeExactly 'user@gate.invalid'
                $rows[0].IsShared | Should -BeExactly 'False'
            } finally { Remove-Item -LiteralPath $path -Force -ErrorAction SilentlyContinue }
        }
    }
    It 'reads the shared permission CSV with a comma or a semicolon, and never matches an empty name' -ForEach @(@{Delimiter=','},@{Delimiter=';'}) {
        $runtime=New-GateRuntime -Name 'perm-csv'
        $path=Join-Path ([IO.Path]::GetTempPath()) ('pra-perm-'+[guid]::NewGuid().ToString('N')+'.csv')
        [IO.File]::WriteAllText($path,("Shared{0}Group`r`n{0}EmptyNameGroup`r`nshared1{0}Group1`r`nsomeone-else{0}Group2" -f $Delimiter),(New-Object Text.UTF8Encoding($true)))
        try {
            InModuleScope PRA.Directory -Parameters @{ Path=$path; Runtime=$runtime } {
                Mock Get-PraGroup { [pscustomobject]@{ DistinguishedName="CN=$Identity,DC=gate,DC=invalid"; Name=$Identity } }
                Mock Expand-PraTrustee { @('member@gate.invalid') }
                $context=New-GateContext $Runtime
                $context.Config.SharedMailbox=@{ Enabled=$true; PermissionSource='Csv'; CsvPath=$Path; CaptureSendOnBehalf=$false; CustomAttribute='extensionAttribute1' }
                # No mailNickname and no DisplayName: the empty names must not match the empty Shared cell of the first line.
                $user=[pscustomobject]@{ ObjectGUID=[guid]'00000000-0000-0000-0000-000000000009'; DistinguishedName='CN=shared1,OU=Tests,DC=gate,DC=invalid'; SamAccountName='shared1'; mailNickname=''; DisplayName=''; Name='' }
                $result=Get-PraSharedPermission -Context $context -User $user
                $result.FullAccess | Should -Contain 'member@gate.invalid'
                $result.SendAs | Should -Contain 'member@gate.invalid'
                Should -Invoke Get-PraGroup -Times 1 -Exactly -ParameterFilter { $Identity -eq 'Group1' }
                Should -Invoke Get-PraGroup -Times 0 -ParameterFilter { $Identity -eq 'EmptyNameGroup' }
                $none=[pscustomobject]@{ ObjectGUID=[guid]'00000000-0000-0000-0000-000000000008'; DistinguishedName='CN=x,OU=Tests,DC=gate,DC=invalid'; SamAccountName='unlisted'; mailNickname=''; DisplayName=''; Name='' }
                { Get-PraSharedPermission -Context $context -User $none } | Should -Throw '*no line*'
            }
        } finally { Remove-Item -LiteralPath $path -Force -ErrorAction SilentlyContinue }
    }
    It 'creates the missing logs and reports folders with the protected private ACL of the backups, and leaves existing folders alone' {
        $base=Join-Path ([IO.Path]::GetTempPath()) ('pra-acl-'+[guid]::NewGuid().ToString('N'))
        try {
            $logs=Join-Path $base 'logs'; $reports=Join-Path $base 'reports'
            InModuleScope PRA.Common -Parameters @{ Logs=$logs; Reports=$reports } {
                Initialize-PraPrivateFolder -Path $Logs
                Initialize-PraPrivateFolder -Path $Reports
                foreach ($folder in @($Logs,$Reports)) {
                    $acl=[IO.FileSystemAclExtensions]::GetAccessControl([IO.DirectoryInfo]::new($folder))
                    $acl.AreAccessRulesProtected | Should -BeTrue
                    $sids=@($acl.GetAccessRules($true,$false,[Security.Principal.SecurityIdentifier]) | ForEach-Object { $_.IdentityReference.Value } | Sort-Object -Unique)
                    $expected=@([Security.Principal.WindowsIdentity]::GetCurrent().User.Value,'S-1-5-18','S-1-5-32-544') | Sort-Object -Unique
                    ($sids -join ',') | Should -BeExactly ($expected -join ',')
                }
            }
            # The backups use the very same ACL source.
            Import-Module (Join-Path $global:PraGate.Package 'module\PRA.Directory.psm1') -Force -Global
            $backup=Join-Path $base 'Backups'
            New-PraPrivateDirectory $backup -Confirm:$false
            $backupAcl=[IO.FileSystemAclExtensions]::GetAccessControl([IO.DirectoryInfo]::new($backup))
            $backupAcl.AreAccessRulesProtected | Should -BeTrue
            (@($backupAcl.GetAccessRules($true,$false,[Security.Principal.SecurityIdentifier]) | ForEach-Object { $_.IdentityReference.Value } | Sort-Object -Unique) -join ',') |
                Should -BeExactly ((@([Security.Principal.WindowsIdentity]::GetCurrent().User.Value,'S-1-5-18','S-1-5-32-544') | Sort-Object -Unique) -join ',')
            # An existing folder (for example prepared by the administrator) is not modified.
            $existing=Join-Path $base 'existing'; $null=New-Item -ItemType Directory -Path $existing
            $before=(Get-Acl -LiteralPath $existing).Sddl
            InModuleScope PRA.Common -Parameters @{ Path=$existing } { Initialize-PraPrivateFolder -Path $Path }
            (Get-Acl -LiteralPath $existing).Sddl | Should -BeExactly $before
        } finally { Remove-Item -LiteralPath $base -Recurse -Force -ErrorAction SilentlyContinue }
    }
    It 'creates the log and report folders of a real run through the private ACL helper' {
        $runtime=New-GateRuntime -Name 'private-run-folders'
        Remove-Item -LiteralPath (Join-Path $runtime.Root 'logs'),(Join-Path $runtime.Root 'reports') -Recurse -Force
        $run=Invoke-GateProcess $runtime @{Action='Convert';Mode='Preview';Phase='Both';ConfigPath=$runtime.ConfigPath}
        $run.ExitCode | Should -Be 0
        foreach ($name in 'logs','reports') {
            $folder=Join-Path $runtime.Root $name
            (Test-Path -LiteralPath $folder) | Should -BeTrue
            ([IO.FileSystemAclExtensions]::GetAccessControl([IO.DirectoryInfo]::new($folder))).AreAccessRulesProtected | Should -BeTrue -Because $name
            @(Get-ChildItem -LiteralPath $folder -File).Count | Should -BeGreaterThan 0
        }
    }
}

Describe 'Release 2.3.0 - MissingFullAccess and the Exchange Online child protocol (production Cloud module source)' -Tag 'Release230' {
    It 'matches the MissingFullAccess answer on the exact message prefix and the trustee case-insensitively' {
        $ast=[Management.Automation.Language.Parser]::ParseFile((Join-Path $global:PraGate.Source 'module\PRA.Cloud.psm1'),[ref]$null,[ref]$null)
        $node=$ast.Find({ param($n) $n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq 'MissingFullAccess' },$true)
        $node | Should -Not -BeNullOrEmpty
        . ([scriptblock]::Create($node.Extent.Text))
        # The function uses the ordinal helpers defined next to it in the worker text.
        foreach ($helper in 'SameOrdinal','SameIgnoreCase') {
            $helperNode = $ast.Find({ param($n) $n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq $helper },$true)
            $helperNode | Should -Not -BeNullOrEmpty
            . ([scriptblock]::Create($helperNode.Extent.Text))
        }
        function New-AnswerRecord([string]$Message,[string]$Code='NotFound') {
            $json=@{ error=@{ code=$Code; message=$Message; innererror=@{ message=$Message; type='Microsoft.Exchange.Admin.OData.Core.ODataServiceException' } } } | ConvertTo-Json -Depth 5 -Compress
            New-Object Management.Automation.ErrorRecord ((New-Object Exception ('HttpStatusCode=404 '+$json)),'x',[Management.Automation.ErrorCategory]::NotSpecified,$null)
        }
        MissingFullAccess (New-AnswerRecord 'No permissions were found for the user:Trustee@Gate.Invalid') 'trustee@gate.invalid' | Should -BeTrue
        MissingFullAccess (New-AnswerRecord 'No permissions were found for the user:trustee@gate.invalid') 'trustee@gate.invalid' | Should -BeTrue
        MissingFullAccess (New-AnswerRecord 'no permissions were found for the user:trustee@gate.invalid') 'trustee@gate.invalid' | Should -BeFalse
        MissingFullAccess (New-AnswerRecord 'No permissions were found for the user:other@gate.invalid') 'trustee@gate.invalid' | Should -BeFalse
        MissingFullAccess (New-AnswerRecord 'No permissions were found for the user:trustee@gate.invalid' 'Other') 'trustee@gate.invalid' | Should -BeFalse
    }
    It 'silences module warnings and information in the Exchange Online child while errors stay fatal' {
        $child=[IO.File]::ReadAllText((Join-Path $global:PraGate.Source 'module\PRA.Cloud.psm1'))
        $child | Should -Match "\`$WarningPreference='SilentlyContinue'; \`$InformationPreference='SilentlyContinue'"
        $child | Should -Match 'Connect-ExchangeOnline @connect -WarningAction SilentlyContinue -InformationAction SilentlyContinue 6>\$null 3>\$null'
        $child | Should -Not -Match "\`$ErrorActionPreference\s*=\s*'SilentlyContinue'"
    }
}

Describe 'Release 3.0.0 - the PowerShell 7.5+ engine' -Tag 'Release300' {
    BeforeAll {
        $script:Ps7Files = @(Get-ChildItem -LiteralPath $global:PraGate.Source -Recurse -File | Where-Object { $_.Extension -in '.ps1','.psm1' })
        $script:Ps7Runtime = @('Invoke-PraRemoteMailbox.ps1','PraRemoteMailbox.psm1','module\PRA.Common.psm1','module\PRA.Directory.psm1','module\PRA.Backup.psm1','module\PRA.Cloud.psm1','module\PRA.Gui.psm1','module\PRA.Gui.Directory.ps1','module\Test-PackageIntegrity.ps1')
    }
    It 'requires PowerShell 7.5 on the 9 runtime files, without an edition requirement and without a Windows PowerShell 5.1 branch' {
        $script:Ps7Files.Count | Should -Be 9
        foreach ($relative in $script:Ps7Runtime) {
            $text = [IO.File]::ReadAllText((Join-Path $global:PraGate.Source $relative))
            $text | Should -Match '(?m)^#Requires -Version 7\.5\r?$' -Because $relative
            $text | Should -Not -Match '(?m)^#Requires -PSEdition' -Because $relative
            $text | Should -Not -Match '(?m)^#Requires -Version 5' -Because $relative
            $text | Should -Not -Match "PSEdition\s+-ne\s+'Desktop'" -Because $relative
            $text | Should -Not -Match '(?i)powershell\.exe' -Because $relative
        }
    }
    It 'requires PowerShell 7.5 on the gate, the tests and the tools' {
        # The two files of the frozen Windows PowerShell 5.1 fixtures stay 5.1-compatible on purpose: the generator must run under powershell.exe to freeze real 5.1 files
        # (it also requires the Desktop edition), and the replay test runs on both engines.
        $fiveOne = @('PraLegacyFixtures.Tests.ps1','New-LegacyFixtures.ps1')
        foreach ($file in @(@(Get-ChildItem -LiteralPath (Join-Path $global:PraGate.Release 'tests') -File -Filter '*.ps1') + @(Get-ChildItem -LiteralPath (Join-Path $global:PraGate.Release 'tools') -File -Filter '*.ps1') | Where-Object { $_.Name -cnotin $fiveOne })) {
            [IO.File]::ReadAllText($file.FullName) | Should -Match '(?m)^#Requires -Version 7\.5\r?$' -Because $file.Name
        }
    }
    It 'reads JSON only through ConvertFrom-PraJson: no other ConvertFrom-Json in the package without -DateKind String' {
        foreach ($file in $script:Ps7Files) {
            $text = [IO.File]::ReadAllText($file.FullName)
            $skipFrom = -1; $skipTo = -1
            if ($file.Name -ceq 'PRA.Common.psm1') {
                $skipFrom = $text.IndexOf('function ConvertFrom-PraJson {', [StringComparison]::Ordinal)
                $skipTo = $text.IndexOf('function Get-PraToolVersion {', [StringComparison]::Ordinal)
                $skipFrom | Should -BeGreaterThan 0
                $skipTo | Should -BeGreaterThan $skipFrom
            }
            foreach ($match in [regex]::Matches($text, 'ConvertFrom-Json(?! -DateKind String)')) {
                $inside = $skipFrom -ge 0 -and $match.Index -ge $skipFrom -and $match.Index -lt $skipTo
                $inside | Should -BeTrue -Because ('bare ConvertFrom-Json at offset ' + $match.Index + ' of ' + $file.Name)
            }
        }
        # The wrapper itself must use -DateKind String.
        $common = [IO.File]::ReadAllText((Join-Path $global:PraGate.Source 'module\PRA.Common.psm1'))
        $common | Should -Match 'end \{ \(\$parts -join "`n"\) \| ConvertFrom-Json -DateKind String -ErrorAction Stop \}'
    }
    It 'ConvertFrom-PraJson keeps every date as the string that was written (a bare ConvertFrom-Json does not)' {
        $json = '{"CapturedUtc":"2026-11-03T10:11:12.1234567Z","CreatedUtc":"2026-11-03T10:11:12+00:00","N":3,"Items":[{"Utc":"2026-11-03T10:11:12.0000000Z"}]}'
        $bare = $json | ConvertFrom-Json
        $bare.CapturedUtc | Should -BeOfType ([datetime]) -Because 'this is the PowerShell 7 behaviour the wrapper exists for'
        $data = $json | ConvertFrom-PraJson
        $data.CapturedUtc | Should -BeOfType ([string])
        $data.CapturedUtc | Should -BeExactly '2026-11-03T10:11:12.1234567Z'
        $data.CreatedUtc | Should -BeExactly '2026-11-03T10:11:12+00:00'
        $data.Items[0].Utc | Should -BeExactly '2026-11-03T10:11:12.0000000Z'
        # File content arrives as one string or as lines; a JSON array is enumerated like ConvertFrom-Json does.
        (@('{"A":', '1}') | ConvertFrom-PraJson).A | Should -Be 1
        @('[1,2,3]' | ConvertFrom-PraJson).Count | Should -Be 3
        { 'not json' | ConvertFrom-PraJson } | Should -Throw
    }
    It 'creates the private folders through FileSystemAclExtensions: protected, no inherited rule, atomic, never over an existing folder' {
        $base = Join-Path ([IO.Path]::GetTempPath()) ('pra-acl3-' + [guid]::NewGuid().ToString('N'))
        try {
            $null = New-Item -ItemType Directory -Path $base
            Import-Module (Join-Path $global:PraGate.Package 'module\PRA.Directory.psm1') -Force -Global
            $private = Join-Path $base 'Batch-private'
            New-PraPrivateDirectory $private -Confirm:$false
            $acl = [IO.FileSystemAclExtensions]::GetAccessControl([IO.DirectoryInfo]::new($private))
            $acl.AreAccessRulesProtected | Should -BeTrue
            @($acl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier]) | Where-Object IsInherited).Count | Should -Be 0
            { New-PraPrivateDirectory $private -Confirm:$false } | Should -Throw '*already exists*'
            $logs = Join-Path $base 'logs'
            InModuleScope PRA.Common -Parameters @{ Path = $logs } { Initialize-PraPrivateFolder -Path $Path }
            $logAcl = [IO.FileSystemAclExtensions]::GetAccessControl([IO.DirectoryInfo]::new($logs))
            $logAcl.AreAccessRulesProtected | Should -BeTrue
            @($logAcl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier]) | Where-Object IsInherited).Count | Should -Be 0
            # The package no longer calls the .NET Framework overloads.
            foreach ($file in $script:Ps7Files) {
                [IO.File]::ReadAllText($file.FullName) | Should -Not -Match '\[IO\.Directory\]::(CreateDirectory\([^)]*,|GetAccessControl)' -Because $file.Name
            }
        } finally { Remove-Item -LiteralPath $base -Recurse -Force -ErrorAction SilentlyContinue }
    }
    It 'gives only the last folder the private ACL: missing parents keep the inheritance of their own parent (Initialize-PraPrivateFolder and New-PraPrivateDirectory)' {
        $base = Join-Path ([IO.Path]::GetTempPath()) ('pra-parents-' + [guid]::NewGuid().ToString('N'))
        try {
            Import-Module (Join-Path $global:PraGate.Package 'module\PRA.Directory.psm1') -Force -Global
            $null = New-Item -ItemType Directory -Path $base
            $leafA = Join-Path $base 'a\b\logs'
            InModuleScope PRA.Common -Parameters @{ Path = $leafA } { Initialize-PraPrivateFolder -Path $Path }
            $leafB = Join-Path $base 'c\d\Batch-x'
            New-PraPrivateDirectory $leafB -Confirm:$false
            foreach ($case in @(@{ Leaf = $leafA; Parents = @('a', 'a\b') }, @{ Leaf = $leafB; Parents = @('c', 'c\d') })) {
                $leafAcl = [IO.FileSystemAclExtensions]::GetAccessControl([IO.DirectoryInfo]::new($case.Leaf))
                $leafAcl.AreAccessRulesProtected | Should -BeTrue
                foreach ($parent in $case.Parents) {
                    $acl = [IO.FileSystemAclExtensions]::GetAccessControl([IO.DirectoryInfo]::new((Join-Path $base $parent)))
                    $acl.AreAccessRulesProtected | Should -BeFalse -Because ('the intermediate folder ' + $parent + ' is not private')
                    @($acl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier]) | Where-Object IsInherited).Count | Should -BeGreaterThan 0
                }
            }
        } finally { Remove-Item -LiteralPath $base -Recurse -Force -ErrorAction SilentlyContinue }
    }
    It 'makes a missing Storage.BackupFolder private as 2.x did, and every folder created under it, but not the folders above it (New-PraPrivateDirectory -Root)' {
        $base = Join-Path ([IO.Path]::GetTempPath()) ('pra-root-' + [guid]::NewGuid().ToString('N'))
        try {
            Import-Module (Join-Path $global:PraGate.Package 'module\PRA.Directory.psm1') -Force -Global
            $null = New-Item -ItemType Directory -Path $base
            $root = Join-Path $base 'above\Backups'
            $leaf = Join-Path $root 'mid\Batch-x'
            New-PraPrivateDirectory $leaf -Root $root -Confirm:$false
            foreach ($relative in @('above\Backups', 'above\Backups\mid', 'above\Backups\mid\Batch-x')) {
                $acl = [IO.FileSystemAclExtensions]::GetAccessControl([IO.DirectoryInfo]::new((Join-Path $base $relative)))
                $acl.AreAccessRulesProtected | Should -BeTrue -Because ($relative + ' is private')
            }
            $above = [IO.FileSystemAclExtensions]::GetAccessControl([IO.DirectoryInfo]::new((Join-Path $base 'above')))
            $above.AreAccessRulesProtected | Should -BeFalse -Because 'a folder above Storage.BackupFolder keeps the inheritance of its own parent'
            # An existing Storage.BackupFolder is left exactly as the administrator set it; only the new batch folder is private.
            New-PraPrivateDirectory (Join-Path $root 'Batch-y') -Root $root -Confirm:$false
            ([IO.FileSystemAclExtensions]::GetAccessControl([IO.DirectoryInfo]::new((Join-Path $root 'Batch-y')))).AreAccessRulesProtected | Should -BeTrue
        } finally { Remove-Item -LiteralPath $base -Recurse -Force -ErrorAction SilentlyContinue }
    }
    It 'reads a person-made CSV with a byte order mark, as strict UTF-8 without one, and with the ANSI code page when it is not UTF-8 (Read-PraCsvText)' {
        $path = Join-Path ([IO.Path]::GetTempPath()) ('pra-ansi-' + [guid]::NewGuid().ToString('N') + '.csv')
        $text = "Shared;Group`r`nBo" + [char]0x00EE + "te-" + [char]0x00E9 + ";Groupe-A`r`n"
        try {
            $ansi = [Text.Encoding]::GetEncoding([Globalization.CultureInfo]::CurrentCulture.TextInfo.ANSICodePage)
            [IO.File]::WriteAllBytes($path, $ansi.GetBytes($text))
            Read-PraCsvText -Path $path | Should -BeExactly $text
            [IO.File]::WriteAllBytes($path, ([byte[]](0xEF, 0xBB, 0xBF)) + [Text.Encoding]::UTF8.GetBytes($text))
            Read-PraCsvText -Path $path | Should -BeExactly $text
            [IO.File]::WriteAllBytes($path, [Text.Encoding]::UTF8.GetBytes($text))
            Read-PraCsvText -Path $path | Should -BeExactly $text
            [IO.File]::WriteAllBytes($path, ([byte[]](0xFF, 0xFE)) + [Text.Encoding]::Unicode.GetBytes($text))
            Read-PraCsvText -Path $path | Should -BeExactly $text
            # The shared permission CSV and the target CSV both use it.
            [IO.File]::ReadAllText((Join-Path $global:PraGate.Source 'module\PRA.Directory.psm1')) | Should -Match 'Read-PraCsvText -Path \$settings\.CsvPath'
            [IO.File]::ReadAllText((Join-Path $global:PraGate.Source 'module\PRA.Common.psm1')) | Should -Match '\$text = Read-PraCsvText -Path \$Path'
            [IO.File]::WriteAllBytes($path, $ansi.GetBytes("Identity`r`n" + [char]0x00E9 + "l" + [char]0x00E8 + "ve@gate.invalid`r`n"))
            (Read-PraTargetCsv -Path $path).Identity | Should -BeExactly ([string][char]0x00E9 + 'l' + [char]0x00E8 + 've@gate.invalid')
        } finally { Remove-Item -LiteralPath $path -Force -ErrorAction SilentlyContinue }
    }
    It 'writes the CSV report with a UTF-8 BOM, with rows and without rows' {
        $runtime = New-GateRuntime -Name 'csv-bom'
        InModuleScope PRA.Common -Parameters @{ Runtime = $runtime } {
            foreach ($withRow in $true, $false) {
                $context = New-GateContext $Runtime -Mode Preview
                if ($withRow) {
                    $row = New-PraRow $context ([pscustomobject]@{ SamAccountName = 'accentu' + [char]0x00E9; UserPrincipalName = 'user@gate.invalid'; IsShared = $false })
                    $row.FinalStatus = 'Planned'; $context.Rows.Add($row)
                }
                $path = Join-Path ([IO.Path]::GetTempPath()) ('pra-bom-' + [guid]::NewGuid().ToString('N') + '.csv')
                try {
                    Write-PraReport $context @{ Csv = $path; Html = '' }
                    $bytes = [IO.File]::ReadAllBytes($path)
                    $bytes.Length | Should -BeGreaterThan 3
                    ('{0:X2}{1:X2}{2:X2}' -f $bytes[0], $bytes[1], $bytes[2]) | Should -BeExactly 'EFBBBF'
                    if ($withRow) { [Text.Encoding]::UTF8.GetString($bytes) | Should -Match ('accentu' + [char]0x00E9) }
                } finally { Remove-Item -LiteralPath $path -Force -ErrorAction SilentlyContinue }
            }
        }
    }
    It 'accepts the .NET collection types of a capture on any runtime and keeps refusing every other type' {
        InModuleScope PRA.Backup {
            $budget = { @{ Left = 1000 } }
            $list = [Collections.Generic.List[string]]::new(); $list.Add('a'); $list.Add('b')
            $array = [Collections.ArrayList]::new(); $null = $array.Add('x')
            $strings = [Collections.Specialized.StringCollection]::new(); $null = $strings.Add('y')
            $readOnly = [Collections.ObjectModel.ReadOnlyCollection[string]]::new([string[]]@('r'))
            foreach ($value in @($list, $array, $strings, $readOnly)) {
                $descriptor = ConvertTo-PraRawDescriptor -Value $value -Attribute 'a' -ObjectGuid 'g' -Depth 0 -Budget (& $budget)
                $descriptor.Kind | Should -BeExactly 'Collection' -Because $value.GetType().FullName
                @($descriptor.Items).Count | Should -Be @($value).Count
                (Test-PraRawCollectionType $descriptor.Type) | Should -BeTrue -Because $descriptor.Type
            }
            # Closed list of type names: no assembly list, but nothing outside the list passes.
            foreach ($value in @([Collections.Generic.HashSet[string]]::new(), [Collections.Queue]::new(), [Collections.Generic.Dictionary[string,string]]::new(), [Collections.Hashtable]::new(), [Collections.Generic.SortedSet[string]]::new())) {
                { ConvertTo-PraRawDescriptor -Value $value -Attribute 'a' -ObjectGuid 'g' -Depth 0 -Budget (& $budget) } | Should -Throw '*unsupported attribute*no fallback*' -Because $value.GetType().FullName
            }
            Test-PraRawCollectionType 'System.Collections.Generic.HashSet`1[[System.String]]' | Should -BeFalse
            Test-PraRawCollectionType 'Evil.Collections.ArrayList' | Should -BeFalse
            [IO.File]::ReadAllText((Join-Path $global:PraGate.Source 'module\PRA.Backup.psm1')) | Should -Not -Match "'mscorlib'"
        }
    }
    It 'imports ADSync through the Windows PowerShell compatibility layer under PowerShell 7 only, and runs the cycle on the objects it returns' {
        $global:PraGateSync = @{ Imports = (New-Object 'Collections.Generic.List[object]'); Started = 0; Polls = 0 }
        function global:Get-ADSyncScheduler { [CmdletBinding()] param() $global:PraGateSync.Polls++; [pscustomobject]@{ SyncCycleInProgress = $false } }
        function global:Start-ADSyncSyncCycle { [CmdletBinding()] param([string]$PolicyType) $global:PraGateSync.Started++; [pscustomobject]@{ Result = 'Success' } }
        try {
            InModuleScope PRA.Directory {
                Mock Import-Module { $global:PraGateSync.Imports.Add(@{ Name = $Name; UseWindowsPowerShell = [bool]$UseWindowsPowerShell; Bound = @($PesterBoundParameters.Keys) }) }
                Mock Start-Sleep { }
                # Self-contained (it also runs in the Windows PowerShell 5.1 endpoint of EntraConnect.Server): an ordinal comparison without PRA.Common.
                $script:PraSyncCycle.ToString() | Should -Match "if \(\[string\]::Equals\(\[string\]\`$PSVersionTable\.PSEdition, 'Core', \[StringComparison\]::Ordinal\)\) \{ \`$import\.UseWindowsPowerShell = \`$true \}"
                $answer = @(& $script:PraSyncCycle 'Delta' 1)
                @($answer | Where-Object { $null -ne $_.PSObject.Properties['Started'] }).Count | Should -Be 1 -Because 'a remote job tells that the cycle started through a marker object'
                @($answer | Where-Object { $null -ne $_.PSObject.Properties['Result'] })[-1].Result | Should -BeExactly 'Success'
            }
            $global:PraGateSync.Imports.Count | Should -Be 1
            $global:PraGateSync.Imports[0].Name | Should -BeExactly 'ADSync'
            $global:PraGateSync.Imports[0].UseWindowsPowerShell | Should -BeTrue
            $global:PraGateSync.Started | Should -Be 1
        } finally {
            Remove-Item -LiteralPath 'Function:\global:Get-ADSyncScheduler','Function:\global:Start-ADSyncSyncCycle' -ErrorAction SilentlyContinue
            Remove-Variable PraGateSync -Scope Global -ErrorAction SilentlyContinue
        }
    }
    It 'starts every child process with the PowerShell 7 that runs the engine (Exchange Online subprocess, window engine, OU helper)' {
        $cloud = [IO.File]::ReadAllText((Join-Path $global:PraGate.Source 'module\PRA.Cloud.psm1'))
        $cloud | Should -Match "\`$exe = Join-Path \`$PSHOME 'pwsh\.exe'"
        $cloud | Should -Match 'ConvertFrom-Json -DateKind String -ErrorAction Stop\r?\n    if \(\$cfg\.Protocol'
        Import-Module (Join-Path $global:PraGate.Package 'module\PRA.Gui.psm1') -Force
        Get-PraGuiEngine | Should -BeExactly (Join-Path $PSHOME 'pwsh.exe')
        (Get-PraGuiOuCommand -Root 'C:\Synthetic' -ConfigPath 'C:\Synthetic\config.psd1' -ResultPath 'C:\Synthetic\ou.json').FilePath | Should -BeExactly (Join-Path $PSHOME 'pwsh.exe')
    }
}

Describe 'Release 3.0.0 - ordinal string comparison under .NET ICU (helpers and static guard)' -Tag 'Ordinal' {
    BeforeAll {
        $script:OrdFiles = @('Invoke-PraRemoteMailbox.ps1','PraRemoteMailbox.psm1','module\PRA.Common.psm1','module\PRA.Directory.psm1','module\PRA.Backup.psm1','module\PRA.Cloud.psm1','module\PRA.Gui.psm1','module\PRA.Gui.Directory.ps1','module\Test-PackageIntegrity.ps1')
        # Commands that compare or order strings with the culture collation. Each exception needs a justification; a stale entry fails the test.
        $script:OrdAllowList = @{
            'module\PRA.Gui.Directory.ps1|Sort-Object DistinguishedName' = 'Display order of the OU picker; nothing is decided from it.'
        }
        # Files exempted from the operator and switch checks: none (the window is checked like the others).
        $script:OrdPendingFiles = @()
        # A switch statement compares its input with the culture collation. Each one that is kept is keyed 'file|condition' and says why no look-alike
        # (zero-width or control character) can reach it; a stale entry fails the test.
        $script:OrdSwitchAllowList = @{
            'Invoke-PraRemoteMailbox.ps1|$Action' = 'ValidateSet parameter, rewritten to its official spelling by the ordinal loop at the top of the entry script before any use.'
            'Invoke-PraRemoteMailbox.ps1|$s.Mode' = 'Scope.Mode was validated by Import-PraConfiguration with an ordinal membership test (Auto, OU, Group, Csv).'
            'Invoke-PraRemoteMailbox.ps1|$cloudAction' = 'Derived by the entry script from $Action and $Expect: one of the literals Convert or Recover.'
            'module\PRA.Common.psm1|$Style' = 'Closed set chosen by PRA.Common itself; PRA_ICONS is matched ordinally (Test-PraOrdinalIn) before it is used.'
            'module\PRA.Common.psm1|$Level' = 'Internal ValidateSet parameter: every caller of Write-PraLog passes a literal.'
            'module\PRA.Common.psm1|$code' = 'Switch over an integer character code (deliberately not over the string).'
            'module\PRA.Common.psm1|$outcome.Status' = 'Status computed by Get-PraOutcome from its own literals (Failed, Pending, Planned, Success).'
            'module\PRA.Directory.psm1|$Kinds[$name]' = 'The kind table of the managed attributes is a constant of the module.'
            'module\PRA.Directory.psm1|Resolve-PraKind $State.Kind' = 'Resolve-PraKind returns the official spelling after an ordinal match, or $null.'
            'module\PRA.Directory.psm1|$code' = 'Switch over an integer character code (deliberately not over the string).'
            'module\PRA.Directory.psm1|[string]$Plan.Row.FinalStatus' = 'Display text only (the next-step wording); nothing is decided from it.'
            'module\PRA.Directory.psm1|$Plan.Operation' = 'Display text only (the planned-operation wording); nothing is decided from it.'
            'module\PRA.Directory.psm1|$permissionSource' = 'Resolved to its official spelling by an ordinal loop just above the switch.'
            'module\PRA.Directory.psm1|$Operation' = 'Compared ordinally with the Operation of the proof just above (Test-PraOrdinalEqual): only the caller literal reaches the switch.'
            'module\PRA.Backup.psm1|$clrToken' = 'Closed token obtained from an ordinal dictionary lookup of the CLR type name.'
            'module\PRA.Backup.psm1|$Type' = 'Ordinal membership in PraRawScalarTypes is tested just above the switch.'
            'module\PRA.Backup.psm1|$kind' = 'Ordinal membership in PraRawRestoreKinds is tested just above the switch.'
            'module\PRA.Backup.psm1|$legacyToken' = 'Closed token built from ordinal comparisons just above the switch.'
            'module\PRA.Cloud.psm1|$Operation' = 'ValidateSet parameter of the internal Exchange Online operations; every caller passes a literal.'
            'module\PRA.Gui.psm1|$Action' = 'Internal key: the request builder (Resolve-GuiOfficialValue, ordinal) rewrites every action to its official spelling; the window passes its own literals.'
            'module\PRA.Gui.psm1|$g.Action' = 'Tile of the window (Convert, Recover, Finalize, Check): set from the Tag of a control of the XAML, never from typed text.'
            'module\PRA.Gui.psm1|$script:Gui.Action' = 'Tile of the window (Convert, Recover, Finalize, Check): set from the Tag of a control of the XAML, never from typed text.'
            'module\PRA.Gui.psm1|$g.Page' = 'Page number 1 to 5 of the window (an integer).'
            'module\PRA.Gui.psm1|$Number' = 'Page number 1 to 5 of the window (an integer).'
            'module\PRA.Gui.psm1|$script:Gui.Filter' = 'Filter of the verification grid chosen by the radio buttons of the window (All, User, Shared, Warn); display only.'
            'module\PRA.Gui.psm1|$Name' = 'Name of a control of the XAML (its Tag), never typed text.'
            'module\PRA.Gui.psm1|$Level' = 'Closed list of pill levels chosen by the window code (Ok, Warn, Fail, Brand); only colours depend on it.'
            'module\PRA.Gui.psm1|$Status' = 'Display status of a row or a log line chosen by the window code (colour and glyph only); nothing is decided from it.'
            'module\PRA.Gui.psm1|$Row.Status' = 'Display status of a row chosen by the window code (glyph and colour only); nothing is decided from it.'
            'module\PRA.Gui.psm1|$role' = 'Role (Both, AD, Cloud, None) computed by the window prerequisite probe from its own literals; wording only.'

            'module\PRA.Gui.psm1|Get-PraGuiField ''Source''' = 'Segmented choice of the window: the value is one of the literals of its own radio buttons.'
            'module\PRA.Gui.psm1|$item.Operation' = 'Operation of a batch file already accepted by Read-PraGuiBatch (ordinal membership in Convert, Recover, RecoverFinalize); wording and icon only.'

            'module\PRA.Gui.psm1|$kind' = 'Kind of a package accepted by the engine (ordinal membership in the three kinds, Result.transferPackageKind); wording only.'
            'module\PRA.Gui.psm1|[string]$Record.kind' = 'Event kind: Read-PraGuiEvents already refused any kind outside its list with an ordinal membership test.'
            'module\PRA.Cloud.psm1|$right' = 'Right name taken from the fixed list FullAccess, SendAs, SendOnBehalf built by the module.'
        }
    }
    It 'exports the ordinal helpers from PRA.Common' {
        foreach ($name in 'Test-PraOrdinalEqual','Test-PraOrdinalIgnoreCaseEqual','Test-PraOrdinalIn','Test-PraOrdinalIgnoreCaseIn','Get-PraOrdinalSorted','Get-PraOrdinalUnique') {
            (Get-Command $name -ErrorAction Stop).ModuleName | Should -BeExactly 'PRA.Common'
        }
    }
    It 'tells "abc" from "abc" plus <Name> and from "ab" plus <Name> plus "c" in every helper (the culture comparison does not)' -ForEach @(
        @{Name='U+0001 (control)';Char=[string][char]0x0001},@{Name='U+0008 (control)';Char=[string][char]0x0008},@{Name='U+200B (zero-width space)';Char=[string][char]0x200B}
        @{Name='U+00AD (soft hyphen)';Char=[string][char]0x00AD},@{Name='U+200C (zero-width non-joiner)';Char=[string][char]0x200C},@{Name='U+FEFF (byte order mark)';Char=[string][char]0xFEFF}
    ) {
        $plain = 'abc'; $tail = 'abc' + $Char; $middle = 'ab' + $Char + 'c'
        foreach ($other in $tail, $middle) {
            Test-PraOrdinalEqual $plain $other | Should -BeFalse
            Test-PraOrdinalEqual $other $plain | Should -BeFalse
            Test-PraOrdinalIgnoreCaseEqual $plain $other | Should -BeFalse
            Test-PraOrdinalIgnoreCaseEqual 'ABC' $other | Should -BeFalse
            Test-PraOrdinalIn $plain @('x', $other) | Should -BeFalse
            Test-PraOrdinalIn $other @('x', $plain) -IgnoreCase | Should -BeFalse
            Test-PraOrdinalIgnoreCaseIn $plain @($other) | Should -BeFalse
            @($plain, $other | Get-PraOrdinalUnique).Count | Should -Be 2
            @($plain, $other | Get-PraOrdinalUnique -IgnoreCase).Count | Should -Be 2
            @($other, $plain | Get-PraOrdinalSorted -Unique).Count | Should -Be 2
        }
        # The exact same text still matches (case rules unchanged).
        Test-PraOrdinalEqual $tail ('abc' + $Char) | Should -BeTrue
        Test-PraOrdinalEqual 'ABC' 'abc' | Should -BeFalse
        Test-PraOrdinalIgnoreCaseEqual 'ABC' 'abc' | Should -BeTrue
        Test-PraOrdinalIn 'abc' @('x', 'ABC') | Should -BeFalse
        Test-PraOrdinalIn 'abc' @('x', 'ABC') -IgnoreCase | Should -BeTrue
    }
    It 'handles $null, empty and non-string values like -ceq / -eq would, and sorts by UTF-16 code unit' {
        Test-PraOrdinalEqual $null $null | Should -BeTrue
        Test-PraOrdinalEqual $null '' | Should -BeFalse
        Test-PraOrdinalEqual '' ([string][char]1) | Should -BeFalse -Because 'U+0001 -ceq empty is true under ICU'
        Test-PraOrdinalIgnoreCaseEqual 7 '7' | Should -BeTrue
        Test-PraOrdinalIn 'a' $null | Should -BeFalse
        Test-PraOrdinalIn 'a' @() | Should -BeFalse
        (@('b','A','a','B') | Get-PraOrdinalSorted) -join ',' | Should -BeExactly 'A,B,a,b'
        (@('b','A','a','B') | Get-PraOrdinalSorted -Descending) -join ',' | Should -BeExactly 'b,a,B,A'
        (@('b','A','a','B') | Get-PraOrdinalSorted -IgnoreCase | ForEach-Object { $_.ToLowerInvariant() }) -join ',' | Should -BeExactly 'a,a,b,b'
        (@([pscustomobject]@{N='z'},[pscustomobject]@{N='Y'},[pscustomobject]@{N='a'}) | Get-PraOrdinalSorted -Property N | ForEach-Object N) -join ',' | Should -BeExactly 'Y,a,z'
        @() | Get-PraOrdinalSorted | Should -BeNullOrEmpty
        (@('x','y','x','X') | Get-PraOrdinalUnique) -join ',' | Should -BeExactly 'x,y,X'
    }
    It 'Get-PraValue finds a key by ordinal, case-insensitive match only' {
        Get-PraValue @{Operation='Convert'} 'operation' 'none' | Should -BeExactly 'Convert'
        Get-PraValue @{Operation='Convert'} ('Operation' + [char]0x200B) 'none' | Should -BeExactly 'none'
        Get-PraValue @{('Operation' + [char]1)='Convert'} 'Operation' 'none' | Should -BeExactly 'none'
    }
    It 'has no culture-sensitive string comparison left in the 8 runtime files (-ceq -cne -cin -cnotin -ccontains -like family, one-argument StartsWith/EndsWith/IndexOf/CompareTo, [string]::Compare, Sort-Object, Group-Object, -Unique)' {
        $used = New-Object 'Collections.Generic.HashSet[string]'
        $banned = @('Ceq','Cne','Cin','Cnotin','Ccontains','Cnotcontains','Clike','Cnotlike','Like','Notlike','Ilike','Inotlike')
        foreach ($relative in $script:OrdFiles) {
            $tokens = $null; $errors = $null
            $ast = [Management.Automation.Language.Parser]::ParseFile((Join-Path $global:PraGate.Source $relative), [ref]$tokens, [ref]$errors)
            $errors.Count | Should -Be 0 -Because $relative
            @($tokens | Where-Object { $_.Kind.ToString() -in $banned } | ForEach-Object { '{0}:{1} {2}' -f $relative, $_.Extent.StartLineNumber, $_.Text }) | Should -BeNullOrEmpty -Because 'comparison operators with a culture collation (use PRA.Common ordinal helpers or [StringComparison]::Ordinal)'
            @($ast.FindAll({ param($n) $n -is [Management.Automation.Language.InvokeMemberExpressionAst] -and $n.Member -is [Management.Automation.Language.StringConstantExpressionAst] -and
                $n.Member.Value -in 'StartsWith','EndsWith','IndexOf','LastIndexOf','CompareTo' -and $n.Arguments.Count -eq 1 }, $true) |
                ForEach-Object { '{0}:{1} {2}' -f $relative, $_.Extent.StartLineNumber, $_.Extent.Text }) | Should -BeNullOrEmpty -Because 'one-argument culture overloads (pass [StringComparison]::Ordinal)'
            @($ast.FindAll({ param($n) $n -is [Management.Automation.Language.InvokeMemberExpressionAst] -and $n.Static -and $n.Expression.Extent.Text -eq '[string]' -and
                $n.Member.Value -in 'Compare','Equals' -and $n.Arguments.Count -eq 2 }, $true) | ForEach-Object { '{0}:{1} {2}' -f $relative, $_.Extent.StartLineNumber, $_.Extent.Text }) | Should -BeNullOrEmpty -Because '[string]::Compare/Equals without a StringComparison'
            $culture = @($ast.FindAll({ param($n) ($n -is [Management.Automation.Language.CommandAst] -and $n.GetCommandName() -in 'Sort-Object','Group-Object','Get-Unique','Compare-Object') -or
                ($n -is [Management.Automation.Language.CommandParameterAst] -and $n.ParameterName -eq 'Unique') }, $true))
            foreach ($node in $culture) {
                $command = if ($node -is [Management.Automation.Language.CommandParameterAst]) { $node.Parent } else { $node }
                $key = $relative + '|' + (($command.Extent.Text -replace '\s+', ' ').Trim())
                if ($script:OrdAllowList.ContainsKey($key)) { [void]$used.Add($key); $script:OrdAllowList[$key] | Should -Not -BeNullOrEmpty }
                else { $key | Should -BeNullOrEmpty -Because ('culture-sensitive command outside the allow-list at line ' + $node.Extent.StartLineNumber) }
            }
        }
        foreach ($key in $script:OrdAllowList.Keys) { $used.Contains($key) | Should -BeTrue -Because ('stale allow-list entry: ' + $key) }
    }
    It 'has no string -eq -ne -in -notin -contains -notcontains and no unjustified switch left in the runtime files, the window included' {
        # The guard resolves the type of a static member (for example [Windows.Input.Key]::Return in the window) to tell an enum or a number from a string:
        # the WPF assemblies must be loaded, whatever the tests that ran before. Loading them needs no desktop.
        Add-Type -AssemblyName PresentationCore, WindowsBase -ErrorAction Stop
        # An operand that is certainly not a string: a number, $true/$false/$null, a negation, a type, a static member of a non-string type, a cast to a
        # value type, or a member that is a number or a flag (Count, Length, ExitCode, Depth, NodeType, PSIsContainer).
        $isSafe = $null
        $isSafe = {
            param($node)
            if ($node -is [Management.Automation.Language.ParenExpressionAst]) { $inner = $node.Pipeline.GetPureExpression(); return ($null -ne $inner -and (& $isSafe $inner)) }
            if ($node -is [Management.Automation.Language.ConstantExpressionAst]) { return ($node.Value -isnot [string]) }
            if ($node -is [Management.Automation.Language.UnaryExpressionAst] -or $node -is [Management.Automation.Language.TypeExpressionAst]) { return $true }
            if ($node -is [Management.Automation.Language.VariableExpressionAst]) { return ($node.VariablePath.UserPath -in 'true', 'false', 'null') }
            if ($node -is [Management.Automation.Language.InvokeMemberExpressionAst] -and $node.Member -is [Management.Automation.Language.StringConstantExpressionAst] -and -not $node.Static) { return ($node.Member.Value -in 'MoveToContent', 'GetHashCode', 'CompareTo') }
            if ($node -is [Management.Automation.Language.MemberExpressionAst] -and $node.Static -and $node.Expression -is [Management.Automation.Language.TypeExpressionAst]) { $type = $node.Expression.TypeName.GetReflectionType(); return ($null -ne $type -and $type -ne [string]) }
            if ($node -is [Management.Automation.Language.MemberExpressionAst] -and $node.Member -is [Management.Automation.Language.StringConstantExpressionAst]) { return ($node.Member.Value -in 'Count', 'Length', 'ExitCode', 'Depth', 'NodeType', 'PSIsContainer') }
            if ($node -is [Management.Automation.Language.ConvertExpressionAst]) { return ($node.StaticType -in [int], [long], [bool], [double], [uint32], [uint64], [byte], [char], [version], [guid]) }
            $false
        }
        $operators = 'Ieq', 'Ine', 'Iin', 'Inotin', 'Icontains', 'Inotcontains'
        $usedSwitches = New-Object 'Collections.Generic.HashSet[string]'
        $checked = 0
        foreach ($relative in $script:OrdFiles) {
            if ($relative -in $script:OrdPendingFiles) { continue }
            $checked++
            $tokens = $null; $errors = $null
            $ast = [Management.Automation.Language.Parser]::ParseFile((Join-Path $global:PraGate.Source $relative), [ref]$tokens, [ref]$errors)
            $errors.Count | Should -Be 0 -Because $relative
            $comparisons = @($ast.FindAll({ param($n) $n -is [Management.Automation.Language.BinaryExpressionAst] -and $n.Operator.ToString() -in $operators }, $true) |
                    Where-Object { -not ((& $isSafe $_.Left) -or (& $isSafe $_.Right)) } |
                    ForEach-Object { '{0}:{1} {2}' -f $relative, $_.Extent.StartLineNumber, (($_.Extent.Text -replace '\s+', ' ')) })
            $comparisons | Should -BeNullOrEmpty -Because 'a string comparison operator uses the culture collation under ICU (use Test-PraOrdinalIgnoreCaseEqual, Test-PraOrdinalEqual or Test-PraOrdinalIn)'
            foreach ($switch in @($ast.FindAll({ param($n) $n -is [Management.Automation.Language.SwitchStatementAst] }, $true))) {
                $condition = (($switch.Condition.Extent.Text -split "`n")[0] -replace '\s+', ' ').Trim()
                $key = $relative + '|' + $condition
                if ($script:OrdSwitchAllowList.ContainsKey($key)) { [void]$usedSwitches.Add($key); $script:OrdSwitchAllowList[$key] | Should -Not -BeNullOrEmpty }
                else { $key | Should -BeNullOrEmpty -Because ('switch outside the allow-list at line ' + $switch.Extent.StartLineNumber + ': a switch compares strings with the culture collation') }
            }
        }
        $checked | Should -BeGreaterThan 5
        foreach ($key in $script:OrdSwitchAllowList.Keys) { $usedSwitches.Contains($key) | Should -BeTrue -Because ('stale switch allow-list entry: ' + $key) }
        # The files still pending are named, so the exclusion cannot grow silently.
        @($script:OrdPendingFiles).Count | Should -Be 0 -Because 'the window is covered by the operator and switch checks'
    }
    It 'keeps ValidateSet from being the only gate: the entry script and the window rewrite or refuse a value without an ordinal match' {
        $entry = [IO.File]::ReadAllText((Join-Path $global:PraGate.Source 'Invoke-PraRemoteMailbox.ps1'))
        $entry | Should -Match ([regex]::Escape("Parameter -{0}: '{1}' is not one of the accepted values ({2}).")) -Because 'the refusal names the parameter, the typed value and the accepted values'
        $entry | Should -Match '\[StringComparison\]::OrdinalIgnoreCase\)\s*\}\)'
        [IO.File]::ReadAllText((Join-Path $global:PraGate.Source 'module\PRA.Gui.psm1')) | Should -Match 'function Resolve-GuiOfficialValue'
    }
    It 'refuses a new regular expression anchored with a bare $ on a hash, GUID or name in the verifier (the line feed that $ also accepts)' {
        [IO.File]::ReadAllText((Join-Path $global:PraGate.Source 'module\Test-PackageIntegrity.ps1')) | Should -Match "Sha256 -cnotmatch '\^\[0-9A-F\]\{64\}\\z'"
    }
}

Describe 'Release 3.0.0 - ordinal comparison: a control or zero-width character is refused by the backup, proof and raw codec readers' -Tag 'Ordinal' {
    BeforeEach {
        $global:PraGate.Runtime = New-GateRuntime -Name 'ordinal-backup'
        $env:PRA_GATE_STATE = $global:PraGate.Runtime.StatePath
        $env:PSModulePath = $global:PraGate.Runtime.Modules + ';' + (Join-Path $PSHOME 'Modules')
        Import-Module ActiveDirectory -Force -Global
        $global:PraGate.Context = New-GateContext $global:PraGate.Runtime
        $global:PraGate.Context.LogFile = Join-Path $global:PraGate.Runtime.Root 'logs\ordinal.log'
    }
    It 'accepts the untouched backup (control for the refusals below)' {
        $plan = New-PraPlan $global:PraGate.Context 'user1' 'Convert'
        $receipt = & (Get-Module PRA.Directory) { param($c, $p) Save-PraBatch $c @($p) 'Convert' } $global:PraGate.Context $plan
        $fresh = New-GateContext $global:PraGate.Runtime
        (Import-PraBackup $fresh $receipt.Path).Data.Operation | Should -BeExactly 'Convert'
    }
    It 'refuses a backup whose <Field> carries <Name>, even with a correct JSON hash' -ForEach @(
        @{Field='.sha256 file (batch hash)';Name='U+0001';Char=[string][char]1;Match='*does not match its .sha256*'}
        @{Field='.sha256 file (batch hash)';Name='U+200B';Char=[string][char]0x200B;Match='*does not match its .sha256*'}
        @{Field='Environment';Name='U+0001';Char=[string][char]1;Match='*another Environment*'}
        @{Field='Environment';Name='U+200B';Char=[string][char]0x200B;Match='*another Environment*'}
        @{Field='Operation';Name='U+0001';Char=[string][char]1;Match='*not an AD backup*'}
        @{Field='Operation';Name='U+200B';Char=[string][char]0x200B;Match='*not an AD backup*'}
        @{Field='RawFormat';Name='U+0001';Char=[string][char]1;Match='*capture format not supported*'}
        @{Field='RawFormat';Name='U+200B';Char=[string][char]0x200B;Match='*capture format not supported*'}
        @{Field='RawHash';Name='U+200B';Char=[string][char]0x200B;Match='*CLIXML SHA-256 mismatch*'}
    ) {
        $plan = New-PraPlan $global:PraGate.Context 'user1' 'Convert'
        $receipt = & (Get-Module PRA.Directory) { param($c, $p) Save-PraBatch $c @($p) 'Convert' } $global:PraGate.Context $plan
        if ($Field -like '.sha256*') { [IO.File]::WriteAllText(($receipt.Path + '.sha256'), ((Get-PraHash $receipt.Path) + $Char)) }
        else {
            $data = [IO.File]::ReadAllText($receipt.Path) | ConvertFrom-PraJson
            $data.$Field = [string]$data.$Field + $Char
            [IO.File]::WriteAllText($receipt.Path, ($data | ConvertTo-Json -Depth 30))
            [IO.File]::WriteAllText(($receipt.Path + '.sha256'), (Get-PraHash $receipt.Path))
        }
        $fresh = New-GateContext $global:PraGate.Runtime
        { Import-PraBackup $fresh $receipt.Path } | Should -Throw $Match
        @(Get-GateWrites $global:PraGate.Runtime).Count | Should -Be 0
    }
    It 'refuses an AD proof whose <Field> carries <Name>, even with a correct hash' -ForEach @(
        @{Field='Environment';Name='U+200B';Char=[string][char]0x200B;Message='AD proof (State file) does not match'}
        @{Field='Operation';Name='U+200B';Char=[string][char]0x200B;Message='AD proof (State file) does not match'}
        @{Field='Kind';Name='U+0001';Char=[string][char]1;Message='AD proof (State file) does not match'}
        @{Field='BackupHash';Name='U+200B';Char=[string][char]0x200B;Message='AD proof does not match its backup'}
    ) {
        $context = $global:PraGate.Context
        $bundles = New-GateSourceBundles $context
        $proofPath = $bundles.State
        # Witness: the untouched proof is accepted, so the refusal below comes from the look-alike character alone.
        $intactContext = New-GateContext $global:PraGate.Runtime
        $intactSource = Import-PraBackup $intactContext $bundles.Source
        { Import-PraProof $intactContext $proofPath $intactSource 'Recover' } | Should -Not -Throw -Because 'the intact proof is accepted'
        $proof = [IO.File]::ReadAllText($proofPath) | ConvertFrom-PraJson
        $proof.$Field = [string]$proof.$Field + $Char
        [IO.File]::WriteAllText($proofPath, ($proof | ConvertTo-Json -Depth 20))
        [IO.File]::WriteAllText(($proofPath + '.sha256'), (Get-PraHash $proofPath))
        $fresh = New-GateContext $global:PraGate.Runtime
        $recoverSource = Import-PraBackup $fresh $bundles.Source
        { Import-PraProof $fresh $proofPath $recoverSource 'Recover' } | Should -Throw -ExpectedMessage ('*' + $Message + '*')
    }
    It 'refuses a raw capture whose <Fault> carries <Name>' -ForEach @(
        @{Fault='RawFormat marker';Name='U+200B';Char=[string][char]0x200B}
        @{Fault='RawFormat marker';Name='U+0001 (as _x0001_)';Char='_x0001_'}
        @{Fault='Kind value';Name='U+200B';Char=[string][char]0x200B}
        @{Fault='Kind value';Name='U+0001 (as _x0001_)';Char='_x0001_'}
        @{Fault='attribute name N';Name='U+200C (valid in an XML name)';Char=[string][char]0x200C}
        @{Fault='element name S';Name='U+200C (valid in an XML name)';Char=[string][char]0x200C}
    ) {
        $context = $global:PraGate.Context
        $user = New-GateUser
        $snapshot = ConvertTo-PraRawSnapshot -User $user -CapturedUtc '2026-09-07T00:00:00.0000000Z'
        $path = Join-Path $global:PraGate.Runtime.Root 'ordinal.clixml'
        Write-PraRawCapture -Context $context -LiteralPath $path -Snapshots @($snapshot)
        $records = @(@{ObjectGuid = $snapshot.ObjectGUID})
        (Test-PraRawCapture -Context $context -LiteralPath $path -Records $records -RawFormat 'PraDataOnlyClixml-v1' -ExpectedSnapshots @($snapshot)).Count | Should -Be 1
        $text = [IO.File]::ReadAllText($path)
        switch ($Fault) {
            'RawFormat marker' { $changed = $text.Replace('>PraDataOnlyClixml-v1<', ('>PraDataOnlyClixml-v1' + $Char + '<')) }
            'Kind value'       { $changed = [regex]::Replace($text, '(<S N="Kind">)(\w+)(</S>)', ('${1}${2}' + $Char + '${3}'), 'None', [timespan]::FromSeconds(5)) }
            'attribute name N' { $changed = $text.Replace('<S N="Kind">', ('<S N' + $Char + '="Kind">')) }
            'element name S'   { $changed = $text.Replace('<S ', ('<S' + $Char + ' ')).Replace('</S>', ('</S' + $Char + '>')) }
        }
        # (Should -BeExactly is itself a culture comparison: compare ordinally.)
        [string]::Equals($changed, $text, [StringComparison]::Ordinal) | Should -BeFalse -Because 'the fault must really change the capture'
        [IO.File]::WriteAllText($path, $changed, (New-Object Text.UTF8Encoding($false)))
        { Test-PraRawCapture -Context $context -LiteralPath $path -Records $records -RawFormat 'PraDataOnlyClixml-v1' -ExpectedSnapshots @($snapshot) } | Should -Throw
        @(Get-GateWrites $global:PraGate.Runtime).Count | Should -Be 0
    }
}

Describe 'Release 3.0.0 - ordinal comparison: the entry script and the Finalize package refuse look-alike values' -Tag 'Ordinal' {
    BeforeAll {
        $script:OrdRuntime = New-GateRuntime -Name 'ordinal-finalize'
        $env:PRA_GATE_STATE = $script:OrdRuntime.StatePath
        $env:PSModulePath = $script:OrdRuntime.Modules + ';' + (Join-Path $PSHOME 'Modules')
        Import-Module ActiveDirectory -Force -Global
        $script:OrdContext = New-GateContext $script:OrdRuntime
        $script:OrdBundles = New-GateSourceBundles $script:OrdContext -ApplySnapshots
        $script:OrdFolder = Split-Path $script:OrdBundles.Manifest -Parent
        $script:OrdWrites = @(Get-GateWrites $script:OrdRuntime).Count
        $script:OrdMutant = {
            param([string]$Field, [string]$Suffix, [switch]$SidecarOnly)
            $name = 'Mutant-' + [guid]::NewGuid().ToString('N').Substring(0, 6) + '.json'
            $path = Join-Path $script:OrdFolder $name
            $manifest = [IO.File]::ReadAllText($script:OrdBundles.Manifest) | ConvertFrom-PraJson
            if (-not $SidecarOnly) { $manifest.$Field = [string]$manifest.$Field + $Suffix }
            [IO.File]::WriteAllText($path, ($manifest | ConvertTo-Json -Depth 20))
            [IO.File]::WriteAllText(($path + '.sha256'), ((Get-PraHash $path) + $(if ($SidecarOnly) { $Suffix } else { '' })))
            $path
        }
    }
    It 'refuses -<Parameter> typed as "<Value>" plus <Name> although ValidateSet accepts it' -ForEach @(
        @{Parameter='Action';Value='Check';Name='U+0001';Char=[string][char]1}
        @{Parameter='Action';Value='Check';Name='U+200B';Char=[string][char]0x200B}
        @{Parameter='Mode';Value='Apply';Name='U+0001';Char=[string][char]1}
        @{Parameter='Mode';Value='Preview';Name='U+200B';Char=[string][char]0x200B}
        @{Parameter='Scope';Value='All';Name='U+00AD';Char=[string][char]0xAD}
        @{Parameter='Expect';Value='Retained';Name='U+200B';Char=[string][char]0x200B}
    ) {
        $arguments = @{Action='Check'; Mode='Preview'; Identity='user1@gate.invalid'; ConfigPath=$script:OrdRuntime.ConfigPath}
        $arguments[$Parameter] = $Value + $Char
        $run = Invoke-GateProcess $script:OrdRuntime $arguments
        $run.ExitCode | Should -Not -Be 0
        $run.Error | Should -Match 'accepted values|not belong to the set|does not belong'
        @(Get-GateWrites $script:OrdRuntime).Count | Should -Be $script:OrdWrites
    }
    It 'accepts the untouched Finalize package past the manifest checks (control)' {
        $run = Invoke-GateProcess $script:OrdRuntime @{Action='Finalize'; Mode='Preview'; ConfigPath=$script:OrdRuntime.ConfigPath; Batch=$script:OrdBundles.Manifest}
        (@($run.MainResult.Issues | ForEach-Object { [string]$_.Message }) -join ' ') | Should -Not -Match 'another version or Environment|SHA-256 mismatch|do not match|points outside'
    }
    It 'refuses a Finalize package whose <Field> carries <Name>' -ForEach @(
        @{Field='manifest .sha256 file';Name='U+200B';Char=[string][char]0x200B;Property='';Match='SHA-256 mismatch';Sidecar=$true}
        @{Field='manifest .sha256 file';Name='U+0001';Char=[string][char]1;Property='';Match='SHA-256 mismatch';Sidecar=$true}
        @{Field='Environment';Name='U+200B';Char=[string][char]0x200B;Property='Environment';Match='another version or Environment';Sidecar=$false}
        @{Field='Environment';Name='U+0001';Char=[string][char]1;Property='Environment';Match='another version or Environment';Sidecar=$false}
        @{Field='Operation';Name='U+200B';Char=[string][char]0x200B;Property='Operation';Match='another version or Environment';Sidecar=$false}
        @{Field='SourceBackupHash';Name='U+200B';Char=[string][char]0x200B;Property='SourceBackupHash';Match='manifest and proofs do not match';Sidecar=$false}
        @{Field='StateHash';Name='U+0001';Char=[string][char]1;Property='StateHash';Match='manifest and proofs do not match';Sidecar=$false}
        @{Field='SourceBackupFile (file name)';Name='U+200B';Char=[string][char]0x200B;Property='SourceBackupFile';Match='Stopped at step ''Loading the Finalize package''';Sidecar=$false}
        @{Field='StateFile (file name)';Name='U+200B';Char=[string][char]0x200B;Property='StateFile';Match='Stopped at step ''Loading the Finalize package''';Sidecar=$false}
        @{Field='SourceBackupFile (path separator)';Name='a parent-folder suffix';Char='\..\x';Property='SourceBackupFile';Match='a file path points outside the package';Sidecar=$false}
        @{Field='StateFile (path separator)';Name='a parent-folder suffix';Char='\..\x';Property='StateFile';Match='a file path points outside the package';Sidecar=$false}
    ) {
        $mutant = if ($Sidecar) { & $script:OrdMutant '' $Char -SidecarOnly } else { & $script:OrdMutant $Property $Char }
        $run = Invoke-GateProcess $script:OrdRuntime @{Action='Finalize'; Mode='Apply'; Force=$true; ConfigPath=$script:OrdRuntime.ConfigPath; Batch=$mutant}
        $run.ExitCode | Should -Be 1
        ($run.MainResult.Issues.Message -join ' ') | Should -Match $Match
        @(Get-GateWrites $script:OrdRuntime).Count | Should -Be $script:OrdWrites
    }
}

Describe 'Release 3.0.0 - transfer package: verification, extraction and refusals (pure functions, synthetic folders)' -Tag 'TransferPackage' {
    BeforeAll {
        Import-Module (Join-Path $global:PraGate.Package 'module\PRA.Common.psm1') -Force -Global
        Add-Type -AssemblyName System.IO.Compression
        $script:TpRoot = Join-Path $global:PraGate.Root 'transfer-pure'
        $null = New-Item -ItemType Directory -Path $script:TpRoot -Force
        $script:TpCounter = 0
        function script:New-TpWork {
            $script:TpCounter++
            $work = Join-Path $script:TpRoot ('w' + $script:TpCounter)
            $null = New-Item -ItemType Directory -Path (Join-Path $work 'src'), (Join-Path $work 'Backups') -Force
            [pscustomobject]@{ Root = $work; Source = (Join-Path $work 'src'); Backups = (Join-Path $work 'Backups'); Outbox = (Join-Path $work 'Backups\Outbox') }
        }
        function script:New-TpFolder([string]$Parent, [string]$Name, [hashtable]$Files) {
            $folder = Join-Path $Parent $Name
            $null = New-Item -ItemType Directory -Path $folder -Force
            foreach ($key in $Files.Keys) { [IO.File]::WriteAllBytes((Join-Path $folder $key), [byte[]]$Files[$key]) }
            $folder
        }
        function script:Get-TpBytes([string]$Text) { (New-Object Text.UTF8Encoding($false)).GetBytes($Text) }
        function script:Get-TpSha([byte[]]$Bytes) { $sha = [Security.Cryptography.SHA256]::Create(); try { ([BitConverter]::ToString($sha.ComputeHash($Bytes))).Replace('-', '').ToLowerInvariant() } finally { $sha.Dispose() } }
        # A hand-made package: entries (name -> bytes) and a manifest built from them unless overridden. The sidecar is valid unless said otherwise.
        function script:New-TpZip {
            param([string]$Path, [System.Collections.Specialized.OrderedDictionary]$Entries, $Manifest = $null, [switch]$NoManifest, [switch]$NoSidecar, [string]$Environment = 'LAB', [string]$Kind = 'Convert', [string]$BatchId = 'aaaaaaaa11111111aaaaaaaa11111111',
                [string[]]$ExtraEntryNames = @(), [string]$RawManifestText = '')
            if ($null -eq $Manifest) {
                $Manifest = [ordered]@{ SchemaVersion = 1; Kind = $Kind; Environment = $Environment; CreatedUtc = '2026-11-04T00:00:00.0000000Z'; ToolVersion = '3.0.0'; BatchId = $BatchId
                    Entries = @($Entries.Keys | ForEach-Object { [ordered]@{ Name = $_; Size = ([byte[]]$Entries[$_]).Length; Sha256 = (Get-TpSha ([byte[]]$Entries[$_])) } }); NextCommand = '.\x.ps1' }
            }
            $stream = [IO.File]::Open($Path, [IO.FileMode]::CreateNew)
            $zip = New-Object IO.Compression.ZipArchive($stream, [IO.Compression.ZipArchiveMode]::Create)
            try {
                if (-not $NoManifest) {
                    $entry = $zip.CreateEntry('transfer.json'); $s = $entry.Open()
                    $text = if ($RawManifestText) { $RawManifestText } else { $Manifest | ConvertTo-Json -Depth 6 }
                    $b = Get-TpBytes $text; $s.Write($b, 0, $b.Length); $s.Dispose()
                }
                foreach ($key in $Entries.Keys) { $entry = $zip.CreateEntry($key); $s = $entry.Open(); $b = [byte[]]$Entries[$key]; $s.Write($b, 0, $b.Length); $s.Dispose() }
            } finally { $zip.Dispose(); $stream.Dispose() }
            if (-not $NoSidecar) { [IO.File]::WriteAllText($Path + '.sha256', (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()) }
        }
        function script:Get-TpChildren([string]$Folder) { @(Get-ChildItem -LiteralPath $Folder -Force -ErrorAction SilentlyContinue).Count }
    }

    It 'accepts a package whose folder prefix, Environment, batch id, file name and checksum file are written in another case' -Tag 'Release313h' {
        $w = New-TpWork
        $batch = 'aaaaaaaa11111111aaaaaaaa11111111'
        $entries = [ordered]@{}
        $entries[('BATCH-' + $batch.ToUpperInvariant() + '/State-x.json')] = Get-TpBytes '{"a":1}'
        $zipPath = Join-Path $w.Root 'PRA-LAB-CONVERT-AAAAAAAA-FOR-CLOUD.ZIP'
        New-TpZip -Path $zipPath -Entries $entries -Environment 'lab' -Kind 'Convert' -BatchId $batch.ToUpperInvariant()
        [IO.File]::WriteAllText($zipPath + '.sha256', (Get-FileHash -LiteralPath $zipPath -Algorithm SHA256).Hash.ToUpperInvariant())
        $info = Get-PraTransferPackage -Path $zipPath -Environment 'Lab'
        $info.Valid | Should -BeTrue -Because $info.Error
        $imported = Import-PraTransferPackage -Path $zipPath -BackupFolder $w.Backups -Environment 'LAB' -ExpectedKind 'Convert'
        $imported.Created.Count | Should -Be 1
        Test-Path -LiteralPath (Join-Path $w.Backups ('batch-' + $batch)) -PathType Container | Should -BeTrue
        $again = Import-PraTransferPackage -Path $zipPath -BackupFolder $w.Backups -Environment 'lab' -ExpectedKind 'Convert'
        $again.Existing.Count | Should -Be 1
    }
    It 'refuses a package that holds two folders whose names differ only by case, and still refuses another Environment' -Tag 'Release313h' {
        $w = New-TpWork
        $batch = 'aaaaaaaa11111111aaaaaaaa11111111'
        $entries = [ordered]@{}
        $entries[('Batch-' + $batch + '/a.json')] = Get-TpBytes '{"a":1}'
        $entries[('batch-' + $batch.ToUpperInvariant() + '/b.json')] = Get-TpBytes '{"b":1}'
        $twice = Join-Path $w.Root 'twice.zip'
        New-TpZip -Path $twice -Entries $entries -Environment 'LAB' -Kind 'Convert' -BatchId $batch
        (Get-PraTransferPackage -Path $twice -Environment 'LAB').Error | Should -Match 'same name apart from letter case'
        $one = [ordered]@{}
        $one[('Batch-' + $batch + '/a.json')] = Get-TpBytes '{"a":1}'
        $other = Join-Path $w.Root 'other.zip'
        New-TpZip -Path $other -Entries $one -Environment 'LAB' -Kind 'Convert' -BatchId $batch
        (Get-PraTransferPackage -Path $other -Environment 'LAB2').Error | Should -Match "made for Environment 'LAB'"
    }
    It 'names the package after its purpose' {
        Get-PraTransferPackageName -Kind Convert -Environment PROD -BatchId 8547AB040273474BA2C720ADE6240FC5 | Should -BeExactly 'PRA-PROD-Convert-8547ab04-for-Cloud.zip'
        Get-PraTransferPackageName -Kind Recover -Environment LAB_1 -BatchId 8547ab04 | Should -BeExactly 'PRA-LAB_1-Recover-8547ab04-for-Cloud.zip'
        Get-PraTransferPackageName -Kind Finalize -Environment PROD -BatchId 8547ab040273474ba2c720ade6240fc5 | Should -BeExactly 'PRA-PROD-Finalize-8547ab04-for-AD.zip'
        { Get-PraTransferPackageName -Kind Other -Environment PROD -BatchId 8547ab04 } | Should -Throw
        { Get-PraTransferPackageName -Kind Convert -Environment 'A B' -BatchId 8547ab04 } | Should -Throw
        { Get-PraTransferPackageName -Kind Convert -Environment PROD -BatchId 'xyz' } | Should -Throw
    }
    It 'round-trips a <Kind> package: written once in the private Outbox, verified, imported to private folders with the original names' -ForEach @(
        @{ Kind = 'Convert'; Folders = @('Batch-8547ab040273474ba2c720ade6240fc5'); Suffix = 'for-Cloud'; Direction = 'ToCloud' }
        @{ Kind = 'Recover'; Folders = @('Batch-8547ab040273474ba2c720ade6240fc5', 'Batch-11112222333344445555666677778888'); Suffix = 'for-Cloud'; Direction = 'ToCloud' }
        @{ Kind = 'Finalize'; Folders = @('Finalize-8547ab040273474ba2c720ade6240fc5'); Suffix = 'for-AD'; Direction = 'ToAD' }
    ) {
        $w = New-TpWork
        $payload = [byte[]](1..40000 | ForEach-Object { [byte]($_ % 253) })
        $paths = @(foreach ($name in $Folders) {
            New-TpFolder $w.Source $name @{ ($name.Substring(0, 5) + '-X.json') = (Get-TpBytes "{`"n`":`"$name`"}"); ($name.Substring(0, 5) + '-X.json.sha256') = (Get-TpBytes 'abc'); 'raw.clixml' = $payload }
        })
        $made = New-PraTransferPackage -Kind $Kind -Environment LAB -BatchId '8547ab040273474ba2c720ade6240fc5' -Folders $paths -OutboxFolder $w.Outbox -NextCommand '.\Invoke-PraRemoteMailbox.ps1 -Batch ''x.zip''' -ToolVersion '3.0.0'
        $made.Name | Should -BeExactly "PRA-LAB-$Kind-8547ab04-$Suffix.zip"
        $made.Path | Should -BeExactly (Join-Path $w.Outbox $made.Name)
        $made.Verified | Should -BeTrue
        ([IO.File]::ReadAllText($made.Path + '.sha256')) | Should -BeExactly (Get-FileHash -LiteralPath $made.Path -Algorithm SHA256).Hash.ToLowerInvariant()
        ([IO.FileSystemAclExtensions]::GetAccessControl((New-Object IO.DirectoryInfo $w.Outbox))).AreAccessRulesProtected | Should -BeTrue
        # Deterministic entry order: the manifest first, then the names in ordinal order.
        $zip = [IO.Compression.ZipFile]::OpenRead($made.Path)
        try {
            $names = @($zip.Entries.FullName)
            $names[0] | Should -BeExactly 'transfer.json'
            (@($names[1..($names.Count - 1)]) -join '|') | Should -BeExactly ((@($names[1..($names.Count - 1)]) | Get-PraOrdinalSorted) -join '|')
            @($zip.Entries.LastWriteTime | ForEach-Object { $_.Year } | Get-PraOrdinalUnique) | Should -Be @('2000')
        } finally { $zip.Dispose() }
        $info = Get-PraTransferPackage -Path $made.Path -Environment LAB
        $info.Valid | Should -BeTrue -Because $info.Error
        $info.Kind | Should -BeExactly $Kind
        $info.Direction | Should -BeExactly $Direction
        $info.Environment | Should -BeExactly 'LAB'
        $info.BatchId | Should -BeExactly '8547ab040273474ba2c720ade6240fc5'
        $info.EntryCount | Should -Be (3 * $Folders.Count)
        $info.ToolVersion | Should -BeExactly '3.0.0'
        $info.NextCommand | Should -Match '-Batch'
        @($info.Folders | Get-PraOrdinalSorted) -join '|' | Should -BeExactly ((@($Folders) | Get-PraOrdinalSorted) -join '|')
        $info.SizeBytes | Should -Be ((Get-Item -LiteralPath $made.Path).Length)
        $imported = Import-PraTransferPackage -Path $made.Path -BackupFolder $w.Backups -Environment LAB
        $imported.Kind | Should -BeExactly $Kind
        $imported.Created.Count | Should -Be $Folders.Count
        $imported.Existing.Count | Should -Be 0
        foreach ($name in $Folders) {
            $target = Join-Path $w.Backups $name
            $imported.Folders | Should -Contain $target
            ([IO.FileSystemAclExtensions]::GetAccessControl((New-Object IO.DirectoryInfo $target))).AreAccessRulesProtected | Should -BeTrue
            foreach ($file in Get-ChildItem -LiteralPath (Join-Path $w.Source $name) -File) {
                (Get-FileHash -LiteralPath (Join-Path $target $file.Name)).Hash | Should -BeExactly (Get-FileHash -LiteralPath $file.FullName).Hash
            }
        }
        # The second import finds identical folders: accepted, nothing written.
        $again = Import-PraTransferPackage -Path $made.Path -BackupFolder $w.Backups -Environment LAB
        $again.Created.Count | Should -Be 0
        $again.Existing.Count | Should -Be $Folders.Count
    }
    It 'does not overwrite an existing package of the same name' {
        $w = New-TpWork
        $folder = New-TpFolder $w.Source 'Batch-8547ab040273474ba2c720ade6240fc5' @{ 'a.json' = (Get-TpBytes '{}') }
        $null = New-PraTransferPackage -Kind Convert -Environment LAB -BatchId 8547ab040273474ba2c720ade6240fc5 -Folders $folder -OutboxFolder $w.Outbox
        { New-PraTransferPackage -Kind Convert -Environment LAB -BatchId 8547ab040273474ba2c720ade6240fc5 -Folders $folder -OutboxFolder $w.Outbox } | Should -Throw '*already exists*'
        @(Get-ChildItem -LiteralPath $w.Outbox -Filter '*.tmp').Count | Should -Be 0
    }
    It 'refuses to pack a folder with a sub-folder or a file name outside the whitelist, and leaves no partial package' {
        $w = New-TpWork
        $folder = New-TpFolder $w.Source 'Batch-8547ab040273474ba2c720ade6240fc5' @{ 'a.json' = (Get-TpBytes '{}') }
        $null = New-Item -ItemType Directory -Path (Join-Path $folder 'sub')
        { New-PraTransferPackage -Kind Convert -Environment LAB -BatchId 8547ab040273474ba2c720ade6240fc5 -Folders $folder -OutboxFolder $w.Outbox } | Should -Throw '*sub-folder*'
        Remove-Item -LiteralPath (Join-Path $folder 'sub')
        [IO.File]::WriteAllText((Join-Path $folder 'bad name.txt'), 'x')
        { New-PraTransferPackage -Kind Convert -Environment LAB -BatchId 8547ab040273474ba2c720ade6240fc5 -Folders $folder -OutboxFolder $w.Outbox } | Should -Throw '*cannot be packed*'
        @(Get-ChildItem -LiteralPath $w.Outbox -ErrorAction SilentlyContinue).Count | Should -Be 0
    }
    It 'refuses a bad package (<Name>) with a reason, never throws from Get-PraTransferPackage, and writes nothing on import' -ForEach @(
        @{ Name = 'tampered entry'; Match = 'does not match its SHA-256' }
        @{ Name = 'extra entry'; Match = 'unexpected entry' }
        @{ Name = 'missing entry'; Match = 'missing from the package' }
        @{ Name = 'duplicate entry'; Match = 'duplicate entry' }
        @{ Name = 'path traversal'; Match = 'refused entry' }
        @{ Name = 'traversal in the middle'; Match = 'refused entry' }
        @{ Name = 'absolute path'; Match = 'refused entry' }
        @{ Name = 'backslash'; Match = 'refused entry' }
        @{ Name = 'drive'; Match = 'refused entry' }
        @{ Name = 'two separators'; Match = 'refused entry' }
        @{ Name = 'reserved device name'; Match = 'refused entry' }
        @{ Name = 'control character'; Match = 'refused entry' }
        @{ Name = 'trailing dot'; Match = 'refused entry' }
        @{ Name = 'wrong folder prefix'; Match = 'refused entry' }
        @{ Name = 'declared size differs'; Match = 'size of' }
        @{ Name = 'wrong Environment'; Match = "Environment 'OTHER'" }
        @{ Name = 'sidecar missing'; Match = '.sha256 file next to the package is missing' }
        @{ Name = 'sidecar mismatch'; Match = 'does not match its .sha256' }
        @{ Name = 'manifest missing'; Match = 'transfer.json is missing' }
        @{ Name = 'manifest not JSON'; Match = 'transfer.json is not valid' }
        @{ Name = 'manifest schema 2'; Match = 'SchemaVersion' }
        @{ Name = 'unknown kind'; Match = 'unknown package kind' }
        @{ Name = 'kind and folder prefix disagree'; Match = 'folders only' }
        @{ Name = 'batch folder not in package'; Match = 'folder of the batch' }
        @{ Name = 'manifest lists transfer.json'; Match = 'refused name' }
        @{ Name = 'not a zip'; Match = 'not a readable ZIP' }
    ) {
        $w = New-TpWork
        $good = [Collections.Specialized.OrderedDictionary]::new()
        $good['Batch-aaaaaaaa11111111aaaaaaaa11111111/Convert-X.json'] = (Get-TpBytes '{"ok":1}')
        $good['Batch-aaaaaaaa11111111aaaaaaaa11111111/raw.bin'] = [byte[]](1..3000 | ForEach-Object { [byte]($_ % 200) })
        $zipPath = Join-Path $w.Root 'bad.zip'
        $args1 = @{ Path = $zipPath; Entries = $good }
        switch ($Name) {
            'tampered entry' { $bad = [Collections.Specialized.OrderedDictionary]::new(); foreach ($k in $good.Keys) { $bad[$k] = $good[$k] }; $manifest = [ordered]@{ SchemaVersion = 1; Kind = 'Convert'; Environment = 'LAB'; CreatedUtc = 'x'; ToolVersion = '3'; BatchId = 'aaaaaaaa11111111aaaaaaaa11111111'; NextCommand = ''
                    Entries = @($good.Keys | ForEach-Object { [ordered]@{ Name = $_; Size = $good[$_].Length; Sha256 = (Get-TpSha (Get-TpBytes 'other')) } }) }
                $args1 = @{ Path = $zipPath; Entries = $good; Manifest = $manifest } }
            'extra entry' { $more = [Collections.Specialized.OrderedDictionary]::new(); foreach ($k in $good.Keys) { $more[$k] = $good[$k] }; $manifest = [ordered]@{ SchemaVersion = 1; Kind = 'Convert'; Environment = 'LAB'; CreatedUtc = 'x'; ToolVersion = '3'; BatchId = 'aaaaaaaa11111111aaaaaaaa11111111'; NextCommand = ''
                    Entries = @($good.Keys | ForEach-Object { [ordered]@{ Name = $_; Size = $good[$_].Length; Sha256 = (Get-TpSha $good[$_]) } }) }
                $more['Batch-aaaaaaaa11111111aaaaaaaa11111111/extra.txt'] = (Get-TpBytes 'evil'); $args1 = @{ Path = $zipPath; Entries = $more; Manifest = $manifest } }
            'missing entry' { $few = [Collections.Specialized.OrderedDictionary]::new(); $first = @($good.Keys)[0]; $few[$first] = $good[$first]
                $manifest = [ordered]@{ SchemaVersion = 1; Kind = 'Convert'; Environment = 'LAB'; CreatedUtc = 'x'; ToolVersion = '3'; BatchId = 'aaaaaaaa11111111aaaaaaaa11111111'; NextCommand = ''
                    Entries = @($good.Keys | ForEach-Object { [ordered]@{ Name = $_; Size = $good[$_].Length; Sha256 = (Get-TpSha $good[$_]) } }) }
                $args1 = @{ Path = $zipPath; Entries = $few; Manifest = $manifest } }
            'duplicate entry' { $stream = [IO.File]::Open($zipPath, [IO.FileMode]::CreateNew); $zip = New-Object IO.Compression.ZipArchive($stream, 'Create')
                $manifest = [ordered]@{ SchemaVersion = 1; Kind = 'Convert'; Environment = 'LAB'; CreatedUtc = 'x'; ToolVersion = '3'; BatchId = 'aaaaaaaa11111111aaaaaaaa11111111'; NextCommand = ''
                    Entries = @([ordered]@{ Name = 'Batch-aaaaaaaa11111111aaaaaaaa11111111/a.json'; Size = 2; Sha256 = (Get-TpSha (Get-TpBytes '{}')) }) }
                foreach ($n in 'transfer.json', 'Batch-aaaaaaaa11111111aaaaaaaa11111111/a.json', 'Batch-aaaaaaaa11111111aaaaaaaa11111111/A.JSON') {
                    $s = $zip.CreateEntry($n).Open(); $b = Get-TpBytes $(if ($n -eq 'transfer.json') { $manifest | ConvertTo-Json -Depth 6 } else { '{}' }); $s.Write($b, 0, $b.Length); $s.Dispose() }
                $zip.Dispose(); $stream.Dispose(); [IO.File]::WriteAllText($zipPath + '.sha256', (Get-FileHash -LiteralPath $zipPath).Hash.ToLowerInvariant()); $args1 = $null }
            'path traversal' { $e = [Collections.Specialized.OrderedDictionary]::new(); $e['../evil.txt'] = (Get-TpBytes 'x'); $args1 = @{ Path = $zipPath; Entries = $e } }
            'traversal in the middle' { $e = [Collections.Specialized.OrderedDictionary]::new(); $e['Batch-aaaaaaaa11111111aaaaaaaa11111111/../evil.txt'] = (Get-TpBytes 'x'); $args1 = @{ Path = $zipPath; Entries = $e } }
            'absolute path' { $e = [Collections.Specialized.OrderedDictionary]::new(); $e['/Windows/evil.txt'] = (Get-TpBytes 'x'); $args1 = @{ Path = $zipPath; Entries = $e } }
            'backslash' { $e = [Collections.Specialized.OrderedDictionary]::new(); $e['Batch-aaaaaaaa11111111aaaaaaaa11111111\evil.txt'] = (Get-TpBytes 'x'); $args1 = @{ Path = $zipPath; Entries = $e } }
            'drive' { $e = [Collections.Specialized.OrderedDictionary]::new(); $e['C:/evil.txt'] = (Get-TpBytes 'x'); $args1 = @{ Path = $zipPath; Entries = $e } }
            'two separators' { $e = [Collections.Specialized.OrderedDictionary]::new(); $e['Batch-aaaaaaaa11111111aaaaaaaa11111111/sub/evil.txt'] = (Get-TpBytes 'x'); $args1 = @{ Path = $zipPath; Entries = $e } }
            'reserved device name' { $e = [Collections.Specialized.OrderedDictionary]::new(); $e['Batch-aaaaaaaa11111111aaaaaaaa11111111/CON.json'] = (Get-TpBytes 'x'); $args1 = @{ Path = $zipPath; Entries = $e } }
            'control character' { $e = [Collections.Specialized.OrderedDictionary]::new(); $e["Batch-aaaaaaaa11111111aaaaaaaa11111111/a$([char]1)b.json"] = (Get-TpBytes 'x'); $args1 = @{ Path = $zipPath; Entries = $e } }
            'trailing dot' { $e = [Collections.Specialized.OrderedDictionary]::new(); $e['Batch-aaaaaaaa11111111aaaaaaaa11111111/evil.'] = (Get-TpBytes 'x'); $args1 = @{ Path = $zipPath; Entries = $e } }
            'wrong folder prefix' { $e = [Collections.Specialized.OrderedDictionary]::new(); $e['Other-aaaaaaaa11111111aaaaaaaa11111111/a.json'] = (Get-TpBytes 'x'); $args1 = @{ Path = $zipPath; Entries = $e } }
            'declared size differs' { $manifest = [ordered]@{ SchemaVersion = 1; Kind = 'Convert'; Environment = 'LAB'; CreatedUtc = 'x'; ToolVersion = '3'; BatchId = 'aaaaaaaa11111111aaaaaaaa11111111'; NextCommand = ''
                    Entries = @($good.Keys | ForEach-Object { [ordered]@{ Name = $_; Size = 5; Sha256 = (Get-TpSha $good[$_]) } }) }
                $args1 = @{ Path = $zipPath; Entries = $good; Manifest = $manifest } }
            'wrong Environment' { $args1 = @{ Path = $zipPath; Entries = $good; Environment = 'OTHER' } }
            'sidecar missing' { $args1 = @{ Path = $zipPath; Entries = $good; NoSidecar = $true } }
            'sidecar mismatch' { $args1 = $null }
            'manifest missing' { $args1 = @{ Path = $zipPath; Entries = $good; NoManifest = $true } }
            'manifest not JSON' { $args1 = @{ Path = $zipPath; Entries = $good; RawManifestText = '{ not json' } }
            'manifest schema 2' { $manifest = [ordered]@{ SchemaVersion = 2; Kind = 'Convert'; Environment = 'LAB'; CreatedUtc = 'x'; ToolVersion = '3'; BatchId = 'aaaaaaaa11111111aaaaaaaa11111111'; NextCommand = ''
                    Entries = @($good.Keys | ForEach-Object { [ordered]@{ Name = $_; Size = $good[$_].Length; Sha256 = (Get-TpSha $good[$_]) } }) }
                $args1 = @{ Path = $zipPath; Entries = $good; Manifest = $manifest } }
            'unknown kind' { $args1 = @{ Path = $zipPath; Entries = $good; Kind = 'Purge' } }
            'kind and folder prefix disagree' { $args1 = @{ Path = $zipPath; Entries = $good; Kind = 'Finalize' } }
            'batch folder not in package' { $args1 = @{ Path = $zipPath; Entries = $good; BatchId = 'bbbbbbbb22222222bbbbbbbb22222222' } }
            'manifest lists transfer.json' { $manifest = [ordered]@{ SchemaVersion = 1; Kind = 'Convert'; Environment = 'LAB'; CreatedUtc = 'x'; ToolVersion = '3'; BatchId = 'aaaaaaaa11111111aaaaaaaa11111111'; NextCommand = ''
                    Entries = @([ordered]@{ Name = 'transfer.json'; Size = 1; Sha256 = (Get-TpSha (Get-TpBytes 'x')) }) }
                $args1 = @{ Path = $zipPath; Entries = $good; Manifest = $manifest } }
            'not a zip' { [IO.File]::WriteAllBytes($zipPath, [byte[]](1..500 | ForEach-Object { [byte]($_ % 251) })); [IO.File]::WriteAllText($zipPath + '.sha256', (Get-FileHash -LiteralPath $zipPath).Hash.ToLowerInvariant()); $args1 = $null }
        }
        if ($null -ne $args1) { New-TpZip @args1 }
        if ($Name -eq 'sidecar mismatch') { New-TpZip -Path $zipPath -Entries $good; [IO.File]::WriteAllText($zipPath + '.sha256', ('0' * 64)) }
        $environment = if ($Name -eq 'wrong Environment') { 'LAB_X' } else { 'LAB' }
        if ($Name -eq 'wrong Environment') { $environment = 'LAB' }
        $info = Get-PraTransferPackage -Path $zipPath -Environment $environment
        $info.Valid | Should -BeFalse
        $info.Error | Should -Match ([regex]::Escape($Match)) -Because $info.Error
        { Import-PraTransferPackage -Path $zipPath -BackupFolder $w.Backups -Environment $environment } | Should -Throw
        (Get-TpChildren $w.Backups) | Should -Be 0 -Because 'verification precedes any write'
    }
    It 'refuses an entry above the per-entry size limit from its declared length, before reading it' {
        $w = New-TpWork
        $zipPath = Join-Path $w.Root 'bomb.zip'
        $stream = [IO.File]::Open($zipPath, [IO.FileMode]::CreateNew)
        $zip = New-Object IO.Compression.ZipArchive($stream, 'Create')
        $entry = $zip.CreateEntry('Batch-aaaaaaaa11111111aaaaaaaa11111111/zeros.bin', [IO.Compression.CompressionLevel]::Fastest); $s = $entry.Open()
        $chunk = New-Object byte[] 1048576; for ($i = 0; $i -lt 257; $i++) { $s.Write($chunk, 0, $chunk.Length) }
        $s.Dispose(); $zip.Dispose(); $stream.Dispose()
        [IO.File]::WriteAllText($zipPath + '.sha256', (Get-FileHash -LiteralPath $zipPath).Hash.ToLowerInvariant())
        (Get-Item -LiteralPath $zipPath).Length | Should -BeLessThan 5MB
        $info = Get-PraTransferPackage -Path $zipPath -Environment LAB
        $info.Valid | Should -BeFalse
        $info.Error | Should -Match 'too large'
        (Get-TpChildren $w.Backups) | Should -Be 0
    }
    It 'refuses a package whose entries together exceed the total size limit' {
        $w = New-TpWork
        $zipPath = Join-Path $w.Root 'total.zip'
        $stream = [IO.File]::Open($zipPath, [IO.FileMode]::CreateNew)
        $zip = New-Object IO.Compression.ZipArchive($stream, 'Create')
        $chunk = New-Object byte[] 1048576
        foreach ($n in 1..3) {
            $entry = $zip.CreateEntry("Batch-aaaaaaaa11111111aaaaaaaa11111111/z$n.bin", [IO.Compression.CompressionLevel]::Fastest); $s = $entry.Open()
            for ($i = 0; $i -lt 200; $i++) { $s.Write($chunk, 0, $chunk.Length) }
            $s.Dispose()
        }
        $zip.Dispose(); $stream.Dispose()
        [IO.File]::WriteAllText($zipPath + '.sha256', (Get-FileHash -LiteralPath $zipPath).Hash.ToLowerInvariant())
        $info = Get-PraTransferPackage -Path $zipPath -Environment LAB
        $info.Valid | Should -BeFalse
        $info.Error | Should -Match 'too large|zip bomb'
    }
    It 'accepts an upper-case sidecar and surrounding spaces, and refuses a sidecar that is not a SHA-256' {
        $w = New-TpWork
        $folder = New-TpFolder $w.Source 'Batch-8547ab040273474ba2c720ade6240fc5' @{ 'a.json' = (Get-TpBytes '{}') }
        $made = New-PraTransferPackage -Kind Convert -Environment LAB -BatchId 8547ab040273474ba2c720ade6240fc5 -Folders $folder -OutboxFolder $w.Outbox
        [IO.File]::WriteAllText($made.Sidecar, "  $((Get-FileHash -LiteralPath $made.Path).Hash.ToUpperInvariant())`r`n")
        (Get-PraTransferPackage -Path $made.Path -Environment LAB).Valid | Should -BeTrue
        [IO.File]::WriteAllText($made.Sidecar, 'not a hash')
        (Get-PraTransferPackage -Path $made.Path -Environment LAB).Valid | Should -BeFalse
    }
    It 'detects a byte flipped inside the package through the sidecar' {
        $w = New-TpWork
        $folder = New-TpFolder $w.Source 'Batch-8547ab040273474ba2c720ade6240fc5' @{ 'a.json' = (Get-TpBytes '{"a":"b"}'); 'raw.bin' = [byte[]](1..2000 | ForEach-Object { [byte]($_ % 251) }) }
        $made = New-PraTransferPackage -Kind Convert -Environment LAB -BatchId 8547ab040273474ba2c720ade6240fc5 -Folders $folder -OutboxFolder $w.Outbox
        $bytes = [IO.File]::ReadAllBytes($made.Path); $bytes[$bytes.Length - 60] = [byte]($bytes[$bytes.Length - 60] -bxor 0xFF); [IO.File]::WriteAllBytes($made.Path, $bytes)
        $info = Get-PraTransferPackage -Path $made.Path -Environment LAB
        $info.Valid | Should -BeFalse
        $info.Error | Should -Match 'does not match its .sha256'
    }
    It 'accepts an identical existing folder and refuses a different one (changed, extra and missing file) without creating the other folders' {
        $w = New-TpWork
        $a = New-TpFolder $w.Source 'Batch-8547ab040273474ba2c720ade6240fc5' @{ 'a.json' = (Get-TpBytes '{"a":1}'); 'b.bin' = [byte[]](1..100) }
        $b = New-TpFolder $w.Source 'Batch-11112222333344445555666677778888' @{ 'c.json' = (Get-TpBytes '{"c":1}') }
        $made = New-PraTransferPackage -Kind Recover -Environment LAB -BatchId 8547ab040273474ba2c720ade6240fc5 -Folders @($a, $b) -OutboxFolder $w.Outbox
        # Only the first folder exists, identical: accepted, the second is created.
        Copy-Item -LiteralPath $a -Destination $w.Backups -Recurse
        $result = Import-PraTransferPackage -Path $made.Path -BackupFolder $w.Backups -Environment LAB
        $result.Existing.Count | Should -Be 1
        $result.Created.Count | Should -Be 1
        Remove-Item -LiteralPath (Join-Path $w.Backups 'Batch-11112222333344445555666677778888') -Recurse -Force
        foreach ($case in @('changed', 'extra', 'missing')) {
            $target = Join-Path $w.Backups 'Batch-8547ab040273474ba2c720ade6240fc5'
            Remove-Item -LiteralPath $target -Recurse -Force; Copy-Item -LiteralPath $a -Destination $w.Backups -Recurse
            switch ($case) {
                'changed' { [IO.File]::WriteAllText((Join-Path $target 'a.json'), '{"a":2}') }
                'extra' { [IO.File]::WriteAllText((Join-Path $target 'extra.txt'), 'x') }
                'missing' { Remove-Item -LiteralPath (Join-Path $target 'b.bin') }
            }
            { Import-PraTransferPackage -Path $made.Path -BackupFolder $w.Backups -Environment LAB } | Should -Throw '*already exists and is different*'
            Test-Path -LiteralPath (Join-Path $w.Backups 'Batch-11112222333344445555666677778888') | Should -BeFalse -Because "${case}: nothing is created when one folder is refused"
        }
    }
    It 'removes the folders it created when a later folder cannot be extracted' {
        $w = New-TpWork
        $a = New-TpFolder $w.Source 'Batch-8547ab040273474ba2c720ade6240fc5' @{ 'a.json' = (Get-TpBytes '{"a":1}') }
        $b = New-TpFolder $w.Source 'Batch-11112222333344445555666677778888' @{ 'c.json' = (Get-TpBytes '{"c":1}') }
        $made = New-PraTransferPackage -Kind Recover -Environment LAB -BatchId 8547ab040273474ba2c720ade6240fc5 -Folders @($a, $b) -OutboxFolder $w.Outbox
        $script:TpCalls = 0
        Mock -ModuleName PRA.Common New-PraPrivateDirectorySecurity {
            $global:TpCalls++
            if ($global:TpCalls -ge 2) { throw 'simulated failure on the second folder' }
            $acl = New-Object Security.AccessControl.DirectorySecurity; $acl.SetAccessRuleProtection($true, $false)
            $acl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule([Security.Principal.WindowsIdentity]::GetCurrent().User, 'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow'))); $acl
        }
        $global:TpCalls = 0
        { Import-PraTransferPackage -Path $made.Path -BackupFolder $w.Backups -Environment LAB } | Should -Throw '*simulated failure*'
        $global:TpCalls | Should -BeGreaterOrEqual 2
        @(Get-ChildItem -LiteralPath $w.Backups -Directory | Where-Object { $_.Name.StartsWith('Batch-', [StringComparison]::Ordinal) }).Count | Should -Be 0 -Because 'the first folder created by the failed import is removed'
    }
    It 'checks the expected kind before reading the content' {
        $w = New-TpWork
        $a = New-TpFolder $w.Source 'Batch-8547ab040273474ba2c720ade6240fc5' @{ 'a.json' = (Get-TpBytes '{"a":1}') }
        $made = New-PraTransferPackage -Kind Convert -Environment LAB -BatchId 8547ab040273474ba2c720ade6240fc5 -Folders $a -OutboxFolder $w.Outbox
        { Import-PraTransferPackage -Path $made.Path -BackupFolder $w.Backups -Environment LAB -ExpectedKind Recover } | Should -Throw '*Convert package*'
        (Import-PraTransferPackage -Path $made.Path -BackupFolder $w.Backups -Environment LAB -ExpectedKind Convert).Kind | Should -BeExactly 'Convert'
    }
}

Describe 'Release 3.0.0 - engine events for the progress view (plan, step, item, progress, result)' -Tag 'EngineEvents' {
    BeforeEach {
        $oldEventPath = $env:PRA_EVENT_FILE
        $runtime = New-GateRuntime -Name 'engine-events'
        $env:PRA_EVENT_FILE = Join-Path $runtime.Root 'engine.events.jsonl'
        Import-Module (Join-Path $global:PraGate.Package 'module\PRA.Common.psm1') -Force -Global
    }
    AfterEach { $env:PRA_EVENT_FILE = $oldEventPath }

    It 'writes a progress event with every field, and nothing without PRA_EVENT_FILE' {
        $context = @{ StepIndex = 3; StepTotal = 5; Issues = (New-Object 'Collections.Generic.List[object]'); Warnings = 0; LogFile = '' }
        Write-PraProgress -Context $context -Text 'Waiting for the mailbox' -Current 30 -Total 3600 -Attempt 2 -MaxAttempts 61 -NextInSeconds 60
        $event = [IO.File]::ReadAllText($env:PRA_EVENT_FILE) | ConvertFrom-Json -DateKind String
        $event.kind | Should -BeExactly 'progress'
        $event.stepId | Should -BeExactly 's3'
        ($event.current, $event.total, $event.attempt, $event.maxAttempts, $event.nextInSeconds) -join ',' | Should -BeExactly '30,3600,2,61,60'
        $event.text | Should -BeExactly 'Waiting for the mailbox'
        $env:PRA_EVENT_FILE = ''
        @(Write-PraProgress -Context $context -Text 'x').Count | Should -Be 0
    }
    It 'closes each step with ok, warn or fail and announces a skipped step at once' {
        $context = @{ StepIndex = 0; StepTotal = 4; Issues = (New-Object 'Collections.Generic.List[object]'); Warnings = 0; LogFile = ''; Action = 'Convert'; CurrentPhase = '' }
        Write-PraStep -Context $context -Title 'One' | Out-Null
        Write-PraItem -Context $context -Status Ok -Text 'fine' -Detail 'more'
        Write-PraStep -Context $context -Title 'Two' | Out-Null
        Write-PraItem -Context $context -Status Warn -Text 'careful'
        Write-PraStep -Context $context -Title 'Three' | Out-Null
        Add-PraIssue $context 'broken'
        Write-PraStep -Context $context -Title 'Four' -Skipped | Out-Null
        InModuleScope PRA.Common -Parameters @{ Ctx = $context } { Close-PraStepEvent -Context $Ctx }
        $events = @(Get-Content -LiteralPath $env:PRA_EVENT_FILE -Encoding UTF8 | ForEach-Object { $_ | ConvertFrom-Json -DateKind String })
        $steps = @($events | Where-Object kind -eq 'step')
        ($steps | ForEach-Object { '{0}:{1}' -f $_.id, $_.state }) -join ',' | Should -BeExactly 's1:running,s1:ok,s2:running,s2:warn,s3:running,s3:fail,s4:skipped'
        $steps[0].endedUtc | Should -BeNullOrEmpty
        $steps[1].startedUtc | Should -Be $steps[0].startedUtc
        $steps[1].endedUtc | Should -Not -BeNullOrEmpty
        $steps[6].startedUtc | Should -Be $steps[6].endedUtc
        $steps[0].index | Should -Be 1
        $steps[0].total | Should -Be 4
        $steps[0].title | Should -BeExactly 'One'
        $items = @($events | Where-Object kind -eq 'item')
        $items[0].stepId | Should -BeExactly 's1'
        $items[0].detail | Should -BeExactly 'more'
        $items[1].stepId | Should -BeExactly 's2'
        $items[1].detail | Should -BeExactly ''
    }
    It 'announces the plan before the first step and closes every step of a Convert AD Preview, the transfer package step being skipped' {
        $run = Invoke-GateProcess $runtime @{Action='Convert';Phase='AD';Mode='Preview';ConfigPath=$runtime.ConfigPath}
        $run.ExitCode | Should -Be 0
        $events = @(Get-Content -LiteralPath $env:PRA_EVENT_FILE -Encoding UTF8 | ForEach-Object { $_ | ConvertFrom-Json -DateKind String })
        $kinds = @($events.kind)
        $plans = @($events | Where-Object kind -eq 'plan')
        $plans.Count | Should -Be 1
        [array]::IndexOf($kinds, 'plan') | Should -BeLessThan ([array]::IndexOf($kinds, 'step'))
        $plan = $plans[0]
        @($plan.steps | ForEach-Object id) -join ',' | Should -BeExactly 's1,s2,s3,s4,s5'
        @($plan.steps | ForEach-Object label) | Should -Contain 'Creating the transfer package'
        $plan.steps[-1].label | Should -BeExactly 'Creating the transfer package'
        $plan.steps[0].PSObject.Properties.Name | Should -Contain 'count'
        $final = @{}
        foreach ($step in @($events | Where-Object kind -eq 'step')) { $final[$step.id] = $step }
        $final.Keys.Count | Should -Be 5
        foreach ($step in $final.Values) { $step.state | Should -BeIn @('ok', 'warn', 'skipped'); $step.endedUtc | Should -Not -BeNullOrEmpty }
        $final['s5'].state | Should -BeExactly 'skipped'
        $final['s5'].title | Should -BeExactly 'Creating the transfer package'
        foreach ($item in @($events | Where-Object kind -eq 'item')) { $item.PSObject.Properties.Name | Should -Contain 'stepId'; $item.PSObject.Properties.Name | Should -Contain 'detail' }
        $result = @($events | Where-Object kind -eq 'result')[0]
        $result.transferPackage | Should -BeExactly ''
        $result.transferPackageKind | Should -BeExactly ''
        @($result.configOverrides).Count | Should -Be 0
        $run.Output | Should -Match 'Creating the transfer package'
        @(Get-GateWrites $runtime).Count | Should -Be 0
    }
    It 'reports a failed run with its last step failed' {
        $run = Invoke-GateProcess $runtime @{Action='Recover';Phase='AD';Mode='Preview';Batch='deadbeef';ConfigPath=$runtime.ConfigPath}
        $run.ExitCode | Should -Be 1
        $events = @(Get-Content -LiteralPath $env:PRA_EVENT_FILE -Encoding UTF8 | ForEach-Object { $_ | ConvertFrom-Json -DateKind String })
        $running = @($events | Where-Object { $_.kind -eq 'step' -and $_.state -eq 'running' })
        $closing = @($events | Where-Object { $_.kind -eq 'step' -and $_.state -eq 'fail' })
        $closing.Count | Should -Be 1
        $closing[0].id | Should -BeExactly $running[-1].id
    }
}

Describe 'Release 3.0.0 - transfer package through the real main (hand-off and import)' -Tag 'TransferPackageMain' {
    BeforeEach {
        $oldEventPath = $env:PRA_EVENT_FILE
        $runtime = New-GateRuntime -Name 'tp-main-ad'
        $env:PRA_EVENT_FILE = Join-Path $runtime.Root 'engine.events.jsonl'
        $script:Cloud = $null
        function script:Get-TpEvents($Path) { @(Get-Content -LiteralPath $Path -Encoding UTF8 | ForEach-Object { $_ | ConvertFrom-Json -DateKind String }) }
        function script:New-TpCloudRuntime([string]$Name) {
            $cloudRuntime = New-GateRuntime -Name $Name
            $cloudRuntime
        }
    }
    AfterEach { $env:PRA_EVENT_FILE = $oldEventPath }

    It 'Convert -Phase AD -Mode Apply writes one verified package in the private Outbox, and the cloud server runs from it (<Spelling>)' -ForEach @(
        @{ Spelling = 'official'; Action = 'Convert'; Mode = 'Apply'; Phase = 'Cloud'; ByName = $false }
        @{ Spelling = 'lower case, by file name from the Inbox'; Action = 'convert'; Mode = 'apply'; Phase = 'cloud'; ByName = $true }
        @{ Spelling = 'upper case'; Action = 'CONVERT'; Mode = 'APPLY'; Phase = 'CLOUD'; ByName = $false }
    ) {
        $run = Invoke-GateProcess $runtime @{Action='Convert';Phase='AD';Mode='Apply';Force=$true;ConfigPath=$runtime.ConfigPath} -TimeoutSeconds 120
        $run.ExitCode | Should -BeIn @(0, 2)
        $events = Get-TpEvents $env:PRA_EVENT_FILE
        $result = @($events | Where-Object kind -eq 'result')[0]
        $result.transferPackageKind | Should -BeExactly 'Convert'
        $zip = $result.transferPackage
        $zip | Should -Match 'PRA-SYNTHETIC_GATE-Convert-[0-9a-f]{8}-for-Cloud\.zip$'
        Test-Path -LiteralPath $zip -PathType Leaf | Should -BeTrue
        Split-Path $zip -Parent | Should -BeExactly (Join-Path $runtime.State.BackupFolder 'Outbox')
        Test-Path -LiteralPath ($zip + '.sha256') | Should -BeTrue
        $run.MainResult.TransferPackage | Should -BeExactly $zip
        ($run.MainResult.NextSteps -join "`n") | Should -Match 'Copy these two files, together in the same folder, to the cloud server \(anywhere\): .*PRA-SYNTHETIC_GATE-Convert-[0-9a-f]{8}-for-Cloud\.zip and .*PRA-SYNTHETIC_GATE-Convert-[0-9a-f]{8}-for-Cloud\.zip\.sha256\. Then run there:'
        ($run.MainResult.NextSteps -join "`n") | Should -Match "-Batch 'PRA-SYNTHETIC_GATE-Convert-[0-9a-f]{8}-for-Cloud\.zip'"
        ($run.MainResult.NextSteps -join "`n") | Should -Not -Match 'Copy the folder'
        $steps = @($events | Where-Object { $_.kind -eq 'step' -and $_.title -eq 'Creating the transfer package' })
        ($steps.state -join ',') | Should -BeExactly 'running,ok'
        @($events | Where-Object { $_.kind -eq 'item' -and $_.text -like 'Transfer package * written (* checksums verified)' }).Count | Should -Be 1
        $info = Get-PraTransferPackage -Path $zip -Environment SYNTHETIC_GATE
        $info.Valid | Should -BeTrue -Because $info.Error
        $info.Kind | Should -BeExactly 'Convert'
        $info.Folders.Count | Should -Be 1
        # The cloud server: another machine, nothing but the package.
        $cloud = New-GateRuntime -Name 'tp-main-cloud'
        $target = $zip
        if ($ByName) {
            $inbox = Join-Path $cloud.State.BackupFolder 'Inbox'; $null = New-Item -ItemType Directory -Path $inbox
            Copy-Item -LiteralPath $zip -Destination $inbox; Copy-Item -LiteralPath ($zip + '.sha256') -Destination $inbox
            $target = [IO.Path]::GetFileName($zip)
        } else {
            $drop = Join-Path $cloud.Root 'dropped'; $null = New-Item -ItemType Directory -Path $drop
            Copy-Item -LiteralPath $zip -Destination $drop; Copy-Item -LiteralPath ($zip + '.sha256') -Destination $drop
            $target = Join-Path $drop ([IO.Path]::GetFileName($zip))
        }
        Remove-Item -LiteralPath $env:PRA_EVENT_FILE -Force
        $env:PRA_EVENT_FILE = Join-Path $cloud.Root 'engine.events.jsonl'
        $second = Invoke-GateProcess $cloud @{Action=$Action;Mode=$Mode;Phase=$Phase;Force=$true;ConfigPath=$cloud.ConfigPath;Batch=$target} -TimeoutSeconds 120
        (@($second.MainResult.Issues | ForEach-Object { [string]$_.Message }) -join ' ') | Should -Not -Match 'Transfer package|does not match|AD proof'
        $second.ExitCode | Should -BeIn @(0, 2)
        @($second.Events | Where-Object Operation -eq 'CloudPhase-SyntheticBarrier').Count | Should -Be 1
        $folder = Join-Path $cloud.State.BackupFolder ('Batch-' + $info.BatchId)
        Test-Path -LiteralPath $folder -PathType Container | Should -BeTrue
        ([IO.FileSystemAclExtensions]::GetAccessControl((New-Object IO.DirectoryInfo $folder))).AreAccessRulesProtected | Should -BeTrue
        @(Get-ChildItem -LiteralPath $folder -File | Where-Object Name -like 'State-*.json').Count | Should -Be 1
        $second.Output | Should -Match 'Transfer package .* verified'
        @(Get-GateWrites $cloud).Count | Should -Be 0
    }
    It 'refuses a Convert package for a Recover cloud phase, a tampered package and a package of another Environment, writing nothing' {
        $run = Invoke-GateProcess $runtime @{Action='Convert';Phase='AD';Mode='Apply';Force=$true;ConfigPath=$runtime.ConfigPath} -TimeoutSeconds 120
        $zip = @(Get-TpEvents $env:PRA_EVENT_FILE | Where-Object kind -eq 'result')[0].transferPackage
        $cloud = New-GateRuntime -Name 'tp-main-refused'
        $before = @(Get-ChildItem -LiteralPath $cloud.State.BackupFolder -Recurse -Force).Count
        $wrongKind = Invoke-GateProcess $cloud @{Action='Recover';Mode='Apply';Phase='Cloud';Force=$true;ConfigPath=$cloud.ConfigPath;Batch=$zip}
        $wrongKind.ExitCode | Should -Be 1
        ($wrongKind.MainResult.Issues.Message -join ' ') | Should -Match 'this is a Convert package, a Recover package is needed'
        # Tampered: flip a byte, the sidecar no longer matches.
        $bad = Join-Path $cloud.Root 'bad.zip'
        $bytes = [IO.File]::ReadAllBytes($zip); $bytes[$bytes.Length - 70] = [byte]($bytes[$bytes.Length - 70] -bxor 0x55); [IO.File]::WriteAllBytes($bad, $bytes)
        Copy-Item -LiteralPath ($zip + '.sha256') -Destination ($bad + '.sha256')
        $tampered = Invoke-GateProcess $cloud @{Action='Convert';Mode='Apply';Phase='Cloud';Force=$true;ConfigPath=$cloud.ConfigPath;Batch=$bad}
        $tampered.ExitCode | Should -Be 1
        ($tampered.MainResult.Issues.Message -join ' ') | Should -Match 'does not match its .sha256'
        # Another Environment.
        Set-GateConfigText $cloud { param($t) $t.Replace("Environment='SYNTHETIC_GATE'", "Environment='OTHER_ENV'") }
        $other = Invoke-GateProcess $cloud @{Action='Convert';Mode='Preview';Phase='Cloud';ConfigPath=$cloud.ConfigPath;Batch=$zip}
        $other.ExitCode | Should -Be 1
        ($other.MainResult.Issues.Message -join ' ') | Should -Match "Environment 'SYNTHETIC_GATE'"
        @(Get-ChildItem -LiteralPath $cloud.State.BackupFolder -Recurse -Force | Where-Object { $_.FullName -notlike '*\Outbox*' }).Count | Should -Be $before
        @(Get-GateWrites $cloud).Count | Should -Be 0
    }
    It 'Recover -Phase AD -Mode Apply packs the new Recover batch and the original Convert batch; the cloud server runs from the package' {
        $env:PRA_GATE_STATE = $runtime.StatePath
        $env:PSModulePath = $runtime.Modules + ';' + (Join-Path $PSHOME 'Modules')
        Remove-Module PRA.Directory -Force -ErrorAction SilentlyContinue
        Get-Module ActiveDirectory -All | Remove-Module -Force -ErrorAction Stop
        Import-Module (Join-Path $runtime.Modules 'ActiveDirectory\ActiveDirectory.psm1') -Force -Global
        Import-Module (Join-Path $global:PraGate.Package 'module\PRA.Directory.psm1') -Force -Global
        $fresh = New-GateContext $runtime
        $plans = @(New-PraPlan $fresh 'user1' 'Convert'; New-PraPlan $fresh 'user2' 'Convert')
        $source = Invoke-PraAdBatch $fresh $plans 'Convert'
        [IO.File]::WriteAllText($runtime.StatePath, [Management.Automation.PSSerializer]::Serialize($global:PraGateAd, 35))
        Remove-Item -LiteralPath $runtime.EventPath -Force -ErrorAction SilentlyContinue
        $run = Invoke-GateProcess $runtime @{Action='Recover';Phase='AD';Mode='Apply';Force=$true;ConfigPath=$runtime.ConfigPath;Batch=$source.Path} -TimeoutSeconds 120
        $run.ExitCode | Should -BeIn @(0, 2) -Because ($run.Output + $run.Error)
        $result = @(Get-TpEvents $env:PRA_EVENT_FILE | Where-Object kind -eq 'result')[0]
        $result.transferPackageKind | Should -BeExactly 'Recover'
        $zip = $result.transferPackage
        $zip | Should -Match 'PRA-SYNTHETIC_GATE-Recover-[0-9a-f]{8}-for-Cloud\.zip$'
        $info = Get-PraTransferPackage -Path $zip -Environment SYNTHETIC_GATE
        $info.Valid | Should -BeTrue -Because $info.Error
        $info.Folders.Count | Should -Be 2
        $info.Folders | Should -Contain (Split-Path (Split-Path $source.Path -Parent) -Leaf)
        $cloud = New-GateRuntime -Name 'tp-main-recover-cloud'
        $drop = Join-Path $cloud.Root 'dropped'; $null = New-Item -ItemType Directory -Path $drop
        Copy-Item -LiteralPath $zip, ($zip + '.sha256') -Destination $drop
        $second = Invoke-GateProcess $cloud @{Action='Recover';Mode='Apply';Phase='Cloud';Force=$true;ConfigPath=$cloud.ConfigPath;Batch=(Join-Path $drop ([IO.Path]::GetFileName($zip)))} -TimeoutSeconds 120
        $messages = ($second.MainResult.Issues.Message -join ' ')
        # The proof and the original Convert source were found in the extracted folders (the synthetic cloud then confirms nothing).
        $messages | Should -Match 'Cloud deprovisioning or AD proof not confirmed'
        $messages | Should -Not -Match 'Transfer package|ORIGINAL Convert|not in'
        foreach ($folder in $info.Folders) { Test-Path -LiteralPath (Join-Path $cloud.State.BackupFolder $folder) -PathType Container | Should -BeTrue }
        @(Get-GateWrites $cloud).Count | Should -Be 0
    }
    It 'Preview of a Convert cloud phase from a package verifies it and reads it from a private temporary folder: nothing is written to the backup folder' {
        $null = Invoke-GateProcess $runtime @{Action='Convert';Phase='AD';Mode='Apply';Force=$true;ConfigPath=$runtime.ConfigPath} -TimeoutSeconds 120
        $zip = @(Get-TpEvents $env:PRA_EVENT_FILE | Where-Object kind -eq 'result')[0].transferPackage
        $cloud = New-GateRuntime -Name 'tp-main-preview'
        $env:PRA_EVENT_FILE = Join-Path $cloud.Root 'engine.events.jsonl'
        $second = Invoke-GateProcess $cloud @{Action='Convert';Mode='Preview';Phase='Cloud';ConfigPath=$cloud.ConfigPath;Batch=$zip}
        $second.ExitCode | Should -BeIn @(0, 2)
        $second.Output | Should -Match 'read from a private temporary folder, deleted at the end'
        $second.Output | Should -Match 'Nothing was written to the backup folder'
        $second.Output | Should -Match '1 folder\(s\) extracted'
        @(Get-ChildItem -LiteralPath $cloud.State.BackupFolder -Directory -Force -ErrorAction SilentlyContinue | Where-Object { $_.Name -like 'Batch-*' -or $_.Name -like '.importing-*' }).Count | Should -Be 0 -Because 'a Preview leaves no batch folder behind'
        @(Get-ChildItem -LiteralPath (Join-Path $cloud.Root 'logs') -Directory -Filter 'preview-*' -ErrorAction SilentlyContinue).Count | Should -Be 0 -Because 'the temporary Preview folder is deleted'
        # Run twice: the same result, still nothing written.
        $third = Invoke-GateProcess $cloud @{Action='Convert';Mode='Preview';Phase='Cloud';ConfigPath=$cloud.ConfigPath;Batch=$zip}
        $third.ExitCode | Should -BeIn @(0, 2)
        $third.Output | Should -Match '1 folder\(s\) extracted'
        @(Get-ChildItem -LiteralPath $cloud.State.BackupFolder -Directory -Force -ErrorAction SilentlyContinue | Where-Object { $_.Name -like 'Batch-*' }).Count | Should -Be 0
    }
}

Describe 'Release 3.0.0 - Recover cloud phase writes the Finalize transfer package' -Tag 'TransferPackageMain' {
    It 'packs the Finalize folder in one ZIP for the AD server and the AD server can import it' {
        $oldEventPath = $env:PRA_EVENT_FILE
        try {
            $runtime = New-GateRuntime -Name 'tp-finalize' -Shared13 -Case CloudConfirmed13
            $env:PRA_GATE_STATE = $runtime.StatePath; $env:PSModulePath = $runtime.Modules + ';' + (Join-Path $PSHOME 'Modules')
            Import-Module ActiveDirectory -Force -Global
            $context = New-GateContext $runtime
            $plans = @(1..13 | ForEach-Object { New-PraPlan $context ('user' + $_) 'Convert' })
            $source = Invoke-PraAdBatch $context $plans 'Convert'
            [IO.File]::WriteAllText($runtime.StatePath, [Management.Automation.PSSerializer]::Serialize($global:PraGateAd, 35))
            $recover = Invoke-GateProcess $runtime @{Action='Recover';Mode='Apply';Phase='AD';Force=$true;ConfigPath=$runtime.ConfigPath;Batch=$source.Path} -TimeoutSeconds 120
            $recover.ExitCode | Should -Be 2
            $recoverPath = @(Get-ChildItem -LiteralPath $runtime.State.BackupFolder -Recurse -File -Filter 'Recover-*.json')[0].FullName
            $env:PRA_EVENT_FILE = Join-Path $runtime.Root 'finalize-events.jsonl'
            $cloud = Invoke-GateProcess $runtime @{Action='Recover';Mode='Apply';Phase='Cloud';Force=$true;ConfigPath=$runtime.ConfigPath;Batch=$recoverPath} -TimeoutSeconds 120
            $cloud.ExitCode | Should -Be 2
            $result = @(Get-Content -LiteralPath $env:PRA_EVENT_FILE -Encoding UTF8 | ForEach-Object { $_ | ConvertFrom-Json -DateKind String } | Where-Object kind -eq 'result')[0]
            $result.transferPackageKind | Should -BeExactly 'Finalize'
            $result.transferPackage | Should -Match 'PRA-SYNTHETIC_GATE-Finalize-[0-9a-f]{8}-for-AD\.zip$'
            ($cloud.MainResult.NextSteps -join "`n") | Should -Match 'to the AD server \(anywhere\): .*for-AD\.zip and .*for-AD\.zip\.sha256\.'
            ($cloud.MainResult.NextSteps -join "`n") | Should -Match "-Action Finalize .*-Batch 'PRA-SYNTHETIC_GATE-Finalize-[0-9a-f]{8}-for-AD\.zip'"
            $info = Get-PraTransferPackage -Path $result.transferPackage -Environment SYNTHETIC_GATE
            $info.Valid | Should -BeTrue -Because $info.Error
            $info.Kind | Should -BeExactly 'Finalize'
            $info.Direction | Should -BeExactly 'ToAD'
            $info.Folders.Count | Should -Be 1
            $fresh = Join-Path $runtime.Root 'ad-server-backups'
            $imported = Import-PraTransferPackage -Path $result.transferPackage -BackupFolder $fresh -Environment SYNTHETIC_GATE -ExpectedKind Finalize
            $imported.Created.Count | Should -Be 1
            $manifestFile = @(Get-ChildItem -LiteralPath $imported.Folders[0] -File -Filter 'Finalize-*.json' | Where-Object { -not $_.Name.EndsWith('.sha256', [StringComparison]::Ordinal) })[0]
            ([IO.File]::ReadAllText($manifestFile.FullName) | ConvertFrom-Json -DateKind String).Operation | Should -BeExactly 'RecoverFinalize'
        } finally { $env:PRA_EVENT_FILE = $oldEventPath }
    }
}

Describe 'Release 3.0.0 - effective run configuration' -Tag 'EffectiveConfig' {
    BeforeAll {
        Import-Module (Join-Path $global:PraGate.Package 'module\PRA.Common.psm1') -Force -Global
    }
    BeforeEach {
        $runtime = New-GateRuntime -Name 'effective-config'
        $run = Join-Path $runtime.Root 'runfolder'
        Initialize-PraPrivateFolder $run
        $baseHash = (Get-FileHash -LiteralPath $runtime.ConfigPath).Hash
    }

    It 'writes base + overrides as a new private file that Import-PraConfiguration accepts, and never touches the base file' {
        $dest = Join-Path $run 'effective.psd1'
        $made = New-PraEffectiveConfiguration -BasePath $runtime.ConfigPath -Root $global:PraGate.Package -Overrides @{ Environment = 'LAB_RUN'; DomainController = 'dc02.gate.invalid'; Cloud = @{ TenantId = '20000000-0000-0000-0000-000000000002'; Organization = 'gate.onmicrosoft.com' }; Scope = @{ IncludeShared = $true } } -Destination $dest
        $made.Path | Should -BeExactly $dest
        $made.Hash | Should -BeExactly (Get-FileHash -LiteralPath $dest).Hash.ToLowerInvariant()
        @($made.Keys | Get-PraOrdinalSorted) -join ',' | Should -BeExactly 'Cloud.Organization,Cloud.TenantId,DomainController,Environment,Scope.IncludeShared'
        (Get-FileHash -LiteralPath $runtime.ConfigPath).Hash | Should -BeExactly $baseHash
        $base = Import-PraConfiguration -Path $runtime.ConfigPath -Root $global:PraGate.Package
        $effective = Import-PraConfiguration -Path $dest -Root $global:PraGate.Package
        $effective.Environment | Should -BeExactly 'LAB_RUN'
        $effective.DomainController | Should -BeExactly 'dc02.gate.invalid'
        $effective.Cloud.TenantId | Should -BeExactly '20000000-0000-0000-0000-000000000002'
        $effective.Scope.IncludeShared | Should -BeTrue
        $differences = @(Get-PraConfigurationDifference -Base $base -Effective $effective)
        @($differences.Key | Get-PraOrdinalSorted) -join ',' | Should -BeExactly 'Cloud.Organization,Cloud.TenantId,DomainController,Environment,Scope.IncludeShared'
        ($differences | Where-Object Key -eq 'Environment').Text | Should -BeExactly 'Environment: SYNTHETIC_GATE -> LAB_RUN'
        # Everything that is not overridden is identical to the base (the difference lists exactly the overridden keys, asserted above).
        [IO.File]::ReadAllText($dest) | Should -Match 'never edit - the base file is unchanged'
    }
    It 'makes the file private to the current account, SYSTEM and Administrators' {
        $dest = Join-Path $run 'effective.psd1'
        $null = New-PraEffectiveConfiguration -BasePath $runtime.ConfigPath -Root $global:PraGate.Package -Overrides @{ Environment = 'LAB_RUN' } -Destination $dest
        $acl = [IO.FileSystemAclExtensions]::GetAccessControl((New-Object IO.FileInfo $dest))
        $acl.AreAccessRulesProtected | Should -BeTrue
        $sids = @($acl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier]) | ForEach-Object { $_.IdentityReference.Value } | Get-PraOrdinalUnique -IgnoreCase | Get-PraOrdinalSorted)
        $expected = @([Security.Principal.WindowsIdentity]::GetCurrent().User.Value, 'S-1-5-18', 'S-1-5-32-544' | Get-PraOrdinalUnique -IgnoreCase | Get-PraOrdinalSorted)
        $sids -join ',' | Should -BeExactly ($expected -join ',')
    }
    It 'refuses an unknown key, a wrong type, a section mismatch, an existing destination and an invalid value, leaving no file' {
        $dest = Join-Path $run 'bad.psd1'
        { New-PraEffectiveConfiguration -BasePath $runtime.ConfigPath -Root $global:PraGate.Package -Overrides @{ Nonsense = 'x' } -Destination $dest } | Should -Throw '*unknown setting*'
        { New-PraEffectiveConfiguration -BasePath $runtime.ConfigPath -Root $global:PraGate.Package -Overrides @{ Cloud = @{ Nonsense = 'x' } } -Destination $dest } | Should -Throw '*unknown setting Cloud.Nonsense*'
        { New-PraEffectiveConfiguration -BasePath $runtime.ConfigPath -Root $global:PraGate.Package -Overrides @{ Environment = 5 } -Destination $dest } | Should -Throw '*must be text*'
        { New-PraEffectiveConfiguration -BasePath $runtime.ConfigPath -Root $global:PraGate.Package -Overrides @{ Scope = @{ IncludeShared = 'yes' } } -Destination $dest } | Should -Throw '*must be*'
        { New-PraEffectiveConfiguration -BasePath $runtime.ConfigPath -Root $global:PraGate.Package -Overrides @{ Cloud = 'x' } -Destination $dest } | Should -Throw '*section*'
        { New-PraEffectiveConfiguration -BasePath $runtime.ConfigPath -Root $global:PraGate.Package -Overrides @{ Environment = 'bad env!' } -Destination $dest } | Should -Throw '*Environment*'
        { New-PraEffectiveConfiguration -BasePath $runtime.ConfigPath -Root $global:PraGate.Package -Overrides @{ Cloud = @{ AppId = 'a1' } } -Destination $dest } | Should -Throw '*Cloud.AppId*'
        { New-PraEffectiveConfiguration -BasePath $runtime.ConfigPath -Root $global:PraGate.Package -Overrides @{ Cloud = @{ UserPrincipalName = "a`nb" } } -Destination $dest } | Should -Throw '*control character*'
        Test-Path -LiteralPath $dest | Should -BeFalse
        $good = Join-Path $run 'good.psd1'
        $null = New-PraEffectiveConfiguration -BasePath $runtime.ConfigPath -Root $global:PraGate.Package -Overrides @{ Environment = 'LAB_RUN' } -Destination $good
        { New-PraEffectiveConfiguration -BasePath $runtime.ConfigPath -Root $global:PraGate.Package -Overrides @{ Environment = 'LAB_RUN' } -Destination $good } | Should -Throw '*already exists*'
        { New-PraEffectiveConfiguration -BasePath (Join-Path $run 'missing.psd1') -Root $global:PraGate.Package -Overrides @{} -Destination (Join-Path $run 'x.psd1') } | Should -Throw '*not found*'
        (Get-FileHash -LiteralPath $runtime.ConfigPath).Hash | Should -BeExactly $baseHash
    }
    It 'keeps a value with quotes, typographic quotes, semicolons and code-like text as data' {
        $dest = Join-Path $run 'quotes.psd1'
        $marker = Join-Path $runtime.Root 'must-not-exist.txt'
        $value = "x'; New-Item -Path '$marker' -ItemType File; '" + [char]0x2018 + [char]0x2019 + '"$(Get-Date)`n'
        $null = New-PraEffectiveConfiguration -BasePath $runtime.ConfigPath -Root $global:PraGate.Package -Overrides @{ Cloud = @{ UserPrincipalName = $value }; Scope = @{ ExcludeSamAccountNames = @("o'neil", 'a;b', '$(x)') } } -Destination $dest
        $effective = Import-PraConfiguration -Path $dest -Root $global:PraGate.Package
        $effective.Cloud.UserPrincipalName | Should -BeExactly $value
        @($effective.Scope.ExcludeSamAccountNames) -join '|' | Should -BeExactly "o'neil|a;b|`$(x)"
        Test-Path -LiteralPath $marker | Should -BeFalse
    }
    It 'runs the main on the effective configuration and lists what differs from the file, in the log, the events and the result' {
        $oldEventPath = $env:PRA_EVENT_FILE
        try {
            $dest = Join-Path $run 'effective.psd1'
            $null = New-PraEffectiveConfiguration -BasePath $runtime.ConfigPath -Root $runtime.Package -Overrides @{ Polling = @{ TimeoutMinutes = 30 }; Cloud = @{ Organization = 'gate.onmicrosoft.com' } } -Destination $dest
            $env:PRA_EVENT_FILE = Join-Path $runtime.Root 'engine.events.jsonl'
            $run1 = Invoke-GateProcess $runtime @{Action='Convert';Phase='AD';Mode='Preview';ConfigPath=$dest;BaseConfigPath=$runtime.ConfigPath}
            $run1.ExitCode | Should -Be 0 -Because ($run1.Output + $run1.Error)
            $events = @(Get-Content -LiteralPath $env:PRA_EVENT_FILE -Encoding UTF8 | ForEach-Object { $_ | ConvertFrom-Json -DateKind String })
            $result = @($events | Where-Object kind -eq 'result')[0]
            @($result.configOverrides | Get-PraOrdinalSorted) -join '|' | Should -BeExactly 'Cloud.Organization: (empty) -> gate.onmicrosoft.com|Polling.TimeoutMinutes: 60 -> 30'
            $texts = @($events | Where-Object { $_.kind -eq 'item' -and $_.text -like 'Run setting:*' })
            $texts.Count | Should -Be 2
            ($texts | ForEach-Object status | Get-PraOrdinalUnique) | Should -BeExactly 'Info'
            ($texts.text -join '|') | Should -Match 'Run setting: Polling.TimeoutMinutes 30 \(configuration file: 60\)'
            $run1.Output | Should -Match 'Run setting: Cloud.Organization gate.onmicrosoft.com'
            Get-Content -LiteralPath $run1.MainResult.LogFile -Raw | Should -Match 'Run setting: Polling.TimeoutMinutes'
            (Get-FileHash -LiteralPath $runtime.ConfigPath).Hash | Should -BeExactly $baseHash
            # Without -BaseConfigPath nothing is listed.
            Remove-Item -LiteralPath $env:PRA_EVENT_FILE -Force
            $run2 = Invoke-GateProcess $runtime @{Action='Convert';Phase='AD';Mode='Preview';ConfigPath=$dest}
            $result2 = @(Get-Content -LiteralPath $env:PRA_EVENT_FILE -Encoding UTF8 | ForEach-Object { $_ | ConvertFrom-Json -DateKind String } | Where-Object kind -eq 'result')[0]
            @($result2.configOverrides).Count | Should -Be 0
            $run2.Output | Should -Not -Match 'Run setting:'
        } finally { $env:PRA_EVENT_FILE = $oldEventPath }
    }
}

Describe 'Release 3.0.0 - native process binding: SetLastError on every import, handle-list launch API' -Tag 'NativeBinding' {
    BeforeAll { Import-Module (Join-Path $global:PraGate.Package 'module\PRA.Common.psm1') -Force -Global }

    It 'returns the existing tables and the new STARTUPINFOEXW with the methods of a handle-list launch' {
        $native = Get-PraNativeProcessApi
        (@($native.Keys) | Get-PraOrdinalSorted) -join ',' | Should -BeExactly 'Api,ProcessInformation,StartupInfo,StartupInfoEx'
        foreach ($name in 'CreateProcessW', 'CreateProcessEx', 'InitializeProcThreadAttributeList', 'UpdateProcThreadAttribute', 'DeleteProcThreadAttributeList', 'GetExitCodeProcess', 'CloseHandle') {
            $native.Api.GetMethod($name) | Should -Not -BeNullOrEmpty -Because $name
        }
        $native.StartupInfoEx.GetField('StartupInfo').FieldType | Should -Be $native.StartupInfo
        $native.StartupInfoEx.GetField('lpAttributeList').FieldType | Should -Be ([IntPtr])
        [Runtime.InteropServices.Marshal]::SizeOf([Activator]::CreateInstance($native.StartupInfoEx)) | Should -Be ([Runtime.InteropServices.Marshal]::SizeOf([Activator]::CreateInstance($native.StartupInfo)) + [IntPtr]::Size)
        $native.Api.GetMethod('CreateProcessW').GetParameters()[8].ParameterType | Should -Be $native.StartupInfo.MakeByRefType()
        $native.Api.GetMethod('CreateProcessEx').GetParameters()[8].ParameterType | Should -Be $native.StartupInfoEx.MakeByRefType()
        $native.Api.GetMethod('InitializeProcThreadAttributeList').GetParameters()[3].ParameterType | Should -Be ([IntPtr].MakeByRefType())
        $native.Api.GetMethod('GetExitCodeProcess').GetParameters()[1].ParameterType | Should -Be ([uint32].MakeByRefType())
        (Get-PraNativeProcessApi).Api | Should -Be $native.Api
    }
    It 'emits every DllImport of the process and path bindings with SetLastError = true' {
        $apis = @((Get-PraNativeProcessApi).Api, (InModuleScope PRA.Common { Get-PraNativePathApi }))
        foreach ($api in $apis) {
            $methods = @($api.GetMethods([Reflection.BindingFlags]'Public,Static,DeclaredOnly'))
            $methods.Count | Should -BeGreaterThan 1
            foreach ($method in $methods) {
                $import = @($method.GetCustomAttributes($false) | Where-Object { $_ -is [Runtime.InteropServices.DllImportAttribute] })
                $import.Count | Should -Be 1 -Because $method.Name
                $import[0].SetLastError | Should -BeTrue -Because $method.Name
                $import[0].Value | Should -BeExactly 'kernel32.dll'
            }
        }
        (Get-PraNativeProcessApi).Api.GetMethod('CreateProcessEx').GetCustomAttributes($false).Where({ $_ -is [Runtime.InteropServices.DllImportAttribute] })[0].EntryPoint | Should -BeExactly 'CreateProcessW'
    }
    It 'keeps the Win32 error of a failed call (CloseHandle on an invalid handle is error 6) and spells it with Get-PraWin32ErrorText' {
        $native = Get-PraNativeProcessApi
        $result = $native.Api.GetMethod('CloseHandle').Invoke($null, [object[]]@([IntPtr]0x12345678)); $lastError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
        $result | Should -BeFalse
        $lastError | Should -Be 6
        Get-PraWin32ErrorText -Code 6 | Should -Match '^6: .+'
        Get-PraWin32ErrorText -Code 6 | Should -BeExactly ('6: ' + (New-Object ComponentModel.Win32Exception(6)).Message)
        Get-PraWin32ErrorText -Code 5 | Should -Match '^5: .+'
    }
    It 'sizes a process attribute list (the first call of a handle-list launch reports ERROR_INSUFFICIENT_BUFFER)' {
        $native = Get-PraNativeProcessApi
        $arguments = [object[]]@([IntPtr]::Zero, 1, 0, [IntPtr]::Zero)
        $result = $native.Api.GetMethod('InitializeProcThreadAttributeList').Invoke($null, $arguments); $lastError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
        $result | Should -BeFalse
        $lastError | Should -Be 122
        ([IntPtr]$arguments[3]).ToInt64() | Should -BeGreaterThan 0
    }
}

Describe 'Release 3.0.0 - phase data and the global report across the two servers' -Tag 'GlobalReport' {
    BeforeAll {
        Import-Module (Join-Path $global:PraGate.Package 'module\PRA.Common.psm1') -Force -Global
        $script:GrRoot = Join-Path $global:PraGate.Root ('lot2b-' + [guid]::NewGuid().ToString('N').Substring(0, 8))
        $null = New-Item -ItemType Directory -Path $script:GrRoot -Force
        $script:Dot = [string][char]0x00B7
        function global:New-GrRow {
            param([string]$Sam, [bool]$Shared, [string]$Status, [string]$Cloud, [string]$Guid, [string]$Warnings = '')
            [pscustomobject]@{ ObjectGuid = $Guid; SamAccountName = $Sam; UserPrincipalName = "$Sam@contoso.com"; Action = 'Convert'; IsShared = $Shared; ADApplied = $true; ADVerified = $true
                BackupPath = 'D:\PRA\Backups\Batch-x\Convert.json'; CloudStatus = $Cloud; CloudDetail = ''; FinalStatus = $Status; Detail = 'detail'; Warnings = $Warnings; LastOperation = ''; GroupAction = ''
                CloudMailbox = $null; CloudLicense = $null; PreserveCloudMailbox = $false; PreserveLicense = $false; DeprovisionConfirmed = $false; PermDetail = ''; PermMissing = @() }
        }
        function global:New-GrContext {
            param([string]$Action, [string]$Phase, [object[]]$Rows, [string[]]$PhaseFolders = @(), [int]$Minutes = 0, [string[]]$Overrides = @(), [string]$Name = 'run')
            $reports = Join-Path $script:GrRoot ('reports-' + $Name)
            $context = @{ Root = $global:PraGate.Package; Version = '3.0.0'; RunId = ((Get-Date -Format 'yyyyMMdd_HHmmss') + '-' + [guid]::NewGuid().ToString('N')); StartTime = (Get-Date).AddMinutes($Minutes); Action = $Action; Mode = 'Apply'; Phase = $Phase
                CurrentPhase = 'Start'; CurrentOperation = ''; CurrentIdentity = ''; StepIndex = 0; StepTotal = 0; Warnings = 0; Issues = (New-Object 'Collections.Generic.List[object]'); Rows = (New-Object 'Collections.Generic.List[object]')
                Server = 'dc01.contoso.com'; Config = @{ Environment = 'GATE'; Cloud = @{ Organization = 'contoso.onmicrosoft.com' } }; AllowMutation = $true; ReportFolder = $reports; NoReport = $false; BatchId = 'abcd1234'
                LogFile = ''; NextSteps = @(); ExitCode = 0; CloudConnectFailed = $false; ResultStatus = ''; PhaseFolders = $PhaseFolders; ConfigOverrides = $Overrides }
            foreach ($row in $Rows) { $context.Rows.Add($row) }
            $context
        }
        function global:New-GrFolder { param([string]$Name) $path = Join-Path $script:GrRoot $Name; $null = New-Item -ItemType Directory -Path $path -Force; $path }
        $script:GuidA = [guid]::NewGuid().ToString(); $script:GuidB = [guid]::NewGuid().ToString(); $script:GuidC = [guid]::NewGuid().ToString()
    }
    AfterAll { Remove-Item -LiteralPath 'Function:\New-GrRow', 'Function:\New-GrContext', 'Function:\New-GrFolder' -ErrorAction SilentlyContinue }

    It 'Convert AD -> Cloud: the cloud server writes ONE report with both sides, for a user and a shared mailbox, with the journey of each object' {
        $folder = New-GrFolder 'Batch-abcd1234ef'
        $ad = New-GrContext Convert AD @((New-GrRow 'alice' $false 'Pending' 'N/A' $script:GuidA), (New-GrRow 'bob.shared' $true 'Pending' 'N/A' $script:GuidB)) -Name 'c1ad' -Overrides @('Polling.TimeoutMinutes: 60 -> 30')
        Register-PraObjectName $ad $script:GuidA 'alice@contoso.com'
        $ad.CurrentIdentity = $script:GuidA
        Write-PraStep -Context $ad -Title 'Backup and Active Directory changes' | Out-Null
        Write-PraItem -Context $ad -Status Ok -Text 'backup written on the AD side'
        $file = Save-PraPhaseData -Context $ad -Folder $folder -HandOff 'Convert'
        Test-Path -LiteralPath $file | Should -BeTrue
        Test-Path -LiteralPath ($file + '.sha256') | Should -BeTrue
        [IO.Path]::GetFileName($file) | Should -Match '^PhaseData-\d{14}-AD-[0-9a-f]{8}\.json$'
        $cloud = New-GrContext Convert Cloud @((New-GrRow 'alice' $false 'Success' 'Success' $script:GuidA), (New-GrRow 'bob.shared' $true 'Success' 'Success' $script:GuidB)) -PhaseFolders @($folder) -Minutes 5 -Name 'c1cloud'
        $report = Write-PraGlobalReport -Context $cloud
        Test-Path -LiteralPath $report.Html | Should -BeTrue
        Test-Path -LiteralPath $report.Csv | Should -BeTrue
        $model = $cloud.GlobalModel
        @($model.Phases | ForEach-Object Label) -join '|' | Should -BeExactly "Convert $script:Dot AD|Convert $script:Dot Cloud"
        $model.Objects.Count | Should -Be 2
        @($model.Objects | ForEach-Object Verdict | Get-PraOrdinalUnique) -join ',' | Should -BeExactly 'done'
        $html = [IO.File]::ReadAllText($report.Html)
        # (the report is HTML: the middle dot is written as an entity)
        foreach ($text in "Convert $script:Dot AD", "Convert $script:Dot Cloud", 'alice@contoso.com', 'bob.shared@contoso.com', 'Shared mailbox', 'User mailbox', 'backup written on the AD side', 'Polling.TimeoutMinutes: 60 -> 30') { $html | Should -Match ([regex]::Escape([Net.WebUtility]::HtmlEncode($text))) }
        $rows = @(Import-Csv -LiteralPath $report.Csv -Delimiter ';')
        $rows.Count | Should -Be 2
        ($rows | Where-Object Name -eq 'alice@contoso.com').Sides | Should -Match 'Convert . AD: Handed over \| Convert . Cloud: Success'
        $rows[0].RunSettings | Should -Match 'Polling.TimeoutMinutes'
    }

    It 'Recover Cloud -> AD (Finalize): one report with Recover AD, Recover Cloud and Finalize, the original Convert shown as history' {
        $convertFolder = New-GrFolder 'Batch-c0ffee0100'
        $recoverFolder = New-GrFolder 'Batch-feed000200'
        $finalizeFolder = New-GrFolder 'Finalize-aaaa000300'
        $convert = New-GrContext Convert Both @((New-GrRow 'alice' $false 'Success' 'Success' $script:GuidA), (New-GrRow 'bob.shared' $true 'Success' 'Success' $script:GuidB)) -Minutes -60 -Name 'c2convert'
        $null = Save-PraPhaseData -Context $convert -Folder $convertFolder
        $recoverAd = New-GrContext Recover AD @((New-GrRow 'alice' $false 'Success' 'N/A' $script:GuidA), (New-GrRow 'bob.shared' $true 'Pending' 'N/A' $script:GuidB)) -PhaseFolders @($convertFolder) -Minutes 0 -Name 'c2ad'
        $null = Save-PraPhaseData -Context $recoverAd -Folder $recoverFolder -HandOff 'Recover'
        $recoverCloud = New-GrContext Recover Cloud @((New-GrRow 'alice' $false 'Success' 'Success' $script:GuidA), (New-GrRow 'bob.shared' $true 'Pending' 'Success' $script:GuidB)) -PhaseFolders @($recoverFolder, $convertFolder) -Minutes 10 -Name 'c2cloud'
        (Copy-PraPhaseData -SourceFolder @($recoverFolder, $convertFolder) -Destination $finalizeFolder) | Should -Be 2
        $null = Save-PraPhaseData -Context $recoverCloud -Folder $finalizeFolder -HandOff 'Finalize'
        $finalize = New-GrContext Finalize Finalize @((New-GrRow 'bob.shared' $true 'Success' 'N/A' $script:GuidB)) -PhaseFolders @($finalizeFolder) -Minutes 20 -Name 'c2final'
        $report = Write-PraGlobalReport -Context $finalize
        $model = $finalize.GlobalModel
        @($model.Phases | ForEach-Object Label) -join '|' | Should -BeExactly "Convert $script:Dot AD + Cloud|Recover $script:Dot AD|Recover $script:Dot Cloud|Finalize $script:Dot AD"
        @($model.Phases | Where-Object Role -eq 'History').Count | Should -Be 1
        $model.Missing.Count | Should -Be 0
        $model.Objects.Count | Should -Be 2
        ($model.Objects | Where-Object Name -eq 'bob.shared@contoso.com').Verdict | Should -BeExactly 'done'
        ($model.Objects | Where-Object Name -eq 'bob.shared@contoso.com').Stages.Count | Should -Be 3
        ($model.Objects | Where-Object Name -eq 'alice@contoso.com').Verdict | Should -BeExactly 'done' -Because 'a user mailbox needs no Finalize: its last stage is its verdict'
        [IO.File]::ReadAllText($report.Html) | Should -Match 'earlier operation'
    }

    It 'refuses a PhaseData file that was changed (checksum) and says plainly that the side is not available' {
        $folder = New-GrFolder 'Batch-badbad0001'
        $ad = New-GrContext Convert AD @((New-GrRow 'alice' $false 'Pending' 'N/A' $script:GuidA)) -Name 'c3ad'
        $file = Save-PraPhaseData -Context $ad -Folder $folder -HandOff 'Convert'
        [IO.File]::AppendAllText($file, ' ')
        $read = Read-PraPhaseData -Folder @($folder) -Environment 'GATE'
        $read.Phases.Count | Should -Be 0
        ($read.Problems -join ' ') | Should -Match 'the checksum does not match'
        $cloud = New-GrContext Convert Cloud @((New-GrRow 'alice' $false 'Success' 'Success' $script:GuidA)) -PhaseFolders @($folder) -Minutes 5 -Name 'c3cloud'
        $report = Write-PraGlobalReport -Context $cloud
        $cloud.GlobalModel.Missing | Should -Contain "Convert $script:Dot AD"
        $html = [IO.File]::ReadAllText($report.Html)
        $html | Should -Match 'not available \(folder from an older version or copied manually\)'
        $html | Should -Match 'the checksum does not match'
        # Another Environment is refused too.
        $other = New-GrFolder 'Batch-badbad0002'
        $null = Save-PraPhaseData -Context (New-GrContext Convert AD @((New-GrRow 'alice' $false 'Pending' 'N/A' $script:GuidA)) -Name 'c3other') -Folder $other
        (Read-PraPhaseData -Folder @($other) -Environment 'ANOTHER').Phases.Count | Should -Be 0
        (Read-PraPhaseData -Folder @($other) -Environment 'GATE').Phases.Count | Should -Be 1
    }

    It 'still writes the global report when the folder carries no phase data (older version, manual copy) and marks the previous side not available' {
        $cloud = New-GrContext Convert Cloud @((New-GrRow 'alice' $false 'Success' 'Success' $script:GuidA)) -PhaseFolders @((New-GrFolder 'Batch-nodata0001')) -Name 'c4'
        $report = Write-PraGlobalReport -Context $cloud
        Test-Path -LiteralPath $report.Html | Should -BeTrue
        $cloud.GlobalModel.Missing.Count | Should -Be 1
        $cloud.GlobalModel.Objects[0].Verdict | Should -BeExactly 'done'
        [IO.File]::ReadAllText($report.Html) | Should -Match 'Side not available'
    }

    It 'Phase Both: the same global layout, one phase, nothing missing' {
        $both = New-GrContext Convert Both @((New-GrRow 'alice' $false 'Success' 'Success' $script:GuidA), (New-GrRow 'carol' $false 'Success' 'Success' $script:GuidC -Warnings 'Forwarding kept')) -Name 'c5'
        $report = Write-PraGlobalReport -Context $both
        $both.GlobalModel.Phases.Count | Should -Be 1
        $both.GlobalModel.Phases[0].Label | Should -BeExactly "Convert $script:Dot AD + Cloud"
        $both.GlobalModel.Missing.Count | Should -Be 0
        ($both.GlobalModel.Objects | Where-Object Name -eq 'carol@contoso.com').Verdict | Should -BeExactly 'done with warnings'
        [IO.File]::ReadAllText($report.Html) | Should -Match 'Objects, end to end'
    }

    It 'an object that is not in the results of the cloud side is listed as pending with the reason (filtered out there)' {
        $folder = New-GrFolder 'Batch-filter0001'
        $ad = New-GrContext Convert AD @((New-GrRow 'alice' $false 'Pending' 'N/A' $script:GuidA), (New-GrRow 'carol' $false 'Pending' 'N/A' $script:GuidC)) -Name 'c6ad'
        $null = Save-PraPhaseData -Context $ad -Folder $folder -HandOff 'Convert'
        $cloud = New-GrContext Convert Cloud @((New-GrRow 'alice' $false 'Success' 'Success' $script:GuidA)) -PhaseFolders @($folder) -Minutes 5 -Name 'c6cloud'
        $null = Write-PraGlobalReport -Context $cloud
        $carol = $cloud.GlobalModel.Objects | Where-Object Name -eq 'carol@contoso.com'
        $carol.Verdict | Should -BeExactly 'pending'
        $carol.Note | Should -Match 'Not in the results of Convert . Cloud'
        $cloud.GlobalModel.Counts.Pending | Should -Be 1
        $cloud.GlobalModel.Counts.Done | Should -Be 1
    }

    It 'Convert AD -> Cloud: the AD phase and its stages read "Handed over" (display only), the raw status stays in the journey and the verdicts do not change' {
        $folder = New-GrFolder 'Batch-handed0001'
        $ad = New-GrContext Convert AD @((New-GrRow 'alice' $false 'Pending' 'N/A' $script:GuidA), (New-GrRow 'bob.shared' $true 'Pending' 'N/A' $script:GuidB)) -Name 'h1ad'
        $null = Save-PraPhaseData -Context $ad -Folder $folder -HandOff 'Convert'
        $cloud = New-GrContext Convert Cloud @((New-GrRow 'alice' $false 'Success' 'Success' $script:GuidA), (New-GrRow 'bob.shared' $true 'Success' 'Success' $script:GuidB)) -PhaseFolders @($folder) -Minutes 5 -Name 'h1cloud'
        $report = Write-PraGlobalReport -Context $cloud
        $model = $cloud.GlobalModel
        [string](Get-PraValue $model.Phases[0].Header 'Status' '') | Should -BeExactly 'Pending' -Because 'the phase itself is recorded as Pending: only the display changes'
        $model.Phases[0].StatusDisplay | Should -BeExactly 'Handed over'
        $model.Phases[0].HandedOverTo | Should -BeExactly "Convert $script:Dot Cloud"
        $model.Phases[1].StatusDisplay | Should -BeExactly 'Success'
        foreach ($entry in $model.Objects) {
            $entry.Stages[0].Status | Should -BeExactly 'Pending'
            $entry.Stages[0].StatusDisplay | Should -BeExactly 'Handed over'
            $entry.Stages[1].StatusDisplay | Should -BeExactly 'Success'
            $entry.Verdict | Should -BeExactly 'done'
        }
        $model.Counts.Pending | Should -Be 0
        $html = [IO.File]::ReadAllText($report.Html)
        $html | Should -Match '<span class="pill ok" title="Pending \(handed over to [^"]*\)">Handed over</span>'
        $html | Should -Match '<span class="pill ok">Handed over</span>'
        $html | Should -Not -Match '<span class="pill warn">Pending</span>'
        $html | Should -Match ([regex]::Escape([Net.WebUtility]::HtmlEncode("Pending (handed over to Convert $script:Dot Cloud)")))
        $rows = @(Import-Csv -LiteralPath $report.Csv -Delimiter ';')
        ($rows | Where-Object Name -eq 'alice@contoso.com').Sides | Should -Match 'Convert . AD: Handed over \| Convert . Cloud: Success'
        ($rows | Where-Object Name -eq 'alice@contoso.com').Journey | Should -Match 'result: Pending \(handed over to Convert . Cloud\)'
    }

    It 'Recover AD -> Cloud -> Finalize: both intermediate phases and their Pending stages read "Handed over"; the last phase keeps its own status' {
        $recoverFolder = New-GrFolder 'Batch-handed0200'
        $finalizeFolder = New-GrFolder 'Finalize-handed0300'
        $recoverAd = New-GrContext Recover AD @((New-GrRow 'alice' $false 'Success' 'N/A' $script:GuidA), (New-GrRow 'bob.shared' $true 'Pending' 'N/A' $script:GuidB)) -Minutes 0 -Name 'h2ad'
        $null = Save-PraPhaseData -Context $recoverAd -Folder $recoverFolder -HandOff 'Recover'
        $recoverCloud = New-GrContext Recover Cloud @((New-GrRow 'alice' $false 'Success' 'Success' $script:GuidA), (New-GrRow 'bob.shared' $true 'Pending' 'Success' $script:GuidB)) -PhaseFolders @($recoverFolder) -Minutes 10 -Name 'h2cloud'
        $null = Copy-PraPhaseData -SourceFolder @($recoverFolder) -Destination $finalizeFolder
        $null = Save-PraPhaseData -Context $recoverCloud -Folder $finalizeFolder -HandOff 'Finalize'
        $finalize = New-GrContext Finalize Finalize @((New-GrRow 'bob.shared' $true 'Success' 'N/A' $script:GuidB)) -PhaseFolders @($finalizeFolder) -Minutes 20 -Name 'h2final'
        $report = Write-PraGlobalReport -Context $finalize
        $model = $finalize.GlobalModel
        @($model.Phases | ForEach-Object StatusDisplay) -join '|' | Should -BeExactly 'Handed over|Handed over|Success'
        $model.Phases[0].HandedOverTo | Should -BeExactly "Recover $script:Dot Cloud"
        $model.Phases[1].HandedOverTo | Should -BeExactly "Finalize $script:Dot AD"
        $bob = $model.Objects | Where-Object Name -eq 'bob.shared@contoso.com'
        @($bob.Stages | ForEach-Object StatusDisplay) -join '|' | Should -BeExactly 'Handed over|Handed over|Success'
        $bob.Verdict | Should -BeExactly 'done'
        $html = [IO.File]::ReadAllText($report.Html)
        $html | Should -Not -Match '<span class="pill warn">Pending</span>'
        (@(Import-Csv -LiteralPath $report.Csv -Delimiter ';') | Where-Object Name -eq 'bob.shared@contoso.com').Sides | Should -Match 'Handed over \| Recover . Cloud: Handed over \| Finalize . AD: Success'
    }

    It 'an object that only the AD side lists stays Pending (warn) while the AD phase itself reads "Handed over"; a last phase that is Pending stays Pending' {
        $folder = New-GrFolder 'Batch-handed0400'
        $ad = New-GrContext Convert AD @((New-GrRow 'alice' $false 'Pending' 'N/A' $script:GuidA), (New-GrRow 'carol' $false 'Pending' 'N/A' $script:GuidC)) -Name 'h3ad'
        $null = Save-PraPhaseData -Context $ad -Folder $folder -HandOff 'Convert'
        $cloud = New-GrContext Convert Cloud @((New-GrRow 'alice' $false 'Success' 'Success' $script:GuidA)) -PhaseFolders @($folder) -Minutes 5 -Name 'h3cloud'
        $report = Write-PraGlobalReport -Context $cloud
        $model = $cloud.GlobalModel
        $model.Phases[0].StatusDisplay | Should -BeExactly 'Handed over'
        $carol = $model.Objects | Where-Object Name -eq 'carol@contoso.com'
        $carol.Stages[0].StatusDisplay | Should -BeExactly 'Pending'
        $carol.Stages[0].HandedOverTo | Should -BeExactly ''
        $carol.Verdict | Should -BeExactly 'pending'
        $html = [IO.File]::ReadAllText($report.Html)
        $html | Should -Match '<span class="pill warn">Pending</span>'
        (@(Import-Csv -LiteralPath $report.Csv -Delimiter ';') | Where-Object Name -eq 'carol@contoso.com').Sides | Should -Match 'Convert . AD: Pending \| Convert . Cloud: -'
        # The last phase: Pending with no later phase stays Pending.
        $folder2 = New-GrFolder 'Batch-handed0500'
        $ad2 = New-GrContext Convert AD @((New-GrRow 'dave' $false 'Pending' 'N/A' $script:GuidA)) -Name 'h3bad'
        $null = Save-PraPhaseData -Context $ad2 -Folder $folder2 -HandOff 'Convert'
        $cloud2 = New-GrContext Convert Cloud @((New-GrRow 'dave' $false 'Pending' 'Success' $script:GuidA)) -PhaseFolders @($folder2) -Minutes 5 -Name 'h3bcloud'
        $report2 = Write-PraGlobalReport -Context $cloud2
        $m2 = $cloud2.GlobalModel
        @($m2.Phases | ForEach-Object StatusDisplay) -join '|' | Should -BeExactly 'Handed over|Pending'
        @($m2.Objects[0].Stages | ForEach-Object StatusDisplay) -join '|' | Should -BeExactly 'Handed over|Pending'
        $m2.Objects[0].Verdict | Should -BeExactly 'pending'
        (@(Import-Csv -LiteralPath $report2.Csv -Delimiter ';'))[0].Sides | Should -Match 'Convert . AD: Handed over \| Convert . Cloud: Pending'
        # One phase alone, still Pending: nothing took it over.
        $single = New-GrContext Convert Both @((New-GrRow 'erin' $false 'Pending' 'N/A' $script:GuidC)) -Name 'h3c'
        $null = Write-PraGlobalReport -Context $single
        $single.GlobalModel.Phases[0].StatusDisplay | Should -BeExactly 'Pending'
        $single.GlobalModel.Objects[0].Stages[0].StatusDisplay | Should -BeExactly 'Pending'
    }

    It 'HTML-encodes every value and neutralises spreadsheet formulas in the CSV' {
        $evil = '<script>alert(1)</script>'
        $ad = New-GrContext Convert Both @((New-GrRow $evil $false 'Success' 'Success' $script:GuidA -Warnings 'a "quoted" <b>warning</b> & more'), (New-GrRow '=cmd' $false 'Error' 'Error' $script:GuidB)) -Name 'c7' -Overrides @('Cloud.Organization: <x> -> "y"')
        $ad.Issues.Add([pscustomobject]@{ Timestamp = 't'; Phase = 'p<'; Operation = 'o'; Identity = 'i'; Source = 's'; Message = 'boom <img src=x onerror=alert(1)>' })
        $report = Write-PraGlobalReport -Context $ad
        $html = [IO.File]::ReadAllText($report.Html)
        $html | Should -Not -Match '<script>alert'
        $html | Should -Not -Match '<img src=x'
        $html | Should -Match '&lt;script&gt;alert\(1\)&lt;/script&gt;'
        $html | Should -Match 'boom &lt;img'
        $html | Should -Match 'Cloud.Organization: &lt;x&gt; -&gt; &quot;y&quot;'
        (@(Import-Csv -LiteralPath $report.Csv -Delimiter ';') | Where-Object { $_.Name -like "'=*" }).Count | Should -Be 1
        ($ad.GlobalModel.Objects | Where-Object Name -eq '=cmd@contoso.com').Verdict | Should -BeExactly 'failed'
    }

    It 'wants a global report only from the run that ends the chain (Apply, nothing handed over)' {
        $both = New-GrContext Convert Both @((New-GrRow 'alice' $false 'Success' 'Success' $script:GuidA)) -Name 'c8'
        Test-PraGlobalReportWanted -Context $both | Should -BeTrue
        $both.HandOff = 'Convert'
        Test-PraGlobalReportWanted -Context $both | Should -BeFalse
        $both.HandOff = ''; $both.AllowMutation = $false
        Test-PraGlobalReportWanted -Context $both | Should -BeFalse
        $check = New-GrContext Check Cloud @((New-GrRow 'alice' $false 'Success' 'Success' $script:GuidA)) -Name 'c8b'
        Test-PraGlobalReportWanted -Context $check | Should -BeFalse
    }

    It 'carries the phase data in the transfer package, listed with its SHA-256, and refuses a package whose phase data was changed' {
        $folder = New-GrFolder 'Batch-abcd9999aa'
        $ad = New-GrContext Convert AD @((New-GrRow 'alice' $false 'Pending' 'N/A' $script:GuidA)) -Name 'c9'
        $null = Save-PraPhaseData -Context $ad -Folder $folder -HandOff 'Convert'
        [IO.File]::WriteAllText((Join-Path $folder 'Convert-x.json'), '{}')
        $package = New-PraTransferPackage -Kind Convert -Environment GATE -BatchId 'abcd9999aa' -Folders @($folder) -OutboxFolder (Join-Path $script:GrRoot 'outbox')
        $info = Get-PraTransferPackage -Path $package.Path -Environment GATE
        $info.Valid | Should -BeTrue -Because $info.Error
        $info.EntryCount | Should -Be 3 -Because 'the batch JSON, the phase data and its checksum'
        $tampered = Join-Path $script:GrRoot 'tampered.zip'
        Copy-Item -LiteralPath $package.Path -Destination $tampered
        $zip = [IO.Compression.ZipFile]::Open($tampered, [IO.Compression.ZipArchiveMode]::Update)
        try {
            $entry = @($zip.Entries | Where-Object { $_.Name -like 'PhaseData-*.json' -and $_.Name -notlike '*.sha256' })[0]
            $reader = New-Object IO.StreamReader($entry.Open()); $text = $reader.ReadToEnd(); $reader.Dispose(); $name = $entry.FullName; $entry.Delete()
            $replacement = $zip.CreateEntry($name); $writer = New-Object IO.StreamWriter($replacement.Open())
            $writer.Write($text.Replace('"Success"', '"Succes5"').Replace('alice', 'alicf')); $writer.Dispose()
        } finally { $zip.Dispose() }
        [IO.File]::WriteAllText($tampered + '.sha256', (Get-FileHash -LiteralPath $tampered -Algorithm SHA256).Hash.ToLowerInvariant())
        $bad = Get-PraTransferPackage -Path $tampered -Environment GATE
        $bad.Valid | Should -BeFalse
        $bad.Error | Should -Match 'does not match its SHA-256|larger|shorter|differs from transfer.json'
    }

    It 'lists the run settings changed in the per-phase HTML report too' {
        $ctx = New-GrContext Convert Both @((New-GrRow 'alice' $false 'Success' 'Success' $script:GuidA)) -Name 'c10' -Overrides @('Polling.TimeoutMinutes: 60 -> 30', 'Directory.ForceReplication: False -> True')
        $html = InModuleScope PRA.Common -Parameters @{ Ctx = $ctx } { Get-PraReportHtml -Context $Ctx -Outcome (Get-PraOutcome $Ctx) }
        $html | Should -Match 'Run settings changed'
        $html | Should -Match 'Polling.TimeoutMinutes: 60 -&gt; 30; Directory.ForceReplication: False -&gt; True'
    }

    It 'item events carry the backup path of the object, else the one of the batch, else nothing; the journey keeps only known objects' {
        $old = $env:PRA_EVENT_FILE
        try {
            $env:PRA_EVENT_FILE = Join-Path $script:GrRoot 'events-backup.jsonl'
            $ctx = New-GrContext Convert AD @() -Name 'c11'
            Register-PraObjectName $ctx $script:GuidA 'alice@contoso.com'
            Register-PraObjectBackup -Context $ctx -Identity @($script:GuidA, 'alice@contoso.com') -Path 'D:\PRA\Backups\Batch-1\a.json'
            $ctx.CurrentIdentity = $script:GuidA; Write-PraItem -Context $ctx -Status Ok -Text 'one'
            $ctx.CurrentIdentity = $script:GuidB; Write-PraItem -Context $ctx -Status Ok -Text 'two'
            Register-PraObjectBackup -Context $ctx -Path 'D:\PRA\Backups\Batch-1'
            $ctx.CurrentIdentity = ''; Write-PraItem -Context $ctx -Status Ok -Text 'three'
            $events = @(Get-Content -LiteralPath $env:PRA_EVENT_FILE -Encoding UTF8 | ForEach-Object { $_ | ConvertFrom-Json -DateKind String })
            @($events | ForEach-Object backup) -join '|' | Should -BeExactly 'D:\PRA\Backups\Batch-1\a.json||D:\PRA\Backups\Batch-1' -Because 'the second object has no backup yet and the batch folder is not known yet'
            $ctx.Journey.Count | Should -Be 1 -Because 'only the named object has a journey'
            $ctx.Journey[0].Name | Should -BeExactly 'alice@contoso.com'
        } finally { $env:PRA_EVENT_FILE = $old }
    }
}

Describe 'Release 3.0.0 - optional forced Active Directory replication (Directory.ForceReplication)' -Tag 'AdReplication' {
    BeforeAll {
        Import-Module (Join-Path $global:PraGate.Package 'module\PRA.Common.psm1') -Force -Global
        $script:RepRuntime = New-GateRuntime -Name 'replication'
        $env:PRA_GATE_STATE = $script:RepRuntime.StatePath
        $env:PSModulePath = $script:RepRuntime.Modules + ';' + (Join-Path $PSHOME 'Modules')
        Import-Module ActiveDirectory -Force -Global
        Import-Module (Join-Path $global:PraGate.Package 'module\PRA.Directory.psm1') -Force -Global
        function global:Invoke-RepScenario {
            param([bool]$Enabled = $true, [string[]]$Targets = @(), [hashtable]$Fail = @{}, [hashtable]$Values = @{}, [string]$Mode = 'Apply', [bool]$Approve = $true)
            $old = $env:PRA_EVENT_FILE
            $events = Join-Path $script:RepRuntime.Root ('rep-' + [guid]::NewGuid().ToString('N') + '.jsonl')
            $env:PRA_EVENT_FILE = $events; $global:LastRepEvents = $events
            try {
                InModuleScope PRA.Directory -Parameters @{ Enabled = $Enabled; Targets = $Targets; Fail = $Fail; Values = $Values; Mode = $Mode; Approve = $Approve } {
                    $script:RepCalls = New-Object 'Collections.Generic.List[string]'; $script:RepFail = $Fail; $script:RepValues = $Values
                    function script:Sync-ADObject { param($Object, $Source, $Destination, $ErrorAction) $script:RepCalls.Add("sync|$Source|$Destination|$Object"); if ($script:RepFail.ContainsKey($Destination)) { throw $script:RepFail[$Destination] } }
                    function script:Get-ADDomainController { param($Filter, $Server, $Identity, $ErrorAction) $script:RepCalls.Add('list'); @([pscustomobject]@{ HostName = 'dc1.gate.invalid'; IsReadOnly = $false }, [pscustomobject]@{ HostName = 'dc2.gate.invalid'; IsReadOnly = $false },
                            [pscustomobject]@{ HostName = 'dc3.gate.invalid'; IsReadOnly = $false }, [pscustomobject]@{ HostName = 'rodc.gate.invalid'; IsReadOnly = $true }) }
                    function script:Get-ADUser { param($Identity, $Properties, $Server, $ErrorAction) $script:RepCalls.Add("read|$Server"); [pscustomobject]@{ ObjectGUID = $Identity; description = $(if ($script:RepValues.ContainsKey($Server)) { $script:RepValues[$Server] } else { 'x' }) } }
                    $approve = $Approve
                    $ctx = @{ Config = @{ Directory = @{ ForceReplication = $Enabled; ReplicationTargets = $Targets; ReplicationVerifyAttempts = 2; ReplicationVerifyDelaySeconds = 1 } }; Server = 'dc1.gate.invalid'; AllowMutation = ($Mode -eq 'Apply'); Mode = $Mode
                        Warnings = 0; Issues = (New-Object 'Collections.Generic.List[object]'); LogFile = ''; CurrentPhase = 'Replication'; CurrentOperation = ''; CurrentIdentity = ''; StepIndex = 0; Version = 'gate'
                        Approval = { param($t, $o) $true }.GetNewClosure(); Rows = (New-Object 'Collections.Generic.List[object]'); Action = 'Convert' }
                    if (-not $approve) { $ctx.Approval = { param($t, $o) $false } }
                    $plans = @(1..2 | ForEach-Object { [pscustomobject]@{ Record = [pscustomobject]@{ ObjectGuid = [guid]::NewGuid().ToString(); DistinguishedName = "CN=u$_,DC=gate,DC=invalid" }
                                Row = [pscustomobject]@{ ADApplied = $true; UserPrincipalName = "u$_@gate.invalid"; SamAccountName = "u$_" }; Kinds = @{ description = 'String' }
                                Desired = @{ description = [ordered]@{ Present = $true; Kind = 'String'; Value = 'x' } } } })
                    Invoke-PraAdReplication -Context $ctx -Plans $plans
                    [pscustomobject]@{ Calls = @($script:RepCalls); Context = $ctx; EventFile = $null }
                }
            } finally { $env:PRA_EVENT_FILE = $old }
        }
    }
    AfterAll { Remove-Item -LiteralPath 'Function:\Invoke-RepScenario' -ErrorAction SilentlyContinue; Remove-Variable LastRepEvents -Scope Global -ErrorAction SilentlyContinue }

    It 'option off: no step to run and no call at all' {
        $run = Invoke-RepScenario -Enabled $false
        $run.Calls.Count | Should -Be 0
    }
    It 'Preview never replicates, even with the option on' {
        $run = Invoke-RepScenario -Mode 'Preview'
        $run.Calls.Count | Should -Be 0
    }
    It 'option on: Sync-ADObject once per object per other writable domain controller (no read-only one), then a read back on each, with progress and item events' {
        $run = Invoke-RepScenario
        @($run.Calls | Where-Object { $_ -like 'sync|*' }).Count | Should -Be 4
        @($run.Calls | Where-Object { $_ -like 'sync|dc1.gate.invalid|dc2.gate.invalid|*' }).Count | Should -Be 2
        @($run.Calls | Where-Object { $_ -like 'sync|dc1.gate.invalid|dc3.gate.invalid|*' }).Count | Should -Be 2
        @($run.Calls | Where-Object { $_ -like '*rodc*' }).Count | Should -Be 0
        @($run.Calls | Where-Object { $_ -like 'read|*' }).Count | Should -BeGreaterOrEqual 4
        @(Get-PraList $run.Context 'ReplicationUnconfirmed').Count | Should -Be 0
        $run.Context.Warnings | Should -Be 0
    }
    It 'emits one progress event per attempt and one item event per object and domain controller' {
        $run = Invoke-RepScenario
        $events = @(Get-Content -LiteralPath $global:LastRepEvents -Encoding UTF8 | ForEach-Object { $_ | ConvertFrom-Json -DateKind String })
        @($events | Where-Object { $_.kind -eq 'progress' -and $_.text -like 'Active Directory replication to *' }).Count | Should -BeGreaterOrEqual 2
        ($events | Where-Object { $_.kind -eq 'progress' } | Select-Object -First 1).maxAttempts | Should -Be 2
        @($events | Where-Object { $_.kind -eq 'item' -and $_.text -like 'Replicated to dc*' }).Count | Should -Be 4
    }
    It 'a domain controller that does not converge is a warning that names it, and the Next steps data keeps it' {
        $run = Invoke-RepScenario -Values @{ 'dc3.gate.invalid' = 'other' }
        @(Get-PraList $run.Context 'ReplicationUnconfirmed') -join ',' | Should -BeExactly 'dc3.gate.invalid'
        $run.Context.Warnings | Should -BeGreaterThan 0
        (@(Get-PraList $run.Context 'WarningList') | ForEach-Object Message) -join ' ' | Should -Match 'dc3.gate.invalid'
    }
    It 'an unreachable domain controller is a warning that names it' {
        $run = Invoke-RepScenario -Fail @{ 'dc2.gate.invalid' = 'The server is not operational.' }
        @(Get-PraList $run.Context 'ReplicationUnconfirmed') -join ',' | Should -BeExactly 'dc2.gate.invalid'
        (@(Get-PraList $run.Context 'WarningList') | ForEach-Object Message) -join ' ' | Should -Match 'dc2.gate.invalid.*not operational'
    }
    It 'an access denied says which right is needed' {
        $run = Invoke-RepScenario -Fail @{ 'dc2.gate.invalid' = 'Access is denied.' }
        (@(Get-PraList $run.Context 'WarningList') | ForEach-Object Message) -join ' ' | Should -Match 'access denied: the account needs the right to replicate a single object'
        (@(Get-PraList $run.Context 'WarningList') | ForEach-Object Message) -join ' ' | Should -Match 'Replication Synchronization'
    }
    It 'a destination that is not approved is not written to, and is reported' {
        $run = Invoke-RepScenario -Approve $false
        @($run.Calls | Where-Object { $_ -like 'sync|*' }).Count | Should -Be 0
        @(Get-PraList $run.Context 'ReplicationUnconfirmed').Count | Should -Be 2
    }
    It 'Directory.ReplicationTargets restricts the destinations and skips the discovery' {
        $run = Invoke-RepScenario -Targets @('dc3.gate.invalid')
        @($run.Calls | Where-Object { $_ -like 'sync|*' } | ForEach-Object { ($_ -split '\|')[2] } | Get-PraOrdinalUnique) -join ',' | Should -BeExactly 'dc3.gate.invalid'
        @($run.Calls | Where-Object { $_ -eq 'list' }).Count | Should -Be 0
    }
    It 'validates the options, is off by default and is in the shipped file; the entry script has the switch' {
        $runtime = New-GateRuntime -Name 'replication-config'
        $config = Import-PraConfiguration -Path $runtime.ConfigPath -Root $runtime.Package
        $config.Directory.ForceReplication | Should -BeFalse
        $config.Directory.ReplicationVerifyAttempts | Should -Be 6
        Set-GateConfigText $runtime { param($t) $t.Replace("Execution=@{Phase='Both'}", "Execution=@{Phase='Both'}`r`n Directory=@{ReplicationVerifyAttempts=0}") }
        { Import-PraConfiguration -Path $runtime.ConfigPath -Root $runtime.Package } | Should -Throw '*Directory.ReplicationVerifyAttempts*'
        Set-GateConfigText $runtime { param($t) $t.Replace('Directory=@{ReplicationVerifyAttempts=0}', "Directory=@{ReplicationTargets=@('bad name!')}") }
        { Import-PraConfiguration -Path $runtime.ConfigPath -Root $runtime.Package } | Should -Throw '*Directory.ReplicationTargets*'
        (Get-Command (Join-Path $global:PraGate.Source 'Invoke-PraRemoteMailbox.ps1')).Parameters.Keys | Should -Contain 'ForceAdReplication'
    }
}

Describe 'Release 3.0.0 - plan counts and the replication step through the real main' -Tag 'Lot2bMain' {
    BeforeEach {
        $oldEventPath = $env:PRA_EVENT_FILE
        $runtime = New-GateRuntime -Name 'lot2b-main'
        $env:PRA_EVENT_FILE = Join-Path $runtime.Root 'engine.events.jsonl'
    }
    AfterEach { $env:PRA_EVENT_FILE = $oldEventPath }
    It 'announces how many objects the steps work on (a count event after targeting), and adds the replication step only with the option' {
        $run = Invoke-GateProcess $runtime @{Action='Convert';Phase='AD';Mode='Preview';ConfigPath=$runtime.ConfigPath}
        $run.ExitCode | Should -Be 0
        $events = @(Get-Content -LiteralPath $env:PRA_EVENT_FILE -Encoding UTF8 | ForEach-Object { $_ | ConvertFrom-Json -DateKind String })
        $counts = @($events | Where-Object kind -eq 'count')
        $counts.Count | Should -Be 1
        $counts[0].count | Should -BeGreaterThan 0
        @($counts[0].stepIds) -join ',' | Should -BeExactly 's2,s3'
        @($events | Where-Object kind -eq 'plan')[0].steps.Count | Should -Be 5
        @(@($events | Where-Object kind -eq 'plan')[0].steps | ForEach-Object label) | Should -Not -Contain 'Active Directory replication'
        Remove-Item -LiteralPath $env:PRA_EVENT_FILE -Force
        $replicated = Invoke-GateProcess $runtime @{Action='Convert';Phase='AD';Mode='Preview';ConfigPath=$runtime.ConfigPath;ForceAdReplication=$true}
        $replicated.ExitCode | Should -Be 0 -Because ($replicated.Output + $replicated.Error)
        $events = @(Get-Content -LiteralPath $env:PRA_EVENT_FILE -Encoding UTF8 | ForEach-Object { $_ | ConvertFrom-Json -DateKind String })
        $labels = @(@($events | Where-Object kind -eq 'plan')[0].steps | ForEach-Object label)
        $labels.Count | Should -Be 6
        $labels[2] | Should -BeExactly 'Backup and Active Directory changes'
        $labels[3] | Should -BeExactly 'Active Directory replication'
        $labels[4] | Should -BeExactly 'Entra Connect synchronisation' -Because 'the replication step sits just before the synchronisation'
        @($events | Where-Object { $_.kind -eq 'step' -and $_.title -eq 'Active Directory replication' } | ForEach-Object state) | Should -Contain 'skipped'
        @(@($events | Where-Object kind -eq 'result')[0].configOverrides) -join '|' | Should -Match 'Directory.ForceReplication'
        @(Get-GateWrites $runtime).Count | Should -Be 0
    }
}

Describe 'Release 3.0.0 - licence group replication, staging extraction, phase order, Next steps, Preview folder' -Tag 'Lot2c' {
    BeforeAll {
        Import-Module (Join-Path $global:PraGate.Package 'module\PRA.Common.psm1') -Force -Global
        $script:C2Root = Join-Path $global:PraGate.Root ('lot2c-' + [guid]::NewGuid().ToString('N').Substring(0, 8))
        $null = New-Item -ItemType Directory -Path $script:C2Root -Force
    }

    It 'replicates and verifies the licence GROUP change too (member added), and names a domain controller whose group does not show the member' {
        $runtime = New-GateRuntime -Name 'replication-group'
        $env:PRA_GATE_STATE = $runtime.StatePath
        $env:PSModulePath = $runtime.Modules + ';' + (Join-Path $PSHOME 'Modules')
        Import-Module ActiveDirectory -Force -Global
        Import-Module (Join-Path $global:PraGate.Package 'module\PRA.Directory.psm1') -Force -Global
        foreach ($case in @(@{ Stale = ''; Expected = 0 }, @{ Stale = 'dc3.gate.invalid'; Expected = 1 })) {
            $run = InModuleScope PRA.Directory -Parameters @{ Stale = $case.Stale } {
                $script:Calls = New-Object 'Collections.Generic.List[string]'; $script:StaleDc = $Stale
                function script:Sync-ADObject { param($Object, $Source, $Destination, $ErrorAction) $script:Calls.Add("sync|$Destination|$Object") }
                function script:Get-ADDomainController { param($Filter, $Server, $Identity, $ErrorAction) @([pscustomobject]@{ HostName = 'dc1.gate.invalid'; IsReadOnly = $false }, [pscustomobject]@{ HostName = 'dc2.gate.invalid'; IsReadOnly = $false }, [pscustomobject]@{ HostName = 'dc3.gate.invalid'; IsReadOnly = $false }) }
                function script:Get-ADUser { param($Identity, $Properties, $Server, $ErrorAction) [pscustomobject]@{ ObjectGUID = $Identity; description = 'x' } }
                function script:Get-ADGroup { param($Identity, $Properties, $Server, $ErrorAction) $script:Calls.Add("group|$Server"); [pscustomobject]@{ member = $(if ($Server -ceq $script:StaleDc) { @() } else { @('CN=u1,DC=gate,DC=invalid') }) } }
                $ctx = @{ Config = @{ Directory = @{ ForceReplication = $true; ReplicationTargets = @(); ReplicationVerifyAttempts = 1; ReplicationVerifyDelaySeconds = 1 } }; Server = 'dc1.gate.invalid'; AllowMutation = $true; Mode = 'Apply'
                    Warnings = 0; Issues = (New-Object 'Collections.Generic.List[object]'); LogFile = ''; CurrentPhase = 'Replication'; CurrentOperation = ''; CurrentIdentity = ''; StepIndex = 0; Version = 'gate'
                    Approval = { param($t, $o) $true }; Rows = (New-Object 'Collections.Generic.List[object]'); Action = 'Convert' }
                $plan = [pscustomobject]@{ Record = [pscustomobject]@{ ObjectGuid = [guid]::NewGuid().ToString(); DistinguishedName = 'CN=u1,DC=gate,DC=invalid'; Licensing = [pscustomobject]@{ GroupDN = 'CN=Lic,DC=gate,DC=invalid'; GroupGuid = [guid]::NewGuid().ToString(); DesiredMember = $true } }
                    Row = [pscustomobject]@{ ADApplied = $true; GroupAction = 'Added'; UserPrincipalName = 'u1@gate.invalid'; SamAccountName = 'u1' }; Kinds = @{ description = 'String' }
                    Desired = @{ description = [ordered]@{ Present = $true; Kind = 'String'; Value = 'x' } } }
                Invoke-PraAdReplication -Context $ctx -Plans @($plan)
                [pscustomobject]@{ Calls = @($script:Calls); Context = $ctx }
            }
            @($run.Calls | Where-Object { $_ -like 'sync|*|CN=Lic,*' }).Count | Should -Be 2 -Because 'the group object is pushed to each other domain controller'
            @($run.Calls | Where-Object { $_ -like 'group|*' }).Count | Should -BeGreaterOrEqual 2
            @(Get-PraList $run.Context 'ReplicationUnconfirmed').Count | Should -Be $case.Expected
            if ($case.Stale) { (@(Get-PraList $run.Context 'ReplicationUnconfirmed') -join ',') | Should -BeExactly $case.Stale }
        }
    }

    It 'extracts through a staging folder: no staging folder is left, a stale one is swept, and the folders come out private' {
        $backup = Join-Path $script:C2Root 'backups-stage'
        $null = New-Item -ItemType Directory -Path $backup -Force
        $stale = Join-Path $backup '.importing-deadbeef'; $null = New-Item -ItemType Directory -Path $stale; (Get-Item $stale).CreationTimeUtc = [datetime]::UtcNow.AddHours(-2)
        $source = Join-Path $script:C2Root 'Batch-5ca1ab1e01'; $null = New-Item -ItemType Directory -Path $source
        [IO.File]::WriteAllText((Join-Path $source 'Convert-x.json'), '{}')
        $package = New-PraTransferPackage -Kind Convert -Environment GATE -BatchId '5ca1ab1e01' -Folders @($source) -OutboxFolder (Join-Path $script:C2Root 'outbox-stage')
        $imported = Import-PraTransferPackage -Path $package.Path -BackupFolder $backup -Environment GATE -ExpectedKind Convert
        $imported.Created.Count | Should -Be 1
        Test-Path -LiteralPath (Join-Path $backup 'Batch-5ca1ab1e01\Convert-x.json') | Should -BeTrue
        @(Get-ChildItem -LiteralPath $backup -Directory -Force | Where-Object { $_.Name -like '.importing-*' }).Count | Should -Be 0 -Because 'the staging folder is removed, and the stale one swept'
        ([IO.FileSystemAclExtensions]::GetAccessControl((New-Object IO.DirectoryInfo (Join-Path $backup 'Batch-5ca1ab1e01')))).AreAccessRulesProtected | Should -BeTrue
        # A second import of the same package: identical, accepted, nothing written.
        $again = Import-PraTransferPackage -Path $package.Path -BackupFolder $backup -Environment GATE -ExpectedKind Convert
        $again.Created.Count | Should -Be 0
        $again.Existing.Count | Should -Be 1
    }

    It 'sweeps a stale temporary package of the Outbox and keeps a distinct temporary name per attempt' {
        $outbox = Join-Path $script:C2Root 'outbox-tmp'
        $null = New-Item -ItemType Directory -Path $outbox
        $old = Join-Path $outbox 'PRA-GATE-Convert-aaaaaaaa-for-Cloud.zip.0123abcd.tmp'; [IO.File]::WriteAllText($old, 'x'); (Get-Item $old).LastWriteTimeUtc = [datetime]::UtcNow.AddDays(-3)
        $source = Join-Path $script:C2Root 'Batch-5ca1ab1e02'; $null = New-Item -ItemType Directory -Path $source; [IO.File]::WriteAllText((Join-Path $source 'Convert-x.json'), '{}')
        $null = New-PraTransferPackage -Kind Convert -Environment GATE -BatchId '5ca1ab1e02' -Folders @($source) -OutboxFolder $outbox
        Test-Path -LiteralPath $old | Should -BeFalse
        @(Get-ChildItem -LiteralPath $outbox -Filter '*.tmp').Count | Should -Be 0
    }

    It 'orders the phases of the chain by their side, not by clock: a cloud server whose clock is behind still reports the objects as done' {
        function Row($sam, $guid, $status, $cloud) { [pscustomobject]@{ ObjectGuid = $guid; SamAccountName = $sam; UserPrincipalName = "$sam@contoso.com"; Action = 'Convert'; IsShared = $false; ADApplied = $true; ADVerified = $true; BackupPath = ''; CloudStatus = $cloud; CloudDetail = ''; FinalStatus = $status; Detail = ''; Warnings = ''; LastOperation = ''; GroupAction = ''; CloudMailbox = $null; CloudLicense = $null; PreserveCloudMailbox = $false; PreserveLicense = $false; DeprovisionConfirmed = $false; PermDetail = ''; PermMissing = @() } }
        function Ctx($phase, $rows, $minutes, $folders) {
            $c = @{ Root = $global:PraGate.Package; Version = '3.0.0'; RunId = ((Get-Date -Format 'yyyyMMdd_HHmmss') + '-' + [guid]::NewGuid().ToString('N')); StartTime = (Get-Date).AddMinutes($minutes); Action = 'Convert'; Mode = 'Apply'; Phase = $phase
                CurrentPhase = ''; CurrentOperation = ''; CurrentIdentity = ''; StepIndex = 0; Warnings = 0; Issues = (New-Object 'Collections.Generic.List[object]'); Rows = (New-Object 'Collections.Generic.List[object]'); Server = ''
                Config = @{ Environment = 'GATE' }; AllowMutation = $true; ReportFolder = (Join-Path $script:C2Root 'reports-skew'); NoReport = $false; BatchId = 'abcd1234'; LogFile = ''; NextSteps = @(); ExitCode = 0; CloudConnectFailed = $false; ResultStatus = ''; PhaseFolders = $folders; ConfigOverrides = @() }
            foreach ($r in $rows) { $c.Rows.Add($r) }; $c
        }
        $guid = [guid]::NewGuid().ToString()
        $folder = Join-Path $script:C2Root 'Batch-5ca1ab1e03'; $null = New-Item -ItemType Directory -Path $folder
        $null = Save-PraPhaseData -Context (Ctx 'AD' @((Row 'alice' $guid 'Pending' 'N/A')) 0 @()) -Folder $folder -HandOff 'Convert'
        $cloud = Ctx 'Cloud' @((Row 'alice' $guid 'Success' 'Success')) -30 @($folder)
        $null = Write-PraGlobalReport -Context $cloud
        @($cloud.GlobalModel.Phases | ForEach-Object { $_.Header.Phase }) -join ',' | Should -BeExactly 'AD,Cloud'
        $cloud.GlobalModel.Objects[0].Verdict | Should -BeExactly 'done'
    }

    It 'keeps the replication warning in the Next steps of a run that failed afterwards (the synchronisation threw)' {
        $ctx = @{ Root = $global:PraGate.Package; Version = '3.0.0'; RunId = ((Get-Date -Format 'yyyyMMdd_HHmmss') + '-' + [guid]::NewGuid().ToString('N')); StartTime = Get-Date; Action = 'Convert'; Mode = 'Apply'; Phase = 'AD'
            CurrentPhase = 'Entra Connect synchronisation'; CurrentOperation = ''; CurrentIdentity = ''; StepIndex = 0; Warnings = 0; Issues = (New-Object 'Collections.Generic.List[object]'); Rows = (New-Object 'Collections.Generic.List[object]')
            Server = ''; Config = @{ Environment = 'GATE' }; AllowMutation = $true; ReportFolder = (Join-Path $script:C2Root 'reports-next'); NoReport = $true; BatchId = 'abcd1234'; LogFile = ''; TranscriptStarted = $false; NextSteps = @()
            ExitCode = 1; CloudConnectFailed = $false; ResultStatus = ''; ReplicationUnconfirmed = @('dc3.gate.invalid') }
        $ctx.Issues.Add([pscustomobject]@{ Timestamp = 't'; Phase = 'p'; Operation = 'Start-ADSyncSyncCycle'; Identity = ''; Source = 'Execution'; Message = 'Timeout: the synchronisation cycle did not end in time' })
        $result = Complete-PraRun -Context $ctx
        $result.ExitCode | Should -Be 1
        ($result.NextSteps -join ' ') | Should -Match 'replication was NOT confirmed on: dc3.gate.invalid'
        ($result.NextSteps -join ' ') | Should -Match 'Start-ADSyncSyncCycle'
    }
}

Describe 'Release 3.0.0 - the window switch -ForceAdReplication and -BaseConfigPath together' -Tag 'Lot2cMain' {
    It 'lists both the switch and the differences with the configuration file' {
        $old = $env:PRA_EVENT_FILE
        try {
            $runtime = New-GateRuntime -Name 'lot2c-main'
            $env:PRA_EVENT_FILE = Join-Path $runtime.Root 'engine.events.jsonl'
            $dest = Join-Path $runtime.Root 'effective.psd1'
            $null = New-PraEffectiveConfiguration -BasePath $runtime.ConfigPath -Root $runtime.Package -Overrides @{ Polling = @{ TimeoutMinutes = 30 } } -Destination $dest
            $run = Invoke-GateProcess $runtime @{Action='Convert';Phase='AD';Mode='Preview';ConfigPath=$dest;BaseConfigPath=$runtime.ConfigPath;ForceAdReplication=$true}
            $run.ExitCode | Should -Be 0 -Because ($run.Output + $run.Error)
            $events = @(Get-Content -LiteralPath $env:PRA_EVENT_FILE -Encoding UTF8 | ForEach-Object { $_ | ConvertFrom-Json -DateKind String })
            $overrides = @(@($events | Where-Object kind -eq 'result')[0].configOverrides) -join '|'
            $overrides | Should -Match 'Polling.TimeoutMinutes'
            $overrides | Should -Match 'Directory.ForceReplication'
        } finally { $env:PRA_EVENT_FILE = $old }
    }
}

Describe 'Release 3.1.0 - X500 control: Active Directory side (expected addresses recorded in the batch, read only)' -Tag 'Lot6' {
    BeforeEach {
        $global:PraGate.Runtime=New-GateRuntime -Name 'x500-ad'
        $env:PRA_GATE_STATE=$global:PraGate.Runtime.StatePath
        $env:PSModulePath=$global:PraGate.Runtime.Modules+';'+(Join-Path $PSHOME 'Modules')
        Remove-Module PRA.Directory -Force -ErrorAction SilentlyContinue
        Get-Module ActiveDirectory -All | Remove-Module -Force -ErrorAction SilentlyContinue
        Import-Module (Join-Path $global:PraGate.Runtime.Modules 'ActiveDirectory\ActiveDirectory.psm1') -Force -Global
        Import-Module (Join-Path $global:PraGate.Package 'module\PRA.Directory.psm1') -Force -Global
        $global:PraGate.Context=New-GateContext $global:PraGate.Runtime
        $global:PraGate.Context.LogFile=Join-Path $global:PraGate.Runtime.Root 'logs\x500-ad.log'
        $global:PraGate.Legacy1='X500:/o=Synthetic/ou=Gate/cn=Recipients/cn=user1'
        $global:PraGate.Older='X500:/o=Synthetic/ou=Gate/cn=User'
    }
    It 'reads legacyExchangeDN with the other attributes and records the X500 of the legacyExchangeDN first, then the on-premises X500 proxies; nothing else is managed' {
        $plan=New-PraPlan $global:PraGate.Context 'user1' 'Convert'
        @($plan.Record.ExpectedX500) | Should -BeExactly @($global:PraGate.Legacy1,$global:PraGate.Older)
        $plan.Record.ExpectedX500 | Should -BeOfType ([string])
        $plan.Kinds.Keys | Should -Not -Contain 'legacyExchangeDN'
        $plan.Record.Attributes.Keys | Should -Not -Contain 'legacyExchangeDN'
        $plan.Record.PlannedAttributes.Keys | Should -Not -Contain 'legacyExchangeDN'
        $read=@(Get-GateEvents $global:PraGate.Runtime | Where-Object Operation -eq 'Get-ADUser')[0]
        @($read.Detail.Properties) | Should -Contain 'legacyExchangeDN'
        @(Get-GateWrites $global:PraGate.Runtime).Count | Should -Be 0
    }
    It 'removes duplicates (ordinal, ignoring case, whole value), keeps the first spelling byte for byte and ignores non-X500 proxies' {
        $user=$global:PraGateAd.Users[0]
        $user.proxyAddresses=[string[]]@($user.proxyAddresses)+'x500:/O=SYNTHETIC/OU=GATE/CN=RECIPIENTS/CN=USER1'+'x500:/o=synthetic/ou=gate/cn=user'+'X500:/o=Old/cn=A B '+'X500:/o=Old/cn=A B '+'smtp:x500:not.x500@gate.invalid'
        $plan=New-PraPlan $global:PraGate.Context 'user1' 'Convert'
        @($plan.Record.ExpectedX500) | Should -BeExactly @($global:PraGate.Legacy1,$global:PraGate.Older,'X500:/o=Old/cn=A B ')
        # a value that differs by one character is another address
        $user.proxyAddresses=[string[]]@($user.proxyAddresses)+'X500:/o=Old/cn=A B'
        @((New-PraPlan $global:PraGate.Context 'user1' 'Convert').Record.ExpectedX500).Count | Should -Be 4
    }
    It 'keeps only the X500 proxies when legacyExchangeDN is empty or absent' -ForEach @(@{Shape='empty'},@{Shape='absent'}) {
        $user=$global:PraGateAd.Users[0]
        if ($Shape -eq 'empty') { $user.legacyExchangeDN='' } else { $user.PSObject.Properties.Remove('legacyExchangeDN') }
        $plan=New-PraPlan $global:PraGate.Context 'user1' 'Convert'
        @($plan.Record.ExpectedX500) | Should -BeExactly @($global:PraGate.Older)
        $user.proxyAddresses=[string[]]@($user.proxyAddresses | Where-Object { $_ -cne $global:PraGate.Older })
        @((New-PraPlan $global:PraGate.Context 'user1' 'Convert').Record.ExpectedX500).Count | Should -Be 0
    }
    It 'writes the field in the batch JSON, re-reads it, and never writes, restores or clears legacyExchangeDN' {
        $context=$global:PraGate.Context
        $plans=@(New-PraPlan $context 'user1' 'Convert';New-PraPlan $context 'user2' 'Convert')
        $receipt=Invoke-PraAdBatch $context $plans 'Convert'
        $saved=Import-PraBackup $context $receipt.Path
        @($saved.Data.Records[0].ExpectedX500) | Should -BeExactly @($global:PraGate.Legacy1,$global:PraGate.Older)
        @($saved.Data.Records[1].ExpectedX500) | Should -BeExactly @('X500:/o=Synthetic/ou=Gate/cn=Recipients/cn=user2',$global:PraGate.Older)
        $global:PraGateAd.Users[0].legacyExchangeDN | Should -BeExactly '/o=Synthetic/ou=Gate/cn=Recipients/cn=user1'
        $writes=@(Get-GateEvents $global:PraGate.Runtime | Where-Object Operation -eq 'Set-ADUser')
        $writes.Count | Should -BeGreaterThan 0
        ($writes | ConvertTo-Json -Depth 10) | Should -Not -Match 'legacyExchangeDN'
        # Recover: the field is empty (nothing to verify after a rollback) and legacyExchangeDN is still untouched.
        $context.Action='Recover'; $context.Source=$receipt; $context.SourceBackupHash=$receipt.Hash
        $recover=@(foreach ($record in $receipt.Data.Records) { New-PraPlan $context $record.ObjectGuid 'Recover' $record })
        @($recover[0].Record.ExpectedX500).Count | Should -Be 0
        $null=Invoke-PraAdBatch $context $recover 'Recover'
        $global:PraGateAd.Users[0].legacyExchangeDN | Should -BeExactly '/o=Synthetic/ou=Gate/cn=Recipients/cn=user1'
        (Get-GateEvents $global:PraGate.Runtime | Where-Object Operation -eq 'Set-ADUser' | ConvertTo-Json -Depth 10) | Should -Not -Match 'legacyExchangeDN'
    }
    It 'shows "X500 to verify after the conversion: N" per object in the plan (information, nothing changes)' {
        $context=$global:PraGate.Context
        $context.Mode='Preview'; $context.AllowMutation=$false
        $plans=@(New-PraPlan $context 'user1' 'Convert';New-PraPlan $context 'user2' 'Convert')
        Invoke-PraAdPreview $context $plans
        $log=[IO.File]::ReadAllText($context.LogFile)
        $log | Should -Match 'user1: X500 to verify after the conversion: 2'
        $log | Should -Match 'user2: X500 to verify after the conversion: 2'
        $log | Should -Match ([regex]::Escape('X500 to verify in Exchange Online : '+$global:PraGate.Legacy1))
        $context.Warnings | Should -Be 0
        @(Get-GateWrites $global:PraGate.Runtime).Count | Should -Be 0
        $global:PraGateAd.Users[0].PSObject.Properties.Remove('legacyExchangeDN')
        $global:PraGateAd.Users[0].proxyAddresses=[string[]]@($global:PraGateAd.Users[0].proxyAddresses | Where-Object { $_ -cne $global:PraGate.Older })
        Invoke-PraAdPreview $context @(New-PraPlan $context 'user1' 'Convert')
        [IO.File]::ReadAllText($context.LogFile) | Should -Match 'user1: X500 to verify after the conversion: 0 \(no legacyExchangeDN and no X500 address on premises\)'
    }
    It 'reads a record written before 3.1.0 (no ExpectedX500) and refuses an invalid field like KeptX500' {
        InModuleScope PRA.Directory {
            $plan=New-PraPlan $global:PraGate.Context 'user1' 'Convert'
            $record=($plan.Record | ConvertTo-Json -Depth 20 | ConvertFrom-Json -DateKind String)
            { Assert-PraStoredRecord $record } | Should -Not -Throw
            $record.PSObject.Properties.Remove('ExpectedX500')
            { Assert-PraStoredRecord $record } | Should -Not -Throw
            $bad=@{
                NotX500=@('smtp:not.x500@gate.invalid'); NullEntry=@('X500:/o=a',$null); Number=@(7); HashTable=@(@{Value='X500:/o=a'})
                TooLong=@('X500:'+('a' * 2100)); TooMany=@(1..2001 | ForEach-Object { 'X500:/o=Synthetic/cn=' + $_ }); Object=([pscustomobject]@{Value='X500:/o=a'})
            }
            foreach ($name in $bad.Keys) {
                $record | Add-Member -NotePropertyName ExpectedX500 -NotePropertyValue $bad[$name] -Force
                { Assert-PraStoredRecord $record } | Should -Throw '*expected X500*' -Because $name
            }
            $record | Add-Member -NotePropertyName ExpectedX500 -NotePropertyValue @('X500:/o=a','x500:/o=B') -Force
            { Assert-PraStoredRecord $record } | Should -Not -Throw
        }
    }
    It 'refuses a re-read batch whose expected X500 list differs from the plan, and refuses an object with too many X500 addresses before any change' {
        InModuleScope PRA.Directory {
            $plan=New-PraPlan $global:PraGate.Context 'user1' 'Convert'
            $stored=($plan.Record | ConvertTo-Json -Depth 20 | ConvertFrom-Json -DateKind String)
            { Assert-PraRecordMatchesPlan -Stored $stored -Expected $plan.Record } | Should -Not -Throw
            $stored.ExpectedX500=@($stored.ExpectedX500[0])
            { Assert-PraRecordMatchesPlan -Stored $stored -Expected $plan.Record } | Should -Throw '*expected X500 addresses not preserved*'
            $stored.ExpectedX500=@($stored.ExpectedX500[0],($plan.Record.ExpectedX500[1].ToLowerInvariant()))
            { Assert-PraRecordMatchesPlan -Stored $stored -Expected $plan.Record } | Should -Throw '*expected X500 addresses not preserved*'
            $global:PraGateAd.Users[0].proxyAddresses=[string[]]@(1..2001 | ForEach-Object { 'X500:/o=Synthetic/cn=' + $_ })
            { New-PraPlan $global:PraGate.Context 'user1' 'Convert' } | Should -Throw '*Too many X500 addresses*'
        }
        @(Get-GateWrites $global:PraGate.Runtime).Count | Should -Be 0
    }
}

Describe 'Release 3.1.0 - X500 control: Exchange Online side (production Cloud module, mocked boundaries, no network)' -Tag 'Lot6' {
    BeforeAll {
        $global:PraGate.X500NetworkPath=Join-Path $global:PraGate.Root 'PraGateX500Network.psm1'
        $networkSource=@'
if ($env:PRA_GATE_NONET -cne 'SYNTHETIC-NO-NETWORK') { throw 'Synthetic interlock absent.' }
function Get-EXOMailbox { [CmdletBinding()]param($Filter,$Properties,$ResultSize,[switch]$InactiveMailboxOnly) throw 'SYNTHETIC BLOCK: EXO mailbox' }
function Get-EXORecipient { [CmdletBinding()]param($UserPrincipalName,$Filter,$Properties,$ResultSize) throw 'SYNTHETIC BLOCK: EXO recipient' }
function Get-MgUser { [CmdletBinding()]param($UserId,$Property) throw 'SYNTHETIC BLOCK: Graph user' }
function Get-MgUserLicenseDetail { [CmdletBinding()]param($UserId,[switch]$All) throw 'SYNTHETIC BLOCK: Graph license' }
function Get-MgContext { [CmdletBinding()]param() [pscustomobject]@{TenantId='20000000-0000-0000-0000-000000000002';ContextScope='Process'} }
function Get-ConnectionInformation { [CmdletBinding()]param() [pscustomobject]@{TenantID='20000000-0000-0000-0000-000000000002';State='Connected';TokenStatus='Active';ConnectionId='30000000-0000-0000-0000-000000000003';ModuleName=$global:PraGate.X500NetworkPath} }
Export-ModuleMember -Function Get-EXOMailbox,Get-EXORecipient,Get-MgUser,Get-MgUserLicenseDetail,Get-ConnectionInformation,Get-MgContext
'@
        [IO.File]::WriteAllText($global:PraGate.X500NetworkPath,$networkSource,(New-Object Text.UTF8Encoding($true)))
        Get-Module PRA.Cloud -All | Remove-Module -Force -ErrorAction SilentlyContinue
        Import-Module $global:PraGate.X500NetworkPath -Global -Force
        Import-Module (Join-Path $global:PraGate.Package 'module\PRA.Cloud.psm1') -Force -Global
        $global:PraGate.X500Legacy='X500:/o=Synthetic/ou=Gate/cn=Recipients/cn=user1'
        $global:PraGate.X500Older='X500:/o=Synthetic/ou=Gate/cn=User'
        $global:PraGate.X500Oldest='X500:/o=Contoso/ou=First Administrative Group/cn=Recipients/cn=user1'
        function global:New-X500Row {
            param([string]$Upn='user1@gate.invalid',[string]$Guid='00000000-0000-0000-0000-000000000001',[string[]]$Expected,[switch]$NoField,[string]$Note='')
            $record=[ordered]@{ObjectGuid=$Guid;UserPrincipalName=$Upn;IsShared=$false}
            if (-not $NoField) { $record.ExpectedX500=[string[]]$Expected }
            if ($Note) { $record.ExpectedX500Note=$Note }
            New-PraRow $global:PraGate.CloudContext ([pscustomobject]$record)
        }
        function global:Get-X500Log { [IO.File]::ReadAllText($global:PraGate.CloudContext.LogFile) }
    }
    BeforeEach {
        $global:PraGate.Runtime=New-GateRuntime -Name 'x500-cloud'
        $context=New-GateContext $global:PraGate.Runtime -Mode Apply -Action Convert
        $context.Phase='Cloud'; $context.Once=$false; $context.CheckScope='Both'; $context.IntervalMinutes=0; $context.TimeoutMinutes=5
        $context.Config.Cloud=@{CheckMailbox=$true;CheckLicense=$false;MailboxCheckVia='Exo';RequiredSkuPartNumber='';TenantId='20000000-0000-0000-0000-000000000002'}
        $context.Config.SharedMailbox.GrantFullAccess=$false
        $context.LogFile=Join-Path $global:PraGate.Runtime.Root 'logs\x500-cloud.log'
        $global:PraGate.CloudContext=$context
        $global:PraGate.X500Calls=0; $global:PraGate.X500Reply=$null
        $global:PraGate.X500Binding=@{TenantId='20000000-0000-0000-0000-000000000002';ConnectionId='30000000-0000-0000-0000-000000000003';ModuleLocation=$global:PraGate.X500NetworkPath;ModulePath=$global:PraGate.X500NetworkPath}
    }
    AfterAll {
        Remove-Item -LiteralPath 'Function:\New-X500Row','Function:\Get-X500Log' -ErrorAction SilentlyContinue
        Remove-Module PRA.Cloud,PraGateX500Network -Force -ErrorAction SilentlyContinue
    }
    It 'every expected address present (case of the type prefix may differ): an Ok line, no warning, one read' {
        $global:PraGate.CloudRow=New-X500Row -Expected @($global:PraGate.X500Legacy,$global:PraGate.X500Older,$global:PraGate.X500Oldest)
        $global:PraGate.X500Reply=[pscustomobject]@{RecipientTypeDetails='UserMailbox';EmailAddresses=[string[]]@('SMTP:user1@gate.invalid','smtp:user1@synthetic.mail.onmicrosoft.com',$global:PraGate.X500Legacy.Replace('X500:','x500:'),$global:PraGate.X500Older,$global:PraGate.X500Oldest)}
        InModuleScope PRA.Cloud {
            Mock Connect-PraCloudSession { param($Context) $Context['_PraCloudSession']=@{Graph=$false;Exo=$true;Subprocess=$false;Binding=$global:PraGate.X500Binding} }
            Mock Close-PraCloudSession { }
            Mock Start-Sleep { }
            Mock Get-EXOMailbox { $global:PraGate.X500Calls++; $global:PraGate.X500Reply }
            Invoke-PraCloudPhase $global:PraGate.CloudContext @($global:PraGate.CloudRow) 'Convert'
        }
        $row=$global:PraGate.CloudRow
        $row.CloudStatus | Should -BeExactly 'Success'
        $row.FinalStatus | Should -BeExactly 'Success'
        $row.Warnings | Should -BeNullOrEmpty
        $row.CloudDetail | Should -Match 'X500:present=3/3'
        $global:PraGate.CloudContext.Warnings | Should -Be 0
        $global:PraGate.CloudContext.Issues.Count | Should -Be 0
        @(Get-PraList $global:PraGate.CloudContext 'X500Missing').Count | Should -Be 0
        Get-X500Log | Should -Match ([regex]::Escape('user1@gate.invalid: X500: 3 of 3 present (legacyExchangeDN + older X500)'))
        $global:PraGate.X500Calls | Should -Be 1
    }
    It 'one address missing after the bounded re-reads: ONE warning listing it (not an error), counted everywhere, the conversion stays done' {
        $global:PraGate.CloudRow=New-X500Row -Expected @($global:PraGate.X500Legacy,$global:PraGate.X500Older,$global:PraGate.X500Oldest)
        $global:PraGate.X500Reply=[pscustomobject]@{RecipientTypeDetails='UserMailbox';EmailAddresses=[string[]]@('SMTP:user1@gate.invalid',$global:PraGate.X500Legacy,$global:PraGate.X500Older)}
        InModuleScope PRA.Cloud {
            Mock Connect-PraCloudSession { param($Context) $Context['_PraCloudSession']=@{Graph=$false;Exo=$true;Subprocess=$false;Binding=$global:PraGate.X500Binding} }
            Mock Close-PraCloudSession { }
            Mock Start-Sleep { }
            Mock Get-EXOMailbox { $global:PraGate.X500Calls++; $global:PraGate.X500Reply }
            Invoke-PraCloudPhase $global:PraGate.CloudContext @($global:PraGate.CloudRow) 'Convert'
        }
        $row=$global:PraGate.CloudRow; $context=$global:PraGate.CloudContext
        $global:PraGate.X500Calls | Should -Be 3 -Because 'the first read and two re-reads, never a long new wait'
        $row.CloudStatus | Should -BeExactly 'Success'
        $row.FinalStatus | Should -BeExactly 'Success'
        $context.Issues.Count | Should -Be 0
        $context.Warnings | Should -Be 1
        $warnings=@(Get-PraList $context 'WarningList')
        $warnings.Count | Should -Be 1
        $warnings[0].Message | Should -BeExactly ('user1@gate.invalid: X500 missing in Exchange Online: '+$global:PraGate.X500Oldest+'. Not serious: the mailbox works. Until this address appears, a reply to a very old message could bounce. To fix it, run an Entra Connect sync, then run -Action Check.')
        $row.Warnings | Should -Match ([regex]::Escape($global:PraGate.X500Oldest))
        $row.CloudDetail | Should -Match 'X500:missing=1/3'
        @(Get-PraList $context 'X500Missing') | Should -BeExactly @('user1@gate.invalid')
        @(Get-PraList $context 'Journey' | Where-Object { $_.Status -eq 'Warn' -and $_.Text -match 'X500 missing' }).Count | Should -Be 1
        Get-X500Log | Should -Match '\[WARN  \] user1@gate.invalid: X500 missing in Exchange Online'
        Get-X500Log | Should -Match ([regex]::Escape('user1@gate.invalid | X500 missing in Exchange Online : '+$global:PraGate.X500Oldest))
    }
    It 'the LegacyExchangeDN of the cloud mailbox itself counts as the X500 address it carries (Exchange Online never lists it in EmailAddresses): no false warning' {
        $own='/o=Synthetic/ou=Gate/cn=Recipients/cn=user1'
        $global:PraGate.CloudRow=New-X500Row -Expected @($global:PraGate.X500Legacy,$global:PraGate.X500Older)
        # EmailAddresses has the older address only; the mailbox's own LegacyExchangeDN is its own property (another case: the comparison ignores it).
        $global:PraGate.X500Reply=[pscustomobject]@{RecipientTypeDetails='UserMailbox';EmailAddresses=[string[]]@('SMTP:user1@gate.invalid',$global:PraGate.X500Older);LegacyExchangeDN=$own.ToUpperInvariant()}
        InModuleScope PRA.Cloud {
            Mock Connect-PraCloudSession { param($Context) $Context['_PraCloudSession']=@{Graph=$false;Exo=$true;Subprocess=$false;Binding=$global:PraGate.X500Binding} }
            Mock Close-PraCloudSession { }
            Mock Start-Sleep { }
            Mock Get-EXOMailbox { param($Filter,$Properties,$ResultSize) $global:PraGate.X500Calls++; $global:PraGate.X500Props=@($Properties); $global:PraGate.X500Reply }
            Invoke-PraCloudPhase $global:PraGate.CloudContext @($global:PraGate.CloudRow) 'Convert'
        }
        $global:PraGate.X500Props | Should -Contain 'LegacyExchangeDN' -Because 'the property is asked for'
        $row=$global:PraGate.CloudRow
        $row.CloudDetail | Should -Match 'X500:present=2/2'
        $row.Warnings | Should -BeNullOrEmpty
        $global:PraGate.CloudContext.Warnings | Should -Be 0
        $global:PraGate.X500Calls | Should -Be 1 -Because 'one read is enough'
        # The LegacyExchangeDN of ANOTHER object is not the one of this mailbox: it does not count.
        $global:PraGate.X500Calls=0
        $global:PraGate.CloudRow=New-X500Row -Expected @($global:PraGate.X500Legacy)
        $global:PraGate.X500Reply=[pscustomobject]@{RecipientTypeDetails='UserMailbox';EmailAddresses=[string[]]@('SMTP:user1@gate.invalid');LegacyExchangeDN='/o=Synthetic/ou=Gate/cn=Recipients/cn=somebody-else'}
        InModuleScope PRA.Cloud {
            Mock Connect-PraCloudSession { param($Context) $Context['_PraCloudSession']=@{Graph=$false;Exo=$true;Subprocess=$false;Binding=$global:PraGate.X500Binding} }
            Mock Close-PraCloudSession { }
            Mock Start-Sleep { }
            Mock Get-EXOMailbox { $global:PraGate.X500Calls++; $global:PraGate.X500Reply }
            Invoke-PraCloudPhase $global:PraGate.CloudContext @($global:PraGate.CloudRow) 'Convert'
        }
        $global:PraGate.CloudRow.CloudDetail | Should -Match 'X500:missing=1/1'
        $global:PraGate.CloudContext.Warnings | Should -Be 1
    }
    It 'while only the X500 addresses are awaited the log says that the mailbox is ready (not "Not ready yet"), counts the checks, and never waits more than two more checks' {
        $global:PraGate.CloudRow=New-X500Row -Expected @($global:PraGate.X500Legacy,$global:PraGate.X500Oldest)
        $global:PraGate.X500Reply=[pscustomobject]@{RecipientTypeDetails='UserMailbox';EmailAddresses=[string[]]@('SMTP:user1@gate.invalid',$global:PraGate.X500Legacy)}
        $global:PraGate.CloudContext.IntervalMinutes=1; $global:PraGate.CloudContext.TimeoutMinutes=60
        InModuleScope PRA.Cloud {
            Mock Connect-PraCloudSession { param($Context) $Context['_PraCloudSession']=@{Graph=$false;Exo=$true;Subprocess=$false;Binding=$global:PraGate.X500Binding} }
            Mock Close-PraCloudSession { }
            Mock Start-Sleep { $global:PraGate.X500Slept++ }
            Mock Get-EXOMailbox { $global:PraGate.X500Calls++; $global:PraGate.X500Reply }
            $global:PraGate.X500Slept=0
            Invoke-PraCloudPhase $global:PraGate.CloudContext @($global:PraGate.CloudRow) 'Convert'
        }
        $log=Get-X500Log
        $log | Should -Match ([regex]::Escape('user1@gate.invalid: mailbox ready; X500 addresses not all visible yet, check 2 of 3 in 60 s'))
        $log | Should -Match ([regex]::Escape('user1@gate.invalid: mailbox ready; X500 addresses not all visible yet, check 3 of 3 in 60 s'))
        $log | Should -Not -Match 'Not ready yet' -Because 'the mailbox is ready: only the X500 addresses are awaited'
        $global:PraGate.X500Calls | Should -Be 3
        $global:PraGate.X500Slept | Should -Be 2 -Because 'two waits only, whatever the 60 minutes of Polling.TimeoutMinutes'
        $global:PraGate.CloudContext.Warnings | Should -Be 1
    }
    It 'a value that lags one synchronisation: missing at the first read, present at the second: Ok after the re-read, progress events sent' {
        $global:PraGate.CloudRow=New-X500Row -Expected @($global:PraGate.X500Legacy,$global:PraGate.X500Older)
        $global:PraGate.X500Reply=[pscustomobject]@{RecipientTypeDetails='UserMailbox';EmailAddresses=[string[]]@('SMTP:user1@gate.invalid',$global:PraGate.X500Legacy)}
        $eventFile=Join-Path $global:PraGate.Runtime.Root 'x500.events.jsonl'; $oldEvent=$env:PRA_EVENT_FILE; $env:PRA_EVENT_FILE=$eventFile
        try {
            InModuleScope PRA.Cloud {
                Mock Connect-PraCloudSession { param($Context) $Context['_PraCloudSession']=@{Graph=$false;Exo=$true;Subprocess=$false;Binding=$global:PraGate.X500Binding} }
                Mock Close-PraCloudSession { }
                Mock Start-Sleep { }
                Mock Get-EXOMailbox {
                    $global:PraGate.X500Calls++
                    if ($global:PraGate.X500Calls -ge 2) { $global:PraGate.X500Reply.EmailAddresses=[string[]]@('SMTP:user1@gate.invalid',$global:PraGate.X500Legacy,$global:PraGate.X500Older) }
                    $global:PraGate.X500Reply
                }
                Invoke-PraCloudPhase $global:PraGate.CloudContext @($global:PraGate.CloudRow) 'Convert'
            }
        } finally { $env:PRA_EVENT_FILE=$oldEvent }
        $row=$global:PraGate.CloudRow; $context=$global:PraGate.CloudContext
        $global:PraGate.X500Calls | Should -Be 2
        $row.CloudStatus | Should -BeExactly 'Success'
        $context.Warnings | Should -Be 0
        $context.Issues.Count | Should -Be 0
        @(Get-PraList $context 'X500Missing').Count | Should -Be 0
        Get-X500Log | Should -Match ([regex]::Escape('user1@gate.invalid: X500: 2 of 2 present (legacyExchangeDN + older X500)'))
        $progress=@(Get-Content -LiteralPath $eventFile -Encoding UTF8 | ForEach-Object { $_ | ConvertFrom-Json -DateKind String } | Where-Object kind -eq 'progress')
        $progress.Count | Should -BeGreaterThan 0
        ($progress.text -join ' ') | Should -Match 'Waiting for the X500 addresses to appear in Exchange Online'
    }
    It 'a batch without the field (3.0.0 or older) is skipped with an explicit information line, never a warning or a failure' {
        $global:PraGate.CloudRow=New-X500Row -NoField
        $global:PraGate.X500Reply=[pscustomobject]@{RecipientTypeDetails='UserMailbox';EmailAddresses=[string[]]@('SMTP:user1@gate.invalid')}
        InModuleScope PRA.Cloud {
            Mock Connect-PraCloudSession { param($Context) $Context['_PraCloudSession']=@{Graph=$false;Exo=$true;Subprocess=$false;Binding=$global:PraGate.X500Binding} }
            Mock Close-PraCloudSession { }
            Mock Start-Sleep { }
            Mock Get-EXOMailbox { $global:PraGate.X500Calls++; $global:PraGate.X500Reply }
            Invoke-PraCloudPhase $global:PraGate.CloudContext @($global:PraGate.CloudRow) 'Convert'
        }
        $global:PraGate.CloudRow.CloudStatus | Should -BeExactly 'Success'
        $global:PraGate.CloudContext.Warnings | Should -Be 0
        $global:PraGate.CloudContext.Issues.Count | Should -Be 0
        $global:PraGate.X500Calls | Should -Be 1
        Get-X500Log | Should -Match ([regex]::Escape('user1@gate.invalid: X500 control skipped, expected addresses not available (batch from 3.0.0 or older)'))
    }
    It 'an empty list (no legacyExchangeDN, no X500) says there is nothing to verify' {
        $global:PraGate.CloudRow=New-X500Row -Expected @()
        $global:PraGate.X500Reply=[pscustomobject]@{RecipientTypeDetails='UserMailbox';EmailAddresses=[string[]]@('SMTP:user1@gate.invalid')}
        InModuleScope PRA.Cloud {
            Mock Connect-PraCloudSession { param($Context) $Context['_PraCloudSession']=@{Graph=$false;Exo=$true;Subprocess=$false;Binding=$global:PraGate.X500Binding} }
            Mock Close-PraCloudSession { }
            Mock Start-Sleep { }
            Mock Get-EXOMailbox { $global:PraGate.X500Calls++; $global:PraGate.X500Reply }
            Invoke-PraCloudPhase $global:PraGate.CloudContext @($global:PraGate.CloudRow) 'Convert'
        }
        $global:PraGate.CloudRow.CloudStatus | Should -BeExactly 'Success'
        $global:PraGate.CloudContext.Warnings | Should -Be 0
        Get-X500Log | Should -Match 'X500 control skipped, nothing to verify'
    }
    It 'EmailAddresses not returned by Exchange Online: a warning (cannot be proven), not an error, and the request asks for the property' {
        $global:PraGate.CloudRow=New-X500Row -Expected @($global:PraGate.X500Legacy)
        $global:PraGate.X500Reply=[pscustomobject]@{RecipientTypeDetails='UserMailbox'}
        InModuleScope PRA.Cloud {
            Mock Connect-PraCloudSession { param($Context) $Context['_PraCloudSession']=@{Graph=$false;Exo=$true;Subprocess=$false;Binding=$global:PraGate.X500Binding} }
            Mock Close-PraCloudSession { }
            Mock Start-Sleep { }
            Mock Get-EXOMailbox { param($Filter,$Properties,$ResultSize) $global:PraGate.X500Calls++; $global:PraGate.X500Props=@($Properties); $global:PraGate.X500Reply }
            Invoke-PraCloudPhase $global:PraGate.CloudContext @($global:PraGate.CloudRow) 'Convert'
        }
        $global:PraGate.X500Props | Should -Contain 'EmailAddresses'
        $global:PraGate.CloudRow.CloudStatus | Should -BeExactly 'Success'
        $global:PraGate.CloudContext.Issues.Count | Should -Be 0
        $global:PraGate.CloudContext.Warnings | Should -Be 1
        $global:PraGate.CloudRow.Warnings | Should -Match 'X500 could not be verified in Exchange Online \(EmailAddresses not returned by Exchange Online\)'
    }
    It 'a single look (preview or -Once) reads once, never waits, and warns about what is missing' {
        $global:PraGate.CloudRow=New-X500Row -Expected @($global:PraGate.X500Legacy,$global:PraGate.X500Older)
        $global:PraGate.CloudContext.Mode='Preview'; $global:PraGate.CloudContext.AllowMutation=$false; $global:PraGate.CloudContext.Once=$true
        $global:PraGate.X500Reply=[pscustomobject]@{RecipientTypeDetails='UserMailbox';EmailAddresses=[string[]]@($global:PraGate.X500Legacy)}
        InModuleScope PRA.Cloud {
            Mock Connect-PraCloudSession { param($Context) $Context['_PraCloudSession']=@{Graph=$false;Exo=$true;Subprocess=$false;Binding=$global:PraGate.X500Binding} }
            Mock Close-PraCloudSession { }
            Mock Start-Sleep { throw 'A single look must not wait.' }
            Mock Get-EXOMailbox { $global:PraGate.X500Calls++; $global:PraGate.X500Reply }
            Invoke-PraCloudPhase $global:PraGate.CloudContext @($global:PraGate.CloudRow) 'Convert'
        }
        $global:PraGate.X500Calls | Should -Be 1
        $global:PraGate.CloudContext.Warnings | Should -Be 1
        $global:PraGate.CloudContext.Issues.Count | Should -Be 0
        $global:PraGate.CloudRow.Warnings | Should -Match ([regex]::Escape($global:PraGate.X500Older))
    }
    It 'two objects: the one that is complete is Ok, the other one warns, and the next-step list counts only the second' {
        $global:PraGate.CloudRow=New-X500Row -Expected @($global:PraGate.X500Legacy)
        $second=New-X500Row -Upn 'user2@gate.invalid' -Guid '00000000-0000-0000-0000-000000000002' -Expected @('X500:/o=Synthetic/ou=Gate/cn=Recipients/cn=user2')
        $global:PraGate.X500Reply=[pscustomobject]@{RecipientTypeDetails='UserMailbox';EmailAddresses=[string[]]@($global:PraGate.X500Legacy)}
        $global:PraGate.X500Second=$second
        InModuleScope PRA.Cloud {
            Mock Connect-PraCloudSession { param($Context) $Context['_PraCloudSession']=@{Graph=$false;Exo=$true;Subprocess=$false;Binding=$global:PraGate.X500Binding} }
            Mock Close-PraCloudSession { }
            Mock Start-Sleep { }
            Mock Get-EXOMailbox { $global:PraGate.X500Calls++; $global:PraGate.X500Reply }
            Invoke-PraCloudPhase $global:PraGate.CloudContext @($global:PraGate.CloudRow,$global:PraGate.X500Second) 'Convert'
        }
        $global:PraGate.CloudRow.Warnings | Should -BeNullOrEmpty
        $global:PraGate.X500Second.Warnings | Should -Match 'user2@gate.invalid: X500 missing in Exchange Online: X500:/o=Synthetic/ou=Gate/cn=Recipients/cn=user2'
        @(Get-PraList $global:PraGate.CloudContext 'X500Missing') | Should -BeExactly @('user2@gate.invalid')
        $global:PraGate.CloudContext.Warnings | Should -Be 1
        $global:PraGate.CloudRow.CloudStatus | Should -BeExactly 'Success'
        $global:PraGate.X500Second.CloudStatus | Should -BeExactly 'Success'
    }
    It 'Microsoft Graph mailbox check: the Entra proxyAddresses are compared, so no Exchange Online session is needed' {
        $global:PraGate.CloudContext.Config.Cloud.MailboxCheckVia='Graph'
        $global:PraGate.CloudRow=New-X500Row -Expected @($global:PraGate.X500Legacy,$global:PraGate.X500Older)
        InModuleScope PRA.Cloud {
            Mock Connect-PraCloudSession { param($Context) $Context['_PraCloudSession']=@{Graph=$true;Exo=$false;Subprocess=$false;GraphContext=@{TenantId='20000000-0000-0000-0000-000000000002';ContextScope='Process'}} }
            Mock Close-PraCloudSession { }
            Mock Start-Sleep { }
            Mock Get-EXOMailbox { throw 'The Graph path must not call Exchange Online.' }
            Mock Get-MgUser {
                $global:PraGate.X500Calls++
                [pscustomobject]@{assignedPlans=@([pscustomobject]@{Service='exchange';CapabilityStatus='Enabled'});provisionedPlans=@([pscustomobject]@{Service='exchange';ProvisioningStatus='Success'})
                    proxyAddresses=[string[]]@('SMTP:user1@gate.invalid',$global:PraGate.X500Legacy,$global:PraGate.X500Older)}
            }
            Mock Get-MgUserLicenseDetail { [pscustomobject]@{SkuPartNumber='SYNTHETIC';ServicePlans=@([pscustomobject]@{ServicePlanName='EXCHANGE_S_ENTERPRISE';ProvisioningStatus='Success'})} }
            Invoke-PraCloudPhase $global:PraGate.CloudContext @($global:PraGate.CloudRow) 'Convert'
        }
        $global:PraGate.CloudRow.CloudStatus | Should -BeExactly 'Success'
        $global:PraGate.CloudContext.Warnings | Should -Be 0
        $global:PraGate.X500Calls | Should -Be 1
        Get-X500Log | Should -Match ([regex]::Escape('X500: 2 of 2 present'))
    }
    It 'Check shows the same comparison read-only (present, missing) and says when the identity was given as a UPN' {
        $context=$global:PraGate.CloudContext
        $context.Mode='Preview'; $context.Action='Check'; $context.AllowMutation=$false; $context.Once=$false; $context.TimeoutMinutes=1
        $global:PraGate.CloudRow=New-X500Row -Expected @($global:PraGate.X500Legacy,$global:PraGate.X500Older)
        $global:PraGate.X500Second=New-X500Row -Upn 'upn.only@gate.invalid' -Guid '00000000-0000-0000-0000-000000000009' -NoField -Note 'identity given as a UPN, no Active Directory read: give the sAMAccountName or -Batch'
        $global:PraGate.X500Reply=[pscustomobject]@{RecipientTypeDetails='UserMailbox';EmailAddresses=[string[]]@($global:PraGate.X500Legacy)}
        InModuleScope PRA.Cloud {
            Mock Connect-PraCloudSession { param($Context) $Context['_PraCloudSession']=@{Graph=$false;Exo=$true;Subprocess=$false;Binding=$global:PraGate.X500Binding} }
            Mock Close-PraCloudSession { }
            Mock Start-Sleep { }
            Mock Get-EXOMailbox { $global:PraGate.X500Calls++; $global:PraGate.X500Reply }
            Invoke-PraCloudPhase $global:PraGate.CloudContext @($global:PraGate.CloudRow,$global:PraGate.X500Second) 'Convert'
        }
        $global:PraGate.CloudRow.Warnings | Should -Match ([regex]::Escape($global:PraGate.X500Older))
        $global:PraGate.CloudContext.Warnings | Should -Be 1
        Get-X500Log | Should -Match ([regex]::Escape('upn.only@gate.invalid: X500 control skipped, expected addresses not available (identity given as a UPN'))
        @(Get-GateWrites $global:PraGate.Runtime).Count | Should -Be 0
    }
    It 'the warning travels into the run result, the per-phase data and the global report, HTML-encoded and without markup injection' {
        $hostile='X500:/o=Synthetic/cn=<b>A&B</b> "q"'
        $global:PraGate.CloudRow=New-X500Row -Expected @($global:PraGate.X500Legacy,$hostile)
        $global:PraGate.X500Reply=[pscustomobject]@{RecipientTypeDetails='UserMailbox';EmailAddresses=[string[]]@($global:PraGate.X500Legacy)}
        InModuleScope PRA.Cloud {
            Mock Connect-PraCloudSession { param($Context) $Context['_PraCloudSession']=@{Graph=$false;Exo=$true;Subprocess=$false;Binding=$global:PraGate.X500Binding} }
            Mock Close-PraCloudSession { }
            Mock Start-Sleep { }
            Mock Get-EXOMailbox { $global:PraGate.X500Calls++; $global:PraGate.X500Reply }
            Invoke-PraCloudPhase $global:PraGate.CloudContext @($global:PraGate.CloudRow) 'Convert'
        }
        $context=$global:PraGate.CloudContext
        $context.Rows.Add($global:PraGate.CloudRow); $context.BatchId='abcd1234'; $context.NextSteps=@(); $context.PhaseFolders=@()
        @(Get-PraList $context 'WarningList').Count | Should -Be 1
        $phase = New-PraPhaseRecord -Context $context
        (@(Get-PraList $phase 'Warnings') | ForEach-Object { $_.Message }) -join ' ' | Should -Match 'X500 missing in Exchange Online'
        $report=Write-PraGlobalReport -Context $context
        $html=[IO.File]::ReadAllText($report.Html)
        $html | Should -Not -Match '<b>A&B</b>'
        $html | Should -Match ([regex]::Escape('&lt;b&gt;A&amp;B&lt;/b&gt;'))
        $html | Should -Match 'X500 missing in Exchange Online'
        $csv=[IO.File]::ReadAllText($report.Csv)
        $csv | Should -Match 'X500 missing in Exchange Online'
    }
    It 'two servers: the expected X500 list travels in the transfer package and is the one the cloud server proves' {
        $adRuntime=New-GateRuntime -Name 'x500-two-ad'
        $oldEvent=$env:PRA_EVENT_FILE; $env:PRA_EVENT_FILE=Join-Path $adRuntime.Root 'engine.events.jsonl'
        try {
            $run=Invoke-GateProcess $adRuntime @{Action='Convert';Phase='AD';Mode='Apply';Force=$true;ConfigPath=$adRuntime.ConfigPath} -TimeoutSeconds 120
            $run.ExitCode | Should -BeIn @(0,2) -Because ($run.Output+$run.Error)
            $zip=@(Get-Content -LiteralPath $env:PRA_EVENT_FILE -Encoding UTF8 | ForEach-Object { $_ | ConvertFrom-Json -DateKind String } | Where-Object kind -eq 'result')[0].transferPackage
        } finally { $env:PRA_EVENT_FILE=$oldEvent }
        $cloudRuntime=New-GateRuntime -Name 'x500-two-cloud'
        $imported=Import-PraTransferPackage -Path $zip -BackupFolder $cloudRuntime.State.BackupFolder -Environment SYNTHETIC_GATE -ExpectedKind Convert
        $batchFile=@(Get-ChildItem -LiteralPath $imported.Folders[0] -File -Filter 'Convert-*.json' | Where-Object { -not $_.Name.EndsWith('.sha256',[StringComparison]::Ordinal) })[0]
        $importContext=New-GateContext $cloudRuntime
        $receipt=Import-PraBackup $importContext $batchFile.FullName
        @($receipt.Data.Records[0].ExpectedX500) | Should -BeExactly @($global:PraGate.X500Legacy,$global:PraGate.X500Older)
        # the cloud server: the row is built from the stored record, exactly as the entry script does
        $global:PraGate.CloudRow=New-X500Row -Expected @()
        $global:PraGate.CloudRow.BackupRec=$receipt.Data.Records[0]
        $global:PraGate.X500Reply=[pscustomobject]@{RecipientTypeDetails='UserMailbox';EmailAddresses=[string[]]@($global:PraGate.X500Legacy)}
        InModuleScope PRA.Cloud {
            Mock Connect-PraCloudSession { param($Context) $Context['_PraCloudSession']=@{Graph=$false;Exo=$true;Subprocess=$false;Binding=$global:PraGate.X500Binding} }
            Mock Close-PraCloudSession { }
            Mock Start-Sleep { }
            Mock Get-EXOMailbox { $global:PraGate.X500Calls++; $global:PraGate.X500Reply }
            Invoke-PraCloudPhase $global:PraGate.CloudContext @($global:PraGate.CloudRow) 'Convert'
        }
        $global:PraGate.CloudContext.Warnings | Should -Be 1
        $global:PraGate.CloudRow.Warnings | Should -Match ([regex]::Escape('X500 missing in Exchange Online: '+$global:PraGate.X500Older+'.'))
        $global:PraGate.CloudRow.CloudStatus | Should -BeExactly 'Success'
    }
}

Describe 'Release 3.1.0 - X500 control through the real main (Check of one identity, Next steps)' -Tag 'Lot6' {
    It 'Check -Identity <Identity> reads legacyExchangeDN in Active Directory (sAMAccountName) or says why it cannot (UPN)' -ForEach @(
        @{Identity='user1';Expected='X500:/o=Synthetic/ou=Gate/cn=Recipients/cn=user1|X500:/o=Synthetic/ou=Gate/cn=User';Note=''}
        @{Identity='user1@gate.invalid';Expected='';Note='identity given as a UPN, no Active Directory read'}
    ) {
        $runtime=New-GateRuntime -Name 'x500-check-main'
        $run=Invoke-GateProcess $runtime @{Action='Check';Identity=$Identity;ConfigPath=$runtime.ConfigPath} -TimeoutSeconds 120
        $run.ExitCode | Should -BeIn @(0,2) -Because ($run.Output+$run.Error)
        $barrier=@($run.Events | Where-Object Operation -eq 'CloudRows-SyntheticBarrier')
        $barrier.Count | Should -Be 1
        $row=@($barrier[0].Rows)[0]
        (@($row.ExpectedX500) -join '|') | Should -BeExactly $Expected
        [string]$row.Note | Should -Match ([regex]::Escape($Note))
        @(Get-GateWrites $runtime).Count | Should -Be 0
    }
    It 'a missing X500 reported by the cloud phase is a warning in the result and a line in the Next steps with the Check command; the exit code does not change' {
        $runtime=New-GateRuntime -Name 'x500-next-steps' -Case CloudX500Missing
        $run=Invoke-GateProcess $runtime @{Action='Convert';Phase='Both';Mode='Apply';Force=$true;ConfigPath=$runtime.ConfigPath} -TimeoutSeconds 120
        $run.ExitCode | Should -Be 0 -Because ($run.Output+$run.Error)
        $run.MainResult.ErrorCount | Should -Be 0
        $run.MainResult.WarningCount | Should -BeGreaterThan 0
        $next=($run.MainResult.NextSteps -join "`n")
        $next | Should -Match 'X500 missing in Exchange Online for 1 object\(s\) \(replies to old messages can bounce\): run an Entra Connect synchronisation, then check again: \.\\Invoke-PraRemoteMailbox\.ps1 -Action Check -Batch [0-9a-f]{8} '
        $next | Should -Match 'To roll back this batch later'
        $run.Output | Should -Match 'X500 missing in Exchange Online'
    }
}

Describe 'Release 3.1.2 - the Entra Connect check proves the account, not the network (mocked remoting, no network)' -Tag 'Release312' {
    BeforeEach {
        # Real (thread) jobs stand for the remote job: the cmdlets of the module only accept a job, and nothing leaves this process.
        $global:PraGateT312 = @{ Computer = ''; AsJob = $false; Option = $null; Script = ''; Message = ''; Stopped = 0; Removed = 0; Job = $null; Slow = $null }
        $global:PraGateT312.Job = Start-ThreadJob -ScriptBlock { 1 }
        $null = Wait-Job -Job $global:PraGateT312.Job
        $global:PraGateT312.Slow = Start-ThreadJob -ScriptBlock { Start-Sleep -Seconds 120 }
    }
    AfterEach {
        foreach ($job in @($global:PraGateT312.Job, $global:PraGateT312.Slow)) { if ($null -ne $job) { Remove-Job -Job $job -Force -ErrorAction SilentlyContinue } }
        Remove-Variable PraGateT312 -Scope Global -ErrorAction SilentlyContinue
        Remove-Item -LiteralPath 'Function:\global:Get-ADSyncScheduler' -ErrorAction SilentlyContinue
    }
    It 'makes an authenticated, bounded, read-only call to EntraConnect.Server and accepts a real answer only' {
        InModuleScope PRA.Directory {
            Mock Invoke-Command { $global:PraGateT312.Computer = $ComputerName; $global:PraGateT312.AsJob = [bool]$AsJob; $global:PraGateT312.Option = $SessionOption; $global:PraGateT312.Script = $ScriptBlock.ToString(); $global:PraGateT312.Job }
            Mock Wait-Job { $Job }
            Mock Receive-Job { [pscustomobject]@{ Computer = 'SRV-SYNC01'; CycleEnabled = $true } }
            Mock Remove-Job { $global:PraGateT312.Removed++ }
            $answer = Test-PraSyncServer -Server 'SRV-SYNC01' -TimeoutSeconds 7
            $answer.Ok | Should -BeTrue
            $answer.Kind | Should -BeExactly 'Ok'
            $answer.Reason | Should -Match 'SRV-SYNC01 accepts this account'
            $global:PraGateT312.Computer | Should -BeExactly 'SRV-SYNC01'
            $global:PraGateT312.AsJob | Should -BeTrue
            $global:PraGateT312.Option.OpenTimeout.TotalSeconds | Should -Be 7 -Because 'the open time of the session is bounded'
            $global:PraGateT312.Option.OperationTimeout.TotalSeconds | Should -Be 7 -Because 'the operation time of the session is bounded'
            $global:PraGateT312.Script | Should -Match 'Get-ADSyncScheduler'
            $global:PraGateT312.Script | Should -Not -Match 'Start-ADSyncSyncCycle' -Because 'the check starts nothing'
            $global:PraGateT312.Removed | Should -Be 1
            $script:PraSyncProbe.ToString() | Should -Not -Match 'Set-|Start-|Add-|Remove-'
        }
        (Get-Content -LiteralPath (Join-Path $global:PraGate.Source 'Invoke-PraRemoteMailbox.ps1') -Raw) | Should -Not -Match 'Test-WSMan' -Because 'Test-WSMan does not authenticate'
    }
    It 'says in plain words why the check failed (<Name>), with what to do' -ForEach @(
        @{ Name = 'access denied';   Message = 'Connecting to remote server SRV-SYNC01 failed with the following error message : Access is denied. For more information, see the about_Remote_Troubleshooting Help topic.'; Kind = 'Denied';      Reason = 'this account has no right on SRV-SYNC01.*Remote Management Users or Administrators.*ADSyncOperators' }
        @{ Name = 'access denied (French Windows)'; Message = 'Accès refusé.'; Kind = 'Denied'; Reason = 'this account has no right on SRV-SYNC01' }
        @{ Name = 'server not reachable'; Message = 'The WinRM client cannot process the request because the server name cannot be resolved.'; Kind = 'Unreachable'; Reason = 'SRV-SYNC01 does not answer to PowerShell remoting \(WinRM, port 5985\): check the server name in EntraConnect.Server' }
        @{ Name = 'no ADSync module there'; Message = "The specified module 'ADSync' was not loaded because no valid module file was found in any module directory."; Kind = 'NoModule'; Reason = 'SRV-SYNC01 answered but the ADSync module is not installed there: it is not the Entra Connect server' }
        @{ Name = 'something else'; Message = 'Something unexpected happened.'; Kind = 'Failed'; Reason = '^Entra Connect could not be checked on SRV-SYNC01: Something unexpected happened$' }
    ) {
        $global:PraGateT312.Message = $Message; $global:PraGateT312.Kind = $Kind; $global:PraGateT312.Reason = $Reason
        InModuleScope PRA.Directory {
            Mock Invoke-Command { $global:PraGateT312.Job }
            Mock Wait-Job { $Job }
            Mock Receive-Job { throw $global:PraGateT312.Message }
            Mock Remove-Job { $global:PraGateT312.Removed++ }
            $answer = Test-PraSyncServer -Server 'SRV-SYNC01' -TimeoutSeconds 5
            $answer.Ok | Should -BeFalse
            $answer.Kind | Should -BeExactly $global:PraGateT312.Kind
            $answer.Reason | Should -Match $global:PraGateT312.Reason
            $answer.Technical | Should -Match ([regex]::Escape(($global:PraGateT312.Message -replace '\s+', ' ').Trim()))
            $global:PraGateT312.Removed | Should -Be 1 -Because 'the job is always removed'
        }
    }
    It 'treats an error raised while the job starts like any other failure, and a server that does not answer in time as not reachable' {
        InModuleScope PRA.Directory {
            Mock Invoke-Command { throw 'Access is denied' }
            (Test-PraSyncServer -Server 'SRV-SYNC01' -TimeoutSeconds 5).Kind | Should -BeExactly 'Denied'
        }
        InModuleScope PRA.Directory {
            Mock Invoke-Command { $global:PraGateT312.Slow }
            Mock Wait-Job { $null }
            Mock Stop-Job { $global:PraGateT312.Stopped++ }
            Mock Receive-Job { throw 'the answer must not be read after a time out' }
            Mock Remove-Job { $global:PraGateT312.Removed++ }
            $answer = Test-PraSyncServer -Server 'SRV-SYNC01' -TimeoutSeconds 5
            $answer.Ok | Should -BeFalse
            $answer.Kind | Should -BeExactly 'Unreachable'
            $answer.Technical | Should -BeExactly 'no answer within 5 seconds'
            $answer.Reason | Should -Match 'within 5 seconds'
            $global:PraGateT312.Stopped | Should -Be 1
            $global:PraGateT312.Removed | Should -Be 1
        }
    }
    It 'checks this server when no Entra Connect server is configured: the module must be there AND answer for this account' {
        InModuleScope PRA.Directory {
            Mock Get-Module { @() }
            $answer = Test-PraSyncServer
            $answer.Kind | Should -BeExactly 'NoModule'
            $answer.Reason | Should -Match 'ADSync module is not on this server'
        }
        function global:Get-ADSyncScheduler { [CmdletBinding()] param() [pscustomobject]@{ SyncCycleEnabled = $true; SyncCycleInProgress = $false } }
        InModuleScope PRA.Directory {
            Mock Get-Module { [pscustomobject]@{ Name = 'ADSync' } }
            Mock Import-Module { }
            (Test-PraSyncServer).Ok | Should -BeTrue
        }
        function global:Get-ADSyncScheduler { [CmdletBinding()] param() throw 'Access is denied.' }
        InModuleScope PRA.Directory {
            Mock Get-Module { [pscustomobject]@{ Name = 'ADSync' } }
            Mock Import-Module { }
            $answer = Test-PraSyncServer
            $answer.Kind | Should -BeExactly 'Denied'
            $answer.Reason | Should -Match 'no right to use Entra Connect on this server.*ADSyncOperators'
        }
    }
}

Describe 'Release 3.1.2 - Entra Connect sync through the real main: stop before any write, never stuck after one' -Tag 'Release312' {
    BeforeEach {
        $oldEventPath = $env:PRA_EVENT_FILE
        function script:Use-RemoteSync($Runtime, [string]$Mode) {
            $Runtime.State.RemoteSync = $Mode
            [IO.File]::WriteAllText($Runtime.StatePath, [Management.Automation.PSSerializer]::Serialize($Runtime.State, 35))
        }
        function script:Enable-SyncConfig($Runtime) {
            Set-GateConfigText $Runtime { param($t) $t.Replace('EntraConnect=@{Sync=$false;Server='''';', 'EntraConnect=@{Sync=$true;Server=''SRV-SYNC01'';') }
        }
    }
    AfterEach { $env:PRA_EVENT_FILE = $oldEventPath }

    It 'Preview reports that the sync will not be possible (<Mode>) and changes nothing' -ForEach @(
        @{ Mode = 'Denied';      Text = 'Entra Connect sync will not be possible: this account has no right on SRV-SYNC01' }
        @{ Mode = 'Unreachable'; Text = 'Entra Connect sync will not be possible: SRV-SYNC01 does not answer to PowerShell remoting' }
    ) {
        $runtime = New-GateRuntime -Name 'sync-preview'
        Enable-SyncConfig $runtime; Use-RemoteSync $runtime $Mode
        $run = Invoke-GateProcess $runtime @{Action='Convert';Phase='AD';Mode='Preview';ConfigPath=$runtime.ConfigPath} -TimeoutSeconds 120
        $run.ExitCode | Should -Be 0 -Because ($run.Output + $run.Error)
        $run.Output | Should -Match ([regex]::Escape($Text))
        $run.Output | Should -Match 'Either fix that, or set EntraConnect\.Sync = \$false in the configuration file and run the synchronisation yourself'
        $run.Output | Should -Not -Match 'reachable, a Delta cycle runs'
        $run.MainResult.WarningCount | Should -BeGreaterThan 0
        @(Get-GateWrites $runtime).Count | Should -Be 0
    }
    It 'Apply stops BEFORE any AD write when the sync cannot work for this account (<Mode>): exit 1, no backup, no write' -ForEach @(
        @{ Mode = 'Denied' }
        @{ Mode = 'Unreachable' }
    ) {
        $runtime = New-GateRuntime -Name 'sync-stop'
        Enable-SyncConfig $runtime; Use-RemoteSync $runtime $Mode
        $run = Invoke-GateProcess $runtime @{Action='Convert';Phase='AD';Mode='Apply';Force=$true;ConfigPath=$runtime.ConfigPath} -TimeoutSeconds 120
        $run.ExitCode | Should -Be 1
        $run.Output | Should -Match 'Entra Connect sync will not be possible'
        $run.Output | Should -Match 'Nothing was changed\.'
        @(Get-GateWrites $runtime).Count | Should -Be 0
        @(Get-ChildItem -LiteralPath $runtime.State.BackupFolder -Directory -ErrorAction SilentlyContinue).Count | Should -Be 0 -Because 'not even a backup is written'
        [string]$run.MainResult.TransferPackage | Should -BeExactly ''
    }
    It 'Apply goes on when the account is accepted, and the report says so' {
        $runtime = New-GateRuntime -Name 'sync-ok'
        Enable-SyncConfig $runtime; Use-RemoteSync $runtime 'Ok'
        $run = Invoke-GateProcess $runtime @{Action='Convert';Phase='AD';Mode='Apply';Force=$true;ConfigPath=$runtime.ConfigPath} -TimeoutSeconds 120
        $run.ExitCode | Should -Be 2 -Because ($run.Output + $run.Error + ' (a hand-over to the cloud server is "done, next step required")')
        $run.MainResult.Status | Should -BeExactly 'Pending'
        $run.Output | Should -Match 'Entra Connect: SRV-SYNC01 accepts this account and Entra Connect answers, a Delta cycle runs after the AD changes'
        $run.Output | Should -Match 'Entra Connect cycle finished on SRV-SYNC01'
        Test-Path -LiteralPath $run.MainResult.TransferPackage -PathType Leaf | Should -BeTrue
        @(Get-GateWrites $runtime).Count | Should -BeGreaterThan 0
    }
    It 'a sync that fails AFTER the verified AD writes ends with the package, exit code 2 and plain next steps; the batch can then be finished' {
        $runtime = New-GateRuntime -Name 'sync-after'
        Enable-SyncConfig $runtime; Use-RemoteSync $runtime 'OkThenFail'
        $run = Invoke-GateProcess $runtime @{Action='Convert';Phase='AD';Mode='Apply';Force=$true;ConfigPath=$runtime.ConfigPath} -TimeoutSeconds 120
        $run.ExitCode | Should -Be 2 -Because ($run.Output + $run.Error)
        $run.MainResult.Status | Should -BeExactly 'Pending'
        $run.MainResult.ErrorCount | Should -Be 0
        $run.MainResult.PendingCount | Should -Be 2
        $writes = @(Get-GateWrites $runtime).Count
        $writes | Should -BeGreaterThan 0
        $zip = [string]$run.MainResult.TransferPackage
        $zip | Should -Match 'PRA-SYNTHETIC_GATE-Convert-[0-9a-f]{8}-for-Cloud\.zip$'
        Test-Path -LiteralPath $zip -PathType Leaf | Should -BeTrue -Because 'the package is written although the sync failed'
        $steps = @($run.MainResult.NextSteps)
        $steps[0] | Should -Match '^AD is changed and verified\. The Entra Connect sync did not run: this account has no right on SRV-SYNC01'
        $steps[1] | Should -BeExactly 'Run a delta sync on SRV-SYNC01 (Start-ADSyncSyncCycle -PolicyType Delta) or wait for the next automatic cycle (about 30 minutes).'
        ($steps -join "`n") | Should -Match 'Copy these two files, together in the same folder, to the cloud server \(anywhere\): .*PRA-SYNTHETIC_GATE-Convert-[0-9a-f]{8}-for-Cloud\.zip and .*PRA-SYNTHETIC_GATE-Convert-[0-9a-f]{8}-for-Cloud\.zip\.sha256\. Then run there:'
        $run.Output | Should -Match 'The Entra Connect sync did not run: this account has no right'
        $folder = @(Get-ChildItem -LiteralPath $runtime.State.BackupFolder -Directory | Where-Object Name -Like 'Batch-*')[0].FullName
        $journal = @(Get-Content -LiteralPath (Get-ChildItem -LiteralPath $folder -Filter 'Journal-*.jsonl')[0].FullName | ForEach-Object { $_ | ConvertFrom-Json -DateKind String })
        @($journal | Where-Object { $_.Operation -ceq 'ADSync' -and $_.Status -ceq 'Failed' }).Count | Should -Be 1
        @($journal | Where-Object { $_.Operation -ceq 'ADSync' -and $_.Status -ceq 'Started' }).Count | Should -Be 1

        # The batch of the lab: no package. Finish it: Preview first (nothing written), a denied account stops, then the account is accepted.
        Remove-Item -LiteralPath $zip, ($zip + '.sha256') -Force
        $short = [string]$run.MainResult.BatchId
        $short | Should -Match '^[0-9a-f]{8}$'
        $arguments = @{Action='Convert';Phase='AD';Force=$true;ConfigPath=$runtime.ConfigPath;Batch=$short}
        $preview = Invoke-GateProcess $runtime (@{Mode='Preview'} + $arguments) -TimeoutSeconds 120
        $preview.ExitCode | Should -Be 0 -Because ($preview.Output + $preview.Error)
        $preview.Output | Should -Match 'AD changes already made and verified \(they are not changed again\)'
        [string]$preview.MainResult.TransferPackage | Should -BeExactly ''
        ($preview.MainResult.NextSteps -join ' ') | Should -Match "-Action Convert -Phase AD -Mode Apply -Batch $short"
        Use-RemoteSync $runtime 'Denied'
        $denied = Invoke-GateProcess $runtime (@{Mode='Apply'} + $arguments) -TimeoutSeconds 120
        $denied.ExitCode | Should -Be 1
        $denied.Output | Should -Match 'Entra Connect sync will not be possible'
        Test-Path -LiteralPath $zip | Should -BeFalse
        Use-RemoteSync $runtime 'Ok'
        $finished = Invoke-GateProcess $runtime (@{Mode='Apply'} + $arguments) -TimeoutSeconds 120
        $finished.ExitCode | Should -Be 2 -Because ($finished.Output + $finished.Error)
        @(Get-GateWrites $runtime).Count | Should -Be $writes -Because 'AD is not changed again'
        Test-Path -LiteralPath $finished.MainResult.TransferPackage -PathType Leaf | Should -BeTrue
        ($finished.MainResult.NextSteps -join "`n") | Should -Match 'Copy these two files, together in the same folder, to the cloud server \(anywhere\): .*for-Cloud\.zip and .*for-Cloud\.zip\.sha256\.'
        $finished.Output | Should -Match 'Entra Connect cycle finished on SRV-SYNC01'
        $journal = @(Get-Content -LiteralPath (Get-ChildItem -LiteralPath $folder -Filter 'Journal-*.jsonl')[0].FullName | ForEach-Object { $_ | ConvertFrom-Json -DateKind String })
        @($journal | Where-Object { $_.Operation -ceq 'ADSync' -and $_.Status -ceq 'Completed' }).Count | Should -Be 1

        # A batch without its AD proof cannot be finished from here.
        Remove-Item -LiteralPath $finished.MainResult.TransferPackage, ($finished.MainResult.TransferPackage + '.sha256') -Force
        Get-ChildItem -LiteralPath $folder -Filter 'State-*' | Remove-Item -Force
        $noProof = Invoke-GateProcess $runtime (@{Mode='Apply'} + $arguments) -TimeoutSeconds 120
        $noProof.ExitCode | Should -Be 1
        $noProof.Output | Should -Match 'has no AD proof \(State file\).*cannot be finished from here\. Nothing was changed'
        @(Get-GateWrites $runtime).Count | Should -Be $writes
    }
    It 'the global report shows one line per object after a batch was finished: the two AD runs are one stage, nothing is lost' {
        $runtime = New-GateRuntime -Name 'sync-global'
        Enable-SyncConfig $runtime; Use-RemoteSync $runtime 'OkThenFail'
        $first = Invoke-GateProcess $runtime @{Action='Convert';Phase='AD';Mode='Apply';Force=$true;ConfigPath=$runtime.ConfigPath} -TimeoutSeconds 120
        $first.ExitCode | Should -Be 2 -Because ($first.Output + $first.Error)
        Remove-Item -LiteralPath $first.MainResult.TransferPackage, ($first.MainResult.TransferPackage + '.sha256') -Force
        Use-RemoteSync $runtime 'Ok'
        $second = Invoke-GateProcess $runtime @{Action='Convert';Phase='AD';Mode='Apply';Force=$true;ConfigPath=$runtime.ConfigPath;Batch=[string]$first.MainResult.BatchId} -TimeoutSeconds 120
        $second.ExitCode | Should -Be 2 -Because ($second.Output + $second.Error)
        $zip = [string]$second.MainResult.TransferPackage
        Test-Path -LiteralPath $zip -PathType Leaf | Should -BeTrue
        # The cloud server: another machine, nothing but the package; it writes the global report.
        $cloud = New-GateRuntime -Name 'sync-global-cloud'
        $drop = Join-Path $cloud.Root 'dropped'; $null = New-Item -ItemType Directory -Path $drop
        Copy-Item -LiteralPath $zip, ($zip + '.sha256') -Destination $drop
        $third = Invoke-GateProcess $cloud @{Action='Convert';Phase='Cloud';Mode='Apply';Force=$true;ConfigPath=$cloud.ConfigPath;Batch=(Join-Path $drop ([IO.Path]::GetFileName($zip)))} -TimeoutSeconds 120
        $third.ExitCode | Should -BeIn @(0, 2) -Because ($third.Output + $third.Error)
        $csvPath = [string]$third.MainResult.GlobalCsvReport
        $htmlPath = [string]$third.MainResult.GlobalHtmlReport
        Test-Path -LiteralPath $csvPath | Should -BeTrue -Because ($third.Output + $third.Error)
        $lines = @(Import-Csv -LiteralPath $csvPath -Delimiter ';' -Encoding utf8BOM)
        $lines.Count | Should -Be 2 -Because 'one line per object, not one per run'
        @($lines | ForEach-Object UserPrincipalName | Sort-Object -Unique).Count | Should -Be 2
        $dot = [string][char]0x00B7
        foreach ($line in $lines) {
            @([regex]::Matches($line.Sides, "Convert $dot AD:")).Count | Should -Be 1 -Because 'the AD side is a single stage'
            $line.Sides | Should -Match "^Convert $dot AD: (Success|Handed over)? ?"
            $line.Sides | Should -Match "Convert $dot Cloud:"
            $line.Journey | Should -Match 'Earlier run' -Because 'the first AD run stays in the journey of the object'
            $line.Journey | Should -Match 'not changed again' -Because 'the second run says it did not write AD'
        }
        # Both runs stay in the timeline of the batch.
        $html = [IO.File]::ReadAllText($htmlPath)
        $timeline = [regex]::Match($html, '(?s)Batch timeline</h2>.*?</table>').Value
        $timeline | Should -Not -BeNullOrEmpty
        @([regex]::Matches($timeline, '<tr><td>Convert &#183; AD</td>')).Count | Should -Be 2 -Because 'the two AD runs are two lines of the timeline'
        $html | Should -Match '<div class="tile-label">Objects</div><div class="tile-value">2</div>'
    }
    It 'Phase Both with a failing sync does not start the cloud part: AD done, run the sync, then continue the batch' {
        $runtime = New-GateRuntime -Name 'sync-both'
        Enable-SyncConfig $runtime; Use-RemoteSync $runtime 'OkThenFail'
        $run = Invoke-GateProcess $runtime @{Action='Convert';Phase='Both';Mode='Apply';Force=$true;ConfigPath=$runtime.ConfigPath} -TimeoutSeconds 120
        $run.ExitCode | Should -Be 2 -Because ($run.Output + $run.Error)
        @($run.Events | Where-Object Operation -eq 'CloudPhase-SyntheticBarrier').Count | Should -Be 0 -Because 'the cloud part waits for the synchronisation'
        # Phase Both ends the chain: the global report line comes first, then the plain steps.
        $steps = @($run.MainResult.NextSteps | Where-Object { $_ -notmatch '^Global report' })
        $steps[0] | Should -Match '^AD is changed and verified\. The Entra Connect sync did not run'
        $steps[1] | Should -Match 'Run a delta sync on SRV-SYNC01'
        $steps[2] | Should -Match '^Then continue this batch from here .*-Action Convert -Phase Cloud -Mode Apply -Batch [0-9a-f]{8}'
        ($steps -join "`n") | Should -Not -Match 'To roll back this batch later'
        $run.Output | Should -Match 'Not run: the Entra Connect sync cycle could not run'
        @(Get-GateWrites $runtime).Count | Should -BeGreaterThan 0
    }
    It 'refuses -Batch with Convert -Phase Both and says which command to use' {
        $runtime = New-GateRuntime -Name 'sync-both-batch'
        $run = Invoke-GateProcess $runtime @{Action='Convert';Phase='Both';Mode='Preview';ConfigPath=$runtime.ConfigPath;Batch='deadbeef'} -TimeoutSeconds 60
        $run.ExitCode | Should -Be 1
        $run.Output | Should -Match 'use -Phase AD -Batch <id>'
    }
    It 're-running a conversion for an object that is already converted points to its batch, and names that object' {
        $first = New-GateRuntime -Name 'converted-a'
        $converted = Invoke-GateProcess $first @{Action='Convert';Phase='AD';Mode='Apply';Force=$true;ConfigPath=$first.ConfigPath} -TimeoutSeconds 120
        $converted.ExitCode | Should -Be 2 -Because ($converted.Output + $converted.Error)
        $short = [string]$converted.MainResult.BatchId
        # Another run of the same lab later: the objects are remote mailboxes now (user1 is the first of the CSV), the batch folder is still there.
        $later = New-GateRuntime -Name 'converted-b' -Case 'AlreadyConverted'
        foreach ($folder in Get-ChildItem -LiteralPath $first.State.BackupFolder -Directory -Filter 'Batch-*') { Copy-Item -LiteralPath $folder.FullName -Destination $later.State.BackupFolder -Recurse }
        $csv = Join-Path $later.Root 'targets.csv'
        [IO.File]::WriteAllText($csv, "Identity`r`nuser1`r`nuser2`r`n", (New-Object Text.UTF8Encoding($true)))
        $run = Invoke-GateProcess $later @{Action='Convert';Phase='AD';Mode='Preview';CsvPath=$csv;ConfigPath=$later.ConfigPath} -TimeoutSeconds 120
        $run.ExitCode | Should -Be 1
        $run.Output | Should -Match "user1 is already converted by batch $short \(it is a remote mailbox now\): nothing was changed\. That batch can be continued: see the next steps\."
        $run.Output | Should -Match "run:\s+\.\\Invoke-PraRemoteMailbox\.ps1 -Action Convert -Phase AD -Mode Apply -Batch $short"
        $steps = @($run.MainResult.NextSteps)
        $steps[0] | Should -BeExactly 'To continue that batch (Entra Connect sync and transfer package; AD is not changed again), run:'
        $steps[1] | Should -Match "^\.\\Invoke-PraRemoteMailbox\.ps1 -Action Convert -Phase AD -Mode Apply -Batch $short -ConfigPath '.+'$" -Because 'the command is in the next steps in full, not cut'
        $run.Output | Should -Match 'object user1\)' -Because 'the stop message names the object of the text, not the last object read'
        $run.Output | Should -Not -Match 'object user2\)'
        @(Get-GateWrites $later).Count | Should -Be 0
        # Started from the window (it sets PRA_EVENT_FILE) there is no command line: the message points to the Task page.
        $env:PRA_EVENT_FILE = Join-Path $later.Root 'engine.events.jsonl'
        $window = Invoke-GateProcess $later @{Action='Convert';Phase='AD';Mode='Preview';CsvPath=$csv;ConfigPath=$later.ConfigPath} -TimeoutSeconds 120
        $window.ExitCode | Should -Be 1
        $window.Output | Should -Match "user1 is already converted by batch $short \(it is a remote mailbox now\): nothing was changed\. That batch can be continued: see the next steps\."
        @($window.MainResult.NextSteps)[0] | Should -Match "^To continue that batch .*go to the Task page, choose Move mailboxes to Exchange Online, then Continue a batch, and pick batch $short\.$"
        $window.Output | Should -Not -Match 'run: \.\\Invoke-PraRemoteMailbox'
        $env:PRA_EVENT_FILE = $oldEventPath
        # Without such a batch the message stays the plain one.
        $alone = New-GateRuntime -Name 'converted-c' -Case 'AlreadyConverted'
        $plain = Invoke-GateProcess $alone @{Action='Convert';Phase='AD';Mode='Preview';Identity='user1';ConfigPath=$alone.ConfigPath} -TimeoutSeconds 120
        $plain.ExitCode | Should -Be 1
        $plain.Output | Should -Match 'Explicit target not eligible \(not an on-premises mailbox of an accepted type\) or excluded: user1\. Nothing converted\.'
    }
}


Describe 'Release 3.1.2 - cloud module versions, hand-over exit code, refused write, missing -Action' -Tag 'Release312' {
    BeforeEach { $global:PraGateT312 = @{ Avail = @(); Loaded = @() } }
    AfterEach { Remove-Variable PraGateT312 -Scope Global -ErrorAction SilentlyContinue }

    It 'chooses ONE Microsoft Graph version for every module, at the minimum or later (<Name>)' -ForEach @(
        @{ Name = 'the highest version that exists for both modules'; Auth = '2.42.0,2.41.1,2.40.0'; Users = '2.41.1,2.35.1'; Version = '2.41.1' }
        @{ Name = 'the same version for both when both are recent'; Auth = '2.41.1'; Users = '2.41.1'; Version = '2.41.1' }
        @{ Name = 'a later version when both have it'; Auth = '2.43.0,2.41.1'; Users = '2.43.0,2.41.1'; Version = '2.43.0' }
    ) {
        $global:PraGateT312.Avail = @(
            @($Auth.Split(',') | ForEach-Object { [pscustomobject]@{ Name = 'Microsoft.Graph.Authentication'; Version = [version]$_ } }) +
            @($Users.Split(',') | ForEach-Object { [pscustomobject]@{ Name = 'Microsoft.Graph.Users'; Version = [version]$_ } }) +
            @([pscustomobject]@{ Name = 'ExchangeOnlineManagement'; Version = [version]'3.10.1' }))
        $report = InModuleScope PRA.Common {
            Mock Get-Module { param($Name, [switch]$ListAvailable) if ($ListAvailable) { $global:PraGateT312.Avail } else { $global:PraGateT312.Loaded } }
            Get-PraCloudModuleReport
        }
        $report.Ok | Should -BeTrue -Because ($report.Messages -join ' ')
        $report.Graph.Version | Should -BeExactly $Version
        $report.Exo.Version | Should -BeExactly '3.10.1'
        @($report.Messages).Count | Should -Be 0
    }
    It 'refuses a set of Graph modules that is not complete in one version, and says what was found, the minimum and the command (<Name>)' -ForEach @(
        @{ Name = 'the lab: Authentication 2.40.0, Users 2.35.1'; Auth = '2.40.0,2.35.1'; Users = '2.35.1'; Found = 'Microsoft.Graph.Authentication 2.40.0, 2.35.1; Microsoft.Graph.Users 2.35.1' }
        @{ Name = 'Users one version behind'; Auth = '2.41.1'; Users = '2.41.0'; Found = 'Microsoft.Graph.Authentication 2.41.1; Microsoft.Graph.Users 2.41.0' }
        @{ Name = 'too old'; Auth = '2.35.1'; Users = '2.35.1'; Found = 'Microsoft.Graph.Authentication 2.35.1; Microsoft.Graph.Users 2.35.1' }
        @{ Name = 'Users missing'; Auth = '2.41.1'; Users = ''; Found = 'found Microsoft.Graph.Authentication 2.41.1; Microsoft.Graph.Users is not installed' }
        @{ Name = 'Authentication missing'; Auth = ''; Users = '2.41.1'; Found = 'found Microsoft.Graph.Users 2.41.1; Microsoft.Graph.Authentication is not installed' }
        @{ Name = 'both missing'; Auth = ''; Users = ''; Found = 'Microsoft Graph: Microsoft.Graph.Authentication is not installed; Microsoft.Graph.Users is not installed' }
    ) {
        $global:PraGateT312.Avail = @(
            @($Auth.Split(',', [StringSplitOptions]::RemoveEmptyEntries) | ForEach-Object { [pscustomobject]@{ Name = 'Microsoft.Graph.Authentication'; Version = [version]$_ } }) +
            @($Users.Split(',', [StringSplitOptions]::RemoveEmptyEntries) | ForEach-Object { [pscustomobject]@{ Name = 'Microsoft.Graph.Users'; Version = [version]$_ } }) +
            @([pscustomobject]@{ Name = 'ExchangeOnlineManagement'; Version = [version]'3.10.1' }))
        $report = InModuleScope PRA.Common {
            Mock Get-Module { param($Name, [switch]$ListAvailable) if ($ListAvailable) { $global:PraGateT312.Avail } else { $global:PraGateT312.Loaded } }
            Get-PraCloudModuleReport
        }
        $report.Ok | Should -BeFalse
        $report.Graph.Ok | Should -BeFalse
        $report.Exo.Ok | Should -BeTrue
        $report.Graph.Message | Should -Match ([regex]::Escape($Found))
        $report.Graph.Message | Should -Not -Match 'found Microsoft\.Graph\.\w+ (is )?not installed'
        $report.Graph.Message | Should -Match 'one same version 2\.41\.1 or later'
        $report.Graph.Message | Should -Match ([regex]::Escape('Run: Install-Module Microsoft.Graph.Authentication -MinimumVersion 2.41.1 -Scope CurrentUser; Install-Module Microsoft.Graph.Users -MinimumVersion 2.41.1 -Scope CurrentUser'))
    }
    It 'refuses an ExchangeOnlineManagement that is too old or missing, with the exact command' -ForEach @(
        @{ Found = '3.10.0'; Text = 'found 3.10.0; the tool needs 3.10.1 or later' }
        @{ Found = '3.9.0,3.8.0'; Text = 'found 3.9.0, 3.8.0; the tool needs 3.10.1 or later' }
        @{ Found = ''; Text = 'not installed; the tool needs 3.10.1 or later' }
    ) {
        $global:PraGateT312.Avail = @(
            @([pscustomobject]@{ Name = 'Microsoft.Graph.Authentication'; Version = [version]'2.41.1' }, [pscustomobject]@{ Name = 'Microsoft.Graph.Users'; Version = [version]'2.41.1' }) +
            @($Found.Split(',', [StringSplitOptions]::RemoveEmptyEntries) | ForEach-Object { [pscustomobject]@{ Name = 'ExchangeOnlineManagement'; Version = [version]$_ } }))
        $report = InModuleScope PRA.Common { Mock Get-Module { param($Name, [switch]$ListAvailable) if ($ListAvailable) { $global:PraGateT312.Avail } else { $global:PraGateT312.Loaded } }; Get-PraCloudModuleReport }
        $report.Ok | Should -BeFalse
        $report.Graph.Ok | Should -BeTrue
        $report.Exo.Message | Should -Match ([regex]::Escape('ExchangeOnlineManagement: ' + $Text))
        $report.Exo.Message | Should -Match ([regex]::Escape('Run: Install-Module ExchangeOnlineManagement -MinimumVersion 3.10.1 -Scope CurrentUser'))
    }
    It 'refuses another Graph version that is already loaded in the session, and accepts the one that is loaded when it is complete' {
        $installed = @(
            [pscustomobject]@{ Name = 'Microsoft.Graph.Authentication'; Version = [version]'2.41.1' }, [pscustomobject]@{ Name = 'Microsoft.Graph.Users'; Version = [version]'2.41.1' },
            [pscustomobject]@{ Name = 'Microsoft.Graph.Authentication'; Version = [version]'2.43.0' }, [pscustomobject]@{ Name = 'Microsoft.Graph.Users'; Version = [version]'2.43.0' },
            [pscustomobject]@{ Name = 'ExchangeOnlineManagement'; Version = [version]'3.10.1' })
        $global:PraGateT312.Avail = $installed
        # An older Graph is loaded: it cannot be replaced in the session.
        $global:PraGateT312.Loaded = @([pscustomobject]@{ Name = 'Microsoft.Graph.Authentication'; Version = [version]'2.40.0' })
        $report = InModuleScope PRA.Common { Mock Get-Module { param($Name, [switch]$ListAvailable) if ($ListAvailable) { $global:PraGateT312.Avail } else { $global:PraGateT312.Loaded } }; Get-PraCloudModuleReport }
        $report.Graph.Ok | Should -BeFalse
        $report.Graph.Message | Should -Match 'Microsoft Graph 2\.40\.0 is already loaded in this PowerShell session.*one same version 2\.41\.1 or later.*new PowerShell 7 window'
        # A complete version is loaded: the same one is used (not the highest).
        $global:PraGateT312.Loaded = @([pscustomobject]@{ Name = 'Microsoft.Graph.Authentication'; Version = [version]'2.41.1' }, [pscustomobject]@{ Name = 'Microsoft.Graph.Users'; Version = [version]'2.41.1' })
        $report = InModuleScope PRA.Common { Mock Get-Module { param($Name, [switch]$ListAvailable) if ($ListAvailable) { $global:PraGateT312.Avail } else { $global:PraGateT312.Loaded } }; Get-PraCloudModuleReport }
        $report.Graph.Ok | Should -BeTrue
        $report.Graph.Version | Should -BeExactly '2.41.1'
        # Two versions loaded together: a state the tool cannot repair.
        $global:PraGateT312.Loaded = @([pscustomobject]@{ Name = 'Microsoft.Graph.Authentication'; Version = [version]'2.41.1' }, [pscustomobject]@{ Name = 'Microsoft.Graph.Users'; Version = [version]'2.43.0' })
        $report = InModuleScope PRA.Common { Mock Get-Module { param($Name, [switch]$ListAvailable) if ($ListAvailable) { $global:PraGateT312.Avail } else { $global:PraGateT312.Loaded } }; Get-PraCloudModuleReport }
        $report.Graph.Ok | Should -BeFalse
        $report.Graph.Message | Should -Match 'several versions are loaded in this PowerShell session \(2\.41\.1, 2\.43\.0\)'
    }
    It 'imports every Graph module with the SAME required version, and refuses before importing when no complete set exists' {
        $text = [IO.File]::ReadAllText((Join-Path $global:PraGate.Source 'module\PRA.Cloud.psm1'))
        $text | Should -Match 'Import-Module Microsoft\.Graph\.Authentication -RequiredVersion \$graphVersion'
        $text | Should -Match 'Import-Module Microsoft\.Graph\.Users -RequiredVersion \$graphVersion'
        $text | Should -Match 'if \(-not \$modules\.Graph\.Ok\) \{ throw \$modules\.Graph\.Message \}'
        [IO.File]::ReadAllText((Join-Path $global:PraGate.Source 'config\PraRemoteMailbox.config.psd1')) | Should -Match "MinModuleVersion\s*=\s*'3\.10\.1'"
    }
    It 'the window shows ONE Cloud modules light, with the same answer as the engine' {
        $guiModule = Import-Module (Join-Path $global:PraGate.Package 'module\PRA.Gui.psm1') -Force -PassThru | Select-Object -Last 1
        $old = & $guiModule {
            $script:GuiCloudModules = @([pscustomobject]@{ Name = 'Microsoft.Graph.Authentication'; Version = [version]'2.40.0' }, [pscustomobject]@{ Name = 'Microsoft.Graph.Users'; Version = [version]'2.35.1' }, [pscustomobject]@{ Name = 'ExchangeOnlineManagement'; Version = [version]'3.10.0' })
            Get-PraGuiPrerequisite -Signin Wam -SyncEnabled $false
        }
        @($old.Lights | Where-Object { $_.Name -in @('Microsoft.Graph', 'ExchangeOnlineManagement') }).Count | Should -Be 0 -Because 'the two modules share one light'
        @($old.Lights | Where-Object Name -eq 'Cloud modules').Count | Should -Be 1
        $cloud = $old.Lights | Where-Object Name -eq 'Cloud modules'
        $cloud.Status | Should -BeExactly 'Fail'
        $cloud.Detail | Should -Match 'found Microsoft.Graph.Authentication 2\.40\.0; Microsoft.Graph.Users 2\.35\.1.*2\.41\.1 or later.*Install-Module Microsoft\.Graph\.Authentication -MinimumVersion 2\.41\.1 -Scope CurrentUser; Install-Module Microsoft\.Graph\.Users -MinimumVersion 2\.41\.1 -Scope CurrentUser'
        $cloud.Detail | Should -Match 'found 3\.10\.0; the tool needs 3\.10\.1 or later.*Install-Module ExchangeOnlineManagement -MinimumVersion 3\.10\.1 -Scope CurrentUser'
        $old.Cloud | Should -BeFalse
        $good = & $guiModule {
            $script:GuiCloudModules = @([pscustomobject]@{ Name = 'Microsoft.Graph.Authentication'; Version = [version]'2.41.1' }, [pscustomobject]@{ Name = 'Microsoft.Graph.Users'; Version = [version]'2.41.1' }, [pscustomobject]@{ Name = 'ExchangeOnlineManagement'; Version = [version]'3.10.1' })
            Get-PraGuiPrerequisite -Signin Wam -SyncEnabled $false
        }
        ($good.Lights | Where-Object Name -eq 'Cloud modules').Status | Should -BeExactly 'Ok'
        ($good.Lights | Where-Object Name -eq 'Cloud modules').Detail | Should -BeExactly 'Exchange Online 3.10.1, Microsoft Graph 2.41.1 (Authentication and Users).'
    }

    It 'Apply with phase Both stops before any write when no complete Graph set is installed; Preview only warns; a phase Cloud Preview stops too' {
        $runtime = New-GateRuntime -Name 'modules-graph'
        # The lab: Authentication 2.40.0 (the most recent), Users 2.35.1 (the only one).
        Remove-Item -LiteralPath (Join-Path $runtime.Modules 'Microsoft.Graph.Authentication'), (Join-Path $runtime.Modules 'Microsoft.Graph.Users') -Recurse -Force
        foreach ($pair in @(@('Microsoft.Graph.Authentication', '2.40.0'), @('Microsoft.Graph.Users', '2.35.1'))) {
            $folder = Join-Path $runtime.Modules $pair[0]; $null = New-Item -ItemType Directory -Path $folder -Force
            [IO.File]::WriteAllText((Join-Path $folder ($pair[0] + '.psd1')), "@{ ModuleVersion='$($pair[1])'; GUID='$([guid]::NewGuid())'; Author='SYNTHETIC' }", (New-Object Text.UTF8Encoding($true)))
        }
        $apply = Invoke-GateProcess $runtime @{Action='Convert';Phase='Both';Mode='Apply';Force=$true;ConfigPath=$runtime.ConfigPath} -TimeoutSeconds 120
        $apply.ExitCode | Should -Be 1
        $apply.Output | Should -Match 'The cloud part cannot run on this server\. Microsoft Graph: found Microsoft\.Graph\.Authentication 2\.40\.0; Microsoft\.Graph\.Users 2\.35\.1\.'
        $apply.Output | Should -Match ([regex]::Escape('Run: Install-Module Microsoft.Graph.Authentication -MinimumVersion 2.41.1 -Scope CurrentUser; Install-Module Microsoft.Graph.Users -MinimumVersion 2.41.1 -Scope CurrentUser'))
        $apply.Output | Should -Match 'Nothing was changed\.'
        @(Get-GateWrites $runtime).Count | Should -Be 0
        @(Get-ChildItem -LiteralPath $runtime.State.BackupFolder -Directory -ErrorAction SilentlyContinue).Count | Should -Be 0 -Because 'no backup either'
        @($apply.Events | Where-Object Operation -Match 'CloudPreflight|CloudPhase').Count | Should -Be 0
        $preview = Invoke-GateProcess $runtime @{Action='Convert';Phase='Both';Mode='Preview';ConfigPath=$runtime.ConfigPath} -TimeoutSeconds 120
        $preview.ExitCode | Should -Be 0 -Because ($preview.Output + $preview.Error)
        $preview.Output | Should -Match 'The cloud part will not be possible on this server\. Microsoft Graph: found'
        $preview.MainResult.WarningCount | Should -BeGreaterThan 0
        $cloud = Invoke-GateProcess $runtime @{Action='Check';Identity='user1@gate.invalid';Mode='Preview';ConfigPath=$runtime.ConfigPath} -TimeoutSeconds 120
        $cloud.ExitCode | Should -Be 1
        $cloud.Output | Should -Match 'The cloud part cannot run on this server\. Microsoft Graph: found'
        # A phase AD run never needs the cloud modules.
        $ad = Invoke-GateProcess $runtime @{Action='Convert';Phase='AD';Mode='Preview';ConfigPath=$runtime.ConfigPath} -TimeoutSeconds 120
        $ad.ExitCode | Should -Be 0 -Because ($ad.Output + $ad.Error)
        $ad.Output | Should -Not -Match 'Microsoft Graph: found'
    }
    It 'Apply with an old ExchangeOnlineManagement stops before any write, and a server with the minimum versions goes on' {
        $runtime = New-GateRuntime -Name 'modules-exo'
        [IO.File]::WriteAllText((Join-Path $runtime.Modules 'ExchangeOnlineManagement\ExchangeOnlineManagement.psd1'), "@{ ModuleVersion='3.9.0'; GUID='$([guid]::NewGuid())'; Author='SYNTHETIC' }", (New-Object Text.UTF8Encoding($true)))
        $stopped = Invoke-GateProcess $runtime @{Action='Convert';Phase='Both';Mode='Apply';Force=$true;ConfigPath=$runtime.ConfigPath} -TimeoutSeconds 120
        $stopped.ExitCode | Should -Be 1
        $stopped.Output | Should -Match ([regex]::Escape('ExchangeOnlineManagement: found 3.9.0; the tool needs 3.10.1 or later. Run: Install-Module ExchangeOnlineManagement -MinimumVersion 3.10.1 -Scope CurrentUser ('))
        @(Get-GateWrites $runtime).Count | Should -Be 0
        $good = New-GateRuntime -Name 'modules-ok'
        $ran = Invoke-GateProcess $good @{Action='Convert';Phase='Both';Mode='Apply';Force=$true;ConfigPath=$good.ConfigPath} -TimeoutSeconds 120
        $ran.ExitCode | Should -BeIn @(0, 2) -Because ($ran.Output + $ran.Error)
        $ran.Output | Should -Match 'Cloud modules: Microsoft Graph 2\.41\.1 \(Authentication and Users\), ExchangeOnlineManagement 3\.10\.1'
        @(Get-GateWrites $good).Count | Should -BeGreaterThan 0
    }

    It 'a phase AD run that ends with a package exits 2 (done, next step required), and the Next steps put the sync before the package when the tool did not run it' {
        $runtime = New-GateRuntime -Name 'handover-code'
        $run = Invoke-GateProcess $runtime @{Action='Convert';Phase='AD';Mode='Apply';Force=$true;ConfigPath=$runtime.ConfigPath} -TimeoutSeconds 120
        $run.ExitCode | Should -Be 2 -Because ($run.Output + $run.Error)
        $run.MainResult.Status | Should -BeExactly 'Pending'
        $run.MainResult.ErrorCount | Should -Be 0
        $run.MainResult.PendingCount | Should -Be 2
        $run.MainResult.SuccessCount | Should -Be 0
        $steps = @($run.MainResult.NextSteps)
        # EntraConnect.Sync = $false in this configuration: the sync is the first of the numbered steps, then the copy of the package.
        $steps[0] | Should -Match '^Run a delta sync on \S+ \(Start-ADSyncSyncCycle -PolicyType Delta\) or wait for the next automatic cycle \(about 30 minutes\)\.$'
        $steps[1] | Should -Match '^Copy these two files, together in the same folder, to the cloud server \(anywhere\): .*for-Cloud\.zip and .*for-Cloud\.zip\.sha256\.'
        $steps.Count | Should -Be 3
        # Preview: nothing is pending, nothing to do on the other server yet.
        $preview = Invoke-GateProcess $runtime @{Action='Convert';Phase='AD';Mode='Preview';ConfigPath=$runtime.ConfigPath} -TimeoutSeconds 120
        $preview.ExitCode | Should -Be 0
        # A run that does everything on one server ends with 0 (nothing left to do).
        $both = New-GateRuntime -Name 'handover-both'
        $done = Invoke-GateProcess $both @{Action='Convert';Phase='Both';Mode='Apply';Force=$true;ConfigPath=$both.ConfigPath} -TimeoutSeconds 120
        $done.MainResult.Status | Should -BeIn @('Success', 'Pending') -Because 'the synthetic cloud barrier decides the end of a phase Both'
        ($done.MainResult.NextSteps -join ' ') | Should -Not -Match 'Run a delta sync on'
    }

    It 'a domain controller that refuses the account before the first write: plain message, nothing changed in AD, the backup folder is marked and not deleted' {
        $runtime = New-GateRuntime -Name 'access-denied' -Case 'AccessDenied'
        $run = Invoke-GateProcess $runtime @{Action='Convert';Phase='AD';Mode='Apply';Force=$true;ConfigPath=$runtime.ConfigPath} -TimeoutSeconds 120
        $run.ExitCode | Should -Be 1
        $run.Output | Should -Match 'Nothing was changed in AD\. This account cannot write to dc01\.gate\.invalid: run the tool on that domain controller, or with an account that has the rights \(see Prerequisites\)\.'
        $run.Output | Should -Not -Match 'AD batch stopped'
        @(Get-GateWrites $runtime).Count | Should -Be 0
        [string]$run.MainResult.TransferPackage | Should -BeExactly ''
        $folder = @(Get-ChildItem -LiteralPath $runtime.State.BackupFolder -Directory | Where-Object Name -Like 'Batch-*')
        $folder.Count | Should -Be 1 -Because 'the backup is kept'
        $next = @($run.MainResult.NextSteps)
        $next[0] | Should -BeExactly ('Nothing was written to Active Directory. The backup folder {0} is marked NOT-APPLIED: you can delete it, or keep it as evidence. It is not a batch to continue or to roll back.' -f $folder[0].FullName)
        $next[1] | Should -BeExactly 'Run the step again on the domain controller dc01.gate.invalid, or with an account that has the right to write there (see Prerequisites). Run the Preview first, then the same command with -Mode Apply:'
        $next[2] | Should -Match '^\.\\Invoke-PraRemoteMailbox\.ps1 -Action Convert -Phase AD$' -Because 'the Preview comes first, and the other server has its own configuration file'
        $run.Output | Should -Match 'Nothing was written to Active Directory\. The backup folder' -Because 'the summary of a refused run carries the next step'
        Test-Path -LiteralPath (Join-Path $folder[0].FullName 'NOT-APPLIED.txt') | Should -BeTrue
        [IO.File]::ReadAllText((Join-Path $folder[0].FullName 'NOT-APPLIED.txt')) | Should -Match 'NOT a batch to continue and NOT a batch to roll back'
        @(Get-ChildItem -LiteralPath $folder[0].FullName -Filter 'Convert-*.json').Count | Should -Be 1
        @(Get-ChildItem -LiteralPath $folder[0].FullName -Filter 'State-*').Count | Should -Be 0 -Because 'no AD proof: nothing was verified'
        $journal = @(Get-Content -LiteralPath (Get-ChildItem -LiteralPath $folder[0].FullName -Filter 'Journal-*.jsonl')[0].FullName | ForEach-Object { $_ | ConvertFrom-Json -DateKind String })
        @($journal | Where-Object { $_.Operation -ceq 'ADBatch' -and $_.Status -ceq 'NotApplied' }).Count | Should -Be 1
        # Any other error keeps the old message.
        $other = New-GateRuntime -Name 'other-error' -Case 'SecondMutationFailure'
        $failed = Invoke-GateProcess $other @{Action='Convert';Phase='AD';Mode='Apply';Force=$true;ConfigPath=$other.ConfigPath} -TimeoutSeconds 120
        $failed.ExitCode | Should -Be 1
        $failed.Output | Should -Match 'AD batch stopped: '
        $failed.Output | Should -Not -Match 'Nothing was changed in AD\. This account cannot write'
        @(Get-ChildItem -LiteralPath $other.State.BackupFolder -Recurse -Filter 'NOT-APPLIED.txt').Count | Should -Be 0
    }

    It 'a missing -Action stops at once with the usage, even when nobody can answer a prompt' {
        $runtime = New-GateRuntime -Name 'no-action'
        $start = New-Object Diagnostics.ProcessStartInfo
        $start.FileName = (Join-Path $PSHOME 'pwsh.exe')
        $start.Arguments = '-NoLogo -NoProfile -File "' + (Join-Path $runtime.Package 'Invoke-PraRemoteMailbox.ps1') + '"'
        $start.UseShellExecute = $false; $start.CreateNoWindow = $true; $start.RedirectStandardOutput = $true; $start.RedirectStandardError = $true; $start.RedirectStandardInput = $true
        $process = [Diagnostics.Process]::Start($start)
        try {
            $out = $process.StandardOutput.ReadToEndAsync(); $err = $process.StandardError.ReadToEndAsync()
            $process.WaitForExit(60000) | Should -BeTrue -Because 'the script must not wait for an answer'
            $process.ExitCode | Should -Be 1
            $text = ($out.Result + $err.Result) -replace '\s+', ' '
            $text | Should -Match '-Action is missing: nothing was done\. Give the task: -Action Convert, Recover, Finalize or Check'
            $text | Should -Match 'Example: \.\\Invoke-PraRemoteMailbox\.ps1 -Action Convert -Mode Preview'
        } finally { if (-not $process.HasExited) { $process.Kill() }; $process.Dispose() }
    }
}

Describe 'Release 3.1.2 - the Next steps of a package Preview, and the scope that only a conversion needs' -Tag 'Release312' {
    It 'a Preview started with a package names the package in its Next steps (nothing was extracted to the backup folder)' {
        $ad = New-GateRuntime -Name 'preview-zip-ad'
        $made = Invoke-GateProcess $ad @{Action='Convert';Phase='AD';Mode='Apply';Force=$true;ConfigPath=$ad.ConfigPath} -TimeoutSeconds 120
        $zip = [string]$made.MainResult.TransferPackage
        Test-Path -LiteralPath $zip -PathType Leaf | Should -BeTrue -Because ($made.Output + $made.Error)
        $cloud = New-GateRuntime -Name 'preview-zip-cloud'
        $drop = Join-Path $cloud.Root 'dropped'; $null = New-Item -ItemType Directory -Path $drop
        Copy-Item -LiteralPath $zip, ($zip + '.sha256') -Destination $drop
        $target = Join-Path $drop ([IO.Path]::GetFileName($zip))
        $preview = Invoke-GateProcess $cloud @{Action='Convert';Phase='Cloud';Mode='Preview';ConfigPath=$cloud.ConfigPath;Batch=$target} -TimeoutSeconds 120
        $preview.ExitCode | Should -BeIn @(0, 2) -Because ($preview.Output + $preview.Error)
        $next = @($preview.MainResult.NextSteps) -join "`n"
        $next | Should -Match ([regex]::Escape("-Action Convert -Phase Cloud -Mode Apply -Batch '" + $target + "'")) -Because 'the exact Apply command, with the package'
        $next | Should -Not -Match '-Batch [0-9a-f]{8,32}\b' -Because 'a batch ID would not be found: the Preview extracted nothing into the backup folder'
        @(Get-ChildItem -LiteralPath $cloud.State.BackupFolder -Directory -ErrorAction SilentlyContinue | Where-Object Name -Like 'Batch-*').Count | Should -Be 0
        # The same Preview from a bare file name (the package is in the Inbox of the cloud server): the command repeats what was typed.
        $inbox = Join-Path $cloud.State.BackupFolder 'Inbox'; $null = New-Item -ItemType Directory -Path $inbox -Force
        Copy-Item -LiteralPath $zip, ($zip + '.sha256') -Destination $inbox
        $named = Invoke-GateProcess $cloud @{Action='Convert';Phase='Cloud';Mode='Preview';ConfigPath=$cloud.ConfigPath;Batch=[IO.Path]::GetFileName($zip)} -TimeoutSeconds 120
        (@($named.MainResult.NextSteps) -join "`n") | Should -Match ([regex]::Escape("-Batch '" + [IO.Path]::GetFileName($zip) + "'"))
        # Every other command of the script that a package Preview can print uses the same value.
        $text = [IO.File]::ReadAllText((Join-Path $global:PraGate.Source 'Invoke-PraRemoteMailbox.ps1'))
        ([regex]::Matches($text, '\$script:PreviewPackage')).Count | Should -BeGreaterOrEqual 8
    }
    It 'Check and the cloud phases do not need the conversion scope; a conversion without any source says what to fill in' {
        $runtime = New-GateRuntime -Name 'scope-empty'
        # The default configuration of the package: Scope.Mode = OU without Scope.SearchBase.
        Set-GateConfigText $runtime { param($t) $t.Replace("Mode='Auto';SearchBase='OU=Tests,DC=gate,DC=invalid'", "Mode='OU';SearchBase=''") }
        $check = Invoke-GateProcess $runtime @{Action='Check';Identity='user1@gate.invalid';Mode='Preview';ConfigPath=$runtime.ConfigPath} -TimeoutSeconds 120
        $check.ExitCode | Should -Be 0 -Because ($check.Output + $check.Error)
        $check.Output | Should -Not -Match 'Scope\.SearchBase'
        $single = Invoke-GateProcess $runtime @{Action='Convert';Phase='AD';Mode='Preview';Identity='user1';ConfigPath=$runtime.ConfigPath} -TimeoutSeconds 120
        $single.ExitCode | Should -Be 0 -Because 'one named account does not need a scope'
        $readsBefore = @(Get-GateEvents $runtime | Where-Object Operation -Match '^Get-AD').Count
        $none = Invoke-GateProcess $runtime @{Action='Convert';Phase='AD';Mode='Preview';ConfigPath=$runtime.ConfigPath} -TimeoutSeconds 120
        $none.ExitCode | Should -Be 1
        $none.Output | Should -Match 'Configuration: Scope\.Mode = OU requires Scope\.SearchBase: no OU is set, so the tool does not know which mailboxes to convert\.'
        $none.Output | Should -Match 'Fill it in the configuration file, or give -Identity \(one account\), -CsvPath \(a CSV file with an Identity column\), -SearchBase \(an OU\) or -Group \(an AD group\) for this run, or set Scope\.Mode = Auto'
        @(Get-GateEvents $runtime | Where-Object Operation -Match '^Get-AD').Count | Should -Be $readsBefore -Because 'the run stops before it reads Active Directory'
        $override = Invoke-GateProcess $runtime @{Action='Convert';Phase='AD';Mode='Preview';SearchBase='OU=Tests,DC=gate,DC=invalid';ConfigPath=$runtime.ConfigPath} -TimeoutSeconds 120
        $override.ExitCode | Should -Be 0 -Because ($override.Output + $override.Error)
        # A Recover does not read the scope either.
        $made = New-GateRuntime -Name 'scope-recover'
        $first = Invoke-GateProcess $made @{Action='Convert';Phase='AD';Mode='Apply';Force=$true;ConfigPath=$made.ConfigPath} -TimeoutSeconds 120
        Set-GateConfigText $made { param($t) $t.Replace("Mode='Auto';SearchBase='OU=Tests,DC=gate,DC=invalid'", "Mode='OU';SearchBase=''") }
        $recover = Invoke-GateProcess $made @{Action='Recover';Phase='AD';Mode='Preview';ConfigPath=$made.ConfigPath;Batch=[string]$first.MainResult.BatchId} -TimeoutSeconds 120
        $recover.Output | Should -Not -Match 'Scope\.SearchBase'
    }
    It 'Import-PraConfiguration leaves the scope to the caller with -DeferScopeCheck, and Test-PraScopeConfiguration says what to fill in for each mode' {
        $runtime = New-GateRuntime -Name 'scope-unit'
        Set-GateConfigText $runtime { param($t) $t.Replace("Mode='Auto';SearchBase='OU=Tests,DC=gate,DC=invalid'", "Mode='OU';SearchBase=''") }
        { Import-PraConfiguration -Path $runtime.ConfigPath -Root $runtime.Package } | Should -Throw '*Scope.Mode = OU requires Scope.SearchBase*'
        $config = Import-PraConfiguration -Path $runtime.ConfigPath -Root $runtime.Package -DeferScopeCheck
        { Test-PraScopeConfiguration -Config $config } | Should -Throw '*Scope.Mode = OU requires Scope.SearchBase: no OU is set*'
        $config.Scope.Mode = 'Group'; $config.Scope.GroupDN = ''
        { Test-PraScopeConfiguration -Config $config } | Should -Throw '*Scope.Mode = Group requires Scope.GroupDN: no group is set*'
        $config.Scope.Mode = 'Csv'; $config.Scope.CsvPath = ''
        { Test-PraScopeConfiguration -Config $config } | Should -Throw '*Scope.Mode = Csv requires Scope.CsvPath: no CSV file is set*'
        $config.Scope.Mode = 'Auto'
        { Test-PraScopeConfiguration -Config $config } | Should -Not -Throw
    }
}

Describe 'Release 3.1.3 - the install commands are valid, a refused run touched nothing, a Preview does not say done' -Tag 'Release313' {
    BeforeEach {
        $global:PraGateT313 = @{ Avail = @(); Loaded = @() }
        function script:Use-RemoteSync313($Runtime, [string]$Mode) {
            $Runtime.State.RemoteSync = $Mode
            [IO.File]::WriteAllText($Runtime.StatePath, [Management.Automation.PSSerializer]::Serialize($Runtime.State, 35))
        }
        function script:Enable-SyncConfig313($Runtime) {
            Set-GateConfigText $Runtime { param($t) $t.Replace('EntraConnect=@{Sync=$false;Server='''';', 'EntraConnect=@{Sync=$true;Server=''SRV-SYNC01'';') }
        }
    }
    AfterEach { Remove-Variable PraGateT313 -Scope Global -ErrorAction SilentlyContinue }

    It 'every Install-Module command of a refusal parses and carries ONE module name (PowerShellGet refuses -MinimumVersion with several)' {
        $global:PraGateT313.Avail = @([pscustomobject]@{ Name = 'Microsoft.Graph.Authentication'; Version = [version]'2.40.0' }, [pscustomobject]@{ Name = 'ExchangeOnlineManagement'; Version = [version]'3.9.0' })
        $report = InModuleScope PRA.Common { Mock Get-Module { param($Name, [switch]$ListAvailable) if ($ListAvailable) { $global:PraGateT313.Avail } else { $global:PraGateT313.Loaded } }; Get-PraCloudModuleReport }
        $report.Graph.Message | Should -Not -Match 'Microsoft\.Graph\.Authentication,\s*Microsoft\.Graph\.Users'
        $texts = @{
            Graph = [regex]::Match($report.Graph.Message, 'Run: (.+?) \(').Groups[1].Value
            Exo = [regex]::Match($report.Exo.Message, 'Run: (.+?) \(').Groups[1].Value
        }
        $texts.Graph | Should -Not -BeNullOrEmpty; $texts.Exo | Should -Not -BeNullOrEmpty
        $names = @()
        foreach ($text in $texts.Values) {
            $errors = $null
            $ast = [Management.Automation.Language.Parser]::ParseInput($text, [ref]$null, [ref]$errors)
            $errors.Count | Should -Be 0 -Because $text
            $commands = @($ast.FindAll({ param($n) $n -is [Management.Automation.Language.CommandAst] }, $true))
            $commands.Count | Should -BeGreaterThan 0
            foreach ($command in $commands) {
                $command.GetCommandName() | Should -BeExactly 'Install-Module'
                $elements = @($command.CommandElements | Select-Object -Skip 1)
                $bare = New-Object 'Collections.Generic.List[string]'; $parameters = @{}
                for ($i = 0; $i -lt $elements.Count; $i++) {
                    if ($elements[$i] -is [Management.Automation.Language.CommandParameterAst]) { $parameters[$elements[$i].ParameterName] = [string]$elements[$i + 1].Value; $i++ }
                    else { $bare.Add([string]$elements[$i].Value) }
                }
                $bare.Count | Should -Be 1 -Because "one name per Install-Module: $text"
                $parameters['MinimumVersion'] | Should -Match '^\d+\.\d+\.\d+$'
                $parameters['Scope'] | Should -BeExactly 'CurrentUser'
                $names += $bare[0]
            }
        }
        $names | Should -Contain 'Microsoft.Graph.Authentication'
        $names | Should -Contain 'Microsoft.Graph.Users'
        $names | Should -Contain 'ExchangeOnlineManagement'
        $report.Graph.Message | Should -Match 'the same version for both'
        $report.Graph.Message | Should -Match '-Scope AllUsers in a window opened as administrator\)\.$' -Because 'the message ends with a full stop after the command'
    }
    It 'a refusal for the cloud modules never runs "Nothing was changed" into the command, and reports no object (0 done, 0 skipped, no global report)' {
        $runtime = New-GateRuntime -Name 'modules-313'
        Remove-Item -LiteralPath (Join-Path $runtime.Modules 'Microsoft.Graph.Authentication'), (Join-Path $runtime.Modules 'Microsoft.Graph.Users') -Recurse -Force
        foreach ($pair in @(@('Microsoft.Graph.Authentication', '2.40.0'), @('Microsoft.Graph.Users', '2.35.1'))) {
            $folder = Join-Path $runtime.Modules $pair[0]; $null = New-Item -ItemType Directory -Path $folder -Force
            [IO.File]::WriteAllText((Join-Path $folder ($pair[0] + '.psd1')), "@{ ModuleVersion='$($pair[1])'; GUID='$([guid]::NewGuid())'; Author='SYNTHETIC' }", (New-Object Text.UTF8Encoding($true)))
        }
        $apply = Invoke-GateProcess $runtime @{Action='Convert';Phase='Both';Mode='Apply';Force=$true;ConfigPath=$runtime.ConfigPath} -TimeoutSeconds 120
        $apply.ExitCode | Should -Be 1
        $apply.Output | Should -Match ([regex]::Escape('Run: Install-Module Microsoft.Graph.Authentication -MinimumVersion 2.41.1 -Scope CurrentUser; Install-Module Microsoft.Graph.Users -MinimumVersion 2.41.1 -Scope CurrentUser (one command per module'))
        $apply.Output | Should -Match '\)\. Nothing was changed\.'
        $apply.Output | Should -Not -Match 'CurrentUser Nothing was changed|AllUsers Nothing was changed'
        $apply.MainResult.SuccessCount | Should -Be 0
        $apply.MainResult.SkippedCount | Should -Be 0
        [string]$apply.MainResult.GlobalHtmlReport | Should -BeExactly ''
    }
    It 'Apply refused by the Entra Connect check: 0 done, nothing counted as skipped, no global report, and the error names the run, not an object ID' {
        $runtime = New-GateRuntime -Name 'sync-refused-313'
        Enable-SyncConfig313 $runtime; Use-RemoteSync313 $runtime 'Denied'
        $run = Invoke-GateProcess $runtime @{Action='Convert';Phase='AD';Mode='Apply';Force=$true;ConfigPath=$runtime.ConfigPath} -TimeoutSeconds 120
        $run.ExitCode | Should -Be 1
        $run.MainResult.SuccessCount | Should -Be 0
        $run.MainResult.SkippedCount | Should -Be 0
        $run.MainResult.PendingCount | Should -Be 0
        $run.MainResult.ErrorCount | Should -Be 1
        $run.MainResult.TotalCount | Should -Be 1
        [string]$run.MainResult.GlobalHtmlReport | Should -BeExactly ''
        [string]$run.MainResult.GlobalCsvReport | Should -BeExactly ''
        $run.Output | Should -Match '0 done'
        $run.Output | Should -Match ' 0 skipped' -Because 'untouched objects are not counted as skipped'
        $run.Output | Should -Not -Match 'object [0-9a-f]{8}-[0-9a-f]{4}-' -Because 'the stop names the run, not the last object looked at'
        $rows = @(Import-Csv -LiteralPath $run.MainResult.CsvReport -Delimiter ';')
        $rows.Count | Should -Be 1
        $rows[0].UserPrincipalName | Should -BeExactly '(run)'
        $rows[0].FinalStatus | Should -BeExactly 'Error'
        @(Get-GateWrites $runtime).Count | Should -Be 0
    }
    It 'a resume (-Phase AD -Batch) refused by the Entra Connect check: 0 done, no global report, the error names the batch' {
        $runtime = New-GateRuntime -Name 'resume-refused-313'
        Enable-SyncConfig313 $runtime; Use-RemoteSync313 $runtime 'OkThenFail'
        $first = Invoke-GateProcess $runtime @{Action='Convert';Phase='AD';Mode='Apply';Force=$true;ConfigPath=$runtime.ConfigPath} -TimeoutSeconds 120
        $first.ExitCode | Should -Be 2 -Because ($first.Output + $first.Error)
        $short = [string]$first.MainResult.BatchId
        $writes = @(Get-GateWrites $runtime).Count
        Use-RemoteSync313 $runtime 'Denied'
        $denied = Invoke-GateProcess $runtime @{Action='Convert';Phase='AD';Mode='Apply';Force=$true;ConfigPath=$runtime.ConfigPath;Batch=$short} -TimeoutSeconds 120
        $denied.ExitCode | Should -Be 1
        $denied.Output | Should -Match 'Entra Connect sync will not be possible'
        $denied.MainResult.SuccessCount | Should -Be 0 -Because 'the refused run did not do anything'
        $denied.MainResult.SkippedCount | Should -Be 0
        $denied.MainResult.ErrorCount | Should -Be 1
        $denied.MainResult.TotalCount | Should -Be 1
        [string]$denied.MainResult.GlobalHtmlReport | Should -BeExactly ''
        [string]$denied.MainResult.GlobalCsvReport | Should -BeExactly ''
        $denied.Output | Should -Match '0 done'
        $denied.Output | Should -Not -Match '[2-9] done'
        $rows = @(Import-Csv -LiteralPath $denied.MainResult.CsvReport -Delimiter ';')
        $rows.Count | Should -Be 1
        $rows[0].UserPrincipalName | Should -BeExactly "(batch $short)"
        @(Get-GateWrites $runtime).Count | Should -Be $writes
    }
    It 'a Preview says "preview" and counts "ready" and "planned" objects, never "done"; an Apply still says "done"' {
        $runtime = New-GateRuntime -Name 'preview-words-313'
        $preview = Invoke-GateProcess $runtime @{Action='Convert';Phase='AD';Mode='Preview';ConfigPath=$runtime.ConfigPath} -TimeoutSeconds 120
        $preview.ExitCode | Should -Be 0 -Because ($preview.Output + $preview.Error)
        $preview.Output | Should -Match 'Convert preview finished - nothing was changed'
        $preview.Output | Should -Match '[0-9]+ ready . [0-9]+ planned . [0-9]+ error\(s\) . [0-9]+ skipped'
        $preview.Output | Should -Not -Match '[0-9]+ done|Convert finished'
        # A Preview of the cloud phase whose mailboxes are already there: the objects are "ready", the title says "preview finished".
        $made = New-GateRuntime -Name 'preview-words-ad-313'
        $ad = Invoke-GateProcess $made @{Action='Convert';Phase='AD';Mode='Apply';Force=$true;ConfigPath=$made.ConfigPath} -TimeoutSeconds 120
        $ad.ExitCode | Should -Be 2 -Because ($ad.Output + $ad.Error)
        $ad.Output | Should -Match '[0-9]+ done . [0-9]+ pending' -Because 'an Apply keeps its words'
        $cloud = Invoke-GateProcess $made @{Action='Convert';Phase='Cloud';Mode='Preview';ConfigPath=$made.ConfigPath;Batch=[string]$ad.MainResult.BatchId} -TimeoutSeconds 120
        $cloud.ExitCode | Should -BeIn @(0, 2) -Because ($cloud.Output + $cloud.Error)
        $cloud.Output | Should -Not -Match 'Convert finished'
        $cloud.Output | Should -Not -Match '[0-9]+ done'
        $cloud.Output | Should -Match 'Convert preview finished - nothing was changed'
        $cloud.Output | Should -Match '[0-9]+ ready'
    }
}

Describe 'Release 3.1.3 - Check: one error for one failure, a plain line at each wait (production Cloud module, mocked boundaries, no network)' -Tag 'Release313' {
    BeforeAll {
        $global:PraGate.X500NetworkPath=Join-Path $global:PraGate.Root 'PraGateCheck313Network.psm1'
        $networkSource=@'
if ($env:PRA_GATE_NONET -cne 'SYNTHETIC-NO-NETWORK') { throw 'Synthetic interlock absent.' }
function Get-EXOMailbox { [CmdletBinding()]param($Filter,$Properties,$ResultSize,[switch]$InactiveMailboxOnly) throw 'SYNTHETIC BLOCK: EXO mailbox' }
function Get-EXORecipient { [CmdletBinding()]param($UserPrincipalName,$Filter,$Properties,$ResultSize) throw 'SYNTHETIC BLOCK: EXO recipient' }
function Get-MgUser { [CmdletBinding()]param($UserId,$Property) throw 'SYNTHETIC BLOCK: Graph user' }
function Get-MgUserLicenseDetail { [CmdletBinding()]param($UserId,[switch]$All) throw 'SYNTHETIC BLOCK: Graph license' }
function Get-MgContext { [CmdletBinding()]param() [pscustomobject]@{TenantId='20000000-0000-0000-0000-000000000002';ContextScope='Process'} }
function Get-ConnectionInformation { [CmdletBinding()]param() [pscustomobject]@{TenantID='20000000-0000-0000-0000-000000000002';State='Connected';TokenStatus='Active';ConnectionId='30000000-0000-0000-0000-000000000003';ModuleName=$global:PraGate.X500NetworkPath} }
Export-ModuleMember -Function Get-EXOMailbox,Get-EXORecipient,Get-MgUser,Get-MgUserLicenseDetail,Get-ConnectionInformation,Get-MgContext
'@
        [IO.File]::WriteAllText($global:PraGate.X500NetworkPath,$networkSource,(New-Object Text.UTF8Encoding($true)))
        Get-Module PRA.Cloud -All | Remove-Module -Force -ErrorAction SilentlyContinue
        Import-Module $global:PraGate.X500NetworkPath -Global -Force
        Import-Module (Join-Path $global:PraGate.Package 'module\PRA.Cloud.psm1') -Force -Global
        $global:PraGate.X500Legacy='X500:/o=Synthetic/ou=Gate/cn=Recipients/cn=user1'
        $global:PraGate.X500Oldest='X500:/o=Contoso/ou=First Administrative Group/cn=Recipients/cn=user1'
    }
    BeforeEach {
        $global:PraGate.Runtime=New-GateRuntime -Name 'check-313'
        $context=New-GateContext $global:PraGate.Runtime -Mode Preview -Action Check
        $context.Phase='Cloud'; $context.Once=$false; $context.CheckScope='Both'; $context.IntervalMinutes=1; $context.TimeoutMinutes=3
        $context.Config.Cloud=@{CheckMailbox=$true;CheckLicense=$false;MailboxCheckVia='Exo';RequiredSkuPartNumber='';TenantId='20000000-0000-0000-0000-000000000002'}
        $context.Config.SharedMailbox.GrantFullAccess=$false
        $context.LogFile=Join-Path $global:PraGate.Runtime.Root 'logs\check-313.log'
        $global:PraGate.CloudContext=$context
        $global:PraGate.X500Binding=@{TenantId='20000000-0000-0000-0000-000000000002';ConnectionId='30000000-0000-0000-0000-000000000003';ModuleLocation=$global:PraGate.X500NetworkPath;ModulePath=$global:PraGate.X500NetworkPath}
        $record=[pscustomobject][ordered]@{ObjectGuid='';SamAccountName='user1@gate.invalid';UserPrincipalName='user1@gate.invalid';IsShared=$false}
        $global:PraGate.CheckRow=New-PraRow $context $record
        $context.Rows.Add($global:PraGate.CheckRow)
    }
    AfterAll {
        Remove-Module PRA.Cloud,PraGateCheck313Network -Force -ErrorAction SilentlyContinue
    }
    It 'a Check given a UPN that fails counts ONE error, not one per layer (<Name>)' -ForEach @(
        @{ Name = 'no mailbox at all'; Reply = $null }
        @{ Name = 'a MailUser: the mailbox is not there yet (-Once)'; Reply = [pscustomobject]@{ RecipientTypeDetails = 'MailUser'; EmailAddresses = [string[]]@('SMTP:user1@gate.invalid') } }
    ) {
        $global:PraGate.CloudContext.Once=$true; $global:PraGate.X500Reply=$Reply
        InModuleScope PRA.Cloud {
            Mock Connect-PraCloudSession { param($Context) $Context['_PraCloudSession']=@{Graph=$false;Exo=$true;Subprocess=$false;Binding=$global:PraGate.X500Binding} }
            Mock Close-PraCloudSession { }
            Mock Start-Sleep { }
            Mock Get-EXOMailbox { if ($null -ne $global:PraGate.X500Reply) { $global:PraGate.X500Reply } }
            Invoke-PraCloudPhase $global:PraGate.CloudContext @($global:PraGate.CheckRow) 'Convert'
        }
        $context=$global:PraGate.CloudContext
        $global:PraGate.CheckRow.FinalStatus | Should -BeExactly 'Error'
        $outcome = Get-PraOutcome $context
        $outcome.Counts.Error | Should -Be 1 -Because (($outcome.Rows | ForEach-Object { $_.FinalStatus + ' ' + $_.UserPrincipalName + ' ' + $_.Detail }) -join ' // ')
        $outcome.Rows.Count | Should -Be 1
        # The error says it in plain words; the technical string is only in the CloudDetail of the row and in the log; the same text is not also a warning.
        $message = [string]$context.Issues[0].Message
        $message | Should -Match '^user1@gate\.invalid: not in the expected state: '
        $message | Should -Not -Match 'MBX:|LIC:|type='
        $global:PraGate.CheckRow.CloudDetail | Should -Match 'MBX:EXO type='
        @(Get-PraList $context 'WarningList' | Where-Object { [string]$_.Message -like '*user1@gate.invalid*' }).Count | Should -Be 0 -Because 'an error is not repeated as a warning'
        [IO.File]::ReadAllText($context.LogFile) | Should -Match 'Technical detail: Expected state not reached .*MBX:EXO type='
    }
    It 'a Check of an object that is still an on-premises mailbox says so in words (no mailbox in Exchange Online yet)' {
        $global:PraGate.CloudContext.Once=$true; $global:PraGate.X500Reply=$null
        InModuleScope PRA.Cloud {
            Mock Connect-PraCloudSession { param($Context) $Context['_PraCloudSession']=@{Graph=$false;Exo=$true;Subprocess=$false;Binding=$global:PraGate.X500Binding} }
            Mock Close-PraCloudSession { }
            Mock Start-Sleep { }
            Mock Get-EXOMailbox { }
            Invoke-PraCloudPhase $global:PraGate.CloudContext @($global:PraGate.CheckRow) 'Convert'
        }
        [string]$global:PraGate.CloudContext.Issues[0].Message | Should -BeExactly 'user1@gate.invalid: not in the expected state: no mailbox in Exchange Online yet (the object is still an on-premises mailbox, or the sync has not run).'
    }
    It 'licence states are told in words, not as a key=value string' -ForEach @(
        @{ Facts = @{ LicenseCount = 0; Enabled = $false; RequiredSku = ''; RequiredSkuOk = $true }; Words = 'no licence is assigned' }
        @{ Facts = @{ LicenseCount = 1; Enabled = $false; RequiredSku = 'ENTERPRISEPACK'; RequiredSkuOk = $false }; Words = 'the required licence \(ENTERPRISEPACK\) is not assigned' }
        @{ Facts = @{ LicenseCount = 1; Enabled = $false; RequiredSku = ''; RequiredSkuOk = $true }; Words = 'Exchange Online is not enabled in the licence' }
    ) {
        $global:PraGate.CloudContext.Once=$true; $global:PraGate.CloudContext.Config.Cloud.CheckLicense=$true; $global:PraGate.CloudContext.Config.Cloud.CheckMailbox=$false
        $global:PraGate.CloudFacts=$Facts
        InModuleScope PRA.Cloud {
            Mock Connect-PraCloudSession { param($Context) $Context['_PraCloudSession']=@{Graph=$true;Exo=$false;Subprocess=$false;Binding=$global:PraGate.X500Binding} }
            Mock Close-PraCloudSession { }
            Mock Start-Sleep { }
            Mock Get-PraGraphFact { [pscustomobject]$global:PraGate.CloudFacts }
            Invoke-PraCloudPhase $global:PraGate.CloudContext @($global:PraGate.CheckRow) 'Convert'
        }
        $global:PraGate.CloudContext.Issues.Count | Should -Be 1
        [string]$global:PraGate.CloudContext.Issues[0].Message | Should -Match $Words
        [string]$global:PraGate.CloudContext.Issues[0].Message | Should -Not -Match 'LIC:|SKUPresent|ExpectedSKU'
        $global:PraGate.CheckRow.CloudDetail | Should -Match 'LIC:OK=False'
    }
    It 'while a Check waits, each wait line says what is awaited and that -Once checks once; the X500 wait lines carry an icon' {
        $icon = & (Get-Module PRA.Common) { Get-PraIcon 'Clock' }
        # A short real wait (about a second): the loop is paced by the clock, the sleep itself is replaced.
        $global:PraGate.CloudContext.Once=$false; $global:PraGate.CloudContext.TimeoutMinutes=0.02
        $records = @(InModuleScope PRA.Cloud {
            Mock Connect-PraCloudSession { param($Context) $Context['_PraCloudSession']=@{Graph=$false;Exo=$true;Subprocess=$false;Binding=$global:PraGate.X500Binding} }
            Mock Close-PraCloudSession { }
            Mock Start-Sleep { [Threading.Thread]::Sleep(250) }
            Mock Get-EXOMailbox { }
            Invoke-PraCloudPhase $global:PraGate.CloudContext @($global:PraGate.CheckRow) 'Convert' 6>&1
        })
        $text = ($records | ForEach-Object { [string]$_ }) -join "`n"
        $text | Should -Match 'Not ready yet: user1@gate\.invalid - next check in [0-9]+ s'
        $text | Should -Match 'Waiting for the mailbox to exist in Exchange Online\. A mailbox that is still on-premises never gets there without a Convert; with -Once the check looks once and stops\.'
        $text | Should -Match ([regex]::Escape($icon + 'Not ready yet')) -Because 'a wait line has its icon'
        # The X500 wait lines (mailbox ready, addresses not all there yet).
        $global:PraGate.CloudContext.Action = 'Convert'
        $global:PraGate.CheckRow = New-PraRow $global:PraGate.CloudContext ([pscustomobject][ordered]@{ ObjectGuid = '00000000-0000-0000-0000-000000000001'; SamAccountName = 'user1@gate.invalid'; UserPrincipalName = 'user1@gate.invalid'; IsShared = $false
            ExpectedX500 = [string[]]@($global:PraGate.X500Legacy, $global:PraGate.X500Oldest) })
        $global:PraGate.X500Reply=[pscustomobject]@{RecipientTypeDetails='UserMailbox';EmailAddresses=[string[]]@('SMTP:user1@gate.invalid',$global:PraGate.X500Legacy)}
        $records = @(InModuleScope PRA.Cloud {
            Mock Connect-PraCloudSession { param($Context) $Context['_PraCloudSession']=@{Graph=$false;Exo=$true;Subprocess=$false;Binding=$global:PraGate.X500Binding} }
            Mock Close-PraCloudSession { }
            Mock Start-Sleep { [Threading.Thread]::Sleep(250) }
            Mock Get-EXOMailbox { $global:PraGate.X500Reply }
            Invoke-PraCloudPhase $global:PraGate.CloudContext @($global:PraGate.CheckRow) 'Convert' 6>&1
        })
        $text = ($records | ForEach-Object { [string]$_ }) -join "`n"
        $text | Should -Match ([regex]::Escape($icon + 'user1@gate.invalid: mailbox ready;') + ' X500 addresses not all visible yet, check [23] of 3 in [0-9]+ s')
    }
}

Describe 'Release 3.1.3 - package files, sync wording, rollback command, Preview blockers, Check words (real main, synthetic)' -Tag 'Release313b' {
    BeforeEach {
        function script:Use-RemoteSync313b($Runtime, [string]$Mode) {
            $Runtime.State.RemoteSync = $Mode
            [IO.File]::WriteAllText($Runtime.StatePath, [Management.Automation.PSSerializer]::Serialize($Runtime.State, 35))
        }
        function script:Enable-SyncConfig313b($Runtime) {
            Set-GateConfigText $Runtime { param($t) $t.Replace('EntraConnect=@{Sync=$false;Server='''';', 'EntraConnect=@{Sync=$true;Server=''SRV-SYNC01'';') }
        }
    }

    It 'the Next step names the zip AND its .sha256 file, and a missing sidecar is refused with what to copy' {
        $runtime = New-GateRuntime -Name 'sidecar-313b'
        $run = Invoke-GateProcess $runtime @{Action='Convert';Phase='AD';Mode='Apply';Force=$true;ConfigPath=$runtime.ConfigPath} -TimeoutSeconds 120
        $run.ExitCode | Should -Be 2 -Because ($run.Output + $run.Error)
        $zip = [string]$run.MainResult.TransferPackage
        $name = [IO.Path]::GetFileName($zip)
        (@($run.MainResult.NextSteps) -join "`n") | Should -Match ([regex]::Escape("Copy these two files, together in the same folder, to the cloud server (anywhere): $zip and $zip.sha256. Then run there:"))
        $cloud = New-GateRuntime -Name 'sidecar-313b-cloud'
        $drop = Join-Path $cloud.Root 'dropped'; $null = New-Item -ItemType Directory -Path $drop
        Copy-Item -LiteralPath $zip -Destination $drop
        $second = Invoke-GateProcess $cloud @{Action='Convert';Phase='Cloud';Mode='Preview';ConfigPath=$cloud.ConfigPath;Batch=(Join-Path $drop $name)} -TimeoutSeconds 120
        $second.ExitCode | Should -Be 1
        $second.Output | Should -Match ([regex]::Escape("the .sha256 file next to the package is missing. Copy $name.sha256 from the Outbox folder of the AD server that wrote the package, into the same folder as the .zip, then run again."))
    }
    It 'a suspended sync scheduler is told with its remedy, with no .NET text, and the cycle is not announced as started' {
        $runtime = New-GateRuntime -Name 'sync-suspended-313b'
        Enable-SyncConfig313b $runtime; Use-RemoteSync313b $runtime 'RawFail'
        $run = Invoke-GateProcess $runtime @{Action='Convert';Phase='AD';Mode='Apply';Force=$true;ConfigPath=$runtime.ConfigPath} -TimeoutSeconds 120
        $run.ExitCode | Should -Be 2 -Because ($run.Output + $run.Error)
        $run.Output | Should -Match ([regex]::Escape('The Entra Connect sync did not run: the synchronisation scheduler is suspended on SRV-SYNC01: run Set-ADSyncScheduler -SchedulerSuspended $false on that server, then run the sync. The AD changes are already made and verified'))
        $run.Output | Should -Not -Match 'InvalidOperationException|MetadirectoryServices|StartSyncCycle'
        $run.Output | Should -Not -Match 'cycle started'
        $steps = @($run.MainResult.NextSteps)
        $steps[0] | Should -BeExactly 'AD is changed and verified. The Entra Connect sync did not run: the synchronisation scheduler is suspended on SRV-SYNC01: run Set-ADSyncScheduler -SchedulerSuspended $false on that server, then run the sync.'
        [IO.File]::ReadAllText([string]$run.MainResult.LogFile) | Should -Match 'technical message: System\.InvalidOperationException: Scheduler is already suspended'
    }
    It 'any other failure of the cycle shows the first line of the message only, never the exception type or the call stack' {
        $runtime = New-GateRuntime -Name 'sync-raw-313b'
        Enable-SyncConfig313b $runtime; Use-RemoteSync313b $runtime 'RawFailOther'
        $run = Invoke-GateProcess $runtime @{Action='Convert';Phase='AD';Mode='Apply';Force=$true;ConfigPath=$runtime.ConfigPath} -TimeoutSeconds 120
        $run.ExitCode | Should -Be 2 -Because ($run.Output + $run.Error)
        $steps = @($run.MainResult.NextSteps)
        $steps[0] | Should -BeExactly 'AD is changed and verified. The Entra Connect sync did not run: the synchronisation cycle could not start on SRV-SYNC01: The sync engine returned an unexpected result.'
        $run.Output | Should -Not -Match 'InvalidOperationException|MetadirectoryServices|StartSyncCycle|cycle started'
        ($steps -join "`n") | Should -Not -Match '\bcheck\b'
        [IO.File]::ReadAllText([string]$run.MainResult.LogFile) | Should -Match 'technical message: System\.InvalidOperationException: The sync engine returned'
    }
    It 'a sync cycle that runs is announced as started before it is reported finished' {
        $runtime = New-GateRuntime -Name 'sync-order-313b'
        Enable-SyncConfig313b $runtime; Use-RemoteSync313b $runtime 'Ok'
        $run = Invoke-GateProcess $runtime @{Action='Convert';Phase='AD';Mode='Apply';Force=$true;ConfigPath=$runtime.ConfigPath} -TimeoutSeconds 120
        $run.ExitCode | Should -Be 2 -Because ($run.Output + $run.Error)
        $started = $run.Output.IndexOf('cycle started on SRV-SYNC01')
        $finished = $run.Output.IndexOf('Entra Connect cycle finished on SRV-SYNC01')
        $started | Should -BeGreaterThan -1
        $finished | Should -BeGreaterThan $started
        $run.Output | Should -Match 'RESULT: PENDING' -Because 'an exit code 2 is not a pass'
        $run.Output | Should -Not -Match 'RESULT: PASS'
        [IO.File]::ReadAllText([string]$run.MainResult.LogFile) | Should -Match 'RESULT: PENDING'
    }
    It 'a server without the RSAT ActiveDirectory module says so in plain words, under its own operation label' {
        $runtime = New-GateRuntime -Name 'rsat-313b'
        $global:PraGate.RsatContext = New-GateContext $runtime -Mode Preview -Action Convert
        $thrown = InModuleScope PRA.Directory {
            Mock Import-Module { throw 'Le module ActiveDirectory est introuvable.' }
            Mock Get-Module { @() }
            try { Initialize-PraDirectory $global:PraGate.RsatContext; '' } catch { $_.Exception.Message }
        }
        $thrown | Should -Match '^The RSAT ActiveDirectory module is not installed on this server: the Active Directory part cannot run here \(install the RSAT feature Active Directory module, or run the AD part on a server that has it\)\.$'
        $global:PraGate.RsatContext.CurrentOperation | Should -BeExactly 'Import-ActiveDirectory'
        Remove-Variable RsatContext -Scope Global -ErrorAction SilentlyContinue
    }
    It 'after a two-server Convert Cloud, the rollback command is the AD phase of the batch' {
        $runtime = New-GateRuntime -Name 'rollback-313b'
        $ad = Invoke-GateProcess $runtime @{Action='Convert';Phase='AD';Mode='Apply';Force=$true;ConfigPath=$runtime.ConfigPath} -TimeoutSeconds 120
        $ad.ExitCode | Should -Be 2 -Because ($ad.Output + $ad.Error)
        $zip = [string]$ad.MainResult.TransferPackage
        $cloud = New-GateRuntime -Name 'rollback-313b-cloud'
        $drop = Join-Path $cloud.Root 'dropped'; $null = New-Item -ItemType Directory -Path $drop
        Copy-Item -LiteralPath $zip, ($zip + '.sha256') -Destination $drop
        $second = Invoke-GateProcess $cloud @{Action='Convert';Phase='Cloud';Mode='Apply';Force=$true;ConfigPath=$cloud.ConfigPath;Batch=(Join-Path $drop ([IO.Path]::GetFileName($zip)))} -TimeoutSeconds 120
        $second.ExitCode | Should -BeIn @(0, 2) -Because ($second.Output + $second.Error)
        (@($second.MainResult.NextSteps) -join "`n") | Should -Match 'To roll back this batch later, on the AD server \(Preview first, then the same command with -Mode Apply\): \.\\Invoke-PraRemoteMailbox\.ps1 -Action Recover -Phase AD -Batch [0-9a-f]{8}$'
        # A single-server batch keeps the plain rollback command (the one server does both parts).
        $both = New-GateRuntime -Name 'rollback-313b-both'
        $done = Invoke-GateProcess $both @{Action='Convert';Phase='Both';Mode='Apply';Force=$true;ConfigPath=$both.ConfigPath} -TimeoutSeconds 120
        (@($done.MainResult.NextSteps) -join "`n") | Should -Match 'To roll back this batch later: \.\\Invoke-PraRemoteMailbox\.ps1 -Action Recover -Batch [0-9a-f]{8}'
    }
    It 'a Preview that knows that the Apply will be refused says what to fix before it proposes the Apply (<Mode>)' -ForEach @(
        @{ Mode = 'Denied';      Fix = 'give this account the rights named in the warning above' }
        @{ Mode = 'Unreachable'; Fix = 'fix the problem named in the warning above' }
    ) {
        $runtime = New-GateRuntime -Name 'preview-blocker-313b'
        Enable-SyncConfig313b $runtime; Use-RemoteSync313b $runtime $Mode
        $run = Invoke-GateProcess $runtime @{Action='Convert';Phase='AD';Mode='Preview';ConfigPath=$runtime.ConfigPath} -TimeoutSeconds 120
        $run.ExitCode | Should -Be 0 -Because ($run.Output + $run.Error)
        $steps = @($run.MainResult.NextSteps)
        $steps[0] | Should -BeExactly ('The Apply would be refused as things stand. First {0}, or set EntraConnect.Sync = $false in the configuration file and run the Entra Connect sync yourself after the AD changes.' -f $Fix)
        $steps[1] | Should -BeExactly 'Then run the Apply:'
        $steps[2] | Should -Match '^\.\\Invoke-PraRemoteMailbox\.ps1 -Action Convert -Phase AD -Mode Apply'
        # When the sync check passes, the Preview proposes the Apply straight away.
        Use-RemoteSync313b $runtime 'Ok'
        $fine = Invoke-GateProcess $runtime @{Action='Convert';Phase='AD';Mode='Preview';ConfigPath=$runtime.ConfigPath} -TimeoutSeconds 120
        (@($fine.MainResult.NextSteps) -join "`n") | Should -Not -Match 'would be refused'
    }
    It 'a Preview with unusable cloud modules says to install them before it proposes the Apply' {
        $runtime = New-GateRuntime -Name 'preview-modules-313b'
        Remove-Item -LiteralPath (Join-Path $runtime.Modules 'Microsoft.Graph.Authentication'), (Join-Path $runtime.Modules 'Microsoft.Graph.Users') -Recurse -Force
        $run = Invoke-GateProcess $runtime @{Action='Convert';Phase='Both';Mode='Preview';ConfigPath=$runtime.ConfigPath} -TimeoutSeconds 120
        $run.ExitCode | Should -Be 0 -Because ($run.Output + $run.Error)
        $steps = @($run.MainResult.NextSteps)
        $steps[0] | Should -BeExactly 'The Apply would be refused as things stand. First install or update the cloud modules with the commands in the warning above.'
        $steps[1] | Should -BeExactly 'Then run the Apply:'
        $steps[2] | Should -Match '-Action Convert -Phase Both -Mode Apply'
    }
    It 'a Check says "as expected" and never "done"; a Check that finds a difference says so, and nothing was changed' {
        $runtime = New-GateRuntime -Name 'check-words-313b'
        $good = Invoke-GateProcess $runtime @{Action='Check';Identity='user1';ConfigPath=$runtime.ConfigPath} -TimeoutSeconds 120
        $good.ExitCode | Should -BeIn @(0, 2) -Because ($good.Output + $good.Error)
        $good.Output | Should -Match '[0-9]+ as expected . 0 not as expected . [0-9]+ skipped'
        $good.Output | Should -Not -Match '[0-9]+ done'
        $bad = New-GateRuntime -Name 'check-not-expected-313b' -Case 'CheckNotExpected'
        $run = Invoke-GateProcess $bad @{Action='Check';Identity='user1';ConfigPath=$bad.ConfigPath} -TimeoutSeconds 120
        $run.ExitCode | Should -Be 1 -Because ($run.Output + $run.Error)
        $run.Output | Should -Match ([regex]::Escape('Check finished: 1 object(s) not in the expected state. Nothing was changed.'))
        $run.Output | Should -Match ([regex]::Escape('Check finished - 1 object(s) not in the expected state'))
        $run.Output | Should -Not -Match 'Check stopped'
        $run.Output | Should -Not -Match 'no restore or clean-up is done'
        $run.Output | Should -Match '0 as expected . 1 not as expected'
        @(Get-GateWrites $bad).Count | Should -Be 0
    }
}
Describe 'Release 3.1.3 - a network failure and an unreachable domain controller are said in plain words (production Cloud and Directory modules, mocked boundaries)' -Tag 'Release313c' {
    BeforeAll {
        $global:PraGate.X500NetworkPath=Join-Path $global:PraGate.Root 'PraGateCheck313cNetwork.psm1'
        $networkSource=@'
if ($env:PRA_GATE_NONET -cne 'SYNTHETIC-NO-NETWORK') { throw 'Synthetic interlock absent.' }
function Get-EXOMailbox { [CmdletBinding()]param($Filter,$Properties,$ResultSize,[switch]$InactiveMailboxOnly) throw 'SYNTHETIC BLOCK: EXO mailbox' }
function Get-EXORecipient { [CmdletBinding()]param($UserPrincipalName,$Filter,$Properties,$ResultSize) throw 'SYNTHETIC BLOCK: EXO recipient' }
function Get-ConnectionInformation { [CmdletBinding()]param() [pscustomobject]@{TenantID='20000000-0000-0000-0000-000000000002';State='Connected';TokenStatus='Active';ConnectionId='30000000-0000-0000-0000-000000000003';ModuleName=$global:PraGate.X500NetworkPath} }
Export-ModuleMember -Function Get-EXOMailbox,Get-EXORecipient,Get-ConnectionInformation
'@
        [IO.File]::WriteAllText($global:PraGate.X500NetworkPath,$networkSource,(New-Object Text.UTF8Encoding($true)))
        Get-Module PRA.Cloud -All | Remove-Module -Force -ErrorAction SilentlyContinue
        Import-Module $global:PraGate.X500NetworkPath -Global -Force
        Import-Module (Join-Path $global:PraGate.Package 'module\PRA.Cloud.psm1') -Force -Global
    }
    BeforeEach {
        $global:PraGate.Runtime=New-GateRuntime -Name 'network-313c'
        $context=New-GateContext $global:PraGate.Runtime -Mode Preview -Action Check
        $context.Phase='Cloud'; $context.Once=$true; $context.CheckScope='Both'; $context.IntervalMinutes=1; $context.TimeoutMinutes=3
        $context.Config.Cloud=@{CheckMailbox=$true;CheckLicense=$false;MailboxCheckVia='Exo';RequiredSkuPartNumber='';TenantId='20000000-0000-0000-0000-000000000002'}
        $context.Config.SharedMailbox.GrantFullAccess=$false
        $context.LogFile=Join-Path $global:PraGate.Runtime.Root 'logs\network-313c.log'
        $global:PraGate.CloudContext=$context
        $global:PraGate.X500Binding=@{TenantId='20000000-0000-0000-0000-000000000002';ConnectionId='30000000-0000-0000-0000-000000000003';ModuleLocation=$global:PraGate.X500NetworkPath;ModulePath=$global:PraGate.X500NetworkPath}
        $record=[pscustomobject][ordered]@{ObjectGuid='';SamAccountName='user1@gate.invalid';UserPrincipalName='user1@gate.invalid';IsShared=$false}
        $global:PraGate.CheckRow=New-PraRow $context $record
        $context.Rows.Add($global:PraGate.CheckRow)
    }
    AfterAll {
        Remove-Module PRA.Cloud,PraGateCheck313cNetwork -Force -ErrorAction SilentlyContinue
    }
    It 'a network failure of the cloud check is one plain line with the UPN and the host, and the raw text only in the technical detail (<Name>)' -ForEach @(
        @{ Name = 'a connection that does not answer (localized text)'; Kind = 'Http'; Text = 'Une tentative de connexion a échoué car le parti connecté n''a pas répondu au-delà d''une certaine durée (graph.microsoft.com:443)'; Expected = 'user1@gate.invalid: Microsoft 365 did not answer (network): graph.microsoft.com:443. Run again.' }
        @{ Name = 'a timeout without a host'; Kind = 'Timeout'; Text = 'The operation has timed out.'; Expected = 'user1@gate.invalid: Microsoft 365 did not answer (network). Run again.' }
        @{ Name = 'only the text tells (the Exchange Online child process)'; Kind = 'Text'; Text = 'Exchange Online child process code=1, stderr=[No such host is known. (outlook.office365.com:443)], stdout=[]'; Expected = 'user1@gate.invalid: Microsoft 365 did not answer (network): outlook.office365.com:443. Run again.' }
    ) {
        $global:PraGate.NetworkFailure=@{ Kind=$Kind; Text=$Text }
        InModuleScope PRA.Cloud {
            Mock Connect-PraCloudSession { param($Context) $Context['_PraCloudSession']=@{Graph=$false;Exo=$true;Subprocess=$false;Binding=$global:PraGate.X500Binding} }
            Mock Close-PraCloudSession { }
            Mock Start-Sleep { }
            Mock Get-EXOMailbox {
                $f=$global:PraGate.NetworkFailure
                switch ($f.Kind) {
                    'Http' { throw [System.Net.Http.HttpRequestException]::new($f.Text, [System.Net.Sockets.SocketException]::new(10060)) }
                    'Timeout' { throw [TimeoutException]::new($f.Text) }
                    default { throw $f.Text }
                }
            }
            Invoke-PraCloudPhase $global:PraGate.CloudContext @($global:PraGate.CheckRow) 'Convert'
        }
        $context=$global:PraGate.CloudContext
        $context.Issues.Count | Should -Be 1
        [string]$context.Issues[0].Message | Should -BeExactly $Expected
        [string]$context.Issues[0].Message | Should -Not -Match '\|\s*$'
        $global:PraGate.CheckRow.CloudDetail | Should -Be $Text -Because 'the raw text is the technical detail of the row'
        $context.NetworkFailure | Should -BeTrue
        $outcome = Get-PraOutcome $context
        $outcome.Counts.Error | Should -Be 1
        $outcome.Counts.RunError | Should -Be 1 -Because 'an object that could not be read is not "not in the expected state"'
        [IO.File]::ReadAllText($context.LogFile) | Should -Match ('Technical detail: ' + [regex]::Escape($Text))
    }
    It 'another failure keeps its own message and never ends with an empty " | "' {
        InModuleScope PRA.Cloud {
            Mock Connect-PraCloudSession { param($Context) $Context['_PraCloudSession']=@{Graph=$false;Exo=$true;Subprocess=$false;Binding=$global:PraGate.X500Binding} }
            Mock Close-PraCloudSession { }
            Mock Start-Sleep { }
            Mock Get-EXOMailbox { throw 'SYNTHETIC: the answer is not valid.' }
            Invoke-PraCloudPhase $global:PraGate.CloudContext @($global:PraGate.CheckRow) 'Convert'
        }
        $context=$global:PraGate.CloudContext
        [string]$context.Issues[0].Message | Should -BeExactly 'SYNTHETIC: the answer is not valid.'
        [bool](Get-PraValue $context 'NetworkFailure' $false) | Should -BeFalse
    }
    It 'Get-PraNetworkFailure tells network errors from the others (<Name>)' -ForEach @(
        @{ Name = 'socket'; Make = { [System.Net.Sockets.SocketException]::new(10061) }; Network = $true }
        @{ Name = 'http without status, inside an aggregate'; Make = { [AggregateException]::new([System.Net.Http.HttpRequestException]::new('x', [System.Net.Sockets.SocketException]::new(11001))) }; Network = $true }
        @{ Name = 'an HTTP answer with a status is not a network failure'; Make = { [System.Net.Http.HttpRequestException]::new('Response status code does not indicate success: 403 (Forbidden).', $null, [System.Net.HttpStatusCode]::Forbidden) }; Network = $false }
        @{ Name = 'a plain error'; Make = { [InvalidOperationException]::new('Microsoft Graph: user not found or not unique (a@b.c).') }; Network = $false }
        @{ Name = 'the write timeout of the child process is not a network failure'; Make = { [InvalidOperationException]::new('Exchange Online timeout; write state unknown. stderr=[], stdout=[]') }; Network = $false }
    ) {
        $global:PraGate.NetworkErrorMaker=$Make
        $result = InModuleScope PRA.Cloud {
            $exception=& $global:PraGate.NetworkErrorMaker
            Get-PraNetworkFailure ([Management.Automation.ErrorRecord]::new($exception, 'x', [Management.Automation.ErrorCategory]::NotSpecified, $null))
        }
        ($null -ne $result) | Should -Be $Network
    }
    It 'a domain controller that does not answer is said in plain words (by type, whatever the language); the raw text stays in the log' {
        $runtime = New-GateRuntime -Name 'dc-down-313c'
        $global:PraGate.DcContext = New-GateContext $runtime -Mode Preview -Action Check
        $global:PraGate.DcContext.Server = 'dc01.gate.invalid'
        $global:PraGate.DcContext.LogFile = Join-Path $runtime.Root 'logs\dc-down-313c.log'
        if (-not ('GateSynthetic.ADServerDownException' -as [type])) { Add-Type -TypeDefinition 'namespace GateSynthetic { public class ADServerDownException : System.Exception { public ADServerDownException(string message) : base(message) { } } }' }
        $thrown = InModuleScope PRA.Directory {
            try { $null = Invoke-PraRead $global:PraGate.DcContext 'Get-ADDomainController' 'dc01.gate.invalid' { throw [GateSynthetic.ADServerDownException]::new('Impossible de contacter le serveur.') }; '' } catch { $_.Exception.Message }
        }
        $thrown | Should -BeExactly 'The domain controller dc01.gate.invalid does not answer from this machine (Active Directory Web Services, TCP 9389): run the Check on a machine that reaches it, or give the UPN of the mailbox as -Identity.'
        $global:PraGate.DcContext.Issues.Count | Should -Be 0 -Because 'the stop of the run is the one error'
        $global:PraGate.DcContext.DcUnreachable | Should -BeTrue
        $global:PraGate.DcContext.CurrentIdentity | Should -BeExactly ''
        [IO.File]::ReadAllText($global:PraGate.DcContext.LogFile) | Should -Match 'AD read failed \| Get-ADDomainController \| DC=dc01\.gate\.invalid .*GateSynthetic\.ADServerDownException \| Impossible de contacter le serveur\.'
        $other = InModuleScope PRA.Directory {
            try { $null = Invoke-PraRead $global:PraGate.DcContext 'Get-ADUser/Identity' 'x' { throw 'SYNTHETIC: other read failure' }; '' } catch { $_.Exception.Message }
        }
        $other | Should -BeExactly 'SYNTHETIC: other read failure'
        $global:PraGate.DcContext.Issues.Count | Should -Be 1 -Because 'any other failure of a read is still logged as an error with its details'
        Remove-Variable DcContext -Scope Global -ErrorAction SilentlyContinue
    }
    It 'the module report says that a Graph module is not installed, and lists versions only for the modules that exist' {
        $global:PraGate.T313c=@([pscustomobject]@{ Name = 'ExchangeOnlineManagement'; Version = [version]'3.10.1' })
        $report = InModuleScope PRA.Common { Mock Get-Module { param($Name, [switch]$ListAvailable) if ($ListAvailable) { $global:PraGate.T313c } else { @() } }; Get-PraCloudModuleReport }
        $report.Graph.Message | Should -Match '^Microsoft Graph: Microsoft\.Graph\.Authentication is not installed; Microsoft\.Graph\.Users is not installed\. The tool needs both'
        $report.Graph.Message | Should -Not -Match 'found'
    }
}
Describe 'Release 3.1.3 - failures told in words, a Check that ran to the end, the rerun commands (real main, synthetic)' -Tag 'Release313c' {
    It 'a Check that cannot reach Microsoft 365 says so with the UPN, counts an error and not "not as expected", changed nothing and proposes the Check again' {
        $runtime = New-GateRuntime -Name 'check-network-313c' -Case 'CloudNetworkFailure'
        $run = Invoke-GateProcess $runtime @{Action='Check';Identity='user1';ConfigPath=$runtime.ConfigPath} -TimeoutSeconds 120
        $run.ExitCode | Should -Be 1 -Because ($run.Output + $run.Error)
        $run.Output | Should -Match ([regex]::Escape('user1@gate.invalid: Microsoft 365 did not answer (network): graph.example.invalid:443. Run again.'))
        $run.Output | Should -Match "Stopped at step 'Cloud' \(operation CloudCheck, object user1@gate\.invalid\): Microsoft 365 did not answer\. Nothing was changed\. Run the Check again\."
        $run.Output | Should -Not -Match 'no restore or clean-up is done'
        $run.Output | Should -Not -Match 'object [0-9a-f]{8}-[0-9a-f]{4}'
        $run.Output | Should -Match '0 as expected . 0 not as expected . 1 error\(s\) . 0 skipped'
        $run.Output | Should -Match 'Check stopped - see the errors below'
        $steps = @($run.MainResult.NextSteps)
        $steps[0] | Should -BeExactly 'Microsoft 365 did not answer from this machine. Nothing was changed: run the Check again when the connection works:'
        $steps[1] | Should -Match '^\.\\Invoke-PraRemoteMailbox\.ps1 -Action Check -Identity ''user1'''
        $run.Output | Should -Match 'run the Check again when the connection works' -Because 'the summary carries the next step'
        @(Get-GateWrites $runtime).Count | Should -Be 0
    }
    It 'a Convert cloud Preview that cannot reach Microsoft 365 says that nothing was changed, never "no restore or clean-up", and proposes the Preview again' {
        $runtime = New-GateRuntime -Name 'preview-network-313c' -Case 'CloudNetworkFailure'
        $ad = Invoke-GateProcess $runtime @{Action='Convert';Phase='AD';Mode='Apply';Force=$true;ConfigPath=$runtime.ConfigPath} -TimeoutSeconds 120
        $ad.ExitCode | Should -Be 2 -Because ($ad.Output + $ad.Error)
        $run = Invoke-GateProcess $runtime @{Action='Convert';Phase='Cloud';Mode='Preview';ConfigPath=$runtime.ConfigPath;Batch=[string]$ad.MainResult.BatchId} -TimeoutSeconds 120
        $run.ExitCode | Should -Be 1 -Because ($run.Output + $run.Error)
        $run.Output | Should -Match 'Microsoft 365 did not answer\. Nothing was changed\. Run the Preview again\.'
        $run.Output | Should -Not -Match 'no restore or clean-up is done'
        $run.Output | Should -Match 'Convert stopped - see the errors below'
        $steps = @($run.MainResult.NextSteps)
        $steps[0] | Should -BeExactly 'Microsoft 365 did not answer from this machine. Nothing was changed: run the Preview again when the connection works:'
        $steps[1] | Should -Match '^\.\\Invoke-PraRemoteMailbox\.ps1 -Action Convert -Phase Cloud -Batch [0-9a-f]{8}'
        $steps[1] | Should -Not -Match '-Mode Apply'
    }
    It 'an Apply of the cloud phase that cannot reach Microsoft 365 keeps an accurate message and proposes the same command again' {
        $runtime = New-GateRuntime -Name 'apply-network-313c'
        $ad = Invoke-GateProcess $runtime @{Action='Convert';Phase='AD';Mode='Apply';Force=$true;ConfigPath=$runtime.ConfigPath} -TimeoutSeconds 120
        $zip = [string]$ad.MainResult.TransferPackage
        $cloud = New-GateRuntime -Name 'apply-network-313c-cloud' -Case 'CloudNetworkFailure'
        $drop = Join-Path $cloud.Root 'dropped'; $null = New-Item -ItemType Directory -Path $drop
        Copy-Item -LiteralPath $zip, ($zip + '.sha256') -Destination $drop
        $run = Invoke-GateProcess $cloud @{Action='Convert';Phase='Cloud';Mode='Apply';Force=$true;ConfigPath=$cloud.ConfigPath;Batch=(Join-Path $drop ([IO.Path]::GetFileName($zip)))} -TimeoutSeconds 120
        $run.ExitCode | Should -Be 1 -Because ($run.Output + $run.Error)
        $run.Output | Should -Match ([regex]::Escape('Microsoft 365 did not answer: the cloud part of this batch is not complete; run it again with the same command.'))
        $run.Output | Should -Not -Match 'Nothing was changed'
        $steps = @($run.MainResult.NextSteps)
        $at = [array]::IndexOf($steps, 'Microsoft 365 did not answer from this machine. What this run already did is kept: run the same command again when the connection works:')
        $at | Should -BeGreaterOrEqual 0 -Because ($steps -join "`n")
        $steps[$at + 1] | Should -Match ('^\.\\Invoke-PraRemoteMailbox\.ps1 -Action Convert -Phase Cloud -Mode Apply -Batch ' + [regex]::Escape("'" + (Join-Path $drop ([IO.Path]::GetFileName($zip))) + "'")) -Because 'the command is the one that was typed: the package path, not the batch ID'
        $steps[$at + 1] | Should -Not -Match '-Batch [0-9a-f]{32}'
    }
    It 'a Check given an account name whose domain controller does not answer: plain message, an error and not "not as expected", the raw text in the log only, the Next steps' {
        $runtime = New-GateRuntime -Name 'check-dc-down-313c' -Case 'AdServerDown'
        $run = Invoke-GateProcess $runtime @{Action='Check';Identity='user1';ConfigPath=$runtime.ConfigPath} -TimeoutSeconds 120
        $run.ExitCode | Should -Be 1 -Because ($run.Output + $run.Error)
        $run.Output | Should -Match ([regex]::Escape('The domain controller dc01.gate.invalid does not answer from this machine (Active Directory Web Services, TCP 9389): run the Check on a machine that reaches it, or give the UPN of the mailbox as -Identity.'))
        $run.Output | Should -Not -Match 'AD read failed|ADServerDownException|Impossible de contacter|ErrorId='
        $run.Output | Should -Match '0 as expected . 0 not as expected . 1 error\(s\) . 0 skipped'
        [IO.File]::ReadAllText([string]$run.MainResult.LogFile) | Should -Match 'AD read failed \| Get-ADDomainController .*ADServerDownException \| Impossible de contacter le serveur'
        $steps = @($run.MainResult.NextSteps)
        $steps[0] | Should -BeExactly 'Nothing was changed. Run the Check again from a machine that reaches the domain controller:'
        $steps[1] | Should -Match '^\.\\Invoke-PraRemoteMailbox\.ps1 -Action Check -Identity ''user1'''
        $steps[3] | Should -Match '^\.\\Invoke-PraRemoteMailbox\.ps1 -Action Check -Identity ''<UPN>'''
        @(Get-GateWrites $runtime).Count | Should -Be 0
    }
    It 'a Preview of the cloud phase run before the Entra Connect sync reminds, first in its Next steps, to run the sync' {
        $runtime = New-GateRuntime -Name 'preview-notyet-313c' -Case 'CloudNotYet'
        $ad = Invoke-GateProcess $runtime @{Action='Convert';Phase='AD';Mode='Apply';Force=$true;ConfigPath=$runtime.ConfigPath} -TimeoutSeconds 120
        $run = Invoke-GateProcess $runtime @{Action='Convert';Phase='Cloud';Mode='Preview';ConfigPath=$runtime.ConfigPath;Batch=[string]$ad.MainResult.BatchId} -TimeoutSeconds 120
        $run.ExitCode | Should -Be 0 -Because ($run.Output + $run.Error)
        $steps = @($run.MainResult.NextSteps)
        $steps[0] | Should -Match '^[0-9]+ object\(s\) are not yet in the expected state in Exchange Online\. If the Entra Connect sync has not run since the Active Directory changes, run it first \(Start-ADSyncSyncCycle -PolicyType Delta on the Entra Connect server, or wait for the next automatic cycle, about 30 minutes\), then run this Preview again\.$'
        $steps[1] | Should -BeExactly 'When the objects are ready, run the Apply:'
        $steps[2] | Should -Match '-Action Convert -Phase Cloud -Mode Apply'
        $run.Output | Should -Match 'Convert preview finished - nothing was changed'
    }
}
Describe 'Release 3.1.3 - the batch named for an object already converted is the current one (production Directory module, synthetic folders)' -Tag 'Release313d' {
    BeforeAll {
        function global:New-Batch313d {
            param([string]$Root, [string]$Id, [string]$Operation, [datetime]$Created, [string]$Guid, [string]$Hash, [string]$Source = '', [string]$Environment = 'SYNTHETIC_GATE', [string]$Prefix = 'Batch')
            $folder = Join-Path $Root ($Prefix + '-' + $Id)
            $null = New-Item -ItemType Directory -Path $folder -Force
            $state = [ordered]@{ SchemaVersion = 2; Operation = $Operation; Kind = 'ADVerified'; Environment = $Environment; BackupFile = ($Operation + '-x.json'); BackupHash = $Hash; SourceBackupHash = $Source
                CreatedUtc = $Created.ToUniversalTime().ToString('o'); Records = @([ordered]@{ ObjectGuid = $Guid; Operation = $Operation; ADVerified = $true }, [ordered]@{ ObjectGuid = '7c2d4e10-3a55-4b0e-9f6a-0d1e2f3a4b5c'; Operation = $Operation; ADVerified = $true }) }
            [IO.File]::WriteAllText((Join-Path $folder ('State-' + $Id + '.json')), ($state | ConvertTo-Json -Depth 5), (New-Object Text.UTF8Encoding($true)))
            if ($Operation -ceq 'Convert') {
                $backup = [ordered]@{ SchemaVersion = 3; Operation = 'Convert'; BatchId = $Id; Environment = $Environment; Records = @([ordered]@{ ObjectGuid = $Guid }) }
                [IO.File]::WriteAllText((Join-Path $folder ('Convert-' + $Environment + '-' + $Id.Substring(0, 8) + '.json')), ($backup | ConvertTo-Json -Depth 5), (New-Object Text.UTF8Encoding($true)))
            }
            (Get-Item -LiteralPath $folder).LastWriteTimeUtc = $Created.ToUniversalTime()
        }
        function global:Find-Batch313d {
            param([string]$Root, [string]$Guid)
            $global:PraGate.T313d = @{ Root = $Root; Guid = $Guid }
            InModuleScope PRA.Directory {
                $context = @{ Config = @{ Environment = 'SYNTHETIC_GATE'; Storage = @{ BackupFolder = $global:PraGate.T313d.Root } } }
                Find-PraConvertedBatch $context $global:PraGate.T313d.Guid
            }
        }
        $global:PraGate.G313d = '5b17e952-08de-42d2-974d-bf578b5b5a1c'
    }
    BeforeEach { $global:PraGate.R313d = Join-Path $global:PraGate.Root ('find-' + [guid]::NewGuid().ToString('N').Substring(0, 6)); $null = New-Item -ItemType Directory -Path $global:PraGate.R313d }
    AfterAll {
        foreach ($name in @('New-Batch313d', 'Find-Batch313d')) { Remove-Item -LiteralPath ('Function:\' + $name) -ErrorAction SilentlyContinue }
        Remove-Variable T313d, G313d, R313d -Scope Global -ErrorAction SilentlyContinue
    }
    It 'names the current batch, not an old batch that was rolled back and that comes last in the alphabet' {
        $root = $global:PraGate.R313d; $guid = $global:PraGate.G313d
        # ff...: converted in January, rolled back by bb... in February; cc...: converted again in March (the current state of the object).
        New-Batch313d $root ('ff000001'.PadRight(32, '0')) 'Convert' ([datetime]'2026-01-10T10:00:00Z') $guid ('a1' * 32)
        New-Batch313d $root ('bb000002'.PadRight(32, '0')) 'Recover' ([datetime]'2026-02-10T10:00:00Z') $guid ('b2' * 32) ('a1' * 32)
        New-Batch313d $root ('cc000003'.PadRight(32, '0')) 'Convert' ([datetime]'2026-03-10T10:00:00Z') $guid ('c3' * 32)
        $found = Find-Batch313d $root $guid
        $found.ShortId | Should -BeExactly 'cc000003'
        $found.BatchId | Should -BeExactly ('cc000003'.PadRight(32, '0'))
    }
    It 'takes the newest by time, whatever the alphabetical order of the folders' {
        $root = $global:PraGate.R313d; $guid = $global:PraGate.G313d
        New-Batch313d $root ('aa000001'.PadRight(32, '0')) 'Convert' ([datetime]'2026-04-10T10:00:00Z') $guid ('a1' * 32)
        New-Batch313d $root ('ff000002'.PadRight(32, '0')) 'Convert' ([datetime]'2026-01-10T10:00:00Z') $guid ('f2' * 32)
        New-Batch313d $root ('cc000003'.PadRight(32, '0')) 'Convert' ([datetime]'2026-02-10T10:00:00Z') $guid ('c3' * 32)
        (Find-Batch313d $root $guid).ShortId | Should -BeExactly 'aa000001'
    }
    It 'ignores a batch of another Environment, even the newest' {
        $root = $global:PraGate.R313d; $guid = $global:PraGate.G313d
        New-Batch313d $root ('cc000001'.PadRight(32, '0')) 'Convert' ([datetime]'2026-03-10T10:00:00Z') $guid ('c3' * 32)
        New-Batch313d $root ('dd000002'.PadRight(32, '0')) 'Convert' ([datetime]'2026-04-10T10:00:00Z') $guid ('d4' * 32) -Environment 'OTHER_ENVIRONMENT'
        (Find-Batch313d $root $guid).ShortId | Should -BeExactly 'cc000001'
        Remove-Item -LiteralPath (Join-Path $root ('Batch-' + 'cc000001'.PadRight(32, '0'))) -Recurse -Force
        Find-Batch313d $root $guid | Should -BeNullOrEmpty -Because 'the only batch left belongs to another Environment'
    }
    It 'gives nothing when the only batch of the object was rolled back, whether the proof of the rollback is a Batch folder or a Finalize folder' {
        $root = $global:PraGate.R313d; $guid = $global:PraGate.G313d
        New-Batch313d $root ('cc000001'.PadRight(32, '0')) 'Convert' ([datetime]'2026-03-10T10:00:00Z') $guid ('c3' * 32)
        (Find-Batch313d $root $guid).ShortId | Should -BeExactly 'cc000001'
        New-Batch313d $root ('ee000002'.PadRight(32, '0')) 'Recover' ([datetime]'2026-03-11T10:00:00Z') $guid ('e5' * 32) ('c3' * 32) -Prefix 'Finalize'
        Find-Batch313d $root $guid | Should -BeNullOrEmpty
    }
    It 'does not care about the case of the Environment, of the folder prefix, of the batch id or of the hashes' -Tag 'Release313h' {
        $root = $global:PraGate.R313d; $guid = $global:PraGate.G313d
        New-Batch313d $root ('CC000001'.PadRight(32, '0')) 'Convert' ([datetime]'2026-03-10T10:00:00Z') $guid ('C3' * 32) -Environment 'synthetic_gate' -Prefix 'BATCH'
        $found = Find-Batch313d $root $guid
        $found.ShortId | Should -BeExactly 'CC000001'
        New-Batch313d $root ('ee000002'.PadRight(32, '0')) 'Recover' ([datetime]'2026-03-11T10:00:00Z') $guid ('e5' * 32) ('c3' * 32) -Environment 'Synthetic_Gate' -Prefix 'finalize'
        Find-Batch313d $root $guid | Should -BeNullOrEmpty -Because 'the rollback names the batch by a hash written in the other case'
    }
    It 'a batch of another Environment is still ignored when the case is the only thing that is the same' -Tag 'Release313h' {
        $root = $global:PraGate.R313d; $guid = $global:PraGate.G313d
        New-Batch313d $root ('dd000002'.PadRight(32, '0')) 'Convert' ([datetime]'2026-04-10T10:00:00Z') $guid ('d4' * 32) -Environment 'SYNTHETIC_GATE_2'
        Find-Batch313d $root $guid | Should -BeNullOrEmpty
    }
    It 'a rollback of another object does not hide the batch' {
        $root = $global:PraGate.R313d; $guid = $global:PraGate.G313d
        New-Batch313d $root ('cc000001'.PadRight(32, '0')) 'Convert' ([datetime]'2026-03-10T10:00:00Z') $guid ('c3' * 32)
        New-Batch313d $root ('bb000002'.PadRight(32, '0')) 'Recover' ([datetime]'2026-03-11T10:00:00Z') '9d1c0c2e-7a33-4f5e-8f0a-1f2e3d4c5b6a' ('b2' * 32) ('c3' * 32)
        (Find-Batch313d $root $guid).ShortId | Should -BeExactly 'cc000001'
    }
}
Describe 'Release 3.1.3 - rerun commands and error counts after a failure (real main, synthetic)' -Tag 'Release313d' {
    It 'a cloud Apply that cannot reach Microsoft 365 proposes the batch as typed: the short ID when the ID was typed' {
        $runtime = New-GateRuntime -Name 'apply-network-313d' -Case 'CloudNetworkFailure'
        $ad = Invoke-GateProcess $runtime @{Action='Convert';Phase='AD';Mode='Apply';Force=$true;ConfigPath=$runtime.ConfigPath} -TimeoutSeconds 120
        $ad.ExitCode | Should -Be 2 -Because ($ad.Output + $ad.Error)
        $short = [string]$ad.MainResult.BatchId
        $run = Invoke-GateProcess $runtime @{Action='Convert';Phase='Cloud';Mode='Apply';Force=$true;ConfigPath=$runtime.ConfigPath;Batch=$short} -TimeoutSeconds 120
        $run.ExitCode | Should -Be 1 -Because ($run.Output + $run.Error)
        $steps = @($run.MainResult.NextSteps)
        $at = [array]::IndexOf($steps, 'Microsoft 365 did not answer from this machine. What this run already did is kept: run the same command again when the connection works:')
        $at | Should -BeGreaterOrEqual 0 -Because ($steps -join "`n")
        $steps[$at + 1] | Should -Match ('^\.\\Invoke-PraRemoteMailbox\.ps1 -Action Convert -Phase Cloud -Mode Apply -Batch ' + $short + ' -ConfigPath ')
    }
    It 'the Error block and the Result line count the same errors, and the stop line of a sign-in failure names the service, not the last object' {
        $runtime = New-GateRuntime -Name 'count-313d' -Case 'CloudConnectFailure'
        $ad = Invoke-GateProcess $runtime @{Action='Convert';Phase='AD';Mode='Apply';Force=$true;ConfigPath=$runtime.ConfigPath} -TimeoutSeconds 120
        $run = Invoke-GateProcess $runtime @{Action='Convert';Phase='Cloud';Mode='Preview';ConfigPath=$runtime.ConfigPath;Batch=[string]$ad.MainResult.BatchId} -TimeoutSeconds 120
        $run.ExitCode | Should -Be 1 -Because ($run.Output + $run.Error)
        $run.Output | Should -Match '0 ready . 0 planned . 2 error\(s\) . 0 skipped'
        $run.Output | Should -Match '2 error\(s\) in total, see the log and the report'
        $run.Output | Should -Not -Match '3 error\(s\) in total'
        $run.Output | Should -Match "Stopped at step 'Cloud' \(operation Connect-MgGraph, service Microsoft Graph\): Microsoft 365 did not answer\. Nothing was changed\. Run the Preview again\."
        $run.Output | Should -Not -Match 'operation Connect-MgGraph, object'
        # An object-level failure still names its object.
        $object = New-GateRuntime -Name 'count-object-313d' -Case 'CloudNetworkFailure'
        $adObject = Invoke-GateProcess $object @{Action='Convert';Phase='AD';Mode='Apply';Force=$true;ConfigPath=$object.ConfigPath} -TimeoutSeconds 120
        $runObject = Invoke-GateProcess $object @{Action='Convert';Phase='Cloud';Mode='Preview';ConfigPath=$object.ConfigPath;Batch=[string]$adObject.MainResult.BatchId} -TimeoutSeconds 120
        $runObject.Output | Should -Match 'operation CloudCheck, object user[0-9]@gate\.invalid'
        $runObject.Output | Should -Match '0 ready . 0 planned . 2 error\(s\) . 0 skipped'
        $runObject.Output | Should -Match '2 error\(s\) in total'
    }
    It 'a Check that cannot reach the domain controller proposes the Check again with its own options, without this machine''s -ConfigPath for the other machine' {
        $runtime = New-GateRuntime -Name 'check-dc-down-313d' -Case 'AdServerDown'
        $run = Invoke-GateProcess $runtime @{Action='Check';Identity='user1';Once=$true;Expect='Deprovisioned';ConfigPath=$runtime.ConfigPath} -TimeoutSeconds 120
        $run.ExitCode | Should -Be 1 -Because ($run.Output + $run.Error)
        $steps = @($run.MainResult.NextSteps)
        $steps[0] | Should -BeExactly 'Nothing was changed. Run the Check again from a machine that reaches the domain controller:'
        $steps[1] | Should -BeExactly ".\Invoke-PraRemoteMailbox.ps1 -Action Check -Identity 'user1' -Expect Deprovisioned -Once"
        $steps[3] | Should -Match "^\.\\Invoke-PraRemoteMailbox\.ps1 -Action Check -Identity '<UPN>' -Expect Deprovisioned -Once -ConfigPath '"
    }
    It 'an AD write refused for a run with -CsvPath says to copy the file to the domain controller and writes its name only' {
        $runtime = New-GateRuntime -Name 'csv-denied-313d' -Case 'AccessDenied'
        $csv = Join-Path $runtime.Root 'targets.csv'
        [IO.File]::WriteAllText($csv, "Identity`r`nuser1`r`nuser2`r`n", (New-Object Text.UTF8Encoding($true)))
        $run = Invoke-GateProcess $runtime @{Action='Convert';Phase='AD';Mode='Apply';Force=$true;CsvPath=$csv;ConfigPath=$runtime.ConfigPath} -TimeoutSeconds 120
        $run.ExitCode | Should -Be 1 -Because ($run.Output + $run.Error)
        $next = @($run.MainResult.NextSteps)
        $next[1] | Should -BeExactly 'Copy the file targets.csv (the -CsvPath of this run) to the domain controller dc01.gate.invalid, to the folder where you run the command.'
        $next[1] | Should -Not -Match 'that server'
        $next[2] | Should -Match '^Run the step again on the domain controller '
        $next[3] | Should -BeExactly ".\Invoke-PraRemoteMailbox.ps1 -Action Convert -Phase AD -CsvPath 'targets.csv'"

    }
    It 'a Phase Both Apply that loses Microsoft 365 after the AD part says that AD is done and continues the batch by its ID' {
        $runtime = New-GateRuntime -Name 'both-network-313d' -Case 'CloudNetworkFailure'
        $run = Invoke-GateProcess $runtime @{Action='Convert';Phase='Both';Mode='Apply';Force=$true;ConfigPath=$runtime.ConfigPath} -TimeoutSeconds 120
        $run.ExitCode | Should -Be 1 -Because ($run.Output + $run.Error)
        @(Get-GateWrites $runtime).Count | Should -BeGreaterThan 0 -Because 'the AD part was written'
        $run.Output | Should -Match ([regex]::Escape('Microsoft 365 did not answer: the cloud part of this batch is not complete; Active Directory is done, see the next steps.'))
        $steps = @($run.MainResult.NextSteps | Where-Object { $_ -notmatch '^Global report' })
        $steps[0] | Should -BeExactly 'Microsoft 365 did not answer from this machine. What this run already did is kept (Active Directory is changed and verified): run the Exchange Online part when the connection works:'
        $steps[1] | Should -Match '^\.\\Invoke-PraRemoteMailbox\.ps1 -Action Convert -Phase Cloud -Mode Apply -Batch [0-9a-f]{8} -ConfigPath '
        $steps[1] | Should -Not -Match '-Phase Both'
        $run.Output | Should -Match 'run the Exchange Online part when the connection works'
    }
    It 'a Phase Both Apply with another cloud failure after the AD part has the same continuation, and a failure before the AD part keeps its own guidance' {
        $runtime = New-GateRuntime -Name 'both-other-313d' -Case 'CloudOtherFailure'
        $run = Invoke-GateProcess $runtime @{Action='Convert';Phase='Both';Mode='Apply';Force=$true;ConfigPath=$runtime.ConfigPath} -TimeoutSeconds 120
        $run.ExitCode | Should -Be 1 -Because ($run.Output + $run.Error)
        @(Get-GateWrites $runtime).Count | Should -BeGreaterThan 0 -Because 'the AD part was written'
        $run.Output | Should -Match ([regex]::Escape('the cloud part of this batch is not complete; Active Directory is done, see the next steps.'))
        $run.Output | Should -Not -Match 'run it again with the same command'
        $steps = @($run.MainResult.NextSteps | Where-Object { $_ -notmatch '^Global report' })
        $steps[0] | Should -BeExactly 'What this run already did is kept (Active Directory is changed and verified). Fix the problem named above, then run the Exchange Online part:'
        $steps[1] | Should -Match '^\.\\Invoke-PraRemoteMailbox\.ps1 -Action Convert -Phase Cloud -Mode Apply -Batch [0-9a-f]{8} -ConfigPath '
        # The cloud pre-check that refuses before any AD write is another case: nothing was written and the existing text stays.
        $before = New-GateRuntime -Name 'both-before-313d' -Case 'CloudPreflightFailure'
        $refused = Invoke-GateProcess $before @{Action='Convert';Phase='Both';Mode='Apply';Force=$true;ConfigPath=$before.ConfigPath} -TimeoutSeconds 120
        $refused.ExitCode | Should -Be 1 -Because ($refused.Output + $refused.Error)
        @(Get-GateWrites $before).Count | Should -Be 0
        $refused.Output | Should -Not -Match 'Active Directory is done'
    }
    It 'a Phase Both Recover that loses the cloud part after the AD part continues with the Recover batch by its ID' {
        $runtime = New-GateRuntime -Name 'both-recover-313d' -Case 'CloudOtherFailure'
        $ad = Invoke-GateProcess $runtime @{Action='Convert';Phase='AD';Mode='Apply';Force=$true;ConfigPath=$runtime.ConfigPath} -TimeoutSeconds 120
        $ad.ExitCode | Should -Be 2 -Because ($ad.Output + $ad.Error)
        $run = Invoke-GateProcess $runtime @{Action='Recover';Phase='Both';Mode='Apply';Force=$true;ConfigPath=$runtime.ConfigPath;Batch=[string]$ad.MainResult.BatchId} -TimeoutSeconds 120
        $run.ExitCode | Should -Be 1 -Because ($run.Output + $run.Error)
        $run.Output | Should -Match ([regex]::Escape('the cloud part of this batch is not complete; Active Directory is done, see the next steps.'))
        $steps = @($run.MainResult.NextSteps | Where-Object { $_ -notmatch '^Global report' })
        $steps[0] | Should -BeExactly 'What this run already did is kept (Active Directory is changed and verified). Fix the problem named above, then run the Exchange Online part:'
        $steps[1] | Should -Match '^\.\\Invoke-PraRemoteMailbox\.ps1 -Action Recover -Phase Cloud -Mode Apply -Batch [0-9a-f]{8} -ConfigPath '
        $steps[1] | Should -Not -Match ('-Batch ' + [string]$ad.MainResult.BatchId) -Because 'the Recover batch is continued, not the Convert batch'
    }
}
Describe 'Release 3.1.3 - every stop ends with a next step, and the Error block shows the errors (real main, synthetic)' -Tag 'Release313e' {
    BeforeAll {
        $global:PraGate.Sync313e = 'If the Entra Connect sync has not run since the Active Directory changes, run it first (Start-ADSyncSyncCycle -PolicyType Delta on the Entra Connect server, or wait for the next automatic cycle, about 30 minutes).'
        function global:Assert-Next313e {
            param($Run, [string]$First, [string]$CommandPattern)
            $steps = @($Run.MainResult.NextSteps | Where-Object { $_ -notmatch '^Global report' })
            $steps.Count | Should -BeGreaterOrEqual 2 -Because ($Run.Output + $Run.Error)
            $steps[0] | Should -BeExactly $First
            $steps[1] | Should -Match $CommandPattern
            $Run.Output | Should -Match ([regex]::Escape($First)) -Because 'the Next block is printed'
        }
    }
    AfterAll {
        Remove-Item -LiteralPath 'Function:\Assert-Next313e' -ErrorAction SilentlyContinue
        Remove-Variable Sync313e -Scope Global -ErrorAction SilentlyContinue
    }
    It 'a Convert cloud Apply that waits for the mailboxes and times out says to run the sync, and to run the same command again; the stop names the number of objects, not one object' {
        $runtime = New-GateRuntime -Name 'timeout-convert-313e' -Case 'CloudWaitTimeout'
        $ad = Invoke-GateProcess $runtime @{Action='Convert';Phase='AD';Mode='Apply';Force=$true;ConfigPath=$runtime.ConfigPath} -TimeoutSeconds 120
        $ad.ExitCode | Should -Be 2 -Because ($ad.Output + $ad.Error)
        $short = [string]$ad.MainResult.BatchId
        $run = Invoke-GateProcess $runtime @{Action='Convert';Phase='Cloud';Mode='Apply';Force=$true;ConfigPath=$runtime.ConfigPath;Batch=$short} -TimeoutSeconds 120
        $run.ExitCode | Should -Be 1 -Because ($run.Output + $run.Error)
        $run.Output | Should -Match ([regex]::Escape("Stopped at step 'Cloud' (operation CloudCheck, 2 object(s)): Exchange Online check failed: the cloud part of this batch is not complete; run it again with the same command."))
        $run.Output | Should -Not -Match 'operation CloudCheck, object'
        $steps = @($run.MainResult.NextSteps | Where-Object { $_ -notmatch '^Global report' })
        $steps.Count | Should -Be 3 -Because ($steps -join "`n")
        $steps[0] | Should -BeExactly $global:PraGate.Sync313e
        $steps[1] | Should -BeExactly 'What this run already did is kept: run the same command again:'
        $steps[2] | Should -Match ('^\.\\Invoke-PraRemoteMailbox\.ps1 -Action Convert -Phase Cloud -Mode Apply -Batch ' + $short + ' -ConfigPath ')
        $run.Output | Should -Match ([regex]::Escape('What this run already did is kept: run the same command again:')) -Because 'the Next block is printed'
        # The Error block lists the errors of the objects first, the stop of the run last.
        $first = $run.Output.LastIndexOf('user1@gate.invalid: still not in the expected state'); $second = $run.Output.LastIndexOf('user2@gate.invalid: still not in the expected state'); $stop = $run.Output.LastIndexOf("Stopped at step 'Cloud'")
        $first | Should -BeGreaterThan 0; $second | Should -BeGreaterThan $first; $stop | Should -BeGreaterThan $second
    }
    It 'a Recover cloud Apply that times out says that the cloud part is not complete, to run the sync and to run the same command again' {
        $runtime = New-GateRuntime -Name 'timeout-recover-313e' -Case 'CloudWaitTimeout'
        $ad = Invoke-GateProcess $runtime @{Action='Convert';Phase='AD';Mode='Apply';Force=$true;ConfigPath=$runtime.ConfigPath} -TimeoutSeconds 120
        $ad.ExitCode | Should -Be 2 -Because ($ad.Output + $ad.Error)
        $recover = Invoke-GateProcess $runtime @{Action='Recover';Phase='AD';Mode='Apply';Force=$true;ConfigPath=$runtime.ConfigPath;Batch=[string]$ad.MainResult.BatchId} -TimeoutSeconds 120
        $recover.ExitCode | Should -Be 2 -Because ($recover.Output + $recover.Error)
        $short = [string]$recover.MainResult.BatchId
        $run = Invoke-GateProcess $runtime @{Action='Recover';Phase='Cloud';Mode='Apply';Force=$true;ConfigPath=$runtime.ConfigPath;Batch=$short} -TimeoutSeconds 120
        $run.ExitCode | Should -Be 1 -Because ($run.Output + $run.Error)
        $run.Output | Should -Match ([regex]::Escape("Stopped at step 'Cloud' (operation CloudCheck, 2 object(s)): Exchange Online check failed: the cloud part of this batch is not complete, so the final restore and clean-up are not done; run it again with the same command."))
        $run.Output | Should -Not -Match 'no restore or clean-up is done'
        $steps = @($run.MainResult.NextSteps | Where-Object { $_ -notmatch '^Global report' })
        $steps[0] | Should -BeExactly $global:PraGate.Sync313e
        $steps[1] | Should -BeExactly 'What this run already did is kept: run the same command again:'
        $steps[2] | Should -Match ('^\.\\Invoke-PraRemoteMailbox\.ps1 -Action Recover -Phase Cloud -Mode Apply -Batch ' + $short + ' -ConfigPath ')
    }
    It 'the Error block shows the object errors first (five, then how many more) and the stop of the run last' {
        $runtime = New-GateRuntime -Name 'many-errors-313e' -Shared13 -TrusteeCount 3 -Case 'CloudWaitTimeout'
        Set-GateConfigText $runtime { param($t) $t.Replace('Report=@{Enabled=$true;', 'Report=@{Enabled=$false;') }
        $ad = Invoke-GateProcess $runtime @{Action='Convert';Phase='AD';Mode='Apply';Force=$true;ConfigPath=$runtime.ConfigPath} -TimeoutSeconds 180
        $ad.ExitCode | Should -Be 2 -Because ($ad.Output + $ad.Error)
        $run = Invoke-GateProcess $runtime @{Action='Convert';Phase='Cloud';Mode='Apply';Force=$true;ConfigPath=$runtime.ConfigPath;Batch=[string]$ad.MainResult.BatchId} -TimeoutSeconds 180
        $run.ExitCode | Should -Be 1 -Because ($run.Output + $run.Error)
        $run.Output | Should -Match '13 error\(s\) in total, see the log and the report'
        $run.Output | Should -Match ([regex]::Escape("... and 8 more, see the report"))
        $more = $run.Output.LastIndexOf('... and 8 more, see the report'); $stop = $run.Output.LastIndexOf("Stopped at step 'Cloud' (operation CloudCheck, 13 object(s))")
        $more | Should -BeGreaterThan 0; $stop | Should -BeGreaterThan $more
        $run.Output.Substring($more) | Should -Not -Match 'user[0-9]+@gate\.invalid: still not in the expected state' -Because 'the lines of the objects all come before the count of the others'
    }
    It 'a Convert cloud Preview that fails for another reason than the network proposes the Preview again' {
        $runtime = New-GateRuntime -Name 'preview-other-313e' -Case 'CloudOtherFailure'
        $ad = Invoke-GateProcess $runtime @{Action='Convert';Phase='AD';Mode='Apply';Force=$true;ConfigPath=$runtime.ConfigPath} -TimeoutSeconds 120
        $short = [string]$ad.MainResult.BatchId
        $run = Invoke-GateProcess $runtime @{Action='Convert';Phase='Cloud';Mode='Preview';ConfigPath=$runtime.ConfigPath;Batch=$short} -TimeoutSeconds 120
        $run.ExitCode | Should -Be 1 -Because ($run.Output + $run.Error)
        Assert-Next313e $run 'Nothing was changed. Fix the problem named above, then run the Preview again:' ('^\.\\Invoke-PraRemoteMailbox\.ps1 -Action Convert -Phase Cloud -Batch ' + $short + ' -ConfigPath ')
    }
    It 'a Check that finds objects not in the expected state proposes the sync, then the Check again' {
        $runtime = New-GateRuntime -Name 'check-not-expected-313e' -Case 'CheckNotExpected'
        $run = Invoke-GateProcess $runtime @{Action='Check';Identity='user1';ConfigPath=$runtime.ConfigPath} -TimeoutSeconds 120
        $run.ExitCode | Should -Be 1 -Because ($run.Output + $run.Error)
        $steps = @($run.MainResult.NextSteps)
        $steps[0] | Should -BeExactly ($global:PraGate.Sync313e.TrimEnd('.') + ', then run the Check again:')
        $steps[1] | Should -Match "^\.\\Invoke-PraRemoteMailbox\.ps1 -Action Check -Identity 'user1' -ConfigPath "
        $run.Output | Should -Match 'then run the Check again:'
    }
    It 'a partial AD batch says which objects may be changed and proposes the Preview, never the Apply again' {
        $runtime = New-GateRuntime -Name 'partial-ad-313e' -Case 'SecondMutationFailure'
        $run = Invoke-GateProcess $runtime @{Action='Convert';Phase='AD';Mode='Apply';Force=$true;ConfigPath=$runtime.ConfigPath} -TimeoutSeconds 120
        $run.ExitCode | Should -Be 1 -Because ($run.Output + $run.Error)
        @(Get-GateWrites $runtime).Count | Should -BeGreaterThan 0
        $steps = @($run.MainResult.NextSteps)
        $steps[0] | Should -Match '^Active Directory was changed for [0-9]+ object\(s\) before the stop \(see the journal and the backup named above\)\. Do not run the Apply again before reading what is left: run the Preview of the same command:$'
        $steps[1] | Should -Match '^\.\\Invoke-PraRemoteMailbox\.ps1 -Action Convert -Phase AD -ConfigPath '
        $steps[1] | Should -Not -Match '-Mode Apply'
        $run.Output | Should -Match 'run the Preview of the same command'
    }
    It 'a stop before anything was written ends with the same command, as typed (usage, batch not found, cloud pre-check)' {
        $usage = New-GateRuntime -Name 'usage-313e'
        $run = Invoke-GateProcess $usage @{Action='Convert';Phase='Both';Mode='Preview';ConfigPath=$usage.ConfigPath;Batch='deadbeef'} -TimeoutSeconds 60
        $run.ExitCode | Should -Be 1 -Because ($run.Output + $run.Error)
        Assert-Next313e $run 'Fix the problem named above, then run the same command again:' '^\.\\Invoke-PraRemoteMailbox\.ps1 -Action Convert -Phase Both -Batch deadbeef -ConfigPath '
        $missing = New-GateRuntime -Name 'missing-313e'
        $run = Invoke-GateProcess $missing @{Action='Recover';Phase='AD';Mode='Apply';Force=$true;ConfigPath=$missing.ConfigPath;Batch='deadbeef'} -TimeoutSeconds 60
        $run.ExitCode | Should -Be 1 -Because ($run.Output + $run.Error)
        Assert-Next313e $run 'Fix the problem named above, then run the same command again:' '^\.\\Invoke-PraRemoteMailbox\.ps1 -Action Recover -Phase AD -Mode Apply -Batch deadbeef -ConfigPath '
        $before = New-GateRuntime -Name 'preflight-313e' -Case 'CloudPreflightFailure'
        $run = Invoke-GateProcess $before @{Action='Convert';Phase='Both';Mode='Apply';Force=$true;ConfigPath=$before.ConfigPath} -TimeoutSeconds 120
        $run.ExitCode | Should -Be 1 -Because ($run.Output + $run.Error)
        @(Get-GateWrites $before).Count | Should -Be 0
        Assert-Next313e $run 'Fix the problem named above, then run the same command again:' '^\.\\Invoke-PraRemoteMailbox\.ps1 -Action Convert -Phase Both -Mode Apply -ConfigPath '
    }
    It 'the Finalize, cloud-phase and Check stops end with a next step too' {
        $finalize = New-GateRuntime -Name 'finalize-313e'
        $run = Invoke-GateProcess $finalize @{Action='Finalize';Mode='Apply';Force=$true;ConfigPath=$finalize.ConfigPath;Batch='deadbeef'} -TimeoutSeconds 60
        $run.ExitCode | Should -Be 1 -Because ($run.Output + $run.Error)
        Assert-Next313e $run 'Fix the problem named above, then run the same command again:' '^\.\\Invoke-PraRemoteMailbox\.ps1 -Action Finalize -Mode Apply -Batch deadbeef -ConfigPath '
        $cloud = New-GateRuntime -Name 'cloud-missing-313e'
        $run = Invoke-GateProcess $cloud @{Action='Convert';Phase='Cloud';Mode='Apply';Force=$true;ConfigPath=$cloud.ConfigPath;Batch='deadbeef'} -TimeoutSeconds 60
        $run.ExitCode | Should -Be 1 -Because ($run.Output + $run.Error)
        Assert-Next313e $run 'Fix the problem named above, then run the same command again:' '^\.\\Invoke-PraRemoteMailbox\.ps1 -Action Convert -Phase Cloud -Mode Apply -Batch deadbeef -ConfigPath '
        $check = New-GateRuntime -Name 'check-usage-313e'
        $run = Invoke-GateProcess $check @{Action='Check';ConfigPath=$check.ConfigPath} -TimeoutSeconds 60
        $run.ExitCode | Should -Be 1 -Because ($run.Output + $run.Error)
        Assert-Next313e $run 'Fix the problem named above, then run the same command again:' '^\.\\Invoke-PraRemoteMailbox\.ps1 -Action Check -ConfigPath '
    }
    It 'a failed run whose own next steps are hidden still ends with the fallback, and one that set its own keeps them' {
        $ctx = @{ Root = $global:PraGate.Package; Version = '3.1.3'; RunId = ((Get-Date -Format 'yyyyMMdd_HHmmss') + '-' + [guid]::NewGuid().ToString('N')); StartTime = Get-Date; Action = 'Convert'; Mode = 'Apply'; Phase = 'AD'
            CurrentPhase = 'Start'; CurrentOperation = ''; CurrentIdentity = ''; StepIndex = 0; Warnings = 0; Issues = (New-Object 'Collections.Generic.List[object]'); Rows = (New-Object 'Collections.Generic.List[object]')
            Server = ''; Config = @{ Environment = 'GATE' }; AllowMutation = $true; ReportFolder = (Join-Path $global:PraGate.Root 'reports-313e'); NoReport = $true; BatchId = 'abcd1234'; LogFile = ''; TranscriptStarted = $false
            NextSteps = @('Copy these two files to the cloud server.'); ExitCode = 1; CloudConnectFailed = $false; ResultStatus = ''; FallbackNext = @('Fix the problem named above, then run the same command again:', '.\Invoke-PraRemoteMailbox.ps1 -Action Convert -Phase AD -Mode Apply') }
        $ctx.Issues.Add([pscustomobject]@{ Timestamp = 't'; Phase = 'p'; Operation = 'Cloud sign-out'; Identity = ''; Source = 'Cloud'; Message = 'Cloud sign-out: refused' })
        $hidden = Complete-PraRun -Context $ctx
        $hidden.ExitCode | Should -Be 1
        $hidden.NextSteps[0] | Should -BeExactly 'Fix the problem named above, then run the same command again:'
        $own = @{} + $ctx; $own.Issues = (New-Object 'Collections.Generic.List[object]'); $own.NextOnFailure = $true; $own.NextSteps = @('Run the cloud part:', '.\Invoke-PraRemoteMailbox.ps1 -Action Convert -Phase Cloud -Mode Apply -Batch abcd1234'); $own.ExitCode = 1; $own.RunId = ((Get-Date -Format 'yyyyMMdd_HHmmss') + '-' + [guid]::NewGuid().ToString('N'))
        $own.Issues.Add([pscustomobject]@{ Timestamp = 't'; Phase = 'p'; Operation = 'x'; Identity = ''; Source = 'Execution'; Message = 'Stopped at step ''Cloud'' (operation x): failed' })
        $kept = Complete-PraRun -Context $own
        $kept.NextSteps[0] | Should -BeExactly 'Run the cloud part:'
    }
}
Describe 'Release 3.1.3 - the members of an AD group for one run (-Group): parameter, resolution, nested members, skipped members (synthetic AD fixture)' -Tag 'Release313g' {
    BeforeAll {
        $global:PraGate.GroupFixture313g = @'
function Get-ADGroup {
    [CmdletBinding()]
    param([object]$Identity,[string]$LDAPFilter,[string[]]$Properties,[string]$Server)
    Assert-GateServer $Server
    Write-GateEvent 'Get-ADGroup' $Identity $Server @{LDAPFilter=$LDAPFilter}
    if ($global:PraGateAd.Case -eq 'GroupFailure') { throw 'SYNTHETIC: group preflight refused.' }
    if (-not $LDAPFilter) { Copy-GateUser $global:PraGateAd.Group; return }
    foreach ($group in @($global:PraGateAd.Groups)) {
        $hit = $false
        if ($LDAPFilter -match 'distinguishedName=([^)]*)\)\)$') { $hit = ($group.DistinguishedName -ieq $Matches[1]) }
        elseif ($LDAPFilter -match 'sAMAccountName=([^)]*)\)\(cn=([^)]*)\)') { $hit = ($group.SamAccountName -ieq $Matches[1]) -or ($group.Name -ieq $Matches[2]) }
        if ($hit) { Copy-GateUser $group }
    }
}
function Expand-GateGroup {
    param($Group,[switch]$Recursive,$Seen)
    foreach ($dn in @($Group.member)) {
        $sub = @($global:PraGateAd.Groups | Where-Object { $_.DistinguishedName -ieq $dn })
        if ($sub.Count) {
            if ($Recursive) { Expand-GateGroup $sub[0] -Recursive -Seen $Seen } else { [pscustomobject]@{objectClass='group';DistinguishedName=$sub[0].DistinguishedName;SamAccountName=$sub[0].SamAccountName;Name=$sub[0].Name} }
            continue
        }
        if ($Seen.ContainsKey($dn)) { continue }
        $Seen[$dn] = $true
        $object = @(@($global:PraGateAd.Users) + @($global:PraGateAd.Others) | Where-Object { $_.DistinguishedName -ieq $dn })[0]
        [pscustomobject]@{objectClass=$object.objectClass;DistinguishedName=$object.DistinguishedName;SamAccountName=$object.SamAccountName;Name=$object.Name}
    }
}
function Get-ADObject {
    [CmdletBinding()]
    param([object]$Identity,[string]$Filter,[string]$LDAPFilter,[string[]]$Properties,[string]$Server,[string]$SearchBase)
    Assert-GateServer $Server
    Write-GateEvent 'Get-ADObject' $Identity $Server @{Filter=$Filter;LDAPFilter=$LDAPFilter;Properties=$Properties}
    if ($LDAPFilter -match '^\(&\(memberOf:1\.2\.840\.113556\.1\.4\.1941:=(.*)\)\(!\(objectClass=group\)\)\)$') {
        $group = @($global:PraGateAd.Groups | Where-Object { [string]$_.DistinguishedName -ieq $Matches[1] })[0]
        Expand-GateGroup $group -Recursive -Seen @{}
        return
    }
    [pscustomobject]@{ DistinguishedName=[string]$Identity; objectClass='organizationalUnit' }
}
Write-GateEvent 'Import-SyntheticAD'
'@
        function global:New-GroupAd313g {
            <# A runtime whose synthetic AD knows groups and their members. #>
            param([string]$Name, [string]$Case = 'Normal')
            $runtime = New-GateRuntime -Name $Name -Case $Case
            $users = @(1..5 | ForEach-Object { New-GateUser $_ })
            $users[2].msExchRecipientTypeDetails = [long]4
            $users[3].homeMDB = $null
            $users[4].msExchRecipientTypeDetails = [long]4
            $dn = { param($cn, $ou) 'CN=' + $cn + ',OU=' + $ou + ',DC=gate,DC=invalid' }
            $group = { param($index, $cn, $ou, $members) [pscustomobject]@{ ObjectGUID = [guid]('30000000-0000-0000-0000-{0:000000000000}' -f $index); DistinguishedName = (& $dn $cn $ou); Name = $cn; SamAccountName = $cn; objectClass = 'group'; member = [string[]]$members } }
            $others = @([pscustomobject]@{ objectClass = 'computer'; DistinguishedName = (& $dn 'PC01' 'Tests'); SamAccountName = 'PC01$'; Name = 'PC01' },
                [pscustomobject]@{ objectClass = 'contact'; DistinguishedName = (& $dn 'Bob Contact' 'Tests'); SamAccountName = ''; Name = 'Bob Contact' })
            $groups = @(
                (& $group 1 'PRA-Wave1' 'Groups' @($users[0].DistinguishedName, $users[1].DistinguishedName, (& $dn 'PRA-Nested' 'Groups'), $others[0].DistinguishedName, $others[1].DistinguishedName, $users[4].DistinguishedName)),
                (& $group 2 'PRA-Nested' 'Groups' @($users[2].DistinguishedName, $users[3].DistinguishedName, $users[0].DistinguishedName)),
                (& $group 3 'PRA-Empty' 'Groups' @()),
                (& $group 4 'PRA-Twin' 'GroupsA' @($users[0].DistinguishedName)),
                (& $group 5 'PRA-Twin' 'GroupsB' @($users[1].DistinguishedName)))
            $runtime.State.Users = $users; $runtime.State.Originals = [Management.Automation.PSSerializer]::Deserialize([Management.Automation.PSSerializer]::Serialize($users, 30))
            $runtime.State.Groups = $groups; $runtime.State.Others = $others
            [IO.File]::WriteAllText($runtime.StatePath, [Management.Automation.PSSerializer]::Serialize($runtime.State, 35))
            $modulePath = Join-Path $runtime.Modules 'ActiveDirectory\ActiveDirectory.psm1'
            $source = [IO.File]::ReadAllText($modulePath)
            $marker = "Write-GateEvent 'Import-SyntheticAD' '' '' `$PSCommandPath"
            if (-not $source.Contains($marker)) { throw 'Group fixture splice boundary missing.' }
            [IO.File]::WriteAllText($modulePath, $source.Replace($marker, $global:PraGate.GroupFixture313g.Replace("Write-GateEvent 'Import-SyntheticAD'", $marker)), (New-Object Text.UTF8Encoding($true)))
            return $runtime
        }
        function global:Use-GroupContext313g {
            <# The runtime loaded in this process (the way the ScopeOU tests do it), and a Preview context whose scope is a group. #>
            param($Runtime, [string]$Group, [bool]$IncludeShared = $false)
            $env:PRA_GATE_STATE = $Runtime.StatePath
            $env:PSModulePath = $Runtime.Modules + ';' + (Join-Path $PSHOME 'Modules')
            Remove-Module PRA.Directory -Force -ErrorAction SilentlyContinue
            Get-Module ActiveDirectory -All | Remove-Module -Force -ErrorAction SilentlyContinue
            Import-Module (Join-Path $Runtime.Modules 'ActiveDirectory\ActiveDirectory.psm1') -Force -Global -ErrorAction Stop
            Import-Module (Join-Path $global:PraGate.Package 'module\PRA.Directory.psm1') -Force -Global -ErrorAction Stop
            $context = New-GateContext $Runtime -Mode Preview
            $scope = $context.Config.Scope
            $scope.Mode = 'Group'; $scope.GroupDN = $Group; $scope.SearchBase = ''; $scope.CsvPath = ''
            $scope.IncludeShared = $IncludeShared; $scope.IncludeRoom = $false; $scope.IncludeEquip = $false
            $context
        }
        function global:Set-Runtime313i {
            <# Edits the state of a group runtime (members, mailbox types) and writes it back for the synthetic directory. #>
            param($Runtime, [scriptblock]$Edit)
            & $Edit $Runtime.State
            [IO.File]::WriteAllText($Runtime.StatePath, [Management.Automation.PSSerializer]::Serialize($Runtime.State, 35))
        }
        function global:New-ConvertedBatch313i {
            <# A Convert batch folder of the backup folder: the AD proof (State file) and the Convert backup, both naming the given objects. #>
            param([string]$Root, [string]$Id, [string[]]$Guids)
            $folder = Join-Path $Root ('Batch-' + $Id)
            $null = New-Item -ItemType Directory -Path $folder -Force
            $state = [ordered]@{ SchemaVersion = 2; Operation = 'Convert'; Kind = 'ADVerified'; Environment = 'SYNTHETIC_GATE'; BackupFile = 'Convert-x.json'; BackupHash = ('a1' * 32); SourceBackupHash = ''
                CreatedUtc = (Get-Date).ToUniversalTime().ToString('o'); Records = @($Guids | ForEach-Object { [ordered]@{ ObjectGuid = $_; Operation = 'Convert'; ADVerified = $true } }) }
            [IO.File]::WriteAllText((Join-Path $folder ('State-' + $Id + '.json')), ($state | ConvertTo-Json -Depth 5), (New-Object Text.UTF8Encoding($true)))
            $backup = [ordered]@{ SchemaVersion = 3; Operation = 'Convert'; BatchId = $Id; Environment = 'SYNTHETIC_GATE'; Records = @($Guids | ForEach-Object { [ordered]@{ ObjectGuid = $_ } }) }
            [IO.File]::WriteAllText((Join-Path $folder ('Convert-SYNTHETIC_GATE-' + $Id.Substring(0, 8) + '.json')), ($backup | ConvertTo-Json -Depth 5), (New-Object Text.UTF8Encoding($true)))
        }
        function global:Convert-Members313i {
            <# Makes the given users (by index) remote mailboxes already, and puts them in the given batches. #>
            param($Runtime, [int[]]$Index, [hashtable]$Batches)
            Set-Runtime313i $Runtime { param($State) foreach ($i in $Index) { $State.Users[$i].homeMDB = $null; $State.Users[$i].msExchRecipientTypeDetails = [long]2147483648 } }
            foreach ($id in $Batches.Keys) { New-ConvertedBatch313i $Runtime.State.BackupFolder $id @($Batches[$id] | ForEach-Object { [string]$Runtime.State.Users[$_].ObjectGUID }) }
        }
    }
    AfterAll {
        foreach ($name in @('New-GroupAd313g', 'Use-GroupContext313g', 'Set-Runtime313i', 'New-ConvertedBatch313i', 'Convert-Members313i')) { Remove-Item -LiteralPath ('Function:\' + $name) -ErrorAction SilentlyContinue }
        Remove-Variable GroupFixture313g -Scope Global -ErrorAction SilentlyContinue
    }
    It 'turns -Group into the group scope of this run, and refuses it with another source' {
        $override = Get-PraTargetOverride -Group '  CN=PRA-Wave1,OU=Groups,DC=contoso,DC=com '
        $override.Mode | Should -BeExactly 'Group'
        $override.GroupDN | Should -BeExactly 'CN=PRA-Wave1,OU=Groups,DC=contoso,DC=com'
        $override.SearchBase | Should -BeExactly ''
        $override.CsvPath | Should -BeExactly ''
        (Get-PraTargetOverride -Group 'PRA-Wave1').GroupDN | Should -BeExactly 'PRA-Wave1'
        { Get-PraTargetOverride -Group 'PRA-Wave1' -SearchBase 'OU=Selected,DC=contoso,DC=com' } | Should -Throw '*Choose one source*'
        { Get-PraTargetOverride -Group 'PRA-Wave1' -CsvPath 'targets.csv' } | Should -Throw '*Choose one source*'
        { Get-PraTargetOverride -Group 'PRA-Wave1' -Identity 'one@contoso.com' } | Should -Throw '*Identity cannot be combined*'
        { Get-PraTargetOverride -Group "bad`nvalue" } | Should -Throw '*control character*'
        { Get-PraTargetOverride -Group '   ' } | Should -Throw '*empty value*'
        (Get-PraTargetOverride).Count | Should -Be 0
    }
    It 'the override is a scope of the run only: the configuration file is not rewritten' {
        $runtime = New-GateRuntime -Name 'override-313g'
        $before = [IO.File]::ReadAllText($runtime.ConfigPath)
        $config = Import-PraConfiguration -Path $runtime.ConfigPath -Root $runtime.Package -ScopeOverride (Get-PraTargetOverride -Group 'PRA-Wave1') -DeferScopeCheck
        $config.Scope.Mode | Should -BeExactly 'Group'
        $config.Scope.GroupDN | Should -BeExactly 'PRA-Wave1'
        [IO.File]::ReadAllText($runtime.ConfigPath) | Should -BeExactly $before
    }
    It 'resolves a name (sAMAccountName or CN) and a distinguished name to the same one group' {
        $runtime = New-GroupAd313g -Name 'resolve-313g'
        $context = Use-GroupContext313g $runtime 'PRA-Wave1'
        $expected = 'CN=PRA-Wave1,OU=Groups,DC=gate,DC=invalid'
        foreach ($value in @('PRA-Wave1', $expected)) {
            $found = Resolve-PraGroup -Context $context -Name $value
            [string]$found.DistinguishedName | Should -BeExactly $expected
        }
        @(Get-GateEvents $runtime | Where-Object Operation -eq 'Get-ADGroup')[-1].Detail.LDAPFilter | Should -Match '^\(&\(objectCategory=group\)\(distinguishedName='
        @(Get-GateWrites $runtime).Count | Should -Be 0
    }
    It 'resolves a group typed in lower case or upper case, by name and by distinguished name, to the same one group' -Tag 'Release313h' {
        $runtime = New-GroupAd313g -Name 'resolve-case-313h'
        $context = Use-GroupContext313g $runtime 'PRA-Wave1'
        $expected = 'CN=PRA-Wave1,OU=Groups,DC=gate,DC=invalid'
        foreach ($value in @('pra-wave1', 'PRA-WAVE1', 'Pra-Wave1', $expected.ToLowerInvariant(), $expected.ToUpperInvariant(), ('  ' + $expected.ToLowerInvariant() + ' '))) {
            $found = Resolve-PraGroup -Context $context -Name $value
            [string]$found.DistinguishedName | Should -BeExactly $expected -Because $value
        }
        { Resolve-PraGroup -Context $context -Name 'pra-twin' } | Should -Throw "*2 groups are named 'pra-twin'*"
        [string](Resolve-PraGroup -Context $context -Name 'cn=pra-twin,ou=groupsb,dc=gate,dc=invalid').DistinguishedName | Should -BeExactly 'CN=PRA-Twin,OU=GroupsB,DC=gate,DC=invalid'
    }
    It 'takes the members of a group given in lower case, with the exclusion list typed in another case' -Tag 'Release313h' {
        $runtime = New-GroupAd313g -Name 'members-case-313h'
        $context = Use-GroupContext313g $runtime 'pra-wave1' -IncludeShared $true
        $context.Config.Scope.Mode = 'group'
        @(Get-PraTarget -Context $context | ForEach-Object SamAccountName | Sort-Object) -join ',' | Should -BeExactly 'user1,user2,user3,user5'
        $context.Config.Scope.ExcludeSamAccountNames = @('USER2', 'User5')
        @(Get-PraTarget -Context $context | ForEach-Object SamAccountName | Sort-Object) -join ',' | Should -BeExactly 'user1,user3'
        @($context.SkippedMembers) | Should -Contain 'user2 (excluded (a system mailbox, or listed in Scope.ExcludeSamAccountNames))'
        $context.ObjectsText | Should -BeExactly 'members of PRA-Wave1 (7, including nested groups)'
    }
    It 'a licence group typed in lower case is found, and its members are matched whatever the case of their distinguished name' -Tag 'Release313h' {
        $runtime = New-GateRuntime -Name 'licence-case-313h' -Preexisting
        $runtime.State.Group.member = @($runtime.State.Group.member | ForEach-Object { ([string]$_).ToLowerInvariant() })
        [IO.File]::WriteAllText($runtime.StatePath, [Management.Automation.PSSerializer]::Serialize($runtime.State, 35))
        $context = Use-GroupContext313g $runtime 'x'
        $context.Config.Licensing.GroupDN = 'cn=license,ou=tests,dc=gate,dc=invalid'
        $plan = New-PraPlan $context 'USER1' 'Convert'
        $plan.Record.Licensing.WasMember | Should -BeTrue
        $plan.Record.Licensing.GroupDN | Should -BeExactly 'CN=License,OU=Tests,DC=gate,DC=invalid'
        $plan.Record.SamAccountName | Should -BeExactly 'user1'
    }
    It 'a run typed in lower case (-Action, -Phase, -Mode, -Group by name and by distinguished name) selects the members and keeps the official spelling in the next command' -Tag 'Release313h' {
        $runtime = New-GroupAd313g -Name 'main-case-313h'
        foreach ($group in @('pra-wave1', 'cn=pra-wave1,ou=groups,dc=gate,dc=invalid')) {
            $run = Invoke-GateProcess $runtime @{Action='convert';Phase='ad';Mode='preview';Group=$group;ConfigPath=$runtime.ConfigPath} -TimeoutSeconds 120
            $run.ExitCode | Should -Be 0 -Because ($run.Output + $run.Error)
            $run.Output | Should -Match ([regex]::Escape('Group PRA-Wave1: 7 member(s), including nested groups'))
            $run.Output | Should -Match ([regex]::Escape('PC01$: not converted, a computer, not a mailbox'))
            $steps = @($run.MainResult.NextSteps)
            $steps[0] | Should -Match ('^\.\\Invoke-PraRemoteMailbox\.ps1 -Action Convert -Phase AD -Mode Apply -Group ' + [regex]::Escape("'" + $group + "'"))
            @(Get-GateWrites $runtime).Count | Should -Be 0
        }
    }
    It 'says plainly that a group is not found, or that several groups have the name' {
        $runtime = New-GroupAd313g -Name 'resolve-errors-313g'
        $context = Use-GroupContext313g $runtime 'PRA-Wave1'
        { Resolve-PraGroup -Context $context -Name 'PRA-Nope' } | Should -Throw "*The group 'PRA-Nope' was not found in Active Directory*Give its name (sAMAccountName or CN) or its distinguished name.*"
        { Resolve-PraGroup -Context $context -Name 'CN=PRA-Nope,OU=Groups,DC=gate,DC=invalid' } | Should -Throw '*was not found in Active Directory*'
        { Resolve-PraGroup -Context $context -Name 'PRA-Twin' } | Should -Throw "*2 groups are named 'PRA-Twin': give the distinguished name of the one to use.*"
        [string](Resolve-PraGroup -Context $context -Name 'CN=PRA-Twin,OU=GroupsB,DC=gate,DC=invalid').DistinguishedName | Should -BeExactly 'CN=PRA-Twin,OU=GroupsB,DC=gate,DC=invalid'
        { Resolve-PraGroup -Context $context -Name 'CN=PRA-Wave1,OU=Groups,DC=other,DC=invalid' } | Should -Throw '*was not found in Active Directory*'
    }
    It 'takes the members of nested groups too, and skips the others with the reason of each, counting all the members' {
        $runtime = New-GroupAd313g -Name 'members-313g'
        $context = Use-GroupContext313g $runtime 'PRA-Wave1'
        $selected = @(Get-PraTarget -Context $context)
        # user1 and user2 directly, user1 again and user3 (shared, not included) and user4 (no mailbox) through the nested group, a computer, a contact, user5 (shared).
        @($selected | ForEach-Object SamAccountName | Sort-Object) -join ',' | Should -BeExactly 'user1,user2'
        $context.ObjectsText | Should -BeExactly 'members of PRA-Wave1 (7, including nested groups)'
        $skipped = @($context.SkippedMembers)
        $skipped.Count | Should -Be 5
        $skipped | Should -Contain 'PC01$ (a computer, not a mailbox)'
        $skipped | Should -Contain 'Bob Contact (a contact, not an on-premises mailbox)'
        $skipped | Should -Contain 'user3 (a shared mailbox, not included in this run)'
        $skipped | Should -Contain 'user4 (no on-premises mailbox)'
        $skipped | Should -Contain 'user5 (a shared mailbox, not included in this run)'
        @(Get-GateWrites $runtime).Count | Should -Be 0
    }
    It 'applies the existing filters to the members: shared mailboxes with IncludeShared, the exclusion list, and the -Scope filter' {
        $runtime = New-GroupAd313g -Name 'filters-313g'
        $context = Use-GroupContext313g $runtime 'PRA-Wave1' -IncludeShared $true
        @(Get-PraTarget -Context $context | ForEach-Object SamAccountName | Sort-Object) -join ',' | Should -BeExactly 'user1,user2,user3,user5'
        $context.SkippedMembers.Count | Should -Be 3
        $context.Config.Scope.ExcludeSamAccountNames = @('user2')
        $selected = @(Get-PraTarget -Context $context)
        @($selected | ForEach-Object SamAccountName | Sort-Object) -join ',' | Should -BeExactly 'user1,user3,user5'
        @($context.SkippedMembers) | Should -Contain 'user2 (excluded (a system mailbox, or listed in Scope.ExcludeSamAccountNames))'
        $users = @(Get-PraTarget -Context $context -MailboxScope UsersOnly)
        @($users | ForEach-Object SamAccountName) -join ',' | Should -BeExactly 'user1'
        @($context.SkippedMembers) | Should -Contain 'user5 (a shared mailbox, not included in this run)'
    }
    It 'an empty group is said in plain words and nothing is selected' {
        $runtime = New-GroupAd313g -Name 'empty-313g'
        $context = Use-GroupContext313g $runtime 'PRA-Empty'
        @(Get-PraTarget -Context $context).Count | Should -Be 0
        $context.TargetsReported | Should -BeTrue
        $context.ObjectsText | Should -BeExactly 'members of PRA-Empty (0, including nested groups)'
        @(Get-GateWrites $runtime).Count | Should -Be 0
    }
    It 'a run with -Group names the group in the header, skips the non-mailboxes, and writes its own command in the Next steps' {
        $runtime = New-GroupAd313g -Name 'main-313g'
        $run = Invoke-GateProcess $runtime @{Action='Convert';Phase='AD';Mode='Preview';Group='PRA-Wave1';ConfigPath=$runtime.ConfigPath} -TimeoutSeconds 120
        $run.ExitCode | Should -Be 0 -Because ($run.Output + $run.Error)
        $run.Output | Should -Match 'members of PRA-Wave1'
        $run.Output | Should -Match ([regex]::Escape('Group PRA-Wave1: 7 member(s), including nested groups'))
        $run.Output | Should -Match ([regex]::Escape('PC01$: not converted, a computer, not a mailbox'))
        $run.Output | Should -Match ([regex]::Escape('members of PRA-Wave1 (7, including nested groups)'))
        @(Get-GateWrites $runtime).Count | Should -Be 0
        $steps = @($run.MainResult.NextSteps)
        $steps[0] | Should -Match "^\.\\Invoke-PraRemoteMailbox\.ps1 -Action Convert -Phase AD -Mode Apply -Group 'PRA-Wave1' -ConfigPath "
        # The report carries the same line and the skipped members.
        $report = @(Get-ChildItem -LiteralPath (Join-Path $runtime.Root 'reports') -Filter '*.html' | Select-Object -First 1)
        $html = [IO.File]::ReadAllText($report[0].FullName)
        $html | Should -Match ([regex]::Escape('members of PRA-Wave1 (7, including nested groups)'))
        $html | Should -Match ([regex]::Escape('PC01$ (a computer, not a mailbox)'))
    }
    It 'an empty group, an unknown group and two groups of one name stop or warn in plain words, before any change' {
        $runtime = New-GroupAd313g -Name 'main-errors-313g'
        $empty = Invoke-GateProcess $runtime @{Action='Convert';Phase='AD';Mode='Apply';Force=$true;Group='PRA-Empty';ConfigPath=$runtime.ConfigPath} -TimeoutSeconds 120
        $empty.Output | Should -Match ([regex]::Escape('The group PRA-Empty has no member: nothing to convert.'))
        $empty.Output | Should -Not -Match 'No on-premises mailbox found in the scope'
        @(Get-GateWrites $runtime).Count | Should -Be 0
        $unknown = Invoke-GateProcess $runtime @{Action='Convert';Phase='AD';Mode='Apply';Force=$true;Group='PRA-Nope';ConfigPath=$runtime.ConfigPath} -TimeoutSeconds 120
        $unknown.ExitCode | Should -Be 1 -Because ($unknown.Output + $unknown.Error)
        $unknown.Output | Should -Match ([regex]::Escape("The group 'PRA-Nope' was not found in Active Directory"))
        @($unknown.MainResult.NextSteps)[1] | Should -Match "-Action Convert -Phase AD -Mode Apply -Group 'PRA-Nope' -ConfigPath "
        $twin = Invoke-GateProcess $runtime @{Action='Convert';Phase='AD';Mode='Apply';Force=$true;Group='PRA-Twin';ConfigPath=$runtime.ConfigPath} -TimeoutSeconds 120
        $twin.ExitCode | Should -Be 1 -Because ($twin.Output + $twin.Error)
        $twin.Output | Should -Match ([regex]::Escape("2 groups are named 'PRA-Twin': give the distinguished name of the one to use."))
        @(Get-GateWrites $runtime).Count | Should -Be 0
    }
    It 'refuses -Group with another source, with a batch, or for another action, in plain words' {
        $runtime = New-GroupAd313g -Name 'exclusive-313g'
        $csv = Join-Path $runtime.Root 'targets.csv'
        [IO.File]::WriteAllText($csv, "Identity`r`nuser1`r`n", (New-Object Text.UTF8Encoding($true)))
        $cases = @(
            @{ Arguments = @{Action='Convert';Phase='AD';Group='PRA-Wave1';Identity='user1'}; Message = 'Identity cannot be combined with a selected OU, CSV or group' },
            @{ Arguments = @{Action='Convert';Phase='AD';Group='PRA-Wave1';CsvPath=$csv}; Message = 'Choose one source: -SearchBase (OU), -CsvPath or -Group, not several.' },
            @{ Arguments = @{Action='Convert';Phase='AD';Group='PRA-Wave1';SearchBase='OU=Tests,DC=gate,DC=invalid'}; Message = 'Choose one source: -SearchBase (OU), -CsvPath or -Group, not several.' },
            @{ Arguments = @{Action='Convert';Phase='AD';Group='PRA-Wave1';Batch='deadbeef'}; Message = '-Phase AD with -Batch finishes a batch as a whole: -Identity, -SearchBase, -CsvPath and -Group cannot be combined with it.' },
            @{ Arguments = @{Action='Convert';Phase='Cloud';Group='PRA-Wave1';Batch='deadbeef'}; Message = 'SearchBase/CsvPath/Group are only available for Convert -Phase AD or Both.' },
            @{ Arguments = @{Action='Check';Group='PRA-Wave1';Identity=''}; Message = 'SearchBase/CsvPath/Group are only available for Convert -Phase AD or Both.' })
        foreach ($case in $cases) {
            $arguments = @{Mode='Preview';ConfigPath=$runtime.ConfigPath} + $case.Arguments
            $run = Invoke-GateProcess $runtime $arguments -TimeoutSeconds 60
            $run.ExitCode | Should -Be 1 -Because ($run.Output + $run.Error)
            $run.Output | Should -Match ([regex]::Escape($case.Message))
        }
        @(Get-GateWrites $runtime).Count | Should -Be 0
    }
    It 'an AD write refused for a run with -Group repeats -Group in the command for the other server' {
        $runtime = New-GroupAd313g -Name 'denied-313g' -Case 'AccessDenied'
        $run = Invoke-GateProcess $runtime @{Action='Convert';Phase='AD';Mode='Apply';Force=$true;Group='CN=PRA-Wave1,OU=Groups,DC=gate,DC=invalid';ConfigPath=$runtime.ConfigPath} -TimeoutSeconds 120
        $run.ExitCode | Should -Be 1 -Because ($run.Output + $run.Error)
        $steps = @($run.MainResult.NextSteps)
        $steps | Should -Contain ".\Invoke-PraRemoteMailbox.ps1 -Action Convert -Phase AD -Group 'CN=PRA-Wave1,OU=Groups,DC=gate,DC=invalid'" -Because ($steps -join "`n")
    }
    It 'the manifest exports the group resolver that the window uses, and the help and the usage name -Group' {
        @((Import-PowerShellDataFile -LiteralPath (Join-Path $global:PraGate.Package 'PraRemoteMailbox.psd1')).FunctionsToExport) | Should -Contain 'Resolve-PraGroup'
        $script = [IO.File]::ReadAllText((Join-Path $global:PraGate.Package 'Invoke-PraRemoteMailbox.ps1'))
        $script | Should -Match '\.PARAMETER Group'
        $script | Should -Match '-Action Convert -Group PRA-Wave1'
    }
    It 'reads the members with the chain of memberships, so a contact or a computer is a member, a group is not, and Get-ADGroupMember is not used' -Tag 'Release313i' {
        $runtime = New-GroupAd313g -Name 'chain-313i'
        $context = Use-GroupContext313g $runtime 'PRA-Wave1'
        $group = Resolve-PraGroup -Context $context -Name 'PRA-Wave1'
        $members = @(Get-PraGroupMember -Context $context -Group $group)
        $members.Count | Should -Be 7
        @($members | ForEach-Object { [string]$_.objectClass } | Sort-Object -Unique) -join ',' | Should -BeExactly 'computer,contact,user'
        @($members | Where-Object { $_.Name -ceq 'Bob Contact' }).Count | Should -Be 1
        $calls = @(Get-GateEvents $runtime | Where-Object Operation -eq 'Get-ADObject' | Where-Object { $_.Detail.LDAPFilter })
        $calls.Count | Should -Be 1
        $calls[0].Detail.LDAPFilter | Should -BeExactly '(&(memberOf:1.2.840.113556.1.4.1941:=CN=PRA-Wave1,OU=Groups,DC=gate,DC=invalid)(!(objectClass=group)))'
        @(Get-GateEvents $runtime | Where-Object Operation -eq 'Get-ADGroupMember').Count | Should -Be 0
    }
    It 'counts a contact that is the only member, with its reason, and the number of members says so' -Tag 'Release313i' {
        $runtime = New-GroupAd313g -Name 'contact-only-313i'
        Set-Runtime313i $runtime { param($State) $State.Groups[2].member = @([string]$State.Others[1].DistinguishedName) }
        $context = Use-GroupContext313g $runtime 'PRA-Empty'
        @(Get-PraTarget -Context $context).Count | Should -Be 0
        $context.ObjectsText | Should -BeExactly 'members of PRA-Empty (1, including nested groups)'
        @($context.SkippedMembers) | Should -Be @('Bob Contact (a contact, not an on-premises mailbox)')
    }
    It 'counts the skipped members in the Result line and in the result object' -Tag 'Release313i' {
        $runtime = New-GroupAd313g -Name 'skipped-313i'
        $run = Invoke-GateProcess $runtime @{Action='Convert';Phase='AD';Mode='Preview';Group='PRA-Wave1';ConfigPath=$runtime.ConfigPath} -TimeoutSeconds 120
        $run.ExitCode | Should -Be 0 -Because ($run.Output + $run.Error)
        $run.Output | Should -Match '2 planned . 0 error\(s\) . 5 skipped'
        $run.MainResult.SkippedCount | Should -Be 5
        @(Get-GateWrites $runtime).Count | Should -Be 0
    }
    It 'gives the way to continue the batch of the members that are already remote mailboxes, one line per batch' -Tag 'Release313i' {
        $runtime = New-GroupAd313g -Name 'continue-313i'
        $a = 'aa000001'.PadRight(32, '0'); $b = 'bb000002'.PadRight(32, '0')
        Convert-Members313i $runtime @(0, 1, 3) @{ $a = @(0, 1); $b = @(3) }
        $context = Use-GroupContext313g $runtime 'PRA-Wave1'
        @(Get-PraTarget -Context $context).Count | Should -Be 0
        @($context.SkippedMembers | Where-Object { $_ -match 'already a remote mailbox' }).Count | Should -Be 3
        $steps = @($context.NextSteps)
        $steps.Count | Should -Be 3
        $steps[0] | Should -BeExactly 'To continue these batches (Entra Connect sync and transfer package; AD is not changed again), run one command per batch:'
        $steps[1] | Should -BeExactly '.\Invoke-PraRemoteMailbox.ps1 -Action Convert -Phase AD -Mode Apply -Batch aa000001'
        $steps[2] | Should -BeExactly '.\Invoke-PraRemoteMailbox.ps1 -Action Convert -Phase AD -Mode Apply -Batch bb000002'
        # One batch only: the sentence of an explicit target.
        $one = New-GroupAd313g -Name 'continue-one-313i'
        Convert-Members313i $one @(0, 1) @{ $a = @(0, 1) }
        $oneContext = Use-GroupContext313g $one 'PRA-Wave1'
        $null = Get-PraTarget -Context $oneContext
        @($oneContext.NextSteps)[0] | Should -BeExactly 'To continue that batch (Entra Connect sync and transfer package; AD is not changed again), run:'
        @($oneContext.NextSteps).Count | Should -Be 2
        # Started from the window the way is the Task page.
        $env:PRA_EVENT_FILE = Join-Path $global:PraGate.Root 'events-313i.jsonl'
        try {
            $window = Use-GroupContext313g $runtime 'PRA-Wave1'
            $null = Get-PraTarget -Context $window
            $lines = @($window.NextSteps)
            $lines.Count | Should -Be 2
            $lines[0] | Should -BeExactly 'To continue batch aa000001 (Entra Connect sync and transfer package; AD is not changed again), go to the Task page, choose Move mailboxes to Exchange Online, then Continue a batch, and pick batch aa000001.'
            $lines[1] | Should -Match 'pick batch bb000002\.$'
        } finally { Remove-Item Env:\PRA_EVENT_FILE -ErrorAction SilentlyContinue }
    }
    It 'a member that is a remote mailbox without a batch of this folder gives no way to continue' -Tag 'Release313i' {
        $runtime = New-GroupAd313g -Name 'continue-none-313i'
        Set-Runtime313i $runtime { param($State) $State.Users[3].homeMDB = $null; $State.Users[3].msExchRecipientTypeDetails = [long]2147483648 }
        $context = Use-GroupContext313g $runtime 'PRA-Wave1'
        $null = Get-PraTarget -Context $context
        @($context.SkippedMembers) | Should -Contain 'user4 (already a remote mailbox)'
        @(Get-PraList $context 'NextSteps').Count | Should -Be 0
    }
    It 'a rerun on a group whose members are all converted ends with the command that continues their batches' -Tag 'Release313i' {
        $runtime = New-GroupAd313g -Name 'rerun-313i'
        $a = 'aa000001'.PadRight(32, '0'); $b = 'bb000002'.PadRight(32, '0')
        Convert-Members313i $runtime @(0, 1, 3) @{ $a = @(0, 1); $b = @(3) }
        $run = Invoke-GateProcess $runtime @{Action='Convert';Phase='AD';Mode='Preview';Group='PRA-Wave1';ConfigPath=$runtime.ConfigPath} -TimeoutSeconds 120
        $run.ExitCode | Should -Be 0 -Because ($run.Output + $run.Error)
        $steps = @($run.MainResult.NextSteps)
        $steps[0] | Should -BeExactly 'To continue these batches (Entra Connect sync and transfer package; AD is not changed again), run one command per batch:'
        $steps[1] | Should -Match '^\.\\Invoke-PraRemoteMailbox\.ps1 -Action Convert -Phase AD -Mode Apply -Batch aa000001 -ConfigPath '
        $steps[2] | Should -Match '^\.\\Invoke-PraRemoteMailbox\.ps1 -Action Convert -Phase AD -Mode Apply -Batch bb000002 -ConfigPath '
        $run.Output | Should -Match 'To continue these batches'
        @(Get-GateWrites $runtime).Count | Should -Be 0
    }
    It 'an option combination that is refused never gets the refused command back: one corrected command per valid choice, the other options kept' -Tag 'Release313i' {
        $runtime = New-GroupAd313g -Name 'refusals-313i'
        $csv = Join-Path $runtime.Root 'targets.csv'
        [IO.File]::WriteAllText($csv, "Identity`r`nuser1`r`n", (New-Object Text.UTF8Encoding($true)))
        # -Identity with -Group: one command with -Group only, one with -Identity only.
        $run = Invoke-GateProcess $runtime @{Action='Convert';Phase='AD';Mode='Preview';Group='PRA-Wave1';Identity='user1';Scope='UsersOnly';ConfigPath=$runtime.ConfigPath} -TimeoutSeconds 120
        $run.ExitCode | Should -Be 1 -Because ($run.Output + $run.Error)
        $steps = @($run.MainResult.NextSteps)
        $steps[0] | Should -BeExactly 'These options select the objects in different ways and cannot be combined (-Identity, -Group): keep one of them. Run the command with the one you want:'
        $steps[1] | Should -BeExactly 'Only -Identity (remove -Group):'
        $steps[2] | Should -Match "^\.\\Invoke-PraRemoteMailbox\.ps1 -Action Convert -Phase AD -Identity 'user1' -Scope UsersOnly -ConfigPath "
        $steps[2] | Should -Not -Match '-Group'
        $steps[3] | Should -BeExactly 'Only -Group (remove -Identity):'
        $steps[4] | Should -Match "^\.\\Invoke-PraRemoteMailbox\.ps1 -Action Convert -Phase AD -Scope UsersOnly -Group 'PRA-Wave1' -ConfigPath "
        $steps[4] | Should -Not -Match '-Identity'
        $run.Output | Should -Match 'Only -Group \(remove -Identity\)'
        # Several sources: one command per source.
        $run = Invoke-GateProcess $runtime @{Action='Convert';Phase='AD';Mode='Preview';Group='PRA-Wave1';CsvPath=$csv;ConfigPath=$runtime.ConfigPath} -TimeoutSeconds 120
        $run.ExitCode | Should -Be 1 -Because ($run.Output + $run.Error)
        $steps = @($run.MainResult.NextSteps)
        $steps[1] | Should -BeExactly 'Only -CsvPath (remove -Group):'
        $steps[2] | Should -Match '-CsvPath ' ; $steps[2] | Should -Not -Match '-Group'
        $steps[3] | Should -BeExactly 'Only -Group (remove -CsvPath):'
        $steps[4] | Should -Match "-Group 'PRA-Wave1'" ; $steps[4] | Should -Not -Match '-CsvPath'
        # -Group with -Phase Cloud: the -Phase AD command (no batch), or the cloud command without -Group.
        $run = Invoke-GateProcess $runtime @{Action='Convert';Phase='Cloud';Mode='Preview';Group='PRA-Wave1';Batch='deadbeef';ConfigPath=$runtime.ConfigPath} -TimeoutSeconds 120
        $run.ExitCode | Should -Be 1 -Because ($run.Output + $run.Error)
        $steps = @($run.MainResult.NextSteps)
        $steps[0] | Should -Match '^-Group only selects the mailboxes of a new conversion, which is the AD phase \(or Both\) and takes no batch\. Run it with -Phase AD:$'
        $steps[1] | Should -Match "^\.\\Invoke-PraRemoteMailbox\.ps1 -Action Convert -Phase AD -Group 'PRA-Wave1' -ConfigPath "
        $steps[1] | Should -Not -Match '-Batch'
        $steps[2] | Should -BeExactly 'Or keep -Phase Cloud and remove -Group:'
        $steps[3] | Should -Match '^\.\\Invoke-PraRemoteMailbox\.ps1 -Action Convert -Phase Cloud -Batch deadbeef -ConfigPath '
        $steps[3] | Should -Not -Match '-Group'
        # -Group for another action: the command without it, and the conversion of the group.
        $run = Invoke-GateProcess $runtime @{Action='Check';Group='PRA-Wave1';ConfigPath=$runtime.ConfigPath} -TimeoutSeconds 120
        $run.ExitCode | Should -Be 1 -Because ($run.Output + $run.Error)
        $steps = @($run.MainResult.NextSteps)
        $steps[1] | Should -Match "^\.\\Invoke-PraRemoteMailbox\.ps1 -Action Check -Identity '<UPN>' -ConfigPath "
        $steps[3] | Should -Match "^\.\\Invoke-PraRemoteMailbox\.ps1 -Action Convert -Phase AD -Group 'PRA-Wave1' -ConfigPath "
        # -Phase AD -Batch with a selector: the batch alone, or the new conversion without -Batch.
        $run = Invoke-GateProcess $runtime @{Action='Convert';Phase='AD';Mode='Preview';Group='PRA-Wave1';Batch='deadbeef';ConfigPath=$runtime.ConfigPath} -TimeoutSeconds 120
        $run.ExitCode | Should -Be 1 -Because ($run.Output + $run.Error)
        $steps = @($run.MainResult.NextSteps)
        $steps[1] | Should -Match '^\.\\Invoke-PraRemoteMailbox\.ps1 -Action Convert -Phase AD -Batch deadbeef -ConfigPath '
        $steps[1] | Should -Not -Match '-Group'
        $steps[3] | Should -Match "^\.\\Invoke-PraRemoteMailbox\.ps1 -Action Convert -Phase AD -Group 'PRA-Wave1' -ConfigPath "
        $steps[3] | Should -Not -Match '-Batch'
        @(Get-GateWrites $runtime).Count | Should -Be 0
    }
    It 'says which groups share a name, with their distinguished names (five at most, then how many more)' -Tag 'Release313i' {
        $runtime = New-GroupAd313g -Name 'twins-313i'
        Set-Runtime313i $runtime { param($State)
            $template = $State.Groups[3]
            $State.Groups = @($State.Groups) + @(3..7 | ForEach-Object {
                    [pscustomobject]@{ ObjectGUID = [guid]('30000000-0000-0000-0000-{0:000000000000}' -f (10 + $_)); DistinguishedName = ('CN=PRA-Twin,OU=GroupsX{0},DC=gate,DC=invalid' -f $_); Name = 'PRA-Twin'; SamAccountName = 'PRA-Twin'; objectClass = 'group'; member = [string[]]@() } })
        }
        $context = Use-GroupContext313g $runtime 'PRA-Wave1'
        $message = ''
        try { $null = Resolve-PraGroup -Context $context -Name 'PRA-Twin' } catch { $message = $_.Exception.Message }
        $message | Should -Match "^7 groups are named 'PRA-Twin': give the distinguished name of the one to use\. They are: CN=PRA-Twin,OU=Groups[A-Z0-9]+,DC=gate,DC=invalid( \| CN=PRA-Twin,OU=Groups[A-Z0-9]+,DC=gate,DC=invalid){4} \(and 2 more\)\.$"
        $few = New-GroupAd313g -Name 'twins-two-313i'
        $fewContext = Use-GroupContext313g $few 'PRA-Wave1'
        $fewMessage = ''
        try { $null = Resolve-PraGroup -Context $fewContext -Name 'PRA-Twin' } catch { $fewMessage = $_.Exception.Message }
        $fewMessage | Should -BeExactly "2 groups are named 'PRA-Twin': give the distinguished name of the one to use. They are: CN=PRA-Twin,OU=GroupsA,DC=gate,DC=invalid | CN=PRA-Twin,OU=GroupsB,DC=gate,DC=invalid."
    }
    It 'an Apply that needs a confirmation the console cannot ask for proposes the same command with -Force, or an interactive console' -Tag 'Release313i' {
        $runtime = New-GroupAd313g -Name 'noconfirm-313i'
        $run = Invoke-GateProcess $runtime @{Action='Convert';Phase='AD';Mode='Apply';Group='PRA-Wave1';ConfigPath=$runtime.ConfigPath} -TimeoutSeconds 120
        $run.ExitCode | Should -Be 1 -Because ($run.Output + $run.Error)
        ($run.MainResult.Issues.Message -join ' ') | Should -Match 'Apply needs a confirmation'
        $steps = @($run.MainResult.NextSteps)
        $steps[0] | Should -BeExactly 'Nothing was written. This console cannot ask for the confirmation: add -Force to the command, or run it in an interactive console and answer yes:'
        $steps[1] | Should -Match "^\.\\Invoke-PraRemoteMailbox\.ps1 -Action Convert -Phase AD -Mode Apply -Group 'PRA-Wave1' -ConfigPath .* -Force$"
        @(Get-GateWrites $runtime).Count | Should -Be 0
    }
    It 'an Apply refused for lack of confirmation writes no global report and counts only the skipped group members, not the planned objects' -Tag 'Release313j' {
        $runtime = New-GroupAd313g -Name 'noconfirm-313j'
        $run = Invoke-GateProcess $runtime @{Action='Convert';Phase='AD';Mode='Apply';Group='PRA-Wave1';ConfigPath=$runtime.ConfigPath} -TimeoutSeconds 120
        $run.ExitCode | Should -Be 1 -Because ($run.Output + $run.Error)
        $run.MainResult.SkippedCount | Should -Be 5
        $run.MainResult.PlannedCount | Should -Be 0
        $run.Output | Should -Match '0 done . 0 pending . 1 error\(s\) . 5 skipped'
        @(Get-ChildItem -LiteralPath (Join-Path $runtime.Root 'reports') -Filter '*.global.*' -ErrorAction SilentlyContinue).Count | Should -Be 0
        @(Get-GateWrites $runtime).Count | Should -Be 0
    }
    It 'two groups of one name give one command per distinguished name, and a -Batch with a selector names the option check' -Tag 'Release313j' {
        $runtime = New-GroupAd313g -Name 'twins-next-313j'
        $run = Invoke-GateProcess $runtime @{Action='Convert';Phase='AD';Mode='Preview';Group='PRA-Twin';Scope='UsersOnly';ConfigPath=$runtime.ConfigPath} -TimeoutSeconds 120
        $run.ExitCode | Should -Be 1 -Because ($run.Output + $run.Error)
        $steps = @($run.MainResult.NextSteps)
        $steps.Count | Should -Be 3
        $steps[0] | Should -BeExactly 'To use one of these groups, run the command with its distinguished name (one command per group):'
        $steps[1] | Should -Match "^\.\\Invoke-PraRemoteMailbox\.ps1 -Action Convert -Phase AD -Scope UsersOnly -Group 'CN=PRA-Twin,OU=GroupsA,DC=gate,DC=invalid' -ConfigPath "
        $steps[2] | Should -Match "-Group 'CN=PRA-Twin,OU=GroupsB,DC=gate,DC=invalid' -ConfigPath "
        $steps[1] | Should -Not -Match "-Group 'PRA-Twin'"
        $refused = Invoke-GateProcess $runtime @{Action='Convert';Phase='AD';Mode='Preview';Group='PRA-Wave1';Batch='deadbeef';ConfigPath=$runtime.ConfigPath} -TimeoutSeconds 120
        $refused.ExitCode | Should -Be 1 -Because ($refused.Output + $refused.Error)
        $refused.Output | Should -Match 'Stopped at step .* \(operation Check-Options'
        $refused.Output | Should -Not -Match 'Check-ReportFolder'
        @(Get-GateWrites $runtime).Count | Should -Be 0
    }
    It 'a batch short id on a machine without a Backups folder gives a plain message and the package or the copy of the batch folder as next steps' -Tag 'Release313j' {
        $runtime = New-GroupAd313g -Name 'nobackups-313j'
        if (Test-Path -LiteralPath $runtime.State.BackupFolder) { Remove-Item -LiteralPath $runtime.State.BackupFolder -Recurse -Force }
        $run = Invoke-GateProcess $runtime @{Action='Convert';Phase='Cloud';Mode='Preview';Batch='deadbeef';ConfigPath=$runtime.ConfigPath} -TimeoutSeconds 120
        $run.ExitCode | Should -Be 1 -Because ($run.Output + $run.Error)
        $run.Output | Should -Match ([regex]::Escape('No batch is stored on this machine yet: the backup folder'))
        $run.Output | Should -Not -Match 'Backup folder not found'
        $steps = @($run.MainResult.NextSteps)
        $steps[0] | Should -Match '^On the server that received a transfer package, give the package itself'
        $steps[1] | Should -Match "^\.\\Invoke-PraRemoteMailbox\.ps1 -Action Convert -Phase Cloud -Batch '<folder>\\<package name>-for-Cloud\.zip' -ConfigPath "
        $steps[2] | Should -Match '^Otherwise copy the batch folder \(Batch-deadbeef\.\.\. or Finalize-deadbeef\.\.\.\) into '
        $steps[3] | Should -Match '-Action Convert -Phase Cloud -Batch deadbeef -ConfigPath '
    }
    It 'the window variant of the ambiguous group name says to type the distinguished name in the AD group field' -Tag 'Release313j' {
        $runtime = New-GroupAd313g -Name 'twins-window-313j'
        $context = Use-GroupContext313g $runtime 'PRA-Wave1'
        $saved = $env:PRA_EVENT_FILE
        try {
            $env:PRA_EVENT_FILE = Join-Path $runtime.Root 'events-window.jsonl'
            try { $null = Resolve-PraGroup -Context $context -Name 'PRA-Twin' } catch { $null = $_ }
        } finally { if ($null -eq $saved) { Remove-Item Env:\PRA_EVENT_FILE -ErrorAction SilentlyContinue } else { $env:PRA_EVENT_FILE = $saved } }
        @($context.NextSteps).Count | Should -Be 3
        @($context.NextSteps)[0] | Should -BeExactly 'Type the distinguished name of the group to use in the AD group field. One of:'
        @($context.NextSteps)[1] | Should -BeExactly 'CN=PRA-Twin,OU=GroupsA,DC=gate,DC=invalid'
        $context.NextOnFailure | Should -BeTrue
    }
}
Describe 'Release 3.1.3 - the stop names the object that failed, a cancel is not an error, configuration values and the unreachable controller are told in words (real main and production modules, synthetic)' -Tag 'Release313i' {
    It 'the stop of a cloud check names the object that failed, not the last object the loop looked at' {
        $runtime = New-GateRuntime -Name 'first-fails-313i' -Case 'CloudFirstFails'
        $ad = Invoke-GateProcess $runtime @{Action='Convert';Phase='AD';Mode='Apply';Force=$true;ConfigPath=$runtime.ConfigPath} -TimeoutSeconds 120
        $short = [string]$ad.MainResult.BatchId
        $run = Invoke-GateProcess $runtime @{Action='Convert';Phase='Cloud';Mode='Preview';ConfigPath=$runtime.ConfigPath;Batch=$short} -TimeoutSeconds 120
        $run.ExitCode | Should -Be 1 -Because ($run.Output + $run.Error)
        $run.Output | Should -Match ([regex]::Escape("user1@gate.invalid: Exchange Online session: connection state 'Disconnected', expected Connected."))
        $run.Output | Should -Match "Stopped at step 'Cloud' \(operation CloudCheck, object user1@gate\.invalid\): Exchange Online check failed\. Nothing was changed\. Run the Preview again\."
        $run.Output | Should -Not -Match 'object user2@gate\.invalid'
    }
    It 'a run cancelled by the operator is reported as cancelled: no error, RESULT: CANCELLED, exit code 1, and the command to run it again' {
        $log = Join-Path $global:PraGate.Root 'cancel-313i.log'
        [IO.File]::WriteAllText($log, 'log' + [Environment]::NewLine)
        $ctx = @{ Root = $global:PraGate.Package; Version = '3.1.3'; RunId = ((Get-Date -Format 'yyyyMMdd_HHmmss') + '-' + [guid]::NewGuid().ToString('N')); StartTime = Get-Date; Action = 'Convert'; Mode = 'Apply'; Phase = 'AD'
            CurrentPhase = 'Start'; CurrentOperation = 'Confirm-Apply'; CurrentIdentity = ''; StepIndex = 0; Warnings = 0; Issues = (New-Object 'Collections.Generic.List[object]'); Rows = (New-Object 'Collections.Generic.List[object]')
            Server = ''; Config = @{ Environment = 'GATE' }; AllowMutation = $false; ReportFolder = (Join-Path $global:PraGate.Root 'reports-313i'); NoReport = $true; BatchId = ''; LogFile = $log; TranscriptPath = $log; _PraTranscriptCreated = $true; TranscriptStarted = $false
            NextSteps = @(); ExitCode = 1; CloudConnectFailed = $false; ResultStatus = ''; Cancelled = $true
            FallbackNext = @('Nothing was written. To run it, give the same command again and answer yes to the confirmation:', '.\Invoke-PraRemoteMailbox.ps1 -Action Convert -Phase AD -Mode Apply') }
        $skipped = New-Object 'Collections.Generic.List[string]'; $skipped.Add('PC01$ (a computer, not a mailbox)'); $ctx.SkippedMembers = $skipped
        $result = Complete-PraRun -Context $ctx
        $result.Status | Should -BeExactly 'Cancelled' -Because (@($result.Issues | ForEach-Object { $_.Message }) -join ' / ')
        $result.ExitCode | Should -Be 1
        $result.ErrorCount | Should -Be 0
        $result.SkippedCount | Should -Be 1
        @($result.Issues).Count | Should -Be 0
        $result.NextSteps[0] | Should -BeExactly 'Nothing was written. To run it, give the same command again and answer yes to the confirmation:'
        $text = [IO.File]::ReadAllText($log)
        $text | Should -Match 'RESULT: CANCELLED'
        $text | Should -Not -Match 'RESULT: FAIL'
    }
    It 'a configuration value that is none of the accepted words is quoted, with the accepted words and the configuration file' {
        $runtime = New-GateRuntime -Name 'badvalues-313i'
        $cases = @(
            @{ From = "Mode='Auto'"; To = "Mode='Groupe'"; Key = 'Scope.Mode'; Accepted = 'Auto, OU, Group or Csv'; Value = 'Groupe' },
            @{ From = "PermissionSource='None'"; To = "PermissionSource='Ldap'"; Key = 'SharedMailbox.PermissionSource'; Accepted = 'AD, Csv, CustomAttribute or None'; Value = 'Ldap' },
            @{ From = "PolicyType='Delta'"; To = "PolicyType='Full'"; Key = 'EntraConnect.PolicyType'; Accepted = 'Delta or Initial'; Value = 'Full' },
            @{ From = "Execution=@{Phase='Both'}"; To = "Execution=@{Phase='Cloudy'}"; Key = 'Execution.Phase'; Accepted = 'Both, AD or Cloud'; Value = 'Cloudy' })
        foreach ($case in $cases) {
            $text = [IO.File]::ReadAllText($runtime.ConfigPath)
            $text.Contains($case.From) | Should -BeTrue -Because $case.From
            $path = Join-Path $runtime.Root ('bad-' + [guid]::NewGuid().ToString('N').Substring(0, 6) + '.psd1')
            [IO.File]::WriteAllText($path, $text.Replace($case.From, $case.To))
            $expected = ('Configuration: {0} must be {1}: the value is ''{2}'' in {3}.' -f $case.Key, $case.Accepted, $case.Value, $path)
            { Import-PraConfiguration -Path $path -Root $runtime.Package -DeferScopeCheck } | Should -Throw -ExpectedMessage $expected -ExceptionType ([System.Management.Automation.RuntimeException]) -Because $case.Key
        }
        $emptyPath = Join-Path $runtime.Root 'empty-mode.psd1'
        [IO.File]::WriteAllText($emptyPath, [IO.File]::ReadAllText($runtime.ConfigPath).Replace("Mode='Auto'", "Mode=''"))
        { Import-PraConfiguration -Path $emptyPath -Root $runtime.Package -DeferScopeCheck } | Should -Throw '*Scope.Mode must be Auto, OU, Group or Csv: the value is empty in *'
    }
    It 'a Convert Preview whose domain controller does not answer points at the controller, the configuration and the machine to run from' {
        $runtime = New-GateRuntime -Name 'dc-down-313i' -Case 'AdServerDown'
        $run = Invoke-GateProcess $runtime @{Action='Convert';Phase='AD';Mode='Preview';Identity='user1';ConfigPath=$runtime.ConfigPath} -TimeoutSeconds 120
        $run.ExitCode | Should -Be 1 -Because ($run.Output + $run.Error)
        $steps = @($run.MainResult.NextSteps)
        $steps[0] | Should -BeExactly 'Nothing was changed. Active Directory did not answer on the domain controller dc01.gate.invalid: check that it is running and reachable from this machine (TCP 9389), or set another one in DomainController of Gate.psd1. Then run the same command again:'
        $steps[1] | Should -Match "^\.\\Invoke-PraRemoteMailbox\.ps1 -Action Convert -Phase AD -Identity 'user1' -ConfigPath "
        $steps[2] | Should -BeExactly 'Or run the same command on a machine that reaches dc01.gate.invalid, or on the domain controller itself (the configuration file of that machine is used):'
        $steps[3] | Should -BeExactly ".\Invoke-PraRemoteMailbox.ps1 -Action Convert -Phase AD -Identity 'user1'"
        @(Get-GateWrites $runtime).Count | Should -Be 0
    }
}
Describe 'Release 3.1.3 - letter case never matters: configuration, CSV, batch ids, packages and addresses (real main and production modules, synthetic)' -Tag 'Release313h' {
    BeforeAll {
        function global:Use-Context313h {
            <# The runtime loaded in this process (the way the ScopeOU tests do it), and a Preview context. #>
            param($Runtime)
            $env:PRA_GATE_STATE = $Runtime.StatePath
            $env:PSModulePath = $Runtime.Modules + ';' + (Join-Path $PSHOME 'Modules')
            Remove-Module PRA.Directory -Force -ErrorAction SilentlyContinue
            Get-Module ActiveDirectory -All | Remove-Module -Force -ErrorAction SilentlyContinue
            Import-Module (Join-Path $Runtime.Modules 'ActiveDirectory\ActiveDirectory.psm1') -Force -Global -ErrorAction Stop
            Import-Module (Join-Path $global:PraGate.Package 'module\PRA.Directory.psm1') -Force -Global -ErrorAction Stop
            New-GateContext $Runtime -Mode Preview
        }
        function global:Set-LowerConfig313h {
            <# Every enumerated value of the configuration written in lower case. #>
            param($Runtime)
            Set-GateConfigText $Runtime { param($t) $t.Replace("Environment='SYNTHETIC_GATE'", "Environment='synthetic_gate'").Replace("Mode='Auto'", "Mode='auto'").Replace("PermissionSource='None'", "PermissionSource='none'").Replace("PolicyType='Delta'", "PolicyType='delta'").Replace("Execution=@{Phase='Both'}", "Execution=@{Phase='both'}; Cloud=@{MailboxCheckVia='exo'}") }
        }
    }
    AfterAll {
        foreach ($name in @('Use-Context313h', 'Set-LowerConfig313h')) { Remove-Item -LiteralPath ('Function:\' + $name) -ErrorAction SilentlyContinue }
    }
    It 'reads every enumerated configuration value in any letter case and keeps the official spelling' {
        $runtime = New-GateRuntime -Name 'config-case-313h'
        Set-LowerConfig313h $runtime
        $config = Import-PraConfiguration -Path $runtime.ConfigPath -Root $runtime.Package -DeferScopeCheck
        $config.Scope.Mode | Should -BeExactly 'Auto'
        $config.SharedMailbox.PermissionSource | Should -BeExactly 'None'
        $config.EntraConnect.PolicyType | Should -BeExactly 'Delta'
        $config.Cloud.MailboxCheckVia | Should -BeExactly 'Exo'
        $config.Execution.Phase | Should -BeExactly 'Both'
        $config.Environment | Should -BeExactly 'synthetic_gate'
        $override = Import-PraConfiguration -Path $runtime.ConfigPath -Root $runtime.Package -ScopeOverride @{ mode = 'group'; groupdn = 'pra-wave1' } -DeferScopeCheck
        $override.Scope.Mode | Should -BeExactly 'Group'
        $override.Scope.GroupDN | Should -BeExactly 'pra-wave1'
        Set-GateConfigText $runtime { param($t) $t.Replace("Mode='auto'", "Mode='autox'") }
        { Import-PraConfiguration -Path $runtime.ConfigPath -Root $runtime.Package -DeferScopeCheck } | Should -Throw '*Scope.Mode must be Auto, OU, Group or Csv*'
    }
    It 'a Convert typed and configured in lower case (-Action, -Mode, Environment, Scope.Mode, Execution.Phase, ...) runs to the end' {
        $runtime = New-GateRuntime -Name 'main-lower-313h'
        Set-LowerConfig313h $runtime
        $run = Invoke-GateProcess $runtime @{Action='convert';Mode='apply';Force=$true;ConfigPath=$runtime.ConfigPath} -TimeoutSeconds 120
        $run.ExitCode | Should -BeIn @(0, 2) -Because ($run.Output + $run.Error)
        @($run.MainResult.Issues).Count | Should -Be 0
        $run.MainResult.ErrorCount | Should -Be 0
        $run.MainResult.Phase | Should -BeExactly 'Both'
        @(Get-GateWrites $runtime).Count | Should -BeGreaterThan 0
    }
    It 'accepts every ValidateSet parameter in lower case: -Scope, -Expect, -Phase, -Mode, -Action' {
        $runtime = New-GateRuntime -Name 'validate-lower-313h'
        $scope = Invoke-GateProcess $runtime @{Action='convert';Phase='ad';Mode='preview';Scope='usersonly';ConfigPath=$runtime.ConfigPath} -TimeoutSeconds 120
        $scope.ExitCode | Should -Be 0 -Because ($scope.Output + $scope.Error)
        $scope.Output | Should -MatchExactly 'users only'
        foreach ($expect in @('provisioned', 'deprovisioned', 'RETAINED')) {
            $check = Invoke-GateProcess $runtime @{Action='check';Identity='user1';Expect=$expect;ConfigPath=$runtime.ConfigPath} -TimeoutSeconds 120
            $check.ExitCode | Should -BeIn @(0, 2) -Because ($check.Output + $check.Error)
            $check.Output | Should -MatchExactly ('expect ' + [regex]::Escape((Get-Culture).TextInfo.ToTitleCase($expect.ToLowerInvariant())))
        }
        @(Get-GateWrites $runtime).Count | Should -Be 0
    }
    It 'reads a target CSV whose header and values are written in another case' {
        $runtime = New-GateRuntime -Name 'csv-case-313h'
        $csv = Join-Path $runtime.Root 'targets.csv'
        [IO.File]::WriteAllText($csv, "IDENTITY;Other`r`nUSER1;x`r`nUSER2@GATE.INVALID;y`r`n", (New-Object Text.UTF8Encoding($true)))
        (@(Read-PraTargetCsv -Path $csv) | ForEach-Object Identity) -join '|' | Should -BeExactly 'USER1|USER2@GATE.INVALID'
        [IO.File]::WriteAllText($csv, "`"identity`",Other`r`nUser1,x`r`n", (New-Object Text.UTF8Encoding($true)))
        (@(Read-PraTargetCsv -Path $csv) | ForEach-Object Identity) -join '|' | Should -BeExactly 'User1'
        [IO.File]::WriteAllText($csv, "IDENTITY;Other`r`nUSER1;x`r`nUSER2@GATE.INVALID;y`r`n", (New-Object Text.UTF8Encoding($true)))
        $context = Use-Context313h $runtime
        $context.Config.Scope.Mode = 'csv'; $context.Config.Scope.CsvPath = $csv; $context.Config.Scope.SearchBase = ''
        @(Get-PraTarget -Context $context | ForEach-Object SamAccountName | Sort-Object) -join ',' | Should -BeExactly 'user1,user2'
        $run = Invoke-GateProcess $runtime @{Action='convert';Phase='ad';Mode='preview';CsvPath=$csv;ConfigPath=$runtime.ConfigPath} -TimeoutSeconds 120
        $run.ExitCode | Should -Be 0 -Because ($run.Output + $run.Error)
        $run.Output | Should -Match 'user1'
        $run.Output | Should -Match 'user2'
        @(Get-GateWrites $runtime).Count | Should -Be 0
    }
    It 'an exclusion typed in another case excludes the account' {
        $runtime = New-GateRuntime -Name 'exclude-case-313h'
        $csv = Join-Path $runtime.Root 'targets.csv'
        [IO.File]::WriteAllText($csv, "Identity`r`nuser1`r`nuser2`r`n", (New-Object Text.UTF8Encoding($true)))
        $context = Use-Context313h $runtime
        $context.Config.Scope.Mode = 'CSV'; $context.Config.Scope.CsvPath = $csv; $context.Config.Scope.SearchBase = ''
        $context.Config.Scope.ExcludeSamAccountNames = @('USER2')
        { Get-PraTarget -Context $context } | Should -Throw '*Explicit target not eligible*excluded: user2*'
    }
    It 'a batch typed with an upper-case id, and a package named in another case, are found and verified (two servers, real main)' {
        $adRuntime = New-GateRuntime -Name 'pkg-case-313h-ad'
        $run = Invoke-GateProcess $adRuntime @{Action='Convert';Phase='AD';Mode='Apply';Force=$true;ConfigPath=$adRuntime.ConfigPath} -TimeoutSeconds 120
        $run.ExitCode | Should -BeIn @(0, 2) -Because ($run.Output + $run.Error)
        $zip = [string]$run.MainResult.TransferPackage
        Test-Path -LiteralPath $zip -PathType Leaf | Should -BeTrue
        $short = [regex]::Match([IO.Path]::GetFileName($zip), '-([0-9a-f]{8})-for-Cloud\.zip$').Groups[1].Value
        $short.Length | Should -Be 8
        # The AD server: the short id in upper case, one object by its sAMAccountName in upper case.
        $recover = Invoke-GateProcess $adRuntime @{Action='recover';Phase='ad';Mode='preview';Batch=$short.ToUpperInvariant();Identity='USER1';ConfigPath=$adRuntime.ConfigPath} -TimeoutSeconds 120
        $recover.ExitCode | Should -Be 0 -Because ($recover.Output + $recover.Error)
        $recover.Output | Should -Match 'user1'
        # The cloud server: the file is named in capitals on disk, its checksum file too, the configuration writes the Environment in lower case.
        $cloud = New-GateRuntime -Name 'pkg-case-313h-cloud'
        Set-GateConfigText $cloud { param($t) $t.Replace("Environment='SYNTHETIC_GATE'", "Environment='synthetic_gate'") }
        $inbox = Join-Path $cloud.State.BackupFolder 'Inbox'; $null = New-Item -ItemType Directory -Path $inbox
        $onDisk = [IO.Path]::GetFileName($zip).ToUpperInvariant().Replace('.ZIP', '.zip')
        Copy-Item -LiteralPath $zip -Destination (Join-Path $inbox $onDisk)
        [IO.File]::WriteAllText((Join-Path $inbox ($onDisk + '.SHA256')), (Get-Content -LiteralPath ($zip + '.sha256') -Raw).Trim().ToUpperInvariant())
        $typed = [IO.Path]::GetFileName($zip).ToLowerInvariant()
        $second = Invoke-GateProcess $cloud @{Action='convert';Phase='cloud';Mode='apply';Force=$true;ConfigPath=$cloud.ConfigPath;Batch=$typed} -TimeoutSeconds 120
        (@($second.MainResult.Issues | ForEach-Object { [string]$_.Message }) -join ' ') | Should -Not -Match 'Transfer package|does not match|AD proof|Environment'
        $second.ExitCode | Should -BeIn @(0, 2) -Because ($second.Output + $second.Error)
        $second.Output | Should -Match 'Transfer package .* verified'
        @($second.Events | Where-Object Operation -eq 'CloudPhase-SyntheticBarrier').Count | Should -Be 1
        # The batch is now in the backup folder of the cloud server: its id in upper case finds it.
        $again = Invoke-GateProcess $cloud @{Action='CONVERT';Phase='CLOUD';Mode='PREVIEW';ConfigPath=$cloud.ConfigPath;Batch=$short.ToUpperInvariant()} -TimeoutSeconds 120
        $again.ExitCode | Should -BeIn @(0, 2) -Because ($again.Output + $again.Error)
        (@($again.MainResult.Issues | ForEach-Object { [string]$_.Message }) -join ' ') | Should -Not -Match 'not found|ambiguous|Invalid batch'
        @(Get-GateWrites $cloud).Count | Should -Be 0
    }
    It 'compares proxy addresses by their address part and keeps the primary flag in the case of the type prefix' {
        $result = InModuleScope PRA.Directory {
            $state = { param($values) @{ Present = $true; Kind = 'MultiString'; Value = [string[]]$values } }
            $reference = & $state @('SMTP:Alice@Contoso.com', 'smtp:alice.a@contoso.com', 'X500:/o=Org/cn=Alice')
            $recased = & $state @('SMTP:alice@contoso.COM', 'smtp:ALICE.A@contoso.com', 'x500:/O=ORG/CN=ALICE')
            $demoted = & $state @('smtp:Alice@Contoso.com', 'smtp:alice.a@contoso.com', 'X500:/o=Org/cn=Alice')
            $added = & $state @('SMTP:ALICE@CONTOSO.COM', 'smtp:alice.a@contoso.com', 'X500:/O=Org/CN=Alice', 'x500:/o=org/cn=New', 'X500:/O=ORG/CN=NEW')
            $removed = & $state @('SMTP:Alice@Contoso.com', 'smtp:alice.a@contoso.com')
            $context = @{ Config = @{ Routing = @{ RoutingDomain = 'CONTOSO.mail.onmicrosoft.COM'; AutoDetect = $true } } }
            $proxies = @('smtp:Alice@contoso.com', 'smtp:bob@contoso.com', 'smtp:ALICE@CONTOSO.MAIL.ONMICROSOFT.COM', 'smtp:bob@contoso.mail.onmicrosoft.com')
            $primaryAlice = [pscustomobject]@{ SamAccountName = 'bob'; mail = 'bob@contoso.com'; mailNickname = 'bob'; proxyAddresses = @('SMTP:Alice@contoso.com') + $proxies[1..3] }
            $noPrimary = [pscustomobject]@{ SamAccountName = 'bob'; mail = 'bob@contoso.com'; mailNickname = 'bob'; proxyAddresses = $proxies }
            [pscustomobject]@{
                Recased = (Get-PraX500Difference $recased $reference)
                Demoted = (Get-PraX500Difference $demoted $reference)
                Added = (Get-PraX500Difference $added $reference)
                Removed = (Get-PraX500Difference $removed $reference)
                RoutingFromPrimary = (Get-PraRoutingAddress $context $primaryAlice)
                RoutingWithoutPrimary = (Get-PraRoutingAddress $context $noPrimary)
                Expected = @(Get-PraExpectedX500 -LegacyExchangeDN '/o=Org/cn=Alice' -ProxyAddresses @('x500:/O=ORG/CN=ALICE', 'X500:/o=org/cn=older', 'SMTP:a@b.com'))
                Key = @('SMTP:Alice@Contoso.COM', 'smtp:Alice@Contoso.COM', 'noprefix' | ForEach-Object { Get-PraProxyAddressKey $_ })
            }
        }
        $result.Recased.OtherEqual | Should -BeTrue
        @($result.Recased.Added).Count | Should -Be 0
        @($result.Recased.Removed).Count | Should -Be 0
        $result.Demoted.OtherEqual | Should -BeFalse -Because 'SMTP: (primary) becoming smtp: is a difference'
        $result.Added.OtherEqual | Should -BeTrue
        @($result.Added.Added) | Should -Be @('x500:/o=org/cn=New')
        @($result.Added.Removed).Count | Should -Be 0
        $result.Removed.OtherEqual | Should -BeTrue
        @($result.Removed.Removed) | Should -Be @('X500:/o=Org/cn=Alice')
        $result.RoutingFromPrimary | Should -BeExactly 'ALICE@CONTOSO.MAIL.ONMICROSOFT.COM' -Because 'the SMTP: entry is the primary address: its local part chooses the routing address'
        $result.RoutingWithoutPrimary | Should -BeExactly 'bob@contoso.mail.onmicrosoft.com' -Because 'no entry has the SMTP: prefix: the mail attribute chooses'
        @($result.Expected) | Should -Be @('X500:/o=Org/cn=Alice', 'X500:/o=org/cn=older')
        @($result.Key) | Should -Be @('SMTP:alice@contoso.com', 'smtp:alice@contoso.com', 'noprefix')
        $found = Compare-PraX500Address -Expected @('X500:/o=A/cn=Bob', 'X500:/o=A/cn=Carl') -Actual @('x500:/O=A/CN=BOB', 'SMTP:x@y.com')
        @($found.Present) | Should -Be @('X500:/o=A/cn=Bob')
        @($found.Missing) | Should -Be @('X500:/o=A/cn=Carl')
    }
}
AfterAll {
    $env:PSModulePath=$global:PraGate.OriginalModulePath
    $env:PRA_GATE_NONET=$global:PraGate.OriginalNonet
    $env:PRA_GATE_STATE=$global:PraGate.OriginalState
    Remove-Module ActiveDirectory,ADSync,PRA.Directory,PRA.Backup,PRA.Common,PRA.Gui -Force -ErrorAction SilentlyContinue
    if ($env:PRA_GATE_EVIDENCE) {
        [IO.File]::WriteAllText((Join-Path $env:PRA_GATE_EVIDENCE 'fixture-provenance.txt'),"SYNTHETIC ONLY. AD and ADSync from temporary PSModulePath; production main/Common/Directory copied unchanged. Main Cloud replaced by declared synthetic barrier. No real AD/EXO/Graph/ADSync executed. Temporary fixture root: $($global:PraGate.Root)")
    }
    if ([IO.Directory]::Exists($global:PraGate.Root)) { [IO.Directory]::Delete($global:PraGate.Root,$true) }
    foreach ($name in @('New-GateUser','New-GateRuntime','New-GateContext','Get-GateEvents','Set-GateConfigText','Get-GateWrites','Save-GateDeltaEvidence','Invoke-GateProcess','New-GateSourceBundles','Get-GateCodec','Get-GateExpectedNodes','Assert-GateWireSnapshot','Save-GateOomEvidence')) { Remove-Item -LiteralPath ('Function:\'+$name) -ErrorAction SilentlyContinue }
    Remove-Variable PraGateAd,PraGate -Scope Global -ErrorAction SilentlyContinue
}
