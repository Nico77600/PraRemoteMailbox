<#
.SYNOPSIS
    PRA Remote Mailbox - Exchange Online and Microsoft Graph adapter (no AD read or write).

.DESCRIPTION
    Public functions (no pipeline output; result rows are updated in place; an error sets the row to
    Error and records a run error, or throws):

      Initialize-PraCloudPreflight  Convert, Apply, phase Both: sign-in, targets and trustees resolved
                                    in Exchange Online BEFORE the AD part (read only)
      Invoke-PraCloudPhase          checks (and waits for) the expected cloud state of every row and, in
                                    Apply, grants the shared mailbox permissions
      Invoke-PraRetentionCheck      Check -Expect Retained: retention policy holds (read only)
      Close-PraCloudSession         signs out the sessions opened by this module (idempotent)

    Expected cloud states:
      Convert  user: mailbox provisioned (Exchange Online type, or Graph provisioning) and a licence
               with Exchange enabled; shared: SharedMailbox, then every FullAccess, SendAs and
               SendOnBehalf permission present.
      Recover  mailbox gone and recipient back to MailUser (DeprovisionConfirmed = true); licence
               removed unless the user was already in the licence group. KeepCloudShared: the shared
               mailbox must still exist (never a deprovisioning confirmation).
    DeprovisionConfirmed becomes true ONLY after these checks; the entry script requires it before any
    final restore. A cloud error is never taken as "absent".

    Writes (Convert, Apply, phase Cloud or Both): each permission grant needs the operator approval,
    a fresh check of the AD proof, a journal line "Started", ONE Add call, a journal line "Applied",
    bounded re-reads (Exo.GrantVerifyAttempts x Exo.GrantVerifyDelaySeconds) and a line "Verified".
    A grant is never retried.

    Sessions: Microsoft Graph is connected before Exchange Online (assembly conflicts in Windows
    PowerShell 5.1); an Exchange Online or Graph session that already exists in the console is refused;
    tenant, token, connection ID and module path are checked before each call. Exo.UseSubprocess (or
    an ExchangeOnlineManagement older than Exo.MinModuleVersion) runs every Exchange Online call in a
    child Windows PowerShell (certificate sign-in only).

.NOTES
    Author  : Nicolas Fabert
    Version : 2.0.1
#>
#Requires -Version 5.1
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# Fixed worker body, also run in the child process: no code or cmdlet name ever comes from data.
$script:PraExoWorker = {
    param([ValidateSet('Probe','Preflight','Mailbox','Recipient','Hold','Permission','Grant')][string]$Operation,$P,$Permit,$SessionBinding,$OnApplied)
    Set-StrictMode -Version Latest
    $ErrorActionPreference = 'Stop'
    function V {
        param($Object,[string]$Name,$Default=$null)
        if ($null -ne $Object) {
            if ($Object -is [System.Collections.IDictionary]) {
                if ($Object.Contains($Name)) { return ,($Object[$Name]) }
            } elseif ($null -ne $Object.PSObject.Properties[$Name]) { return ,($Object.PSObject.Properties[$Name].Value) }
        }
        return ,$Default
    }
    function Session {
        param([string]$Right='')
        $tenant=[string](V $SessionBinding 'TenantId' (V $P 'TenantId' ''))
        $parsed=[guid]::Empty
        if (-not [guid]::TryParse($tenant,[ref]$parsed) -or $parsed -eq [guid]::Empty) { throw 'Expected Exchange Online tenant missing or invalid (Cloud.TenantId).' }
        $organization=[string](V $SessionBinding 'Organization' (V $P 'Organization' ''))
        $appId=[string](V $SessionBinding 'AppId' (V $P 'AppId' ''))
        $connections=@(Get-ConnectionInformation -ErrorAction Stop)
        if ($connections.Count -ne 1) { throw 'Exactly one Exchange Online connection is expected in this process.' }
        $c=$connections[0]; $location=[string](V $c 'ModuleName' ''); $id=[string](V $c 'ConnectionId' '')
        # Interactive sign-in reports the tenant GUID; certificate (app-only) sign-in reports the
        # organisation domain (tenant.onmicrosoft.com) and the AppId: both are accepted, nothing else.
        $sessionTenant=[string](V $c 'TenantID' '')
        $tenantOk=($sessionTenant -eq $tenant) -or ($organization -and $sessionTenant -eq $organization)
        if ($appId -and [string](V $c 'AppId' '') -ne $appId) { $tenantOk=$false }
        if (-not $tenantOk -or [string](V $c 'State' '') -ne 'Connected' -or
            [string](V $c 'TokenStatus' '') -ne 'Active' -or -not $id -or -not [IO.Path]::IsPathRooted($location)) {
            throw ("Exchange Online session: wrong tenant ({0}), state, token, connection ID or module path." -f $sessionTenant)
        }
        $modules=@(Get-Module | Where-Object { $_.ModuleBase -eq $location -or $_.Path -eq $location })
        if ($modules.Count -ne 1 -or -not $modules[0].Path) { throw 'Module of the Exchange Online session not found or ambiguous.' }
        if ($null -ne $SessionBinding -and (V $SessionBinding 'ConnectionId' '')) {
            if ($id -ne (V $SessionBinding 'ConnectionId') -or $location -ne (V $SessionBinding 'ModuleLocation') -or
                $modules[0].Path -ne (V $SessionBinding 'ModulePath')) { throw 'The Exchange Online session changed.' }
        }
        $command=$null
        if ($Right) {
            $name=switch ($Right) { 'FullAccess' { 'Add-MailboxPermission' }; 'SendAs' { 'Add-RecipientPermission' }; 'SendOnBehalf' { 'Set-Mailbox' }; default { throw 'Unknown permission.' } }
            $commands=@(Get-Command -Name $name -Module $modules[0].Name -All -ErrorAction Stop)
            if ($commands.Count -ne 1 -or $null -eq $commands[0].Module -or $commands[0].Module.Path -ne $modules[0].Path) {
                throw "Command $name is not from the module of the Exchange Online session."
            }
            $command=$commands[0]
        }
        return @{ TenantId=$tenant; Organization=$organization; AppId=$appId; ConnectionId=$id; ModuleLocation=$location; ModulePath=$modules[0].Path; Command=$command }
    }
    function ExactFilter {
        param([string]$Upn)
        if ([string]::IsNullOrWhiteSpace($Upn) -or $Upn -match '[\r\n\x00]') { throw 'Empty or invalid UPN.' }
        return "UserPrincipalName -eq '$($Upn.Replace("'","''"))'"
    }
    function MissingRecipient {
        param([System.Management.Automation.ErrorRecord]$Record,[string]$Upn)
        # A selector read (-UserPrincipalName) answers an absent object with HTTP 404 ManagementObjectNotFoundException
        # instead of an empty result (seen in the lab while a deprovisioned mailbox turns into a MailUser).
        $text=$Record.Exception.Message
        if ($text -notmatch 'HttpStatusCode=404') { return $false }
        $json=[regex]::Match($text,'(?s)\{\s*"error"\s*:\s*\{.*\}\s*\}')
        if (-not $json.Success) { return $false }
        try {
            $payload=$json.Value | ConvertFrom-Json -ErrorAction Stop
            $object="object '"+[WildcardPattern]::Escape($Upn)+"' couldn't be found"
            $detail=@($payload.error.details | Where-Object { [string]$_.message -like '*|Microsoft.Exchange.Configuration.Tasks.ManagementObjectNotFoundException|*' })
            return ($payload.error.code -ceq 'NotFound' -and [string]$payload.error.message -like "*$object*" -and $detail.Count -gt 0 -and [string]$detail[0].message -like "*$object*")
        } catch { return $false }
    }
    function Recipient {
        param([string]$Upn)
        if ([string]::IsNullOrWhiteSpace($Upn) -or $Upn -match '[\r\n\x00]') { throw 'Empty or invalid UPN.' }
        # Recipient exposes a dedicated UPN selector, not a UserPrincipalName output/filter property.
        # "Not found" is read through -ErrorVariable (no transcript error line); any other error stops.
        $recipientErrors=$null
        try { $items = @(Get-EXORecipient -UserPrincipalName $Upn -Properties RecipientTypeDetails,PrimarySmtpAddress,ExternalDirectoryObjectId,Guid,DistinguishedName -ResultSize Unlimited -ErrorAction SilentlyContinue -ErrorVariable recipientErrors -WarningAction Stop) }
        catch { if (-not (MissingRecipient $_ $Upn)) { throw }; $items=@(); $recipientErrors=@($_) }
        $recipientErrors=@($recipientErrors | Where-Object { $null -ne $_ })
        if ($recipientErrors.Count) {
            foreach ($record in $recipientErrors) {
                if ($record -isnot [System.Management.Automation.ErrorRecord] -or -not (MissingRecipient $record $Upn)) { throw $record }
            }
            if ($items.Count) { throw "Exchange Online returned a recipient and 'not found' for: $Upn" }
            return @{ Found=$false; Type=$null; Keys=@() }
        }
        if ($items.Count -gt 1) { throw "Exchange Online recipient not unique: $Upn" }
        if ($items.Count -eq 0) { return @{ Found=$false; Type=$null; Keys=@() } }
        $type = [string](V $items[0] 'RecipientTypeDetails')
        if (-not $type) { throw "Recipient type not returned: $Upn" }
        $oid=[string](V $items[0] 'ExternalDirectoryObjectId' ''); $smtp=[string](V $items[0] 'PrimarySmtpAddress' '')
        $parsed=[guid]::Empty
        if (-not [guid]::TryParse($oid,[ref]$parsed) -or $parsed -eq [guid]::Empty -or [string]::IsNullOrWhiteSpace($smtp)) { throw "Recipient identity incomplete: $Upn" }
        $expected=V (V $P 'ExpectedIdentities' @{}) $Upn
        if ($null -ne $expected -and ($oid -ne (V $expected 'ObjectId') -or $smtp -ne (V $expected 'PrimarySmtpAddress'))) { throw "Recipient identity changed since the pre-check: $Upn" }
        $keys = @($Upn) + @(foreach ($key in @('UserPrincipalName','PrimarySmtpAddress','ExternalDirectoryObjectId','Guid','DistinguishedName','Identity','Alias','Name','DisplayName','Sid','SamAccountName')) {
            $val = [string](V $items[0] $key); if (-not [string]::IsNullOrWhiteSpace($val)) { $val }
        })
        return @{ Found=$true; Type=$type; Keys=@($keys | Select-Object -Unique); ObjectId=$oid; PrimarySmtpAddress=$smtp }
    }
    function Mailbox {
        param([string]$Upn,[switch]$Hold)
        $grantParameters = @{ Filter=(ExactFilter $Upn); Properties=@('RecipientTypeDetails'); ResultSize='Unlimited' }
        if ($Hold) { $grantParameters.Properties += @('IsInactiveMailbox','InPlaceHolds','LitigationHoldEnabled','RetentionHoldEnabled') }
        $items = @(Get-EXOMailbox @grantParameters -ErrorAction Stop)
        if ($Hold -and $items.Count -eq 0) { $items = @(Get-EXOMailbox @grantParameters -InactiveMailboxOnly -ErrorAction Stop) }
        if ($items.Count -gt 1) { throw "Exchange Online mailbox not unique: $Upn" }
        if ($items.Count -eq 0) { return @{ Found=$false; Type=$null; Holds=@(); IsInactive=$false; Litigation=$false; RetentionHold=$false } }
        $m = $items[0]; $type = [string](V $m 'RecipientTypeDetails')
        if (-not $type) { throw "Mailbox type not returned: $Upn" }
        $holds = V -Object $m -Name 'InPlaceHolds' -Default @()
        return @{ Found=$true; Type=$type; Holds=@($holds | Where-Object { $null -ne $_ }); IsInactive=[bool](V -Object $m -Name 'IsInactiveMailbox' -Default $false)
            Litigation=[bool](V -Object $m -Name 'LitigationHoldEnabled' -Default $false); RetentionHold=[bool](V -Object $m -Name 'RetentionHoldEnabled' -Default $false) }
    }
    function NormalizeAcl {
        param([object[]]$Entries,[string]$Right,$Target)
        $field=if ($Right -eq 'FullAccess') { 'User' } else { 'Trustee' }
        foreach ($entry in $Entries) {
            foreach ($key in @('Identity',$field,'AccessRights','IsInherited')) {
                if ($null -eq (V $entry $key)) { throw "$Right permission entry: field $key missing or null" }
            }
            $identity=[string](V $entry 'Identity'); $principal=[string](V $entry $field)
            $inherited=V $entry 'IsInherited'; $rawRights=V $entry 'AccessRights'; $rawRights=@($rawRights)
            if ($identity -notin $Target.Keys -or [string]::IsNullOrWhiteSpace($principal) -or $inherited -isnot [bool] -or $rawRights.Count -eq 0) { throw "Unexpected $Right permission entry (format or identity)." }
            $rights=@(foreach ($access in $rawRights) {
                if (($access -isnot [string] -and $access -isnot [enum]) -or [string]::IsNullOrWhiteSpace([string]$access)) { throw "Invalid $Right access right type." }
                [string]$access
            })
            if ($Right -eq 'FullAccess') {
                $deny=V $entry 'Deny'
                if ($deny -is [System.Management.Automation.SwitchParameter]) { $deny=$deny.IsPresent }
                if ($deny -isnot [bool]) { throw 'Invalid FullAccess Deny value.' }
                $control=if ($deny) { 'Deny' } else { 'Allow' }
            } else {
                $rawControl=V $entry 'AccessControlType'
                if ($rawControl -isnot [string] -and $rawControl -isnot [enum]) { throw 'Invalid AccessControlType type.' }
                $control=[string]$rawControl
                if ($control -notin @('Allow','Deny')) { throw 'Invalid AccessControlType value.' }
            }
            if ($control -eq 'Deny' -and $Right -in $rights) { throw "A $Right Deny entry exists: grant refused." }
            [pscustomobject]@{ Identity=$identity; Principal=$principal; Rights=$rights; Control=$control; Inherited=$inherited }
        }
    }
    function AclKey {
        param($Entry)
        return ($Entry.Principal+'|'+$Entry.Control+'|'+$Entry.Inherited+'|'+(($Entry.Rights | ForEach-Object { $_.ToLowerInvariant() } | Sort-Object) -join ',')).ToLowerInvariant()
    }
    function MissingFullAccess {
        param([System.Management.Automation.ErrorRecord]$Record,[string]$Trustee)
        $json=[regex]::Match($Record.Exception.Message,'(?s)\{\s*"error"\s*:\s*\{.*\}\s*\}')
        if (-not $json.Success) { return $false }
        try {
            $payload=$json.Value | ConvertFrom-Json -ErrorAction Stop
            $expected='No permissions were found for the user:'+$Trustee
            return ($payload.error.code -ceq 'NotFound' -and $payload.error.message -ceq $expected -and
                $payload.error.innererror.message -ceq $expected -and $payload.error.innererror.type -ceq 'Microsoft.Exchange.Admin.OData.Core.ODataServiceException')
        } catch { return $false }
    }
    function Permission {
        param([string]$Upn,[string]$Trustee,[string]$Right,$Recipient,$Target,[switch]$AllowPendingVisibility)
        if ($Right -in @('FullAccess','SendAs')) {
            $globalRaw=@(if ($Right -eq 'FullAccess') { Get-EXOMailboxPermission -Identity $Upn -ErrorAction Stop -WarningAction Stop }
                else { Get-EXORecipientPermission -Identity $Upn -ErrorAction Stop -WarningAction Stop })
            if ($globalRaw.Count -eq 0 -or $globalRaw.Count -ge 1000) { throw "$Right permission list empty or possibly truncated." }
            $globalEntries=@(NormalizeAcl $globalRaw $Right $Target)
            if (-not @($globalEntries | Where-Object { $_.Principal -in @('NT AUTHORITY\SELF','S-1-5-10') -and $Right -in $_.Rights -and -not $_.Inherited }).Count) { throw "$Right permission list without the expected SELF entry." }
            $expectedEntries=@($globalEntries | Where-Object { $Right -in $_.Rights -and $_.Principal -in $Recipient.Keys })
            # "No permissions were found" is the normal answer before a grant. It is read through -ErrorVariable,
            # not -ErrorAction Stop, so that Windows PowerShell does not write it as an error in the transcript.
            # Every error record is still checked: anything else than that exact answer stops, as before.
            $filteredErrors=$null
            $filteredRaw=@(if ($Right -eq 'FullAccess') { Get-EXOMailboxPermission -Identity $Upn -User $Trustee -ErrorAction SilentlyContinue -ErrorVariable filteredErrors -WarningAction Stop }
                else { Get-EXORecipientPermission -Identity $Upn -Trustee $Trustee -ErrorAction Stop -WarningAction Stop })
            $filteredErrors=@($filteredErrors | Where-Object { $null -ne $_ })
            if ($filteredErrors.Count) {
                foreach ($record in $filteredErrors) {
                    if ($record -isnot [System.Management.Automation.ErrorRecord] -or -not (MissingFullAccess $record $Trustee)) { throw $record }
                }
                if ($expectedEntries.Count -gt 0) { if ($AllowPendingVisibility) { return $false }; throw $filteredErrors[0] }
                $filteredRaw=@()
            }
            $entries=@(NormalizeAcl $filteredRaw $Right $Target)
            foreach ($entry in $entries) { if ($entry.Principal -notin $Recipient.Keys) { throw "Filtered $Right read inconsistent for $Trustee." } }
            $actualEntries=@($entries | Where-Object { $Right -in $_.Rights })
            $expected=@($expectedEntries | ForEach-Object { AclKey $_ } | Sort-Object)
            $actual=@($actualEntries | ForEach-Object { AclKey $_ } | Sort-Object)
            if (($expected | ConvertTo-Json -Compress) -cne ($actual | ConvertTo-Json -Compress)) {
                if ($AllowPendingVisibility -and (($expected.Count -eq 0) -xor ($actual.Count -eq 0))) { return $false }
                throw "Full and filtered $Right reads disagree for $Trustee."
            }
            return (@($actualEntries | Where-Object { -not $_.Inherited -and $_.Control -eq 'Allow' }).Count -gt 0)
        }
        $mb = @(Get-Mailbox -Filter (ExactFilter $Upn) -ResultSize Unlimited -ErrorAction Stop)
        if ($mb.Count -ne 1) { throw "Mailbox not unique for the SendOnBehalf read: $Upn" }
        $delegates=V -Object $mb[0] -Name 'GrantSendOnBehalfTo' -Default @()
        foreach ($delegate in $delegates) {
            if ($null -eq $delegate) { continue }
            $ids = @([string]$delegate, [string](V $delegate 'DistinguishedName'), [string](V $delegate 'ObjectGuid'))
            if (@($ids | Where-Object { $_ -and $_ -in $Recipient.Keys }).Count) { return $true }
            # Exchange Online can return an ADObjectId as a Name: exact resolution, an ambiguity stops.
            $name = ([string]$delegate).Replace("'","''")
            $resolved = @(Get-EXORecipient -Filter "Name -eq '$name'" -Properties Guid,DistinguishedName,ExternalDirectoryObjectId -ResultSize Unlimited -ErrorAction Stop)
            if ($resolved.Count -gt 1) { throw "SendOnBehalf delegate not unique: $delegate" }
            foreach ($r in $resolved) {
                foreach ($key in @('Guid','DistinguishedName','ExternalDirectoryObjectId')) {
                    $id = [string](V $r $key); if ($id -and $id -in $Recipient.Keys) { return $true }
                }
            }
        }
        return $false
    }
    $binding=Session
    if ($Operation -eq 'Probe') { [void]$binding.Remove('Command'); return @{ Connected=$true; Binding=$binding } }
    $SessionBinding=$binding
    $upn = [string](V $P 'Upn')
    if ($Operation -eq 'Preflight') {
        $target=Recipient $upn
        if (-not $target.Found) { throw "Target not found in Exchange Online at the pre-check: $upn" }
        $identities=@{}; $identities[$upn]=$target
        $requests=V $P 'Requests' @()
        foreach ($request in @($requests)) {
            $trustee=[string](V $request 'Trustee'); $right=[string](V $request 'Right')
            $null=Session $right
            $resolved=Recipient $trustee
            if (-not $resolved.Found) { throw "Trustee not found in Exchange Online at the pre-check: $trustee" }
            if ($resolved.ObjectId -eq $target.ObjectId) { throw 'A mailbox cannot be delegated to itself.' }
            $identities[$trustee]=$resolved
        }
        return @{ Found=$true; Type=$target.Type; Identities=$identities }
    }
    switch ($Operation) {
        'Mailbox' { return (Mailbox $upn) }
        'Recipient' { return (Recipient $upn) }
        'Hold' { return (Mailbox $upn -Hold) }
    }
    $trustee = [string](V $P 'Trustee'); $right = [string](V $P 'Right')
    if ($right -notin @('FullAccess','SendAs','SendOnBehalf')) { throw 'Unknown permission.' }
    if ($Operation -eq 'Grant') {
        foreach ($flag in @('AllowMutation','Approved','Authorized','JournalStarted')) {
            $b = V -Object $Permit -Name $flag -Default $false
            if ($b -isnot [bool] -or -not $b) { throw 'Exchange Online grant without its individual authorisation.' }
        }
        if ((V $Permit 'Target') -cne $upn -or (V $Permit 'Trustee') -cne $trustee -or (V $Permit 'Right') -cne $right -or
            (V $Permit 'Action') -ne 'Convert' -or (V $Permit 'Mode') -ne 'Apply' -or (V $Permit 'Phase') -notin @('Cloud','Both')) { throw 'Exchange Online authorisation does not match this grant.' }
        if ((Mailbox $upn).Type -ne 'SharedMailbox') { throw 'Grant refused: SharedMailbox not confirmed.' }
    }
    $rcpt = Recipient $trustee
    if (-not $rcpt.Found) {
        if ($Operation -eq 'Grant') { throw "Trustee no longer in Exchange Online: $trustee" }
        return @{ TrusteeFound=$false; Verified=$false; Mutated=$false }
    }
    $target=Recipient $upn
    if (-not $target.Found) { throw "Target not found in Exchange Online: $upn" }
    if ($Operation -eq 'Grant' -and $target.Type -ne 'SharedMailbox') { throw 'Grant refused: SharedMailbox recipient not confirmed.' }
    if ($target.ObjectId -eq $rcpt.ObjectId) { throw 'A mailbox cannot be delegated to itself.' }
    $ok = Permission -Upn $upn -Trustee $trustee -Right $right -Recipient $rcpt -Target $target
    if ($Operation -eq 'Permission' -or $ok) { return @{ TrusteeFound=$true; Verified=[bool]$ok; Mutated=$false } }
    $attempts=V $P 'GrantVerifyAttempts' 13; $delay=V $P 'GrantVerifyDelaySeconds' 10
    if (($attempts -isnot [int] -and $attempts -isnot [long]) -or $attempts -lt 1 -or $attempts -gt 60 -or
        ($delay -isnot [int] -and $delay -isnot [long]) -or $delay -lt 1 -or $delay -gt 30) { throw 'Invalid Exchange Online verification cadence (1..60 reads, 1..30 seconds).' }
    if ($OnApplied -isnot [scriptblock]) { throw 'The Applied journal callback is required before an Exchange Online grant.' }
    $write=Session $right
    switch ($right) {
        'FullAccess' { & $write.Command -Identity $upn -User $trustee -AccessRights FullAccess -AutoMapping:([bool](V -Object $P -Name 'AutoMapping' -Default $false)) -InheritanceType All -Confirm:$false -ErrorAction Stop | Out-Null }
        'SendAs' { & $write.Command -Identity $upn -Trustee $trustee -AccessRights SendAs -Confirm:$false -ErrorAction Stop | Out-Null }
        'SendOnBehalf' { & $write.Command -Identity $upn -GrantSendOnBehalfTo @{ Add=$trustee } -Confirm:$false -ErrorAction Stop | Out-Null }
    }
    # Add returned. Persist this fact before any eventual-consistency read, never repeat Add.
    try {
        $null=& $OnApplied
        for ($attempt=1; $attempt -le $attempts; $attempt++) {
            $null=Session
            $currentTarget=Recipient $upn; $currentTrustee=Recipient $trustee
            foreach ($pair in @(@($target,$currentTarget),@($rcpt,$currentTrustee))) {
                if (-not $pair[1].Found -or $pair[0].ObjectId -ne $pair[1].ObjectId -or $pair[0].PrimarySmtpAddress -ne $pair[1].PrimarySmtpAddress -or $pair[0].Type -ne $pair[1].Type) { throw 'Exchange Online identity changed during the verification.' }
            }
            if ((Mailbox $upn).Type -ne 'SharedMailbox') { throw 'SharedMailbox lost during the verification.' }
            if (Permission -Upn $upn -Trustee $trustee -Right $right -Recipient $currentTrustee -Target $currentTarget -AllowPendingVisibility) {
                return @{ TrusteeFound=$true; Verified=$true; Mutated=$true; Error='' }
            }
            if ($attempt -lt $attempts) { Start-Sleep -Seconds $delay }
        }
        throw "$right added but not verified after $attempts reads: $upn / $trustee"
    } catch { return @{ TrusteeFound=$true; Verified=$false; Mutated=$true; Error=('Add returned, verification failed: '+$_.Exception.Message) } }
}

function Get-PraCloudSession {
    param([hashtable]$Context)
    if (-not $Context.ContainsKey('_PraCloudSession')) {
        $Context['_PraCloudSession'] = @{ GraphAttempted=$false; ExoAttempted=$false; Graph=$false; Exo=$false; Subprocess=$false
            Binding=$null; OwnedExoIds=@(); GraphContext=$null; Identities=@{}; Preflight=$false }
    }
    return $Context['_PraCloudSession']
}

function Write-PraCloudError {
    param([hashtable]$Context,$Row,[string]$Message)
    if ($null -ne $Row) {
        $Row.CloudStatus='Error'; $Row.FinalStatus='Error'; $Row.CloudDetail=$Message
        if ($null -ne $Row.PSObject.Properties['DeprovisionConfirmed']) { $Row.DeprovisionConfirmed=$false }
        $Row.Detail = ([string](Get-PraValue $Row 'Detail' '') + ' | cloud: ' + $Message).Trim(' ','|')
        $Context.CurrentIdentity=[string](Get-PraValue $Row 'ObjectGuid' (Get-PraValue $Row 'UserPrincipalName' ''))
    }
    # Recorded here, whatever the logger does with Issues.
    [void]$Context.Issues.Add([pscustomobject]@{ Timestamp=(Get-Date).ToString('o'); Phase=$Context.CurrentPhase
        Source='Cloud'; Operation=$Context.CurrentOperation; Identity=$Context.CurrentIdentity; Message=$Message })
    $null = Write-PraLog -Context $Context -Message $Message -Level Warning
}

function Invoke-PraExoSubprocess {
    param([hashtable]$Context,[string]$Operation,[hashtable]$Params,$Permit,$OnApplied)
    $cloud = Get-PraValue $Context.Config 'Cloud' @{}
    $id = [guid]::NewGuid().ToString('N')
    $appliedPath=Join-Path ([IO.Path]::GetTempPath()) ('praexo_'+$id+'.applied.json')
    $request = @{ Protocol=1; Id=$id; Operation=$Operation; Params=$Params; Permit=$Permit; AppliedPath=$appliedPath
        TenantId=(Get-PraValue $cloud 'TenantId' ''); DisableWAM=(Get-PraValue (Get-PraValue $Context.Config 'Exo' @{}) 'DisableWAM' $false)
        AppId=(Get-PraValue $cloud 'AppId' ''); Thumb=(Get-PraValue $cloud 'CertificateThumbprint' ''); Org=(Get-PraValue $cloud 'Organization' '') }
    $b64 = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes(($request | ConvertTo-Json -Depth 12 -Compress)))
    $child = @'
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
[Console]::OutputEncoding = New-Object Text.UTF8Encoding($false)
$ProgressPreference='SilentlyContinue'
$cfg=$null; $data=$null; $failure=''; $attempted=$false; $ownedIds=@()
try {
    $cfg = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('__REQUEST__')) | ConvertFrom-Json -ErrorAction Stop
    if ($cfg.Protocol -ne 1 -or $cfg.Id -notmatch '^[a-f0-9]{32}$') { throw 'Invalid Exchange Online request.' }
    Import-Module ExchangeOnlineManagement -ErrorAction Stop
    if (@(Get-ConnectionInformation -ErrorAction Stop).Count) { throw 'The Exchange Online child process is not clean.' }
    $connect=@{ AppId=$cfg.AppId; CertificateThumbprint=$cfg.Thumb; Organization=$cfg.Org; ShowBanner=$false; ErrorAction='Stop' }
    if ($cfg.DisableWAM) {
        if (-not (Get-Command Connect-ExchangeOnline -ErrorAction Stop).Parameters.ContainsKey('DisableWAM')) { throw 'DisableWAM is not supported by this ExchangeOnlineManagement.' }
        $connect.DisableWAM=$true
    }
    $attempted=$true
    try { Connect-ExchangeOnline @connect | Out-Null }
    finally { $ownedIds=@(Get-ConnectionInformation -ErrorAction Stop | ForEach-Object { [string]$_.ConnectionId }) }
    $worker = {
__WORKER__
    }
    $probe=& $worker 'Probe' @{ TenantId=$cfg.TenantId; Organization=$cfg.Org; AppId=$cfg.AppId } $null $null $null
    $onApplied={
        $text=@{ Protocol=1; Id=$cfg.Id; Status='Applied'; Target=$cfg.Params.Upn; Trustee=$cfg.Params.Trustee; Right=$cfg.Params.Right } | ConvertTo-Json -Compress
        $stream=New-Object IO.FileStream($cfg.AppliedPath,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
        try { $bytes=[Text.Encoding]::UTF8.GetBytes($text); $stream.Write($bytes,0,$bytes.Length); $stream.Flush($true) } finally { $stream.Dispose() }
    }
    $results = @(& $worker $cfg.Operation $cfg.Params $cfg.Permit $probe.Binding $onApplied)
    if ($results.Count -ne 1) { throw 'Exchange Online result not unique.' }
    $data=$results[0]
} catch { $failure=$_.Exception.Message }
finally {
    if ($attempted) {
        try {
            foreach ($ownedId in $ownedIds) {
                if (-not $ownedId) { throw 'Own connection ID missing: a global sign-out is not allowed.' }
                Disconnect-ExchangeOnline -ConnectionId $ownedId -Confirm:$false -ErrorAction Stop 6>$null | Out-Null
            }
        }
        catch { $failure += ' | Exchange Online sign-out: ' + $_.Exception.Message }
    }
}
$correlation = if ($null -ne $cfg) { $cfg.Id } else { '' }
[Console]::Out.WriteLine(([ordered]@{ Protocol=1; Id=$correlation; Ok=($failure -eq ''); Data=$data; Error=$failure } | ConvertTo-Json -Depth 12 -Compress))
if ($failure) { exit 1 }; exit 0
'@
    $child = $child.Replace('__REQUEST__',$b64).Replace('__WORKER__',$script:PraExoWorker.ToString())
    $tmp = Join-Path ([IO.Path]::GetTempPath()) ('praexo_'+$id+'.ps1')
    $process = $null; $started=$false
    try {
        [IO.File]::WriteAllText($tmp,$child,(New-Object Text.UTF8Encoding($true)))
        $exe = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
        $si = New-Object Diagnostics.ProcessStartInfo
        $si.FileName=$exe; $si.Arguments='-NoProfile -NonInteractive -ExecutionPolicy Bypass -File "'+$tmp+'"'
        $si.UseShellExecute=$false; $si.CreateNoWindow=$true; $si.RedirectStandardOutput=$true; $si.RedirectStandardError=$true
        $si.StandardOutputEncoding=New-Object Text.UTF8Encoding($false); $si.StandardErrorEncoding=New-Object Text.UTF8Encoding($false)
        $process = New-Object Diagnostics.Process; $process.StartInfo=$si
        $started=$process.Start()
        if (-not $started) { throw 'The Exchange Online child process cannot start.' }
        $stdout = $process.StandardOutput.ReadToEndAsync(); $stderr = $process.StandardError.ReadToEndAsync()
        $wait = [int][Math]::Min(2147483647,([Math]::Max(1,[int]$Context.TimeoutMinutes)*60000.0))
        $timedOut = -not $process.WaitForExit($wait)
        if ($timedOut) { $process.Kill(); $process.WaitForExit() }
        $out = $stdout.GetAwaiter().GetResult().Trim(); $err = $stderr.GetAwaiter().GetResult().Trim()
        if ($timedOut) { throw "Exchange Online timeout; write state unknown. stderr=[$err], stdout=[$out]" }
        if ($process.ExitCode -ne 0 -or $err) { throw "Exchange Online child process code=$($process.ExitCode), stderr=[$err], stdout=[$out]" }
        if (-not $out.StartsWith('{') -or -not $out.EndsWith('}') -or $out -match '[\r\n]') { throw 'Exchange Online child output is not the expected one-line JSON.' }
        $res = $out | ConvertFrom-Json -ErrorAction Stop
        if (@($res.PSObject.Properties.Name).Count -ne 5 -or (Get-PraValue $res 'Protocol' 0) -ne 1 -or
            (Get-PraValue $res 'Id' '') -cne $id -or (Get-PraValue $res 'Ok' $false) -isnot [bool] -or
            (Get-PraValue $res 'Ok' $false) -ne $true -or (Get-PraValue $res 'Error' 'invalid') -ne '') { throw 'Exchange Online child result invalid or failed.' }
        $data = Get-PraValue $res 'Data' $null
        if ($null -eq $data) { throw 'Exchange Online result missing.' }
        return $data
    } finally {
        try {
            if ($null -ne $process) {
                try { if ($started -and -not $process.HasExited) { $process.Kill(); $process.WaitForExit() } }
                finally { $process.Dispose() }
            }
        } finally {
            try {
                # Child's durable Applied receipt survives timeout/protocol/verification failures.
                if ([IO.File]::Exists($appliedPath)) {
                    $receipt=[IO.File]::ReadAllText($appliedPath) | ConvertFrom-Json -ErrorAction Stop
                    if ($Operation -ne 'Grant' -or $receipt.Protocol -ne 1 -or $receipt.Id -cne $id -or $receipt.Status -cne 'Applied' -or
                        $receipt.Target -cne $Params.Upn -or $receipt.Trustee -cne $Params.Trustee -or $receipt.Right -cne $Params.Right -or $OnApplied -isnot [scriptblock]) { throw 'Invalid Applied receipt from the Exchange Online child process.' }
                    $null=& $OnApplied
                    [IO.File]::Delete($appliedPath)
                }
            } finally { if ([IO.File]::Exists($tmp)) { [IO.File]::Delete($tmp) } }
        }
    }
}

function Invoke-PraExo {
    param([hashtable]$Context,[ValidateSet('Probe','Preflight','Mailbox','Recipient','Hold','Permission','Grant')][string]$Operation,[hashtable]$Params=@{},$Permit=$null,$OnApplied=$null)
    $session = Get-PraCloudSession $Context
    if (-not $session.Exo) { throw 'Exchange Online connection required but not available.' }
    if (-not $session.Subprocess -and [string](Get-PraValue (Get-PraValue $session 'Binding' $null) 'TenantId' '') -ne
        [string](Get-PraValue (Get-PraValue $Context.Config 'Cloud' @{}) 'TenantId' '')) { throw 'Exchange Online tenant of the session differs from Cloud.TenantId.' }
    if ($Operation -eq 'Grant' -and ($null -eq $Permit -or $Context.AllowMutation -isnot [bool] -or -not $Context.AllowMutation -or
        $Context.Mode -ne 'Apply' -or $Context.Action -ne 'Convert' -or $Context.Phase -notin @('Cloud','Both') -or $WhatIfPreference)) { throw 'Grant without an active write authorisation.' }
    $Params=$Params.Clone()
    $Params.ExpectedIdentities=Get-PraValue $session 'Identities' @{}
    if ($Operation -eq 'Grant') {
        $exo=Get-PraValue $Context.Config 'Exo' @{}
        $Params.GrantVerifyAttempts=Get-PraValue $exo 'GrantVerifyAttempts' 13
        $Params.GrantVerifyDelaySeconds=Get-PraValue $exo 'GrantVerifyDelaySeconds' 10
    }
    $results = @(if ($session.Subprocess) { Invoke-PraExoSubprocess -Context $Context -Operation $Operation -Params $Params -Permit $Permit -OnApplied $OnApplied }
        else { & $script:PraExoWorker $Operation $Params $Permit (Get-PraValue $session 'Binding' $null) $OnApplied })
    if ($results.Count -ne 1) { throw 'Exchange Online result not unique.' }
    $result=$results[0]
    $booleans=switch ($Operation) { 'Probe' { 'Connected' }; 'Permission' { 'TrusteeFound'; 'Verified' }; 'Grant' { 'TrusteeFound'; 'Verified'; 'Mutated' }; default { 'Found' } }
    foreach ($key in $booleans) { if ((Get-PraValue $result $key $null) -isnot [bool]) { throw "Invalid Exchange Online result: $key must be a boolean." } }
    if ($Operation -in @('Mailbox','Recipient','Hold') -and (Get-PraValue $result 'Found' $false) -and -not [string](Get-PraValue $result 'Type' '')) { throw 'Exchange Online result without type.' }
    return $result
}

function Connect-PraCloudSession {
    param([hashtable]$Context,[bool]$NeedGraph,[bool]$NeedExo)
    $s = Get-PraCloudSession $Context; $cloud=Get-PraValue $Context.Config 'Cloud' @{}
    $app=[string](Get-PraValue $cloud 'AppId' ''); $thumb=[string](Get-PraValue $cloud 'CertificateThumbprint' '')
    $tenant=[string](Get-PraValue $cloud 'TenantId' ''); $parsed=[guid]::Empty
    if (($NeedGraph -or $NeedExo) -and (-not [guid]::TryParse($tenant,[ref]$parsed) -or $parsed -eq [guid]::Empty)) { throw 'Cloud.TenantId (GUID of the tenant) is required.' }
    if ([bool]$app -ne [bool]$thumb) { throw 'Certificate sign-in incomplete: set both Cloud.AppId and Cloud.CertificateThumbprint.' }
    if ($NeedGraph -and $s.Graph) { Assert-PraGraphSession $Context }
    if ($NeedExo -and $s.Exo) { $null=Invoke-PraExo -Context $Context -Operation Probe }
    # Graph must establish its CLR dependencies before EXO in this dedicated process.
    # Removing a module cannot repair an already-loaded conflicting assembly.
    if ($NeedGraph -and -not $s.Graph) {
        $Context.CurrentOperation='Connect-MgGraph'
        Import-Module Microsoft.Graph.Authentication -ErrorAction Stop
        Import-Module Microsoft.Graph.Users -ErrorAction Stop
        if ($null -ne (Get-MgContext -ErrorAction Stop)) { throw 'A Microsoft Graph session already exists in this console: run the tool in a new Windows PowerShell window.' }
        $connect=@{ TenantId=$tenant; ContextScope='Process'; NoWelcome=$true; ErrorAction='Stop' }
        if ($app) { $connect.ClientId=$app; $connect.CertificateThumbprint=$thumb } else { $connect.Scopes=@('User.Read.All') }
        $s.GraphAttempted=$true
        try { Connect-MgGraph @connect | Out-Null }
        catch {
            # Typical when Exchange Online was used earlier in the same console: its assemblies stay loaded.
            if ($_.Exception.Message -match 'does not have an implementation|Could not load (type|file or assembly)|Method not found') {
                throw ('Microsoft Graph cannot load in this console (assembly conflict, usually because Exchange Online was used earlier in the same window): run the tool in a new Windows PowerShell window. Detail: '+$_.Exception.Message)
            }
            throw
        }
        finally { $s.GraphContext=Get-MgContext -ErrorAction Stop }
        $s.Graph=$true
        Assert-PraGraphSession $Context
        $null = Write-PraLog -Context $Context -Message ('Microsoft Graph connected ({0}, tenant verified)' -f $(if ($app) { 'certificate' } else { [string](Get-PraValue $s.GraphContext 'Account' 'interactive') })) -Level Success
    }
    if ($NeedExo -and -not $s.Exo) {
        $Context.CurrentOperation='Connect-ExchangeOnline'
        $exo = Get-PraValue $Context.Config 'Exo' @{}
        $min = [version][string](Get-PraValue $exo 'MinModuleVersion' '3.10.0')
        $installed = @(Get-Module ExchangeOnlineManagement -ListAvailable | Sort-Object Version -Descending)
        if ($installed.Count -eq 0) { throw 'ExchangeOnlineManagement module not found (Install-Module ExchangeOnlineManagement -MinimumVersion 3.10.0 -Scope AllUsers -Force); the tool never installs modules.' }
        $s.Subprocess = [bool](Get-PraValue $exo 'UseSubprocess' $false) -or $installed[0].Version -lt $min
        if ($s.Subprocess) {
            if (-not $app) { throw 'Exchange Online child process required (Exo.UseSubprocess or old module): certificate sign-in is mandatory.' }
            $s.Exo=$true
            $probe = Invoke-PraExo $Context 'Probe'
            if ((Get-PraValue $probe 'Connected' $false) -ne $true) { throw 'Exchange Online child process connection not confirmed.' }
        } else {
            Import-Module ExchangeOnlineManagement -MinimumVersion $min -ErrorAction Stop
            if (@(Get-ConnectionInformation -ErrorAction Stop).Count) { throw 'An Exchange Online session already exists in this console: run the tool in a new Windows PowerShell window (nothing was signed out).' }
            if (-not (Get-Command Disconnect-ExchangeOnline -ErrorAction Stop).Parameters.ContainsKey('ConnectionId')) { throw 'This ExchangeOnlineManagement cannot sign out one connection (ConnectionId): update the module.' }
            $connect=@{ ShowBanner=$false; ErrorAction='Stop' }
            if ($app) { $connect.AppId=$app; $connect.CertificateThumbprint=$thumb; $connect.Organization=Get-PraValue $cloud 'Organization' '' }
            else {
                $upn=[string](Get-PraValue $cloud 'UserPrincipalName' '')
                if ($upn) {
                    if (-not (Get-Command Connect-ExchangeOnline -ErrorAction Stop).Parameters.ContainsKey('UserPrincipalName')) { throw 'Cloud.UserPrincipalName is not supported by this ExchangeOnlineManagement.' }
                    $connect.UserPrincipalName=$upn
                }
            }
            $disableWam=Get-PraValue $exo 'DisableWAM' $false
            if ($disableWam -isnot [bool]) { throw 'Exo.DisableWAM must be $true or $false.' }
            if ($disableWam) {
                if (-not (Get-Command Connect-ExchangeOnline -ErrorAction Stop).Parameters.ContainsKey('DisableWAM')) { throw 'Exo.DisableWAM is not supported by this ExchangeOnlineManagement.' }
                $connect.DisableWAM=$true
            }
            $s.ExoAttempted=$true; $s.OwnedExoIds=$null
            try { Connect-ExchangeOnline @connect | Out-Null }
            finally { $s.OwnedExoIds=@(Get-ConnectionInformation -ErrorAction Stop | ForEach-Object { [string]$_.ConnectionId }) }
            $probe=& $script:PraExoWorker 'Probe' @{ TenantId=$tenant; Organization=[string](Get-PraValue $cloud 'Organization' ''); AppId=$app } $null $null $null
            $s.Binding=$probe.Binding; $s.Exo=$true
        }
        $null = Write-PraLog -Context $Context -Message ("Exchange Online connected ({0}{1})" -f $(if ($app) { 'certificate' } else { 'interactive' }), $(if ($s.Subprocess) { ', child process' } else { '' })) -Level Success
    }
}

function Assert-PraGraphSession {
    param([hashtable]$Context)
    $s=Get-PraCloudSession $Context; $current=Get-MgContext -ErrorAction Stop
    $tenant=[string](Get-PraValue (Get-PraValue $Context.Config 'Cloud' @{}) 'TenantId' '')
    if ($null -eq $current -or [string](Get-PraValue $current 'TenantId' '') -ne $tenant -or
        [string](Get-PraValue $current 'ContextScope' '') -ne 'Process') { throw 'Microsoft Graph session missing, on another tenant or not limited to this process.' }
    foreach ($key in @('TenantId','ClientId','Account','AuthType','ContextScope')) {
        if ([string](Get-PraValue $current $key '') -cne [string](Get-PraValue $s.GraphContext $key '')) { throw 'The Microsoft Graph session changed.' }
    }
}

function Close-PraCloudSession {
    <#
    .SYNOPSIS
        Signs out the sessions opened by this module; a sign-out failure is an error.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][hashtable]$Context)
    if (-not $Context.ContainsKey('_PraCloudSession')) { return }
    $s=$Context['_PraCloudSession']; $errors=New-Object 'System.Collections.Generic.List[string]'
    if ($s.ExoAttempted) {
        try {
            if ($null -eq (Get-PraValue $s 'OwnedExoIds' $null)) { throw 'Own Exchange Online connections unknown: a global sign-out is not allowed.' }
            $currentIds=@(Get-ConnectionInformation -ErrorAction Stop | ForEach-Object { [string]$_.ConnectionId })
            $ownedIds=Get-PraValue $s 'OwnedExoIds' @()
            foreach ($id in @($ownedIds)) {
                if (-not $id) { throw 'Own connection ID missing: a global sign-out is not allowed.' }
                if ($id -in $currentIds) { Disconnect-ExchangeOnline -ConnectionId $id -Confirm:$false -ErrorAction Stop 6>$null | Out-Null }
            }
            $s.ExoAttempted=$false; $s.Exo=$false
        }
        catch { [void]$errors.Add('Exchange Online sign-out: '+$_.Exception.Message) }
    }
    if ($s.GraphAttempted) {
        try {
            $current=Get-MgContext -ErrorAction Stop
            if ($null -ne $current) {
                if ($null -eq (Get-PraValue $s 'GraphContext' $null)) { throw 'The Microsoft Graph session was not opened by the tool: not signed out.' }
                foreach ($key in @('TenantId','ClientId','Account','AuthType','ContextScope')) {
                    if ([string](Get-PraValue $current $key '') -cne [string](Get-PraValue $s.GraphContext $key '')) { throw 'The Microsoft Graph session was replaced: not signed out.' }
                }
                Disconnect-MgGraph -ErrorAction Stop | Out-Null
            }
            $s.GraphAttempted=$false; $s.Graph=$false
        }
        catch { [void]$errors.Add('Microsoft Graph sign-out: '+$_.Exception.Message) }
    }
    if ($errors.Count) {
        $Context.CloudConnectFailed=$true; $Context.CurrentOperation='Close-PraCloudSession'
        Write-PraCloudError -Context $Context -Row $null -Message ($errors -join ' | ')
        throw ($errors -join ' | ')
    }
    [void]$Context.Remove('_PraCloudSession')
}

function Get-PraPermissionRequest {
    param([hashtable]$Context,$Row)
    if (-not [bool](Get-PraValue $Row 'IsShared' $false)) { return }
    $cfg = Get-PraValue $Context.Config 'SharedMailbox' @{}
    if (-not [bool](Get-PraValue $cfg 'Enabled' $false)) { return }
    foreach ($right in @('FullAccess','SendAs','SendOnBehalf')) {
        if ($right -ne 'SendOnBehalf' -and (Get-PraValue $cfg 'PermissionSource' 'None') -eq 'None') { continue }
        if ([bool](Get-PraValue $cfg ('Grant'+$right) $false)) {
            foreach ($u in @((Get-PraValue $Row ('Shared'+$right) @()) | Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) } | Select-Object -Unique)) {
                [pscustomobject]@{ Right=$right; Trustee=[string]$u }
            }
        }
    }
}

function Initialize-PraCloudPreflight {
    <#
    .SYNOPSIS
        Signs in and resolves every target and trustee in Exchange Online BEFORE the AD part of a Convert (Apply, phase Both). Read only.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][hashtable]$Context,[Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Rows)
    $Context.CurrentPhase='CloudPreflight'; $Context.CurrentOperation='Prepare'; $Context.CurrentIdentity=''
    try {
        if ($Context.Action -ne 'Convert' -or $Context.Mode -ne 'Apply' -or $Context.Phase -ne 'Both' -or
            $Context.AllowMutation -isnot [bool] -or -not $Context.AllowMutation -or $WhatIfPreference) { throw 'The pre-check is only for Convert, Apply, phase Both.' }
        if ($Context.CloudCheckScope -notin @('Both','MailboxOnly','LicenseOnly')) { throw 'Invalid CloudCheckScope.' }
        $cloud=Get-PraValue $Context.Config 'Cloud' @{}; $exo=Get-PraValue $Context.Config 'Exo' @{}
        foreach ($key in @('CheckMailbox','CheckLicense')) { if ((Get-PraValue $cloud $key $false) -isnot [bool]) { throw "Cloud.$key must be `$true or `$false." } }
        foreach ($key in @('UseSubprocess','DisableWAM')) { if ((Get-PraValue $exo $key $false) -isnot [bool]) { throw "Exo.$key must be `$true or `$false." } }
        $attempts=Get-PraValue $exo 'GrantVerifyAttempts' 13; $delay=Get-PraValue $exo 'GrantVerifyDelaySeconds' 10
        if (($attempts -isnot [int] -and $attempts -isnot [long]) -or $attempts -lt 1 -or $attempts -gt 60 -or
            ($delay -isnot [int] -and $delay -isnot [long]) -or $delay -lt 1 -or $delay -gt 30) { throw 'Invalid Exchange Online verification cadence.' }
        $via=[string](Get-PraValue $cloud 'MailboxCheckVia' 'Graph')
        if ($via -notin @('Graph','Exo')) { throw 'Invalid Cloud.MailboxCheckVia.' }
        $needGraph=$false
        foreach ($row in $Rows) {
            if ((Get-PraValue $row 'IsShared' $false) -isnot [bool] -or (Get-PraValue $row 'FinalStatus' '') -eq 'Error') { throw 'Invalid or failed row at the pre-check.' }
            $shared=[bool](Get-PraValue $row 'IsShared' $false)
            if (-not $shared -and (($Context.CloudCheckScope -ne 'MailboxOnly' -and (Get-PraValue $cloud 'CheckLicense' $false)) -or
                ($Context.CloudCheckScope -ne 'LicenseOnly' -and (Get-PraValue $cloud 'CheckMailbox' $false) -and $via -eq 'Graph'))) { $needGraph=$true }
        }
        # EXO resolves each target even while it is still a MailUser; no provisioning assertion here.
        Connect-PraCloudSession -Context $Context -NeedGraph $needGraph -NeedExo ($Rows.Count -gt 0)
        $session=Get-PraCloudSession $Context
        foreach ($row in $Rows) {
            $upn=[string](Get-PraValue $row 'UserPrincipalName' '')
            $Context.CurrentIdentity=$upn; $Context.CurrentOperation='ResolvePreflightIdentity'
            $requests=@(Get-PraPermissionRequest $Context $row)
            $result=Invoke-PraExo -Context $Context -Operation Preflight -Params @{ Upn=$upn; Requests=$requests }
            $identities=Get-PraValue $result 'Identities' @{}
            $names=if ($identities -is [System.Collections.IDictionary]) { @($identities.Keys) } else { @($identities.PSObject.Properties.Name) }
            foreach ($name in $names) {
                $identity=Get-PraValue $identities $name $null
                $previous=Get-PraValue $session.Identities $name $null
                if ($null -ne $previous -and ((Get-PraValue $previous 'ObjectId') -ne (Get-PraValue $identity 'ObjectId') -or
                    (Get-PraValue $previous 'PrimarySmtpAddress') -ne (Get-PraValue $identity 'PrimarySmtpAddress'))) { throw 'Contradictory identities at the pre-check.' }
                $session.Identities[$name]=$identity
            }
            if ($needGraph -and -not [bool](Get-PraValue $row 'IsShared' $false)) {
                Assert-PraGraphSession $Context
                $users=@(Get-MgUser -UserId $upn -Property Id,UserPrincipalName -ErrorAction Stop)
                $target=Get-PraValue $session.Identities $upn $null
                if ($users.Count -ne 1 -or [string](Get-PraValue $users[0] 'Id' '') -ne [string](Get-PraValue $target 'ObjectId' '') -or
                    [string](Get-PraValue $users[0] 'UserPrincipalName' '') -ne $upn) { throw "Graph and Exchange Online identities differ at the pre-check: $upn" }
            }
        }
        $session.Preflight=$true; $Context.CloudConnectFailed=$false
        $null=Write-PraLog -Context $Context -Message ('Pre-check passed: {0} target(s) and their trustees resolved in Exchange Online (read only)' -f $Rows.Count) -Level Success
    } catch {
        $failure=$_.Exception.Message; $Context.CloudConnectFailed=$true
        try { Close-PraCloudSession -Context $Context } catch { $failure+=' | sign-out after the pre-check: '+$_.Exception.Message }
        throw $failure
    }
}

function Invoke-PraPermissionGrant {
    param([hashtable]$Context,$Row,[hashtable]$Params)
    if ($Context.AllowMutation -isnot [bool] -or -not $Context.AllowMutation -or $Context.Mode -ne 'Apply' -or
        $Context.Action -ne 'Convert' -or $Context.Phase -notin @('Cloud','Both') -or $WhatIfPreference) { throw 'Permission missing and writes are not allowed in this mode.' }
    $adVerified=Get-PraValue $Row 'ADVerified' $false
    if ($adVerified -isnot [bool] -or -not $adVerified) { throw 'Grant refused: a verified AD proof is required.' }
    foreach ($name in @('Approval','AssertCloudAuthorization','JournalMutation')) {
        if ($Context[$name] -isnot [scriptblock]) { throw "Required callback missing: $name" }
    }
    $target=$Params.Upn; $operation="Grant $($Params.Right) to $($Params.Trustee)"
    $Context.CurrentOperation=$operation; $Context.CurrentIdentity=[string](Get-PraValue $Row 'ObjectGuid' $target)
    $approval = @(& $Context.Approval $target $operation)
    if ($approval.Count -ne 1 -or $approval[0] -isnot [bool] -or -not $approval[0]) { throw "Grant refused or not confirmed: $operation" }
    $proof = @(& $Context.AssertCloudAuthorization $Row)
    if ($proof.Count -gt 1 -or ($proof.Count -eq 1 -and ($proof[0] -isnot [bool] -or -not $proof[0]))) { throw 'Backup/AD proof refused or ambiguous.' }
    # The callbacks cannot re-open a forbidden mode before the call.
    if (-not $Context.AllowMutation -or $Context.Mode -ne 'Apply' -or $Context.Action -ne 'Convert' -or $WhatIfPreference) { throw 'Authorisation revoked.' }
    $detail="UPN=$target; Trustee=$($Params.Trustee); Right=$($Params.Right); ObjectGuid=$($Context.CurrentIdentity)"
    $Row.LastOperation=$operation
    $null = & $Context.JournalMutation $target $operation 'Started' $detail
    $permit=@{ AllowMutation=$true; Approved=$true; Authorized=$true; JournalStarted=$true; Target=$target
        Trustee=$Params.Trustee; Right=$Params.Right; Action=$Context.Action; Mode=$Context.Mode; Phase=$Context.Phase }
    try {
        $onApplied={ $null=& $Context.JournalMutation $target $operation 'Applied' ($detail+'; Add returned; verification pending') }.GetNewClosure()
        $res = Invoke-PraExo -Context $Context -Operation 'Grant' -Params $Params -Permit $permit -OnApplied $onApplied
        $verified=Get-PraValue $res 'Verified' $false
        if ($verified -isnot [bool] -or -not $verified) { throw ([string](Get-PraValue $res 'Error' 'Permission re-read not confirmed.')) }
        $null = & $Context.JournalMutation $target $operation 'Verified' ($detail+'; Mutated='+(Get-PraValue $res 'Mutated' $false))
    } catch {
        $failure=$_.Exception.Message
        try { $null = & $Context.JournalMutation $target $operation 'Failed' ($detail+'; '+$failure) }
        catch { $failure += ' | journal line Failed not written: '+$_.Exception.Message }
        throw $failure
    }
}

function Invoke-PraSharedPermission {
    <#
    .SYNOPSIS
        Checks every permission of a shared mailbox in Exchange Online and grants the missing ones (Apply).
    .DESCRIPTION
        Trustees are always resolved strictly: a trustee missing in Exchange Online is an error.
        Preview of a Convert: a missing permission is counted "to grant" (no error).
    .OUTPUTS
        Number of permissions still to grant (Preview only; 0 in Apply).
    #>
    [CmdletBinding(SupportsShouldProcess=$true,ConfirmImpact='Low')]
    param([hashtable]$Context,$Row,[object[]]$Requests)
    $Row.PermMissing=@(); $verified=0; $toGrant=0; $missing=New-Object 'System.Collections.Generic.List[string]'
    $cfg=Get-PraValue $Context.Config 'SharedMailbox' @{}
    $upn=[string](Get-PraValue $Row 'UserPrincipalName' '')
    $preview=($Context.Action -eq 'Convert' -and ($Context.Mode -ne 'Apply' -or -not $Context.AllowMutation -or $WhatIfPreference))
    foreach ($request in $Requests) {
        $p=@{ Upn=$upn; Trustee=$request.Trustee; Right=$request.Right; AutoMapping=[bool](Get-PraValue $cfg 'AutoMapping' $false) }
        $Row.PermDetail="Permissions verified=$verified/$($Requests.Count); current=$($request.Right)/$($request.Trustee)"
        $r=Invoke-PraExo -Context $Context -Operation 'Permission' -Params $p
        if ((Get-PraValue $r 'TrusteeFound' $false) -ne $true) {
            if (-not $missing.Contains($request.Trustee)) { [void]$missing.Add($request.Trustee) }
            $Row.PermMissing=$missing.ToArray(); continue
        }
        if ((Get-PraValue $r 'Verified' $false) -ne $true) {
            if ($preview) { $toGrant++; continue }
            if ($Context.AllowMutation -isnot [bool] -or -not $Context.AllowMutation -or $Context.Mode -ne 'Apply' -or
                $Context.Action -ne 'Convert' -or $Context.Phase -notin @('Cloud','Both') -or $WhatIfPreference) { throw 'Permission missing and writes are not allowed in this mode.' }
            # Native ShouldProcess per right; it never replaces the approval, proof and journal of the grant.
            if (-not $PSCmdlet.ShouldProcess($upn,"Grant $($request.Right) to $($request.Trustee)")) { throw 'Exchange Online grant refused (ShouldProcess).' }
            Invoke-PraPermissionGrant -Context $Context -Row $Row -Params $p
            $null=Write-PraLog -Context $Context -Message ("{0}: {1} granted to {2} and verified" -f $upn,$request.Right,$request.Trustee) -Level Sub
        }
        $verified++
    }
    $Row.PermDetail="Permissions verified=$verified/$($Requests.Count); to grant=$toGrant; trustees missing in Exchange Online=$($missing.Count)"
    if ($missing.Count) { throw ($Row.PermDetail+': '+($missing -join ', ')) }
    if (($verified+$toGrant) -ne $Requests.Count) { throw $Row.PermDetail }
    return $toGrant
}

function Get-PraGraphFact {
    param([hashtable]$Context,[string]$Upn,[bool]$Mailbox,[bool]$License)
    if (-not (Get-PraCloudSession $Context).Graph) { throw 'Microsoft Graph required but not connected.' }
    Assert-PraGraphSession $Context
    $props=@('assignedPlans'); if ($Mailbox) { $props+='provisionedPlans' }; if ($License) { $props+='assignedLicenses' }
    $users=@(Get-MgUser -UserId $Upn -Property $props -ErrorAction Stop)
    if ($users.Count -ne 1 -or $null -eq $users[0]) { throw "Microsoft Graph: user not found or not unique ($Upn)." }
    $values=@{}; $sentinel=New-Object object
    foreach ($prop in $props) {
        $value=Get-PraValue $users[0] $prop $sentinel
        if ([object]::ReferenceEquals($value,$sentinel)) { throw "Microsoft Graph: property not returned ($prop)." }
        $values[$prop]=@($value | Where-Object { $null -ne $_ })
    }
    foreach ($p in $values.assignedPlans) {
        if (-not [string](Get-PraValue $p 'Service' '') -or -not [string](Get-PraValue $p 'CapabilityStatus' '')) { throw 'Microsoft Graph: incomplete assignedPlan, Exchange removal not proven.' }
    }
    if ($Mailbox) {
        foreach ($p in $values.provisionedPlans) {
            if (-not [string](Get-PraValue $p 'Service' '') -or -not [string](Get-PraValue $p 'ProvisioningStatus' '')) { throw 'Microsoft Graph: incomplete provisionedPlan.' }
        }
    }
    $enabled=@($values.assignedPlans | Where-Object { (Get-PraValue $_ 'Service' '') -eq 'exchange' -and (Get-PraValue $_ 'CapabilityStatus' '') -eq 'Enabled' }).Count -gt 0
    $prov=$false; $plans=@(); $sku=@()
    if ($Mailbox) { $prov=@($values.provisionedPlans | Where-Object { (Get-PraValue $_ 'Service' '') -eq 'exchange' -and (Get-PraValue $_ 'ProvisioningStatus' '') -eq 'Success' }).Count -gt 0 }
    $required=[string](Get-PraValue (Get-PraValue $Context.Config 'Cloud' @{}) 'RequiredSkuPartNumber' '')
    if ($Mailbox -or ($License -and $required)) {
        $details=@(Get-MgUserLicenseDetail -UserId $Upn -All -ErrorAction Stop)
        foreach ($d in $details) {
            $sku += [string](Get-PraValue $d 'SkuPartNumber' '')
            foreach ($p in @((Get-PraValue $d 'ServicePlans' @()) | Where-Object { (Get-PraValue $_ 'ServicePlanName' '') -like 'EXCHANGE_*' })) {
                $status=[string](Get-PraValue $p 'ProvisioningStatus' '')
                $plans += ([string](Get-PraValue $p 'ServicePlanName' '')+':'+$status)
                if ($status -eq 'Success') { $prov=$true }
            }
        }
    }
    $count=0; if ($License) { $count=$values.assignedLicenses.Count }
    return @{ Enabled=$enabled; Provisioned=$prov; LicenseCount=$count; RequiredSku=$required
        RequiredSkuOk=(-not $required -or $required -in $sku); Detail=($plans -join ',') }
}

function Invoke-PraCloudPhase {
    <#
    .SYNOPSIS
        Checks (and waits for) the expected Exchange Online state of every row and, in Apply, grants the shared mailbox permissions.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][hashtable]$Context,[Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Rows,
        [Parameter(Mandatory)][ValidateSet('Convert','Recover')][string]$Act)
    $Context.CurrentPhase='Cloud'; $Context.CurrentOperation='Prepare'; $Context.CurrentIdentity=''; $Context.CloudConnectFailed=$false
    $states=New-Object 'System.Collections.Generic.List[object]'
    try {
        $scope=[string]$Context.CloudCheckScope
        if ($Context.Action -in @('Convert','Recover') -and $Context.Action -ne $Act) { throw 'Context action and -Act differ.' }
        if ($scope -notin @('Both','MailboxOnly','LicenseOnly')) { throw 'Invalid CloudCheckScope.' }
        if ([int]$Context.TimeoutMinutes -lt 0 -or [int]$Context.IntervalMinutes -lt 0) { throw 'Negative cloud polling values.' }
        $cloud=Get-PraValue $Context.Config 'Cloud' @{}
        $via=[string](Get-PraValue $cloud 'MailboxCheckVia' 'Graph')
        if ($via -notin @('Graph','Exo')) { throw 'Invalid Cloud.MailboxCheckVia.' }
        $needGraph=$false; $needExo=$false
        foreach ($row in $Rows) {
            Add-Member -InputObject $row -NotePropertyName DeprovisionConfirmed -NotePropertyValue $false -Force
            $row.CloudMailbox=$null; $row.CloudLicense=$null; $row.CloudStatus='Pending'; $row.CloudDetail=''
            $upn=[string](Get-PraValue $row 'UserPrincipalName' '')
            if (-not $upn) { Write-PraCloudError -Context $Context -Row $row -Message 'UPN missing: check impossible.'; continue }
            if ((Get-PraValue $row 'FinalStatus' '') -eq 'Error') { Write-PraCloudError -Context $Context -Row $row -Message 'Previous error: cloud part not allowed.'; continue }
            $shared=[bool](Get-PraValue $row 'IsShared' $false)
            $preserveMailbox=Get-PraValue $row 'PreserveCloudMailbox' $false; $preserveLicense=Get-PraValue $row 'PreserveLicense' $false
            if ($preserveMailbox -isnot [bool] -or $preserveLicense -isnot [bool] -or ($preserveMailbox -and -not $shared)) {
                Write-PraCloudError -Context $Context -Row $row -Message 'Invalid keep flags (PreserveCloudMailbox is for shared mailboxes only).'; continue
            }
            $requests=@(); if ($Act -eq 'Convert') { $requests=@(Get-PraPermissionRequest $Context $row) }
            $mb=($scope -ne 'LicenseOnly') -and ([bool](Get-PraValue $cloud 'CheckMailbox' $false) -or $Act -eq 'Recover' -or $requests.Count -gt 0)
            $lic=($scope -ne 'MailboxOnly') -and -not $shared -and [bool](Get-PraValue $cloud 'CheckLicense' $false)
            if (-not $mb -and -not $lic) {
                $row.CloudStatus='Skipped'; $row.CloudDetail='No applicable check; no restore confirmation.'; $row.FinalStatus='Skipped'; continue
            }
            $graphMailbox=$mb -and -not $shared -and $via -eq 'Graph'
            $exoMailbox=$mb -and ($Act -eq 'Recover' -or $shared -or $via -eq 'Exo')
            $needGraph=$needGraph -or $lic -or $graphMailbox; $needExo=$needExo -or $exoMailbox
            [void]$states.Add(@{ Row=$row; Upn=$upn; Shared=$shared; Mailbox=$mb; License=$lic; GraphMailbox=$graphMailbox
                ExoMailbox=$exoMailbox; Requests=$requests; PreserveMailbox=$preserveMailbox; PreserveLicense=$preserveLicense; Done=$false })
        }
        if ($states.Count -eq 0) { return }
        try { Connect-PraCloudSession -Context $Context -NeedGraph $needGraph -NeedExo $needExo }
        catch { $Context.CloudConnectFailed=$true; throw }
        $clock=[Diagnostics.Stopwatch]::StartNew(); $timeout=[double]$Context.TimeoutMinutes*60; $attempt=0
        do {
            $attempt++; $pending=@($states | Where-Object { -not $_.Done })
            $null=Write-PraLog -Context $Context -Message ("Check {0}: {1} object(s) in Exchange Online" -f $attempt, $pending.Count) -Level Info
            foreach ($s in $pending) {
                $row=$s.Row; $Context.CurrentIdentity=[string](Get-PraValue $row 'ObjectGuid' $s.Upn); $Context.CurrentOperation='CloudCheck'
                try {
                    $details=New-Object 'System.Collections.Generic.List[string]'; $mbok=$true; $licok=$true; $facts=$null
                    if ($s.GraphMailbox -or $s.License) { $facts=Get-PraGraphFact -Context $Context -Upn $s.Upn -Mailbox $s.GraphMailbox -License $s.License }
                    if ($s.ExoMailbox) {
                        $m=Invoke-PraExo -Context $Context -Operation 'Mailbox' -Params @{ Upn=$s.Upn }
                        if ($Act -eq 'Recover') {
                            if ($s.PreserveMailbox) {
                                $mbok=(Get-PraValue $m 'Found' $false) -eq $true -and (Get-PraValue $m 'Type' '') -eq 'SharedMailbox'
                                [void]$details.Add("MBX:KeepCloudShared SharedMailbox present=$mbok; deprovisioning NOT confirmed, tag kept")
                            } else {
                                $r=Invoke-PraExo -Context $Context -Operation 'Recipient' -Params @{ Upn=$s.Upn }
                                $mbok=(Get-PraValue $m 'Found' $true) -eq $false -and (Get-PraValue $r 'Found' $false) -eq $true -and (Get-PraValue $r 'Type' '') -eq 'MailUser'
                                [void]$details.Add("MBX:absence=$(-not [bool](Get-PraValue $m 'Found' $true)); recipient=$(Get-PraValue $r 'Type' 'none')")
                                if ($s.GraphMailbox) { [void]$details.Add("Graph:Enabled=$($facts.Enabled),Provisioned=$($facts.Provisioned) (Exchange Online is authoritative, Graph errors stop)") }
                            }
                        } else {
                            $type=[string](Get-PraValue $m 'Type' '')
                            $mbok=if ($s.Shared) { $type -eq 'SharedMailbox' } else { $type -in @('UserMailbox','SharedMailbox','RoomMailbox','EquipmentMailbox') }
                            [void]$details.Add("MBX:EXO type=$type")
                        }
                    } elseif ($s.GraphMailbox) { $mbok=$facts.Provisioned; [void]$details.Add("MBX:Graph provisioning=$mbok; Enabled=$($facts.Enabled) [$($facts.Detail)]") }
                    if ($s.Mailbox) { $row.CloudMailbox=[bool]$mbok }
                    if ($s.License) {
                        $licok=if ($Act -eq 'Convert' -or $s.PreserveLicense) { $facts.LicenseCount -gt 0 -and $facts.Enabled -and $facts.RequiredSkuOk }
                            elseif ($facts.RequiredSku) { -not $facts.RequiredSkuOk } else { -not $facts.Enabled }
                        $row.CloudLicense=[bool]$licok
                        [void]$details.Add("LIC:OK=$licok; Preserve=$($s.PreserveLicense); ExpectedSKU=$($facts.RequiredSku); SKUPresent=$($facts.RequiredSkuOk); licences=$($facts.LicenseCount); ExchangeEnabled=$($facts.Enabled)")
                    } elseif ($s.Shared) { [void]$details.Add('LIC:N/A (shared)') }
                    $row.CloudDetail=$details -join ' | '
                    if ($mbok -and $licok) {
                        if ($Act -eq 'Recover' -and -not $s.ExoMailbox) {
                            $row.CloudStatus='Skipped'; $row.FinalStatus='Skipped'; $row.CloudDetail+=' | LicenseOnly: no Exchange Online confirmation, restore not allowed.'
                        } else {
                            $toGrant=0
                            if ($s.Mailbox -and $s.Requests.Count) { $toGrant=[int](Invoke-PraSharedPermission -Context $Context -Row $row -Requests $s.Requests) }
                            $row.DeprovisionConfirmed=($Act -eq 'Recover' -and $s.ExoMailbox -and -not $s.PreserveMailbox)
                            if ($toGrant -gt 0) {
                                $row.CloudStatus='Planned'; $row.FinalStatus='Planned'
                                $null=Write-PraLog -Context $Context -Message ("{0}: SharedMailbox ready, {1} permission(s) to grant in Apply" -f $s.Upn, $toGrant) -Level Info
                            } else {
                                $row.CloudStatus='Success'
                                $row.FinalStatus=if ($Act -eq 'Recover' -and [bool](Get-PraValue $row 'DeproPending' $false)) { 'Pending' } else { 'Success' }
                                $what=if ($Act -eq 'Recover') { if ($s.PreserveMailbox) { 'shared mailbox kept in Exchange Online' } else { 'deprovisioned in Exchange Online (now a MailUser)' } }
                                    elseif ($s.Shared) { 'SharedMailbox ready, ' + ([string]$row.PermDetail -replace '; to grant=0; trustees missing in Exchange Online=0', '') }
                                    else { 'mailbox' + $(if ($s.License) { ' and licence' } else { '' }) + ' ready' }
                                $null=Write-PraLog -Context $Context -Message ("{0}: {1}" -f $s.Upn, $what) -Level Success
                            }
                        }
                        $s.Done=$true
                    } else { $row.CloudStatus='Pending' }
                } catch { Write-PraCloudError -Context $Context -Row $row -Message ($_.Exception.Message+' | '+[string]$row.PermDetail); $s.Done=$true }
            }
            $pending=@($states | Where-Object { -not $_.Done })
            if (-not $pending.Count -or $Context.Once -or $clock.Elapsed.TotalSeconds -ge $timeout) { break }
            $seconds=[Math]::Min([Math]::Max(1,([double]$Context.IntervalMinutes*60)),[Math]::Max(0,($timeout-$clock.Elapsed.TotalSeconds)))
            $null=Write-PraLog -Context $Context -Message ("Not ready yet: {0} - next check in {1:0} s (waiting up to {2} min in total)" -f (($pending | ForEach-Object { $_.Upn }) -join ', '), $seconds, $Context.TimeoutMinutes) -Level Sub
            foreach ($s in $pending) { $null=Write-PraLog -Context $Context -Message ("{0} | {1}" -f $s.Upn, $s.Row.CloudDetail) -Level Detail }
            if ($seconds -gt 0) { Start-Sleep -Milliseconds ([int][Math]::Min(2147483647,($seconds*1000))) }
        } while ($true)
        $preview=(-not $Context.AllowMutation -and $Context.Action -in @('Convert','Recover'))
        foreach ($s in $states) {
            if ($s.Done) { continue }
            if ($preview) {
                $s.Row.CloudStatus='Pending'; $s.Row.FinalStatus='Planned'
                $s.Row.Detail=([string]$s.Row.Detail+' | not yet in the expected state in Exchange Online (preview): '+$s.Row.CloudDetail).Trim(' ','|')
                $null=Write-PraLog -Context $Context -Message ("{0}: not yet in the expected state ({1})" -f $s.Upn, $s.Row.CloudDetail) -Level Info
            }
            else { Write-PraCloudError -Context $Context -Row $s.Row -Message ('Expected state not reached (timeout or -Once): '+$s.Row.CloudDetail) }
        }
    } catch {
        $failure=$_.Exception.Message
        foreach ($row in $Rows) { Write-PraCloudError -Context $Context -Row $row -Message $failure }
        if ($Rows.Count -eq 0) { Write-PraCloudError -Context $Context -Row $null -Message $failure }
    } finally {
        try { Close-PraCloudSession $Context }
        catch { foreach ($row in $Rows) { Write-PraCloudError -Context $Context -Row $row -Message ('Cloud sign-out failed: '+$_.Exception.Message) } }
    }
}

function Invoke-PraRetentionCheck {
    <#
    .SYNOPSIS
        Checks that the retention policy holds the active or inactive mailboxes (read only, never a deprovisioning confirmation).
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][hashtable]$Context,[Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Rows)
    $Context.CurrentPhase='Retention'; $Context.CurrentOperation='Prepare'; $Context.CurrentIdentity=''; $Context.CloudConnectFailed=$false
    try {
        if ($Rows.Count -eq 0) { return }
        $cfg=Get-PraValue $Context.Config 'Retention' @{}; $raw=[string](Get-PraValue $cfg 'PolicyGuid' '')
        $guid=$null; $parsed=[guid]::Empty
        if ($raw) {
            if (-not [guid]::TryParse($raw,[ref]$parsed) -or $parsed -eq [guid]::Empty) { throw 'Retention.PolicyGuid is not a GUID.' }
            $guid=$parsed.ToString('N')
        }
        try { Connect-PraCloudSession -Context $Context -NeedGraph $false -NeedExo $true }
        catch { $Context.CloudConnectFailed=$true; throw }
        $cloud=Get-PraValue $Context.Config 'Cloud' @{}; $name=[string](Get-PraValue $cfg 'PolicyName' '')
        if (-not $guid -and $name -and [bool](Get-PraValue $cfg 'UseComplianceSession' $false) -and -not [string](Get-PraValue $cloud 'AppId' '')) {
            $Context.CurrentOperation='ResolveRetentionPolicy'
            $session=Get-PraCloudSession $Context
            if ($session.Subprocess) { throw 'Interactive policy lookup (Connect-IPPSSession) is not possible with the Exchange Online child process.' }
            $beforeIds=@(Get-ConnectionInformation -ErrorAction Stop | ForEach-Object { [string]$_.ConnectionId })
            $session.ExoAttempted=$true
            try { Connect-IPPSSession -ShowBanner:$false -ErrorAction Stop | Out-Null }
            finally {
                $newIds=@(Get-ConnectionInformation -ErrorAction Stop | ForEach-Object { [string]$_.ConnectionId } | Where-Object { $_ -notin $beforeIds })
                $session.OwnedExoIds=@($session.OwnedExoIds)+$newIds
            }
            try {
                $policies=@(Get-RetentionCompliancePolicy -Identity $name -ErrorAction Stop)
                if ($policies.Count -ne 1) { throw 'Retention policy not found or not unique.' }
                $raw=[string](Get-PraValue $policies[0] 'Guid' '')
                if (-not $raw) { $raw=[string](Get-PraValue $policies[0] 'ExchangeObjectId' '') }
                if (-not [guid]::TryParse($raw,[ref]$parsed) -or $parsed -eq [guid]::Empty) { throw 'Retention policy GUID missing or invalid.' }
                $guid=$parsed.ToString('N')
            } finally {
                foreach ($id in $newIds) { Disconnect-ExchangeOnline -ConnectionId $id -Confirm:$false -ErrorAction Stop 6>$null | Out-Null }
            }
        }
        foreach ($row in $Rows) {
            Add-Member -InputObject $row -NotePropertyName DeprovisionConfirmed -NotePropertyValue $false -Force
            $Context.CurrentOperation='VerifyRetention'; $Context.CurrentIdentity=[string](Get-PraValue $row 'ObjectGuid' '')
            $row.CloudMailbox=$null; $row.CloudLicense=$null; $row.CloudStatus='Pending'
            try {
                $h=Invoke-PraExo -Context $Context -Operation 'Hold' -Params @{ Upn=[string](Get-PraValue $row 'UserPrincipalName' '') }
                $row.CloudMailbox=[bool](Get-PraValue $h 'Found' $false)
                $holds=Get-PraValue $h 'Holds' @(); $holds=@($holds | Where-Object { $null -ne $_ })
                $included=$false; $excluded=$false; $deleteOnly=$false
                foreach ($hold in $holds) {
                    if ([string]$hold -match '^(?<excluded>-)?(?:mbx|grp|skp|UniH)?(?<id>[a-f0-9]{32}|[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12})(?::(?<action>[123]))?$') {
                        if (($Matches.id -replace '-','') -eq $guid) {
                            if ($Matches.ContainsKey('excluded')) { $excluded=$true }
                            elseif ($Matches.ContainsKey('action') -and $Matches.action -eq '1') { $deleteOnly=$true }
                            else { $included=$true }
                        }
                    }
                }
                $row.CloudDetail="Retention: Found=$($row.CloudMailbox); Inactive=$(Get-PraValue $h 'IsInactive' $false); Litigation=$(Get-PraValue $h 'Litigation' $false); RetentionHold=$(Get-PraValue $h 'RetentionHold' $false); Holds=[$($holds -join ',')]"
                if (-not $row.CloudMailbox) { throw ('Mailbox not found (active or inactive). '+$row.CloudDetail) }
                if (-not $guid) { throw ('Policy unknown: set Retention.PolicyGuid (a hold may exist, check it manually). '+$row.CloudDetail) }
                if ($excluded -or $deleteOnly -or -not $included) { throw ('Not covered by the policy (or excluded, or delete-only); an adaptive scope can take several days. '+$row.CloudDetail) }
                $row.CloudStatus='Success'; if ($row.FinalStatus -ne 'Error') { $row.FinalStatus='Success' }
                $row.CloudDetail+=' | COVERED (GUID='+$guid+')'
                $null=Write-PraLog -Context $Context -Message $row.CloudDetail -Level Success
            } catch { Write-PraCloudError -Context $Context -Row $row -Message $_.Exception.Message }
        }
    } catch {
        $failure=$_.Exception.Message
        foreach ($row in $Rows) { Write-PraCloudError -Context $Context -Row $row -Message $failure }
        if ($Rows.Count -eq 0) { Write-PraCloudError -Context $Context -Row $null -Message $failure }
    } finally {
        try { Close-PraCloudSession $Context }
        catch { foreach ($row in $Rows) { Write-PraCloudError -Context $Context -Row $row -Message ('Sign-out after the retention check failed: '+$_.Exception.Message) } }
    }
}

Export-ModuleMember -Function Initialize-PraCloudPreflight,Invoke-PraCloudPhase,Invoke-PraRetentionCheck,Close-PraCloudSession
