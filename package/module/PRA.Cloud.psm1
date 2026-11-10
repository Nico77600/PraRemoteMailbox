<#
.SYNOPSIS
    PRA Remote Mailbox - Exchange Online and Microsoft Graph adapter (no AD read or write).

.DESCRIPTION
    Public functions (no pipeline output; result rows are updated in place; an error sets the row to
    Error and records a run error, or throws):

      Initialize-PraCloudPreflight  Convert or Recover, Apply, phase Both: sign-in, targets (and, for Convert,
                                    trustees) resolved in Exchange Online BEFORE the AD part (read only)
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

    Sessions: Microsoft Graph is connected before Exchange Online (kept from 2.x, where both modules shared
    one set of assemblies under Windows PowerShell 5.1; free of cost under PowerShell 7); an Exchange Online
    or Graph session that already exists in the console is refused;
    tenant, token, connection ID and module path are checked before each call. Exo.UseSubprocess (or
    an ExchangeOnlineManagement older than Exo.MinModuleVersion) runs every Exchange Online call in a
    child PowerShell 7 process (certificate sign-in only).

.NOTES
    Author  : Nicolas Fabert
    Version : 3.1.2
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

# Fixed worker body, also run in the child process: no code or cmdlet name ever comes from data.
$script:PraExoWorker = {
    param([ValidateSet('Probe','Preflight','Mailbox','Recipient','Hold','Permission','Grant')][string]$Operation,$P,$Permit,$SessionBinding,$OnApplied,$OnProgress)
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
    # Ordinal comparisons only (the child process cannot load PRA.Common): on .NET with ICU, -eq/-ceq/-in/-like/switch and the
    # string overloads of StartsWith/IndexOf ignore zero-weight characters (U+0001, U+200B...), so "a" would equal "a<U+0001>".
    function SameOrdinal { param($A,$B) if ($null -eq $A -or $null -eq $B) { return ($null -eq $A -and $null -eq $B) }; return [string]::Equals([string]$A,[string]$B,[StringComparison]::Ordinal) }
    function SameIgnoreCase { param($A,$B) if ($null -eq $A -or $null -eq $B) { return ($null -eq $A -and $null -eq $B) }; return [string]::Equals([string]$A,[string]$B,[StringComparison]::OrdinalIgnoreCase) }
    function InSet {
        param($Value,$Set,[switch]$IgnoreCase)
        $comparison=if ($IgnoreCase) { [StringComparison]::OrdinalIgnoreCase } else { [StringComparison]::Ordinal }
        foreach ($item in @($Set)) {
            if ($null -eq $item -or $null -eq $Value) { if ($null -eq $item -and $null -eq $Value) { return $true }; continue }
            if ([string]::Equals([string]$Value,[string]$item,$comparison)) { return $true }
        }
        return $false
    }
    function InSetIgnoreCase { param($Value,$Set) return (InSet -Value $Value -Set $Set -IgnoreCase) }
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
        $tenantOk=(SameIgnoreCase $sessionTenant $tenant) -or ($organization -and (SameIgnoreCase $sessionTenant $organization))
        if ($appId -and -not (SameIgnoreCase ([string](V $c 'AppId' '')) $appId)) { $tenantOk=$false }
        if (-not $tenantOk -or -not (SameIgnoreCase ([string](V $c 'State' '')) 'Connected') -or
            -not (SameIgnoreCase ([string](V $c 'TokenStatus' '')) 'Active') -or -not $id -or -not [IO.Path]::IsPathRooted($location)) {
            throw ("Exchange Online session: wrong tenant ({0}), state, token, connection ID or module path." -f $sessionTenant)
        }
        $modules=@(Get-Module | Where-Object { (SameIgnoreCase $_.ModuleBase $location) -or (SameIgnoreCase $_.Path $location) })
        if ($modules.Count -ne 1 -or -not $modules[0].Path) { throw 'Module of the Exchange Online session not found or ambiguous.' }
        if ($null -ne $SessionBinding -and (V $SessionBinding 'ConnectionId' '')) {
            if (-not (SameIgnoreCase $id (V $SessionBinding 'ConnectionId')) -or -not (SameIgnoreCase $location (V $SessionBinding 'ModuleLocation')) -or
                -not (SameIgnoreCase $modules[0].Path (V $SessionBinding 'ModulePath'))) { throw 'The Exchange Online session changed.' }
        }
        $command=$null
        if ($Right) {
            $name=if (SameIgnoreCase $Right 'FullAccess') { 'Add-MailboxPermission' } elseif (SameIgnoreCase $Right 'SendAs') { 'Add-RecipientPermission' } elseif (SameIgnoreCase $Right 'SendOnBehalf') { 'Set-Mailbox' } else { throw 'Unknown permission.' }
            $commands=@(Get-Command -Name $name -Module $modules[0].Name -All -ErrorAction Stop)
            if ($commands.Count -ne 1 -or $null -eq $commands[0].Module -or -not (SameIgnoreCase $commands[0].Module.Path $modules[0].Path)) {
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
            $payload=$json.Value | ConvertFrom-Json -DateKind String -ErrorAction Stop
            # Substring searches are ordinal and case-insensitive (the former -like was case-insensitive, and culture-sensitive under ICU).
            $object="object '"+$Upn+"' couldn't be found"
            $detail=@($payload.error.details | Where-Object { ([string]$_.message).IndexOf('|Microsoft.Exchange.Configuration.Tasks.ManagementObjectNotFoundException|',[StringComparison]::OrdinalIgnoreCase) -ge 0 })
            return ((SameOrdinal $payload.error.code 'NotFound') -and ([string]$payload.error.message).IndexOf($object,[StringComparison]::OrdinalIgnoreCase) -ge 0 -and $detail.Count -gt 0 -and ([string]$detail[0].message).IndexOf($object,[StringComparison]::OrdinalIgnoreCase) -ge 0)
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
        if ($null -ne $expected -and (-not (SameIgnoreCase $oid (V $expected 'ObjectId')) -or -not (SameIgnoreCase $smtp (V $expected 'PrimarySmtpAddress')))) { throw "Recipient identity changed since the pre-check: $Upn" }
        $keys = @($Upn) + @(foreach ($key in @('UserPrincipalName','PrimarySmtpAddress','ExternalDirectoryObjectId','Guid','DistinguishedName','Identity','Alias','Name','DisplayName','Sid','SamAccountName')) {
            $val = [string](V $items[0] $key); if (-not [string]::IsNullOrWhiteSpace($val)) { $val }
        })
        $seenKeys = New-Object 'System.Collections.Generic.HashSet[string]' -ArgumentList ([StringComparer]::OrdinalIgnoreCase)
        return @{ Found=$true; Type=$type; Keys=@($keys | Where-Object { $seenKeys.Add([string]$_) }); ObjectId=$oid; PrimarySmtpAddress=$smtp }
    }
    function Mailbox {
        param([string]$Upn,[switch]$Hold)
        $grantParameters = @{ Filter=(ExactFilter $Upn); Properties=@('RecipientTypeDetails','EmailAddresses','LegacyExchangeDN'); ResultSize='Unlimited' }
        if ($Hold) { $grantParameters.Properties += @('IsInactiveMailbox','InPlaceHolds','LitigationHoldEnabled','RetentionHoldEnabled') }
        $items = @(Get-EXOMailbox @grantParameters -ErrorAction Stop)
        if ($Hold -and $items.Count -eq 0) { $items = @(Get-EXOMailbox @grantParameters -InactiveMailboxOnly -ErrorAction Stop) }
        if ($items.Count -gt 1) { throw "Exchange Online mailbox not unique: $Upn" }
        if ($items.Count -eq 0) { return @{ Found=$false; Type=$null; Holds=@(); IsInactive=$false; Litigation=$false; RetentionHold=$false; HasAddresses=$false; Addresses=[string[]]@() } }
        $m = $items[0]; $type = [string](V $m 'RecipientTypeDetails')
        if (-not $type) { throw "Mailbox type not returned: $Upn" }
        $holds = V -Object $m -Name 'InPlaceHolds' -Default @()
        # EmailAddresses (every proxy address of the mailbox, X500 included): whether Exchange Online returned the property at all is kept apart from "empty".
        $hasAddresses = if ($m -is [System.Collections.IDictionary]) { $m.Contains('EmailAddresses') } else { $null -ne $m.PSObject.Properties['EmailAddresses'] }
        $rawAddresses = V -Object $m -Name 'EmailAddresses' -Default @()
        # Exchange Online never lists the LegacyExchangeDN of a mailbox in its own EmailAddresses, but Entra Connect may have written it on premises as an X500 address
        # while the object was still a MailUser: the mailbox counts as carrying X500:<its own LegacyExchangeDN> (the whole value is compared ignoring case, like every X500).
        $ownDn = [string](V -Object $m -Name 'LegacyExchangeDN' -Default '')
        $addressList = @($rawAddresses | Where-Object { $null -ne $_ } | ForEach-Object { [string]$_ })
        if ($ownDn -and -not (InSetIgnoreCase ('X500:' + $ownDn) $addressList)) { $addressList += ('X500:' + $ownDn) }
        return @{ Found=$true; Type=$type; Holds=@($holds | Where-Object { $null -ne $_ }); IsInactive=[bool](V -Object $m -Name 'IsInactiveMailbox' -Default $false)
            Litigation=[bool](V -Object $m -Name 'LitigationHoldEnabled' -Default $false); RetentionHold=[bool](V -Object $m -Name 'RetentionHoldEnabled' -Default $false)
            HasAddresses=[bool]$hasAddresses; Addresses=[string[]]$addressList }
    }
    function NormalizeAcl {
        param([object[]]$Entries,[string]$Right,$Target)
        $field=if ((SameIgnoreCase $Right 'FullAccess')) { 'User' } else { 'Trustee' }
        foreach ($entry in $Entries) {
            foreach ($key in @('Identity',$field,'AccessRights','IsInherited')) {
                if ($null -eq (V $entry $key)) { throw "$Right permission entry: field $key missing or null" }
            }
            $identity=[string](V $entry 'Identity'); $principal=[string](V $entry $field)
            $inherited=V $entry 'IsInherited'; $rawRights=V $entry 'AccessRights'; $rawRights=@($rawRights)
            if (-not (InSetIgnoreCase $identity $Target.Keys) -or [string]::IsNullOrWhiteSpace($principal) -or $inherited -isnot [bool] -or $rawRights.Count -eq 0) { throw "Unexpected $Right permission entry (format or identity)." }
            $rights=@(foreach ($access in $rawRights) {
                if (($access -isnot [string] -and $access -isnot [enum]) -or [string]::IsNullOrWhiteSpace([string]$access)) { throw "Invalid $Right access right type." }
                [string]$access
            })
            if ((SameIgnoreCase $Right 'FullAccess')) {
                $deny=V $entry 'Deny'
                if ($deny -is [System.Management.Automation.SwitchParameter]) { $deny=$deny.IsPresent }
                if ($deny -isnot [bool]) { throw 'Invalid FullAccess Deny value.' }
                $control=if ($deny) { 'Deny' } else { 'Allow' }
            } else {
                $rawControl=V $entry 'AccessControlType'
                if ($rawControl -isnot [string] -and $rawControl -isnot [enum]) { throw 'Invalid AccessControlType type.' }
                $control=[string]$rawControl
                if (-not (InSetIgnoreCase $control @('Allow','Deny'))) { throw 'Invalid AccessControlType value.' }
                $control=if (SameIgnoreCase $control 'Deny') { 'Deny' } else { 'Allow' }
            }
            if ((SameIgnoreCase $control 'Deny') -and (InSetIgnoreCase $Right $rights)) { throw "A $Right Deny entry exists: grant refused." }
            [pscustomobject]@{ Identity=$identity; Principal=$principal; Rights=$rights; Control=$control; Inherited=$inherited }
        }
    }
    function AclKey {
        param($Entry)
        $sortedRights=[string[]]@($Entry.Rights | ForEach-Object { $_.ToLowerInvariant() })
        [Array]::Sort($sortedRights,[StringComparer]::Ordinal)
        return ($Entry.Principal+'|'+$Entry.Control+'|'+$Entry.Inherited+'|'+($sortedRights -join ',')).ToLowerInvariant()
    }
    function MissingFullAccess {
        param([System.Management.Automation.ErrorRecord]$Record,[string]$Trustee)
        $json=[regex]::Match($Record.Exception.Message,'(?s)\{\s*"error"\s*:\s*\{.*\}\s*\}')
        if (-not $json.Success) { return $false }
        try {
            $payload=$json.Value | ConvertFrom-Json -DateKind String -ErrorAction Stop
            # The message prefix stays an exact (case-sensitive) match. The trustee echoed by Exchange Online is compared
            # case-insensitively: the service may return the UPN or alias with another casing than the one requested.
            $prefix='No permissions were found for the user:'
            $messages=@([string]$payload.error.message,[string]$payload.error.innererror.message)
            foreach ($message in $messages) {
                if (-not $message.StartsWith($prefix,[StringComparison]::Ordinal) -or
                    -not [string]::Equals($message.Substring($prefix.Length),$Trustee,[StringComparison]::OrdinalIgnoreCase)) { return $false }
            }
            return ((SameOrdinal $payload.error.code 'NotFound') -and (SameOrdinal $payload.error.innererror.type 'Microsoft.Exchange.Admin.OData.Core.ODataServiceException'))
        } catch { return $false }
    }
    function Permission {
        param([string]$Upn,[string]$Trustee,[string]$Right,$Recipient,$Target,[switch]$AllowPendingVisibility)
        if ((SameIgnoreCase $Right 'FullAccess') -or (SameIgnoreCase $Right 'SendAs')) {
            $globalRaw=@(if ((SameIgnoreCase $Right 'FullAccess')) { Get-EXOMailboxPermission -Identity $Upn -ErrorAction Stop -WarningAction Stop }
                else { Get-EXORecipientPermission -Identity $Upn -ErrorAction Stop -WarningAction Stop })
            if ($globalRaw.Count -eq 0 -or $globalRaw.Count -ge 1000) { throw "$Right permission list empty or possibly truncated." }
            $globalEntries=@(NormalizeAcl $globalRaw $Right $Target)
            if (-not @($globalEntries | Where-Object { (InSetIgnoreCase $_.Principal @('NT AUTHORITY\SELF','S-1-5-10')) -and (InSetIgnoreCase $Right $_.Rights) -and -not $_.Inherited }).Count) { throw "$Right permission list without the expected SELF entry." }
            $expectedEntries=@($globalEntries | Where-Object { (InSetIgnoreCase $Right $_.Rights) -and (InSetIgnoreCase $_.Principal $Recipient.Keys) })
            # "No permissions were found" is the normal answer before a grant. It is read through -ErrorVariable,
            # not -ErrorAction Stop, so that Windows PowerShell does not write it as an error in the transcript.
            # Every error record is still checked: anything else than that exact answer stops, as before.
            $filteredErrors=$null
            $filteredRaw=@(if ((SameIgnoreCase $Right 'FullAccess')) { Get-EXOMailboxPermission -Identity $Upn -User $Trustee -ErrorAction SilentlyContinue -ErrorVariable filteredErrors -WarningAction Stop }
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
            foreach ($entry in $entries) { if (-not (InSetIgnoreCase $entry.Principal $Recipient.Keys)) { throw "Filtered $Right read inconsistent for $Trustee." } }
            $actualEntries=@($entries | Where-Object { InSetIgnoreCase $Right $_.Rights })
            $expected=[string[]]@($expectedEntries | ForEach-Object { AclKey $_ }); [Array]::Sort($expected,[StringComparer]::Ordinal)
            $actual=[string[]]@($actualEntries | ForEach-Object { AclKey $_ }); [Array]::Sort($actual,[StringComparer]::Ordinal)
            if (-not (SameOrdinal ($expected | ConvertTo-Json -Compress) ($actual | ConvertTo-Json -Compress))) {
                if ($AllowPendingVisibility -and (($expected.Count -eq 0) -xor ($actual.Count -eq 0))) { return $false }
                throw "Full and filtered $Right reads disagree for $Trustee."
            }
            return (@($actualEntries | Where-Object { -not $_.Inherited -and (SameIgnoreCase $_.Control 'Allow') }).Count -gt 0)
        }
        $mb = @(Get-Mailbox -Filter (ExactFilter $Upn) -ResultSize Unlimited -ErrorAction Stop)
        if ($mb.Count -ne 1) { throw "Mailbox not unique for the SendOnBehalf read: $Upn" }
        $delegates=V -Object $mb[0] -Name 'GrantSendOnBehalfTo' -Default @()
        foreach ($delegate in $delegates) {
            if ($null -eq $delegate) { continue }
            $ids = @([string]$delegate, [string](V $delegate 'DistinguishedName'), [string](V $delegate 'ObjectGuid'))
            if (@($ids | Where-Object { $_ -and (InSetIgnoreCase $_ $Recipient.Keys) }).Count) { return $true }
            # Exchange Online can return an ADObjectId as a Name: exact resolution, an ambiguity stops.
            $name = ([string]$delegate).Replace("'","''")
            $resolved = @(Get-EXORecipient -Filter "Name -eq '$name'" -Properties Guid,DistinguishedName,ExternalDirectoryObjectId -ResultSize Unlimited -ErrorAction Stop)
            if ($resolved.Count -gt 1) { throw "SendOnBehalf delegate not unique: $delegate" }
            foreach ($r in $resolved) {
                foreach ($key in @('Guid','DistinguishedName','ExternalDirectoryObjectId')) {
                    $id = [string](V $r $key); if ($id -and (InSetIgnoreCase $id $Recipient.Keys)) { return $true }
                }
            }
        }
        return $false
    }
    # The ValidateSet of the worker accepts any casing and, under ICU, names with an invisible character: only the exact names pass.
    if (-not (InSet $Operation @('Probe','Preflight','Mailbox','Recipient','Hold','Permission','Grant'))) { throw 'Unknown Exchange Online operation.' }
    $binding=Session
    if ((SameIgnoreCase $Operation 'Probe')) { [void]$binding.Remove('Command'); return @{ Connected=$true; Binding=$binding } }
    $SessionBinding=$binding
    $upn = [string](V $P 'Upn')
    if ((SameIgnoreCase $Operation 'Preflight')) {
        $target=Recipient $upn
        if (-not $target.Found) { throw "Target not found in Exchange Online at the pre-check: $upn" }
        $identities=@{}; $identities[$upn]=$target
        $requests=V $P 'Requests' @()
        foreach ($request in @($requests)) {
            $trustee=[string](V $request 'Trustee'); $right=[string](V $request 'Right')
            $null=Session $right
            $resolved=Recipient $trustee
            if (-not $resolved.Found) { throw "Trustee not found in Exchange Online at the pre-check: $trustee" }
            if (SameIgnoreCase $resolved.ObjectId $target.ObjectId) { throw 'A mailbox cannot be delegated to itself.' }
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
    if (-not (InSetIgnoreCase $right @('FullAccess','SendAs','SendOnBehalf'))) { throw 'Unknown permission.' }
    # From here on the right has its official spelling (the permit below is still compared with the right as it was requested).
    $requestedRight = $right
    $right = @('FullAccess','SendAs','SendOnBehalf') | Where-Object { SameIgnoreCase $_ $requestedRight } | Select-Object -First 1
    if ((SameIgnoreCase $Operation 'Grant')) {
        foreach ($flag in @('AllowMutation','Approved','Authorized','JournalStarted')) {
            $b = V -Object $Permit -Name $flag -Default $false
            if ($b -isnot [bool] -or -not $b) { throw 'Exchange Online grant without its individual authorisation.' }
        }
        if (-not (SameOrdinal (V $Permit 'Target') $upn) -or -not (SameOrdinal (V $Permit 'Trustee') $trustee) -or -not (SameOrdinal (V $Permit 'Right') $requestedRight) -or
            -not (SameIgnoreCase (V $Permit 'Action') 'Convert') -or -not (SameIgnoreCase (V $Permit 'Mode') 'Apply') -or -not (InSetIgnoreCase (V $Permit 'Phase') @('Cloud','Both'))) { throw 'Exchange Online authorisation does not match this grant.' }
        if (-not (SameIgnoreCase (Mailbox $upn).Type 'SharedMailbox')) { throw 'Grant refused: SharedMailbox not confirmed.' }
    }
    $rcpt = Recipient $trustee
    if (-not $rcpt.Found) {
        if ((SameIgnoreCase $Operation 'Grant')) { throw "Trustee no longer in Exchange Online: $trustee" }
        return @{ TrusteeFound=$false; Verified=$false; Mutated=$false }
    }
    $target=Recipient $upn
    if (-not $target.Found) { throw "Target not found in Exchange Online: $upn" }
    if ((SameIgnoreCase $Operation 'Grant') -and -not (SameIgnoreCase $target.Type 'SharedMailbox')) { throw 'Grant refused: SharedMailbox recipient not confirmed.' }
    if (SameIgnoreCase $target.ObjectId $rcpt.ObjectId) { throw 'A mailbox cannot be delegated to itself.' }
    $ok = Permission -Upn $upn -Trustee $trustee -Right $right -Recipient $rcpt -Target $target
    if ((SameIgnoreCase $Operation 'Permission') -or $ok) { return @{ TrusteeFound=$true; Verified=[bool]$ok; Mutated=$false } }
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
                if (-not $pair[1].Found -or -not (SameIgnoreCase $pair[0].ObjectId $pair[1].ObjectId) -or -not (SameIgnoreCase $pair[0].PrimarySmtpAddress $pair[1].PrimarySmtpAddress) -or -not (SameIgnoreCase $pair[0].Type $pair[1].Type)) { throw 'Exchange Online identity changed during the verification.' }
            }
            if (-not (SameIgnoreCase (Mailbox $upn).Type 'SharedMailbox')) { throw 'SharedMailbox lost during the verification.' }
            if (Permission -Upn $upn -Trustee $trustee -Right $right -Recipient $currentTrustee -Target $currentTarget -AllowPendingVisibility) {
                return @{ TrusteeFound=$true; Verified=$true; Mutated=$true; Error='' }
            }
            if ($OnProgress -is [scriptblock]) { $null=& $OnProgress $attempt $attempts $(if ($attempt -lt $attempts) { $delay } else { 0 }) }
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

function Read-PraExoProgress {
    <# New complete lines of the progress file of the child process (from Offset); each valid line is passed to Relay (attempt, max, next). Returns the new offset. #>
    param([string]$Path,[long]$Offset,[scriptblock]$Relay)
    if (-not [IO.File]::Exists($Path)) { return $Offset }
    try {
        $stream=New-Object IO.FileStream($Path,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::ReadWrite)
        try {
            if ($stream.Length -le $Offset) { return $Offset }
            [void]$stream.Seek($Offset,[IO.SeekOrigin]::Begin)
            $bytes=New-Object byte[] ([int][Math]::Min(65536,$stream.Length-$Offset))
            $count=$stream.Read($bytes,0,$bytes.Length)
        } finally { $stream.Dispose() }
        $text=(New-Object Text.UTF8Encoding($false)).GetString($bytes,0,$count)
        $end=$text.LastIndexOf("`n",[StringComparison]::Ordinal)
        if ($end -lt 0) { return $Offset }
        foreach ($line in $text.Substring(0,$end).Split("`n")) {
            try {
                $entry=$line | ConvertFrom-PraJson
                $null=& $Relay ([int](Get-PraValue $entry 'Attempt' 0)) ([int](Get-PraValue $entry 'Max' 0)) ([int](Get-PraValue $entry 'Next' 0))
            } catch { $null=$_ }
        }
        return ($Offset+(New-Object Text.UTF8Encoding($false)).GetByteCount($text.Substring(0,$end+1)))
    } catch { return $Offset }
}

function Invoke-PraExoSubprocess {
    param([hashtable]$Context,[string]$Operation,[hashtable]$Params,$Permit,$OnApplied,$OnProgress)
    $cloud = Get-PraValue $Context.Config 'Cloud' @{}
    $id = [guid]::NewGuid().ToString('N')
    $appliedPath=Join-Path ([IO.Path]::GetTempPath()) ('praexo_'+$id+'.applied.json')
    $progressPath=Join-Path ([IO.Path]::GetTempPath()) ('praexo_'+$id+'.progress.jsonl')
    $request = @{ Protocol=1; Id=$id; Operation=$Operation; Params=$Params; Permit=$Permit; AppliedPath=$appliedPath; ProgressPath=$progressPath
        TenantId=(Get-PraValue $cloud 'TenantId' ''); DisableWAM=(Get-PraValue (Get-PraValue $Context.Config 'Exo' @{}) 'DisableWAM' $false)
        AppId=(Get-PraValue $cloud 'AppId' ''); Thumb=(Get-PraValue $cloud 'CertificateThumbprint' ''); Org=(Get-PraValue $cloud 'Organization' '') }
    $b64 = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes(($request | ConvertTo-Json -Depth 12 -Compress)))
    $child = @'
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
[Console]::OutputEncoding = New-Object Text.UTF8Encoding($false)
$ProgressPreference='SilentlyContinue'
# The parent accepts ONE line of JSON on stdout and nothing on stderr. A module warning (ExchangeOnlineManagement prints
# update and deprecation notices) or an information record must not reach those streams. Errors are NOT silenced:
# $ErrorActionPreference='Stop' turns them into the JSON failure, and the worker's own -WarningAction Stop calls
# (explicit on the cmdlet) still turn a warning raised by a cmdlet of the worker into a failure (fail closed).
$WarningPreference='SilentlyContinue'; $InformationPreference='SilentlyContinue'
$cfg=$null; $data=$null; $failure=''; $attempted=$false; $ownedIds=@()
try {
    $cfg = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('__REQUEST__')) | ConvertFrom-Json -DateKind String -ErrorAction Stop
    if ($cfg.Protocol -ne 1 -or $cfg.Id -notmatch '^[a-f0-9]{32}\z') { throw 'Invalid Exchange Online request.' }
    Import-Module ExchangeOnlineManagement -ErrorAction Stop
    if (@(Get-ConnectionInformation -ErrorAction Stop).Count) { throw 'The Exchange Online child process is not clean.' }
    $connect=@{ AppId=$cfg.AppId; CertificateThumbprint=$cfg.Thumb; Organization=$cfg.Org; ShowBanner=$false; ErrorAction='Stop' }
    if ($cfg.DisableWAM) {
        if (-not (Get-Command Connect-ExchangeOnline -ErrorAction Stop).Parameters.ContainsKey('DisableWAM')) { throw 'DisableWAM is not supported by this ExchangeOnlineManagement.' }
        $connect.DisableWAM=$true
    }
    $attempted=$true
    try { Connect-ExchangeOnline @connect -WarningAction SilentlyContinue -InformationAction SilentlyContinue 6>$null 3>$null | Out-Null }
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
    $onProgress={
        param($attempt,$max,$next)
        $line=(@{ Attempt=[int]$attempt; Max=[int]$max; Next=[int]$next } | ConvertTo-Json -Compress)+"`n"
        [IO.File]::AppendAllText($cfg.ProgressPath,$line,(New-Object Text.UTF8Encoding($false)))
    }
    $results = @(& $worker $cfg.Operation $cfg.Params $cfg.Permit $probe.Binding $onApplied $onProgress)
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
[Console]::Out.WriteLine(([ordered]@{ Protocol=1; Id=$correlation; Ok=($failure.Length -eq 0); Data=$data; Error=$failure } | ConvertTo-Json -Depth 12 -Compress))
if ($failure) { exit 1 }; exit 0
'@
    $child = $child.Replace('__REQUEST__',$b64).Replace('__WORKER__',$script:PraExoWorker.ToString())
    $tmp = Join-Path ([IO.Path]::GetTempPath()) ('praexo_'+$id+'.ps1')
    $process = $null; $started=$false
    try {
        [IO.File]::WriteAllText($tmp,$child,(New-Object Text.UTF8Encoding($true)))
        $exe = Join-Path $PSHOME 'pwsh.exe'
        if (-not [IO.File]::Exists($exe)) { throw 'PowerShell 7 (pwsh.exe) is not available for the Exchange Online child process.' }
        $si = New-Object Diagnostics.ProcessStartInfo
        $si.FileName=$exe; $si.Arguments='-NoProfile -NonInteractive -ExecutionPolicy Bypass -File "'+$tmp+'"'
        $si.UseShellExecute=$false; $si.CreateNoWindow=$true; $si.RedirectStandardOutput=$true; $si.RedirectStandardError=$true
        $si.StandardOutputEncoding=New-Object Text.UTF8Encoding($false); $si.StandardErrorEncoding=New-Object Text.UTF8Encoding($false)
        $process = New-Object Diagnostics.Process; $process.StartInfo=$si
        $started=$process.Start()
        if (-not $started) { throw 'The Exchange Online child process cannot start.' }
        $stdout = $process.StandardOutput.ReadToEndAsync(); $stderr = $process.StandardError.ReadToEndAsync()
        $wait = [int][Math]::Min(2147483647,([Math]::Max(1,[int]$Context.TimeoutMinutes)*60000.0))
        # The wait is a loop: every second the progress lines the child appended (one per verification read) are relayed to the window.
        $waitClock=[Diagnostics.Stopwatch]::StartNew(); $progressOffset=[long]0; $timedOut=$false
        while ($true) {
            if ($process.WaitForExit(1000)) { break }
            if ($waitClock.ElapsedMilliseconds -ge $wait) { $timedOut=$true; $process.Kill(); $process.WaitForExit(); break }
            if ($OnProgress -is [scriptblock]) { $progressOffset=Read-PraExoProgress -Path $progressPath -Offset $progressOffset -Relay $OnProgress }
        }
        if ($OnProgress -is [scriptblock]) { $progressOffset=Read-PraExoProgress -Path $progressPath -Offset $progressOffset -Relay $OnProgress }
        $out = $stdout.GetAwaiter().GetResult().Trim(); $err = $stderr.GetAwaiter().GetResult().Trim()
        if ($timedOut) { throw "Exchange Online timeout; write state unknown. stderr=[$err], stdout=[$out]" }
        if ($process.ExitCode -ne 0 -or $err) { throw "Exchange Online child process code=$($process.ExitCode), stderr=[$err], stdout=[$out]" }
        if (-not $out.StartsWith('{',[StringComparison]::Ordinal) -or -not $out.EndsWith('}',[StringComparison]::Ordinal) -or $out -match '[\r\n]') { throw 'Exchange Online child output is not the expected one-line JSON.' }
        $res = $out | ConvertFrom-PraJson
        if (@($res.PSObject.Properties.Name).Count -ne 5 -or (Get-PraValue $res 'Protocol' 0) -ne 1 -or
            -not (Test-PraOrdinalEqual (Get-PraValue $res 'Id' '') $id) -or (Get-PraValue $res 'Ok' $false) -isnot [bool] -or
            (Get-PraValue $res 'Ok' $false) -ne $true -or -not (Test-PraOrdinalEqual (Get-PraValue $res 'Error' 'invalid') '')) { throw 'Exchange Online child result invalid or failed.' }
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
                    $receipt=[IO.File]::ReadAllText($appliedPath) | ConvertFrom-PraJson
                    if ((-not (Test-PraOrdinalIgnoreCaseEqual $Operation 'Grant')) -or $receipt.Protocol -ne 1 -or -not (Test-PraOrdinalEqual $receipt.Id $id) -or -not (Test-PraOrdinalEqual $receipt.Status 'Applied') -or
                        -not (Test-PraOrdinalEqual $receipt.Target $Params.Upn) -or -not (Test-PraOrdinalEqual $receipt.Trustee $Params.Trustee) -or -not (Test-PraOrdinalEqual $receipt.Right $Params.Right) -or $OnApplied -isnot [scriptblock]) { throw 'Invalid Applied receipt from the Exchange Online child process.' }
                    $null=& $OnApplied
                    [IO.File]::Delete($appliedPath)
                }
            } finally { foreach ($leftover in @($tmp,$progressPath)) { if ([IO.File]::Exists($leftover)) { [IO.File]::Delete($leftover) } } }
        }
    }
}

function Invoke-PraExo {
    param([hashtable]$Context,[ValidateSet('Probe','Preflight','Mailbox','Recipient','Hold','Permission','Grant')][string]$Operation,[hashtable]$Params=@{},$Permit=$null,$OnApplied=$null,$OnProgress=$null)
    $session = Get-PraCloudSession $Context
    if (-not $session.Exo) { throw 'Exchange Online connection required but not available.' }
    if (-not $session.Subprocess -and -not (Test-PraOrdinalIgnoreCaseEqual ([string](Get-PraValue (Get-PraValue $session 'Binding' $null) 'TenantId' '')) ([string](Get-PraValue (Get-PraValue $Context.Config 'Cloud' @{}) 'TenantId' '')))) { throw 'Exchange Online tenant of the session differs from Cloud.TenantId.' }
    if ((Test-PraOrdinalIgnoreCaseEqual $Operation 'Grant') -and ($null -eq $Permit -or $Context.AllowMutation -isnot [bool] -or -not $Context.AllowMutation -or
        -not (Test-PraOrdinalEqual $Context.Mode 'Apply') -or -not (Test-PraOrdinalEqual $Context.Action 'Convert') -or -not (Test-PraOrdinalIn $Context.Phase @('Cloud','Both')) -or $WhatIfPreference)) { throw 'Grant without an active write authorisation.' }
    $Params=$Params.Clone()
    $Params.ExpectedIdentities=Get-PraValue $session 'Identities' @{}
    if ((Test-PraOrdinalIgnoreCaseEqual $Operation 'Grant')) {
        $exo=Get-PraValue $Context.Config 'Exo' @{}
        $Params.GrantVerifyAttempts=Get-PraValue $exo 'GrantVerifyAttempts' 13
        $Params.GrantVerifyDelaySeconds=Get-PraValue $exo 'GrantVerifyDelaySeconds' 10
    }
    $results = @(if ($session.Subprocess) { Invoke-PraExoSubprocess -Context $Context -Operation $Operation -Params $Params -Permit $Permit -OnApplied $OnApplied -OnProgress $OnProgress }
        else { & $script:PraExoWorker $Operation $Params $Permit (Get-PraValue $session 'Binding' $null) $OnApplied $OnProgress })
    if ($results.Count -ne 1) { throw 'Exchange Online result not unique.' }
    $result=$results[0]
    $booleans=switch ($Operation) { 'Probe' { 'Connected' }; 'Permission' { 'TrusteeFound'; 'Verified' }; 'Grant' { 'TrusteeFound'; 'Verified'; 'Mutated' }; default { 'Found' } }
    foreach ($key in $booleans) { if ((Get-PraValue $result $key $null) -isnot [bool]) { throw "Invalid Exchange Online result: $key must be a boolean." } }
    if ((Test-PraOrdinalIn $Operation @('Mailbox','Recipient','Hold')) -and (Get-PraValue $result 'Found' $false) -and -not [string](Get-PraValue $result 'Type' '')) { throw 'Exchange Online result without type.' }
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
        # ONE version of every Graph module (the highest that exists for all, at the minimum or later): two versions in one session fail with an opaque assembly error.
        $modules = Get-PraCloudModuleReport -MinExo ([string](Get-PraValue (Get-PraValue $Context.Config 'Exo' @{}) 'MinModuleVersion' '3.10.1'))
        if (-not $modules.Graph.Ok) { throw $modules.Graph.Message }
        $graphVersion = [version]$modules.Graph.Version
        Import-Module Microsoft.Graph.Authentication -RequiredVersion $graphVersion -ErrorAction Stop
        Import-Module Microsoft.Graph.Users -RequiredVersion $graphVersion -ErrorAction Stop
        if ($null -ne (Get-MgContext -ErrorAction Stop)) { throw 'A Microsoft Graph session already exists in this console: run the tool in a new PowerShell 7 window.' }
        $connect=@{ TenantId=$tenant; ContextScope='Process'; NoWelcome=$true; ErrorAction='Stop' }
        if ($app) { $connect.ClientId=$app; $connect.CertificateThumbprint=$thumb } else { $connect.Scopes=@('User.Read.All') }
        $s.GraphAttempted=$true
        try { Connect-MgGraph @connect | Out-Null }
        catch {
            # Typical when Exchange Online was used earlier in the same console: its assemblies stay loaded.
            if ($_.Exception.Message -match 'does not have an implementation|Could not load (type|file or assembly)|Method not found') {
                throw ('Microsoft Graph cannot load in this console (assembly conflict, usually because Exchange Online was used earlier in the same window): run the tool in a new PowerShell 7 window. Detail: '+$_.Exception.Message)
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
        $min = [version][string](Get-PraValue $exo 'MinModuleVersion' '3.10.1')
        $modules = Get-PraCloudModuleReport -MinExo ([string]$min)
        if (-not $modules.Exo.Ok) { throw ($modules.Exo.Message + ' The tool never installs modules.') }
        $s.Subprocess = [bool](Get-PraValue $exo 'UseSubprocess' $false)
        if ($s.Subprocess) {
            if (-not $app) { throw 'Exchange Online child process required (Exo.UseSubprocess or old module): certificate sign-in is mandatory.' }
            $s.Exo=$true
            $probe = Invoke-PraExo $Context 'Probe'
            if ((Get-PraValue $probe 'Connected' $false) -ne $true) { throw 'Exchange Online child process connection not confirmed.' }
        } else {
            Import-Module ExchangeOnlineManagement -MinimumVersion $min -ErrorAction Stop
            if (@(Get-ConnectionInformation -ErrorAction Stop).Count) { throw 'An Exchange Online session already exists in this console: run the tool in a new PowerShell 7 window (nothing was signed out).' }
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
    if ($null -eq $current -or -not (Test-PraOrdinalIgnoreCaseEqual ([string](Get-PraValue $current 'TenantId' '')) $tenant) -or
        -not (Test-PraOrdinalIgnoreCaseEqual ([string](Get-PraValue $current 'ContextScope' '')) 'Process')) { throw 'Microsoft Graph session missing, on another tenant or not limited to this process.' }
    foreach ($key in @('TenantId','ClientId','Account','AuthType','ContextScope')) {
        if (-not (Test-PraOrdinalEqual ([string](Get-PraValue $current $key '')) ([string](Get-PraValue $s.GraphContext $key '')))) { throw 'The Microsoft Graph session changed.' }
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
                if (Test-PraOrdinalIgnoreCaseIn $id $currentIds) { Disconnect-ExchangeOnline -ConnectionId $id -Confirm:$false -ErrorAction Stop 6>$null | Out-Null }
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
                    if (-not (Test-PraOrdinalEqual ([string](Get-PraValue $current $key '')) ([string](Get-PraValue $s.GraphContext $key '')))) { throw 'The Microsoft Graph session was replaced: not signed out.' }
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
        if ((-not (Test-PraOrdinalIgnoreCaseEqual $right 'SendOnBehalf')) -and (Test-PraOrdinalIgnoreCaseEqual (Get-PraValue $cfg 'PermissionSource' 'None') 'None')) { continue }
        if ([bool](Get-PraValue $cfg ('Grant'+$right) $false)) {
            foreach ($u in @((Get-PraValue $Row ('Shared'+$right) @()) | Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) } | Get-PraOrdinalUnique -IgnoreCase)) {
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
        if (-not (Test-PraOrdinalIn $Context.Action @('Convert','Recover')) -or -not (Test-PraOrdinalEqual $Context.Mode 'Apply') -or -not (Test-PraOrdinalEqual $Context.Phase 'Both') -or
            $Context.AllowMutation -isnot [bool] -or -not $Context.AllowMutation -or $WhatIfPreference) { throw 'The pre-check is only for Convert or Recover, Apply, phase Both.' }
        # Recover mirrors the checks its cloud phase will make (mailbox gone, licence removed), so it needs the same
        # sessions; it has no trustees to resolve and does not pin identities (a deprovisioned user becomes a MailUser).
        $isRecover=(Test-PraOrdinalEqual $Context.Action 'Recover')
        $cloud=Get-PraValue $Context.Config 'Cloud' @{}; $exo=Get-PraValue $Context.Config 'Exo' @{}
        foreach ($key in @('CheckMailbox','CheckLicense')) { if ((Get-PraValue $cloud $key $false) -isnot [bool]) { throw "Cloud.$key must be `$true or `$false." } }
        foreach ($key in @('UseSubprocess','DisableWAM')) { if ((Get-PraValue $exo $key $false) -isnot [bool]) { throw "Exo.$key must be `$true or `$false." } }
        $attempts=Get-PraValue $exo 'GrantVerifyAttempts' 13; $delay=Get-PraValue $exo 'GrantVerifyDelaySeconds' 10
        if (($attempts -isnot [int] -and $attempts -isnot [long]) -or $attempts -lt 1 -or $attempts -gt 60 -or
            ($delay -isnot [int] -and $delay -isnot [long]) -or $delay -lt 1 -or $delay -gt 30) { throw 'Invalid Exchange Online verification cadence.' }
        $via=[string](Get-PraValue $cloud 'MailboxCheckVia' 'Exo')
        if (-not (Test-PraOrdinalIgnoreCaseIn $via @('Graph','Exo'))) { throw 'Invalid Cloud.MailboxCheckVia.' }
        $via=if (Test-PraOrdinalIgnoreCaseEqual $via 'Graph') { 'Graph' } else { 'Exo' }
        $needGraph=$false
        foreach ($row in $Rows) {
            if ((Get-PraValue $row 'IsShared' $false) -isnot [bool] -or (Test-PraOrdinalIgnoreCaseEqual (Get-PraValue $row 'FinalStatus' '') 'Error')) { throw 'Invalid or failed row at the pre-check.' }
            $shared=[bool](Get-PraValue $row 'IsShared' $false)
            $mailboxCheck=($isRecover -or [bool](Get-PraValue $cloud 'CheckMailbox' $false))
            if (-not $shared -and ([bool](Get-PraValue $cloud 'CheckLicense' $false) -or ($mailboxCheck -and (Test-PraOrdinalIgnoreCaseEqual $via 'Graph')))) { $needGraph=$true }
        }
        # EXO resolves each target even while it is still a MailUser; no provisioning assertion here.
        Connect-PraCloudSession -Context $Context -NeedGraph $needGraph -NeedExo ($Rows.Count -gt 0)
        $session=Get-PraCloudSession $Context
        foreach ($row in $Rows) {
            $upn=[string](Get-PraValue $row 'UserPrincipalName' '')
            $Context.CurrentIdentity=$upn; $Context.CurrentOperation='ResolvePreflightIdentity'
            $requests=if ($isRecover) { @() } else { @(Get-PraPermissionRequest $Context $row) }
            $result=Invoke-PraExo -Context $Context -Operation Preflight -Params @{ Upn=$upn; Requests=$requests }
            $identities=Get-PraValue $result 'Identities' @{}
            $names=if ($identities -is [System.Collections.IDictionary]) { @($identities.Keys) } else { @($identities.PSObject.Properties.Name) }
            foreach ($name in $names) {
                if ($isRecover) { continue }
                $identity=Get-PraValue $identities $name $null
                $previous=Get-PraValue $session.Identities $name $null
                if ($null -ne $previous -and (-not (Test-PraOrdinalIgnoreCaseEqual (Get-PraValue $previous 'ObjectId') (Get-PraValue $identity 'ObjectId')) -or
                    -not (Test-PraOrdinalIgnoreCaseEqual (Get-PraValue $previous 'PrimarySmtpAddress') (Get-PraValue $identity 'PrimarySmtpAddress')))) { throw 'Contradictory identities at the pre-check.' }
                $session.Identities[$name]=$identity
            }
            if ($needGraph -and -not [bool](Get-PraValue $row 'IsShared' $false)) {
                Assert-PraGraphSession $Context
                $users=@(Get-MgUser -UserId $upn -Property Id,UserPrincipalName -ErrorAction Stop)
                $target=Get-PraValue $identities $upn $null
                if ($users.Count -ne 1 -or -not (Test-PraOrdinalIgnoreCaseEqual ([string](Get-PraValue $users[0] 'Id' '')) ([string](Get-PraValue $target 'ObjectId' ''))) -or
                    -not (Test-PraOrdinalIgnoreCaseEqual ([string](Get-PraValue $users[0] 'UserPrincipalName' '')) $upn)) { throw "Graph and Exchange Online identities differ at the pre-check: $upn" }
            }
        }
        $session.Preflight=$true; $Context.CloudConnectFailed=$false
        $null=Write-PraLog -Context $Context -Message $(if ($isRecover) { 'Pre-check passed: {0} target(s) resolved in Exchange Online (read only)' -f $Rows.Count } else { 'Pre-check passed: {0} target(s) and their trustees resolved in Exchange Online (read only)' -f $Rows.Count }) -Level Success
    } catch {
        $failure=$_.Exception.Message; $Context.CloudConnectFailed=$true
        try { Close-PraCloudSession -Context $Context } catch { $failure+=' | sign-out after the pre-check: '+$_.Exception.Message }
        throw $failure
    }
}

function Invoke-PraPermissionGrant {
    param([hashtable]$Context,$Row,[hashtable]$Params)
    if ($Context.AllowMutation -isnot [bool] -or -not $Context.AllowMutation -or -not (Test-PraOrdinalEqual $Context.Mode 'Apply') -or
        -not (Test-PraOrdinalEqual $Context.Action 'Convert') -or -not (Test-PraOrdinalIn $Context.Phase @('Cloud','Both')) -or $WhatIfPreference) { throw 'Permission missing and writes are not allowed in this mode.' }
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
    if (-not $Context.AllowMutation -or -not (Test-PraOrdinalEqual $Context.Mode 'Apply') -or -not (Test-PraOrdinalEqual $Context.Action 'Convert') -or $WhatIfPreference) { throw 'Authorisation revoked.' }
    $detail="UPN=$target; Trustee=$($Params.Trustee); Right=$($Params.Right); ObjectGuid=$($Context.CurrentIdentity)"
    $Row.LastOperation=$operation
    $null = & $Context.JournalMutation $target $operation 'Started' $detail
    $permit=@{ AllowMutation=$true; Approved=$true; Authorized=$true; JournalStarted=$true; Target=$target
        Trustee=$Params.Trustee; Right=$Params.Right; Action=$Context.Action; Mode=$Context.Mode; Phase=$Context.Phase }
    try {
        $onApplied={ $null=& $Context.JournalMutation $target $operation 'Applied' ($detail+'; Add returned; verification pending') }.GetNewClosure()
        $exoSettings=Get-PraValue $Context.Config 'Exo' @{}
        $verifyAttempts=[int](Get-PraValue $exoSettings 'GrantVerifyAttempts' 13); $verifyDelay=[int](Get-PraValue $exoSettings 'GrantVerifyDelaySeconds' 10)
        Write-PraProgress -Context $Context -Text ("Granting {0} to {1} on {2}: the change is verified up to {3} times, {4} s apart" -f $Params.Right,$Params.Trustee,$target,$verifyAttempts,$verifyDelay) -Attempt 0 -MaxAttempts $verifyAttempts -NextInSeconds $verifyDelay
        $grantText="Verifying {0} for {1} on {2}" -f $Params.Right,$Params.Trustee,$target
        $onProgress={ param($attempt,$max,$next) Write-PraProgress -Context $Context -Text $grantText -Attempt $attempt -MaxAttempts $max -NextInSeconds $next }.GetNewClosure()
        $res = Invoke-PraExo -Context $Context -Operation 'Grant' -Params $Params -Permit $permit -OnApplied $onApplied -OnProgress $onProgress
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
    $preview=((Test-PraOrdinalEqual $Context.Action 'Convert') -and (-not (Test-PraOrdinalEqual $Context.Mode 'Apply') -or -not $Context.AllowMutation -or $WhatIfPreference))
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
            if ($Context.AllowMutation -isnot [bool] -or -not $Context.AllowMutation -or -not (Test-PraOrdinalEqual $Context.Mode 'Apply') -or
                -not (Test-PraOrdinalEqual $Context.Action 'Convert') -or -not (Test-PraOrdinalIn $Context.Phase @('Cloud','Both')) -or $WhatIfPreference) { throw 'Permission missing and writes are not allowed in this mode.' }
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
    param([hashtable]$Context,[string]$Upn,[bool]$Mailbox,[bool]$License,[bool]$Addresses=$false)
    if (-not (Get-PraCloudSession $Context).Graph) { throw 'Microsoft Graph required but not connected.' }
    Assert-PraGraphSession $Context
    $props=@('assignedPlans'); if ($Mailbox) { $props+='provisionedPlans' }; if ($License) { $props+='assignedLicenses' }; if ($Addresses) { $props+='proxyAddresses' }
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
    $enabled=@($values.assignedPlans | Where-Object { (Test-PraOrdinalIgnoreCaseEqual (Get-PraValue $_ 'Service' '') 'exchange') -and (Test-PraOrdinalIgnoreCaseEqual (Get-PraValue $_ 'CapabilityStatus' '') 'Enabled') }).Count -gt 0
    $prov=$false; $plans=@(); $sku=@()
    if ($Mailbox) { $prov=@($values.provisionedPlans | Where-Object { (Test-PraOrdinalIgnoreCaseEqual (Get-PraValue $_ 'Service' '') 'exchange') -and (Test-PraOrdinalIgnoreCaseEqual (Get-PraValue $_ 'ProvisioningStatus' '') 'Success') }).Count -gt 0 }
    $required=[string](Get-PraValue (Get-PraValue $Context.Config 'Cloud' @{}) 'RequiredSkuPartNumber' '')
    if ($Mailbox -or ($License -and $required)) {
        $details=@(Get-MgUserLicenseDetail -UserId $Upn -All -ErrorAction Stop)
        foreach ($d in $details) {
            $sku += [string](Get-PraValue $d 'SkuPartNumber' '')
            foreach ($p in @((Get-PraValue $d 'ServicePlans' @()) | Where-Object { ([string](Get-PraValue $_ 'ServicePlanName' '')).StartsWith('EXCHANGE_',[StringComparison]::OrdinalIgnoreCase) })) {
                $status=[string](Get-PraValue $p 'ProvisioningStatus' '')
                $plans += ([string](Get-PraValue $p 'ServicePlanName' '')+':'+$status)
                if (Test-PraOrdinalIgnoreCaseEqual $status 'Success') { $prov=$true }
            }
        }
    }
    $count=0; if ($License) { $count=$values.assignedLicenses.Count }
    return @{ Enabled=$enabled; Provisioned=$prov; LicenseCount=$count; RequiredSku=$required
        RequiredSkuOk=(-not $required -or (Test-PraOrdinalIgnoreCaseIn $required $sku)); Detail=($plans -join ','); Addresses=[string[]]@(if ($Addresses) { $values.proxyAddresses | ForEach-Object { [string]$_ } }) }
}

function Get-PraCloudAddress {
    <# Addresses of the cloud mailbox (read only): Exchange Online EmailAddresses, or the Entra proxyAddresses when the mailbox check goes through Graph. Has = the property was returned. #>
    param([hashtable]$Context,$State)
    if ($State.ExoMailbox) {
        $m = Invoke-PraExo -Context $Context -Operation 'Mailbox' -Params @{ Upn=$State.Upn }
        if ((Get-PraValue $m 'Found' $false) -ne $true) { throw 'the mailbox is no longer found in Exchange Online' }
        return @{ Has=[bool](Get-PraValue $m 'HasAddresses' $false); List=[string[]]@(Get-PraList $m 'Addresses') }
    }
    $facts = Get-PraGraphFact -Context $Context -Upn $State.Upn -Mailbox $false -License $false -Addresses $true
    return @{ Has=$true; List=[string[]]@($facts.Addresses) }
}

function Complete-PraX500Check {
    <# Result of the X500 control of one object: an Ok line when every expected address is there, otherwise ONE warning (the conversion itself stays done). #>
    param([hashtable]$Context,$State)
    $row = $State.Row; $failure = [string](Get-PraValue $State 'X500Failure' ''); $last = $State.X500Last
    $Context.CurrentIdentity = [string](Get-PraValue $row 'ObjectGuid' $State.Upn); $Context.CurrentOperation = 'X500Check'
    $State.Done = $true
    if (-not $failure -and $null -ne $last -and $last.Missing.Count -eq 0) {
        Write-PraItem -Context $Context -Status Ok -Text ('{0}: X500: {1} of {1} present (legacyExchangeDN + older X500)' -f $State.Upn, $last.Total)
        $row.CloudDetail = ([string]$row.CloudDetail + ' | X500:present=' + $last.Total + '/' + $last.Total).Trim(' ', '|')
        return
    }
    $advice = 'Not serious: the mailbox works. Until this address appears, a reply to a very old message could bounce. To fix it, run an Entra Connect sync, then run -Action Check.'
    if ($failure) {
        $text = '{0}: X500 could not be verified in Exchange Online ({1}). {2}' -f $State.Upn, $failure, $advice
        $row.CloudDetail = ([string]$row.CloudDetail + ' | X500:not verified').Trim(' ', '|')
    }
    else {
        $shown = @($last.Missing | Select-Object -First 5) -join ', '
        if ($last.Missing.Count -gt 5) { $shown += (' + {0} more (full list in the log)' -f ($last.Missing.Count - 5)) }
        foreach ($value in $last.Missing) { Write-PraLog -Context $Context -Message ('{0} | X500 missing in Exchange Online : {1}' -f $State.Upn, $value) -Level Detail }
        $text = '{0}: X500 missing in Exchange Online: {1}. {2}' -f $State.Upn, $shown, $advice
        $row.CloudDetail = ([string]$row.CloudDetail + ' | X500:missing=' + $last.Missing.Count + '/' + $last.Total).Trim(' ', '|')
    }
    Write-PraItem -Context $Context -Status Warn -Text $text
    $row.Warnings = ([string](Get-PraValue $row 'Warnings' '') + '; ' + $text).Trim(' ', ';')
    if (-not $Context.ContainsKey('X500Missing')) { $Context['X500Missing'] = New-Object 'Collections.Generic.List[string]' }
    [void]$Context['X500Missing'].Add([string]$State.Upn)
}

function Invoke-PraX500Step {
    <#
    .SYNOPSIS
        One read of the X500 control (Convert): the addresses read in this iteration (Fresh) or a new read. Returns true once the result is final:
        every address present, or the bounded number of reads used up, or Final (a single look: preview, -Once).
    #>
    param([hashtable]$Context,$State,$Fresh,[int]$MaxReads,[bool]$Final)
    $State.X500Reads++; $State.X500Failure = ''
    try {
        $addresses = if ($null -ne $Fresh) { $Fresh } else { Get-PraCloudAddress -Context $Context -State $State }
        if (-not $addresses.Has) { throw $(if ($State.ExoMailbox) { 'EmailAddresses not returned by Exchange Online' } else { 'proxyAddresses not returned by Microsoft Graph' }) }
        $State.X500Last = Compare-PraX500Address -Expected $State.X500 -Actual $addresses.List
    }
    catch { $State.X500Failure = [string]$_.Exception.Message; $State.X500Last = $null }
    $good = ([string]::IsNullOrEmpty($State.X500Failure) -and $State.X500Last.Missing.Count -eq 0)
    if ($good -or $Final -or $State.X500Reads -ge $MaxReads) { Complete-PraX500Check -Context $Context -State $State; return $true }
    $found = if ($null -ne $State.X500Last) { 'X500:{0} of {1} present, read {2} of {3}' -f $State.X500Last.Present.Count, $State.X500Last.Total, $State.X500Reads, $MaxReads } else { 'X500:not readable yet, read {0} of {1}' -f $State.X500Reads, $MaxReads }
    $State.Row.CloudDetail = ([string]$State.Row.CloudDetail -replace ' \| X500:[^|]*\z', '') + ' | ' + $found
    return $false
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
        if (-not (Test-PraOrdinalIn $Act @('Convert','Recover'))) { throw 'Unknown -Act.' }
        if ((Test-PraOrdinalIn $Context.Action @('Convert','Recover')) -and -not (Test-PraOrdinalEqual $Context.Action $Act)) { throw 'Context action and -Act differ.' }
        if ([int]$Context.TimeoutMinutes -lt 0 -or [int]$Context.IntervalMinutes -lt 0) { throw 'Negative cloud polling values.' }
        $cloud=Get-PraValue $Context.Config 'Cloud' @{}
        $via=[string](Get-PraValue $cloud 'MailboxCheckVia' 'Exo')
        if (-not (Test-PraOrdinalIgnoreCaseIn $via @('Graph','Exo'))) { throw 'Invalid Cloud.MailboxCheckVia.' }
        $via=if (Test-PraOrdinalIgnoreCaseEqual $via 'Graph') { 'Graph' } else { 'Exo' }
        $needGraph=$false; $needExo=$false
        foreach ($row in $Rows) {
            Add-Member -InputObject $row -NotePropertyName DeprovisionConfirmed -NotePropertyValue $false -Force
            $row.CloudMailbox=$null; $row.CloudLicense=$null; $row.CloudStatus='Pending'; $row.CloudDetail=''
            $upn=[string](Get-PraValue $row 'UserPrincipalName' '')
            if (-not $upn) { Write-PraCloudError -Context $Context -Row $row -Message 'UPN missing: check impossible.'; continue }
            if (Test-PraOrdinalIgnoreCaseEqual (Get-PraValue $row 'FinalStatus' '') 'Error') { Write-PraCloudError -Context $Context -Row $row -Message 'Previous error: cloud part not allowed.'; continue }
            $shared=[bool](Get-PraValue $row 'IsShared' $false)
            $preserveMailbox=Get-PraValue $row 'PreserveCloudMailbox' $false; $preserveLicense=Get-PraValue $row 'PreserveLicense' $false
            if ($preserveMailbox -isnot [bool] -or $preserveLicense -isnot [bool] -or ($preserveMailbox -and -not $shared)) {
                Write-PraCloudError -Context $Context -Row $row -Message 'Invalid keep flags (PreserveCloudMailbox is for shared mailboxes only).'; continue
            }
            $requests=@(); if ((Test-PraOrdinalIgnoreCaseEqual $Act 'Convert')) { $requests=@(Get-PraPermissionRequest $Context $row) }
            $mb=([bool](Get-PraValue $cloud 'CheckMailbox' $false) -or (Test-PraOrdinalIgnoreCaseEqual $Act 'Recover') -or $requests.Count -gt 0)
            $lic=-not $shared -and [bool](Get-PraValue $cloud 'CheckLicense' $false)
            if (-not $mb -and -not $lic) {
                $row.CloudStatus='Skipped'; $row.CloudDetail='No applicable check; no restore confirmation.'; $row.FinalStatus='Skipped'; continue
            }
            # X500 control (Convert): the addresses recorded by the AD phase must be on the cloud mailbox. A batch written before 3.1.0 has none: skipped, never a failure.
            $x500Expected=$null
            if ($mb -and (Test-PraOrdinalIgnoreCaseEqual $Act 'Convert')) {
                $source=Get-PraValue $row 'BackupRec' $null
                $stored=Get-PraValue $source 'ExpectedX500' $null
                $Context.CurrentIdentity=[string](Get-PraValue $row 'ObjectGuid' $upn); $Context.CurrentOperation='X500Check'
                if ($null -eq $stored) {
                    Write-PraItem -Context $Context -Status Info -Text ('{0}: X500 control skipped, expected addresses not available ({1})' -f $upn, [string](Get-PraValue $source 'ExpectedX500Note' 'batch from 3.0.0 or older'))
                }
                else {
                    $x500Expected=[string[]]@(@($stored) | Where-Object { $null -ne $_ } | ForEach-Object { [string]$_ })
                    if (-not $x500Expected.Count) {
                        Write-PraItem -Context $Context -Status Info -Text ('{0}: X500 control skipped, nothing to verify (no legacyExchangeDN and no X500 address on premises)' -f $upn)
                        $x500Expected=$null
                    }
                }
            }
            $graphMailbox=$mb -and -not $shared -and (Test-PraOrdinalIgnoreCaseEqual $via 'Graph')
            $exoMailbox=$mb -and ((Test-PraOrdinalIgnoreCaseEqual $Act 'Recover') -or $shared -or (Test-PraOrdinalIgnoreCaseEqual $via 'Exo'))
            $needGraph=$needGraph -or $lic -or $graphMailbox; $needExo=$needExo -or $exoMailbox
            [void]$states.Add(@{ Row=$row; Upn=$upn; Shared=$shared; Mailbox=$mb; License=$lic; GraphMailbox=$graphMailbox
                ExoMailbox=$exoMailbox; Requests=$requests; PreserveMailbox=$preserveMailbox; PreserveLicense=$preserveLicense; Done=$false
                X500=$x500Expected; X500Reads=0; X500Failure=''; X500Last=$null; CoreDone=$false })
        }
        if ($states.Count -eq 0) { return }
        try { Connect-PraCloudSession -Context $Context -NeedGraph $needGraph -NeedExo $needExo }
        catch { $Context.CloudConnectFailed=$true; throw }
        $clock=[Diagnostics.Stopwatch]::StartNew(); $timeout=[double]$Context.TimeoutMinutes*60; $attempt=0
        $x500MaxReads=3   # first read + two re-reads at the polling interval: the cloud value can lag one synchronisation, never a long new wait
        do {
            $attempt++; $pending=@($states | Where-Object { -not $_.Done })
            $null=Write-PraLog -Context $Context -Message ("Check {0}: {1} object(s) in Exchange Online" -f $attempt, $pending.Count) -Level Info
            foreach ($s in $pending) {
                $row=$s.Row; $Context.CurrentIdentity=[string](Get-PraValue $row 'ObjectGuid' $s.Upn); $Context.CurrentOperation='CloudCheck'
                try {
                    if ($s.CoreDone) { $null=Invoke-PraX500Step -Context $Context -State $s -Fresh $null -MaxReads $x500MaxReads -Final ([bool]$Context.Once); continue }
                    $details=New-Object 'System.Collections.Generic.List[string]'; $mbok=$true; $licok=$true; $facts=$null
                    if ($s.GraphMailbox -or $s.License) { $facts=Get-PraGraphFact -Context $Context -Upn $s.Upn -Mailbox $s.GraphMailbox -License $s.License -Addresses ([bool]($null -ne $s.X500 -and $s.GraphMailbox)) }
                    if ($s.ExoMailbox) {
                        $m=Invoke-PraExo -Context $Context -Operation 'Mailbox' -Params @{ Upn=$s.Upn }
                        if ((Test-PraOrdinalIgnoreCaseEqual $Act 'Recover')) {
                            if ($s.PreserveMailbox) {
                                $mbok=(Get-PraValue $m 'Found' $false) -eq $true -and (Test-PraOrdinalIgnoreCaseEqual (Get-PraValue $m 'Type' '') 'SharedMailbox')
                                [void]$details.Add("MBX:KeepCloudShared SharedMailbox present=$mbok; deprovisioning NOT confirmed, tag kept")
                            } else {
                                $r=Invoke-PraExo -Context $Context -Operation 'Recipient' -Params @{ Upn=$s.Upn }
                                $mbok=(Get-PraValue $m 'Found' $true) -eq $false -and (Get-PraValue $r 'Found' $false) -eq $true -and (Test-PraOrdinalIgnoreCaseEqual (Get-PraValue $r 'Type' '') 'MailUser')
                                [void]$details.Add("MBX:absence=$(-not [bool](Get-PraValue $m 'Found' $true)); recipient=$(Get-PraValue $r 'Type' 'none')")
                                if ($s.GraphMailbox) { [void]$details.Add("Graph:Enabled=$($facts.Enabled),Provisioned=$($facts.Provisioned) (Exchange Online is authoritative, Graph errors stop)") }
                            }
                        } else {
                            $type=[string](Get-PraValue $m 'Type' '')
                            $mbok=if ($s.Shared) { Test-PraOrdinalIgnoreCaseEqual $type 'SharedMailbox' } else { Test-PraOrdinalIgnoreCaseIn $type @('UserMailbox','SharedMailbox','RoomMailbox','EquipmentMailbox') }
                            [void]$details.Add("MBX:EXO type=$type")
                        }
                    } elseif ($s.GraphMailbox) { $mbok=$facts.Provisioned; [void]$details.Add("MBX:Graph provisioning=$mbok; Enabled=$($facts.Enabled) [$($facts.Detail)]") }
                    if ($s.Mailbox) { $row.CloudMailbox=[bool]$mbok }
                    if ($s.License) {
                        $licok=if ((Test-PraOrdinalIgnoreCaseEqual $Act 'Convert') -or $s.PreserveLicense) { $facts.LicenseCount -gt 0 -and $facts.Enabled -and $facts.RequiredSkuOk }
                            elseif ($facts.RequiredSku) { -not $facts.RequiredSkuOk } else { -not $facts.Enabled }
                        $row.CloudLicense=[bool]$licok
                        [void]$details.Add("LIC:OK=$licok; Preserve=$($s.PreserveLicense); ExpectedSKU=$($facts.RequiredSku); SKUPresent=$($facts.RequiredSkuOk); licences=$($facts.LicenseCount); ExchangeEnabled=$($facts.Enabled)")
                    } elseif ($s.Shared) { [void]$details.Add('LIC:N/A (shared)') }
                    $row.CloudDetail=$details -join ' | '
                    if ($mbok -and $licok) {
                        if ((Test-PraOrdinalIgnoreCaseEqual $Act 'Recover') -and -not $s.ExoMailbox) {
                            $row.CloudStatus='Skipped'; $row.FinalStatus='Skipped'; $row.CloudDetail+=' | LicenseOnly: no Exchange Online confirmation, restore not allowed.'
                        } else {
                            $toGrant=0
                            if ($s.Mailbox -and $s.Requests.Count) { $toGrant=[int](Invoke-PraSharedPermission -Context $Context -Row $row -Requests $s.Requests) }
                            $row.DeprovisionConfirmed=((Test-PraOrdinalIgnoreCaseEqual $Act 'Recover') -and $s.ExoMailbox -and -not $s.PreserveMailbox)
                            if ($toGrant -gt 0) {
                                $row.CloudStatus='Planned'; $row.FinalStatus='Planned'
                                $null=Write-PraLog -Context $Context -Message ("{0}: SharedMailbox ready, {1} permission(s) to grant in Apply" -f $s.Upn, $toGrant) -Level Info
                            } else {
                                $row.CloudStatus='Success'
                                $row.FinalStatus=if ((Test-PraOrdinalIgnoreCaseEqual $Act 'Recover') -and [bool](Get-PraValue $row 'DeproPending' $false)) { 'Pending' } else { 'Success' }
                                $what=if ((Test-PraOrdinalIgnoreCaseEqual $Act 'Recover')) { if ($s.PreserveMailbox) { 'shared mailbox kept in Exchange Online' } else { 'deprovisioned in Exchange Online (now a MailUser)' } }
                                    elseif ($s.Shared) { 'SharedMailbox ready, ' + ([string]$row.PermDetail -replace '; to grant=0; trustees missing in Exchange Online=0', '') }
                                    else { 'mailbox' + $(if ($s.License) { ' and licence' } else { '' }) + ' ready' }
                                $null=Write-PraLog -Context $Context -Message ("{0}: {1}" -f $s.Upn, $what) -Level Success
                            }
                        }
                        $s.CoreDone=$true
                        if ($null -ne $s.X500) {
                            $fresh=$null
                            if ($s.ExoMailbox) { $fresh=@{ Has=[bool](Get-PraValue $m 'HasAddresses' $false); List=[string[]]@(Get-PraList $m 'Addresses') } }
                            elseif ($s.GraphMailbox -and $null -ne $facts) { $fresh=@{ Has=$true; List=[string[]]@($facts.Addresses) } }
                            $null=Invoke-PraX500Step -Context $Context -State $s -Fresh $fresh -MaxReads $x500MaxReads -Final ([bool]$Context.Once)
                        } else { $s.Done=$true }
                    } else { $row.CloudStatus='Pending' }
                } catch { Write-PraCloudError -Context $Context -Row $row -Message ($_.Exception.Message+' | '+[string]$row.PermDetail); $s.Done=$true }
            }
            $pending=@($states | Where-Object { -not $_.Done })
            if (-not $pending.Count -or $Context.Once -or $clock.Elapsed.TotalSeconds -ge $timeout) { break }
            $seconds=[Math]::Min([Math]::Max(1,([double]$Context.IntervalMinutes*60)),[Math]::Max(0,($timeout-$clock.Elapsed.TotalSeconds)))
            # A mailbox that is ready and only waits for its X500 addresses is not "not ready": its own message, and the wait is at most two more checks.
            $notReady=@($pending | Where-Object { -not $_.CoreDone })
            if ($notReady.Count) { $null=Write-PraLog -Context $Context -Message ("Not ready yet: {0} - next check in {1:0} s (waiting up to {2} min in total)" -f (($notReady | ForEach-Object { $_.Upn }) -join ', '), $seconds, $Context.TimeoutMinutes) -Level Sub }
            foreach ($s in @($pending | Where-Object { $_.CoreDone })) { $null=Write-PraLog -Context $Context -Message ("{0}: mailbox ready; X500 addresses not all visible yet, check {1} of {2} in {3:0} s" -f $s.Upn, ([int]$s.X500Reads + 1), $x500MaxReads, $seconds) -Level Sub }
            foreach ($s in $pending) { $null=Write-PraLog -Context $Context -Message ("{0} | {1}" -f $s.Upn, $s.Row.CloudDetail) -Level Detail }
            $intervalSeconds=[Math]::Max(1,([double]$Context.IntervalMinutes*60))
            $waitText=if ((Test-PraOrdinalIgnoreCaseEqual $Act 'Recover')) { 'Waiting for Exchange Online to finish deprovisioning' } elseif ((Test-PraOrdinalIgnoreCaseEqual $Act 'Convert')) { 'Waiting for the mailbox and licence to appear in Exchange Online' } else { 'Waiting for Exchange Online' }
            if (@($pending | Where-Object { -not $_.CoreDone }).Count -eq 0) { $waitText='Waiting for the X500 addresses to appear in Exchange Online (Entra Connect synchronisation)' }
            Write-PraProgress -Context $Context -Text ("{0} ({1} object(s) not ready)" -f $waitText,$pending.Count) -Current ([int]$clock.Elapsed.TotalSeconds) -Total ([int]$timeout) -Attempt $attempt -MaxAttempts ([int][Math]::Ceiling($timeout/$intervalSeconds)+1) -NextInSeconds ([int][Math]::Ceiling($seconds))
            if ($seconds -gt 0) { Start-Sleep -Milliseconds ([int][Math]::Min(2147483647,($seconds*1000))) }
        } while ($true)
        $preview=(-not $Context.AllowMutation -and (Test-PraOrdinalIn $Context.Action @('Convert','Recover')))
        foreach ($s in $states) {
            if ($s.Done) { continue }
            if ($s.CoreDone) { Complete-PraX500Check -Context $Context -State $s; continue }
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
                $newIds=@(Get-ConnectionInformation -ErrorAction Stop | ForEach-Object { [string]$_.ConnectionId } | Where-Object { -not (Test-PraOrdinalIgnoreCaseIn $_ $beforeIds) })
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
                    if ([string]$hold -match '^(?<excluded>-)?(?:mbx|grp|skp|UniH)?(?<id>[a-f0-9]{32}|[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12})(?::(?<action>[123]))?\z') {
                        if (Test-PraOrdinalIgnoreCaseEqual ($Matches.id -replace '-','') $guid) {
                            if ($Matches.ContainsKey('excluded')) { $excluded=$true }
                            elseif ($Matches.ContainsKey('action') -and (Test-PraOrdinalIgnoreCaseEqual $Matches.action '1')) { $deleteOnly=$true }
                            else { $included=$true }
                        }
                    }
                }
                $row.CloudDetail="Retention: Found=$($row.CloudMailbox); Inactive=$(Get-PraValue $h 'IsInactive' $false); Litigation=$(Get-PraValue $h 'Litigation' $false); RetentionHold=$(Get-PraValue $h 'RetentionHold' $false); Holds=[$($holds -join ',')]"
                if (-not $row.CloudMailbox) { throw ('Mailbox not found (active or inactive). '+$row.CloudDetail) }
                if (-not $guid) { throw ('Policy unknown: set Retention.PolicyGuid (a hold may exist, check it manually). '+$row.CloudDetail) }
                if ($excluded -or $deleteOnly -or -not $included) { throw ('Not covered by the policy (or excluded, or delete-only); an adaptive scope can take several days. '+$row.CloudDetail) }
                $row.CloudStatus='Success'; if (-not (Test-PraOrdinalIgnoreCaseEqual $row.FinalStatus 'Error')) { $row.FinalStatus='Success' }
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

# SIG # Begin signature block
# MIImKQYJKoZIhvcNAQcCoIImGjCCJhYCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCBuk2+Au1Hz+cFK
# X0Ax6iz9SHrq6g2j4Ew7vBBSbyH1MKCCDW8wggZyMIIEWqADAgECAghkM1HTxzif
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
# wZislcdCZuS6MYIYEDCCGAwCAQEwgYwweDELMAkGA1UEBhMCVVMxDjAMBgNVBAgM
# BVRleGFzMRAwDgYDVQQHDAdIb3VzdG9uMREwDwYDVQQKDAhTU0wgQ29ycDE0MDIG
# A1UEAwwrU1NMLmNvbSBDb2RlIFNpZ25pbmcgSW50ZXJtZWRpYXRlIENBIFJTQSBS
# MQIQBof4ljXihJpmCqqt2mhAWzANBglghkgBZQMEAgEFAKCBhDAYBgorBgEEAYI3
# AgEMMQowCKACgAChAoAAMBkGCSqGSIb3DQEJAzEMBgorBgEEAYI3AgEEMBwGCisG
# AQQBgjcCAQsxDjAMBgorBgEEAYI3AgEVMC8GCSqGSIb3DQEJBDEiBCC3NJvdPH4T
# gx5HbAn5pMGP0+td7wpDQ4VSaLpwTSy3wjANBgkqhkiG9w0BAQEFAASCAgCfkWjY
# CLKfq067n8XRlLa+E6CgObQqsNOHGuwJ8ibcnP4XQox84nQW4QiqVSSBRY+v4kcw
# E/VSJB0MASdf/zVqTqzHldNMwMFR/XhNjS04+dnSALG+W3TC2gw3tcCJWLv3aca3
# 3t2NLx0nlCLhTVVo5dyEwwIAKHJCQ6kxOokONbr4h5vmEqlQFBuC+YWXPz+iseFg
# JKpIpUo/ssACGLj+eGSsqZ80WBIdCdC9VjavQizaajnyme3dyL2U4E1JduUhwD4X
# b++LRzc4Bb5ccH4Svg2Meb6O1RYYnXZ9zSsaKtT7mQMy1BPOqqjEVYpPSAgEJvrn
# lxGjtj3er1B55VK/gAoRgc+9oWI9oLeOQMETVTg7QkrL5su8ZiA+xn0BsqpnjPxP
# ScveJeJAZvPQr4346VPEpJnMwW6r0be0sqCPJvXGGwwCMiqkvP8cKPPyOY/3fflG
# bEUiwyjDhFPpsQkYNN43f1DOBoPmBHmHnCWlicu9f5LEfklVw5OGEzphLcJHqq8/
# 5CX/lcEKOQ0ifuXJVPXDPCspbU5mRX4lU0pDN+7Irt6tqwi3pUAx9mtIjkCn5g7y
# sC/cPDAsLwVpND36OfpRvi70vZ8FGx2JRYZyWWDMB+TfQ+GYvLEK0ekozgt809Dh
# 58hPVxLYC4MuhwIRNXRNvEdoqW//yqq1Azu28aGCFM0wghTJBgorBgEEAYI3AwMB
# MYIUuTCCFLUGCSqGSIb3DQEHAqCCFKYwghSiAgEDMQ0wCwYJYIZIAWUDBAIBMIGJ
# BgsqhkiG9w0BCRABBKB6BHgwdgIBAQYMKwYBBAGCqTABAwYBMDEwDQYJYIZIAWUD
# BAIBBQAEIHw9SWzDtx6eW+CA8EJz72stBoydPgFX1mh0vOrxer8KAghhSibitsyB
# NBgPMjAyNjExMTAwODMzMjFaMAMCAQECEA+ycnfdgCe80wKS8mC8MlGgghGnMIIE
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
# wzSPOzGCAlUwggJRAgEBMIGGMHIxCzAJBgNVBAYTAlVTMQ4wDAYDVQQIDAVUZXhh
# czEQMA4GA1UEBwwHSG91c3RvbjERMA8GA1UECgwIU1NMIENvcnAxLjAsBgNVBAMM
# JVNTTC5jb20gVGltZXN0YW1waW5nIElzc3VpbmcgUlNBIENBIDICEFRD+De9Wu4Y
# AYRyuFzajuMwCwYJYIZIAWUDBAIBoIIBYDAaBgkqhkiG9w0BCQMxDQYLKoZIhvcN
# AQkQAQQwHAYJKoZIhvcNAQkFMQ8XDTI2MTExMDA4MzMyMVowKAYJKoZIhvcNAQk0
# MRswGTALBglghkgBZQMEAgGhCgYIKoZIzj0EAwIwLwYJKoZIhvcNAQkEMSIEIBoh
# mQckqyRAt8iZP7jONJaXAAm+OtHHm4Zy3fUYA/d4MIHIBgsqhkiG9w0BCRACLzGB
# uDCBtTCBsjCBrwQgV0/qF6r6XnxqK5sIyZixc15FCzhzykTmokygkw5j87AwgYow
# dqR0MHIxCzAJBgNVBAYTAlVTMQ4wDAYDVQQIDAVUZXhhczEQMA4GA1UEBwwHSG91
# c3RvbjERMA8GA1UECgwIU1NMIENvcnAxLjAsBgNVBAMMJVNTTC5jb20gVGltZXN0
# YW1waW5nIElzc3VpbmcgUlNBIENBIDICEFRD+De9Wu4YAYRyuFzajuMwCgYIKoZI
# zj0EAwIERjBEAiAGrpgmWfaFUWSBPGQoAONIhWRs4m60ZjIEJYtMl7MHUAIgKGKG
# 6XTz7CcmXJtFGh1LitIlK3l2XF/3Z95mlPDPQ58=
# SIG # End signature block
