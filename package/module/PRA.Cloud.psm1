<#
.SYNOPSIS
    PRA Remote Mailbox - Exchange Online and Microsoft Graph adapter (no AD read or write).

.DESCRIPTION
    Public functions (no pipeline output; result rows are updated in place; an error sets the row to
    Error and records a run error, or throws):

      Initialize-PraCloudPreflight  Convert or Recover, Apply, phase Both: sign-in, targets (and, for Convert,
                                    trustees) resolved in Exchange Online before the AD part (read only)
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

    Identity: unless Cloud.IdentityCheck = Off, the Microsoft Entra ID account of every object (and of every trustee of a permission to grant) must carry the Active
    Directory source anchor of the object (onPremisesImmutableId = base64 of the objectGUID or of ms-DS-ConsistencyGuid). Another account, a cloud-only account or an
    ambiguous answer is an error for that object and nothing is changed on it. The Exchange Online object of a confirmed account is read with -ExternalDirectoryObjectId (by UPN
    only when no account is confirmed) and must carry the ExternalDirectoryObjectId of that account; a permission is written with the confirmed ids of the mailbox and of the trustee.

    Retries: a read of Microsoft Graph or Exchange Online is sent again on 408, 429, 502, 503, 504, a timeout or no answer (Retry-After honoured), within
    Cloud.RetryBudgetObjectSeconds for an object and Cloud.RetryBudgetRunMinutes for the run; a throttled answer slows the calls of the whole run, and a run that used
    up its budget stops with one error. Any other failure is not sent again.

    Sessions: Microsoft Graph is connected before Exchange Online; an Exchange Online
    or Graph session that already exists in the console is refused;
    tenant, token, connection ID and module path are checked before each call. Exo.UseSubprocess (or
    an ExchangeOnlineManagement older than Exo.MinModuleVersion) runs every Exchange Online call in a
    child PowerShell 7 process (certificate sign-in only).

.NOTES
    Author  : Nicolas Fabert
    Version : 3.2.0
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
    param([ValidateSet('Probe','Preflight','Mailbox','Recipient','Hold','HoldBulk','Permission','Grant')][string]$Operation,$P,$Permit,$SessionBinding,$OnApplied,$OnProgress)
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
    function InGuidSet {
        # A GUID is compared by value, whatever its text format (braces, hyphens, case). Text that is not a GUID never matches.
        param($Value,$Set)
        $left=[guid]::Empty
        if (-not [guid]::TryParse([string]$Value,[ref]$left) -or $left -eq [guid]::Empty) { return $false }
        foreach ($item in @($Set)) { $right=[guid]::Empty; if ([guid]::TryParse([string]$item,[ref]$right) -and $right.Equals($left)) { return $true } }
        return $false
    }
    function Session {
        param([string]$Right='')
        $tenant=[string](V $SessionBinding 'TenantId' (V $P 'TenantId' ''))
        $parsed=[guid]::Empty
        if (-not [guid]::TryParse($tenant,[ref]$parsed) -or $parsed -eq [guid]::Empty) { throw 'Expected Exchange Online tenant missing or invalid (Cloud.TenantId).' }
        $organization=[string](V $SessionBinding 'Organization' (V $P 'Organization' ''))
        $appId=[string](V $SessionBinding 'AppId' (V $P 'AppId' ''))
        # The connection is read again once, after a short pause, when only its state, token, connection ID or module path is not as expected: a connection that is still settling.
        # A wrong tenant or application is not transient and stops at once.
        $c=$null; $location=''; $id=''; $problems=@()
        for ($attempt=1; $attempt -le 2; $attempt++) {
            $connections=@(Get-ConnectionInformation -ErrorAction Stop)
            if ($connections.Count -ne 1) { throw 'Exactly one Exchange Online connection is expected in this process.' }
            $c=$connections[0]; $location=[string](V $c 'ModuleName' ''); $id=[string](V $c 'ConnectionId' '')
            # Interactive sign-in reports the tenant GUID; certificate (app-only) sign-in reports the
            # organisation domain (tenant.onmicrosoft.com) and the AppId: both are accepted, nothing else.
            $sessionTenant=[string](V $c 'TenantID' '')
            $problems=@(); $transient=@()
            if (-not ((SameIgnoreCase $sessionTenant $tenant) -or ($organization -and (SameIgnoreCase $sessionTenant $organization)))) {
                $problems+=("wrong tenant ({0}), expected {1}" -f $(if ($sessionTenant) { $sessionTenant } else { 'none' }),$tenant)
            }
            if ($appId -and -not (SameIgnoreCase ([string](V $c 'AppId' '')) $appId)) {
                $problems+=("wrong application ID ({0}), expected {1}" -f $(if ([string](V $c 'AppId' '')) { [string](V $c 'AppId' '') } else { 'none' }),$appId)
            }
            $state=[string](V $c 'State' ''); $token=[string](V $c 'TokenStatus' '')
            if (-not (SameIgnoreCase $state 'Connected')) { $transient+=("connection state '{0}', expected Connected" -f $state) }
            if (-not (SameIgnoreCase $token 'Active')) { $transient+=("token status '{0}', expected Active" -f $token) }
            if (-not $id) { $transient+=('no connection ID') }
            if (-not [IO.Path]::IsPathRooted($location)) { $transient+=("module path '{0}' is not a full path" -f $location) }
            $problems+=$transient
            if (-not $transient.Count -or $transient.Count -ne $problems.Count -or $attempt -ge 2) { break }
            Start-Sleep -Seconds 2
        }
        if ($problems.Count) { throw ('Exchange Online session: {0}.' -f ($problems -join '; ')) }
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
    # The Exchange Online object of a confirmed account is looked up by the Entra id (its ExternalDirectoryObjectId); the UPN is the key only when no id is known.
    function Confirmed {
        param([string]$Upn)
        $id=V (V $P 'VerifiedObjectIds' @{}) $Upn
        if ($null -ne $id -and $id) { return [string]$id }
        return ''
    }
    # The selector of a read of the Exchange Online object: the dedicated -ExternalDirectoryObjectId parameter for a confirmed account, the UPN as the identity otherwise.
    function Selector {
        param([string]$Upn)
        $id=Confirmed $Upn
        if ($id) { return @{ ExternalDirectoryObjectId=$id } }
        return @{ Identity=$Upn }
    }
    # The value that names the object in a write (-Identity, -User, -Trustee): the confirmed Entra id, the UPN only when no id is known.
    function WriteKey {
        param([string]$Name)
        $id=Confirmed $Name
        if ($id) { return $id }
        return $Name
    }
    # An absent object by a GUID is told like an absent object by a UPN: the key is echoed in the text, in any casing.
    function NotFoundText {
        param([string]$Text,[string]$Key)
        foreach ($form in @(("object '"+$Key+"' couldn't be found"),("Couldn't find object `""+$Key+"`""),("object '"+$Key+"' couldn"+[char]0x2019+"t be found"))) {
            if ($Text.IndexOf($form,[StringComparison]::OrdinalIgnoreCase) -ge 0) { return $true }
        }
        return $false
    }
    function MissingRecipient {
        param([System.Management.Automation.ErrorRecord]$Record,[string]$Upn)
        # A selector read (-UserPrincipalName or -ExternalDirectoryObjectId) answers an absent object with HTTP 404 ManagementObjectNotFoundException
        # instead of an empty result (for example while a deprovisioned mailbox turns into a MailUser).
        $text=$Record.Exception.Message
        if ($text -notmatch 'HttpStatusCode=404') { return $false }
        $json=[regex]::Match($text,'(?s)\{\s*"error"\s*:\s*\{.*\}\s*\}')
        if (-not $json.Success) { return $false }
        try {
            $payload=$json.Value | ConvertFrom-Json -DateKind String -ErrorAction Stop
            $detail=@($payload.error.details | Where-Object { ([string]$_.message).IndexOf('|Microsoft.Exchange.Configuration.Tasks.ManagementObjectNotFoundException|',[StringComparison]::OrdinalIgnoreCase) -ge 0 })
            return ((SameOrdinal $payload.error.code 'NotFound') -and (NotFoundText ([string]$payload.error.message) $Upn) -and $detail.Count -gt 0 -and (NotFoundText ([string]$detail[0].message) $Upn))
        } catch { return $false }
    }
    function Recipient {
        param([string]$Upn)
        if ([string]::IsNullOrWhiteSpace($Upn) -or $Upn -match '[\r\n\x00]') { throw 'Empty or invalid UPN.' }
        # Recipient exposes a dedicated UPN selector, not a UserPrincipalName output/filter property.
        # "Not found" is read through -ErrorVariable (no transcript error line); any other error stops.
        $recipientErrors=$null
        $byId=Confirmed $Upn
        $selector=if ($byId) { @{ ExternalDirectoryObjectId=$byId } } else { @{ UserPrincipalName=$Upn; ResultSize='Unlimited' } }
        $missingKey=if ($byId) { $byId } else { $Upn }
        try { $items = @(Get-EXORecipient @selector -Properties RecipientTypeDetails,PrimarySmtpAddress,ExternalDirectoryObjectId,Guid,DistinguishedName -ErrorAction SilentlyContinue -ErrorVariable recipientErrors -WarningAction Stop) }
        catch { if (-not (MissingRecipient $_ $missingKey)) { throw }; $items=@(); $recipientErrors=@($_) }
        $recipientErrors=@($recipientErrors | Where-Object { $null -ne $_ })
        if ($recipientErrors.Count) {
            foreach ($record in $recipientErrors) {
                if ($record -isnot [System.Management.Automation.ErrorRecord] -or -not (MissingRecipient $record $missingKey)) { throw $record }
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
        $confirmed=V (V $P 'VerifiedObjectIds' @{}) $Upn
        if ($null -ne $confirmed -and $confirmed -and -not (SameIgnoreCase $oid $confirmed)) { throw "The Exchange Online recipient is not the Microsoft Entra ID account confirmed for this object: $Upn" }
        $keys = @($Upn) + @(foreach ($key in @('UserPrincipalName','PrimarySmtpAddress','ExternalDirectoryObjectId','Guid','DistinguishedName','Identity','Alias','Name','DisplayName','Sid','SamAccountName')) {
            $val = [string](V $items[0] $key); if (-not [string]::IsNullOrWhiteSpace($val)) { $val }
        })
        $seenKeys = New-Object 'System.Collections.Generic.HashSet[string]' -ArgumentList ([StringComparer]::OrdinalIgnoreCase)
        return @{ Found=$true; Type=$type; Keys=@($keys | Where-Object { $seenKeys.Add([string]$_) }); ObjectId=$oid; PrimarySmtpAddress=$smtp }
    }
    # The inactive mailbox of a deleted account has no account to confirm and another ExternalDirectoryObjectId than a live account with the same UPN.
    # Without a confirmed account it is found by UPN. With a confirmed account, an inactive mailbox that carries another ExternalDirectoryObjectId belongs to an
    # earlier account: it is not the mailbox of this object and never decides the verdict. One that carries none is a candidate found by UPN. Several candidates
    # are told apart by the mailbox GUID recorded on premises (ExchangeGuid) when the record has one; otherwise they are an ambiguity, never a guess.
    # A single candidate found by UPN must carry the recorded mailbox GUID only when the record shows that the GUID was kept on the cloud mailbox (GuidKept).
    # Used by the read of one mailbox and by the in-memory match of a bulk read: one rule set.
    function PickInactive {
        param([string]$Upn,[string]$ById,[object[]]$Guids,[bool]$GuidKept,[object[]]$Items)
        $items=@($Items)
        $earlier={ param([int]$Count) @{ Found=$false; Type=$null; Holds=@(); IsInactive=$false; Litigation=$false; RetentionHold=$false; HasAddresses=$false; Addresses=[string[]]@(); EarlierAccount=$true; EarlierCount=$Count } }
        if ($ById) {
            $own = @($items | Where-Object { SameIgnoreCase ([string](V $_ 'ExternalDirectoryObjectId' '')) $ById })
            $nameless = @($items | Where-Object { [string]::IsNullOrWhiteSpace([string](V $_ 'ExternalDirectoryObjectId' '')) })
            if ($own.Count) { $items = $own }
            elseif ($nameless.Count) { $items = $nameless }
            elseif ($items.Count) { return @{ Earlier=(& $earlier ([int]$items.Count)); Items=@(); InactiveByUpn=$false } }
        }
        $recorded = @(); foreach ($group in @($Guids)) { foreach ($each in @($group)) { if ($each) { $recorded += [string]$each } } }
        $foundById = [bool]($ById -and @($items | Where-Object { SameIgnoreCase ([string](V $_ 'ExternalDirectoryObjectId' '')) $ById }).Count)
        if ($items.Count -eq 1 -and $GuidKept -and $recorded.Count -and -not $foundById -and -not (InGuidSet (V $items[0] 'ExchangeGuid' '') $recorded)) {
            return @{ Earlier=(& $earlier 1); Items=@(); InactiveByUpn=$false }
        }
        if ($items.Count -gt 1 -and -not $foundById) {
            $matching = @($items | Where-Object { InGuidSet (V $_ 'ExchangeGuid' '') $recorded })
            if ($matching.Count -ne 1) {
                $tellApart = if ($recorded.Count) { ' The mailbox GUID recorded for this object does not tell them apart either.' } else { ' This object has no mailbox GUID recorded (it was not an on-premises mailbox, or the record is older), so nothing tells them apart.' }
                throw ("Exchange Online has $($items.Count) inactive mailboxes for $Upn and nothing tells which one belongs to this object: the retention cannot be checked for it.$tellApart To list them, run: Get-EXOMailbox -InactiveMailboxOnly -Filter ""$(ExactFilter $Upn)"" -Properties ExternalDirectoryObjectId,ExchangeGuid,WhenSoftDeleted,InPlaceHolds | Format-List Name,ExternalDirectoryObjectId,ExchangeGuid,WhenSoftDeleted,InPlaceHolds. Then check by hand, in the Microsoft Purview portal, the retention of the mailbox of this object.")
            }
            $items = $matching
        }
        $inactiveByUpn = ($items.Count -eq 1 -and -not ($ById -and (SameIgnoreCase ([string](V $items[0] 'ExternalDirectoryObjectId' '')) $ById)))
        return @{ Earlier=$null; Items=$items; InactiveByUpn=[bool]$inactiveByUpn }
    }
    function MailboxResult {
        param($Item,[string]$Upn,[bool]$InactiveByUpn)
        $m = $Item; $type = [string](V $m 'RecipientTypeDetails')
        if (-not $type) { throw "Mailbox type not returned: $Upn" }
        $mailboxOid=[string](V $m 'ExternalDirectoryObjectId' ''); $confirmed=V (V $P 'VerifiedObjectIds' @{}) $Upn
        if (-not $InactiveByUpn -and $mailboxOid -and $null -ne $confirmed -and $confirmed -and -not (SameIgnoreCase $mailboxOid $confirmed)) { throw "The Exchange Online mailbox is not the Microsoft Entra ID account confirmed for this object: $Upn" }
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
            HasAddresses=[bool]$hasAddresses; Addresses=[string[]]$addressList; IdentityByUpn=[bool]$InactiveByUpn }
    }
    function Mailbox {
        param([string]$Upn,[switch]$Hold)
        $properties = @('RecipientTypeDetails','EmailAddresses','LegacyExchangeDN','ExternalDirectoryObjectId')
        if ($Hold) { $properties += @('IsInactiveMailbox','InPlaceHolds','LitigationHoldEnabled','RetentionHoldEnabled','ExchangeGuid') }
        $byId = Confirmed $Upn
        if ($byId) {
            # Where an absent mailbox is the expected answer (AbsenceConfirms: the deprovisioning check of a Recover, the retention check), only an explicit, recognised "not found" for this id counts as absent;
            # any other error is a failed read. Elsewhere an absent mailbox only means "not yet", and the broader match stays.
            try { $items = @(Get-EXOMailbox -ExternalDirectoryObjectId $byId -Properties $properties -ErrorAction Stop) }
            catch {
                $absent = MissingRecipient $_ $byId
                if (-not $absent -and -not [bool](V $P 'AbsenceConfirms' $false)) { $absent = ($_.Exception.Message -match "(?i)couldn.t be found|couldn.t find|HttpStatusCode=404|ManagementObjectNotFoundException") }
                if (-not $absent) { throw }
                $items = @()
            }
        }
        else { $items = @(Get-EXOMailbox -Filter (ExactFilter $Upn) -Properties $properties -ResultSize Unlimited -ErrorAction Stop) }
        $inactiveByUpn = $false
        if ($Hold -and $items.Count -eq 0) {
            $candidates = @(Get-EXOMailbox -Filter (ExactFilter $Upn) -Properties $properties -ResultSize Unlimited -InactiveMailboxOnly -ErrorAction Stop)
            $recordedGuids = V $P 'MailboxGuids' @()
            $pick = PickInactive $Upn $byId $recordedGuids ([bool](V $P 'GuidKept' $false)) $candidates
            if ($null -ne $pick.Earlier) { return $pick.Earlier }
            $items = @($pick.Items); $inactiveByUpn = [bool]$pick.InactiveByUpn
        }
        if ($items.Count -gt 1) { throw "Exchange Online mailbox not unique: $Upn" }
        if ($items.Count -eq 0) { return @{ Found=$false; Type=$null; Holds=@(); IsInactive=$false; Litigation=$false; RetentionHold=$false; HasAddresses=$false; Addresses=[string[]]@() } }
        return (MailboxResult $items[0] $Upn $inactiveByUpn)
    }
    # The retention check of many mailboxes: the ACTIVE mailboxes that carry the retention tag and one of the UPNs of the rows (about 50 at a time) are read with a server-side filter,
    # then each row is matched in memory: by the confirmed Entra id when there is one, else by UPN, exactly one mailbox. A row that this cannot settle (no tagged active mailbox, several, an inactive mailbox)
    # is left out of the answer: the caller reads it with Mailbox, whose rules decide.
    # A failure that would stop every other read too: no answer (a network failure, a timeout), a refusal (401, 403, insufficient privileges), throttling or an unavailable service (408, 429, 502, 503, 504).
    # The bulk read stops with it; any other failure concerns the search only. The worker also runs in a child process that cannot load the module, so it carries its own copy of the rules of
    # Get-PraNetworkFailure, Get-PraCloudFailureInfo and Get-PraGraphRefusal (same inner exceptions, same texts, English and French); a test keeps the two in step.
    function StopClass {
        param([System.Management.Automation.ErrorRecord]$Record)
        $texts = New-Object 'System.Collections.Generic.List[string]'
        $detail = [string](V (V $Record 'ErrorDetails' $null) 'Message' '')
        if ($detail) { $texts.Add($detail) }
        $network = $false; $status = 0; $visited = 0
        $queue = New-Object 'System.Collections.Generic.Queue[object]'; $queue.Enqueue($Record.Exception)
        while ($queue.Count -gt 0 -and $visited -lt 20) {
            $visited++
            $e = $queue.Dequeue(); if ($null -eq $e) { continue }
            $texts.Add([string]$e.Message)
            if ($e -is [System.Net.Sockets.SocketException] -or $e -is [TimeoutException] -or $e -is [System.Threading.Tasks.TaskCanceledException]) { $network = $true }
            elseif ($e -is [System.Net.Http.HttpRequestException] -and $null -eq (V $e 'StatusCode' $null)) { $network = $true }
            elseif ($e -is [System.Net.WebException] -and ([string](V $e 'Status' '')) -cmatch '^(ConnectFailure|NameResolutionFailure|Timeout|ConnectionClosed|ReceiveFailure|SendFailure|ProxyNameResolutionFailure|KeepAliveFailure)\z') { $network = $true }
            $response = V $e 'Response' $null
            foreach ($holder in @($e, $response)) {
                if ($null -eq $holder -or $status -ne 0) { continue }
                $code = V $holder 'StatusCode' $null
                if ($null -ne $code) { try { $status = [int]$code } catch { $status = 0 } }
            }
            if ($e -is [AggregateException]) { foreach ($inner in $e.InnerExceptions) { $queue.Enqueue($inner) } }
            elseif ($null -ne $e.InnerException) { $queue.Enqueue($e.InnerException) }
        }
        $all = $texts -join ' '
        if ($status -eq 0) {
            foreach ($match in [regex]::Matches($all, '(?i)(?:HttpStatusCode|status ?code|status)\D{0,40}?(\d{3})(?!\d)')) {
                $candidate = [int]$match.Groups[1].Value
                if ($candidate -ge 400 -and $candidate -le 599) { $status = $candidate; break }
            }
        }
        if ($status -eq 0) {
            if ($all -match '(?i)TooManyRequests|Too Many Requests|throttl') { $status = 429 }
            elseif ($all -match '(?i)ServiceUnavailable|Service Unavailable') { $status = 503 }
            elseif ($all -match '(?i)GatewayTimeout|Gateway Timeout') { $status = 504 }
            elseif ($all -match '(?i)BadGateway|Bad Gateway') { $status = 502 }
            elseif ($all -match '(?i)RequestTimeout|Request Timeout') { $status = 408 }
        }
        if ($status -eq 401 -or $status -eq 403 -or $status -eq 408 -or $status -eq 429 -or $status -eq 502 -or $status -eq 503 -or $status -eq 504) { return $true }
        if ($network -or $all -match '(?i)timed out|connection attempt failed|actively refused|no such host|name or service not known|could not be resolved|forcibly closed|network is unreachable|tentative de connexion|n.a pas r.pondu') { return $true }
        if ($status -eq 0 -and $all -match '(?i)\btimeout\b|task was canceled|operation was canceled') { return $true }
        return [bool]($all -match '(?i)Insufficient privileges|Authorization_RequestDenied|Authorization_IdentityNotFound|Forbidden')
    }
    function HoldBulk {
        $properties = @('RecipientTypeDetails','ExternalDirectoryObjectId','UserPrincipalName','IsInactiveMailbox','InPlaceHolds','LitigationHoldEnabled','RetentionHoldEnabled','ExchangeGuid')
        $results = New-Object 'System.Collections.Generic.List[object]'
        $activeCount = 0; $searches = 0; $chunkFailures = 0; $failedInARow = 0; $stopped = $false
        $add = {
            param($Index,[string]$Key,$Item)
            $list = $null
            if (-not $Index.TryGetValue($Key,[ref]$list)) { $list = New-Object 'System.Collections.Generic.List[object]'; $Index[$Key] = $list }
            $list.Add($Item)
        }
        $groups = V $P 'Groups' @()
        foreach ($group in @($groups)) {
            $attribute = [string](V $group 'Attribute' ''); $value = [string](V $group 'Value' '')
            if ($attribute -notmatch '\ACustomAttribute([1-9]|1[0-5])\z' -or [string]::IsNullOrWhiteSpace($value) -or $value -match '[\r\n\x00]') { throw 'Invalid retention tag filter.' }
            $tagFilter = "($attribute -eq '$($value.Replace("'","''"))')"
            $rowsValue = V $group 'Rows' @()
            $rowList = @($rowsValue)
            for ($offset = 0; $offset -lt $rowList.Count; $offset += 50) {
                $chunk = @($rowList[$offset..([Math]::Min($offset + 49, $rowList.Count - 1))])
                $names = New-Object 'System.Collections.Generic.List[string]'
                $seenName = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
                foreach ($row in $chunk) {
                    $rowUpn = [string](V $row 'Upn' '')
                    if ([string]::IsNullOrWhiteSpace($rowUpn) -or $rowUpn -match '[\r\n\x00]' -or -not $seenName.Add($rowUpn)) { continue }
                    $names.Add("(UserPrincipalName -eq '$($rowUpn.Replace("'","''"))')")
                }
                if (-not $names.Count) { continue }
                $filter = $tagFilter + ' -and (' + ($names -join ' -or ') + ')'
                $byUpn = New-Object 'System.Collections.Generic.Dictionary[string,System.Collections.Generic.List[object]]' ([StringComparer]::OrdinalIgnoreCase)
                $byId = New-Object 'System.Collections.Generic.Dictionary[string,System.Collections.Generic.List[object]]' ([StringComparer]::OrdinalIgnoreCase)
                $searches++
                $found = $null
                try { $found = @(Get-EXOMailbox -Filter $filter -Properties $properties -ResultSize Unlimited -ErrorAction Stop) }
                catch {
                    if (StopClass $_) { throw }
                    $chunkFailures++; $failedInARow++
                    if ($failedInARow -ge 2) { $stopped = $true; break }
                    continue
                }
                $failedInARow = 0
                foreach ($mailbox in $found) {
                    $activeCount++
                    & $add $byUpn ([string](V $mailbox 'UserPrincipalName' '')) $mailbox
                    & $add $byId ([string](V $mailbox 'ExternalDirectoryObjectId' '')) $mailbox
                }
                foreach ($row in $chunk) {
                    $rowUpn = [string](V $row 'Upn' ''); $rowId = [string](V $row 'ById' ''); $answer = $null
                    try {
                        $candidates = $null
                        $found = if ($rowId) { $byId.TryGetValue($rowId,[ref]$candidates) } else { $byUpn.TryGetValue($rowUpn,[ref]$candidates) }
                        if ($found -and $candidates.Count -eq 1 -and -not [bool](V $candidates[0] 'IsInactiveMailbox' $false)) { $answer = MailboxResult $candidates[0] $rowUpn $false }
                    } catch { $answer = $null }
                    if ($null -ne $answer) { $answer.Key = [string](V $row 'Key' ''); $results.Add($answer) }
                }
            }
            if ($stopped) { break }
        }
        return @{ Found=$true; Results=$results.ToArray(); ActiveCount=[int]$activeCount; Searches=[int]$searches; ChunkFailures=[int]$chunkFailures; Stopped=[bool]$stopped }
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
            # The message prefix is an exact (case-sensitive) match. The trustee echoed by Exchange Online is compared
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
            $lookup=Selector $Upn
            $globalRaw=@(if ((SameIgnoreCase $Right 'FullAccess')) { Get-EXOMailboxPermission @lookup -ErrorAction Stop -WarningAction Stop }
                else { Get-EXORecipientPermission @lookup -ErrorAction Stop -WarningAction Stop })
            if ($globalRaw.Count -eq 0 -or $globalRaw.Count -ge 1000) { throw "$Right permission list empty or possibly truncated." }
            $globalEntries=@(NormalizeAcl $globalRaw $Right $Target)
            if (-not @($globalEntries | Where-Object { (InSetIgnoreCase $_.Principal @('NT AUTHORITY\SELF','S-1-5-10')) -and (InSetIgnoreCase $Right $_.Rights) -and -not $_.Inherited }).Count) { throw "$Right permission list without the expected SELF entry." }
            $expectedEntries=@($globalEntries | Where-Object { (InSetIgnoreCase $Right $_.Rights) -and (InSetIgnoreCase $_.Principal $Recipient.Keys) })
            # "No permissions were found" is the normal answer before a grant. It is read through -ErrorVariable,
            # not -ErrorAction Stop, so that Windows PowerShell does not write it as an error in the transcript.
            # Every error record is checked: anything else than that exact answer stops.
            $filteredErrors=$null
            $filteredRaw=@(if ((SameIgnoreCase $Right 'FullAccess')) { Get-EXOMailboxPermission @lookup -User $Trustee -ErrorAction SilentlyContinue -ErrorVariable filteredErrors -WarningAction Stop }
                else { Get-EXORecipientPermission @lookup -Trustee $Trustee -ErrorAction Stop -WarningAction Stop })
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
        $mb = @(if (Confirmed $Upn) { Get-Mailbox -Identity (Confirmed $Upn) -ErrorAction Stop } else { Get-Mailbox -Filter (ExactFilter $Upn) -ResultSize Unlimited -ErrorAction Stop })
        if ($mb.Count -ne 1) { throw "Mailbox not unique for the SendOnBehalf read: $Upn" }
        $behalfOid=[string](V $mb[0] 'ExternalDirectoryObjectId' '')
        if ($behalfOid -and -not (SameIgnoreCase $behalfOid $Target.ObjectId)) { throw "The mailbox of the SendOnBehalf read is not the confirmed Exchange Online recipient: $Upn" }
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
    if (-not (InSet $Operation @('Probe','Preflight','Mailbox','Recipient','Hold','HoldBulk','Permission','Grant'))) { throw 'Unknown Exchange Online operation.' }
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
        'HoldBulk' { return (HoldBulk) }
    }
    $trustee = [string](V $P 'Trustee'); $right = [string](V $P 'Right')
    if (-not (InSetIgnoreCase $right @('FullAccess','SendAs','SendOnBehalf'))) { throw 'Unknown permission.' }
    # From here on the right has its official spelling; the permit below is compared with the right as it was requested.
    $requestedRight = $right
    $right = @('FullAccess','SendAs','SendOnBehalf') | Where-Object { SameIgnoreCase $_ $requestedRight } | Select-Object -First 1
    if ((SameIgnoreCase $Operation 'Grant')) {
        foreach ($flag in @('AllowMutation','Approved','Authorized','JournalStarted')) {
            $b = V -Object $Permit -Name $flag -Default $false
            if ($b -isnot [bool] -or -not $b) { throw 'Exchange Online grant without its individual authorisation.' }
        }
        if (-not (SameIgnoreCase (V $Permit 'Target') $upn) -or -not (SameIgnoreCase (V $Permit 'Trustee') $trustee) -or -not (SameOrdinal (V $Permit 'Right') $requestedRight) -or
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
    $writeTarget=WriteKey $upn; $writeTrustee=WriteKey $trustee
    switch ($right) {
        'FullAccess' { & $write.Command -Identity $writeTarget -User $writeTrustee -AccessRights FullAccess -AutoMapping:([bool](V -Object $P -Name 'AutoMapping' -Default $false)) -InheritanceType All -Confirm:$false -ErrorAction Stop | Out-Null }
        'SendAs' { & $write.Command -Identity $writeTarget -Trustee $writeTrustee -AccessRights SendAs -Confirm:$false -ErrorAction Stop | Out-Null }
        'SendOnBehalf' { & $write.Command -Identity $writeTarget -GrantSendOnBehalfTo @{ Add=$writeTrustee } -Confirm:$false -ErrorAction Stop | Out-Null }
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
    $session = $Context['_PraCloudSession']
    foreach ($name in @('Verified', 'IdentityCache')) { if (-not $session.ContainsKey($name)) { $session[$name] = @{} } }
    return $session
}

function Get-PraNetworkFailure {
    <# $null when the error is not a network failure (no answer, refused, unknown host, connection closed); otherwise an object whose Host is the "host:port" the error names ('' when it names none). Looks at the inner exceptions, then at the text (the Exchange Online child process only returns text). #>
    param([Parameter(Mandatory)]$ErrorRecord)
    $texts=New-Object 'System.Collections.Generic.List[string]'; $network=$false
    $queue=New-Object 'System.Collections.Generic.Queue[object]'; $queue.Enqueue($ErrorRecord.Exception)
    while ($queue.Count) {
        $e=$queue.Dequeue(); if ($null -eq $e) { continue }
        $texts.Add([string]$e.Message)
        if ($e -is [System.Net.Sockets.SocketException] -or $e -is [TimeoutException] -or $e -is [System.Threading.Tasks.TaskCanceledException]) { $network=$true }
        elseif ($e -is [System.Net.Http.HttpRequestException] -and $null -eq $e.StatusCode) { $network=$true }
        elseif ($e -is [System.Net.WebException] -and ([string]$e.Status) -match '^(ConnectFailure|NameResolutionFailure|Timeout|ConnectionClosed|ReceiveFailure|SendFailure|ProxyNameResolutionFailure|KeepAliveFailure)\z') { $network=$true }
        if ($e -is [AggregateException]) { foreach ($inner in $e.InnerExceptions) { $queue.Enqueue($inner) } }
        elseif ($null -ne $e.InnerException) { $queue.Enqueue($e.InnerException) }
    }
    $all=$texts -join ' '
    if (-not $network -and $all -notmatch '(?i)timed out|connection attempt failed|actively refused|no such host|name or service not known|could not be resolved|forcibly closed|network is unreachable|tentative de connexion|n.a pas r.pondu') { return $null }
    $hostPort=''
    if ($all -match '(?<h>[A-Za-z0-9][A-Za-z0-9\-]*(?:\.[A-Za-z0-9\-]+)+:\d{1,5})') { $hostPort=$Matches.h }
    return [pscustomobject]@{ Host=$hostPort }
}

function Write-PraCloudError {
    <# One cloud error: a run error, the row of the object, ONE red line (plain words in $Message) and, when given, the technical text in the log and in the CloudDetail of the row. -RunError: the object could not be read (it is not "not in the expected state"). #>
    param([hashtable]$Context,$Row,[string]$Message,[string]$Technical='',[switch]$RunError)
    if ($null -ne $Row) {
        $Row.CloudStatus='Error'; $Row.FinalStatus='Error'; $Row.CloudDetail=$(if ($Technical) { $Technical } else { $Message })
        if ($RunError) { Add-Member -InputObject $Row -NotePropertyName RunError -NotePropertyValue $true -Force }
        if ($null -ne $Row.PSObject.Properties['DeprovisionConfirmed']) { $Row.DeprovisionConfirmed=$false }
        $Row.Detail = ([string](Get-PraValue $Row 'Detail' '') + ' | cloud: ' + $Message).Trim(' ','|')
        # A Check given a UPN has no object GUID: the error is then attached to the UPN, so that the run counts ONE error for it.
        $Context.CurrentIdentity=[string](Get-PraValue $Row 'ObjectGuid' '')
        if (-not $Context.CurrentIdentity) { $Context.CurrentIdentity=[string](Get-PraValue $Row 'UserPrincipalName' '') }
    }
    [void]$Context.Issues.Add([pscustomobject]@{ Timestamp=(Get-Date).ToString('o'); Phase=$Context.CurrentPhase
        Source='Cloud'; Operation=$Context.CurrentOperation; Identity=$Context.CurrentIdentity; Message=$Message })
    Write-PraItem -Context $Context -Status Fail -Text $Message -Detail $Technical
    if ($Technical) { $null = Write-PraLog -Context $Context -Message ('Technical detail: {0}' -f $Technical) -Level Detail }
}

function Write-PraCloudFailure {
    <# A cloud call that threw. A network failure is said in plain words with the raw text in the technical detail only; any other failure keeps its message. -Expectation: the message of another failure may be a result of the check itself (not a run error). #>
    param([hashtable]$Context,$Row,[Parameter(Mandatory)]$ErrorRecord,[string]$Upn='',[string]$Extra='',[switch]$Expectation)
    $raw=[string]$ErrorRecord.Exception.Message
    $network=Get-PraNetworkFailure $ErrorRecord
    if ($null -ne $network) {
        $Context.NetworkFailure=$true
        $plain='{0}Microsoft 365 did not answer (network){1}. Run again.' -f $(if ($Upn) { $Upn + ': ' } else { '' }), $(if ($network.Host) { ': ' + $network.Host } else { '' })
        Write-PraCloudError -Context $Context -Row $Row -Message $plain -Technical $raw -RunError
        return
    }
    $info=Get-PraCloudFailureInfo $ErrorRecord
    if ($info.Throttled) {
        $retried=[bool]($ErrorRecord.Exception.Data['PraRetryExhausted'])
        $plain=if ($retried) { '{0}Microsoft 365 kept limiting the requests or was unavailable (HTTP {1}) and the retry time of this object is used up. Run again in a few minutes.' -f $(if ($Upn) { $Upn + ': ' } else { '' }), $info.Status }
            else { '{0}Microsoft 365 limited the requests or was unavailable (HTTP {1}); the call was not sent again (a look that cannot wait, a retry budget of 0, or a write). Run again in a few minutes.' -f $(if ($Upn) { $Upn + ': ' } else { '' }), $info.Status }
        Write-PraCloudError -Context $Context -Row $Row -Message $plain -Technical $raw -RunError
        return
    }
    $message=$(if ($Extra) { $raw + ' | ' + $Extra } else { $raw })
    if ($Expectation) { Write-PraCloudError -Context $Context -Row $Row -Message $message } else { Write-PraCloudError -Context $Context -Row $Row -Message $message -RunError }
}

function ConvertTo-PraRetryAfterSecond {
    <# The seconds that a Retry-After value asks for: a number of seconds, or an HTTP date (RFC 1123, read with the invariant culture) counted from now. 0 for anything else and for a date in the past. #>
    [CmdletBinding()]
    param([AllowNull()][string]$Text)
    $value = ([string]$Text).Trim()
    $seconds = 0
    if ($value -cmatch '^\d{1,5}\z' -and [int]::TryParse($value, [Globalization.NumberStyles]::None, [Globalization.CultureInfo]::InvariantCulture, [ref]$seconds)) { return $seconds }
    $when = [DateTimeOffset]::MinValue
    $styles = [Globalization.DateTimeStyles]::AssumeUniversal -bor [Globalization.DateTimeStyles]::AllowWhiteSpaces
    if ($value -and ([DateTimeOffset]::TryParseExact($value, 'r', [Globalization.CultureInfo]::InvariantCulture, $styles, [ref]$when) -or [DateTimeOffset]::TryParse($value, [Globalization.CultureInfo]::InvariantCulture, $styles, [ref]$when))) {
        return [int][Math]::Min(86400, [Math]::Max(0, [Math]::Ceiling(($when - [DateTimeOffset]::UtcNow).TotalSeconds)))
    }
    return 0
}

function Get-PraCloudFailureInfo {
    <# What a failed cloud call says about itself: Status (the HTTP status, 0 when there is none), RetryAfter (seconds, 0 when none, never more than two minutes), Transient (the same read can be sent again: 408, 429, 502, 503, 504, a timeout or a connection that did not answer), Throttled (429 or 503) and NotFound (404). Looks at the inner exceptions, then at the text (the Exchange Online child process only returns text). #>
    [CmdletBinding()]
    param([Parameter(Mandatory)]$ErrorRecord)
    $status = 0; $retryAfter = 0
    $texts = New-Object 'System.Collections.Generic.List[string]'
    $queue = New-Object 'System.Collections.Generic.Queue[object]'; $queue.Enqueue($ErrorRecord.Exception)
    $detail = [string](Get-PraValue (Get-PraValue $ErrorRecord 'ErrorDetails' $null) 'Message' '')
    if ($detail) { $texts.Add($detail) }
    $visited = 0
    while ($queue.Count -gt 0 -and $visited -lt 20) {
        $visited++
        $e = $queue.Dequeue(); if ($null -eq $e) { continue }
        $texts.Add([string]$e.Message)
        $response = Get-PraValue $e 'Response' $null
        foreach ($holder in @($e, $response)) {
            if ($null -eq $holder -or $status -ne 0) { continue }
            $code = Get-PraValue $holder 'StatusCode' $null
            if ($null -ne $code) { try { $status = [int]$code } catch { $status = 0 } }
        }
        $headers = Get-PraValue $response 'Headers' $null
        if ($null -ne $headers -and $retryAfter -eq 0) {
            $retry = Get-PraValue $headers 'RetryAfter' $null
            if ($null -ne $retry) {
                $delta = Get-PraValue $retry 'Delta' $null; $when = Get-PraValue $retry 'Date' $null
                if ($null -ne $delta) { try { $retryAfter = [int][Math]::Ceiling(([TimeSpan]$delta).TotalSeconds) } catch { $retryAfter = 0 } }
                elseif ($null -ne $when) { try { $retryAfter = [int][Math]::Ceiling(([DateTimeOffset]$when - [DateTimeOffset]::UtcNow).TotalSeconds) } catch { $retryAfter = 0 } }
            }
            else { $retryAfter = ConvertTo-PraRetryAfterSecond ([string](Get-PraValue $headers 'Retry-After' '')) }
        }
        if ($e -is [AggregateException]) { foreach ($inner in $e.InnerExceptions) { $queue.Enqueue($inner) } }
        elseif ($null -ne $e.InnerException) { $queue.Enqueue($e.InnerException) }
    }
    $all = $texts -join ' '
    if ($status -eq 0) {
        foreach ($match in [regex]::Matches($all, '(?i)(?:HttpStatusCode|status ?code|status)\D{0,40}?(\d{3})(?!\d)')) {
            $candidate = [int]$match.Groups[1].Value
            if ($candidate -ge 400 -and $candidate -le 599) { $status = $candidate; break }
        }
    }
    if ($status -eq 0) {
        if ($all -match '(?i)TooManyRequests|Too Many Requests|throttl') { $status = 429 }
        elseif ($all -match '(?i)ServiceUnavailable|Service Unavailable') { $status = 503 }
        elseif ($all -match '(?i)GatewayTimeout|Gateway Timeout') { $status = 504 }
        elseif ($all -match '(?i)BadGateway|Bad Gateway') { $status = 502 }
        elseif ($all -match '(?i)RequestTimeout|Request Timeout') { $status = 408 }
        elseif ($all -match '(?i)Request_ResourceNotFound') { $status = 404 }
    }
    if ($retryAfter -le 0) {
        $dateText = [regex]::Match($all, '(?i)retry[- ]after\W{0,8}(?<d>(?:Mon|Tue|Wed|Thu|Fri|Sat|Sun),\s+\d{1,2}\s+[A-Za-z]{3}\s+\d{4}\s+\d{2}:\d{2}:\d{2}\s+GMT)')
        if ($dateText.Success) { $retryAfter = ConvertTo-PraRetryAfterSecond $dateText.Groups['d'].Value }
        else {
            $numberText = [regex]::Match($all, '(?i)retry[- ]after\D{0,20}?(?<n>\d{1,5})(?!\d|\s*[A-Za-z]{3}\s+\d{4})')
            if ($numberText.Success) { $retryAfter = [int]$numberText.Groups['n'].Value }
        }
    }
    $retryAfter = [Math]::Min([Math]::Max($retryAfter, 0), 120)
    $transient = $false
    if ($status -ne 0) { $transient = (Test-PraOrdinalIn $status @(408, 429, 502, 503, 504)) }
    else { $transient = ($null -ne (Get-PraNetworkFailure $ErrorRecord)) -or ($all -match '(?i)\btimeout\b|timed out|task was canceled|operation was canceled') }
    return [pscustomobject]@{ Status = $status; RetryAfter = $retryAfter; Transient = [bool]$transient; Throttled = (Test-PraOrdinalIn $status @(429, 503)); NotFound = ($status -eq 404) }
}

function Get-PraRetryState {
    <# The retry budgets of this run (Cloud.RetryBudgetObjectSeconds per object, Cloud.RetryBudgetRunMinutes for the run) and what has been spent. Created on first use. #>
    [CmdletBinding()]
    param([hashtable]$Context)
    if (-not $Context.ContainsKey('_PraRetry')) {
        $cloud = Get-PraValue $Context.Config 'Cloud' @{}
        $Context['_PraRetry'] = @{ ObjectBudget = [int](Get-PraValue $cloud 'RetryBudgetObjectSeconds' 180); RunBudget = ([int](Get-PraValue $cloud 'RetryBudgetRunMinutes' 30) * 60)
            RunSpent = 0; Objects = @{}; Retries = 0; Throttled = 0; Pace = 0; RunExhausted = $false }
    }
    return $Context['_PraRetry']
}

function Stop-PraCloudRun {
    <# The retry time of the run is used up: ONE plain error ends the cloud part (nothing is asked of Microsoft 365 any more), never one failure per object. #>
    [CmdletBinding()]
    param([hashtable]$Context, [Exception]$Inner = $null)
    $state = Get-PraRetryState $Context
    $state.RunExhausted = $true
    $minutes = [Math]::Round($state.RunBudget / 60.0, 1)
    if ($state.Throttled -gt 0) {
        $Context.CloudThrottled = $true
        $message = 'Microsoft 365 is limiting or not answering this run: the {0} minute(s) allowed for retries are used up ({1} retries, {2} throttled answers). Nothing more is asked of Microsoft 365. What this run already did is kept: run the same command again in a few minutes.' -f $minutes, $state.Retries, $state.Throttled
    }
    else {
        $Context.NetworkFailure = $true
        $message = 'Microsoft 365 did not answer (network): the {0} minute(s) allowed for retries are used up ({1} retries). Nothing more is asked of Microsoft 365. What this run already did is kept: run the same command again when the connection works.' -f $minutes, $state.Retries
    }
    $failure = [System.InvalidOperationException]::new($message, $Inner)
    $failure.Data['PraRunBudget'] = $true
    throw $failure
}

function Invoke-PraCloudCall {
    <# One read with retries (Invoke-PraCloudCallCore). A failure of a Microsoft Graph call is marked (Data PraGraph), so that a refusal of Microsoft Graph is told apart from a failure of Exchange Online. #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][hashtable]$Context, [Parameter(Mandatory)][string]$Call, [Parameter(Mandatory)][scriptblock]$Script, [object[]]$ArgumentList = @(), [switch]$NoRetry)
    try { return (Invoke-PraCloudCallCore @PSBoundParameters) }
    catch {
        if ($Call.StartsWith('Microsoft Graph', [StringComparison]::OrdinalIgnoreCase)) { $_.Exception.Data['PraGraph'] = $true }
        throw
    }
}

function Invoke-PraCloudCallCore {
    <#
    .SYNOPSIS
        One read of Microsoft Graph or Exchange Online that can be sent again. A transient failure (408, 429, 502, 503, 504, a timeout, no answer) is retried after the
        Retry-After of the answer, or 5, 10, 20, 40 seconds, at most five tries, within the budget of the object and the budget of the run; each retry is in the log (Detail).
        A throttled answer also slows the next calls of the whole run (a pause that doubles up to 30 seconds and halves after each success). Any other failure (a 4xx
        other than 408 and 429, a refusal, a bad answer) is thrown as it is at once. -NoRetry: one try (a write is never sent again).
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][hashtable]$Context, [Parameter(Mandatory)][string]$Call, [Parameter(Mandatory)][scriptblock]$Script, [object[]]$ArgumentList = @(), [switch]$NoRetry)
    $state = Get-PraRetryState $Context
    $key = [string](Get-PraValue $Context 'CurrentIdentity' '')
    if ($NoRetry -or $state.ObjectBudget -le 0 -or $state.RunBudget -le 0) { return (& $Script @ArgumentList) }
    if ($state.RunExhausted) { Stop-PraCloudRun -Context $Context }
    if ($state.Pace -gt 0) {
        if (($state.RunSpent + $state.Pace) -gt $state.RunBudget) { Stop-PraCloudRun -Context $Context }
        $null = Write-PraLog -Context $Context -Message ('Cloud calls slowed down after throttling: pausing {0} s before {1}' -f $state.Pace, $Call) -Level Detail
        Start-Sleep -Seconds $state.Pace
        $state.RunSpent += $state.Pace
    }
    for ($try = 1; $true; $try++) {
        $clock = [Diagnostics.Stopwatch]::StartNew()
        try {
            $answer = & $Script @ArgumentList
            if ($state.Pace -gt 0) { $state.Pace = [int][Math]::Floor($state.Pace / 2) }
            return $answer
        }
        catch {
            $failure = $_
            $info = Get-PraCloudFailureInfo $failure
            if (-not $info.Transient) { throw }
            if ($info.Throttled) { $state.Throttled++; $state.Pace = [int][Math]::Min(30, [Math]::Max(2, $state.Pace * 2)) }
            # The seconds that the failed call itself took (a timeout) count against both budgets, like the waits.
            $took = [int][Math]::Floor($clock.Elapsed.TotalSeconds)
            $spent = $(if ($state.Objects.ContainsKey($key)) { [int]$state.Objects[$key] } else { 0 }) + $took
            $state.Objects[$key] = $spent; $state.RunSpent += $took
            $wait = if ($info.RetryAfter -gt 0) { [int]$info.RetryAfter } else { [int][Math]::Min(60, 5 * [Math]::Pow(2, $try - 1)) }
            $runOut = (($state.RunSpent + $wait) -gt $state.RunBudget)
            if ($try -ge 5 -or ($spent + $wait) -gt $state.ObjectBudget -or $runOut) {
                $null = Write-PraLog -Context $Context -Message ('Retry budget used up | {0} | {1} | status {2} | {3} tries | object {4} of {5} s, run {6} of {7} s' -f $Call, $key, $info.Status, $try, $spent, $state.ObjectBudget, $state.RunSpent, $state.RunBudget) -Level Detail
                if ($runOut) { Stop-PraCloudRun -Context $Context -Inner $failure.Exception }
                $failure.Exception.Data['PraRetryExhausted'] = $true
                throw $failure
            }
            $null = Write-PraLog -Context $Context -Message ('Retry {0} | {1} | {2} | status {3}{4} | waiting {5} s | object {6} of {7} s, run {8} of {9} s' -f $try, $Call, $key, $(if ($info.Status) { $info.Status } else { 'no answer' }), $(if ($info.RetryAfter -gt 0) { ' (Retry-After ' + $info.RetryAfter + ' s)' } else { '' }), $wait, ($spent + $wait), $state.ObjectBudget, ($state.RunSpent + $wait), $state.RunBudget) -Level Detail
            Start-Sleep -Seconds $wait
            $state.Objects[$key] = $spent + $wait; $state.RunSpent += $wait; $state.Retries++
        }
    }
}

function Test-PraIdentityCheck {
    <# Cloud.IdentityCheck: Anchor (the default, also when the setting is missing) confirms every cloud account against the Active Directory source anchor; Off finds accounts by UPN only. #>
    [CmdletBinding()]
    param([hashtable]$Context)
    return (-not (Test-PraOrdinalIgnoreCaseEqual ([string](Get-PraValue (Get-PraValue $Context.Config 'Cloud' @{}) 'IdentityCheck' 'Anchor')) 'Off'))
}

function Get-PraEntraAccount {
    <# The Entra ID accounts found by UPN (-Upn) or by source anchor (-Anchor), read only. An account that does not exist is an empty answer, never an error. #>
    [CmdletBinding()]
    param([hashtable]$Context, [string]$Upn, [string]$Anchor, [string[]]$Property = @())
    Assert-PraGraphSession $Context
    $select = @(@('id', 'userPrincipalName', 'onPremisesImmutableId', 'onPremisesSyncEnabled') + @($Property) | Get-PraOrdinalUnique -IgnoreCase)
    if ($Anchor) {
        $filter = "onPremisesImmutableId eq '{0}'" -f $Anchor.Replace("'", "''")
        $byAnchor = { param($Filter, $Property) Get-MgUser -Filter $Filter -Property $Property -ErrorAction Stop }
        return @(Invoke-PraCloudCall -Context $Context -Call 'Microsoft Graph user by source anchor' -Script $byAnchor -ArgumentList @($filter, $select))
    }
    $byUpn = { param($UserId, $Property) Get-MgUser -UserId $UserId -Property $Property -ErrorAction Stop }
    try { return @(Invoke-PraCloudCall -Context $Context -Call 'Microsoft Graph user' -Script $byUpn -ArgumentList @($Upn, $select)) }
    catch { if ((Get-PraCloudFailureInfo $_).NotFound) { return @() }; throw }
}

function Resolve-PraCloudIdentity {
    <#
    .SYNOPSIS
        Confirms that the Entra ID account found by UPN is the account synchronised from the Active Directory object (read only).
    .DESCRIPTION
        Status Match       the account carries one of the source anchors (onPremisesImmutableId, compared exactly).
        Status Mismatch    the account with this UPN carries another anchor, is not synchronised (cloud only), or the synchronised account has another UPN.
        Status Ambiguous   Microsoft Entra ID returns several accounts.
        Status NotFound    no account by UPN and none by anchor (not synchronised yet).
        Status NoAnchor    the record has no usable anchor: the account is only found by UPN (-SyncedOnly: a cloud-only account is still a Mismatch).
        -Recorded $false: the anchors were derived from the objectGUID of a record written by an older version.
    #>
    [CmdletBinding()]
    param([hashtable]$Context, [Parameter(Mandatory)][string]$Upn, [AllowNull()][string[]]$Anchors, [bool]$Recorded = $true, [switch]$SyncedOnly, [string[]]$Property = @())
    $anchorList = @($Anchors | Where-Object { $_ })
    $result = { param($Status, $ObjectId, $Message, $Technical, $Account = $null) [pscustomobject]@{ Status = $Status; ObjectId = $ObjectId; Message = $Message; Technical = $Technical; Account = $Account } }
    $older = if ($Recorded) { '' } else { ' The record was written by an older version: it holds only the objectGUID, not the ms-DS-ConsistencyGuid.' }
    $accounts = @(Get-PraEntraAccount -Context $Context -Upn $Upn -Property $Property)
    if ($accounts.Count -gt 1) {
        return (& $result 'Ambiguous' '' ('{0}: Microsoft Entra ID returned {1} accounts for this UPN, so the right one cannot be chosen. Nothing was changed on it. Remove the duplicate account in Microsoft Entra ID, then run the same command again.' -f $Upn, $accounts.Count) ('accounts=' + (@($accounts | ForEach-Object { [string](Get-PraValue $_ 'Id' '') }) -join ',')))
    }
    if ($accounts.Count -eq 1) {
        $id = [string](Get-PraValue $accounts[0] 'Id' ''); $found = [string](Get-PraValue $accounts[0] 'OnPremisesImmutableId' '')
        if (-not $anchorList.Count) {
            if ($SyncedOnly -and -not $found) { return (& $result 'Mismatch' $id ('{0}: the Microsoft Entra ID account with this UPN is a cloud-only account, not an account synchronised from Active Directory. Nothing was changed on it. Give one of the two accounts another UPN, then run the same command again.' -f $Upn) ('id=' + $id)) }
            return (& $result 'NoAnchor' $id '' ('id=' + $id) $accounts[0])
        }
        if (Test-PraOrdinalIn $found $anchorList) { return (& $result 'Match' $id '' ('id=' + $id + '; onPremisesImmutableId=' + $found) $accounts[0]) }
        if ($found) {
            $form = if ($found -cmatch '^[A-Za-z0-9+/]{22}==\z') { 'is the base64 of a GUID, but not the objectGUID or the ms-DS-ConsistencyGuid of this Active Directory object' } else { 'is not the base64 of a GUID' }
            return (& $result 'Mismatch' $id ('{0}: the Microsoft Entra ID account with this UPN is synchronised, but its onPremisesImmutableId {1}. Nothing was changed on it. Your tenant may use another source anchor than the objectGUID or the ms-DS-ConsistencyGuid: check by hand that this account is the one of this object, then set Cloud.IdentityCheck = ''Off'' in the configuration file and run the same command again.{2}' -f $Upn, $form, $older) ('id=' + $id + '; onPremisesImmutableId=' + $found + '; expected=' + ($anchorList -join ' or ')))
        }
        return (& $result 'Mismatch' $id ('{0}: the Microsoft Entra ID account with this UPN is not the account synchronised from this Active Directory object (it is a cloud-only account). Nothing was changed on it. Give one of the two accounts another UPN so that Entra Connect can synchronise this object under its own UPN, or leave this object out, then run the same command again.{1}' -f $Upn, $older) ('id=' + $id + '; onPremisesImmutableId=; expected=' + ($anchorList -join ' or ')))
    }
    if (-not $anchorList.Count) { return (& $result 'NotFound' '' '' '') }
    $byAnchor = @{}
    foreach ($anchor in $anchorList) {
        foreach ($account in @(Get-PraEntraAccount -Context $Context -Anchor $anchor)) {
            $accountId = [string](Get-PraValue $account 'Id' '')
            if ($accountId -and -not $byAnchor.ContainsKey($accountId)) { $byAnchor[$accountId] = $account }
        }
    }
    if ($byAnchor.Count -gt 1) { return (& $result 'Ambiguous' '' ('{0}: Microsoft Entra ID has {1} accounts that carry the source anchor of this Active Directory object, so the right one cannot be chosen. Nothing was changed on it. Remove the duplicate account in Microsoft Entra ID, then run the same command again.' -f $Upn, $byAnchor.Count) ('accounts=' + (@($byAnchor.Keys) -join ','))) }
    if ($byAnchor.Count -eq 1) {
        $other = @($byAnchor.Values)[0]
        return (& $result 'Mismatch' ([string](Get-PraValue $other 'Id' '')) ('{0}: the account synchronised from this Active Directory object is {1} in Microsoft Entra ID, not {0}. Nothing was changed on it. Make the UPN in Active Directory and in Microsoft Entra ID the same (then let Entra Connect synchronise), then run the same command again.' -f $Upn, [string](Get-PraValue $other 'UserPrincipalName' '')) ('id=' + [string](Get-PraValue $other 'Id' '')))
    }
    return (& $result 'NotFound' '' '' '')
}

function Get-PraGraphRefusal {
    <# $null unless Microsoft Graph refused the read of an account (401, 403, insufficient privileges): then the plain message with its next step (the permission, or Cloud.IdentityCheck = Off) and the technical text. #>
    [CmdletBinding()]
    param([Parameter(Mandatory)]$ErrorRecord, [string]$Upn = '')
    $info = Get-PraCloudFailureInfo $ErrorRecord
    $raw = [string]$ErrorRecord.Exception.Message
    $refused = (Test-PraOrdinalIn $info.Status @(401, 403)) -or ($raw -match '(?i)Insufficient privileges|Authorization_RequestDenied|Authorization_IdentityNotFound|Forbidden')
    if (-not $refused) { return $null }
    if ($info.Status -eq 401) {
        $expired = '{0}: Microsoft Graph did not accept the sign-in (HTTP 401): the sign-in expired or was refused. Nothing was changed. Sign in again: run the same command again and sign in when asked. With a certificate (application), check that the certificate is installed and still valid, and that Cloud.TenantId and Cloud.AppId are the ones of your app registration.' -f $Upn
        return [pscustomobject]@{ Message = $expired; Technical = $raw; Kind = 'Expired' }
    }
    $message ='{0}: Microsoft Graph refused to read the Microsoft Entra ID account that confirms this object ({1}). Nothing was changed. The tool reads every account with the permission User.Read.All: with a sign-in by a person, the administrator must consent to User.Read.All; with a certificate (application), add the application permission User.Read.All to the app registration and grant admin consent. Then run the same command again. Or set Cloud.IdentityCheck = ''Off'' in the configuration file: the accounts are then found by UPN only, without this read.' -f $Upn, $(if ($info.Status) { 'HTTP ' + $info.Status } else { 'insufficient privileges' })
    return [pscustomobject]@{ Message = $message; Technical = $raw; Kind = 'Denied' }
}

function Confirm-PraCloudIdentity {
    <# The Entra ID account (and the account of each trustee) of one object is the one synchronised from Active Directory. Returns Ok, Wait (not in Microsoft Entra ID yet: read again at the next check) or Failed (an error is recorded; the object is never acted on). #>
    [CmdletBinding()]
    param([hashtable]$Context, $State, [switch]$Throw)
    $row = $State.Row; $upn = [string]$State.Upn
    $fail = { param($Message, $Technical) if ($Throw) { throw $Message }; Write-PraCloudError -Context $Context -Row $row -Message $Message -Technical $Technical -RunError; return 'Failed' }
    if (-not (Test-PraIdentityCheck $Context)) {
        if (-not [bool](Get-PraValue $Context 'IdentityCheckOffSaid' $false)) {
            $Context.IdentityCheckOffSaid = $true
            Write-PraItem -Context $Context -Status Info -Text 'Cloud.IdentityCheck = Off: the Microsoft Entra ID accounts are found by UPN only, they are not confirmed against Active Directory.'
        }
        return 'Ok'
    }
    $session = Get-PraCloudSession $Context
    $source = Get-PraValue $row 'BackupRec' $null; if ($null -eq $source) { $source = $row }
    $anchor = Get-PraSourceAnchor -Record $source
    if ($session.IdentityCache.ContainsKey($upn)) { $verdict = $session.IdentityCache[$upn] }
    else {
        try { $verdict = Resolve-PraCloudIdentity -Context $Context -Upn $upn -Anchors $anchor.Candidates -Recorded $anchor.Recorded -Property ([string[]]@(Get-PraList $State 'FactProps')) }
        catch { $refusal = Get-PraGraphRefusal -ErrorRecord $_ -Upn $upn; if ($null -eq $refusal) { throw }; if (-not $Throw) { $Context.GraphRefused = $true }; return (& $fail $refusal.Message $refusal.Technical) }
        if (Test-PraOrdinalIn $verdict.Status @('Match', 'Mismatch', 'Ambiguous')) { $session.IdentityCache[$upn] = $verdict }
    }
    if (Test-PraOrdinalIn $verdict.Status @('Mismatch', 'Ambiguous')) { return (& $fail $verdict.Message $verdict.Technical) }
    if (Test-PraOrdinalEqual $verdict.Status 'NotFound') {
        if ($Throw) { throw ('{0}: the account is not in Microsoft Entra ID (neither by UPN nor by source anchor). It must be synchronised from Active Directory before this run: run the Entra Connect sync, then run the command again.' -f $upn) }
        $State.PlainText = 'the account is not in Microsoft Entra ID yet (the Entra Connect sync has not run)'
        $row.CloudStatus = 'Pending'
        return 'Wait'
    }
    if (Test-PraOrdinalEqual $verdict.Status 'NoAnchor') {
        if ($Context.AllowMutation -is [bool] -and $Context.AllowMutation -and @($State.Requests).Count) {
            return (& $fail ('{0}: the Active Directory identity of this object is not in the record, so the Microsoft Entra ID account cannot be confirmed and no permission is granted. Give the object by its sAMAccountName or run its batch, then run the command again.' -f $upn) '')
        }
        $note = '{0}: the Microsoft Entra ID account is found by its UPN only: this object has no Active Directory identity in the record (the identity was given as a UPN). Give its sAMAccountName or -Batch to have it confirmed.' -f $upn
        Write-PraItem -Context $Context -Status Warn -Text $note
        $row.Warnings = ([string](Get-PraValue $row 'Warnings' '') + '; ' + $note).Trim(' ', ';')
    }
    $session.Verified[$upn] = [string]$verdict.ObjectId
    # The account read for the identity also carries the properties of the first facts read: it is passed on once, never kept.
    $State.Account = $verdict.Account; $verdict.Account = $null
    $trustees = @(@($State.Requests) | ForEach-Object { [string]$_.Trustee } | Get-PraOrdinalUnique -IgnoreCase)
    # A record whose trustee anchors are incomplete (the schema could not be read) asks no more of a trustee than an older record: a synchronised account.
    $incomplete = [bool](Get-PraValue $source 'SharedTrusteeAnchorsIncomplete' $false)
    foreach ($trustee in $trustees) {
        $stored = if ($incomplete) { $null } else { Get-PraValue (Get-PraValue $source 'SharedTrusteeAnchors' $null) $trustee $null }
        if ($session.IdentityCache.ContainsKey($trustee)) { $answer = $session.IdentityCache[$trustee] }
        else {
            try { $answer = Resolve-PraCloudIdentity -Context $Context -Upn $trustee -Anchors ([string[]]@(if ($null -ne $stored) { @($stored) })) -Recorded ($null -ne $stored) -SyncedOnly }
            catch { $refusal = Get-PraGraphRefusal -ErrorRecord $_ -Upn $trustee; if ($null -eq $refusal) { throw }; if (-not $Throw) { $Context.GraphRefused = $true }; return (& $fail $refusal.Message $refusal.Technical) }
            if (Test-PraOrdinalIn $answer.Status @('Match', 'Mismatch', 'Ambiguous')) { $session.IdentityCache[$trustee] = $answer }
        }
        if (Test-PraOrdinalIn $answer.Status @('Mismatch', 'Ambiguous')) { return (& $fail ('Permissions on {0} are not granted. {1}' -f $upn, $answer.Message) $answer.Technical) }
        if (-not (Test-PraOrdinalEqual $answer.Status 'NotFound')) { $session.Verified[$trustee] = [string]$answer.ObjectId }
    }
    return 'Ok'
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
                        -not (Test-PraOrdinalIgnoreCaseEqual $receipt.Target $Params.Upn) -or -not (Test-PraOrdinalIgnoreCaseEqual $receipt.Trustee $Params.Trustee) -or -not (Test-PraOrdinalEqual $receipt.Right $Params.Right) -or $OnApplied -isnot [scriptblock]) { throw 'Invalid Applied receipt from the Exchange Online child process.' }
                    $null=& $OnApplied
                    [IO.File]::Delete($appliedPath)
                }
            } finally { foreach ($leftover in @($tmp,$progressPath)) { if ([IO.File]::Exists($leftover)) { [IO.File]::Delete($leftover) } } }
        }
    }
}

function Invoke-PraExo {
    param([hashtable]$Context,[ValidateSet('Probe','Preflight','Mailbox','Recipient','Hold','HoldBulk','Permission','Grant')][string]$Operation,[hashtable]$Params=@{},$Permit=$null,$OnApplied=$null,$OnProgress=$null)
    $session = Get-PraCloudSession $Context
    if (-not $session.Exo) { throw 'Exchange Online connection required but not available.' }
    if (-not $session.Subprocess -and -not (Test-PraOrdinalIgnoreCaseEqual ([string](Get-PraValue (Get-PraValue $session 'Binding' $null) 'TenantId' '')) ([string](Get-PraValue (Get-PraValue $Context.Config 'Cloud' @{}) 'TenantId' '')))) { throw 'Exchange Online tenant of the session differs from Cloud.TenantId.' }
    if ((Test-PraOrdinalIgnoreCaseEqual $Operation 'Grant') -and ($null -eq $Permit -or $Context.AllowMutation -isnot [bool] -or -not $Context.AllowMutation -or
        -not (Test-PraOrdinalEqual $Context.Mode 'Apply') -or -not (Test-PraOrdinalEqual $Context.Action 'Convert') -or -not (Test-PraOrdinalIn $Context.Phase @('Cloud','Both')) -or $WhatIfPreference)) { throw 'Grant without an active write authorisation.' }
    $Params=$Params.Clone()
    $Params.ExpectedIdentities=Get-PraValue $session 'Identities' @{}
    $verified=@{}
    foreach ($name in @(@([string](Get-PraValue $Params 'Upn' '')) + @([string](Get-PraValue $Params 'Trustee' '')) + @(Get-PraList $Params 'Requests' | ForEach-Object { [string](Get-PraValue $_ 'Trustee' '') }))) {
        if ($name -and $session.Verified.ContainsKey($name)) { $verified[$name]=[string]$session.Verified[$name] }
    }
    $Params.VerifiedObjectIds=$verified
    if ((Test-PraOrdinalIgnoreCaseEqual $Operation 'Grant')) {
        $exo=Get-PraValue $Context.Config 'Exo' @{}
        $Params.GrantVerifyAttempts=Get-PraValue $exo 'GrantVerifyAttempts' 13
        $Params.GrantVerifyDelaySeconds=Get-PraValue $exo 'GrantVerifyDelaySeconds' 10
    }
    $dispatch = {
        param($Ctx, $Sess, $Op, $Prm, $Prt, $Applied, $Progress)
        if ($Sess.Subprocess) { Invoke-PraExoSubprocess -Context $Ctx -Operation $Op -Params $Prm -Permit $Prt -OnApplied $Applied -OnProgress $Progress }
        else { & $script:PraExoWorker $Op $Prm $Prt (Get-PraValue $Sess 'Binding' $null) $Applied $Progress }
    }
    $dispatchArguments = @($Context, $session, $Operation, $Params, $Permit, $OnApplied, $OnProgress)
    $results = @(if (Test-PraOrdinalIgnoreCaseEqual $Operation 'Grant') { & $dispatch @dispatchArguments }
        else { Invoke-PraCloudCall -Context $Context -Call ('Exchange Online ' + $Operation) -Script $dispatch -ArgumentList $dispatchArguments })
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
    # Graph is connected before Exchange Online.
    if ($NeedGraph -and -not $s.Graph) {
        $Context.CurrentOperation='Connect-MgGraph'
        # ONE version of every Graph module: the highest that exists for all of them, at the minimum or later.
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
            if ($_.Exception.Message -match 'does not have an implementation|Could not load (type|file or assembly)|Method not found') {
                throw ('Microsoft Graph could not load an assembly in this console: close this window and run the tool in a new PowerShell 7 window. Detail: '+$_.Exception.Message)
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
        if (-not (Test-PraOrdinalIgnoreCaseEqual ([string](Get-PraValue $current $key '')) ([string](Get-PraValue $s.GraphContext $key '')))) { throw 'The Microsoft Graph session changed.' }
    }
}

function Close-PraCloudSession {
    <#
    .SYNOPSIS
        Signs out the sessions opened by this module; a sign-out failure is a warning (the session stays recorded, a later call tries again).
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
                    if (-not (Test-PraOrdinalIgnoreCaseEqual ([string](Get-PraValue $current $key '')) ([string](Get-PraValue $s.GraphContext $key '')))) { throw 'The Microsoft Graph session was replaced: not signed out.' }
                }
                Disconnect-MgGraph -ErrorAction Stop | Out-Null
            }
            $s.GraphAttempted=$false; $s.Graph=$false
        }
        catch { [void]$errors.Add('Microsoft Graph sign-out: '+$_.Exception.Message) }
    }
    if ($errors.Count) {
        $Context.CurrentOperation='Close-PraCloudSession'
        Write-PraSignOutWarning -Context $Context -Message ($errors -join ' | ')
        return
    }
    [void]$Context.Remove('_PraCloudSession')
}

function Get-PraPermissionRequest {
    param([hashtable]$Context,$Row)
    if (-not [bool](Get-PraValue $Row 'IsShared' $false)) { return }
    # The settings stored in the batch by the Convert run decide; a batch that has none follows the configuration of this server.
    $cfg = Get-PraValue $Context 'BatchGrantSettings' $null
    if ($null -eq $cfg) { $cfg = Get-PraValue $Context.Config 'SharedMailbox' @{} }
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
        Signs in and resolves every target and trustee in Exchange Online before the AD part of a Convert (Apply, phase Both). Read only.
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
        if (Test-PraIdentityCheck $Context) { $needGraph=$true }
        # EXO resolves each target even while it is still a MailUser; no provisioning assertion here.
        Connect-PraCloudSession -Context $Context -NeedGraph $needGraph -NeedExo ($Rows.Count -gt 0)
        $session=Get-PraCloudSession $Context
        foreach ($row in $Rows) {
            $upn=[string](Get-PraValue $row 'UserPrincipalName' '')
            $Context.CurrentIdentity=$upn; $Context.CurrentOperation='ResolvePreflightIdentity'
            $requests=if ($isRecover) { @() } else { @(Get-PraPermissionRequest $Context $row) }
            $null=Confirm-PraCloudIdentity -Context $Context -State @{ Row=$row; Upn=$upn; Requests=$requests; PlainText='' } -Throw
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
            if ($session.Verified.ContainsKey($upn) -and [string]$session.Verified[$upn]) {
                # The account was read for the identity check: its id is compared with the one Exchange Online returns, with no second read.
                $confirmedTarget=Get-PraValue $identities $upn $null
                if (-not (Test-PraOrdinalIgnoreCaseEqual ([string]$session.Verified[$upn]) ([string](Get-PraValue $confirmedTarget 'ObjectId' '')))) { throw "Graph and Exchange Online identities differ at the pre-check: $upn" }
            }
            elseif ($needGraph -and -not [bool](Get-PraValue $row 'IsShared' $false)) {
                Assert-PraGraphSession $Context
                $readUser={ param($UserId,$Property) Get-MgUser -UserId $UserId -Property $Property -ErrorAction Stop }
                $users=@(Invoke-PraCloudCall -Context $Context -Call 'Microsoft Graph user' -Script $readUser -ArgumentList @($upn,@('Id','UserPrincipalName')))
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

function Get-PraGrantKey {
    <# The identity of one grant in this run: the mailbox (its confirmed Entra id, else its UPN), the right and the trustee (its confirmed id, else as given). #>
    param([hashtable]$Context,[string]$Upn,[string]$Right,[string]$Trustee)
    $verified=(Get-PraCloudSession $Context).Verified
    $mailbox=if ($verified.ContainsKey($Upn) -and [string]$verified[$Upn]) { [string]$verified[$Upn] } else { $Upn }
    $who=if ($verified.ContainsKey($Trustee) -and [string]$verified[$Trustee]) { [string]$verified[$Trustee] } else { $Trustee }
    return ($mailbox+'|'+$Right+'|'+$who)
}

function Get-PraGrantsApplied {
    <# The grants already sent in this run (mailbox id, right, trustee; ignoring case): a grant in this set is never sent again, whatever a later read shows. #>
    param([hashtable]$Context)
    if (-not $Context.ContainsKey('_PraGrantsApplied')) { $Context['_PraGrantsApplied']=New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase) }
    return ,$Context['_PraGrantsApplied']
}

function Get-PraGrantsVerified {
    <# The grants of this run that were sent and then read back as present (the same keys): a later read that does not show one is a permission to check by hand, never a reason to send it again. #>
    param([hashtable]$Context)
    if (-not $Context.ContainsKey('_PraGrantsVerified')) { $Context['_PraGrantsVerified']=New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase) }
    return ,$Context['_PraGrantsVerified']
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
    [void](Get-PraGrantsApplied $Context).Add((Get-PraGrantKey -Context $Context -Upn $target -Right ([string]$Params.Right) -Trustee ([string]$Params.Trustee)))
    $Context.GrantsSent=[int](Get-PraValue $Context 'GrantsSent' 0)+1
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
        [void](Get-PraGrantsVerified $Context).Add((Get-PraGrantKey -Context $Context -Upn $target -Right ([string]$Params.Right) -Trustee ([string]$Params.Trustee)))
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
    $Row.PermMissing=@(); $verified=0; $toGrant=0; $missing=New-Object 'System.Collections.Generic.List[string]'; $byHand=New-Object 'System.Collections.Generic.List[string]'
    $cfg=Get-PraValue $Context.Config 'SharedMailbox' @{}
    $upn=[string](Get-PraValue $Row 'UserPrincipalName' '')
    $preview=((Test-PraOrdinalEqual $Context.Action 'Convert') -and (-not (Test-PraOrdinalEqual $Context.Mode 'Apply') -or -not $Context.AllowMutation -or $WhatIfPreference))
    foreach ($request in $Requests) {
        $p=@{ Upn=$upn; Trustee=$request.Trustee; Right=$request.Right; AutoMapping=[bool](Get-PraValue $cfg 'AutoMapping' $false) }
        $Row.PermDetail="Permissions verified=$verified/$($Requests.Count); current=$($request.Right)/$($request.Trustee)"
        $r=Invoke-PraExo -Context $Context -Operation 'Permission' -Params $p
        if ((Get-PraValue $r 'TrusteeFound' $false) -ne $true) {
            if (-not (Test-PraOrdinalIn $request.Trustee $missing.ToArray() -IgnoreCase)) { [void]$missing.Add($request.Trustee) }
            $Row.PermMissing=$missing.ToArray(); continue
        }
        if ((Get-PraValue $r 'Verified' $false) -ne $true) {
            if ($preview) { $toGrant++; continue }
            $grantKey=Get-PraGrantKey -Context $Context -Upn $upn -Right ([string]$request.Right) -Trustee ([string]$request.Trustee)
            if ((Get-PraGrantsApplied $Context).Contains($grantKey)) {
                # Sent in this run: never sent again, and not counted as verified either. The read does not show it: the permission is to check by hand.
                $null=Write-PraLog -Context $Context -Message ("{0}: {1} to {2} was already sent in this run{3}; it is not sent again and the last read does not show it" -f $upn,$request.Right,$request.Trustee,$(if ((Get-PraGrantsVerified $Context).Contains($grantKey)) { ' and read back as present' } else { '' })) -Level Detail
                [void]$byHand.Add(('{0} for {1}' -f $request.Right,$request.Trustee))
                continue
            }
            if ($Context.AllowMutation -isnot [bool] -or -not $Context.AllowMutation -or -not (Test-PraOrdinalEqual $Context.Mode 'Apply') -or
                -not (Test-PraOrdinalEqual $Context.Action 'Convert') -or -not (Test-PraOrdinalIn $Context.Phase @('Cloud','Both')) -or $WhatIfPreference) { throw 'Permission missing and writes are not allowed in this mode.' }
            # Native ShouldProcess per right; it never replaces the approval, proof and journal of the grant.
            if (-not $PSCmdlet.ShouldProcess($upn,"Grant $($request.Right) to $($request.Trustee)")) { throw 'Exchange Online grant refused (ShouldProcess).' }
            # A failure of the grant step is final for this run, whatever its cause: the grant is never sent twice. A later run reads the permissions first.
            try { Invoke-PraPermissionGrant -Context $Context -Row $Row -Params $p }
            catch {
                $grantFailure = [System.InvalidOperationException]::new([string]$_.Exception.Message, $_.Exception)
                $grantFailure.Data['PraGrantFailed'] = $true
                throw $grantFailure
            }
            $null=Write-PraLog -Context $Context -Message ("{0}: {1} granted to {2} and verified" -f $upn,$request.Right,$request.Trustee) -Level Sub
        }
        $verified++
    }
    $Row.PermDetail="Permissions verified=$verified/$($Requests.Count); to grant=$toGrant; trustees missing in Exchange Online=$($missing.Count)"
    if ($byHand.Count) { $Row.PermDetail+="; to check by hand=$($byHand.Count)" }
    if ($missing.Count) { throw ($Row.PermDetail+': '+($missing -join ', ')) }
    if (($verified+$toGrant+$byHand.Count) -ne $Requests.Count) { throw $Row.PermDetail }
    if ($byHand.Count) {
        $note=('{0}: {1} permission(s) were granted in this run but a later read does not show them: {2}. They were not sent again. Check them by hand: Get-EXOMailboxPermission -Identity {0} | Format-Table User,AccessRights; Get-EXORecipientPermission -Identity {0} | Format-Table Trustee,AccessRights' -f $upn,$byHand.Count,($byHand -join '; '))
        $Row.Warnings=([string](Get-PraValue $Row 'Warnings' '') + '; ' + $note).Trim(' ',';')
        Write-PraItem -Context $Context -Status Warn -Text $note
    }
    return $toGrant
}

function Get-PraGraphFactProperty {
    <# The Graph properties that Get-PraGraphFact reads for these questions. #>
    param([bool]$Mailbox,[bool]$License,[bool]$Addresses=$false)
    $props=@('assignedPlans'); if ($Mailbox) { $props+='provisionedPlans' }; if ($License) { $props+='assignedLicenses' }; if ($Addresses) { $props+='proxyAddresses' }
    return $props
}

function Get-PraGraphFact {
    <# The Graph facts of one account. The account is read by the Entra id confirmed for the object (by UPN when none is known). -Account: the user already read with these properties (the identity check), taken as the answer of the first read (the account is then not read again). #>
    param([hashtable]$Context,[string]$Upn,[bool]$Mailbox,[bool]$License,[bool]$Addresses=$false,$Account=$null)
    if (-not (Get-PraCloudSession $Context).Graph) { throw 'Microsoft Graph required but not connected.' }
    Assert-PraGraphSession $Context
    $props=@(Get-PraGraphFactProperty -Mailbox $Mailbox -License $License -Addresses $Addresses)
    $verified=(Get-PraCloudSession $Context).Verified
    $confirmed=if ($verified.ContainsKey($Upn) -and [string]$verified[$Upn]) { [string]$verified[$Upn] } else { '' }
    $lookup=if ($confirmed) { $confirmed } else { $Upn }
    $sentinel=New-Object object
    $prefetched=($null -ne $Account -and -not @($props | Where-Object { [object]::ReferenceEquals((Get-PraValue $Account $_ $sentinel),$sentinel) }).Count)
    if ($prefetched) { $users=@($Account) }
    else {
        $readUser={ param($UserId,$Property) Get-MgUser -UserId $UserId -Property $Property -ErrorAction Stop }
        $users=@(Invoke-PraCloudCall -Context $Context -Call 'Microsoft Graph user' -Script $readUser -ArgumentList @($lookup,@($props + 'id')))
    }
    if ($users.Count -ne 1 -or $null -eq $users[0]) { throw "Microsoft Graph: user not found or not unique ($Upn)." }
    $returnedId=[string](Get-PraValue $users[0] 'Id' '')
    if ($confirmed -and $returnedId -and -not (Test-PraOrdinalIgnoreCaseEqual $returnedId $confirmed)) { throw "Microsoft Graph returned another account than the one confirmed for this object: $Upn. Nothing was changed on it. Run the same command again, the account is then confirmed once more. If this comes back, look at the account: Get-MgUser -UserId $confirmed -Property Id,UserPrincipalName,OnPremisesImmutableId" }
    $values=@{}
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
        $readDetails={ param($UserId) Get-MgUserLicenseDetail -UserId $UserId -All -ErrorAction Stop }
        $details=@(Invoke-PraCloudCall -Context $Context -Call 'Microsoft Graph licence details' -Script $readDetails -ArgumentList @($lookup))
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
    catch {
        # The stop of the run is not a result of the control: it goes to the caller.
        if ((Get-PraRetryState $Context).RunExhausted) { throw }
        $State.X500Failure = [string]$_.Exception.Message; $State.X500Last = $null
    }
    $good = ([string]::IsNullOrEmpty($State.X500Failure) -and $State.X500Last.Missing.Count -eq 0)
    if ($good -or $Final -or $State.X500Reads -ge $MaxReads) { Complete-PraX500Check -Context $Context -State $State; return $true }
    $found = if ($null -ne $State.X500Last) { 'X500:{0} of {1} present, read {2} of {3}' -f $State.X500Last.Present.Count, $State.X500Last.Total, $State.X500Reads, $MaxReads } else { 'X500:not readable yet, read {0} of {1}' -f $State.X500Reads, $MaxReads }
    $State.Row.CloudDetail = ([string]$State.Row.CloudDetail -replace ' \| X500:[^|]*\z', '') + ' | ' + $found
    return $false
}

function Write-PraUnfinishedFailure {
    <# A failure that ends a cloud part before every row is done. A row that finished (Success, Skipped, Planned, Error) keeps its result. A run stop (the retry time of the run is used up) leaves the other rows Pending under ONE error; any other failure is an error of each row that was not finished (or one run error when every row had finished). -What: 'finished' or 'checked'. #>
    param([hashtable]$Context,[AllowEmptyCollection()][object[]]$Rows,[Parameter(Mandatory)]$ErrorRecord,[string]$What='finished')
    $unfinished=@($Rows | Where-Object { -not (Test-PraOrdinalIn ([string](Get-PraValue $_ 'CloudStatus' '')) @('Success','Skipped','Error','Planned')) })
    $runStop=((Get-PraRetryState $Context).RunExhausted -or ($ErrorRecord.Exception.Data['PraRunBudget'] -eq $true))
    if ($runStop) {
        foreach ($row in $unfinished) {
            $row.CloudStatus='Pending'; $row.FinalStatus='Pending'
            $row.Detail=([string](Get-PraValue $row 'Detail' '')+' | not '+$What+': the retry time of the run is used up').Trim(' ','|')
        }
        $Context.CurrentIdentity=''
        Write-PraCloudError -Context $Context -Row $null -Message ('{0} {1} object(s) were not {2}.' -f $ErrorRecord.Exception.Message, $unfinished.Count, $What) -Technical $(if ($null -ne $ErrorRecord.Exception.InnerException) { [string]$ErrorRecord.Exception.InnerException.Message } else { '' })
        return
    }
    foreach ($row in $unfinished) { Write-PraCloudFailure -Context $Context -Row $row -ErrorRecord $ErrorRecord -Upn ([string](Get-PraValue $row 'UserPrincipalName' '')) }
    if (-not $unfinished.Count) { Write-PraCloudFailure -Context $Context -Row $null -ErrorRecord $ErrorRecord }
}

function Get-PraRecordedMailboxGuid {
    <# The mailbox GUID that the record kept from Active Directory (msExchMailboxGuid, before the conversion), as a GUID text; none when the record has none. #>
    param($Record)
    $state = Get-PraValue (Get-PraValue $Record 'Attributes' $null) 'msExchMailboxGuid' $null
    $value = [string](Get-PraValue $state 'Value' '')
    if (-not $value) { return }
    try { $bytes = [Convert]::FromBase64String($value) } catch { return }
    if ($bytes.Length -eq 16) { ([guid]::new($bytes)).ToString() }
}

function Write-PraSignOutWarning {
    <# The sign-out of the cloud sessions failed: a warning, never an error of an object (what the run did is not changed by it). #>
    param([hashtable]$Context,[Parameter(Mandatory)][string]$Message)
    $null=Write-PraLog -Context $Context -Message ('Technical detail: sign-out failed: {0}' -f $Message) -Level Detail
    if ([bool](Get-PraValue $Context 'CloudSignOutWarned' $false)) { return }
    $Context.CloudSignOutWarned=$true
    Write-PraItem -Context $Context -Status Warn -Text ('The sign-out of Microsoft 365 failed ({0}). What this run did is not affected. If a session is still open, close it: Disconnect-ExchangeOnline -Confirm:$false; Disconnect-MgGraph' -f ($Message -replace '\s+',' '))
}

function Invoke-PraCloudPhase {
    <#
    .SYNOPSIS
        Checks (and waits for) the expected Exchange Online state of every row and, in Apply, grants the shared mailbox permissions.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][hashtable]$Context,[Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Rows,
        [Parameter(Mandatory)][ValidateSet('Convert','Recover')][string]$Act)
    $Context.CurrentPhase='Cloud'; $Context.CurrentOperation='Prepare'; $Context.CurrentIdentity=''; $Context.CloudConnectFailed=$false; $Context.NetworkFailure=$false; $Context.NotYetExpected=0; $Context.CloudNotReached=0; $Context.GraphRefused=$false
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
            if (-not $upn) { Write-PraCloudError -Context $Context -Row $row -Message 'UPN missing: check impossible.' -RunError; continue }
            if (Test-PraOrdinalIgnoreCaseEqual (Get-PraValue $row 'FinalStatus' '') 'Error') { Write-PraCloudError -Context $Context -Row $row -Message 'Previous error: cloud part not allowed.' -RunError; continue }
            $shared=[bool](Get-PraValue $row 'IsShared' $false)
            $preserveMailbox=Get-PraValue $row 'PreserveCloudMailbox' $false; $preserveLicense=Get-PraValue $row 'PreserveLicense' $false
            if ($preserveMailbox -isnot [bool] -or $preserveLicense -isnot [bool] -or ($preserveMailbox -and -not $shared)) {
                Write-PraCloudError -Context $Context -Row $row -Message 'Invalid keep flags (PreserveCloudMailbox is for shared mailboxes only).' -RunError; continue
            }
            $requests=@(); if ((Test-PraOrdinalIgnoreCaseEqual $Act 'Convert')) { $requests=@(Get-PraPermissionRequest $Context $row) }
            # A permission that the record carries and the settings in effect do not grant is never silent: a warning names it (the result is "done with warnings"),
            # and the row says it is to grant by hand (report and CSV).
            if ($shared -and (Test-PraOrdinalIgnoreCaseEqual $Act 'Convert')) {
                $notGranted=New-Object 'System.Collections.Generic.List[string]'
                $requested=New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
                foreach ($request in $requests) { [void]$requested.Add(([string]$request.Right)+'|'+([string]$request.Trustee)) }
                foreach ($right in @('FullAccess','SendAs','SendOnBehalf')) {
                    foreach ($trustee in @((Get-PraValue $row ('Shared'+$right) @()) | Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) } | Get-PraOrdinalUnique -IgnoreCase)) {
                        if (-not $requested.Contains($right+'|'+[string]$trustee)) { $notGranted.Add(('{0} {1}' -f $right,[string]$trustee)) }
                    }
                }
                if ($notGranted.Count) {
                    $whose=if (Test-PraOrdinalIgnoreCaseEqual ([string](Get-PraValue $Context 'GrantSettingsSource' 'Configuration')) 'Batch') { 'the settings the batch was converted with' } else { 'the settings of this server (this batch does not record its own)' }
                    $note=('{0}: {1} shared mailbox permission(s) not granted by {2} - to grant by hand: {3}.' -f $upn,$notGranted.Count,$whose,($notGranted -join '; '))
                    $row.Warnings=([string](Get-PraValue $row 'Warnings' '') + '; ' + $note).Trim(' ',';')
                    $null=Write-PraLog -Context $Context -Message ($note + ' They are in the backup file and in the report.') -Level Warning
                }
            }
            $mb=([bool](Get-PraValue $cloud 'CheckMailbox' $false) -or (Test-PraOrdinalIgnoreCaseEqual $Act 'Recover') -or $requests.Count -gt 0)
            $lic=-not $shared -and [bool](Get-PraValue $cloud 'CheckLicense' $false)
            if (-not $mb -and -not $lic) {
                $row.CloudStatus='Skipped'; $row.CloudDetail='No applicable check; no restore confirmation.'; $row.FinalStatus='Skipped'; continue
            }
            # X500 control (Convert): the addresses recorded by the AD phase must be on the cloud mailbox. A batch written without the list has none: the control is skipped, never a failure.
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
            # The object is waited for from here on: it is not done until the checks below say so.
            $row.FinalStatus='Pending'
            $exoMailbox=$mb -and ((Test-PraOrdinalIgnoreCaseEqual $Act 'Recover') -or $shared -or (Test-PraOrdinalIgnoreCaseEqual $via 'Exo'))
            $needGraph=$needGraph -or $lic -or $graphMailbox; $needExo=$needExo -or $exoMailbox
            [void]$states.Add(@{ Row=$row; Upn=$upn; Shared=$shared; Mailbox=$mb; License=$lic; GraphMailbox=$graphMailbox
                ExoMailbox=$exoMailbox; Requests=$requests; PreserveMailbox=$preserveMailbox; PreserveLicense=$preserveLicense; Done=$false; PlainText=''
                X500=$x500Expected; X500Reads=0; X500Failure=''; X500Last=$null; CoreDone=$false; IdentityChecked=$false; LastFailure=$null })
        }
        if ($states.Count -eq 0) { return }
        if (Test-PraIdentityCheck $Context) { $needGraph=$true }
        try { Connect-PraCloudSession -Context $Context -NeedGraph $needGraph -NeedExo $needExo }
        catch { $Context.CloudConnectFailed=$true; throw }
        $clock=[Diagnostics.Stopwatch]::StartNew(); $timeout=[double]$Context.TimeoutMinutes*60; $attempt=0
        $x500MaxReads=3   # first read + two re-reads at the polling interval: the cloud value can lag one synchronisation, never a long new wait
        $stopRun=$null; $graphStop=$false
        do {
            $attempt++; $pending=@($states | Where-Object { -not $_.Done })
            $Context.CurrentIdentity=''
            $null=Write-PraLog -Context $Context -Message ("Check {0}: {1} object(s) in Exchange Online" -f $attempt, $pending.Count) -Level Info
            foreach ($s in $pending) {
                $row=$s.Row; $Context.CurrentIdentity=[string](Get-PraValue $row 'ObjectGuid' $s.Upn); $Context.CurrentOperation='CloudCheck'
                try {
                    $s.LastFailure=$null
                    if ($s.CoreDone) { $null=Invoke-PraX500Step -Context $Context -State $s -Fresh $null -MaxReads $x500MaxReads -Final ([bool]$Context.Once); continue }
                    if (-not $s.IdentityChecked) {
                        $Context.CurrentOperation='ConfirmIdentity'
                        if ($s.GraphMailbox -or $s.License) { $s.FactProps=[string[]]@(Get-PraGraphFactProperty -Mailbox $s.GraphMailbox -License $s.License -Addresses ([bool]($null -ne $s.X500 -and $s.GraphMailbox))) }
                        $outcome=Confirm-PraCloudIdentity -Context $Context -State $s
                        $Context.CurrentOperation='CloudCheck'
                        if (Test-PraOrdinalEqual $outcome 'Failed') { $s.Done=$true; if ([bool](Get-PraValue $Context 'GraphRefused' $false)) { $graphStop=$true; break }; continue }
                        if (Test-PraOrdinalEqual $outcome 'Wait') { continue }
                        $s.IdentityChecked=$true
                    }
                    $details=New-Object 'System.Collections.Generic.List[string]'; $plain=New-Object 'System.Collections.Generic.List[string]'; $mbok=$true; $licok=$true; $facts=$null
                    if ($s.GraphMailbox -or $s.License) {
                        $account=Get-PraValue $s 'Account' $null
                        $s.Account=$null
                        $facts=Get-PraGraphFact -Context $Context -Upn $s.Upn -Mailbox $s.GraphMailbox -License $s.License -Addresses ([bool]($null -ne $s.X500 -and $s.GraphMailbox)) -Account $account
                    }
                    if ($s.ExoMailbox) {
                        $m=Invoke-PraExo -Context $Context -Operation 'Mailbox' -Params @{ Upn=$s.Upn; AbsenceConfirms=((Test-PraOrdinalIgnoreCaseEqual $Act 'Recover') -and -not $s.PreserveMailbox) }
                        if ((Test-PraOrdinalIgnoreCaseEqual $Act 'Recover')) {
                            if ($s.PreserveMailbox) {
                                $mbok=(Get-PraValue $m 'Found' $false) -eq $true -and (Test-PraOrdinalIgnoreCaseEqual (Get-PraValue $m 'Type' '') 'SharedMailbox')
                                [void]$details.Add("MBX:KeepCloudShared SharedMailbox present=$mbok; deprovisioning NOT confirmed, tag kept")
                                if (-not $mbok) { [void]$plain.Add('the shared mailbox is not in Exchange Online as a shared mailbox') }
                            } else {
                                $r=Invoke-PraExo -Context $Context -Operation 'Recipient' -Params @{ Upn=$s.Upn }
                                $mbok=(Get-PraValue $m 'Found' $true) -eq $false -and (Get-PraValue $r 'Found' $false) -eq $true -and (Test-PraOrdinalIgnoreCaseEqual (Get-PraValue $r 'Type' '') 'MailUser')
                                [void]$details.Add("MBX:absence=$(-not [bool](Get-PraValue $m 'Found' $true)); recipient=$(Get-PraValue $r 'Type' 'none')")
                                if ($s.GraphMailbox) { [void]$details.Add("Graph:Enabled=$($facts.Enabled),Provisioned=$($facts.Provisioned) (Exchange Online is authoritative, Graph errors stop)") }
                                if (-not $mbok) { [void]$plain.Add($(if ((Get-PraValue $m 'Found' $true) -eq $true) { 'the mailbox still exists in Exchange Online (not deprovisioned yet)' } else { 'the object is not yet a mail user in Exchange Online (the sync has not run)' })) }
                            }
                        } else {
                            $type=[string](Get-PraValue $m 'Type' '')
                            $mbok=if ($s.Shared) { Test-PraOrdinalIgnoreCaseEqual $type 'SharedMailbox' } else { Test-PraOrdinalIgnoreCaseIn $type @('UserMailbox','SharedMailbox','RoomMailbox','EquipmentMailbox') }
                            [void]$details.Add("MBX:EXO type=$type")
                            if (-not $mbok) { [void]$plain.Add($(if (-not $type) { 'no mailbox in Exchange Online yet (the object is still an on-premises mailbox, or the sync has not run)' } elseif ($s.Shared) { "it is a $type in Exchange Online, not a shared mailbox" } else { "it is a $type in Exchange Online, not a mailbox" })) }
                        }
                    } elseif ($s.GraphMailbox) {
                        $mbok=$facts.Provisioned; [void]$details.Add("MBX:Graph provisioning=$mbok; Enabled=$($facts.Enabled) [$($facts.Detail)]")
                        if (-not $mbok) { [void]$plain.Add('the mailbox is not provisioned in Exchange Online yet') }
                    }
                    if ($s.Mailbox) { $row.CloudMailbox=[bool]$mbok }
                    if ($s.License) {
                        $licok=if ((Test-PraOrdinalIgnoreCaseEqual $Act 'Convert') -or $s.PreserveLicense) { $facts.LicenseCount -gt 0 -and $facts.Enabled -and $facts.RequiredSkuOk }
                            elseif ($facts.RequiredSku) { -not $facts.RequiredSkuOk } else { -not $facts.Enabled }
                        $row.CloudLicense=[bool]$licok
                        [void]$details.Add("LIC:OK=$licok; Preserve=$($s.PreserveLicense); ExpectedSKU=$($facts.RequiredSku); SKUPresent=$($facts.RequiredSkuOk); licences=$($facts.LicenseCount); ExchangeEnabled=$($facts.Enabled)")
                        if (-not $licok) {
                            [void]$plain.Add($(if ((Test-PraOrdinalIgnoreCaseEqual $Act 'Convert') -or $s.PreserveLicense) {
                                if ([int]$facts.LicenseCount -le 0) { 'no licence is assigned' }
                                elseif ($facts.RequiredSku -and -not $facts.RequiredSkuOk) { 'the required licence ({0}) is not assigned' -f $facts.RequiredSku }
                                elseif (-not $facts.Enabled) { 'Exchange Online is not enabled in the licence' }
                                else { 'the licence is not in the expected state' }
                            } elseif ($facts.RequiredSku) { 'the licence ({0}) is still assigned' -f $facts.RequiredSku } else { 'Exchange Online is still enabled in the licence' }))
                        }
                    } elseif ($s.Shared) { [void]$details.Add('LIC:N/A (shared)') }
                    $row.CloudDetail=$details -join ' | '; $s.PlainText=$plain -join '; '
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
                } catch {
                    $failure=$_
                    $info=Get-PraCloudFailureInfo $failure
                    if ((Get-PraRetryState $Context).RunExhausted) { $stopRun=$failure; break }
                    if ($failure.Exception.Data['PraGraph'] -eq $true) {
                        # A refusal of Microsoft Graph (no permission, expired sign-in) is the same for every object: ONE error, the objects not finished stay Pending.
                        $refusal=Get-PraGraphRefusal -ErrorRecord $failure -Upn $s.Upn
                        if ($null -ne $refusal) {
                            Write-PraCloudError -Context $Context -Row $row -Message $refusal.Message -Technical $refusal.Technical -RunError
                            $s.Done=$true; $Context.GraphRefused=$true; $graphStop=$true; break
                        }
                    }
                    if ($failure.Exception.Data['PraGrantFailed'] -eq $true) {
                        # The grant step is never repeated in this run (a second Add would need a new approval and new journal lines): the object ends here, a later run reads the permissions first.
                        Write-PraCloudError -Context $Context -Row $row -RunError -Message ('{0}: a shared mailbox permission could not be granted or verified ({1}). It is not granted a second time in this run: run the cloud phase again later, it reads the permissions first and grants only what is missing.' -f $s.Upn, ([string]$failure.Exception.Message -replace '\s+',' ')) -Technical ([string]$failure.Exception.Message)
                        $s.Done=$true; continue
                    }
                    if ($info.Transient -and -not $Context.Once -and $clock.Elapsed.TotalSeconds -lt $timeout) {
                        $s.LastFailure=$failure; $row.CloudStatus='Pending'
                        $s.PlainText='Microsoft 365 could not be read just now ({0}); the read is repeated at the next check' -f $(if ($info.Status) { 'HTTP ' + $info.Status } else { 'no answer' })
                        $null=Write-PraLog -Context $Context -Message ("{0} | cloud read failed, repeated at the next check | {1}" -f $s.Upn, ([string]$failure.Exception.Message -replace '\s+',' ')) -Level Detail
                    }
                    else { Write-PraCloudFailure -Context $Context -Row $row -ErrorRecord $failure -Upn $s.Upn -Extra ([string]$row.PermDetail); $s.Done=$true }
                }
            }
            $Context.CurrentIdentity=''
            if ($null -ne $stopRun -or $graphStop) { break }
            $pending=@($states | Where-Object { -not $_.Done })
            if (-not $pending.Count -or $Context.Once -or $clock.Elapsed.TotalSeconds -ge $timeout) { break }
            $seconds=[Math]::Min([Math]::Max(1,([double]$Context.IntervalMinutes*60)),[Math]::Max(0,($timeout-$clock.Elapsed.TotalSeconds)))
            # A mailbox that is ready and only waits for its X500 addresses is not "not ready": its own message, and the wait is at most two more checks.
            $notReady=@($pending | Where-Object { -not $_.CoreDone })
            # A Check says what it waits for: a mailbox that was never converted (still on-premises) does not reach the expected state, and the wait is long. -Once looks once.
            $checkHint=if ((Test-PraOrdinalIgnoreCaseEqual $Context.Action 'Check')) { ' Waiting for {0}. A mailbox that is still on-premises never gets there without a Convert; with -Once the check looks once and stops.' -f $(if ((Test-PraOrdinalIgnoreCaseEqual $Act 'Recover')) { 'the mailbox to be deprovisioned (a MailUser) in Exchange Online' } else { 'the mailbox to exist in Exchange Online' }) } else { '' }
            $Context.CurrentIdentity=''
            if ($notReady.Count) { Write-PraItem -Context $Context -Status Info -Icon Clock -Text ("Not ready yet: {0} - next check in {1:0} s (waiting up to {2} min in total).{3}" -f ((@($notReady | Select-Object -First 20 | ForEach-Object { $_.Upn }) -join ', ') + $(if ($notReady.Count -gt 20) { ' and {0} more (all of them are in the log)' -f ($notReady.Count - 20) } else { '' })), $seconds, $Context.TimeoutMinutes, $checkHint) }
            foreach ($s in @($pending | Where-Object { $_.CoreDone })) { $Context.CurrentIdentity=[string](Get-PraValue $s.Row 'ObjectGuid' $s.Upn); Write-PraItem -Context $Context -Status Info -Icon Clock -Text ("{0}: mailbox ready; X500 addresses not all visible yet, check {1} of {2} in {3:0} s" -f $s.Upn, ([int]$s.X500Reads + 1), $x500MaxReads, $seconds) }
            $Context.CurrentIdentity=''
            foreach ($s in $pending) { $null=Write-PraLog -Context $Context -Message ("{0} | {1}" -f $s.Upn, $s.Row.CloudDetail) -Level Detail }
            $intervalSeconds=[Math]::Max(1,([double]$Context.IntervalMinutes*60))
            $waitText=if ((Test-PraOrdinalIgnoreCaseEqual $Act 'Recover')) { 'Waiting for Exchange Online to finish deprovisioning' } elseif ((Test-PraOrdinalIgnoreCaseEqual $Act 'Convert')) { 'Waiting for the mailbox and licence to appear in Exchange Online' } else { 'Waiting for Exchange Online' }
            if (@($pending | Where-Object { -not $_.CoreDone }).Count -eq 0) { $waitText='Waiting for the X500 addresses to appear in Exchange Online (Entra Connect synchronisation)' }
            Write-PraProgress -Context $Context -Text ("{0} ({1} object(s) not ready)" -f $waitText,$pending.Count) -Current ([int]$clock.Elapsed.TotalSeconds) -Total ([int]$timeout) -Attempt $attempt -MaxAttempts ([int][Math]::Ceiling($timeout/$intervalSeconds)+1) -NextInSeconds ([int][Math]::Ceiling($seconds))
            if ($seconds -gt 0) { Start-Sleep -Milliseconds ([int][Math]::Min(2147483647,($seconds*1000))) }
        } while ($true)
        $preview=(-not $Context.AllowMutation -and (Test-PraOrdinalIn $Context.Action @('Convert','Recover')))
        if ($graphStop) {
            foreach ($s in @($states | Where-Object { -not $_.Done -and $_.CoreDone })) { $Context.CurrentIdentity=[string](Get-PraValue $s.Row 'ObjectGuid' $s.Upn); Complete-PraX500Check -Context $Context -State $s }
            $Context.CurrentIdentity=''
            $unfinished=@($states | Where-Object { -not $_.Done })
            foreach ($s in $unfinished) {
                $s.Row.CloudStatus='Pending'; $s.Row.FinalStatus='Pending'
                $s.Row.Detail=([string]$s.Row.Detail+' | not finished: Microsoft Graph refused the read, see the error above').Trim(' ','|')
            }
            $null=Write-PraLog -Context $Context -Message ('Microsoft Graph refused a read: {0} object(s) were not finished and nothing more is asked of Microsoft Graph in this run' -f $unfinished.Count) -Level Detail
        }
        elseif ($null -ne $stopRun) {
            foreach ($s in @($states | Where-Object { -not $_.Done -and $_.CoreDone })) { $Context.CurrentIdentity=[string](Get-PraValue $s.Row 'ObjectGuid' $s.Upn); Complete-PraX500Check -Context $Context -State $s }
            $Context.CurrentIdentity=''
            $unfinished=@($states | Where-Object { -not $_.Done })
            foreach ($s in $unfinished) {
                $s.Row.CloudStatus='Pending'; $s.Row.FinalStatus='Pending'
                $s.Row.Detail=([string]$s.Row.Detail+' | not finished: the retry time of the run is used up').Trim(' ','|')
            }
            $Context.CurrentIdentity=''; $Context.CurrentOperation='CloudCheck'
            Write-PraCloudError -Context $Context -Row $null -Message ('{0} {1} object(s) were not finished.' -f $stopRun.Exception.Message, $unfinished.Count) -Technical $(if ($null -ne $stopRun.Exception.InnerException) { [string]$stopRun.Exception.InnerException.Message } else { '' })
        }
        else { foreach ($s in $states) {
            if ($s.Done) { continue }
            $Context.CurrentIdentity=[string](Get-PraValue $s.Row 'ObjectGuid' $s.Upn)
            if ($s.CoreDone) { Complete-PraX500Check -Context $Context -State $s; continue }
            if ($preview) {
                $s.Row.CloudStatus='Pending'; $s.Row.FinalStatus='Planned'; $Context.NotYetExpected=[int]$Context.NotYetExpected+1
                $s.Row.Detail=([string]$s.Row.Detail+' | not yet in the expected state in Exchange Online (preview): '+$s.Row.CloudDetail).Trim(' ','|')
                $null=Write-PraLog -Context $Context -Message ("{0}: not yet in the expected state: {1}" -f $s.Upn, $(if ($s.PlainText) { $s.PlainText } else { 'see the log' })) -Level Info
                $null=Write-PraLog -Context $Context -Message ("{0}: technical detail: {1}" -f $s.Upn, $s.Row.CloudDetail) -Level Detail
            }
            elseif ($null -ne $s.LastFailure) { Write-PraCloudFailure -Context $Context -Row $s.Row -ErrorRecord $s.LastFailure -Upn $s.Upn -Extra ([string]$s.Row.PermDetail) }
            else {
                $because=$(if ($s.PlainText) { $s.PlainText } else { 'see the log' })
                $message=$(if ($Context.Once) { '{0}: not in the expected state: {1}.' -f $s.Upn,$because } else { '{0}: still not in the expected state after waiting {1} min: {2}.' -f $s.Upn,$Context.TimeoutMinutes,$because })
                $Context.CloudNotReached=[int]$Context.CloudNotReached+1
                Write-PraCloudError -Context $Context -Row $s.Row -Message $message -Technical ('Expected state not reached (timeout or -Once): '+$s.Row.CloudDetail)
            }
        }; $Context.CurrentIdentity='' }
    } catch {
        Write-PraUnfinishedFailure -Context $Context -Rows $Rows -ErrorRecord $_ -What 'finished'
    } finally {
        try { Close-PraCloudSession $Context }
        catch { Write-PraSignOutWarning -Context $Context -Message ([string]$_.Exception.Message) }
    }
}

# From this many rows the retention check reads the tagged mailboxes in bulk instead of one by one.
$script:PraRetentionBulkMinimum = 20

function Get-PraRetentionVerdictError {
    <# The exception of a retention check that is an answer about the mailbox, not a failure to ask: Kind is NoMailbox (nothing to retain), PolicyUnknown (the policy is not named, so coverage cannot be told) or NotCovered. #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][ValidateSet('NoMailbox','PolicyUnknown','NotCovered')][string]$Kind,[Parameter(Mandatory)][string]$Message)
    $failure=[System.InvalidOperationException]::new($Message)
    $failure.Data['PraRetention']=$Kind
    return $failure
}

function Resolve-PraRetentionPolicyGuid {
    <# Signs in to Exchange Online and returns the GUID of the retention policy (N format): Retention.PolicyGuid, else the policy found from Retention.PolicyName in an interactive compliance session (Retention.UseComplianceSession). $null when neither is set. #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][hashtable]$Context)
    $cfg=Get-PraValue $Context.Config 'Retention' @{}; $raw=[string](Get-PraValue $cfg 'PolicyGuid' '')
    $guid=$null; $parsed=[guid]::Empty
    if ($raw) {
        if (-not [guid]::TryParse($raw,[ref]$parsed) -or $parsed -eq [guid]::Empty) { throw 'Retention.PolicyGuid is not a GUID.' }
        $guid=$parsed.ToString('N')
    }
    try { Connect-PraCloudSession -Context $Context -NeedGraph (Test-PraIdentityCheck $Context) -NeedExo $true }
    catch { $Context.CloudConnectFailed=$true; throw }
    $cloud=Get-PraValue $Context.Config 'Cloud' @{}; $name=[string](Get-PraValue $cfg 'PolicyName' '')
    if (-not $guid -and $name -and [bool](Get-PraValue $cfg 'UseComplianceSession' $false) -and -not [string](Get-PraValue $cloud 'AppId' '')) {
        $Context.CurrentOperation='ResolveRetentionPolicy'
        $session=Get-PraCloudSession $Context
        if ($session.Subprocess) { throw 'Interactive policy lookup (Connect-IPPSSession) is not possible with the Exchange Online child process.' }
        $beforeIds=@(Get-ConnectionInformation -ErrorAction Stop | ForEach-Object { [string]$_.ConnectionId })
        $session.ExoAttempted=$true
        try { Connect-IPPSSession -ShowBanner:$false -ErrorAction Stop | Out-Null }
        catch { $Context.CloudConnectFailed=$true; throw }
        finally {
            $newIds=@(Get-ConnectionInformation -ErrorAction Stop | ForEach-Object { [string]$_.ConnectionId } | Where-Object { -not (Test-PraOrdinalIgnoreCaseIn $_ $beforeIds) })
            $session.OwnedExoIds=@($session.OwnedExoIds)+$newIds
        }
        try {
            $readPolicy={ param($Identity) Get-RetentionCompliancePolicy -Identity $Identity -ErrorAction Stop }
            $policies=@(Invoke-PraCloudCall -Context $Context -Call 'Get-RetentionCompliancePolicy' -Script $readPolicy -ArgumentList @($name))
            if ($policies.Count -ne 1) { throw 'Retention policy not found or not unique.' }
            $raw=[string](Get-PraValue $policies[0] 'Guid' '')
            if (-not $raw) { $raw=[string](Get-PraValue $policies[0] 'ExchangeObjectId' '') }
            if (-not [guid]::TryParse($raw,[ref]$parsed) -or $parsed -eq [guid]::Empty) { throw 'Retention policy GUID missing or invalid.' }
            $guid=$parsed.ToString('N')
        } finally {
            foreach ($id in $newIds) { Disconnect-ExchangeOnline -ConnectionId $id -Confirm:$false -ErrorAction Stop 6>$null | Out-Null }
        }
    }
    return $guid
}

function Test-PraMailboxGuidKept {
    <# True when the batch left the mailbox GUID on the object (msExchMailboxGuid is still present in the state that the Convert wrote), so that the cloud mailbox carries the recorded GUID. False when the Convert cleared it, and for a record that does not say. #>
    param($Record)
    $planned = Get-PraValue (Get-PraValue $Record 'PlannedAttributes' $null) 'msExchMailboxGuid' $null
    if ($null -eq $planned) { return $false }
    return [bool](Get-PraValue $planned 'Present' $false)
}

function Get-PraRetentionHoldDecision {
    <# The verdict of the retention policy $Guid for one mailbox, from the answer of the Hold read ($Hold): 'Covered' (the row is a success, its detail says so); any other answer is thrown as a verdict (Get-PraRetentionVerdictError). Shared by the read of one mailbox and by the match of a bulk read. #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][hashtable]$Context,[Parameter(Mandatory)]$Row,[Parameter(Mandatory)]$Hold,[AllowNull()][string]$Guid,[string]$HoldUpn,[switch]$Strict)
    $h=$Hold
    $Row.CloudMailbox=[bool](Get-PraValue $h 'Found' $false)
    if ([bool](Get-PraValue $h 'EarlierAccount' $false)) {
        $note=('{0}: not this object''s mailbox. Exchange Online has an inactive mailbox with this UPN, but it belongs to an earlier account (another ExternalDirectoryObjectId than the account confirmed for this object, or another mailbox GUID than the one recorded for it), so its retention does not count for this object. To see it, run: Get-EXOMailbox -InactiveMailboxOnly -Filter "UserPrincipalName -eq ''{1}''" -Properties ExternalDirectoryObjectId,ExchangeGuid,WhenSoftDeleted | Format-List Name,ExternalDirectoryObjectId,ExchangeGuid,WhenSoftDeleted' -f $HoldUpn, $HoldUpn.Replace("'","''"))
        Write-PraItem -Context $Context -Status Warn -Text $note
        $Row.Warnings=([string](Get-PraValue $Row 'Warnings' '') + '; ' + $note).Trim(' ',';')
        throw (Get-PraRetentionVerdictError -Kind NoMailbox -Message 'No mailbox of this object to retain: the only inactive mailbox with this UPN is not this object''s mailbox (it belongs to an earlier account). Retention: Found=False; EarlierAccount=True')
    }
    if ([bool](Get-PraValue $h 'IdentityByUpn' $false)) {
        $note=('{0}: the inactive mailbox is found by its UPN only: its account is deleted, so it cannot be confirmed against Active Directory. Check that it is the mailbox of this object.' -f $HoldUpn)
        Write-PraItem -Context $Context -Status Warn -Text $note
        $Row.Warnings=([string](Get-PraValue $Row 'Warnings' '') + '; ' + $note).Trim(' ',';')
    }
    $holds=Get-PraValue $h 'Holds' @(); $holds=@($holds | Where-Object { $null -ne $_ })
    $included=$false; $excluded=$false; $deleteOnly=$false
    foreach ($hold in $holds) {
        if ([string]$hold -match '^(?<excluded>-)?(?:mbx|grp|skp|UniH)?(?<id>[a-f0-9]{32}|[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12})(?::(?<action>[123]))?\z') {
            if (Test-PraOrdinalIgnoreCaseEqual ($Matches.id -replace '-','') $Guid) {
                if ($Matches.ContainsKey('excluded')) { $excluded=$true }
                elseif ($Matches.ContainsKey('action') -and (Test-PraOrdinalIgnoreCaseEqual $Matches.action '1')) { $deleteOnly=$true }
                else { $included=$true }
            }
        }
    }
    $Row.CloudDetail="Retention: Found=$($Row.CloudMailbox); Inactive=$(Get-PraValue $h 'IsInactive' $false); Litigation=$(Get-PraValue $h 'Litigation' $false); RetentionHold=$(Get-PraValue $h 'RetentionHold' $false); Holds=[$($holds -join ',')]"
    if (-not $Row.CloudMailbox) { throw (Get-PraRetentionVerdictError -Kind NoMailbox -Message ('Mailbox not found (active or inactive). '+$Row.CloudDetail)) }
    if (-not $Guid) { throw (Get-PraRetentionVerdictError -Kind PolicyUnknown -Message ('Policy unknown: set Retention.PolicyGuid (a hold may exist, check it manually). '+$Row.CloudDetail)) }
    if ($excluded -or $deleteOnly -or -not $included) { throw (Get-PraRetentionVerdictError -Kind NotCovered -Message ('Not covered by the policy (or excluded, or delete-only); an adaptive scope can take several days. '+$Row.CloudDetail)) }
    $Row.CloudStatus='Success'; if (-not (Test-PraOrdinalIgnoreCaseEqual $Row.FinalStatus 'Error')) { $Row.FinalStatus='Success' }
    $Row.CloudDetail+=' | COVERED (GUID='+$Guid+')'
    $null=Write-PraLog -Context $Context -Message $Row.CloudDetail -Level $(if ($Strict) { 'Detail' } else { 'Success' })
    return 'Covered'
}

function Test-PraRetentionRow {
    <# Reads the mailbox of one row in Exchange Online and tells whether the retention policy $Guid holds it: 'Covered' (the row is a success, its detail says so) or 'Failed' (an identity check failed and was recorded as an error). Any other answer is thrown: a verdict (Get-PraRetentionVerdictError) or the failure of a call. -Strict: a failed identity check is thrown instead of recorded. -Hold: the answer of a read already made (a bulk read), used instead of a read. -IdentityDone: the account of the row was already confirmed. #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][hashtable]$Context,[Parameter(Mandatory)]$Row,[AllowNull()][string]$Guid,[switch]$Strict,$Hold=$null,[switch]$IdentityDone)
    $holdUpn=[string](Get-PraValue $Row 'UserPrincipalName' '')
    # An inactive mailbox has no account in Microsoft Entra ID any more: it is found by UPN only. An account that exists must be the synchronised one.
    if (-not $IdentityDone -and (Test-PraIdentityCheck $Context)) {
        $identity=Confirm-PraCloudIdentity -Context $Context -State @{ Row=$Row; Upn=$holdUpn; Requests=@(); PlainText='' } -Throw:$Strict
        if (Test-PraOrdinalEqual $identity 'Failed') { return 'Failed' }
    }
    $h=$Hold
    if ($null -eq $h) {
        $holdSource=Get-PraValue $Row 'BackupRec' $null; if ($null -eq $holdSource) { $holdSource=$Row }
        $h=Invoke-PraExo -Context $Context -Operation 'Hold' -Params @{ Upn=$holdUpn; MailboxGuids=[string[]]@(Get-PraRecordedMailboxGuid $holdSource); GuidKept=(Test-PraMailboxGuidKept $holdSource); AbsenceConfirms=$true }
    }
    return (Get-PraRetentionHoldDecision -Context $Context -Row $Row -Hold $h -Guid $Guid -HoldUpn $holdUpn -Strict:$Strict)
}

function Invoke-PraRetentionCheck {
    <#
    .SYNOPSIS
        Checks that the retention policy holds the active or inactive mailboxes (read only, never a deprovisioning confirmation).
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][hashtable]$Context,[Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Rows)
    $Context.CurrentPhase='Retention'; $Context.CurrentOperation='Prepare'; $Context.CurrentIdentity=''; $Context.CloudConnectFailed=$false; $Context.NetworkFailure=$false; $Context.GraphRefused=$false
    try {
        if ($Rows.Count -eq 0) { return }
        $guid=Resolve-PraRetentionPolicyGuid -Context $Context
        $Context.RetentionPolicyGuid=[string]$guid
        $stopRun=$null; $graphStop=$false
        foreach ($row in $Rows) { Add-Member -InputObject $row -NotePropertyName RetentionVerdict -NotePropertyValue 'NotChecked' -Force }
        foreach ($row in $Rows) {
            Add-Member -InputObject $row -NotePropertyName DeprovisionConfirmed -NotePropertyValue $false -Force
            Add-Member -InputObject $row -NotePropertyName RetentionVerdict -NotePropertyValue 'NotChecked' -Force
            $Context.CurrentOperation='VerifyRetention'; $Context.CurrentIdentity=[string](Get-PraValue $row 'ObjectGuid' '')
            $row.CloudMailbox=$null; $row.CloudLicense=$null; $row.CloudStatus='Pending'
            try {
                if (Test-PraOrdinalEqual (Test-PraRetentionRow -Context $Context -Row $row -Guid $guid) 'Failed') {
                    $row.RetentionVerdict='Unverified'
                    if ([bool](Get-PraValue $Context 'GraphRefused' $false)) { $graphStop=$true; break }
                    continue
                }
                $row.RetentionVerdict='Covered'
            } catch {
                $failure=$_
                $verdictKind=[string]$failure.Exception.Data['PraRetention']
                # What the object itself says is its verdict. A row that was read and failed, whatever the failure (not unique, another account, no answer, throttling), is Unverified, also when the loop goes on
                # with the next row; NotChecked is only for the rows that the loop did not reach because it stopped (the retry time of the run, a refusal of Microsoft Graph).
                if (Test-PraOrdinalIn $verdictKind @('NoMailbox','NotCovered')) { $row.RetentionVerdict=$verdictKind }
                else { $row.RetentionVerdict='Unverified' }
                # The retry time of the run is used up: ONE error for the run, the rows not checked stay Pending (never one error per row).
                if ((Get-PraRetryState $Context).RunExhausted) { $stopRun=$failure; break }
                if ($failure.Exception.Data['PraGraph'] -eq $true) {
                    $refusal=Get-PraGraphRefusal -ErrorRecord $failure -Upn ([string](Get-PraValue $row 'UserPrincipalName' ''))
                    if ($null -ne $refusal) {
                        Write-PraCloudError -Context $Context -Row $row -Message $refusal.Message -Technical $refusal.Technical -RunError
                        $Context.GraphRefused=$true; $graphStop=$true; break
                    }
                }
                Write-PraCloudFailure -Context $Context -Row $row -ErrorRecord $failure -Upn ([string](Get-PraValue $row 'UserPrincipalName' '')) -Expectation
            }
        }
        if ($graphStop) {
            $notChecked=@($Rows | Where-Object { -not (Test-PraOrdinalIn ([string](Get-PraValue $_ 'CloudStatus' '')) @('Success','Error')) })
            foreach ($row in $notChecked) { $row.CloudStatus='Pending'; $row.FinalStatus='Pending'; $row.Detail=([string](Get-PraValue $row 'Detail' '')+' | not checked: Microsoft Graph refused the read, see the error above').Trim(' ','|') }
            $null=Write-PraLog -Context $Context -Message ('Microsoft Graph refused a read: {0} object(s) were not checked and nothing more is asked of Microsoft Graph in this run' -f $notChecked.Count) -Level Detail
        }
        elseif ($null -ne $stopRun) {
            $notChecked=@($Rows | Where-Object { -not (Test-PraOrdinalIn ([string](Get-PraValue $_ 'CloudStatus' '')) @('Success','Error')) })
            foreach ($row in $notChecked) { $row.CloudStatus='Pending'; $row.FinalStatus='Pending'; $row.Detail=([string](Get-PraValue $row 'Detail' '')+' | not checked: the retry time of the run is used up').Trim(' ','|') }
            $Context.CurrentIdentity=''; $Context.CurrentOperation='VerifyRetention'
            Write-PraCloudError -Context $Context -Row $null -Message ('{0} {1} object(s) were not checked.' -f $stopRun.Exception.Message, $notChecked.Count) -Technical $(if ($null -ne $stopRun.Exception.InnerException) { [string]$stopRun.Exception.InnerException.Message } else { '' })
        }
    } catch {
        Write-PraUnfinishedFailure -Context $Context -Rows $Rows -ErrorRecord $_ -What 'checked'
    } finally {
        try { Close-PraCloudSession $Context }
        catch { Write-PraSignOutWarning -Context $Context -Message ([string]$_.Exception.Message) }
    }
}

function Get-PraRetentionFailureReason {
    <# The plain reason why one retention read failed, and whether the same failure will stop every other read (the retry time of the run, a refusal of Microsoft Graph, no answer, throttling). #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][hashtable]$Context,[Parameter(Mandatory)]$ErrorRecord,[string]$Upn='')
    $prefix=$(if ($Upn) { $Upn + ': ' } else { '' })
    $raw=[string]$ErrorRecord.Exception.Message
    if ((Get-PraRetryState $Context).RunExhausted -or $ErrorRecord.Exception.Data['PraRunBudget'] -eq $true) { return [pscustomobject]@{ Reason=$raw; Stops=$true; Technical=$(if ($null -ne $ErrorRecord.Exception.InnerException) { [string]$ErrorRecord.Exception.InnerException.Message } else { '' }) } }
    if ($ErrorRecord.Exception.Data['PraGraph'] -eq $true) {
        $refusal=Get-PraGraphRefusal -ErrorRecord $ErrorRecord -Upn $Upn
        if ($null -ne $refusal) { return [pscustomobject]@{ Reason=$refusal.Message; Stops=$true; Technical=$refusal.Technical } }
    }
    $network=Get-PraNetworkFailure $ErrorRecord
    if ($null -ne $network) { return [pscustomobject]@{ Reason=('{0}Microsoft 365 did not answer (network){1}.' -f $prefix, $(if ($network.Host) { ': ' + $network.Host } else { '' })); Stops=$true; Technical=$raw } }
    $info=Get-PraCloudFailureInfo $ErrorRecord
    if ($info.Throttled) { return [pscustomobject]@{ Reason=('{0}Microsoft 365 limited the requests or was unavailable (HTTP {1}).' -f $prefix, $info.Status); Stops=$true; Technical=$raw } }
    return [pscustomobject]@{ Reason=($prefix + $raw); Stops=$false; Technical='' }
}

function Test-PraRetentionCoverage {
    <#
    .SYNOPSIS
        Before a Recover removes the cloud mailboxes: for each row, tells whether the retention policy holds the mailbox (read only, within the retry budgets of this check).
    .DESCRIPTION
        Never records an error of the run. A mailbox that the policy does not hold is in NotCovered; a mailbox that could not be read, or whose policy is not named, is in Unverified (the rest are Unverified too once a
        failure would stop every other read). A row without a mailbox in Exchange Online has nothing to retain (NoMailbox, listed in NoMailboxList). The rows of the caller are not changed.
        With 20 rows or more, the active mailboxes that carry the retention tag are read in bulk (a server-side filter on the tag and on about 50 UPNs at a time, so 100 searches for 5,000 objects) and each row is
        matched in memory by its confirmed account, else by its UPN; a row that this does not settle with exactly one tagged active mailbox (none, several, an inactive mailbox) is read on its own, whose rules decide.
        No bulk read is made once a failure has stopped the reads. Microsoft Entra ID accounts are confirmed one by one (kept for the cloud part that follows).
        The check has its own retry budget: what it spends is not taken from the budget of the cloud part.
        -CloseSession signs out of the sessions that this check opened; without it the session stays open for the cloud part that follows.
    .OUTPUTS
        Checked, Covered, NoMailbox, NoMailboxList, NotCovered and Unverified (each entry: ObjectGuid, Upn, Reason), StopReason, SignInFailed and SignInMessage (the sign-in failed: told by the caller, never left as the failure of the run), PolicyGuid, BulkCalls, Searches (bulk searches of Exchange Online), BulkResolved, SingleReads and
        CouldNotAsk: true only when Exchange Online could not be reached or asked (the sign-in failed, no answer, throttling, the policy not named) and every row that is not covered is Unverified with that one reason of the run;
        any answer about one object (a mailbox not held, another account, not unique, an ambiguity) leaves it false.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][hashtable]$Context,[Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Rows,[switch]$CloseSession)
    $result=[pscustomobject]@{ Checked=0; Covered=0; NoMailbox=0; NoMailboxList=(New-Object 'Collections.Generic.List[object]'); NotCovered=(New-Object 'Collections.Generic.List[object]'); Unverified=(New-Object 'Collections.Generic.List[object]'); StopReason=''; CouldNotAsk=$false; SignInFailed=$false; SignInMessage=''; PolicyGuid=''; BulkCalls=0; Searches=0; BulkResolved=0; SingleReads=0 }
    $flags=@{ Reach=$false }
    $connectFailedBefore=[bool](Get-PraValue $Context 'CloudConnectFailed' $false)
    $Context.CurrentOperation='VerifyRetention'; $Context.CurrentIdentity=''; $Context.CloudConnectFailed=$false
    $addEntry={ param($List,$Row,[string]$Reason) $List.Add([pscustomobject]@{ ObjectGuid=[string](Get-PraValue $Row 'ObjectGuid' ''); Upn=[string](Get-PraValue $Row 'UserPrincipalName' ''); Reason=$Reason }) }
    $finish={
        $result.NotCovered=[object[]]$result.NotCovered.ToArray(); $result.Unverified=[object[]]$result.Unverified.ToArray(); $result.NoMailboxList=[object[]]$result.NoMailboxList.ToArray()
        $rowSpecific=@($result.Unverified | Where-Object { -not (Test-PraOrdinalEqual ([string]$_.Reason) $result.StopReason) }).Count
        $result.CouldNotAsk=($flags.Reach -and $result.NotCovered.Count -eq 0 -and $rowSpecific -eq 0)
        $result
    }
    $hadRetry=$Context.ContainsKey('_PraRetry'); $savedRetry=$null
    if ($hadRetry) { $savedRetry=$Context['_PraRetry']; [void]$Context.Remove('_PraRetry') }
    try {
        if ($Rows.Count -eq 0) { return (& $finish) }
        $cfg=Get-PraValue $Context.Config 'Retention' @{}; $cloud=Get-PraValue $Context.Config 'Cloud' @{}
        $named=[bool][string](Get-PraValue $cfg 'PolicyGuid' '') -or ([bool][string](Get-PraValue $cfg 'PolicyName' '') -and [bool](Get-PraValue $cfg 'UseComplianceSession' $false) -and -not [string](Get-PraValue $cloud 'AppId' ''))
        if (-not $named) {
            $result.StopReason='Retention.PolicyGuid is not set in the configuration file (and the policy cannot be found from its name), so the retention policy of the mailboxes cannot be told.'
            $flags.Reach=$true
            foreach ($row in $Rows) { & $addEntry $result.Unverified $row $result.StopReason }
            return (& $finish)
        }
        $guid=$null
        try { $guid=Resolve-PraRetentionPolicyGuid -Context $Context }
        catch {
            $failed=Get-PraRetentionFailureReason -Context $Context -ErrorRecord $_
            if ($failed.Technical) { $null=Write-PraLog -Context $Context -Message ('Technical detail: {0}' -f $failed.Technical) -Level Detail }
            $result.StopReason=$failed.Reason; $result.SignInFailed=[bool](Get-PraValue $Context 'CloudConnectFailed' $false); if ($result.SignInFailed) { $result.SignInMessage=$failed.Reason }
            $flags.Reach=([bool]$failed.Stops -or $result.SignInFailed)
            foreach ($row in $Rows) { & $addEntry $result.Unverified $row $result.StopReason }
            return (& $finish)
        }
        $result.PolicyGuid=[string]$guid
        # What a failed read says: a verdict about the mailbox, or a failure that concerns the one mailbox, or one that stops every other read.
        $classify={
            param($Failure,$Row,[string]$Upn)
            $kind=[string]$Failure.Exception.Data['PraRetention']
            if (Test-PraOrdinalEqual $kind 'NoMailbox') {
                $result.NoMailbox++; $result.NoMailboxList.Add([pscustomobject]@{ ObjectGuid=[string](Get-PraValue $Row 'ObjectGuid' ''); Upn=$Upn; Reason=[string]$Failure.Exception.Message })
                $null=Write-PraLog -Context $Context -Message ('{0}: no mailbox to retain in Exchange Online: {1}' -f $Upn, $Failure.Exception.Message) -Level Detail
            }
            elseif (Test-PraOrdinalEqual $kind 'NotCovered') { & $addEntry $result.NotCovered $Row $Failure.Exception.Message }
            elseif (Test-PraOrdinalEqual $kind 'PolicyUnknown') { & $addEntry $result.Unverified $Row $Failure.Exception.Message }
            else {
                $failed=Get-PraRetentionFailureReason -Context $Context -ErrorRecord $Failure -Upn $Upn
                if ($failed.Technical) { $null=Write-PraLog -Context $Context -Message ('Technical detail: {0}' -f $failed.Technical) -Level Detail }
                & $addEntry $result.Unverified $Row $failed.Reason
                if ($failed.Stops) { $result.StopReason=$failed.Reason; $flags.Reach=$true }
            }
        }
        $identityOn=Test-PraIdentityCheck $Context
        $work=New-Object 'Collections.Generic.List[object]'
        foreach ($row in $Rows) {
            if ($result.StopReason) { & $addEntry $result.Unverified $row $result.StopReason; continue }
            $objectGuid=[string](Get-PraValue $row 'ObjectGuid' ''); $upn=[string](Get-PraValue $row 'UserPrincipalName' '')
            $Context.CurrentOperation='VerifyRetention'; $Context.CurrentIdentity=$objectGuid
            $source=Get-PraValue $row 'BackupRec' $null; if ($null -eq $source) { $source=$row }
            $shadow=[pscustomobject]@{ ObjectGuid=$objectGuid; UserPrincipalName=$upn; BackupRec=$source; CloudMailbox=$null; CloudLicense=$null; CloudStatus='Pending'; CloudDetail=''; FinalStatus='Planned'; Warnings=''; Detail='' }
            $result.Checked++
            if ($identityOn) {
                try { $null=Confirm-PraCloudIdentity -Context $Context -State @{ Row=$shadow; Upn=$upn; Requests=@(); PlainText='' } -Throw }
                catch { & $classify $_ $row $upn; continue }
            }
            $work.Add([pscustomobject]@{ Row=$row; Shadow=$shadow; Upn=$upn; Source=$source; Hold=$null })
        }
        $byKey=$null
        if ($work.Count -ge $script:PraRetentionBulkMinimum -and -not $result.StopReason) {
            $groups=New-Object 'Collections.Generic.Dictionary[string,object]' -ArgumentList ([StringComparer]::OrdinalIgnoreCase)
            $verified=if ($identityOn) { (Get-PraCloudSession $Context).Verified } else { @{} }
            for ($index=0; $index -lt $work.Count; $index++) {
                $entry=$work[$index]
                $tag=Get-PraValue $entry.Source 'Retention' $null
                $attribute=[string](Get-PraValue $tag 'Attribute' ''); $value=[string](Get-PraValue $tag 'Value' '')
                if ($attribute -notmatch '\AextensionAttribute(?<n>[1-9]|1[0-5])\z' -or -not $value) { continue }
                $custom='CustomAttribute'+$Matches.n
                $groupKey=$custom+'='+$value
                if (-not $groups.ContainsKey($groupKey)) { $groups[$groupKey]=@{ Attribute=$custom; Value=$value; Rows=(New-Object 'Collections.Generic.List[object]') } }
                $confirmed=''; if ($identityOn -and $verified.ContainsKey($entry.Upn)) { $confirmed=[string]$verified[$entry.Upn] }
                $groups[$groupKey].Rows.Add(@{ Key=[string]$index; Upn=$entry.Upn; ById=$confirmed })
            }
            if ($groups.Count) {
                $Context.CurrentOperation='VerifyRetention'; $Context.CurrentIdentity=''
                try {
                    $request=@(foreach ($group in $groups.Values) { @{ Attribute=$group.Attribute; Value=$group.Value; Rows=$group.Rows.ToArray() } })
                    $bulk=Invoke-PraExo -Context $Context -Operation 'HoldBulk' -Params @{ Groups=$request }
                    $result.BulkCalls++; $result.Searches=[int](Get-PraValue $bulk 'Searches' 0)
                    $byKey=New-Object 'Collections.Generic.Dictionary[string,object]' -ArgumentList ([StringComparer]::Ordinal)
                    $answers=Get-PraValue $bulk 'Results' @()
                    foreach ($answered in @($answers)) { $byKey[[string](Get-PraValue $answered 'Key' '')]=$answered }
                    $null=Write-PraLog -Context $Context -Message ('Retention read in bulk: {0} tagged active mailbox(es) found in {1} search(es); {2} of the {3} object(s) settled by them{4}' -f (Get-PraValue $bulk 'ActiveCount' 0), $result.Searches, $byKey.Count, $work.Count, $(if ([int](Get-PraValue $bulk 'ChunkFailures' 0)) { '; ' + (Get-PraValue $bulk 'ChunkFailures' 0) + ' search(es) failed and their objects are read one by one' + $(if ([bool](Get-PraValue $bulk 'Stopped' $false)) { ' (the bulk read stopped after two searches in a row failed: the objects not searched are read one by one too)' } else { '' }) } else { '' })) -Level Detail
                }
                catch {
                    $failure=$_
                    $failed=Get-PraRetentionFailureReason -Context $Context -ErrorRecord $failure
                    if ($failed.Technical) { $null=Write-PraLog -Context $Context -Message ('Technical detail: {0}' -f $failed.Technical) -Level Detail }
                    $null=Write-PraLog -Context $Context -Message ('The bulk read of the mailboxes that carry the retention tag failed ({0}): they are read one by one' -f ($failed.Reason -replace '\s+',' ')) -Level Detail
                    if ($failed.Stops) { $result.StopReason=$failed.Reason; $flags.Reach=$true }
                    $byKey=$null
                }
            }
        }
        for ($index=0; $index -lt $work.Count; $index++) {
            $entry=$work[$index]
            $answered=$null
            if ($null -ne $byKey -and $byKey.TryGetValue([string]$index,[ref]$answered)) { $entry.Hold=$answered }
            elseif ($result.StopReason) { & $addEntry $result.Unverified $entry.Row $result.StopReason; continue }
            $Context.CurrentOperation='VerifyRetention'; $Context.CurrentIdentity=[string]$entry.Shadow.ObjectGuid
            if ($null -ne $entry.Hold) { $result.BulkResolved++ } else { $result.SingleReads++ }
            try { $null=Test-PraRetentionRow -Context $Context -Row $entry.Shadow -Guid $guid -Strict -IdentityDone -Hold $entry.Hold; $result.Covered++ }
            catch { & $classify $_ $entry.Row $entry.Upn }
        }
        return (& $finish)
    } finally {
        $Context.CurrentIdentity=''; $Context.CloudConnectFailed=$connectFailedBefore
        if ($hadRetry) { $Context['_PraRetry']=$savedRetry } else { [void]$Context.Remove('_PraRetry') }
        if ($CloseSession) {
            try { Close-PraCloudSession $Context }
            catch { Write-PraSignOutWarning -Context $Context -Message ([string]$_.Exception.Message) }
        }
    }
}

Export-ModuleMember -Function Initialize-PraCloudPreflight,Invoke-PraCloudPhase,Invoke-PraRetentionCheck,Test-PraRetentionCoverage,Close-PraCloudSession

# SIG # Begin signature block
# MIImKQYJKoZIhvcNAQcCoIImGjCCJhYCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCC4Rg/xj6zkn2FZ
# W/vvuviAqZPbvC5ADXd2nQZWZgDdlKCCDW8wggZyMIIEWqADAgECAghkM1HTxzif
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
# AQQBgjcCAQsxDjAMBgorBgEEAYI3AgEVMC8GCSqGSIb3DQEJBDEiBCB5Ae/1VGfm
# WUniBtBz8sl5TxPQ2wYCgZ4KsBZlEkZdezANBgkqhkiG9w0BAQEFAASCAgCPuZKa
# nRkgmJEpvPWYEGQhhPKRokH3K4fXt6ckFEfVnTlovO775z8yGfU+jlo6kTRJaHH9
# EBr9Pz9xvb2KvySk2jeQbQoRfN0KEppF7x9QBvOCmncSVX2BX38h9+aEl6Pn8kd8
# RuDtRU7+9nCNP51sCYxC5dRUwkbmX14p4rlkmgc40qxH1mQUh/6WzDNiVdPAHRsS
# xT1g/VPcz9zBirSMxKpMnYNMh10NQnyAb6s0tf4FIkrHAm/88n81POOvv/NmCqGR
# PZN8IN/7TmBdhty1B2NM6X2PU/gz96qasnabMCNnXToPYFZ0AR0w3W/hB3zLo4yG
# 3yKs586BE8yBPlSwzF2XmMEn0qUrDhNkn5CL0It/tLUAai9RpyMwnoNyqaYlcbEy
# pD2mcI61ks91QJxWWoadHX/ty2kZ8DkHm3dNCMwJnC01HlJa/jjkfi9NFo/P9Lu2
# y19lNOYth7u8982SUvq8XIOAuXc9BT2nxo3YQUEBGVW8CxriPfcA86ovtMmWXXCN
# Ma6Lu0yoQDWnuP5DJRlvi4nmccQyoj++XQ/odoGXRQBnf/dehVz1n+qk5QKsK4NG
# 1FqJ2Ihbi1guUCXrC0GzSLOvYitLe4U77Rb65n7va2GuDSYpTfuIxdiutUU0AaPU
# PA4nIfg6mWXPm/kumMtIDavT9rfTEkND3YTYKKGCFM0wghTJBgorBgEEAYI3AwMB
# MYIUuTCCFLUGCSqGSIb3DQEHAqCCFKYwghSiAgEDMQ0wCwYJYIZIAWUDBAIBMIGJ
# BgsqhkiG9w0BCRABBKB6BHgwdgIBAQYMKwYBBAGCqTABAwYBMDEwDQYJYIZIAWUD
# BAIBBQAEIIjIssPZB2hQ+6MBgxc9zh0GhU7kzKwesJqvoodrLo3hAghMKXh9OGDr
# +hgPMjAyNjExMTMxMjEyNDJaMAMCAQECEFEHqQEf7GUqnMJstYwCs7WgghGnMIIE
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
# AQkQAQQwHAYJKoZIhvcNAQkFMQ8XDTI2MTExMzEyMTI0MlowKAYJKoZIhvcNAQk0
# MRswGTALBglghkgBZQMEAgGhCgYIKoZIzj0EAwIwLwYJKoZIhvcNAQkEMSIEIJGJ
# kW5oGtwnxOhyA4T22lBCirRwxgbJkULMgMUN5yNIMIHIBgsqhkiG9w0BCRACLzGB
# uDCBtTCBsjCBrwQgV0/qF6r6XnxqK5sIyZixc15FCzhzykTmokygkw5j87AwgYow
# dqR0MHIxCzAJBgNVBAYTAlVTMQ4wDAYDVQQIDAVUZXhhczEQMA4GA1UEBwwHSG91
# c3RvbjERMA8GA1UECgwIU1NMIENvcnAxLjAsBgNVBAMMJVNTTC5jb20gVGltZXN0
# YW1waW5nIElzc3VpbmcgUlNBIENBIDICEFRD+De9Wu4YAYRyuFzajuMwCgYIKoZI
# zj0EAwIERjBEAiAc3yUiws97caRGY9gagaQ+ljFnIHc8ovBs7vx2hu7ynQIgKC+D
# 5LrdU7TMN+MCV/KRS7lPLwUKW6A3hZKvpiGwYcE=
# SIG # End signature block
