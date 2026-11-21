#
#  PRA Remote Mailbox - configuration file
#  --------------------------------------------------------------------------
#  Author  : Nicolas Fabert
#  Version : 3.1.4
#
#  This file is read by Invoke-PraRemoteMailbox.ps1. It is a PowerShell data
#  file: text between quotes, $true / $false, numbers, and @( ) for lists.
#  Lines starting with # are comments. An unknown setting is refused
#  (spelling mistakes are detected).
#
#  Relative paths (.\Backups, .\logs ...) are relative to the tool folder. Inside the tool folder only
#  .\Backups, .\logs and .\reports are accepted for BackupFolder, Logging.Folder and Report.Folder (the signed
#  package must not receive other files); use a folder outside the tool folder for anything else.
#  Everything is set here; the command line only chooses the action
#  (see docs\PraRemoteMailbox-Guide.md, chapter 6).
#
#  Two-server setup: the AD server and the cloud server each have their copy
#  of this file, with the SAME Environment (a batch is only accepted by a
#  configuration of the same Environment).
#
@{
    # Label of this environment, used in the backup file names (letters, digits, - _ .).
    Environment      = 'PROD'

    # Domain controller used for EVERY read and write of a run (writable DC).
    # Recommended: always the same DC (the AD versions uSNChanged are per DC). '' = discovered.
    DomainController = ''

    # ---------------------------------------------------------------------
    # Which mailboxes are converted (Convert without -Identity).
    #   Auto  : every on-premises mailbox (homeMDB set) under SearchBase ('' = whole domain)
    #   OU    : every on-premises mailbox under SearchBase (SearchBase required)
    #   Group : members of GroupDN (recursive)
    #   Csv   : the objects listed in CsvPath (column Identity = UPN, sAMAccountName, DN or GUID)
    # System mailboxes (HealthMailbox*, SystemMailbox*, Microsoft Exchange*) are always excluded.
    # ---------------------------------------------------------------------
    Scope = @{
        Mode                   = 'OU'
        SearchBase             = ''
        GroupDN                = ''
        CsvPath                = ''             # e.g. '.\config\Targets.csv' (see Targets.sample.csv)
        IncludeShared          = $true          # shared mailboxes (msExchRecipientTypeDetails 4)
        IncludeRoom            = $false         # room mailboxes (16)
        IncludeEquip           = $false         # equipment mailboxes (32)
        ExcludeSamAccountNames = @()            # sAMAccountName never converted
    }

    # ---------------------------------------------------------------------
    # User mailboxes -> RemoteUserMailbox.
    # ---------------------------------------------------------------------
    Remote = @{
        RecipientType    = 1        # msExchRemoteRecipientType: 1 = provision a new cloud mailbox
        HandleArchives   = $true    # + 2 (archive) when the user has an on-premises archive
        ClearMailboxGuid = $true    # clear msExchMailboxGuid (a new, empty cloud mailbox is created)
    }

    # targetAddress of the remote mailbox: <alias>@RoutingDomain, or the existing proxy address in
    # this domain when AutoDetect finds one.
    Routing = @{
        AutoDetect    = $true
        RoutingDomain = ''
    }

    # Group-based licensing: users are added to this AD group (synchronised to Entra ID, it carries
    # the Exchange Online licence). Recover removes them again (unless they were already members).
    Licensing = @{
        Enabled = $true
        GroupDN = ''
    }

    # ---------------------------------------------------------------------
    # Shared mailboxes -> RemoteSharedMailbox (never licensed). Used when Scope.IncludeShared = $true.
    # ---------------------------------------------------------------------
    SharedMailbox = @{
        Enabled             = $true
        RemoteRecipientType = 97             # 97 = first provisioning of a shared mailbox; 99 = with archive
        # Where the FullAccess / SendAs holders are read (Exchange on-premises is not needed):
        #   AD              : ACEs of the shared mailbox object (FullAccess in msExchMailboxSecurityDescriptor,
        #                     SendAs in nTSecurityDescriptor); groups are expanded to their members
        #   Csv             : CsvPath, columns Shared,Group: the members of Group get FullAccess + SendAs
        #   CustomAttribute : the AD group whose <CustomAttribute> = name of the shared mailbox
        #   None            : FullAccess / SendAs not reproduced
        PermissionSource    = 'AD'
        CsvPath             = ''             # PermissionSource = Csv (see SharedPermissions.sample.csv)
        CustomAttribute     = 'extensionAttribute1'
        CaptureSendOnBehalf = $true          # SendOnBehalf from publicDelegates (any PermissionSource)
        GrantFullAccess     = $true          # grant the permissions in Exchange Online (Convert)
        GrantSendAs         = $true
        GrantSendOnBehalf   = $true
        AutoMapping         = $true          # FullAccess: the shared mailbox appears in Outlook
        # Accounts never reproduced as trustees (on top of SELF, SYSTEM and the admin groups).
        ExcludeTrusteeSamAccountNames = @('Administrator')
        # Recover: the cloud shared mailbox is deprovisioned before its on-premises attributes come
        # back (default). $true = keep the cloud shared mailbox (rare).
        KeepCloudSharedOnRecover = $false
        # Recover -Phase Cloud always writes a Finalize package; it never restores AD.
        # With -Phase Both, $true also defers final AD restoration to a separate Finalize run
        # (automatic when the ActiveDirectory module is not on this server).
        DeferOnPremRestore  = $false
    }

    # ---------------------------------------------------------------------
    # Optional forced Active Directory replication, before the Entra Connect synchronisation.
    #   ForceReplication = $true : each object changed in the run is pushed from the domain controller that was written to the other
    #                  writable domain controllers (Sync-ADObject), then read back there. A domain controller that does not confirm
    #                  is a warning that names it (the synchronisation still runs). Needs the right to replicate a single object
    #                  (normally Domain Admins). OFF by default; -ForceAdReplication or the checkbox of the window turn it on for one run.
    #   ReplicationTargets : optional list of domain controllers to restrict it to (for example the ones the Entra Connect connector reads);
    #                  empty = every other writable domain controller of the domain.
    # ---------------------------------------------------------------------
    Directory = @{
        ForceReplication              = $false
        ReplicationTargets            = @()
        ReplicationVerifyAttempts     = 6
        ReplicationVerifyDelaySeconds = 10
    }

    # ---------------------------------------------------------------------
    # Entra Connect synchronisation after the AD changes (Apply).
    #   Sync = $true : one cycle is run and the tool waits for its end before the cloud part.
    #                  On this server (ADSync module) or on Server through PowerShell remoting.
    #                  Checked before any AD change.
    #   Sync = $false: the operator runs it (Start-ADSyncSyncCycle -PolicyType Delta).
    # ---------------------------------------------------------------------
    EntraConnect = @{
        Sync           = $true
        Server         = ''    # '' = this server
        PolicyType     = 'Delta'
        TimeoutMinutes = 15
    }

    # ---------------------------------------------------------------------
    # Microsoft 365 tenant and sign-in (cloud part).
    #   Interactive : AppId and CertificateThumbprint empty; the administrator signs in
    #                 (UserPrincipalName = expected account, '' = any).
    #   Certificate : AppId + CertificateThumbprint of an app registration (unattended runs,
    #                 see the guide, annex C).
    # ---------------------------------------------------------------------
    Cloud = @{
        TenantId              = ''
        Organization          = ''
        AppId                 = ''
        CertificateThumbprint = ''
        UserPrincipalName     = ''
        CheckMailbox          = $true        # wait for the mailbox (Convert) / its removal (Recover)
        CheckLicense          = $true        # wait for a licence with Exchange enabled (users)
        MailboxCheckVia       = 'Exo'        # Exo (mailbox type in Exchange Online) or Graph (provisioning)
        RequiredSkuPartNumber = ''           # '' = any licence with Exchange; e.g. 'SPE_E3'
        IdentityCheck         = 'Anchor'     # Anchor = the Entra ID account must carry the AD source anchor (objectGUID or ms-DS-ConsistencyGuid); Off = accounts are found by UPN only
        RetryBudgetObjectSeconds = 180       # most seconds one object waits in retries of throttled or unreachable cloud calls (0 = no retry)
        RetryBudgetRunMinutes    = 30        # most minutes the whole run waits in retries; used up, the run stops cleanly (0 = no retry)
    }

    # Exchange Online module.
    Exo = @{
        MinModuleVersion        = '3.10.1'   # the module must be at least this version (the tool stops before any change otherwise)
        UseSubprocess           = $false     # $true = every Exchange Online call in a child PowerShell
        DisableWAM              = $false     # $false (default) = interactive sign-in through the Windows broker (WAM); $true = browser sign-in instead
        GrantVerifyAttempts     = 13         # re-reads after ONE grant (never retried)
        GrantVerifyDelaySeconds = 10
    }

    # How long the cloud part waits (Entra Connect + Exchange Online provisioning can take 15-60 min).
    Polling = @{
        IntervalMinutes = 1
        TimeoutMinutes  = 60
    }

    # ---------------------------------------------------------------------
    # Retention tag: written at Convert so that an adaptive scope of a Purview retention policy
    # keeps the old mailbox (extensionAttributeN on-premises = CustomAttributeN in Exchange Online).
    # Recover restores the original value. PolicyGuid is used by -Action Check -Expect Retained and by the
    # retention check that comes before a Recover.
    #   CheckBeforeRecover = $true : before it removes the cloud mailboxes, a Recover (Preview and Apply, AD part) reads each mailbox that
    #                  carries the retention tag and checks that the retention policy holds it. The Apply STOPS, before any change, when a
    #                  mailbox is not covered or cannot be checked (for instance PolicyGuid is empty); the Preview says so and the Apply
    #                  is then refused. -AcceptRetentionRisk (a checkbox in the window) goes on for ONE run: the run says so in a warning.
    #   CheckBeforeRecover = $false: the check is off for every run. Each Recover says so once, in a warning; it never claims the check passed.
    #   ProofMaxAgeHours   : two-server setup. The AD server often cannot ask Exchange Online. A Check -Expect Retained -Batch <id> on the cloud
    #                  server writes a retention proof (RetentionProof-...json and its .sha256 file, in its Backups\Outbox folder). Copied to the
    #                  Backups\Inbox folder of the AD server, it stands in for the check of a Recover (phase AD) when it is intact, of this batch
    #                  and Environment, not older than this many hours (1 to 720), and covers every object of the Recover. Where Exchange Online
    #                  can be asked (phase Both, a certificate sign-in, or an interactive console) its answer decides and the proof is read only
    #                  when Exchange Online cannot be reached. The hours are the setting of the server that reads the proof (the AD server).
    #                  The proof must also be of the same Convert batch file and, when PolicyGuid is set here, of that policy. Only the NEWEST
    #                  proof of the batch counts; an older proof never completes it. Without PolicyGuid here the proof is accepted and the run prints
    #                  the policy GUID the proof names.
    # ---------------------------------------------------------------------
    Retention = @{
        Enabled              = $true
        PolicyName           = 'PRA-Converted-Retention'
        PolicyGuid           = ''            # (Get-RetentionCompliancePolicy '<name>').Guid
        UseComplianceSession = $false        # find the GUID from PolicyName (interactive Connect-IPPSSession)
        CheckBeforeRecover   = $true         # $false = no retention check before a Recover
        ProofMaxAgeHours     = 24            # age limit of a retention proof from the cloud server (1 to 720 hours)
        Tag = @{
            Enabled   = $true
            Attribute = 'extensionAttribute1'
            Value     = 'Converted'
        }
    }

    # Default phase when -Phase is not given: Both (one server does AD + cloud), AD or Cloud.
    Execution = @{
        Phase = 'Both'
    }

    # ---------------------------------------------------------------------
    # Files. Backups hold AD attribute values: keep them on a durable, protected volume and copy
    # them outside the server. Each batch is a private folder Backups\Batch-<id>.
    # ---------------------------------------------------------------------
    Storage = @{
        BackupFolder         = '.\Backups'
        ForbiddenBackupRoots = @()           # volumes where backups are refused (e.g. temporary disks 'D:\')
    }
    Logging = @{
        Folder = '.\logs'                    # one log + one transcript per run
    }
    Report = @{
        Enabled = $true                      # CSV + HTML report of each run
        Folder  = '.\reports'
    }
}
