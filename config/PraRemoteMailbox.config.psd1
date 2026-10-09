#
#  PRA Remote Mailbox - configuration file
#  --------------------------------------------------------------------------
#  Author  : Nicolas Fabert
#  Version : 2.1.0
#
#  This file is read by Invoke-PraRemoteMailbox.ps1. It is a PowerShell data
#  file: text between quotes, $true / $false, numbers, and @( ) for lists.
#  Lines starting with # are comments. An unknown setting is refused
#  (spelling mistakes are detected).
#
#  Relative paths (.\Backups, .\logs ...) are relative to the tool folder.
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
    # Entra Connect synchronisation after the AD changes (Apply).
    #   Sync = $true : one cycle is run and the tool waits for its end before the cloud part.
    #                  On this server (ADSync module) or on Server through PowerShell remoting.
    #                  Checked BEFORE any AD change.
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
    }

    # Exchange Online module.
    Exo = @{
        MinModuleVersion        = '3.10.0'   # older = child process isolation (certificate sign-in only)
        UseSubprocess           = $false     # $true = every Exchange Online call in a child PowerShell
        DisableWAM              = $true      # interactive sign-in in the browser instead of the Windows broker
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
    # Recover restores the original value. PolicyGuid is only used by -Action Check -Expect Retained.
    # ---------------------------------------------------------------------
    Retention = @{
        Enabled              = $true
        PolicyName           = 'PRA-Converted-Retention'
        PolicyGuid           = ''            # (Get-RetentionCompliancePolicy '<name>').Guid
        UseComplianceSession = $false        # find the GUID from PolicyName (interactive Connect-IPPSSession)
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
