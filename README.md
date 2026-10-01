# PRA Remote Mailbox

Hybrid Exchange disaster recovery: when the on-premises Exchange servers are lost, turns the on-premises
mailboxes into **remote mailboxes** so that users get a mailbox in **Exchange Online**; rolls everything
back when Exchange is available again. Active Directory and Entra Connect are the only systems changed
on-premises; every change is backed up first.

- **Author:** Nicolas Fabert
- **Version:** 2.0.0 (see [CHANGELOG.md](CHANGELOG.md))
- **Documentation:** [docs/PraRemoteMailbox-Guide.md](docs/PraRemoteMailbox-Guide.md) (also as HTML: `docs\PraRemoteMailbox-Guide.html`)

## Quick start

```powershell
# Windows PowerShell 5.1 (not PowerShell 7), RSAT ActiveDirectory, ExchangeOnlineManagement 3.10+,
# Microsoft.Graph.Authentication + Microsoft.Graph.Users
cd <tool folder>
notepad .\config\PraRemoteMailbox.config.psd1        # scope, licence group, Entra Connect, tenant

.\Invoke-PraRemoteMailbox.ps1 -Action Convert -Identity jdupont@contoso.com   # preview for one user (nothing is written)
.\Invoke-PraRemoteMailbox.ps1 -Action Convert                    # preview of the configured scope (e.g. an OU)
.\Invoke-PraRemoteMailbox.ps1 -Action Convert -Mode Apply        # convert: backup, AD, sync, Exchange Online
.\Invoke-PraRemoteMailbox.ps1 -Action Convert -Scope SharedOnly -Mode Apply   # only the shared mailboxes of the scope
.\Invoke-PraRemoteMailbox.ps1 -Action Recover -Batch 490cc62e    # preview of the roll-back of that batch
.\Invoke-PraRemoteMailbox.ps1 -Action Check -Identity user@contoso.com
```

More examples (one user, an OU, shared mailboxes only, a list, roll-back): guide, chapter 8.

Every run starts in **Preview**; `-Mode Apply` asks one confirmation (or none with `-Force`). The end of each
run prints the batch ID and the exact next command. Exit codes: 0 = done, 1 = failed, 2 = done, next step required.

To deliver the tool, run `.\tools\New-PraPackage.ps1`: it copies only the files needed to run into
`..\package\PraRemoteMailbox-<version>` (no backup, no log, environment values emptied), ready to be zipped.

## License
[MIT](LICENSE).
