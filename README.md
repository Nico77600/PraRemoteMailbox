# PRA Remote Mailbox

Hybrid Exchange **disaster recovery**: when the on-premises **Exchange servers are lost**, gives every user a mailbox in **Exchange Online** by turning the on-premises mailboxes into **remote mailboxes** — user and shared mailboxes, with their **FullAccess, SendAs and SendOnBehalf** permissions — and **rolls everything back** when Exchange is available again. Only Active Directory is changed on-premises, and every change is backed up first.

![Convert of two users and two shared mailboxes](docs/images/console-apply.png)

## Why

In a hybrid organisation, a mailbox hosted on-premises is only a *mail user* for Exchange Online. If the on-premises Exchange servers are lost (ransomware, site loss, corrupted databases), these users have no mailbox at all — and a normal migration is impossible, because moving a mailbox needs the on-premises servers. As long as **Active Directory and Entra Connect** still work, the fastest way back to e-mail is to give each user a **new, empty mailbox in Exchange Online** and to recreate the access to the shared mailboxes. *PRA* stands for *Plan de Reprise d'Activité*, the disaster recovery plan.

Done by hand, this means rewriting about ten Exchange attributes per object in Active Directory, for hundreds of objects, under stress — and keeping every original value to come back later: a wrong or lost value cannot be repaired without a backup. With Exchange down, the shared mailbox permissions also exist only as copies in Active Directory. This tool does the whole conversion in a planned, verified and **reversible** way.

## How it works

```
Convert   Read AD ───► Backup ───► Write AD ───► Entra Connect ───► Exchange Online
          scope,       JSON +      remote         one delta          mailboxes, licences,
          attributes,  SHA-256,    mailbox,       cycle              shared mailbox
          permissions  re-read     licence group                     permissions granted

Recover   the same batch, the other way: original AD values back, licence removed,
          cloud shared mailboxes removed before the on-premises ones come back
```

- **One script, one configuration file**: `-Action Convert | Recover | Finalize | Check`, `-Mode Preview | Apply`. The scope is one object, an OU, the members of an AD group or a CSV list — users only, shared mailboxes only, or both.
- **Preview first**: every run reads and plans without writing, and the console shows only the attributes that change. `-Mode Apply` asks one confirmation after the plan (`-Force` for unattended runs).
- **Backup before any write**: a complete backup of every object (JSON + CLIXML + SHA-256) is written and re-read before the first AD change; every AD write is re-read; the **first error stops the batch**. Each Apply prints a short **batch ID** and the exact next command — `-Action Recover -Batch <id>` rolls the batch back.
- **Shared mailbox permissions**: read from the copies Exchange keeps in Active Directory (`msExchMailboxSecurityDescriptor`, the *Send As* right, `publicDelegates`); groups are expanded to their users, nested groups included; every holder is found in Exchange Online **before** any AD write; each right is granted once, then re-read until Exchange Online shows it. Entries of deleted accounts are ignored and reported as warnings.
- **Entra Connect**: one delta cycle, on the local or a remote Entra Connect server, checked **before** the first AD write; the tool then waits for the mailboxes and the licences in Exchange Online.
- **One or two servers**: everything from one server, or the AD part on-premises and the cloud part on an isolated server (a Finalize package carries the last step back).
- **Traceability**: log, PowerShell transcript, CSV and a self-contained **HTML report** for every run; exit codes 0 = done, 1 = failed, 2 = done, next step required.

![HTML report](docs/images/report.png)

<details>
<summary><b>Preview of a Convert</b> — what will change, attribute by attribute, nothing written</summary>

![Preview of a Convert](docs/images/console-preview.png)

</details>

## Requirements

| Item | Requirement |
|---|---|
| Scenario | Hybrid Exchange organisation (Exchange Server + Exchange Online) synchronised by **Entra Connect**. Exchange on-premises is not needed (it is down); Active Directory and Entra Connect must work |
| PowerShell | **Windows PowerShell 5.1** (`powershell.exe`), not PowerShell 7 |
| Modules | RSAT `ActiveDirectory`, `ExchangeOnlineManagement` 3.10 or later, `Microsoft.Graph.Authentication` and `Microsoft.Graph.Users` |
| Permissions | Active Directory: write the Exchange attributes of the objects in scope and the members of the licence group. Entra Connect: `ADSyncOperators` (or local administrator), WinRM when remote. Exchange Online: **Exchange Recipient Administrator**. Microsoft Graph: `User.Read.All`. For unattended runs: an application with a certificate (guide, annex C) |
| Licences | A licence group that gives Exchange Online to the users (shared mailboxes need no licence) |
| Console | Windows Terminal for emoji and colours; the classic console shows symbols |

## Quick start

```powershell
git clone https://github.com/Nico77600/PraRemoteMailbox.git
cd PraRemoteMailbox
notepad .\config\PraRemoteMailbox.config.psd1      # scope, licence group, routing domain, Entra Connect, tenant

.\Invoke-PraRemoteMailbox.ps1 -Action Convert -Identity jdupont@contoso.com   # preview for one user: nothing is written
.\Invoke-PraRemoteMailbox.ps1 -Action Convert                                 # preview of the configured scope (e.g. an OU)
.\Invoke-PraRemoteMailbox.ps1 -Action Convert -Mode Apply                     # backup, AD, sync, Exchange Online
.\Invoke-PraRemoteMailbox.ps1 -Action Convert -Scope SharedOnly -Mode Apply   # only the shared mailboxes of the scope
.\Invoke-PraRemoteMailbox.ps1 -Action Recover -Batch 1d5ac20b                 # preview of the roll-back of that batch
.\Invoke-PraRemoteMailbox.ps1 -Action Recover -Batch 1d5ac20b -Mode Apply     # roll the batch back
.\Invoke-PraRemoteMailbox.ps1 -Action Check -Identity jdupont@contoso.com     # provisioned or not in Exchange Online
```

Keep the `Backups` folder on a durable, protected volume: the backups are the only way back. The zip of each [release](https://github.com/Nico77600/PraRemoteMailbox/releases) contains only the files needed to run; `.\tools\New-PraPackage.ps1` builds the same package from the repository.

## Documentation

The **administrator guide** covers the disaster scenario, what changes in Active Directory, the shared mailbox permissions, installation, configuration, unattended execution with a certificate, ready-to-use recipes (one user, an OU, shared mailboxes only, a list, the roll-back, two servers), the reports, troubleshooting, the internals and the lab test campaign:

- [docs/PraRemoteMailbox-Guide.md](docs/PraRemoteMailbox-Guide.md)
- `docs/PraRemoteMailbox-Guide.html` — the same guide as a single HTML file (download it and open it locally)

## Tests

```powershell
# Windows PowerShell 5.1 (powershell.exe), like the tool; Pester 5+ and PSScriptAnalyzer 1.25.0 installed
powershell.exe -NoProfile -File .\tests\Invoke-TestGate.ps1     # no directory, no tenant needed
```

The gate runs the real entry script against a synthetic Active Directory, Entra Connect and Exchange Online (279 tests): no write before the complete backup, stop at the first error, no write in Preview, no Apply without confirmation, memory bounds, proofs and Finalize packages. The tool was also validated on a real Active Directory, Entra Connect and Microsoft 365 tenant (guide, annex B). Only `tools\Build-Documentation.ps1`, which rebuilds the HTML guide on a workstation, needs PowerShell 7.4+.

## License

[MIT](LICENSE).

## Disclaimer

Personal project, provided as is. It is not an official Microsoft product and is not supported by Microsoft. The tool changes production objects in Active Directory and creates mailboxes in Exchange Online: run the preview, review the plan, keep the backups and test in a lab before using it in a real disaster.
