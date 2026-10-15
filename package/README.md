# PRA Remote Mailbox

When the on-premises Exchange servers are lost, gives every user a mailbox in Exchange Online and rolls everything back when Exchange is available again. Windows PowerShell 5.1 engine, optional WPF window. Author: Nicolas Fabert. Version 2.2.0.

This folder contains everything needed to run the tool: `Invoke-PraRemoteMailbox.ps1`, its modules and WPF window, the configuration and CSV samples, the report template and the administrator guide. Tests and build tools stay outside it, in the repository.

> [!IMPORTANT]
> Files downloaded from the Internet may be blocked by Windows and fail to run. Before using this project, unblock every file in the downloaded folder:
>
> ```powershell
> Get-ChildItem "C:\Chemin\Du\Dossier" -Recurse -File -Force | Unblock-File
> ```
>
> Replace the example path with the folder where you downloaded or extracted this project.
>
> The `Install-Module` commands in this documentation use `-Force`, so they also update or reinstall a module that is already installed. If an older version still conflicts, close every PowerShell window, open a new one (as administrator for `-Scope AllUsers`), run `Uninstall-Module <ModuleName> -AllVersions -Force`, then run the `Install-Module` command again.

## Requirements

- Windows PowerShell 5.1 for the operations; PowerShell 7.5+ only for the native Fluent window (operations still run in Windows PowerShell 5.1).
- RSAT `ActiveDirectory`, `ExchangeOnlineManagement` 3.10 or later, `Microsoft.Graph.Authentication` and `Microsoft.Graph.Users`.
- A hybrid Exchange organisation synchronised by Entra Connect, and the permissions listed in the administrator guide, chapter 4.
- Windows Terminal for emoji and colours.
- To read the HTML report: a current desktop Microsoft Edge or Google Chrome (the report is compressed and needs `DecompressionStream`; the CSV with the same name works everywhere).

## Quick start

```powershell
notepad .\config\PraRemoteMailbox.config.psd1      # scope, licence group, routing domain, Entra Connect, tenant

.\Invoke-PraRemoteMailbox.ps1 -Action Convert -Identity jdupont@contoso.com   # preview: nothing is written
.\Invoke-PraRemoteMailbox.ps1 -Action Convert -Mode Apply                     # backup, AD, sync, Exchange Online
.\Invoke-PraRemoteMailbox.ps1 -Action Recover -Batch 1d5ac20b -Mode Apply     # roll a batch back
.\Invoke-PraRemoteMailbox.ps1 -Action Check -Identity jdupont@contoso.com     # provisioned or not in Exchange Online
pwsh -STA -File .\Invoke-PraRemoteMailbox.ps1 -Gui                            # optional WPF window
```

Keep the `Backups` folder on a durable, protected volume: the backups are the only way back.

## Package integrity

The tool runs only from a package signed by its owner. `module\Test-PackageIntegrity.ps1` and `PackageIntegrity.psd1` must carry a valid, timestamped signature of `0F28E442889F17B5F4D251E8F96E7CC6E2C9C6D6`; every PowerShell file must be signed by the same owner; every stable file (modules, XAML, template, sample CSV files, README, licence, guide, images) must match the signed manifest. The entry script, each module and the GUI helper check this first. A changed, missing, duplicated, unexpected or reparse-point file stops the tool before any import, window or operation. There is no unsigned mode, switch or environment bypass; do not disable your execution policy or this check to clear an error.

Edit only `config\PraRemoteMailbox.config.psd1` and your own CSV lists in `config\`: they are data, outside the check, like the generated `Backups`, `logs` and `reports` folders. A signature detects a change; it does not stop the file system from being written.

Output folders: `Storage.BackupFolder`, `Logging.Folder` and `Report.Folder` must be either a folder outside the package or, inside the package, exactly the canonical `Backups`, `logs` and `reports` folder (a sub-folder of its own canonical folder is accepted, the name is case-sensitive). Any other folder inside the package, such as `.\audit`, is refused with a clear message before a file is written, because the integrity check would reject the unexpected files at the next start. The check uses the physical location resolved by Windows (`\\?\` prefix, junction, SUBST, 8.3 name and legacy aliases included) and refuses a path it cannot resolve. Choose an external path for a custom location.

## Content

| Item | Role |
|---|---|
| `Invoke-PraRemoteMailbox.ps1` | Entry script. |
| `module\` | Modules, WPF window (`PRA.Gui.xaml`), direct GUI helper and the integrity verifier. |
| `config\` | Configuration to fill in and the two CSV samples. |
| `templates\` | HTML report template. |
| `docs\` | Administrator guide, Markdown and self-contained HTML, with images. |
| `PackageIntegrity.psd1` | Owner-signed manifest of the stable files. |
| `README.md` | This package readme. |
| `LICENSE` | MIT license. |
| `CHANGELOG.md` | Change log (added to release packages by the package builder). |

## Documentation

- [Administrator guide](docs/PraRemoteMailbox-Guide.md) - also `docs/PraRemoteMailbox-Guide.html`, a single file to open locally

Project page, releases and change log: https://github.com/Nico77600/PraRemoteMailbox

License: [MIT](LICENSE).

## Disclaimer

This Script is a Personal project.
It's provided "AS-IS". It's not an official Microsoft product so no support can be expected from Microsoft.

As any scripts you must read carefully the documentation and test it first in a Test environment before any run in Production.

The tool changes production objects in Active Directory and creates mailboxes in Exchange Online: run the preview, review the plan, keep the backups and test in a lab before using it in a real disaster.
