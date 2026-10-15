# Changelog

All notable changes of PRA Remote Mailbox. Author: Nicolas Fabert. Versions follow `MAJOR.MINOR.PATCH`:
a MAJOR version changes the command line or the configuration file, a MINOR version adds a feature,
a PATCH version fixes a defect. The backup formats have their own version (see the guide, annex D).

## 2.2.0 — Unreleased (source only; no tag, no release)

### Added
- **Signed-package integrity (Windows PowerShell 5.1).** `module\Test-PackageIntegrity.ps1` and the
  manifest `PackageIntegrity.psd1` verify, before any code runs, the owner's timestamped Authenticode
  signature (fixed thumbprint) of the verifier, the manifest and every PowerShell file, and the SHA256 of
  every stable file (modules, XAML, report template, sample CSV files, README, licence, guide, images).
  The entry script, each module and the GUI helper run the same bootstrap first. A changed, missing,
  duplicated, unexpected or reparse-point file fails closed; there is no unsigned mode or bypass.
  The configuration and the operational CSV lists in `config\` are data, outside the check, as are
  `Backups\`, `logs\` and `reports\`. A backup, log or report folder inside the package other than its own
  canonical `Backups`, `logs` or `reports` folder (a sub-folder is fine) is now refused before any file is
  written, judged on the physical location (a `\\?\` prefix, junction, SUBST drive, 8.3 name or `Documents and Settings` alias cannot hide the package; an unresolvable path is refused; external paths are unchanged): such files would be rejected at the next start.
  The final manifest is generated from the finalized signed and timestamped runtime bytes.
- `tests\PackageIntegrity.Tests.ps1`: static inventory/bootstrap checks, a controlled fixture (only the
  signature call is substituted) for tamper, missing, unexpected, duplicate, manifest-schema and reparse
  cases, builder checks, and the native signed-package or unsigned fail-closed state of the real package.

- **Report export snapshot.** The filtered CSV export in the report page now iterates a copy of the rows selected
  when it starts, so changing a filter while it runs cannot change the exported rows or the reported count.

- **High-volume HTML report.** The report page no longer builds a table per row. The rows (22 fields),
  run errors and warnings are streamed by a Windows PowerShell 5.1 writer into dictionary-indexed,
  gzip+base64 chunks of at most 20,000 rows; the page decodes all chunks when it opens (eager, not lazy)
  and shows virtualized *Summary* and *All 22 fields* grids with at most 200 data rows in the page.
  Status/type/action/flag/text filters (AND, over every row), a search over the 22 fields, keyboard
  navigation, a details dialog, paged warnings and run errors, and a filtered CSV export of all matching
  rows (BOM, quoted, formulas neutralised). A current desktop Edge or Chrome is required
  (`DecompressionStream`); otherwise the page explains it and the CSV holds every row. Compression is not
  encryption. The server CSV is unchanged.
- `tests\PraReport.Tests.ps1` with synthetic 50,000 and 100,000 row reports (exact counts, chunk
  boundaries, last row, escaping, fields) and `tests\ReportFixture.ps1`.

### Changed
- The runtime moved to the `package\` folder (entry, `module\`, `config\`, `templates\`, `docs\`, runtime
  README and licence). Inside the package, and in the extracted release, every path is unchanged. Tests,
  tools and the gate stay outside the distribution. `tools\New-PraPackage.ps1` now builds from
  `package\`, verifies the signed source first and refuses an unsigned or changed one.
- Documentation and tools (`Build-Documentation.ps1`, `New-ReadmeImages.ps1`) use the new paths.

## 2.1.0 — 2026-10-09

### Added
- **Direct target selection for Convert AD/Both:** configuration, OU (DN or read-only directory
  picker) and CSV (Identity column, comma/semicolon). Run-specific `-SearchBase`/`-CsvPath` overrides
  never rewrite the configuration; source/file changes invalidate Preview. Users and shared
  mailboxes continue through the same eligibility, duplicate and backup guards.
- **WPF window** (`-Gui`) for Convert, Recover, Finalize and Check, with explicit AD + cloud, AD-only
  and cloud-only execution. Native Fluent with PowerShell 7.5+; compatible WPF controls with Windows
  PowerShell 5.1. Every operation still runs the existing Windows PowerShell 5.1 engine.
- Preview before Apply, typed confirmation, batch selection, progress and activity, result rows,
  log/report access and the next-server handoff instructions. Changing the request or its input
  files invalidates the preview. A failed or incomplete preview never authorizes Apply.
- Optional structured JSONL events from the common module for the window; ordinary CLI output,
  reports, transcripts and backup formats stay unchanged. GUI module and XAML included in packaging.
- Offline GUI Pester suite and regressions for event/result coherence and split recovery.

### Changed
- **Recover -Phase Cloud now always packages final AD restoration**, even when ActiveDirectory is
  installed and `DeferOnPremRestore = $false`. Run Finalize on the AD server using the package printed
  in the result. Phase Both retains its existing inline restoration unless explicitly deferred.
- `-Gui` can run in either PowerShell edition; actual command-line operations still require Desktop.
  No GUI action runs live on startup, and the window cannot close while its engine is running.

### Fixed
- Large-batch receipt fingerprints and raw backup validation avoid redundant per-string
  PowerShell binding and regex callbacks. Structural hashes, raw XML bytes, live tamper checks
  and the existing memory/time watchdogs remain unchanged.
- The offline gate validates structured help metadata instead of matching localized headings.
  French and English help both pass, while a missing synopsis, insufficient examples or a missing
  real `WhatIf` parameter still fail the gate.

This version has offline validation only; no new live-tenant campaign has been performed.

## 2.0.1 — 2026-10-07

### Fixed
- **Scheduled task / `powershell.exe -File`:** Windows PowerShell 5.1 leaves `$PSScriptRoot` empty in the
  default values of `param()` when a script runs with `-File`. The default `-ConfigPath` of
  `Invoke-PraRemoteMailbox.ps1` (and `-Source` / `-Destination` of `tools\Build-Documentation.ps1`) was built
  there, so the script stopped at once with `Join-Path: Cannot bind argument to parameter 'Path' because it is an
  empty string`. The defaults are now resolved in the script body; an explicit `-ConfigPath` behaves as before.
  Found while building the scenario 2 tool (PRA Cloud Mailbox), whose Collect runs as a scheduled task.

### Tests
- New block "Scripts start with powershell.exe -File (scheduled task)": no `param()` default of the entry script
  or of the tools may read `$PSScriptRoot`, `$PSCommandPath` or `$MyInvocation`.

## 2.0.0 — 2026-10-01

Rewrite of the operator experience on the model of Purview DLP Report: one entry script driven by the
configuration file, a readable console, one guide. **The safety engine is unchanged** (backup before
any write, receipts and SHA-256, AD proofs, stop at the first error); backups written by 1.3.x are read
by 2.0.0 (tested in the lab: Recover of a 1.3.6 batch).

### Changed — command line and files (breaking)

| 1.3.6 | 2.0.0 |
|---|---|
| `PRA-RemoteMailbox.ps1` in `release\` | `Invoke-PraRemoteMailbox.ps1` at the root of the tool folder |
| `config\DRP-Config.psd1` | `config\PraRemoteMailbox.config.psd1` (English comments, unknown keys refused) |
| `-Action Convert\|Recover\|CloudCheck` | `-Action Convert\|Recover\|Finalize\|Check` |
| `-Mode Inventory\|Simulate\|Apply` (default Inventory) | `-Mode Preview\|Apply` (default Preview); `-WhatIf` = Preview |
| `-Phase Both\|AD\|Cloud\|Finalize\|TagCleanup` | `-Phase Both\|AD\|Cloud`, default `Execution.Phase`; Finalize is an action |
| `-BackupFile <path>` + `-StateFile <path>` | `-Batch <id>` (the 8 characters printed at the end of the previous step) or a path |
| `-MailboxScope` | `-Scope` |
| `-CloudCheckScope`, `-VerifyRetention` | `-Expect Provisioned\|Deprovisioned\|Retained` |
| `-SyncADConnect` | `EntraConnect.Sync` (default `$true`), local or remote (`EntraConnect.Server`) |
| `-DeferSharedRestore`, `-KeepCloudShared` | `SharedMailbox.DeferOnPremRestore`, `SharedMailbox.KeepCloudSharedOnRecover` |
| `-DomainController`, `-BackupDirectory`, `-LogPath`, `-TranscriptPath`, `-ReportDirectory`, `-NoReport`, `-IntervalMinutes`, `-TimeoutMinutes` | configuration only: `DomainController`, `Storage`, `Logging`, `Report`, `Polling` |
| `-SkipCloudCheck`, `-DeprovisionCloudShared` (obsolete aliases) | removed |
| `ADConnect.WaitForSync`, `SharedMailbox.VerifyTrusteeInCloud` (ignored by 1.3.x) | removed (the tool always waits; trustees are always checked) |
| exit code 0 also for Pending | 0 = done, 1 = failed, **2 = done, next step required** (Pending) |

### Added

- **One confirmation per run** after the plan is shown (instead of one prompt per AD write); `-Force` for unattended runs.
- **Batch IDs**: every Apply prints a short batch ID and the exact **next command**; `-Batch` finds the batch
  folder, its AD proof, and (cloud phase of a Recover) its Convert source by SHA-256.
- **Remote Entra Connect synchronisation** (`EntraConnect.Server`, PowerShell remoting) and a check of the
  synchronisation **before** the first AD write (1.3.x failed after the AD writes when ADSync was missing).
- Console in the style of Purview DLP Report: banner, numbered steps, compact before/after view (only the
  attributes that change), summary card with the result, the batch and the next step. Full values stay in the log.
- HTML report with tiles, status badges and a filter (`templates\Report.template.html`).
- The plan of a shared mailbox lists **who will get FullAccess, SendAs and SendOnBehalf** (first holders on
  screen, complete lists in the log), so that the permissions can be checked in Preview.
- **Permission entries of an account no longer in AD** ("Account Unknown": deleted, or another domain) are
  ignored and reported as **warnings** — yellow line in the console, `[WARN]` in the log, CSV column `Warnings`,
  *Warnings* tile and card in the HTML report, yellow summary card. 1.3.x stopped the whole batch on them.
  Warnings never change the exit code. The result object (`-PassThru`) has `WarningCount` and `Warnings`.
- Preview of a cloud phase: one pass, never waits; missing permissions are shown "to grant" (1.3.x reported an error).
- `tools\New-PraPackage.ps1` (delivery package with the environment values emptied) and
  `tools\Build-Documentation.ps1` (HTML guide).
- Single guide `docs\PraRemoteMailbox-Guide.md` / `.html` (replaces the operator guide, the technical
  documentation and the release notes of 1.3.x).
- `-PassThru`: returns the result object of the run (status, exit code, batch ID, next steps, paths) for
  scripts and orchestrators. Without it the tool writes nothing to the pipeline (1.3.x always did, which
  printed a raw object after the summary in an interactive console).

### Fixed

- **Certificate (app-only) sign-in to Exchange Online always failed**: the session guard compared
  `Get-ConnectionInformation.TenantID` with the tenant GUID, but app-only sessions report the organisation
  domain. The guard now accepts the configured `Cloud.Organization` (and checks the `AppId`). This is the
  "certificate returns UnAuthorized" blocker noted in the 1.3.4 pilot.
- The AD module no longer creates the `AD:` drive on a default domain controller at import.
- The PowerShell 5.1 transcript is readable again (one `Write-Host` per line).
- Before each FullAccess grant, Exchange Online answers "No permissions were found" (the normal answer when
  the right is not there yet). It was read with `-ErrorAction Stop`, so Windows PowerShell 5.1 wrote it in the
  transcript as a `TerminatingError` line that looked like a failure. It is now read through `-ErrorVariable`:
  no line in the transcript, and any other error still stops the run as before (lab T16: 0 such line).
- **Recover stopped on a normal transient state** (lab T17): right after the sync, while the cloud shared mailbox
  turned into a MailUser, Exchange Online briefly answered "object couldn't be found" (HTTP 404) for the
  recipient. The check took it as an error and stopped (nothing restored on-premises, safe, but the operator had
  to start again). This exact answer now means "not there yet": the check waits and reads again. Any other 404
  or error still stops.
- **Check (or Convert) after another run in the same console**: Microsoft Graph could not load next to the
  Exchange Online assemblies of the previous run and failed with an obscure `GetTokenAsync ... does not have an
  implementation`. The message now says what to do: run the tool in a new Windows PowerShell window.

### Code review 2026-09-30 — other findings

See the guide, annex F: dead settings, duplicated mode values, per-write prompts, implicit selection of the
"most recent" backup (removed), messages in two languages, 358-character lines, French/English mix. All
addressed in 2.0.0. No defect of the backup/proof engine was found.

### Validation

- Test gate on VMLLM (Windows PowerShell 5.1, Pester 6.0.0, PSScriptAnalyzer 1.25.0): **279 / 279 passed**,
  0 analyzer error (evidence `tests\evidence\gate\v2.0.0-release`). The 61 tests of the removed path options
  of 1.3.6 are replaced by tests of `-Batch` and of the confirmation (1.3.6: 325 tests).
- Lab campaign 2026-09-30 / 2026-10-01 on `exlab.lab` + tenant M365CPI89259425 (real AD, Entra Connect and
  Exchange Online): 28 runs — Convert, Recover on one and two servers, Finalize, Check, Recover of a 1.3.6
  batch, shared mailbox permissions given to a group (nested group included), SendAs actually granted,
  SendOnBehalf (guide, annex B). 26 PASS; the 5 defects found (approval callback with `-Force` in a
  non-interactive process; certificate session guard; recipient 404 during the Recover check; Graph after
  Exchange Online in the same console; transcript lines) are fixed and covered by the gate.

## 1.3.x — 2026-09-07 to 2026-09-10 (summary)

| Version | Change |
|---|---|
| 1.3.6 | Exchange Online pre-check before the AD writes of a Convert (phase Both); bounded verification after one grant; invalid path characters reported precisely. |
| 1.3.5 | Shared mailboxes provisioned with `msExchRemoteRecipientType` 97 (99 with archive); 100/102 refused for a new Convert. |
| 1.3.4 | Capture of the declared properties of a native ADUser only. |
| 1.3.3 | Data-only CLIXML capture written and validated as a stream (backup schema 3), bounded permission cache: the out-of-memory of a 13 shared mailbox batch cannot happen any more. |
| 1.3.2 | Transcript start on hosts that create the file late. |
| 1.3.1 | Before / planned / verified values in the console and the log. |
| 1.3.0 | Backup of the whole batch **before** the first write, AD proofs, stop at the first error (fix of the 1.2.5 incident: the backup was written after the writes). |
| 1.2.5 | Original script (June 2026). |
