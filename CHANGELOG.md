# Changelog

All notable changes of PRA Remote Mailbox. Author: Nicolas Fabert. Versions follow `MAJOR.MINOR.PAhCH`:
a MAJOR version changes the command line or the configuration file, a MINOR version adds a feature,
a PAhCH version fixes a defect. The backup formats have their own version (see the guide, annex D).

## 3.0.0 — Unreleased (source only; no tag, no release)

**Breaking: PowerShell 7.5+ required. 2.2.x remains the Windows PowerShell 5.1 release; backups from 2.x restore unchanged.**
The engine, the window, the tests and the tools now run on PowerShell 7.5 or later (`pwsh.exe`) only; Windows PowerShell 5.1
and PowerShell 7.4 are refused by `#Requires -Version 7.5` before any code runs (the integrity bootstrap is not reached, there
is no fallback path). The 2.3.0 corrections below are included. Not signed yet: the owner signs the PowerShell files and
regenerates `PackageIntegrity.psd1` before any use (guide, annex E). Offline validation only: no live-tenant campaign yet (guide,
annex B, *Lab revalidation of the PowerShell 7 engine*).

### Added (lot 2: the guided console and the transfer package)
- **New operator console** (`-Gui`, English, native Fluent theme). Five pages: **Setup, Task, Verify, Run, Next steps**. Setup shows the environment, what
  the server can run (AD, Cloud or both, from real detection: modules, certificate with its expiry, Windows account broker) and one line, *This run: ...*, with
  **Change...** to open the run settings (Environment, domain controller, mailbox scope, sign-in, tenant, organization; changed values are marked, with Reset).
  Task: four tiles (Move mailboxes, Roll back, Complete a rollback when a package exists, Check a mailbox), the object source of a new Convert (single identity
  first, configured scope, OU, CSV), the batches of every environment and the transfer packages of `Backups\Inbox` (**Import package...**), the phase inferred.
  Verify: plain summary and grid of the Preview, confirmation word in any letter case. Run: the steps announced by the engine with their state, counters, per-step bars,
  explicit waits (*attempt 4 / 13, next check in 7 s*), objects and warnings in plain words, journey card of an object. Next steps: the package to carry, the exact command,
  the status of the batch (AD, Cloud, Finalize). Expert mode keeps the phase, `MaxObjects`, `Expect`, `Once`, another configuration file and the command line.
- **Run settings apply to the run only.** The window writes an **effective configuration** (the file plus the changed values) in a private run folder, the engine loads it with
  the same validation (`Import-PraConfiguration`), its SHA-256 is part of the Preview guard, and the log, the result and the report list the settings that differ from the file
  (`-BaseConfigPath`, new optional parameter). The `.psd1` is never written. The Environment follows (and is locked to) the batch being continued.
- **Transfer package.** At each handover (Convert/Recover `-Phase AD`, Finalize package of a Recover cloud phase) an Apply writes ONE file in `Backups\Outbox`:
  `PRA-<Env>-Convert|Recover-<id8>-for-Cloud.zip` or `PRA-<Env>-Finalize-<id8>-for-AD.zip`, with a `.sha256` sidecar and a `transfer.json` manifest (entries with size and
  SHA-256). `-Batch <package.zip>` (and **Import package...**) verifies the sidecar, the manifest, the Environment and every entry hash **before writing** (zip-slip, duplicate and
  unexpected names, size bombs refused), extracts into private folders, accepts an identical existing folder and refuses a different one; all proof checks are unchanged and copying folders
  by hand still works. New steps: *Creating the transfer package* in the plan of an AD phase.
- **Engine events for the progress view** (backward compatible, only with `PRA_EVENT_FILE`): `plan` (the ordered steps), `step` (state running/ok/warn/fail/skipped, start and end),
  `item` (with `stepId` and `detail`), `progress` (attempt, maximum, seconds to the next try: Entra Connect wait, grant verification, deprovisioning and mailbox polling), and
  `transferPackage`, `transferPackageKind`, `configOverrides` in the `result`. The console output of the CLI is unchanged.

### Added (lot 2b: console fixes, global report, optional AD replication)
- **Global report across the servers.** The last server writes ONE report (`*.global.html` and `.csv`) that follows every object end to end: the timeline of the phases (server, operator, times, run
  settings changed), one row per object with its journey on each side and its verdict, totals, errors and warnings per side. Convert (AD, Cloud) and Recover (AD, Cloud, Finalize) alike, any object type; Phase Both
  uses the same layout. The previous phase travels in the transfer package as `PhaseData-*.json` (+ `.sha256`, listed in `transfer.json`: a changed file is refused at import); an older folder without it
  is reported as *not available*. The console opens it (*Open global report*); the result has `GlobalHtmlReport`/`GlobalCsvReport`. The per-phase HTML report lists the run settings changed.
- **Optional forced Active Directory replication** (`Directory.ForceReplication`, off by default; `-ForceAdReplication`; checkbox in the run settings): a step before the Entra Connect sync pushes each
  changed object to the other writable domain controllers (`Sync-ADObject`) and reads it back; failures are named warnings, never silent. New settings `Directory.ReplicationTargets`,
  `ReplicationVerifyAttempts`, `ReplicationVerifyDelaySeconds`.
- **Engine events.** `progress` per attempt for the grant verification (also from the Exchange Online child process), the Entra Connect cycle (local and remote), the mailbox polling; new `count` event (objects per
  step, once targeting is done); item events carry the backup path.

### Changed (lot 2b)
- The console runs **Phase Both** (no transfer package) on a server that can do the AD and the cloud side; the AD or Cloud phase and the package only when the server can do one side only (Expert mode can still force a phase).
- Run page: running counters (*1 / 2 objects*) with a proportional bar, steps that work on the whole batch in the journey of each object, the backup path of the object, neutral grey light for what is not used, a short
  *This run* line that names only the modified settings, an explicit title of the verification (*2 mailboxes will be converted (1 user, 1 shared) · nothing blocking*), themed *Preview again* button, **Back** no longer
  leads to the verification once an Apply has run, **Open report / Open log** next to the status, an identity check under the Identity field (read-only lookup in a child process, bounded).
- Tests: the engine event file of the tests no longer shares its name with the synthetic AD event file (the 10 reds of the lot 2 gate were a real file mix-up, not a flaky test).

### Changed (lot 2d: the cloud X500 is kept on Recover)
- **Recover keeps the cloud `X500:` address.** While an object is a remote mailbox, Entra Connect adds an `X500:` address of the cloud mailbox to `proxyAddresses` (lab evidence). Recover restored the list exactly as captured and so removed it: replies to messages sent from the cloud during the disaster, and cached Outlook entries, would bounce after the rollback. The restored list is now the original one plus every `X500:` entry on the object at plan time that was not in the original (users and shared mailboxes, Recover and the final restore of a Finalize); the routing `smtp:` address added by Convert is still removed, no `X500:` is invented, other address types are never touched, no duplicate (ordinal, ignoring case). The Preview and the report say *N cloud X500 address(es) kept*; the batch record carries `KeptX500` (absent in an older batch: none).
- **Finalize accepts the writeback, and only the writeback.** The Entra Connect writeback moves `uSNChanged` after the AD proof. It is accepted when the DN is unchanged, the `X500:` entries of `proxyAddresses` are the only difference from the list of the proof and every other managed attribute is as the proof left it; any other change still refuses the restore. Limit, written in the code and the guide: an attribute that the tool does not manage cannot be told apart from `msDS-ExternalDirectoryObjectId` by the version alone.
- **Guides.** The lab showed that Exchange Online keeps a deprovisioned cloud mailbox disconnected (not listed as soft-deleted) and reattached it with the same `ExchangeGuid` on a new Convert; the retention period is unknown, so saving its content before a rollback stays the advice. The synchronised mail user can be named by its object id: search by UPN, alias or address.

### Added (lot 5: documentation for a total beginner, minimum permissions)
- **User guide** (`package\docs\PraRemoteMailbox-UserGuide.md`, plus its HTML). Plain words for someone who has never used the tool: what it does in three short sentences, a checklist with boxes,
  the rights to ask the administrator for, set up once, then the paths *Try one mailbox*, *Move everyone on one server*, *Move everyone on two servers*, *Roll back*, *Complete the rollback*,
  *Check a mailbox* and *Read the report*. One action per step, each with the console screenshot (a red frame and a number on what to click), *what you should see* and *what to do if not*, a
  *Stop and ask* box, a table *I see this / it means / do this* for the common messages and a picture dictionary. The administrator guide is now the **reference guide**: each chapter starts with a
  two-line plain summary, and the README follows the house order (Why, Get started with the numbered scenario steps, How it works, Console, Reports, Requirements, Documentation).
- **Minimum permissions derived from the code** (reference guide, chapter 4; plain version in the user guide, chapter 2): the 10 Active Directory attributes and the one `extensionAttribute` that
  the tool writes, the licence group `member`, the reads, the single right of the optional forced replication (*Replication synchronization*), `dsacls` commands to delegate them without Domain
  Admin; Entra Connect (`ADSyncOperators`, remote session); Microsoft Graph (delegated `User.Read.All` with a one-time admin consent, or the application permission); Exchange Online (every cmdlet
  that the code calls, and the role for a person or for the application with `Exchange.ManageAsApp`). Each line names the place in the code. What the code cannot tell is listed for a lab check
  (role of the person for the Graph reads, right that replicates a single object, role of each Exchange cmdlet, certificate store). Annex C: certificate requirements (CurrentUser\My, private key,
  expiry, CSP provider).
- **Pictures generated, not drawn** (`tools\New-DocumentationImages.ps1`): the real console against a synthetic engine (light and dark), the real reports on synthetic phase data, and the diagrams
  (why, path, how it works, Convert and Recover, two servers and one file, rights, principles, shared mailbox access, picture dictionary). `tools\Build-Documentation.ps1` builds both HTML guides
  (guided path block, numbered steps, links between the guides). The obsolete 2.x pictures are removed.
- **Tests** (`tests\PraDocumentation.Tests.ps1`): pictures used exist, have an alternative text and are in the integrity inventory; no real machine, user or path in the documents; the Graph scope
  of the guide is the one of the code and every cloud cmdlet of the code is in the permissions chapter; the *Start here* part of the user guide keeps short sentences.

### Changed (breaking)
- **Host.** `#Requires -Version 7.5` on the 9 runtime files (the `-PSEdition Desktop` requirement and the run-time edition check of
  the entry script are removed). Run `pwsh -File .\Invoke-PraRemoteMailbox.ps1 ...`; a scheduled task starts `pwsh.exe`, not
  `powershell.exe`.
- **Child processes** (window engine child, OU list helper, Exchange Online subprocess) start `$PSHOME\pwsh.exe`. The cloud
  child keeps no `-NonInteractive`, stdin closed and WAM on, but now has its own new console (see the review fixes below). The window
  no longer rewrites `PSModulePath` for its child.
- **Window.** Native Fluent theme only (PowerShell 7.5+ / .NET 9); the Windows PowerShell 5.1 fallback with classic WPF controls
  is gone. The window is the new guided console (see *Added*); the French labels of the former window are replaced by English text. `Get-PraGuiNativeModulePath` is removed.
- **Entra Connect, local cycle.** `ADSync` is imported with `-UseWindowsPowerShell` under PowerShell 7 (compatibility
  session). The cycle started with `EntraConnect.Server` (WinRM) is unchanged: it runs in the Windows PowerShell 5.1 endpoint of
  the remote server.
- **Changed defaults** (they apply when a key is absent from your configuration file; a key you set is never changed, and the
  keys are the ones listed as "Configuration" under 2.3.0 below):
  - `Retention.PolicyName`: `''` (2.2.x) becomes `'PRA-Converted-Retention'` (same value as the shipped file). A configuration that
    relied on the empty default now names that policy; set `PolicyName = ''` explicitly to keep the old behaviour.
  - `Polling.IntervalMinutes`: `5` (2.2.x) becomes `1` (same value as the shipped file): the cloud part asks Exchange Online every minute.
  - `Exo.DisableWAM`: the shipped file now sets `$false` (WAM, the Windows account broker) instead of `$true` (browser); the code default is `$false`.
  - `Cloud.AppId` now requires `Cloud.Organization` and a GUID `Cloud.TenantId` at load (see 2.3.0, Configuration).
- Messages: "a new PowerShell 7 window" for the Exchange Online / Graph session conflicts; the path-length message no longer
  mentions Windows PowerShell.

### Fixed (review of lots 3 and 3b, lot 4)
- **Backup folders private as in 2.x.** `New-PraPrivateDirectory -Root` gives the private ACL to every folder created from `Storage.BackupFolder` (included) down to the
  batch folder, so a missing `Storage.BackupFolder` is born private as it was with 2.x; folders above it keep the inheritance of their own parent.
- **Schema version compared as a number.** The window and the backup import cast the JSON `SchemaVersion` to an integer before the numeric comparisons (a string or a double no longer slips through).
- **CI.** The SHA-256 of the downloaded PowerShell archive is compared ordinally (`Install-PowerShell.ps1`).
- **Tests tightened.** The Finalize-package file-name cases assert the real refusal (and a parent-folder suffix is refused as "points outside the package"); the look-alike AD proof
  cases assert their message and a witness that the untouched proof is accepted; the `#Requires` refusal tests assert `7.5` only; the `ValidateSet` guard asserts the whole message.

### Fixed (needed by PowerShell 7, found by study and by the migration)
- **JSON dates.** `ConvertFrom-Json` of PowerShell 7 turns ISO 8601 strings (`CapturedUtc`, `CreatedUtc`, `Utc`) into
  `[DateTime]`, which would have refused every schema 3 backup (`Raw/JSON: CapturedUtc mismatch`) and the memory fingerprint
  (`Type not allowed in a receipt`). All reads go through the new `ConvertFrom-PraJson` of `PRA.Common`
  (`-DateKind String`, the reason for the 7.5 minimum); the Exchange Online worker and its child process, which are
  self-contained, call `ConvertFrom-Json -DateKind String` themselves. A gate test refuses any other `ConvertFrom-Json` in
  `package\`.
- **Private folders.** `[IO.Directory]::CreateDirectory(path, security)` and `GetAccessControl(path)` do not exist on .NET:
  the batch, cloud, Finalize, log and report folders are created with `[IO.FileSystemAclExtensions]::Create` and verified
  with `GetAccessControl` on a `DirectoryInfo` (same private ACL, protected, still created in one step).
- **Raw codec.** The mscorlib/System assembly whitelist for the BCL collections of a capture is removed (the same types live in
  `System.Private.CoreLib` / `System.Collections.*` on .NET). The strict, closed list of full type names
  (`Test-PraRawCollectionType`) stays the filter on write and on read; everything else is still refused ("no fallback").
- **CSV report** is written with `-Encoding utf8BOM` (PowerShell 7 `UTF8` has no BOM; Excel needs it for the accents).

### Fixed (review of the 2.3.0 changes)
- **Cloud child console.** With `CreateNoWindow = $false` the cloud child shared the console of the terminal that started the
  window: closing that terminal killed the engine in the middle of an Apply, and under Windows Terminal the console window
  is a hidden pseudo-console. The child is now started with `CreateProcess` and `CREATE_NEW_CONSOLE` (Reflection.Emit binding in
  `PRA.Common`, `Get-PraNativeProcessApi`, no compiler) with stdin, stdout and stderr still redirected. Guide, chapter 8.
- **No runtime compiler in the window.** The C# `Add-Type` stream collector is replaced by `Stream.CopyToAsync` to
  `<id>.stdout.txt` / `<id>.stderr.txt` (pure .NET); the window reads the files progressively.
- Window: the last partial console line and the "hidden lines" counter are flushed at the end of the run; a short event text hides
  a console line only when it is the whole line; the preview grid shows the value, not the formula-guard apostrophe of the CSV.
- Wording: a closed stdin gives a prompt an empty answer, after which the engine's own checks refuse (no "fails at once").
- **Shared permission CSV** and target CSV: a byte order mark is honoured, a file that is not UTF-8 (Excel or Notepad "ANSI") is
  read with the system ANSI code page (`Read-PraCsvText`) instead of turning the accents into replacement characters.
- **Private folders**: only the last folder gets the private ACL; missing parent folders are created with the normal
  inheritance of their own parent.
- Tests: the version test has external anchors (3.0.0 and the first heading of this file); the window test proves the console of
  the cloud child (own console window, only process attached) and of the AD-only child (none).

### Security: ordinal string comparisons under .NET ICU
- **Why.** On PowerShell 7 (.NET with ICU globalisation) every culture-sensitive string comparison ignores zero-weight and control
  characters: `"a" -ceq "a<U+0001>"` is `$true`, `U+0001` equals `U+0008`, `-like` ignores zero-width characters, and so do `-eq`, `-ne`, `-in`,
  `-contains`, `switch`, `Group-Object`, `Select-Object -Unique`, `Sort-Object`, `.StartsWith(string)`, `.EndsWith(string)`,
  `.IndexOf(string)` and culture-comparer hash tables. Windows PowerShell 5.1 (NLS) was strict. Regular expressions, `.Contains(string)`,
  `[string]::Equals` and the default `Dictionary`/`HashSet` are ordinal and were not affected (measured with a small experiment on .NET 9 / ICU; table in the guide, chapter 12).
- **Fix.** Every comparison that guards integrity, identity or authorisation is now ordinal: batch, proof, receipt and `.sha256` hashes,
  GUIDs, certificate thumbprints, `Environment`, `Operation` and `Kind`, file names and path containment, the `RawFormat` marker, type
  names and XML element names of the data-only codec, JSON fields of proofs and manifests, trustees and identities matched against
  Active Directory or Exchange Online results, the typed confirmation, the guards of the window and the integrity verifier. Case-insensitive
  identity matches (UPN, sAMAccountName, SMTP, GUID text) use `OrdinalIgnoreCase`; the others `Ordinal`. New exported helpers in `PRA.Common`:
  `Test-PraOrdinalEqual`, `Test-PraOrdinalIgnoreCaseEqual`, `Test-PraOrdinalIn`, `Test-PraOrdinalIgnoreCaseIn`, `Sort-PraOrdinal`, `Get-PraOrdinalUnique`.
- **ValidateSet.** `ValidateSet` itself compares with the culture comparison and accepts `Apply<U+0001>`; the entry script (and the
  window request) now refuse a value that has no ordinal match instead of keeping it as typed.
- **Orderings.** Canonical or hash-relevant orderings use an ordinal sort (they were culture-aware under ICU).
- **Validation expressions** of identifiers, hashes and names end with `\z` instead of `$` (a trailing line feed no longer passes).
- **Tests.** A static guard refuses any new `-ceq`, `-cne`, `-cin`, `-cnotin` (and `-ccontains`) in the runtime files outside a documented
  allow-list, and behavioural tests prove that a control or zero-width character is refused in a batch hash, `Environment`,
  `Operation`, a file name of a Finalize package, the typed confirmation, the `RawFormat` marker and a raw XML element name.

### Packaging: module manifest (lot 4)
- **`PraRemoteMailbox.psd1` + `PraRemoteMailbox.psm1`** at the root of the package, aligned with ExchangeLogReport: `RootModule`, `ModuleVersion` (3.0.0, tested
  equal to `Get-PraToolVersion` and to the top entry of this file), a new `GUID`, `Author`, `Description`, `PowerShellVersion = 7.5`, `CompatiblePSEditions = Core` and an
  explicit `FunctionsToExport` (no wildcard; empty cmdlets, variables and aliases). The entry script, the window and the GUI helper import the manifest instead of the
  individual modules. The root module authenticates the package (same bootstrap as every runtime file), then loads `PRA.Common` and `PRA.Directory` (which loads `PRA.Backup`).
  `PRA.Cloud` is **still loaded only when the cloud phase needs it** (Graph before Exchange Online in the dedicated process) and `PRA.Gui` only for `-Gui`: behaviour unchanged.
  The manifest and the root module are two more owner-signed files (ten PowerShell files plus `PackageIntegrity.psd1`: eleven signatures) and are listed in `PackageIntegrity.psd1`.
- The split `module\PRA.*.psm1` files are kept as the parts of the module (reviewability, history); the unit tests still import them one by one to reach their internal functions.

### Security: child process launch of the window
- **Only the three pipe ends reach the cloud child.** `CreateProcess` was called with `bInheritHandles = TRUE`, so every inheritable handle of the window process leaked to the
  engine (a stray copy of a pipe end could delay the end of the stream and the run never completed). The child is now started with a `STARTUPINFOEX` and a
  `PROC_THREAD_ATTRIBUTE_HANDLE_LIST` that names its three standard handles (same Reflection.Emit binding, no compiler).
- **A failed start says why.** The native imports keep the Win32 error (`SetLastError = true`): the "CreateProcess failed" message carries the code and the system text. A child that dies
  before the window can attach to it is no longer silent: its error output and exit code are in the error.
- **Ordinal guard.** The static test now also refuses the case-insensitive operators on strings (`-eq -ne -in -notin -contains -notcontains`) and every unjustified `switch` in the runtime
  files, the window included (the window uses the ordinal helpers for every string comparison).

### Compatibility
- **Backup formats are unchanged**: backup schema 3 and `PraDataOnlyClixml-v1`, proof schema 2, Finalize manifest schema 2.
  The codec is designed to write the same bytes on both engines and every hash is a hash of file bytes, so backups, proofs, journals and
  Finalize packages written by 2.x restore with 3.0.0 unchanged, and files written by 3.0.0 stay readable by 2.2.x (standard
  JSON). No conversion tool is needed.
- Known cosmetic differences in new files: JSON indentation and escaping (PowerShell 7), and the order of multi-value lists
  (now an ordinal sort, see "Security" below; 2.x wrote a culture-aware order). Neither is compared across files.

### Tests, CI and tools
- Gate under PowerShell 7.5+ (`pwsh -File tests\Invoke-TestGate.ps1`); PSScriptAnalyzer with the PowerShell 7 (Core, Windows)
  compatibility profiles (none newer than 7.0 is shipped); `#Requires -Version 7.5` on the gate and the tools. The tests
  that asserted Windows PowerShell 5.1 are inverted or replaced, never relaxed: the entry script is now proved to refuse
  Windows PowerShell 5.1 (and every runtime file to stop at `#Requires`), the window tests run under PowerShell 7 only, the
  two-engine tests keep their assertions on PowerShell 7, and the test of the removed 5.1 module-path rewriting asserts that it is gone.
- New: refusal of Windows PowerShell 5.1 by `#Requires` for the 9 runtime files (the root module included), no bare `ConvertFrom-Json`, `ConvertFrom-PraJson`
  keeps dates as text, private folder ACL, CSV BOM, codec on .NET collection types, `ADSync` import switch, engine children.
- **Replay of files written by the real 2.2.0 under Windows PowerShell 5.1.** `tests\PraLegacyFixtures.Tests.ps1` (in the gate and in `.github\ci.json`)
  reads, through the production readers only, the files frozen in `tests\fixtures\ps51-2.2.0`: Convert and Recover backups (schema 3) with their
  CLIXML, journals and AD proofs, a Finalize package with its cloud journal, a 13-shared-mailbox Convert/Recover pair (native security descriptors), the
  historical schema 1 and 2 files and an all-types capture. They were produced by the released 2.2.0 code under `powershell.exe` 5.1 (generator:
  `tools\New-LegacyFixtures.ps1`, not part of the package; synthetic data only) and are checked byte for byte against `fixtures.sha256`. 23 checks
  pass under PowerShell 7 (and under 5.1 against 2.2.0): backup import, raw codec decode, proofs, Finalize manifest, the current codec writing the
  same bytes as the 5.1 file, and the refusal of one flipped byte. This is the evidence for "backups from 2.x restore unchanged"; a restore
  in a real directory remains a lab step (guide, annex B).
- CI runs on PowerShell 7.5: `.github\scripts\Install-PowerShell.ps1` installs the pinned 7.5.13 archive (SHA-256 checked)
  when the runner ships 7.4.
- `tools\New-PraPackage.ps1`, `tools\Build-Documentation.ps1` and `tools\New-ReadmeImages.ps1` require PowerShell 7.5.

## 2.3.0 — Unreleased (source only; no tag, no release)

Engine, window, tests and documentation corrections after the review of 2.2.0. The backup, receipt and proof
engine is unchanged. Not signed yet: the owner signs the PowerShell files and regenerates `PackageIntegrity.psd1`
before any use (see the guide, annex E).

### Fixed
- **Letter case of the parameters.** `-Action convert -Phase cloud -Mode apply` failed in the proof check because
  `ValidateSet` keeps the value as typed while the proofs, batches and journals are compared (on purpose)
  case-sensitively. The entry script now rewrites `-Action`, `-Mode`, `-Phase`, `-Scope` and `-Expect` (and any
  other `ValidateSet` string parameter) to their official spelling right after the parameters are bound. The
  strict `-cne` / `-ceq` integrity comparisons downstream are unchanged.
- **Window, cloud sign-in.** The engine child of the window ran with `-NonInteractive` and no console window, so
  the interactive Exchange Online / Graph sign-in (Windows account broker, WAM) had no parent window and failed
  with an MSAL error. Cloud actions now start the child with a console (inherited, or a new visible one),
  without `-NonInteractive`, with stdin closed. Shipped `Exo.DisableWAM` is `$false` (WAM on); Graph keeps its
  default. The activity log now shows the engine's console lines as they arrive. Guide chapter 8.
- **Window, confirmation and paths.** The typed confirmation (`CONVERT`, `RECOVER`, `FINALIZE`) is case-insensitive
  and trimmed; the configuration path is compared as a full path, ignoring case.
- **Recover `-Phase Both`** had no read-only cloud pre-check before the AD writes. It now signs in and resolves
  the targets in Exchange Online (no trustee, no identity pinning) before the first AD write, like Convert.
- **Configuration.** `Cloud.AppId` now requires `Cloud.Organization` and a GUID `Cloud.TenantId` at load.
  The code defaults equal the shipped file (`Polling.IntervalMinutes` 1, `Retention.PolicyName`
  `PRA-Converted-Retention`, `Cloud.MailboxCheckVia` `Exo`, `Exo.DisableWAM` `$false`).
- `-Confirm:$false` skipping the single Apply confirmation is documented (help, guide); behaviour unchanged.
- **Server CSV report:** values starting with `=`, `+`, `-`, `@`, TAB or CR are neutralised (apostrophe), like
  the CSV export of the HTML report.
- **`logs\` and `reports\`** are created with the private ACL of the backups (current account, SYSTEM,
  Administrators, no inheritance). An existing folder is left untouched.
- The **cloud journal folder** is created after the confirmation, not before.
- **Next-step command:** `-Batch`, `-Identity`, `-SearchBase`, `-CsvPath` and `-ConfigPath` are quoted as data
  (apostrophe and typographic quotes doubled).
- **Shared permissions CSV:** comma or semicolon (read from the header, not from the regional setting); an empty
  mailbox name no longer matches an empty `Shared` cell.
- **MissingFullAccess:** the message prefix stays an exact match, the trustee is compared case-insensitively.
- **Exchange Online child process:** warnings and information records of a module can no longer break the
  one-line JSON protocol; errors stay fatal.

### Changed
- **One version source:** `$script:ToolVersion` of `PRA.Common`, exported as `Get-PraToolVersion`. The entry
  script, the window and `tools\New-PraPackage.ps1` read it. The literal `Version` comments that the signature
  forces are listed in the guide, annex E, and checked by the tests.
- `-Scope` is documented as ignored by Convert with `-Identity`.
- Guide: truncated sentences, journal statuses, file lists, missing configuration keys (chapter 6), environment
  variables, version annex; the HTML guide and the README banner were rebuilt.

### Removed
- `CloudCheckScope` (never set to anything but `Both`) and the name patterns of the trustee filter that could
  never match a SID reference (the groups are filtered by name once resolved).

### Tests and CI
- New Pester coverage: letter case, Recover pre-check, Organization/TenantId, unknown keys and types,
  `Confirm-PraApply`, CSV neutralisation, shared permission CSV, next-step quoting, the window confirmation, path
  comparison, child-process settings and progressive output, version consistency, defaults versus shipped file.
- CI uploads the real gate evidence (`tests/evidence/gate`) instead of a non-existent file, no longer carries
  dead PowerShell 7 steps, and the advisory PSScriptAnalyzer run also covers `tests\` and `tools\`.

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
- Lab campaign 2026-09-30 / 2026-10-01 on a lab Active Directory domain + a Microsoft 365 test tenant (real AD, Entra Connect and
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
