<#
.SYNOPSIS
    Photographs the real PRA Remote Mailbox window against a synthetic runtime, for the documentation (repository tool, never shipped).
.DESCRIPTION
    Called by tools\New-DocumentationImages.ps1, once per scenario and theme, in its own PowerShell 7.5+ STA process.
    It builds the real window (package\module\PRA.Gui.psm1) in a copy of the package whose signature check is substituted
    (tests\IntegrityFixture.ps1), with the synthetic engine StubEngine.ps1 instead of the real one, then drives the five pages
    like an operator and renders them to PNG. Callouts (a red frame and a number) mark what the operator must click.
    Synthetic values only, injected here and never read from the machine: computer SRV-PRA01, account CONTOSO\pra.operator, tool folder
    D:\PRA\PraRemoteMailbox, backups D:\PRA\Backups. Every text of the window is checked before each photo: a real machine name, user
    name or local path stops the run.
.PARAMETER Shots
    Output folder of the PNG files (named console-<shot>-<light|dark>.png).
.PARAMETER Scenario
    single    one mailbox on a server that runs both sides
    scope     the configured scope (users and a shared mailbox) on a server that runs both sides
    twoserver the AD server of a two-server move (red lights for the cloud modules, transfer package)
    cloud     the cloud server: imports the transfer package
    rollback  Roll back a conversion on a server that runs both sides
    finalize  Complete a rollback on the AD server
    check     Check a mailbox
.PARAMETER Repository
    Root of the repository (default: two folders above this script).
.NOTES
    Author  : Nicolas Fabert
    Version : 3.1.0
    Part of : PRA Remote Mailbox (repository tool, not in the package)
#>
#Requires -Version 7.5
param(
    [Parameter(Mandatory)][string]$Shots,
    [ValidateSet('Light', 'Dark')][string]$Theme = 'Light',
    [ValidateSet('single', 'scope', 'twoserver', 'cloud', 'rollback', 'finalize', 'check')][string]$Scenario = 'single',
    [string]$Repository
)
$ErrorActionPreference = 'Stop'
# Real values of this machine, kept only to make sure that none of them reaches a picture.
$real = @($env:COMPUTERNAME, $env:USERNAME, $env:USERDOMAIN, $env:USERPROFILE, $env:TEMP, $env:LOCALAPPDATA, $env:APPDATA) | Where-Object { $_ -and $_.Length -ge 3 }
[Threading.Thread]::CurrentThread.CurrentCulture = [Globalization.CultureInfo]::GetCultureInfo('en-US'); [Threading.Thread]::CurrentThread.CurrentUICulture = [Globalization.CultureInfo]::GetCultureInfo('en-US')
$env:COMPUTERNAME = 'SRV-PRA01'; $env:USERDOMAIN = 'CONTOSO'; $env:USERNAME = 'pra.operator'; $env:USERDNSDOMAIN = 'CONTOSO.COM'
if (-not $Repository) { $Repository = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent }
$repo = (Resolve-Path $Repository).Path
$work = Join-Path ([IO.Path]::GetTempPath()) ('pra-doc-' + $Scenario + '-' + $Theme + '-' + [guid]::NewGuid().ToString('N').Substring(0, 6))
try {
    . (Join-Path $repo 'tests\IntegrityFixture.ps1')
    . (Join-Path $PSScriptRoot 'New-PackageCopy.ps1')
    New-DocumentationPackageCopy -Repository $repo -Destination (Join-Path $work 'source')
    $null = New-PraIntegrityFixture -SourcePackage (Join-Path $work 'source') -Destination (Join-Path $work 'package') -Changelog (Join-Path $repo 'CHANGELOG.md')
    $pkg = Join-Path $work 'package'
    Import-Module (Join-Path $pkg 'module\PRA.Common.psm1') -Force
    Import-Module (Join-Path $pkg 'module\PRA.Gui.psm1') -Force
    $enc = New-Object Text.UTF8Encoding($true)
    function W($p, $t) { $null = New-Item -ItemType Directory -Path (Split-Path $p -Parent) -Force; [IO.File]::WriteAllText($p, $t, $enc) }
    function J($p, $d) { W $p ($d | ConvertTo-Json -Depth 15); W ($p + '.sha256') ((Get-FileHash $p).Hash.ToLowerInvariant()) }
    $root = Join-Path $work 'runtime'
    New-Item -ItemType Directory -Path $root -Force | Out-Null
    $config = Join-Path $root 'config\PraRemoteMailbox.psd1'
    $phaseConfig = switch ($Scenario) { 'twoserver' { 'AD' } 'finalize' { 'AD' } 'cloud' { 'Cloud' } default { 'Both' } }
    W $config "@{Environment='LAB'; DomainController='dc01.contoso.com'; Scope=@{Mode='OU';SearchBase='OU=Wave1,DC=contoso,DC=com'}; Licensing=@{Enabled=`$false}; EntraConnect=@{Sync=`$true;Server='SRV-AADC01'}; Execution=@{Phase='$phaseConfig'}; Cloud=@{Organization='contoso.onmicrosoft.com'}}"
    W (Join-Path $root 'module\PRA.Synthetic.psm1') '# marker'
    Copy-Item (Join-Path $PSScriptRoot 'StubEngine.ps1') (Join-Path $root 'Invoke-PraRemoteMailbox.ps1')
    # The package checks of the console run a helper of the package folder: a stand-in that calls the real code of the fixture copy.
    Copy-Item (Join-Path $PSScriptRoot 'StubPackageCheck.ps1') (Join-Path $root 'module\PRA.Gui.Directory.ps1')
    W (Join-Path $root 'package-root.txt') $pkg
    # Synthetic people. Alice is the "test first" mailbox; the others are the configured scope.
    $names = @('adele.vance', 'alex.wilber', 'diego.siciliani', 'grady.archie', 'isaiah.langford', 'finance.shared')
    $objects = @($names | ForEach-Object { @{ sam = $_; upn = "$_@contoso.com"; guid = [guid]::NewGuid().ToString(); shared = ($_ -eq 'finance.shared'); warning = $(if ($_ -eq 'finance.shared') { 'Forwarding to an outside address is kept' } else { '' }) } })
    $alice = @{ sam = 'alice.vance'; upn = 'alice.vance@contoso.com'; guid = [guid]::NewGuid().ToString(); shared = $false; warning = '' }
    W (Join-Path $root 'scenario.json') ($(if ($Scenario -in 'single', 'rollback', 'check') { @($alice) + $objects } else { $objects }) | ConvertTo-Json -Depth 4)
    if ($Scenario -in 'single', 'scope') { foreach ($flag in 'entra', 'grant') { W (Join-Path $root "hold.$flag") 'hold' } }
    # A Convert batch (with its Active Directory proof) in the backup folder.
    $id = [guid]::NewGuid().ToString('N')
    $folder = Join-Path $root "Backups\Batch-$id"
    $rec = @{ObjectGuid = [guid]::NewGuid().ToString(); SamAccountName = 'alice.vance'; UserPrincipalName = 'alice.vance@contoso.com'; IsShared = $false }
    if ($Scenario -ne 'cloud') {
        J (Join-Path $folder 'Convert-LAB-fixture.json') @{SchemaVersion = 2; Operation = 'Convert'; Environment = 'LAB'; BatchId = $id; RunId = '20261104_091200-abc'; SourceBackupHash = ''; Records = @($rec) }
        W (Join-Path $folder 'raw.clixml') '<x/>'
        J (Join-Path $folder "State-$id.json") @{SchemaVersion = 2; Operation = 'Convert'; Kind = 'ADVerified'; Environment = 'LAB'; Records = @(@{ObjectGuid = $rec.ObjectGuid; ADVerified = $true }) }
    }
    if ($Scenario -eq 'cloud') {
        # The transfer package that the AD server wrote, waiting in the Inbox of the cloud server.
        $source = Join-Path $work "source\Batch-$id"
        J (Join-Path $source 'Convert-LAB-fixture.json') @{SchemaVersion = 2; Operation = 'Convert'; Environment = 'LAB'; BatchId = $id; RunId = '20261104_091200-abc'; SourceBackupHash = ''; Records = @($rec) }
        $filler = New-Object byte[] 18400000; [Random]::new(7).NextBytes($filler)
        $null = New-Item -ItemType Directory -Path $source -Force; [IO.File]::WriteAllBytes((Join-Path $source 'raw.clixml'), $filler)
        J (Join-Path $source "State-$id.json") @{SchemaVersion = 2; Operation = 'Convert'; Kind = 'ADVerified'; Environment = 'LAB'; Records = @(@{ObjectGuid = $rec.ObjectGuid; ADVerified = $true }) }
        $null = New-PraTransferPackage -Kind Convert -Environment 'LAB' -BatchId $id -Folders @($source) -OutboxFolder (Join-Path $root 'Backups\Inbox')
    }
    if ($Scenario -eq 'finalize') {
        # A Finalize folder, as the cloud server of a Recover leaves it for the AD server.
        $ffolder = Join-Path $root "Backups\Finalize-$id"
        $item = @{ObjectGuid = [guid]::NewGuid().ToString(); SamAccountName = 'finance.shared'; UserPrincipalName = 'finance.shared@contoso.com'; IsShared = $true }
        J (Join-Path $ffolder 'RecoverFinalize-fixture.json') @{SchemaVersion = 2; Operation = 'RecoverFinalize'; Environment = 'LAB'; BatchId = $id; SourceBackupHash = ''; Records = @($item); Items = @($item) }
    }

    $bothProbe = { param($r) [pscustomobject]@{ Lights = @(
                [ordered]@{Name = 'RSAT ActiveDirectory'; Status = 'Ok'; Detail = 'Installed, version 1.0.1.0.' }, [ordered]@{Name = 'ExchangeOnlineManagement'; Status = 'Ok'; Detail = 'Installed, version 3.10.0.' },
                [ordered]@{Name = 'Microsoft.Graph'; Status = 'Ok'; Detail = 'Installed, version 2.25.0.' }, [ordered]@{Name = 'Entra Connect sync'; Status = 'Ok'; Detail = 'The synchronisation is started on SRV-AADC01 (reachability is checked when the run starts).' },
                [ordered]@{Name = 'Sign-in: Interactive (WAM)'; Status = 'Ok'; Detail = 'A Microsoft sign-in window opens when the run starts.' }); AD = $true; Cloud = $true; Role = 'Both' } }
    $adProbe = { param($r) [pscustomobject]@{ Lights = @(
                [ordered]@{Name = 'RSAT ActiveDirectory'; Status = 'Ok'; Detail = 'Installed, version 1.0.1.0.' }, [ordered]@{Name = 'ExchangeOnlineManagement'; Status = 'Fail'; Detail = 'Not installed (version 3.10.0 or later needed): Install-Module ExchangeOnlineManagement.' },
                [ordered]@{Name = 'Microsoft.Graph'; Status = 'Fail'; Detail = 'Not installed (Authentication and Users): the cloud parts and Check cannot run on this server.' }, [ordered]@{Name = 'Entra Connect sync'; Status = 'Ok'; Detail = 'The synchronisation is started on SRV-AADC01 (reachability is checked when the run starts).' },
                [ordered]@{Name = 'Sign-in: Interactive (WAM)'; Status = 'Ok'; Detail = 'A Microsoft sign-in window opens when the run starts.' }); AD = $true; Cloud = $false; Role = 'AD' } }
    $cloudProbe = { param($r) [pscustomobject]@{ Lights = @(
                [ordered]@{Name = 'RSAT ActiveDirectory'; Status = 'Fail'; Detail = 'Not installed: the Active Directory parts cannot run on this server (install the RSAT feature Active Directory module).' }, [ordered]@{Name = 'ExchangeOnlineManagement'; Status = 'Ok'; Detail = 'Installed, version 3.10.0.' },
                [ordered]@{Name = 'Microsoft.Graph'; Status = 'Ok'; Detail = 'Installed, version 2.25.0.' }, [ordered]@{Name = 'Entra Connect sync'; Status = 'NA'; Detail = 'Not used: this server does not change Active Directory.' },
                [ordered]@{Name = 'Sign-in: Interactive (WAM)'; Status = 'Ok'; Detail = 'A Microsoft sign-in window opens when the run starts.' }); AD = $false; Cloud = $true; Role = 'Cloud' } }
    $probe = switch ($Scenario) { 'twoserver' { $adProbe } 'finalize' { $adProbe } 'cloud' { $cloudProbe } default { $bothProbe } }
    $identityProbe = { param($identity) [pscustomobject]@{ Success = $true; Found = $true; Count = 1; DisplayName = 'Alice Vance'; UserPrincipalName = 'alice.vance@contoso.com'; SamAccountName = 'alice.vance'; MailboxType = 'User mailbox' } }
    $toolVersion = [regex]::Match([IO.File]::ReadAllText((Join-Path $repo 'package\Invoke-PraRemoteMailbox.ps1')), '(?m)^\s*Version\s*:\s*(\d+\.\d+\.\d+)\s*$').Groups[1].Value
    $g = New-PraGuiWindow -Root $root -ConfigPath $config -Version $toolVersion -Theme $Theme -PrerequisiteProbe $probe -IdentityProbe $identityProbe

    function Pump($ms = 120) { $f = New-Object Windows.Threading.DispatcherFrame; $t = New-Object Windows.Threading.DispatcherTimer; $t.Interval = [timespan]::FromMilliseconds($ms); $t.Tag = $f; $t.Add_Tick({ param($s) $s.Tag.Continue = $false; $s.Stop() }); $t.Start(); [Windows.Threading.Dispatcher]::PushFrame($f) }
    $syntheticRoot = 'D:\PRA\PraRemoteMailbox'
    function Walk($element, [scriptblock]$visit) { & $visit $element; $n = [Windows.Media.VisualTreeHelper]::GetChildrenCount($element); for ($i = 0; $i -lt $n; $i++) { Walk ([Windows.Media.VisualTreeHelper]::GetChild($element, $i)) $visit } }
    function Mask($text) { if (-not $text) { return $text }; ([string]$text).Replace((Join-Path $root 'Backups'), 'D:\PRA\Backups').Replace($root, $syntheticRoot) }
    $leak = (@($real | ForEach-Object { [regex]::Escape($_) }) + @('REDMOND', 'DESKTOP-', 'C:\\Users', '\\AppData\\', 'scratchpad', 'Temp\\claude')) -join '|'
    $null = New-Item -ItemType Directory -Path $Shots -Force
    $theme = $Theme.ToLowerInvariant()
    function Get-Bounds($name) {
        $el = $g.Controls[$name]
        if (-not $el -or -not $el.IsVisible -or $el.ActualWidth -lt 2) { return $null }
        $t = $el.TransformToVisual($g.Controls.Root)
        return $t.TransformBounds([Windows.Rect]::new(0, 0, $el.ActualWidth, $el.ActualHeight))
    }
    function Shot([string]$name, [object[]]$Callouts = @(), [string]$CropTo = '', [int]$Height = 940) {
        $g.Form.Height = $Height; Pump; $g.Form.UpdateLayout(); Pump
        $bad = New-Object 'Collections.Generic.List[string]'
        Walk $g.Controls.Root { param($e)
            if ($e -is [Windows.Controls.TextBlock]) { $m = Mask $e.Text; if ($m -ne $e.Text) { $e.Text = $m }; if ($e.Text -match $leak) { $bad.Add($e.Text) } }
            elseif ($e -is [Windows.Controls.TextBox]) { $m = Mask $e.Text; if ($m -ne $e.Text) { $e.Text = $m }; if ($e.Text -match $leak) { $bad.Add($e.Text) } }
        }
        if ($bad.Count) { throw "Real value in the window ($name): $($bad[0])" }
        Pump; $g.Form.UpdateLayout(); Pump
        $el = $g.Controls.Root; $w = [int][Math]::Ceiling($el.ActualWidth); $h = [int][Math]::Ceiling($el.ActualHeight)
        $rtb = [Windows.Media.Imaging.RenderTargetBitmap]::new($w, $h, 96, 96, [Windows.Media.PixelFormats]::Pbgra32); $rtb.Render($el)
        $source = $rtb
        $boxes = @(foreach ($c in $Callouts) { $b = Get-Bounds $c[0]; if ($b) { [pscustomobject]@{ Bounds = $b; Text = [string]$c[1] } } })
        if ($boxes.Count) {
            $dv = [Windows.Media.DrawingVisual]::new(); $dc = $dv.RenderOpen()
            $dc.DrawImage($rtb, [Windows.Rect]::new(0, 0, $w, $h))
            $red = [Windows.Media.SolidColorBrush]::new([Windows.Media.Color]::FromRgb(0xE0, 0x24, 0x2E)); $pen = [Windows.Media.Pen]::new($red, 3)
            $white = [Windows.Media.Brushes]::White; $face = [Windows.Media.Typeface]::new('Segoe UI Semibold')
            foreach ($box in $boxes) {
                $b = $box.Bounds; $r = [Windows.Rect]::new($b.X - 3, $b.Y - 3, $b.Width + 6, $b.Height + 6)
                $dc.DrawRoundedRectangle($null, $pen, $r, 6, 6)
                $cx = [Math]::Max(14, $r.X); $cy = [Math]::Max(14, $r.Y)
                $dc.DrawEllipse($red, [Windows.Media.Pen]::new($white, 2), [Windows.Point]::new($cx, $cy), 13, 13)
                $label = [Windows.Media.FormattedText]::new($box.Text, [Globalization.CultureInfo]::InvariantCulture, [Windows.FlowDirection]::LeftToRight, $face, 16, $white, 1.0)
                $dc.DrawText($label, [Windows.Point]::new($cx - $label.Width / 2, $cy - $label.Height / 2))
            }
            $dc.Close()
            $source = [Windows.Media.Imaging.RenderTargetBitmap]::new($w, $h, 96, 96, [Windows.Media.PixelFormats]::Pbgra32); $source.Render($dv)
        }
        $frame = if ($CropTo) {
            $b = Get-Bounds $CropTo
            if (-not $b) { throw "Crop target not visible: $CropTo" }
            $x = [int][Math]::Max(0, $b.X - 20); $y = [int][Math]::Max(0, $b.Y - 20)
            $cw = [int][Math]::Min($w - $x, $b.Width + 40); $ch = [int][Math]::Min($h - $y, $b.Height + 40)
            [Windows.Media.Imaging.BitmapFrame]::Create([Windows.Media.Imaging.CroppedBitmap]::new($source, [Windows.Int32Rect]::new($x, $y, $cw, $ch)))
        } else { [Windows.Media.Imaging.BitmapFrame]::Create($source) }
        $png = [Windows.Media.Imaging.PngBitmapEncoder]::new(); $png.Frames.Add($frame)
        $file = Join-Path $Shots ("console-$name-$theme.png"); $fs = [IO.File]::Create($file); try { $png.Save($fs) } finally { $fs.Close() }
        "shot console-$name-$theme"
    }
    function Click($n) { $g.Controls[$n].RaiseEvent((New-Object Windows.RoutedEventArgs ([Windows.Controls.Button]::ClickEvent))) }
    function WaitRun { $d = [datetime]::UtcNow.AddSeconds(120); while ($g.Run -and [datetime]::UtcNow -lt $d) { Pump 100 }; if ($g.Run) { throw 'timeout' } }
    function WaitStep($stepId, $status) { $d = [datetime]::UtcNow.AddSeconds(60); while ([datetime]::UtcNow -lt $d) { Pump 150; $row = $g.Model.ById[$stepId]; if ($row -and $row.Status -eq $status) { return } }; throw "step $stepId never reached $status" }
    function Release($flag) { Remove-Item (Join-Path $root "hold.$flag") -ErrorAction SilentlyContinue }
    function GoToTask($tile) { Click 'BtnNext'; if ($g.Page -ne 2) { throw "not on page 2: $($g.Page) $($g.Controls.Footer.Text)" }; $g.Controls[$tile].IsChecked = $true; Pump }
    # Package checks and imports run in a child process (the window stays responsive): wait until none is running or queued.
    function WaitPackages { $d = [datetime]::UtcNow.AddSeconds(180); Pump 200; while (($g.PkgJob -or $g.PkgQueue.Count) -and [datetime]::UtcNow -lt $d) { Pump 200 }; if ($g.PkgJob -or $g.PkgQueue.Count) { throw 'package check timeout' }; Pump 300 }
    function PreviewThenConfirm($word) {
        Click 'BtnNext'; WaitPackages
        if ($g.Page -ne 3) { throw "not on page 3: $($g.Page) $($g.Controls.TaskError.Text) $($g.Controls.Footer.Text)" }
    }
    $g.Form.Show(); Pump 300
    $c = $g.Controls
    $word = 'convert'
    switch ($Scenario) {
        'single' {
            Shot 'setup' @(, @('Lights', '1')) ; Shot 'setup-lights' -CropTo 'Lights'
            Click 'BtnChange'; Pump; Shot 'settings' @(, @('SettingsCard', '1')); Click 'BtnDoneSettings'
            Shot 'setup-next' @(, @('BtnNext', '1'))
            GoToTask 'T_Convert'
            Shot 'task' @(@('T_Convert', '1'), @('S_Source_Single', '2'))
            $c.F_Identity.Text = 'alice.vance@contoso.com'; Pump
            Click 'BtnCheckIdentity'; Pump
            Shot 'task-identity' @(@('F_Identity', '1'), @('BtnCheckIdentity', '2'), @('PhasePill', '3'), @('BtnNext', '4'))
            PreviewThenConfirm $word
            Shot 'verify-before' @(, @('BtnPreview', '1'))
            Click 'BtnPreview'; Pump 600; WaitRun; Pump
            if (-not $g.Pending) { throw "no pending: $($c.SumText.Text) $($g.PreviewError)" }
            $c.ConfirmBox.Text = $word; Pump
            Shot 'verify' @(@('ConfirmBox', '1'), @('BtnNext', '2'))
            if (-not $c.BtnNext.IsEnabled) { throw 'Run not enabled' }
            Click 'BtnNext'; Pump 1200
            Shot 'run-early'
            WaitStep 's5' 'Wait'; Pump 400
            $c.StepList.SelectedIndex = 4; Pump
            Shot 'run-waiting' @(, @('StepList', '1'))
            Release 'entra'; Release 'grant'
            WaitRun; Pump
            $c.StepList.SelectedIndex = 3; Pump; $c.DetObjList.SelectedIndex = 0; Pump
            Shot 'run-finished' @(, @('BtnNext', '1'))
            Click 'BtnNext'; Pump; Shot 'next' @(@('BtnReport', '1'), @('BtnLog', '2'))
        }
        'scope' {
            GoToTask 'T_Convert'
            $c.S_Source_Scope.IsChecked = $true; Pump
            Shot 'task-scope' @(, @('S_Source_Scope', '1'))
            PreviewThenConfirm $word
            Click 'BtnPreview'; Pump 600; WaitRun; Pump
            if (-not $g.Pending) { throw "no pending: $($c.SumText.Text) $($g.PreviewError)" }
            $c.ConfirmBox.Text = $word; Pump
            Shot 'verify-scope' @(@('VerList', '1'), @('ConfirmBox', '2'))
            Click 'BtnNext'; Pump 1200
            Release 'entra'
            WaitStep 's6' 'Wait'; Pump 400
            $c.StepList.SelectedIndex = 5; Pump
            Shot 'run-grant'
            Release 'grant'
            WaitRun; Pump
            $c.StepList.SelectedIndex = 1; Pump; $c.DetObjList.SelectedIndex = 5; Pump
            Shot 'run-finished-scope'
            Click 'BtnNext'; Pump; Shot 'next-global' @(, @('BtnReport', '1'))
        }
        'twoserver' {
            Shot 'setup-red' @(, @('Lights', '1')); Shot 'setup-red-lights' -CropTo 'Lights'
            GoToTask 'T_Convert'
            $c.S_Source_Scope.IsChecked = $true; Pump
            Shot 'task-ad' @(, @('PhasePill', '1'))
            PreviewThenConfirm $word
            Click 'BtnPreview'; Pump 600; WaitRun; Pump
            if (-not $g.Pending) { throw "no pending: $($c.SumText.Text) $($g.PreviewError)" }
            $c.ConfirmBox.Text = $word; Pump
            Shot 'verify-ad'
            Click 'BtnNext'; Pump 1200
            WaitRun; Pump
            $c.StepList.SelectedIndex = 4; Pump
            Shot 'run-package'
            Click 'BtnNext'; Pump; Shot 'next-package' @(@('PkgName', '1'), @('BtnOpenFolder', '2'), @('NextCmdBox', '3'))
        }
        'cloud' {
            GoToTask 'T_Convert'
            $c.Mode_Continue.IsChecked = $true; Pump; WaitPackages
            Shot 'task-continue' @(@('Mode_Continue', '1'), @('BtnImport', '2'), @('BatchList', '3'))
            if (@($g.BatchRows).Count -gt 0) { $c.BatchList.SelectedIndex = 0; Pump }
            Shot 'task-package-selected' @(@('BatchList', '1'), @('PhasePill', '2'), @('BtnNext', '3'))
            PreviewThenConfirm $word
            Click 'BtnPreview'; Pump 600; WaitRun; Pump
            if (-not $g.Pending) { throw "no pending: $($c.SumText.Text) $($g.PreviewError)" }
            $c.ConfirmBox.Text = $word; Pump
            Shot 'verify-cloud' @(, @('ConfirmBox', '1'))
            Click 'BtnNext'; Pump 1200
            WaitRun; Pump
            Shot 'run-cloud'
            Click 'BtnNext'; Pump; Shot 'next-cloud' @(, @('BtnReport', '1'))
        }
        'rollback' {
            GoToTask 'T_Recover'
            Shot 'task-rollback' @(@('T_Recover', '1'), @('BatchList', '2'))
            if (@($g.BatchRows).Count -gt 0) { $c.BatchList.SelectedIndex = 0; Pump }
            Shot 'task-rollback-selected' @(@('BatchList', '1'), @('BtnNext', '2'))
            PreviewThenConfirm 'recover'
            Click 'BtnPreview'; Pump 600; WaitRun; Pump
            if (-not $g.Pending) { throw "no pending: $($c.SumText.Text) $($g.PreviewError)" }
            $c.ConfirmBox.Text = 'recover'; Pump
            Shot 'verify-rollback' @(, @('ConfirmBox', '1'))
            Click 'BtnNext'; Pump 1200
            WaitRun; Pump
            Shot 'run-rollback'
            Click 'BtnNext'; Pump; Shot 'next-rollback' @(, @('BtnReport', '1'))
        }
        'finalize' {
            GoToTask 'T_Finalize'
            if (@($g.BatchRows).Count -gt 0) { $c.BatchList.SelectedIndex = 0; Pump }
            Shot 'task-finalize' @(@('T_Finalize', '1'), @('BatchList', '2'), @('BtnNext', '3'))
            # The Verify, Run and Next steps pages of a Finalize. They are photographed here but not copied to docs\images by New-DocumentationImages.ps1:
            # a new picture needs its name in the signed integrity verifier (package\module\Test-PackageIntegrity.ps1) first.
            PreviewThenConfirm 'finalize'
            Click 'BtnPreview'; Pump 600; WaitRun; Pump
            if (-not $g.Pending) { throw "no pending: $($c.SumText.Text) $($g.PreviewError)" }
            $c.ConfirmBox.Text = 'finalize'; Pump
            Shot 'verify-finalize' @(@('ConfirmBox', '1'), @('BtnNext', '2'))
            Click 'BtnNext'; Pump 1200
            WaitRun; Pump
            Shot 'run-finalize'
            Click 'BtnNext'; Pump; Shot 'next-finalize' @(, @('BtnReport', '1'))
        }
        'check' {
            GoToTask 'T_Check'
            $c.F_CheckUpn.Text = 'alice.vance@contoso.com'; Pump
            Shot 'task-check' @(@('T_Check', '1'), @('F_CheckUpn', '2'), @('BtnNext', '3'))
            Click 'BtnNext'; Pump
            if ($g.Page -eq 3) { Click 'BtnPreview'; Pump 600; WaitRun; Pump }
            Shot 'verify-check'
        }
    }
    'SHOTS-OK'
    $g.Form.Close()
}
finally {
    if (Test-Path $work) { Remove-Item $work -Recurse -Force -ErrorAction SilentlyContinue }
}
