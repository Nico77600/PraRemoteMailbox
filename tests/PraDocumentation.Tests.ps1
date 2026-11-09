<#
.SYNOPSIS
    Documentation tests for PRA Remote Mailbox 3.1.2 (offline; reads the repository files only: no AD, Exchange, Graph or network).
.DESCRIPTION
    Keeps the README, the user guide and the reference guide honest:
      - every picture they use exists, has an alternative text, is in the integrity inventory, and no picture is left unused;
      - no real machine name, user name or local path appears in the documents;
      - the Microsoft Graph scope written in the guide is the one that the code requests, and every cloud and directory cmdlet that the code
        calls is named in the permissions chapter (so the permission list cannot drift from the code);
      - the links between the documents resolve, the versions agree;
      - the "Start here" part of the user guide keeps short sentences and common words (a simple readability measure).
.NOTES
    Author  : Nicolas Fabert
    Version : 3.1.2
#>
#Requires -Version 7.5

BeforeAll {
    . (Join-Path $PSScriptRoot 'IntegrityFixture.ps1')
    $script:Repo =[IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
    $script:Docs = Join-Path $script:Repo 'package\docs'
    $script:Images = Join-Path $script:Docs 'images'
    function script:Read-Doc([string]$Relative) { [IO.File]::ReadAllText((Join-Path $script:Repo $Relative)) -replace "`r`n", "`n" }
    $script:Readme = Read-Doc 'README.md'
    $script:PackageReadme = Read-Doc 'package\README.md'
    $script:UserGuide = Read-Doc 'package\docs\PraRemoteMailbox-UserGuide.md'
    $script:Guide = Read-Doc 'package\docs\PraRemoteMailbox-Guide.md'
    $script:Cloud = Read-Doc 'package\module\PRA.Cloud.psm1'
    $script:Directory = Read-Doc 'package\module\PRA.Directory.psm1'
    $script:Documents = [ordered]@{ 'README.md' = $script:Readme; 'package\README.md' = $script:PackageReadme; 'UserGuide' = $script:UserGuide; 'Guide' = $script:Guide }
    function script:Get-ImageReferences([string]$Text, [string]$Base) {
        # Markdown images and the src / srcset of HTML pictures, resolved against the folder of the document.
        $found = New-Object 'Collections.Generic.List[string]'
        foreach ($m in [regex]::Matches($Text, '!\[[^\]]*\]\(([^)\s]+)\)')) { $found.Add($m.Groups[1].Value) }
        foreach ($m in [regex]::Matches($Text, '(?:src|srcset)="([^"]+\.png)(?:\?[^"]*)?"')) { $found.Add($m.Groups[1].Value) }
        foreach ($f in $found) { [IO.Path]::GetFullPath((Join-Path $Base ($f -replace '/', '\'))) }
    }
    function script:Get-Slug([string]$Heading) {
        $s = $Heading.ToLowerInvariant() -replace '[^\p{L}\p{N}\s_-]', ''
        return ($s.Trim() -replace '\s', '-')
    }
    function script:Get-ProseSentences([string]$Markdown, [bool]$Tables) {
        $text = $Markdown -replace "`r`n", "`n"
        $text = [regex]::Replace($text, '(?s)^---\n.*?\n---\n', '')
        $text = [regex]::Replace($text, '(?s)```.*?```', '')
        $lines = foreach ($l in ($text -split "`n")) {
            $x = $l.Trim()
            if (-not $x) { continue }
            if ($x.StartsWith('|')) {
                if (-not $Tables -or $x -match '^\|[-| :]+\|$') { continue }
                $x = (($x.Trim('|') -split '\|' | ForEach-Object { $_.Trim() }) -join '. ')
            }
            if ($x.StartsWith('#') -or $x.StartsWith('!') -or $x.StartsWith('<!--')) { continue }
            $x = $x -replace '^(>\s*)+', '' -replace '^\[!\w+\]\s*$', '' -replace '^[-*]\s+(\[[ x]\]\s+)?', '' -replace '^\d+\.\s+', ''
            $x = [regex]::Replace($x, '\[([^\]]*)\]\([^)]*\)', '$1')
            $x = [regex]::Replace($x, '`[^`]*`', 'CODE')
            $x = $x -replace '\*\*|__|\*', ''
            if ($x.Trim()) { $x }
        }
        foreach ($l in $lines) { foreach ($s in [regex]::Split($l, '(?<=[.!?:])\s+')) { $s = $s.Trim(); if ($s -match '\w') { $s } } }
    }
    function script:Get-Readability([string]$Markdown, [bool]$Tables = $false) {
        $sentences = @(Get-ProseSentences $Markdown $Tables)
        $counts = @($sentences | ForEach-Object { @($_ -split '\s+' | Where-Object { $_ -match '\w' }).Count })
        $words = @($sentences | ForEach-Object { $_ -split '\s+' | Where-Object { $_ -match '\w' } })
        $syllables = 0
        foreach ($w in $words) {
            $x = $w.ToLowerInvariant() -replace '[^a-z]', ''
            if ($x.Length -le 3) { $syllables++; continue }
            $x = $x -replace '(?:[^laeiouy]es|ed|[^laeiouy]e)$', '' -replace '^y', ''
            $syllables += [Math]::Max(1, ([regex]::Matches($x, '[aeiouy]{1,2}')).Count)
        }
        [pscustomobject]@{
            Sentences = $sentences.Count; Words = $words.Count; Average = ($counts | Measure-Object -Average).Average
            Over20 = @($counts | Where-Object { $_ -gt 20 }).Count; Over25 = @($counts | Where-Object { $_ -gt 25 }).Count
            FleschReadingEase = 206.835 - 1.015 * ($words.Count / $sentences.Count) - 84.6 * ($syllables / $words.Count)
        }
    }
}

Describe 'Pictures' {
    It 'every picture used by the README and the guides exists' {
        $missing = foreach ($entry in @(
                @{ Text = $script:Readme; Base = $script:Repo }, @{ Text = $script:PackageReadme; Base = (Join-Path $script:Repo 'package') }
                @{ Text = $script:UserGuide; Base = $script:Docs }, @{ Text = $script:Guide; Base = $script:Docs })) {
            foreach ($path in @(Get-ImageReferences $entry.Text $entry.Base)) { if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { $path } }
        }
        @($missing) | Should -BeNullOrEmpty
    }
    It 'no picture of docs\images is left unused' {
        $used = New-Object 'Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
        foreach ($entry in @(
                @{ Text = $script:Readme; Base = $script:Repo }, @{ Text = $script:UserGuide; Base = $script:Docs }, @{ Text = $script:Guide; Base = $script:Docs })) {
            foreach ($path in @(Get-ImageReferences $entry.Text $entry.Base)) { [void]$used.Add($path) }
        }
        $orphans = @(Get-ChildItem -LiteralPath $script:Images -Filter '*.png' | Where-Object { -not $used.Contains($_.FullName) } | ForEach-Object Name)
        $orphans | Should -BeNullOrEmpty
    }
    It 'the pictures of docs\images are exactly the ones of the integrity inventory (verifier, fixture)' {
        $onDisk = @(Get-ChildItem -LiteralPath $script:Images -Filter '*.png' | ForEach-Object { 'docs\images\' + $_.Name } | Sort-Object { $_ } -CaseSensitive)
        $fixture = @(Get-PraExpectedInventory | Where-Object { $_ -like 'docs\images\*' } | Sort-Object { $_ } -CaseSensitive)
        $verifier = @([regex]::Matches((Read-Doc 'package\module\Test-PackageIntegrity.ps1'), "(?m)^\s*'(docs\\images\\[^']+)'") | ForEach-Object { $_.Groups[1].Value } | Sort-Object { $_ } -CaseSensitive)
        $manifest = @([regex]::Matches((Read-Doc 'package\PackageIntegrity.psd1'), "Path = '(docs\\images\\[^']+)'") | ForEach-Object { $_.Groups[1].Value } | Sort-Object { $_ } -CaseSensitive)
        ($fixture -join '|') | Should -BeExactly ($onDisk -join '|')
        ($verifier -join '|') | Should -BeExactly ($onDisk -join '|')
        ($manifest -join '|') | Should -BeExactly ($onDisk -join '|')
    }
    It 'every picture of a document has an alternative text' {
        foreach ($name in $script:Documents.Keys) {
            $text = $script:Documents[$name]
            @([regex]::Matches($text, '!\[\s*\]\(')).Count | Should -Be 0 -Because "$name has a markdown picture without alternative text"
            foreach ($m in [regex]::Matches($text, '<img\b[^>]*>')) { $m.Value | Should -Match 'alt="[^"]{8,}"' -Because "$name has an <img> without alternative text" }
        }
    }
    It 'every light picture of the README picture elements has its dark twin' {
        foreach ($m in [regex]::Matches($script:Readme, 'srcset="(package/docs/images/[^"]+)-dark\.png"')) {
            Test-Path -LiteralPath (Join-Path $script:Repo (($m.Groups[1].Value + '-light.png') -replace '/', '\')) | Should -BeTrue -Because $m.Groups[1].Value
        }
    }
    It 'the README uses at least the numbered path, the transfer diagram and the console pages (pictures everywhere the operator acts)' {
        foreach ($name in 'readme-path', 'readme-transfer', 'readme-why', 'console-setup', 'console-task', 'console-verify', 'console-next') { $script:Readme | Should -Match $name }
        @(Get-ImageReferences $script:UserGuide $script:Docs).Count | Should -BeGreaterThan 30
    }
}

Describe 'No private name in the documents' {
    It 'no real machine, user name or local path in <Name>' -ForEach @(
        @{ Name = 'README'; Path = 'README.md' }, @{ Name = 'package README'; Path = 'package\README.md' }, @{ Name = 'user guide'; Path = 'package\docs\PraRemoteMailbox-UserGuide.md' }
        @{ Name = 'reference guide'; Path = 'package\docs\PraRemoteMailbox-Guide.md' }, @{ Name = 'CHANGELOG'; Path = 'CHANGELOG.md' }
        @{ Name = 'user guide HTML'; Path = 'package\docs\PraRemoteMailbox-UserGuide.html' }, @{ Name = 'reference guide HTML'; Path = 'package\docs\PraRemoteMailbox-Guide.html' }
    ) {
        $text = Read-Doc $Path
        $text = [regex]::Replace($text, 'data:image/png;base64,[A-Za-z0-9+/=]+', 'data:image')
        $text | Should -Not -Match '(?i)nfabert|REDMOND|DESKTOP-[A-Z0-9]|C:\\Users\\|\\AppData\\|scratchpad|Temp\\claude'
    }
}

Describe 'Versions and links' {
    It 'the two guides carry the version of the tool' {
        $version = [regex]::Match((Read-Doc 'package\Invoke-PraRemoteMailbox.ps1'), '(?m)^\s*Version\s*:\s*(\d+\.\d+\.\d+)\s*$').Groups[1].Value
        $version | Should -Match '^\d+\.\d+\.\d+$'
        foreach ($guide in $script:UserGuide, $script:Guide) { [regex]::Match($guide, '(?m)^version:\s*(\S+)').Groups[1].Value | Should -BeExactly $version }
    }
    It 'the relative links between the documents resolve, with their heading anchor' {
        $problems = foreach ($entry in @(
                @{ Name = 'README.md'; Text = $script:Readme; Base = $script:Repo }, @{ Name = 'user guide'; Text = $script:UserGuide; Base = $script:Docs }
                @{ Name = 'reference guide'; Text = $script:Guide; Base = $script:Docs }, @{ Name = 'package README'; Text = $script:PackageReadme; Base = (Join-Path $script:Repo 'package') })) {
            foreach ($m in [regex]::Matches($entry.Text, '(?<!\!)\[[^\]]+\]\((?!https?:|mailto:)([^)#\s]*)(?:#([^)\s]*))?\)')) {
                $file = if ($m.Groups[1].Value) { [IO.Path]::GetFullPath((Join-Path $entry.Base ($m.Groups[1].Value -replace '/', '\'))) } else { $null }
                if ($file -and -not (Test-Path -LiteralPath $file)) { "$($entry.Name): missing file $($m.Groups[1].Value)"; continue }
                $anchor = $m.Groups[2].Value
                if ($anchor) {
                    $target = if ($file) { Read-Doc ($file.Substring($script:Repo.Length + 1)) } else { $entry.Text }
                    $slugs = @([regex]::Matches($target, '(?m)^#{1,6}\s+(.+)$') | ForEach-Object { Get-Slug $_.Groups[1].Value })
                    $stripped = @($slugs | ForEach-Object { $_ -replace '^\d+-', '' -replace '-{2,}', '-' })
                    if (($anchor -notin $slugs) -and ($anchor -notin $stripped)) { "$($entry.Name): no heading for #$anchor in $($m.Groups[1].Value)" }
                }
            }
        }
        @($problems) | Should -BeNullOrEmpty
    }
    It 'the README, the package README and the reference guide point to the user guide, and the user guide to the reference guide' {
        $script:Readme | Should -Match 'PraRemoteMailbox-UserGuide\.md'
        $script:PackageReadme | Should -Match 'PraRemoteMailbox-UserGuide\.md'
        $script:Guide | Should -Match 'PraRemoteMailbox-UserGuide\.md'
        $script:UserGuide | Should -Match 'PraRemoteMailbox-Guide\.md'
    }
    It 'the user guide has the guided path block and the Stop and ask box; the guides build into HTML with the path' {
        $script:UserGuide | Should -Match '(?m)^```path$'
        $script:UserGuide | Should -Match '\*\*Stop and ask\.\*\*'
        (Read-Doc 'package\docs\PraRemoteMailbox-UserGuide.html') | Should -Match '<!--path-->'
    }
}

Describe 'Links and wording of the guides' {
    BeforeAll {
        function script:Read-GuideHtml([string]$Name) { [regex]::Replace((Read-Doc "package\docs\$Name.html"), 'data:image/png;base64,[A-Za-z0-9+/=]+', 'data:image') }
        $script:Html = [ordered]@{ 'PraRemoteMailbox-UserGuide' = (Read-GuideHtml 'PraRemoteMailbox-UserGuide'); 'PraRemoteMailbox-Guide' = (Read-GuideHtml 'PraRemoteMailbox-Guide') }
    }
    It 'every link of the two HTML guides leads somewhere: the file is next to it and the anchor is an id of the target page' {
        $problems = foreach ($name in $script:Html.Keys) {
            foreach ($m in [regex]::Matches($script:Html[$name], '<a [^>]*href="([^"]*)"')) {
                $href = $m.Groups[1].Value
                if ($href -match '^(https?:|mailto:)') { continue }
                $file, $anchor = $href -split '#', 2
                $target = if ($file) { Join-Path $script:Docs $file } else { Join-Path $script:Docs "$name.html" }
                if (-not (Test-Path -LiteralPath $target -PathType Leaf)) { "${name}: missing file $href"; continue }
                if ($anchor) {
                    $page = if ($file) { Read-GuideHtml ([IO.Path]::GetFileNameWithoutExtension($file)) } else { $script:Html[$name] }
                    if ($page -notmatch ('\sid="' + [regex]::Escape($anchor) + '"')) { "${name}: no id for $href" }
                }
            }
        }
        @($problems) | Should -BeNullOrEmpty
    }
    It 'the HTML guides have no picture without a source (the zoom window creates its picture when it opens)' {
        foreach ($name in $script:Html.Keys) { @([regex]::Matches($script:Html[$name], '<img\b(?![^>]*\ssrc="[^"]+")[^>]*>')).Count | Should -Be 0 -Because "$name has an <img> without src" }
    }
    It 'the guided path is drawn once in the HTML user guide (the picture that follows the path block is for Markdown readers only)' {
        @([regex]::Matches($script:Html['PraRemoteMailbox-UserGuide'], '<!--path-->')).Count | Should -Be 1
        $script:Html['PraRemoteMailbox-UserGuide'] | Should -Not -Match '<figcaption>The path\.'
        $script:UserGuide | Should -Match 'images/readme-path-light\.png'
    }
    It 'every mention of a chapter or an annex is a link, in both guides' {
        foreach ($entry in @(@{ Name = 'user guide'; Text = $script:UserGuide }, @{ Name = 'reference guide'; Text = $script:Guide })) {
            $text = [regex]::Replace($entry.Text, '(?s)^---\n.*?\n---\n', '')
            $text = [regex]::Replace($text, '(?s)```.*?```', '')
            $text = [regex]::Replace($text, '(?m)^#{1,6}\s.*$', '')
            $text = [regex]::Replace($text, '\[[^\]]*\]\([^)]*\)', '')
            $text = [regex]::Replace($text, '`[^`]*`', '')
            @([regex]::Matches($text, '(?i)\b(?:chapter \d+|annex [A-F])\b') | ForEach-Object { $_.Value }) | Should -BeNullOrEmpty -Because "$($entry.Name) names a chapter or an annex without a link"
        }
    }
    It 'every mention of the reference guide in the user guide names its file' {
        $script:UserGuide | Should -Match 'PraRemoteMailbox-Guide\.html'
        foreach ($m in [regex]::Matches($script:UserGuide, '\[reference guide[^\]]*\]\(PraRemoteMailbox-Guide\.md[^)]*\)')) {
            $after = $script:UserGuide.Substring($m.Index + $m.Length, [Math]::Min(120, $script:UserGuide.Length - $m.Index - $m.Length))
            $before = $script:UserGuide.Substring([Math]::Max(0, $m.Index - 120), [Math]::Min(120, $m.Index))
            (($before + $after) -match 'PraRemoteMailbox-Guide\.html') | Should -BeTrue -Because "the file is not named near: $($m.Value)"
        }
    }
    It 'the user guide explains the two servers before it uses their names: the cloud server is a machine of the company, not a server in the cloud' {
        $first = [regex]::Match($script:UserGuide, '(?i)cloud server').Index
        $script:UserGuide.Substring($first - 2, 40) | Should -Match '\*\*Cloud server\*\*'
        $first = [regex]::Match($script:UserGuide, '(?i)directory server').Index
        $script:UserGuide.Substring($first - 2, 40) | Should -Match '\*\*Directory server\*\*'
        $script:UserGuide | Should -Match '(?s)### Which path is mine\?.*not\*\* a server in the cloud'
        $script:UserGuide | Should -Match '\| \*\*Cloud server\*\* \| Any Windows machine of your company'
        $script:Guide | Should -Match 'not a machine hosted in the cloud'
        $script:Readme | Should -Match 'not a server hosted in the cloud'
    }
    It 'the user guide says where the phase is on the Task page, and which server each rollback part runs on' {
        $script:UserGuide | Should -Match 'What will happen on this server'
        $script:UserGuide | Should -Match '(?s)pink pill.*Phase: Cloud'
        $script:UserGuide | Should -Match '\*\*Where do I do this\?\*\*'
        $script:UserGuide | Should -Match 'column \*\*TYPE\*\*'
    }
    It 'the transfer package name pattern of the guide is the one of the code' {
        $name = [regex]::Match($script:UserGuide, '`(PRA-PROD-Convert-490cc62e-for-Cloud\.zip)`').Groups[1].Value
        $name | Should -Not -BeNullOrEmpty
        (Read-Doc 'package\module\PRA.Common.psm1') | Should -Match ([regex]::Escape("'PRA-{0}-{1}-{2}-for-{3}.zip'"))
        $script:UserGuide | Should -Match 'You never rename the file'
    }
}

Describe 'Minimum permissions follow the code' {
    It 'the Graph scopes of the guide are exactly the delegated scopes that the code requests' {
        $code = @([regex]::Matches($script:Cloud, '\$connect\.Scopes\s*=\s*@\(([^)]*)\)') | ForEach-Object { [regex]::Matches($_.Groups[1].Value, "'([^']+)'") | ForEach-Object { $_.Groups[1].Value } } | Sort-Object -Unique)
        $code.Count | Should -BeGreaterThan 0
        $row = @($script:Guide -split "`n" | Where-Object { $_.StartsWith('| **Delegated scopes requested by the code**') })
        $row.Count | Should -Be 1
        $documented = @([regex]::Matches($row[0], '`([A-Za-z]+(?:\.[A-Za-z]+)+)`') | ForEach-Object { $_.Groups[1].Value } | Sort-Object -Unique)
        ($documented -join ',') | Should -BeExactly ($code -join ',')
    }
    It 'the certificate sign-in of the code requests no scope (the application permissions are the ones of the guide)' {
        $script:Cloud | Should -Match '\$connect\.ClientId=\$app; \$connect\.CertificateThumbprint=\$thumb'
        $script:Guide | Should -Match '\| \*\*Application permissions\*\* \| none \| `User\.Read\.All` \(Microsoft Graph, type \*Application\*\) \|'
        $script:Guide | Should -Match 'Exchange\.ManageAsApp'
    }
    It 'every Graph scope or permission named in a document is the one of the code, or Exchange.ManageAsApp' {
        $code = @([regex]::Matches($script:Cloud, '\$connect\.Scopes\s*=\s*@\(([^)]*)\)') | ForEach-Object { [regex]::Matches($_.Groups[1].Value, "'([^']+)'") | ForEach-Object { $_.Groups[1].Value } })
        foreach ($name in $script:Documents.Keys) {
            foreach ($m in [regex]::Matches($script:Documents[$name], '\b[A-Z][A-Za-z]+\.(?:Read|ReadWrite|ReadBasic)(?:\.[A-Za-z]+)?\b')) {
                $m.Value | Should -BeIn $code -Because "$name names a Graph permission that the code does not request"
            }
        }
    }
    It 'every cloud and directory cmdlet that the code calls is named in the permissions chapter of the reference guide' {
        $start = $script:Guide.IndexOf("`n### Permissions`n"); $end = $script:Guide.IndexOf("`n## 5. Installation")
        $start | Should -BeGreaterThan 0; $end | Should -BeGreaterThan $start
        $chapter = $script:Guide.Substring($start, $end - $start)
        $names = New-Object 'Collections.Generic.HashSet[string]'
        foreach ($m in [regex]::Matches($script:Cloud, '\b(?:Get-EXO[A-Za-z]+|Add-MailboxPermission|Add-RecipientPermission|Set-Mailbox|Get-Mailbox|Get-MgUser(?:LicenseDetail)?|Get-RetentionCompliancePolicy|Connect-IPPSSession)\b')) { [void]$names.Add($m.Value) }
        foreach ($m in [regex]::Matches($script:Directory + (Read-Doc 'package\module\PRA.Gui.Directory.ps1'), '\b(?:Get|Set|Add|Remove|Sync)-AD[A-Za-z]+\b|\bStart-ADSyncSyncCycle\b')) { [void]$names.Add($m.Value) }
        $names.Count | Should -BeGreaterThan 20
        $missing = @($names | Where-Object { -not $chapter.Contains($_) })
        $missing | Should -BeNullOrEmpty
    }
    It 'every attribute that the code writes in Active Directory is named in the permissions chapter' {
        $block = [regex]::Match($script:Directory, '(?s)\$script:AttributeKinds = \[ordered\]@\{(.*?)\n\}').Groups[1].Value
        $attributes = @([regex]::Matches($block, '(\w+)=''') | ForEach-Object { $_.Groups[1].Value })
        $attributes.Count | Should -Be 10
        $start = $script:Guide.IndexOf("`n### Permissions`n"); $end = $script:Guide.IndexOf("`n## 5. Installation")
        $chapter = $script:Guide.Substring($start, $end - $start)
        foreach ($a in $attributes) { $chapter | Should -Match ('`' + $a + '`') -Because "$a is written by the code" }
    }
}

Describe 'Readability of the user guide' {
    It 'the Start here part keeps short sentences and common words' {
        $a = $script:UserGuide.IndexOf('## 1. Start here'); $b = $script:UserGuide.IndexOf('## 3. Set up once')
        $r = Get-Readability $script:UserGuide.Substring($a, $b - $a)
        $r.Average | Should -BeLessThan 12
        $r.Over20 | Should -Be 0
        $r.FleschReadingEase | Should -BeGreaterThan 80
    }
    It 'the whole user guide, tables included, has no sentence over 25 words and stays easy to read' {
        $r = Get-Readability $script:UserGuide $true
        $r.Over25 | Should -Be 0
        $r.Average | Should -BeLessThan 12
        $r.FleschReadingEase | Should -BeGreaterThan 75
    }
    It 'names the buttons of the console exactly (bold)' {
        foreach ($button in 'Choose a task', 'Continue to verification', 'Preview', 'Convert the mailboxes', 'Roll back the mailboxes', 'Finalize the rollback', 'Check the mailbox', 'Import package', 'Open report', 'Open folder', 'Check again', 'What next?') {
            $script:UserGuide | Should -Match ('\*\*' + [regex]::Escape($button)) -Because "the button $button must be named like in the console"
        }
    }
}
