<#
.SYNOPSIS
    High-volume HTML report tests for PRA Remote Mailbox 2.2.0 (offline; synthetic data only: no AD, Exchange, Graph or network).
.DESCRIPTION
    Report-only evidence: the real Write-PraReport / Write-PraReportHtml of a fixture copy of the package write the
    reports of synthetic runs (up to 100,000 rows), and the compressed data is decoded exactly like the page does and
    compared with the outcome. Browser behaviour (virtual grid, filters, export) is measured separately in a real
    browser; these tests never claim it. Set PRA_REPORT_EVIDENCE to a folder to keep the generated reports and the
    measured generation times (they are measurements, not gates).
.NOTES
    Author  : Nicolas Fabert
    Version : 2.2.0
#>
#Requires -Version 5.1

BeforeAll {
    . (Join-Path $PSScriptRoot 'IntegrityFixture.ps1')
    . (Join-Path $PSScriptRoot 'ReportFixture.ps1')
    $script:Repo = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
    $script:Work = Join-Path ([IO.Path]::GetTempPath()) ('PR-' + [guid]::NewGuid().ToString('N').Substring(0, 8))
    $null = New-Item -ItemType Directory -Path $script:Work -Force
    $script:Package = Join-Path $script:Work 'package'
    New-PraIntegrityFixture -SourcePackage (Join-Path $script:Repo 'package') -Destination $script:Package -Changelog (Join-Path $script:Repo 'CHANGELOG.md')
    Get-Module PRA.* | Remove-Module -Force -ErrorAction SilentlyContinue
    Import-Module (Join-Path $script:Package 'module\PRA.Common.psm1') -Force -Global
    $script:Evidence = $env:PRA_REPORT_EVIDENCE
    $script:Measurements = @()
    function script:Get-Decoded($Data, [string]$Kind, [int]$Field, [int]$Index) { $ds = $Data.Data[$Kind]; return $ds.Dict[$Field][$ds.Cols[$Field][$Index]] }
    function script:Compare-Rows($Decoded, $Outcome, [int[]]$Indexes) {
        $ds = $Decoded.Data.rows; $names = $ds.Fields; $bad = New-Object 'Collections.Generic.List[string]'
        foreach ($i in $Indexes) {
            for ($f = 0; $f -lt $names.Count; $f++) {
                $expected = $Outcome.Rows[$i].($names[$f]); $actual = $ds.Dict[$f][$ds.Cols[$f][$i]]
                $same = if ($null -eq $expected) { $null -eq $actual } elseif ($expected -is [bool]) { ($actual -is [bool]) -and $actual -eq $expected } else { ($actual -is [string]) -and $actual -ceq [string]$expected }
                if (-not $same) { $bad.Add(('row {0} {1}: expected [{2}] got [{3}]' -f $i, $names[$f], $expected, $actual)) }
            }
        }
        return , $bad
    }
}

AfterAll {
    Remove-Module PRA.Common -Force -ErrorAction SilentlyContinue
    if ($script:Work -and (Test-Path -LiteralPath $script:Work)) { Remove-Item -LiteralPath $script:Work -Recurse -Force -ErrorAction SilentlyContinue }
}

Describe 'Report template (static)' {
    BeforeAll { $script:Template = [IO.File]::ReadAllText((Join-Path $script:Repo 'package\templates\Report.template.html'), [Text.Encoding]::UTF8) }
    It 'is offline: no external resource, request or telemetry call' {
        $script:Template | Should -Not -Match '(?i)https?://|<link\b|\bsrc\s*=|@import|fetch\(|XMLHttpRequest|WebSocket|sendBeacon|navigator\.|import\(|eval\(|new Function'
    }
    It 'detects the missing gzip support and the decoding errors explicitly, without any uncompressed fallback' {
        $script:Template | Should -Match 'typeof DecompressionStream !== "function"'
        $script:Template | Should -Match 'could not be read'
        $script:Template | Should -Match 'chunks found'
        $script:Template | Should -Match '<noscript>'
    }
    It 'exports a snapshot of the rows selected at the click and never reads the live view after a yield' {
        $handler = $script:Template.Substring($script:Template.IndexOf('el("export").addEventListener("click"'))
        $handler = $handler.Substring(0, $handler.IndexOf('// ---- Wiring'))
        $handler | Should -Match 'snapshot = view\.slice\(\)'
        $handler | Should -Not -Match '\bview\b(?!\.slice\(\))'
        ([regex]::Matches($handler, 'snapshot\.length')).Count | Should -BeGreaterOrEqual 3
    }
    It 'bounds the mounted rows to 200 and builds cells with textContent only' {
        $script:Template | Should -Match 'MAX_MOUNT = 200'
        $script:Template | Should -Not -Match 'innerHTML|outerHTML|insertAdjacentHTML|document\.write'
    }
    It 'keeps every marker used by the writer' {
        foreach ($marker in '{{TITLE}}', '{{SUBTITLE}}', '{{VERSION}}', '{{META}}', '{{TILES}}', '{{NEXT}}', '{{DATA_NOTICE}}', '{{DATA}}') { $script:Template.Contains($marker) | Should -BeTrue }
    }
}

Describe 'Report writer' {
    It 'escapes quotes, backslashes, control characters, HTML-significant characters and line separators' {
        InModuleScope PRA.Common {
            ConvertTo-PraJsonString "a`"b\c`n`r`t<>&$([char]0x2028)$([char]0x01)" | Should -BeExactly '"a\"b\\c\n\r\t\u003c\u003e\u0026\u2028\u0001"'
            ConvertTo-PraJsonString $null | Should -BeExactly 'null'
            ConvertTo-PraJsonScalar $false | Should -BeExactly 'false'
            ConvertTo-PraJsonScalar 12 | Should -BeExactly '12'
        }
    }
    It 'keeps the values, null and false of the 22 fields, the statuses and the verdict of a small run' {
        $res = Invoke-PraSyntheticReport -PackageRoot $script:Package -Directory (Join-Path $script:Work 'small') -Rows 300 -Issues 12 -Warnings 4
        $decoded = Read-PraReportData $res.Reports.Html
        $decoded.Meta.rows.fields.Count | Should -Be 22
        $decoded.Meta.rows.count | Should -Be $res.Outcome.Rows.Count
        $decoded.Data.rows.Count | Should -Be $res.Outcome.Rows.Count
        $decoded.Data.issues.Count | Should -Be 12
        $decoded.Data.warnings.Count | Should -Be 4
        (Compare-Rows $decoded $res.Outcome (0..($res.Outcome.Rows.Count - 1))).Count | Should -Be 0
        $decoded.Html | Should -Match '<div class="tile-label">Result</div><div class="tile-value">Failed</div>'
        $decoded.Html | Should -Match ('<div class="tile-label">Objects</div><div class="tile-value">{0}</div>' -f $res.Outcome.Rows.Count)
        $decoded.Html | Should -Match '<div class="tile-label">Warnings</div><div class="tile-value">4</div>'
        $decoded.Html | Should -Match 'Synthetic next step'
        $decoded.Html | Should -Match 'object row\(s\), 12 run error\(s\) and 4 warning\(s\)'
        $decoded.Html | Should -Not -Match '<table id="rows">'
    }
    It 'never writes raw field text outside the compressed data and the encoded header' {
        $res = Invoke-PraSyntheticReport -PackageRoot $script:Package -Directory (Join-Path $script:Work 'raw') -Rows 200 -Name raw
        $html = [IO.File]::ReadAllText($res.Reports.Html)
        $html | Should -Not -Match 'user000010@contoso|synthetic detail for the report volume'
        $html | Should -Not -Match 'alert\("x"\)'
    }
    It 'still returns the report as a string for small runs (same serializer)' {
        $res = Invoke-PraSyntheticReport -PackageRoot $script:Package -Directory (Join-Path $script:Work 'string') -Rows 20 -Name string
        $text = & (Get-Module PRA.Common) { param($c, $o) Get-PraReportHtml -Context $c -Outcome $o } $res.Context $res.Outcome
        $text | Should -Match 'id="pra-meta"'
        ([regex]::Matches($text, '<script type="application/x-pra-chunk" data-kind=')).Count | Should -Be 1
    }
    It 'cuts chunks on the row limit and on the text-size limit, with dictionary index 0 reserved for null' {
        $context = New-PraSyntheticContext -PackageRoot $script:Package -Rows 25
        $outcome = & (Get-Module PRA.Common) { param($c) Get-PraOutcome $c } $context
        $writer = New-Object IO.StringWriter
        & (Get-Module PRA.Common) { param($c, $o, $w) Write-PraReportHtml -Context $c -Outcome $o -Writer $w -ChunkRows 10 } $context $outcome $writer
        $path = Join-Path $script:Work 'chunks.html'; [IO.File]::WriteAllText($path, $writer.ToString())
        $decoded = Read-PraReportData $path
        ($decoded.Data.rows.Chunks -join ',') | Should -Be '10,10,5'
        $decoded.Meta.chunks.rows | Should -Be 3
        $decoded.Data.rows.Dict[0][0] | Should -BeNullOrEmpty
        (Compare-Rows $decoded $outcome (0..24)).Count | Should -Be 0
        $writer2 = New-Object IO.StringWriter
        & (Get-Module PRA.Common) { param($c, $o, $w) Write-PraReportHtml -Context $c -Outcome $o -Writer $w -ChunkRows 1000 -ChunkChars 400 } $context $outcome $writer2
        [IO.File]::WriteAllText($path, $writer2.ToString())
        $split = Read-PraReportData $path
        $split.Data.rows.Chunks.Count | Should -BeGreaterThan 3
        $split.Data.rows.Count | Should -Be 25
        (Compare-Rows $split $outcome (0..24)).Count | Should -Be 0
    }
    It 'writes both formats and an empty but valid HTML report when there is no row, keeping the CSV header-only' {
        $res = Invoke-PraSyntheticReport -PackageRoot $script:Package -Directory (Join-Path $script:Work 'empty') -Rows 0 -Name empty
        $decoded = Read-PraReportData $res.Reports.Html
        $decoded.Meta.rows.count | Should -Be 0
        $decoded.Meta.chunks.rows | Should -Be 0
        ([IO.File]::ReadAllLines($res.Reports.Csv)).Count | Should -Be 1
        $decoded.Html | Should -Match '<div class="tile-label">Objects</div><div class="tile-value">0</div>'
    }
    It 'keeps the server CSV schema and values (22 columns, semicolon, unchanged by the HTML data)' {
        $res = Invoke-PraSyntheticReport -PackageRoot $script:Package -Directory (Join-Path $script:Work 'csv') -Rows 50 -Name csv
        $csv = @(Import-Csv -LiteralPath $res.Reports.Csv -Delimiter ';')
        $csv.Count | Should -Be 50
        (@($csv[0].PSObject.Properties.Name) -join ',') | Should -BeExactly ((& (Get-Module PRA.Common) { $script:RowFields }) -join ',')
        $csv[3].SamAccountName | Should -BeExactly $res.Outcome.Rows[3].SamAccountName
    }
}

Describe 'High-volume reports (report-only, synthetic)' {
    It 'writes and decodes <Rows> rows with <Issues> run errors and <Warnings> warnings, chunk boundaries and the last row included' -ForEach @(
        @{ Rows = 50000; Issues = 2500; Warnings = 600 }
        @{ Rows = 100000; Issues = 5000; Warnings = 1200 }
    ) {
        $directory = if ($script:Evidence) { $script:Evidence } else { Join-Path $script:Work "volume$Rows" }
        $res = Invoke-PraSyntheticReport -PackageRoot $script:Package -Directory $directory -Rows $Rows -Issues $Issues -Warnings $Warnings -Name ('report-{0}' -f $Rows)
        $outcome = $res.Outcome
        $total = $outcome.Rows.Count
        $total | Should -BeGreaterOrEqual $Rows
        $decoded = Read-PraReportData $res.Reports.Html
        $decoded.Meta.rows.count | Should -Be $total
        $decoded.Data.rows.Count | Should -Be $total
        $decoded.Meta.chunks.rows | Should -Be ([math]::Ceiling($total / 20000))
        @($decoded.Data.rows.Chunks | Where-Object { $_ -gt 20000 }).Count | Should -Be 0
        $decoded.Data.rows.Chunks[0] | Should -Be 20000
        $decoded.Data.issues.Count | Should -Be $Issues
        $decoded.Data.warnings.Count | Should -Be $Warnings
        $statusField = [array]::IndexOf($decoded.Data.rows.Fields, 'FinalStatus')
        $counts = @{}
        $statusDict = $decoded.Data.rows.Dict[$statusField]; $statusCols = $decoded.Data.rows.Cols[$statusField]
        for ($i = 0; $i -lt $total; $i++) { $s = $statusDict[$statusCols[$i]]; $counts[$s] = 1 + [int]$counts[$s] }
        foreach ($status in 'Success', 'AlreadyDone', 'Pending', 'Error', 'Planned') { $counts[$status] | Should -Be @($outcome.Rows | Where-Object { $_.FinalStatus -eq $status }).Count }
        $boundaries = New-Object 'Collections.Generic.List[int]'
        for ($i = 0; $i -lt $total; $i += 37) { $boundaries.Add($i) }
        foreach ($edge in 0, 19999, 20000, 20001, 39999, 40000, 59999, 60000, 79999, 80000, 99999, 100000, ($total - 2), ($total - 1)) { if ($edge -ge 0 -and $edge -lt $total) { $boundaries.Add($edge) } }
        (Compare-Rows $decoded $outcome ($boundaries | Sort-Object -Unique)).Count | Should -Be 0
        (Get-Decoded $decoded 'rows' ([array]::IndexOf($decoded.Data.rows.Fields, 'Detail')) ($total - 1)) | Should -BeExactly $outcome.Rows[$total - 1].Detail
        @(Import-Csv -LiteralPath $res.Reports.Csv -Delimiter ';').Count | Should -Be $total
        $script:Measurements += [pscustomobject]@{ rows = $Rows; outcomeRows = $total; issues = $Issues; warnings = $Warnings; chunks = $decoded.Meta.chunks.rows; metrics = $res.Metrics }
        if ($script:Evidence) { ($script:Measurements | ConvertTo-Json -Depth 5) | Set-Content -LiteralPath (Join-Path $script:Evidence 'generation-measurements.json') -Encoding UTF8 }
    }
}
