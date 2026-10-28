#Requires -Version 5.1
<#
    ONE REPORT OF EVERY DEVIATION FROM THE SHIPPED DEFAULTS (engine/_shared/SI-DeviationReport.ps1, setup/Get-SIDeviationReport.ps1).

    NO EMOJI IN THIS FILE: it has no BOM, and PowerShell 5.1 would decode it as Windows-1252.

    What these pin, and why each matters:
      * THE SHARED FIXTURE (tests/fixtures/deviation-report-cases.json) gives exactly the expected rows, in order. The
        Pro web app's C# twin is held to the same file, so the page and the PowerShell report can never disagree.
      * ONLY REAL DEVIATIONS: a setting equal to its shipped default (25 = 25.0, [] = none) is not one; a setting with
        no shipped default is install configuration, not a deviation; a secret is never read; an 'inherit' override and
        a revoked exemption are not deviations.
      * EXPIRY IS VISIBLE: an expired exemption is listed and flagged, never silently dropped; 'expiring' is the 30-day
        window, at its exact edge.
      * WHO AND WHY: the owner is whoever introduced the deviation since it was last reset, ChangedBy is the latest
        change, and the reason is the latest one given.
      * THE COMMUNITY CLI reads the custom files against the shipped ones, never writes to the install, never prints a
        secret, filters by kind and writes a CSV a spreadsheet cannot execute.
#>

BeforeAll {
    $script:SIRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
    . (Join-Path $script:SIRoot 'engine\_shared\SI-DeviationReport.ps1')
    $script:Fixture = ConvertFrom-SIDevJson ([System.IO.File]::ReadAllText((Join-Path $script:SIRoot 'tests\fixtures\deviation-report-cases.json')))
    $script:Now = [datetime]::SpecifyKind([datetime]'2026-10-03T12:00:00', [DateTimeKind]::Utc)
    $script:Cols = @('Kind', 'Item', 'Scope', 'ShippedDefault', 'Current', 'Reason', 'Owner', 'ChangedBy', 'ChangedAt', 'ExpiresAt', 'Status', 'HistoryName', 'HistoryScope')
    function script:CatalogEntry($name, $default, [bool]$secret = $false) { [pscustomobject]@{ name = $name; secret = $secret; default = $default } }
    function script:SettingRow($name, $json, $scope = 'solution') { @{ Name = $name; Scope = $scope; ValueJson = $json; KeyVaultSecretName = $null; UpdatedAt = '2026-09-01T00:00:00Z'; UpdatedBy = 'u@example.test' } }
    function script:Utf8NoBom { New-Object System.Text.UTF8Encoding($false) }
    function script:Write-TreeFile([string]$Root, [string]$Rel, [string]$Text) {
        $p = Join-Path $Root $Rel
        $d = Split-Path -Parent $p
        if (-not (Test-Path -LiteralPath $d)) { New-Item -ItemType Directory -Path $d -Force | Out-Null }
        [System.IO.File]::WriteAllText($p, $Text, (Utf8NoBom))
    }
}

Describe 'the shared fixture: the PowerShell report and the web app read the same rows the same way' {
    It 'gives exactly the expected rows, in order, column for column' {
        $f = $script:Fixture
        $rows = @(Get-SIDeviationReport -Settings @($f.settings) -Catalog @($f.catalog) -Documents @($f.documents) -Templates @($f.templates) `
            -Overrides @($f.overrides) -Exemptions @($f.exemptions) -ChangeLog @($f.changeLog) -Now (ConvertTo-SIDevUtc $f.now) -ExpiringDays $f.expiringDays)
        $rows.Count | Should -Be @($f.expected).Count
        $diff = New-Object System.Collections.Generic.List[string]
        for ($i = 0; $i -lt $rows.Count; $i++) {
            foreach ($c in $script:Cols) {
                if ([string]$rows[$i].$c -cne [string]$f.expected[$i].$c) { $diff.Add(('row {0} {1}: [{2}] <> [{3}]' -f $i, $c, $rows[$i].$c, $f.expected[$i].$c)) }
            }
        }
        $diff | Should -BeNullOrEmpty
    }
    It 'covers every kind the report knows' {
        @($script:Fixture.expected | ForEach-Object { $_.Kind } | Sort-Object -Unique) | Should -Be @(Get-SIDeviationKinds | Sort-Object)
    }
    It 'the report columns are the eleven the page and the CSV show' {
        Get-SIDeviationColumns | Should -Be @('Kind', 'Item', 'Scope', 'ShippedDefault', 'Current', 'Reason', 'Owner', 'ChangedBy', 'ChangedAt', 'ExpiresAt', 'Status')
    }
}

Describe 'status: active, expiring within 30 days, expired' {
    It '<_.Expires> -> <_.Status>' -ForEach @(
        @{ Expires = $null; Status = 'active' }
        @{ Expires = '2026-10-03T11:59:59Z'; Status = 'expired' }
        @{ Expires = '2026-10-03T12:00:00Z'; Status = 'expired' }
        @{ Expires = '2026-10-03T12:00:01Z'; Status = 'expiring' }
        @{ Expires = '2026-11-02T12:00:00Z'; Status = 'expiring' }
        @{ Expires = '2026-11-02T12:00:01Z'; Status = 'active' }
    ) {
        Get-SIDeviationStatus -ExpiresAt $_.Expires -Now $script:Now | Should -Be $_.Status
    }
    It 'a SQL time read back without a kind is UTC, and the window is a parameter' {
        $sqlTime = [datetime]::SpecifyKind([datetime]'2026-10-05T00:00:00', [DateTimeKind]::Unspecified)
        Get-SIDeviationStatus -ExpiresAt $sqlTime -Now $script:Now | Should -Be 'expiring'
        Get-SIDeviationStatus -ExpiresAt $sqlTime -Now $script:Now -ExpiringDays 1 | Should -Be 'active'
    }
}

Describe 'settings: only a value that differs from a KNOWN shipped default' {
    It 'equal values are not deviations: 25 = 25.0, [] = (none), true = true, a one-item list = the same list' {
        $cat = @((CatalogEntry 'A' 25), (CatalogEntry 'B' @()), (CatalogEntry 'C' $true), (CatalogEntry 'D' @('x')), (CatalogEntry 'E' 0.5))
        $rows = @(Get-SIDeviationReport -Catalog $cat -Settings @((SettingRow 'A' '25.0'), (SettingRow 'B' 'null'), (SettingRow 'C' 'true'), (SettingRow 'D' '["x"]'), (SettingRow 'E' '0.50')) -Now $script:Now)
        $rows | Should -BeNullOrEmpty
    }
    It 'a different value is one row with the shipped and the current value as canonical JSON' {
        $rows = @(Get-SIDeviationReport -Catalog @((CatalogEntry 'D' @('x')), (CatalogEntry 'N' 1.5)) -Settings @((SettingRow 'D' '["x","y"]' 'engine:endpoint'), (SettingRow 'N' '2')) -Now $script:Now)
        $rows.Count | Should -Be 2
        $d = $rows | Where-Object Item -eq 'D'
        $d.Scope | Should -Be 'engine:endpoint'; $d.ShippedDefault | Should -Be '["x"]'; $d.Current | Should -Be '["x","y"]'
        ($rows | Where-Object Item -eq 'N').ShippedDefault | Should -Be '1.5'
    }
    It 'left out: no shipped default (install configuration), a secret, a Key Vault reference, a setting the catalog does not know' {
        $cat = @((CatalogEntry 'Workspace' $null), (CatalogEntry 'Key' 'x' $true), (CatalogEntry 'Ref' 'x'))
        $kv = SettingRow 'Ref' $null; $kv.KeyVaultSecretName = 'kv-name'
        @(Get-SIDeviationReport -Catalog $cat -Settings @((SettingRow 'Workspace' '"w"'), (SettingRow 'Key' '"leak"'), $kv, (SettingRow 'Unknown' '1')) -Now $script:Now) | Should -BeNullOrEmpty
    }
}

Describe 'who and why: the change history' {
    It 'Owner = the first change since the last reset, ChangedBy = the latest, Reason = the latest reason given' {
        $log = @(
            @{ ChangeId = 1; Name = 'A'; Scope = 'solution'; Action = 'Set'; ChangedBy = 'old'; ChangedAt = '2026-01-01T00:00:00Z'; Reason = 'gone' }
            @{ ChangeId = 2; Name = 'A'; Scope = 'solution'; Action = 'Reset'; ChangedBy = 'r'; ChangedAt = '2026-02-01T00:00:00Z' }
            @{ ChangeId = 4; Name = 'A'; Scope = 'solution'; Action = 'Set'; ChangedBy = 'last'; ChangedAt = '2026-04-01T00:00:00Z'; Reason = '' }
            @{ ChangeId = 3; Name = 'A'; Scope = 'solution'; Action = 'Set'; ChangedBy = 'owner'; ChangedAt = '2026-03-01T00:00:00Z'; Reason = 'why' }
        )
        $r = @(Get-SIDeviationReport -Catalog @(CatalogEntry 'A' 1) -Settings @(SettingRow 'A' '2') -ChangeLog $log -Now $script:Now)[0]
        $r.Owner | Should -Be 'owner'; $r.ChangedBy | Should -Be 'last'; $r.ChangedAt | Should -Be '2026-04-01T00:00:00Z'; $r.Reason | Should -Be 'why'
    }
    It 'another scope''s history is not borrowed; without history the row''s own Updated fields are used' {
        $log = @(@{ ChangeId = 1; Name = 'A'; Scope = 'engine:endpoint'; Action = 'Set'; ChangedBy = 'other'; ChangedAt = '2026-01-01T00:00:00Z'; Reason = 'x' })
        $r = @(Get-SIDeviationReport -Catalog @(CatalogEntry 'A' 1) -Settings @(SettingRow 'A' '2') -ChangeLog $log -Now $script:Now)[0]
        $r.Owner | Should -Be 'u@example.test'; $r.ChangedAt | Should -Be '2026-09-01T00:00:00Z'; $r.Reason | Should -Be ''
    }
}

Describe 'exemptions, exclusions, rules, item overrides' {
    It 'a revoked exemption is not listed; an expired one is, flagged; the exemption''s own reason wins' {
        $e = @(
            @{ ExemptionId = 1; Scope = 'issue'; Cve = 'CVE-2025-0001'; Reason = 'r1'; ExpiresAt = '2026-09-01T00:00:00Z'; CreatedBy = 'a'; CreatedAt = '2026-08-01T00:00:00Z' }
            @{ ExemptionId = 2; Scope = 'asset'; AssetKey = 'k'; Reason = 'r2'; CreatedBy = 'a'; CreatedAt = '2026-08-01T00:00:00Z'; RevokedAt = '2026-08-02T00:00:00Z' }
        )
        $rows = @(Get-SIDeviationReport -Exemptions $e -Now $script:Now)
        $rows.Count | Should -Be 1
        $rows[0].Status | Should -Be 'expired'; $rows[0].Reason | Should -Be 'r1'; $rows[0].HistoryName | Should -Be 'exemption/1'
    }
    It 'exclusion notes are not exclusions; an unreadable document is shown, not hidden' {
        @(Get-SIDevExclusionEntries -Body '{ "_n": "x", "Comment": "c", "$schema": "s", "ExcludedCves": [] }') | Should -BeNullOrEmpty
        (Get-SIDevExclusionEntries -Body '{broken')[0].Item | Should -Be '(unreadable)'
        @(Get-SIDevExclusionEntries -Body '{ "CveMinAgeDays": 0 }') | Should -BeNullOrEmpty -Because '0 is the shipped value'
    }
    It 'a rule: turned off / other tiers / same tiers / no shipped rule' {
        $ship = "id: R`nset:`n  Tier: 1`n"
        (Get-SIDevRuleClass -Body "id: R`nmode: disable`n" -ShippedBody $ship).Kind | Should -Be 'DisabledDetection'
        $m = Get-SIDevRuleClass -Body "id: R`nset:`n  Tier: 0`n  x: 1`n" -ShippedBody $ship
        $m.Kind | Should -Be 'TierMove'; $m.Shipped | Should -Be 'tier 1'; $m.Current | Should -Be 'tier 0'
        (Get-SIDevRuleClass -Body "id: R`npurpose: x`nset:`n  Tier: 1`n" -ShippedBody $ship -ShippedLabel 'template 3.0').Shipped | Should -Be 'template 3.0'
        (Get-SIDevRuleClass -Body "id: R`n" -ShippedBody $null).Current | Should -Be 'added'
    }
    It 'an inherit override is no deviation; a disabled non-detection item is an ItemOverride turned off' {
        $o = @(
            @{ Kind = 'naming'; ItemKey = 'X'; State = 'inherit' }
            @{ Kind = 'cmdbownership'; ItemKey = 'defaults'; State = 'disable'; UpdatedBy = 'u'; UpdatedAt = '2026-09-01T00:00:00Z' }
        )
        $rows = @(Get-SIDeviationReport -Overrides $o -Templates @(@{ Kind = 'cmdbownership'; ItemKey = 'defaults'; TemplateVersion = '3'; BodyJson = '{}' }) -Now $script:Now)
        $rows.Count | Should -Be 1
        $rows[0].Kind | Should -Be 'ItemOverride'; $rows[0].Current | Should -Be 'turned off'; $rows[0].ShippedDefault | Should -Be 'on'
    }
    It 'CSV: the report columns, a formula-looking cell defused, commas and quotes quoted' {
        $row = [pscustomobject]@{ Kind = 'Exclusion'; Item = '=HYPERLINK("x")'; Scope = 'a,b'; ShippedDefault = '-1'; Current = 'x'; Reason = '@r'; Owner = ''; ChangedBy = ''; ChangedAt = $null; ExpiresAt = $null; Status = 'active' }
        $lines = (ConvertTo-SIDeviationCsv -Rows @($row)) -split "`r`n"
        $lines[0] | Should -Be 'Kind,Item,Scope,ShippedDefault,Current,Reason,Owner,ChangedBy,ChangedAt,ExpiresAt,Status'
        $lines[1] | Should -Be 'Exclusion,"''=HYPERLINK(""x"")","a,b",''-1,x,''@r,,,,,active'
    }
}

Describe 'the Community CLI: the custom files against the shipped ones' {
    BeforeAll {
        $script:Tree = Join-Path ([System.IO.Path]::GetTempPath()) ('si-devreport-' + [guid]::NewGuid().ToString('N').Substring(0, 8))
        $script:Overlay = Join-Path $script:Tree '_overlay'
        $t = $script:Tree
        New-Item -ItemType Directory -Path (Join-Path $t 'engine\_shared') -Force | Out-Null
        Copy-Item -LiteralPath (Join-Path $script:SIRoot 'engine\_shared\SI-DeviationReport.ps1') -Destination (Join-Path $t 'engine\_shared')
        New-Item -ItemType Directory -Path (Join-Path $t 'setup\_shared') -Force | Out-Null
        Copy-Item -LiteralPath (Join-Path $script:SIRoot 'setup\Get-SIDeviationReport.ps1') -Destination (Join-Path $t 'setup')
        Copy-Item -LiteralPath (Join-Path $script:SIRoot 'setup\_shared\SI-ScriptRun.ps1') -Destination (Join-Path $t 'setup\_shared')   # the run helper every person-run script loads first
        Write-TreeFile $t 'launcher\_lib\SecurityInsight.shared-defaults.ps1' "`$global:WorkspaceName = 'log-si'`r`n`$global:SI_SPN_Secret = ''`r`n`$global:UseProxy = `$false`r`n"
        Write-TreeFile $t 'launcher\endpoint\LauncherConfig.defaults.ps1' "`$global:SI_AssetLimit = 0`r`n`$global:MailTo = @()`r`n"
        Write-TreeFile $t 'config\SecurityInsight.custom.ps1' ("`$global:WorkspaceName = 'log-custom'`r`n`$global:SI_SPN_Secret = 'SuperSecretValue123'`r`n" +
            "`$global:UseProxy = (Get-Date).Year -gt 2000`r`n`$global:SI_TenantId = 'no-shipped-default'`r`n")
        Write-TreeFile $t 'launcher\endpoint\LauncherConfig.custom.ps1' "`$global:SI_AssetLimit = 0`r`n`$global:MailTo = @('a@example.test')`r`n"
        Write-TreeFile $t 'risk-analysis-detection\RiskAnalysis_Queries_Locked.yaml' "Reports:`r`n  - ReportName: Report_A`r`n  - ReportName: Report_B`r`n"
        Write-TreeFile $t 'risk-analysis-detection\RiskAnalysis_Queries_Custom.yaml' "Reports:`r`n  - ReportName: Report_A`r`n  - ReportName: Report_New`r`n"
        Write-TreeFile $t 'risk-analysis-detection\RiskAnalysisGlobalExclusions.custom.json' '{ "_purpose": "x", "ExcludedAssetTags": ["--Excluded--SI"] }'
        Write-TreeFile $t 'risk-analysis-detection\Report_A.exclude.custom.json' '{ "ExcludedCves": ["CVE-2025-0001"], "CveMinAgeDays": 14 }'
        Write-TreeFile $t 'risk-analysis-detection\Report_A.exclude.json' '{ "ExcludedCves": ["CVE-1999-0001"] }'
        Write-TreeFile $t 'risk-analysis-detection\Report_B.exclude.json' '{ "ExcludedConfigurationIds": ["scid-1"] }'
        Write-TreeFile $t 'risk-analysis-detection\Device_X.exclude.json.sample' '{ "ExcludedCves": ["CVE-2000-0001"] }'
        Write-TreeFile $t 'risk-analysis-detection\riskscore_weighted.schema.custom.json' '{ "weightedRiskFactors": { "identity": { "fields": [ { "field": "f", "valueMap": { "a": 120 } } ] } } }'
        $rule = { param($id, $tier) "id: $id`r`nmode: locked`r`ndetections:`r`n  - id: $id`r`n    set:`r`n      Tier: $tier`r`n" }
        Write-TreeFile $t 'asset-profiling-enrichment\endpoint\Folder\R1.locked.yaml' (& $rule 'R1' 1)
        Write-TreeFile $t 'asset-profiling-enrichment\endpoint\Folder\R1.custom.yaml' "id: R1`r`nmode: disable`r`n"
        Write-TreeFile $t 'asset-profiling-enrichment\endpoint\Folder\R2.locked.yaml' (& $rule 'R2' 2)
        Write-TreeFile $t 'asset-profiling-enrichment\endpoint\Folder\R2.custom.yaml' (& $rule 'R2' 0)
        Write-TreeFile $t 'asset-profiling-enrichment\endpoint\Folder\R3.locked.yaml' (& $rule 'R3' 1)
        Write-TreeFile $t 'asset-profiling-enrichment\endpoint\Folder\R3.custom.yaml' ((& $rule 'R3' 1) + "purpose: 'ours'`r`n")
        Write-TreeFile $t 'asset-profiling-enrichment\identity\R4.custom.yaml' (& $rule 'R4' 2)
        Write-TreeFile $t 'asset-profiling-enrichment\endpoint\Folder\R5.locked.yaml' (& $rule 'R5' 2)
        Write-TreeFile $t 'asset-profiling-enrichment\endpoint\Folder\R6.custom.sample.yaml' (& $rule 'R6' 0)
        Write-TreeFile $script:Overlay 'endpoint\R3.custom.yaml' (& $rule 'R3' 3)
        Write-TreeFile $t 'logs\settings-changes.log' ('{"time":"2026-09-01T08:00:00Z","user":"first@example.test","file":"config\\SecurityInsight.custom.ps1","setting":"WorkspaceName","action":"Set"}' + "`r`n" +
            '{"time":"2026-09-02T08:00:00Z","user":"second@example.test","file":"config\\SecurityInsight.custom.ps1","setting":"WorkspaceName","action":"Set"}' + "`r`n" +
            '{"time":"2026-09-03T08:00:00Z","user":"excl@example.test","file":"risk-analysis-detection\\Report_A.exclude.custom.json","setting":"ExcludedCves","action":"Set"}' + "`r`n")
        $script:Hash = { @(Get-ChildItem -LiteralPath $script:Tree -Recurse -File | Sort-Object FullName | ForEach-Object { '{0}|{1}' -f $_.FullName, (Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash }) -join "`n" }
        $script:Before = & $script:Hash
        $script:Rows = @(& (Join-Path $t 'setup\Get-SIDeviationReport.ps1') -OverlayRoot $script:Overlay)
    }
    AfterAll { Remove-Item -LiteralPath $script:Tree -Recurse -Force -ErrorAction SilentlyContinue }

    It 'objects with the report columns' {
        $script:Rows.Count | Should -BeGreaterThan 0
        @($script:Rows[0].PSObject.Properties.Name) | Should -Be @(Get-SIDeviationColumns)
    }
    It 'settings: a different value against the shipped default, code shown as code, equal values and install configuration left out' {
        $s = @($script:Rows | Where-Object Kind -eq 'Setting')
        $w = $s | Where-Object Item -eq 'WorkspaceName'
        $w.ShippedDefault | Should -Be '"log-si"'; $w.Current | Should -Be '"log-custom"'; $w.Scope | Should -Be 'solution'
        $w.Owner | Should -Be 'first@example.test'; $w.ChangedBy | Should -Be 'second@example.test'; $w.ChangedAt | Should -Be '2026-09-02T08:00:00Z'
        ($s | Where-Object Item -eq 'UseProxy').Current | Should -Be '(set by code)'
        ($s | Where-Object Item -eq 'MailTo').Scope | Should -Be 'engine:endpoint'
        @($s | Where-Object { $_.Item -in 'SI_AssetLimit', 'SI_TenantId' }) | Should -BeNullOrEmpty
    }
    It 'a secret is never in the report or its CSV' {
        @($script:Rows | Where-Object Item -eq 'SI_SPN_Secret') | Should -BeNullOrEmpty
        ($script:Rows | Out-String) | Should -Not -Match 'SuperSecretValue123'
        $csv = Join-Path $script:Tree 'out\all.csv'
        & (Join-Path $script:Tree 'setup\Get-SIDeviationReport.ps1') -OverlayRoot $script:Overlay -AsCsv -CsvPath $csv | Out-Null
        [System.IO.File]::ReadAllText($csv) | Should -Not -Match 'SuperSecretValue123'
    }
    It 'exclusions: the custom file wins over the plain one for the same report; a plain one counts when it is the only one; samples do not' {
        $x = @($script:Rows | Where-Object Kind -eq 'Exclusion')
        @($x | ForEach-Object { '{0}|{1}' -f $_.Scope, $_.Item }) | Should -Be @('Report_A|CveMinAgeDays', 'Report_A|ExcludedCves: CVE-2025-0001', 'Report_B|ExcludedConfigurationIds: scid-1', 'global|ExcludedAssetTags: --Excluded--SI') -Because 'ordinal: uppercase before lowercase'
        ($x | Where-Object Item -eq 'ExcludedCves: CVE-2025-0001').ChangedBy | Should -Be 'excl@example.test'
    }
    It 'rules: turned off, moved tier, the overlay winning over the in-tree custom rule, an added rule; a sample is not a rule' {
        $r = @($script:Rows | Where-Object { $_.Scope -eq 'rule' })
        ($r | Where-Object Item -eq 'endpoint/R1').Kind | Should -Be 'DisabledDetection'
        $m = $r | Where-Object Item -eq 'endpoint/R2'; $m.Kind | Should -Be 'TierMove'; $m.ShippedDefault | Should -Be 'tier 2'; $m.Current | Should -Be 'tier 0'
        $o = $r | Where-Object Item -eq 'endpoint/R3'; $o.Kind | Should -Be 'TierMove'; $o.Current | Should -Be 'tier 3'
        ($r | Where-Object Item -eq 'identity/R4').Current | Should -Be 'added'
        @($r | Where-Object { $_.Item -in 'endpoint/R5', 'endpoint/R6' }) | Should -BeNullOrEmpty
    }
    It 'reports in the custom catalog: one replacing a shipped report, one added; weights per engine' {
        $p = @($script:Rows | Where-Object Scope -eq 'rareport')
        ($p | Where-Object Item -eq 'report/Report_A').Current | Should -Be 'overridden'
        ($p | Where-Object Item -eq 'report/Report_New').Current | Should -Be 'added'
        ($script:Rows | Where-Object Kind -eq 'RiskWeights').Item | Should -Be 'weightedRiskFactors/identity'
    }
    It '-Kind filters; -AsCsv writes the CSV (with a BOM) and returns the file' {
        @(& (Join-Path $script:Tree 'setup\Get-SIDeviationReport.ps1') -OverlayRoot $script:Overlay -Kind TierMove | ForEach-Object Kind | Sort-Object -Unique) | Should -Be @('TierMove')
        $csv = Join-Path $script:Tree 'out\tier.csv'
        $f = & (Join-Path $script:Tree 'setup\Get-SIDeviationReport.ps1') -OverlayRoot $script:Overlay -Kind TierMove -AsCsv -CsvPath $csv
        $f.FullName | Should -Be $csv
        $bytes = [System.IO.File]::ReadAllBytes($csv)
        $bytes[0..2] | Should -Be @(0xEF, 0xBB, 0xBF)
        $lines = @(([System.Text.Encoding]::UTF8.GetString($bytes, 3, $bytes.Length - 3)) -split "`r`n" | Where-Object { $_ })
        $lines[0] | Should -Be 'Kind,Item,Scope,ShippedDefault,Current,Reason,Owner,ChangedBy,ChangedAt,ExpiresAt,Status'
        $lines.Count | Should -Be 3
    }
    It 'nothing in the install was written (only the CSV files asked for)' {
        Remove-Item -LiteralPath (Join-Path $script:Tree 'out') -Recurse -Force -ErrorAction SilentlyContinue
        & $script:Hash | Should -Be $script:Before
    }
    It 'a clean install (no custom files) reports nothing' {
        $clean = Join-Path $script:Tree '_clean'
        New-Item -ItemType Directory -Path (Join-Path $clean 'engine\_shared'), (Join-Path $clean 'setup') -Force | Out-Null
        Copy-Item -LiteralPath (Join-Path $script:SIRoot 'engine\_shared\SI-DeviationReport.ps1') -Destination (Join-Path $clean 'engine\_shared')
        Write-TreeFile $clean 'launcher\_lib\SecurityInsight.shared-defaults.ps1' "`$global:WorkspaceName = 'log-si'`r`n"
        @(& (Join-Path $script:SIRoot 'setup\Get-SIDeviationReport.ps1') -SIRoot $clean) | Should -BeNullOrEmpty
    }
}

Describe 'the report is part of the free payload' {
    It 'the core and the CLI load nothing but the core (a Community copy has no Pro paths)' {
        foreach ($rel in 'engine\_shared\SI-DeviationReport.ps1', 'setup\Get-SIDeviationReport.ps1') {
            $tokens = $null; $errs = $null
            $ast = [System.Management.Automation.Language.Parser]::ParseFile((Join-Path $script:SIRoot $rel), [ref]$tokens, [ref]$errs)
            @($errs) | Should -BeNullOrEmpty
            $dots = @($ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.CommandAst] -and $n.InvocationOperator -eq 'Dot' }, $true) | ForEach-Object { $_.Extent.Text })
            foreach ($d in $dots) { $d | Should -Match 'SI-DeviationReport\.ps1|SI-ScriptRun\.ps1' }   # SI-ScriptRun: the run helper (setup\_shared, free)
        }
    }
    It 'both files are ASCII (PowerShell 5.1 reads a BOM-less file as Windows-1252)' {
        foreach ($rel in 'engine\_shared\SI-DeviationReport.ps1', 'setup\Get-SIDeviationReport.ps1', 'tests\pester\SIv3-DeviationReport.Tests.ps1') {
            $b = [System.IO.File]::ReadAllBytes((Join-Path $script:SIRoot $rel))
            @($b | Where-Object { $_ -gt 0x7F }).Count | Should -Be 0 -Because $rel
        }
    }
}
