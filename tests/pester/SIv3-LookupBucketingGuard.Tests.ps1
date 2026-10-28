#Requires -Version 5.1
<#
    GUARD OVER THE WHOLE REPORT CATALOG: NO LOOKUP TRAVELS WHOLE IN EVERY SLICE OF A QUERY UNLESS IT IS LISTED HERE.

    A report that goes to advanced hunting has its SecurityInsight tables inlined into the request (about 1 MB).
    Slicing the report shrinks a lookup only when the lookup is cut WITH it. There are three ways a lookup is safe:

      SPLIT      it carries a column the engine keys on (Get-SICLBucketKey) -- each slice gets its own rows
      REDUCED    it has no per-asset key, and the report declares how the engine finds, per slice, the keys the
                 graph rows of that slice can have (report field LookupNeededKeys) -- used when it would not fit whole
      LISTED     it is a small table with no per-asset key at all, named below with the reason and its largest size

    Anything else is copied whole into every slice and grows with the customer: that is what stopped a customer's
    whole run on 2026-10-13 (`_dfcPairs`, 43,124 rows, 1.1 MB). A new report cannot bring that back: it fails here.
#>

BeforeDiscovery {
    $siRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
    $yaml = [IO.File]::ReadAllText((Join-Path $siRoot 'risk-analysis-detection\RiskAnalysis_Queries_Locked.yaml'))
    $catalog = $yaml.Substring(0, $yaml.IndexOf("`nReportTemplates:"))
    $script:ReportCases = @([regex]::Matches($catalog, '(?s)- ReportName: (\S+)\r?\n(.*?)(?=\r?\n    - ReportName: |\z)') |
        ForEach-Object { @{ Name = $_.Groups[1].Value; Body = $_.Groups[2].Value } })
}

BeforeAll {
    $script:SIRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
    . (Join-Path $script:SIRoot 'engine\risk-analysis\_shared\RA-ProfileAugment.ps1')
    . (Join-Path $script:SIRoot 'engine\risk-analysis\_shared\RA-GraphHunting.ps1')
    $script:_CrossDomainBucketCoalesce = @()

    # 🔒 THE ALLOW-LIST. Short on purpose. An entry needs: why the lookup has no per-asset key, and what bounds its size.
    $script:WholeAllowed = @{
        # One row per Defender for Cloud ASSESSMENT KIND (assessment key -> severity, security issue), read only for a
        # recommendation edge whose node the graph has lost. Its key is the assessment, not an asset, and it is joined
        # BEFORE the slices are cut, so it cannot be cut with them. Bounded by the number of assessment kinds a tenant
        # has, not by its resources: 1,244 rows = 80 KB at the largest customer measured (2026-10-13), about 66 bytes
        # a row. It stays safe up to about 10,000 rows (0.65 MB with the query text); beyond that the engine fails the
        # report at once and says so (SIv3-LookupTooLargeForOneQuery).
        '_dfcRecByKey' = 'one row per Defender assessment kind; joined before the slices are cut'
        # #675: one row per SUBSCRIPTION (its most critical CI's tier). It MUST travel whole: cut per slice it gave a
        # subscription-level row the minimum over one slice's share of the subscription's CIs. Bounded by the number of
        # subscriptions (a few hundred at the largest tenants, about 50 bytes a row), not by resources.
        '_subTierG' = 'one row per subscription; must be whole in every slice or a subscription row gets a slice''s share of its CIs (#675)'
    }

    $script:LetRx = '(?ms)\blet\s+(?<var>\w+)\s*=\s*(?<body>[^;]*?\bSI_[A-Za-z]+(?:_Profile)?_CL\b[^;]*?);'

    function script:Get-QueryText {
        # The report's query as the engine reads it: the text under ReportQuery, without the YAML indentation.
        param([string]$Body)
        $i = $Body.IndexOf('ReportQuery:')
        if ($i -lt 0) { return '' }
        return $Body.Substring($i)
    }
    function script:Remove-TextAndComments {
        param([string]$Text)
        $s = [regex]::Replace($Text, '"[^"\r\n]*"', '""')
        $s = [regex]::Replace($s, "'[^'\r\n]*'", "''")
        return [regex]::Replace($s, '//[^\r\n]*', '')
    }
    function script:Test-GoesToAdvancedHunting {
        # The engine's own routing test: the graph tables, or a Defender table only advanced hunting has.
        param([string]$Query)
        return (($Query -match '\bExposureGraph(?:Nodes|Edges)\b') -or (Test-RAQueryNeedsAdvancedHunting -Query $Query))
    }
    function script:Get-LookupColumns {
        # The columns of a lookup: its last `project` (the same place the engine reads the columns of an empty result).
        param([string]$LetBody)
        $pm = [regex]::Matches($LetBody, '(?s)\|\s*project\s+(?!-)(.*?)(?=\||\)\s*$|$)')
        if ($pm.Count -eq 0) { return @() }
        $last = $pm[$pm.Count - 1].Groups[1].Value
        $depth = 0; $cur = ''; $parts = New-Object System.Collections.Generic.List[string]
        foreach ($ch in $last.ToCharArray()) {
            if ($ch -eq '(' -or $ch -eq '[') { $depth++ } elseif ($ch -eq ')' -or $ch -eq ']') { $depth-- }
            if ($ch -eq ',' -and $depth -le 0) { $parts.Add($cur); $cur = '' } else { $cur += $ch }
        }
        if ($cur.Trim()) { $parts.Add($cur) }
        return @($parts | ForEach-Object { if ($_ -match '^\s*([A-Za-z_]\w*)') { $Matches[1] } } | Where-Object { $_ })
    }
    function script:Test-LookupIsSplit {
        # The engine's own key detection, on a row that has a value in every column of the lookup.
        param([string[]]$Columns)
        if (@($Columns).Count -eq 0) { return $false }
        $h = [ordered]@{}
        foreach ($c in $Columns) { $h[$c] = 'x' }
        return (-not [string]::IsNullOrWhiteSpace((Get-SICLBucketKey -Row ([pscustomobject]$h))))
    }
    function script:Get-DeclaredLookups {
        # The lookups the report declares under LookupNeededKeys.
        param([string]$Body)
        $i = $Body.IndexOf('LookupNeededKeys:')
        if ($i -lt 0) { return @() }
        $head = $Body.Substring(0, [Math]::Max(0, $Body.IndexOf('ReportQuery:')))
        return @([regex]::Matches($head, '(?m)^\s*-\s*Lookup:\s*(\w+)\s*$') | ForEach-Object { $_.Groups[1].Value })
    }
}

Describe 'the catalog is read whole' {
    It 'every report of the query file is checked' {
        # read again here, the same way the cases above are made (the discovery's list is not visible at run time)
        $yaml = [IO.File]::ReadAllText((Join-Path $script:SIRoot 'risk-analysis-detection\RiskAnalysis_Queries_Locked.yaml'))
        $catalog = $yaml.Substring(0, $yaml.IndexOf("`nReportTemplates:"))
        $names = @([regex]::Matches($catalog, '(?s)- ReportName: (\S+)\r?\n(.*?)(?=\r?\n    - ReportName: |\z)') | ForEach-Object { $_.Groups[1].Value })
        $names.Count | Should -BeGreaterOrEqual 130 -Because 'the query file held 130 reports on 2026-10-13; fewer means the reader lost some'
        @($names | Where-Object { $_ -eq 'Azure_Recommendations_Summary' }).Count  | Should -Be 1
        @($names | Where-Object { $_ -eq 'Azure_Recommendations_Detailed' }).Count | Should -Be 1
    }
    It 'the key detection used here is the engine''s own' {
        Test-LookupIsSplit -Columns @('_ciKey', 'si_tier') | Should -BeTrue
        Test-LookupIsSplit -Columns @('_dfcKey')           | Should -BeFalse
        Test-LookupIsSplit -Columns @('_akKey', '_akSeverity', '_akIssue') | Should -BeFalse
    }
    It 'the allow-list is short' {
        $script:WholeAllowed.Count | Should -BeLessOrEqual 3 -Because 'a lookup copied whole into every slice is the exception that has to be argued, not a habit'
    }
}

Describe 'no lookup is copied whole into every slice -- <Name>' -ForEach $script:ReportCases {
    BeforeAll {
        $script:Query    = Get-QueryText -Body $Body
        $script:Stripped = Remove-TextAndComments -Text $script:Query
        $script:ToAH     = Test-GoesToAdvancedHunting -Query $script:Stripped
        $script:Lets     = @([regex]::Matches($script:Stripped, $script:LetRx) | ForEach-Object { @{ Var = $_.Groups['var'].Value; Body = $_.Groups['body'].Value } })
        $script:Declared = @(Get-DeclaredLookups -Body $Body)
    }

    It 'every inlined lookup is split per slice, reduced per slice, or on the allow-list' {
        if (-not $script:ToAH) { Set-ItResult -Skipped -Because 'this report is answered by Log Analytics itself: nothing is inlined'; return }
        $whole = @()
        foreach ($l in $script:Lets) {
            $cols = @(Get-LookupColumns -LetBody $l.Body)
            if (Test-LookupIsSplit -Columns $cols) { continue }
            if ($script:Declared -contains $l.Var) { continue }
            if ($script:WholeAllowed.ContainsKey($l.Var)) { continue }
            $whole += ('{0} (columns: {1})' -f $l.Var, ($cols -join ', '))
        }
        $whole | Should -BeNullOrEmpty -Because 'a lookup without a key the slices are cut on is copied whole into every slice and grows with the customer; give it a per-asset key column the engine knows, declare LookupNeededKeys for it, or argue it onto the allow-list'
    }

    It 'no SecurityInsight table is read outside a lookup (it would be inlined whole, every column)' {
        if (-not $script:ToAH) { Set-ItResult -Skipped -Because 'this report is answered by Log Analytics itself: nothing is inlined'; return }
        $rest = [regex]::Replace($script:Stripped, $script:LetRx, '')
        @([regex]::Matches($rest, '\bSI_[A-Za-z][A-Za-z0-9]*(?:_[A-Za-z][A-Za-z0-9]*)*_CL\b') | ForEach-Object { $_.Value } | Sort-Object -Unique) | Should -BeNullOrEmpty
    }

    It 'a sliced report that inlines a lookup has the slice filter the lookups are cut with' {
        if (-not $script:ToAH -or $script:Lets.Count -eq 0) { Set-ItResult -Skipped -Because 'nothing is inlined'; return }
        $script:Query | Should -Match '//__BUCKET_FILTER_BEGIN__'
        $script:Query | Should -Match '//__BUCKET_FILTER_END__'
    }

    It 'a declared reduction is complete: the lookup exists, the cut point is there once, and every key line is the query''s own' {
        if ($script:Declared.Count -eq 0) { Set-ItResult -Skipped -Because 'this report declares no reduction'; return }
        ([regex]::Matches($script:Query, '(?m)^\s*//__SI_LOOKUP_KEYS_HERE__\s*$')).Count | Should -Be 1
        $cut = $script:Query.IndexOf('//__SI_LOOKUP_KEYS_HERE__')
        $cut | Should -BeGreaterThan $script:Query.IndexOf('//__BUCKET_FILTER_END__') -Because 'the keys must be those of THIS slice''s rows'
        foreach ($d in $script:Declared) {
            @($script:Lets | Where-Object { $_.Var -eq $d }).Count | Should -Be 1 -Because "the declared lookup $d must be a lookup of this report"
            $firstJoin = [regex]::Match($script:Query.Substring($cut), ('join\s+kind\s*=\s*\w+\s*\(\s*{0}\b' -f [regex]::Escape($d)))
            $firstJoin.Success | Should -BeTrue -Because "the lookup $d must be joined after the cut point, not before it"
        }
        $head  = $Body.Substring(0, $Body.IndexOf('ReportQuery:'))
        $block = [regex]::Match($head, '(?s)LookupNeededKeys:.*?(?=\r?\n      [A-Za-z])').Value
        $lines = @($block -split "\r?\n" | ForEach-Object { $_.Trim() } | Where-Object { $_ -like '| extend *' })
        $lines.Count | Should -BeGreaterThan 0
        $flat = ($script:Query -split "\r?\n" | ForEach-Object { $_.Trim() })
        foreach ($ln in $lines) {
            $flat | Should -Contain $ln -Because 'a key computed differently from the report''s own would find the wrong pairs'
        }
        $block | Should -Match '(?m)^\s*\|\s*project __siNeeded = pack_array\('
        $block | Should -Match '(?m)^\s*Column:\s*\w+\s*$'
    }
}
