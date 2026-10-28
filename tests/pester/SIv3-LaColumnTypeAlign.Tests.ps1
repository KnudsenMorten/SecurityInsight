#Requires -Version 5.1
<#
    EVERY VALUE RA POSTS MATCHES THE TYPE OF THE LOG ANALYTICS COLUMN IT LANDS IN (#148).

    Log Analytics silently discards a value whose type differs from an existing column's. Measured on the
    internal workspace: SI_RiskAnalysis_Detailed_CL holds CriticalityTier as string, the engine sent ints,
    and the tier was missing on ~87% of Detailed rows while the export had every value. The engine now
    reads the table's real column types and converts sample and rows to them.
#>

BeforeAll {
    $script:SIRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
    . (Join-Path $script:SIRoot 'engine\risk-analysis\_shared\RA-ColumnTypeAlign.ps1')
}

Describe 'a value converts to the column type, culture-independent' {
    BeforeAll { $script:savedCulture = [System.Threading.Thread]::CurrentThread.CurrentCulture
                [System.Threading.Thread]::CurrentThread.CurrentCulture = [System.Globalization.CultureInfo]::GetCultureInfo('da-DK') }
    AfterAll  { [System.Threading.Thread]::CurrentThread.CurrentCulture = $script:savedCulture }

    It 'int into a string column becomes its text (the lost tier)' {
        (ConvertTo-RALaColumnValue -Value 0 -Type 'string').Value | Should -Be '0'
    }
    It 'a decimal into a string column keeps the invariant point on a da-DK host' {
        (ConvertTo-RALaColumnValue -Value 7.8 -Type 'string').Value | Should -Be '7.8'
    }
    It 'text digits into an int column become a number; a non-number is refused, not nulled' {
        (ConvertTo-RALaColumnValue -Value '3' -Type 'int').Value | Should -Be 3
        (ConvertTo-RALaColumnValue -Value 'Low' -Type 'int').Ok  | Should -BeFalse
        (ConvertTo-RALaColumnValue -Value 2.5 -Type 'long').Ok   | Should -BeFalse
    }
    It 'a list into a string column is kept as JSON' {
        (ConvertTo-RALaColumnValue -Value @('a','b') -Type 'string').Value | Should -Be '["a","b"]'
    }
    It 'dynamic / datetime / unknown types pass the value through unchanged' {
        (ConvertTo-RALaColumnValue -Value 7.8 -Type 'dynamic').Value | Should -Be 7.8
    }
}

Describe 'rows are converted in place and the report names every column touched' {
    It 'converts only declared, convertible columns and reports the rest' {
        $rows = @(
            [pscustomobject]@{ CriticalityTier = 0; Impact = 7.8; Weight = 100; Note = 'x' },
            [pscustomobject]@{ CriticalityTier = 2; Impact = 9.0; Weight = 'n/a'; Note = 'y' }
        )
        $types = @{ CriticalityTier = 'string'; Impact = 'dynamic'; Weight = 'int'; Note = 'string' }
        $rep = Set-RALaColumnTypes -Rows $rows -Types $types
        $rows[0].CriticalityTier | Should -Be '0'
        $rows[1].CriticalityTier | Should -Be '2'
        $rows[0].Impact          | Should -Be 7.8
        $rep.Converted['CriticalityTier'] | Should -Be 2
        $rep.Failed['Weight']             | Should -Be 1
        $rows[1].Weight          | Should -Be 'n/a'   # kept, and reported -- never silently nulled
    }
}

Describe 'a decimal CVSS in a whole-number column lands: exact in the _Exact companion (invariant text), rounded in the column' {
    BeforeAll { $script:savedCulture = [System.Threading.Thread]::CurrentThread.CurrentCulture
                [System.Threading.Thread]::CurrentThread.CurrentCulture = [System.Globalization.CultureInfo]::GetCultureInfo('da-DK') }
    AfterAll  { [System.Threading.Thread]::CurrentThread.CurrentCulture = $script:savedCulture }

    It '"7.9" and "7,9" are both 7.9 -- never 79 -- on a da-DK host' {
        ConvertTo-RADecimal '7.9' | Should -Be 7.9
        ConvertTo-RADecimal '7,9' | Should -Be 7.9
        ConvertTo-RADecimal 7.9   | Should -Be 7.9
        ConvertTo-RADecimal '79'  | Should -Be 79
        ConvertTo-RADecimal '1,234' | Should -BeNullOrEmpty   # a thousands separator is not a decimal comma
        ConvertTo-RADecimal 'High'  | Should -BeNullOrEmpty
        ConvertTo-RADecimal $true   | Should -BeNullOrEmpty
    }
    It 'a comma decimal in a real column is 7.9, and in an int column is refused rather than read as 79' {
        (ConvertTo-RALaColumnValue -Value '7,9' -Type 'real').Value | Should -Be 7.9
        (ConvertTo-RALaColumnValue -Value '7,9' -Type 'int').Ok     | Should -BeFalse
    }
    It 'only an int column that receives a fraction gets a companion -- or one whose companion already exists' {
        $rows = @([pscustomobject]@{ Impact = 7.9; Tier = 2; Score = 9 }, [pscustomobject]@{ Impact = 9; Tier = 0; Score = 8 })
        $types = @{ Impact = 'int'; Tier = 'int'; Score = 'long'; Score_Exact = 'string'; Name = 'string' }
        @(Get-RALaDecimalCompanions -Rows $rows -Types $types) | Should -Be @('Impact', 'Score')
        @(Get-RALaDecimalCompanions -Rows @([pscustomobject]@{ Impact = 9 }) -Types @{ Impact = 'int' }).Count | Should -Be 0
    }
    It 'every numeric row gets the exact value in the companion and the rounded value in the column' {
        $rows = @(
            [pscustomobject]@{ Impact = 7.9 }, [pscustomobject]@{ Impact = '7,5' },
            [pscustomobject]@{ Impact = 9 },   [pscustomobject]@{ Impact = $null }
        )
        $rep = Set-RALaColumnTypes -Rows $rows -Types @{ Impact = 'int' } -DecimalCompanions @('Impact')
        $rows[0].Impact | Should -Be 8;  $rows[0].Impact_Exact | Should -BeExactly '7.9'
        $rows[1].Impact | Should -Be 8;  $rows[1].Impact_Exact | Should -BeExactly '7.5'
        $rows[2].Impact | Should -Be 9;  $rows[2].Impact_Exact | Should -BeExactly '9'
        $rows[3].Impact | Should -BeNullOrEmpty; $rows[3].Impact_Exact | Should -BeNullOrEmpty
        $rows[0].Impact_Exact | Should -BeOfType [string]   # text: the ingest module mistypes a double column
        $rep.Rounded['Impact'] | Should -Be 2
        $rep.Failed.Count      | Should -Be 0
    }
    It 'TEXT in a number column (the measured sentence in Impact) lands in the _Text companion; numbers stay numbers' {
        $types = @{ Impact = 'int' }
        $rows = @(
            [pscustomobject]@{ Impact = '84 asset(s) at tier 3 are suppressed from every Risk Analysis report.' },
            [pscustomobject]@{ Impact = 7.9 }, [pscustomobject]@{ Impact = 9 }
        )
        $txt = @(Get-RALaTextCompanions -Rows $rows -Types $types)
        $dec = @(Get-RALaDecimalCompanions -Rows $rows -Types $types)
        $txt | Should -Be @('Impact'); $dec | Should -Be @('Impact')
        $rep = Set-RALaColumnTypes -Rows $rows -Types $types -DecimalCompanions $dec -TextCompanions $txt
        $rows[0].Impact_Text | Should -Be '84 asset(s) at tier 3 are suppressed from every Risk Analysis report.'
        $rows[0].Impact      | Should -BeNullOrEmpty
        $rows[1].Impact_Text | Should -BeNullOrEmpty
        $rows[1].Impact | Should -Be 8; $rows[1].Impact_Exact | Should -BeExactly '7.9'
        $rep.MovedToText['Impact'] | Should -Be 1
        $rep.Failed.Count | Should -Be 0     # nothing is left that cannot land
        @(Get-RALaTextCompanions -Rows @([pscustomobject]@{ Impact = '7,5' }) -Types $types).Count | Should -Be 0   # a decimal comma is a number, not text
    }
    It 'the schema sample always declares the companion as text, even with no value in it' {
        $sample = @([pscustomobject]@{ Impact = $null }, [pscustomobject]@{ Impact = $null })
        $null = Set-RALaColumnTypes -Rows $sample -Types @{ Impact = 'int' } -DecimalCompanions @('Impact') -EnsureCompanionTyped
        $sample[0].Impact_Exact | Should -BeOfType [string]
    }
    It 'EVERY sample row carries text in the companion (the module types a new column from the first row carrying it: an empty cell made it dynamic)' {
        $sample = @([pscustomobject]@{ Impact = $null; S = 'x' }, [pscustomobject]@{ Impact = 7.9; S = '84 assets ...' })
        $null = Set-RALaColumnTypes -Rows $sample -Types @{ Impact = 'int' } -DecimalCompanions @('Impact') -TextCompanions @('Impact') -EnsureCompanionTyped
        foreach ($r in $sample) { $r.Impact_Exact | Should -BeOfType [string]; $r.Impact_Text | Should -BeOfType [string] }
        $sample[1].Impact_Exact | Should -BeExactly '7.9'
    }
}

Describe 'the real column types are read from Azure, throttling included' {
    It '200: the map carries custom and standard columns' {
        Mock Invoke-SIAzRestMethod { [pscustomobject]@{ StatusCode = 200; Content = '{"properties":{"schema":{"columns":[{"name":"CriticalityTier","type":"string"}],"standardColumns":[{"name":"TimeGenerated","type":"datetime"}]}}}' } }
        $m = Get-RALaTableColumnTypes -WorkspaceResourceId '/subscriptions/s/resourceGroups/r/providers/Microsoft.OperationalInsights/workspaces/w' -TableName 'SI_RiskAnalysis_Detailed'
        $m['CriticalityTier'] | Should -Be 'string'
        $m['TimeGenerated']   | Should -Be 'datetime'
        Should -Invoke Invoke-SIAzRestMethod -ParameterFilter { $Path -like '*/tables/SI_RiskAnalysis_Detailed_CL?api-version=*' }
    }
    It '404 (a new table): an empty map, so the first ingest defines the types' {
        Mock Invoke-SIAzRestMethod { [pscustomobject]@{ StatusCode = 404; Content = '' } }
        (Get-RALaTableColumnTypes -WorkspaceResourceId '/w' -TableName 'T').Count | Should -Be 0
    }
    It 'throttled, then answered: retried and read' {
        $script:n = 0
        Mock Start-Sleep { }
        Mock Invoke-SIAzRestMethod { $script:n++; if ($script:n -eq 1) { [pscustomobject]@{ StatusCode = 429; Content = '' } } else { [pscustomobject]@{ StatusCode = 200; Content = '{"properties":{"schema":{"columns":[{"name":"A","type":"int"}]}}}' } } }
        (Get-RALaTableColumnTypes -WorkspaceResourceId '/w' -TableName 'T')['A'] | Should -Be 'int'
    }
    It 'forbidden: $null, so the caller says it could not check' {
        Mock Invoke-SIAzRestMethod { [pscustomobject]@{ StatusCode = 403; Content = '' } }
        Get-RALaTableColumnTypes -WorkspaceResourceId '/w' -TableName 'T' | Should -BeNullOrEmpty
    }
}

Describe 'WIRING -- the ingest converts the sample and the rows before posting' {
    It 'types are read before the DCR is declared, and applied to both sample and rows' {
        $src = Get-Content -LiteralPath (Join-Path $script:SIRoot 'engine\risk-analysis\Invoke-RiskAnalysis.ps1') -Raw
        $read = $src.IndexOf('Get-RALaTableColumnTypes -WorkspaceResourceId $laWs -TableName $laTable')
        # the companions are decided from EVERY row, declared through the sample, and applied to the posted rows
        $src | Should -Match 'Get-RALaDecimalCompanions -Rows @\(\$__pgPage\)'
        $src | Should -Match 'Get-RALaTextCompanions -Rows @\(\$__pgPage\)'
        $src | Should -Match 'Set-RALaColumnTypes -Rows \$schemaSample -Types \$__laTypes -DecimalCompanions \$__decCols -TextCompanions \$__txtCols -NumberCompanions \$__numCols -EnsureCompanionTyped'
        # the posted rows are aligned chunk by chunk (RA-Delivery.ps1), with the same types and companions
        $src | Should -Match 'ConvertTo-RALaPostRows -Rows \$__chunk -HostName \$__raHost -Fqdn \$__raFqdn -User \$__raUser\s*`\s*-Types \$__laTypes -DecimalCompanions \$__decCols -TextCompanions \$__txtCols -NumberCompanions \$__numCols'
        $del = Get-Content -LiteralPath (Join-Path $script:SIRoot 'engine\risk-analysis\_shared\RA-Delivery.ps1') -Raw
        $del | Should -Match 'Set-RALaColumnTypes -Rows \$data -Types \$Types -DecimalCompanions \$DecimalCompanions -TextCompanions \$TextCompanions -NumberCompanions \$NumberCompanions'
        # rounding happens on COPIES, never on the report's own rows
        $del | Should -Match '\[void\]\$copies\.Add\(\$r\.PSObject\.Copy\(\)\)'
        $del.IndexOf('$r.PSObject.Copy()') | Should -BeLessThan $del.IndexOf('Set-RALaColumnTypes -Rows $data')
        $samp = $src.IndexOf('Set-RALaColumnTypes -Rows $schemaSample')
        $decl = $src.IndexOf('$null = Update-SILogTableSchema')
        $rows = $src.IndexOf('ConvertTo-RALaPostRows -Rows $__chunk')
        $post = $src.IndexOf('Send-SILogData', $rows)
        $read | Should -BeGreaterThan 0
        $read | Should -BeLessThan $samp
        $samp | Should -BeLessThan $decl
        $rows | Should -BeGreaterThan $decl
        $rows | Should -BeLessThan $post
    }
}
