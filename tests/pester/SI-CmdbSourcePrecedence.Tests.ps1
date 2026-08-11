#Requires -Version 5.1
<#
    AUDIT #58.1 / #58.2 / #58.3 -- CMDB source precedence.

    Operator, 2026-08-11: "if servicenow connector is enabled. then it wins over any generic cmdb.csv
    file. only one cmdb can be active ... with fail-loud".

    The rules being pinned are not arithmetic -- they are the difference between an answer you can
    explain and one you cannot. Blending two CMDBs makes "why does this asset say Critical?"
    unanswerable (#54's defect class), and silently substituting one for another hands the customer
    plausible-but-stale data on a green run (#57's defect class).
#>

BeforeAll {
    $shared = Join-Path (Split-Path -Parent (Split-Path -Parent $PSScriptRoot)) 'engine\asset-profiling\shared'
    . (Join-Path $shared 'CmdbSource.ps1')
}

Describe 'CMDB source precedence -- audit #58.1' {

    Context 'the catalog' {

        It 'declares a strict order with no ties -- a tie would make the winner arbitrary' {
            $cat = @(Get-SICmdbSourceCatalog)
            $cat.Count | Should -BeGreaterThan 1
            $orders = @($cat | ForEach-Object { [int]$_.Order })
            (@($orders | Sort-Object -Unique)).Count | Should -Be $orders.Count
        }

        It 'ranks ServiceNow above the generic CSV, which is the operator instruction' {
            $cat = @(Get-SICmdbSourceCatalog)
            $sn  = $cat | Where-Object { $_.Id -eq 'servicenow' }
            $csv = $cat | Where-Object { $_.Id -eq 'generic-csv' }
            [int]$sn.Order | Should -BeLessThan ([int]$csv.Order)
        }

        It 'marks the generic CSV as Free and implemented, and ServiceNow as Pro and NOT implemented' {
            # 🔴 The free CSV importer must never be gated. `cmdbName` alone appears ~510x in the report
            # catalog, so a loose "ServiceNow = Pro" would break both customer populations at once.
            $cat = @(Get-SICmdbSourceCatalog)
            $csv = $cat | Where-Object { $_.Id -eq 'generic-csv' }
            $sn  = $cat | Where-Object { $_.Id -eq 'servicenow' }
            $csv.Edition     | Should -Be 'Free'
            $csv.Implemented | Should -BeTrue
            $sn.Edition      | Should -Be 'Pro'
            $sn.Implemented  | Should -BeFalse -Because 'the rich ServiceNow CMDB does not exist yet'
        }
    }

    Context 'resolution' {

        It 'selects the generic CSV when it is the only source available' {
            $r = Resolve-SICmdbSource -Available @{ 'generic-csv' = $true; 'servicenow' = $false }
            $r.Source | Should -Be 'generic-csv'
            $r.Fatal  | Should -BeFalse
        }

        It 'selects none, without error, when nothing is configured' {
            $r = Resolve-SICmdbSource -Available @{ 'generic-csv' = $false; 'servicenow' = $false }
            $r.Source | Should -Be 'none'
            $r.Fatal  | Should -BeFalse
        }

        It 'treats an unknown / absent key as not-available rather than throwing' {
            # A partially-populated availability map is a configuration state, not a crash.
            { Resolve-SICmdbSource -Available @{} } | Should -Not -Throw
            (Resolve-SICmdbSource -Available @{}).Source | Should -Be 'none'
        }

        It 'NEVER merges: with two sources available, the lower-precedence one is SHADOWED' {
            # Pinned with a catalog whose higher source IS implemented, so this tests the ordering
            # rule itself rather than the not-implemented refusal below.
            $cat = @(
                @{ Id = 'richcmdb';    Order = 1; Edition = 'Pro';  Implemented = $true;  Description = 'test rich CMDB' },
                @{ Id = 'generic-csv'; Order = 3; Edition = 'Free'; Implemented = $true;  Description = 'CSV' }
            )
            $r = Resolve-SICmdbSource -Available @{ 'richcmdb' = $true; 'generic-csv' = $true } -Catalog $cat
            $r.Source     | Should -Be 'richcmdb'
            $r.Shadowed   | Should -Contain 'generic-csv'
            $r.Fatal      | Should -BeFalse
        }

        It 'SAYS OUT LOUD that the shadowed source stopped being read' {
            # A customer who maintains a CSV and then enables a live CMDB must be told their CSV is no
            # longer read -- not discover it from risk scores that moved for no visible reason.
            $cat = @(
                @{ Id = 'richcmdb';    Order = 1; Edition = 'Pro';  Implemented = $true; Description = 'test rich CMDB' },
                @{ Id = 'generic-csv'; Order = 3; Edition = 'Free'; Implemented = $true; Description = 'CSV' }
            )
            $r = Resolve-SICmdbSource -Available @{ 'richcmdb' = $true; 'generic-csv' = $true } -Catalog $cat
            $r.Reason | Should -Match 'NOT merged'
            $r.Reason | Should -Match 'generic-csv'
        }
    }

    Context 'fail-loud -- audit #58.2' {

        It 'REFUSES a source that is declared available but not implemented' {
            # This is the live shape today: someone sets the ServiceNow flag, but the connector does
            # not exist. Selecting it would leave cmdb* empty while the log claimed a rich CMDB won.
            $r = Resolve-SICmdbSource -Available @{ 'servicenow' = $true; 'generic-csv' = $true }
            $r.Fatal  | Should -BeTrue
            $r.Source | Should -Be 'none'
            $r.Reason | Should -Match 'NOT IMPLEMENTED'
        }

        It 'does NOT fall through to the CSV when the higher source is refused' {
            # 🔑 THE CORE OF #58.2. Falling through here is the tempting, friendly behaviour and it is
            # exactly wrong: the customer asked for ServiceNow data and would silently receive CSV
            # data instead. Wrong-but-plausible is worse than empty, because empty is visible.
            $r = Resolve-SICmdbSource -Available @{ 'servicenow' = $true; 'generic-csv' = $true }
            $r.Source | Should -Not -Be 'generic-csv'
        }

        It 'returns the refusal instead of throwing, so the caller decides how loud to be' {
            { Resolve-SICmdbSource -Available @{ 'servicenow' = $true } } | Should -Not -Throw
        }
    }

    Context 'availability from configuration' {

        It 'does not offer the CSV when the provider flag is off, even if the file exists' {
            $a = Get-SICmdbSourceAvailability -SolutionRoot (Split-Path -Parent (Split-Path -Parent $PSScriptRoot)) `
                                              -EnableCmdbProvider $false -EnableServiceNowCmdb $false
            $a['generic-csv'] | Should -BeFalse
        }

        It 'does not offer the CSV when the flag is on but no CSV was ever delivered' {
            # "enabled but the file is missing" must resolve to none-with-a-reason, not to a source
            # that cannot answer -- otherwise every row is silently blank and the log says CSV won.
            $tmp = Join-Path ([System.IO.Path]::GetTempPath()) ("si-cmdb-{0}" -f ([guid]::NewGuid().ToString('N')))
            New-Item -ItemType Directory -Path $tmp -Force | Out-Null
            try {
                $a = Get-SICmdbSourceAvailability -SolutionRoot $tmp -EnableCmdbProvider $true -EnableServiceNowCmdb $false
                $a['generic-csv'] | Should -BeFalse
                (Resolve-SICmdbSource -Available $a).Source | Should -Be 'none'
            } finally { Remove-Item -Recurse -Force $tmp -ErrorAction SilentlyContinue }
        }

        It 'finds the CSV in the PRE-v2.2.421 folder too, so an existing customer file is never ignored' {
            # The provider was renamed generic-cmdb <- servicenow-cmdb. A customer who has not moved
            # their CSV must keep working; silently ignoring it would empty cmdb* on a green run.
            $tmp = Join-Path ([System.IO.Path]::GetTempPath()) ("si-cmdb-{0}" -f ([guid]::NewGuid().ToString('N')))
            New-Item -ItemType Directory -Path (Join-Path $tmp 'asset-profiling-providers\servicenow-cmdb') -Force | Out-Null
            Set-Content -LiteralPath (Join-Path $tmp 'asset-profiling-providers\servicenow-cmdb\CMDB.csv') -Value 'cmdbID;cmdbName' -Encoding UTF8
            try {
                $a = Get-SICmdbSourceAvailability -SolutionRoot $tmp -EnableCmdbProvider $true -EnableServiceNowCmdb $false
                $a['generic-csv'] | Should -BeTrue
                (Resolve-SICmdbSource -Available $a).Source | Should -Be 'generic-csv'
            } finally { Remove-Item -Recurse -Force $tmp -ErrorAction SilentlyContinue }
        }
    }

    Context 'the source is visible in the DATA -- audit #58.3' {

        It 'Reconcile stamps CmdbSource onto every row' {
            $recon = Join-Path (Split-Path -Parent (Split-Path -Parent $PSScriptRoot)) 'engine\asset-profiling\stages\Invoke-Reconcile.ps1'
            $src   = [System.IO.File]::ReadAllText($recon)
            $src | Should -Match 'CmdbSource\s*=\s*\$__cmdbSourceForRun'
        }

        It 'Reconcile RE-RESOLVES rather than stamping a blank when Schedule did not set it' {
            # 🪤 A silently empty CmdbSource on every row is indistinguishable from the column-loss
            # defect #57.1(d) exists to catch. Do not manufacture the shape we now guard for.
            $recon = Join-Path (Split-Path -Parent (Split-Path -Parent $PSScriptRoot)) 'engine\asset-profiling\stages\Invoke-Reconcile.ps1'
            $src   = [System.IO.File]::ReadAllText($recon)
            $src | Should -Match 'IsNullOrWhiteSpace\(\$__cmdbSourceForRun\)'
            $src | Should -Match 'Resolve-SICmdbSource'
        }

        It 'CmdbSource is declared in every profile schema that carries the other Cmdb audit columns' {
            # Audit #48: a produced column missing from the DCR schema sample is DROPPED at ingest.
            # Enforced generally by SI-IngestSchemaCoverage; asserted here so this column's own
            # release cannot regress it.
            $schemaDir = Join-Path (Split-Path -Parent (Split-Path -Parent $PSScriptRoot)) 'asset-profiling-schema'
            foreach ($n in @('azure','endpoint','identity')) {
                $j = Get-Content (Join-Path $schemaDir "$n.schema.locked.json") -Raw | ConvertFrom-Json
                @($j.fields | Where-Object { $_.name -eq 'CmdbSource' }).Count |
                    Should -Be 1 -Because "$n must declare CmdbSource exactly once"
            }
        }
    }
}
