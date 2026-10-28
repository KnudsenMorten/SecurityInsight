#Requires -Version 5.1
<#
    AUDIT #59.3 / N1 + N8 -- the CMDB column naming contract.

    Operator, 2026-08-11, on the column model: "it is about having the right columns that adds value
    to a security person", in service of "a consistent model when we add webfrontend and connectors"
    -- and the example given was `cmdbName` vs `CmdbName`.

    WHAT THE MEASUREMENT ACTUALLY FOUND. Across all four profile schemas, exactly 4 of 606 distinct
    column names are camelCase and 602 are Pascal. The 4 are cmdbId / cmdbName / cmdbCriticality /
    cmdbDataSensitivity. Casing by declared source:

        derived 190, azure 189, exposureGraph 169, entra 55, mde 53, shodan 9, mdi 5  -- ALL Pascal
        cmdb 12                                                                        -- ALL camel

    So "casing encodes provenance" is FALSE as a general rule: 480 externally-sourced fields are
    Pascal. But WITHIN the cmdb family the split is coherent and useful:

        cmdb…  (camel)  = a value copied VERBATIM from the CMDB record   (source: cmdb)
        Cmdb…  (Pascal) = SI's own METADATA about the match              (source: derived)

    DECISION (operator, 2026-08-11): rename NOTHING; document the rule and enforce it. Renaming is a
    breaking change to a live query surface -- ~30 paying customers and ~6,000 community installs bind
    `cmdbName`, and at finite LA retention with no backfill a rename SPLITS HISTORY so that no single
    query sees both sides. The actual defect was that the rule was never written down. It now lives in
    docs/DESIGN.md, and this file stops it drifting.

    🪤 THE ONE EXEMPTION IS EXPLICIT, NOT SILENT. LastSeenInCmdb carries a CMDB value and so "should"
    be cmdbLastSeen. It pre-dates the convention and renaming it would break the same way. It is
    listed below by name so that it is visible in the test output rather than quietly tolerated --
    a new column landing on the wrong side FAILS.
#>

# 🪤 DISCOVERY-TIME, NOT RUN-TIME. Pester expands `-ForEach` while DISCOVERING tests, before any
# BeforeAll has executed. A `-ForEach $script:Something` assigned in BeforeAll therefore expands to an
# EMPTY list, generating ZERO test cases -- and a suite that silently runs nothing still reports green.
# That happened here on the first run of this file: 3 tests x 3 engines = 9 assertions vanished and the
# summary said "15 Passed, 1 Failed", which is indistinguishable from those tests having passed.
# Keep this list a top-level literal. (Same defect class as #59.3's own measurement traps.)
$CmdbEnginesForDiscovery = @('endpoint', 'identity', 'azure')

BeforeAll {
    $script:SIRoot    = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    $script:SchemaDir = Join-Path $script:SIRoot 'asset-profiling-schema'

    # Engines whose schemas carry the CMDB family (publicip does not reconcile against CMDB).
    # Run-time copy; the discovery-time list above is what drives -ForEach.
    $script:CmdbEngines = @('endpoint', 'identity', 'azure')

    # The documented exception -- see the file header. Adding a name here is a deliberate act.
    $script:NamingExemptions = @('LastSeenInCmdb')

    $script:GetCmdbFields = {
        param($Engine)
        $p = Join-Path $script:SchemaDir "$Engine.schema.locked.json"
        $j = Get-Content $p -Raw | ConvertFrom-Json
        @($j.fields | Where-Object { $_.name -and $_.name -match 'cmdb' })
    }
}

Describe 'CMDB column naming contract -- audit #59.3 N1' {

    Context 'the value-vs-metadata rule holds in every schema' {

        It '<_>: every source=cmdb column is camelCase (a CMDB VALUE)' -ForEach $CmdbEnginesForDiscovery {
            $fields = & $script:GetCmdbFields $_
            $fields.Count | Should -BeGreaterThan 0
            foreach ($f in $fields | Where-Object { $_.source -eq 'cmdb' }) {
                if ($f.name -in $script:NamingExemptions) { continue }
                $f.name | Should -MatchExactly '^cmdb[A-Z]' `
                    -Because "$($f.name) carries a value copied from the CMDB, so it belongs in the cmdb* namespace"
            }
        }

        It '<_>: every derived Cmdb* column is PascalCase (SI MATCH METADATA)' -ForEach $CmdbEnginesForDiscovery {
            $fields = & $script:GetCmdbFields $_
            foreach ($f in $fields | Where-Object { $_.source -eq 'derived' -and $_.name -like 'Cmdb*' }) {
                $f.name | Should -MatchExactly '^Cmdb[A-Z]' `
                    -Because "$($f.name) is SI's account of the match, not a CMDB value"
            }
        }

        It '<_>: no column differs from another only by case' -ForEach $CmdbEnginesForDiscovery {
            # 🔴 KQL column references are CASE-SENSITIVE. Two columns differing only in case is the
            # failure the operator named: a consumer binds one spelling and silently gets nothing.
            $fields = & $script:GetCmdbFields $_
            $names  = @($fields.name)
            $folded = @($names | ForEach-Object { $_.ToLowerInvariant() })
            (@($folded | Sort-Object -Unique)).Count | Should -Be $names.Count `
                -Because "collision(s) in: $($names -join ', ')"
        }
    }

    Context 'the exemption list stays honest' {

        It 'contains only names that are actually declared, and each really does break the rule' {
            # An exemption for a column that no longer exists, or that now conforms, is dead weight
            # that hides the next real violation. Force it to be pruned.
            $all = @()
            foreach ($e in $script:CmdbEngines) { $all += & $script:GetCmdbFields $e }
            foreach ($x in $script:NamingExemptions) {
                $matching = @($all | Where-Object { $_.name -eq $x })
                $matching.Count | Should -BeGreaterThan 0 -Because "exemption '$x' must name a declared column"
                # It is exempt precisely because it is source=cmdb but NOT camelCase.
                $matching[0].source | Should -Be 'cmdb'
                $x | Should -Not -MatchExactly '^cmdb[A-Z]' -Because "'$x' would not need an exemption if it conformed"
            }
        }
    }

    Context 'the family is consistent ACROSS engines -- a connector reads all three' {

        It 'declares the identical CMDB column set in endpoint, identity and azure' {
            $sets = foreach ($e in $script:CmdbEngines) {
                , (@((& $script:GetCmdbFields $e).name) | Sort-Object)
            }
            $baseline = $sets[0] -join ','
            for ($i = 1; $i -lt $sets.Count; $i++) {
                ($sets[$i] -join ',') | Should -Be $baseline `
                    -Because "$($script:CmdbEngines[$i]) must expose the same CMDB columns as $($script:CmdbEngines[0])"
            }
        }
    }
}

Describe 'Every engine-emitted CMDB column is DECLARED -- audit #59.3 N8' {

    # N8: CmdbMatchRule, CmdbMatchConfidence and LastSeenInCmdb were emitted and coerced by the
    # engine, and documented in DESIGN.md, but declared in NO schema (0 declarations, 31 code
    # references). That is the inverse of #59.1's "declared with readers but never produced", and it
    # left schema-driven tooling -- including the column-fill work -- blind to three real columns.

    It 'declares every column in the engine cmdb string-coercion list' {
        $build = Join-Path $script:SIRoot 'engine\asset-profiling\shared\Build-EndpointProfileRow.ps1'
        $build | Should -Exist
        $txt = Get-Content $build -Raw

        $m = [regex]::Match($txt, '\$cmdbStringFields\s*=\s*@\(([^)]*)\)', 'Singleline')
        $m.Success | Should -BeTrue -Because 'the engine must still declare its cmdb string-field list'
        $emitted = @([regex]::Matches($m.Groups[1].Value, "'([^']+)'") | ForEach-Object { $_.Groups[1].Value })
        $emitted.Count | Should -BeGreaterThan 0

        $declared = @((& $script:GetCmdbFields 'endpoint').name)
        foreach ($col in $emitted) {
            $declared | Should -Contain $col `
                -Because "the engine emits '$col'; an undeclared column is invisible to schema-driven tooling"
        }
    }

    It 'declares CmdbMatchConfidence, which is the family''s only NUMERIC column' {
        # Handled outside the string-coercion list in Build-*ProfileRow.ps1, so the test above cannot
        # see it. Its type matters: a consumer that assumes the whole Cmdb* family is string breaks.
        foreach ($e in $script:CmdbEngines) {
            $f = @(& $script:GetCmdbFields $e | Where-Object { $_.name -eq 'CmdbMatchConfidence' })
            $f.Count | Should -Be 1 -Because "$e must declare CmdbMatchConfidence"
            $f[0].type | Should -Be 'real'
        }
    }
}
