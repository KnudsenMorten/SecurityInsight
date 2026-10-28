#Requires -Version 5.1
<#
    AUDIT #98 -- an asset id must say WHERE IT CAME FROM.

    Operator, 2026-09-01: "does it stor the id source" / "so i know where it came from". It did not,
    and the answer was checked against the live tables rather than the code comments: `SI_IdSource`
    exists but belongs to the correlation layer (`ledger` vs `derived-provisional`) and ships on
    neither the risk-analysis tables nor the profile tables. The only `*Source` columns there are
    `CmdbSource` (which CMDB feed) and `DiscoverySourceProducts` (which product saw the asset).

    🔴 WHY IT IS WORTH A COLUMN, AND THE MEASUREMENT THAT SETTLED IT. The operator's own challenge
    was "is it used for something", and on ~98% of rows the answer would be identical. Measured over
    the 1000 distinct impacted-asset ids on one live snapshot: **978 SI-authored asset ids, 19
    ExposureGraph node ids (32 bare hex characters), 3 ARM resource ids carrying an `az:` prefix,
    and 3 raw IPv4 addresses.** The 2% that differ are precisely the ids nobody can resolve, and an
    SI asset id and an EG node id are both hex -- they look alike and live in different systems.

    🪤 THE `az:` PREFIX IS THE TELL. Somebody already hit this and solved it on one path by mangling
    the VALUE with a namespace marker, which breaks joins: an `az:`-prefixed id matches nothing in
    the profile tables. That is why the answer is a separate additive column, not a prefix
    convention extended to the other three namespaces.
#>

BeforeAll {
    $shared = Join-Path (Split-Path -Parent (Split-Path -Parent $PSScriptRoot)) 'engine\risk-analysis\_shared'
    . (Join-Path $shared 'RA-AssetIdentityMap.ps1')
}

Describe 'Get-SIAssetIdSource -- audit #98' {

    Context 'the four namespaces measured on the live snapshot' {

        It 'names an ExposureGraph node id, which is 32 hex characters with NO dashes' {
            Get-SIAssetIdSource -AssetId '2e0935f3af34462ca62f6efa231312f7' |
                Should -Be 'Exposure Graph node id'
        }

        It 'names an Azure resource id whether or not it carries the az: prefix' {
            Get-SIAssetIdSource -AssetId 'az:/subscriptions/7e867037-59b5-4edc-97ee-3f904de63b79' |
                Should -Be 'Azure resource id'
            Get-SIAssetIdSource -AssetId '/subscriptions/7e867037/resourceGroups/rg-x' |
                Should -Be 'Azure resource id'
        }

        It 'names an IP address, which for a public-IP report genuinely IS the asset' {
            Get-SIAssetIdSource -AssetId '108.143.47.209' | Should -Be 'IP address'
            Get-SIAssetIdSource -AssetId '2001:db8::1'    | Should -Be 'IP address'
        }
    }

    Context 'the distinction that cannot be made from the value' {

        It 'prefers what this run AUTHORED over what the value looks like' {
            # 🔴 THE LOAD-BEARING CASE. A GUID that we authored and a GUID we did not are the same
            # shape. Reading the shape first would file every SI asset id as a directory object and
            # send an operator to the wrong system. The map answers first, always.
            $id = '4f302285-3ad7-405e-b9cb-be411b20f04c'
            Get-SIAssetIdSource -AssetId $id | Should -Not -Be 'SecurityInsight asset id'

            $ids = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
            [void]$ids.Add($id)
            Set-Variable -Name '_SIIdentityIds' -Value $ids -Scope Script

            Get-SIAssetIdSource -AssetId $id | Should -Be 'SecurityInsight asset id'
        }

        It 'matches the map case-insensitively, because MDE, ARM and EG disagree about case constantly' {
            $ids = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
            [void]$ids.Add('ABCDEF01-2345-6789-ABCD-EF0123456789')
            Set-Variable -Name '_SIIdentityIds' -Value $ids -Scope Script

            Get-SIAssetIdSource -AssetId 'abcdef01-2345-6789-abcd-ef0123456789' |
                Should -Be 'SecurityInsight asset id'
        }

        It 'treats an ABSENT map as "unknown", never as "not ours"' {
            # 🪤 The map is built once per run and may legitimately be missing -- a run that never
            # needed it, or a table this install does not have. Absent is not a negative answer, so
            # the id must fall through to shape rather than be declared foreign.
            Set-Variable -Name '_SIIdentityIds' -Value $null -Scope Script
            { Get-SIAssetIdSource -AssetId '4f302285-3ad7-405e-b9cb-be411b20f04c' } | Should -Not -Throw
            Get-SIAssetIdSource -AssetId '2e0935f3af34462ca62f6efa231312f7' |
                Should -Be 'Exposure Graph node id'
        }
    }

    Context 'the answers that must not be silent' {

        It 'returns blank for a blank id, so a row with no id does not gain a fake provenance' {
            Get-SIAssetIdSource -AssetId ''    | Should -Be ''
            Get-SIAssetIdSource -AssetId '   ' | Should -Be ''
            Get-SIAssetIdSource -AssetId $null | Should -Be ''
        }

        It 'NAMES an unrecognised format rather than blanking it' {
            # 📌 "Unrecognized" is a fact an operator can act on. A blank reads as a missing value
            # and invites the reader to assume the id is fine.
            Get-SIAssetIdSource -AssetId 'srv01.contoso.local' | Should -Be 'Unrecognized id format'
        }
    }

    Context 'is it REACHABLE -- the question six never-wired defects went unasked' {

        It 'is actually called by the risk-analysis engine, not merely defined' {
            # 🔑 Green unit tests never prove a feature is reachable. Five "declared but never
            # wired" cases in this solution are the reason this is its own assertion.
            $engine = Join-Path (Split-Path -Parent (Split-Path -Parent $PSScriptRoot)) 'engine\risk-analysis\Invoke-RiskAnalysis.ps1'
            $src = Get-Content -LiteralPath $engine -Raw
            $src | Should -Match 'Get-SIAssetIdSource\s+-AssetId'
            $src | Should -Match "AssetIdSource"
        }

        It 'the engine fills the column only where an AssetId actually exists' {
            # 📌 Additive means adding DATA where the id is, never a column to a report that
            # publishes no asset id at all.
            $engine = Join-Path (Split-Path -Parent (Split-Path -Parent $PSScriptRoot)) 'engine\risk-analysis\Invoke-RiskAnalysis.ps1'
            $src = Get-Content -LiteralPath $engine -Raw
            $src | Should -Match "OutputPropertyOrder -contains 'AssetId'"
        }
        It 'never fills AssetId from a recommendation or setting id (#193)' {
            # A connector keys on AssetId. A ConfigurationId (scid-2090, a recommendation name) published there
            # files the finding against an "asset" that does not exist.
            $engine = Join-Path (Split-Path -Parent (Split-Path -Parent $PSScriptRoot)) 'engine\risk-analysis\Invoke-RiskAnalysis.ps1'
            $line = [regex]::Match((Get-Content -LiteralPath $engine -Raw), "@\{ Target = 'AssetId';\s+Candidates = @\(([^)]*)\)").Groups[1].Value
            $line | Should -Not -BeNullOrEmpty
            $line | Should -Not -Match 'Configuration'
            $line | Should -Match "^'SI_AssetId'" -Because 'the authored v3 id stays first'
        }
    }
}
