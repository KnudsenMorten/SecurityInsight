#Requires -Version 5.1
<#
.SYNOPSIS
    Pester v5 -- the asset-profiling PROVIDER CONTRACT (audit #42 / #44, suite T1).

.DESCRIPTION
    `asset-profiling-providers/_manifest.schema.locked.json` defines the contract every connector
    must satisfy, and until now **nothing validated any manifest against it**. The schema is a
    JSON-Schema document that no part of the engine reads: providers were checked by eye.

    That matters more as connectors multiply (#42: ServiceNow live REST, an MCP client, a SQL
    source). A manifest is the only machine-readable description of what a provider IS -- its
    direction (`kind`), which engines it feeds, how it authenticates, whether it pages in bulk, and
    what call budget it must respect. A typo in it is silent: the provider still loads, and the
    field that would have constrained it simply never matches.

    PowerShell 5.1 has no JSON-Schema validator, and adding a dependency to satisfy one test would
    be worse than the problem. So this suite reads the schema and enforces its *required keys,
    enums and patterns* directly -- which also means the schema stays the single source of truth:
    the cases below derive their expectations FROM it rather than restating them.

    It also REPORTS, rather than fails on, the gap that matters most right now: ServiceNow's
    manifest declares `kind: both` + `auth: api-key` + `bulk: true`, but `Refresh-CmdbCache.ps1`
    contains no REST call at all and ships in sample-CSV mode. A declared-but-unimplemented
    provider is exactly the "armed but not firing" shape this audit chapter has now hit five times
    (#1, #3, #7, #9, #3a), so it is pinned here where it cannot quietly persist.
#>

BeforeAll {
    # tests/pester/<file>.ps1 -> tests/pester -> tests -> solution root (3 levels up)
    $_root = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
    $script:SiRoot        = $_root
    $script:ProviderRoot  = Join-Path $_root 'asset-profiling-providers'
    $script:SchemaPath    = Join-Path $script:ProviderRoot '_manifest.schema.locked.json'

    $script:Schema = $null
    if (Test-Path $script:SchemaPath) {
        $script:Schema = Get-Content -Raw -LiteralPath $script:SchemaPath | ConvertFrom-Json
    }

    # Every provider folder, with its manifest (locked or plain) parsed.
    # @() wraps the WHOLE pipeline -- `@(x) | Where-Object` unwraps a single result, which would
    # make .Count return $null on a one-provider tree and quietly skip every case below.
    $script:Providers = @(
        Get-ChildItem -Path $script:ProviderRoot -Directory -ErrorAction SilentlyContinue |
            ForEach-Object {
                $dir = $_
                $mf  = Get-ChildItem -Path $dir.FullName -Filter 'manifest*.json' -File -ErrorAction SilentlyContinue |
                       Select-Object -First 1
                $json = $null
                $parseError = $null
                if ($mf) {
                    try { $json = Get-Content -Raw -LiteralPath $mf.FullName | ConvertFrom-Json }
                    catch { $parseError = $_.Exception.Message }
                }
                [pscustomobject]@{
                    Folder       = $dir.Name
                    Path         = $dir.FullName
                    ManifestPath = if ($mf) { $mf.FullName } else { $null }
                    Manifest     = $json
                    ParseError   = $parseError
                }
            }
    )

    function Get-SchemaEnum {
        param([Parameter(Mandatory)][string]$Property)
        if (-not $script:Schema) { return @() }
        $p = $script:Schema.properties.$Property
        if ($p -and $p.enum) { return @($p.enum) }
        return @()
    }
}

# ============================================================================
Describe 'the provider manifest schema itself' {
# ============================================================================

    It 'the locked schema exists where providers reference it' {
        Test-Path $script:SchemaPath | Should -BeTrue
    }

    It 'parses, and declares the required keys the engine depends on' {
        $script:Schema | Should -Not -BeNullOrEmpty
        $req = @($script:Schema.required)
        foreach ($k in @('id','kind','engines','auth','bulk')) { $req | Should -Contain $k }
    }

    It 'at least one provider exists to validate' {
        # Guards against the whole suite passing vacuously if the folder is ever moved --
        # the exact failure mode audit #29 part 2 found in the rule lint, which scanned two
        # folders that no longer existed and reported clean over ZERO files.
        $script:Providers.Count | Should -BeGreaterThan 0
    }
}

# ============================================================================
Describe 'every provider satisfies the contract' {
# ============================================================================

    It 'every provider folder has a manifest, and it parses' {
        $bad = @($script:Providers | Where-Object { -not $_.ManifestPath -or $_.ParseError })
        ($bad | ForEach-Object { "$($_.Folder): $(if($_.ParseError){$_.ParseError}else{'no manifest*.json'})" }) -join ' || ' |
            Should -BeNullOrEmpty
    }

    It 'every manifest declares all schema-required keys' {
        $req = @($script:Schema.required)
        $missing = @()
        foreach ($p in $script:Providers) {
            if (-not $p.Manifest) { continue }
            $names = @($p.Manifest.PSObject.Properties.Name)
            foreach ($k in $req) { if ($names -notcontains $k) { $missing += "$($p.Folder) missing '$k'" } }
        }
        $missing -join ' || ' | Should -BeNullOrEmpty
    }

    It 'every manifest id equals its folder name' {
        # The id is how the engine resolves a provider to a directory. A mismatch means the
        # manifest describes one provider and the code loads another.
        $bad = @($script:Providers | Where-Object { $_.Manifest -and $_.Manifest.id -cne $_.Folder })
        ($bad | ForEach-Object { "$($_.Folder) declares id '$($_.Manifest.id)'" }) -join ' || ' |
            Should -BeNullOrEmpty
    }

    It 'every manifest id matches the schema pattern (lowercase + dashes)' {
        $pattern = $script:Schema.properties.id.pattern
        $pattern | Should -Not -BeNullOrEmpty
        $bad = @($script:Providers | Where-Object { $_.Manifest -and $_.Manifest.id -notmatch $pattern })
        ($bad | ForEach-Object { $_.Folder }) -join ' || ' | Should -BeNullOrEmpty
    }

    It 'every kind is one the schema allows' {
        $allowed = Get-SchemaEnum -Property 'kind'
        $allowed.Count | Should -BeGreaterThan 0
        $bad = @($script:Providers | Where-Object { $_.Manifest -and $allowed -notcontains $_.Manifest.kind })
        ($bad | ForEach-Object { "$($_.Folder): kind='$($_.Manifest.kind)'" }) -join ' || ' |
            Should -BeNullOrEmpty
    }

    It 'every auth.type is one the schema allows' {
        $allowed = @($script:Schema.properties.auth.properties.type.enum)
        $allowed.Count | Should -BeGreaterThan 0
        $bad = @($script:Providers | Where-Object { $_.Manifest -and $allowed -notcontains $_.Manifest.auth.type })
        ($bad | ForEach-Object { "$($_.Folder): auth.type='$($_.Manifest.auth.type)'" }) -join ' || ' |
            Should -BeNullOrEmpty
    }

    It 'every declared engine is a real SI engine' {
        $allowed = @($script:Schema.properties.engines.items.enum)
        $allowed.Count | Should -BeGreaterThan 0
        $bad = @()
        foreach ($p in $script:Providers) {
            if (-not $p.Manifest) { continue }
            foreach ($e in @($p.Manifest.engines)) {
                if ($allowed -notcontains $e) { $bad += "$($p.Folder): engine '$e'" }
            }
        }
        $bad -join ' || ' | Should -BeNullOrEmpty
    }

    It 'engines is non-empty -- a provider that feeds nothing is dead weight' {
        $bad = @($script:Providers | Where-Object { $_.Manifest -and @($_.Manifest.engines).Count -eq 0 })
        ($bad | ForEach-Object { $_.Folder }) -join ' || ' | Should -BeNullOrEmpty
    }

    It 'bulk is a real boolean, not the string "true"' {
        # JSON "true" and true are different things, and the engine branches on it.
        $bad = @($script:Providers | Where-Object { $_.Manifest -and $_.Manifest.bulk -isnot [bool] })
        ($bad | ForEach-Object { "$($_.Folder): bulk is $($_.Manifest.bulk.GetType().Name)" }) -join ' || ' |
            Should -BeNullOrEmpty
    }

    It 'any declared rateLimit.per matches the schema pattern' {
        $pattern = $script:Schema.properties.rateLimit.properties.per.pattern
        $bad = @()
        foreach ($p in $script:Providers) {
            if (-not $p.Manifest -or -not $p.Manifest.rateLimit) { continue }
            $per = $p.Manifest.rateLimit.per
            if ($per -and $per -notmatch $pattern) { $bad += "$($p.Folder): per='$per'" }
        }
        $bad -join ' || ' | Should -BeNullOrEmpty
    }
}

# ============================================================================
Describe 'declared vs implemented -- the gap must stay visible' {
# ============================================================================

    It 'a provider declaring auth other than none does not ship as a file reader' -Skip:$false {
        # REPORT, not a hard fail on ServiceNow specifically: this is the general property, and
        # ServiceNow is currently its one violator (#42). When the live REST read lands (build
        # order 44.8 phase 2) this case starts passing on its own, and it will FAIL again the day
        # someone adds another manifest promising an API it has not written.
        $offenders = @()
        foreach ($p in $script:Providers) {
            if (-not $p.Manifest) { continue }
            if ($p.Manifest.auth.type -eq 'none') { continue }
            $code = @(Get-ChildItem -Path $p.Path -Filter '*.ps1' -File -Recurse -ErrorAction SilentlyContinue |
                      ForEach-Object { Get-Content -Raw -LiteralPath $_.FullName })
            if ($code.Count -eq 0) { continue }
            $joined = $code -join "`n"
            $callsHttp = $joined -match 'Invoke-RestMethod|Invoke-WebRequest|Invoke-SIPagedRest|HttpClient'
            if (-not $callsHttp) { $offenders += $p.Folder }
        }
        # Known and tracked: servicenow-cmdb ships in sample-CSV mode (#42, build order phase 2).
        $unexpected = @($offenders | Where-Object { $_ -ne 'servicenow-cmdb' })
        $unexpected -join ' || ' | Should -BeNullOrEmpty
    }

    It 'servicenow-cmdb is still the ONLY declared-but-unimplemented provider' {
        # Pins the exception above so it cannot silently grow into a habit. When ServiceNow gains
        # its REST path this case fails and BOTH it and the exception get deleted together --
        # which is the point: the exception cannot outlive the gap it documents.
        $sn = @($script:Providers | Where-Object { $_.Folder -eq 'servicenow-cmdb' })
        $sn.Count | Should -Be 1
        $code = @(Get-ChildItem -Path $sn[0].Path -Filter '*.ps1' -File -Recurse -ErrorAction SilentlyContinue |
                  ForEach-Object { Get-Content -Raw -LiteralPath $_.FullName }) -join "`n"
        $code | Should -Not -BeNullOrEmpty
        ($code -match 'Invoke-RestMethod|Invoke-WebRequest|Invoke-SIPagedRest') | Should -BeFalse `
            -Because 'when this fails, ServiceNow has gained its live REST path -- delete this case AND the allowance above it'
    }

    It 'the contract doc referenced by the schema is recorded as missing' {
        # _manifest.schema.locked.json says "See _PROVIDER_CONTRACT.md" and no such file exists
        # anywhere in the tree (#42). Anyone writing the next provider has the JSON schema but no
        # statement of what Read-<X>ProviderData must RETURN. Asserted so the gap is visible in a
        # test run rather than only in a backlog entry.
        $schemaText = Get-Content -Raw -LiteralPath $script:SchemaPath
        $schemaText | Should -Match '_PROVIDER_CONTRACT\.md'
        $found = @(Get-ChildItem -Path $script:SiRoot -Filter '_PROVIDER_CONTRACT.md' -Recurse -File -ErrorAction SilentlyContinue)
        $found.Count | Should -Be 0 `
            -Because 'when this fails the contract doc has been written -- delete this case and drop the #42 gap note'
    }
}

# ============================================================================
Describe 'negative verification -- these cases can actually fail' {
# ============================================================================

    It 'the required-key case notices a manifest missing a required key' {
        $req = @($script:Schema.required)
        $fake = [pscustomobject]@{ id = 'x'; kind = 'in' }   # missing engines/auth/bulk
        $names = @($fake.PSObject.Properties.Name)
        $missing = @($req | Where-Object { $names -notcontains $_ })
        $missing.Count | Should -BeGreaterThan 0
    }

    It 'the enum case notices an invalid kind' {
        $allowed = Get-SchemaEnum -Property 'kind'
        $allowed | Should -Not -Contain 'sideways'
    }

    It 'the id-matches-folder case notices a mismatch' {
        $fake = [pscustomobject]@{ Folder = 'servicenow-cmdb'; Manifest = [pscustomobject]@{ id = 'snow' } }
        ($fake.Manifest.id -cne $fake.Folder) | Should -BeTrue
    }
}
