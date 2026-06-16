#Requires -Version 5.1
<#
.SYNOPSIS
    Pre-publish gate test suite for SecurityInsight v2.2 (Pester v5).
.DESCRIPTION
    9 Describe blocks. Uses Pester v5 -ForEach so dynamic test cases work.
#>

BeforeDiscovery {
    # tests/pester/<file>.ps1 -> tests/pester -> tests -> v2.2 (3 ups from $PSCommandPath)
    $_v22 = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
    # v2.2 -> SecurityInsight -> SOLUTIONS -> AutomateIT (repo root, 3 more ups)
    $_repo = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $_v22))
    $script:_V22Root  = $_v22
    $script:_RepoRoot = $_repo

    $script:_AllYaml = @(Get-ChildItem -Path $_v22 -Filter '*.locked.yaml' -Recurse -File -ErrorAction SilentlyContinue) +
                      @(Get-ChildItem -Path $_v22 -Filter '*.custom.sample.yaml' -Recurse -File -ErrorAction SilentlyContinue) |
        Where-Object { $_.FullName -notmatch '[\\/](OUTPUT|logs|staging)[\\/]' }
    $script:_AllJson = Get-ChildItem -Path $_v22 -Filter '*.json' -Recurse -File -ErrorAction SilentlyContinue |
        Where-Object { $_.FullName -notmatch '[\\/](OUTPUT|logs|staging)[\\/]' -and $_.Name -notmatch '\.bak' }
    # Skip stale one-shot tool scripts (used during major doc restructure work; not part of shipped product).
    $script:_AllPs1 = Get-ChildItem -Path $_v22 -Filter '*.ps1' -Recurse -File -ErrorAction SilentlyContinue |
        Where-Object {
            $_.FullName -notmatch '[\\/](OUTPUT|logs|staging)[\\/]' -and
            $_.Name -notin @('Cleanup-SingleVersionVoice.ps1','Renumber-After-NewChapter3.ps1','Reverse-ReadmeRestructure.ps1','Strip-VersionFraming.ps1','Strip-VersionFraming-Pass2.ps1')
        }
    $script:_AllSamples = Get-ChildItem -Path $_v22 -Filter '*.custom.sample.json' -Recurse -File -ErrorAction SilentlyContinue
    $script:_LockedSchemas = Get-ChildItem -Path (Join-Path $_v22 'asset-profiling-schema') -Filter '*.schema.locked.json' -File -ErrorAction SilentlyContinue
}

BeforeAll {
    Import-Module powershell-yaml -Force
    # Path resolution after the v2.2 flatten:
    #   tests/pester/<file>.ps1 -> tests/pester -> tests -> SecurityInsight  (3 ups)
    #   SecurityInsight -> SOLUTIONS -> AutomateIT  (2 more ups, NOT 3 as before flatten)
    $_v22 = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
    $_repo = Split-Path -Parent (Split-Path -Parent $_v22)
    $script:V22Root  = $_v22
    $script:RepoRoot = $_repo
    $script:RaYaml   = Join-Path $_v22 'risk-analysis-detection\RiskAnalysis_Queries_Locked.yaml'
    $script:Readme   = Join-Path $_v22 'README.md'
    $script:RaCatalog   = ConvertFrom-Yaml (Get-Content -Raw -LiteralPath $script:RaYaml)
    $script:RaReports   = @($script:RaCatalog.Reports)
    $script:RaTemplates = @($script:RaCatalog.ReportTemplates)
    # Authoritative report count: count `- ReportName:` entries directly. ConvertFrom-Yaml
    # on Linux (GitHub Actions runner) sometimes undercounts vs the literal entry count.
    # Both should agree; if they don't, use the regex-derived total as truth.
    # v2.2.305 -- scope to the Reports section only. ReportTemplates[] entries also use
    # `- ReportName:` syntax (each template names itself that way), so a flat count
    # over the whole file overcounts by the template count -- e.g. 116 reports + 2
    # templates = 118 false-positive total, breaking README/docs drift checks.
    $rawYaml = Get-Content -Raw -LiteralPath $script:RaYaml
    $reportsSection = ($rawYaml -split '(?m)^ReportTemplates:')[0]
    $script:RaReportCount = ([regex]::Matches($reportsSection, '(?m)^\s+- ReportName:')).Count
}

# ============================================================================
Describe 'RepoHygiene' {
# ============================================================================

    It 'No customer .custom.yaml files tracked' {
        $bad = git -C $script:RepoRoot ls-files 'SOLUTIONS/SecurityInsight/**/*.custom.yaml' 2>$null |
                   Where-Object { $_ -notlike '*.custom.sample.yaml' }
            $bad | Should -BeNullOrEmpty -Because "leaks: $($bad -join ', ')"
    }

    It 'No customer .custom.json files tracked' {
        # The privilege-tier-catalog SHIPPED baseline is .locked.json (tracked
        # since v2.2.15); customer overrides at .custom.json stay ignored. So
        # the original "no .custom.json tracked" rule applies uniformly again --
        # no per-file exception needed.
        $bad = git -C $script:RepoRoot ls-files 'SOLUTIONS/SecurityInsight/**/*.custom.json' 2>$null |
                   Where-Object { $_ -notlike '*.custom.sample.json' -and $_ -notlike '*.exclude.json.sample' }
            $bad | Should -BeNullOrEmpty -Because "leaks: $($bad -join ', ')"
    }

    It 'No LauncherConfig.custom.ps1 tracked' {
        $bad = git -C $script:RepoRoot ls-files 'SOLUTIONS/SecurityInsight/**/LauncherConfig.custom.ps1' 2>$null
            $bad | Should -BeNullOrEmpty -Because "leaks: $($bad -join ', ')"
    }

    It 'No CMDB.csv outside /sample/ tracked' {
        $bad = git -C $script:RepoRoot ls-files 'SOLUTIONS/SecurityInsight/**/CMDB.csv' 2>$null |
                   Where-Object { $_ -notlike '*/sample/CMDB.csv' }
            $bad | Should -BeNullOrEmpty -Because "leaks: $($bad -join ', ')"
    }

    It 'No private-key files (.pfx/.cer/.key/.pem) tracked' {
        $bad = git -C $script:RepoRoot ls-files 'SOLUTIONS/SecurityInsight/' 2>$null |
                   Where-Object { $_ -match '\.(pfx|cer|key|pem)$' }
            $bad | Should -BeNullOrEmpty -Because "leaks: $($bad -join ', ')"
    }

    It 'No backup / editor temp files tracked (.bak, .swp, ~)' {
        $bad = git -C $script:RepoRoot ls-files 'SOLUTIONS/SecurityInsight/' 2>$null |
                   Where-Object { $_ -match '\.bak\b|\.swp$|~$' }
            $bad | Should -BeNullOrEmpty -Because "leaks: $($bad -join ', ')"
    }

    It 'No params.json (per-tenant config) tracked' {
        $bad = git -C $script:RepoRoot ls-files 'SOLUTIONS/SecurityInsight/' 2>$null |
                   Where-Object { $_ -match '(^|/)params\.json$|\.params\.json$' }
            $bad | Should -BeNullOrEmpty -Because "leaks: $($bad -join ', ')"
    }

    It 'No OUTPUT/logs/staging content tracked' {
        $bad = git -C $script:RepoRoot ls-files 'SOLUTIONS/SecurityInsight/' 2>$null |
                   Where-Object { $_ -match '/(OUTPUT|logs|staging)/' }
            $bad | Should -BeNullOrEmpty -Because "leaks: $($bad -join ', ')"
    }
}

# ============================================================================
Describe 'YamlValidity' {
# ============================================================================

    It 'YAML found' {
        # Direct probe (BeforeDiscovery script: vars don't always survive into It-scope).
        $count = (Get-ChildItem -Path $script:V22Root -Filter '*.locked.yaml' -Recurse -File -ErrorAction SilentlyContinue).Count
        $count | Should -BeGreaterThan 0
    }

    It 'parses: <_.Name>' -ForEach $script:_AllYaml {
        $null = ConvertFrom-Yaml (Get-Content -Raw -LiteralPath $_.FullName)
    }

    It 'RA YAML has at least 100 reports' {
        $script:RaReports.Count | Should -BeGreaterThan 99
    }

    It 'RA YAML has at least 2 ReportTemplates' {
        $script:RaTemplates.Count | Should -BeGreaterOrEqual 2
    }

    It 'RA YAML has both Summary and Detailed templates' {
        $names = $script:RaTemplates.ReportName
        $names | Should -Contain 'RiskAnalysis_Summary'
        $names | Should -Contain 'RiskAnalysis_Detailed'
    }
}

# ============================================================================
Describe 'JsonValidity' {
# ============================================================================

    It 'parses: <_.Name>' -ForEach $script:_AllJson {
        $null = Get-Content -Raw -LiteralPath $_.FullName | ConvertFrom-Json
    }

    It 'risk-analysis.schema.locked.json has $schema + domains' {
        $j = Get-Content -Raw -LiteralPath (Join-Path $script:V22Root 'risk-analysis-detection\risk-analysis.schema.locked.json') | ConvertFrom-Json
        $j.'$schema'  | Should -Not -BeNullOrEmpty
        $j.domains    | Should -Not -BeNullOrEmpty
    }

    It 'asset-profiling-schema/SCHEMA.locked.json present + parses' {
        $p = Join-Path $script:V22Root 'asset-profiling-schema\SCHEMA.locked.json'
        Test-Path $p | Should -BeTrue
        { Get-Content -Raw -LiteralPath $p | ConvertFrom-Json } | Should -Not -Throw
    }
}

# ============================================================================
Describe 'PowerShellSyntax' {
# ============================================================================

    It 'tokenizes: <_.Name>' -ForEach $script:_AllPs1 {
        $err = $null
        [void][System.Management.Automation.PSParser]::Tokenize((Get-Content -Raw -LiteralPath $_.FullName), [ref]$err)
        if ($err -and $err.Count) { throw ("Parse error: " + $err[0].Message) }
    }
}

# ============================================================================
Describe 'RAReportStructure' {
# ============================================================================

    It 'every Report has all required fields' {
        # Single-test summary form (avoids Pester v5 -ForEach hashtable scope-leak).
        $required = 'ReportName','ReportPurpose','SecurityDomain','OutputPropertyOrder','ReportQuery'
        $missing = @()
        foreach ($r in $script:RaReports) {
            foreach ($f in $required) {
                if ($null -eq $r.$f -or ($r.$f -is [string] -and [string]::IsNullOrWhiteSpace($r.$f))) {
                    $missing += "$($r.ReportName) missing '$f'"
                }
            }
        }
        $missing | Should -BeNullOrEmpty -Because "$($missing.Count) required-field gaps: $($missing -join '; ')"
    }

    It 'no duplicate ReportName values' {
        $names = $script:RaReports.ReportName
        $dupes = $names | Group-Object | Where-Object Count -gt 1 | ForEach-Object Name
        $dupes | Should -BeNullOrEmpty -Because "duplicates: $($dupes -join ', ')"
    }

    It 'every Report SecurityDomain in allowed set' {
        $allowed = 'Endpoint','Identity','Azure','PublicIP','PublicIp','Hygiene','RiskAnalysis'
        $bad = @()
        foreach ($r in $script:RaReports) {
            if ($r.SecurityDomain -notin $allowed) {
                $bad += "$($r.ReportName) -> '$($r.SecurityDomain)'"
            }
        }
        $bad | Should -BeNullOrEmpty -Because "$($bad.Count) reports use unknown SecurityDomain: $($bad -join '; ')"
    }

    It 'every Report ReportPurpose >= 80 chars' {
        $weak = @()
        foreach ($r in $script:RaReports) {
            $len = ($r.ReportPurpose -as [string]).Trim().Length
            if ($len -lt 80) { $weak += "$($r.ReportName) ($len chars)" }
        }
        $weak | Should -BeNullOrEmpty -Because "$($weak.Count) ReportPurpose entries < 80 chars: $($weak -join '; ')"
    }
}

# ============================================================================
Describe 'TemplateCoverage' {
# ============================================================================

    It 'every Report appears in at least one template (no orphans)' {
        $allReports  = @($script:RaReports.ReportName)
        $allIncluded = @($script:RaTemplates | ForEach-Object { $_.ReportsIncluded.Name }) | Sort-Object -Unique
        $orphans = $allReports | Where-Object { $_ -notin $allIncluded }
        $orphans | Should -BeNullOrEmpty -Because "orphans: $($orphans -join ', ')"
    }

    It 'no ghost references in templates' {
        $allReports  = @($script:RaReports.ReportName)
        $allIncluded = @($script:RaTemplates | ForEach-Object { $_.ReportsIncluded.Name }) | Sort-Object -Unique
        $ghosts = $allIncluded | Where-Object { $_ -notin $allReports }
        $ghosts | Should -BeNullOrEmpty -Because "ghosts: $($ghosts -join ', ')"
    }
}

# ============================================================================
Describe 'DocConsistency' {
# ============================================================================

    It 'README claims same total report count as YAML' {
        $readmeText = Get-Content -Raw -LiteralPath $script:Readme
        $claimed = ([regex]::Matches($readmeText, '(\b\d{2,4}\b)\s+(?:Risk Analysis reports|attacker-centric KQL reports)') |
                    ForEach-Object { [int]$_.Groups[1].Value })
        $claimed | Should -Not -BeNullOrEmpty
        # Use the regex-derived YAML report count (authoritative) rather than
        # ConvertFrom-Yaml's parsed structure -- the latter undercounts on the
        # Linux GitHub Actions runner due to a powershell-yaml version quirk.
        $claimed | ForEach-Object { $_ | Should -Be $script:RaReportCount -Because "README ($_) vs YAML ($script:RaReportCount) drift" }
    }

    It 'linked doc exists: <_>' -ForEach @(
        $readmeText = Get-Content -Raw -LiteralPath (Join-Path $script:_V22Root 'README.md')
        [regex]::Matches($readmeText, '\]\(\./([^)]+\.md)\)') |
            ForEach-Object { $_.Groups[1].Value } |
            Sort-Object -Unique
    ) {
        Test-Path (Join-Path $script:V22Root $_) | Should -BeTrue
    }

    # NOTE: the per-topic doc `docs/risk-analysis-detection.md` (and the other 17
    # topic docs + ROADMAP) were consolidated into the single `docs/DESIGN.md`
    # under the shared 5-doc model. The RA report catalog now lives in DESIGN.md's
    # "Risk Analysis report catalog (model & inventory)" section, and the catalog
    # count is verified against the YAML by the 'README claims same total report
    # count as YAML' test above (README is synthesized from FEATURES + DESIGN).
    It 'docs/DESIGN.md exists' {
        Test-Path (Join-Path $script:V22Root 'docs\DESIGN.md') | Should -BeTrue
    }

    It 'docs/DESIGN.md documents the Risk Analysis report catalog' {
        $design = Get-Content -Raw -LiteralPath (Join-Path $script:V22Root 'docs\DESIGN.md')
        $design | Should -Match 'Risk Analysis report catalog' -Because 'the consolidated RA detection catalog must remain documented in DESIGN.md'
        $design | Should -Match 'RiskAnalysis_Queries_Locked\.yaml' -Because 'DESIGN.md must point at the YAML authority file the catalog is generated from'
    }
}

# ============================================================================
Describe 'SampleQuality' {
# ============================================================================

    It 'sample non-empty: <_.Name>' -ForEach $script:_AllSamples {
        $obj = Get-Content -Raw -LiteralPath $_.FullName | ConvertFrom-Json
        $keys = $obj.PSObject.Properties.Name
        $keys.Count | Should -BeGreaterThan 0
    }

    It '<_.Name> has .custom.sample.json sibling' -ForEach $script:_LockedSchemas {
        $sampleName = $_.Name -replace '\.locked\.json$','.custom.sample.json'
        $samplePath = Join-Path $_.Directory.FullName $sampleName
        Test-Path $samplePath | Should -BeTrue
    }
}

# ============================================================================
Describe 'WorkflowSyntax' {
# ============================================================================

    It '.github/workflows/publish.yml exists + parses' {
        $p = Join-Path $script:RepoRoot '.github\workflows\publish.yml'
        Test-Path $p | Should -BeTrue
        { ConvertFrom-Yaml (Get-Content -Raw -LiteralPath $p) } | Should -Not -Throw
    }

    It '.github/workflows/si-preview-prepublish.yml exists + parses' {
        $p = Join-Path $script:RepoRoot '.github\workflows\si-preview-prepublish.yml'
        Test-Path $p | Should -BeTrue
        { ConvertFrom-Yaml (Get-Content -Raw -LiteralPath $p) } | Should -Not -Throw
    }
}
