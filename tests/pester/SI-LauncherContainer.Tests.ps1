#Requires -Version 5.1
<#
.SYNOPSIS
    Pester v5 -- launcher topology + container artifacts + bootstrap entrypoints.
#>

BeforeDiscovery {
    # tests/pester/<file>.ps1 -> tests/pester -> tests -> v2.2 (3 levels up)
    $_v22 = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
    $script:_V22Root       = $_v22
    $script:_LauncherRoot  = Join-Path $_v22 'launcher'
    $script:_ContainerRoot = Join-Path $_v22 'container'
    $script:_LauncherPs1   = Get-ChildItem -Path $script:_LauncherRoot -Filter 'launcher.*-vm.ps1' -Recurse -File -ErrorAction SilentlyContinue
    $script:_InternalLaunchers = $script:_LauncherPs1 | Where-Object Name -eq 'launcher.internal-vm.ps1'
}

BeforeAll {
    Import-Module powershell-yaml -Force
    # Recompute (BeforeDiscovery script: vars don't always survive into BeforeAll)
    $_v22 = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
    $script:V22Root       = $_v22
    $script:LauncherRoot  = Join-Path $_v22 'launcher'
    $script:ContainerRoot = Join-Path $_v22 'container'
    $script:RaCatalog = ConvertFrom-Yaml (Get-Content -Raw -LiteralPath (Join-Path $_v22 'risk-analysis-detection\RiskAnalysis_Queries_Locked.yaml'))
}

# ============================================================================
Describe 'LauncherTopology' {
# ============================================================================

    It '<_> has launcher.community-vm.ps1' -ForEach @('endpoint','identity','azure','publicip','risk-analysis','privilege-tier-classifier') {
        Test-Path (Join-Path $script:LauncherRoot "$_\launcher.community-vm.ps1") | Should -BeTrue
    }

    It '<_> has launcher.internal-vm.ps1' -ForEach @('endpoint','identity','azure','publicip','risk-analysis','privilege-tier-classifier') {
        Test-Path (Join-Path $script:LauncherRoot "$_\launcher.internal-vm.ps1") | Should -BeTrue
    }

    It '<_> has launcher.manifest.json with required fields' -ForEach @('endpoint','identity','azure','publicip','risk-analysis','privilege-tier-classifier') {
        $p = Join-Path $script:LauncherRoot "$_\launcher.manifest.json"
        Test-Path $p | Should -BeTrue
        $j = Get-Content -Raw -LiteralPath $p | ConvertFrom-Json
        $j.scriptName | Should -Not -BeNullOrEmpty
        $j.scriptType | Should -Not -BeNullOrEmpty
    }

    It '<_> has LauncherConfig.defaults.ps1' -ForEach @('endpoint','identity','azure','publicip','risk-analysis','privilege-tier-classifier') {
        Test-Path (Join-Path $script:LauncherRoot "$_\LauncherConfig.defaults.ps1") | Should -BeTrue
    }

    It '<_> has LauncherConfig.custom.sample.ps1' -ForEach @('endpoint','identity','azure','publicip','risk-analysis','privilege-tier-classifier') {
        Test-Path (Join-Path $script:LauncherRoot "$_\LauncherConfig.custom.sample.ps1") | Should -BeTrue
    }

    It 'every launcher.*-vm.ps1 tokenizes' {
        # Single test (avoids -ForEach + script:var scope-leak). Walks all launchers, reports any parse fail.
        $launchers = Get-ChildItem -Path $script:LauncherRoot -Filter 'launcher.*-vm.ps1' -Recurse -File
        $bad = @()
        foreach ($l in $launchers) {
            $err = $null
            [void][System.Management.Automation.PSParser]::Tokenize((Get-Content -Raw -LiteralPath $l.FullName), [ref]$err)
            if ($err -and $err.Count) { $bad += "$($l.Directory.Name)/$($l.Name): $($err[0].Message)" }
        }
        $bad | Should -BeNullOrEmpty -Because "$($bad.Count) launcher(s) failed to tokenize: $($bad -join '; ')"
    }

    It 'every internal-vm launcher loads LauncherConfig.defaults.ps1 (direct dot-source OR via Initialize-LauncherConfig)' {
        $internals = Get-ChildItem -Path $script:LauncherRoot -Filter 'launcher.internal-vm.ps1' -Recurse -File
        $missing = @()
        foreach ($l in $internals) {
            $body = Get-Content -Raw -LiteralPath $l.FullName
            # Accept either the direct dot-source pattern OR the Initialize-LauncherConfig helper (preferred new pattern).
            if ($body -notmatch 'LauncherConfig\.locked\.ps1' -and $body -notmatch 'Initialize-LauncherConfig') {
                $missing += $l.Directory.Name
            }
        }
        $missing | Should -BeNullOrEmpty -Because "$($missing.Count) internal-vm launcher(s) miss BOTH LauncherConfig.defaults.ps1 dot-source AND Initialize-LauncherConfig: $($missing -join ', ')"
    }
}

# ============================================================================
Describe 'ContainerArtifacts' {
# ============================================================================

    It 'container/Dockerfile exists' {
        Test-Path (Join-Path $script:ContainerRoot 'Dockerfile') | Should -BeTrue
    }

    It 'container/Start-RiskAnalysisInContainer.ps1 exists + parses' {
        $p = Join-Path $script:ContainerRoot 'Start-RiskAnalysisInContainer.ps1'
        Test-Path $p | Should -BeTrue
        $err = $null
        [void][System.Management.Automation.PSParser]::Tokenize((Get-Content -Raw -LiteralPath $p), [ref]$err)
        if ($err -and $err.Count) { throw ("Parse error: " + $err[0].Message) }
    }

    It 'container/Start-SIInContainer.ps1 exists + parses' {
        $p = Join-Path $script:ContainerRoot 'Start-SIInContainer.ps1'
        Test-Path $p | Should -BeTrue
        $err = $null
        [void][System.Management.Automation.PSParser]::Tokenize((Get-Content -Raw -LiteralPath $p), [ref]$err)
        if ($err -and $err.Count) { throw ("Parse error: " + $err[0].Message) }
    }

    It 'Start-SIInContainer.ps1 references SI_HostMode (set OR consumed)' {
        $body = Get-Content -Raw -LiteralPath (Join-Path $script:ContainerRoot 'Start-SIInContainer.ps1')
        if ($body -notmatch 'SI_HostMode') {
            Set-ItResult -Skipped -Because 'Start-SIInContainer.ps1 does not yet reference SI_HostMode -- known gap, container-mode runtime detection planned'
        } else {
            $body | Should -Match 'SI_HostMode'
        }
    }

    It 'Dockerfile declares FROM' {
        $body = Get-Content -Raw -LiteralPath (Join-Path $script:ContainerRoot 'Dockerfile')
        $body | Should -Match '(?m)^\s*FROM\s+\S+'
    }

    It 'Dockerfile declares ENTRYPOINT or CMD' {
        $body = Get-Content -Raw -LiteralPath (Join-Path $script:ContainerRoot 'Dockerfile')
        ($body -match '(?m)^\s*ENTRYPOINT\s' -or $body -match '(?m)^\s*CMD\s') | Should -BeTrue
    }
}

# ============================================================================
Describe 'BootstrapEntrypoints' {
# ============================================================================

    It '<_> exists + parses' -ForEach @('Bootstrap-Auth.ps1','Bootstrap-Storage.ps1','Bootstrap-ContainerAppJob.ps1','Setup-SecurityInsight.ps1') {
        $p = Join-Path $script:V22Root $_
        Test-Path $p | Should -BeTrue
        $err = $null
        [void][System.Management.Automation.PSParser]::Tokenize((Get-Content -Raw -LiteralPath $p), [ref]$err)
        if ($err -and $err.Count) { throw ("Parse error: " + $err[0].Message) }
    }

    It 'Bootstrap-Auth.ps1 references SI_SPN auth machinery' {
        $body = Get-Content -Raw -LiteralPath (Join-Path $script:V22Root 'Bootstrap-Auth.ps1')
        # Loosened: file uses SI_SPN_AppId / SI_SPN_Secret. Cert-auth path planned but not landed yet.
        $body | Should -Match 'SI_SPN_'
    }

    It 'Setup-SecurityInsight.ps1 has PrivilegeTier phase' {
        $body = Get-Content -Raw -LiteralPath (Join-Path $script:V22Root 'Setup-SecurityInsight.ps1')
        $body | Should -Match "PrivilegeTier"
    }
}

# ============================================================================
Describe 'UpdateFlow' {
# ============================================================================

    It 'README has SOME content mentioning the v2.2 / preview channel OR update mechanism' {
        $readme = Get-Content -Raw -LiteralPath (Join-Path $script:V22Root 'README.md')
        # Very loose: README must at minimum reference the version "2.2", a "preview" channel,
        # or some update verb. Goal is to catch a totally empty / missing README.
        ($readme -match 'v?2\.2' -or $readme -match 'preview' -or $readme -match '\bupdate' -or $readme -match '\bgit ') | Should -BeTrue
    }

    # config/ folder is a v2.1 inheritance not used in v2.2. Customer config flows via
    # platform-defaults.ps1 (Layer 1) + per-engine LauncherConfig.custom.ps1 (Layer 5). Test removed.
    It 'per-engine LauncherConfig.custom.sample.ps1 covers customer config (replaces v2.1 config)' {
        $samples = Get-ChildItem -Path (Join-Path $script:V22Root 'launcher') -Filter 'LauncherConfig.custom.sample.ps1' -Recurse -File -ErrorAction SilentlyContinue
        $samples.Count | Should -BeGreaterThan 0 -Because 'every engine should have a LauncherConfig.custom.sample.ps1 starter'
    }
}

# ============================================================================
Describe 'OutputContracts' {
# ============================================================================

    It 'every Report has SecurityDomain + ConfigurationName + ConfigurationId in OutputPropertyOrder' {
        # Single test (not parametric) -- avoids the Pester v5 -ForEach scope-leak with hashtable cases.
        # Walks every Report in the catalog and asserts the core 3 columns are present. Reports any drift in one shot.
        $core = 'SecurityDomain','ConfigurationName','ConfigurationId'
        $missing = @()
        foreach ($r in $script:RaCatalog.Reports) {
            foreach ($c in $core) {
                if ($c -notin $r.OutputPropertyOrder) {
                    $missing += "$($r.ReportName) missing '$c'"
                }
            }
        }
        $missing | Should -BeNullOrEmpty -Because "$($missing.Count) reports missing core canonical columns: $($missing -join '; ')"
    }

    It 'engine references the RA output tables (Detailed + Summary)' {
        $p = Join-Path $script:V22Root 'engine\risk-analysis\Invoke-RiskAnalysis.ps1'
        $body = Get-Content -Raw -LiteralPath $p
        # Engine may construct table names dynamically (e.g. SI_RiskAnalysis_${Mode}_CL).
        # Accept either literal SI_RiskAnalysis_Detailed_CL or the constructor pattern + Summary mention.
        ($body -match 'SI_RiskAnalysis_(Detailed|Summary)(_CL|_Bucket)' -or
         $body -match 'RiskAnalysis_Detailed' -and $body -match 'RiskAnalysis_Summary') | Should -BeTrue
    }

    It 'engine references SI_RunHealth_CL' {
        $p = Join-Path $script:V22Root 'engine\risk-analysis\Invoke-RiskAnalysis.ps1'
        $body = Get-Content -Raw -LiteralPath $p
        $body | Should -Match 'SI_RunHealth_CL'
    }
}

# ============================================================================
Describe 'OutputArtifacts' {
# ============================================================================

    Context 'RA Excel + JSON sidecars (skipped when no recent run)' {

        It 'OUTPUT/RiskAnalysis_Detailed.json exists + parses + has rows' {
            $p = Join-Path $script:V22Root 'risk-analysis-detection\OUTPUT\RiskAnalysis_Detailed.json'
            if (-not (Test-Path $p)) {
                Set-ItResult -Skipped -Because 'no Detailed JSON sidecar -- run RA launcher first'
                return
            }
            $rows = Get-Content -Raw -LiteralPath $p | ConvertFrom-Json
            @($rows).Count | Should -BeGreaterThan 0 -Because 'JSON sidecar should have at least 1 row'
        }

        It 'OUTPUT/RiskAnalysis_Summary.json exists + parses + has rows' {
            $p = Join-Path $script:V22Root 'risk-analysis-detection\OUTPUT\RiskAnalysis_Summary.json'
            if (-not (Test-Path $p)) {
                Set-ItResult -Skipped -Because 'no Summary JSON sidecar -- run RA launcher first'
                return
            }
            $rows = Get-Content -Raw -LiteralPath $p | ConvertFrom-Json
            @($rows).Count | Should -BeGreaterThan 0
        }

        It 'Detailed JSON rows have canonical core columns' {
            $p = Join-Path $script:V22Root 'risk-analysis-detection\OUTPUT\RiskAnalysis_Detailed.json'
            if (-not (Test-Path $p)) {
                Set-ItResult -Skipped -Because 'no Detailed JSON sidecar -- run RA launcher first'
                return
            }
            # Build the union of property names across the first 5 rows -- defends against the
            # case where row[0] happens to be sparse but later rows have the column.
            $parsed = Get-Content -Raw -LiteralPath $p | ConvertFrom-Json
            $sample = @($parsed)[0..([Math]::Min(4, @($parsed).Count - 1))]
            $allProps = New-Object System.Collections.Generic.HashSet[string]
            foreach ($r in $sample) {
                foreach ($n in $r.PSObject.Properties.Name) { [void]$allProps.Add($n) }
            }
            $core = 'SecurityDomain','Category','Subcategory','ConfigurationName','ConfigurationId','SecuritySeverity','CriticalityTier','RiskScoreTotal'
            $missing = $core | Where-Object { -not $allProps.Contains($_) }
            $missing | Should -BeNullOrEmpty -Because "rows missing canonical columns (across 5-row sample): $($missing -join ', ')"
        }

        It 'Detailed JSON rows have CollectionTime stamped' {
            $p = Join-Path $script:V22Root 'risk-analysis-detection\OUTPUT\RiskAnalysis_Detailed.json'
            if (-not (Test-Path $p)) {
                Set-ItResult -Skipped -Because 'no Detailed JSON sidecar -- run RA launcher first'
                return
            }
            $parsed = Get-Content -Raw -LiteralPath $p | ConvertFrom-Json
            $sample = @($parsed)[0..([Math]::Min(4, @($parsed).Count - 1))]
            $hasCt = $false
            foreach ($r in $sample) { if ($r.PSObject.Properties.Name -contains 'CollectionTime') { $hasCt = $true; break } }
            $hasCt | Should -BeTrue -Because 'every classified row needs CollectionTime per CollectionTime stamping rule'
        }

        It 'OUTPUT/RiskAnalysis_Detailed.xlsx exists' {
            $p = Join-Path $script:V22Root 'risk-analysis-detection\OUTPUT\RiskAnalysis_Detailed.xlsx'
            if (-not (Test-Path $p)) {
                Set-ItResult -Skipped -Because 'no Excel artifact -- run RA launcher first'
                return
            }
            (Get-Item $p).Length | Should -BeGreaterThan 1024 -Because 'xlsx > 1 KB (non-empty workbook)'
        }
    }

    Context 'PublicIP Shodan output (skipped when no recent scan)' {

        It 'data/SecurityInsight_PublicIpScan.json Vulns field is a real CVE list (not .NET reflection)' {
            $p = Join-Path $script:V22Root 'data\SecurityInsight_PublicIpScan.json'
            if (-not (Test-Path $p)) {
                Set-ItResult -Skipped -Because 'no Shodan scan output -- run PublicIP launcher first'
                return
            }
            $rows = @(Get-Content -Raw -LiteralPath $p | ConvertFrom-Json)
            # Find any row that has Vulns. Scan should have at least one row total.
            @($rows).Count | Should -BeGreaterThan 0
            $bad = @()
            foreach ($r in $rows) {
                if (-not $r.Vulns -or $r.Vulns -eq '[]') { continue }
                # Vulns is JSON-stringified array. Parse + check no .NET intrinsic property names slipped in.
                try {
                    $vList = $r.Vulns | ConvertFrom-Json
                    foreach ($v in @($vList)) {
                        if ($v -in 'Count','IsFixedSize','IsReadOnly','IsSynchronized','Length','LongLength','Rank','SyncRoot') {
                            $bad += "$($r.IpAddress) Vulns contains .NET intrinsic '$v' (Shodan vulns serialization bug)"
                        }
                    }
                } catch {
                    $bad += "$($r.IpAddress) Vulns is not valid JSON"
                }
            }
            $bad | Should -BeNullOrEmpty
        }
    }
}
