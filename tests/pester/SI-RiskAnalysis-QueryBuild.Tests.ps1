#Requires -Version 5.1
<#
.SYNOPSIS
    Pester v5 tests for the Risk Analysis engine's query-build + multi-path
    logging behaviour (offline, no network).
.DESCRIPTION
    Invoke-RiskAnalysis.ps1 is a runnable SCRIPT (top-level body runs on load),
    so we cannot dot-source it directly. Instead we parse it with the PS AST and
    inject ONLY the specific function definitions under test into the test scope,
    plus the $script:_DynamicGroupKeyCols initializer they depend on.

    Covers:
      A) Add-DynamicGroupKeyCasts -- the SEM0001 guard. Every `summarize ... by`
         group key that can be `dynamic` (cmdb*) is wrapped in tostring(); numeric
         columns are NOT cast; alias-form keys (`cmdbX = ""`) are left alone; the
         transform is idempotent.
      B) Deferred superseded-attempt logging -- a failed fallback attempt that is
         later SUPERSEDED by success must NOT emit a [WARN]; only a single [INFO].
         A total failure flushes exactly one consolidated [WARN].
#>

BeforeAll {
    # tests/pester/<file>.ps1 -> tests/pester -> tests -> SecurityInsight (3 ups)
    $si = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
    $enginePath = Join-Path $si 'engine\risk-analysis\Invoke-RiskAnalysis.ps1'
    if (-not (Test-Path $enginePath)) { throw "RA engine not found at $enginePath" }

    # Parse + extract only the functions we test (+ the cols initializer).
    $tokens = $null; $errs = $null
    $ast = [System.Management.Automation.Language.Parser]::ParseFile($enginePath, [ref]$tokens, [ref]$errs)
    if ($errs -and $errs.Count) { throw "RA engine has parse errors: $($errs.Count)" }

    $wantFns = @('Add-DynamicGroupKeyCasts','Reset-SupersededAttempts','Add-SupersededAttempt',
                 'Resolve-SupersededOnSuccess','Flush-SupersededAttempts')
    $fnAsts = $ast.FindAll({ param($n)
        $n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $wantFns -contains $n.Name
    }, $true)

    # Logging shims (the real ones live in the engine body we don't load). They
    # record what would have been written so the tests can assert log levels.
    $script:LogLines = New-Object System.Collections.Generic.List[string]
    function Write-Info  ($msg){ $script:LogLines.Add("[INFO] $msg") }
    function Write-Warn2 ($msg){ $script:LogLines.Add("[WARN] $msg") }
    function Write-Diag  ($msg){ $script:LogLines.Add("[DIAG] $msg") }

    # The cols initializer the cast fn reads.
    $script:_DynamicGroupKeyCols = @('cmdbName','cmdbId','cmdbCriticality','cmdbDataSensitivity')

    foreach ($f in $fnAsts) { Invoke-Expression $f.Extent.Text }
}

Describe 'Add-DynamicGroupKeyCasts (SEM0001 dynamic group-key guard)' {

    It 'casts a bare cmdbName group key with tostring()' {
        $q = "T | summarize C=count() by SecurityDomain, cmdbName`n| project C"
        (Add-DynamicGroupKeyCasts -Query $q) | Should -Match 'tostring\(cmdbName\)'
    }

    It 'casts every cmdb* group key (cmdbId / cmdbCriticality) in the PublicIP summarize shape' {
        $q = @'
SI_VulnerabilityPIP_CL
| summarize AssetCount = dcount(IpAddress), RiskFactor_Consequence = max(RiskFactor_Consequence)
  by SecurityDomain, Category, CriticalityTier, CriticalityTierLevel, SecuritySeverity,
     cmdbId, cmdbName, cmdbCriticality, cmdbDataSensitivity = ""
| order by CriticalityTier asc
'@
        $r = Add-DynamicGroupKeyCasts -Query $q
        $r | Should -Match 'tostring\(cmdbId\)'
        $r | Should -Match 'tostring\(cmdbName\)'
        $r | Should -Match 'tostring\(cmdbCriticality\)'
    }

    It 'leaves an ALIAS-form group key (cmdbDataSensitivity = "") uncast' {
        $q = 'T | summarize C=count() by cmdbName, cmdbDataSensitivity = ""' + "`n" + '| project C'
        $r = Add-DynamicGroupKeyCasts -Query $q
        $r | Should -Match 'cmdbDataSensitivity = ""'
        $r | Should -Not -Match 'tostring\(cmdbDataSensitivity\)'
    }

    It 'does NOT cast numeric columns (RiskScore* / *Tier) -- ordering/scoring stays numeric' {
        $q = @'
T
| summarize RiskScoreTotal = max(RiskScoreTotal) by SecurityDomain, CriticalityTier, cmdbName
| project RiskScoreTotal
'@
        $r = Add-DynamicGroupKeyCasts -Query $q
        $r | Should -Not -Match 'tostring\(CriticalityTier\)'
        $r | Should -Not -Match 'tostring\(RiskScoreTotal\)'
        $r | Should -Match 'max\(RiskScoreTotal\)'   # aggregate untouched
        $r | Should -Match 'tostring\(cmdbName\)'    # the dynamic key still cast
    }

    It 'never double-wraps an already-cast key' {
        $q = "T | summarize C=count() by tostring(cmdbName), Category`n| project C"
        (Add-DynamicGroupKeyCasts -Query $q) | Should -Not -Match 'tostring\(tostring\(cmdbName\)\)'
    }

    It 'is idempotent (a second pass changes nothing)' {
        $q = @'
T
| summarize C=count() by SecurityDomain, cmdbId, cmdbName, cmdbCriticality
| project C
'@
        $once  = Add-DynamicGroupKeyCasts -Query $q
        $twice = Add-DynamicGroupKeyCasts -Query $once
        $twice | Should -BeExactly $once
    }

    It 'does not touch cmdbName used OUTSIDE a summarize-by (project/extend)' {
        $q = "T | extend cmdbName = tostring(column_ifexists('cmdbName','')) | project cmdbName, Category"
        (Add-DynamicGroupKeyCasts -Query $q) | Should -BeExactly $q
    }

    It 'leaves the post-by pipe operators (| project / | order) intact' {
        $q = "T`n| summarize X=count() by SecurityDomain, cmdbName,`n   cmdbId`n| project X`n| order by X desc"
        $r = Add-DynamicGroupKeyCasts -Query $q
        $r | Should -Match '\| project X'
        $r | Should -Match '\| order by X desc'
        $r | Should -Match 'tostring\(cmdbName\)'
    }

    It 'produces no bare cmdb* group key in the rendered by-clause (the actual SEM0001 trigger)' {
        $q = @'
T
| summarize C=count()
  by SecurityDomain, Category, cmdbId, cmdbName, cmdbCriticality, cmdbDataSensitivity
| project C
'@
        $r = Add-DynamicGroupKeyCasts -Query $q
        # Every cmdb* key must now appear only inside tostring(...).
        foreach ($c in @('cmdbId','cmdbName','cmdbCriticality','cmdbDataSensitivity')) {
            ($r -match ('tostring\(' + $c + '\)')) | Should -BeTrue
            # No occurrence of the bare key that is NOT immediately inside tostring(.
            ($r -match ('(?<!tostring\()' + $c + '\b(?!\))')) | Should -BeFalse -Because "$c must not appear bare"
        }
    }
}

Describe 'Deferred superseded multi-path logging (no WARN when a later path wins)' {

    BeforeEach {
        $script:LogLines = New-Object System.Collections.Generic.List[string]
        Reset-SupersededAttempts
    }

    It 'emits NO [WARN] and exactly one [INFO] when a fallback path succeeds after an earlier failure' {
        Add-SupersededAttempt -Path 'lake' -Message 'ClientCertificateCredential authentication failed'
        Resolve-SupersededOnSuccess -WinningPath 'LA-direct'

        $warns = @($script:LogLines | Where-Object { $_ -like '[[]WARN]*' })
        $infos = @($script:LogLines | Where-Object { $_ -like '[[]INFO]*' })
        $warns.Count | Should -Be 0
        $infos.Count | Should -Be 1
        $infos[0] | Should -Match 'LA-direct'
        $infos[0] | Should -Match '1 superseded'
    }

    It 'emits NOTHING extra on success when there were no superseded attempts (clean first-path win)' {
        Resolve-SupersededOnSuccess -WinningPath 'lake'
        $script:LogLines.Count | Should -Be 0
    }

    It 'flushes exactly ONE consolidated [WARN] when ALL paths fail' {
        Add-SupersededAttempt -Path 'lake' -Message 'AADSTS lake token failed'
        Flush-SupersededAttempts
        $warns = @($script:LogLines | Where-Object { $_ -like '[[]WARN]*' })
        $warns.Count | Should -Be 1
        $warns[0] | Should -Match 'all data paths failed'
        $warns[0] | Should -Match 'lake'
    }

    It 'clears the buffer after a success so the next query starts clean' {
        Add-SupersededAttempt -Path 'lake' -Message 'x'
        Resolve-SupersededOnSuccess -WinningPath 'advanced-hunting'
        # second query: clean win, no prior attempts -> no log
        $script:LogLines = New-Object System.Collections.Generic.List[string]
        Resolve-SupersededOnSuccess -WinningPath 'lake'
        $script:LogLines.Count | Should -Be 0
    }
}

# ---------------------------------------------------------------------------
# C) Cross-domain bucket re-key (v2.2.385). The 6 cross-domain Attack_Paths
#    Summary reports timed out at the 900s advanced-hunting ceiling because the
#    EG-side bucket filter was SUPPRESSED whenever a CL let carried a non-EG
#    bucket key (Target_AzureResourceId_Guid) -> every bucket scanned ALL EG
#    nodes (unbounded). The fix re-keys the partition onto an EG-native column
#    (declared per-report via crossDomainBucketCoalesce.EgNativeKey) so:
#      * New-BucketFilterKql leads the EG __bucket_key coalesce with that key
#        (EG side genuinely partitioned -> bounded; not a cap).
#      * Get-SICLBucketKey leads with the matching CL ClColumn (same value =
#        EG NodeId hex) -> CL + EG partitions identical -> lossless joins.
# ---------------------------------------------------------------------------
Describe 'Cross-domain bucket re-key (EG-native partition, lossless CL alignment)' {

    BeforeAll {
        $si = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
        $enginePath = Join-Path $si 'engine\risk-analysis\Invoke-RiskAnalysis.ps1'
        $tokens = $null; $errs = $null
        $ast = [System.Management.Automation.Language.Parser]::ParseFile($enginePath, [ref]$tokens, [ref]$errs)
        if ($errs -and $errs.Count) { throw "RA engine has parse errors: $($errs.Count)" }
        $wantFns = @('New-BucketFilterKql','Get-SICLBucketKey','Get-SISha256Bucket')
        $fnAsts = $ast.FindAll({ param($n)
            $n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $wantFns -contains $n.Name
        }, $true)
        function Write-Info  ($msg){ }
        foreach ($f in $fnAsts) { Invoke-Expression $f.Extent.Text }
    }

    Context 'EG-side bucket filter (New-BucketFilterKql)' {

        It 'leads the __bucket_key coalesce with the declared EgNativeKey (bounded EG partition)' {
            $script:_CrossDomainBucketCoalesce = @(@{ ClColumn = 'Target_AzureResourceId_Guid'; EgNativeKey = 'NodeId' })
            $kql = New-BucketFilterKql -BucketCount 8 -BucketIndex 0 -ReportName 'Attack_Paths_Summary_Github_to_Azure_Resources'
            # First column_ifexists inside the coalesce must be the EG-native key.
            $first = ([regex]::Match($kql, "coalesce\(\s*tostring\(column_ifexists\('(?<c>[^']+)'")).Groups['c'].Value
            $first | Should -Be 'NodeId'
            $kql | Should -Match 'hash_sha256'
            $kql | Should -Match '__bucket == 0'
        }

        It 'falls back to the standard DeviceKey-first coalesce when no coalesce is declared' {
            $script:_CrossDomainBucketCoalesce = @()
            $kql = New-BucketFilterKql -BucketCount 4 -BucketIndex 1 -ReportName 'Some_Report'
            $first = ([regex]::Match($kql, "coalesce\(\s*tostring\(column_ifexists\('(?<c>[^']+)'")).Groups['c'].Value
            $first | Should -Be 'DeviceKey'
        }

        It 'promotes a non-NodeId EgNativeKey (AadDeviceId for the Device report)' {
            $script:_CrossDomainBucketCoalesce = @(
                @{ ClColumn = 'Source_AadDeviceId'; EgNativeKey = 'AadDeviceId' },
                @{ ClColumn = 'Target_AzureResourceId_Guid' }
            )
            $kql = New-BucketFilterKql -BucketCount 16 -BucketIndex 3 -ReportName 'Attack_Paths_Summary_Device_with_high_severity_vulnerabilities_allows_lateral_movement_Azure'
            $first = ([regex]::Match($kql, "coalesce\(\s*tostring\(column_ifexists\('(?<c>[^']+)'")).Groups['c'].Value
            $first | Should -Be 'AadDeviceId'
        }
    }

    Context 'CL-side bucket key (Get-SICLBucketKey)' {

        It 'keys a _TargetCmdb row on the declared ClColumn (matches the EG NodeId value)' {
            $script:_CrossDomainBucketCoalesce = @(@{ ClColumn = 'Target_AzureResourceId_Guid'; EgNativeKey = 'NodeId' })
            $row = [pscustomobject]@{ Target_AzureResourceId_Guid = 'abc123nodehex'; Target_cmdbName = 'svc-sql' }
            (Get-SICLBucketKey -Row $row) | Should -Be 'abc123nodehex'
        }

        It 'keys a _SourceCmdb row on Source_AadDeviceId when declared (Device report)' {
            $script:_CrossDomainBucketCoalesce = @(
                @{ ClColumn = 'Source_AadDeviceId'; EgNativeKey = 'AadDeviceId' },
                @{ ClColumn = 'Target_AzureResourceId_Guid' }
            )
            $row = [pscustomobject]@{ Source_AadDeviceId = 'aad-guid-xyz'; Source_cmdbName = 'host01' }
            (Get-SICLBucketKey -Row $row) | Should -Be 'aad-guid-xyz'
        }

        It 'EG and CL sides hash the SAME value to the SAME bucket (aligned partition)' {
            $script:_CrossDomainBucketCoalesce = @(@{ ClColumn = 'Target_AzureResourceId_Guid'; EgNativeKey = 'NodeId' })
            $val = 'deadbeefcafenode42'
            $clRow = [pscustomobject]@{ Target_AzureResourceId_Guid = $val }
            $clBucket = Get-SISha256Bucket -Key (Get-SICLBucketKey -Row $clRow) -BucketCount 32
            # EG side hashes the same NodeId value through the same SHA256 math.
            $egBucket = Get-SISha256Bucket -Key $val -BucketCount 32
            $clBucket | Should -Be $egBucket
        }
    }
}

# ---------------------------------------------------------------------------
# D) YAML contract: every cross-domain Attack_Paths *Summary* report must
#    declare an EG-native crossDomainBucketCoalesce (so its EG-side bucket
#    filter stays active / bounded) and must NOT bucket on a bare cmdb*/CL
#    column alone. Detailed reports are out of scope (different bucket model).
# ---------------------------------------------------------------------------
Describe 'Cross-domain Attack_Paths Summary reports re-key off EG-native columns (YAML)' {

    BeforeAll {
        $si = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
        $script:LockedYaml = Join-Path $si 'risk-analysis-detection\RiskAnalysis_Queries_Locked.yaml'
        if (-not (Test-Path $script:LockedYaml)) { throw "Locked queries YAML not found at $($script:LockedYaml)" }
        Import-Module powershell-yaml -ErrorAction SilentlyContinue
        $script:Catalog = ConvertFrom-Yaml -Yaml (Get-Content -Raw $script:LockedYaml)
        $script:CrossDomainSummaries = @($script:Catalog.Reports | Where-Object {
            $_.ReportName -like 'Attack_Paths_Summary_*' -and $_.ReportName -notlike '*_Detailed*'
        })
    }

    It 'finds the 6 cross-domain Attack_Paths Summary reports' {
        @($script:CrossDomainSummaries).Count | Should -Be 6
    }

    It 'every cross-domain Summary report declares an EG-native crossDomainBucketCoalesce' {
        foreach ($r in $script:CrossDomainSummaries) {
            $r.crossDomainBucketCoalesce | Should -Not -BeNullOrEmpty -Because "report '$($r.ReportName)' must re-key off an EG-native column"
            $egKeys = @($r.crossDomainBucketCoalesce | ForEach-Object { $_.EgNativeKey } | Where-Object { $_ })
            @($egKeys).Count | Should -BeGreaterThan 0 -Because "report '$($r.ReportName)' must name at least one EgNativeKey"
            foreach ($k in $egKeys) {
                $k | Should -BeIn @('NodeId','AadDeviceId','SourceNodeId','TargetNodeId','DeviceKey') -Because "the bucket partition for '$($r.ReportName)' must be an EG-native column, not a cmdb*/CL column"
            }
        }
    }

    It 'still projects the CL enrichment columns (cmdbName) in every cross-domain Summary report' {
        foreach ($r in $script:CrossDomainSummaries) {
            $q = ($r.ReportQuery -join "`n")
            $q | Should -Match 'cmdbName' -Because "report '$($r.ReportName)' must keep client-side CL enrichment"
        }
    }

    It 'declared ClColumn(s) are not bare cmdb* group keys (CL enrichment is post-applied, not the partition)' {
        foreach ($r in $script:CrossDomainSummaries) {
            $clCols = @($r.crossDomainBucketCoalesce | ForEach-Object { $_.ClColumn } | Where-Object { $_ })
            foreach ($c in $clCols) {
                $c | Should -Not -Match '^cmdb' -Because "the partition key for '$($r.ReportName)' must not be a cmdb* column"
            }
        }
    }
}
