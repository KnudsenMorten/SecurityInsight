#Requires -Version 5.1
<#
    THE "PRIVILEGED / ADMIN ACCOUNT" REPORTS COVER TIER 0 AND TIER 1 ONLY (operator 2026-10-09: "fix the filter").
    v2.2's identity collection held mostly privileged identities, so three report pairs that never filtered on privilege
    looked right. v3 collects EVERY user, and on a large tenant (~9,000 identities) each pair flagged almost all of them:
    "Privileged user, stale password" 8,885 identities, "Admin account synced from on-prem" 8,861, "Admin account never
    used" 8,749 -- for 12 identities at Tier 0-2. Their own purpose says "Privileged accounts (Tier 0/1)", so their tier
    scope is tier 0 and tier 1. OFFLINE: reads the locked catalog.
#>

BeforeAll {
    $script:SIRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
    $script:Lines = [IO.File]::ReadAllLines((Join-Path $script:SIRoot 'risk-analysis-detection\RiskAnalysis_Queries_Locked.yaml'))
    function script:Get-ReportTierScope([string]$Name) {
        $start = -1
        for ($i = 0; $i -lt $script:Lines.Count; $i++) { if ($script:Lines[$i] -match ('^\s*- ReportName:\s*' + [regex]::Escape($Name) + '\s*$')) { $start = $i; break } }
        if ($start -lt 0) { return $null }
        $end = $script:Lines.Count
        for ($i = $start + 1; $i -lt $script:Lines.Count; $i++) { if ($script:Lines[$i] -match '^\s*- ReportName:') { $end = $i; break } }
        for ($i = $start; $i -lt $end; $i++) {
            if ($script:Lines[$i] -match '^\s*CriticalityTierLevelScope:\s*$') {
                $tiers = New-Object System.Collections.Generic.List[string]
                for ($j = $i + 1; $j -lt $end -and $script:Lines[$j] -match '^\s*- .* - tier (\d)\s*$'; $j++) { $tiers.Add($Matches[1]) }
                return , $tiers.ToArray()
            }
        }
        , @()
    }
    $script:Pairs = 'Identity_PrivilegedUser_StalePassword', 'Identity_AdminAccount_OnPremSynced', 'Identity_AdminAccount_NeverUsed'
}

Describe 'the privileged / admin account reports are scoped to tier 0 and tier 1' {
    It '<_> (Summary and Detailed) covers tier 0 and tier 1 only' -ForEach @('Identity_PrivilegedUser_StalePassword', 'Identity_AdminAccount_OnPremSynced', 'Identity_AdminAccount_NeverUsed') {
        foreach ($g in 'Summary', 'Detailed') {
            $s = Get-ReportTierScope ("{0}_{1}" -f $_, $g)
            $null -ne $s | Should -BeTrue -Because ("{0}_{1} is in the locked catalog" -f $_, $g)
            ($s -join ',') | Should -Be '0,1' -Because 'v3 collects every user: a wider scope flags every account on a large tenant'
        }
    }
    It 'the all-users report (no MFA) still covers every tier -- its purpose is all enabled users' {
        (Get-ReportTierScope 'Identity_NoMFA_Detailed') -join ',' | Should -Be '0,1,2,3'
    }
}
