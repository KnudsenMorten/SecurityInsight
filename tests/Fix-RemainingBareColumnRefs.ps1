#Requires -Version 5.1
<#
.SYNOPSIS
    targeted bare-column-ref fixes for the 10 failing reports
    after 's `tostring(<col>)` sweep.

.DESCRIPTION
    wrapped bare `tostring(<col>)` refs. But these reports have
    bare refs in OTHER positions:
      - `| where <Col> == ...`  -- bare in where predicate
      - `| where isnotempty(<Col>)` -- bare inside isnotempty
      - `| project ..., <Col>, ...`  -- bare list entry in project
      - `strcat(..., <Col>, ...)`  -- bare in strcat / extend RHS

    Each fails with KQL Syntax Error when the column isn't materialized in
    this tenant's LA table (sparse-population schema, common in Profile_CL).

    Fix: targeted regex rewrites for the SPECIFIC bare refs surfaced in the
    full-test launcher run. Idempotent.
#>
[CmdletBinding()]
param(
    [string]$Yaml = (Join-Path $PSScriptRoot '..\risk-analysis-detection\RiskAnalysis_Queries_Locked.yaml'),
    [switch]$WhatIfMode
)

$y = Get-Content -LiteralPath $Yaml -Raw

# Specific replacements -- key = pattern, value = replacement
$rules = [ordered]@{
    # WHERE bool-column references
    '\| where SecureBootEnabled == false or VTpmEnabled == false' =
        '| where tobool(column_ifexists("SecureBootEnabled", true)) == false or tobool(column_ifexists("VTpmEnabled", true)) == false'
    '\| where DisabledPrivilegedUser == true' =
        '| where tobool(column_ifexists("DisabledPrivilegedUser", false)) == true'
    # WHERE isnotempty(<bare>)
    '\| where isnotempty\(Owner\) and isnotempty\(AppOwnerOrganizationId\)' =
        '| where isnotempty(tostring(column_ifexists("Owner", ""))) and isnotempty(tostring(column_ifexists("AppOwnerOrganizationId", "")))'
    # PROJECT bare bool columns inside let-binding subquery (Endpoint_TPMOrSecureBootDisabled_Tier0)
    '\| project AzureResourceId, SecureBootEnabled, VTpmEnabled' =
        '| project AzureResourceId, SecureBootEnabled=tobool(column_ifexists("SecureBootEnabled", false)), VTpmEnabled=tobool(column_ifexists("VTpmEnabled", false))'
    # strcat that interpolates bare bool columns -- safe because strcat can take any type
    'strcat\("SecureBoot=", SecureBootEnabled, " vTPM=", VTpmEnabled\)' =
        'strcat("SecureBoot=", tobool(column_ifexists("SecureBootEnabled", false)), " vTPM=", tobool(column_ifexists("VTpmEnabled", false)))'
    # Identity_PrivilegedUser_NoConditionalAccess: where ConditionalAccess columns
    '\| where ConditionalAccessExcluded == true' =
        '| where tobool(column_ifexists("ConditionalAccessExcluded", false)) == true'
    '\| where ConditionalAccessAssignedPolicies == 0' =
        '| where toint(column_ifexists("ConditionalAccessAssignedPolicies", -1)) == 0'
    # Identity_PrivilegedUser_NonTrustedSignIn / similar
    '\| where NonTrustedSignInDetected == true' =
        '| where tobool(column_ifexists("NonTrustedSignInDetected", false)) == true'
    # Hygiene_ClassificationDrift_RuleVsTier
    '\| where SIRules contains "Tier0" and Tier > 0' =
        '| where tostring(column_ifexists("SIRules", "")) contains "Tier0" and toint(column_ifexists("Tier", 999)) > 0'
}

$total = 0
foreach ($pat in $rules.Keys) {
    $repl = $rules[$pat]
    $matches = [regex]::Matches($y, $pat)
    if ($matches.Count -gt 0) {
        $y = [regex]::Replace($y, $pat, $repl)
        Write-Host ("Wrapped {0,3} occurrence(s): {1}" -f $matches.Count, ($pat.Substring(0, [Math]::Min(70, $pat.Length)))) -ForegroundColor Cyan
        $total += $matches.Count
    }
}

Write-Host ("Total replacements: {0}" -f $total) -ForegroundColor Green

if ($WhatIfMode) { Write-Host '(WhatIf -- no writes)' -ForegroundColor White; return }
Set-Content -LiteralPath $Yaml -Value $y -Encoding UTF8 -NoNewline
Write-Host 'YAML rewritten in place.' -ForegroundColor Green
