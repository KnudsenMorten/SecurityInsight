#Requires -Version 5.1
<#
.SYNOPSIS
    SI Analyzer -- data plane (read-only). Live workspace via the SI engine's auth
    path, with a demo/seed-data fallback when no workspace is reachable.

.DESCRIPTION
    Reuses the SI engine's Log-Analytics access pattern: Invoke-AzOperationalInsightsQuery
    against the workspace resolved from $global:SI_WorkspaceResourceId (the SAME
    function shape as Invoke-LogAnalyticsKqlQuery in Invoke-RiskAnalysis.ps1). It
    re-uses the existing Connect-AzAccount session (SPN + cert) -- no new auth.

    Every query is forced through Test-SiKqlReadOnly (the guardrail) before it is
    submitted, even prestaged ones -- defence in depth.

    When -UseDemoData is set (or the workspace is unreachable / not configured),
    rows are loaded from analyzer/seed/demo-snapshot.json so the POC runs offline.

    PowerShell 5.1-safe.
#>

Set-StrictMode -Version Latest

# Dot-source the guardrail (sibling lib). Idempotent.
$script:_kqlLib = Join-Path $PSScriptRoot 'SiAnalyzer-Kql.ps1'
if (Test-Path -LiteralPath $script:_kqlLib) { . $script:_kqlLib }

function Get-SiDemoDataPath {
    # 'seed' (not 'data') -- the solution .gitignore ignores DATA/ (runtime output);
    # this is committed seed data for the offline demo fallback.
    return (Join-Path (Split-Path -Parent $PSScriptRoot) 'seed\demo-snapshot.json')
}

function Get-SiDemoRows {
    [CmdletBinding()] param([string]$Path)
    if ([string]::IsNullOrWhiteSpace($Path)) { $Path = Get-SiDemoDataPath }
    if (-not (Test-Path -LiteralPath $Path)) {
        throw "SI Analyzer demo data not found at $Path"
    }
    $json = Get-Content -LiteralPath $Path -Raw -Encoding UTF8
    $obj = $json | ConvertFrom-Json
    # NOTE: do NOT comma-protect here. $obj.rows is already an array; ,@(...) would
    # wrap it as a single-element [Object[]] containing the inner array, which then
    # survives an outer @() and breaks property access ([double]$r.RiskScoreTotal ->
    # Object[]). Returning the array plainly lets the caller's @() normalise it.
    if ($obj.PSObject.Properties.Name -contains 'rows') { return [object[]]$obj.rows }
    return [object[]]$obj
}

function Test-SiWorkspaceConfigured {
    [CmdletBinding()] param()
    if (-not (Get-Variable -Name SI_WorkspaceResourceId -Scope Global -ErrorAction SilentlyContinue)) { return $false }
    return (-not [string]::IsNullOrWhiteSpace([string]$global:SI_WorkspaceResourceId))
}

# ---------------------------------------------------------------------------
# Run a KQL query read-only. Forces the guardrail; uses the live workspace if
# configured + reachable, else throws (caller decides whether to demo-fallback).
# Mirrors Invoke-RiskAnalysis.ps1's Invoke-LogAnalyticsKqlQuery auth shape.
# ---------------------------------------------------------------------------
function Invoke-SiAnalyzerQuery {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Query,
        [int]$TimeoutSec = 300
    )

    $gate = Test-SiKqlReadOnly -Query $Query
    if (-not $gate.Allowed) {
        throw ("SI Analyzer guardrail rejected the query: {0}" -f ($gate.Reasons -join '; '))
    }

    if (-not (Test-SiWorkspaceConfigured)) {
        throw "SI Analyzer: no workspace configured (`$global:SI_WorkspaceResourceId is empty)."
    }

    if (-not (Get-Command Invoke-AzOperationalInsightsQuery -ErrorAction SilentlyContinue)) {
        throw "SI Analyzer: Az.OperationalInsights not available -- cannot reach the live workspace."
    }
    if (-not (Get-Command Get-AzOperationalInsightsWorkspace -ErrorAction SilentlyContinue)) {
        throw "SI Analyzer: Az.OperationalInsights workspace cmdlet not available."
    }

    # Resolve the workspace customer (GUID) id from the ARM resource id -- same as the engine.
    $rid = $global:SI_WorkspaceResourceId
    $parts = $rid -split '/'
    $sub = $null; $rg = $null; $name = $null
    for ($i = 0; $i -lt $parts.Count; $i++) {
        if ($parts[$i] -ieq 'subscriptions' -and $i + 1 -lt $parts.Count) { $sub = $parts[$i + 1] }
        if ($parts[$i] -ieq 'resourcegroups' -and $i + 1 -lt $parts.Count) { $rg = $parts[$i + 1] }
        if ($parts[$i] -ieq 'workspaces' -and $i + 1 -lt $parts.Count) { $name = $parts[$i + 1] }
    }
    if (-not $sub -or -not $rg -or -not $name) {
        throw "SI Analyzer: could not parse subscription/resource-group/name from SI_WorkspaceResourceId."
    }

    $ws = Get-AzOperationalInsightsWorkspace -ResourceGroupName $rg -Name $name -ErrorAction Stop
    $custId = $ws.CustomerId.Guid

    $resp = Invoke-AzOperationalInsightsQuery -WorkspaceId $custId -Query $Query -Wait $TimeoutSec -ErrorAction Stop
    if (-not $resp -or -not $resp.Results) { return @() }
    return @($resp.Results)
}

# ---------------------------------------------------------------------------
# High-level: get the rows for an analysis. Tries the live workspace; on any
# failure (not configured / unreachable / module missing) falls back to demo
# data and returns a flag so the UI can warn. -UseDemoData forces demo.
# ---------------------------------------------------------------------------
function Get-SiAnalyzerRows {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Query,
        [switch]$UseDemoData,
        [string]$DemoPath
    )

    if ($UseDemoData) {
        return [pscustomobject]@{ Rows = Get-SiDemoRows -Path $DemoPath; Source = 'demo'; Warning = 'Using demo/seed data (offline mode).' }
    }

    try {
        $rows = Invoke-SiAnalyzerQuery -Query $Query
        return [pscustomobject]@{ Rows = @($rows); Source = 'workspace'; Warning = $null }
    } catch {
        $msg = $_.Exception.Message
        try {
            $rows = Get-SiDemoRows -Path $DemoPath
            return [pscustomobject]@{ Rows = @($rows); Source = 'demo'; Warning = ("Live workspace unavailable -- using demo data. ({0})" -f $msg) }
        } catch {
            throw ("SI Analyzer: live workspace failed AND demo data unavailable: {0}" -f $msg)
        }
    }
}
