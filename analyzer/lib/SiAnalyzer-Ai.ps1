#Requires -Version 5.1
<#
.SYNOPSIS
    SI Analyzer -- AI prompt assembly + AI-optional fail-soft + NL->KQL composition.

.DESCRIPTION
    Offline-testable core (the assembly + degradation are pure; the actual call is
    a thin wrapper that no-ops without config). Reuses the SI Azure OpenAI globals
    ($global:OpenAI_endpoint / _deployment / _apiKey / _apiVersion) -- the SAME
    config the RA summary uses (Invoke-RiskAnalysis.ps1). No new AI infra.

      * Test-SiAiAvailable        -- is the reused SI OpenAI config present?
      * Build-SiGroundedPrompt    -- assemble a grounded prompt from KQL result
                                     rows (the AI must cite the rows; never invent).
      * Build-SiNlToKqlPrompt     -- assemble the NL->KQL composition prompt
                                     (schema + allow-list + read-only contract).
      * Get-SiTemplatedSummary    -- the AI-optional fallback: a plain-language
                                     summary built from the rows WITHOUT AI.
      * Invoke-SiAiChat           -- thin Azure OpenAI chat call (reuses SI config);
                                     returns $null when AI is unavailable (fail-soft).

    PowerShell 5.1-safe.
#>

Set-StrictMode -Version Latest

function Test-SiAiAvailable {
    [CmdletBinding()] param()
    $endpoint   = if (Get-Variable -Name OpenAI_endpoint   -Scope Global -ErrorAction SilentlyContinue) { $global:OpenAI_endpoint }   else { $null }
    $deployment = if (Get-Variable -Name OpenAI_deployment -Scope Global -ErrorAction SilentlyContinue) { $global:OpenAI_deployment } else { $null }
    $apiKey     = if (Get-Variable -Name OpenAI_apiKey     -Scope Global -ErrorAction SilentlyContinue) { $global:OpenAI_apiKey }     else { $null }
    return (-not [string]::IsNullOrWhiteSpace([string]$endpoint) -and
            -not [string]::IsNullOrWhiteSpace([string]$deployment) -and
            -not [string]::IsNullOrWhiteSpace([string]$apiKey))
}

function ConvertTo-SiRowsForGrounding {
    # Compact the rows to a JSON block small enough to ground the AI but complete
    # enough to cite. Caps the number of rows passed (the worklist top-N), never
    # the data scanned for the rollup (that's done upstream).
    param(
        [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Rows,
        [int]$MaxRows = 50
    )
    $take = @($Rows | Select-Object -First $MaxRows)
    return ($take | ConvertTo-Json -Depth 6)
}

# ---------------------------------------------------------------------------
# Grounded verdict/summary prompt. AI gets the ACTUAL rows + a strict instruction
# to write in plain management language, cite the data, and never invent.
# ---------------------------------------------------------------------------
function Build-SiGroundedPrompt {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Instruction,
        [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Rows,
        [string]$Audience = 'analyst',
        [int]$MaxRows = 50
    )

    $rowsJson = ConvertTo-SiRowsForGrounding -Rows $Rows -MaxRows $MaxRows
    $rowCount = @($Rows).Count

    $tone = if ($Audience -eq 'management') {
        'Write for a non-technical leader. No jargon, no table names, no KQL. Lead with what it means for the business and what to do.'
    } else {
        'Write for a security analyst. Be concrete and actionable. For each finding give: what it is, why it matters, what to do, how urgent.'
    }

    return @"
$Instruction

GROUNDING RULES (must follow):
- Use ONLY the data rows below. Do not invent assets, scores, or facts.
- Every claim must trace to a row. If the data does not support a claim, say so.
- $tone

There are $rowCount finding rows in scope (showing up to $MaxRows below):

DATA ROWS (JSON):
$rowsJson
"@
}

# ---------------------------------------------------------------------------
# NL -> KQL composition prompt. Gives the model the schema, the allow-list, and a
# hard read-only contract. The model's output is STILL passed through the
# Test-SiKqlReadOnly guardrail before execution -- this prompt is a first line,
# not the only line, of defence.
# ---------------------------------------------------------------------------
function Build-SiNlToKqlPrompt {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Question,
        [Parameter(Mandatory)][AllowEmptyCollection()][string[]]$AllowedTables
    )

    $tableList = ($AllowedTables -join ', ')

    return @"
You translate a plain-English security question into a SINGLE read-only Kusto (KQL) query
over a Microsoft Sentinel / Log Analytics workspace.

HARD RULES:
- READ-ONLY ONLY. Never emit a control command (anything starting with '.'), never use
  set/append/create/drop/alter/delete/ingest/purge/externaldata/cluster()/database().
- Read ONLY from these tables: $tableList
- Anchor on the latest snapshot: filter `where CollectionTime == toscalar(<Table> | summarize max(CollectionTime))`.
- Available risk columns: ConfigurationName, ConfigurationId, CriticalityTier (0-3), CriticalityTierLevel,
  SecuritySeverity, RiskScoreTotal, RiskScoreTotal_Weighted, RiskFactor_Consequence, RiskFactor_Probability,
  CollectionTime.
- End with a reasonable `take` (<= 200). Return ONLY the KQL, no prose, no markdown fences.

QUESTION:
$Question
"@
}

# ---------------------------------------------------------------------------
# AI-optional fallback. Build a plain-language summary from the rows with NO AI.
# This is what the management exec summary / analyst verdict degrade to when the
# SI OpenAI config is absent -- warn, never hard-fail.
# ---------------------------------------------------------------------------
function Get-SiTemplatedSummary {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Rows,
        [string]$Audience = 'analyst',
        $Diff = $null
    )

    $rows = @($Rows)
    if ($rows.Count -eq 0) {
        return "No findings in the current snapshot. (AI summary unavailable -- showing a generated summary.)"
    }

    $total = 0.0; foreach ($r in $rows) { $total += [double]$r.RiskScoreTotal }
    $top = @($rows | Sort-Object { [double]$_.RiskScoreTotal } -Descending | Select-Object -First 5)

    $byTier = @{}
    foreach ($r in $rows) {
        $t = if ($r.PSObject.Properties.Name -contains 'CriticalityTierLevel' -and $r.CriticalityTierLevel) { [string]$r.CriticalityTierLevel } else { 'Unclassified' }
        if (-not $byTier.ContainsKey($t)) { $byTier[$t] = 0 }
        $byTier[$t] += 1
    }

    $sb = New-Object System.Text.StringBuilder
    if ($Audience -eq 'management') {
        [void]$sb.AppendLine("Overall risk picture (auto-generated -- AI summary unavailable):")
        [void]$sb.AppendLine(("- {0} findings in scope, combined risk score {1}." -f $rows.Count, ([math]::Round($total,1))))
        if ($null -ne $Diff) {
            $dir = if ($Diff.ScoreDelta -lt 0) { 'down' } elseif ($Diff.ScoreDelta -gt 0) { 'up' } else { 'unchanged' }
            [void]$sb.AppendLine(("- Risk is {0} {1} since the previous snapshot ({2} new, {3} closed)." -f $dir, [math]::Abs($Diff.ScoreDelta), $Diff.NewCount, $Diff.ClosedCount))
        }
        [void]$sb.AppendLine("- Biggest contributors to risk right now:")
        foreach ($r in $top) {
            [void]$sb.AppendLine(("    * {0} ({1}) -- score {2}" -f $r.ConfigurationName, $r.CriticalityTierLevel, ([math]::Round([double]$r.RiskScoreTotal,1))))
        }
        [void]$sb.AppendLine("Recommendation: focus remediation on the highest-scoring critical-tier items above for the biggest score reduction.")
    } else {
        [void]$sb.AppendLine("Top findings (auto-generated -- AI verdict unavailable):")
        foreach ($r in $top) {
            $sev = if ($r.PSObject.Properties.Name -contains 'SecuritySeverity') { $r.SecuritySeverity } else { 'n/a' }
            [void]$sb.AppendLine(("- {0} [{1}, severity {2}, score {3}]" -f $r.ConfigurationName, $r.CriticalityTierLevel, $sev, ([math]::Round([double]$r.RiskScoreTotal,1))))
            if ($r.PSObject.Properties.Name -contains 'RiskFactor_Consequence' -and $r.RiskFactor_Consequence) {
                [void]$sb.AppendLine(("    why: {0}" -f $r.RiskFactor_Consequence))
            }
        }
        [void]$sb.AppendLine("Action: triage highest score first; verify the contributing factors above in the evidence rows.")
    }
    return $sb.ToString().TrimEnd()
}

# ---------------------------------------------------------------------------
# Thin Azure OpenAI chat call. Reuses the SI OpenAI config globals. Returns the
# assistant text, or $null when AI is unavailable / the call fails (fail-soft --
# the caller then uses Get-SiTemplatedSummary). Non-streaming for simplicity.
# ---------------------------------------------------------------------------
function Invoke-SiAiChat {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$SystemPrompt,
        [Parameter(Mandatory)][string]$UserPrompt,
        [int]$MaxTokens = 0
    )

    if (-not (Test-SiAiAvailable)) { return $null }

    try {
        $endpoint   = $global:OpenAI_endpoint.TrimEnd('/')
        $deployment = $global:OpenAI_deployment
        $apiVersion = if (Get-Variable -Name OpenAI_apiVersion -Scope Global -ErrorAction SilentlyContinue) { $global:OpenAI_apiVersion } else { '2025-01-01-preview' }
        $apiKey     = $global:OpenAI_apiKey
        if ($MaxTokens -lt 1) {
            $MaxTokens = if (Get-Variable -Name OpenAI_MaxTokensPerRequest -Scope Global -ErrorAction SilentlyContinue) { [int]$global:OpenAI_MaxTokensPerRequest } else { 4096 }
        }

        $uri = "$endpoint/openai/deployments/$deployment/chat/completions?api-version=$apiVersion"
        $body = @{
            model = $deployment
            temperature = 0
            top_p = 1.0
            max_tokens = $MaxTokens
            messages = @(
                @{ role = 'system'; content = $SystemPrompt },
                @{ role = 'user';   content = $UserPrompt }
            )
        } | ConvertTo-Json -Depth 12 -Compress

        $resp = Invoke-RestMethod -Method Post -Uri $uri -Headers @{ 'api-key' = $apiKey } `
            -ContentType 'application/json' -Body $body -ErrorAction Stop
        if ($resp -and $resp.choices -and $resp.choices.Count -gt 0) {
            return [string]$resp.choices[0].message.content
        }
        return $null
    } catch {
        Write-Warning ("SI Analyzer AI call failed -- falling back to templated summary: {0}" -f $_.Exception.Message)
        return $null
    }
}
