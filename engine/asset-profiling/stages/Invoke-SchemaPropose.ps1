#Requires -Version 5.1
<#
    SchemaPropose stage. For each NEW finding from SchemaDiff, ask AI to:
      - Classify security relevance (1-10)
      - If >= 5: draft a posture rule YAML + matching risk-analysis KQL

    Cost: one AI call per new finding. Budgeted via $global:MaxAiSpendPerRun
    + $global:SI_SchemaProposeAiCeiling (override). Findings beyond the
    budget are deferred to next week's sweep.

    Output goes onto RunContext.SchemaProposals -- consumed by SchemaOutput
    which writes the YAML drafts + the audit table.
#>

$script:SI_SchemaPropose_SystemPrompt = @'
You receive a NEW finding from a Microsoft Defender XDR schema sweep.
Your job: assess security relevance and propose a draft detection rule.

The finding is ONE of:
  - newProperty   { Label, Path }     a new node-property path within an
                                       Exposure Graph node label
  - newEdge       { EdgeLabel }       a new edge type in ExposureGraphEdges
  - newTriple     { Source,Edge,Target } a new (source, edge, target)
                                       relationship pattern
  - newColumn     { Table, Column, Type } a new column in a hunting table

Return ONLY JSON (no commentary, no markdown fences) with EXACTLY:

  Relevance       -- integer 1-10. 1=not security relevant; 10=critical
                     security signal that warrants a detection now.
                     Examples:
                       hasAdLeakedCredentials                       = 10
                       can impersonate as (edge label)              = 10
                       device --has credentials of--> user (triple) = 9
                       isActive (just an enabled flag)              = 5
                       displayName (cosmetic)                       = 1

  Engine          -- 'endpoint' | 'identity' | 'azure' | 'crossengine'
                     Pick the engine whose posture-rules folder this rule
                     belongs in. crossengine = the rule joins multiple
                     engines' classification tables.

  RuleType        -- 'KqlHunting' (most common) | 'AssetMetadata' | 'AssetTag'

  PostureRuleYaml -- A FULL YAML body string ready to drop into
                     posture-rules-pending/<engine>/<RuleName>.yaml.
                     Must include: PostureRuleVersion: 2, Name, AppliesTo,
                     RuleType, Mode (always 'Test' for AI-proposed),
                     QueryEngine, ProofLabel, ProofWeight (0-100),
                     Description, and Query (when KqlHunting).

  RiskQueryKql    -- (optional, when applicable) standalone KQL for a
                     risk-analysis report, distinct from the posture-rule
                     query. Empty string when not applicable.

  Reasoning       -- ONE sentence explaining the relevance score + the
                     attack pattern this would catch.

When Relevance < 5, set PostureRuleYaml = "" and RiskQueryKql = "" --
the engine then logs the finding to the catalog without writing a draft.

Quality bar: any rule you propose MUST be runnable as written. Use real
column names from the Defender XDR schema (DeviceLogonEvents.DeviceId,
ExposureGraphNodes.NodeProperties, etc.). Use Mode: Test by default so
humans review before promoting to Production.
'@

function Invoke-SISchemaProposeAi {
    [CmdletBinding()]
    param([Parameter(Mandatory)][hashtable]$Finding)

    # Schema-discover meta-engine. Gate on its own opt-in flag so customers can
    # enable schema-drift AI independently of per-engine classification AI.
    . (Join-Path (Split-Path -Parent $PSScriptRoot) 'shared\Test-SIAIEnabled.ps1')
    if (-not (Test-SIAIEnabled -Engine 'schemadiscover')) { return $null }

    $body = @{
        messages = @(
            @{ role = 'system'; content = $script:SI_SchemaPropose_SystemPrompt },
            @{ role = 'user';   content = ($Finding | ConvertTo-Json -Depth 6 -Compress) }
        )
        temperature     = 0.0
        response_format = @{ type = 'json_object' }
    } | ConvertTo-Json -Depth 8 -Compress

    $url = ('{0}/openai/deployments/{1}/chat/completions?api-version={2}' -f `
            $global:OpenAI_endpoint.TrimEnd('/'),
            $global:OpenAI_deployment,
            $global:OpenAI_apiVersion)

    try {
        $resp = Invoke-RestMethod -Method Post -Uri $url `
            -Headers @{ 'api-key' = $global:OpenAI_apiKey; 'Content-Type' = 'application/json' } `
            -Body $body -ErrorAction Stop
        return ($resp.choices[0].message.content | ConvertFrom-Json)
    } catch {
        Write-Warning ('SchemaPropose AI call failed: {0}' -f $_.Exception.Message)
        return $null
    }
}

function Invoke-SISchemaPropose {
    [CmdletBinding()]
    param([Parameter(Mandatory)][object]$RunContext)

    if (-not $RunContext.SchemaDiff) {
        return [pscustomobject]@{ Stage='SchemaPropose'; Summary='no diff available -- skipped' }
    }

    if ($RunContext.StorageContext.Mode -eq 'Mock') {
        $RunContext | Add-Member -MemberType NoteProperty -Name SchemaProposals -Value @() -Force
        return [pscustomobject]@{ Stage='SchemaPropose'; Summary='mock (skipped)' }
    }

    # Budget. Each finding = ~$0.005-0.01.
    $ceiling = if ($global:SI_SchemaProposeAiCeiling -gt 0) { [double]$global:SI_SchemaProposeAiCeiling } else { 5.0 }
    $perCall = if ($global:SI_AI_CostPerCallEstimate -gt 0) { [double]$global:SI_AI_CostPerCallEstimate } else { 0.01 }
    $spent   = 0.0

    # Build the finding queue: prioritise edges + triples (high-leverage)
    # over individual properties (long tail).
    $queue = New-Object System.Collections.ArrayList
    foreach ($t in @($RunContext.SchemaDiff.NewEdgeTriples)) {
        [void]$queue.Add(@{ Type='newTriple'; Source=$t.Source; Edge=$t.Edge; Target=$t.Target })
    }
    foreach ($el in @($RunContext.SchemaDiff.NewEdgeLabels)) {
        [void]$queue.Add(@{ Type='newEdge'; EdgeLabel=$el })
    }
    foreach ($p in @($RunContext.SchemaDiff.NewNodeProperties)) {
        [void]$queue.Add(@{ Type='newProperty'; Label=$p.Label; Path=$p.Path })
    }
    foreach ($c in @($RunContext.SchemaDiff.NewTableColumns)) {
        [void]$queue.Add(@{ Type='newColumn'; Table=$c.Table; Column=$c.Column; ColumnType=$c.Type })
    }

    Write-SIInfo ('   {0} new findings; AI ceiling ${1}; per-call ~${2}' -f $queue.Count, $ceiling, $perCall)

    $proposals = New-Object System.Collections.ArrayList
    $deferred  = 0
    foreach ($f in $queue) {
        if (($spent + $perCall) -gt $ceiling) {
            $deferred++
            continue
        }
        $ai = Invoke-SISchemaProposeAi -Finding $f
        $spent += $perCall
        if ($null -eq $ai) { continue }

        [void]$proposals.Add(@{
            Finding         = $f
            Relevance       = if ($null -ne $ai.Relevance) { [int]$ai.Relevance } else { 0 }
            Engine          = [string]$ai.Engine
            RuleType        = [string]$ai.RuleType
            PostureRuleYaml = [string]$ai.PostureRuleYaml
            RiskQueryKql    = [string]$ai.RiskQueryKql
            Reasoning       = [string]$ai.Reasoning
        })
    }

    $RunContext | Add-Member -MemberType NoteProperty -Name SchemaProposals -Value $proposals -Force

    [pscustomobject]@{
        Stage     = 'SchemaPropose'
        Findings  = $queue.Count
        Proposals = $proposals.Count
        Deferred  = $deferred
        AiSpent   = ('{0:n2}' -f $spent)
        Summary   = ('{0}/{1} findings -> proposals; {2} deferred (budget); ~${3}' -f $proposals.Count, $queue.Count, $deferred, ('{0:n2}' -f $spent))
    }
}
