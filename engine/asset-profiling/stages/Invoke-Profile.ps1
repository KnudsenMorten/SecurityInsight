#Requires -Version 5.1
<#
    Invoke-Profile.ps1

    PROFILE stage (ARCHITECTURE.md § 4). Runs AFTER Stage Classify --
    overlays AssetProfileBy* YAML rule matches onto the per-asset Verdict
    block produced by Classify. always-on (opt-in flag dropped).
    There is one rule engine; the legacy hardcoded catalog matches in
    Classify continue to produce per-source verdict columns, while Profile
    feeds the SIRules flat column and contributes to the final tier MIN.

    Three-pass execution per ARCHITECTURE.md § 9:
      1. COMPILE    -- load rules via Get-SIRuleSet
      2. BULK FETCH -- Build-SIRuleIndexes (one external call per kind)
      3. PER-ASSET  -- Invoke-SIRuleEval (O(1) index lookups)

    For each asset, ALL matched rules are collected (not first-match-wins) so
    SIRules is a complete audit trail. Verdict updates:
      Verdict.SI_RuleMatches = @($matchedRule, ...)   -- ordered, full detail
      Verdict.SI_RuleTier    = MIN(rule.set.tier across matches) | $null
      Verdict.SI_Tier        = MIN(Verdict.SI_Tier, Verdict.SI_RuleTier)
      Verdict.SI_RuleTags    = unique flattened set of tags from matched rules
#>

function Invoke-SIProfile {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][object]$RunContext
    )

    $engine = $RunContext.Engine
    Write-SIInfo ("engine={0}" -f $engine)

    # Resolve helpers from this script's location
    $sharedRoot = Split-Path -Parent $PSScriptRoot
    . (Join-Path $sharedRoot 'shared\Get-SIRuleSet.ps1')
    . (Join-Path $sharedRoot 'shared\RuleEval.ps1')
    . (Join-Path $sharedRoot 'shared\RuleIndexes.ps1')

    # ---- Pass 1: COMPILE ----
    $rules = Get-SIRuleSet -Engine $engine
    Write-SIInfo ("compile: {0} rules loaded" -f $rules.Count)

    # ---- Read assets from Classify-stage staging (preserves the per-source
    # verdict block produced upstream so Profile only OVERLAYS rule matches).
    $siRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSScriptRoot))
    . (Join-Path $siRoot 'engine\asset-profiling\storage\StagingBlob.ps1')
    $records = @(Read-SIStageShards -Context $RunContext.StorageContext `
                                    -ContainerName $RunContext.StagingContainer `
                                    -RunId $RunContext.RunId `
                                    -Stage 'Classify' `
                                    -ReplicaIndex ([int]$RunContext.ShardIndex))
    Write-SIInfo ("{0} records read from Classify staging" -f $records.Count)

    if ($rules.Count -eq 0 -or $records.Count -eq 0) {
        return [pscustomobject]@{
            Stage         = 'Profile'
            Engine        = $engine
            RulesLoaded   = $rules.Count
            AssetsScanned = $records.Count
            Matched       = 0
            NoMatch       = $records.Count
            Summary       = ('{0} rules x {1} assets -> 0 matched (skipped)' -f $rules.Count, $records.Count)
        }
    }

    # ---- Pass 2: BULK FETCH ----
    $indexStats = Build-SIRuleIndexes -Engine $engine -Rules $rules -Assets $records -RunContext $RunContext
    foreach ($k in $indexStats.Keys) {
        $s = $indexStats[$k]
        if ($s.Built) { Write-SIInfo ("index '{0}' built ({1} entries, {2} ms)" -f $k, $s.Rows, $s.Ms) }
        else          { Write-SIInfo ("index '{0}' NOT built ({1})" -f $k, $s.Error) }
    }

    # ---- Pass 3: PER-ASSET (collect ALL matches, not first-wins) ----
    $matchedAssets = 0; $noMatchAssets = 0; $totalMatches = 0
    $perRuleHits   = @{}   # per-rule-name fire counter for visibility
    $perRuleMs     = @{}   # cumulative time per rule -- spotting slow rules
    $_total = $records.Count; $_i = 0
    Reset-SIProgress -Label "ProfileRuleEval-$engine" -ErrorAction SilentlyContinue
    $_ruleSw = [System.Diagnostics.Stopwatch]::new()
    foreach ($r in $records) {
        $_i++
        try { Write-SIProgress -Label "ProfileRuleEval-$engine" -Index $_i -Total $_total } catch { }
        $matches = New-Object System.Collections.ArrayList
        foreach ($rule in $rules) {
            $_ruleSw.Restart()
            $hit = Invoke-SIRuleEval -Asset $r -Rule $rule
            $_ruleSw.Stop()
            $_rkey = [string]$rule.Id
            if ($perRuleMs.ContainsKey($_rkey)) { $perRuleMs[$_rkey] += $_ruleSw.Elapsed.TotalMilliseconds }
            else                                 { $perRuleMs[$_rkey] = $_ruleSw.Elapsed.TotalMilliseconds }
            if (-not $hit) { continue }
            $totalMatches++
            $set = $hit.Set
            [void]$matches.Add([pscustomobject]@{
                RuleId       = [string]$hit.RuleId
                DetectionId  = [string]$hit.DetectionId
                Tier         = if ($null -ne $set.Tier)         { [int]$set.Tier }              else { $null }
                Purpose      = if ($set.Purpose)                { [string]$set.Purpose }        else { $null }
                Category     = if ($set.Category)               { [string]$set.Category }       else { $null }
                Tags         = if ($set.Tags)                   { @($set.Tags) }                else { @() }
                cmdbId       = if ($set.cmdbId)                 { [string]$set.cmdbId }         else { $null }
                cmdbName     = if ($set.cmdbName)               { [string]$set.cmdbName }       else { $null }
            })
            # per-rule fire counter
            $rkey = ('{0}/{1}' -f $hit.RuleId, $hit.DetectionId)
            if ($perRuleHits.ContainsKey($rkey)) { $perRuleHits[$rkey]++ } else { $perRuleHits[$rkey] = 1 }
        }

        # Logon-graph tier inheritance is now a NATIVE rule:
        # asset-profiling-enrichment/endpoint/AssetProfileByLogonUser.locked.yaml
        # uses kind=mostFrequentUserTier to read Metadata.MostFrequentUserTier
        # (stamped by Enrich/Get-SIBulkDeviceUserCorrelation) and emits a tier set.

        # Ensure $r has a Verdict object to overlay onto (Classify writes one;
        # if missing for any reason create a minimal pscustomobject so
        # Add-Member works uniformly).
        $verdict = $r.Verdict
        if ($null -eq $verdict) {
            $verdict = [pscustomobject]@{ SI_Tier = $null; SI_Status = 'no-classify-verdict' }
            if ($r.PSObject.Properties['Verdict']) { $r.Verdict = $verdict }
            else { Add-Member -InputObject $r -MemberType NoteProperty -Name 'Verdict' -Value $verdict -Force }
        }

        # SI_RuleMatches: array of matched rules (empty when none).
        $matchArr = @($matches)
        Add-Member -InputObject $verdict -MemberType NoteProperty -Name 'SI_RuleMatches' -Value $matchArr -Force

        # SI_RuleTier: MIN tier across matched rules (or $null when no rule
        # supplied a tier). Excludes nulls so a matched rule without `set.tier`
        # doesn't pin the asset to T0.
        $ruleTier = $null
        foreach ($m in $matchArr) {
            if ($null -eq $m.Tier) { continue }
            if ($null -eq $ruleTier -or $m.Tier -lt $ruleTier) { $ruleTier = [int]$m.Tier }
        }
        Add-Member -InputObject $verdict -MemberType NoteProperty -Name 'SI_RuleTier' -Value $ruleTier -Force

        # SI_RuleTags: flattened unique set across matches.
        $tagSet = New-Object System.Collections.Generic.HashSet[string]
        foreach ($m in $matchArr) {
            foreach ($t in $m.Tags) {
                if (-not [string]::IsNullOrWhiteSpace([string]$t)) { [void]$tagSet.Add([string]$t) }
            }
        }
        Add-Member -InputObject $verdict -MemberType NoteProperty -Name 'SI_RuleTags' -Value (@($tagSet) | Sort-Object) -Force

        # Final tier = MIN(existing Verdict.SI_Tier, SI_RuleTier). Existing tier
        # stays when no rule contributed (ruleTier = $null).
        # explicit $null guard on $verdict.SI_Tier BEFORE [int] cast.
        # Without this, PowerShell evaluates [int]$null = 0 (no exception, just
        # silent coercion), making $existing=0, and MIN(3, 0) = 0 -- so any
        # asset where Classify left SI_Tier=null would land Tier=0 even when
        # the matched rule clearly emitted Tier=3. (Task #113 root cause.)
        if ($null -ne $ruleTier) {
            $existing = $null
            if ($verdict.PSObject.Properties['SI_Tier'] -and $null -ne $verdict.SI_Tier) {
                try { $existing = [int]$verdict.SI_Tier } catch { $existing = $null }
            }
            $final = if ($null -eq $existing) { $ruleTier } elseif ($ruleTier -lt $existing) { $ruleTier } else { $existing }
            $verdict.SI_Tier = $final
        }

        # Stamp first-match cmdb hints onto record top-level so Reconcile sees them.
        $firstWithCmdb = $matchArr | Where-Object { $_.cmdbId } | Select-Object -First 1
        if ($firstWithCmdb) {
            foreach ($f in @('cmdbId','cmdbName')) {
                if (-not $r.PSObject.Properties[$f]) {
                    Add-Member -InputObject $r -MemberType NoteProperty -Name $f -Value ([string]$firstWithCmdb.$f) -Force
                } elseif ([string]::IsNullOrWhiteSpace([string]$r.$f)) {
                    $r.$f = [string]$firstWithCmdb.$f
                }
            }
        }

        if ($matchArr.Count -gt 0) { $matchedAssets++ } else { $noMatchAssets++ }
    }
    Write-SIInfo ("per-asset eval: assets-matched={0} no-match={1} total-matches={2}" -f $matchedAssets, $noMatchAssets, $totalMatches)
    # per-rule fire breakdown so operators see WHICH rules fired
    if ($perRuleHits.Count -gt 0) {
        Write-SIInfo 'rule-fire summary:'
        foreach ($k in ($perRuleHits.Keys | Sort-Object { -$perRuleHits[$_] })) {
            Write-SIInfo ('  {0,5}x  {1}' -f $perRuleHits[$k], $k)
        }
    }
    # rule-time summary -- top-20 rules by cumulative ms across
    # all assets in this Pass 3. Helps spot the one expensive `kind:` (kustoSets,
    # hasAzureTagDirectOrParent, big nameMatches regex set, etc.).
    if ($perRuleMs.Count -gt 0) {
        $topN = 20
        $totalRuleMs = ($perRuleMs.Values | Measure-Object -Sum).Sum
        Write-SIInfo ('rule-time summary (top {0} by cumulative ms; total={1:N0} ms across all rules):' -f $topN, $totalRuleMs)
        $ranked = $perRuleMs.GetEnumerator() | Sort-Object Value -Descending | Select-Object -First $topN
        foreach ($entry in $ranked) {
            $pct = if ($totalRuleMs -gt 0) { 100 * $entry.Value / $totalRuleMs } else { 0 }
            $avgMs = $entry.Value / [Math]::Max($records.Count, 1)
            Write-SIInfo ('  {0,8:N0} ms  ({1,5:N1}%)  avg/asset={2,5:N1} ms  {3}' -f $entry.Value, $pct, $avgMs, $entry.Key)
        }
    }

    # Re-write enriched records back to Classify staging
    Write-SIStageShard -Context $RunContext.StorageContext `
                       -ContainerName $RunContext.StagingContainer `
                       -RunId $RunContext.RunId `
                       -Stage 'Classify' `
                       -ShardIndex $RunContext.ShardIndex `
                       -Records $records | Out-Null

    return [pscustomobject]@{
        Stage         = 'Profile'
        Engine        = $engine
        RulesLoaded   = $rules.Count
        AssetsScanned = $records.Count
        Matched       = $matchedAssets
        NoMatch       = $noMatchAssets
        TotalMatches  = $totalMatches
        IndexStats    = $indexStats
        Summary       = ('{0} rules x {1} assets -> {2} assets matched ({3} total rule-matches)' -f $rules.Count, $records.Count, $matchedAssets, $totalMatches)
    }
}
