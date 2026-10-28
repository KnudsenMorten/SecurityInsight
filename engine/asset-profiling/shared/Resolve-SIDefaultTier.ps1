#Requires -Version 5.1
<#
    Resolve-SIDefaultTier.ps1 -- the DEFAULT tier is a RULE, not a number in the code.

    The tier an asset gets when nothing else gave it one used to be a constant 3 in each profile builder. It is now the
    default tier rule in the rule set (asset-profiling-enrichment/shared/AssetProfileByDefaultTier.locked.yaml,
    `fallback: true`), with one detection per asset kind, so it is configured like any other rule: a custom copy, the
    Pro Rules page, or a whole-rule move on the Tier board.

      Get-SIDefaultTier       -Engine <kind> [-Asset]   the default rule's verdict for one asset ({ Tier; RuleId; DetectionId })
                                                         or $null when no default rule applies (turned off, or no detection
                                                         for this kind) -- the asset is then Unclassified, never a guess
      Get-SIDefaultTierValue  -Engine <kind> [-Asset]   just the tier (int) or $null
      Resolve-SITierByName    -Engine <kind> -Name      the MIN tier of the rules that can be decided from a NAME alone
                                                         (nameMatches arms -- which is also what a Tier board pin is)
      Resolve-SIUnprofiledTier -Engine <kind> -Name     name rules first, then the default rule: what Risk Analysis uses for
                                                         a finding on an asset no profiler has seen

    Where the default rule comes from: the rule set in force (shipped tree + overlay, or the Pro database's rules). When
    the Pro rule set does not carry the default rule yet (an install whose templates predate it), the SHIPPED rule file
    applies -- unless the rule set turned it off, which is honoured.
    PS 5.1 safe; never throws for a missing rule (returns $null).
#>

if (-not (Get-Command -Name Get-SIRuleSet -ErrorAction SilentlyContinue)) { . (Join-Path $PSScriptRoot 'Get-SIRuleSet.ps1') }
if (-not (Get-Command -Name Invoke-SIRuleEval -ErrorAction SilentlyContinue)) { . (Join-Path $PSScriptRoot 'RuleEval.ps1') }
# Get-SIRuleSet reports through Write-SIInfo, which the profiler chassis defines; elsewhere (Risk Analysis) it is quiet.
if (-not (Get-Command -Name Write-SIInfo -ErrorAction SilentlyContinue)) {
    function Write-SIInfo { param([Parameter(Mandatory)][string]$Message) Write-Verbose $Message }
}

$script:SIDefaultTierEngines = @('endpoint', 'identity', 'azure', 'publicip')
if ($null -eq $script:SIDefaultTierCache) { $script:SIDefaultTierCache = @{} }
if ($null -eq $script:SINameRuleCache) { $script:SINameRuleCache = @{} }

function Get-SIDefaultTierCacheKey {
    param([Parameter(Mandatory)][string]$Engine)
    '{0}|{1}|{2}' -f $Engine.ToLowerInvariant(), [string]$global:SI_EnrichmentDataRoot, [bool]$global:SI_ProRulesFromSql
}

function Clear-SIDefaultTierCache { $script:SIDefaultTierCache = @{}; $script:SINameRuleCache = @{} }

function Get-SIDefaultTierRules {
    <# The default tier rule(s) in force for one asset kind (cached per run). Empty when turned off or absent. #>
    param([Parameter(Mandatory)][ValidateSet('endpoint', 'identity', 'azure', 'publicip')][string]$Engine,
          [string]$SolutionRoot)
    $key = Get-SIDefaultTierCacheKey -Engine $Engine
    if (-not $SolutionRoot -and $script:SIDefaultTierCache.ContainsKey($key)) { return $script:SIDefaultTierCache[$key] }
    $set = @()
    try {
        $set = if ($SolutionRoot) { @(Get-SIRuleSet -Engine $Engine -Fallback -SolutionRootOverride $SolutionRoot 3>$null) }
               else { @(Get-SIRuleSet -Engine $Engine -Fallback 3>$null) }
    } catch { $set = @() }
    $set = @($set | ForEach-Object { $_ } | Where-Object { $null -ne $_ })
    $active = @($set | Where-Object { $_.Fallback -and $_.Mode -ne 'disable' })
    if ($active.Count -eq 0 -and -not $SolutionRoot) {
        # The rule set in force carries no default rule (a Pro install whose rules come from templates that predate it):
        # the shipped rule applies -- except where the rule set turned it off.
        $off = @($set | Where-Object { $_.Mode -eq 'disable' } | ForEach-Object { [string]$_.Id })
        $siRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSScriptRoot))
        $tree = @()
        try { $tree = @(Get-SIRuleSet -Engine $Engine -Fallback -SolutionRootOverride $siRoot 3>$null) } catch { $tree = @() }
        $active = @($tree | ForEach-Object { $_ } | Where-Object { $null -ne $_ -and $_.Fallback -and $_.Mode -ne 'disable' -and $off -notcontains [string]$_.Id })
    }
    if (-not $SolutionRoot) { $script:SIDefaultTierCache[$key] = $active }
    $active
}

function Get-SIDefaultTier {
    <# The default tier rule's verdict for one asset of -Engine kind: { Tier; RuleId; DetectionId }, or $null. #>
    param([Parameter(Mandatory)][ValidateSet('endpoint', 'identity', 'azure', 'publicip')][string]$Engine,
          $Asset, [string]$SolutionRoot)
    $rules = @(Get-SIDefaultTierRules -Engine $Engine -SolutionRoot $SolutionRoot)
    if ($rules.Count -eq 0) { return $null }
    # the evaluator sees the asset's kind (the per-kind detections) plus whatever the caller knows about the asset
    $probe = @{ SI_AssetKind = $Engine }
    if ($null -ne $Asset) {
        if ($Asset -is [System.Collections.IDictionary]) { foreach ($k in $Asset.Keys) { if (-not $probe.ContainsKey([string]$k)) { $probe[[string]$k] = $Asset[$k] } } }
        else { foreach ($p in $Asset.PSObject.Properties) { if (-not $probe.ContainsKey($p.Name)) { $probe[$p.Name] = $p.Value } } }
    }
    $best = $null
    foreach ($r in $rules) {
        $hit = $null
        try { $hit = Invoke-SIRuleEval -Asset $probe -Rule $r } catch { $hit = $null }
        if ($null -eq $hit -or $null -eq $hit.Set) { continue }
        $t = $null
        $raw = if ($hit.Set -is [System.Collections.IDictionary]) { $hit.Set['Tier'] } else { $hit.Set.Tier }
        if ($null -ne $raw -and "$raw" -ne '') { $n = 0; if ([int]::TryParse([string]$raw, [ref]$n) -and $n -ge 0 -and $n -le 3) { $t = $n } }
        if ($null -eq $t) { continue }
        if ($null -eq $best -or $t -lt $best.Tier) { $best = [pscustomobject]@{ Tier = $t; RuleId = [string]$hit.RuleId; DetectionId = [string]$hit.DetectionId } }
    }
    $best
}

function Get-SIDefaultTierValue {
    <# The default tier (0-3) for one asset of -Engine kind, or $null when no default rule applies. #>
    param([Parameter(Mandatory)][ValidateSet('endpoint', 'identity', 'azure', 'publicip')][string]$Engine, $Asset)
    $d = Get-SIDefaultTier -Engine $Engine -Asset $Asset
    if ($null -eq $d) { return $null }
    [int]$d.Tier
}

function Get-SINameOnlyRules {
    <#
        The rules in force for -Engine reduced to what a NAME can decide: in an 'any' detection only its nameMatches arms
        are kept; an 'all' detection is kept only when every arm is nameMatches. Rules left with no detection drop out.
        This is the rule set as far as a finding's own fields can answer it (a Tier board pin is a nameMatches rule).
    #>
    param([Parameter(Mandatory)][ValidateSet('endpoint', 'identity', 'azure', 'publicip')][string]$Engine)
    $key = Get-SIDefaultTierCacheKey -Engine $Engine
    if ($script:SINameRuleCache.ContainsKey($key)) { return $script:SINameRuleCache[$key] }
    $rules = @()
    try { $rules = @(Get-SIRuleSet -Engine $Engine 3>$null) } catch { $rules = @() }
    $out = New-Object System.Collections.Generic.List[object]
    foreach ($r in @($rules | ForEach-Object { $_ } | Where-Object { $null -ne $_ -and $_.Mode -ne 'disable' })) {
        $dets = New-Object System.Collections.Generic.List[object]
        foreach ($d in @($r.Detections)) {
            if ($null -eq $d -or $null -eq $d.Detect) { continue }
            $anyList = $d.Detect.any; $allList = $d.Detect.all
            if ($anyList) {
                $names = @(@($anyList) | Where-Object { [string]$_.kind -eq 'nameMatches' })
                if ($names.Count) { $dets.Add([pscustomobject]@{ Id = $d.Id; Detect = @{ any = $names }; Set = $d.Set; ExcludeAssets = $d.ExcludeAssets }) }
            } elseif ($allList) {
                $all = @($allList)
                if ($all.Count -and @($all | Where-Object { [string]$_.kind -ne 'nameMatches' }).Count -eq 0) { $dets.Add($d) }
            }
        }
        if ($dets.Count) {
            $out.Add([pscustomobject]@{ Id = $r.Id; Mode = $r.Mode; Detections = $dets.ToArray(); Fallback = $false })
        }
    }
    $arr = $out.ToArray()
    $script:SINameRuleCache[$key] = $arr
    $arr
}

function Resolve-SITierByName {
    <# The MIN tier the name-decidable rules give -Name for -Engine: { Tier; RuleId; DetectionId }, or $null. #>
    param([Parameter(Mandatory)][ValidateSet('endpoint', 'identity', 'azure', 'publicip')][string]$Engine,
          [AllowEmptyString()][string]$Name)
    if ([string]::IsNullOrWhiteSpace($Name)) { return $null }
    $probe = @{ Name = $Name.Trim(); SI_AssetKind = $Engine }
    $best = $null
    foreach ($r in @(Get-SINameOnlyRules -Engine $Engine)) {
        $hit = $null
        try { $hit = Invoke-SIRuleEval -Asset $probe -Rule $r } catch { $hit = $null }
        if ($null -eq $hit -or $null -eq $hit.Set) { continue }
        $raw = if ($hit.Set -is [System.Collections.IDictionary]) { $hit.Set['Tier'] } else { $hit.Set.Tier }
        $n = 0
        if ($null -eq $raw -or -not [int]::TryParse([string]$raw, [ref]$n) -or $n -lt 0 -or $n -gt 3) { continue }
        if ($null -eq $best -or $n -lt $best.Tier) { $best = [pscustomobject]@{ Tier = $n; RuleId = [string]$hit.RuleId; DetectionId = [string]$hit.DetectionId } }
    }
    $best
}

function Resolve-SIUnprofiledTier {
    <#
        The tier of an asset no profiler has seen, from what is known about it (its kind and its name): the rules a name
        can decide first (MIN, as the profilers combine rules), the default tier rule when none of them matches.
        Returns { Tier; SetBy ('rule' | 'default'); RuleId; DetectionId } or $null (no kind, or no default rule in force).
    #>
    param([AllowEmptyString()][string]$Engine, [AllowEmptyString()][string]$Name)
    if ([string]::IsNullOrWhiteSpace($Engine) -or $script:SIDefaultTierEngines -notcontains $Engine.ToLowerInvariant()) { return $null }
    $e = $Engine.ToLowerInvariant()
    $byName = Resolve-SITierByName -Engine $e -Name $Name
    if ($null -ne $byName) { return [pscustomobject]@{ Tier = $byName.Tier; SetBy = 'rule'; RuleId = $byName.RuleId; DetectionId = $byName.DetectionId } }
    $d = Get-SIDefaultTier -Engine $e -Asset @{ Name = $Name }
    if ($null -eq $d) { return $null }
    [pscustomobject]@{ Tier = $d.Tier; SetBy = 'default'; RuleId = $d.RuleId; DetectionId = $d.DetectionId }
}
