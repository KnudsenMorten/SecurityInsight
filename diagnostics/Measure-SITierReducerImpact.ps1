#Requires -Version 5.1
<#
    Would arming the tier reducer change any tier, and in which DIRECTION?

    RUN THIS BEFORE DECLARING ANY `question` GROUPING. On 2026-08-12 a proposed grouping looked entirely
    reasonable and this script rejected it in seconds: of 720 source-pair x tier combinations, 78
    changed and ALL 78 made the tier LESS critical. Zero made it more critical.

        endpoint_catalog_match(T2) vs posture_rule_target_tier(T0)  ->  T2, was T0

    A posture rule that detected Tier 0, discarded because the catalog outranks it. That is ruling (f)
    inverted -- "we need to prioritise tier 0 over tier 1" -- reached from a third direction after the
    operator had already corrected two earlier drafts of this area.

    🔒 THE ACCEPTANCE BAR, CORRECTED. An earlier version of this header said the LESS-critical count must
    be ZERO. That is wrong and would forbid the feature outright: the stale-tag case the operator
    described -- tag asserts T0, observation shows a T3 workstation -- is INHERENTLY a less-critical
    change, and it is the entire reason the rule exists. Under plain MIN the operator's other example
    (tag T3 vs graph T0) already resolves correctly, so contradiction resolution earns its keep ONLY in
    the direction that lowers a tier.

    The real bar: EVERY less-critical change must have the ASSERTED claim as the suppressed one. An
    observed detection appearing in the suppressed column is a defect -- that is a true signal being
    discarded, which is the expensive direction to be wrong in. This script now checks that itself and
    prints PASS/FAIL rather than leaving it to be eyeballed.

    The live tier histogram still needs a real run -- but the CLASSIFICATION's effect is fully
    enumerable offline, which is why this exists.
#>
$ErrorActionPreference = 'Stop'
$si = 'C:\claude-sessions\SI-v3\SOLUTIONS\SecurityInsight'
. "$si\engine\asset-profiling\shared\Get-SITierTrustList.ps1"
. "$si\engine\asset-profiling\shared\Resolve-SITierClaims.ps1"

$schema = Get-Content "$si\asset-profiling-schema\endpoint.schema.locked.json" -Raw | ConvertFrom-Json
$armed  = Get-SITierTrustList -Aggregator $schema.aggregator

# The same list with every question AND kind stripped = today's behaviour (plain MIN). Both must be
# dropped: `kind` is now what arms the reducer, so copying it would compare the armed list to itself.
$inertContrib = $schema.aggregator.contributors | ForEach-Object {
    [pscustomobject]@{ id = $_.id; order = $_.order; trusted = $_.trusted }
}
$inert = Get-SITierTrustList -Aggregator ([pscustomobject]@{ contributors = $inertContrib })

$ids = @($armed.Id)
$tiers = 0..3
$changed = New-Object System.Collections.Generic.List[object]
$total = 0

# Every PAIR of sources x every tier combination. Pairs are where contradiction can first appear;
# larger sets reduce to the same rule applied repeatedly.
for ($i = 0; $i -lt $ids.Count; $i++) {
  for ($j = $i + 1; $j -lt $ids.Count; $j++) {
    foreach ($ta in $tiers) {
      foreach ($tb in $tiers) {
        $claims = @(
          [pscustomobject]@{ SourceId = $ids[$i]; Tier = $ta }
          [pscustomobject]@{ SourceId = $ids[$j]; Tier = $tb }
        )
        $before = (Resolve-SITierClaims -Claims $claims -TrustList $inert).Tier
        $after  = (Resolve-SITierClaims -Claims $claims -TrustList $armed).Tier
        $total++
        if ($before -ne $after) {
          # WHICH source got suppressed is the number that matters -- see the acceptance bar in the
          # header. A less-critical change is fine when the ASSERTED claim lost, and a defect when an
          # observed detection did.
          $sup = @((Resolve-SITierClaims -Claims $claims -TrustList $armed).Contradicted).SourceId -join ','
          [void]$changed.Add([pscustomobject]@{
            A = $ids[$i]; TierA = $ta; B = $ids[$j]; TierB = $tb; Before = $before; After = $after
            Suppressed = $sup
          })
        }
      }
    }
  }
}

"combinations evaluated : $total"
"combinations that CHANGE: $($changed.Count)  ({0:n1}%)" -f (100 * $changed.Count / $total)

if ($changed.Count -gt 0) {
  "`n--- direction of change (does arming ever make a tier LESS critical?) ---"
  $up   = @($changed | Where-Object { $_.After -lt $_.Before })   # more critical
  $down = @($changed | Where-Object { $_.After -gt $_.Before })   # LESS critical -- the risky direction
  "  more critical after arming : $($up.Count)"
  "  LESS critical after arming : $($down.Count)   <-- these suppress a signal; each must be justified"

  "`n--- WHICH SOURCE WAS SUPPRESSED (the acceptance bar: only ASSERTED sources may appear) ---"
  $changed | Group-Object Suppressed | Sort-Object Count -Descending |
    ForEach-Object {
      $k = Get-SITierClaimKind -TrustList $armed -Id $_.Name
      "  {0,-34} {1,3}   [{2}]" -f $_.Name, $_.Count, $k
    }

  # THE BAR, CHECKED RATHER THAN EYEBALLED. An observed detection in the suppressed column means a
  # true signal is being discarded -- the failure mode that got this area wrong twice already.
  $violations = @($changed | Where-Object {
      $_.Suppressed -and (Get-SITierClaimKind -TrustList $armed -Id $_.Suppressed) -ne 'asserted'
  })
  "`n--- ACCEPTANCE BAR ---"
  if ($violations.Count -eq 0) {
    "  PASS -- every suppressed claim is an ASSERTED one. No observed detection is discarded."
  } else {
    "  FAIL -- $($violations.Count) change(s) suppress an OBSERVED detection. The model is wrong:"
    $violations | Group-Object Suppressed | ForEach-Object { "    {0,-34} {1}" -f $_.Name, $_.Count }
  }

  "`n--- sample of LESS-critical outcomes (max 12) ---"
  $down | Select-Object -First 12 | ForEach-Object {
    "  {0}(T{1}) vs {2}(T{3})  ->  T{4} was T{5}" -f $_.A, $_.TierA, $_.B, $_.TierB, $_.After, $_.Before
  }
}

"`n--- the two cases that must NOT change ---"
$ca = Resolve-SITierClaims -TrustList $armed -Claims @(
  [pscustomobject]@{ SourceId='endpoint_catalog_match'; Tier=0 }
  [pscustomobject]@{ SourceId='tenant_si_manual_tag';   Tier=2 }
)
"  certificate authority in a Tier-2 subscription : T$($ca.Tier)  (must be 0)"
$ga = Resolve-SITierClaims -TrustList $armed -Claims @(
  [pscustomobject]@{ SourceId='endpoint_catalog_match';   Tier=2 }
  [pscustomobject]@{ SourceId='endpoint_user_based_tier'; Tier=0 }
)
"  GA logon on a Tier-2 catalog hit               : T$($ga.Tier)  (must be 0)"
