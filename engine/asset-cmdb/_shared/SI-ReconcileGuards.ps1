#Requires -Version 5.1
<#
    RECONCILE GUARDS -- the connector's safety properties, as pure functions.

    ✅ PROMOTED OUT OF `diagnostics/` 2026-08-28 (V3-HANDOFF task SN-2). It used to say "SI v3 PoC"
    and "a promotion candidate for the connector work". It was measured on 2026-08-28 that 11 of its
    12 guards existed NOWHERE in `engine/` -- while `V3-ARCHITECTURE` §4.4 claimed "All twelve built
    and proven". They were built and proven as pure functions, in a folder that does not ship. A green
    tick over an empty space.

    🔒 THE FOUR CLOSE GUARDS PROTECT A PATH THAT DOES NOT EXIST YET. `Invoke-SICmdbSync` has no
    close/retire capability (SN-4), so `Get-SIReconcilePlan` is not called by anything today. That is
    deliberate and it is TRIPWIRED: `SIv3-ReconcileGuardsWired.Tests.ps1` fails the moment a close path
    appears in `engine/asset-cmdb/` without these guards in front of it. Building SN-4 before SN-2 is
    what puts an unguarded mass-close into the product.

    📌 ONE GUARD IS ALREADY SHIPPED UNDER ANOTHER NAME. Ambiguity (`Get-SIMatchDecision`'s
    dead-letter half) is implemented in `SI-ServiceNowClient.ps1` as `Ambiguous = (Rows.Count > 1)`
    and in `SI-CmdbSyncApply.ps1` as the `Review` bucket -- "multiple match, never forced". Do NOT
    re-implement it here; two copies of one safety rule diverge, and the divergence is silent.

    These are the design's SAFETY properties made executable. Every one exists because the failure it
    prevents is expensive and hard to reverse:

      * a mass-close wipes a customer's open tickets. THIS ESTATE HAS ALREADY DONE THE EQUIVALENT ONCE
        -- 2026-06-15, the PIM engine disabled 53 production users from an empty desired set with no
        guard. Same shape, one solution over.
      * a wrong close REASON falsifies remediation metrics, and it flatters, so nobody investigates.
      * an approved-but-stale intent closes a machine that came back to life while a human worked
        through the queue.
      * a duplicate CI is effectively permanent once incidents and changes point at it.

    No I/O, no Azure, no ServiceNow. Everything here is decidable from arguments, so the guards can be
    proven before anything is built on top of them.

    🔒 NOTHING HERE APPLIES ANYTHING. These functions decide; they never act.
#>

# NO Set-StrictMode here. MEASURED 2026-08-12: Set-StrictMode in a dot-sourced file LEAKS INTO THE
# CALLER'S SCOPE, so a library silently overrides the strictness its host chose -- and the shipped
# engines run Set-StrictMode -Off ("designed for non-StrictMode environments"). This file is dot-sourced
# by its tests today and is a promotion candidate for the connector work; removing it here means the
# hazard does not travel with the code, which is exactly how it reached the correlation engine.
function New-SIReconcileDecision {
    param([string]$Action, [string]$Reason, [string]$Detail, $Plan)
    [pscustomobject]@{ Action = $Action; Reason = $Reason; Detail = $Detail; Plan = $Plan }
}

function Get-SIReconcilePlan {
    <#
        The core diff, with every mass-close guard applied BEFORE a plan is returned.

        desired = what the current snapshot says is true
        actual  = what we previously asserted to the target (ExternalLink)

        Returns Action = 'Proceed' | 'Halt'. A 'Halt' NEVER carries an applyable close set -- callers
        cannot accidentally act on a refused plan, because there is nothing in it to act on.
    #>
    param(
        # AllowEmptyString is required as well as AllowEmptyCollection: real key lists contain blanks,
        # and without it the guard throws on the exact input it exists to tolerate.
        [Parameter(Mandatory)] [AllowEmptyCollection()] [AllowEmptyString()] [AllowNull()] [string[]] $DesiredKeys,
        [Parameter(Mandatory)] [AllowEmptyCollection()] [AllowEmptyString()] [AllowNull()] [string[]] $ActualKeys,
        [Parameter(Mandatory)] [bool]   $RunComplete,
        [string] $ScopeVersion       = 'v1',
        [string] $PreviousScopeVersion = 'v1',
        [int]    $MaxCloseAbsolute   = 50,
        [double] $MaxClosePercent    = 10.0,
        # #414: the vulnerability connector's ceiling is proportional only by default -- no absolute count
        [switch] $NoAbsoluteLimit
    )

    $desired = @($DesiredKeys | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
    $actual  = @($ActualKeys  | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })

    # ---- GUARD 1: a run that did not complete is not evidence of anything -------------------------
    # Absence of data is not evidence of absence. A throttled or failed collection produces a small
    # `desired` that looks exactly like a genuinely emptied estate.
    if (-not $RunComplete) {
        return New-SIReconcileDecision -Action 'Halt' -Reason 'RunIncomplete' `
            -Detail 'Reconcile refused: the collection run is not marked complete.' -Plan $null
    }

    # ---- GUARD 2: an empty desired set closes EVERYTHING ------------------------------------------
    # The PIM 2026-06-15 shape. Refuse before computing, so no caller can pick the close set out.
    if ($desired.Count -eq 0 -and $actual.Count -gt 0) {
        return New-SIReconcileDecision -Action 'Halt' -Reason 'EmptyDesiredSet' `
            -Detail ("Reconcile refused: desired set is EMPTY while {0} links are open." -f $actual.Count) -Plan $null
    }

    # ---- GUARD 3: a SCOPE CHANGE is a complete run that should still close nothing -----------------
    # Someone narrows a filter, the run succeeds completely, and hundreds of assets legitimately
    # vanish. Every completeness check passes. Absences are Excluded, not Stale.
    $scopeChanged = ($ScopeVersion -ne $PreviousScopeVersion)

    $desiredSet = @{}; foreach ($k in $desired) { $desiredSet[$k.ToLowerInvariant()] = $true }
    $actualSet  = @{}; foreach ($k in $actual)  { $actualSet[$k.ToLowerInvariant()]  = $true }

    $adds   = @($desired | Where-Object { -not $actualSet.ContainsKey($_.ToLowerInvariant()) })
    $closes = @($actual  | Where-Object { -not $desiredSet.ContainsKey($_.ToLowerInvariant()) })
    $keeps  = @($desired | Where-Object {      $actualSet.ContainsKey($_.ToLowerInvariant()) })

    if ($scopeChanged -and $closes.Count -gt 0) {
        return New-SIReconcileDecision -Action 'Halt' -Reason 'ScopeChanged' `
            -Detail ("Collection scope changed ({0} -> {1}); {2} absences are EXCLUDED, not stale. Reporting the scope delta instead of acting on it." -f $PreviousScopeVersion, $ScopeVersion, $closes.Count) `
            -Plan ([pscustomobject]@{ Adds = $adds; Keeps = $keeps; Closes = @(); Excluded = $closes })
    }

    # ---- GUARD 4: closure ceiling, absolute AND proportional ---------------------------------------
    # A legitimate mass-remediation is rare enough to be worth a human confirming. A broken run is not.
    $pct = if ($actual.Count -gt 0) { [math]::Round(100.0 * $closes.Count / $actual.Count, 1) } else { 0.0 }
    if ((-not $NoAbsoluteLimit -and $closes.Count -gt $MaxCloseAbsolute) -or $pct -gt $MaxClosePercent) {
        $ceil = if ($NoAbsoluteLimit) { '{0}%' -f $MaxClosePercent } else { 'abs {0} / {1}%' -f $MaxCloseAbsolute, $MaxClosePercent }
        return New-SIReconcileDecision -Action 'Halt' -Reason 'CloseCeilingExceeded' `
            -Detail ("Closure set {0} of {1} open links ({2}%) exceeds the ceiling ({3})." -f $closes.Count, $actual.Count, $pct, $ceil) `
            -Plan ([pscustomobject]@{ Adds = $adds; Keeps = $keeps; Closes = @(); Proposed = $closes })
    }

    New-SIReconcileDecision -Action 'Proceed' -Reason 'Ok' -Detail ("{0} add / {1} keep / {2} close" -f $adds.Count, $keeps.Count, $closes.Count) `
        -Plan ([pscustomobject]@{ Adds = $adds; Keeps = $keeps; Closes = $closes; Excluded = @() })
}

function Get-SIAssetLifecycleState {
    <#
        POSITIVE EVIDENCE closes. ABSENCE only ever proposes.

        "ARM returned 404 for this resource id" is a fact.
        "It wasn't in the list this time" is not.

        That single distinction separates a useful reconciler from a destructive one.
    #>
    param(
        [Parameter(Mandatory)] [bool] $SeenThisRun,
        [bool]   $SourceRan          = $true,
        [bool]   $PositiveRemoval    = $false,   # source explicitly says gone (404 / deleted / offboarded-with-delete)
        [bool]   $StillExistsUnmanaged = $false, # exists but no longer covered (licence lapsed, offboarded)
        [bool]   $ScopeExcluded      = $false,
        [int]    $DaysSinceSeen      = 0,
        [int]    $GraceDays          = 14
    )

    if (-not $SourceRan)         { return 'Unknown'   }   # freeze: never act on a source that did not run
    if ($ScopeExcluded)          { return 'Excluded'  }   # we stopped looking; that says nothing about the asset
    if ($PositiveRemoval)        { return 'Decommissioned' }
    if ($SeenThisRun)            { return 'Active'    }
    if ($StillExistsUnmanaged)   { return 'Unmanaged' }   # a finding, not an absence
    if ($DaysSinceSeen -le $GraceDays) { return 'Missing' }
    'Stale'
}

function Get-SILifecycleAction {
    <# Which states may CLOSE on their own, and which may only PROPOSE. #>
    param([Parameter(Mandatory)][string]$State)
    switch ($State) {
        'Decommissioned' { 'Close'   }   # positive evidence
        'Stale'          { 'Propose' }   # absence past grace -- a human confirms
        'Active'         { 'None'    }
        'Missing'        { 'None'    }   # within grace: too early to mean anything
        'Unmanaged'      { 'None'    }   # raise as a finding elsewhere, do not close
        'Excluded'       { 'None'    }
        'Unknown'        { 'None'    }
        default          { 'None'    }
    }
}

function Get-SIFindingCloseReason {
    <#
        The close REASON is not cosmetic. Closing vulnerabilities as "fixed" because the machine was
        scrapped falsifies remediation rate and MTTR -- and it flatters, so it is never investigated.
    #>
    param(
        [Parameter(Mandatory)] [string] $AssetState,
        [Parameter(Mandatory)] [bool]   $FindingStillPresent
    )
    if ($FindingStillPresent) { return $null }               # nothing closes
    switch ($AssetState) {
        'Active'         { 'Remediated'       }              # the only true security outcome
        'Decommissioned' { 'AssetRetired'     }              # NOT remediated
        'Excluded'       { 'NoLongerMonitored'}              # not a security outcome at all
        'Stale'          { 'AssetRetired'     }
        default          { $null }                            # Unknown / Missing / Unmanaged: do not close
    }
}

function Test-SIIntentStillValid {
    <#
        An intent is a PROPOSAL ABOUT A STATE, not a standing instruction.

        The failure this prevents, and it bites in the sympathetic case: a Close is raised Monday for a
        stale laptop; Wednesday the laptop returns; Thursday a human approves Monday's intent -- and the
        CI plus its vulnerabilities close for a machine that is demonstrably alive, with every other
        guard passing because the run was complete, the scope unchanged, and a human really did approve.
    #>
    param(
        [Parameter(Mandatory)] [string] $IntentDerivedFromState,
        [Parameter(Mandatory)] [string] $CurrentState,
        [int] $AgeMinutes = 0,
        [int] $ExpiryMinutes = 1440
    )
    if ($IntentDerivedFromState -ne $CurrentState) {
        return [pscustomobject]@{ Valid = $false; Reason = 'Superseded'
            Detail = ("state moved {0} -> {1} since the intent was raised" -f $IntentDerivedFromState, $CurrentState) }
    }
    if ($AgeMinutes -gt $ExpiryMinutes) {
        return [pscustomobject]@{ Valid = $false; Reason = 'Expired'
            Detail = ("intent is {0}m old (limit {1}m); re-derive from current facts" -f $AgeMinutes, $ExpiryMinutes) }
    }
    [pscustomobject]@{ Valid = $true; Reason = 'Ok'; Detail = '' }
}

function Get-SIMatchDecision {
    <#
        Confidence travels with the match, and the threshold is PER ACTION -- a match good enough to
        ENRICH is not necessarily good enough to CLOSE. Ambiguity is never a match: two candidates
        dead-letter for a human rather than silently picking the first, because picking arbitrarily is
        how the wrong ticket gets closed.
    #>
    param(
        [Parameter(Mandatory)] [int]    $CandidateCount,
        [Parameter(Mandatory)] [double] $Confidence,
        [Parameter(Mandatory)] [ValidateSet('Enrich','Close','CreateCi')] [string] $Action,
        [double] $MinEnrich = 0.60,
        [double] $MinClose  = 0.95,
        [double] $MinCreate = 0.99
    )
    if ($CandidateCount -eq 0) { return [pscustomobject]@{ Decision = 'NoMatch';    Reason = 'no candidate' } }
    if ($CandidateCount -gt 1) { return [pscustomobject]@{ Decision = 'DeadLetter'; Reason = ("ambiguous: {0} candidates" -f $CandidateCount) } }

    $need = switch ($Action) { 'Enrich' { $MinEnrich } 'Close' { $MinClose } 'CreateCi' { $MinCreate } }
    if ($Confidence -lt $need) {
        return [pscustomobject]@{ Decision = 'Propose'; Reason = ("confidence {0} below {1} threshold {2}" -f $Confidence, $Action, $need) }
    }
    [pscustomobject]@{ Decision = 'Apply'; Reason = '' }
}

function Test-SIRelationshipStable {
    <#
        Relationships flap: correlation is probabilistic, so a small change in evidence can add and drop
        an edge on alternating runs -- spamming the target's audit trail and potentially firing their
        downstream automation each time. Removal is deliberately MORE conservative than assertion.
    #>
    param(
        [Parameter(Mandatory)] [ValidateSet('Assert','Remove')] [string] $Change,
        [Parameter(Mandatory)] [int] $ConsecutiveRuns,
        [int] $ConfirmAssert = 2,
        [int] $ConfirmRemove = 3
    )
    $need = if ($Change -eq 'Assert') { $ConfirmAssert } else { $ConfirmRemove }
    [pscustomobject]@{
        Stable = ($ConsecutiveRuns -ge $need)
        Needed = $need
        Detail = ("{0} confirmed on {1}/{2} consecutive runs" -f $Change, $ConsecutiveRuns, $need)
    }
}

function Test-SIFieldMapOperationAllowed {
    <#
        The field map is customer-authored, so an expression language in it is REMOTE CODE EXECUTION in
        the engine. SI's audited baseline is explicitly "no Invoke-Expression on untrusted input".
        Only a closed set of declarative operations is permitted.
    #>
    param([Parameter(Mandatory)][AllowEmptyString()][string]$Operation)
    $allowed = @('concat','coalesce','trim','upper','lower','substring','split','take','default','values')
    [pscustomobject]@{
        Allowed = ($allowed -contains $Operation.ToLowerInvariant())
        Closed  = $allowed
    }
}

function Get-SIMappingResolution {
    <#
        RESOLVED-ZERO: a field mapping that resolved on a previous run and now resolves 0% is a FINDING,
        not a log line. An upstream rename empties the destination column while the run reports success
        -- #48 / #57 / #58.5 with a new cause.
    #>
    param(
        [Parameter(Mandatory)] [int] $Resolved,
        [Parameter(Mandatory)] [int] $Total,
        [Parameter(Mandatory)] [AllowNull()] [System.Nullable[double]] $BaselinePercent
    )
    $pct = if ($Total -gt 0) { [math]::Round(100.0 * $Resolved / $Total, 1) } else { 0.0 }
    $verdict = 'Ok'
    if ($Total -gt 0 -and $Resolved -eq 0 -and $null -ne $BaselinePercent -and $BaselinePercent -gt 0) {
        $verdict = 'RESOLVED-ZERO'
    } elseif ($Total -gt 0 -and $null -ne $BaselinePercent -and $BaselinePercent -gt 0 -and $pct -lt ($BaselinePercent * 0.2)) {
        # 🪤 The `$Total -gt 0` guard is load-bearing and was MISSING in the first cut: a run that
        #    returned zero rows scored 0% and tripped FILL-DROP, reporting a drained column on an empty
        #    result. "0 rows is NOT a pass" cuts both ways -- it is also not a failure.
        $verdict = 'FILL-DROP'
    }
    [pscustomobject]@{ Percent = $pct; Verdict = $verdict; Resolved = $Resolved; Total = $Total }
}
