#Requires -Version 5.1
<#
    Schedule stage.

    Engine-level scheduling is currently driven by the Container App Job
    cron (or KEDA producer). This stage's role:

      * Resolve the effective tier-cadence map (engine defaults +
        $global:SI_TierCadence_T0..TE customer overrides).
      * Stamp the resolved map onto $RunContext.TierCadence for Stage
        Collect to use when gating per-asset re-classification.
      * Emit the map to the run log for operator visibility.

    Tier-driven cadence -- the central design from . Each asset
    is re-classified at most once per cadence-window for its known tier:
      T0 = 12h     (DCs, breakglass, GA admins -- watch tightly)
      T1 = 24h     (production servers, privileged role holders)
      T2 = 3d      (workstations, regular users)
      T3 = 7d      (test/dev, service accounts, externals, guests, shadow --
                    the lowest-trust catch-all; dropped TE,
                    T3 absorbs that population)
    Customer can override any value via $global:SI_TierCadence_<tier>.
    Unknown / first-seen tier defaults to 24h (treats new assets as T1
    for re-classification cadence -- conservative).
#>

function Resolve-SITimespan {
    <#
        Parses cadence strings like '12h', '3d', '7d', '30d', '90m', '1h30m'
        into [TimeSpan]. Defensive -- returns 24h on any parse failure so
        the engine never silently runs on a bogus interval.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Spec)

    $s = $Spec.Trim().ToLowerInvariant()
    $totalSeconds = 0
    # Match each <number><unit> pair (h/d/m/s). Multiple pairs sum.
    $matched = $false
    foreach ($m in [regex]::Matches($s, '(\d+)\s*(h|d|m|s|w)')) {
        $matched = $true
        $n = [int]$m.Groups[1].Value
        switch ($m.Groups[2].Value) {
            'w' { $totalSeconds += $n * 7 * 86400 }
            'd' { $totalSeconds += $n * 86400 }
            'h' { $totalSeconds += $n * 3600 }
            'm' { $totalSeconds += $n * 60 }
            's' { $totalSeconds += $n }
        }
    }
    if (-not $matched) {
        Write-Warning ("Resolve-SITimespan: '{0}' did not parse -- defaulting to 24h" -f $Spec)
        return [timespan]::FromHours(24)
    }
    return [timespan]::FromSeconds($totalSeconds)
}

function Get-SIEffectiveCadenceMap {
    <#
        Builds the per-tier cadence map for this run:
          1. start with engine defaults
          2. customer override per tier via $global:SI_TierCadence_<tier>
          3. parse strings to TimeSpan
        Returns hashtable: { 'T0'=[timespan]; 'T1'=...; 'T2'=...; 'T3'=...; '_default'=... }
    #>
    [CmdletBinding()]
    param()

    $defaults = @{
        T0 = '12h'
        T1 = '24h'
        T2 = '3d'
        T3 = '7d'        # lowest-trust catch-all (test/dev/external/guest/shadow)
        _default = '24h' # used when cached tier is null/unknown
    }
    $resolved = @{}
    foreach ($tier in @('T0','T1','T2','T3','_default')) {
        $globalName = if ($tier -eq '_default') { 'SI_TierCadence_Default' } else { ('SI_TierCadence_{0}' -f $tier) }
        $override = (Get-Variable -Name $globalName -ValueOnly -Scope Global -ErrorAction SilentlyContinue)
        $spec = if (-not [string]::IsNullOrWhiteSpace($override)) { [string]$override } else { $defaults[$tier] }
        $resolved[$tier] = Resolve-SITimespan -Spec $spec
    }
    return $resolved
}

function Get-SITierCadence {
    <#
        Per-asset cadence lookup. Falls back to _default when cached tier
        is null / empty / not in the map (handles new tier names Microsoft
        might add or stale 'Unknown' entries from a prior schema).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][hashtable]$CadenceMap,
        [string]$Tier
    )
    if ([string]::IsNullOrWhiteSpace($Tier)) { return $CadenceMap['_default'] }
    if ($CadenceMap.ContainsKey($Tier))      { return $CadenceMap[$Tier] }
    return $CadenceMap['_default']
}

function Invoke-SISchedule {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][object]$RunContext
    )

    $cadenceMap = Get-SIEffectiveCadenceMap

    # Stamp on the RunContext so Stage Collect can read it without re-resolving.
    $RunContext | Add-Member -MemberType NoteProperty -Name TierCadence -Value $cadenceMap -Force

    # Format: '12h' for sub-day cadences, '72h (3d)' for multi-day so operators
    # don't have to mentally divide by 24 to read the run schedule.
    $cadenceText = ($cadenceMap.GetEnumerator() | Sort-Object Name | ForEach-Object {
        $h = [int]$_.Value.TotalHours
        $label = if ($h -gt 24) { '{0}h ({1}d)' -f $h, [int]($h / 24) } else { '{0}h' -f $h }
        '{0}={1}' -f $_.Key, $label
    }) -join ' '

    # auto-refresh CMDB cache when $global:SI_EnableCmdbProvider=$true.
    # Skip refresh when cache is fresher than $global:SI_CmdbRefreshIntervalHours
    # (default 24h) so we don't re-read the CSV every engine run. Failure is
    # non-fatal: Reconcile handles a stale / empty cache gracefully.
    $cmdbRefresh = $null

    # AUDIT #58.1 -- resolve WHICH CMDB source is active before doing anything with one.
    # Exactly one is ever active and sources are never merged (see shared/CmdbSource.ps1).
    $__siRootForCmdb = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSScriptRoot))
    . (Join-Path $__siRootForCmdb 'engine\asset-profiling\shared\CmdbSource.ps1')
    $__cmdbAvail = Get-SICmdbSourceAvailability -SolutionRoot $__siRootForCmdb `
                                                -EnableCmdbProvider   $global:SI_EnableCmdbProvider `
                                                -EnableServiceNowCmdb $global:SI_EnableServiceNowCmdb
    $__cmdbPick = Resolve-SICmdbSource -Available $__cmdbAvail

    # 🔴 #58.2 FAIL LOUD. A refused configuration stops the CMDB path outright. It must NOT quietly
    # fall through to a lower-precedence source: silent substitution hands the customer plausible but
    # stale data on a green run, and wrong-but-plausible is worse than empty because empty is visible.
    if ($__cmdbPick.Fatal) {
        Write-Error ("CMDB source resolution REFUSED: {0}" -f $__cmdbPick.Reason)
    }
    # Reason is already a full sentence beginning "CMDB source '<id>' selected ..." -- do not prefix it
    # again, or the log reads "CMDB source: CMDB source 'generic-csv' selected".
    Write-SIInfo ([string]$__cmdbPick.Reason)

    # Stamp on the RunContext so Reconcile stamps it onto every row (#58.3) without re-resolving --
    # and so the two stages can never disagree about which source answered.
    $RunContext | Add-Member -MemberType NoteProperty -Name CmdbSource -Value ([string]$__cmdbPick.Source) -Force

    if ($global:SI_EnableCmdbProvider -and $__cmdbPick.Source -eq 'generic-csv') {
        $intervalH = if ($global:SI_CmdbRefreshIntervalHours) { [int]$global:SI_CmdbRefreshIntervalHours } else { 24 }
        try {
            $siRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSScriptRoot))
            . (Join-Path $siRoot 'engine\asset-profiling\storage\CmdbCache.ps1')
            $age = Get-SICmdbCacheAge -Context $RunContext.StorageContext
            # ForceFullRun also forces CMDB refresh. Mirrors the
            # ForceFullRun semantics for the fingerprint cache --
            # one switch invalidates all caches consistently. Useful after a
            # partial-write left the cache in a known-bad state.
            $forceCmdb = ($RunContext.ForceFullRun -eq $true)
            $needsRefresh = ($forceCmdb -or $age.State -eq 'never' -or $age.HoursOld -ge $intervalH)
            if ($needsRefresh) {
                $reason = if ($forceCmdb) { '-ForceFullRun bypasses cache age' }
                          elseif ($age.State -eq 'never') { 'never synced' }
                          else { ('{0}h old >= {1}h interval' -f $age.HoursOld, $intervalH) }
                Write-SIInfo ("CMDB provider ENABLED -- refreshing cache ({0}) ..." -f $reason)
                # v2.2.421 -- provider renamed 'servicenow-cmdb' -> 'generic-cmdb' (it was never
                # ServiceNow-specific; it reads a CSV). Fall back to the old folder so a partially
                # updated install still finds the refresh script rather than skipping it.
                $refreshScript = Join-Path $siRoot 'asset-profiling-providers\generic-cmdb\Refresh-CmdbCache.ps1'
                if (-not (Test-Path $refreshScript)) {
                    $legacyRefresh = Join-Path $siRoot 'asset-profiling-providers\servicenow-cmdb\Refresh-CmdbCache.ps1'
                    if (Test-Path $legacyRefresh) { $refreshScript = $legacyRefresh }
                }
                if (Test-Path $refreshScript) {
                    # v2.2.422 (#58.5) -- THE OAUTH SKIP IS GONE. CmdbCache's write paths are now
                    # OAuth-aware (bearer token against Table REST), so there is nothing to skip.
                    #
                    # What this branch used to do, and why it mattered: it said the refresh was
                    # "silently a no-op" and that Reconcile "continues against the existing cached
                    # snapshot". On an OAuth tenant there IS no existing snapshot -- the cache was
                    # never written in the first place -- so cmdbName / cmdbCriticality /
                    # cmdbDataSensitivity were empty on EVERY run since v2.2.314. Measured
                    # 2026-08-11: 0 of 1,810 rows carried them, while cmdbId sat at 66%.
                    #
                    # Pass the KEY only in KeyAuth mode; under OAuth the refresh script builds its
                    # own OAuth context (Connect-AzAccount having already been done by the launcher).
                    $isOAuth = ($RunContext.StorageContext.Mode -eq 'OAuth') -or
                               [string]::IsNullOrWhiteSpace([string]$RunContext.StorageContext.AccountKey)
                    $cmdbRefresh = if ($isOAuth) {
                        & $refreshScript -StorageAccountName ([string]$RunContext.StorageContext.AccountName) -UseOAuth
                    } else {
                        & $refreshScript -StorageAccountName ([string]$RunContext.StorageContext.AccountName) -StorageKey ([string]$RunContext.StorageContext.AccountKey)
                    }
                    Write-SIInfo ("CMDB cache refreshed: {0} services written" -f $cmdbRefresh.ServicesWritten)
                } else {
                    # #58.2 -- the SELECTED source cannot answer. Say that, rather than naming a path.
                    Write-Warning ("CMDB source 'generic-csv' was selected but its refresh script is missing at {0}. cmdb* will be populated only from whatever the cache already holds, and NO other CMDB source will be substituted for it -- exactly one source is ever active." -f $refreshScript)
                }
            } else {
                Write-SIInfo ("CMDB provider ENABLED -- cache fresh ({0}h old, interval {1}h) -- skip refresh" -f $age.HoursOld, $intervalH)
            }
        } catch {
            $loc = if ($_.InvocationInfo -and $_.InvocationInfo.ScriptName) {
                '{0}:{1}' -f (Split-Path -Leaf $_.InvocationInfo.ScriptName), $_.InvocationInfo.ScriptLineNumber
            } else { 'unknown' }
            # #58.2 -- the old wording ("Reconcile will use existing cache (if any)") read as
            # reassurance. It is not: continuing against an unrefreshed cache means cmdb* may be
            # PLAUSIBLE BUT STALE, which is the failure mode this audit exists to stop -- empty is
            # visible, wrong is not. Say what the reader must actually decide about. No other source
            # is substituted; resolution picked exactly one before this ran.
            Write-Warning ("CMDB refresh FAILED for the selected source 'generic-csv' at {0} -- {1}. Reconcile continues against the cache AS IT ALREADY STANDS, so cmdb* values may be STALE rather than absent; check the cache-age line above before trusting them. No other CMDB source will be substituted." -f $loc, $_.Exception.Message)
        }
    }

    [pscustomobject]@{
        Stage       = 'Schedule'
        Ready       = $true
        Cadence     = $cadenceMap
        CmdbRefresh = $cmdbRefresh
        Summary     = ('ready -- cadence: {0}' -f $cadenceText)
    }
}
