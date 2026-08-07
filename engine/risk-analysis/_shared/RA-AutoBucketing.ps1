#######################################################################################################
#  SecurityInsight - Risk Analysis engine
#  Adaptive bucketing: overflow/transient detection, the bucket-count cache and the challenger.
#
#  Splitting a query that would exceed platform limits into N buckets, remembering the count that
#  worked, and periodically re-testing whether a smaller count would now do (the "challenger").
#
#  NOTE this span is not purely declarations - it also carries the
#  `$script:AutoBucketConfirmedKey = '__confirmed'` assignment that sits between two groups of
#  functions. That is safe here and only here: the span is CONTIGUOUS and is dot-sourced at exactly
#  the position it occupied, so the assignment still runs at the same point in the load sequence,
#  relative to the same neighbours.
#
#  AUDIT #16: moved VERBATIM out of Invoke-RiskAnalysis.ps1 on 2026-08-05. Dot-sourced back in at
#  exactly the position it occupied, so load order is unchanged. Every function body is
#  byte-identical to before the move - verified with tests/Get-EngineFunctionInventory.ps1,
#  which compares a SHA-256 of each function's source text before and after.
#
#  Do NOT add $PSScriptRoot-dependent code here: in this file it resolves to _shared/, one level
#  deeper than the engine root the main script derives $siRoot from.
#######################################################################################################

function Test-IsBucketOverflowError {
  # ONLY true-overflow signals -- the kind that bucketing actually solves.
  # 'A task was canceled' / 'timeout' / 'TaskCanceledException' are TRANSIENT
  # (re-auth needed, Defender Graph backend hiccup, throttle); escalating bucket
  # count amplifies them (more buckets = more API calls = more throttle). They
  # are now classified separately via Test-IsTransientPlatformError below, which
  # the outer bucket loop reacts to with re-auth + same-bucket retry instead.
  param(
    [Parameter(Mandatory=$true)]
    [object] $Err
  )

  $msg = ""

  if ($Err -is [System.Management.Automation.ErrorRecord]) {
    $detailMsg = ""
    try { if ($Err.ErrorDetails) { $detailMsg = [string]$Err.ErrorDetails.Message } } catch {}
    $msg = [string]($Err.Exception.Message + " " + $detailMsg)
  } else {
    $msg = [string]$Err
  }

  $m = $msg.ToLowerInvariant()

  # Signatures for "too many rows / result limit / response too large"
  # (deterministic overflow -- bucketing is the right answer)
  if (
    $m -match "too many" -or
    $m -match "result.*limit" -or
    $m -match "response.*too large" -or
    $m -match "payload.*too large" -or
    $m -match "request entity too large" -or
    $m -match "exceeded the allowed result size" -or
    $m -match "exceeded the allowed limits" -or
    ($m -match "rows" -and $m -match "limit")
  ) { return $true }

  return $false
}

function Test-IsDeterministicTooLargeError {
  <#
    AUDIT #24 -- "this query cannot finish in the budget", as distinct from "the
    platform hiccuped".

    THE BUG THIS FIXES. The run path and the probe path classified the SAME failure
    differently, so the probe could never learn a higher bucket count for exactly the
    reports that need one:

      run   (Invoke-RiskAnalysis.ps1:1235) $isDeterministicTooLarge = TaskCanceled OR 502
            -> rethrows on purpose, and its own comment says it does so "so the AutoBucket
               escalation in the outer loop can re-run with a higher bucket count"
      probe (Get-OptimalBucketCount)       used Test-IsBucketOverflowError ALONE, which
            deliberately excludes TaskCanceled -> threw -> "AutoBucket failed ... Falling
            back to configured BucketCount=2"

    Measured consequence: a complete RiskAnalysis_Summary run cascaded through TEN 900s
    timeouts, finished successfully, and left all 59 cache entries equal to 2 -- it had
    learned nothing and would re-pay every timeout the next night. RA-Summary 6h23.

    WHY THIS IS NOT JUST "escalate on transients". Test-IsBucketOverflowError excludes
    timeouts for a documented reason: escalating on a genuine transient amplifies it
    (more buckets = more API calls = more throttle). That reasoning holds for 429 /
    re-auth / service-unavailable, and this function still refuses those. It returns true
    only for the two signals the run path already treats as "too big":
      * TaskCanceled -- the HttpClient 900s ceiling; the query did not fit in the budget
      * 502 from the nginx in front of runHuntingQuery -- upstream response too large
    Throttle and auth signals win over both, so a 429 that happens to mention a timeout is
    still classified transient.
  #>
  param([Parameter(Mandatory=$true)][object]$Err)

  $msg = ""
  if ($Err -is [System.Management.Automation.ErrorRecord]) {
    $detailMsg = ""
    try { if ($Err.ErrorDetails) { $detailMsg = [string]$Err.ErrorDetails.Message } } catch {}
    $msg = [string]($Err.Exception.Message + " " + $detailMsg)
  } else {
    $msg = [string]$Err
  }
  $m = $msg.ToLowerInvariant()

  # Throttle / auth FIRST -- these are the cases the exclusion was written to protect,
  # and escalating on them makes things worse. They win even if a timeout is mentioned.
  if (
    $m -match "too many requests" -or
    $m -match "\b429\b" -or
    $m -match "throttl" -or
    $m -match "\b503\b" -or
    $m -match "service unavailable" -or
    $m -match "invalidauthenticationtoken" -or
    $m -match "access token" -or
    $m -match "\b401\b" -or
    $m -match "unauthorized"
  ) { return $false }

  # The two "query is too big" signals, matching Invoke-RiskAnalysis.ps1:1227/1234.
  if ($Err -is [System.Management.Automation.ErrorRecord] -and
      $Err.Exception -is [System.Threading.Tasks.TaskCanceledException]) { return $true }
  if (
    $m -match "a task was canceled" -or
    $m -match "taskcanceledexception" -or
    $m -match "502 bad gateway" -or
    $m -match "\[unknownerror\][^<]*<html>"
  ) { return $true }

  return $false
}

function Test-IsTransientPlatformError {
  # Re-auth needed / Defender Graph backend hiccup / throttle. NOT row-overflow.
  # Right response is reconnect + same-bucket retry, NOT bucket escalation.
  param([Parameter(Mandatory=$true)][object]$Err)

  $msg = ""
  if ($Err -is [System.Management.Automation.ErrorRecord]) {
    $detailMsg = ""
    try { if ($Err.ErrorDetails) { $detailMsg = [string]$Err.ErrorDetails.Message } } catch {}
    $msg = [string]($Err.Exception.Message + " " + $detailMsg)
  } else {
    $msg = [string]$Err
  }
  $m = $msg.ToLowerInvariant()

  if ($Err -is [System.Management.Automation.ErrorRecord] -and
      $Err.Exception -is [System.Threading.Tasks.TaskCanceledException]) { return $true }

  if (
    $m -match "a task was canceled" -or
    $m -match "taskcanceledexception" -or
    $m -match "timed out" -or
    $m -match "timeout" -or
    $m -match "too many requests" -or
    $m -match "\b429\b" -or
    $m -match "throttl" -or
    $m -match "\b503\b" -or
    $m -match "\b502\b" -or
    $m -match "\b504\b" -or
    $m -match "service unavailable" -or
    $m -match "bad gateway" -or
    $m -match "gateway timeout" -or
    $m -match "invalidauthenticationtoken" -or
    $m -match "access token" -or
    $m -match "\b401\b" -or
    $m -match "unauthorized" -or
    $m -match "forbidden temporarily"
  ) { return $true }

  return $false
}

function Get-AutoBucketCachePath {
  param([Parameter(Mandatory=$true)][string]$SettingsPath)
  Join-Path $SettingsPath "OUTPUT\AutoBucketCache.json"
}

function ConvertTo-HashtableDeep {
  param([Parameter(Mandatory=$true)]$InputObject)

  if ($null -eq $InputObject) { return $null }

  # Hashtable / IDictionary
  if ($InputObject -is [System.Collections.IDictionary]) {
    $out = @{}
    foreach ($k in $InputObject.Keys) {
      $out[[string]$k] = ConvertTo-HashtableDeep -InputObject $InputObject[$k]
    }
    return $out
  }

  # PSCustomObject
  if ($InputObject -is [pscustomobject]) {
    $out = @{}
    foreach ($p in $InputObject.PSObject.Properties) {
      $out[[string]$p.Name] = ConvertTo-HashtableDeep -InputObject $p.Value
    }
    return $out
  }

  # IEnumerable (but not string)
  if (($InputObject -is [System.Collections.IEnumerable]) -and -not ($InputObject -is [string])) {
    $list = @()
    foreach ($i in $InputObject) {
      $list += ,(ConvertTo-HashtableDeep -InputObject $i)
    }
    return $list
  }

  return $InputObject
}

function Read-AutoBucketCache {
  param([Parameter(Mandatory=$true)][string]$Path)

  if (-not (Test-Path -LiteralPath $Path)) { return @{} }

  try {
    $raw = Get-Content -LiteralPath $Path -Raw -ErrorAction Stop
    if ([string]::IsNullOrWhiteSpace($raw)) { return @{} }

    $obj = ($raw | ConvertFrom-Json -ErrorAction Stop)
    if ($null -eq $obj) { return @{} }

    $ht = ConvertTo-HashtableDeep -InputObject $obj
    if ($null -eq $ht) { return @{} }

    # Support both flat and wrapped cache formats
    foreach ($wrapper in @('Entries','Cache','Data','AutoBucket')) {
      if (($ht -is [hashtable]) -and $ht.ContainsKey($wrapper) -and ($ht[$wrapper] -is [hashtable])) {
        return $ht[$wrapper]
      }
    }

    if ($ht -is [hashtable]) { return $ht }

    # If the root isn't a hashtable, treat it as empty (unexpected format)
    return @{}
  } catch {
    return @{}
  }
}

function Get-AutoBucketCacheFallbackValue {
  param(
    [Parameter(Mandatory=$true)][hashtable]$Cache,
    [Parameter(Mandatory=$true)][string]$QueryKey,
    [Parameter(Mandatory=$true)][int]$MaxBucketCount
  )

  # PowerShell 5.1 compatibility + cache format migration:
  # - New cache key format is: <ReportName>|<QueryHash>
  # - Older cache files may still contain keys like: <ReportName>|<QueryHash>|cap<Max>
  #
  # If the exact key is missing, try to reuse any legacy cap-key for the same base key.
  $base = [string]$QueryKey
  if ([string]::IsNullOrWhiteSpace($base)) { return $null }

  $legacyPrefix = ($base + '|cap')
  $candidates = New-Object System.Collections.Generic.List[int]

  foreach ($k in $Cache.Keys) {
    $ks = [string]$k
    if ($ks -eq $base -or $ks -like ($legacyPrefix + '*')) {
      $v = $Cache[$k]
      $vi = 0
      if ([int]::TryParse([string]$v, [ref]$vi)) {
        if ($vi -ge 1) { $candidates.Add($vi) }
      }
    }
  }

  if ($candidates.Count -eq 0) { return $null }

  # Use the largest cached "working" bucket count to avoid re-probing.
  $best = ($candidates | Measure-Object -Maximum).Maximum
  $best = [int]$best
  if ($best -lt 1) { return $null }
  if ($best -gt $MaxBucketCount) { $best = $MaxBucketCount }
  return $best
}

function Get-StableQueryHash32 {
  param(
    [Parameter(Mandatory=$true)][string]$Text
  )

  # NOTE: .NET string.GetHashCode() is not stable across processes.
  # We use SHA256 and take the first 4 bytes as an unsigned 32-bit integer.
  $norm = ($Text -replace '\s+', ' ').Trim()
  $bytes = [System.Text.Encoding]::UTF8.GetBytes($norm)
  $sha = [System.Security.Cryptography.SHA256]::Create()
  try {
    $hashBytes = $sha.ComputeHash($bytes)
  } finally {
    if ($sha -and ($sha -is [System.IDisposable])) { $sha.Dispose() }
  }

  return [System.BitConverter]::ToUInt32($hashBytes, 0)
}

function Write-AutoBucketCache {
  param(
    [Parameter(Mandatory=$true)][string]$Path,
    [Parameter(Mandatory=$true)][object]$CacheObject
  )

  $dir = Split-Path -Parent $Path
  if (-not (Test-Path -LiteralPath $dir)) {
    New-Item -Path $dir -ItemType Directory -Force | Out-Null
  }

  $CacheObject | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $Path -Encoding UTF8
}

function Get-CacheValue {
  param([Parameter(Mandatory=$true)][object]$Cache,[Parameter(Mandatory=$true)][string]$Key)

  if ($Cache -is [hashtable]) {
    if ($Cache.ContainsKey($Key)) { return $Cache[$Key] }
    return $null
  }

  try {
    $p = $Cache.PSObject.Properties[$Key]
    if ($p) { return $p.Value }
  } catch {}

  return $null
}

function Set-CacheValue {
  param([Parameter(Mandatory=$true)][ref]$Cache,[Parameter(Mandatory=$true)][string]$Key,[Parameter(Mandatory=$true)][int]$Value)

  if ($Cache.Value -is [hashtable]) {
    $Cache.Value[$Key] = $Value
    return
  }

  try {
    $Cache.Value | Add-Member -NotePropertyName $Key -NotePropertyValue $Value -Force
  } catch {
    $ht = @{}
    foreach ($prop in $Cache.Value.PSObject.Properties) { $ht[$prop.Name] = $prop.Value }
    $ht[$Key] = $Value
    $Cache.Value = $ht
  }
}

# v2.2.383 -- reserved sidecar key under which confirmedAt timestamps for the
# AutoBucket challenger live. Real cache keys are of the form
# '<ReportName>|<QueryHash>' so the '__confirmed' prefix cannot collide.
$script:AutoBucketConfirmedKey = '__confirmed'

function Get-AutoBucketReportName {
  # The cache key shape is '<ReportName>|<QueryHash>' (Get-StableQueryHash32
  # produces a UInt32). Returns '' for malformed keys + for the reserved
  # '__confirmed' sidecar.
  param([Parameter(Mandatory=$true)][string]$QueryKey)
  if ([string]::IsNullOrWhiteSpace($QueryKey)) { return '' }
  if ($QueryKey.StartsWith('__')) { return '' }
  $i = $QueryKey.LastIndexOf('|')
  if ($i -lt 1) { return '' }
  return $QueryKey.Substring(0, $i)
}

function Remove-AutoBucketStaleSiblings {
  <#
    v2.2.383 Layer 1 -- stale-hash auto-eviction. When the engine touches
    cache key '<R>|<currentHash>', any other entries matching prefix '<R>|'
    are leftover query-content drift from earlier YAML revisions and can
    never be re-validated against current code. Evict them so the median
    used by the challenger (Layer 2) reflects only live entries.

    Mutates $Cache.Value in-place. Returns the number of siblings evicted
    so the caller can decide whether to persist the cleaned cache.
  #>
  param(
    [Parameter(Mandatory=$true)][ref]$Cache,
    [Parameter(Mandatory=$true)][string]$QueryKey
  )
  if ($Cache.Value -isnot [hashtable]) { return 0 }
  $reportName = Get-AutoBucketReportName -QueryKey $QueryKey
  if ([string]::IsNullOrWhiteSpace($reportName)) { return 0 }
  $prefix = ($reportName + '|')
  $toEvict = New-Object System.Collections.Generic.List[string]
  foreach ($k in $Cache.Value.Keys) {
    $ks = [string]$k
    if ($ks -eq $QueryKey) { continue }                    # keep the live one
    if ($ks -eq $script:AutoBucketConfirmedKey) { continue } # keep the sidecar
    if ($ks.StartsWith($prefix)) { [void]$toEvict.Add($ks) }
  }
  foreach ($k in $toEvict) {
    [void]$Cache.Value.Remove($k)
    # Also drop any matching confirmedAt sidecar entry.
    if ($Cache.Value.ContainsKey($script:AutoBucketConfirmedKey) -and
        $Cache.Value[$script:AutoBucketConfirmedKey] -is [hashtable] -and
        $Cache.Value[$script:AutoBucketConfirmedKey].ContainsKey($k)) {
      [void]$Cache.Value[$script:AutoBucketConfirmedKey].Remove($k)
    }
  }
  return $toEvict.Count
}

function Test-AutoBucketChallenger {
  <#
    v2.2.383 Layer 2+3 -- median-challenger with confirmation TTL. Returns
    $true if the cached value is statistically suspect (>= 10x median of
    other live entries) AND was not recently confirmed by a challenger
    re-probe. Returns $false to trust the cached value as-is.

    Math: median is computed over OTHER live entries (excluding $QueryKey
    itself so an outlier doesn't pull up its own comparison set, and
    excluding the '__confirmed' sidecar). If the cache has fewer than
    MinEntries live values, return $false -- sample too small to flag.

    TTL: if a confirmedAt timestamp exists for $QueryKey within the last
    ConfirmDays days, return $false -- the value was re-probed recently
    enough that we don't want to burn another probe.

    Multiplier + MinEntries + ConfirmDays come from $global:* knobs with
    safe defaults (10x, 10 entries, 7 days) so operators can dial without
    touching code.
  #>
  param(
    [Parameter(Mandatory=$true)][object]$Cache,
    [Parameter(Mandatory=$true)][string]$QueryKey,
    [Parameter(Mandatory=$true)][int]$CachedValue
  )
  if ($Cache -isnot [hashtable]) { return $false }

  $multiplier = if ($global:AutoBucketChallenger_MedianMultiplier) { [int]$global:AutoBucketChallenger_MedianMultiplier } else { 10 }
  $minEntries = if ($global:AutoBucketChallenger_MinEntries)        { [int]$global:AutoBucketChallenger_MinEntries }        else { 10 }
  $confirmDays = if ($global:AutoBucketChallenger_ConfirmDays)      { [int]$global:AutoBucketChallenger_ConfirmDays }       else { 7 }
  if ($multiplier -lt 2) { $multiplier = 2 }
  if ($minEntries -lt 2) { $minEntries = 2 }

  # Confirmation TTL short-circuit.
  if ($Cache.ContainsKey($script:AutoBucketConfirmedKey) -and
      $Cache[$script:AutoBucketConfirmedKey] -is [hashtable] -and
      $Cache[$script:AutoBucketConfirmedKey].ContainsKey($QueryKey)) {
    $stampRaw = [string]$Cache[$script:AutoBucketConfirmedKey][$QueryKey]
    $stamp = [datetime]::MinValue
    if ([datetime]::TryParse($stampRaw, [ref]$stamp)) {
      $ageDays = ([datetime]::UtcNow - $stamp.ToUniversalTime()).TotalDays
      if ($ageDays -le $confirmDays) { return $false }
    }
  }

  # Median across OTHER live entries.
  $others = New-Object System.Collections.Generic.List[int]
  foreach ($k in $Cache.Keys) {
    $ks = [string]$k
    if ($ks -eq $QueryKey) { continue }
    if ($ks -eq $script:AutoBucketConfirmedKey) { continue }
    $v = $Cache[$k]
    $vi = 0
    if ([int]::TryParse([string]$v, [ref]$vi)) {
      if ($vi -ge 1) { [void]$others.Add($vi) }
    }
  }
  if ($others.Count -lt ($minEntries - 1)) { return $false }
  $sorted = $others.ToArray() | Sort-Object
  $n = $sorted.Length
  $median = if ($n % 2 -eq 1) { [int]$sorted[[int]($n / 2)] } else { [int](($sorted[$n / 2 - 1] + $sorted[$n / 2]) / 2) }
  if ($median -lt 1) { $median = 1 }
  return ($CachedValue -gt ($multiplier * $median))
}

function Set-AutoBucketConfirmed {
  # v2.2.383 Layer 3 -- stamp confirmedAt sidecar so future runs skip the
  # challenger probe for ConfirmDays days. Called after a challenger re-probe
  # converges on a value (whether or not that value changed -- a confirmed
  # 'still 229' is just as valuable as a corrected 'now 32').
  param(
    [Parameter(Mandatory=$true)][ref]$Cache,
    [Parameter(Mandatory=$true)][string]$QueryKey
  )
  if ($Cache.Value -isnot [hashtable]) { return }
  if (-not $Cache.Value.ContainsKey($script:AutoBucketConfirmedKey) -or
      $Cache.Value[$script:AutoBucketConfirmedKey] -isnot [hashtable]) {
    $Cache.Value[$script:AutoBucketConfirmedKey] = @{}
  }
  $Cache.Value[$script:AutoBucketConfirmedKey][$QueryKey] = ([datetime]::UtcNow.ToString('o'))
}

function Get-OptimalBucketCount {
  <#
    AUDIT #24 FUTILITY GUARD -- why the escalation needs a stop condition.

    Giving the probe the run path's "a 900s timeout means too big" rule (see
    Test-IsDeterministicTooLargeError) was correct but incomplete: the ramp had nothing
    telling it when splitting CANNOT help. Live proof on
    Attack_Paths_Summary_Identity_Group_Membership_to_Privileged_Resources:

      bucketCount = 2 -> 4 -> 8 -> ... -> 65536   (16 rungs, 13 x 900s, 242 minutes,
                                                   never converged, heading for a throw)

    The RUN path already has this stop condition -- that is exactly what FUTILE-PRUNE
    detects ("all children timed out => splitting deeper won't help"). The PROBE had no
    equivalent, so it ramped to the cap.

    THE AUDIT'S ROOT CAUSE FOR THAT RUNAWAY WAS WRONG -- corrected from the live log
    2026-08-06. #24 recorded the report as "EG-suppressed", i.e. that
    $script:_SkipEGBucketForCrossDomain was set and every sub-query therefore still did the
    full Exposure-Graph work. An EG-suppression test alone would never have fired for it,
    because the run log says the opposite in as many words:

      [crossdomain] report '...Identity_Group_Membership_to_Privileged_Resources' declares
      EG-aligned CL bucket key(s): Target_AzureResourceId_Guid -- EG-side bucket filter
      stays ACTIVE (bounded EG work).

    It is one of the v2.2.404 crossDomainBucketCoalesce reports, so that flag is FALSE for
    it. What the same log DOES show is the real discriminator: across the 16 rungs the
    inlined CL payload fell 25,996 -> 13,250 -> 6,937 -> 3,755 -> 2,156 -> 868 bytes while
    EVERY rung still died at exactly 900s. The body was never the constraint -- by rung 1 it
    was already ~2.5% of the 1MB nginx cap.

    Hence the general rule this guard uses, of which EG suppression is one special case:
      * PAYLOAD-BOUND -- inline body large (near the cap). Splitting is exactly the right
        answer; keep escalating. This is what CL bucketing was built for.
      * EG-BOUND -- inline body already a small fraction of the cap and STILL hitting the
        query-time ceiling. The cost is Exposure-Graph work that the bucket filter is not
        reducing, and halving an 868-byte payload again cannot change that. Stop.
    A report that genuinely needs a high count stays payload-bound at every rung until it
    fits, so this cannot cut off legitimate escalation. Where no inline payload exists at
    all (the 2-phase path) the signal is 0 and the guard deliberately stays out of the way.

    WHERE THE CHECK HAD TO GO, and why the audit's own prescription would not have worked.
    The audit said to "skip probing entirely for EG-suppressed reports -- the engine knows
    which they are at that point". It does NOT. The flag is $false when this function is
    called: Invoke-RiskAnalysis.ps1:2296 resets it at the top of every report and it is only
    set by Resolve-ProfileCLLetBlocks *during* the first probe (that file's own comment at
    :2293 says so). Resolve-ProfileCLLetBlocks runs inside Invoke-GraphHuntingQuery BEFORE
    the query is submitted (RA-GraphHunting.ps1:154), so the flag is reliably set once the
    first rung has failed -- which makes BETWEEN RUNGS the earliest point the information
    exists. Cost of the guard is therefore exactly ONE ceiling timeout, which is what this
    report class paid before the #24 fix, minus the misleading "AutoBucket failed" warning.

    CEILING ONLY, NOT OVERFLOW -- the distinction that keeps this guard safe. A rows/payload
    overflow (Test-IsBucketOverflowError: 413, "too many rows", result-limit) IS fixed by
    bucketing even when the EG filter is suppressed, because the CL inline payload still
    shrinks ~1/N per bucket. Only the 900s CEILING class (Test-IsDeterministicTooLargeError)
    is futile under EG suppression. So the futility stop fires on a ceiling failure and
    never on an overflow failure.

    NO CACHE WRITE ON A FUTILE STOP. Returning the floor deliberately skips the cache write
    and the confirmedAt stamp at the bottom of this function. Stamping would suppress the
    challenger for ConfirmDays, and the value would survive a later YAML
    crossDomainBucketCoalesce declaration that makes the report splittable again -- the
    query is hashed BEFORE bucket-filter injection (Invoke-RiskAnalysis.ps1:2481), so that
    declaration does not change the cache key and Layer 1 stale-hash eviction would not
    clear it. Not caching reproduces the known-good pre-#24 behaviour exactly.

    THE RAMP CAP IS A BACKSTOP, NOT THE FIX. It bounds an unknown report class that cannot
    converge for some other reason. Default 10 doublings is chosen to stay above the real
    learned values this cache has historically held (62, 125, 127, 232, 248, 256, 496 --
    496 is 8 doublings from a floor of 2), so it cannot suppress the learning #24 exists to
    restore. Override with $global:AutoBucketMaxRampDoublings.
  #>
  param(
    [Parameter(Mandatory=$true)][string]$QueryKey,
    [Parameter(Mandatory=$false)][string[]]$LegacyKeys,
    [Parameter(Mandatory=$true)][int]$MaxBucketCount,
    [Parameter(Mandatory=$true)][scriptblock]$ProbeScript,
    [Parameter(Mandatory=$false)][int]$MinBucketCount = 1,
    # Returns $true when splitting cannot distribute this report's work. Evaluated only
    # AFTER a ceiling failure, because that is the first moment the caller can know.
    [Parameter(Mandatory=$false)][scriptblock]$FutilityCheck,
    # 0 = use $global:AutoBucketMaxRampDoublings, else the built-in default of 10.
    [Parameter(Mandatory=$false)][int]$MaxRampDoublings = 0
  )

  if ($MaxBucketCount -lt 1) { return 1 }
  if ($MinBucketCount -lt 1) { $MinBucketCount = 1 }
  if ($MinBucketCount -gt $MaxBucketCount) { $MinBucketCount = $MaxBucketCount }

  # Memo. Honour only if >= floor; otherwise re-probe (user raised the floor
  # via YAML BucketCount, so a smaller cached value is stale).
  if ($script:AutoBucketMemo.ContainsKey($QueryKey)) {
    $memoVal = [int]$script:AutoBucketMemo[$QueryKey]
    if ($memoVal -ge $MinBucketCount) { return $memoVal }
  }
  if ($LegacyKeys) {
    foreach ($lk in $LegacyKeys) {
      if (-not [string]::IsNullOrWhiteSpace($lk) -and $script:AutoBucketMemo.ContainsKey($lk)) {
        $val = [int]$script:AutoBucketMemo[$lk]
        if ($val -ge $MinBucketCount) {
          $script:AutoBucketMemo[$QueryKey] = $val
          return $val
        }
      }
    }
  }

  # Cache on disk (optional)
  $cachePath = $null
  $cache = $null
  $script:_AutoBucketWasChallenged = $false   # v2.2.383 -- set true when Layer 2 fires
  if ([bool]$global:AutoBucketCache -and -not [string]::IsNullOrWhiteSpace([string]$global:SettingsPath)) {
    $cachePath = Get-AutoBucketCachePath -SettingsPath $global:SettingsPath
    $cache = Read-AutoBucketCache -Path $cachePath

    # v2.2.383 Layer 1 -- evict stale-hash siblings (other entries with the
    # same '<ReportName>|' prefix but different hash) so the median used by
    # Layer 2 reflects only current-hash entries. Persist back if any moved.
    $_cacheRefL1 = [ref]$cache
    $_evicted = Remove-AutoBucketStaleSiblings -Cache $_cacheRefL1 -QueryKey $QueryKey
    $cache = $_cacheRefL1.Value
    if ($_evicted -gt 0) {
      Write-Info ("AutoBucket cache: evicted {0} stale-hash sibling(s) for '{1}'" -f $_evicted, (Get-AutoBucketReportName -QueryKey $QueryKey))
      try { Write-AutoBucketCache -Path $cachePath -CacheObject $cache } catch {}
    }

    # Read-AutoBucketCache returns a hashtable, but keep the older getter for safety
    $cached = Get-CacheValue -Cache $cache -Key $QueryKey
    if ($null -ne $cached) {
      $ci = [int]$cached
      if ($ci -ge $MinBucketCount -and $ci -le $MaxBucketCount) {
        # v2.2.383 Layer 2+3 -- if the cached value is way above the median
        # of all other live entries AND no recent confirmation stamp exists,
        # the value is statistically suspect (likely poison from an unrelated
        # larger workload). Fall through to the probe path; the probe write
        # at the bottom of this function will stamp confirmedAt either way.
        if (Test-AutoBucketChallenger -Cache $cache -QueryKey $QueryKey -CachedValue $ci) {
          Write-Info ("AutoBucket challenger: '{0}' cached={1} flagged as suspect (>10x median of other live entries) -- re-probing." -f $QueryKey, $ci)
          $script:_AutoBucketWasChallenged = $true
        } else {
          Write-Info ("AutoBucket cache hit: '{0}' => {1}" -f $QueryKey, $ci)
          $script:AutoBucketMemo[$QueryKey] = $ci
          return $ci
        }
      } elseif ($ci -lt $MinBucketCount) {
        Write-Info ("AutoBucket cache hit '{0}' => {1} ignored (below YAML floor {2}; re-probing from floor)" -f $QueryKey, $ci, $MinBucketCount)
      }
    }

    # Try legacy keys (e.g., old unstable GetHashCode-based identity)
    if ($LegacyKeys) {
      foreach ($lk in $LegacyKeys) {
        if ([string]::IsNullOrWhiteSpace($lk)) { continue }
        $cached2 = Get-CacheValue -Cache $cache -Key $lk
        if ($null -ne $cached2) {
          $ci2 = [int]$cached2
          if ($ci2 -ge $MinBucketCount -and $ci2 -le $MaxBucketCount) {
            Write-Info ("AutoBucket cache hit (legacy): '{0}' => {1}" -f $lk, $ci2)
            # Migrate in-memory to new key
            $script:AutoBucketMemo[$QueryKey] = $ci2
            # Persist migration best-effort
            if ($cachePath) {
              $cacheRef = [ref]$cache
              Set-CacheValue -Cache $cacheRef -Key $QueryKey -Value $ci2
              $cache = $cacheRef.Value
              try { Write-AutoBucketCache -Path $cachePath -CacheObject $cache } catch {}
            }
            return $ci2
          }
        }
      }
    }

    # Fallback for old cache formats (cap in key) and other key mismatches
    if ($cache -is [hashtable]) {
      $fallback = Get-AutoBucketCacheFallbackValue -Cache $cache -QueryKey $QueryKey -MaxBucketCount $MaxBucketCount
      if ($null -ne $fallback -and [int]$fallback -ge $MinBucketCount) {
        Write-Info ("AutoBucket cache fallback: '{0}' => {1}" -f $QueryKey, $fallback)
        $script:AutoBucketMemo[$QueryKey] = [int]$fallback
        return [int]$fallback
      }
    }
  }

  # Exponential probe: starts at MinBucketCount (configured YAML floor), then
  # doubles. Probing below the YAML-declared floor wastes one ~900s attempt
  # per ramp-up step and confuses operators ("why is it starting at 1 when I
  # said 64?"). The probe still ESCALATES (doubles) past the floor when the
  # configured count itself overflows.
  $try = $MinBucketCount
  $lastFail = $MinBucketCount - 1
  if ($lastFail -lt 0) { $lastFail = 0 }
  $firstOk = 0

  # AUDIT #24 backstop -- see the block comment on this function.
  $rampCap = if ($MaxRampDoublings -gt 0) { $MaxRampDoublings }
             elseif ($global:AutoBucketMaxRampDoublings) { [int]$global:AutoBucketMaxRampDoublings }
             else { 10 }
  if ($rampCap -lt 1) { $rampCap = 1 }
  $doublings = 0

  while ($try -le $MaxBucketCount) {
    try {
      Write-Info ("AutoBucket probing '{0}' with bucketCount={1}" -f $QueryKey, $try)
      & $ProbeScript -BucketCount $try | Out-Null
      $firstOk = $try
      break
    } catch {
      # AUDIT #24: a 900s ceiling timeout / 502-too-large means ESCALATE, exactly as the
      # run path already concludes. Before this, only Test-IsBucketOverflowError counted,
      # so the ramp aborted on the very failure bucketing exists to solve and fell back to
      # the configured count -- which is why every cache entry ended up at the floor.
      $isOverflow = [bool](Test-IsBucketOverflowError $_)
      $isCeiling  = [bool](Test-IsDeterministicTooLargeError $_)
      if (-not ($isOverflow -or $isCeiling)) { throw }

      # AUDIT #24 futility guard. A CEILING failure under EG suppression can never be
      # solved by splitting -- every sub-query still does the full Exposure-Graph work.
      # An OVERFLOW failure still shrinks with bucketing (the CL inline payload is ~1/N
      # per bucket), so it must keep escalating even for the same report.
      if ($isCeiling -and -not $isOverflow -and $FutilityCheck) {
        # The check may return a STRING describing why it is futile, or a plain $true.
        # A string is preferred: this message is the only record of WHY a report stopped
        # early, and a hardcoded explanation is how #24 came to carry a wrong root cause in
        # the first place. ([bool] on a non-empty string is $true, so plain $true still works.)
        $verdict  = $null
        $isFutile = $false
        try { $verdict = & $FutilityCheck; $isFutile = [bool]$verdict } catch { $isFutile = $false }
        if ($isFutile) {
          $reason = if ($verdict -is [string] -and -not [string]::IsNullOrWhiteSpace($verdict)) { [string]$verdict }
                    else { 'splitting cannot distribute this report''s work' }
          Write-Warn2 ("AutoBucket FUTILE-STOP: '{0}' hit the query-time ceiling at bucketCount={1} and {2} -- no bucket count will succeed. Using the configured count {3} instead of escalating toward MaxBucketCount={4}. Not cached, so this is re-evaluated next run." -f $QueryKey, $try, $reason, $MinBucketCount, $MaxBucketCount)
          return $MinBucketCount
        }
      }

      $doublings++
      if ($doublings -gt $rampCap) {
        Write-Warn2 ("AutoBucket RAMP-CAP: '{0}' still failing at bucketCount={1} after {2} doubling(s) from the configured count {3}. Stopping rather than ramping on toward MaxBucketCount={4}; splitting does not appear to be reducing this query's work. Using {3}. Not cached, so this is re-evaluated next run. Raise `$global:AutoBucketMaxRampDoublings if a report legitimately needs a higher count." -f $QueryKey, $try, $rampCap, $MinBucketCount, $MaxBucketCount)
        return $MinBucketCount
      }
      $lastFail = $try
      $try = $try * 2
    }
  }

  if ($firstOk -eq 0) {
    throw ("AutoBucket: query '{0}' did not succeed up to MaxBucketCount={1}" -f $QueryKey, $MaxBucketCount)
  }

  # Binary search: (lastFail, firstOk]
  $low = [Math]::Max($lastFail + 1, 1)
  $high = $firstOk

  while ($low -lt $high) {
    $mid = [int][Math]::Floor(($low + $high) / 2)
    try {
      Write-Info ("AutoBucket binary probe '{0}' with bucketCount={1}" -f $QueryKey, $mid)
      & $ProbeScript -BucketCount $mid | Out-Null
      $high = $mid
    } catch {
      # AUDIT #24: same classification as the ramp above -- a ceiling timeout at $mid means
      # $mid is too low, not that the probe should abort.
      if (-not ((Test-IsBucketOverflowError $_) -or (Test-IsDeterministicTooLargeError $_))) { throw }
      $low = $mid + 1
    }
  }

  $optimal = $low
  Write-Info ("AutoBucket chosen for '{0}': {1}" -f $QueryKey, $optimal)

  $script:AutoBucketMemo[$QueryKey] = $optimal

  if ($cachePath) {
    $cacheRef = [ref]$cache
    Set-CacheValue -Cache $cacheRef -Key $QueryKey -Value $optimal
    # v2.2.383 Layer 3 -- always stamp confirmedAt after a probe converges
    # (whether or not Layer 2 fired). A 'still 229' confirmation buys the
    # entry ConfirmDays of skipped challenger probes; a 'corrected from
    # 229 to 32' write also gets stamped so the new value isn't itself
    # re-challenged before it has a chance to prove itself.
    Set-AutoBucketConfirmed -Cache $cacheRef -QueryKey $QueryKey
    $cache = $cacheRef.Value
    try { Write-AutoBucketCache -Path $cachePath -CacheObject $cache } catch {}
    if ($script:_AutoBucketWasChallenged) {
      $_outcome = if ($optimal -eq [int]$cached) { 'confirmed' } else { 'corrected' }
      Write-Info ("AutoBucket challenger: '{0}' {1} -- cached={2}, probed={3}" -f $QueryKey, $_outcome, $cached, $optimal)
    }
  }

  return $optimal
}
