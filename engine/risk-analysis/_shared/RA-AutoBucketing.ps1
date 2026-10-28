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

  # 🔴 A THROTTLE IS NOT AN OVERFLOW. "too many" below exists for "too many rows/records", and it also
  # matched "429 Too Many Requests" -- so a throttled bucket was treated as too BIG, and the main loop
  # escalated the bucket count and re-ran the report with MORE calls against an API that was already
  # throttling. Excluded first, so no other pattern can claim it.
  if ($m -match "too many requests" -or $m -match "\b429\b" -or $m -match "throttl") { return $false }

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

  # The recognised PLATFORM cancellations (#99/#106) are resizable too -- the hunting layer already
  # treats them as deterministic-too-large. Without this the PROBE path could not learn a higher bucket
  # count for exactly those reports and fell back to the configured default.
  $prefix = ''
  if (Get-Command -Name 'Get-RAPlatformFailurePrefixPattern' -ErrorAction SilentlyContinue) {
    $prefix = [string](Get-RAPlatformFailurePrefixPattern)
  }
  if ($prefix -ne '' -and $msg -match $prefix) { return $true }

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
    $m -match "forbidden temporarily" -or
    # the connection itself failed (a part asked ahead surfaces it as "Exception calling GetResult ... An error occurred
    # while sending the request"): the platform, not the query -- the same slice is asked again (working rule 4); live
    # 2026-10-19, a large customer's Summary lost one of 14 slices to it and the report was NOT complete
    $m -match "an error occurred while sending the request" -or
    $m -match "the response ended prematurely" -or
    $m -match "connection (was )?(forcibly )?(closed|reset)" -or
    $m -match "transport-level error"
  ) { return $true }

  return $false
}

function Get-RAPlatformPrefixPatternSafe {
  # The shared platform-failure prefix list lives in RA-GraphHunting.ps1, which the engine dot-sources
  # BEFORE this file. Guarded so this file still loads standalone (tests, tools) -- in that case there
  # is simply no prefix to match, which is the pre-existing behaviour.
  if (Get-Command -Name 'Get-RAPlatformFailurePrefixPattern' -ErrorAction SilentlyContinue) {
    return [string](Get-RAPlatformFailurePrefixPattern)
  }
  return ''
}

function Test-RASplitCanStillFit {
  <#
    PURE. Is a finer split still able to make THIS refused request fit? True when the service refused the request for its
    SIZE (413 Request Entity Too Large) while the query carried CL rows inlined per slice (-InlineBytes > 0: the hybrid
    inline is cut by the same hash as the slice, so every further split sends a quarter of them), and what the request
    carries besides them (-OverheadBytes, the query text and the lookups sent whole) is below the limit. Then a deeper split
    is NOT futile -- the sub-bucket pass must not prune it (live 2026-10-19, rc11, a large school: 123,478 inlined rows,
    6.0 MB at 4 slices and 1.5 MB at 16 -- every 16-slice child refused, its subtree pruned "as futile" and the report lost,
    while 64 slices carry ~380 KB each). A timeout, a result too large or a request whose remainder alone is over the limit
    stays futile as before.
  #>
  param([Parameter(Mandatory = $true)][object]$Err, [long]$InlineBytes = 0, [long]$OverheadBytes = 0, [long]$LimitBytes = 1048576)
  $msg = ''
  if ($Err -is [System.Management.Automation.ErrorRecord]) {
    $d = ''; try { if ($Err.ErrorDetails) { $d = [string]$Err.ErrorDetails.Message } } catch { }
    $msg = [string]($Err.Exception.Message + ' ' + $d)
  } else { $msg = [string]$Err }
  if ($msg -notmatch '(?i)413 Request Entity Too Large|RequestEntityTooLarge|request entity too large') { return $false }
  if ($InlineBytes -le 0) { return $false }
  return ($OverheadBytes -ge 0 -and $OverheadBytes -lt $LimitBytes)
}

function Test-RABucketOutOfMemory {
  <#
    PURE. Did reading or processing this slice's answer run THIS worker out of memory? A .NET OutOfMemoryException anywhere in
    the chain, or its text -- also as the hunting layer words it ("advanced hunting returned a body that is not JSON: Exception
    of type 'System.OutOfMemoryException' was thrown": the answer could not be parsed because the process had no memory for
    it, not because the service sent something broken). That is a SIZE signal for this worker, never a query defect: the
    slice is split and asked again in smaller slices (live 2026-10-20/21: one Detailed slice failed this way run after run
    and its rows stayed unknown). The service's own "preempted ... high CPU and/or memory" answer is NOT this (a busy
    backend, Test-RABucketBusyAnswer).
  #>
  param([Parameter(Mandatory=$true)][object]$Err)
  if ($Err -is [System.Management.Automation.ErrorRecord]) {
    for ($ex = $Err.Exception; $null -ne $ex; $ex = $ex.InnerException) {
      if ($ex -is [System.OutOfMemoryException]) { return $true }
      if ($ex.Data -and $ex.Data.Contains('SIRAOutOfMemory')) { return $true }
    }
    $d = ''; try { if ($Err.ErrorDetails) { $d = [string]$Err.ErrorDetails.Message } } catch { }
    $msg = [string]($Err.Exception.Message + ' ' + $d)
  } elseif ($Err -is [System.Exception]) {
    for ($ex = $Err; $null -ne $ex; $ex = $ex.InnerException) { if ($ex -is [System.OutOfMemoryException]) { return $true } }
    $msg = [string]$Err.Message
  } else { $msg = [string]$Err }
  if ($msg -match '(?i)preempted|high cpu|memory resource consumption') { return $false }
  return [bool]($msg -match '(?i)OutOfMemoryException|\bout of memory\b|\bOOMKilled\b|Insufficient memory')
}

function Get-RABucketFailureAction {
  <#
    WHAT TO DO WITH A BUCKET THAT FAILED -- one decision, shared by the main bucket loop, the late-retry
    pass and the sub-bucket pass, so the three can never classify the same failure differently.

    🔒 THE CONTRACT: A BUCKET IS NEVER WRITTEN OFF WHILE A RECOVERY IS LEFT. Losing findings is the
    worst outcome this engine has -- a finding that disappears reads as FIXED downstream. So every
    failure is routed to the recovery that matches its CAUSE, and only a query DEFECT (which fails
    identically on every attempt) or an exhausted recovery is recorded as lost.

      'Split'  -- the slice is too big or too slow for the backend: the 900s client ceiling, a 502 from
                  the proxy, a result-size overflow, or a recognised platform cancellation. Retrying the
                  SAME size fails the same way; a SMALLER slice is the fix, so it goes to sub-bucketing.
      'Retry'  -- the API is throttling or had an issue: 429, 503, 504, auth expiry, a transient timeout
                  on a small request. 🔴 NEVER SPLIT THESE. Splitting multiplies the calls, and against
                  a throttling API that makes it worse (the reason Test-IsBucketOverflowError excludes
                  transients). The same slice is retried after backoff + re-auth, and if that runs out
                  it is retried AGAIN after the rest of the report, when the throttle window has passed.
      'Defect' -- the QUERY is wrong (syntax/semantic/type). Working rule 4: fail on attempt 1 and say
                  the query must be fixed -- re-running cannot succeed.
      'Fail'   -- unrecognised. Recorded as lost, loudly, never silently.

    -AllTimedOut is the hunting layer's own verdict for the call that just failed (every attempt hit the
    ceiling / it bypassed retries as deterministic-too-large). It is trusted as a 'Split' signal.
  #>
  param(
    [Parameter(Mandatory=$true)][object]$Err,
    [bool]$AllTimedOut = $false
  )

  # "No slice count can make this report fit" (RA-ProfileAugment.ps1, raised before anything is sent) is never
  # split and never retried -- both would repeat a request that cannot be accepted. Its text carries sizes
  # ("429 KB"), so it is recognised by its mark BEFORE any text pattern below can claim it.
  if ((Get-Command -Name 'Test-RAReportCannotRunError' -ErrorAction SilentlyContinue) -and (Test-RAReportCannotRunError -Err $Err)) { return 'Fail' }

  $msg = ""
  if ($Err -is [System.Management.Automation.ErrorRecord]) {
    $detailMsg = ""
    try { if ($Err.ErrorDetails) { $detailMsg = [string]$Err.ErrorDetails.Message } } catch {}
    $msg = [string]($Err.Exception.Message + " " + $detailMsg)
  } else {
    $msg = [string]$Err
  }

  # A recognised PLATFORM cancellation (#99/#106) carries the service's generic "Fix semantic errors"
  # tail, so it must be recognised BEFORE the defect test or it is misread as a broken query.
  $prefix = Get-RAPlatformPrefixPatternSafe
  $isPlatformPrefix = ($prefix -ne '' -and $msg -match $prefix)
  if ($isPlatformPrefix) { return 'Split' }

  $m = $msg.ToLowerInvariant()
  # 'Absent' -- the tenant has no Microsoft Defender XDR, so advanced hunting answers 403 "Account is not provisioned"
  # (RA-GraphHunting.ps1 then says so once and sends no further query). Permanent and NOT a loss: there is no data to
  # lose. Checked before the auth test, which "Unauthorized" in the same answer would otherwise match (live 2026-10-06).
  if ($m -match 'account is not provisioned|si-ra: advanced hunting is not provisioned') { return 'Absent' }
  # ... or SecurityInsight's OWN profile table does not exist yet: Log Analytics makes a table on its first row, and a
  # tenant without devices (no Defender for Endpoint) never gives the endpoint profiler one -- SEM0100 on
  # SI_Endpoint_Profile_CL is no data, not a query defect (live 2026-10-06, Community rehearsal). Checked before the
  # defect test, which "SemanticError" would otherwise match. Only SI_*_CL names: any other missing name stays a defect.
  if ($msg -match "Failed to resolve table (?:or column )?expression named 'SI_[A-Za-z0-9_]+_CL'") { return 'Absent' }   # #876: 'union' says "table expression"
  # a tenant without Defender vulnerability management (no licence): its DeviceTvm* tables do not exist -- no data source,
  # not a query defect (customer A 2026-10-15)
  if ($msg -match "Failed to resolve table (?:or column )?expression named 'DeviceTvm[A-Za-z]+'") { return 'Absent' }

  # #880 A BUSY DEFENDER IS ASKED AGAIN, NEVER SPLIT. "Query execution has exceeded the allowed limits. The query execution was
  # preempted ... high CPU and/or memory" (Test-RABucketBusyAnswer) is the backend's load, not the slice's size: it carries the
  # overflow wording, so it is recognised BEFORE every size test below. Live 2026-10-22 (internal): an 11 KB slice with 28 of 700
  # inlined rows was refused; about a third of the requests were refused at every slice size, steadily for two hours; 3 of 8
  # refused slices went through when sent again at the same size 30 s later. Splitting it multiplied the fixed cost every slice
  # pays (263 requests instead of 3) -- the same slice is retried after a pause, then once more after the other slices.
  if (Test-RABucketBusyAnswer -Err $Err) { return 'Retry' }

  # The worker ran out of memory reading (or processing) the slice's answer: the slice is too large for THIS worker -- split
  # it and ask the same rows again in smaller slices (lossless). Never retried at the same size, never a defect.
  if (Test-RABucketOutOfMemory -Err $Err) { return 'Split' }

  if ($msg -match 'Fix syntax errors in your query|Fix semantic errors in your query|SyntaxError|SemanticError|return types are not compatible') {
    return 'Defect'
  }

  # Throttle / auth / service-unavailable are checked BEFORE every size signal and win over the hunting
  # layer's timeout flag: a throttled call must never be split, whatever else its text happens to match.
  $m = $msg.ToLowerInvariant()
  # #882: a 504 GATEWAY TIMEOUT is a busy platform's answer too (live 2026-10-22, a large install: the heavy CVE report's
  # slices answered 504 for over an hour and were given up after the hunting layer's short attempts) -- the same slice is
  # asked again after a longer pause, then once more after the other slices, exactly as a busy answer (#880); never split
  # (splitting multiplies the heavy fixed part every slice pays), never fewer rows: a slice that still fails leaves the report
  # NOT COMPLETE, which keeps its last complete result (#877)
  $isThrottleOrAuth = ($m -match 'too many requests|\b429\b|throttl|\b503\b|service unavailable|\b504\b|gateway time-?out|invalidauthenticationtoken|access token|\b401\b|unauthorized|forbidden temporarily')
  if ($isThrottleOrAuth) { return 'Retry' }

  if (Test-IsBucketOverflowError -Err $Err)          { return 'Split' }
  if (Test-IsDeterministicTooLargeError -Err $Err)   { return 'Split' }

  if ($AllTimedOut) { return 'Split' }

  if (Test-IsTransientPlatformError -Err $Err)       { return 'Retry' }

  return 'Fail'
}

function Get-RABucketRetryDelaySeconds {
  <#
    Backoff for a throttled/unavailable API: exponential, capped, and never shorter than a server-sent
    Retry-After when the error carries one. Attempt is 1-based.
  #>
  param(
    [int]$Attempt = 1,
    [int]$BaseSeconds = 30,
    [int]$MaxSeconds = 300,
    [object]$Err
  )
  if ($Attempt -lt 1) { $Attempt = 1 }
  $delay = [int][Math]::Min([double]$MaxSeconds, $BaseSeconds * [Math]::Pow(2, ($Attempt - 1)))
  if ($null -ne $Err) {
    $text = if ($Err -is [System.Management.Automation.ErrorRecord]) { [string]$Err.Exception.Message + ' ' + [string]$Err.ErrorDetails } else { [string]$Err }
    if ($text -match '(?i)retry-?after[^0-9]{0,5}(\d{1,5})') {
      $ra = [int]$matches[1]
      if ($ra -gt $delay) { $delay = [int][Math]::Min([double]$MaxSeconds, [double]$ra) }
    }
  }
  return $delay
}

# #882 THE LATE RETRY GOES ON WHILE THE RUN MAKES PROGRESS (owner 2026-10-22: "we cannot loose data (prio 1)"; no fixed limits
# on SI's own work). A slice the API refused as busy / throttled / 504 through its in-loop retries is asked again after the other
# slices -- in PASSES. Pass 1 is the late retry as it always was (per slice the same ladder of SI_BucketLateRetries attempts with
# a longer pause, Retry-After honoured, re-auth). Another pass runs over the slices still refused ONLY when the pass before
# recovered at least one slice; a whole pass that recovers nothing stops it -- no clock, no count of passes. What is still
# refused then is a named loss (the report is NOT COMPLETE and keeps its last complete result, #877).
# The pass loop stays INLINE in the caller (its body sets the caller's own variables); these keep its state:
#   $s = New-RALatePasses -Pending <indices>
#   while (Step-RALatePasses -State $s) { foreach ($i in $s.Current) { ...; Set-RALatePassResult -State $s -Index $i -Result ok|retry|gone } }
#   foreach ($i in $s.Left) { <named loss> }
#     ok    the slice's rows were recovered (progress)
#     retry still refused as busy / throttled / unavailable -- asked again in the next pass, if there is one
#     gone  left the late retry without rows recovered here (moved to the smaller slices, or recorded lost) -- not asked
#           again, and NOT progress
function New-RALatePasses {
  <# #882 PURE. The state of one report's late-retry passes. #>
  param([AllowEmptyCollection()][int[]]$Pending = @())
  $p = New-Object System.Collections.Generic.List[int]
  foreach ($i in @($Pending)) { $p.Add([int]$i) }
  [pscustomobject]@{ Pass = 0; Current = [int[]]@(); Next = $p; Recovered = 0L; RecoveredThisPass = 0L; RecoveredLastPass = 0L; Stopped = $false; Left = [int[]]@() }
}

function Step-RALatePasses {
  <# #882 PURE (over -State). $true when another pass is to run (its slices in .Current, its number in .Pass); $false when every
     slice is done, or when the pass just run recovered nothing (.Stopped, the slices still refused in .Left). #>
  param([Parameter(Mandatory)]$State)
  $pending = [int[]]@($State.Next.ToArray())
  if ($pending.Count -eq 0) { $State.Current = [int[]]@(); $State.Left = [int[]]@(); return $false }
  if ($State.Pass -ge 1 -and $State.RecoveredThisPass -eq 0) {
    $State.Stopped = $true; $State.Current = [int[]]@(); $State.Left = $pending
    return $false
  }
  $State.Pass++
  $State.Current = $pending
  $State.Next = New-Object System.Collections.Generic.List[int]
  $State.RecoveredLastPass = $State.RecoveredThisPass
  $State.RecoveredThisPass = 0L
  return $true
}

function Set-RALatePassResult {
  <# #882 PURE (over -State). One slice's outcome in the current pass: ok (progress) | retry (asked again next pass) | gone. #>
  param([Parameter(Mandatory)]$State, [Parameter(Mandatory)][int]$Index, [Parameter(Mandatory)][ValidateSet('ok', 'retry', 'gone')][string]$Result)
  if ($Result -eq 'ok') { $State.Recovered++; $State.RecoveredThisPass++ }
  elseif ($Result -eq 'retry') { $State.Next.Add($Index) }
}

function Test-RASubSliceAskAgain {
  <# #882 PURE. A smaller slice refused as busy / throttled after its in-loop retries is asked again (How = 'again') for its first
     -LateRounds rounds as before, and after them for as long as the sub-slice pass recovered at least one slice since this
     slice was queued last (-RecoveredNow > -RecoveredAtAsk) -- the late passes' rule, one slice at a time. #>
  param([int]$Rounds, [int]$LateRounds, [long]$RecoveredNow, [long]$RecoveredAtAsk)
  if ($Rounds -lt $LateRounds) { return $true }
  return ($RecoveredNow -gt $RecoveredAtAsk)
}

function Get-RABucketOverflowStep {
  <#
    #722 PURE. What the main bucket loop does with a slice the service has just answered as TOO LARGE (Test-IsBucketOverflowError:
    response / result / payload too large, over the row or size limit, resource limits exceeded).

      'Split' -- queue the slice for the sub-bucket pass now: no pause, no second request at the same size.
      'Probe' -- send the same slice again after PauseSeconds (30 s, 60 s, 120 s ... capped at 180 s).

    ProbeAttempts is how many times a too-large slice is sent at the same size in all (SI_BucketOverflowRetries). The default
    is 1: split on the first too-large answer. Live 2026-10-16 (a large customer, two Detailed reports): with 3, each of 8
    buckets was sent three times with 30 s + 60 s pauses, failed all three, and every 4-way sub-slice then succeeded -- about
    12 minutes of pauses per report that could not succeed. Splitting is lossless (the sub-slices together are exactly the
    slice; rows already retrieved are kept), so the only price of splitting a slice that a re-send would have carried is a
    few smaller requests.
    Throttle / service-unavailable / timeout are NOT routed here (Test-IsBucketOverflowError excludes them; they go to
    Get-RABucketFailureAction -> 'Retry' with backoff + re-auth): working rule 4 -- only the PLATFORM is re-run.
  #>
  # #737 -Busy: the answer was the service's "preempted ... high CPU and/or memory" (Test-RABucketBusyAnswer) -- backend
  # pressure, not a slice that is too large. It is sent once more at the same size after a pause before it is split (the
  # v2.2.199 behaviour #722 dropped: live 2026-10-17 a busy backend split half of a report's slices at once and the next
  # run started at 4 x the count).
  param([int]$OverflowAttempt = 1, [int]$ProbeAttempts = 1, [switch]$Busy)
  if ($OverflowAttempt -lt 1) { $OverflowAttempt = 1 }
  if ($Busy -and $ProbeAttempts -lt 2) { $ProbeAttempts = 2 }
  if ($OverflowAttempt -lt $ProbeAttempts) {
    return [pscustomobject]@{ Action = 'Probe'; PauseSeconds = [int][Math]::Min(180, 30 * [Math]::Pow(2, ($OverflowAttempt - 1))) }
  }
  return [pscustomobject]@{ Action = 'Split'; PauseSeconds = 0 }
}

# #737: the client ceiling of one advanced-hunting request (Invoke-SIHuntingQueryRest -TimeoutSec 900). A slice's TIME is
# measured against it the same way its rows and bytes are measured against the answer limits (RA-BucketStore.ps1).
$script:RASliceCeilingSeconds = 900

function Test-RABucketBusyAnswer {
  <# #737 PURE. The service's "preempted ... high CPU and/or memory" answer -- the backend is busy, the slice is not proven
     too large (v2.2.199). It carries the overflow wording "exceeded the allowed limits", so it is recognised by its own. #>
  param([Parameter(Mandatory=$true)][object]$Err)
  $msg = if ($Err -is [System.Management.Automation.ErrorRecord]) { [string]$Err.Exception.Message + ' ' + [string]$Err.ErrorDetails } else { [string]$Err }
  return [bool]($msg -match '(?i)preempted|high cpu|memory resource consumption')
}

function Test-RABucketExplicitTooLarge {
  <# #737 PURE. The service SAID the slice is too large (result size, row limit, payload / response / request too large) --
     not a busy backend (preempted), and not a 502 / timeout, whose cause only the slice's own measured answer can tell. #>
  # An answer this worker had no memory for is too large for it -- a size signal like the service's own (the slice is split
  # and the next run starts finer).
  param([Parameter(Mandatory=$true)][object]$Err)
  if (Test-RABucketBusyAnswer -Err $Err) { return $false }
  if (Test-RABucketOutOfMemory -Err $Err) { return $true }
  return [bool](Test-IsBucketOverflowError -Err $Err)
}

function Get-RASliceNeed {
  <#
    #737 PURE. How many slices ONE split slice really needed, from its own measured answer: the rows, the estimated bytes
    and the time its sub-slices took together, against HALF of each limit (30,000 rows, 64 MB, the 900 s ceiling -- the
    same "half of every limit" the measured sizing uses). A slice whose answer came back far within every limit failed
    because the backend was busy, not because it was too large: it needs 1 (it is retried / recovered, never escalated).
    The service saying "too large", or sub-slices that were lost, is at least 2. Never more than the finest split that
    worked (-Bound) -- it is proven enough.
  #>
  # #880 A SLICE WHOSE ONLY FAILURES WERE BUSY ANSWERS (Busy > 0; no smaller slice refused for its size -- SizeFails 0; the
  # service never said "too large"; the worker had its memory) proved nothing about its size: it is sized from its measured
  # rows and bytes alone -- never from its time (a busy backend's time) and never "at least 2" for a part lost to the busy
  # backend (LostBusy). Live 2026-10-22: such slices raised a report's remembered count 2 -> 18 -> 28.
  param($Slice, [int]$Bound = 4)
  if ($null -eq $Slice) { return 1 }
  $prop = { param($n) if ($Slice.PSObject.Properties[$n]) { $Slice.$n } else { $null } }
  $busyOnly = ([int]('0' + [string](& $prop 'Busy')) -gt 0 -and [int]('0' + [string](& $prop 'SizeFails')) -eq 0 -and
               -not [bool](& $prop 'TooLarge') -and -not [bool](& $prop 'OutOfMemory') -and -not [bool](& $prop 'Lost'))
  $rowLimit = if ($script:SIRaBucketRowLimit) { [double]$script:SIRaBucketRowLimit } else { 30000.0 }
  $byteLimit = if ($script:SIRaBucketAnswerBytes) { [double]$script:SIRaBucketAnswerBytes } else { [double]64MB }
  $ceiling = if ($script:RASliceCeilingSeconds) { [double]$script:RASliceCeilingSeconds } else { 900.0 }
  $f = 0.0
  $f = [Math]::Max($f, [double]('0' + [string]$Slice.Rows) / ($rowLimit / 2.0))
  $f = [Math]::Max($f, [double]('0' + [string]$Slice.Bytes) / ($byteLimit / 2.0))
  if (-not $busyOnly) { $f = [Math]::Max($f, [double]('0' + [string]$Slice.Seconds) / ($ceiling / 2.0)) }
  $need = [int][Math]::Max(1, [Math]::Ceiling($f))
  if ($busyOnly) {
    if ($Bound -lt 2) { $Bound = 2 }
    if ($need -gt $Bound) { $need = $Bound }
    return $need
  }
  # A slice this WORKER had no memory for: the service's limits do not show it (its rows can be far below them), so it is
  # sized from what the worker DID hold -- the slice's rows against the largest of its smaller slices that went through
  # (MaxPartRows); at least 2. Measured, never a fixed number of slices.
  if ($Slice.PSObject.Properties['OutOfMemory'] -and [bool]$Slice.OutOfMemory) {
    $part = if ($Slice.PSObject.Properties['MaxPartRows']) { [double]('0' + [string]$Slice.MaxPartRows) } else { 0.0 }
    $all = [double]('0' + [string]$Slice.Rows)
    if ($part -gt 0 -and $all -gt 0) { $need = [int][Math]::Max($need, [Math]::Ceiling($all / $part)) }
    if ($need -lt 2) { $need = 2 }
  }
  if (([bool]$Slice.TooLarge -or [bool]$Slice.Lost) -and $need -lt 2) { $need = 2 }
  if ($Bound -lt 2) { $Bound = 2 }
  if ($need -gt $Bound) { $need = $Bound }
  return $need
}

function Get-RACountAfterSplit {
  <#
    #722 / #737 PURE. The bucket count the NEXT run starts from after slices of THIS report had to be split.

    #737 (live 2026-10-17, build 2138): #722 jumped the whole report to the finest count a split slice worked at whenever
    half or more of its buckets were split, and #640 doubled it for a single split slice. A busy backend (900 s timeouts,
    502s, preemptions) split half of a 58-bucket report's slices -> the next run started at 232; a 2-bucket report with one
    such slice -> 8. The remembered count only went up, so the next runs paid 4 x the requests for the same rows.

    Now the count is SIZED TO THE ANSWER: each split slice is replaced by the number of slices its own measured answer needed
    (Get-RASliceNeed: rows, bytes and time against half of each limit), so
        next = BucketCount + SUM over the split slices of (need - 1)
    * a slice the backend failed while its answer was small needs 1 -> adds nothing (a transient is not escalated);
    * every bucket truly too large and needing the 4-way split -> 4 x the count (the #722 live case, 8 -> 32);
    * one hot slice of 64 needing 3 -> 66, not 128;
    * never more than the finest count that worked, never below the count used, within the configured maximum (-Cap).
    -Slices: one object per split bucket of THIS report: @{ Rows; Bytes; Seconds; TooLarge; Lost }.
  #>
  # #880 -Incomplete: the report ended NOT COMPLETE (a slice's rows are unknown) -- its count is never raised from it (the
  # measurement is partial; live 2026-10-22 two NOT COMPLETE runs raised a count 2 -> 18 -> 28). -ProvenOnly (the save during
  # the run, in case it stops part-way): only the slices whose SIZE is proven -- the service said "too large" or the worker had
  # no memory for it; a slice split for a 502 / timeout is sized when the report is done, from its whole measured answer.
  param([int]$BucketCount, [object[]]$Slices = @(), [int]$WorkingCount = 0, [int]$FanOut = 4, [int]$Cap = 0, [switch]$ProvenOnly, [switch]$Incomplete)
  if ($BucketCount -lt 1) { $BucketCount = 1 }
  if ($Incomplete) { return [int]$BucketCount }
  $bound = if ($WorkingCount -gt $BucketCount) { [int][Math]::Floor($WorkingCount / [double]$BucketCount) } else { [Math]::Max(2, $FanOut) }
  $next = [long]$BucketCount
  foreach ($s in @($Slices | Where-Object { $null -ne $_ })) {
    if ($ProvenOnly -and -not ([bool]$s.TooLarge -or ($s.PSObject.Properties['OutOfMemory'] -and [bool]$s.OutOfMemory))) { continue }
    $next += ([long](Get-RASliceNeed -Slice $s -Bound $bound) - 1)
  }
  if ($Cap -gt 0 -and $next -gt $Cap) { $next = $Cap }
  if ($next -lt $BucketCount) { $next = $BucketCount }
  return [int]$next
}

function Test-RASplitReducesFailure {
  <#
    #880 PURE. Does splitting one bucket DEEPER still reduce its failure -- measured, never a fixed depth or number?
    -Tried / -Failed: per split depth of ONE bucket (1 = its first split into smaller slices, 2 = theirs ...), how many of its
    smaller slices were asked and how many of them were refused for their size or time (busy answers are retried, never counted
    here; a request the inlined rows make too large and a slice the worker had no memory for always shrink with a split and are
    not routed here). Depth 0 is the bucket itself: 1 asked, 1 refused. -Depth: the depth whose slices are about to be asked.
    True while the refused SHARE went down from depth-2 to depth-1: the split is distributing the work. False when it did not --
    the smaller slices are refused as often as their parents were (live 2026-10-22: a report split six levels deep, to 1/73,728
    of its devices, and its smaller slices were still refused about as often as at the top). The old rule stopped only when ALL
    four children of one parent failed.
  #>
  param([hashtable]$Tried = @{}, [hashtable]$Failed = @{}, [int]$Depth = 1)
  if ($Depth -lt 2) { return $true }
  $share = {
    param([int]$d)
    if ($d -le 0) { return 1.0 }
    $t = [double]('0' + [string]$Tried[$d]); $f = [double]('0' + [string]$Failed[$d])
    if ($t -le 0) { return $null }
    return ($f / $t)
  }
  $now = & $share ($Depth - 1)
  if ($null -eq $now) { return $true }
  $before = & $share ($Depth - 2)
  if ($null -eq $before) { $before = 1.0 }
  return ([double]$now -lt [double]$before)
}

function Test-RASubSplitAddressable {
  <#
    PURE (owner 2026-10-22: no fixed limits -- the sub-split's depth cap of 6 is gone). Can a slice asked at -SliceCount slices
    be split once more into -FanOut smaller ones? The bucket filter hashes the key into that many slices, an [int] count: past
    2^31 - 1 no finer key partition exists. That is the only end besides the measured one (Test-RASplitReducesFailure); a slice
    still refused there is a named loss and the report is NOT COMPLETE.
  #>
  param([long]$SliceCount, [int]$FanOut = 4)
  if ($SliceCount -lt 1 -or $FanOut -lt 2) { return $false }
  return (([long]$SliceCount * [long]$FanOut) -le [long][int]::MaxValue)
}

function Test-RABucketRunFarBelow {
  <#
    #737 PURE. Whether EVERY slice of this report's run came back far below every limit: under 25 % (SIRaBucketDownFraction)
    of the rows, the answer bytes, the request room and -- unlike the database-only STEP 3 -- the 900 s ceiling. Time is
    what makes this safe for a report whose count is set by COMPUTE (an Exposure-Graph-heavy attack path returns few rows
    and still needs its slices): a slice near the ceiling is never "far below". A run with no measured slice is not.
  #>
  param($Measure)
  if ($null -eq $Measure) { return $false }
  if (-not $Measure.PSObject.Properties['Slices'] -or [int]$Measure.Slices -lt 1) { return $false }
  $frac = if ($script:SIRaBucketDownFraction) { [double]$script:SIRaBucketDownFraction } else { 0.25 }
  $rowLimit = if ($script:SIRaBucketRowLimit) { [double]$script:SIRaBucketRowLimit } else { 30000.0 }
  $byteLimit = if ($script:SIRaBucketAnswerBytes) { [double]$script:SIRaBucketAnswerBytes } else { [double]64MB }
  $reqLimit = if ($script:SIRaBucketRequestBytes) { [double]$script:SIRaBucketRequestBytes } else { [double]1MB }
  $ceiling = if ($script:RASliceCeilingSeconds) { [double]$script:RASliceCeilingSeconds } else { 900.0 }
  if ([double]$Measure.MaxBucketRows -ge ($frac * $rowLimit)) { return $false }
  if ([double]$Measure.MaxBucketBytes -ge ($frac * $byteLimit)) { return $false }
  if ([double]$Measure.MaxBucketSeconds -ge ($frac * $ceiling)) { return $false }
  $req = [double]$Measure.MaxRequestBytes
  if ($req -gt 0) {
    $over = if ($Measure.PSObject.Properties['MaxFixedBytes']) { [double]$Measure.MaxFixedBytes } else { 0.0 }
    $room = [Math]::Max(1.0, $reqLimit - $over)
    if (($req - $over) -ge ($frac * $room)) { return $false }
  }
  return $true
}

function Get-RACountAfterSmallRun {
  <# #737 PURE. A report whose every slice came back far below every limit starts its next run at HALF the count (rounded
     up), never below the configured count (-Floor) or 1. One step per run: the next run measures again. #>
  param([int]$BucketCount, [int]$Floor = 1)
  if ($Floor -lt 1) { $Floor = 1 }
  if ($BucketCount -le $Floor) { return [int][Math]::Max(1, $BucketCount) }
  return [int][Math]::Max($Floor, [Math]::Ceiling($BucketCount / 2.0))
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

  # #640: with the Pro database the counts live THERE only -- the run reads its in-memory copy of the database state
  # (Initialize-AutoBucketSqlStore), never a file.
  if (Test-AutoBucketSqlActive) { return (ConvertTo-HashtableDeep -InputObject $script:AutoBucketSql.State) }

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

function Test-AutoBucketWriteAllowed {
  <#
    #882: may this process keep bucket sizing state (the remembered counts, their history)? A queue worker sets
    $script:AutoBucketWriteGate { } -> @{ Live; Why } (or a bool) -- RA-ScaleOut.ps1 Test-RAScaleOutRunLive: a worker of a run
    that is over writes NOTHING (live 2026-10-22: a worker of an interrupted run raised the count the next run used). FAIL
    CLOSED: a gate that throws or answers nothing = not allowed. Without a gate (a single job, a producer) = allowed. The
    refusal is said once per process.
  #>
  if (-not (Get-Variable -Name AutoBucketWriteGate -Scope Script -ErrorAction SilentlyContinue) -or $null -eq $script:AutoBucketWriteGate) { return $true }
  $ok = $false; $why = ''
  try {
    $g = & $script:AutoBucketWriteGate
    if ($g -is [bool]) { $ok = $g }
    elseif ($null -ne $g -and $g.PSObject.Properties['Live']) { $ok = [bool]$g.Live; $why = [string]$g.Why }
    else { $why = 'the check answered nothing' }
  } catch { $ok = $false; $why = [string]$_.Exception.Message }
  if (-not $ok -and -not ((Get-Variable -Name AutoBucketWriteRefusedSaid -Scope Script -ErrorAction SilentlyContinue) -and $script:AutoBucketWriteRefusedSaid)) {
    $script:AutoBucketWriteRefusedSaid = $true
    Write-Warning ("bucket sizing: nothing is kept -- this worker's run is not the live one any more{0}" -f $(if ($why) { ' (' + $why + ')' } else { '' }))
  }
  return [bool]$ok
}

function Write-AutoBucketCache {
  param(
    [Parameter(Mandatory=$true)][string]$Path,
    [Parameter(Mandatory=$true)][object]$CacheObject
  )

  # #882: a worker of a run that is over keeps nothing (fail closed)
  if (-not (Test-AutoBucketWriteAllowed)) { return }

  # #640: with the Pro database every write goes there (only what changed), never to a file.
  if (Test-AutoBucketSqlActive) { Save-AutoBucketSqlState -CacheObject $CacheObject; return }

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
  # [Math]::Floor, not [int](): PowerShell's [int] cast rounds half-to-EVEN, so for n=3 it picked
  # index 2 (the MAXIMUM) and for n=7 index 4 -- the "median" was biased upward on every odd count (#121).
  $mid = [int][Math]::Floor($n / 2)
  $median = if ($n % 2 -eq 1) { [int]$sorted[$mid] } else { [int](($sorted[$mid - 1] + $sorted[$mid]) / 2) }
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

  # Where the returned count came from (memo | cache | configured | probe): the end-of-run write stamps a count
  # "confirmed" only when this run decided it (Test-AutoBucketCountDecidedThisRun).
  $script:_AutoBucketSource = 'configured'
  # #697 (2): whether a probe rung FAILED in this call (a count a failed query proved necessary) -- read by the report loop
  $script:_AutoBucketProbeFailed = $false
  if ($MaxBucketCount -lt 1) { return 1 }
  if ($MinBucketCount -lt 1) { $MinBucketCount = 1 }
  if ($MinBucketCount -gt $MaxBucketCount) { $MinBucketCount = $MaxBucketCount }

  # Memo. Honour only if >= floor; otherwise re-probe (user raised the floor
  # via YAML BucketCount, so a smaller cached value is stale).
  if ($script:AutoBucketMemo.ContainsKey($QueryKey)) {
    $memoVal = [int]$script:AutoBucketMemo[$QueryKey]
    if ($memoVal -ge $MinBucketCount) { $script:_AutoBucketSource = 'memo'; return $memoVal }
  }
  if ($LegacyKeys) {
    foreach ($lk in $LegacyKeys) {
      if (-not [string]::IsNullOrWhiteSpace($lk) -and $script:AutoBucketMemo.ContainsKey($lk)) {
        $val = [int]$script:AutoBucketMemo[$lk]
        if ($val -ge $MinBucketCount) {
          $script:AutoBucketMemo[$QueryKey] = $val
          $script:_AutoBucketSource = 'memo'
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
          $script:_AutoBucketSource = 'cache'
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
            $script:_AutoBucketSource = 'cache'
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

    # Fallback for old cache formats (cap in key) and other key mismatches.
    # #640 DEFECT FIX: NOT after the challenger flagged the count -- the fallback also matches the report's own key, so it
    # handed the suspect count straight back and the re-probe never ran (a rogue count was kept forever).
    if ($cache -is [hashtable] -and -not $script:_AutoBucketWasChallenged) {
      $fallback = Get-AutoBucketCacheFallbackValue -Cache $cache -QueryKey $QueryKey -MaxBucketCount $MaxBucketCount
      if ($null -ne $fallback -and [int]$fallback -ge $MinBucketCount) {
        Write-Info ("AutoBucket cache fallback: '{0}' => {1}" -f $QueryKey, $fallback)
        $script:AutoBucketMemo[$QueryKey] = [int]$fallback
        $script:_AutoBucketSource = 'cache'
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
      # "No slice count can make this report fit" ends the ramp at once: every further rung would build the same
      # request again. Rethrown as it is, so the caller fails the report and goes on with the next one.
      if ((Get-Command -Name 'Test-RAReportCannotRunError' -ErrorAction SilentlyContinue) -and (Test-RAReportCannotRunError -Err $_)) { throw }
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

      $script:_AutoBucketProbeFailed = $true
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
      if ((Get-Command -Name 'Test-RAReportCannotRunError' -ErrorAction SilentlyContinue) -and (Test-RAReportCannotRunError -Err $_)) { throw }
      if (-not ((Test-IsBucketOverflowError $_) -or (Test-IsDeterministicTooLargeError $_))) { throw }
      $script:_AutoBucketProbeFailed = $true
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

  $script:_AutoBucketSource = 'probe'
  return $optimal
}


# =====================================================================================================================
# #640 BUCKET SIZING -- THE CORE OF RISK ANALYSIS (owner 2026-10-13: "we must this one right, as it is the core of si";
# "also config about sizing should of course be in sql only"). With the Pro database:
#   * the remembered counts live in the database only (cfg.RaBucketState, RA-BucketStore.ps1): Read-AutoBucketCache /
#     Write-AutoBucketCache above read and write the run's copy of it and send every change there -- the logic of the
#     probe, the challenger and the stale-query eviction is unchanged;
#   * a ONE-TIME reset an Admin staged (Operations > Risk Analysis query splitting) is consumed at the start of the run;
#   * the counts an install learned before are imported ONCE;
#   * every report's run leaves a history row (count, how it was decided, the measured result), from which the usual
#     count, the jump warning (step 2), sizing down (step 3) and sizing from a measured result (step 4) are worked out.
# Without the Pro database nothing here is active and the bucketing works exactly as before.
# =====================================================================================================================

function Remove-AutoBucketReportEntries {
  <#
    PURE. Removes every cache entry of the named reports -- '<ReportName>|<fingerprint>' and the legacy
    '<ReportName>|<hash>|cap<N>' -- and their confirmedAt stamps. '*' names every report. Mutates $Cache.Value; returns the
    report names that had an entry (each once).
  #>
  param(
    [Parameter(Mandatory=$true)][ref]$Cache,
    [string[]]$ReportNames = @()
  )
  $removed = New-Object System.Collections.Generic.List[string]
  if ($Cache.Value -isnot [hashtable]) { return ,$removed.ToArray() }
  $names = @($ReportNames | Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) } | ForEach-Object { ([string]$_).Trim() })
  if ($names.Count -eq 0) { return ,$removed.ToArray() }
  $all = ($names -contains '*')
  $toRemove = New-Object System.Collections.Generic.List[string]
  foreach ($k in @($Cache.Value.Keys)) {
    $ks = [string]$k
    if ($ks -eq $script:AutoBucketConfirmedKey) { continue }
    $i = $ks.IndexOf('|')
    if ($i -lt 1) { continue }
    $report = $ks.Substring(0, $i)
    if ($all -or ($names -contains $report)) {
      [void]$toRemove.Add($ks)
      if (-not $removed.Contains($report)) { [void]$removed.Add($report) }
    }
  }
  $stamps = $null
  if ($Cache.Value.ContainsKey($script:AutoBucketConfirmedKey) -and $Cache.Value[$script:AutoBucketConfirmedKey] -is [hashtable]) { $stamps = $Cache.Value[$script:AutoBucketConfirmedKey] }
  foreach ($k in $toRemove) {
    [void]$Cache.Value.Remove($k)
    if ($stamps -and $stamps.ContainsKey($k)) { [void]$stamps.Remove($k) }
  }
  return ,$removed.ToArray()
}

function Get-AutoBucketPreviousCount {
  <#
    A report whose QUERY CHANGED (a new build changes its fingerprint, so its remembered count is under another key) starts
    from the count the report used under its earlier query -- as a remembered count, not a confirmed one -- instead of
    sizing again from scratch (live 2026-10-16: a report that ran complete in 24 slices sized itself again after an update,
    with failed and re-split requests). Only when nothing is remembered for -QueryKey itself (memo or store): then the
    largest count remembered for the same report under another fingerprint, never below a count a failed query proved
    necessary for the report (its history, Pro), within [-Floor, -Cap]. $null when there is none.
  #>
  param([Parameter(Mandatory=$true)][string]$QueryKey, [int]$Floor = 1, [int]$Cap = 0)
  $report = Get-AutoBucketReportName -QueryKey $QueryKey
  if ([string]::IsNullOrWhiteSpace($report)) { return $null }
  $memo = $null
  if ((Get-Variable -Name AutoBucketMemo -Scope Script -ErrorAction SilentlyContinue) -and $script:AutoBucketMemo -is [hashtable]) { $memo = $script:AutoBucketMemo }
  if ($memo -and $memo.ContainsKey($QueryKey)) { return $null }
  $cache = @{}
  if ([bool]$global:AutoBucketCache -and -not [string]::IsNullOrWhiteSpace([string]$global:SettingsPath)) {
    try { $cache = Read-AutoBucketCache -Path (Get-AutoBucketCachePath -SettingsPath $global:SettingsPath) } catch { $cache = @{} }
    if ($cache -isnot [hashtable]) { $cache = @{} }
  }
  if ($cache.ContainsKey($QueryKey)) { return $null }
  $prefix = $report + '|'
  $best = 0
  foreach ($src in @($cache, $memo)) {
    if ($null -eq $src) { continue }
    foreach ($k in @($src.Keys)) {
      $ks = [string]$k
      if ($ks -eq $QueryKey -or $ks.StartsWith('__') -or -not $ks.StartsWith($prefix)) { continue }
      $v = 0
      if ([int]::TryParse([string]$src[$k], [ref]$v) -and $v -gt $best) { $best = $v }
    }
  }
  if ($best -lt 1) { return $null }
  if ((Test-AutoBucketSqlActive) -and (Get-Command -Name Get-SIRaBucketProvenCount -ErrorAction SilentlyContinue)) {
    $proven = Get-SIRaBucketProvenCount -History @($script:AutoBucketSql.History[$report] | Where-Object { $_ }) -Floor $Floor
    if ($proven -gt $best) { $best = $proven }
  }
  if ($best -lt $Floor) { $best = $Floor }
  if ($Cap -gt 0 -and $best -gt $Cap) { $best = $Cap }
  return [int]$best
}

function Save-AutoBucketCountEarly {
  <#
    The count a report runs at is kept AS SOON AS a slice has succeeded at it -- not only when the whole report is done
    (live 2026-10-16: a report of 64 slices takes hours; two runs were stopped part-way, so the count found was never kept
    and every run paid the sizing again). The count only ever goes UP here (a lower count tried this run never replaces a
    higher remembered one) and is NOT stamped confirmed -- the end of the report still writes and confirms it as before.
    Returns $true when it was written.
  #>
  # #880 -Incomplete: a slice of this report's run is already lost (its rows are unknown) -- the run is NOT COMPLETE and keeps
  # nothing early: a run stopped part-way must not leave behind a count raised from a partial answer (live 2026-10-22: an
  # interrupted worker kept raising a report's count while its slices were refused by a busy backend).
  param([Parameter(Mandatory=$true)][string]$QueryKey, [Parameter(Mandatory=$true)][int]$Count, [switch]$Incomplete)
  if ([string]::IsNullOrWhiteSpace($QueryKey) -or $Count -lt 1 -or $Incomplete) { return $false }
  if (-not [bool]$global:AutoBucketCache -or [string]::IsNullOrWhiteSpace([string]$global:SettingsPath)) { return $false }
  $path = Get-AutoBucketCachePath -SettingsPath $global:SettingsPath
  $cache = Read-AutoBucketCache -Path $path
  if ($cache -isnot [hashtable]) { $cache = @{} }
  $cur = 0
  if ($cache.ContainsKey($QueryKey) -and [int]::TryParse([string]$cache[$QueryKey], [ref]$cur) -and $cur -ge $Count) { return $false }
  if (-not (Test-AutoBucketWriteAllowed)) { return $false }   # #882: a worker of a run that is over keeps nothing
  $cache[$QueryKey] = [int]$Count
  Write-AutoBucketCache -Path $path -CacheObject $cache
  return $true
}

function Test-AutoBucketCountDecidedThisRun {
  <#
    PURE. Whether a report's successful run DECIDED its bucket count -- only then may the end-of-run write stamp it
    confirmed. True when the count was probed, sized down or set from the configured count this run, or the run had to
    raise it. FALSE for a count taken unchanged from what was remembered: stamping it on every run kept the challenger's
    7-day pause open forever on a daily schedule, so a count that went rogue was never re-tested (#640; owner 2026-10-13:
    "backend issues made it increment the bucket size so last known went rogue").
  #>
  param([string]$Source, [int]$StartCount, [int]$FinalCount)
  if ($FinalCount -ne $StartCount) { return $true }
  return -not (@('memo', 'cache') -contains [string]$Source)
}

function Test-AutoBucketSqlActive {
  return [bool]((Get-Variable -Name AutoBucketSql -Scope Script -ErrorAction SilentlyContinue) -and $null -ne $script:AutoBucketSql)
}

function Initialize-AutoBucketSqlStore {
  <#
    Run start, Pro: the bucket counts of this template come from the database. In order: the one-time import of the counts
    the install learned before (-ImportCache, only when the template was never imported); "Reset query split memory"
    (-ResetAll: every count of the template is forgotten); the one-time resets an Admin staged (consumed ONCE, recorded
    with this run's id); then the template's counts and the reports' history. Returns @{ Imported; Resets; Entries;
    Offline }. When the database cannot be read the run goes on with nothing remembered and keeps nothing (Offline) --
    never with counts from anywhere else.
  #>
  param(
    [Parameter(Mandatory=$true)][scriptblock]$Invoke,
    [Parameter(Mandatory=$true)][string]$Template,
    [string]$RunId,
    [hashtable]$ImportCache,
    [string]$ImportSource = 'the counts kept before this version',
    [switch]$ResetAll
  )
  $res = [pscustomobject]@{ Imported = -1; Resets = @(); Entries = 0; Offline = $false; Problem = ''; TestRowsRemoved = 0 }
  $script:AutoBucketSql = [pscustomobject]@{ Invoke = $Invoke; Template = $Template; RunId = $RunId; State = @{}; Saved = @{}; History = @{}; Offline = $false }
  try {
    if (-not (Test-SIRaBucketTables -Invoke $Invoke)) { throw 'the database has no bucket sizing tables yet (the update applies them)' }
    if ($null -ne $ImportCache) { $res.Imported = Import-SIRaBucketCountsOnce -Invoke $Invoke -Template $Template -Cache $ImportCache -Source $ImportSource }
    if ($ResetAll) { $null = & $Invoke (Get-SIRaBucketSql 'DeleteTemplate') @{ Template = $Template } 'nonquery' }
    $res.Resets = @(Invoke-SIRaBucketResetConsume -Invoke $Invoke -Template $Template -RunId $RunId)
    # #833: the state the report certification's test template left behind, once no run has used it for a week (guarded)
    $res.TestRowsRemoved = Invoke-SIRaBucketTestTemplatePrune -Invoke $Invoke -Template $Template
    $state = Read-SIRaBucketState -Invoke $Invoke -Template $Template
    $script:AutoBucketSql.State = $state
    $script:AutoBucketSql.Saved = ConvertTo-HashtableDeep -InputObject $state
    $script:AutoBucketSql.History = Read-SIRaBucketHistory -Invoke $Invoke -Template $Template
    $res.Entries = @($state.Keys | Where-Object { -not ([string]$_).StartsWith('__') }).Count
  } catch {
    $script:AutoBucketSql.Offline = $true
    $res.Offline = $true
    $res.Problem = [string]$_.Exception.Message
  }
  # a reset also forgets what this run already holds in memory
  if (@($res.Resets).Count -and (Get-Variable -Name AutoBucketMemo -Scope Script -ErrorAction SilentlyContinue)) {
    $memo = @{}; foreach ($k in @($script:AutoBucketMemo.Keys)) { $memo[[string]$k] = 1 }
    $ref = [ref]$memo; $null = Remove-AutoBucketReportEntries -Cache $ref -ReportNames @($res.Resets)
    foreach ($k in @($script:AutoBucketMemo.Keys)) { if (-not $ref.Value.ContainsKey([string]$k)) { [void]$script:AutoBucketMemo.Remove($k) } }
  }
  return $res
}

function Save-AutoBucketSqlState {
  <# Write-AutoBucketCache with the database: the run's copy becomes -CacheObject and only what changed is sent. #>
  param([Parameter(Mandatory=$true)][object]$CacheObject)
  $new = ConvertTo-HashtableDeep -InputObject $CacheObject
  if ($new -isnot [hashtable]) { $new = @{} }
  $script:AutoBucketSql.State = $new
  if ($script:AutoBucketSql.Offline -or -not $script:AutoBucketSql.Invoke) { return }
  try {
    $null = Save-SIRaBucketStateDiff -Invoke $script:AutoBucketSql.Invoke -Template $script:AutoBucketSql.Template -Before $script:AutoBucketSql.Saved -After $new
    $script:AutoBucketSql.Saved = ConvertTo-HashtableDeep -InputObject $new
  } catch {
    Write-Warning ("the bucket counts could not be saved in the database ({0}); the next run sizes the changed reports again" -f $_.Exception.Message)
  }
}

# ---- the measured result of one report's run (one bucket at a time; nothing of the rows is kept) --------------------

function Reset-AutoBucketMeasure {
  # SplitRows / SplitBytes: the rows and bytes of the lookups that were split per bucket, summed over the report's buckets
  # (what more buckets divide); MaxFixedBytes: the largest part of one request that more buckets do not shrink. All three
  # are THIS report's own (#697 (2)) -- never the run-wide largest values of the hybrid inlining.
  # #737: Slices / MaxBucketSeconds -- how many slices were measured and the longest one took (Test-RABucketRunFarBelow).
  $script:AutoBucketMeasure = [pscustomobject]@{ ResultRows = 0L; MaxBucketRows = 0L; MaxBucketBytes = 0L; MaxRequestBytes = 0L; SplitRows = 0L; SplitBytes = 0L; MaxFixedBytes = 0L; Slices = 0; MaxBucketSeconds = 0.0 }
}

function Get-AutoBucketRowBytes {
  <# PURE. The size of an answer of -Rows rows, estimated from up to 20 of them as compact JSON (what the service sends). #>
  param([long]$Rows, [object[]]$Sample = @())
  if ($Rows -le 0) { return 0L }
  $s = @($Sample | Where-Object { $null -ne $_ } | Select-Object -First 20)
  if ($s.Count -eq 0) { return 0L }
  $len = 0L
  try { $len = [long]([string](ConvertTo-Json -InputObject $s -Depth 5 -Compress)).Length } catch { return 0L }
  return [long][Math]::Ceiling(($len / [double]$s.Count) * $Rows)
}

function Add-AutoBucketMeasure {
  <# One bucket's answer: its rows, the estimated bytes of its answer and the bytes of its request (0 = not known).
     -RequestShape (#697 (2)): the shape of the request this bucket really sent (Get-RAHybridRequestShape: BodyBytes,
     FixedBytes, Lookups with Rows / WireBytes / Whole). When given, the request is measured from it, not from -RequestBytes. #>
  param([long]$Rows, [object[]]$Sample = @(), [long]$RequestBytes = 0, $RequestShape = $null, [double]$Seconds = 0)
  if (-not (Get-Variable -Name AutoBucketMeasure -Scope Script -ErrorAction SilentlyContinue) -or $null -eq $script:AutoBucketMeasure) { Reset-AutoBucketMeasure }
  $m = $script:AutoBucketMeasure
  foreach ($n in 'SplitRows', 'SplitBytes', 'MaxFixedBytes') { if (-not $m.PSObject.Properties[$n]) { $m | Add-Member -NotePropertyName $n -NotePropertyValue 0L } }
  if (-not $m.PSObject.Properties['Slices']) { $m | Add-Member -NotePropertyName Slices -NotePropertyValue 0 }
  if (-not $m.PSObject.Properties['MaxBucketSeconds']) { $m | Add-Member -NotePropertyName MaxBucketSeconds -NotePropertyValue 0.0 }
  $m.Slices = [int]$m.Slices + 1
  if ($Seconds -gt [double]$m.MaxBucketSeconds) { $m.MaxBucketSeconds = [double]$Seconds }
  $m.ResultRows += [long]$Rows
  if ($Rows -gt $m.MaxBucketRows) { $m.MaxBucketRows = [long]$Rows }
  $b = Get-AutoBucketRowBytes -Rows $Rows -Sample $Sample
  if ($b -gt $m.MaxBucketBytes) { $m.MaxBucketBytes = $b }
  $body = 0L
  if ($null -ne $RequestShape -and [long]$RequestShape.BodyBytes -gt 0) {
    $body = [long]$RequestShape.BodyBytes
    $fixed = [long]$RequestShape.FixedBytes
    if ($fixed -gt $m.MaxFixedBytes) { $m.MaxFixedBytes = $fixed }
    foreach ($l in @(@($RequestShape.Lookups) | Where-Object { $null -ne $_ })) {
      if ([bool]$l.Whole) { continue }
      $m.SplitRows += [long]$l.Rows
      $m.SplitBytes += [long]$l.WireBytes
    }
  } else { $body = [long]$RequestBytes }
  if ($body -gt $m.MaxRequestBytes) { $m.MaxRequestBytes = $body }
}

function Get-AutoBucketRequestMeasure {
  <# PURE. The report's own request numbers for its history row (#697 (2)): @{ Rows; BytesPerRow; OverheadBytes } of the
     lookups split per bucket, from the run's measure. Zeros when nothing was split. #>
  param($Measure)
  $o = [pscustomobject]@{ Rows = 0L; BytesPerRow = 0; OverheadBytes = 0 }
  if ($null -eq $Measure -or -not $Measure.PSObject.Properties['SplitRows']) { return $o }
  $o.OverheadBytes = [int][Math]::Min([long][int]::MaxValue, [long]$Measure.MaxFixedBytes)
  if ([long]$Measure.SplitRows -gt 0 -and [long]$Measure.SplitBytes -gt 0) {
    $o.Rows = [long]$Measure.SplitRows
    $o.BytesPerRow = [int][Math]::Max(1, [Math]::Ceiling([double]$Measure.SplitBytes / [double]$Measure.SplitRows))
  }
  return $o
}

# ---- per report: where the count starts, and what the run leaves behind ---------------------------------------------

function Get-AutoBucketStartPlan {
  <#
    Before a report is sized: STEP 4 -- a report with no remembered count for its current query (after a reset, or a
    changed query) that HAS a measured earlier run starts from the count worked out from that measurement
    (Get-SIRaBucketCountFromMeasure) instead of 1, 2, 4, 8. Returns @{ MinCount; Measured } (Measured = $null: start as
    before, from the configured count).
    #833 A CHANGED QUERY STARTS FROM ITS MEASURED NEED, not from the count of its earlier query: the engine asks this plan
    FIRST and takes the earlier query's count (Get-AutoBucketPreviousCount) only when nothing was ever measured. The need
    is the report's last measured run against half of every limit -- rows, bytes, the request AND the slice time (a run
    that found no rows is a measurement too). A count a failed query proved is kept only when it was proved by the
    CURRENT query; a measurement without the slice time (a history row from before #833) still keeps the counts the
    report's earlier queries proved, because without the time a count set by compute would not show.
    -Floor: the lowest count the report may run at (Get-AutoBucketLearnFloor: 1 unless its template sets a count);
    -Start: the configured count -- where a first run with nothing measured starts (and the floor of the proof of a probe).
    Without -Start both are -Floor, as before.
  #>
  param([string]$ReportName, [string]$QueryKey, [int]$Floor, [int]$Cap, [int]$Start = 0)
  if ($Start -lt 1) { $Start = $Floor }
  if ($Floor -lt 1) { $Floor = 1 }
  $plan = [pscustomobject]@{ MinCount = $Start; Measured = $null }
  if (-not (Test-AutoBucketSqlActive)) { return $plan }
  # a remembered count: it is taken as it is -- down to the floor (the down plan decides whether it comes down); with the
  # store off nothing is read back, so a probe starts where it always did
  $remembered = if ([bool]$global:AutoBucketCache) { $Floor } else { $Start }
  if ($script:AutoBucketSql.State.ContainsKey($QueryKey)) { $plan.MinCount = $remembered; return $plan }
  if ($script:AutoBucketMemo -and $script:AutoBucketMemo.ContainsKey($QueryKey)) { $plan.MinCount = $Floor; return $plan }
  $h = @($script:AutoBucketSql.History[$ReportName] | Where-Object { $_ })
  # #880: a NOT COMPLETE run's measurement is partial -- it sizes nothing
  $m = $h | Where-Object { [string]$_.Decided -ne 'incomplete' } | Where-Object { [double]('0' + [string]$_.ResultRows) -gt 0 -or [double]('0' + [string]$_.RequestRows) -gt 0 -or [double]('0' + [string]$_.MaxRequestBytes) -gt 0 -or
                           ($_.PSObject.Properties['MaxBucketSeconds'] -and [double]('0' + [string]$_.MaxBucketSeconds) -gt 0) } | Select-Object -First 1
  if (-not $m) { return $plan }
  $c = Get-SIRaBucketCountFromMeasure -Measure $m
  if ($null -eq $c) { return $plan }
  # #697 (2): never below a count a failed query proved necessary for this report (a raise, or a probe that climbed);
  # #833: proved by THIS query -- unless the measurement has no slice time
  $timed = ($m.PSObject.Properties['MaxBucketSeconds'] -and [double]('0' + [string]$m.MaxBucketSeconds) -gt 0)
  $fp = ''
  if ($timed) { $parts = Split-SIRaBucketKey -Key $QueryKey; if ($parts) { $fp = [string]$parts.Fingerprint } }
  $proven = if ($timed -and -not $fp) { 0 } else { Get-SIRaBucketProvenCount -History $h -Floor $Start -Fingerprint $fp }
  $min = [int][Math]::Min([Math]::Max(1, $Cap), [Math]::Max([Math]::Max($Floor, [int]$c), $proven))
  [pscustomobject]@{ MinCount = $min; Measured = [int]$c }
}

function Get-AutoBucketLearnFloor {
  <#
    #833 PURE. THE LOWEST COUNT A REPORT'S LEARNED SIZE MAY COME DOWN TO. The configured count (2 for every report,
    SI_AutoBucketDefaultDetailed for Detailed) is where a report STARTS when nothing is known -- it was also used as the
    floor of every way down, so a report could never go below 2 (audit #56.1, 2026-08-10: "the bucket floor is hardcoded
    2"; live 2026-10-20: 58 of 69 Detailed reports returned under 100 rows, 18 none, every one ran 2+ buckets). That floor
    was not a safety rule: nothing about one slice is less safe than two -- the slice filter, the lookups, the overflow
    split and the loss count work the same at 1 (one slice = the whole query; a too-large answer is split into 4 as
    always). Only a count the report's own template sets (-TemplateCount, the YAML BucketCount: "you don't need to try
    less than 64", v2.2.281) stays a floor. Without the Pro database (no history, no measurement) the floor is the
    configured count as before.
  #>
  param([int]$Configured = 2, [int]$TemplateCount = 0, [switch]$Measured)
  if ($TemplateCount -gt 0) { return [int]$TemplateCount }
  if (-not $Measured) { return [int][Math]::Max(1, $Configured) }
  return 1
}

function Get-AutoBucketDownPlan {
  <# For a report whose count came from what was remembered: STEP 5 (#697 (2)) first -- a count no failure proved comes
     back down towards what the report's last run measured, at most half per run; else STEP 3 -- half the count when its
     last 3 runs were far below every limit.
     #833: -Floor is the learn floor (Get-AutoBucketLearnFloor); -ProbeFloor the configured count (a probe above it proved
     its count); -QueryKey keeps the proof to the report's current query. #>
  param([string]$ReportName, [int]$Count, [int]$Floor, [int]$ProbeFloor = 0, [string]$QueryKey = '')
  if (-not (Test-AutoBucketSqlActive)) { return [pscustomobject]@{ Count = $Count; Down = $false; Why = '' } }
  $h = @($script:AutoBucketSql.History[$ReportName])
  $fp = ''
  if ($QueryKey) { $parts = Split-SIRaBucketKey -Key $QueryKey; if ($parts) { $fp = [string]$parts.Fingerprint } }
  $s = Get-SIRaBucketShrinkCount -Count $Count -Floor $Floor -History $h -ProbeFloor $ProbeFloor -Fingerprint $fp
  if ($s.Down) { return $s }
  Get-SIRaBucketDownCount -Count $Count -Floor $Floor -History $h
}

function Complete-AutoBucketReport {
  <#
    After a report's successful run: its history row (the count it started with and ended with, how it was decided, the
    measured result, the usual count and the jump flag), and STEP 2 -- the jump warning (Test-SIRaBucketJump) collected for
    the run's one guard event. Returns the jump reason ('' = none). Never throws.
    #833: -FinalCount is the count KEPT for the next run (the same number the run's last sizing line says and the state
    holds); a count kept LOWER than the run started with is recorded as 'down' (it was sized down from this run's
    measurement), never as 'cache'. -RanCount: the count the measured slices ran at; with the slice time (the longest
    slice) it is the time measurement the next sizing uses (Get-SIRaBucketCountFromMeasure).
  #>
  # #880 -Incomplete: the report ended NOT COMPLETE -- recorded as 'incomplete' (never 'raised': it proves no count, and its
  # partial measurement sizes nothing; Get-SIRaBucketShrinkCount / Get-SIRaBucketDownCount / Get-AutoBucketStartPlan skip it).
  param([string]$ReportName, [string]$QueryKey, [int]$StartCount, [int]$FinalCount, [string]$Source,
        [long]$RequestRows = 0, [int]$RequestBytesPerRow = 0, [int]$RequestOverheadBytes = 0, [int]$RanCount = 0, [switch]$Incomplete)
  if (-not (Test-AutoBucketSqlActive)) { return '' }
  if (-not (Get-Variable -Name AutoBucketJumps -Scope Script -ErrorAction SilentlyContinue) -or $null -eq $script:AutoBucketJumps) { $script:AutoBucketJumps = New-Object System.Collections.Generic.List[object] }
  $why = ''
  try {
    $earlier = @(@($script:AutoBucketSql.History[$ReportName]) | Where-Object { $_ } | ForEach-Object { [int]$_.BucketCount })
    $usual = Get-SIRaBucketUsual -Counts $earlier
    $why = Test-SIRaBucketJump -Count $FinalCount -Usual $usual
    $decided = if ($Incomplete) { 'incomplete' } elseif ($FinalCount -gt $StartCount) { 'raised' } elseif ($FinalCount -lt $StartCount) { 'down' } else {
      switch ($Source) { 'memo' { 'cache' } 'cache' { 'cache' } 'hint' { 'cache' } 'probe' { 'probe' } 'measured' { 'measured' } 'down' { 'down' } default { 'configured' } }
    }
    $m = if ((Get-Variable -Name AutoBucketMeasure -Scope Script -ErrorAction SilentlyContinue) -and $script:AutoBucketMeasure) { $script:AutoBucketMeasure } else { $null }
    $slices = if ($m -and $m.PSObject.Properties['Slices']) { [int]$m.Slices } else { 0 }
    $secs = if ($slices -gt 0 -and $m.PSObject.Properties['MaxBucketSeconds']) { [int][Math]::Max(1, [Math]::Ceiling([double]$m.MaxBucketSeconds)) } else { $null }
    $parts = Split-SIRaBucketKey -Key $QueryKey
    $row = [pscustomobject]@{
      ReportName = $ReportName; Fingerprint = $(if ($parts) { $parts.Fingerprint } else { $null }); RunId = $script:AutoBucketSql.RunId
      StartCount = $StartCount; BucketCount = $FinalCount; Decided = $decided
      ResultRows = $(if ($m) { $m.ResultRows } else { $null }); MaxBucketRows = $(if ($m) { $m.MaxBucketRows } else { $null })
      MaxBucketBytes = $(if ($m) { $m.MaxBucketBytes } else { $null }); MaxRequestBytes = $(if ($m -and $m.MaxRequestBytes -gt 0) { $m.MaxRequestBytes } else { $null })
      RequestRows = $(if ($m -and $m.MaxRequestBytes -gt 0 -and $RequestRows -gt 0) { $RequestRows } else { $null })
      RequestBytesPerRow = $(if ($m -and $m.MaxRequestBytes -gt 0 -and $RequestBytesPerRow -gt 0) { $RequestBytesPerRow } else { $null })
      RequestOverheadBytes = $(if ($m -and $m.MaxRequestBytes -gt 0 -and $RequestOverheadBytes -gt 0) { $RequestOverheadBytes } else { $null })
      UsualCount = $usual; Jump = [bool]$why
      MaxBucketSeconds = $secs; RanCount = $(if ($null -ne $secs -and $RanCount -ge 1) { $RanCount } else { $null })
    }
    if ($why) { $script:AutoBucketJumps.Add([pscustomobject]@{ Report = $ReportName; Count = $FinalCount; Usual = $usual; Why = $why }) }
    if (-not $script:AutoBucketSql.Offline -and $script:AutoBucketSql.Invoke -and (Test-AutoBucketWriteAllowed)) { Add-SIRaBucketHistory -Invoke $script:AutoBucketSql.Invoke -Template $script:AutoBucketSql.Template -Row $row }
  } catch {
    Write-Warning ("the bucket history of '{0}' could not be recorded: {1}" -f $ReportName, $_.Exception.Message)
  }
  return $why
}