#######################################################################################################
#  SecurityInsight - Risk Analysis engine
#  Advanced Hunting query submission, retry policy and deterministic-failure classification.
#
#  Invoke-GraphHuntingQuery alone - ~600 lines, the largest function left in the engine after the
#  earlier tranches. This is where a query is actually submitted to Advanced Hunting, where the
#  900s HttpClient ceiling is recognised as "too big" rather than transient (audit #24), and where
#  the retry-vs-escalate decision is made. Moved verbatim; changing any of that is a SEPARATE change.
#
#  AUDIT #16: moved VERBATIM out of Invoke-RiskAnalysis.ps1 on 2026-08-05. Dot-sourced back in at
#  exactly the position it occupied, so load order is unchanged. Every function body is
#  byte-identical to before the move - verified with tests/Get-EngineFunctionInventory.ps1,
#  which compares a SHA-256 of each function's source text before and after.
#
#  Do NOT add $PSScriptRoot-dependent code here: in this file it resolves to _shared/, one level
#  deeper than the engine root the main script derives $siRoot from.
#######################################################################################################

# #690 (37): the Log Analytics route reads through the parted reader (a result too large for one answer is read in parts)
if (-not (Get-Command -Name Invoke-LogAnalyticsKqlQueryParted -ErrorAction SilentlyContinue)) { . (Join-Path $PSScriptRoot 'RA-LaPartedRead.ps1') }

# ---------------------------------------------------------------------------------------------------
# 🔑 THE RECOGNISED PLATFORM-FAILURE PREFIXES — ONE LIST, TWO CONSUMERS.
#
# Advanced Hunting appends the SAME generic sentence, "Fix semantic errors in your query.", to
# failures that have nothing to do with the query. The signal is the PREFIX; that tail is boilerplate.
# Two such prefixes have now been measured five weeks apart, and each cost a report's findings plus a
# session spent looking for a fault in a query that had none:
#
#   audit #99  (2026-09-01)  ScalarEvaluator.Evaluate failed: Query cancelled on creation:. Fix semantic…
#                            Its TWIN bucket, same report same run, ran the SAME QUERY TEXT successfully
#                            seven times after sub-bucketing.
#   audit #106 (2026-09-03)  Errors occurred while resolving remote entities. Failed to resolve name or
#                            pattern 'TvmSCASnapshotCooked' … Fix semantic errors in your query.
#                            `TvmSCASnapshotCooked` appears NOWHERE in this repo — it is Microsoft's
#                            internal entity behind the DOCUMENTED DeviceTvmSecureConfigurationAssessment
#                            tables the report queries. Same query: 449 rows, then 0, then 448 on re-run.
#
# 📌 A LIST RATHER THAN A THIRD `-or`. Adding one literal per incident is precisely how this recurred;
# naming the set once, in one place, is what makes the next one a one-line addition here instead of a
# second divergent fix. **Both** classification sites consume it — this file's per-bucket test and the
# report-level verdict in Invoke-RiskAnalysis.ps1 — because #99 proved that fixing only the first
# resizes the bucket correctly and STILL tells the operator the query is permanently broken.
#
# 🔒 THE v2.2.455 SEPARATION IS NOT WIDENED. A genuine mixed-type case() or a plain syntax error carries
# none of these prefixes, still fails on attempt 1, and still says the query must be fixed.
$script:RAPlatformFailurePrefixes = @(
    'Query cancelled on creation'                       # audit #99  -- a cancellation, not a defect
    'ScalarEvaluator\.Evaluate failed'                  # audit #99  -- its companion form
    'Errors occurred while resolving remote entities'   # audit #106 -- service-side entity resolution
)

function Get-RAPlatformFailurePrefixPattern {
    <#
        The recognised platform-failure prefixes as ONE alternation, for `-match`.
        Exposed as a function so both classification sites share one definition and a test can
        assert they do -- rather than each site carrying its own copy of the regex.
    #>
    ($script:RAPlatformFailurePrefixes -join '|')
}

function Test-RAHuntingNotProvisioned {
    <# PURE. Graph's answer when the tenant has no Microsoft Defender XDR (advanced hunting is not provisioned). #>
    param([AllowNull()][AllowEmptyString()][string]$Message)
    return ([string]$Message -match 'Account is not provisioned|SI-RA: advanced hunting is not provisioned')
}

function Test-RANoDataSource {
    <#
        PURE. A query that has NO data source in this tenant -- not a failure, nothing to lose: Defender XDR advanced
        hunting is not provisioned, or SecurityInsight's own profile table (SI_*_CL) does not exist yet because its
        profiler has never had a row for it (Log Analytics makes a table on its first row; e.g. no devices without
        Defender for Endpoint), or Defender vulnerability management's tables (DeviceTvm*) are not in this tenant (no licence for it -- customer A 2026-10-15: Device_Missing_CVEs / Device_Recommendations alerted as query defects). Live 2026-10-06, Community rehearsal. Any other missing name is still a query defect.
    #>
    param([AllowNull()][AllowEmptyString()][string]$Message)
    # #876: a 'union' leaf says "table expression", a 'where' leaf "table or column expression" -- both: the table is not there
    return ((Test-RAHuntingNotProvisioned -Message $Message) -or ([string]$Message -match "Failed to resolve table (?:or column )?expression named 'SI_[A-Za-z0-9_]+_CL'") -or ([string]$Message -match "Failed to resolve table (?:or column )?expression named 'DeviceTvm[A-Za-z]+'"))
}

function Get-RAHuntingNotProvisionedMessage {
    'SI-RA: advanced hunting is not provisioned in this tenant (no Microsoft Defender XDR) -- this query has no data source here'
}

function Test-RAQueryNeedsAdvancedHunting {
    <# PURE. True when the query reads a Defender table at a TABLE position (start of a statement, after a pipe, '(',
       ',', '=', union / join) that advanced hunting always has and a Log Analytics workspace only has when Defender
       streams it there -- and reads no Sentinel-only table (those keep the Log Analytics route). Exact table names, never
       a prefix: a column such as DeviceKey or a let name such as DeviceInfoLatest is not a table. Comments and string
       literals are ignored. #>
    param([string]$Query)
    if ([string]::IsNullOrWhiteSpace($Query)) { return $false }
    $s = [regex]::Replace($Query, '//[^\r\n]*', '')
    $s = [regex]::Replace($s, '@?"(?:[^"\\\r\n]|\\.)*"', '""')
    $s = [regex]::Replace($s, "@?'(?:[^'\\\r\n]|\\.)*'", "''")
    $anchor = '(?m)(?:^|\||\(|,|=|\bunion\b|\bjoin\b(?:\s+kind\s*=\s*\w+)?)\s*'
    $ahOnly = '(?:DeviceInfo|DeviceNetworkInfo|DeviceLogonEvents|DeviceProcessEvents|DeviceNetworkEvents|DeviceFileEvents|DeviceRegistryEvents|DeviceEvents|DeviceImageLoadEvents|DeviceFileCertificateInfo|DeviceTvm[A-Za-z]+|DeviceBaselineCompliance[A-Za-z]+|IdentityInfo|IdentityLogonEvents|IdentityQueryEvents|IdentityDirectoryEvents|IdentityAccountInfo|AlertInfo|AlertEvidence|CloudAppEvents|BehaviorInfo|BehaviorEntities)\b'
    $sentinelOnly = '(?:SigninLogs|AuditLogs|AADNonInteractiveUserSignInLogs|AADServicePrincipalSignInLogs|AADManagedIdentitySignInLogs|AADProvisioningLogs|IntuneAuditLogs|MicrosoftGraphActivityLogs)\b'
    if ($s -notmatch ($anchor + $ahOnly)) { return $false }
    if ($s -match ($anchor + $sentinelOnly)) { return $false }
    return $true
}

function Invoke-RAResolveLookups {
    <#
        #674 FAIL CLOSED. The query's SecurityInsight lookups (its let-bindings and any other SI_*_CL table it names) read
        from Log Analytics and put into the query. A read that fails is NOT left for a fallback any more: the old fallback
        (a whole-table copy, then the query as it was) ended in Microsoft Defender, which does not have these tables, where
        `union isfuzzy` turned the lookup EMPTY and the report came back Complete -- with the recommendations the Defender
        recommendation report also lists, or without its CI / CMDB values. Now that read failing throws the "lookup
        unavailable" error (the report is not complete, plainly said). A table that does not exist in Log Analytics at all
        is passed on unchanged: that is the existing "no data source in this tenant" rule.
        -Resolve / -Shadow are seams for tests.
    #>
    param([Parameter(Mandatory)][string]$Query, [Parameter(Mandatory)][string]$WorkspaceResourceId, [int]$BucketCount = 0, [int]$BucketIndex = 0,
          [scriptblock]$Resolve, [scriptblock]$Shadow)
    try {
        $Query = if ($Resolve) { & $Resolve $Query } else { Resolve-ProfileCLLetBlocks -Query $Query -WorkspaceResourceId $WorkspaceResourceId -BucketCount $BucketCount -BucketIndex $BucketIndex }
    } catch {
        $e = ConvertTo-RALookupUnavailableError -What 'its lookups' -Err $_
        if ($e) { Write-Err2 ("[scope] {0}" -f $e.Message); throw $e }
        throw
    }
    try {
        $Query = if ($Shadow) { & $Shadow $Query } else { Add-CLSnapshotShadows -Query $Query -WorkspaceResourceId $WorkspaceResourceId }
    } catch {
        $e = ConvertTo-RALookupUnavailableError -What 'a SecurityInsight table it reads' -Err $_
        if ($e) { Write-Err2 ("[shadow] {0}" -f $e.Message); throw $e }
        throw
    }
    return $Query
}

function Invoke-GraphHuntingQuery {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Query,
        [int]$ReconnectMaxAgeMinutes = 45,
        [int]$MaxRetries = 4,
        # #673 plan B: set on the inner call, so the query plan B built is sent as it is
        [switch]$SIDefenderFilterDone
    )

    # #673 PLAN B (SI_RA_DefenderFilterInEngine / SI_RA_DefenderFilterCompare, in-engine ON by default since rc2, compare off -- REMOVE-ME): the
    # Azure recommendation reports' Defender de-duplication is taken out of the query and done against the run's Defender
    # list in SQL (RA-DefenderFilter.ps1). Off, or for any other query, nothing here changes.
    if (-not $SIDefenderFilterDone -and (Get-Command -Name Get-RADefenderFilterPlan -ErrorAction SilentlyContinue)) {
        $__dfcPlan = Get-RADefenderFilterPlan -Query $Query
        if ($null -ne $__dfcPlan) {
            $__dfcRe = $ReconnectMaxAgeMinutes; $__dfcMr = $MaxRetries
            return (Invoke-RADefenderFilterAnswer -Plan $__dfcPlan -Core { param($q) Invoke-GraphHuntingQuery -Query $q -ReconnectMaxAgeMinutes $__dfcRe -MaxRetries $__dfcMr -SIDefenderFilterDone })
        }
        # an answer of any other query hands nothing off: no number of an earlier answer may be booked against it
        $script:RADfcLast = $null
    }

    # 2026-05-02 -- 2-phase post-augment plan holder. Populated by Resolve-ProfileAugmentPlan
    # in the EG+CL hybrid block below, consumed after AH submission to attach alias cols
    # to returned rows from a single LA snapshot per (TableName, RightKey). Empty array
    # means no augment needed (LA-direct, EG-only, or hybrid-fallback path).
    $augmentPlans      = @()
    $augmentWsForCL    = $null

    # The "every attempt hit the ceiling" verdict belongs to THIS call. Cleared on entry so a failure on
    # the LA-direct, lake or auth path -- none of which reach the advanced-hunting loop that sets it --
    # can never be read with a PREVIOUS call's value. A stale $true made an unrelated 429 or token
    # expiry look like a 900s timeout: the bucket was split (more calls against a throttling API) and
    # the re-auth branch was skipped.
    $script:_LastGraphHuntingAllTimedOut = $false
    # The measured shape of the request (what more slices can shrink, what they cannot) belongs to THIS call too:
    # a size refusal must never be judged against the previous query's numbers.
    $script:_RAHybridLastRequest = $null
    $script:_RAHybridLookups     = $null
    $script:_RALookupNeededKeySets = $null

    # Per-query reset of the deferred/superseded multi-path log buffer (BUG B). Earlier
    # failed routes (lake) get stashed silently; a later success emits one INFO, a total
    # failure emits one WARN. Without this reset the buffer would leak across queries.
    Reset-SupersededAttempts

    # SEM0001 guard (root-cause): cast known-dynamic CL group keys (cmdb*) in every
    # `summarize ... by` clause to tostring() BEFORE any submission path runs. This is the
    # single chokepoint all report queries flow through (lake / AH / LA-direct all branch
    # off below), so casting here once covers them all -- including the engine-built
    # PublicIP open-port/vuln summarize and the 6 cross-domain Attack_Paths Summary reports.
    $Query = Add-DynamicGroupKeyCasts -Query $Query

    # CL-table routing: any query that references SI_*_CL chooses between two paths --
    #   PURE-LA  (no Defender XDR tables) -> submit the whole query directly to Log Analytics.
    #            No let-block, no advanced-hunting round trip, no body-size limit.
    #   MIXED    (CL + Device* / Identity* / ExposureGraph* / ...) -> AH route IF the CL table
    #            is mirrored into AH; else LA-direct with cross-workspace let for the XDR side.
    $customClPattern = '\bSI_[A-Za-z][A-Za-z0-9]*(?:_[A-Za-z][A-Za-z0-9]*)*_CL\b'
    if ($Query -match $customClPattern) {
        # Probe AH first: if every referenced SI_*_CL table is visible in advanced hunting,
        # submit as-is (unified Defender XDR portal customers). Otherwise fall back to
        # LA-direct (the only path that works without Sentinel data lake mirroring).
        $clTableHits = @([regex]::Matches($Query, $customClPattern) | ForEach-Object { $_.Value } | Sort-Object -Unique)
        $available = $true
        # EG-references force AH. ExposureGraphNodes/Edges ONLY exist in advanced
        # hunting (no LA mirroring path), so any query referencing them MUST route to AH. The
        # AH probe for SI_*_Profile_CL can return false-negative when the SPN's Graph token
        # can't see CL even though it IS mirrored to AH for interactive users -- that probe
        # failure mustn't push us to LA when EG is in the query (LA would then EG-skip and
        # we'd produce zero rows). Skip the probe in this case; if CL truly isn't in AH for
        # this tenant, AH returns a clear "Failed to resolve table" error which the retry/
        # schema-classifier downstream surfaces with the right remediation.
        $queryReferencesEG = ($Query -match '\bExposureGraph(?:Nodes|Edges)\b')
        # 🔴 A DEFENDER TABLE THAT ONLY ADVANCED HUNTING HAS GOES THE SAME WAY AS THE GRAPH. A report that joins the CI
        # (SI_CI_CL) with Defender vulnerability management (DeviceTvm*, DeviceInfo) and no graph table was sent to Log
        # Analytics with a cross-workspace let-block -- which only works where Defender streams those tables into the
        # Sentinel workspace. Where it does not, the let-block failed and the single-workspace retry failed on the missing
        # table ("Failed to resolve table or column expression named 'DeviceInfo'"): both Device_Recommendations reports
        # lost every bucket on one run. Advanced hunting always has them; the CI is inlined there exactly as for the graph.
        # A query that also reads a Sentinel-only table (SigninLogs, AuditLogs, ...) keeps the Log Analytics route.
        $queryNeedsAdvancedHunting = $queryReferencesEG -or (Test-RAQueryNeedsAdvancedHunting -Query $Query)
        if ($queryNeedsAdvancedHunting) {
            $wsForCL = if (-not [string]::IsNullOrWhiteSpace([string]$global:SI_WorkspaceResourceId)) { [string]$global:SI_WorkspaceResourceId } else { [string]$global:WorkspaceResourceId }

            # #674 -- a hand-off list that reads EMPTY while its table should hold the latest list (a new install's first
            # ~45 minutes, or a count that cannot be had) ends this report as not complete, BEFORE any route is chosen, so
            # the three set-ups (Defender XDR only / + Sentinel / + Sentinel data lake) decide it the same way: from SI's
            # own workspace. An intentionally empty hand-off (#278: the receiving report is not in the run) has no SI table
            # in its block and is not looked at. Outside every try below: this error must reach the report loop.
            if (Get-Command -Name Assert-RAHandoffLookupReadable -ErrorAction SilentlyContinue) {
                Assert-RAHandoffLookupReadable -Query $Query -WorkspaceResourceId $wsForCL
            }

            # PRIMARY PATH: Sentinel data lake KQL API. Single query covers EG+CL natively.
            # Microsoft docs (sentinel/datalake/kql-queries-api) confirms SPN auth IS
            # supported; the only constraint is that Entra ID / Defender XDR Unified RBAC
            # roles can't be used to grant the SPN -- it must be granted via workspace
            # Azure RBAC. If the SPN doesn't have access yet, we get InvalidDatabaseInQuery
            # and automatically fall back to the hybrid pre-fetch+inline path below.
            # Cache the unavailability after first failure so we don't waste a lake-call
            # per report (100+ queries x ~1s each = noticeable latency).
            # a part asked AHEAD (RA-PartsInParallel.ps1) is only ever an advanced-hunting request: the lake is not asked ahead
            if (-not $script:_SentinelLakeUnavailable -and $null -ne $script:SIHuntingPrefetch -and $script:SIHuntingPrefetch.Capture) { throw (Get-SIHuntingNotAheadText) }
            if (-not $script:_SentinelLakeUnavailable) {
                Write-Diag ("[lake] probing Sentinel data lake for {0} ..." -f (Split-Path -Leaf $wsForCL))
                [void](Save-RARenderedQuery -Query $Query -Tag 'lake')
                # 🔑 v2.2.451 -- the lake helper now RETURNS its failure instead of THROWING it, so an
                # un-onboarded lake (the common case) no longer writes a terminating-error block into
                # the customer's transcript. The catch stays as a backstop for a genuine fault; the
                # handling below is identical either way.
                $lakeMsg = $null
                try {
                    $lakeRows = Invoke-SISentinelLakeQuery -Query $Query -WorkspaceResourceId $wsForCL
                    if ($null -ne $lakeRows -and $lakeRows -isnot [array] -and
                        $lakeRows.PSObject -and $lakeRows.PSObject.Properties['_SILakeError']) {
                        $lakeMsg = [string]$lakeRows._SILakeError
                    } else {
                        Write-Ok ("[lake] {0} row(s) returned -- single-query path active." -f (@($lakeRows).Count))
                        # the lake's answer is not checked for a cut at its row limit: a report it answers is counted, never
                        # taken from its slices (Get-RAReportExpectedRows)
                        $script:RALakeAnswered = $true
                        return [pscustomobject]@{ _SIDirectRows = @($lakeRows) }
                    }
                } catch {
                    $lakeMsg = $_.Exception.Message
                }
                if ($lakeMsg) {
                    # Multi-path fallback policy (operator ask): when one path (lake) fails
                    # but a later path (hybrid / AH / LA-direct) SUCCEEDS for the same query,
                    # do NOT emit a WARN for the superseded attempt -- it confuses operators
                    # reading the log into thinking the report failed. Stash the failure
                    # SILENTLY here (full detail preserved) and let Resolve-HuntingFallback*
                    # decide: a single INFO if a later path succeeds, a single WARN only if
                    # EVERY path fails. See Add-SupersededAttempt / Flush-SupersededAttempts.
                    # All known "lake just won't work for this run" patterns are PERMANENT
                    # within a run, so flip the short-circuit flag either way.
                    Add-SupersededAttempt -Path 'lake' -Message ($lakeMsg -split "`n" | Select-Object -First 1)
                    if ($lakeMsg -match 'InvalidDatabaseInQuery|not available for current user|Forbidden|403|Unauthorized|401|TenantNotFound|Tenant not registered|404|Not Found') {
                        Write-Diag ("[lake] unavailable for this run ({0}). Using hybrid fallback for ALL subsequent queries." -f ($lakeMsg -split "`n" | Select-Object -First 1))
                    } else {
                        Write-Diag ("[lake] attempt failed ({0}); trying hybrid fallback (warning deferred until/unless all paths fail)." -f ($lakeMsg -split "`n" | Select-Object -First 1))
                    }
                    $script:_SentinelLakeUnavailable = $true
                }
            }
            # Suppress per-query "lake skipped" chatter once we know it's unavailable.

            # 2026-05-02 -- 2-PHASE POST-AUGMENT (preferred). Detect the canonical
            # `let <var> = SI_*_Profile_CL | ... | project ... ; ... | join (<var>) on ... | extend <alias> = <var-col>`
            # pattern and STRIP it from the query. The remaining query is pure EG (or EG
            # joined with other AH tables) and submits cleanly through AH. After rows
            # return, Invoke-ProfileAugment fetches the CL snapshot ONCE per (TableName,
            # RightKey), builds an in-memory hashtable, and stamps the alias columns
            # post-hoc. Avoids both the 1MB nginx body cap (no inlined datatable) and the
            # malformed-KQL failures the inline path produced for Attack_Paths reports.
            #
            # FALLBACK: when the augment-plan regex doesn't match (e.g. cmdb cols used
            # in a downstream summarize-by, or non-canonical join shape), fall through to
            # the legacy hybrid path: pre-fetch + inline as datatable() + table-shadow.
            try {
                # 🔬 DIAGNOSTIC CAPTURE -- OFF BY DEFAULT, and it exists because this input is the one
                # thing that cannot be reconstructed afterwards (audit #104).
                # `staging/risk-analysis/ra-rendered-*.kql` is written AFTER the legacy path has already
                # inlined the CL snapshot as a `datatable(...)`, i.e. it is the OUTPUT of the decision
                # below, never its input. A fix for the plan resolver validated against those files is
                # validated against nothing: MEASURED 2026-09-03, the UNMODIFIED resolver yields 0 plans
                # on all 79 of them, so a "control" run there cannot distinguish a good change from a
                # bad one. This dump persists the exact string the resolver is handed, plus what it
                # returned, so a fixture can be built and a control can actually mean something.
                # 🔒 Set `$global:SI_RA_DumpAugmentInput = $true` to enable. Writes nothing otherwise --
                # no cost, no files, no log line on the ~6,000 installs that never set it.
                # 📌 REMOVE-ME once #104 is closed and its regression fixture is committed.
                if ($global:SI_RA_DumpAugmentInput) {
                    try {
                        $dumpDir = if ($global:SI_StagingPath) { Join-Path $global:SI_StagingPath 'risk-analysis' }
                                   elseif ($global:OutputPath) { Join-Path $global:OutputPath 'staging\risk-analysis' }
                                   else { Join-Path $env:TEMP 'si-ra' }
                        New-Item -Path $dumpDir -ItemType Directory -Force -ErrorAction SilentlyContinue | Out-Null
                        $dumpStamp = (Get-Date -Format 'yyyyMMdd-HHmmss-fff')
                        # The INPUT, byte-for-byte. This is the fixture.
                        [System.IO.File]::WriteAllText((Join-Path $dumpDir ("ra-augin-{0}.kql" -f $dumpStamp)), [string]$Query, (New-Object System.Text.UTF8Encoding($false)))
                    } catch { }
                }

                $planResult = Resolve-ProfileAugmentPlan -Query $Query

                if ($global:SI_RA_DumpAugmentInput) {
                    try {
                        $sbD = New-Object System.Text.StringBuilder
                        [void]$sbD.AppendLine("=== plans returned: " + @($planResult.Plans).Count + " ===")
                        foreach ($pD in @($planResult.Plans)) {
                            [void]$sbD.AppendLine("")
                            [void]$sbD.AppendLine("--- Var=" + [string]$pD['Var'] + " Table=" + [string]$pD['TableName'] + " LeftKey=" + [string]$pD['LeftKey'] + " RightKey=" + [string]$pD['RightKey'] + " ---")
                            [void]$sbD.AppendLine("ProjectionKql:")
                            [void]$sbD.AppendLine([string]$pD['ProjectionKql'])
                        }
                        [System.IO.File]::WriteAllText((Join-Path $dumpDir ("ra-augin-{0}.plans.txt" -f $dumpStamp)), $sbD.ToString(), (New-Object System.Text.UTF8Encoding($false)))
                    } catch { }
                }

                if ($planResult.Plans -and @($planResult.Plans).Count -gt 0) {
                    $Query           = $planResult.Query
                    $augmentPlans    = @($planResult.Plans)
                    $augmentWsForCL  = $wsForCL
                    Write-Info ("[2phase] active: {0} plan(s); let+join+extend stripped from query, augment will run post-AH" -f $augmentPlans.Count)
                }
            } catch {
                Write-Warn2 ("[2phase] plan resolve failed; falling back to legacy hybrid. Reason: {0}" -f $_.Exception.Message)
            }

            if (-not $augmentPlans -or @($augmentPlans).Count -eq 0) {
                # Legacy hybrid: pre-fetch + inline as datatable() literal.
                # v2.2.325 -- per-bucket CL-snapshot bucketing. Bucket loop in
                # MAIN sets $script:_CurrentBucketCount/_Index before each call;
                # Resolve-ProfileCLLetBlocks then filters the inline datatable
                # to only the rows whose SHA256-bucket matches the current EG
                # bucket. Reduces inline payload from full snapshot to ~1/N per
                # bucket, breaking the 1MB nginx body cap at root cause instead
                # of escalating bucket counts to absurd levels (122,880+ today).
                # Skipped for *_Detailed (composite-key EG buckets misalign with
                # single-key CL buckets) and for unset state (non-bucketed runs).
                # v2.2.331 -- Detailed reports no longer skip CL-bucketing. With
                # composite EG bucket key removed (now device-only for both Summary
                # and Detailed), the alignment that prevented Detailed bucketing
                # in v2.2.325 no longer applies. Both report shapes use the same
                # device-key hash, so a CL row in bucket B always matches its EG
                # counterpart in bucket B.
                $_bk = 0; $_bi = 0
                if ([int]$script:_CurrentBucketCount -gt 1) {
                    $_bk = [int]$script:_CurrentBucketCount
                    $_bi = [int]$script:_CurrentBucketIndex
                }
                # A LOOKUP WITHOUT A PER-ASSET KEY THAT DOES NOT FIT WHOLE IS CUT TO THIS SLICE (RA-ProfileAugment.ps1,
                # "send only the rows the slice can match"). Only a report that declares it (LookupNeededKeys), only a
                # sliced query, and only once the whole lookup has proved too large in this run -- then every slice
                # first asks which keys it can match. Deliberately OUTSIDE the try blocks below: a key query that fails
                # is a failed slice and must reach the bucket loop, not turn into a fallback.
                $script:_RALookupNeededKeySets = $null
                # 659fb78a: the lookups whose whole text was NOT built because it is over the planning budget (Resolve-ProfileCLLetBlocks
                # measures it first, the #730 bounded build) -- a placeholder stands in until the cut below replaces it
                $script:_RALookupCutWanted = @{}
                $__queryBeforeInlining = $Query
                $__keyDecl = @()
                # 659fb78a: the declared cut applies to an UNSLICED query too (one part: the whole query asks for its keys) -- the
                # whole lookup is never sent just to be refused for its size
                if ((Get-Command -Name Get-RALookupNeededKeyDeclarations -ErrorAction SilentlyContinue)) {
                    $__keyDecl = @(Get-RALookupNeededKeyDeclarations -Query $Query)
                }
                if (-not $script:_RALookupReductionOn) { $script:_RALookupReductionOn = @{} }
                $__reduce = @($__keyDecl | Where-Object { $script:_RALookupReductionOn.ContainsKey((Get-RALookupReductionId -Declaration $_)) })
                if ($__reduce.Count -gt 0) {
                    Invoke-RALookupKeyDiscovery -Query $__queryBeforeInlining -WorkspaceResourceId $wsForCL -BucketCount $_bk -BucketIndex $_bi -Declarations $__reduce -ReconnectMaxAgeMinutes $ReconnectMaxAgeMinutes
                }
                # #674 FAIL CLOSED: a lookup that cannot be read ends THIS report as not complete (Invoke-RAResolveLookups);
                # it is never left for a fallback that turns it empty. A table that does not exist is passed on as before.
                $Query = Invoke-RAResolveLookups -Query $Query -WorkspaceResourceId $wsForCL -BucketCount $_bk -BucketIndex $_bi
                # The first slice that shows a declared lookup does not fit whole: what no slice count can shrink is over
                # the size the engine plans a request to. From here on, for this run, that lookup is cut per slice.
                if ($__keyDecl.Count -gt 0 -and $__reduce.Count -lt $__keyDecl.Count) {
                    $__shape = Get-RAHybridRequestShape -Query $Query -BucketCount $_bk
                    $__wholeNow = @(@($__shape.Lookups) | Where-Object { [bool]$_.Whole })
                    $__turnOn = @($__keyDecl | Where-Object { $__d = $_; @($__wholeNow | Where-Object { [string]$_.Name -eq [string]$__d.Lookup }).Count -gt 0 })
                    # 659fb78a: a lookup measured over the budget was never built whole -- that alone turns its cut on
                    $__wanted = @($__keyDecl | Where-Object { $script:_RALookupCutWanted.ContainsKey([string]$_.Lookup) })
                    if ($__wanted.Count -gt 0 -or ($__turnOn.Count -gt 0 -and [long]$__shape.FixedBytes -gt (Get-RAHuntingPlanningBudgetBytes))) {
                        if ($__wanted.Count -gt 0) { $__turnOn = @(@($__turnOn) + @($__wanted | Where-Object { $__x = $_; -not @($__turnOn | Where-Object { [string]$_.Lookup -eq [string]$__x.Lookup }).Count })) }
                        foreach ($__d in $__turnOn) {
                            $script:_RALookupReductionOn[(Get-RALookupReductionId -Declaration $__d)] = $true
                            $__w = @($__wholeNow | Where-Object { [string]$_.Name -eq [string]$__d.Lookup })[0]
                            if ($script:_RALookupCutWanted.ContainsKey([string]$__d.Lookup)) {
                                Write-Info ([string]::Format([System.Globalization.CultureInfo]::InvariantCulture, "the lookup {0} ({1:N0} rows, more than {2}) does not fit whole in every part of the query -- its whole text is not built; from here on each part is first asked which of its keys it can match, and only those rows are sent with it", [string]$__d.Lookup, [int]$script:_RALookupCutWanted[[string]$__d.Lookup], [string](Format-RAByteSize -Bytes ([long](Get-RAHuntingPlanningBudgetBytes)))))
                            } else {
                                Write-Info ([string]::Format([System.Globalization.CultureInfo]::InvariantCulture, "the lookup {0} ({1:N0} rows, {2}) does not fit whole in every part of the query -- from here on each part is first asked which of its keys it can match, and only those rows are sent with it", [string]$__d.Lookup, [int]$__w.Rows, [string](Format-RAByteSize -Bytes ([long]$__w.WireBytes))))
                            }
                        }
                        $__reduce = @($__keyDecl | Where-Object { $script:_RALookupReductionOn.ContainsKey((Get-RALookupReductionId -Declaration $_)) })
                        Invoke-RALookupKeyDiscovery -Query $__queryBeforeInlining -WorkspaceResourceId $wsForCL -BucketCount $_bk -BucketIndex $_bi -Declarations $__reduce -ReconnectMaxAgeMinutes $ReconnectMaxAgeMinutes
                        $Query = $__queryBeforeInlining
                        $Query = Invoke-RAResolveLookups -Query $Query -WorkspaceResourceId $wsForCL -BucketCount $_bk -BucketIndex $_bi
                    }
                }
                $script:_RALookupNeededKeySets = $null
                # 659fb78a FAIL CLOSED: a placeholder (a lookup whose whole text was not built) is NEVER sent -- the cut above replaces
                # it; one still standing is this part's failure, never an empty lookup
                $__ph = @(@($script:_RAHybridLookups) | Where-Object { $null -ne $_ -and $_.ContainsKey('Placeholder') -and [bool]$_.Placeholder })
                if ($__ph.Count -gt 0) { throw (New-Object System.InvalidOperationException(('the lookup {0} was not cut to this part of the query and is too large to send whole -- this part is not sent (its rows are unknown, never read against an empty lookup)' -f (@($__ph | ForEach-Object { [string]$_.Name }) -join ', ')))) }
                # 🔴 BEFORE ANYTHING IS SENT: can this query fit at ANY slice count? The lookups without a key the
                # slices are cut on are copied whole into every slice, and so is the query text -- more slices never
                # shrink that part. When it is by itself at or over what one request can carry, this throws, and the
                # bucket loop fails the report in one decision instead of trying every slice (measured 2026-10-13:
                # 1,024 slices x 3 attempts, about 34 hours, none of which could be accepted). Deliberately OUTSIDE
                # the two try blocks above: they turn any error into a fallback, and this one must reach the caller.
                # (Guarded only so this file still loads on its own in a test; the engine always loads RA-ProfileAugment.ps1 first.)
                if (Get-Command -Name Assert-RAHybridQueryFits -ErrorAction SilentlyContinue) {
                    Assert-RAHybridQueryFits -Query $Query -BucketCount $_bk
                }
            }
            [void](Save-RARenderedQuery -Query $Query -Tag 'hybrid')
        } else {
            foreach ($clTbl in $clTableHits) {
                if (-not (Test-AdvancedHuntingHasTable -TableName $clTbl)) { $available = $false; break }
            }
        }
        # v2.2.272 -- diagnostic breadcrumb. Class 1 routing bug (the customer):
        # Endpoint_ActiveCompromise_Detected_Detailed had probe say "NOT in AH" yet
        # AH submission still happened. Log the routing decision so the next run
        # tells us which branch actually fired.
        # 🔴 THIS LINE IS VISIBLE ON PURPOSE, AND IT STAYS VISIBLE.
        # A routing bug has now been seen twice -- v2.2.272 on one report, 2026-08-26 on another --
        # where the probe answered "not in advanced hunting" and the query was submitted there
        # anyway, losing the bucket and shipping the report PARTIAL. Both times the breadcrumb that
        # would have named the branch was Write-Diag, i.e. verbose-only, so neither run could be
        # explained afterwards. A diagnostic that only fires once someone already suspects a problem
        # is not a diagnostic. One line per query is a fair price for being able to answer "why did
        # it go there" from a log the customer already has.
        $__route = if ($available) { 'advanced hunting' } else { 'Log Analytics direct' }
        $__tbls  = if (@($clTableHits).Count) { @($clTableHits) -join ', ' } else { 'none' }
        $__eg    = if ($queryReferencesEG) { ' (query also uses ExposureGraph)' } elseif ($queryNeedsAdvancedHunting) { ' (query also uses Defender tables only advanced hunting has)' } else { '' }
        Write-Info ("routing to {0} -- SI tables in this query: {1}{2}" -f $__route, $__tbls, $__eg)
        if (-not $available) {
            # the Log Analytics route is not asked ahead (RA-PartsInParallel.ps1): only advanced-hunting requests are
            if ($null -ne $script:SIHuntingPrefetch -and $script:SIHuntingPrefetch.Capture) { throw (Get-SIHuntingNotAheadText) }
            # same fallback as LA-ingest path. Resolution order:
            # RA-specific (SI_RiskAnalysis_*, for split-workspace setups) -> v2.2 unified
            # (SI_*) -> bare legacy. Customer config sets $global:SI_WorkspaceResourceId
            # per the unified contract; without the SI_* fallback every Profile_CL query
            # threw "Cannot bridge ... $global:WorkspaceResourceId is not set".
            $wsResId = if (-not [string]::IsNullOrWhiteSpace([string]$global:SI_RiskAnalysis_WorkspaceResourceId)) { [string]$global:SI_RiskAnalysis_WorkspaceResourceId }
                       elseif (-not [string]::IsNullOrWhiteSpace([string]$global:SI_WorkspaceResourceId))           { [string]$global:SI_WorkspaceResourceId }
                       else { [string]$global:WorkspaceResourceId }
            if ([string]::IsNullOrWhiteSpace($wsResId)) {
                throw "Cannot bridge SI_*_CL tables: no workspace configured. Set `$global:SI_WorkspaceResourceId (preferred), `$global:SI_RiskAnalysis_WorkspaceResourceId (split-workspace), or legacy `$global:WorkspaceResourceId. Or enable Sentinel data lake + table mirroring."
            }

            # XDR-table detection. \b on both sides means SI_IdentityAssets_CL doesn't trigger
            # the Identity* branch (no word boundary between '_' and 'I'). Negative lookaheads
            # exclude our custom tables explicitly (Identity(?!Assets)). DeviceTvm IS an XDR
            # table from MDVM (only exists in advanced hunting), so it gets its own branch.
            #
            # CRITICAL: strip KQL string literals + line comments BEFORE matching, otherwise
            # column-value strings like SecurityDomain == "Identity" or Category == "Email"
            # falsely trigger the regex and force pure-LA queries through the let-block bridge
            # (which then hits nginx 413 on big estates). v2.1.199 had this bug; v2.1.200 fixes.
            $queryForDetection = $Query
            $queryForDetection = [regex]::Replace($queryForDetection, '"[^"\r\n]*"', '""')   # double-quoted strings
            $queryForDetection = [regex]::Replace($queryForDetection, "'[^'\r\n]*'", "''")   # single-quoted strings
            $queryForDetection = [regex]::Replace($queryForDetection, "@'[^']*'", "''")      # @'...' verbatim single
            $queryForDetection = [regex]::Replace($queryForDetection, '@"[^"]*"', '""')      # @"..." verbatim double
            $queryForDetection = [regex]::Replace($queryForDetection, '//[^\r\n]*', '')      # // line comments

            # TABLE-POSITION ANCHOR (same fix Test-Smoke got in ).
            # Without anchoring, `\bDevice(?!Tvm)\w*\b` greedily matches column names
            # like DeviceKey / DeviceName -- which are NOT XDR tables. Result: false-
            # positive XDR detection forces the cross-workspace let-block, which then
            # injects invalid KQL like `let DeviceKey = workspace(...).DeviceKey;` and
            # the whole query 400s. Restrict to legal table-reference positions:
            # - start-of-line / start-of-statement (after newline+optional whitespace)
            # - after `|` (pipe operator: `... | DeviceInfo` would be illegal but
            #   `... | join (DeviceInfo | ...) on X` IS â€” the table follows `(` though)
            # - after `(` (start of parenthesized subquery: `union(DeviceInfo, ...)` `join (DeviceInfo)`)
            # - after `,` (table-arg lists: `union DeviceInfo, DeviceLogonEvents`)
            # - after `=` (let assignment: `let X = DeviceInfo | ...`)
            # - after the literal keywords `union` / `join` / `materialize` / `evaluate`
            #   (followed by a single space then the table name)
            # Tables that live in the Defender / Sentinel workspace -- NOT in the SI
            # workspace where SI_*_Profile_CL lives. These get cross-workspace let
            # blocks pointing at $global:SI_DefenderWorkspaceResourceId.
            #
            # Two families:
            #   (a) Defender XDR Advanced Hunting tables (Device* / Identity* / Email* etc.)
            #       These are queryable via /security/runHuntingQuery OR via the Sentinel
            #       LA workspace if mirroring/data-lake is enabled. Either way, NOT in the
            #       SI workspace.
            #   (b) Sentinel-side LA tables (SigninLogs / AuditLogs / AAD*SignInLogs)
            #       Standard Entra diagnostic-settings outputs. Live in the Defender /
            #       Sentinel workspace by convention. NOT in the SI workspace.
            #
            # Position anchor (assembled below) blocks DeviceKey (column) from matching --
            # bare `\bDevice\w*\b` was the rev2 false-positive regression.
            $xdrTableNames = '(' +
                # ---- (a) Defender XDR Advanced Hunting families ----
                'Device\w*' +                                       # MDE P2 + MDVM + MDB Baseline (all Device* tables)
                '|Identity(?!Assets|Type|Provider)\w*' +            # MDI: IdentityInfo, IdentityLogonEvents, IdentityAccountInfo
                '|ExposureGraph\w*' +                               # MDEM: ExposureGraphNodes, ExposureGraphEdges
                '|Email\w*' +                                       # MDO: EmailEvents, EmailUrlInfo, EmailAttachmentInfo
                '|Message(?:Events|PostDelivery|UrlInfo)\w*' +      # MDO: MessageEvents, MessagePostDeliveryEvents, MessageUrlInfo
                '|UrlClickEvents' +                                 # MDO
                '|CloudApp\w*' +                                    # MDA: CloudAppEvents
                '|AppFileEvents' +                                  # MDA
                '|Cloud(?:Audit|Dns|Process|Storage)\w*' +          # Defender for Cloud
                '|Alert(?:Evidence|Info)' +                         # XDR
                '|Behavior(?:Entities|Info)' +                      # XDR
                '|AAD\w*SignIn\w*' +                                # Entra (XDR-side)
                '|EntraId\w*SignIn\w*' +                            # Entra (XDR-side)
                '|GraphAPIAuditEvents' +                            # Entra (XDR-side)
                # ---- (b) Sentinel-workspace LA tables (Entra diagnostic settings) ----
                '|SigninLogs' +                                     # Entra interactive sign-ins (LA-side)
                '|AADNonInteractiveUserSignInLogs' +                # Entra non-interactive (LA-side)
                '|AADServicePrincipalSignInLogs' +                  # Entra SPN sign-ins (LA-side)
                '|AADManagedIdentitySignInLogs' +                   # Entra MI sign-ins (LA-side)
                '|AADProvisioningLogs' +                            # Entra provisioning (LA-side)
                '|AuditLogs' +                                      # Entra audit (LA-side)
                '|IntuneAuditLogs' +                                # Intune (LA-side)
                '|MicrosoftGraphActivityLogs' +                     # Graph activity (LA-side)
                ')\b'

            # Anchor: TIGHT table-reference positions. Earlier draft used [|=(,] which
            # caught `ConfigurationName=DeviceName` as table-position (= anchor) and
            # `coalesce(DeviceName, ...)` (( anchor) and `project A, DeviceName` (, anchor).
            # Real KQL table refs only appear at:
            #   - start of statement (^ in multiline)
            #   - immediately after a `|` pipe (with optional whitespace)
            #   - after a keyword: union | join | materialize | evaluate
            # The `let X = TableName` case isn't supported -- rare in practice and the
            # let body usually ends with `|` so the next pipe catches it.
            $xdrTablePattern = '(?ms)(?:(?:^|\|)\s*|\b(?:union|join|materialize|evaluate)\s+(?:\(\s*)?)' + $xdrTableNames

            # Find every distinct table identifier at table-position; -AllMatches needed
            # so we can dedupe and emit one let per unique name.
            $xdrMatches = [regex]::Matches($queryForDetection, $xdrTablePattern)
            $xdrTableHits = @($xdrMatches | ForEach-Object { $_.Groups[1].Value } | Sort-Object -Unique)
            $hasXdrTables = $xdrTableHits.Count -gt 0

            # EG-only tables (ExposureGraphNodes /
            # ExposureGraphEdges) only exist in Defender XDR Advanced Hunting. They're
            # NOT exposed as tables in any LA workspace by default. The cross-workspace
            # let-block we'd inject (`workspace('xdr-ws').ExposureGraphNodes`) will fail
            # because the Defender LA workspace doesn't have EG either. Customer would
            # need to enable Sentinel data lake + table mirroring for EG to make these
            # queries work. Until the flag is on (`$global:SI_HasExposureGraphInLA = $true`),
            # SKIP the report cleanly rather than retry-fail-retry-fail.
            #
            # Detection: SUBSTRING check on the stripped query (NOT the position-anchor
            # XDR regex), because EG often appears in `let _x = ExposureGraphNodes`
            # let-bindings -- which my position-anchor regex correctly ignores (= isn't
            # a table-position anchor, would otherwise match column projections like
            # `ConfigurationName=DeviceName`). Substring check is safe here because no
            # legitimate KQL column would be named `ExposureGraphNodes` / `ExposureGraphEdges`.
            $egNeeded = @()
            if ($queryForDetection -match '\bExposureGraphNodes\b') { $egNeeded += 'ExposureGraphNodes' }
            if ($queryForDetection -match '\bExposureGraphEdges\b') { $egNeeded += 'ExposureGraphEdges' }
            if ($egNeeded.Count -gt 0 -and -not $global:SI_HasExposureGraphInLA) {
                Write-Warn2 ("Skipping report -- query needs ExposureGraph table(s) ({0}) which aren't exposed in any LA workspace. Enable Sentinel data lake + table mirroring for ExposureGraph in `$global:SI_DefenderWorkspaceResourceId, then set `$global:SI_HasExposureGraphInLA = `$true to opt in." -f ($egNeeded -join ', '))
                return [pscustomobject]@{ _SIDirectRows = @() }
            }

            # _CL tables ALWAYS require Log Analytics --
            # they don't exist in Defender XDR Advanced Hunting. The let-block-then-AH
            # Route SI_*_CL queries to LA-direct unconditionally. When the query also
            # references XDR tables (DeviceInfo, IdentityInfo, ExposureGraph*, AAD*
            # SignIn*, etc.), prepend a cross-workspace let-block resolving each XDR
            # table via `workspace("<defender-ws>").TableName`. Defender workspace
            # resolves from $global:SI_DefenderWorkspaceResourceId
            # and falls back to $wsResId if no separate Defender workspace is configured
            # (single-workspace tenants where Sentinel + XDR live alongside SI_*_CL).
            $crossWorkspaceLet = ''
            if ($hasXdrTables) {
                $defenderWs = if (-not [string]::IsNullOrWhiteSpace([string]$global:SI_DefenderWorkspaceResourceId)) {
                    [string]$global:SI_DefenderWorkspaceResourceId
                } else { $wsResId }

                # Reuse the dedup'd hits captured during $hasXdrTables detection above.
                # The let SHADOWS the bare identifier downstream so the rest of the query
                # reads as written -- no in-place rewriting that might miss a reference
                # inside a join() or union() arg.
                $sb = New-Object System.Text.StringBuilder
                foreach ($t in $xdrTableHits) {
                    [void]$sb.AppendLine(("let {0} = workspace('{1}').{0};" -f $t, $defenderWs))
                }
                $crossWorkspaceLet = $sb.ToString()
                if ($defenderWs -eq $wsResId) {
                    Write-Info ("Query joins SI_*_CL with {0} XDR table(s) ({1}); routing to LA-direct with cross-table self-workspace let-block (single-workspace setup -- no separate `$global:SI_DefenderWorkspaceResourceId)." -f $xdrTableHits.Count, ($xdrTableHits -join ', '))
                } else {
                    Write-Info ("Query joins SI_*_CL with {0} XDR table(s) ({1}); routing to LA-direct with cross-workspace let-block bridging to `$global:SI_DefenderWorkspaceResourceId." -f $xdrTableHits.Count, ($xdrTableHits -join ', '))
                }
            } else {
                Write-Info "Query touches only Log Analytics tables (no Defender XDR tables); routing entire query directly to LA workspace -- no let-block, no advanced-hunting round trip, no body-size limit."
            }

            $finalQuery = if ($crossWorkspaceLet) { $crossWorkspaceLet + "`n" + $Query } else { $Query }
            [void](Save-RARenderedQuery -Query $finalQuery -Tag 'la-direct')
            # v2.2.272 -- diagnostic. Confirm we actually got HERE on routes that the
            # probe said should be LA-direct.
            Write-Diag ("[route] LA-direct submission entered. wsResId={0} hasXdr={1} crossLetLen={2}" -f $wsResId, $hasXdrTables, $crossWorkspaceLet.Length)

            # NO @() wrap on the call below. Invoke-LogAnalyticsKqlQuery returns the rows
            # array via `,@($resp.Results)` (comma-protected so PowerShell emits it as ONE
            # value). `@(call)` would re-wrap that single value into a [Object[1] of
            # Object[N]], then the foreach below iterated ONCE with $r = the inner array,
            # and Calculate-RiskScore later read $r.PSObject.Properties = System.Array's
            # native props (Count/Length/SyncRoot/...). Plain assignment captures the
            # inner rows array directly. v2.1.204 fix.
            #
            # fallback (per user request): if the cross-workspace XDR let
            # block resolves to a Defender workspace that doesn't have the table (mis-
            # configured `$global:SI_DefenderWorkspaceResourceId`, or the customer's
            # XDR tables actually live alongside SI_*_CL in the same workspace), retry
            # against the SI workspace alone -- raw query, no let. Cleaner than failing
            # the whole report when LA can resolve the table itself.
            try {
                # v2.2.280 -- visible heartbeat before the LA call. Same silent-gap
                # problem as the AH path: large LA-direct queries can sit for
                # minutes before returning, and operators saw the engine appear
                # to hang.
                Write-Info "submitting query to Log Analytics direct (may take several minutes for large workspaces)..."
                $_laSw = [System.Diagnostics.Stopwatch]::StartNew()
                # #690 (37): read in parts when one answer is too short for a limit (also a report without query slices)
                $rows = Invoke-LogAnalyticsKqlQueryParted -WorkspaceResourceId $wsResId -Query $finalQuery -What 'the report''s query'
                $_laSw.Stop()
                Write-Info ("Log Analytics returned in {0:F1}s" -f $_laSw.Elapsed.TotalSeconds)
            } catch {
                # Cross-workspace failures surface as generic BadRequest (the inner
                # SemanticError isn't always propagated through the LA REST layer).
                # Auto-fallback only when WE prepended a cross-workspace let -- otherwise
                # the failure is in the user's query itself and re-running it changes
                # nothing. We retry against $wsResId alone (no let-block) so single-
                # workspace setups where XDR tables happen to live alongside SI_*_CL
                # still resolve. If that also fails, the original error surfaces below.
                $shouldFallback = $crossWorkspaceLet -and ($_.Exception.Message -match "BadRequest|Failed to resolve|SemanticError")
                if ($shouldFallback) {
                    Write-Warn2 ("Cross-workspace XDR lookup failed ({0}). Retrying as direct LA query against `$global:SI_WorkspaceResourceId (single-workspace fallback)." -f $_.Exception.Message)
                    $rows = Invoke-LogAnalyticsKqlQueryParted -WorkspaceResourceId $wsResId -Query $Query -What 'the report''s query'
                } else { throw }
            }
            if ($null -eq $rows) { $rows = @() }
            # Bypass the Microsoft Graph response shape entirely. v2.1.199 tried to mock
            # it by wrapping each row's data in an AdditionalProperties hashtable and
            # returning a 1-element Results array -- but PowerShell's property broadcast
            # on a 1-element PSCustomObject array returns the raw hashtable in a way
            # that downstream Calculate-RiskScore iterated as System.Array (Length/Rank/
            # SyncRoot appeared on the row, the real data ended up in SyncRoot, every
            # column except the first leaked as null). v2.1.202 fix: ship the clean rows
            # in a marker property `_SIDirectRows` and have the engine detect it and
            # use them directly, skipping the `.AdditionalProperties` + ConvertTo-PSObjectDeep
            # dance that only makes sense for Microsoft Graph SDK responses.
            $cleanRows = New-Object System.Collections.Generic.List[object]
            foreach ($r in $rows) {
                $h = [ordered]@{}
                foreach ($p in $r.PSObject.Properties) { $h[$p.Name] = $p.Value }
                [void]$cleanRows.Add([pscustomobject]$h)
            }
            Resolve-SupersededOnSuccess -WinningPath 'LA-direct'
            return [pscustomobject]@{ _SIDirectRows = $cleanRows.ToArray() }
        }
    }

    # v2.2.198 -- track whether every retry attempt on this submission ended in
    # TaskCanceledException (= 900s HttpClient timeout). If so, outer AutoBucket
    # loop treats it as a DETERMINISTIC failure (the query genuinely can't run
    # within 900s on this tenant's Graph hunting backend) and skips remaining
    # buckets instead of paying another 5+ hours of identical timeouts. Reset
    # to true before each call; flipped false in the catch on ANY non-timeout
    # exception OR on success below.
    $script:_LastGraphHuntingAllTimedOut = $true

    [void](Save-RARenderedQuery -Query $Query -Tag 'ah')
    # v2.2.272 -- diagnostic. If a query that referenced SI_*_CL ends up here, log
    # how it got past the LA-direct branch (Class 1 routing-bug paste).
    if ($Query -match '\bSI_[A-Za-z][A-Za-z0-9]*(?:_[A-Za-z][A-Za-z0-9]*)*_CL\b') {
        Write-Diag ("[route] AH submission entered for query containing SI_*_CL -- either EG-hybrid path resolved CL, or LA-direct branch was bypassed.")
    }

    # BUG B -- wrap the AH retry loop so that if EVERY path (lake -> EG-hybrid -> AH)
    # ultimately fails, the deferred superseded-attempt buffer is flushed as a SINGLE
    # consolidated WARN. Successful returns inside the loop already called
    # Resolve-SupersededOnSuccess (which clears the buffer), so this catch only fires
    # on real total failure. Re-throw preserves the original per-report error handling.
    try {
    # A tenant WITHOUT Microsoft Defender XDR has no advanced hunting: Graph answers every query 403 "Account is not
    # provisioned" (live 2026-10-06, Community rehearsal in a tenant with Entra ID P2 only -- each query burned 4
    # attempts plus late retries with minutes of backoff). Once it has said so in this run, no further query is sent.
    if ($script:_RAHuntingNotProvisioned) { throw (Get-RAHuntingNotProvisionedMessage) }
    for ($attempt = 1; $attempt -le $MaxRetries; $attempt++) {
        Ensure-GraphAuth -MaxAgeMinutes $ReconnectMaxAgeMinutes

        try {
            # v2.2.280 -- visible heartbeat BEFORE the AH submission. Without
            # this, operators saw the engine go silent for up to 15 min between
            # "snapshot inlined" and the next log line whenever a query took its
            # full HttpClient ceiling (TaskCanceled@900s pattern). Print start
            # + duration so progress is observable.
            Write-Info ("submitting query to advanced hunting (attempt {0}/{1}; may take up to 900s if too large)..." -f $attempt, $MaxRetries)
            $_ahSw = [System.Diagnostics.Stopwatch]::StartNew()
            # 🔑 v2.2.452 -- ASK WITHOUT -ErrorAction Stop, THEN RAISE A SHORT ERROR OURSELVES.
            # `-ErrorAction Stop` PROMOTED the cmdlet's non-terminating error to a terminating one,
            # and a PowerShell transcript records every terminating error in full: ~20 lines of HTTP
            # status, request ids and x-ms-ags-diagnostic headers, TWICE per failure (once for the
            # cmdlet, once for this function's re-throw). Customers reading their own log saw raw
            # .NET dumps and rang up. The FAILURE is worth logging -- a query that exceeds AH limits
            # drives bucket escalation -- but the FORM was wrong.
            # 🔴 THE TRAP, AND IT NEARLY BROKE ESCALATION: the 900s ceiling arrives as
            # "The request was canceled due to the configured HttpClient.Timeout of 900 seconds
            # elapsing." That text matches NEITHER message fallback in Test-IsBucketOverflowError
            # ('a task was canceled' / 'taskcanceledexception') -- today it is caught ONLY by the
            # `-is [TaskCanceledException]` TYPE check. Throwing a plain string would erase the type
            # and silently stop the AutoBucket ramp on exactly the reports that need it. So the type
            # is preserved AS TEXT, which both this function and Test-IsBucketOverflowError already
            # match on.
            # 🔑 PURE REST (#113b). Same endpoint the SDK wrapped -- POST /beta/security/runHuntingQuery
            # -- and the adapter returns the SDK's `Results[].AdditionalProperties` shape, so the
            # conversion loop below and the four `$resp.Results.AdditionalProperties` readers in
            # Invoke-RiskAnalysis.ps1 are untouched.
            # 🔒 THE ERROR CONTRACT ABOVE IS PRESERVED, NOT REPLACED. Invoke-SIHuntingQueryRest already
            # normalises the two signals this path depends on -- a client timeout is re-thrown as text
            # containing 'TaskCanceledException', and an HTTP failure carries a composed status line so
            # '502 Bad Gateway' still matches -- so the throw stays a plain string exactly as it became
            # in v2.2.452, and the classifiers below see the same text they always did.
            $ahResp = Invoke-SIHuntingQueryRest -Query $Query -Token $script:GraphAccessToken -TimeoutSec 900
            $_ahSw.Stop()
            Write-Info ("advanced hunting returned in {0:F1}s" -f $_ahSw.Elapsed.TotalSeconds)
            # #641: advanced hunting returns at most 100,000 rows and says nothing when it cuts there (its answer carries only
            # the schema and the rows). An answer AT the cap is taken as cut: refused, worded so the slice is made smaller.
            $__ahCap = if ([int]$global:SI_RA_HuntingRowCap -gt 0) { [int]$global:SI_RA_HuntingRowCap } else { 100000 }
            if ($null -ne $ahResp -and $null -ne $ahResp.Results -and @($ahResp.Results).Count -ge $__ahCap) {
                throw ("advanced hunting returned {0} rows -- its row limit, so the answer may be cut: Query execution has exceeded the allowed limits" -f @($ahResp.Results).Count)
            }

            # 2-phase post-augment: when Resolve-ProfileAugmentPlan stripped cmdb let/join/
            # extend from the query, the AH rows lack those columns. Convert the Graph
            # response shape (Results[].AdditionalProperties hashtables) to clean
            # PSCustomObjects, augment in PowerShell from a single LA fetch per plan,
            # and ship as _SIDirectRows so the caller's existing marker-property branch
            # picks them up (same shape as the LA-direct + Sentinel-lake paths).
            if ($augmentPlans -and @($augmentPlans).Count -gt 0) {
                $cleanRows = New-Object System.Collections.Generic.List[object]
                if ($null -ne $ahResp -and $null -ne $ahResp.Results) {
                    foreach ($r in $ahResp.Results) {
                        $h = [ordered]@{}
                        if ($null -ne $r.AdditionalProperties) {
                            foreach ($k in $r.AdditionalProperties.Keys) { $h[[string]$k] = $r.AdditionalProperties[$k] }
                        } else {
                            foreach ($p in $r.PSObject.Properties) { $h[$p.Name] = $p.Value }
                        }
                        [void]$cleanRows.Add([pscustomobject]$h)
                    }
                }
                $augmented = Invoke-ProfileAugment -Rows $cleanRows.ToArray() -Plans $augmentPlans -WorkspaceResourceId $augmentWsForCL
                Resolve-SupersededOnSuccess -WinningPath 'advanced-hunting'
                return [pscustomobject]@{ _SIDirectRows = @($augmented) }
            }

            Resolve-SupersededOnSuccess -WinningPath 'advanced-hunting'
            return $ahResp
        } catch {
            # a part asked AHEAD (RA-PartsInParallel.ps1): its request is on its way (or it is not asked ahead) -- nothing
            # here is retried, counted, classified or said; the part's own run does all of that with the answer
            if ($null -ne $script:SIHuntingPrefetch -and $script:SIHuntingPrefetch.Capture) { throw }
            $msg = $_.Exception.Message
            # #709: every 429 / 502 / 504 answer is counted for the report that is running (the run record's Retries)
            if (Get-Command -Name Add-SIReportRetryAnswer -ErrorAction SilentlyContinue) { Add-SIReportRetryAnswer -Message $msg }
            # #674: a lookup the report needs could not be read after the rows came back (the post-query enrichment) --
            # never retried here, never classified as anything else: the report is not complete.
            if ((Get-Command -Name Test-RALookupUnavailableError -ErrorAction SilentlyContinue) -and (Test-RALookupUnavailableError -Err $_)) { $script:_LastGraphHuntingAllTimedOut = $false; throw }

            # 🔒 'TaskCanceledException' is matched as TEXT as well as by type: since v2.2.452 the
            # error is raised by us as a short message rather than propagated as the SDK's exception
            # object, so the type check no longer fires and the text is what carries the signal. Both
            # forms are accepted so this works whichever path produced the error.
            $isTaskCanceled = ($_.Exception -is [System.Threading.Tasks.TaskCanceledException]) -or ($msg -match 'A task was canceled') -or ($msg -match 'TaskCanceledException')
            # v2.2.276 -- 502 Bad Gateway from nginx (in front of /security/runHuntingQuery)
            # is the SAME deterministic "query too big" pattern as TaskCanceled. nginx
            # responds 502 when the upstream AH backend produces a response too large
            # for nginx to proxy. Retrying the identical query just burns 4 more
            # attempts (each up to 900s) on the same fail. Classify it like
            # TaskCanceled so the AutoBucket escalation kicks in immediately.
            $is502BadGateway = ($msg -match '502 Bad Gateway' -or $msg -match '\[UnknownError\][^<]*<html>')
            # 🔴 "Query cancelled on creation" IS A CANCELLATION, NOT A QUERY DEFECT -- and it was
            # being read as one because of the sentence the SERVICE APPENDS AFTER IT.
            # The full message is:
            #   ScalarEvaluator.Evaluate failed: Query cancelled on creation:. Fix semantic errors in your query.
            # That trailing sentence is generic boilerplate; the signal is the prefix. The
            # query-defect test below matches on "Fix semantic errors in your query", so this
            # failure was classified PERMANENT, the bucket was never retried or sub-bucketed, and
            # the operator was told the query has to be fixed.
            #
            # 🔬 MEASURED ON THE 2026-09-01 SUMMARY RUN, and the same run disproves the diagnosis:
            # `Attack_Paths_Summary_Github_to_Azure_Resources` split into 2 buckets. Bucket 1 (249
            # rows inlined) got this message and was declared a permanent query defect. Bucket 2
            # (231 rows) hit the 900s ceiling, was correctly queued for sub-bucketing, split 4 then
            # 16 ways -- and EVERY sub-bucket ran the SAME QUERY TEXT successfully (312s, 59s, 56s,
            # 49s, 46s, 32s, 31s). Submitting that query text to advanced hunting directly returns
            # cleanly. A semantically invalid query cannot do either of those things.
            #
            # 🔑 So it belongs with the too-large family: the bucket is resizable, and the sub-bucket
            # pass is exactly what recovers it. Its twin proved that on the same report in the same
            # run.
            # 🔒 DELIBERATELY NARROW. The v2.2.455 separation of query defects from platform failures
            # is correct and must not be widened -- a real semantic error still has to fail on
            # attempt 1 and say the query needs fixing. Only a RECOGNISED PLATFORM PREFIX moves.
            #
            # 🔴 A SECOND PREFIX ARRIVED (audit #106, 2026-09-03), WHICH IS WHY THIS IS NOW A LIST.
            # `Device_Recommendations_Detailed` went 449 -> 0. Both buckets failed on attempt 1 with:
            #   Errors occurred while resolving remote entities. Failed to resolve name or pattern
            #   'TvmSCASnapshotCooked' in one or more scopes: ($Cluster='', Database='').
            #   Fix semantic errors in your query.
            # Same shape as the cancellation: the SIGNAL is the prefix, the trailing sentence is the
            # service's boilerplate, and the query-defect test below reads the boilerplate.
            # 🔬 AND THE QUERY IS FINE -- MEASURED, not argued. `TvmSCASnapshotCooked` appears NOWHERE
            # in this repository; it is Microsoft's internal entity behind the DOCUMENTED
            # `DeviceTvmSecureConfigurationAssessment` / `...KB` tables the report actually queries.
            # The identical query returned 449 rows two hours earlier, and **a re-run returned 448**.
            # So it is service-side entity resolution, a retry is the correct response, and telling
            # the operator "RE-RUNNING WILL FAIL IDENTICALLY" cost a whole report's findings.
            #
            # 📌 ONE LIST, NOT A THIRD LITERAL NEXT TIME. Two of these have now appeared five weeks
            # apart, both with the same boilerplate tail. Adding a third `-or` each time is how this
            # keeps recurring, so the recognised prefixes are named ONCE here and consumed by BOTH
            # classification sites (this one, and the report-level verdict in Invoke-RiskAnalysis.ps1
            # -- #99 proved that fixing only this one still mislabels the report to the operator).
            # 🪤 The list itself is defined at FILE SCOPE (Get-RAPlatformFailurePrefixPattern, top of
            # this file) and NOT here. Defining it inside this catch would mean it exists only after a
            # failure has already occurred -- and the OTHER consumer is the report-level verdict, which
            # runs at the end of the run and would silently fall back to matching nothing.
            $isCancelledOnCreation = ($msg -match (Get-RAPlatformFailurePrefixPattern))
            $isDeterministicTooLarge = $isTaskCanceled -or $is502BadGateway -or $isCancelledOnCreation
            # v2.2.198 -- any non-timeout failure means this call is NOT a clean
            # deterministic-timeout pattern, so the outer AutoBucket loop should
            # treat subsequent buckets as still worth trying.
            if (-not $isDeterministicTooLarge) { $script:_LastGraphHuntingAllTimedOut = $false }
            $looksAuth      = ($msg -match 'InvalidAuthenticationToken|Access token|Authentication|Unauthorized|401')
            $looksThrottle  = ($msg -match 'Too Many Requests|429|throttl|temporar')


            $looksOverflow  = (Test-IsBucketOverflowError -Err $_) -or ($msg -match 'exceeded the allowed result size|exceeded the allowed limits|preempted')

            # 413 Request Entity Too Large -- the nginx in front of /security/runHuntingQuery
            # rejected the body size before it reached the hunting backend. This is hit by the
            # let-block bridge on big customer estates whenever a SI_*_(Profile|Assets)_CL
            # snapshot is inlined as datatable() and the row count + columns push the body
            # over the ~1 MB cap. The warning emitted below names the ACTUAL tables in the
            # current query (not a hardcoded SI_IdentityAssets_CL reference).
            $looksRequestTooLarge = ($msg -match '413 Request Entity Too Large')

            # Schema error: missing table or column. Deterministic -- retrying cannot help.
            # Capture the table name and classify it by Defender service so the log line tells
            # the customer WHICH service / SKU they're missing.
            $looksSchemaError = $false
            $missingTable     = $null
            if ($msg -match "Failed to resolve (?:table or column )?expression named '([^']+)'") {
                $looksSchemaError = $true
                $missingTable     = $matches[1]
            }

            # No Defender XDR in this tenant: permanent for the whole run, never retried, never a reconnect.
            if (Test-RAHuntingNotProvisioned -Message $msg) {
                if (-not $script:_RAHuntingNotProvisioned) {
                    Write-Warn2 'Microsoft Defender XDR advanced hunting is not provisioned in this tenant ("Account is not provisioned") -- the reports that need it have no data here; no query is sent to it again in this run.'
                }
                $script:_RAHuntingNotProvisioned = $true
                throw (Get-RAHuntingNotProvisionedMessage)
            }

if ($looksAuth) {
                Write-Warn2 "Graph auth issue detected. Reconnecting and retrying..."
                try { Connect-GraphHighPriv } catch { Write-Err2 "Graph reconnect failed: $($_.Exception.Message)"; throw }
            }


            if ($looksRequestTooLarge) {
                # Inspect THIS query (with KQL string literals stripped to avoid false positives
                # like the Identity / Email regex trap from v2.1.199) to decide which fix to surface.
                $qStripped = $Query
                $qStripped = [regex]::Replace($qStripped, '"[^"\r\n]*"', '""')
                $qStripped = [regex]::Replace($qStripped, "'[^'\r\n]*'", "''")
                $qStripped = [regex]::Replace($qStripped, "@'[^']*'", "''")
                $qStripped = [regex]::Replace($qStripped, '@"[^"]*"', '""')
                $qStripped = [regex]::Replace($qStripped, '//[^\r\n]*', '')
                $referencesSignInTables = ($qStripped -match '\b(AAD\w*SignIn\w*|EntraId\w*SignIn\w*|GraphAPIAuditEvents)\b')

                # Identify the ACTUAL SI_*_(Profile|Assets)_CL tables this query inlines, so the
                # warning names them instead of the legacy hardcoded `SI_IdentityAssets_CL`.
                $actualClTables = @([regex]::Matches($qStripped, '\bSI_[A-Za-z][A-Za-z0-9]*(?:_[A-Za-z][A-Za-z0-9]*)*_CL\b') |
                                    ForEach-Object { $_.Value } | Sort-Object -Unique)
                $clTablesDisplay = if ($actualClTables.Count -gt 0) { ($actualClTables -join ', ') } else { 'SI_*_(Profile|Assets)_CL' }

                # v2.2.324 -- reframed for operators. Customers reading the log
                # interpret the original "Query body EXCEEDED... HARD LIMIT... NOT
                # RETRYABLE" copy as a hard failure (red alarm), when in practice
                # the engine just adjusts shard sizing and continues. Re-cast as a
                # normal sizing / tuning step. The long-form data-lake tip now
                # emits ONCE per run via $script:_LakeTipShown so the same advice
                # doesn't repeat per-bucket per-retry.
                Write-Info ("Query body is being tuned for the advanced-hunting endpoint (1 MB shard cap). Calculating optimal shard count for {0}." -f $clTablesDisplay)

                if (-not $script:_LakeTipShown) {
                    $script:_LakeTipShown = $true
                    if ($referencesSignInTables) {
                        Write-Info ("Tip (one-time): this query joins {0} with XDR sign-in tables and must include an inline shard of your asset table. To skip the sizing pass entirely, either forward Entra Sign-in + Audit logs to Log Analytics (so the report becomes pure-LA), or enable Microsoft Sentinel data lake + table mirroring for {0} (asset table becomes natively visible to advanced hunting -- no inline needed)." -f $clTablesDisplay)
                    } else {
                        Write-Info ("Tip (one-time): enable Microsoft Sentinel data lake + table mirroring for {0} to skip the sizing pass entirely. With mirroring on, the engine submits queries directly with no inline shard. Alternative: reduce the per-row size of the asset Profile schema." -f $clTablesDisplay)
                    }
                }
                throw
            }

            if ($looksOverflow) {
                Write-Warn2 "Query exceeded allowed limits/result size; not retrying (deterministic failure)."
                throw
            }

            if ($looksSchemaError) {
                $owner = Get-DefenderTableOwner -TableName $missingTable
                Write-Warn2 ("Table '{0}' not present in this tenant's advanced hunting schema. {1}" -f $missingTable, $owner)
                Write-Warn2 "Not retrying (deterministic schema failure -- retries cannot conjure a missing table)."
                throw
            }

            # Syntax errors are deterministic -- retrying produces the same parse error.
            # AH/Graph swallows the error body's line/column info, so dump the rendered
            # query path (already written in the staging block above) for portal paste.
            # 🔴 SEMANTIC errors are exactly as permanent as syntax errors, and Advanced Hunting
            # words them DIFFERENTLY. A `case()` whose branches return mixed types comes back as
            # "Fix SEMANTIC errors in your query" -- which this pattern did not match, so the
            # query burned all 4 attempts, was recorded as an ordinary lost bucket, and the
            # operator was told to re-run a report that fails identically every single time.
            # Platform failures (timeout / 5xx / throttle) are retried below; a query DEFECT
            # never recovers by being repeated, so it must fail on the first attempt and say so.
            # 🪤 AND THE CANCELLATION MUST BE EXCLUDED HERE, NOT JUST FLAGGED ABOVE. This test runs
            # BEFORE the too-large branch, so a message carrying both the cancellation prefix and the
            # service's generic "Fix semantic errors" suffix would still be thrown as permanent and
            # never reach the resize path. See $isCancelledOnCreation for the measurement.
            $looksQueryDefect = (-not $isCancelledOnCreation) -and
                                ($msg -match 'Fix syntax errors in your query|Fix semantic errors in your query|SyntaxError|SemanticError|Expected:|return types are not compatible')
            if ($looksQueryDefect) {
                $defectKind = if ($msg -match 'semantic|not compatible') { 'semantic' } else { 'syntax' }
                Write-Warn2 ("Query failed with a KQL {0} error -- NOT retryable. Re-running this report will fail identically; the query itself has to be fixed: {1}" -f $defectKind, $msg)
                try {
                    if ($script:_RAStagingDir -and (Test-Path $script:_RAStagingDir)) {
                        $hashLast = [System.Security.Cryptography.MD5]::Create().ComputeHash([System.Text.Encoding]::UTF8.GetBytes($Query))
                        $hashLastStr = -join ($hashLast[0..3] | ForEach-Object { $_.ToString('x2') })
                        $renderedPath = Join-Path $script:_RAStagingDir ("ra-rendered-{0}.kql" -f $hashLastStr)
                        if (Test-Path $renderedPath) {
                            Write-Warn2 ("Paste rendered query into Sentinel/AH portal for the precise line+column: {0}" -f $renderedPath)
                        }
                    }
                } catch { }
                throw
            }

            # v2.2.273 / v2.2.276 -- fail-fast on deterministic "query too large"
            # patterns. The 4x900s retry pattern was useful when timeouts looked
            # transient, but in practice when AH hits the HttpClient ceiling (900s)
            # OR nginx returns 502 (upstream response too large for nginx to proxy),
            # the query is genuinely too big. Retrying burns hours on identical
            # fails. Bubble up after the FIRST occurrence so the AutoBucket
            # escalation in the outer loop can re-run with a higher bucket count
            # immediately. The script:_LastGraphHuntingAllTimedOut flag is the
            # signal the outer bucket loop reads.
            if ($isDeterministicTooLarge) {
                # 🔒 Operator-facing, so it describes the BEHAVIOUR and never the internals (working
                # rule 3). "cancelled before it started" is what actually happened and is what makes
                # the resize the right next step.
                $reason = if ($isTaskCanceled)          { 'TaskCanceled@900s (HttpClient ceiling)' }
                          elseif ($isCancelledOnCreation) { 'the service cancelled the query before it started -- too large or too complex to plan' }
                          else                          { '502 Bad Gateway (nginx upstream-response-too-large)' }
                Write-Err2 ("Query failed deterministically ({0}) on attempt {1} -- bypassing retries. AutoBucket escalation will resize the report at higher bucket count." -f $reason, $attempt)
                $script:_LastGraphHuntingAllTimedOut = $true
                throw
            }

            # The worker had no memory to read this answer: the same request at the same size would fail the same way (live
            # 2026-10-20/21, one Detailed slice, run after run). The memory is given back and the caller asks the same rows in
            # smaller slices -- never retried here.
            if ((Get-Command -Name Test-RABucketOutOfMemory -ErrorAction SilentlyContinue) -and (Test-RABucketOutOfMemory -Err $_)) {
                [System.GC]::Collect(); [System.GC]::WaitForPendingFinalizers(); [System.GC]::Collect()
                Write-Warn2 'the answer is too large for this worker''s memory -- not asked again at this size; the same rows are asked in smaller slices'
                throw
            }

            if ($attempt -lt $MaxRetries) {
                $sleepSec = if ($looksThrottle) { [math]::Min(60, 5 * $attempt) }
                            else { [math]::Min(20, 2 * $attempt) }

                Write-Warn2 ("Query failed (attempt {0}/{1}). Waiting {2}s then retrying... {3}" -f $attempt, $MaxRetries, $sleepSec, $msg)
                Start-Sleep -Seconds $sleepSec
                # v2.2.276 -- visible "now retrying" line so operators can tell
                # the engine isn't hung when the next attempt takes its full 900s
                # before returning. Without this the log goes silent for up to
                # 15 min between "Waiting 2s" and the next attempt's outcome.
                Write-Info ("Retrying attempt {0}/{1} now (call may take up to 900s)..." -f ($attempt + 1), $MaxRetries)
                continue
            }

            Write-Err2 ("Query failed after {0} attempts: {1}" -f $MaxRetries, $msg)
            throw
        }
    }
    } catch {
        # All paths failed for this query -- emit the one consolidated WARN (BUG B)
        # then re-throw so the per-report handler behaves exactly as before.
        # (not for a part asked ahead: its own run says what happened)
        if (-not ($null -ne $script:SIHuntingPrefetch -and $script:SIHuntingPrefetch.Capture)) { Flush-SupersededAttempts }
        throw
    }
}
