#Requires -Version 5.1
<#
    Get-SIMdcAssessmentSources -- Defender for Cloud's assessments read from TWO sources and combined per assessment
    (2026-11-20, priority 1).

    WHY. Since about 2026-11-10 Azure Resource Graph returns NO `microsoft.security/assessments` rows for many free-plan
    subscriptions, while the ARM assessments API still returns them (live: Resource Graph 0, the API 43 + 22 on the same
    subscriptions, same identity). SecurityInsight read Resource Graph only and took 0 rows as "complete, nothing there".
    At other installs Resource Graph holds MORE than the API. So neither source replaces the other:

      * Resource Graph: securityresources, type microsoft.security/assessments, one row per assessment (paged to the end,
        Invoke-SIArgPaged -- its retry rules);
      * the ARM API, per subscription: GET /subscriptions/{id}/providers/Microsoft.Security/assessments
        ?api-version=2021-06-01, following nextLink (Invoke-SIAzRestRequest -- the engine's own REST client and retry
        rules: 429 / 5xx retried, any other 4xx fails at once);
      * UNION per assessment: key = the assessed resource's id + the assessment's name (lower-case). An assessment in
        either source is kept; one in both is kept once (the newer status change wins, a field one side lacks is taken
        from the other). SecurityInsight never holds fewer rows than either source.

    COMPLETE per subscription (a release never makes a working install worse):
      * the API answered: the union, as above;
      * the API failed after the retries AND Resource Graph returned rows for that subscription: Resource Graph's rows
        are its answer (exactly the behaviour before the API was read) -- complete, with ONE warning naming the
        subscription and the API error (Warnings);
      * the API failed AND Resource Graph returned no rows for it: INCOMPLETE -- unknown, never "nothing there";
      * a Resource Graph read that stops early, or the subscription listing failing: INCOMPLETE.
    The caller records an incomplete pull incomplete (the resources not read keep what they had): absence is not
    remediation.

    One row per assessment: @{ ResourceId; AssessmentKey; Status; Severity; DisplayName; FirstEvaluated; StatusChanged;
    SubscriptionId }. The callers summarise it into the shapes they used before (Get-SIMdcAssessmentSummary.ps1,
    Get-SIMdcExposure.ps1, the data-health check), so every consumer and the stored collection stay as they are.

    The API's list carries no severity on every row (metadata is not always expanded): a row without one takes it from
    Defender for Cloud's assessment catalogue (GET /providers/Microsoft.Security/assessmentMetadata), read once and only
    when needed. That catalogue failing never drops a row; it is said.

    REST only, no PowerShell modules. Rights: Reader (Microsoft.Security/assessments/read) -- what the Azure collector
    already has. READ ONLY. PowerShell 5.1: no ?. / ??, no ternary.
#>

if (-not (Get-Command -Name Invoke-SIArm -ErrorAction SilentlyContinue)) { . (Join-Path $PSScriptRoot '../../_shared/SI-AzRest.ps1') }
if (-not (Get-Command -Name Invoke-SIArgPaged -ErrorAction SilentlyContinue)) { . (Join-Path $PSScriptRoot 'Invoke-SIArgPaged.ps1') }

$script:SIMdcAssessmentApiVersion = '2021-06-01'
# one read serves both captures of a run (the exposure and the summary read the same assessments)
$script:SIMdcAssessmentReadCache = $null
$script:SIMdcAssessmentCacheMinutes = 30

function Get-SIMdcAssessmentRowsKql {
    <# PURE. The Resource Graph query: ONE row per assessment, sorted for stable paging. #>
    @"
securityresources
| where type =~ 'microsoft.security/assessments'
| extend ResourceId = tolower(tostring(properties.resourceDetails.Id))
| where isnotempty(ResourceId)
| project ResourceId, AssessmentKey = tolower(name), Status = tostring(properties.status.code), Severity = tostring(properties.metadata.severity),
          DisplayName = tostring(properties.displayName), FirstEvaluated = tostring(properties.status.firstEvaluationDate),
          StatusChanged = tostring(properties.status.statusChangeDate), SubscriptionId = tolower(subscriptionId)
| order by ResourceId asc, AssessmentKey asc
"@
}

function Get-SIMdcItemValue {
    <# PURE. A property of an object or a dictionary, case-insensitive; $null when it is not there. #>
    param($Object, [string]$Name)
    if ($null -eq $Object) { return $null }
    if ($Object -is [System.Collections.IDictionary]) { foreach ($k in @($Object.Keys)) { if ([string]$k -ieq $Name) { return $Object[$k] } }; return $null }
    $p = $Object.PSObject.Properties[$Name]
    if ($p) { return $p.Value }
    $null
}

function ConvertTo-SIMdcDateRaw {
    <# PURE. A date AS THE SOURCE GAVE IT (a [datetime] -- ConvertFrom-Json in PS 7 makes one -- or its text), so the stored
       value is what the Resource Graph summary stored before; $null when there is none. #>
    param($Value)
    if ($null -eq $Value) { return $null }
    if ($Value -is [datetime]) { return $Value }
    $t = ([string]$Value).Trim(); if (-not $t) { return $null }
    $t
}

function ConvertTo-SIMdcDateValue {
    <# PURE. Text -> [datetime] UTC for comparing; $null when it is not a date. #>
    param($Value)
    if ($null -eq $Value) { return $null }
    if ($Value -is [datetime]) { return $Value.ToUniversalTime() }
    $t = ([string]$Value).Trim(); if (-not $t) { return $null }
    $d = [datetime]::MinValue
    $st = [Globalization.DateTimeStyles]::AdjustToUniversal -bor [Globalization.DateTimeStyles]::AssumeUniversal
    if ([datetime]::TryParse($t, [Globalization.CultureInfo]::InvariantCulture, $st, [ref]$d)) { return $d }
    $null
}

function ConvertFrom-SIMdcGraphAssessment {
    <# PURE. One Resource Graph row (Get-SIMdcAssessmentRowsKql) -> the one-row-per-assessment shape; $null without a resource id or name. #>
    param($Row)
    if ($null -eq $Row) { return $null }
    $rid = ([string](Get-SIMdcItemValue $Row 'ResourceId')).Trim().ToLowerInvariant()
    $key = ([string](Get-SIMdcItemValue $Row 'AssessmentKey')).Trim().ToLowerInvariant()
    if (-not $rid -or -not $key) { return $null }
    [pscustomobject][ordered]@{
        ResourceId = $rid; AssessmentKey = $key
        Status = ([string](Get-SIMdcItemValue $Row 'Status')).Trim(); Severity = ([string](Get-SIMdcItemValue $Row 'Severity')).Trim()
        DisplayName = ([string](Get-SIMdcItemValue $Row 'DisplayName')).Trim()
        FirstEvaluated = (ConvertTo-SIMdcDateRaw (Get-SIMdcItemValue $Row 'FirstEvaluated')); StatusChanged = (ConvertTo-SIMdcDateRaw (Get-SIMdcItemValue $Row 'StatusChanged'))
        SubscriptionId = ([string](Get-SIMdcItemValue $Row 'SubscriptionId')).Trim().ToLowerInvariant()
    }
}

function ConvertFrom-SIMdcArmAssessment {
    <# PURE. One assessment of the ARM API (its JSON object) -> the one-row-per-assessment shape; $null without a resource id or name.
       The property names are read without case (the API writes resourceDetails.Id and .id). #>
    param($Item, [string]$SubscriptionId = '')
    if ($null -eq $Item) { return $null }
    $p = Get-SIMdcItemValue $Item 'properties'
    $rd = Get-SIMdcItemValue $p 'resourceDetails'
    $rid = ([string](Get-SIMdcItemValue $rd 'Id')).Trim().ToLowerInvariant()
    $key = ([string](Get-SIMdcItemValue $Item 'name')).Trim().ToLowerInvariant()
    if (-not $rid -or -not $key) { return $null }
    $st = Get-SIMdcItemValue $p 'status'; $md = Get-SIMdcItemValue $p 'metadata'
    [pscustomobject][ordered]@{
        ResourceId = $rid; AssessmentKey = $key
        Status = ([string](Get-SIMdcItemValue $st 'code')).Trim(); Severity = ([string](Get-SIMdcItemValue $md 'severity')).Trim()
        DisplayName = ([string](Get-SIMdcItemValue $p 'displayName')).Trim()
        FirstEvaluated = (ConvertTo-SIMdcDateRaw (Get-SIMdcItemValue $st 'firstEvaluationDate')); StatusChanged = (ConvertTo-SIMdcDateRaw (Get-SIMdcItemValue $st 'statusChangeDate'))
        SubscriptionId = ([string]$SubscriptionId).Trim().ToLowerInvariant()
    }
}

function Get-SIMdcAssessmentRowKey {
    <# PURE. The key two sources are combined by: the assessed resource's id + the assessment's name, lower-case. #>
    param($Row)
    ([string](Get-SIMdcItemValue $Row 'ResourceId')).ToLowerInvariant() + '|' + ([string](Get-SIMdcItemValue $Row 'AssessmentKey')).ToLowerInvariant()
}

function Merge-SIMdcAssessmentRow {
    <# PURE. Two rows of the SAME assessment -> one: the newer status change wins; a field the winner lacks comes from the other. #>
    param([Parameter(Mandatory)]$A, [Parameter(Mandatory)]$B)
    $da = ConvertTo-SIMdcDateValue $A.StatusChanged; $db = ConvertTo-SIMdcDateValue $B.StatusChanged
    $win = $A; $other = $B
    if ($null -ne $db -and ($null -eq $da -or $db -gt $da)) { $win = $B; $other = $A }
    $o = [ordered]@{}
    foreach ($n in 'ResourceId', 'AssessmentKey', 'Status', 'Severity', 'DisplayName', 'FirstEvaluated', 'StatusChanged', 'SubscriptionId') {
        $v = $win.$n; if ($null -eq $v -or "$v" -eq '') { $v = $other.$n }
        $o[$n] = $v
    }
    [pscustomobject]$o
}

function Merge-SIMdcAssessmentRows {
    <#
    .SYNOPSIS  PURE. The UNION of the two sources per assessment (Get-SIMdcAssessmentRowKey): every assessment of either is
               kept, one in both is kept once (Merge-SIMdcAssessmentRow). Sorted by resource, then assessment (a stable order).
    #>
    param([AllowEmptyCollection()][object[]]$Graph = @(), [AllowEmptyCollection()][object[]]$Api = @())
    $byKey = New-Object 'System.Collections.Generic.Dictionary[string,object]' ([StringComparer]::OrdinalIgnoreCase)
    foreach ($set in @(, @($Graph)) + @(, @($Api))) {
        foreach ($r in $set) {
            if ($null -eq $r -or -not [string]$r.ResourceId -or -not [string]$r.AssessmentKey) { continue }
            $k = Get-SIMdcAssessmentRowKey $r
            $have = $null
            if ($byKey.TryGetValue($k, [ref]$have)) { $byKey[$k] = Merge-SIMdcAssessmentRow -A $have -B $r } else { $byKey[$k] = $r }
        }
    }
    $keys = New-Object System.Collections.Generic.List[string]
    foreach ($k in $byKey.Keys) { $keys.Add($k) }
    $keys.Sort([StringComparer]::Ordinal)
    $out = New-Object System.Collections.Generic.List[object]
    foreach ($k in $keys) { $out.Add($byKey[$k]) }
    return , $out.ToArray()
}

function Read-SIMdcArmPages {
    <# One ARM list read to its end (nextLink). -Get { param([string]$Uri) } -> the parsed page (value, nextLink); throws on an
       HTTP failure. Returns @{ Items; Pages }. Throws when a page fails -- the caller decides what that means. #>
    # AZHANG-1: -TimeoutMinutes stops the read (throws) once it has taken that long (0 = none); -OnPage { param($Pages, $Items) }
    # is told after every page (the caller's progress line). A page that hands back only items already read (a next link
    # that changes but returns the same page again) stops the read, as a repeated next link does.
    param([Parameter(Mandatory)][string]$Uri, [Parameter(Mandatory)][scriptblock]$Get, [double]$TimeoutMinutes = 0, [scriptblock]$OnPage)
    $items = New-Object System.Collections.Generic.List[object]
    $next = $Uri; $pages = 0
    $readStart = [datetime]::UtcNow
    $seen = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::Ordinal)
    $seenIds = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    while ($next) {
        if (-not $seen.Add([string]$next)) { throw ('the same next page was handed back twice ({0}) -- the read cannot be finished' -f (([string]$next) -replace '\?.*$', '')) }
        if ($TimeoutMinutes -gt 0 -and ([datetime]::UtcNow - $readStart).TotalMinutes -ge $TimeoutMinutes) {
            throw ('the read did not finish within {0} minute(s) ({1} page(s), {2} item(s) read) -- stopped' -f $TimeoutMinutes, $pages, $items.Count)
        }
        $page = & $Get ([string]$next)
        $pages++
        $vals = @(Get-SIMdcItemValue $page 'value')
        $withId = 0; $repeated = 0
        foreach ($v in $vals) {
            if ($null -eq $v) { continue }
            $items.Add($v)
            $vid = [string](Get-SIMdcItemValue $v 'id')
            if ($vid) { $withId++; if (-not $seenIds.Add($vid)) { $repeated++ } }
        }
        if ($pages -gt 1 -and $withId -gt 0 -and $repeated -eq $withId) {
            throw ('page {0} handed back only items already read ({1}) -- the read cannot be finished' -f $pages, (([string]$Uri) -replace '\?.*$', ''))
        }
        $next = [string](Get-SIMdcItemValue $page 'nextLink')
        if ($OnPage) { try { $null = & $OnPage $pages $items.Count } catch { } }
    }
    [pscustomobject]@{ Items = $items.ToArray(); Pages = $pages }
}

function Get-SIMdcReadTimeoutMinutes {
    <# AZHANG-1: how long the assessments API read of ONE subscription may take: $global:SI_MdcArmSubscriptionTimeoutMinutes,
       else 15 (it takes seconds). A subscription that runs out is treated as one whose read failed: Resource Graph's rows
       answer for it when it has some, else it is UNKNOWN -- never "nothing there". #>
    $v = 0
    try { $v = [double](Get-Variable -Scope Global -Name SI_MdcArmSubscriptionTimeoutMinutes -ValueOnly -ErrorAction Ignore) } catch { $v = 0 }
    if ($v -gt 0) { return $v }
    15
}

function Get-SIMdcArmGetDefault {
    <# The real page read: the engine's REST client (retries 429 / 5xx; any other 4xx fails at once with its body). #>
    # AZHANG-1: each page waits at most Get-SIAzureReadTimeoutSec (120 s) and is tried 4 times, each retry SAID -- it was
    # 6 x 300 s with the retries silent (Write-Verbose): at a large install the step printed nothing for over an hour
    {
        param([string]$Uri)
        $r = Invoke-SIAzRestRequest -Method GET -Uri $Uri -What 'Defender for Cloud assessments API' -TimeoutSec (Get-SIAzureReadTimeoutSec) -MaxAttempts 4 `
                 -OnRetry { param($Code, $Wait, $Attempt, $Max, $What) Write-SIReadProgress ('Defender for Cloud assessments API: no answer (HTTP {0}) on {1} -- retry {2}/{3} in {4}s' -f $Code, (([string]$Uri) -replace '\?.*$', ''), $Attempt, ($Max - 1), $Wait) }
        if ($null -eq $r -or -not [string]$r.Content) { $null } else { $r.Content | ConvertFrom-Json }
    }
}

function Get-SIMdcSubscriptionIds {
    <# The subscriptions to read the API of: the ones given, else every subscription the identity can read (Disabled /
       Deleted left out, as Resource Graph does). Throws when they cannot be listed. #>
    param([string[]]$SubscriptionIds = @(), [Parameter(Mandatory)][scriptblock]$Get)
    $given = @(@($SubscriptionIds) | Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) } | ForEach-Object { ([string]$_).Trim().ToLowerInvariant() } | Select-Object -Unique)
    if ($given.Count -gt 0) { return , $given }
    $r = Read-SIMdcArmPages -Uri 'https://management.azure.com/subscriptions?api-version=2022-12-01' -Get $Get
    $ids = @(foreach ($s in @($r.Items)) {
        $state = [string](Get-SIMdcItemValue $s 'state')
        if ($state -in 'Disabled', 'Deleted') { continue }
        $id = ([string](Get-SIMdcItemValue $s 'subscriptionId')).Trim().ToLowerInvariant()
        if ($id) { $id }
    })
    return , @($ids | Select-Object -Unique)
}

function Read-SIMdcArmAssessments {
    <#
    .SYNOPSIS  The ARM assessments API, per subscription, every page. Returns @{ Rows; Complete; Failed (subscription ->
               error); PerSubscription (subscription -> rows read); Subscriptions; Error }. Never throws: a subscription
               whose read fails (4xx / 5xx after the retries) is named in Failed and makes Complete $false.
    .PARAMETER Get  test seam: { param([string]$Uri) } -> the parsed page; throws on an HTTP failure.
    #>
    param([string[]]$SubscriptionIds = @(), [scriptblock]$Get, [double]$ProgressSeconds = 60)
    if (-not $Get) { $Get = Get-SIMdcArmGetDefault }
    $rows = New-Object System.Collections.Generic.List[object]
    $failed = [ordered]@{}; $per = @{}
    $subs = @()
    try { $subs = Get-SIMdcSubscriptionIds -SubscriptionIds $SubscriptionIds -Get $Get; $subs = @($subs | Where-Object { $_ }) }
    catch {
        $e = ('the subscriptions could not be listed: {0}' -f (([string]$_.Exception.Message) -split "`n")[0].Trim())
        return [pscustomobject]@{ Rows = @(); Complete = $false; Failed = [ordered]@{ '*' = $e }; PerSubscription = @{}; Subscriptions = @(); Error = $e }
    }
    # AZHANG-1: a progress line at least every -ProgressSeconds (and at the start of a read of many subscriptions), and a
    # time-out per subscription (Get-SIMdcReadTimeoutMinutes) -- a subscription that runs out is a failed read (below)
    $started = [datetime]::UtcNow
    $clock = @{ Last = [datetime]::UtcNow }
    if ($ProgressSeconds -gt 0 -and $subs.Count -gt 1) { Write-SIReadProgress ('Defender for Cloud assessments API: reading {0} subscription(s) ...' -f $subs.Count) }
    $tmo = Get-SIMdcReadTimeoutMinutes
    $i = 0
    foreach ($s in $subs) {
        $i++
        $uri = 'https://management.azure.com/subscriptions/{0}/providers/Microsoft.Security/assessments?api-version={1}' -f $s, $script:SIMdcAssessmentApiVersion
        $say = {
            param($Pg, $N)
            if ($ProgressSeconds -gt 0 -and ([datetime]::UtcNow - $clock.Last).TotalSeconds -ge $ProgressSeconds) {
                Write-SIReadProgress ('Defender for Cloud assessments: subscription {0} of {1}, page {2} ({3} assessment(s) of it so far, {4} in all; {5:n0}s)' -f $i, $subs.Count, $Pg, $N, ($rows.Count + $N), ([datetime]::UtcNow - $started).TotalSeconds)
                $clock.Last = [datetime]::UtcNow
            }
        }
        try {
            $r = Read-SIMdcArmPages -Uri $uri -Get $Get -TimeoutMinutes $tmo -OnPage $say
            $n = 0
            foreach ($it in @($r.Items)) { $row = ConvertFrom-SIMdcArmAssessment -Item $it -SubscriptionId $s; if ($row) { $rows.Add($row); $n++ } }
            $per[$s] = $n
        } catch {
            $failed[$s] = (([string]$_.Exception.Message) -split "`n")[0].Trim()
        }
    }
    $err = ''
    if ($failed.Count -gt 0) { $err = ('the assessments API did not answer for {0} of {1} subscription(s): {2}' -f $failed.Count, $subs.Count, ((@($failed.Keys) | ForEach-Object { '{0} ({1})' -f $_, $failed[$_] }) -join '; ')) }
    [pscustomobject]@{ Rows = $rows.ToArray(); Complete = ($failed.Count -eq 0); Failed = $failed; PerSubscription = $per; Subscriptions = $subs; Error = $err }
}

function Read-SIMdcGraphAssessments {
    <#
    .SYNOPSIS  Resource Graph, one row per assessment, paged to the end. Returns @{ Rows; Complete; Error }. Never throws.
    .PARAMETER Query  test seam: { param($Kql) } -> the rows (the whole answer); a throw = the read failed.
    #>
    param([string[]]$SubscriptionIds = @(), [scriptblock]$Query)
    $rows = New-Object System.Collections.Generic.List[object]
    $kql = Get-SIMdcAssessmentRowsKql
    try {
        if ($Query) {
            foreach ($x in @(& $Query $kql)) { $row = ConvertFrom-SIMdcGraphAssessment -Row $x; if ($row) { $rows.Add($row) } }
            return [pscustomobject]@{ Rows = $rows.ToArray(); Complete = $true; Error = '' }
        }
        # #727 page by page: each page is made slim at once, the raw page is let go
        $take = { param($PageRows) foreach ($x in @($PageRows)) { $row = ConvertFrom-SIMdcGraphAssessment -Row $x; if ($row) { $rows.Add($row) } } }
        $page = Invoke-SIArgPaged -Query $kql -SourceLabel 'Defender for Cloud assessments (Resource Graph)' -SubscriptionIds $SubscriptionIds -OnPage $take -TimeoutMinutes 30 -WarningAction SilentlyContinue
        return [pscustomobject]@{ Rows = $rows.ToArray(); Complete = [bool]$page.Complete; Error = $(if ($page.Complete) { '' } else { [string]$page.Error }) }
    } catch {
        return [pscustomobject]@{ Rows = $rows.ToArray(); Complete = $false; Error = ('Resource Graph: ' + [string]$_.Exception.Message) }
    }
}

function Add-SIMdcMissingSeverity {
    <# Rows without a severity take it from Defender for Cloud's assessment catalogue (read once, only when a row lacks one).
       Returns '' or what could not be read (said by the caller; the rows are kept either way). -Get: the page seam. #>
    param([AllowEmptyCollection()][object[]]$Rows = @(), [scriptblock]$Get, [string[]]$SubscriptionIds = @())
    $need = @($Rows | Where-Object { $null -ne $_ -and -not [string]$_.Severity })
    if ($need.Count -eq 0) { return '' }
    if (-not $Get) { $Get = Get-SIMdcArmGetDefault }
    $sev = @{}
    $why = ''
    $uris = New-Object System.Collections.Generic.List[string]
    $uris.Add(('https://management.azure.com/providers/Microsoft.Security/assessmentMetadata?api-version={0}' -f $script:SIMdcAssessmentApiVersion))
    # custom assessments are described per subscription
    foreach ($s in @($need | ForEach-Object { [string]$_.SubscriptionId } | Where-Object { $_ } | Select-Object -Unique)) { $uris.Add(('https://management.azure.com/subscriptions/{0}/providers/Microsoft.Security/assessmentMetadata?api-version={1}' -f $s, $script:SIMdcAssessmentApiVersion)) }
    foreach ($u in $uris) {
        try {
            foreach ($m in @((Read-SIMdcArmPages -Uri $u -Get $Get -TimeoutMinutes (Get-SIMdcReadTimeoutMinutes)).Items)) {
                $n = ([string](Get-SIMdcItemValue $m 'name')).Trim().ToLowerInvariant()
                $v = [string](Get-SIMdcItemValue (Get-SIMdcItemValue $m 'properties') 'severity')
                if ($n -and $v -and -not $sev.ContainsKey($n)) { $sev[$n] = $v }
            }
        } catch { if (-not $why) { $why = (([string]$_.Exception.Message) -split "`n")[0].Trim() } }
    }
    $left = 0
    foreach ($r in $need) { $k = ([string]$r.AssessmentKey).ToLowerInvariant(); if ($sev.ContainsKey($k)) { $r.Severity = [string]$sev[$k] } else { $left++ } }
    if ($left -gt 0) {
        $t = ('{0} assessment(s) from the assessments API have no severity in Defender for Cloud''s catalogue' -f $left)
        if ($why) { $t = $t + (' (the catalogue could not be read whole: {0})' -f $why) }
        return $t
    }
    ''
}

function Get-SIMdcAssessmentRows {
    <#
    .SYNOPSIS  Defender for Cloud's assessments from Resource Graph AND the ARM API, combined per assessment (union).
               Returns @{ Rows; Complete; Error; GraphCount; ApiCount; GraphEmptySubscriptions (Resource Graph had none
               while the API had some); Note }. Complete only when both reads are whole. Never throws.
    .PARAMETER GraphQuery  test seam for Resource Graph: { param($Kql) } -> rows (one per assessment).
    .PARAMETER ArmGet      test seam for the ARM API: { param([string]$Uri) } -> the parsed page; a throw = that read failed.
    .PARAMETER NoCache     read again even when this run already read the same subscriptions.
    #>
    param([string[]]$SubscriptionIds = @(), [scriptblock]$GraphQuery, [scriptblock]$ArmGet, [switch]$NoCache)
    $seamed = ($GraphQuery -or $ArmGet)
    $ck = ((@($SubscriptionIds) | Where-Object { $_ } | ForEach-Object { ([string]$_).ToLowerInvariant() } | Sort-Object) -join ',')
    if (-not $seamed -and -not $NoCache -and $null -ne $script:SIMdcAssessmentReadCache -and $script:SIMdcAssessmentReadCache.Key -eq $ck -and
        $script:SIMdcAssessmentReadCache.At -gt [datetime]::UtcNow.AddMinutes(-$script:SIMdcAssessmentCacheMinutes)) {
        return $script:SIMdcAssessmentReadCache.Result
    }
    $g = Read-SIMdcGraphAssessments -SubscriptionIds $SubscriptionIds -Query $GraphQuery
    $a = Read-SIMdcArmAssessments -SubscriptionIds $SubscriptionIds -Get $ArmGet
    $note = Add-SIMdcMissingSeverity -Rows @($a.Rows) -Get $ArmGet -SubscriptionIds $SubscriptionIds
    $rows = Merge-SIMdcAssessmentRows -Graph @($g.Rows) -Api @($a.Rows)
    # the subscriptions Resource Graph no longer answers for (it had none; the API had some) -- said, never an anomaly
    $gSubs = @{}; foreach ($r in @($g.Rows)) { if ($r.SubscriptionId) { $gSubs[[string]$r.SubscriptionId] = $true } }
    $gapSubs = @(foreach ($s in @($a.PerSubscription.Keys)) { if ([int]$a.PerSubscription[$s] -gt 0 -and -not $gSubs.ContainsKey([string]$s)) { [string]$s } })
    # PER SUBSCRIPTION (coordinator 2026-11-20 -- a release never makes a working install worse): a subscription whose API
    # read failed after the retries is answered by Resource Graph's rows when Resource Graph HAS rows for it (exactly the
    # behaviour before the API was read) -- complete, with one warning naming it and the error. Resource Graph with no rows
    # for it = unknown -> incomplete. The subscription listing failing ('*') and a failed Resource Graph read stay incomplete.
    $apiComplete = $true
    $apiErrs = New-Object System.Collections.Generic.List[string]
    $warnings = New-Object System.Collections.Generic.List[string]
    $failedCount = 0
    if ($null -ne $a.Failed) { $failedCount = @($a.Failed.Keys).Count }
    foreach ($s in @(if ($failedCount -gt 0) { $a.Failed.Keys })) {
        $why = [string]$a.Failed[$s]
        if ([string]$s -ne '*' -and [bool]$g.Complete -and $gSubs.ContainsKey(([string]$s).ToLowerInvariant())) {
            $warnings.Add(('Defender for Cloud assessments API did not answer for subscription {0} ({1}) -- Resource Graph''s rows are that subscription''s answer, as before' -f $s, $why))
        } else {
            $apiComplete = $false
            if ([string]$s -eq '*') { $apiErrs.Add($why) }
            else { $apiErrs.Add(('the assessments API did not answer for subscription {0} and Resource Graph has no rows for it -- unknown, not "nothing there" ({1})' -f $s, $why)) }
        }
    }
    $errs = @(@([string]$g.Error) + @($apiErrs) | Where-Object { $_ })
    $res = [pscustomobject]@{
        Rows = $rows; Complete = ([bool]$g.Complete -and $apiComplete); Error = ($errs -join '; ')
        GraphCount = @($g.Rows).Count; ApiCount = @($a.Rows).Count; GraphEmptySubscriptions = @($gapSubs | Sort-Object); Note = $note
        Warnings = $warnings.ToArray()
    }
    if (-not $seamed) { $script:SIMdcAssessmentReadCache = [pscustomobject]@{ Key = $ck; At = [datetime]::UtcNow; Result = $res } }
    $res
}

function Format-SIMdcSourceGapText {
    <# PURE. '' or the line that says Resource Graph no longer answers for N subscription(s) and the API's rows were used. #>
    param([AllowEmptyCollection()][string[]]$Subscriptions = @())
    $n = @($Subscriptions | Where-Object { $_ }).Count
    if ($n -eq 0) { return '' }
    'Resource Graph no longer returns Defender for Cloud assessments for {0} subscription(s) -- they were read from the Defender for Cloud assessments API (a source-read gap at Microsoft, not a gap in SecurityInsight''s data)' -f $n
}

function ConvertTo-SIMdcAssessmentSummaryRows {
    <#
    .SYNOPSIS  PURE. One row per assessment -> one row per resource in the shape the Resource Graph summary query gave
               (ResourceId, Assessed, Unhealthy, High, Medium, Low, OldestUnhealthy, NewestChange, TopHigh, TopMedium,
               TopLow), so ConvertTo-SIMdcAssessmentObjects reads it unchanged. Sorted by ResourceId.
    #>
    param([AllowEmptyCollection()][object[]]$Rows = @(), [int]$Top = 5)
    if ($Top -lt 1) { $Top = 1 }
    $by = New-Object 'System.Collections.Generic.Dictionary[string,object]' ([StringComparer]::OrdinalIgnoreCase)
    $order = New-Object System.Collections.Generic.List[string]
    foreach ($r in @($Rows)) {
        if ($null -eq $r -or -not [string]$r.ResourceId) { continue }
        $id = ([string]$r.ResourceId).ToLowerInvariant()
        $s = $null
        if (-not $by.TryGetValue($id, [ref]$s)) {
            $s = @{ ResourceId = $id; Assessed = 0; Unhealthy = 0; High = 0; Medium = 0; Low = 0; Oldest = $null; OldestText = $null; Newest = $null; NewestText = $null
                    TopHigh = (New-Object System.Collections.Generic.List[object]); TopMedium = (New-Object System.Collections.Generic.List[object]); TopLow = (New-Object System.Collections.Generic.List[object]) }
            $by[$id] = $s; $order.Add($id)
        }
        $s.Assessed++
        if ([string]$r.Status -ine 'Unhealthy') { continue }
        $s.Unhealthy++
        $sev = [string]$r.Severity
        $item = [pscustomobject][ordered]@{ id = ([string]$r.AssessmentKey).ToLowerInvariant(); name = [string]$r.DisplayName; severity = $sev }
        if ($sev -ieq 'High') { $s.High++; if ($s.TopHigh.Count -lt $Top) { $s.TopHigh.Add($item) } }
        elseif ($sev -ieq 'Medium') { $s.Medium++; if ($s.TopMedium.Count -lt $Top) { $s.TopMedium.Add($item) } }
        else { if ($sev -ieq 'Low') { $s.Low++ }; if ($s.TopLow.Count -lt $Top) { $s.TopLow.Add($item) } }
        $fe = ConvertTo-SIMdcDateValue $r.FirstEvaluated
        if ($null -ne $fe -and ($null -eq $s.Oldest -or $fe -lt $s.Oldest)) { $s.Oldest = $fe; $s.OldestText = $r.FirstEvaluated }
        $sc = ConvertTo-SIMdcDateValue $r.StatusChanged
        if ($null -ne $sc -and ($null -eq $s.Newest -or $sc -gt $s.Newest)) { $s.Newest = $sc; $s.NewestText = $r.StatusChanged }
    }
    $order.Sort([StringComparer]::Ordinal)
    $out = New-Object System.Collections.Generic.List[object]
    foreach ($id in $order) {
        $s = $by[$id]
        $o = [ordered]@{ ResourceId = $s.ResourceId; Assessed = $s.Assessed; Unhealthy = $s.Unhealthy; High = $s.High; Medium = $s.Medium; Low = $s.Low }
        if ($null -ne $s.OldestText) { $o['OldestUnhealthy'] = $s.OldestText }
        if ($null -ne $s.NewestText) { $o['NewestChange'] = $s.NewestText }
        $o['TopHigh'] = $s.TopHigh.ToArray(); $o['TopMedium'] = $s.TopMedium.ToArray(); $o['TopLow'] = $s.TopLow.ToArray()
        $out.Add([pscustomobject]$o)
    }
    return , $out.ToArray()
}

function ConvertTo-SIMdcExposureRows {
    <# PURE. One row per assessment -> one row per resource with an Unhealthy internet-exposure assessment (the assessment's
       key in -AssessmentKeys, or its name has the word "internet"): @{ ResourceId; Assessments = its names }. #>
    param([AllowEmptyCollection()][object[]]$Rows = @(), [string[]]$AssessmentKeys = @())
    $keys = @{}; foreach ($k in @($AssessmentKeys)) { if ($k) { $keys[([string]$k).ToLowerInvariant()] = $true } }
    $by = [ordered]@{}
    foreach ($r in @($Rows)) {
        if ($null -eq $r -or -not [string]$r.ResourceId) { continue }
        if ([string]$r.Status -ine 'Unhealthy') { continue }
        $dn = [string]$r.DisplayName
        if (-not ($keys.ContainsKey(([string]$r.AssessmentKey).ToLowerInvariant()) -or $dn -match '(?i)(^|[^a-z0-9])internet([^a-z0-9]|$)')) { continue }
        $id = ([string]$r.ResourceId).ToLowerInvariant()
        if (-not $by.Contains($id)) { $by[$id] = New-Object System.Collections.Generic.List[string] }
        if ($dn -and -not $by[$id].Contains($dn)) { $by[$id].Add($dn) }
    }
    $out = New-Object System.Collections.Generic.List[object]
    foreach ($id in @($by.Keys)) { $out.Add([pscustomobject]@{ ResourceId = $id; Assessments = $by[$id].ToArray() }) }
    return , $out.ToArray()
}

function ConvertTo-SIMdcHealthRows {
    <# PURE. One row per assessment -> the data-health check's rows: @{ ResourceId; Unhealthy; Changed (the newest status change) }. #>
    param([AllowEmptyCollection()][object[]]$Rows = @())
    $by = [ordered]@{}
    foreach ($r in @($Rows)) {
        if ($null -eq $r -or -not [string]$r.ResourceId) { continue }
        $id = ([string]$r.ResourceId).ToLowerInvariant()
        if (-not $by.Contains($id)) { $by[$id] = @{ U = 0; C = $null; CT = $null } }
        $s = $by[$id]
        if ([string]$r.Status -ieq 'Unhealthy') { $s.U++ }
        $sc = ConvertTo-SIMdcDateValue $r.StatusChanged
        if ($null -ne $sc -and ($null -eq $s.C -or $sc -gt $s.C)) { $s.C = $sc }
    }
    $out = New-Object System.Collections.Generic.List[object]
    foreach ($id in @($by.Keys)) { $out.Add([pscustomobject]@{ ResourceId = $id; Unhealthy = $by[$id].U; Changed = $by[$id].C }) }
    return , $out.ToArray()
}
