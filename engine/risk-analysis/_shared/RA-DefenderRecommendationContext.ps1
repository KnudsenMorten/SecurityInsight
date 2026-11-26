#Requires -Version 5.1
<#
    WHAT DEFENDER SAYS ABOUT A SECURITY RECOMMENDATION THAT ADVANCED HUNTING DOES NOT CARRY -- from the Defender
    recommendations API (GET https://api.securitycenter.microsoft.com/api/recommendations, application permission
    SecurityRecommendation.Read.All on WindowsDefenderATP, READ ONLY), put on the vulnerability and configuration rows
    of Risk Analysis before they are scored and stored:

      si_exposure_impact   how much the tenant's exposure score falls when the recommendation is done   (exposureImpact)
      si_active_alert      an active alert is associated with the recommendation                         (activeAlert)

    HOW A ROW FINDS ITS RECOMMENDATION -- by what the row already carries, never by a request per row:
      * a configuration row: its ConfigurationId (scid-...) is the recommendation "sca-_-<ConfigurationId>";
      * a vulnerability row: Defender recommends per SOFTWARE, not per CVE ("va-_-<vendor>-_-<product>"), so the row's
        affected vendor and product (SI_AffectedVendor / SI_AffectedProduct, ';'-joined) name the recommendation. A CVE
        that concerns several products takes the HIGHEST exposure impact among them, and has an active alert when any
        of them has one.

    ONE READ PER RUN, NO CALL PER ROW: the list is paged and summarised page by page; the read stops when a page comes
    back short, and stops with an error when the service hands the same page again.

    CONTEXT ONLY: nothing here changes a risk factor or a score. A value the API does not give is left out (unknown),
    never written as false / 0.

    #1373 DEFENDER'S OWN REMEDIATION TYPE (owner 2026-11-25: "why does fx update openssl show as policy" -> "Use Defender's type";
    "problem is that you left out the remediation task"): the same read gives every recommendation's remediationType (Update |
    Upgrade | ConfigurationChange | Uninstall), productName and vendor (Microsoft Defender for Endpoint API, Recommendation
    resource type). A recommendation row of ANOTHER provider that names the same recommendation by title (Defender for Cloud's
    "Update openssl" -- Defender's "<remediationType> <productName>", or its recommendationName) gets them as
    si_recommendation_remediation_type / si_recommendation_product / si_recommendation_vendor (stored with the finding only,
    never in a report's own columns): the remediation task's kind and tool follow Defender's type (finding-fields.locked.json).
    No other row changes; no new permission (the same read).

    NEVER BLOCKS: a refused read (the permission is not granted yet) or a read that does not complete is said ONCE in
    plain words and the rows go on unchanged. PURE except Get-RADefenderRecommendationIndex. PowerShell 7, REST only.
#>

$script:RADefenderRecUrl = 'https://api.securitycenter.microsoft.com/api/recommendations'
$script:RADefenderRecPageSize = 8000

function Write-RADefenderReadInfo {
    <# One plain line about a Defender read of this run (Write-Info when the engine's console helpers are loaded). #>
    param([string]$Line)
    if (Get-Command -Name Write-Info -ErrorAction SilentlyContinue) { Write-Info $Line } else { Write-Host $Line }
}

function Get-RADefenderReadTimeoutSeconds {
    <#
        PURE over the setting. The time limit of every request of a Defender read: SI_RA_DefenderReadTimeoutSec, default
        180 s. Live 2026-10-14 on internal: the once-per-run read of the vulnerability list ran 26 minutes with no line, and
        a request without a limit can wait for ever -- a run must never hang on an answer that does not come.
    #>
    param($Setting = $global:SI_RA_DefenderReadTimeoutSec)
    $n = 0
    if ($null -ne $Setting -and ([string]$Setting).Trim() -ne '' -and [int]::TryParse(([string]$Setting).Trim(), [ref]$n) -and $n -gt 0) { return $n }
    180
}

function Invoke-RADefenderPagedRead {
    <#
        The pager of a Defender read: Invoke-SIPagedRest's rules (follow the service's next links; a passing failure --
        429 / 502 / 503 / 504 / no answer -- retried up to -MaxAttempts times, waiting what the service asks, at most 60 s;
        any other failure stops the read and keeps what came), with ONE difference: every request has a time limit
        (-TimeoutSec), so a request that is never answered counts as no answer instead of waiting for ever.
        Returns @{ Count; Complete; Pages; Retries; Error }; each page's rows go to -OnPage.
    #>
    param([Parameter(Mandatory)][string]$Url, [Parameter(Mandatory)][string]$Token, [Parameter(Mandatory)][string]$SourceLabel,
          [Parameter(Mandatory)][scriptblock]$OnPage, [int]$TimeoutSec = 180, [int]$MaxAttempts = 4, [int]$MaxDelaySeconds = 60)
    $headers = @{ Authorization = ('Bearer ' + $Token) }
    $count = 0; $pages = 0; $retries = 0; $complete = $true; $errMsg = $null
    $next = $Url
    while ($next) {
        $attempt = 0; $resp = $null; $failed = $false
        while ($true) {
            $attempt++
            try {
                $resp = Invoke-RestMethod -Method Get -Uri $next -Headers $headers -TimeoutSec $TimeoutSec -ErrorAction Stop
                break
            } catch {
                $status = 0
                if (Get-Command -Name Get-SIRestHttpStatus -ErrorAction SilentlyContinue) { $status = Get-SIRestHttpStatus -ErrorRecord $_ }
                $isTransient = ($null -eq $status) -or ($status -in 429, 502, 503, 504) -or ($status -eq 0)
                $detail = $_.Exception.Message
                if ($_.ErrorDetails -and $_.ErrorDetails.Message) { $detail = $_.ErrorDetails.Message }
                if (-not $isTransient -or $attempt -ge $MaxAttempts) {
                    $failed = $true
                    $errMsg = ('{0}: page {1} failed after {2} attempt(s) -- HTTP {3} {4}' -f $SourceLabel, ($pages + 1), $attempt, $status, $detail)
                    break
                }
                $delay = $null
                if (Get-Command -Name Get-SIRetryAfterSeconds -ErrorAction SilentlyContinue) { $delay = Get-SIRetryAfterSeconds -ErrorRecord $_ }
                if ($null -eq $delay) { $delay = [int][Math]::Pow(2, $attempt - 1) }
                if ($delay -gt $MaxDelaySeconds) { $delay = $MaxDelaySeconds }
                $retries++
                Start-Sleep -Seconds $delay
            }
        }
        if ($failed) { $complete = $false; break }
        if ($resp.value) { $count += @($resp.value).Count; $null = & $OnPage @($resp.value) }
        $pages++
        $next = $resp.'@odata.nextLink'
    }
    [pscustomobject]@{ Count = $count; Complete = $complete; Pages = $pages; Retries = $retries; Error = $errMsg }
}


function Get-RADefenderRecommendationKey {
    <#
        PURE. The key(s) a recommendation is found by: 'sca|<configuration id>' for a configuration recommendation,
        'va|<vendor>|<product>' for a software recommendation (lower case). @() when the object names neither.
    #>
    param($Item)
    if ($null -eq $Item) { return @() }
    $g = { param($n) $p = $Item.PSObject.Properties[$n]; if ($p) { ([string]$p.Value).Trim().ToLowerInvariant() } else { '' } }
    $keys = [System.Collections.Generic.List[string]]::new()
    $id = & $g 'id'
    $parts = @($id -split '-_-')
    if ($parts.Count -ge 2 -and $parts[0] -eq 'sca' -and $parts[1]) { $keys.Add('sca|' + $parts[1]) }
    elseif ($parts.Count -ge 3 -and $parts[0] -eq 'va' -and $parts[1] -and $parts[2]) { $keys.Add('va|' + $parts[1] + '|' + $parts[2]) }
    # the object's own vendor / product, when the id does not say it (or says it differently)
    $vendor = & $g 'vendor'; $product = & $g 'productName'
    if ($vendor -and $product -and ($parts.Count -lt 1 -or $parts[0] -ne 'sca')) {
        $k = 'va|' + $vendor + '|' + $product
        if (-not $keys.Contains($k)) { $keys.Add($k) }
    }
    # #1373 by title: its own name, and "<remediationType> <productName>" (how Defender for Cloud names the same recommendation)
    foreach ($nm in @((& $g 'recommendationName'), $(if ((& $g 'remediationType') -and $product) { (& $g 'remediationType') + ' ' + $product } else { '' }))) {
        $nk = ConvertTo-RADefenderRecommendationTitleKey $nm
        if ($nk -and -not $keys.Contains($nk)) { $keys.Add($nk) }
    }
    return $keys.ToArray()
}

function ConvertTo-RADefenderRecommendationTitleKey {
    <# PURE. #1373 a recommendation title as the index compares it: 'name|' + lower case, '_' and runs of spaces one space. '' for none. #>
    param([AllowNull()][AllowEmptyString()][string]$Title)
    $s = (([string]$Title).Trim().ToLowerInvariant() -replace '[\s_]+', ' ').Trim()
    if (-not $s) { return '' }
    'name|' + $s
}

function ConvertTo-RADefenderRecommendationEntry {
    <# PURE. One recommendation object of the API as the values a row takes: only what the API states. $null when it states neither. #>
    param($Item)
    if ($null -eq $Item) { return $null }
    $g = { param($n) $p = $Item.PSObject.Properties[$n]; if ($p) { $p.Value } else { $null } }
    $e = [ordered]@{}
    $d = 0.0
    $inv = [System.Globalization.CultureInfo]::InvariantCulture
    $x = & $g 'exposureImpact'
    if ($x -is [double] -or $x -is [decimal] -or $x -is [single] -or $x -is [int] -or $x -is [long]) { $e['si_exposure_impact'] = [Math]::Round([double]$x, 5) }
    elseif ($null -ne $x -and [double]::TryParse(([string]$x), [System.Globalization.NumberStyles]::Float, $inv, [ref]$d)) { $e['si_exposure_impact'] = [Math]::Round($d, 5) }
    $a = & $g 'activeAlert'
    if ($a -is [bool]) { $e['si_active_alert'] = $a }
    elseif ($null -ne $a -and "$a" -match '^(?i)(true|false)$') { $e['si_active_alert'] = ("$a" -ieq 'true') }
    # #1373 Defender's remediation type and the software it is about (as Defender states them)
    $rt = ([string](& $g 'remediationType')).Trim()
    if ($rt) {
        $e['si_recommendation_remediation_type'] = $rt
        $pn = ([string](& $g 'productName')).Trim(); if ($pn) { $e['si_recommendation_product'] = $pn }
        $vn = ([string](& $g 'vendor')).Trim(); if ($vn) { $e['si_recommendation_vendor'] = $vn }
    }
    if ($e.Count -eq 0) { return $null }
    return $e
}

function Merge-RADefenderRecommendationEntry {
    <#
        PURE. Two entries as one: the highest exposure impact; an active alert when either has one, none only when one
        says none and the other does not say otherwise. A value neither states stays out.
    #>
    param($A, $B)
    if ($null -eq $A) { return $B }
    if ($null -eq $B) { return $A }
    $e = [ordered]@{}
    $ia = if ($A.Contains('si_exposure_impact')) { [double]$A['si_exposure_impact'] } else { $null }
    $ib = if ($B.Contains('si_exposure_impact')) { [double]$B['si_exposure_impact'] } else { $null }
    if ($null -ne $ia -and $null -ne $ib) { $e['si_exposure_impact'] = [Math]::Max($ia, $ib) }
    elseif ($null -ne $ia) { $e['si_exposure_impact'] = $ia }
    elseif ($null -ne $ib) { $e['si_exposure_impact'] = $ib }
    $aa = if ($A.Contains('si_active_alert')) { [bool]$A['si_active_alert'] } else { $null }
    $ab = if ($B.Contains('si_active_alert')) { [bool]$B['si_active_alert'] } else { $null }
    if ($aa -eq $true -or $ab -eq $true) { $e['si_active_alert'] = $true }
    elseif ($null -ne $aa -or $null -ne $ab) { $e['si_active_alert'] = $false }
    # #1373 the remediation type and its software: the first entry that states them (one recommendation, one type)
    foreach ($n in 'si_recommendation_remediation_type', 'si_recommendation_product', 'si_recommendation_vendor') {
        if ($A.Contains($n) -and [string]$A[$n]) { $e[$n] = $A[$n] } elseif ($B.Contains($n) -and [string]$B[$n]) { $e[$n] = $B[$n] }
    }
    return $e
}

function Get-RADefenderRecommendationIndex {
    <#
    .SYNOPSIS  The run's recommendation index (key -> entry), read once and cached; @{ Index; Complete; Error; Read }.
               Never throws.
    .PARAMETER Fetch  test seam: { param($url) @{ Rows; Complete; Error } } instead of the Defender API.
    #>
    param([scriptblock]$Fetch, [switch]$Refresh)
    if ($null -ne $global:RA_DefenderRecIndex -and -not $Refresh) { return $global:RA_DefenderRecIndex }
    # names no helper on the call path uses: the page block below runs inside the pager and finds them by scope
    $raRecState = @{ Index = @{}; Complete = $false; Error = $null; Read = 0; PageRows = 0; PageFirst = '' }
    $raRecKeep = {
        param($raRecPage)
        foreach ($raRecItem in @($raRecPage)) {
            if ($null -eq $raRecItem) { continue }
            $raRecState.Read++
            $raRecState.PageRows++
            if ($raRecState.PageRows -eq 1) { $p0 = $raRecItem.PSObject.Properties['id']; if ($p0) { $raRecState.PageFirst = [string]$p0.Value } }
            $raRecEntry = ConvertTo-RADefenderRecommendationEntry -Item $raRecItem
            if ($null -eq $raRecEntry) { continue }
            foreach ($raRecKey in @(Get-RADefenderRecommendationKey -Item $raRecItem)) {
                $raRecState.Index[$raRecKey] = Merge-RADefenderRecommendationEntry -A $raRecState.Index[$raRecKey] -B $raRecEntry
            }
        }
        # a long read is never silent: how far it is, at most every 30 s (the state keeps when it last said so)
        if ($raReadSw -and ($raReadSw.Elapsed.TotalSeconds - [double]$raRecState.SayAt) -ge 30) { $raRecState.SayAt = $raReadSw.Elapsed.TotalSeconds; Write-RADefenderReadInfo ('Defender''s recommendation list: {0:N0} read so far, {1:N0} index entries ({2:N0} s so far)' -f $raRecState.Read, $raRecState.Index.Count, $raReadSw.Elapsed.TotalSeconds) }
    }
    # every request has a time limit (Invoke-RADefenderPagedRead) and the read says how far it is
    $raReadSw = [System.Diagnostics.Stopwatch]::StartNew()
    try {
        $token = $null
        if (-not $Fetch) {
            Write-RADefenderReadInfo ('reading Defender''s recommendation list once for this run (summarised by recommendation) ...')
            $siRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSScriptRoot))
            if (-not (Get-Command -Name Get-SIGraphToken -ErrorAction SilentlyContinue)) { . (Join-Path $siRoot 'auth\Get-SIGraphToken.ps1') }
            if (-not (Get-Command -Name Invoke-SIPagedRest -ErrorAction SilentlyContinue)) { . (Join-Path $siRoot 'engine\asset-profiling\shared\Invoke-SIPagedRest.ps1') }
            $token = Get-SIGraphToken -Resource Defender
            if (-not $token) { throw 'no token for the Defender API' }
        }
        # the first call follows the service's own next links to the end; a service that gives none returns exactly one
        # full page, and the read goes on by position until a page comes back short
        $skip = 0
        while ($true) {
            $url = '{0}?$top={1}' -f $script:RADefenderRecUrl, $script:RADefenderRecPageSize
            if ($skip -gt 0) { $url += ('&$skip={0}' -f $skip) }
            $raRecState.PageRows = 0
            $firstBefore = [string]$raRecState.PageFirst; $raRecState.PageFirst = ''
            $ok = $false; $err = $null; $pages = 1
            if ($Fetch) {
                $r = & $Fetch $url
                if ($null -ne $r) { $ok = [bool]$r.Complete; $err = $r.Error; & $raRecKeep $r.Rows }
                else { $err = 'no answer' }
            } else {
                $r = Invoke-RADefenderPagedRead -Url $url -Token $token -SourceLabel 'Defender recommendations' -TimeoutSec (Get-RADefenderReadTimeoutSeconds) -OnPage { param($raRecRows) & $raRecKeep $raRecRows }
                $ok = [bool]$r.Complete; $err = $r.Error
                if ([int]$r.Pages -gt 0) { $pages = [int]$r.Pages }
            }
            if (-not $ok) { $raRecState.Error = [string]$err; break }
            $got = [int]$raRecState.PageRows
            if ($pages -gt 1 -or $got -lt $script:RADefenderRecPageSize) { $raRecState.Complete = $true; break }
            # a service that ignores the position would hand the same full page for ever: the read must have moved on
            if ($skip -gt 0 -and $firstBefore -and [string]$raRecState.PageFirst -eq $firstBefore) { $raRecState.Error = 'the recommendation list did not move past its first page'; break }
            $skip += $got
        }
    } catch {
        $raRecState.Error = $_.Exception.Message
    }
    Write-RADefenderReadInfo ('Defender''s recommendation list read once for this run: {0:N0} read, {1:N0} index entries, in {2:N0} s{3}' -f $raRecState.Read, $raRecState.Index.Count, $raReadSw.Elapsed.TotalSeconds, $(if ($raRecState.Complete) { '' } else { ' -- NOT complete' }))
    $raRecState.Remove('SayAt')
    $raRecState.Remove('PageRows')
    $raRecState.Remove('PageFirst')
    $global:RA_DefenderRecIndex = $raRecState
    return $raRecState
}

function Get-RADefenderRecommendationReadMessage {
    <# PURE. What to tell the operator when the read did not complete -- plain words, no internals. '' when it did. #>
    param([hashtable]$State)
    if ($null -eq $State -or $State.Complete) { return '' }
    $err = [string]$State.Error
    if ($err -match '(?i)\b403\b|Forbidden|Unauthorized|\b401\b|does not have any of the required') {
        return 'The exposure impact and the active alert of the Defender recommendations were not read: the permission SecurityRecommendation.Read.All is not granted to SecurityInsight yet -- run the permission setup again and give admin consent. The vulnerability and configuration findings are complete without them; those two columns stay empty.'
    }
    return ('The exposure impact and the active alert of the Defender recommendations could not be read in this run ({0}). The vulnerability and configuration findings are complete without them; those two columns stay empty.' -f $err)
}

function Get-RADefenderRecommendationRowKeys {
    <# PURE. The index keys one finding row can be found by (see the header). @() for a row of another kind. #>
    param($Row)
    if ($null -eq $Row) { return @() }
    $p = $Row.PSObject.Properties['ConfigurationId']
    $cid = if ($p) { ([string]$p.Value).Trim().ToLowerInvariant() } else { '' }
    if ($cid -match '^scid-') { return @('sca|' + $cid) }
    if ($cid -notmatch '^cve-\d{4}-\d+$') { return @() }
    # each list: its ';' parts, trimmed, lower-cased, blanks dropped, each once (first place kept) -- a loop, not a pipeline
    # (this runs once per vulnerability row)
    $lists = foreach ($n in 'SI_AffectedVendor', 'SI_AffectedProduct') {
        $q = $Row.PSObject.Properties[$n]
        $l = [System.Collections.Generic.List[string]]::new()
        if ($q -and $null -ne $q.Value) {
            $seen = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::Ordinal)
            foreach ($part in (([string]$q.Value) -split ';')) { $x = $part.Trim().ToLowerInvariant(); if ($x -and $seen.Add($x)) { $l.Add($x) } }
        }
        , $l.ToArray()
    }
    $vendors = $lists[0]; $products = $lists[1]
    $keys = [System.Collections.Generic.List[string]]::new()
    foreach ($v in $vendors) { foreach ($pr in $products) { $keys.Add('va|' + $v + '|' + $pr) } }
    return $keys.ToArray()
}

function Add-RADefenderRecommendationContext {
    <#
    .SYNOPSIS  The Defender recommendation context on the rows (Add-RADefenderRecommendationContextCore), then #1373's title rule
               for a Defender for Cloud / Exposure Graph recommendation the Defender for Endpoint list does not hold
               (Add-RARecommendationTitleType). Returns the rows.
    #>
    param([AllowEmptyCollection()][object[]]$Rows = @(), [hashtable]$Index, [scriptblock]$Log, [string]$ReportName = '')
    $out = Add-RADefenderRecommendationContextCore -Rows $Rows -Index $Index -Log $Log
    $null = Add-RARecommendationTitleType -Rows @($out) -ReportName $ReportName
    return , @($out)
}

function Get-RARecommendationTitleTypeReports {
    <# PURE. #1373 the reports whose recommendations are Defender's own (Defender for Cloud, the Exposure Graph). #>
    , @('^(?i)Azure_DefenderRecommendations_', '^(?i)Azure_Recommendations_')
}

function Add-RARecommendationTitleType {
    <#
        PURE. #1373 (live on internal 3.1.50, collection 126: 179 of 180 Defender for Cloud "Update <software>" rows had no type --
        their assets are scanned by Defender for Cloud itself (containers, registries, servers without Defender for Endpoint), so
        Defender for Endpoint's recommendation list does not hold them). Defender names such a recommendation "<remediationType>
        <productName>" -- the type is the title's verb: a row of those reports titled "Update | Upgrade | Uninstall <one word>"
        (the product id: no space) that the Defender list did not type gets that verb as si_recommendation_remediation_type and the
        word as si_recommendation_product. Anything else (a title of several words, another report) is left as it is. Returns the
        rows typed.
    #>
    param([AllowEmptyCollection()][object[]]$Rows = @(), [string]$ReportName = '')
    $n = 0
    $reports = Get-RARecommendationTitleTypeReports
    foreach ($r in @($Rows)) {
        if ($null -eq $r -or -not $r.PSObject.Properties['ConfigurationName']) { continue }
        if ($r.PSObject.Properties['si_recommendation_remediation_type'] -and [string]$r.si_recommendation_remediation_type) { continue }
        $cid = if ($r.PSObject.Properties['ConfigurationId']) { [string]$r.ConfigurationId } else { '' }
        if ($cid -match '^(?i)(scid-|CVE-\d{4}-\d+$)') { continue }
        $rep = $ReportName
        if (-not $rep) { foreach ($c in 'ReportName', 'AssetDetectedInReportName') { if ($r.PSObject.Properties[$c] -and [string]$r.$c) { $rep = [string]$r.$c; break } } }
        $ok = $false; foreach ($p in $reports) { if ($rep -match $p) { $ok = $true; break } }
        if (-not $ok) { continue }
        $m = [regex]::Match(([string]$r.ConfigurationName).Trim(), '^(?i)(update|upgrade|uninstall)\s+(\S+)$')
        if (-not $m.Success) { continue }
        $verb = $m.Groups[1].Value.Substring(0, 1).ToUpperInvariant() + $m.Groups[1].Value.Substring(1).ToLowerInvariant()
        foreach ($kv in @(@('si_recommendation_remediation_type', $verb), @('si_recommendation_product', $m.Groups[2].Value))) {
            if ($r.PSObject.Properties[$kv[0]]) { $r.($kv[0]) = $kv[1] } else { $r.PSObject.Properties.Add([System.Management.Automation.PSNoteProperty]::new($kv[0], $kv[1])) }
        }
        $n++
    }
    $n
}

function Add-RADefenderRecommendationContextCore {
    <#
    .SYNOPSIS  Puts the exposure impact and the active alert of the Defender recommendation on every vulnerability and
               configuration row that names one. Returns the rows. Rows of other reports, and a run whose read did not
               complete, come back unchanged (the reason said once per run).
    .PARAMETER Index  test seam: the state of Get-RADefenderRecommendationIndex.
    .PARAMETER Log    { param($message) } for the one message (default Write-Warning).
    #>
    param([AllowEmptyCollection()][object[]]$Rows = @(), [hashtable]$Index, [scriptblock]$Log)
    if ($global:SI_RA_DefenderRecommendationContext -and ([string]$global:SI_RA_DefenderRecommendationContext).Trim().ToLowerInvariant() -in 'off', 'false', '0') { return , @($Rows) }
    # (a loop, not a pipeline over every row of the slice)
    $mineL = [System.Collections.Generic.List[object]]::new()
    # #1373 a recommendation row of another provider (not a Defender configuration id, not a CVE) with a title: Defender's
    # remediation type by that title
    $byTitleL = [System.Collections.Generic.List[object]]::new()
    foreach ($x in @($Rows)) {
        if ($null -eq $x -or -not $x.PSObject.Properties['ConfigurationId']) { continue }
        if ([string]$x.ConfigurationId -match '^(?i)(scid-|CVE-\d{4}-\d+$)') { $mineL.Add($x); continue }
        if ($x.PSObject.Properties['ConfigurationName'] -and ([string]$x.ConfigurationName).Trim()) { $byTitleL.Add($x) }
    }
    $mine = $mineL.ToArray()
    if ($mine.Count -eq 0 -and $byTitleL.Count -eq 0) { return , @($Rows) }
    if ($null -eq $Index) { $Index = Get-RADefenderRecommendationIndex }
    if ($null -eq $Index -or -not $Index.Complete) {
        if (-not $global:RA_DefenderRecSaid) {
            $global:RA_DefenderRecSaid = $true
            $msg = Get-RADefenderRecommendationReadMessage -State $Index
            if ($msg) { if ($Log) { & $Log $msg } else { Write-Warning $msg } }
        }
        return , @($Rows)
    }
    $ix = $Index.Index
    foreach ($r in $mine) {
        $e = $null
        foreach ($k in @(Get-RADefenderRecommendationRowKeys -Row $r)) {
            if ($ix.ContainsKey($k)) { $e = Merge-RADefenderRecommendationEntry -A $e -B $ix[$k] }
        }
        if ($null -eq $e) { continue }
        foreach ($name in 'si_exposure_impact', 'si_active_alert') {
            if (-not $e.Contains($name)) { continue }
            if ($r.PSObject.Properties[$name]) { $r.$name = $e[$name] } else { $r.PSObject.Properties.Add([System.Management.Automation.PSNoteProperty]::new($name, $e[$name])) }
        }
    }
    # #1373 the title rows: Defender's remediation type and its software, nothing else
    foreach ($r in $byTitleL) {
        $tk = ConvertTo-RADefenderRecommendationTitleKey ([string]$r.ConfigurationName)
        if (-not $tk -or -not $ix.ContainsKey($tk)) { continue }
        $e = $ix[$tk]
        if (-not $e.Contains('si_recommendation_remediation_type')) { continue }
        foreach ($name in 'si_recommendation_remediation_type', 'si_recommendation_product', 'si_recommendation_vendor') {
            if (-not $e.Contains($name)) { continue }
            if ($r.PSObject.Properties[$name]) { $r.$name = $e[$name] } else { $r.PSObject.Properties.Add([System.Management.Automation.PSNoteProperty]::new($name, $e[$name])) }
        }
    }
    return , @($Rows)
}
