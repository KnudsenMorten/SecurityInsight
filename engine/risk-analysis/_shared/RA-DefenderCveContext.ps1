#Requires -Version 5.1
<#
    THE EXPLOIT DETAILS OF A CVE THAT ADVANCED HUNTING DOES NOT CARRY -- from the Defender vulnerability API
    (GET https://api.securitycenter.microsoft.com/api/vulnerabilities, application permission Vulnerability.Read.All on
    WindowsDefenderATP, READ ONLY), put on the vulnerability rows of Risk Analysis before they are scored and stored:

      si_exploit_verified   the exploit is verified to work            (exploitVerified)
      si_in_exploit_kit     the exploit is part of an exploit kit      (exploitInKit)
      si_exploit_types      the kinds of exploit known, ';'-joined     (exploitTypes)
      si_exposed_devices    devices in the tenant exposed to the CVE   (exposedMachines)
    and, only where the row has none: si_epss (epss), si_cvss_vector (cvssVector), si_published (publishedOn).

    OPT-IN, DEFAULT OFF (SI_RA_DefenderCveApi = on; owner 2026-10-15). By default the CVE reports' own advanced-hunting
    query fills these fields -- exposed devices counted per CVE over the tenant's vulnerability management table, EPSS /
    CVSS vector / published date from its knowledge base, verified exploit / exploit kit from the Exposure Graph node --
    and nothing here calls the API. Exploit types, and verified / kit on rows the graph does not carry, stay unknown.

    WHY. The rows Defender vulnerability management adds beside the Exposure Graph (a CVE the graph does not carry) know
    "an exploit exists" and nothing more -- verified / in a kit were written as false, which reads as a fact. The API
    states them per CVE.

    ONLY THE REPORT'S OWN CVEs ARE READ, NEVER ONE TWICE IN A RUN: the distinct CVE ids of the rows being enriched are asked
    for with OData filters ($filter=id in ('CVE-a','CVE-b',...); when the service refuses that form on the run's first
    request, $filter=id eq 'CVE-a' or id eq 'CVE-b' ...), as many ids per request as keep the address
    under a length limit (SI_RA_DefenderCveFilterUrlMax, default 6,000 characters; split and sent again when the service
    says it is too long), the service's next links followed; a later slice asks only for the ids not asked yet and its
    answers join the same index. Kept, as in the whole-list read: the CVEs that expose at least one device of the tenant.
    Live 2026-10-15 on internal: the whole catalogue (351,176 CVEs, paged by position, deep pages up to 6 minutes each)
    took 27-71 minutes of a 35-78 minute Detailed report, to keep 6,661.
    THE WHOLE LIST, AS BEFORE, when the service refuses the filter on the run's first request (400 / 405 / 501, "not
    supported"), when it answers a filtered request with CVEs it was not asked for (it ignored the filter), or when
    SI_RA_DefenderCveRead = 'full': read once per run, paged (8,000 per page) -- said once in plain words.

    CONTEXT ONLY: nothing here changes a risk factor or a score -- those stay the report's (the Risk Analysis scoring
    block). A value the API does not give is left out (unknown), never written as false / 0.

    NEVER BLOCKS: a refused read (the permission is not granted yet) or a read that does not complete is said ONCE in
    plain words and the rows go on unchanged. PURE except Get-RADefenderCveIndex. PowerShell 7, REST only.
#>

$script:RADefenderCveUrl = 'https://api.securitycenter.microsoft.com/api/vulnerabilities'
$script:RADefenderCvePageSize = 8000

function Test-RADefenderCveApiOn {
    <# PURE over the setting. SI_RA_DefenderCveApi = on / true / 1 reads the Defender vulnerability API; default OFF. #>
    param($Setting = $global:SI_RA_DefenderCveApi)
    $null -ne $Setting -and ([string]$Setting).Trim().ToLowerInvariant() -in 'on', 'true', '1', 'yes'
}

function Write-RADefenderReadDiag {
    <# A verbose-only line (the engine's Write-Diag when it is loaded): per request timings and retries. #>
    param([string]$Line)
    if (Get-Command -Name Write-Diag -ErrorAction SilentlyContinue) { Write-Diag $Line }
}

function Get-RADefenderCveFilterUrlMax {
    <#
        PURE over the setting. The longest address of one filtered request: SI_RA_DefenderCveFilterUrlMax, default 6,000
        characters (well under the ~8 KB many web servers take). Not a row cap: the number of ids per request follows from
        it, and a request the service says is too long is split further.
    #>
    param($Setting = $global:SI_RA_DefenderCveFilterUrlMax)
    $n = 0
    if ($null -ne $Setting -and ([string]$Setting).Trim() -ne '' -and [int]::TryParse(([string]$Setting).Trim(), [ref]$n) -and $n -ge 200) { return $n }
    6000
}

function New-RADefenderCveFilterBatch {
    <#
        PURE. The next filtered request from position -Start of -Ids: as many ids as keep the address at most -MaxLength
        characters (at least one id, whatever its length). Returns @{ Ids; Url }. The ids are CVE ids (checked by the
        caller), so nothing in them needs quoting beyond the address encoding.
    #>
    param([Parameter(Mandatory)][AllowEmptyCollection()][string[]]$Ids, [int]$Start = 0, [int]$MaxLength = 6000, [string]$BaseUrl = $script:RADefenderCveUrl,
          # 'in' = id in ('a','b') (the shorter form; live 2026-10-15 the service takes it), 'or' = id eq 'a' or id eq 'b'
          [ValidateSet('in', 'or')][string]$Form = 'in')
    if ($Form -eq 'in') {
        $prefix = $BaseUrl + '?$filter=' + [uri]::EscapeDataString('id in ('); $sep = [uri]::EscapeDataString(','); $suffix = [uri]::EscapeDataString(')')
        $fmt = "'{0}'"
    } else {
        $prefix = $BaseUrl + '?$filter='; $sep = '%20or%20'; $suffix = ''
        $fmt = "id eq '{0}'"
    }
    $take = New-Object 'System.Collections.Generic.List[string]'
    $parts = New-Object 'System.Collections.Generic.List[string]'
    $len = $prefix.Length + $suffix.Length
    for ($i = $Start; $i -lt $Ids.Count; $i++) {
        $clause = [uri]::EscapeDataString(($fmt -f $Ids[$i]))
        $add = $clause.Length
        if ($take.Count -gt 0) { $add += $sep.Length }
        if ($take.Count -gt 0 -and ($len + $add) -gt $MaxLength) { break }
        $take.Add($Ids[$i]); $parts.Add($clause); $len += $add
    }
    [pscustomobject]@{ Ids = $take.ToArray(); Url = ($prefix + ($parts -join $sep) + $suffix); Form = $Form }
}

function Get-RADefenderErrorStatus {
    <# PURE. The HTTP status in a read's error text ('... -- HTTP 400 ...', '(400)'), 0 when it names none. #>
    param([string]$Text)
    if ($Text -match 'HTTP (\d{3})\b') { return [int]$Matches[1] }
    if ($Text -match '\((\d{3})\)') { return [int]$Matches[1] }
    0
}

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


function ConvertTo-RADefenderCveEntry {
    <# PURE. One vulnerability object of the API as the values a row takes: only what the API states. $null when it has no id. #>
    param($Item)
    if ($null -eq $Item) { return $null }
    $g = { param($n) $p = $Item.PSObject.Properties[$n]; if ($p) { $p.Value } else { $null } }
    $id = ([string](& $g 'id')).Trim().ToUpperInvariant()
    if (-not $id) { return $null }
    $e = [ordered]@{ Id = $id }
    foreach ($pair in @(@('exploitVerified', 'si_exploit_verified'), @('exploitInKit', 'si_in_exploit_kit'))) {
        $v = & $g $pair[0]
        if ($v -is [bool]) { $e[$pair[1]] = $v }
        elseif ($null -ne $v -and "$v" -match '^(?i)(true|false)$') { $e[$pair[1]] = ("$v" -ieq 'true') }
    }
    $types = @(@(& $g 'exploitTypes') | ForEach-Object { ([string]$_).Trim() } | Where-Object { $_ } | Sort-Object -Unique)
    if ($types.Count -gt 0) { $e['si_exploit_types'] = ($types -join ';') }
    $n = 0
    if ($null -ne (& $g 'exposedMachines') -and [int]::TryParse(([string](& $g 'exposedMachines')), [ref]$n)) { $e['si_exposed_devices'] = $n }
    $d = 0.0
    $inv = [System.Globalization.CultureInfo]::InvariantCulture
    $ep = & $g 'epss'
    if ($ep -is [double] -or $ep -is [decimal] -or $ep -is [single] -or $ep -is [int] -or $ep -is [long]) { $e['si_epss'] = [Math]::Round([double]$ep, 5) }
    elseif ($null -ne $ep -and [double]::TryParse(([string]$ep), [System.Globalization.NumberStyles]::Float, $inv, [ref]$d)) { $e['si_epss'] = [Math]::Round($d, 5) }
    $vec = ([string](& $g 'cvssVector')).Trim(); if ($vec) { $e['si_cvss_vector'] = $vec }
    $pub = & $g 'publishedOn'
    if ($pub -is [datetime]) { $e['si_published'] = $pub.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ', $inv) }
    elseif ($null -ne $pub -and "$pub".Trim()) { $e['si_published'] = "$pub".Trim() }
    return $e
}

function Read-RADefenderCveCatalogue {
    <#
    .SYNOPSIS  The WHOLE vulnerability list, paged, kept: the CVEs that expose at least one device of the tenant. Returns
               the state @{ Index; Complete; Error; Read; Mode = 'full' }. Never throws.
    .PARAMETER Fetch  test seam: { param($url) @{ Rows; Complete; Error } } instead of the Defender API.
    #>
    param([scriptblock]$Fetch)
    # names no helper on the call path uses: the page block below runs inside the pager and finds them by scope
    $raCveState = @{ Index = @{}; Complete = $false; Error = $null; Read = 0; PageRows = 0; PageFirst = '' }
    $raCveKeep = {
        param($raCvePage)
        foreach ($raCveItem in @($raCvePage)) {
            if ($null -eq $raCveItem) { continue }
            $raCveState.Read++
            $raCveState.PageRows++
            if ($raCveState.PageRows -eq 1) { $p0 = $raCveItem.PSObject.Properties['id']; if ($p0) { $raCveState.PageFirst = [string]$p0.Value } }
            $raCveExposed = 0
            $raCveProp = $raCveItem.PSObject.Properties['exposedMachines']
            if (-not $raCveProp -or -not [int]::TryParse(([string]$raCveProp.Value), [ref]$raCveExposed) -or $raCveExposed -le 0) { continue }
            $raCveEntry = ConvertTo-RADefenderCveEntry -Item $raCveItem
            if ($null -ne $raCveEntry) { $raCveState.Index[[string]$raCveEntry.Id] = $raCveEntry }
        }
        # a long read is never silent: how far it is, at most every 30 s (the state keeps when it last said so)
        if ($raReadSw -and ($raReadSw.Elapsed.TotalSeconds - [double]$raCveState.SayAt) -ge 30) { $raCveState.SayAt = $raReadSw.Elapsed.TotalSeconds; Write-RADefenderReadInfo ('Defender''s vulnerability list: {0:N0} read so far, {1:N0} concern this tenant''s devices ({2:N0} s so far)' -f $raCveState.Read, $raCveState.Index.Count, $raReadSw.Elapsed.TotalSeconds) }
    }
    # every request has a time limit (Invoke-RADefenderPagedRead) and the read says how far it is
    $raReadSw = [System.Diagnostics.Stopwatch]::StartNew()
    try {
        $token = $null
        if (-not $Fetch) {
            Write-RADefenderReadInfo ('reading Defender''s vulnerability list once for this run (the CVEs that concern this tenant''s devices are kept) ...')
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
            $url = '{0}?$top={1}' -f $script:RADefenderCveUrl, $script:RADefenderCvePageSize
            if ($skip -gt 0) { $url += ('&$skip={0}' -f $skip) }
            $raCveState.PageRows = 0
            $firstBefore = [string]$raCveState.PageFirst; $raCveState.PageFirst = ''
            $ok = $false; $err = $null; $pages = 1
            if ($Fetch) {
                $r = & $Fetch $url
                if ($null -ne $r) { $ok = [bool]$r.Complete; $err = $r.Error; & $raCveKeep $r.Rows }
                else { $err = 'no answer' }
            } else {
                $r = Invoke-RADefenderPagedRead -Url $url -Token $token -SourceLabel 'Defender vulnerabilities' -TimeoutSec (Get-RADefenderReadTimeoutSeconds) -OnPage { param($raCveRows) & $raCveKeep $raCveRows }
                $ok = [bool]$r.Complete; $err = $r.Error
                if ([int]$r.Pages -gt 0) { $pages = [int]$r.Pages }
            }
            if (-not $ok) { $raCveState.Error = [string]$err; break }
            $got = [int]$raCveState.PageRows
            if ($pages -gt 1 -or $got -lt $script:RADefenderCvePageSize) { $raCveState.Complete = $true; break }
            # a service that ignores the position would hand the same full page for ever: the read must have moved on
            if ($skip -gt 0 -and $firstBefore -and [string]$raCveState.PageFirst -eq $firstBefore) { $raCveState.Error = 'the vulnerability list did not move past its first page'; break }
            $skip += $got
        }
    } catch {
        $raCveState.Error = $_.Exception.Message
    }
    Write-RADefenderReadInfo ('Defender''s vulnerability list read once for this run: {0:N0} read, {1:N0} concern this tenant''s devices, in {2:N0} s{3}' -f $raCveState.Read, $raCveState.Index.Count, $raReadSw.Elapsed.TotalSeconds, $(if ($raCveState.Complete) { '' } else { ' -- NOT complete' }))
    $raCveState.Remove('SayAt')
    $raCveState.Remove('PageRows')
    $raCveState.Remove('PageFirst')
    $raCveState.Mode = 'full'
    return $raCveState
}

function Read-RADefenderCveById {
    <#
        Asks the service for -Ids (CVE ids, upper case, none asked before) with filtered requests and puts what it keeps
        into -State (the run's index). Returns 'ok', 'refused' (the service does not take the filter -- only on the run's
        first filtered request), 'ignored' (it answered with CVEs it was not asked for) or 'failed' (a request failed after
        the pager's retries: -State is then not complete). An id the service does not return is not in the catalogue: it
        is asked (never again this run) and stays unknown.
    #>
    param([Parameter(Mandatory)][hashtable]$State, [Parameter(Mandatory)][string[]]$Ids, [scriptblock]$Fetch, [string]$Token)
    $raIdBatch = @{ Ids = $null; Foreign = 0; Got = 0 }
    $raIdKeep = {
        param($raIdPage)
        foreach ($raIdItem in @($raIdPage)) {
            if ($null -eq $raIdItem) { continue }
            $raIdP = $raIdItem.PSObject.Properties['id']
            $raIdK = if ($raIdP) { ([string]$raIdP.Value).Trim().ToUpperInvariant() } else { '' }
            if (-not $raIdBatch.Ids.Contains($raIdK)) { $raIdBatch.Foreign++; continue }
            $raIdBatch.Got++
            $State.Read++
            # the same rule as the whole-list read: kept only when it exposes at least one device of the tenant
            $raIdExposed = 0
            $raIdProp = $raIdItem.PSObject.Properties['exposedMachines']
            if (-not $raIdProp -or -not [int]::TryParse(([string]$raIdProp.Value), [ref]$raIdExposed) -or $raIdExposed -le 0) { continue }
            $raIdEntry = ConvertTo-RADefenderCveEntry -Item $raIdItem
            if ($null -ne $raIdEntry) { $State.Index[[string]$raIdEntry.Id] = $raIdEntry }
        }
        # a service that ignored the filter would hand its whole list: stop at its first page
        if ($raIdBatch.Foreign -gt 0) { throw 'RA-DEFENDER-FILTER-IGNORED' }
    }
    $max = Get-RADefenderCveFilterUrlMax
    $pos = 0
    while ($pos -lt $Ids.Count) {
        if (-not $State.Form) { $State.Form = 'in' }
        $b = New-RADefenderCveFilterBatch -Ids $Ids -Start $pos -MaxLength $max -Form $State.Form
        $raIdBatch.Ids = [System.Collections.Generic.HashSet[string]]::new([string[]]$b.Ids, [System.StringComparer]::OrdinalIgnoreCase)
        $raIdBatch.Foreign = 0; $raIdBatch.Got = 0
        $sw = [System.Diagnostics.Stopwatch]::StartNew()
        $ok = $false; $err = $null; $retries = 0; $pages = 1
        try {
            if ($Fetch) {
                $r = & $Fetch $b.Url
                if ($null -ne $r) { $ok = [bool]$r.Complete; $err = [string]$r.Error; & $raIdKeep $r.Rows }
                else { $err = 'no answer' }
            } else {
                $r = Invoke-RADefenderPagedRead -Url $b.Url -Token $Token -SourceLabel 'Defender vulnerabilities' -TimeoutSec (Get-RADefenderReadTimeoutSeconds) -OnPage { param($raIdRows) & $raIdKeep $raIdRows }
                $ok = [bool]$r.Complete; $err = [string]$r.Error; $retries = [int]$r.Retries; $pages = [int]$r.Pages
            }
        } catch {
            if ($raIdBatch.Foreign -gt 0) {
                Write-RADefenderReadDiag ('Defender vulnerabilities: a filtered request of {0} ids was answered with {1} CVE(s) not asked for -- the filter was ignored' -f $b.Ids.Count, $raIdBatch.Foreign)
                return 'ignored'
            }
            $ok = $false; $err = $_.Exception.Message
        }
        $State.Requests++
        if (-not $ok) {
            $status = Get-RADefenderErrorStatus -Text $err
            $tooLong = ($status -in 414, 431) -or ($err -match '(?i)too long|URL.{0,20}length|query string')
            $notTaken = ($status -in 400, 405, 501) -or ($err -match '(?i)not supported|NotSupported|not implemented|invalid filter|filter parameter is invalid|could not find a property')
            if ($notTaken -and -not $tooLong -and $State.Form -eq 'in' -and [int]$State.FilteredOk -eq 0) {
                # the service does not take "id in (...)": the same ids as "id eq ... or id eq ..."
                Write-RADefenderReadDiag ('Defender vulnerabilities: the first request in the form id in (...) was refused (HTTP {0}) -- asking in the form id eq ... or ...' -f $status)
                $State.Form = 'or'
                continue
            }
            if (($tooLong -or $status -eq 400) -and $b.Ids.Count -gt 1) {
                # measure -> adapt: the address may be longer, or carry more conditions, than the service takes; split it
                # (always shorter than the refused address, so the next request carries fewer ids -- down to one)
                $max = [int][Math]::Floor($b.Url.Length / 2)
                Write-RADefenderReadDiag ('Defender vulnerabilities: a filtered request of {0} ids ({1} characters) was refused (HTTP {2}) -- asking again with addresses of at most {3} characters' -f $b.Ids.Count, $b.Url.Length, $status, $max)
                continue
            }
            if ($notTaken -and [int]$State.FilteredOk -eq 0) {
                Write-RADefenderReadDiag ('Defender vulnerabilities: the first filtered request was refused (HTTP {0}): {1}' -f $status, $err)
                return 'refused'
            }
            Write-RADefenderReadDiag ('Defender vulnerabilities: a filtered request of {0} ids failed after {1:N1} s: {2}' -f $b.Ids.Count, $sw.Elapsed.TotalSeconds, $err)
            $State.Complete = $false; $State.Error = $err
            return 'failed'
        }
        $State.FilteredOk++
        foreach ($id in $b.Ids) { $null = $State.Asked.Add($id) }
        Write-RADefenderReadDiag ('Defender vulnerabilities: request {0}: {1} ids asked, {2} returned, {3} page(s), {4} retries, {5:N0} ms, {6} characters' -f $State.Requests, $b.Ids.Count, $raIdBatch.Got, $pages, $retries, $sw.Elapsed.TotalMilliseconds, $b.Url.Length)
        $pos += $b.Ids.Count
    }
    'ok'
}

function Get-RADefenderCveIndex {
    <#
    .SYNOPSIS  The run's CVE index (CVE id, upper case -> entry); @{ Index; Complete; Error; Read; Mode }. Never throws.
               With -Ids: only those CVEs are asked for (filtered requests), the ones not asked yet this run; the
               answers join the run's index. Without -Ids (or SI_RA_DefenderCveRead = 'full', or a service that does
               not take the filter): the whole list, read once per run. Kept: the CVEs that expose at least one device.
    .PARAMETER Ids    the CVE ids of the rows being enriched.
    .PARAMETER Fetch  test seam: { param($url) @{ Rows; Complete; Error } } instead of the Defender API.
    #>
    param([string[]]$Ids, [scriptblock]$Fetch, [switch]$Refresh)
    $cached = $global:RA_DefenderCveIndex
    if ($Refresh) { $cached = $null }
    $byIds = $PSBoundParameters.ContainsKey('Ids') -and -not ($global:SI_RA_DefenderCveRead -and ([string]$global:SI_RA_DefenderCveRead).Trim().ToLowerInvariant() -eq 'full')
    # a whole-list read, and a read that did not complete, stand for the run
    if ($null -ne $cached -and (-not $byIds -or [string]$cached.Mode -ne 'ids' -or -not $cached.Complete)) { return $cached }
    if (-not $byIds) {
        $full = Read-RADefenderCveCatalogue -Fetch $Fetch
        $global:RA_DefenderCveIndex = $full
        return $full
    }
    $state = $cached
    if ($null -eq $state) {
        $state = @{ Index = @{}; Complete = $true; Error = $null; Read = 0; Mode = 'ids'; Requests = 0; FilteredOk = 0
                    Asked = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase) }
    }
    $want = New-Object 'System.Collections.Generic.List[string]'
    $seen = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($i in @($Ids)) {
        $k = ([string]$i).Trim().ToUpperInvariant()
        if ($k -notmatch '^CVE-\d{4}-\d+$') { continue }
        if ($state.Asked.Contains($k) -or -not $seen.Add($k)) { continue }
        $want.Add($k)
    }
    $global:RA_DefenderCveIndex = $state
    if ($want.Count -eq 0) { return $state }
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    $requestsBefore = [int]$state.Requests; $readBefore = [int]$state.Read; $keptBefore = $state.Index.Count
    $outcome = 'failed'
    try {
        $token = $null
        if (-not $Fetch) {
            $siRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSScriptRoot))
            if (-not (Get-Command -Name Get-SIGraphToken -ErrorAction SilentlyContinue)) { . (Join-Path $siRoot 'auth\Get-SIGraphToken.ps1') }
            if (-not (Get-Command -Name Invoke-SIPagedRest -ErrorAction SilentlyContinue)) { . (Join-Path $siRoot 'engine\asset-profiling\shared\Invoke-SIPagedRest.ps1') }
            $token = Get-SIGraphToken -Resource Defender
            if (-not $token) { throw 'no token for the Defender API' }
        }
        Write-RADefenderReadInfo ('reading the details of {0:N0} vulnerabilities from Defender (only the ones these findings name) ...' -f $want.Count)
        $outcome = Read-RADefenderCveById -State $state -Ids $want.ToArray() -Fetch $Fetch -Token $token
    } catch {
        $state.Complete = $false; $state.Error = $_.Exception.Message
    }
    if ($outcome -in 'refused', 'ignored') {
        Write-RADefenderReadInfo 'Defender does not answer a read of single vulnerabilities here -- reading its whole vulnerability list once for this run instead (this takes longer).'
        $full = Read-RADefenderCveCatalogue -Fetch $Fetch
        $global:RA_DefenderCveIndex = $full
        return $full
    }
    Write-RADefenderReadInfo ('Defender''s details of {0:N0} vulnerabilities read in {1:N0} request(s) and {2:N0} s: {3:N0} found, {4:N0} concern this tenant''s devices{5}' -f $want.Count, ([int]$state.Requests - $requestsBefore), $sw.Elapsed.TotalSeconds, ([int]$state.Read - $readBefore), ($state.Index.Count - $keptBefore), $(if ($state.Complete) { '' } else { ' -- NOT complete' }))
    return $state
}

function Get-RADefenderCveReadMessage {
    <# PURE. What to tell the operator when the read did not complete -- plain words, no internals. '' when it did. #>
    param([hashtable]$State)
    if ($null -eq $State -or $State.Complete) { return '' }
    $err = [string]$State.Error
    if ($err -match '(?i)\b403\b|Forbidden|Unauthorized|\b401\b|does not have any of the required') {
        return 'The exploit details of the vulnerabilities (verified exploit, exploit kit, exposed devices) were not read from Defender: the permission Vulnerability.Read.All is not granted to SecurityInsight yet -- run the permission setup again and give admin consent. The vulnerability findings are complete without them; those columns stay empty.'
    }
    return ('The exploit details of the vulnerabilities (verified exploit, exploit kit, exposed devices) could not be read from Defender in this run ({0}). The vulnerability findings are complete without them; those columns stay empty.' -f $err)
}

function Add-RADefenderCveContext {
    <#
    .SYNOPSIS  Puts the API's exploit details on every row whose ConfigurationId is a CVE id. Returns the rows. Rows of
               other reports, and a run whose read did not complete, come back unchanged (the reason said once per run).
    .PARAMETER Index  test seam: the state of Get-RADefenderCveIndex.
    .PARAMETER Log    { param($message) } for the one message (default Write-Warning).
    .PARAMETER Fetch  test seam: handed to Get-RADefenderCveIndex (instead of the Defender API).
    #>
    param([AllowEmptyCollection()][object[]]$Rows = @(), [hashtable]$Index, [scriptblock]$Log, [scriptblock]$Fetch)
    if ($global:SI_RA_DefenderCveContext -and ([string]$global:SI_RA_DefenderCveContext).Trim().ToLowerInvariant() -in 'off', 'false', '0') { return , @($Rows) }
    # (a loop, not a pipeline over every row of the slice)
    $cveL = New-Object 'System.Collections.Generic.List[object]'
    foreach ($x in @($Rows)) { if ($null -ne $x -and $x.PSObject.Properties['ConfigurationId'] -and [string]$x.ConfigurationId -match '^(?i)CVE-\d{4}-\d+$') { $cveL.Add($x) } }
    $cveRows = $cveL.ToArray()
    if ($cveRows.Count -eq 0) { return , @($Rows) }
    # OPT-IN (owner 2026-10-15: "the report is a simple kusto query against defender xdr and pull vulnerabilities"): the
    # report's own query carries what advanced hunting knows (exposed devices, EPSS, CVSS vector, published date, the
    # graph's verified exploit / exploit kit); the API is read only when SI_RA_DefenderCveApi is on. An index handed in
    # (-Index) is applied as given.
    if ($null -eq $Index -and -not (Test-RADefenderCveApiOn)) { return , @($Rows) }
    if ($null -eq $Index) {
        # only the CVEs these rows name, the ones not read yet this run (Get-RADefenderCveIndex -Ids)
        $idSet = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
        foreach ($x in $cveRows) { $null = $idSet.Add(([string]$x.ConfigurationId).Trim().ToUpperInvariant()) }
        $idArr = New-Object string[] $idSet.Count; $idSet.CopyTo($idArr)
        $Index = Get-RADefenderCveIndex -Ids $idArr -Fetch $Fetch
    }
    if ($null -eq $Index -or -not $Index.Complete) {
        if (-not $global:RA_DefenderCveSaid) {
            $global:RA_DefenderCveSaid = $true
            $msg = Get-RADefenderCveReadMessage -State $Index
            if ($msg) { if ($Log) { & $Log $msg } else { Write-Warning $msg } }
        }
        return , @($Rows)
    }
    $ix = $Index.Index
    foreach ($r in $cveRows) {
        $k = ([string]$r.ConfigurationId).Trim().ToUpperInvariant()
        if (-not $ix.ContainsKey($k)) { continue }
        $e = $ix[$k]
        foreach ($name in 'si_exploit_verified', 'si_in_exploit_kit', 'si_exploit_types', 'si_exposed_devices') {
            if (-not $e.Contains($name)) { continue }
            if ($r.PSObject.Properties[$name]) { $r.$name = $e[$name] } else { $r.PSObject.Properties.Add([System.Management.Automation.PSNoteProperty]::new($name, $e[$name])) }
        }
        # only where the row has none: the report's own value (advanced hunting) wins
        foreach ($name in 'si_epss', 'si_cvss_vector', 'si_published') {
            if (-not $e.Contains($name)) { continue }
            $cur = $r.PSObject.Properties[$name]
            if ($cur -and $null -ne $cur.Value -and "$($cur.Value)".Trim() -ne '') { continue }
            if ($cur) { $r.$name = $e[$name] } else { $r.PSObject.Properties.Add([System.Management.Automation.PSNoteProperty]::new($name, $e[$name])) }
        }
    }
    return , @($Rows)
}
