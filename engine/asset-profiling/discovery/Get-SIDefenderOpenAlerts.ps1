#Requires -Version 5.1
<#
    Get-SIDefenderOpenAlerts -- the OPEN alerts per device (owner 2026-10-11: "Yes, add it"), next to the alerts of the
    last 30 days that advanced hunting gives (Get-SIDefenderDeviceContext.ps1). Advanced hunting does not carry an
    alert's status, so "open" cannot be said from it; the security alerts of Microsoft Graph do:

      GET /v1.0/security/alerts_v2 (SecurityAlert.Read.All -- read only), the alerts whose status is new or in progress,
      ONE tenant-wide paged read per run. Each page is summarised per device AS IT IS READ (the alert's device evidence
      names the Defender device id) and let go -- never a request per device, no cap on alerts or pages.

    Kept as the 'openAlerts' part of the device's Defender record (provider mde, record type device), so the data-model
    mapping (data-model/mappings/mde.locked.json, openAlerts.*) fills:

      si_open_alerts                    how many open alerts name the device (0 when the read was whole and none does)
      si_open_alerts_highest_severity   the highest severity among them (High / Medium / Low / Informational)
      si_open_alert_title / _id / _time the newest open alert: its title, its id and when it was raised

    UNKNOWN IS NOT ZERO. A read that is refused (the permission is not granted yet), fails, or stops before the last page
    writes NOTHING: the fields stay unknown. A refusal is said once with the permission to grant, a failure once with its
    reason. Only a WHOLE read lets a device without an open alert say 0.

    READ ONLY: nothing is written to Defender. Never throws. No PowerShell modules. PURE except Get-SIDefenderOpenAlerts
    and Add-SIDefenderOpenAlertParts. PowerShell 5.1 safe: no ?. / ??, no ternary.
#>


function Get-SIOpenAlertSeverityRank {
    <# PURE. An alert severity as a number to compare: high 4, medium 3, low 2, informational 1, anything else 0. #>
    param([AllowNull()][AllowEmptyString()][string]$Severity)
    switch (([string]$Severity).Trim().ToLowerInvariant()) {
        'high' { return 4 }
        'medium' { return 3 }
        'low' { return 2 }
        'informational' { return 1 }
        default { return 0 }
    }
}

function Get-SIOpenAlertSeverityName {
    <# PURE. The severity as the device fields say it (High / Medium / Low / Informational); '' when the source gives none. #>
    param([int]$Rank)
    switch ($Rank) {
        4 { return 'High' }
        3 { return 'Medium' }
        2 { return 'Low' }
        1 { return 'Informational' }
        default { return '' }
    }
}

function Test-SIOpenAlertStatus {
    <# PURE. Is the alert open? Status new or in progress (as Microsoft Graph spells them); resolved and unknown are not. #>
    param([AllowNull()][AllowEmptyString()][string]$Status)
    return (([string]$Status).Trim() -match '^(?i)(new|inProgress)$')
}

function ConvertTo-SIOpenAlertTime {
    <# PURE. An alert time as a UTC DateTime (Graph gives ISO 8601 text; a parsed response gives a DateTime); $null when unreadable. #>
    param($Value)
    if ($null -eq $Value) { return $null }
    if ($Value -is [datetime]) { return $Value.ToUniversalTime() }
    if ($Value -is [System.DateTimeOffset]) { return $Value.UtcDateTime }
    $t = ([string]$Value).Trim()
    if (-not $t) { return $null }
    $d = [datetime]::MinValue
    $styles = [System.Globalization.DateTimeStyles]::AdjustToUniversal -bor [System.Globalization.DateTimeStyles]::AssumeUniversal
    if ([datetime]::TryParse($t, [System.Globalization.CultureInfo]::InvariantCulture, $styles, [ref]$d)) { return $d }
    return $null
}

function Get-SIOpenAlertDeviceIds {
    <#
    .SYNOPSIS  PURE. The Defender device ids an alert names: the mdeDeviceId of each device evidence, lower-cased, each once.
               An evidence of another kind (a user, a file, a process) carries none and is passed over.
    #>
    param($Alert)
    $ids = New-Object System.Collections.Generic.List[string]
    if ($null -eq $Alert) { return @() }
    $ev = $null
    if ($Alert -is [System.Collections.IDictionary]) { $ev = $Alert['evidence'] } else { $p = $Alert.PSObject.Properties['evidence']; if ($p) { $ev = $p.Value } }
    foreach ($e in @($ev)) {
        if ($null -eq $e) { continue }
        $id = $null
        if ($e -is [System.Collections.IDictionary]) { $id = $e['mdeDeviceId'] } else { $p = $e.PSObject.Properties['mdeDeviceId']; if ($p) { $id = $p.Value } }
        $s = ([string]$id).Trim().ToLowerInvariant()
        if ($s -and -not $ids.Contains($s)) { $ids.Add($s) }
    }
    return $ids.ToArray()
}

function Add-SIOpenAlertsToSummary {
    <#
    .SYNOPSIS  PURE (it changes only -Summary). One page of alerts summarised per device: -Summary is Defender device id
               (lower) -> @{ Open; Rank; Title; Id; Time }. An alert that is not open is passed over (the read asks for
               the open ones; a source that answers more is still read right). Returns the number of open alerts in the page.
    #>
    param([AllowNull()]$Alerts, [Parameter(Mandatory)][hashtable]$Summary)
    $open = 0
    foreach ($a in @($Alerts)) {
        if ($null -eq $a) { continue }
        $g = { param($n) if ($a -is [System.Collections.IDictionary]) { $a[$n] } else { $p = $a.PSObject.Properties[$n]; if ($p) { $p.Value } else { $null } } }
        if (-not (Test-SIOpenAlertStatus ([string](& $g 'status')))) { continue }
        $open++
        $rank = Get-SIOpenAlertSeverityRank ([string](& $g 'severity'))
        $time = ConvertTo-SIOpenAlertTime (& $g 'createdDateTime')
        $title = ([string](& $g 'title')).Trim()
        $alertId = ([string](& $g 'id')).Trim()
        foreach ($dev in @(Get-SIOpenAlertDeviceIds -Alert $a)) {
            $s = $Summary[$dev]
            if ($null -eq $s) { $s = @{ Open = 0; Rank = 0; Title = ''; Id = ''; Time = $null }; $Summary[$dev] = $s }
            $s['Open'] = [int]$s['Open'] + 1
            if ($rank -gt [int]$s.Rank) { $s.Rank = $rank }
            # the newest alert: the latest time; an alert without a readable time only when nothing is kept yet
            $newer = $false
            if ($null -ne $time) { $newer = ($null -eq $s.Time -or $time -gt $s.Time) }
            elseif ($null -eq $s.Time -and -not $s.Id) { $newer = $true }
            if ($newer) { $s.Title = $title; $s.Id = $alertId; $s.Time = $time }
        }
    }
    return $open
}

function ConvertTo-SIOpenAlertPart {
    <#
    .SYNOPSIS  PURE. A device's summary as its 'openAlerts' record part. Without a summary (-Summary $null) the device has
               no open alert: Open 0 and nothing else -- only called after a WHOLE read.
    #>
    param($Summary)
    $o = [ordered]@{ Open = 0 }
    if ($null -eq $Summary) { return [pscustomobject]$o }
    $o['Open'] = [int]$Summary['Open']
    $sev = Get-SIOpenAlertSeverityName -Rank ([int]$Summary.Rank)
    if ($sev) { $o['HighestSeverity'] = $sev }
    if ([string]$Summary.Title) { $o['Title'] = [string]$Summary.Title }
    if ([string]$Summary.Id) { $o['Id'] = [string]$Summary.Id }
    if ($null -ne $Summary.Time) { $o['Time'] = ([datetime]$Summary.Time).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss.fffZ', [System.Globalization.CultureInfo]::InvariantCulture) }
    return [pscustomobject]$o
}

function Get-SIOpenAlertReadOutcome {
    <# PURE. What a failed read of the open alerts means: 'refused' (the identity lacks the permission), 'filter' (the source
       does not accept the status filter: the read is made without it), or 'failed' (anything else). #>
    param([AllowNull()][AllowEmptyString()][string]$ErrorText)
    $t = [string]$ErrorText
    if ($t -match '(?i)\b403\b|forbidden|authorization_requestdenied|insufficient privileges|not authorized|missing application roles|does not have .*permission|access ?denied') { return 'refused' }
    if ($t -match '(?i)\b400\b|BadRequest|invalid filter|not supported|unsupported') { return 'filter' }
    return 'failed'
}

function Get-SIDefenderOpenAlerts {
    <#
    .SYNOPSIS  The open alerts of the tenant, summarised per device: ONE paged read, made once per run (the answer is kept
               for the later parts of the same run -- the same -RunId in this process; another run, or -Force, reads
               again). Never throws.
               Returns @{ RunId; Read; Complete; Alerts; ByDevice; Skipped }:
                 Read      the read was made and answered
                 Complete  every page was read (only then a device without an alert may say 0)
                 Alerts    open alerts read
                 ByDevice  Defender device id (lower) -> @{ Open; Rank; Title; Id; Time }
                 Skipped   why nothing is known ('' when the read was whole)
    .PARAMETER Fetch  (tests) { param($Url, $Label, $OnPage) } -> @{ Complete; Error; Rows } -- with $OnPage the rows go to
                      it page by page. Default: Invoke-SIPagedRest with this install's Graph token.
    .PARAMETER Log    { param($Level, $Message) } -- INFO / WARN. Default: the host.
    #>
    [CmdletBinding()]
    param([string]$Token, [scriptblock]$Fetch, [scriptblock]$Log, [string]$RunId = '', [switch]$Force)
    if (-not $Force -and $null -ne $global:SIDefenderOpenAlertsRead -and [string]$global:SIDefenderOpenAlertsRead.RunId -eq $RunId) { return $global:SIDefenderOpenAlertsRead }
    if (-not $Log) { $Log = { param($Level, $Message) if ($Level -eq 'WARN') { Write-Warning $Message } else { Write-Host ('[INFO] ' + $Message) } } }
    $alertsUrl = 'https://graph.microsoft.com/v1.0/security/alerts_v2'
    $openFilter = "status eq 'new' or status eq 'inProgress'"
    $permission = 'SecurityAlert.Read.All'
    $res = [pscustomobject]@{ RunId = $RunId; Read = $false; Complete = $false; Alerts = 0; ByDevice = @{}; Skipped = '' }
    try {
        if (-not $Fetch) {
            if (-not $Token) {
                if (-not (Get-Command -Name Get-SIGraphToken -ErrorAction SilentlyContinue)) { . (Join-Path $PSScriptRoot '../../../auth/Get-SIGraphToken.ps1') }
                $Token = Get-SIGraphToken -Resource Graph
            }
            if (-not (Get-Command -Name Invoke-SIPagedRest -ErrorAction SilentlyContinue)) { . (Join-Path (Split-Path -Parent $PSScriptRoot) 'shared/Invoke-SIPagedRest.ps1') }
            $tok = $Token
            $Fetch = {
                param($Url, $Label, $OnPage)
                $a = @{ Url = $Url; Token = $tok; SourceLabel = $Label; WarningAction = 'SilentlyContinue' }
                if ($OnPage) { $a['OnPage'] = $OnPage }
                Invoke-SIPagedRest @a
            }
        }
        # the read with the status filter; a source that does not accept the filter is read without it (the status of
        # every alert is checked as it is summarised either way)
        $urls = @(
            ($alertsUrl + '?$filter=' + [uri]::EscapeDataString($openFilter)),
            $alertsUrl
        )
        $err = ''; $complete = $false; $summary = @{}; $count = 0
        foreach ($url in $urls) {
            $summary = @{}; $state = @{ Open = 0 }; $err = ''; $page = $null
            $onPage = { param($Rows) $state.Open += (Add-SIOpenAlertsToSummary -Alerts $Rows -Summary $summary) }
            try { $page = & $Fetch $url 'Defender open alerts' $onPage } catch { $err = [string]$_.Exception.Message }
            if ($page -and $page.PSObject.Properties['Error'] -and [string]$page.Error) { $err = [string]$page.Error }
            # a caller's fetch that returns the rows instead of handing them page by page
            if ($page -and $page.PSObject.Properties['Rows'] -and @($page.Rows).Count -gt 0 -and $state.Open -eq 0 -and $summary.Count -eq 0) { & $onPage @($page.Rows) }
            $count = [int]$state.Open
            $complete = (-not $err)
            if ($complete -and $page -and $page.PSObject.Properties['Complete'] -and $null -ne $page.Complete) { $complete = [bool]$page.Complete }
            if (-not $err) { break }
            # only a refused FILTER is worth the second read; a missing permission or an outage answers the same again
            if ((Get-SIOpenAlertReadOutcome -ErrorText $err) -ne 'filter') { break }
        }
        if ($err -or -not $complete) {
            $why = Get-SIOpenAlertReadOutcome -ErrorText $err
            if ($why -eq 'refused') {
                $res.Skipped = ('not permitted: the identity may not read the security alerts ({0})' -f $permission)
                & $Log 'INFO' ('Defender open alerts: not read -- the identity lacks {0} (Microsoft Graph, read only). Grant it with Grant-SIIdentity.ps1 and give admin consent to see how many open alerts each device has, their highest severity and the newest one. Until then those device fields stay unknown (never 0); the alerts of the last 30 days are unaffected.' -f $permission)
            } else {
                if (-not $err) { $err = 'the read stopped before the last page' }
                $res.Skipped = 'the read failed'
                & $Log 'WARN' ('Defender open alerts: the read did not complete ({0}) -- the open alert fields of the devices stay unknown this run (never 0); the alerts of the last 30 days are unaffected.' -f $err)
            }
        } else {
            $res.Read = $true; $res.Complete = $true; $res.Alerts = $count; $res.ByDevice = $summary
            & $Log 'INFO' ('Defender open alerts: {0} open alert(s) read in one tenant-wide read; {1} device(s) are named by at least one' -f $count, $summary.Count)
        }
    } catch {
        $res.Skipped = 'the read failed'
        & $Log 'WARN' ('Defender open alerts: could not be read ({0}) -- the open alert fields stay unknown this run; the run continues.' -f $_.Exception.Message)
    }
    $global:SIDefenderOpenAlertsRead = $res
    return $res
}

function Add-SIDefenderOpenAlertParts {
    <#
    .SYNOPSIS  Keeps the open alerts of the given Defender device ids as the 'openAlerts' part of each device's record --
               from the one tenant-wide read of this run. A device no open alert names gets Open 0, but ONLY when the
               read was whole; otherwise no device gets a part (unknown, never 0). Returns the number of devices that
               got one. Does nothing without the record capture. Never throws.
    #>
    param([Parameter(Mandatory)][AllowEmptyCollection()][string[]]$DeviceIds, [string]$Token, [scriptblock]$Fetch, [scriptblock]$Log, [string]$RunId = '', [switch]$Force)
    if (-not (Get-Command -Name Add-SIRecordPart -ErrorAction SilentlyContinue)) { return 0 }
    $ids = @($DeviceIds | Where-Object { $_ } | ForEach-Object { ([string]$_).Trim().ToLowerInvariant() } | Sort-Object -Unique)
    if ($ids.Count -eq 0) { return 0 }
    $a = @{}
    if ($Token) { $a['Token'] = $Token }
    if ($Fetch) { $a['Fetch'] = $Fetch }
    if ($Log) { $a['Log'] = $Log }
    if ($RunId) { $a['RunId'] = $RunId }
    if ($Force) { $a['Force'] = $true }
    $read = Get-SIDefenderOpenAlerts @a
    if ($null -eq $read -or -not $read.Read -or -not $read.Complete) { return 0 }
    $n = 0
    foreach ($id in $ids) {
        try { Add-SIRecordPart -Provider 'mde' -RecordType 'device' -Key $id -Part 'openAlerts' -Object (ConvertTo-SIOpenAlertPart -Summary $read.ByDevice[$id]); $n++ } catch { }
    }
    return $n
}
