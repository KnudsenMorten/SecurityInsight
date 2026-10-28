#Requires -Version 5.1
<#
    SecurityInsight -- THE NIGHTLY SCHEDULE (owner 2026-10-21: "i propose that we move the start time for all si jobs to 7pm
    on all sites" / "so they are done next morning"; before that, 2026-10-15: "we need it to be complete hopefully by 8am
    next day" / "11pm danish time", then "can we take 11pm local time for region"): on EVERY install,
      * the UPDATER runs at 18:30, and
      * the Daily PIPELINE starts after it, at 19:00,
    in the time zone of THE AZURE REGION the install runs in

    THE 19:00 MOVE (2026-10-21; step 9l of the update, AFTER the region step 9c below). The region step (2026-10-15) put
    every install on 23:00 / 23:30 in its region's zone; this step moves ONLY those SHIPPED values, ONCE, under its own
    marker (job tag si-nightly-1900; Pro cfg.InstallState 'NightlySchedule1900'; a folder .si-update\nightly-schedule-1900.json):
      * the updater's job: the region zone's 23:00 ticks with the tag '23:00 <zone>' -> the zone's 18:30 ticks (e.g.
        Europe/Amsterdam '30 16,17 * * *'; a zone without daylight saving one tick) and the tag '18:30 <zone>' (one
        read-modify-write PATCH of trigger + tags, read back);
      * the pipeline start: '23:30' with the region's zone (the region step's value) -> '19:00' in the same zone (Pro:
        cfg.Setting + cfg.JobFlow in one transaction with change-log rows; a folder: config\SecurityInsight.custom.ps1 +
        config\job-flow.custom.json). Where the region step has not run yet (a plan, or a region step that failed this
        time), the values IT would move are this step's shipped values too, so the end state is the same.
    A value the customer set (anything else) stays, said in one plain line. Never fails the update; -DetectOnly plans only.
    The updater still runs BEFORE the pipeline the same evening (18:30 < 19:00); a release roll started by hand is unaffected.
    The text below describes the region step (23:00 / 23:30), which stays as the first of the two moves.

    (the region step, 2026-10-15:) the updater at 23:00 and the pipeline at 23:30 in the time zone of the install's region (the location of its Container Apps environment, else of its
    resource group) -- westeurope -> Europe/Amsterdam, northeurope -> Europe/Dublin, eastus -> America/New_York, ... -- so
    the night's collection, correlation and delivery are complete by 08:00 local time. Not the install's own configured
    zone. A region SecurityInsight does not know uses Danish time (Europe/Copenhagen), said in one plain line.

    THE UPDATER'S TIMER. A Container Apps job's cron is UTC only. The UTC hours that are 23:00 in the zone are computed FROM
    THE ZONE (Get-SINightlyUpdaterCron: its standard and its daylight-saving offset) -- Europe/Amsterdam 21:00 + 22:00 UTC
    ('0 21,22 * * *'), America/New_York '0 3,4 * * *', a zone without daylight saving (Asia/Tokyo) ONE tick ('0 14 * * *').
    The job records the zone in its tag si-nightly-schedule ('23:00 <zone>'), and the updater checks that zone's clock when
    it starts (Test-SIUpdaterNightlyTick): the tick that is 23:00 there runs; the other one ends at once with one plain line
    -- not a failure. The check applies only to an updater on exactly its zone's ticks; a timer the customer chose, and a run
    started by hand, by a release or by the web app, always run. Right all year, daylight saving included.

    EXISTING INSTALLS reach the new state through the update (rule: every setup default change needs an updater step), ONCE
    under the marker of this step (job tag si-nightly-region; Pro cfg.InstallState 'NightlyScheduleRegion'; a folder
    .si-update\nightly-schedule-region.json). Only SHIPPED values move; a customer's own value stays untouched:
      * the updater's job: the old shipped '0 3 * * *' (a job the Danish-time step never reached), and the Danish-time
        step's own values -- '0 21,22 * * *' with the tag '23:00 Europe/Copenhagen' (or without a tag: what a new install
        of that release wrote) -- get the region's ticks (one read-modify-write PATCH of trigger + tags, read back).
      * the pipeline start (Pro: cfg.Setting + cfg.JobFlow, in one transaction with its change-log rows; a folder:
        config\SecurityInsight.custom.ps1 + config\job-flow.custom.json): '23:30' + 'Europe/Copenhagen' (the Danish-time
        step's value) gets the region's zone; the old shipped '22:00' becomes 23:30 in the region's zone -- only where the
        Danish-time step never ran (after it, a 22:00 is a value the customer set again). The zone is STORED with the time.
    NEW INSTALLS use the region's time FROM THE START: the guided install (SI-GuidedInstall.ps1) writes the pipeline's 19:00
    with the region's zone, Install-SIUpdaterJob.ps1 gives the updater the region zone's 18:30 ticks and the tags
    ('18:30 <zone>', the region, si-nightly-1900) -- all from Get-SINightlyNewInstallSchedule -- and the install records BOTH
    one-time steps' markers (the job tags si-nightly-region + si-nightly-1900, cfg.InstallState 'NightlyScheduleRegion' +
    'NightlySchedule1900', .si-update\nightly-schedule-region.json + nightly-schedule-1900.json), so the update finds nothing
    to move. A region SecurityInsight does not know: Danish time, said in one plain line.
    Everything that decides is PURE; the Azure / SQL / file calls go through seams.
#>

$script:SINightly = @{
    Zone             = 'Europe/Copenhagen'     # the fallback for a region SecurityInsight does not know
    ZoneWindows      = 'Romance Standard Time'
    UpdaterHour      = 23
    UpdaterCron      = '0 21,22 * * *'         # the Danish-time step's ticks (a new install writes its region zone's ticks)
    OldUpdaterCron   = '0 3 * * *'
    ShippedJobTag    = '23:00 Europe/Copenhagen'
    TickWindowMin    = 10
    PipelineStart    = '23:30'
    OldPipelineStart = '22:00'
    Marker           = 'NightlyScheduleRegion'
    OldMarker        = 'NightlySchedule'
    JobTag           = 'si-nightly-schedule'
    RegionTag        = 'si-nightly-region'
    MarkerFile       = 'nightly-schedule-region.json'
    OldMarkerFile    = 'nightly-schedule.json'
    By               = 'SecurityInsight update'
    # the 19:00 move (owner 2026-10-21): what a new install writes and what step 9l moves the region step's values to
    At               = '18:30'                 # the updater, local time of the region
    Start            = '19:00'                 # the pipeline, local time of the region
    RegionAt         = '23:00'                 # the region step's updater time (what step 9l moves from)
    AtCron           = '30 16,17 * * *'        # 18:30 Danish time in UTC -- the fallback when a zone's ticks cannot be computed
    Marker1900       = 'NightlySchedule1900'
    Tag1900          = 'si-nightly-1900'
    MarkerFile1900   = 'nightly-schedule-1900.json'
}

# Azure public regions -> the IANA time zone of the region's location.
$script:SIRegionZones = [ordered]@{
    # Americas
    'eastus' = 'America/New_York'; 'eastus2' = 'America/New_York'; 'eastus3' = 'America/New_York'; 'eastus2euap' = 'America/New_York'
    'centralus' = 'America/Chicago'; 'northcentralus' = 'America/Chicago'; 'southcentralus' = 'America/Chicago'; 'centraluseuap' = 'America/Chicago'
    'westcentralus' = 'America/Denver'; 'westus' = 'America/Los_Angeles'; 'westus2' = 'America/Los_Angeles'; 'westus3' = 'America/Phoenix'
    'canadacentral' = 'America/Toronto'; 'canadaeast' = 'America/Toronto'
    'brazilsouth' = 'America/Sao_Paulo'; 'brazilsoutheast' = 'America/Sao_Paulo'
    'mexicocentral' = 'America/Mexico_City'; 'chilecentral' = 'America/Santiago'
    # Europe
    'northeurope' = 'Europe/Dublin'; 'westeurope' = 'Europe/Amsterdam'
    'uksouth' = 'Europe/London'; 'ukwest' = 'Europe/London'
    'francecentral' = 'Europe/Paris'; 'francesouth' = 'Europe/Paris'
    'germanywestcentral' = 'Europe/Berlin'; 'germanynorth' = 'Europe/Berlin'
    'switzerlandnorth' = 'Europe/Zurich'; 'switzerlandwest' = 'Europe/Zurich'
    'norwayeast' = 'Europe/Oslo'; 'norwaywest' = 'Europe/Oslo'
    'swedencentral' = 'Europe/Stockholm'; 'swedensouth' = 'Europe/Stockholm'
    'denmarkeast' = 'Europe/Copenhagen'; 'finlandcentral' = 'Europe/Helsinki'
    'polandcentral' = 'Europe/Warsaw'; 'italynorth' = 'Europe/Rome'; 'spaincentral' = 'Europe/Madrid'
    'austriaeast' = 'Europe/Vienna'; 'belgiumcentral' = 'Europe/Brussels'; 'greececentral' = 'Europe/Athens'
    # Middle East and Africa
    'israelcentral' = 'Asia/Jerusalem'; 'qatarcentral' = 'Asia/Qatar'
    'uaenorth' = 'Asia/Dubai'; 'uaecentral' = 'Asia/Dubai'; 'saudiarabiaeast' = 'Asia/Riyadh'
    'southafricanorth' = 'Africa/Johannesburg'; 'southafricawest' = 'Africa/Johannesburg'
    # Asia Pacific
    'centralindia' = 'Asia/Kolkata'; 'southindia' = 'Asia/Kolkata'; 'westindia' = 'Asia/Kolkata'
    'jioindiacentral' = 'Asia/Kolkata'; 'jioindiawest' = 'Asia/Kolkata'
    'eastasia' = 'Asia/Hong_Kong'; 'southeastasia' = 'Asia/Singapore'
    'japaneast' = 'Asia/Tokyo'; 'japanwest' = 'Asia/Tokyo'
    'koreacentral' = 'Asia/Seoul'; 'koreasouth' = 'Asia/Seoul'
    'australiaeast' = 'Australia/Sydney'; 'australiasoutheast' = 'Australia/Melbourne'
    'australiacentral' = 'Australia/Sydney'; 'australiacentral2' = 'Australia/Sydney'
    'newzealandnorth' = 'Pacific/Auckland'; 'indonesiacentral' = 'Asia/Jakarta'; 'malaysiawest' = 'Asia/Kuala_Lumpur'
    'taiwannorth' = 'Asia/Taipei'; 'taiwannorthwest' = 'Asia/Taipei'
}

function Get-SINightlyRegionZone {
    <#
        PURE. The install's Azure region (a name, 'westeurope', or the display form 'West Europe') -> @{ Region; Zone; Known;
        Line }. A region not in the map (or none) -> Europe/Copenhagen, and Line says so in one plain line ('' when known).
    #>
    param([AllowEmptyString()][AllowNull()][string]$Region)
    $r = ("$Region".ToLowerInvariant()) -replace '[^a-z0-9]', ''
    if ($r -and $script:SIRegionZones.Contains($r)) { return [pscustomobject]@{ Region = $r; Zone = [string]$script:SIRegionZones[$r]; Known = $true; Line = '' } }
    $line = if ($r) { "The Azure region '$r' has no time zone known to SecurityInsight -- the nightly update and pipeline use Danish time (Europe/Copenhagen)." }
            else { "The install's Azure region is not known -- the nightly update and pipeline use Danish time (Europe/Copenhagen)." }
    [pscustomobject]@{ Region = $r; Zone = $script:SINightly.Zone; Known = $false; Line = $line }
}

function Get-SINightlyZone {
    <# A time zone on this machine: -Id an IANA id (default Europe/Copenhagen) or a TimeZoneInfo; $null when not known. #>
    param($Id = $script:SINightly.Zone)
    if ($Id -is [TimeZoneInfo]) { return $Id }
    $s = "$Id".Trim(); if (-not $s) { return $null }
    $ids = @($s)
    if ($s -eq $script:SINightly.Zone) { $ids += $script:SINightly.ZoneWindows }
    try { $w = $null; if ([TimeZoneInfo].GetMethod('TryConvertIanaIdToWindowsId', [type[]]@([string], [string].MakeByRefType())) -and [TimeZoneInfo]::TryConvertIanaIdToWindowsId($s, [ref]$w)) { $ids += $w } } catch { }
    foreach ($x in $ids) { try { return [TimeZoneInfo]::FindSystemTimeZoneById($x) } catch { } }
    $null
}

function Get-SINightlyZoneId {
    <# PURE. The IANA id to show / store for -Zone (a string id, or a TimeZoneInfo). #>
    param($Zone)
    if ($Zone -is [TimeZoneInfo]) { if ($Zone.Id -eq $script:SINightly.ZoneWindows) { return $script:SINightly.Zone }; return $Zone.Id }
    "$Zone".Trim()
}

function Get-SINightlyUpdaterTicks {
    <#
        PURE. The UTC times that are -At (HH:mm; default 18:30, the updater's time) in -Zone over a year (every day's -At,
        converted): one per offset the zone uses -- two for a zone with daylight saving, one for a zone without. Sorted.
        @( @{ Hour; Minute } ); empty = zone not known.
    #>
    param($Zone, [int]$Year = [datetime]::UtcNow.Year, [string]$At = $script:SINightly.At)
    $tz = Get-SINightlyZone $Zone
    if (-not $tz) { return @() }
    $hm = [regex]::Match("$At", '^\s*(\d{1,2}):(\d{2})\s*$'); if (-not $hm.Success) { return @() }
    $seen = @{}
    $d = New-Object datetime($Year, 1, 1, [int]$hm.Groups[1].Value, [int]$hm.Groups[2].Value, 0, [DateTimeKind]::Unspecified)
    for ($i = 0; $i -lt 366; $i++) {
        $l = $d.AddDays($i); if ($l.Year -ne $Year) { break }
        if ($tz.IsInvalidTime($l)) { continue }
        $u = [TimeZoneInfo]::ConvertTimeToUtc($l, $tz)
        $seen['{0:00}:{1:00}' -f $u.Hour, $u.Minute] = [pscustomobject]@{ Hour = $u.Hour; Minute = $u.Minute }
    }
    @($seen.Keys | Sort-Object | ForEach-Object { $seen[$_] })
}

function Get-SINightlyUpdaterCron {
    <#
        PURE. The updater's cron for -Zone: its -At ticks in UTC (default 18:30: Europe/Amsterdam '30 16,17 * * *'; the region
        step's -At '23:00': '0 21,22 * * *'); '' = zone not known. A half-hour zone whose ticks differ in minutes is not one cron
        ('' -- the caller falls back).
    #>
    param($Zone, [int]$Year = [datetime]::UtcNow.Year, [string]$At = $script:SINightly.At)
    $t = @(Get-SINightlyUpdaterTicks -Zone $Zone -Year $Year -At $At)
    if (-not $t.Count) { return '' }
    if (@($t | ForEach-Object { $_.Minute } | Sort-Object -Unique).Count -gt 1) { return '' }
    '{0} {1} * * *' -f $t[0].Minute, ((@($t | ForEach-Object { $_.Hour } | Sort-Object -Unique)) -join ',')
}

function Test-SIUpdaterNightlyTick {
    <#
        PURE. Does THIS start of the updater go on? -Cron: the updater job's own cron ('' = not known). -Zone: the zone the
        job records (tag si-nightly-schedule; an IANA id or a TimeZoneInfo). -Mode: SI_UPDATER_MODE (a run started for a
        purpose). Only a start on one of the zone's ticks, on exactly the zone's timer, is checked: it goes on when it is 18:30
        in the zone (or 23:00 on the region step's ticks, a job the 19:00 move has not reached yet), and ends (Go $false) on
        the other tick. Everything else goes on. Returns @{ Go; Why; LocalTime }.
    #>
    param([Parameter(Mandatory)][datetime]$NowUtc, [AllowEmptyString()][string]$Cron = '', [AllowEmptyString()][string]$Mode = '', $Zone = $script:SINightly.Zone)
    $u = if ($NowUtc.Kind -eq 'Local') { $NowUtc.ToUniversalTime() } else { [datetime]::SpecifyKind($NowUtc, 'Utc') }
    $go = { param($why, $lt) [pscustomobject]@{ Go = $true; Why = $why; LocalTime = $lt } }
    if ("$Mode".Trim()) { return (& $go 'a run started for a purpose' $null) }
    $tz = if ($null -eq $Zone) { $null } else { Get-SINightlyZone $Zone }
    if (-not $tz) { return (& $go 'the time zone is not known on this machine -- the update runs' $null) }
    $zid = Get-SINightlyZoneId $(if ($Zone -is [TimeZoneInfo]) { $Zone } else { "$Zone" })
    $have = ("$Cron".Trim()) -replace '\s+', ' '
    $at = $null
    foreach ($a in @($script:SINightly.At, $script:SINightly.RegionAt)) {
        $want = Get-SINightlyUpdaterCron -Zone $tz -Year $u.Year -At $a
        if ($want -and $have -eq $want) { $at = $a; break }
    }
    if (-not $at) { return (& $go 'the updater runs on its own timer' $null) }
    $ticks = @(Get-SINightlyUpdaterTicks -Zone $tz -Year $u.Year -At $at)
    $onTick = @($ticks | Where-Object { $m = ($u.Hour * 60 + $u.Minute) - ($_.Hour * 60 + $_.Minute); $m -ge 0 -and $m -lt $script:SINightly.TickWindowMin }).Count
    if (-not $onTick) { return (& $go 'started by hand or by a release' $null) }
    $local = [TimeZoneInfo]::ConvertTimeFromUtc($u, $tz)
    if ($local.Hour -eq [int]($at.Split(':')[0])) { return (& $go ('{0:HH:mm} in {1}' -f $local, $zid) $local) }
    [pscustomobject]@{ Go = $false; LocalTime = $local
        Why = ('It is {0:HH:mm} in {1}: SecurityInsight updates at {2} in the time zone of its Azure region, so this start ends here (not a failure; the update runs at the other start time tonight).' -f $local, $zid, $at) }
}

function Test-SINightlyOldPipelineStart {
    <# PURE. Is -Value the old shipped start time -- '22:00' (also '22:00 local time', a JSON string '"22:00"')? #>
    param([AllowNull()]$Value)
    if ($null -eq $Value -or $Value -is [DBNull]) { return $false }
    $t = ([string]$Value).Trim().Trim('"').Trim()
    $t -match '^22:00( local( time)?)?$'
}

function Test-SINightlyShippedPipeline {
    <# PURE. Is -Start / -Zone exactly the Danish-time step's value: '23:30' with 'Europe/Copenhagen' (JSON strings allowed)? #>
    param([AllowNull()]$Start, [AllowNull()]$Zone)
    if ($null -eq $Start -or $Start -is [DBNull] -or $null -eq $Zone -or $Zone -is [DBNull]) { return $false }
    (([string]$Start).Trim().Trim('"').Trim() -eq $script:SINightly.PipelineStart) -and (([string]$Zone).Trim().Trim('"').Trim() -eq $script:SINightly.Zone)
}

function ConvertTo-SINightlyTagMap {
    <# PURE. A job's tags (object or dictionary) as an ordered dictionary. #>
    param($Job)
    $tags = [ordered]@{}
    if ($Job -and $Job.PSObject.Properties['tags'] -and $null -ne $Job.tags) {
        if ($Job.tags -is [System.Collections.IDictionary]) { foreach ($k in $Job.tags.Keys) { $tags[[string]$k] = [string]$Job.tags[$k] } }
        else { foreach ($p in $Job.tags.PSObject.Properties) { $tags[$p.Name] = [string]$p.Value } }
    }
    $tags
}

function Get-SINightlyJobCron {
    <# PURE. The job's cron ('' when it has no timer). #>
    param($Job)
    try { $c = $Job.properties.configuration; if ([string]$c.triggerType -eq 'Schedule' -and $c.scheduleTriggerConfig) { return ([string]$c.scheduleTriggerConfig.cronExpression).Trim() } } catch { }
    ''
}

function Get-SINightlyJobZone {
    <# PURE. The zone the updater job records (tag si-nightly-schedule '23:00 <zone>'); none -> Europe/Copenhagen (what a job without it was set to). #>
    param($Job)
    $t = ConvertTo-SINightlyTagMap $Job
    if ($t.Contains($script:SINightly.JobTag)) { $m = [regex]::Match([string]$t[$script:SINightly.JobTag], '^\s*\d{1,2}:\d{2}\s+(\S+)\s*$'); if ($m.Success) { return $m.Groups[1].Value } }
    $script:SINightly.Zone
}

function Get-SINightlyUpdaterCronPlan {
    <#
        PURE. What the update does to the updater job's timer (-Job: ARM GET shape; -Region: the install's Azure region, else
        the job's own location). @{ Action = done | change | keep; Cron; Zone; Region; Body (the PATCH: tags + the trigger
        only -- never the template or the secrets); Why; RegionLine }.
          done   -- the job carries the tag si-nightly-region: this step ran before, nothing changes
          change -- on a shipped timer (the old '0 3 * * *' the Danish-time step never reached, or that step's '0 21,22 * * *'
                    with its tag '23:00 Europe/Copenhagen' or no tag) -> the region's ticks, plus the tags
          keep   -- a timer the customer chose: kept; only the tags are added so the step never looks again
    #>
    param([Parameter(Mandatory)]$Job, [AllowEmptyString()][AllowNull()][string]$Region = '')
    $tags = ConvertTo-SINightlyTagMap $Job
    $name = [string]$Job.name
    if ($tags.Contains($script:SINightly.RegionTag)) { return [pscustomobject]@{ Action = 'done'; Cron = (Get-SINightlyJobCron $Job); Zone = (Get-SINightlyJobZone $Job); Region = [string]$tags[$script:SINightly.RegionTag]; Body = $null; Why = ('{0}: the nightly update time was set before -- nothing to change' -f $name); RegionLine = '' } }
    if (-not "$Region".Trim() -and $Job.PSObject.Properties['location']) { $Region = [string]$Job.location }
    $rz = Get-SINightlyRegionZone $Region
    $zone = $rz.Zone
    $zoneCron = Get-SINightlyUpdaterCron -Zone $zone -At $script:SINightly.RegionAt
    if (-not $zoneCron) { $zone = $script:SINightly.Zone; $zoneCron = $script:SINightly.UpdaterCron }
    $hadTag = $tags.Contains($script:SINightly.JobTag)
    $oldTag = if ($hadTag) { ([string]$tags[$script:SINightly.JobTag]).Trim() } else { '' }
    $isShipped = {
        param([string]$c)
        $n = ("$c".Trim()) -replace '\s+', ' '
        ($n -eq $script:SINightly.OldUpdaterCron -and -not $hadTag) -or ($n -eq $script:SINightly.UpdaterCron -and (-not $hadTag -or $oldTag -eq $script:SINightly.ShippedJobTag))
    }
    $cfg = $null; try { $cfg = $Job.properties.configuration } catch { }
    $cron = Get-SINightlyJobCron $Job
    $tags[$script:SINightly.JobTag] = '23:00 ' + $zone
    $tags[$script:SINightly.RegionTag] = $(if ($rz.Region) { $rz.Region } else { 'unknown' })
    $where = if ($rz.Known) { '{0}, the time zone of its Azure region ({1})' -f $zone, $rz.Region } else { $zone }
    $res = { param($a, $c, $b, $w) [pscustomobject]@{ Action = $a; Cron = $c; Zone = $zone; Region = $rz.Region; Body = $b; Why = $w; RegionLine = $rz.Line } }
    if ($cfg -and [string]$cfg.triggerType -eq 'Schedule' -and (& $isShipped $cron)) {
        $src = $cfg.scheduleTriggerConfig
        $par = 1; $rcc = 1
        if ($src.PSObject.Properties['parallelism'] -and $src.parallelism) { $par = $src.parallelism }
        if ($src.PSObject.Properties['replicaCompletionCount'] -and $src.replicaCompletionCount) { $rcc = $src.replicaCompletionCount }
        $c = [ordered]@{ triggerType = 'Schedule' }
        if ($cfg.PSObject.Properties['replicaTimeout'] -and $cfg.replicaTimeout) { $c.replicaTimeout = $cfg.replicaTimeout }
        $c.scheduleTriggerConfig = [ordered]@{ cronExpression = $zoneCron; parallelism = $par; replicaCompletionCount = $rcc }
        return (& $res 'change' $zoneCron ([ordered]@{ tags = $tags; properties = [ordered]@{ configuration = $c } }) ('{0}: the update runs at 23:00 in {1} (timer ''{2}'' UTC)' -f $name, $where, $zoneCron))
    }
    if ($cfg -and [string]$cfg.triggerType -ne 'Schedule' -and $tags.Contains('si-disabled-cron') -and (& $isShipped ([string]$tags['si-disabled-cron']))) {
        $tags['si-disabled-cron'] = $zoneCron
        return (& $res 'change' '' ([ordered]@{ tags = $tags }) ('{0} has no timer now; when it gets it back, it runs at 23:00 in {1}' -f $name, $where))
    }
    & $res 'keep' $cron ([ordered]@{ tags = $tags }) ('{0} runs on a timer of your own ({1}) -- kept' -f $name, $(if ($cron) { "'$cron' UTC" } else { 'none' }))
}

function Get-SINightly1900UpdaterPlan {
    <#
        PURE. The 19:00 move of the updater job's timer (owner 2026-10-21), once. -Job: ARM GET shape; -Region: the install's
        Azure region (else the job's own location). Same shape as Get-SINightlyUpdaterCronPlan: @{ Action = done | change |
        keep; Cron; Zone; Region; Body (tags + the trigger only); Why; RegionLine }.
          done   -- the job carries the tag si-nightly-1900
          change -- the region step's value: the zone's 23:00 ticks with the tag '23:00 <zone>' (or, where the region step
                    has not run yet, a value IT would move) -> the zone's 18:30 ticks + the tag '18:30 <zone>'
          keep   -- a timer the customer chose: kept; only the tag si-nightly-1900 is added so the step never looks again
    #>
    param([Parameter(Mandatory)]$Job, [AllowEmptyString()][AllowNull()][string]$Region = '')
    $tags = ConvertTo-SINightlyTagMap $Job
    $name = [string]$Job.name
    $S = $script:SINightly
    if ($tags.Contains($S.Tag1900)) { return [pscustomobject]@{ Action = 'done'; Cron = (Get-SINightlyJobCron $Job); Zone = (Get-SINightlyJobZone $Job); Region = [string]$tags[$S.RegionTag]; Body = $null; Why = ('{0}: the nightly update time was set before -- nothing to change' -f $name); RegionLine = '' } }
    $cfg = $null; try { $cfg = $Job.properties.configuration } catch { }
    $cron = Get-SINightlyJobCron $Job
    $line = ''; $reg = ''
    if ($tags.Contains($S.RegionTag)) {
        # the region step ran: its value is the zone's 23:00 ticks with the tag '23:00 <zone>'
        $zone = Get-SINightlyJobZone $Job
        $reg = [string]$tags[$S.RegionTag]
        $tag = if ($tags.Contains($S.JobTag)) { ([string]$tags[$S.JobTag]).Trim() } else { '' }
        $from = Get-SINightlyUpdaterCron -Zone $zone -At $S.RegionAt
        if (-not $from -and $zone -eq $S.Zone) { $from = $S.UpdaterCron }
        $isShipped = { param([string]$c) $from -and $tag -eq ($S.RegionAt + ' ' + $zone) -and ((("$c".Trim()) -replace '\s+', ' ') -eq $from) }
        $shippedNow = $cfg -and [string]$cfg.triggerType -eq 'Schedule' -and (& $isShipped $cron)
        $shippedOff = $cfg -and [string]$cfg.triggerType -ne 'Schedule' -and $tags.Contains('si-disabled-cron') -and (& $isShipped ([string]$tags['si-disabled-cron']))
    } else {
        # the region step has not run (a plan, or it failed this time): what IT would move is shipped here too
        $rp = Get-SINightlyUpdaterCronPlan -Job $Job -Region $Region
        $zone = $rp.Zone; $reg = $(if ($rp.Region) { $rp.Region } else { 'unknown' }); $line = $rp.RegionLine
        $shippedNow = $rp.Action -eq 'change' -and [bool]$rp.Cron
        $shippedOff = $rp.Action -eq 'change' -and -not $rp.Cron
    }
    $toCron = Get-SINightlyUpdaterCron -Zone $zone
    if (-not $toCron) { if ($zone -eq $S.Zone) { $toCron = $S.AtCron } else { $shippedNow = $false; $shippedOff = $false } }
    $tags[$S.Tag1900] = $zone
    if (-not $tags.Contains($S.RegionTag)) { $tags[$S.RegionTag] = $reg }
    $where = if ($reg -and $reg -ne 'unknown') { '{0}, the time zone of its Azure region ({1})' -f $zone, $reg } else { $zone }
    $res = { param($a, $c, $b, $w) [pscustomobject]@{ Action = $a; Cron = $c; Zone = $zone; Region = $reg; Body = $b; Why = $w; RegionLine = $line } }
    if ($shippedNow) {
        $tags[$S.JobTag] = $S.At + ' ' + $zone
        $src = $cfg.scheduleTriggerConfig
        $par = 1; $rcc = 1
        if ($src.PSObject.Properties['parallelism'] -and $src.parallelism) { $par = $src.parallelism }
        if ($src.PSObject.Properties['replicaCompletionCount'] -and $src.replicaCompletionCount) { $rcc = $src.replicaCompletionCount }
        $c = [ordered]@{ triggerType = 'Schedule' }
        if ($cfg.PSObject.Properties['replicaTimeout'] -and $cfg.replicaTimeout) { $c.replicaTimeout = $cfg.replicaTimeout }
        $c.scheduleTriggerConfig = [ordered]@{ cronExpression = $toCron; parallelism = $par; replicaCompletionCount = $rcc }
        return (& $res 'change' $toCron ([ordered]@{ tags = $tags; properties = [ordered]@{ configuration = $c } }) ('{0}: the update runs at {1} in {2} (timer ''{3}'' UTC), before the daily pipeline at {4}' -f $name, $S.At, $where, $toCron, $S.Start))
    }
    if ($shippedOff) {
        $tags[$S.JobTag] = $S.At + ' ' + $zone
        $tags['si-disabled-cron'] = $toCron
        return (& $res 'change' '' ([ordered]@{ tags = $tags }) ('{0} has no timer now; when it gets it back, it runs at {1} in {2}' -f $name, $S.At, $where))
    }
    & $res 'keep' $cron ([ordered]@{ tags = $tags }) ('{0} runs on a timer of your own ({1}) -- kept' -f $name, $(if ($cron) { "'$cron' UTC" } else { 'none' }))
}

function Get-SINightlyNewInstallSchedule {
    <#
        PURE. What a NEW install writes for -Region (the Azure region it goes into; '' = not known): @{ Region; Zone; Known;
        Line (one plain line when the region is not known, else ''); UpdaterCron (the zone's 18:30 ticks in UTC); UpdaterTags
        (the job's tags si-nightly-schedule '18:30 <zone>' + si-nightly-region '<region>' | 'unknown' + si-nightly-1900
        '<zone>' -- the update's one-time steps then see nothing to move); UpdaterTagArgs (the same as k=v); PipelineStart
        '19:00'; PipelineZone; Marker (the JSON the Pro markers / the folder markers record) }.
    #>
    param([AllowEmptyString()][AllowNull()][string]$Region = '', [int]$Year = [datetime]::UtcNow.Year)
    $S = $script:SINightly
    $rz = Get-SINightlyRegionZone $Region
    $zone = $rz.Zone
    $cron = Get-SINightlyUpdaterCron -Zone $zone -Year $Year
    if (-not $cron) { $zone = $S.Zone; $cron = $S.AtCron }
    $reg = if ($rz.Region) { $rz.Region } else { 'unknown' }
    $tags = [ordered]@{}; $tags[$S.JobTag] = $S.At + ' ' + $zone; $tags[$S.RegionTag] = $reg; $tags[$S.Tag1900] = $zone
    $marker = [ordered]@{ region = $reg; zone = $zone; updater = ($S.At + ' ' + $zone); pipeline = ($S.Start + ' ' + $zone); by = 'install' } | ConvertTo-Json -Compress
    [pscustomobject]@{ Region = $rz.Region; Zone = $zone; Known = [bool]$rz.Known; Line = $rz.Line; UpdaterCron = $cron; UpdaterTags = $tags
                       UpdaterTagArgs = @($tags.Keys | ForEach-Object { '{0}={1}' -f $_, $tags[$_] }); PipelineStart = $S.Start; PipelineZone = $zone; Marker = $marker }
}

function Get-SINightlyScheduleText {
    <# PURE. The schedule in plain words for -Zone: "18:30 local time (Europe/Amsterdam, the install's Azure region)"; the fallback zone without a known region: "18:30 Danish time (Europe/Copenhagen)". -At: the time (default the updater's 18:30; the pipeline's '19:00'). #>
    param([string]$Zone = $script:SINightly.Zone, [bool]$Known = $true, [string]$At = $script:SINightly.At)
    if (-not $Known) { return ('{0} Danish time ({1}; the install''s Azure region is not known)' -f $At, $script:SINightly.Zone) }
    '{0} local time ({1}, the install''s Azure region)' -f $At, $Zone
}

function Get-SINightlyInstallMarkerSql {
    <#
        PURE. A NEW Pro install's markers: cfg.InstallState 'NightlyScheduleRegion' and 'NightlySchedule1900' (the update's
        one-time steps then see nothing to move), each written only when it is not there yet and the table exists. -Marker:
        the JSON of Get-SINightlyNewInstallSchedule. Literal values (no parameters), quotes doubled.
    #>
    param([Parameter(Mandatory)][string]$Marker, [string]$By = 'guided install')
    $q = { param($s) ([string]$s).Replace("'", "''") }
    @(foreach ($n in @($script:SINightly.Marker, $script:SINightly.Marker1900)) {
        "IF OBJECT_ID(N'cfg.InstallState') IS NOT NULL AND NOT EXISTS (SELECT 1 FROM cfg.InstallState WHERE Name = N'{0}') INSERT cfg.InstallState (Name, Value, [Version], UpdatedBy) VALUES (N'{0}', N'{1}', NULL, N'{2}');" -f (& $q $n), (& $q $Marker), (& $q $By)
    }) -join "`n"
}

function Set-SINightlyInstallMarkerFile {
    <# A NEW folder's markers .si-update\nightly-schedule-region.json + nightly-schedule-1900.json under -Root (each written only when it is not there). Never throws; $true when one was written. #>
    param([Parameter(Mandatory)][string]$Root, [Parameter(Mandatory)][string]$Marker)
    try {
        $dir = [IO.Path]::Combine($Root, '.si-update'); $wrote = $false
        foreach ($n in @($script:SINightly.MarkerFile, $script:SINightly.MarkerFile1900)) {
            $f = [IO.Path]::Combine($dir, $n)
            if (Test-Path -LiteralPath $f) { continue }
            if (-not (Test-Path -LiteralPath $dir)) { New-Item -ItemType Directory -Force -Path $dir | Out-Null }
            [IO.File]::WriteAllText($f, $Marker); $wrote = $true
        }
        $wrote
    } catch { $false }
}

function Get-SINightlyInstallRegion {
    <#
        The install's Azure region: the location of its Container Apps environment, else of its resource group (ARM REST
        through the update's seam, -Rest { param($Method, $Uri, $Body, $Resource, $Headers) } -> @{ Status; Body }). '' when
        neither can be read. Never throws.
    #>
    param([Parameter(Mandatory)]$Rest, [Parameter(Mandatory)][string]$SubscriptionId, [Parameter(Mandatory)][string]$ResourceGroup)
    $arm = 'https://management.azure.com'
    $base = '{0}/subscriptions/{1}/resourceGroups/{2}' -f $arm, $SubscriptionId, $ResourceGroup
    foreach ($uri in @(($base + '/providers/Microsoft.App/managedEnvironments?api-version=2025-07-01'), ($base + '?api-version=2021-04-01'))) {
        try {
            $r = & $Rest 'GET' $uri $null $arm @{}
            if (-not $r -or [int]$r.Status -ne 200) { continue }
            $b = [string]$r.Body | ConvertFrom-Json
            $loc = if ($b.PSObject.Properties['value']) { @($b.value | Where-Object { $_ -and [string]$_.location } | ForEach-Object { [string]$_.location })[0] } else { [string]$b.location }
            if ("$loc".Trim()) { return "$loc".Trim() }
        } catch { }
    }
    ''
}

function Invoke-SINightlyUpdaterSchedule {
    <#
        The updater job's timer, once (Get-SINightlyUpdaterCronPlan): GET, PATCH (read-modify-write), GET again and check.
        -Rest: the update's REST seam. -Region: the install's Azure region ('' = the job's own location). -Step: 'region' (the
        region step 9c, Get-SINightlyUpdaterCronPlan) or '1900' (the 19:00 move 9l, Get-SINightly1900UpdaterPlan). Never throws.
        Returns @{ Action; Zone; Region; Lines }.
    #>
    param([Parameter(Mandatory)]$Rest, [Parameter(Mandatory)][string]$SubscriptionId, [Parameter(Mandatory)][string]$ResourceGroup,
          [Parameter(Mandatory)][string]$JobName, [AllowEmptyString()][string]$Region = '', [switch]$WhatIf, [string]$ApiVersion = '2025-07-01',
          [ValidateSet('region', '1900')][string]$Step = 'region')
    $doneTag = if ($Step -eq '1900') { $script:SINightly.Tag1900 } else { $script:SINightly.RegionTag }
    $lines = New-Object System.Collections.Generic.List[string]
    $uri = 'https://management.azure.com/subscriptions/{0}/resourceGroups/{1}/providers/Microsoft.App/jobs/{2}?api-version={3}' -f $SubscriptionId, $ResourceGroup, $JobName, $ApiVersion
    $arm = 'https://management.azure.com'
    $out = { param($a, $p) [pscustomobject]@{ Action = $a; Zone = $(if ($p) { $p.Zone } else { '' }); Region = $(if ($p) { $p.Region } else { '' }); Lines = $lines.ToArray() } }
    try {
        $g = & $Rest 'GET' $uri $null $arm @{}
        if (-not $g -or [int]$g.Status -ne 200) { $lines.Add(('nightly update time: {0} could not be read (HTTP {1}) -- the next update tries again' -f $JobName, $(if ($g) { $g.Status } else { 0 }))); return (& $out 'failed' $null) }
        $job = [string]$g.Body | ConvertFrom-Json
        $p = if ($Step -eq '1900') { Get-SINightly1900UpdaterPlan -Job $job -Region $Region } else { Get-SINightlyUpdaterCronPlan -Job $job -Region $Region }
        if ($p.Action -eq 'done') { return (& $out 'done' $p) }
        if ($p.RegionLine) { $lines.Add($p.RegionLine) }
        if ($WhatIf) { $lines.Add(('nightly update time: {0} (re-run with -Apply)' -f $p.Why)); return (& $out ('plan-' + $p.Action) $p) }
        $r = & $Rest 'PATCH' $uri ($p.Body | ConvertTo-Json -Depth 10 -Compress) $arm @{ 'Content-Type' = 'application/json' }
        if (-not $r -or [int]$r.Status -lt 200 -or [int]$r.Status -ge 300) { $lines.Add(('nightly update time: {0} was NOT changed (HTTP {1}) -- the next update tries again' -f $JobName, $(if ($r) { $r.Status } else { 0 }))); return (& $out 'failed' $p) }
        # read back: ARM answers the PATCH before the job carries it
        $ok = $false
        for ($i = 0; $i -lt 6 -and -not $ok; $i++) {
            if ($i) { Start-Sleep -Seconds 5 }
            $b = & $Rest 'GET' $uri $null $arm @{}
            if ($b -and [int]$b.Status -eq 200) {
                $now = [string]$b.Body | ConvertFrom-Json
                $ok = (ConvertTo-SINightlyTagMap $now).Contains($doneTag) -and (-not $p.Cron -or (Get-SINightlyJobCron $now) -eq $p.Cron)
            }
        }
        if (-not $ok) { $lines.Add(('nightly update time: {0} did not read back as changed -- the next update checks it again' -f $JobName)); return (& $out 'failed' $p) }
        $lines.Add(('nightly update time: {0}' -f $p.Why))
        & $out $p.Action $p
    } catch { $lines.Add(('nightly update time: not checked ({0}) -- the next update tries again' -f $_.Exception.Message)); & $out 'failed' $null }
}

function ConvertTo-SINightlyFlowJson {
    <#
        PURE. A stored pipeline (cfg.JobFlow / job-flow.custom.json) on a shipped start -> the region's zone (-Zone):
          '23:30' + 'Europe/Copenhagen' (the Danish-time step's value) -> its timeZone becomes -Zone;
          the old '22:00' -> '23:30' + -Zone, only with -MoveOld (the Danish-time step never ran here).
        Only a definition that HAS a time zone (one stored before time zones reads its time as UTC and is kept). The text is
        changed in place (the rest stays byte for byte). $null = nothing to change.
    #>
    param([AllowEmptyString()][AllowNull()][string]$Json, [string]$Zone = $script:SINightly.Zone, [bool]$MoveOld = $true)
    if (-not "$Json".Trim()) { return $null }
    $st = [regex]::Match($Json, '"startTime"\s*:\s*"([^"]*)"')
    $tz = [regex]::Match($Json, '"timeZone"\s*:\s*"([^"]*)"')
    if (-not $st.Success -or -not $tz.Success) { return $null }
    $parts = @()
    if ($MoveOld -and (Test-SINightlyOldPipelineStart $st.Groups[1].Value)) {
        $parts = @(@{ M = $st; New = ('"startTime":"{0}"' -f $script:SINightly.PipelineStart) }, @{ M = $tz; New = ('"timeZone":"{0}"' -f $Zone) })
    } elseif ((Test-SINightlyShippedPipeline $st.Groups[1].Value $tz.Groups[1].Value) -and $Zone -ne $script:SINightly.Zone) {
        $parts = @(@{ M = $tz; New = ('"timeZone":"{0}"' -f $Zone) })
    } else { return $null }
    # the later match first, so the earlier index stays right
    $out = $Json
    foreach ($x in @($parts | Sort-Object { $_.M.Index } -Descending)) { $out = $out.Substring(0, $x.M.Index) + $x.New + $out.Substring($x.M.Index + $x.M.Length) }
    $out
}

function Get-SINightlyPipelineLine {
    <# PURE. The one plain line for the customer. #>
    param([string]$Zone, [bool]$Changed, [bool]$HasOwn)
    if ($Changed) { return ('The daily pipeline now starts at 23:30 in {0} (the time zone of the install''s Azure region), after the nightly update at 23:00.' -f $Zone) }
    if ($HasOwn) { return 'The daily pipeline keeps the start time you chose.' }
    ''
}

function Get-SINightlyPipelinePlan {
    <#
        PURE. The Pro database's part: -Rows = cfg.Setting rows of SI_Pipeline_StartTime / SI_Pipeline_TimeZone (Name, Scope,
        ValueJson), -FlowJson = cfg.JobFlow's daily definition ('' none), -Done = this step's marker exists, -OldDone = the
        Danish-time step's marker exists, -Zone = the region's zone. Returns @{ Done; Settings = [@{ Name; Scope; Old; New;
        Insert }]; FlowJson (the new definition, or $null); Lines }. Any other value is the customer's: nothing at that scope changes.
    #>
    param([AllowEmptyCollection()][object[]]$Rows = @(), [AllowEmptyString()][AllowNull()][string]$FlowJson = '', [bool]$Done = $false,
          [bool]$OldDone = $false, [string]$Zone = $script:SINightly.Zone)
    $set = New-Object System.Collections.Generic.List[object]
    $lines = New-Object System.Collections.Generic.List[string]
    if ($Done) { return [pscustomobject]@{ Done = $true; Settings = @(); FlowJson = $null; Lines = @() } }
    $rows = @($Rows | Where-Object { $_ })
    $zoneJson = '"{0}"' -f $Zone
    $shippedSeen = $false
    foreach ($r in @($rows | Where-Object { [string]$_.Name -eq 'SI_Pipeline_StartTime' })) {
        $scope = [string]$r.Scope
        $z = @($rows | Where-Object { [string]$_.Name -eq 'SI_Pipeline_TimeZone' -and [string]$_.Scope -eq $scope })[0]
        if (-not $OldDone -and (Test-SINightlyOldPipelineStart ([string]$r.ValueJson))) {
            $set.Add([pscustomobject]@{ Name = 'SI_Pipeline_StartTime'; Scope = $scope; Old = [string]$r.ValueJson; New = ('"{0}"' -f $script:SINightly.PipelineStart); Insert = $false })
        } elseif ($z -and (Test-SINightlyShippedPipeline ([string]$r.ValueJson) ([string]$z.ValueJson))) {
            $shippedSeen = $true
        } else { continue }
        if (-not $z) { $set.Add([pscustomobject]@{ Name = 'SI_Pipeline_TimeZone'; Scope = $scope; Old = $null; New = $zoneJson; Insert = $true }) }
        elseif (([string]$z.ValueJson).Trim() -ne $zoneJson) { $set.Add([pscustomobject]@{ Name = 'SI_Pipeline_TimeZone'; Scope = $scope; Old = [string]$z.ValueJson; New = $zoneJson; Insert = $false }) }
    }
    $flow = ConvertTo-SINightlyFlowJson -Json $FlowJson -Zone $Zone -MoveOld (-not $OldDone)
    $changed = [bool]($set.Count -or $flow)
    $hasOwn = (-not $shippedSeen) -and ([string]$FlowJson -match '"startTime"\s*:\s*"([^"]*)"' -or @($rows | Where-Object { [string]$_.Name -eq 'SI_Pipeline_StartTime' }).Count)
    $l = Get-SINightlyPipelineLine -Zone $Zone -Changed $changed -HasOwn $hasOwn
    if ($l) { $lines.Add($l) }
    [pscustomobject]@{ Done = $false; Settings = $set.ToArray(); FlowJson = $flow; Lines = $lines.ToArray() }
}

function Get-SINightlyPipelineSql {
    <#
        The Pro database's statements. 'Read': the two markers, the two settings' rows and the daily pipeline. 'Apply' (-Plan):
        ONE transaction -- each setting written with its cfg.ChangeLog row (the same writes as Set-SIProSetting: the
        Settings page's history shows them), the pipeline definition (cfg.JobFlow keeps its own journal), and the marker
        last. A marker that appeared meanwhile (another run) = nothing is written. Returns @{ Sql; Params }.
    #>
    param([Parameter(Mandatory)][ValidateSet('Read', 'Apply')][string]$Name, $Plan, [string]$By = $script:SINightly.By,
          [string]$Zone = $script:SINightly.Zone, [AllowEmptyString()][string]$Region = '')
    if ($Name -eq 'Read') {
        return [pscustomobject]@{ Params = @{}; Sql = @"
SELECT CASE WHEN Name = N'$($script:SINightly.Marker)' THEN N'marker' ELSE N'oldmarker' END AS Kind, Name, CAST(N'' AS nvarchar(64)) AS Scope, Value AS ValueJson FROM cfg.InstallState WHERE OBJECT_ID(N'cfg.InstallState') IS NOT NULL AND Name IN (N'$($script:SINightly.Marker)', N'$($script:SINightly.OldMarker)')
UNION ALL SELECT N'setting', Name, Scope, ValueJson FROM cfg.Setting WHERE Name IN (N'SI_Pipeline_StartTime', N'SI_Pipeline_TimeZone')
UNION ALL SELECT N'flow', FlowId, CAST(N'' AS nvarchar(64)), DefinitionJson FROM cfg.JobFlow WHERE OBJECT_ID(N'cfg.JobFlow') IS NOT NULL AND FlowId = N'daily';
"@ }
    }
    $p = [ordered]@{ By = $By; Reason = ('the nightly schedule: the update at 23:00 and the pipeline at 23:30 in {0}, the time zone of the install''s Azure region (owner decision 2026-10-15)' -f $Zone)
                     Marker = $script:SINightly.Marker; MarkerValue = ''; FlowJson = [DBNull]::Value }
    $sb = New-Object System.Text.StringBuilder
    $null = $sb.AppendLine('SET XACT_ABORT ON;')
    $null = $sb.AppendLine('BEGIN TRAN;')
    $null = $sb.AppendLine('IF EXISTS (SELECT 1 FROM cfg.InstallState WITH (UPDLOCK, HOLDLOCK) WHERE Name = @Marker) BEGIN COMMIT; RETURN; END')
    $i = 0
    foreach ($s in @($Plan.Settings)) {
        $i++
        $p["N$i"] = [string]$s.Name; $p["S$i"] = [string]$s.Scope; $p["V$i"] = [string]$s.New
        $null = $sb.AppendLine(("DECLARE @old$i nvarchar(max) = (SELECT ValueJson FROM cfg.Setting WHERE Name = @N$i AND Scope = @S$i);"))
        $null = $sb.AppendLine(("IF EXISTS (SELECT 1 FROM cfg.Setting WHERE Name = @N$i AND Scope = @S$i) UPDATE cfg.Setting SET ValueJson = @V$i, KeyVaultSecretName = NULL, UpdatedAt = SYSUTCDATETIME(), UpdatedBy = @By WHERE Name = @N$i AND Scope = @S$i;"))
        $null = $sb.AppendLine(("ELSE INSERT cfg.Setting (Name, Scope, ValueJson, KeyVaultSecretName, UpdatedBy) VALUES (@N$i, @S$i, @V$i, NULL, @By);"))
        $null = $sb.AppendLine(("INSERT cfg.ChangeLog (Name, Scope, Action, OldValue, NewValue, ChangedBy, Reason) VALUES (@N$i, @S$i, N'Set', @old$i, @V$i, @By, @Reason);"))
    }
    if ($Plan.FlowJson) {
        $p.FlowJson = [string]$Plan.FlowJson
        $null = $sb.AppendLine("UPDATE cfg.JobFlow SET DefinitionJson = @FlowJson, UpdatedAt = SYSUTCDATETIME(), UpdatedBy = @By WHERE FlowId = N'daily';")
    }
    $p.MarkerValue = ([ordered]@{ region = $(if ($Region) { $Region } else { 'unknown' }); zone = $Zone; updater = ('23:00 ' + $Zone); pipeline = $(if (@($Plan.Settings).Count -or $Plan.FlowJson) { '23:30 ' + $Zone } else { 'kept' }); settings = @(@($Plan.Settings) | ForEach-Object { '{0} ({1})' -f $_.Name, $_.Scope }); at = [datetime]::UtcNow.ToString('o') } | ConvertTo-Json -Compress)
    $null = $sb.AppendLine('INSERT cfg.InstallState (Name, Value, [Version], UpdatedBy) VALUES (@Marker, @MarkerValue, NULL, @By);')
    $null = $sb.AppendLine('COMMIT;')
    [pscustomobject]@{ Sql = $sb.ToString(); Params = $p }
}

function Invoke-SINightlyPipelineStart {
    <#
        The Pro database's part, once. -Sql { param($Query, $Params, $Mode) } ('reader' -> rows, 'nonquery'). -Zone: the
        region's zone; -Region: the region (recorded). Never throws. Returns @{ Action = done | changed | kept | plan | failed; Lines }.
    #>
    param([Parameter(Mandatory)][scriptblock]$Sql, [string]$Zone = $script:SINightly.Zone, [AllowEmptyString()][string]$Region = '', [switch]$WhatIf)
    try {
        $q = Get-SINightlyPipelineSql -Name Read
        $rows = @(& $Sql $q.Sql $q.Params 'reader' | ForEach-Object { $_ } | Where-Object { $_ } | ForEach-Object { if ($_ -is [System.Collections.IDictionary]) { [pscustomobject]$_ } else { $_ } })
        $done = [bool]@($rows | Where-Object { [string]$_.Kind -eq 'marker' }).Count
        $oldDone = [bool]@($rows | Where-Object { [string]$_.Kind -eq 'oldmarker' }).Count
        $flow = @($rows | Where-Object { [string]$_.Kind -eq 'flow' })[0]
        $plan = Get-SINightlyPipelinePlan -Rows @($rows | Where-Object { [string]$_.Kind -eq 'setting' }) -FlowJson $(if ($flow -and -not ($flow.ValueJson -is [DBNull])) { [string]$flow.ValueJson } else { '' }) -Done $done -OldDone $oldDone -Zone $Zone
        if ($plan.Done) { return [pscustomobject]@{ Action = 'done'; Lines = @() } }
        if ($WhatIf) { return [pscustomobject]@{ Action = 'plan'; Lines = @($plan.Lines | ForEach-Object { '{0} (re-run with -Apply)' -f $_ }) } }
        $a = Get-SINightlyPipelineSql -Name Apply -Plan $plan -Zone $Zone -Region $Region
        $null = & $Sql $a.Sql $a.Params 'nonquery'
        [pscustomobject]@{ Action = $(if (@($plan.Settings).Count -or $plan.FlowJson) { 'changed' } else { 'kept' }); Lines = @($plan.Lines) }
    } catch { [pscustomobject]@{ Action = 'failed'; Lines = @(('The daily pipeline''s start time was not checked ({0}) -- the next update tries again.' -f $_.Exception.Message)) } }
}

function ConvertTo-SINightlyConfigText {
    <#
        PURE. config\SecurityInsight.custom.ps1 on a shipped start -> the region's zone (-Zone):
          $global:SI_Pipeline_StartTime = '23:30' with SI_Pipeline_TimeZone 'Europe/Copenhagen' -> the zone line becomes -Zone;
          the old '22:00' -> '23:30' and the zone line -Zone (changed, else added right after the start time), only with -MoveOld.
        A commented line is not a setting and is left alone. $null = nothing to change.
    #>
    param([AllowEmptyString()][AllowNull()][string]$Text, [string]$Zone = $script:SINightly.Zone, [bool]$MoveOld = $true)
    if (-not "$Text") { return $null }
    $rxStart = [regex]'(?m)^(?<pre>[ \t]*\$global:SI_Pipeline_StartTime[ \t]*=[ \t]*)(?<q>[''"])(?<v>[^''"\r\n]*)\k<q>'
    $rxZone = [regex]'(?m)^(?<pre>[ \t]*\$global:SI_Pipeline_TimeZone[ \t]*=[ \t]*)(?<q>[''"])(?<v>[^''"\r\n]*)\k<q>'
    $m = @($rxStart.Matches($Text))
    if (-not $m.Count) { return $null }
    $last = $m[-1]   # the last one wins in PowerShell
    $z0 = @($rxZone.Matches($Text))
    $setZone = { param($t)
        $z = @($rxZone.Matches($t))
        if ($z.Count) { $zl = $z[-1]; return ($t.Substring(0, $zl.Index) + $zl.Groups['pre'].Value + "'" + $Zone + "'" + $t.Substring($zl.Index + $zl.Length)) }
        $at = [regex]::Match($t.Substring($last.Index), '\r?\n')
        $nl = if ($t -match "`r`n") { "`r`n" } else { "`n" }
        $line = "`$global:SI_Pipeline_TimeZone = '{0}'" -f $Zone
        if ($at.Success) { $pos = $last.Index + $at.Index + $at.Length; return ($t.Substring(0, $pos) + $line + $nl + $t.Substring($pos)) }
        $t + $nl + $line + $nl
    }
    if ($MoveOld -and (Test-SINightlyOldPipelineStart $last.Groups['v'].Value)) {
        $out = $Text.Substring(0, $last.Index) + $last.Groups['pre'].Value + "'" + $script:SINightly.PipelineStart + "'" + $Text.Substring($last.Index + $last.Length)
        return (& $setZone $out)
    }
    if ($z0.Count -and (Test-SINightlyShippedPipeline $last.Groups['v'].Value $z0[-1].Groups['v'].Value) -and $Zone -ne $script:SINightly.Zone) { return (& $setZone $Text) }
    $null
}

function Invoke-SINightlyPipelineFiles {
    <#
        A folder install's part (Community; the files a container install shares with its jobs), once: -Root = the
        SecurityInsight folder, -Zone = the region's zone. Only when config\SecurityInsight.custom.ps1 exists (an extracted
        release has none: nothing done, nothing recorded). The marker .si-update\nightly-schedule-region.json records that it
        ran; the Danish-time step's marker (nightly-schedule.json) means a 22:00 found now is the customer's. Never throws.
        Returns @{ Action = none | done | changed | kept | plan | failed; Lines }.
    #>
    param([Parameter(Mandatory)][string]$Root, [string]$Zone = $script:SINightly.Zone, [AllowEmptyString()][string]$Region = '', [switch]$WhatIf)
    try {
        $cfg = [IO.Path]::Combine($Root, 'config', 'SecurityInsight.custom.ps1')
        if (-not (Test-Path -LiteralPath $cfg)) { return [pscustomobject]@{ Action = 'none'; Lines = @() } }
        $markerDir = [IO.Path]::Combine($Root, '.si-update')
        $marker = [IO.Path]::Combine($markerDir, $script:SINightly.MarkerFile)
        if (Test-Path -LiteralPath $marker) { return [pscustomobject]@{ Action = 'done'; Lines = @() } }
        $moveOld = -not (Test-Path -LiteralPath ([IO.Path]::Combine($markerDir, $script:SINightly.OldMarkerFile)))
        $flowFile = [IO.Path]::Combine($Root, 'config', 'job-flow.custom.json')
        $read = { param($p) $b = [IO.File]::ReadAllBytes($p); $bom = ($b.Length -ge 3 -and $b[0] -eq 0xEF -and $b[1] -eq 0xBB -and $b[2] -eq 0xBF); [pscustomobject]@{ Text = [Text.Encoding]::UTF8.GetString($b, $(if ($bom) { 3 } else { 0 }), $b.Length - $(if ($bom) { 3 } else { 0 })); Bom = $bom } }
        $c = & $read $cfg
        $newCfg = ConvertTo-SINightlyConfigText -Text $c.Text -Zone $Zone -MoveOld $moveOld
        $f = if (Test-Path -LiteralPath $flowFile) { & $read $flowFile } else { $null }
        $newFlow = if ($f) { ConvertTo-SINightlyFlowJson -Json $f.Text -Zone $Zone -MoveOld $moveOld } else { $null }
        $changed = [bool]($newCfg -or $newFlow)
        $rxS = [regex]'(?m)^[ \t]*\$global:SI_Pipeline_StartTime[ \t]*=[ \t]*[''"](?<v>[^''"\r\n]*)[''"]'
        $rxZ = [regex]'(?m)^[ \t]*\$global:SI_Pipeline_TimeZone[ \t]*=[ \t]*[''"](?<v>[^''"\r\n]*)[''"]'
        $sM = @($rxS.Matches($c.Text)); $zM = @($rxZ.Matches($c.Text))
        $shipped = $sM.Count -and $zM.Count -and (Test-SINightlyShippedPipeline $sM[-1].Groups['v'].Value $zM[-1].Groups['v'].Value)
        $hasOwn = (-not $shipped) -and ($sM.Count -or ($f -and $f.Text -match '"startTime"'))
        $line = Get-SINightlyPipelineLine -Zone $Zone -Changed $changed -HasOwn $hasOwn
        if ($WhatIf) { return [pscustomobject]@{ Action = 'plan'; Lines = @($(if ($line) { '{0} (re-run with -Apply)' -f $line })) } }
        $write = { param($p, $t, $bom) [IO.File]::WriteAllText($p, $t, (New-Object System.Text.UTF8Encoding($bom))) }
        if ($newCfg) { & $write $cfg $newCfg $c.Bom }
        if ($newFlow) { & $write $flowFile $newFlow $f.Bom }
        if (-not (Test-Path -LiteralPath $markerDir)) { New-Item -ItemType Directory -Force -Path $markerDir | Out-Null }
        [IO.File]::WriteAllText($marker, ([ordered]@{ region = $(if ($Region) { $Region } else { 'unknown' }); zone = $Zone; updater = ('23:00 ' + $Zone); pipeline = $(if ($changed) { '23:30 ' + $Zone } else { 'kept' }); at = [datetime]::UtcNow.ToString('o') } | ConvertTo-Json -Compress))
        [pscustomobject]@{ Action = $(if ($changed) { 'changed' } else { 'kept' }); Lines = @($(if ($line) { $line })) }
    } catch { [pscustomobject]@{ Action = 'failed'; Lines = @(('The daily pipeline''s start time was not checked ({0}) -- the next update tries again.' -f $_.Exception.Message)) } }
}

# ---------------------------------------------------------------------------------------------------------------------------
# THE 19:00 MOVE of the pipeline start (owner 2026-10-21: "move the start time for all si jobs to 7pm on all sites" / "so they
# are done next morning"), step 9l of the update, once, AFTER the region step. Shipped = the region step's value ('23:30' with
# the region's zone); where the region step has not run yet (-RegionDone $false: a plan, or that step failed this time), also
# the values IT would move ('23:30' Europe/Copenhagen; the old '22:00' where the Danish-time step never ran). Anything else is
# the customer's. The zone is stored with the time.
# ---------------------------------------------------------------------------------------------------------------------------

function Test-SINightly1900ShippedStart {
    <# PURE. Is -Start / -StartZone (JSON strings allowed; -StartZone may be $null) a shipped pipeline start for the 19:00 move, in the region zone -Zone? #>
    param([AllowNull()]$Start, [AllowNull()]$StartZone, [string]$Zone = $script:SINightly.Zone, [bool]$RegionDone = $true, [bool]$OldDone = $true)
    if ($null -eq $Start -or $Start -is [DBNull]) { return $false }
    $s = ([string]$Start).Trim().Trim('"').Trim()
    $z = if ($null -eq $StartZone -or $StartZone -is [DBNull]) { '' } else { ([string]$StartZone).Trim().Trim('"').Trim() }
    if ($s -eq $script:SINightly.PipelineStart -and $z -eq $Zone) { return $true }
    if ($RegionDone) { return $false }
    if ($s -eq $script:SINightly.PipelineStart -and $z -eq $script:SINightly.Zone) { return $true }
    (-not $OldDone) -and (Test-SINightlyOldPipelineStart $Start)
}

function ConvertTo-SINightly1900FlowJson {
    <#
        PURE. A stored pipeline (cfg.JobFlow / job-flow.custom.json) on a shipped start (Test-SINightly1900ShippedStart) ->
        "startTime":"19:00" with "timeZone" -Zone. Only a definition that HAS a time zone (one stored before time zones reads
        its time as UTC and is kept). The text is changed in place (the rest byte for byte). $null = nothing to change.
    #>
    param([AllowEmptyString()][AllowNull()][string]$Json, [string]$Zone = $script:SINightly.Zone, [bool]$RegionDone = $true, [bool]$OldDone = $true)
    if (-not "$Json".Trim()) { return $null }
    $st = [regex]::Match($Json, '"startTime"\s*:\s*"([^"]*)"')
    $tz = [regex]::Match($Json, '"timeZone"\s*:\s*"([^"]*)"')
    if (-not $st.Success -or -not $tz.Success) { return $null }
    if (-not (Test-SINightly1900ShippedStart $st.Groups[1].Value $tz.Groups[1].Value -Zone $Zone -RegionDone $RegionDone -OldDone $OldDone)) { return $null }
    $parts = @(@{ M = $st; New = ('"startTime":"{0}"' -f $script:SINightly.Start) }, @{ M = $tz; New = ('"timeZone":"{0}"' -f $Zone) })
    $out = $Json
    foreach ($x in @($parts | Sort-Object { $_.M.Index } -Descending)) { $out = $out.Substring(0, $x.M.Index) + $x.New + $out.Substring($x.M.Index + $x.M.Length) }
    $out
}

function Get-SINightly1900Line {
    <# PURE. The one plain line for the customer. #>
    param([string]$Zone, [bool]$Changed, [bool]$HasOwn)
    if ($Changed) { return ('The daily pipeline now starts at {0} in {1} (the time zone of the install''s Azure region), after the nightly update at {2} -- so the night''s results are ready the next morning.' -f $script:SINightly.Start, $Zone, $script:SINightly.At) }
    if ($HasOwn) { return 'The daily pipeline keeps the start time you chose.' }
    ''
}

function Get-SINightly1900PipelinePlan {
    <#
        PURE. The Pro database's part of the 19:00 move: -Rows = cfg.Setting rows of SI_Pipeline_StartTime /
        SI_Pipeline_TimeZone (Name, Scope, ValueJson), -FlowJson = cfg.JobFlow's daily definition, -Done = this step's marker,
        -RegionDone / -OldDone = the region / Danish-time step's marker, -Zone = the region's zone. Returns @{ Done; Settings =
        [@{ Name; Scope; Old; New; Insert }]; FlowJson; Lines }. Any other value is the customer's: nothing at that scope changes.
    #>
    param([AllowEmptyCollection()][object[]]$Rows = @(), [AllowEmptyString()][AllowNull()][string]$FlowJson = '', [bool]$Done = $false,
          [bool]$RegionDone = $true, [bool]$OldDone = $true, [string]$Zone = $script:SINightly.Zone)
    if ($Done) { return [pscustomobject]@{ Done = $true; Settings = @(); FlowJson = $null; Lines = @() } }
    $set = New-Object System.Collections.Generic.List[object]
    $rows = @($Rows | Where-Object { $_ })
    $zoneJson = '"{0}"' -f $Zone
    $startRows = @($rows | Where-Object { [string]$_.Name -eq 'SI_Pipeline_StartTime' })
    foreach ($r in $startRows) {
        $scope = [string]$r.Scope
        $z = @($rows | Where-Object { [string]$_.Name -eq 'SI_Pipeline_TimeZone' -and [string]$_.Scope -eq $scope })[0]
        if (-not (Test-SINightly1900ShippedStart ([string]$r.ValueJson) $(if ($z) { [string]$z.ValueJson } else { $null }) -Zone $Zone -RegionDone $RegionDone -OldDone $OldDone)) { continue }
        $set.Add([pscustomobject]@{ Name = 'SI_Pipeline_StartTime'; Scope = $scope; Old = [string]$r.ValueJson; New = ('"{0}"' -f $script:SINightly.Start); Insert = $false })
        if (-not $z) { $set.Add([pscustomobject]@{ Name = 'SI_Pipeline_TimeZone'; Scope = $scope; Old = $null; New = $zoneJson; Insert = $true }) }
        elseif (([string]$z.ValueJson).Trim() -ne $zoneJson) { $set.Add([pscustomobject]@{ Name = 'SI_Pipeline_TimeZone'; Scope = $scope; Old = [string]$z.ValueJson; New = $zoneJson; Insert = $false }) }
    }
    $flow = ConvertTo-SINightly1900FlowJson -Json $FlowJson -Zone $Zone -RegionDone $RegionDone -OldDone $OldDone
    $changed = [bool]($set.Count -or $flow)
    $hasOwn = (-not $changed) -and ($startRows.Count -or ([string]$FlowJson -match '"startTime"\s*:\s*"([^"]*)"'))
    $l = Get-SINightly1900Line -Zone $Zone -Changed $changed -HasOwn $hasOwn
    [pscustomobject]@{ Done = $false; Settings = $set.ToArray(); FlowJson = $flow; Lines = @($(if ($l) { $l })) }
}

function Get-SINightly1900PipelineSql {
    <#
        The Pro database's statements for the 19:00 move. 'Read': the three markers (this step's, the region step's, the
        Danish-time step's), the two settings' rows and the daily pipeline. 'Apply' (-Plan): ONE transaction -- each setting
        with its cfg.ChangeLog row (as Set-SIProSetting writes them), the pipeline definition, and the marker
        'NightlySchedule1900' last; a marker that appeared meanwhile = nothing is written. Returns @{ Sql; Params }.
    #>
    param([Parameter(Mandatory)][ValidateSet('Read', 'Apply')][string]$Name, $Plan, [string]$By = $script:SINightly.By,
          [string]$Zone = $script:SINightly.Zone, [AllowEmptyString()][string]$Region = '')
    $S = $script:SINightly
    if ($Name -eq 'Read') {
        $q = "SELECT CASE WHEN Name = N'{0}' THEN N'marker1900' WHEN Name = N'{1}' THEN N'marker' ELSE N'oldmarker' END AS Kind, Name, CAST(N'' AS nvarchar(64)) AS Scope, Value AS ValueJson FROM cfg.InstallState WHERE OBJECT_ID(N'cfg.InstallState') IS NOT NULL AND Name IN (N'{0}', N'{1}', N'{2}')" -f $S.Marker1900, $S.Marker, $S.OldMarker
        $q += "`nUNION ALL SELECT N'setting', Name, Scope, ValueJson FROM cfg.Setting WHERE Name IN (N'SI_Pipeline_StartTime', N'SI_Pipeline_TimeZone')"
        $q += "`nUNION ALL SELECT N'flow', FlowId, CAST(N'' AS nvarchar(64)), DefinitionJson FROM cfg.JobFlow WHERE OBJECT_ID(N'cfg.JobFlow') IS NOT NULL AND FlowId = N'daily';"
        return [pscustomobject]@{ Params = @{}; Sql = $q }
    }
    $p = [ordered]@{ By = $By; Reason = ('the nightly schedule: the update at {0} and the pipeline at {1} in {2}, the time zone of the install''s Azure region, so the night''s results are ready the next morning (owner decision 2026-10-21)' -f $S.At, $S.Start, $Zone)
                     Marker = $S.Marker1900; MarkerValue = ''; FlowJson = [DBNull]::Value }
    $sb = New-Object System.Text.StringBuilder
    $null = $sb.AppendLine('SET XACT_ABORT ON;')
    $null = $sb.AppendLine('BEGIN TRAN;')
    $null = $sb.AppendLine('IF EXISTS (SELECT 1 FROM cfg.InstallState WITH (UPDLOCK, HOLDLOCK) WHERE Name = @Marker) BEGIN COMMIT; RETURN; END')
    $i = 0
    foreach ($row in @($Plan.Settings)) {   # not $s: PowerShell names are case-insensitive, $S is the schedule
        $i++
        $p["N$i"] = [string]$row.Name; $p["S$i"] = [string]$row.Scope; $p["V$i"] = [string]$row.New
        $null = $sb.AppendLine(("DECLARE @old$i nvarchar(max) = (SELECT ValueJson FROM cfg.Setting WHERE Name = @N$i AND Scope = @S$i);"))
        $null = $sb.AppendLine(("IF EXISTS (SELECT 1 FROM cfg.Setting WHERE Name = @N$i AND Scope = @S$i) UPDATE cfg.Setting SET ValueJson = @V$i, KeyVaultSecretName = NULL, UpdatedAt = SYSUTCDATETIME(), UpdatedBy = @By WHERE Name = @N$i AND Scope = @S$i;"))
        $null = $sb.AppendLine(("ELSE INSERT cfg.Setting (Name, Scope, ValueJson, KeyVaultSecretName, UpdatedBy) VALUES (@N$i, @S$i, @V$i, NULL, @By);"))
        $null = $sb.AppendLine(("INSERT cfg.ChangeLog (Name, Scope, Action, OldValue, NewValue, ChangedBy, Reason) VALUES (@N$i, @S$i, N'Set', @old$i, @V$i, @By, @Reason);"))
    }
    if ($Plan.FlowJson) {
        $p.FlowJson = [string]$Plan.FlowJson
        $null = $sb.AppendLine("UPDATE cfg.JobFlow SET DefinitionJson = @FlowJson, UpdatedAt = SYSUTCDATETIME(), UpdatedBy = @By WHERE FlowId = N'daily';")
    }
    $moved = [bool](@($Plan.Settings).Count -or $Plan.FlowJson)
    $p.MarkerValue = ([ordered]@{ region = $(if ($Region) { $Region } else { 'unknown' }); zone = $Zone; updater = ($S.At + ' ' + $Zone); pipeline = $(if ($moved) { $S.Start + ' ' + $Zone } else { 'kept' }); settings = @(@($Plan.Settings) | ForEach-Object { '{0} ({1})' -f $_.Name, $_.Scope }); at = [datetime]::UtcNow.ToString('o') } | ConvertTo-Json -Compress)
    $null = $sb.AppendLine('INSERT cfg.InstallState (Name, Value, [Version], UpdatedBy) VALUES (@Marker, @MarkerValue, NULL, @By);')
    $null = $sb.AppendLine('COMMIT;')
    [pscustomobject]@{ Sql = $sb.ToString(); Params = $p }
}

function Invoke-SINightly1900PipelineStart {
    <#
        The Pro database's part of the 19:00 move, once. -Sql { param($Query, $Params, $Mode) } ('reader' -> rows,
        'nonquery'). -Zone: the region's zone; -Region: recorded. Never throws. Returns @{ Action = done | changed | kept |
        plan | failed; Lines }.
    #>
    param([Parameter(Mandatory)][scriptblock]$Sql, [string]$Zone = $script:SINightly.Zone, [AllowEmptyString()][string]$Region = '', [switch]$WhatIf)
    try {
        $q = Get-SINightly1900PipelineSql -Name Read
        $rows = @(& $Sql $q.Sql $q.Params 'reader' | ForEach-Object { $_ } | Where-Object { $_ } | ForEach-Object { if ($_ -is [System.Collections.IDictionary]) { [pscustomobject]$_ } else { $_ } })
        $kind = { param($k) [bool]@($rows | Where-Object { [string]$_.Kind -eq $k }).Count }
        $flow = @($rows | Where-Object { [string]$_.Kind -eq 'flow' })[0]
        $flowJson = if ($flow -and -not ($flow.ValueJson -is [DBNull])) { [string]$flow.ValueJson } else { '' }
        $plan = Get-SINightly1900PipelinePlan -Rows @($rows | Where-Object { [string]$_.Kind -eq 'setting' }) -FlowJson $flowJson -Done (& $kind 'marker1900') -RegionDone (& $kind 'marker') -OldDone (& $kind 'oldmarker') -Zone $Zone
        if ($plan.Done) { return [pscustomobject]@{ Action = 'done'; Lines = @() } }
        if ($WhatIf) { return [pscustomobject]@{ Action = 'plan'; Lines = @($plan.Lines | ForEach-Object { '{0} (re-run with -Apply)' -f $_ }) } }
        $a = Get-SINightly1900PipelineSql -Name Apply -Plan $plan -Zone $Zone -Region $Region
        $null = & $Sql $a.Sql $a.Params 'nonquery'
        [pscustomobject]@{ Action = $(if (@($plan.Settings).Count -or $plan.FlowJson) { 'changed' } else { 'kept' }); Lines = @($plan.Lines) }
    } catch { [pscustomobject]@{ Action = 'failed'; Lines = @(('The daily pipeline''s start time was not checked ({0}) -- the next update tries again.' -f $_.Exception.Message)) } }
}

function ConvertTo-SINightly1900ConfigText {
    <#
        PURE. config\SecurityInsight.custom.ps1 on a shipped start (Test-SINightly1900ShippedStart: the last
        $global:SI_Pipeline_StartTime with the last $global:SI_Pipeline_TimeZone) -> '19:00' and the zone line -Zone (changed,
        else added right after the start time). A commented line is not a setting. $null = nothing to change.
    #>
    param([AllowEmptyString()][AllowNull()][string]$Text, [string]$Zone = $script:SINightly.Zone, [bool]$RegionDone = $true, [bool]$OldDone = $true)
    if (-not "$Text") { return $null }
    $rxStart = [regex]'(?m)^(?<pre>[ \t]*\$global:SI_Pipeline_StartTime[ \t]*=[ \t]*)(?<q>[''"])(?<v>[^''"\r\n]*)\k<q>'
    $rxZone = [regex]'(?m)^(?<pre>[ \t]*\$global:SI_Pipeline_TimeZone[ \t]*=[ \t]*)(?<q>[''"])(?<v>[^''"\r\n]*)\k<q>'
    $m = @($rxStart.Matches($Text))
    if (-not $m.Count) { return $null }
    $last = $m[-1]
    $z0 = @($rxZone.Matches($Text))
    $zv = if ($z0.Count) { $z0[-1].Groups['v'].Value } else { $null }
    if (-not (Test-SINightly1900ShippedStart $last.Groups['v'].Value $zv -Zone $Zone -RegionDone $RegionDone -OldDone $OldDone)) { return $null }
    $t = $Text.Substring(0, $last.Index) + $last.Groups['pre'].Value + "'" + $script:SINightly.Start + "'" + $Text.Substring($last.Index + $last.Length)
    $z = @($rxZone.Matches($t))
    if ($z.Count) { $zl = $z[-1]; return ($t.Substring(0, $zl.Index) + $zl.Groups['pre'].Value + "'" + $Zone + "'" + $t.Substring($zl.Index + $zl.Length)) }
    $at = [regex]::Match($t.Substring($last.Index), '\r?\n')
    $nl = if ($t -match "`r`n") { "`r`n" } else { "`n" }
    $line = "`$global:SI_Pipeline_TimeZone = '{0}'" -f $Zone
    if ($at.Success) { $pos = $last.Index + $at.Index + $at.Length; return ($t.Substring(0, $pos) + $line + $nl + $t.Substring($pos)) }
    $t + $nl + $line + $nl
}

function Invoke-SINightly1900PipelineFiles {
    <#
        A folder install's part of the 19:00 move (Community; the files a container install shares with its jobs), once:
        -Root = the SecurityInsight folder, -Zone = the region's zone. Only when config\SecurityInsight.custom.ps1 exists. The
        marker .si-update\nightly-schedule-1900.json records that it ran; the region step's marker (nightly-schedule-region.json)
        and the Danish-time step's (nightly-schedule.json) say which earlier values are still shipped. Never throws.
        Returns @{ Action = none | done | changed | kept | plan | failed; Lines }.
    #>
    param([Parameter(Mandatory)][string]$Root, [string]$Zone = $script:SINightly.Zone, [AllowEmptyString()][string]$Region = '', [switch]$WhatIf)
    try {
        $S = $script:SINightly
        $cfg = [IO.Path]::Combine($Root, 'config', 'SecurityInsight.custom.ps1')
        if (-not (Test-Path -LiteralPath $cfg)) { return [pscustomobject]@{ Action = 'none'; Lines = @() } }
        $markerDir = [IO.Path]::Combine($Root, '.si-update')
        $marker = [IO.Path]::Combine($markerDir, $S.MarkerFile1900)
        if (Test-Path -LiteralPath $marker) { return [pscustomobject]@{ Action = 'done'; Lines = @() } }
        $regionDone = Test-Path -LiteralPath ([IO.Path]::Combine($markerDir, $S.MarkerFile))
        $oldDone = Test-Path -LiteralPath ([IO.Path]::Combine($markerDir, $S.OldMarkerFile))
        $flowFile = [IO.Path]::Combine($Root, 'config', 'job-flow.custom.json')
        $read = { param($p) $b = [IO.File]::ReadAllBytes($p); $bom = ($b.Length -ge 3 -and $b[0] -eq 0xEF -and $b[1] -eq 0xBB -and $b[2] -eq 0xBF); [pscustomobject]@{ Text = [Text.Encoding]::UTF8.GetString($b, $(if ($bom) { 3 } else { 0 }), $b.Length - $(if ($bom) { 3 } else { 0 })); Bom = $bom } }
        $c = & $read $cfg
        $newCfg = ConvertTo-SINightly1900ConfigText -Text $c.Text -Zone $Zone -RegionDone $regionDone -OldDone $oldDone
        $f = if (Test-Path -LiteralPath $flowFile) { & $read $flowFile } else { $null }
        $newFlow = if ($f) { ConvertTo-SINightly1900FlowJson -Json $f.Text -Zone $Zone -RegionDone $regionDone -OldDone $oldDone } else { $null }
        $changed = [bool]($newCfg -or $newFlow)
        $hasOwn = (-not $changed) -and (($c.Text -match '(?m)^[ \t]*\$global:SI_Pipeline_StartTime[ \t]*=') -or ($f -and $f.Text -match '"startTime"'))
        $line = Get-SINightly1900Line -Zone $Zone -Changed $changed -HasOwn $hasOwn
        if ($WhatIf) { return [pscustomobject]@{ Action = 'plan'; Lines = @($(if ($line) { '{0} (re-run with -Apply)' -f $line })) } }
        $write = { param($p, $t, $bom) [IO.File]::WriteAllText($p, $t, (New-Object System.Text.UTF8Encoding($bom))) }
        if ($newCfg) { & $write $cfg $newCfg $c.Bom }
        if ($newFlow) { & $write $flowFile $newFlow $f.Bom }
        if (-not (Test-Path -LiteralPath $markerDir)) { New-Item -ItemType Directory -Force -Path $markerDir | Out-Null }
        [IO.File]::WriteAllText($marker, ([ordered]@{ region = $(if ($Region) { $Region } else { 'unknown' }); zone = $Zone; updater = ($S.At + ' ' + $Zone); pipeline = $(if ($changed) { $S.Start + ' ' + $Zone } else { 'kept' }); at = [datetime]::UtcNow.ToString('o') } | ConvertTo-Json -Compress))
        [pscustomobject]@{ Action = $(if ($changed) { 'changed' } else { 'kept' }); Lines = @($(if ($line) { $line })) }
    } catch { [pscustomobject]@{ Action = 'failed'; Lines = @(('The daily pipeline''s start time was not checked ({0}) -- the next update tries again.' -f $_.Exception.Message)) } }
}
