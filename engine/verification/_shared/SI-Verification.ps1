#Requires -Version 5.1
<#
    SECURITYINSIGHT PRO -- THE VERIFICATION SERVICE: data-collection gap discovery (docs/V3-DATA-MODEL.md 2.11).
    Settings and plans SecurityInsight's data depends on that are NOT enabled in the customer's Microsoft estate --
    Defender for Cloud plans, devices and VMs without a Defender sensor, sensors not reporting, unsupported operating
    systems, missing multicloud connectors, empty Advanced Hunting tables, sign-in logs not reaching the security
    workspace, collectors that did not complete. READ-ONLY: it never changes a setting.

    This file is PURE: the catalog, one evaluator per check over data already read, and the decision state (ignored /
    accepted, each due for review after 180 days). The reads are in Invoke-SIVerification.ps1, the database in
    SI-VerificationStore.ps1.

    A finding = @{ CheckId; FindingKey; ScopeKind; ScopeKey; ScopeName; Severity; Detail }. FindingKey = '<checkId>|<scope key>'
    (lower-case) -- stable across runs, so decisions and history follow it.
    A check whose source could not be read is NOT CHECKED (with the reason): its open findings are left as they were,
    never resolved by absence (working rule 4).
    PowerShell 5.1: no ?. / ??, no ternary.
#>

function Get-SIVerificationCatalog {
    <# The check catalog (config\verification-checks.locked.json). -Path for tests. #>
    param([string]$Path)
    if (-not $Path) { $Path = [IO.Path]::Combine((Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSScriptRoot))), 'config', 'verification-checks.locked.json') }
    $j = [IO.File]::ReadAllText($Path) | ConvertFrom-Json
    $j
}

function Get-SIVerificationCheck {
    param([Parameter(Mandatory)]$Catalog, [Parameter(Mandatory)][string]$Id)
    @($Catalog.checks | Where-Object { [string]$_.id -eq $Id })[0]
}

function New-SIVerificationFinding {
    <# PURE. One finding of a check, keyed '<checkId>|<scope key>' (lower-case). #>
    param([Parameter(Mandatory)]$Check, [Parameter(Mandatory)][string]$ScopeKey, [string]$ScopeName = '', [string]$Detail = '', [string]$Severity)
    $sev = [string]$Check.severity; if ($Severity) { $sev = $Severity }
    [pscustomobject][ordered]@{
        CheckId    = [string]$Check.id
        FindingKey = ('{0}|{1}' -f [string]$Check.id, $ScopeKey).ToLowerInvariant()
        ScopeKind  = [string]$Check.scope
        ScopeKey   = $ScopeKey
        ScopeName  = $(if ($ScopeName) { $ScopeName } else { $ScopeKey })
        Severity   = $sev
        Detail     = $Detail
    }
}

function Get-SIVerifyShortName {
    <# PURE. A host name without its domain, lower-case: 'srv01.contoso.local' -> 'srv01'. #>
    param([AllowEmptyString()][AllowNull()][string]$Name)
    if ([string]::IsNullOrWhiteSpace($Name)) { return '' }
    ($Name.Trim().ToLowerInvariant() -split '\.')[0]
}

function Get-SIVerifyValue {
    <# PURE. A property of a row, whatever the row is (hashtable / object); $null when absent. #>
    param($Row, [Parameter(Mandatory)][string]$Name)
    if ($null -eq $Row) { return $null }
    if ($Row -is [System.Collections.IDictionary]) { if ($Row.Contains($Name)) { return $Row[$Name] } else { return $null } }
    $p = $Row.PSObject.Properties[$Name]; if ($p) { return $p.Value }
    $null
}

function ConvertTo-SIVerifyDate {
    param($Value)
    if ($null -eq $Value -or "$Value" -eq '') { return $null }
    if ($Value -is [datetime]) { return $Value.ToUniversalTime() }
    $d = [datetime]::MinValue
    if ([datetime]::TryParse([string]$Value, [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]'AdjustToUniversal, AssumeUniversal', [ref]$d)) { return $d }
    $null
}

# ---------------------------------------------------------------------------------------------------------------------
#  THE CHECKS -- each PURE over rows already read; each writes its findings to the output (callers wrap it in @())
# ---------------------------------------------------------------------------------------------------------------------

function Test-SIVerifyDefenderPlans {
    <#
        defender-plan-off: every ENABLED subscription x every in-scope plan (catalog defenderPlans) whose pricing is not
        Standard -- a plan with no pricing row at all counts as off (Free). -Pricings: rows with subscriptionId, name,
        tier. -Subscriptions: rows with subscriptionId, name, state.
    #>
    param([Parameter(Mandatory)]$Catalog, [AllowEmptyCollection()][object[]]$Pricings = @(), [AllowEmptyCollection()][object[]]$Subscriptions = @())
    $check = Get-SIVerificationCheck -Catalog $Catalog -Id 'defender-plan-off'
    $tier = @{}
    foreach ($p in $Pricings) {
        $k = ('{0}|{1}' -f [string](Get-SIVerifyValue $p 'subscriptionId'), [string](Get-SIVerifyValue $p 'name')).ToLowerInvariant()
        $tier[$k] = [string](Get-SIVerifyValue $p 'tier')
    }
    $out = New-Object System.Collections.Generic.List[object]
    foreach ($s in $Subscriptions) {
        $state = [string](Get-SIVerifyValue $s 'state')
        if ($state -and $state -ne 'Enabled') { continue }
        $sid = [string](Get-SIVerifyValue $s 'subscriptionId'); $sname = [string](Get-SIVerifyValue $s 'name')
        foreach ($plan in @($Catalog.defenderPlans)) {
            $t = $tier[('{0}|{1}' -f $sid, [string]$plan).ToLowerInvariant()]
            if ($t -eq 'Standard') { continue }
            $now = $(if ($t) { $t } else { 'not set (Free)' })
            $out.Add((New-SIVerificationFinding -Check $check -ScopeKey ('{0}/{1}' -f $sid, $plan) -ScopeName ('{0} -- {1}' -f $(if ($sname) { $sname } else { $sid }), $plan) `
                -Detail ('Defender for Cloud plan {0} is {1} on subscription {2}.' -f $plan, $now, $(if ($sname) { "$sname ($sid)" } else { $sid }))))
        }
    }
    $out.ToArray()
}

function Test-SIVerifyVmOnboarding {
    <#
        vm-not-onboarded: every RUNNING Azure VM that no Defender for Endpoint machine matches -- by the VM's resource id
        (machine vmMetadata.resourceId), its vmId (vmMetadata.vmId) or its name (the machine's short host name).
        -Vms: id, name, vmId, powerState. -Machines: the Defender machines.
    #>
    param([Parameter(Mandatory)]$Catalog, [AllowEmptyCollection()][object[]]$Vms = @(), [AllowEmptyCollection()][object[]]$Machines = @())
    $check = Get-SIVerificationCheck -Catalog $Catalog -Id 'vm-not-onboarded'
    $byRes = @{}; $byVmId = @{}; $byName = @{}
    foreach ($m in $Machines) {
        $vm = Get-SIVerifyValue $m 'vmMetadata'
        $rid = [string](Get-SIVerifyValue $vm 'resourceId'); if ($rid) { $byRes[$rid.ToLowerInvariant()] = $true }
        $vid = [string](Get-SIVerifyValue $vm 'vmId'); if ($vid) { $byVmId[$vid.ToLowerInvariant()] = $true }
        $n = Get-SIVerifyShortName ([string](Get-SIVerifyValue $m 'computerDnsName')); if ($n) { $byName[$n] = $true }
    }
    $out = New-Object System.Collections.Generic.List[object]
    foreach ($v in $Vms) {
        $ps = [string](Get-SIVerifyValue $v 'powerState')
        if ($ps -and $ps -notmatch '(?i)running') { continue }
        $id = ([string](Get-SIVerifyValue $v 'id')).ToLowerInvariant()
        $vid = ([string](Get-SIVerifyValue $v 'vmId')).ToLowerInvariant()
        $name = [string](Get-SIVerifyValue $v 'name')
        if (($id -and $byRes.ContainsKey($id)) -or ($vid -and $byVmId.ContainsKey($vid)) -or ($name -and $byName.ContainsKey((Get-SIVerifyShortName $name)))) { continue }
        $out.Add((New-SIVerificationFinding -Check $check -ScopeKey $id -ScopeName $name -Detail ('The running VM {0} is not in Defender for Endpoint (no machine with its resource id, VM id or name).' -f $name)))
    }
    $out.ToArray()
}

function Test-SIVerifyDeviceOnboarding {
    <#
        device-not-onboarded: every ENABLED Entra device on Windows or macOS that signed in within -StaleDays and that no
        Defender machine matches by aadDeviceId or short name. -Devices: id, deviceId, displayName, operatingSystem,
        accountEnabled, approximateLastSignInDateTime.
    #>
    param([Parameter(Mandatory)]$Catalog, [AllowEmptyCollection()][object[]]$Devices = @(), [AllowEmptyCollection()][object[]]$Machines = @(),
          [int]$StaleDays = 30, [datetime]$Now = [datetime]::UtcNow)
    $check = Get-SIVerificationCheck -Catalog $Catalog -Id 'device-not-onboarded'
    $byAad = @{}; $byName = @{}
    foreach ($m in $Machines) {
        $a = [string](Get-SIVerifyValue $m 'aadDeviceId'); if ($a) { $byAad[$a.ToLowerInvariant()] = $true }
        $n = Get-SIVerifyShortName ([string](Get-SIVerifyValue $m 'computerDnsName')); if ($n) { $byName[$n] = $true }
    }
    $since = $Now.ToUniversalTime().AddDays(-[Math]::Max(1, $StaleDays))
    $out = New-Object System.Collections.Generic.List[object]
    foreach ($d in $Devices) {
        $en = Get-SIVerifyValue $d 'accountEnabled'
        if ($null -ne $en -and -not [bool]$en) { continue }
        $os = [string](Get-SIVerifyValue $d 'operatingSystem')
        if ($os -notmatch '^(?i)(windows|macos|mac os)') { continue }
        $seen = ConvertTo-SIVerifyDate (Get-SIVerifyValue $d 'approximateLastSignInDateTime')
        if ($null -eq $seen -or $seen -lt $since) { continue }
        $aad = ([string](Get-SIVerifyValue $d 'deviceId')).ToLowerInvariant()
        $name = [string](Get-SIVerifyValue $d 'displayName')
        if (($aad -and $byAad.ContainsKey($aad)) -or ($name -and $byName.ContainsKey((Get-SIVerifyShortName $name)))) { continue }
        $out.Add((New-SIVerificationFinding -Check $check -ScopeKey $(if ($aad) { $aad } else { $name.ToLowerInvariant() }) -ScopeName $name `
            -Detail ('The {0} device {1} signed in on {2:yyyy-MM-dd} and is not in Defender for Endpoint.' -f $os, $name, $seen)))
    }
    $out.ToArray()
}

function Test-SIVerifySensorHealth {
    <#
        sensor-unhealthy: every Defender machine seen within -StaleDays (older = stale, not a gap) whose healthStatus is
        not Active, or whose lastSeen is older than -HeartbeatDays.
    #>
    param([Parameter(Mandatory)]$Catalog, [AllowEmptyCollection()][object[]]$Machines = @(), [int]$StaleDays = 30, [int]$HeartbeatDays = 7, [datetime]$Now = [datetime]::UtcNow)
    $check = Get-SIVerificationCheck -Catalog $Catalog -Id 'sensor-unhealthy'
    $stale = $Now.ToUniversalTime().AddDays(-[Math]::Max(1, $StaleDays))
    $beat = $Now.ToUniversalTime().AddDays(-[Math]::Max(1, $HeartbeatDays))
    $out = New-Object System.Collections.Generic.List[object]
    foreach ($m in $Machines) {
        $seen = ConvertTo-SIVerifyDate (Get-SIVerifyValue $m 'lastSeen')
        if ($null -eq $seen -or $seen -lt $stale) { continue }
        $h = [string](Get-SIVerifyValue $m 'healthStatus')
        $why = $null
        if ($h -and $h -ne 'Active') { $why = ('its sensor reports {0}' -f $h) }
        elseif ($seen -lt $beat) { $why = ('it last reported on {0:yyyy-MM-dd} (more than {1} days ago)' -f $seen, $HeartbeatDays) }
        if (-not $why) { continue }
        $id = [string](Get-SIVerifyValue $m 'id'); $name = [string](Get-SIVerifyValue $m 'computerDnsName')
        $out.Add((New-SIVerificationFinding -Check $check -ScopeKey $id -ScopeName $name -Detail ('{0}: {1}.' -f $name, $why)))
    }
    $out.ToArray()
}

function Test-SIVerifyUnsupportedOs {
    <# os-unsupported: every Defender machine seen within -StaleDays whose osPlatform is in the catalog's unsupportedOs list. #>
    param([Parameter(Mandatory)]$Catalog, [AllowEmptyCollection()][object[]]$Machines = @(), [int]$StaleDays = 30, [datetime]$Now = [datetime]::UtcNow)
    $check = Get-SIVerificationCheck -Catalog $Catalog -Id 'os-unsupported'
    $eos = @{}; foreach ($u in @($Catalog.unsupportedOs)) { $eos[([string]$u.osPlatform).ToLowerInvariant()] = $u }
    $stale = $Now.ToUniversalTime().AddDays(-[Math]::Max(1, $StaleDays))
    $out = New-Object System.Collections.Generic.List[object]
    foreach ($m in $Machines) {
        $seen = ConvertTo-SIVerifyDate (Get-SIVerifyValue $m 'lastSeen')
        if ($null -eq $seen -or $seen -lt $stale) { continue }
        $os = [string](Get-SIVerifyValue $m 'osPlatform')
        if (-not $os -or -not $eos.ContainsKey($os.ToLowerInvariant())) { continue }
        $u = $eos[$os.ToLowerInvariant()]
        $id = [string](Get-SIVerifyValue $m 'id'); $name = [string](Get-SIVerifyValue $m 'computerDnsName')
        $note = ''; if ($u.PSObject.Properties['note'] -and $u.note) { $note = ' (' + [string]$u.note + ')' }
        $out.Add((New-SIVerificationFinding -Check $check -ScopeKey $id -ScopeName $name -Detail ('{0} runs {1}, out of support since {2}{3}.' -f $name, $os, [string]$u.endOfSupport, $note)))
    }
    $out.ToArray()
}

function Test-SIVerifyMulticloud {
    <# multicloud-connector-absent: ONE tenant finding when Defender for Cloud has no AWS / GCP connector at all. #>
    param([Parameter(Mandatory)]$Catalog, [AllowEmptyCollection()][object[]]$Connectors = @())
    $check = Get-SIVerificationCheck -Catalog $Catalog -Id 'multicloud-connector-absent'
    if (@($Connectors | Where-Object { $_ }).Count -gt 0) { return }
    New-SIVerificationFinding -Check $check -ScopeKey 'tenant' -ScopeName 'Tenant' -Detail 'Defender for Cloud has no AWS or GCP connector.'
}

function Test-SIVerifyHuntingTables {
    <#
        hunting-table-empty: every catalog table whose read returned 0 rows. -Counts: table -> row count ($null = the table
        could not be read: not a finding -- the run reports it as not checked for that table).
    #>
    param([Parameter(Mandatory)]$Catalog, [Parameter(Mandatory)][hashtable]$Counts)
    $check = Get-SIVerificationCheck -Catalog $Catalog -Id 'hunting-table-empty'
    $out = New-Object System.Collections.Generic.List[object]
    foreach ($t in @($Catalog.huntingTables)) {
        if (-not $Counts.ContainsKey([string]$t) -or $null -eq $Counts[[string]$t]) { continue }
        if ([long]$Counts[[string]$t] -gt 0) { continue }
        $out.Add((New-SIVerificationFinding -Check $check -ScopeKey ([string]$t) -ScopeName ([string]$t) -Detail ('The Advanced Hunting table {0} has no rows.' -f $t)))
    }
    $out.ToArray()
}

function Test-SIVerifySignInLogs {
    <# signin-logs-missing: every catalog table with 0 rows in the last day in the security workspace (-Counts as above). #>
    param([Parameter(Mandatory)]$Catalog, [Parameter(Mandatory)][hashtable]$Counts, [string]$WorkspaceName = 'the security workspace')
    $check = Get-SIVerificationCheck -Catalog $Catalog -Id 'signin-logs-missing'
    $out = New-Object System.Collections.Generic.List[object]
    foreach ($t in @($Catalog.signInTables)) {
        if (-not $Counts.ContainsKey([string]$t) -or $null -eq $Counts[[string]$t]) { continue }
        if ([long]$Counts[[string]$t] -gt 0) { continue }
        $out.Add((New-SIVerificationFinding -Check $check -ScopeKey ([string]$t) -ScopeName ([string]$t) -Detail ('{0} received no {1} rows in the last day.' -f $WorkspaceName, $t)))
    }
    $out.ToArray()
}

function Test-SIVerifyCollectors {
    <#
        collector-incomplete: every catalog collector engine whose newest run-health END in the window is not 'success',
        or that has no END in the window at all. -RunHealth: rows with Engine, ExitReason, TimeGenerated (the END rows).
    #>
    param([Parameter(Mandatory)]$Catalog, [AllowEmptyCollection()][object[]]$RunHealth = @(), [int]$WindowHours = 26)
    $check = Get-SIVerificationCheck -Catalog $Catalog -Id 'collector-incomplete'
    $last = @{}
    foreach ($r in $RunHealth) {
        $e = ([string](Get-SIVerifyValue $r 'Engine')).ToLowerInvariant(); if (-not $e) { continue }
        $t = ConvertTo-SIVerifyDate (Get-SIVerifyValue $r 'TimeGenerated')
        if (-not $last.ContainsKey($e) -or ($t -and $last[$e].T -and $t -gt $last[$e].T)) { $last[$e] = [pscustomobject]@{ T = $t; Exit = [string](Get-SIVerifyValue $r 'ExitReason'); Msg = [string](Get-SIVerifyValue $r 'ErrorMessage') } }
    }
    $out = New-Object System.Collections.Generic.List[object]
    foreach ($e in @($Catalog.collectorEngines)) {
        $k = ([string]$e).ToLowerInvariant()
        if (-not $last.ContainsKey($k)) {
            $out.Add((New-SIVerificationFinding -Check $check -ScopeKey $k -ScopeName $k -Detail ('The {0} collector has no finished run in the last {1} hours.' -f $k, $WindowHours)))
            continue
        }
        $l = $last[$k]
        if ($l.Exit -eq 'success') { continue }
        $msg = $l.Msg; if ($msg.Length -gt 300) { $msg = $msg.Substring(0, 300) + '...' }
        $out.Add((New-SIVerificationFinding -Check $check -ScopeKey $k -ScopeName $k -Detail ('The last {0} run ended {1}{2}.' -f $k, $(if ($l.Exit) { $l.Exit } else { 'without a result' }), $(if ($msg) { ': ' + $msg } else { '' }))))
    }
    $out.ToArray()
}

# ---------------------------------------------------------------------------------------------------------------------
#  DECISIONS -- ignored / accepted, each due for review after the catalog's decisionReviewDays (180)
# ---------------------------------------------------------------------------------------------------------------------

function Get-SIVerificationDecisionState {
    <#
        PURE. The ACTIVE decision of each finding (the newest decision row that is not revoked) and whether its review is
        DUE (ReviewDueAt <= now). -Decisions: rows with DecisionId, FindingKey, Decision, Reason, Owner, DecidedBy,
        DecidedAt, ReviewDueAt, RevokedAt. Returns FindingKey -> @{ Decision; ...; ReviewDue }.
    #>
    param([AllowEmptyCollection()][object[]]$Decisions = @(), [datetime]$Now = [datetime]::UtcNow)
    $state = @{}
    foreach ($d in ($Decisions | Where-Object { $_ } | Sort-Object { [long](Get-SIVerifyValue $_ 'DecisionId') })) {
        $k = ([string](Get-SIVerifyValue $d 'FindingKey')).ToLowerInvariant(); if (-not $k) { continue }
        if ($null -ne (Get-SIVerifyValue $d 'RevokedAt') -and "$(Get-SIVerifyValue $d 'RevokedAt')" -ne '') { if ($state.ContainsKey($k) -and $state[$k].DecisionId -eq [long](Get-SIVerifyValue $d 'DecisionId')) { $state.Remove($k) }; continue }
        $due = ConvertTo-SIVerifyDate (Get-SIVerifyValue $d 'ReviewDueAt')
        $state[$k] = [pscustomobject]@{
            DecisionId = [long](Get-SIVerifyValue $d 'DecisionId'); Decision = [string](Get-SIVerifyValue $d 'Decision'); Reason = [string](Get-SIVerifyValue $d 'Reason')
            Owner = [string](Get-SIVerifyValue $d 'Owner'); DecidedBy = [string](Get-SIVerifyValue $d 'DecidedBy'); ReviewDueAt = $due
            ReviewDue = [bool]($null -ne $due -and $due -le $Now.ToUniversalTime())
        }
    }
    $state
}

function Get-SIVerificationReviewDue {
    <# PURE. The review date of a decision taken -At: + the catalog's decisionReviewDays (180). #>
    param([Parameter(Mandatory)]$Catalog, [datetime]$At = [datetime]::UtcNow)
    $days = 180
    if ($Catalog.defaults -and $Catalog.defaults.decisionReviewDays) { $days = [int]$Catalog.defaults.decisionReviewDays }
    $At.ToUniversalTime().AddDays($days)
}

function Get-SIVerificationSummary {
    <#
        PURE. The run's summary per check -- what the setup telemetry's controls (framework §8.7, SI #491) will report:
        state (ok | gaps | not-checked), open / ignored / accepted / review-due counts. -Results: CheckId -> @{ Ran; Reason;
        Findings }. -Decisions: Get-SIVerificationDecisionState.
    #>
    param([Parameter(Mandatory)]$Catalog, [Parameter(Mandatory)][hashtable]$Results, [hashtable]$Decisions = @{})
    foreach ($c in @($Catalog.checks | Where-Object { [string]$_.state -ne 'not_used' })) {
        $r = $Results[[string]$c.id]
        if (-not $r -or -not $r.Ran) {
            [pscustomobject][ordered]@{ CheckId = [string]$c.id; State = 'not-checked'; Reason = $(if ($r) { [string]$r.Reason } else { 'not run' }); Open = 0; Ignored = 0; Accepted = 0; ReviewDue = 0 }
            continue
        }
        $open = 0; $ign = 0; $acc = 0; $due = 0
        foreach ($f in @($r.Findings)) {
            $d = $Decisions[[string]$f.FindingKey]
            if (-not $d) { $open++; continue }
            if ($d.Decision -eq 'ignored') { $ign++ } elseif ($d.Decision -eq 'accepted') { $acc++ } else { $open++ }
            if ($d.ReviewDue) { $due++ }
        }
        [pscustomobject][ordered]@{ CheckId = [string]$c.id; State = $(if (($open + $acc + $ign) -gt 0) { 'gaps' } else { 'ok' }); Reason = ''; Open = $open; Ignored = $ign; Accepted = $acc; ReviewDue = $due }
    }
}
