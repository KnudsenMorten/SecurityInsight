#Requires -Version 5.1
<#
    ONE ACTIVE REVISION (SI #1414; framework SEC-PATCH-PIPELINE-1 point 6, owner 2026-11-26: "will an attacker see the new or
    old image if they try to attack ?" -> "yes, check that against each solutions ... the same for ALL existing Solutions +
    future"). After every swap -- the normal update AND the image-only short path -- NOTHING old answers from the internet:
    every container app of the install with an ingress runs in SINGLE revision mode with EXACTLY ONE active revision, the
    newest one, proven healthy, with all (100 %) of the traffic, and no traffic label (a label is its own address).

    The apps are DISCOVERED from the install's resource group (every container app there with an ingress: the web app, the MCP
    server and any later one -- never a fixed list of two). Per app:
      1. THE KEEPER: the app's newest revision must be its latest READY one, Provisioned, Healthy, Running / RunningAtMaxScale
         with at least one replica (the web app roll's own rule). A newest revision still on its way (a change just before
         this step -- an identity PATCH, a setting -- made it) is WAITED for, bounded (-ReadyWaitSeconds), and then judged.
         Not proven, or traffic pinned BY NAME to another revision: NOTHING is changed on that app (never deactivate the
         only healthy revision, never override a pin) and it is a FAILURE.
      2. Multiple or Labels mode, a split / labelled traffic list -> ONE PATCH of the configuration: activeRevisionsMode
         Single, ingress.traffic = latest revision 100 % (the rest of the ingress as read). A configuration change makes no
         new revision. The app's provisioningState is waited for (Succeeded) before anything else, then read again.
      3. every OTHER revision still active -> deactivated (POST .../revisions/<name>/deactivate; a 409 is waited out; an
         answer "already inactive" or a refusal is said -- the read-back decides).
      4. READ BACK (bounded wait, a deactivation settles in seconds): Single, exactly the keeper active, 100 % to it, no label.
         Not proven = a FAILURE, said with what was read. A plan run (-WhatIf) changes nothing and says what it would set.
    Rights: the updater's Contributor on the resource group covers Microsoft.App/containerApps/write and
    .../revisions/deactivate/action -- nothing new is granted, ever.
    Callers: the updater's normal update (post-roll, after the web app roll read back healthy), its image-only short path
    (last), the post-roll run (the release's own code), EVERY other updater run (no code installed: an unproven state is
    tried again; only reads when all is right), and the release's setup\Invoke-SIContainerUpdate.ps1 (its last step, so the
    release that brings this reaches it in the same update -- a WARNING only there; the failure record is the updater's).
    A failure is LOUD at every updater caller: the update's failure report to Invardia (step post-roll) and the run's
    result -- never silent. PowerShell 5.1 and 7. No PowerShell module.
#>

$script:SISingleRevisionApi = '2025-07-01'

function Invoke-SISingleRevisionArm {
    <# The ARM call of this file over SecurityInsight's REST client (-Rest: SI-UpdateRest.ps1's seam). -Method 'LIST' = every
       item of a list (nextLink followed); a 404 = $null; anything else that fails throws. #>
    param([Parameter(Mandatory)][scriptblock]$Rest, [Parameter(Mandatory)][string]$Method, [Parameter(Mandatory)][string]$Path, $Body)
    $v = if ("$script:SISingleRevisionApi".Trim()) { $script:SISingleRevisionApi } else { '2025-07-01' }
    $uri = Get-SIArmUri -Path $Path -ApiVersion $v
    if ($Method -eq 'LIST') { return @(Get-SIRestList -Rest $Rest -Uri $uri -What 'listing') }
    $b = if ($null -ne $Body -and -not ($Body -is [string])) { ConvertTo-Json -InputObject $Body -Depth 60 -Compress } else { $Body }
    Invoke-SIRestJson -Rest $Rest -Method $Method -Uri $uri -Body $b -AllowNotFound -Headers @{ 'Content-Type' = 'application/json' } -What ('{0} {1}' -f $Method, $Path)
}

function Get-SISingleRevisionProp {
    <# PURE. A nested property of an ARM object ($null when any step is missing). #>
    param($Object, [string[]]$Path)
    $o = $Object
    foreach ($p in $Path) {
        if ($null -eq $o) { return $null }
        if ($o -is [System.Collections.IDictionary]) { $o = $o[$p]; continue }
        $pp = $o.PSObject.Properties[$p]; if (-not $pp) { return $null }; $o = $pp.Value
    }
    $o
}

function Test-SISingleRevisionApp {
    <# PURE. Is -App (ARM shape) one this step looks after: a container app with an ingress (external or internal). #>
    param($App)
    [bool]($App -and "$($App.name)".Trim() -and $null -ne (Get-SISingleRevisionProp $App @('properties', 'configuration', 'ingress')))
}

function Get-SISingleRevisionState {
    <#
        PURE. What -App (ARM shape) and its -Revisions (ARM shape) are now, against the rule: @{ App; External; Mode; Latest;
        Ready; Active (names); Keeper ('' = none proven); KeeperWhy; TrafficOk; Labels (count); LatestImage; Ok }.
        The keeper = the newest revision, when it is also the latest READY one, provisioned (not failed), Healthy, running.
        TrafficOk = no label, and the traffic list sends 100 % to the keeper (by name, or as "latest" while the latest is it);
        an app read without a traffic list sends everything to its latest revision.
    #>
    param([Parameter(Mandatory)]$App, [object[]]$Revisions = @())
    $p = { param($o, $path) Get-SISingleRevisionProp $o $path }
    $name = [string]$App.name
    $mode = [string](& $p $App @('properties', 'configuration', 'activeRevisionsMode')); if (-not $mode) { $mode = 'Single' }
    $latest = [string](& $p $App @('properties', 'latestRevisionName'))
    $ready = [string](& $p $App @('properties', 'latestReadyRevisionName'))
    $ext = [bool]("$(& $p $App @('properties', 'configuration', 'ingress', 'external'))" -match '^(?i)true$')
    $revs = @(@($Revisions) | Where-Object { $_ -and "$($_.name)".Trim() })
    $active = @($revs | Where-Object { "$(& $p $_ @('properties', 'active'))" -match '^(?i)true$' } | ForEach-Object { [string]$_.name })
    $keeper = ''; $why = ''
    $lr = @($revs | Where-Object { [string]$_.name -eq $latest })[0]
    if (-not $latest) { $why = 'its newest revision could not be read' }
    elseif ($latest -ne $ready) { $why = ('its newest revision {0} is not ready (the latest ready one is {1})' -f $latest, $(if ($ready) { $ready } else { 'none' })) }
    elseif (-not $lr) { $why = ('its newest revision {0} is not in the revision list' -f $latest) }
    else {
        $ps = [string](& $p $lr @('properties', 'provisioningState')); $hs = [string](& $p $lr @('properties', 'healthState')); $rs = [string](& $p $lr @('properties', 'runningState'))
        $rp = & $p $lr @('properties', 'replicas')
        # the web app roll's own rule (Test-SIUpdaterRevisionServing): provisioned, Healthy, Running / RunningAtMaxScale ONLY; and
        # at least one replica when the read says how many. An empty provisioning state = not ready yet.
        if ($ps -ne 'Provisioned') { $why = ('its newest revision {0} is {1}' -f $latest, $(if ($ps) { $ps } else { 'not provisioned yet' })) }
        elseif ($hs -ne 'Healthy') { $why = ('its newest revision {0} is {1}' -f $latest, $(if ($hs) { $hs } else { 'not healthy yet' })) }
        elseif ($rs -notin 'Running', 'RunningAtMaxScale') { $why = ('its newest revision {0} is {1}' -f $latest, $(if ($rs) { $rs } else { 'not running yet' })) }
        elseif ($null -ne $rp -and "$rp" -match '^\d+$' -and [int]"$rp" -lt 1) { $why = ('its newest revision {0} runs no replica' -f $latest) }
        elseif ($active -notcontains $latest) { $why = ('its newest revision {0} is not active' -f $latest) }
        else { $keeper = $latest }
    }
    $traffic = @(& $p $App @('properties', 'configuration', 'ingress', 'traffic') | Where-Object { $null -ne $_ })
    $labels = @($traffic | Where-Object { "$(& $p $_ @('label'))".Trim() }).Count
    $w = 0
    if (-not $traffic.Count) { $w = 100 }
    else {
        foreach ($t in $traffic) {
            $tn = [string](& $p $t @('revisionName')); $isLatest = "$(& $p $t @('latestRevision'))" -match '^(?i)true$'
            if (($keeper -and $tn -eq $keeper) -or (-not $tn -and $isLatest -and $latest -and $latest -eq $keeper)) { $w += [int](0 + (& $p $t @('weight'))) }
        }
    }
    $trafficOk = [bool]($keeper -and $labels -eq 0 -and $w -ge 100)
    $img = ''; try { $img = [string](@(& $p $App @('properties', 'template', 'containers') | Where-Object { $_ })[0].image) } catch { $img = '' }
    # no keeper YET: the newest revision is still on its way (a change just before this step -- an identity PATCH, a setting --
    # made it), not failed: the caller waits for it, bounded, and then judges the newest healthy revision
    $pending = $false
    if (-not $keeper -and $latest) {
        $lps = if ($lr) { [string](& $p $lr @('properties', 'provisioningState')) } else { '' }
        $lrs = if ($lr) { [string](& $p $lr @('properties', 'runningState')) } else { '' }
        $pending = -not ($lps -eq 'Failed' -or $lrs -eq 'Failed')
    }
    # revisions the traffic list names that are not the keeper (pinned by name)
    $pinned = @($traffic | ForEach-Object { [string](& $p $_ @('revisionName')) } | Where-Object { $_ -and $_ -ne $keeper } | Select-Object -Unique)
    [pscustomobject]@{ App = $name; External = $ext; Mode = $mode; Latest = $latest; Ready = $ready; Active = @($active); Keeper = $keeper; KeeperWhy = $why; Pending = $pending
                       Pinned = @($pinned); TrafficOk = $trafficOk; Labels = $labels; LatestImage = $img
                       Ok = [bool]($keeper -and $mode -eq 'Single' -and $active.Count -eq 1 -and $active[0] -eq $keeper -and $trafficOk) }
}

function Get-SISingleRevisionPlan {
    <# PURE. What must change on one app (-State: Get-SISingleRevisionState): @{ Refuse ('' = go); PatchMode; Deactivate (names) }.
       No proven keeper = Refuse (nothing is changed). #>
    param([Parameter(Mandatory)]$State)
    if (-not $State.Keeper) { return [pscustomobject]@{ Refuse = ('{0}: {1} -- nothing was changed, the revisions that answer now keep answering' -f $State.App, $State.KeeperWhy); PatchMode = $false; Deactivate = @() } }
    # traffic pinned BY NAME to another revision is someone's deliberate choice: never overridden here -- refused, said
    $pinned = @(@($State.Pinned) | Where-Object { $_ })
    if ($pinned.Count) { return [pscustomobject]@{ Refuse = ('{0}: its traffic is pinned by name to {1} (not the newest revision {2}) -- nothing was changed; an older revision may still answer until the pin is removed' -f $State.App, ($pinned -join ', '), $State.Keeper); PatchMode = $false; Deactivate = @() } }
    [pscustomobject]@{ Refuse = ''; PatchMode = [bool]($State.Mode -ne 'Single' -or -not $State.TrafficOk)
                       Deactivate = @(@($State.Active) | Where-Object { $_ -and $_ -ne $State.Keeper }) }
}

function New-SISingleRevisionPatchBody {
    <# PURE. The PATCH body: activeRevisionsMode Single and the ingress AS READ with only its traffic set to the latest revision,
       100 % (no label); its read-only address left out. #>
    param([Parameter(Mandatory)]$App)
    $ing = Get-SISingleRevisionProp $App @('properties', 'configuration', 'ingress')
    $copy = [ordered]@{}
    if ($ing) {
        $src = ConvertTo-Json -InputObject $ing -Depth 30 | ConvertFrom-Json
        foreach ($pp in @($src.PSObject.Properties)) { if ($pp.Name -ne 'fqdn' -and $pp.Name -ne 'traffic') { $copy[$pp.Name] = $pp.Value } }
    }
    $copy['traffic'] = @([ordered]@{ latestRevision = $true; weight = 100 })
    [ordered]@{ properties = [ordered]@{ configuration = [ordered]@{ activeRevisionsMode = 'Single'; ingress = $copy } } }
}

function Invoke-SISingleRevision {
    <#
        THE STEP (the file header). -Rest: SecurityInsight's REST seam (Invoke-SISingleRevisionArm), or -Arm: a seam
        { param($Method, $Path, $Body) } with the same contract ('LIST' = every item; 404 = $null). -Apps: names that are
        looked after even when the list misses them (the install record's names); every container app of the resource group
        with an ingress is looked after anyway. -WaitSeconds / -PollSeconds: the read-back's bounded wait. -Sleep: test seam.
        -WhatIf: read and say only. Returns @{ Ok; Text; Apps (one Get-SISingleRevisionState per app, as READ BACK);
        Failures (one line per app that is not proven); Changed (lines) }. Never throws.
    #>
    param([scriptblock]$Arm, [scriptblock]$Rest, [Parameter(Mandatory)][string]$SubscriptionId, [Parameter(Mandatory)][string]$ResourceGroup,
          [string[]]$Apps = @(), [int]$WaitSeconds = 120, [int]$PollSeconds = 10, [int]$ReadyWaitSeconds = 300, [scriptblock]$Sleep, [scriptblock]$Log, [switch]$WhatIf)
    if (-not $Arm) {
        if (-not $Rest) { return [pscustomobject]@{ Ok = $false; Text = 'one active revision NOT proven: no Azure sign-in to read the container apps with'; Apps = @(); Failures = @('no Azure sign-in'); Changed = @() } }
        $Arm = { param([string]$Method, [string]$Path, $Body) Invoke-SISingleRevisionArm -Rest $Rest -Method $Method -Path $Path -Body $Body }
    }
    $say = { param($m) if ($Log) { & $Log $m } }
    $nap = { param($s) if ($Sleep) { & $Sleep $s } elseif ($s -gt 0) { Start-Sleep -Seconds $s } }
    $base = '/subscriptions/{0}/resourceGroups/{1}/providers/Microsoft.App/containerApps' -f $SubscriptionId, $ResourceGroup
    $fail = New-Object System.Collections.Generic.List[string]
    $changed = New-Object System.Collections.Generic.List[string]
    $planned = New-Object System.Collections.Generic.List[string]
    $states = New-Object System.Collections.Generic.List[object]
    $out = { param($ok, $text) [pscustomobject]@{ Ok = [bool]$ok; Text = $text; Apps = $states.ToArray(); Failures = $fail.ToArray(); Changed = $changed.ToArray() } }
    $all = @()
    try { $all = @(& $Arm 'LIST' $base $null | Where-Object { $_ }) }
    catch { $fail.Add(('the container apps of {0} could not be listed ({1}) -- whether only the newest revision answers is NOT proven' -f $ResourceGroup, $_.Exception.Message)); return (& $out $false $fail[0]) }
    # every app once, whatever the case of its name (an ARM name is case-insensitive)
    $seen = @{}
    $names = @(foreach ($x in @(@($all | Where-Object { Test-SISingleRevisionApp $_ } | ForEach-Object { [string]$_.name }) + @($Apps | Where-Object { "$_".Trim() }))) {
        $k = "$x".Trim().ToLowerInvariant(); if (-not $seen.ContainsKey($k)) { $seen[$k] = $true; "$x".Trim() } })
    $busy = { param($e) "$e" -match '(?i)\b409\b|in progress|ContainerAppOperationInProgress' }
    foreach ($n in $names) {
        try {
            $appPath = '{0}/{1}' -f $base, $n
            $app = & $Arm 'GET' $appPath $null
            if (-not $app) { continue }                                  # a recorded name that is not there (moved): nothing to do
            if (-not (Test-SISingleRevisionApp $app)) { continue }       # no ingress: nothing answers
            $st = Get-SISingleRevisionState -App $app -Revisions @(& $Arm 'LIST' ($appPath + '/revisions') $null)
            # a change made just before this step (an identity PATCH, a setting) makes a NEW revision: wait for it, bounded, and
            # judge the newest healthy revision -- never an older one, never "not proven" while it is still on its way
            $readyBy = [datetime]::UtcNow.AddSeconds([Math]::Max(0, $ReadyWaitSeconds))
            while (-not $st.Ok -and -not $st.Keeper -and $st.Pending -and $PollSeconds -gt 0 -and [datetime]::UtcNow -lt $readyBy) {
                & $nap $PollSeconds
                $app = & $Arm 'GET' $appPath $null
                $st = Get-SISingleRevisionState -App $app -Revisions @(& $Arm 'LIST' ($appPath + '/revisions') $null)
            }
            if ($st.Ok) { $states.Add($st); continue }
            $plan = Get-SISingleRevisionPlan -State $st
            if ($plan.Refuse) { $fail.Add($plan.Refuse); $states.Add($st); continue }
            if ($WhatIf) {
                $planned.Add(('{0}: would be set to one active revision ({1}; mode {2}, {3} active)' -f $n, $st.Keeper, $st.Mode, @($st.Active).Count)); $states.Add($st); continue
            }
            if ($plan.PatchMode) {
                $tries = 0
                while ($true) {
                    try { $null = & $Arm 'PATCH' $appPath (New-SISingleRevisionPatchBody -App $app); break }
                    catch {
                        $tries++
                        # an operation still in flight on the app (409) is waited out a little, then said
                        if ($tries -lt 6 -and (& $busy $_.Exception.Message)) { & $nap $PollSeconds; try { $app = & $Arm 'GET' $appPath $null } catch { }; continue }
                        throw
                    }
                }
                $changed.Add(('{0}: Single revision mode, all traffic on {1} (was mode {2}{3})' -f $n, $st.Keeper, $st.Mode, $(if ($st.Labels) { ", $($st.Labels) traffic label(s)" } else { '' })))
                # the PATCH is provisioned before anything is deactivated (a deactivation during it is refused)
                $doneBy = [datetime]::UtcNow.AddSeconds([Math]::Max(0, $WaitSeconds))
                while ($true) {
                    $app = & $Arm 'GET' $appPath $null
                    $ps = [string](Get-SISingleRevisionProp $app @('properties', 'provisioningState'))
                    if (-not $ps -or $ps -eq 'Succeeded') { break }
                    if ($ps -eq 'Failed') { throw ('the change to Single revision mode ended Failed') }
                    if ($PollSeconds -le 0 -or [datetime]::UtcNow -ge $doneBy) { throw ('the change to Single revision mode is still {0} after {1} s' -f $ps, $WaitSeconds) }
                    & $nap $PollSeconds
                }
                # what is active NOW (the mode change may have deactivated the others already), judged again
                $st = Get-SISingleRevisionState -App $app -Revisions @(& $Arm 'LIST' ($appPath + '/revisions') $null)
                $plan = Get-SISingleRevisionPlan -State $st
                if ($plan.Refuse) { $fail.Add($plan.Refuse); $states.Add($st); continue }
            }
            foreach ($r in @($plan.Deactivate)) {
                $tries = 0
                $did = $false
                while ($true) {
                    try { $null = & $Arm 'POST' ('{0}/revisions/{1}/deactivate' -f $appPath, $r) $null; $did = $true; break }
                    catch {
                        $tries++
                        $em = "$($_.Exception.Message)"
                        if ($tries -lt 6 -and (& $busy $em)) { & $nap $PollSeconds; continue }
                        # already inactive (Azure did it with the mode change), or refused: said -- the READ-BACK decides
                        & $say ('one active revision: {0}: revision {1} -- the deactivation answered: {2} (the read-back decides)' -f $n, $r, $em)
                        break
                    }
                }
                if ($did) { $changed.Add(('{0}: revision {1} deactivated' -f $n, $r)) }
            }
            # READ BACK (a deactivation settles in seconds; bounded)
            $deadline = [datetime]::UtcNow.AddSeconds([Math]::Max(0, $WaitSeconds))
            $rb = $null
            do {
                $a2 = & $Arm 'GET' ('{0}/{1}' -f $base, $n) $null
                $rb = Get-SISingleRevisionState -App $a2 -Revisions @(& $Arm 'LIST' ('{0}/{1}/revisions' -f $base, $n) $null)
                if ($rb.Ok -or [datetime]::UtcNow -ge $deadline -or $PollSeconds -le 0) { break }
                & $nap $PollSeconds
            } while ($true)
            $states.Add($rb)
            if (-not $rb.Ok) {
                $fail.Add(('{0}: does not read back with one active revision (mode {1}; active {2}; traffic {3}{4}) -- an older revision may still answer' -f $n, $rb.Mode, ((@($rb.Active) -join ', ')), $(if ($rb.TrafficOk) { '100 % on the newest' } else { 'not all on the newest' }), $(if ($rb.KeeperWhy) { '; ' + $rb.KeeperWhy } else { '' })))
            }
        } catch { $fail.Add(('{0}: one active revision could not be set or read back ({1}) -- an older revision may still answer' -f $n, $_.Exception.Message)) }
    }
    foreach ($l in $changed) { & $say ('one active revision: ' + $l) }
    if ($fail.Count) { return (& $out $false ('one active revision NOT proven: ' + ($fail -join '; '))) }
    if ($states.Count -eq 0) { return (& $out $true 'one active revision: no container app with an ingress in this install') }
    # a plan run (-WhatIf) changes nothing: it says what it WOULD set, never "set now"
    if ($planned.Count -gt 0) { foreach ($l in $planned) { $changed.Add($l) }; return (& $out $true ('one active revision (plan only, nothing changed): ' + ($planned.ToArray() -join '; '))) }
    $list = New-Object System.Collections.Generic.List[string]
    foreach ($s in $states) { $list.Add(('{0} ({1})' -f [string]$s.App, [string]$s.Keeper)) }
    $setNow = ''
    if ($changed.Count -gt 0) { $setNow = ' (set now)' }
    $text = 'one active revision: ' + ($list.ToArray() -join ', ') + ' -- each in Single revision mode, only its newest healthy revision active, all traffic on it' + $setNow
    & $out $true $text
}
