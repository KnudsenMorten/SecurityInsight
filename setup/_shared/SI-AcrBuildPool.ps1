#Requires -Version 5.1
<#
    SecurityInsight -- THE BUILD POOL OF A PRIVATE INSTALL (framework installer rule 11g, Invardia, owner-approved 2026-11-05).

    A private install's registry (Premium, public access Disabled) builds its images on its OWN agent pool inside its network
    (si-vnet-pool, setup\_shared\SI-PrivateNetwork.ps1). The rule:
      1. The pool's count is 0 BETWEEN builds. It only builds images; no job runs on it.
      2. Before the first build of an install / update / setup step, the pool is scaled to S2 x 2 (count 2) and read back
         (provisioningState Succeeded AND the count); after the last build it goes back to 0 in a FINALLY -- also after a
         failed or timed-out build -- read back. A scale-down that fails is said plainly and reported as a failure line of
         its own; it never hides the build result.
      3. Tier S2. The tier cannot change in place (Azure: delete + create the pool again with the same subnet and OS). The
         installer creates the pool at S2 with count 0; the UPDATER moves an existing pool of another tier to S2 ONLY while no
         run of the registry is Queued / Started / Running (and no build of this process holds the pool), same subnet, read
         back. Anything uncertain = the pool is left as it is and that is said -- never a pool deleted without being made again.
      4. The build waits stay as they are (the update: 90 min).

    THE SESSION. A process may build several images (the updater queues the web app / MCP / updater images in parallel with
    the engine build and waits for them later). The pool is held for the whole of that by ONE session (global, nested by a
    depth counter): Open-SIBuildPoolSession / Close-SIBuildPoolSession, or Invoke-SIWithBuildPool around a block. The scale-up
    is LAZY -- Invoke-SIAcrQueueBuild asks for it (Request-SIBuildPoolUp) just before it schedules a build on the pool -- so a
    run that builds nothing never scales the pool. Only the OUTERMOST close scales back to 0, and only when the session
    scaled (or tried to scale) the pool up. Without an open session nothing here touches the pool.

    Every call goes through -Arm { param([string]$Method, [string]$Path, $Body) } (parsed answer, $null for not found, throws
    otherwise -- the seam of SI-PrivateNetwork.ps1) or, when no -Arm is given, -Rest (setup\_shared\SI-UpdateRest.ps1,
    Invoke-SIRestJson). No module, no az. Values live in Get-SIBuildPoolSettings (a function, not a script variable: a script
    that finds these functions already defined does not dot-source this file again). PowerShell 5.1-compatible.
#>

function Get-SIBuildPoolSettings {
    <# PURE. Rule 11g's values. #>
    [pscustomobject]@{
        Tier            = 'S2'
        BuildCount      = 2
        IdleCount       = 0
        Api             = '2019-06-01-preview'
        WaitMinutes     = 30
        PauseSeconds    = 15
        ActiveRunStates = @('Queued', 'Started', 'Running')
        RunsRead        = 20
    }
}

function Get-SIBuildPoolProp {
    <# PURE. A nested property (PSCustomObject or hashtable), $null when any step is missing. #>
    param($Object, [string[]]$Names)
    $o = $Object
    foreach ($n in $Names) {
        if ($null -eq $o) { return $null }
        if ($o -is [System.Collections.IDictionary]) { if ($o.Contains($n)) { $o = $o[$n] } else { return $null }; continue }
        $p = $o.PSObject.Properties[$n]
        if (-not $p) { return $null }
        $o = $p.Value
    }
    $o
}

function Invoke-SIBuildPoolCall {
    <# One ARM call: through -Arm when given, else through -Rest (Invoke-SIRestJson, 404 = $null). Throws on any other error. #>
    param([scriptblock]$Arm, [scriptblock]$Rest, [Parameter(Mandatory)][string]$Method, [Parameter(Mandatory)][string]$Path, $Body)
    if ($Arm) { return (& $Arm $Method $Path $Body) }
    if (-not $Rest) { throw 'no Azure seam (-Arm or -Rest) for the build pool' }
    $u = if ($Path -match '^https://') { $Path } else { 'https://management.azure.com' + $Path }
    Invoke-SIRestJson -Rest $Rest -Method $Method -Uri $u -Body $Body -AllowNotFound -What ('{0} {1}' -f $Method, ($Path -replace '\?.*$', ''))
}

function Get-SIBuildPoolPath {
    <# PURE. The ARM path of agent pool -Pool of -RegistryId (or -PoolId as it is), with the pinned api-version. #>
    param([string]$RegistryId = '', [string]$Pool = '', [string]$PoolId = '')
    $id = if ($PoolId) { $PoolId.TrimEnd('/') } else { '{0}/agentPools/{1}' -f $RegistryId.TrimEnd('/'), $Pool }
    '{0}?api-version={1}' -f $id, (Get-SIBuildPoolSettings).Api
}

function ConvertTo-SIBuildPoolState {
    <# PURE. What a pool (as ARM returns it) reads: @{ Tier; Count; State; Subnet; Os; Location } (Count -1 = not readable). #>
    param($Pool)
    $cnt = -1; $c = Get-SIBuildPoolProp $Pool @('properties', 'count')
    if ($null -ne $c -and "$c" -match '^\d+$') { $cnt = [int]"$c" }
    [pscustomobject]@{
        Tier     = [string](Get-SIBuildPoolProp $Pool @('properties', 'tier'))
        Count    = $cnt
        State    = [string](Get-SIBuildPoolProp $Pool @('properties', 'provisioningState'))
        Subnet   = [string](Get-SIBuildPoolProp $Pool @('properties', 'virtualNetworkSubnetResourceId'))
        Os       = [string](Get-SIBuildPoolProp $Pool @('properties', 'os'))
        Location = [string](Get-SIBuildPoolProp $Pool @('location'))
    }
}

function Set-SIBuildPoolCount {
    <#
        Scales the agent pool -PoolId to -Count agents (PATCH properties.count), then READS IT BACK until Azure reads it
        Succeeded with exactly that count, Failed / Canceled, or -LimitMinutes pass (the clock is -Now, so tests do not wait).
        Never throws. Returns @{ Ok; Count; Tier; State; TimedOut; Line }.
    #>
    param([scriptblock]$Arm, [scriptblock]$Rest, [Parameter(Mandatory)][string]$PoolId, [Parameter(Mandatory)][int]$Count,
          [scriptblock]$Sleep = { param($s) Start-Sleep -Seconds $s }, [scriptblock]$Now = { [datetime]::UtcNow },
          [int]$LimitMinutes = (Get-SIBuildPoolSettings).WaitMinutes, [int]$PauseSeconds = (Get-SIBuildPoolSettings).PauseSeconds)
    $name = ($PoolId.TrimEnd('/') -split '/')[-1]
    $path = Get-SIBuildPoolPath -PoolId $PoolId
    try { $null = Invoke-SIBuildPoolCall -Arm $Arm -Rest $Rest -Method 'PATCH' -Path $path -Body ([ordered]@{ properties = [ordered]@{ count = $Count } }) }
    catch { return @{ Ok = $false; Count = -1; Tier = ''; State = ''; TimedOut = $false; Line = ('the build pool {0} could not be set to {1} agent(s): Azure refused the change ({2})' -f $name, $Count, $_.Exception.Message) } }
    $start = [datetime](& $Now); $deadline = $start.AddMinutes($LimitMinutes)
    $st = $null; $timedOut = $false; $missing = $false
    while ($true) {
        $p = $null; $readOk = $true
        try { $p = Invoke-SIBuildPoolCall -Arm $Arm -Rest $Rest -Method 'GET' -Path $path } catch { $p = $null; $readOk = $false }
        $st = ConvertTo-SIBuildPoolState $p
        # Azure answers "not found": there is no such pool -- never a wait for one
        if ($readOk -and -not $p) { $missing = $true; break }
        if ($p -and $st.State -eq 'Succeeded' -and $st.Count -eq $Count) { break }
        if ($p -and $st.State -in 'Failed', 'Canceled') { break }
        if ([datetime](& $Now) -ge $deadline) { $timedOut = $true; break }
        & $Sleep $PauseSeconds
    }
    $ok = ($st.State -eq 'Succeeded' -and $st.Count -eq $Count)
    $line = if ($ok) { 'the build pool {0} reads {1} agent(s) (tier {2}; read back)' -f $name, $Count, $st.Tier }
            elseif ($missing) { 'the build pool {0} does not exist in the registry' -f $name }
            elseif ($timedOut) { 'the build pool {0} does not read back {1} agent(s) after {2} min (Azure shows: {3}, {4} agent(s))' -f $name, $Count, $LimitMinutes, $(if ($st.State) { $st.State } else { 'not readable' }), $(if ($st.Count -ge 0) { $st.Count } else { '?' }) }
            else { 'Azure did not set the build pool {0} to {1} agent(s) (Azure shows: {2}, {3} agent(s))' -f $name, $Count, $st.State, $(if ($st.Count -ge 0) { $st.Count } else { '?' }) }
    @{ Ok = [bool]$ok; Count = $st.Count; Tier = $st.Tier; State = $st.State; TimedOut = [bool]$timedOut; Line = $line }
}

# ---- the session ------------------------------------------------------------------------------------------------------
function Get-SIBuildPoolSession { <# The open session of this process ($null = none). #> $global:SI_BuildPoolSession }

function Open-SIBuildPoolSession {
    <# Opens (or joins) the build-pool session of this process. Returns the depth after it (1 = this caller is the outermost). #>
    $s = $global:SI_BuildPoolSession
    if (-not ($s -is [hashtable])) {
        $s = @{ Depth = 0; Touched = $false; Up = $false; PoolId = ''; Arm = $null; Rest = $null; Tier = ''; Line = '' }
        $global:SI_BuildPoolSession = $s
    }
    $s.Depth = [int]$s.Depth + 1
    $s.Depth
}

function Request-SIBuildPoolUp {
    <#
        THE LAZY SCALE-UP, asked for just before a build is scheduled on pool -Pool of -RegistryId. Without an open session:
        nothing (Acted = $false). In a session that has the pool up already: nothing. Otherwise the pool is scaled to S2's
        build count (2) and read back; the session is marked as having touched the pool BEFORE the change, so its close
        always brings it back to 0 -- also when the scale-up fails. Never throws: @{ Ok; Acted; Line }.
    #>
    param([scriptblock]$Arm, [scriptblock]$Rest, [Parameter(Mandatory)][string]$RegistryId, [Parameter(Mandatory)][string]$Pool,
          [scriptblock]$Sleep = { param($s) Start-Sleep -Seconds $s }, [scriptblock]$Now = { [datetime]::UtcNow })
    $s = $global:SI_BuildPoolSession
    if (-not ($s -is [hashtable]) -or [int]$s.Depth -lt 1) { return @{ Ok = $true; Acted = $false; Line = '' } }
    $poolId = '{0}/agentPools/{1}' -f $RegistryId.TrimEnd('/'), $Pool
    if ($s.Up -and [string]::Equals([string]$s.PoolId, $poolId, [StringComparison]::OrdinalIgnoreCase)) { return @{ Ok = $true; Acted = $false; Line = '' } }
    $cfg = Get-SIBuildPoolSettings
    $s.Touched = $true; $s.PoolId = $poolId; $s.Arm = $Arm; $s.Rest = $Rest
    $r = Set-SIBuildPoolCount -Arm $Arm -Rest $Rest -PoolId $poolId -Count $cfg.BuildCount -Sleep $Sleep -Now $Now
    $s.Tier = [string]$r.Tier
    if ($r.Ok) {
        $s.Up = $true
        $line = 'the build pool {0} is up for the build: {1} agent(s), tier {2} (read back){3}' -f $Pool, $cfg.BuildCount, $r.Tier, $(if ($r.Tier -and $r.Tier -ne $cfg.Tier) { ('; the update moves it to {0} when no build runs' -f $cfg.Tier) } else { '' })
        return @{ Ok = $true; Acted = $true; Line = $line }
    }
    @{ Ok = $false; Acted = $true; Line = ('the build pool could not be scaled up, so the image cannot be built: {0}' -f $r.Line) }
}

function Test-SIBuildPoolOldUpdater {
    <#
        Is this update run by an updater image from BEFORE rule 11g? Such an image runs the newer release's update script but
        builds its other images (web app, MCP server, its own image) with ITS OWN older build function, which queues on the
        pool as it finds it and holds no build-pool session. Seen as: inside an updater run (its Write-UpdLog is visible)
        with no build-pool session open. Asked BEFORE the update script opens its own session. While such an image runs, the
        release leaves the pool's tier and size as they are, and keeps the pool up for the rest of the update (Close -KeepUp)
        -- the updater's next image (its self-update, the last step of the same update) scales it from the next update on.
    #>
    [bool]((Get-Command -Name Write-UpdLog -ErrorAction SilentlyContinue) -and -not ($global:SI_BuildPoolSession -is [hashtable]))
}

function Close-SIBuildPoolSession {
    <#
        Leaves the session. Only the OUTERMOST close acts, and only when the session touched the pool: the pool goes back to
        0 agents, READ BACK. Never throws: @{ Closed (the session ended here); Touched; Ok; Line }. A scale-down that fails is
        Ok = $false with a plain line (the caller reports it as a failure of its own; the build result stays as it was).
        -KeepUp (only while an updater image older than rule 11g builds the rest of this update, Test-SIBuildPoolOldUpdater):
        the pool keeps its build size, said; the next update brings it to 0.
    #>
    param([scriptblock]$Sleep = { param($s) Start-Sleep -Seconds $s }, [scriptblock]$Now = { [datetime]::UtcNow }, [switch]$KeepUp)
    $s = $global:SI_BuildPoolSession
    if (-not ($s -is [hashtable])) { return @{ Closed = $false; Touched = $false; Ok = $true; Line = '' } }
    $s.Depth = [int]$s.Depth - 1
    if ($s.Depth -gt 0) { return @{ Closed = $false; Touched = [bool]$s.Touched; Ok = $true; Line = '' } }
    $global:SI_BuildPoolSession = $null
    if (-not $s.Touched) { return @{ Closed = $true; Touched = $false; Ok = $true; Line = '' } }
    $name = ([string]$s.PoolId -split '/')[-1]
    if ($KeepUp) { return @{ Closed = $true; Touched = $true; Ok = $true; Line = ('the build pool {0} keeps its build size for the rest of this update (this updater image builds without scaling the pool); the next update brings it back to 0' -f $name) } }
    $r = $null
    try { $r = Set-SIBuildPoolCount -Arm $s.Arm -Rest $s.Rest -PoolId ([string]$s.PoolId) -Count (Get-SIBuildPoolSettings).IdleCount -Sleep $Sleep -Now $Now }
    catch { $r = @{ Ok = $false; Line = $_.Exception.Message } }
    if ($r.Ok) { return @{ Closed = $true; Touched = $true; Ok = $true; Line = ('the build pool {0} is back at 0 agents (read back)' -f $name) } }
    @{ Closed = $true; Touched = $true; Ok = $false
       Line = ('the build pool {0} could NOT be scaled back to 0 agents after the build -- it keeps its agents (and their cost) until it is; the next update scales it down: {1}' -f $name, $r.Line) }
}

function Invoke-SIWithBuildPool {
    <#
        Runs -Action inside a build-pool session: whatever it builds scales the pool up first (lazily), and the pool goes back
        to 0 in a FINALLY -- after a success, a failed build, a timed-out build or a throw. The close's line goes to -Say; a
        scale-down that fails goes to -OnScaleDownFailed { param($Line) } too. The action's output is returned and its error
        rethrown: the scale-down never hides the build result.
    #>
    param([Parameter(Mandatory)][scriptblock]$Action, [scriptblock]$Say = { param($t) Write-Host $t }, [scriptblock]$OnScaleDownFailed,
          [scriptblock]$Sleep = { param($s) Start-Sleep -Seconds $s }, [scriptblock]$Now = { [datetime]::UtcNow })
    $null = Open-SIBuildPoolSession
    try { & $Action }
    finally {
        $c = Close-SIBuildPoolSession -Sleep $Sleep -Now $Now
        if ($c.Line) { try { & $Say $c.Line } catch { } }
        if ($c.Touched -and $c.Closed -and -not $c.Ok -and $OnScaleDownFailed) { try { & $OnScaleDownFailed $c.Line } catch { } }
    }
}

# ---- the updater's convergence: tier S2, 0 agents between builds --------------------------------------------------------
function Get-SIAcrActiveRuns {
    <# The runs of -RegistryId that still go (Queued / Started / Running) among its newest runs. @{ Known; Active } -- Known =
       $false when the runs could not be read (the caller then changes nothing). Never throws. #>
    param([scriptblock]$Arm, [scriptblock]$Rest, [Parameter(Mandatory)][string]$RegistryId)
    $cfg = Get-SIBuildPoolSettings
    try {
        $page = Invoke-SIBuildPoolCall -Arm $Arm -Rest $Rest -Method 'GET' -Path ('{0}/runs?api-version={1}&$top={2}' -f $RegistryId.TrimEnd('/'), $cfg.Api, $cfg.RunsRead)
        $runs = @(if ($page -and $page.PSObject.Properties['value']) { @($page.value) } else { @() }) | Where-Object { $_ }
        $active = @($runs | Where-Object { $st = [string](Get-SIBuildPoolProp $_ @('properties', 'status')); if (-not $st) { $st = [string](Get-SIBuildPoolProp $_ @('status')) }; @($cfg.ActiveRunStates) -contains $st })
        @{ Known = $true; Active = $active.Count }
    } catch { @{ Known = $false; Active = 0 } }
}

function Invoke-SIBuildPoolConverge {
    <#
        THE UPDATER'S STEP (rule 11g point 3): an existing pool reaches the new-install state -- tier S2, 0 agents between
        builds. Changes NOTHING while a build of this process holds the pool, while any run of the registry goes, when the
        runs cannot be read, when the pool is not Succeeded or its subnet is not known. A pool of another tier: DELETE, wait
        until it is gone, PUT it again (tier S2, count 0, the SAME subnet, OS and location), read back. If Azure does not make
        it again, that is said LOUDLY (Failure): the next update makes it again (the private registry step makes a missing pool
        in the endpoints subnet). An S2 pool left with agents: back to 0, read back. No pool: nothing (a public install).
        -WhatIf: the plan only. Never throws: @{ Action (none | skip | scaled | recreated | failed | plan); Ok; Failure; Line }.
    #>
    param([scriptblock]$Arm, [scriptblock]$Rest, [Parameter(Mandatory)][string]$RegistryId, [string]$Pool = 'si-vnet-pool',
          [switch]$WhatIf, [scriptblock]$Sleep = { param($s) Start-Sleep -Seconds $s }, [scriptblock]$Now = { [datetime]::UtcNow })
    $cfg = Get-SIBuildPoolSettings
    $poolId = '{0}/agentPools/{1}' -f $RegistryId.TrimEnd('/'), $Pool
    $path = Get-SIBuildPoolPath -PoolId $poolId
    $res = { param($a, $ok, $fail, $line) @{ Action = $a; Ok = [bool]$ok; Failure = [bool]$fail; Line = $line } }
    $s = $global:SI_BuildPoolSession
    if ($s -is [hashtable] -and $s.Touched) { return (& $res 'skip' $true $false ('the build pool {0} is in use by a build of this update -- its tier and size are checked by the next update' -f $Pool)) }
    $p = $null
    try { $p = Invoke-SIBuildPoolCall -Arm $Arm -Rest $Rest -Method 'GET' -Path $path }
    catch { return (& $res 'skip' $true $false ('the build pool {0} could not be read ({1}) -- it is left as it is' -f $Pool, $_.Exception.Message)) }
    if (-not $p) { return (& $res 'none' $true $false '') }
    $cur = ConvertTo-SIBuildPoolState $p
    if ($cur.State -ne 'Succeeded') { return (& $res 'skip' $true $false ('the build pool {0} reads {1} -- it is left as it is' -f $Pool, $(if ($cur.State) { $cur.State } else { 'no state' }))) }
    $needTier = $cur.Tier -ne $cfg.Tier
    $needCount = $cur.Count -ne $cfg.IdleCount
    # HOTFIX 2026-11-05 (framework 11g update d3adfdd2, from PIM at a customer the same day): Azure REFUSES to create an agent
    # pool at count 0 (AgentPoolInvalidCount), and a delete can take longer than one update waits -- the re-make at S2 below
    # deleted the pool and could not make it again, and a later run read "missing" as "install again" at count 0 (refused
    # again): no build pool, no image builds. Until the re-make is one intent kept across updates (create at 1 -> Succeeded ->
    # scale to 0, read back), a pool of another tier KEEPS its tier: it is only scaled to 0 agents between builds. Never a
    # delete here.
    if ($needTier) {
        $tierNote = ' (tier {0} is kept: Azure cannot change a tier in place, and the move to {1} is made by a later update as one step kept across updates)' -f $cur.Tier, $cfg.Tier
        if (-not $needCount) { return (& $res 'none' $true $false ('the build pool {0}: 0 agents between builds{1}' -f $Pool, $tierNote)) }
        $runs = Get-SIAcrActiveRuns -Arm $Arm -Rest $Rest -RegistryId $RegistryId
        if (-not $runs.Known) { return (& $res 'skip' $true $false ('whether a build runs in the registry could not be read -- the build pool {0} (tier {1}, {2} agent(s)) is left as it is; the next update looks again' -f $Pool, $cur.Tier, $cur.Count)) }
        if ($runs.Active -gt 0) { return (& $res 'skip' $true $false ('{0} build run(s) of the registry still go -- the build pool {1} (tier {2}, {3} agent(s)) is left as it is; the next update looks again' -f $runs.Active, $Pool, $cur.Tier, $cur.Count)) }
        if ($WhatIf) { return (& $res 'plan' $true $false ('the build pool {0} would go back to 0 agents (it has {1} between builds){2}' -f $Pool, $cur.Count, $tierNote)) }
        $r = Set-SIBuildPoolCount -Arm $Arm -Rest $Rest -PoolId $poolId -Count $cfg.IdleCount -Sleep $Sleep -Now $Now
        if ($r.Ok) { return (& $res 'scaled' $true $false ('the build pool {0} had {1} agent(s) between builds: back at 0 (read back){2}' -f $Pool, $cur.Count, $tierNote)) }
        return (& $res 'failed' $false $true ('the build pool {0} could NOT be scaled back to 0 agents: {1}' -f $Pool, $r.Line))
    }
    if (-not $needCount) { return (& $res 'none' $true $false ('the build pool {0}: tier {1}, 0 agents between builds' -f $Pool, $cfg.Tier)) }
    $runs = Get-SIAcrActiveRuns -Arm $Arm -Rest $Rest -RegistryId $RegistryId
    if (-not $runs.Known) { return (& $res 'skip' $true $false ('whether a build runs in the registry could not be read -- the build pool {0} (tier {1}, {2} agent(s)) is left as it is; the next update looks again' -f $Pool, $cur.Tier, $cur.Count)) }
    if ($runs.Active -gt 0) { return (& $res 'skip' $true $false ('{0} build run(s) of the registry still go -- the build pool {1} (tier {2}, {3} agent(s)) is left as it is; the next update looks again' -f $runs.Active, $Pool, $cur.Tier, $cur.Count)) }
    if (-not $needTier) {
        if ($WhatIf) { return (& $res 'plan' $true $false ('the build pool {0} would go back to 0 agents (it has {1} between builds)' -f $Pool, $cur.Count)) }
        $r = Set-SIBuildPoolCount -Arm $Arm -Rest $Rest -PoolId $poolId -Count $cfg.IdleCount -Sleep $Sleep -Now $Now
        if ($r.Ok) { return (& $res 'scaled' $true $false ('the build pool {0} had {1} agent(s) between builds: back at 0 (read back)' -f $Pool, $cur.Count)) }
        return (& $res 'failed' $false $true ('the build pool {0} could NOT be scaled back to 0 agents: {1}' -f $Pool, $r.Line))
    }
    if (-not $cur.Subnet) { return (& $res 'skip' $true $false ('the build pool {0} is tier {1}; its subnet cannot be read, so it is NOT made again at {2} -- left as it is' -f $Pool, $cur.Tier, $cfg.Tier)) }
    $os = if ($cur.Os) { $cur.Os } else { 'Linux' }
    $loc = $cur.Location
    if (-not $loc) {
        try { $loc = [string](Get-SIBuildPoolProp (Invoke-SIBuildPoolCall -Arm $Arm -Rest $Rest -Method 'GET' -Path ('{0}?api-version=2023-07-01' -f $RegistryId.TrimEnd('/'))) @('location')) } catch { $loc = '' }
    }
    if (-not $loc) { return (& $res 'skip' $true $false ('the build pool {0} is tier {1}; its location cannot be read, so it is NOT made again at {2} -- left as it is' -f $Pool, $cur.Tier, $cfg.Tier)) }
    if ($WhatIf) { return (& $res 'plan' $true $false ('the build pool {0} would be made again at tier {1} with 0 agents (it is {2}; Azure cannot change the tier in place), in the same subnet' -f $Pool, $cfg.Tier, $cur.Tier)) }
    # DELETE, then wait until it is gone -- a PUT on a pool Azure still deletes is refused
    try { $null = Invoke-SIBuildPoolCall -Arm $Arm -Rest $Rest -Method 'DELETE' -Path $path }
    catch { return (& $res 'skip' $true $false ('the build pool {0} (tier {1}) could not be removed to move it to {2} ({3}) -- it is left as it is' -f $Pool, $cur.Tier, $cfg.Tier, $_.Exception.Message)) }
    $deadline = ([datetime](& $Now)).AddMinutes($cfg.WaitMinutes)
    $gone = $false
    while ($true) {
        $x = $null; $readOk = $true
        try { $x = Invoke-SIBuildPoolCall -Arm $Arm -Rest $Rest -Method 'GET' -Path $path } catch { $readOk = $false }
        if ($readOk -and -not $x) { $gone = $true; break }
        if ([datetime](& $Now) -ge $deadline) { break }
        & $Sleep $cfg.PauseSeconds
    }
    $body = [ordered]@{ location = $loc; properties = [ordered]@{ count = $cfg.IdleCount; tier = $cfg.Tier; os = $os; virtualNetworkSubnetResourceId = $cur.Subnet } }
    $why = ''
    if ($gone) {
        try { $null = Invoke-SIBuildPoolCall -Arm $Arm -Rest $Rest -Method 'PUT' -Path $path -Body $body } catch { $why = $_.Exception.Message }
    } else { $why = 'Azure did not finish removing it within {0} min' -f $cfg.WaitMinutes }
    if (-not $why) {
        $deadline = ([datetime](& $Now)).AddMinutes($cfg.WaitMinutes)
        $b = $null
        while ($true) {
            try { $b = Invoke-SIBuildPoolCall -Arm $Arm -Rest $Rest -Method 'GET' -Path $path } catch { $b = $null }
            $bs = ConvertTo-SIBuildPoolState $b
            if ($b -and $bs.State -in 'Succeeded', 'Failed', 'Canceled') { break }
            if ([datetime](& $Now) -ge $deadline) { break }
            & $Sleep $cfg.PauseSeconds
        }
        $bs = ConvertTo-SIBuildPoolState $b
        $same = [string]::Equals($bs.Subnet.TrimEnd('/'), $cur.Subnet.TrimEnd('/'), [StringComparison]::OrdinalIgnoreCase)
        if ($b -and $bs.State -eq 'Succeeded' -and $bs.Tier -eq $cfg.Tier -and $bs.Count -eq $cfg.IdleCount -and $same) {
            return (& $res 'recreated' $true $false ('the build pool {0} was tier {1}: made again at tier {2} with 0 agents, in the same subnet (read back)' -f $Pool, $cur.Tier, $cfg.Tier))
        }
        $why = 'it reads back {0}, tier {1}, {2} agent(s){3}' -f $(if ($bs.State) { $bs.State } else { 'not there' }), $bs.Tier, $bs.Count, $(if ($b -and -not $same) { ', another subnet' } else { '' })
    }
    & $res 'failed' $false $true ('THE BUILD POOL {0} WAS REMOVED TO MOVE IT FROM TIER {1} TO {2}, AND AZURE DID NOT MAKE IT AGAIN ({3}). Image builds of this private install cannot run until it exists; the next update makes it again in the same subnet.' -f $Pool, $cur.Tier, $cfg.Tier, $why)
}
