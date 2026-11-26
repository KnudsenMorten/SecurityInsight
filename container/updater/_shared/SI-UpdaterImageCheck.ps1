#Requires -Version 5.1
<#
    caj-si-updater -- THE IMAGE CHECK, EVERY 15 MINUTES (SI #1344; owner IMAGE-30MIN-1 2026-11-24: "chg security agent to chk
    img every30 min" / "goal is to get img upd faster when security cve detected in img"; then "lets chg so agent checks ever
    15 min and solutions checks every 15 min"; framework SEC-LANE-1 G5: every 15 minutes).

    The job caj-si-image-check (setup\_shared\SI-ImageCheckJob.ps1) runs THIS image with SI_UPDATER_MODE = image-check, on
    '*/15 * * * *'. Such a run (Invoke-SIUpdaterImageCheckRun, called from Start-SIUpdater.ps1 right after the sign-in):
      1. steps aside -- one INFO line, nothing read from Invardia -- when the nightly update starts now (its own timer's
         slot), when an update execution of caj-si-updater runs, or an earlier image check still runs. Nothing is stopped;
      2. asks Invardia for its ring's release (the one update client, _shared\SI-UpdaterInvardia.ps1 -- the same signed
         manifest, the same ring, the same install key) and acts ONLY on an image-only release of what runs: a fourth version
         part on the running release (Get-SIImageCheckCandidate), then the image-only proof of the downloaded release
         (Get-SIUpdaterImageOnlyDecision: the patch's own What's new of type security, the same engine code). A code
         release is never applied here -- it stays on the nightly update. Nothing new = ONE INFO line, nothing saved;
      3. applies it AT ONCE by the updater's own image-only path (Invoke-SIUpdaterImageOnly): the images built in the
         install's registry, the engine jobs moved by digest, the web app / MCP server, the updater last -- a running
         execution keeps the image it started with (image-only is code-identical: the next execution takes the new one),
         nothing is ever stopped. A release that says it must be installed while nothing runs (UPDATE-NEEDS-QUIET.txt)
         waits -- one line, the next check tries again;
      4. moves this job's own image to the updater's (Invoke-SIUpdaterImageCheckJob) and READS BACK EVERY JOB's image
         digest against the digest its build produced in the install's registry (framework RELEASE-DRYRUN-1 case (h),
         Test-SIImageCheckBuildDigest; Get-SIImageCheckDigestProof). Not proven = the run fails and says which job;
      5. reports to Invardia as every update does (the run's stages, the failure reports).
    Until a check decides there is work, its log lines are HELD (Start-SIUpdaterQuiet): a check that finds nothing writes one
    line only; one that acts writes everything it held first. PS 5.1 and 7. No module.
#>

if (-not (Get-Command -Name Get-SIImageCheckJobNames -ErrorAction SilentlyContinue)) {
    foreach ($__siIcF in @('/si/setup/_shared/SI-ImageCheckJob.ps1', [IO.Path]::Combine($PSScriptRoot, '..', '..', '..', 'setup', '_shared', 'SI-ImageCheckJob.ps1'))) { if (Test-Path -LiteralPath $__siIcF) { . $__siIcF; break } }
}

function Test-SIImageCheckBuildDigest {
    <#
        PURE. Framework RELEASE-DRYRUN-1 case (h) for ONE job: -Name 'repo:tag' (registry stripped), -RunningDigest (the digest
        the job is pinned to; '' when it runs by tag), -Builds: the install's Succeeded registry runs of exactly that repo:tag
        (@{ Digest; Run }).
          no build of that tag                       NOT proven (fail closed)
          pinned by digest                           OK only when that digest is one this tag's build produced
          by tag, every build of the tag one digest  OK (the tag can only resolve to it)
          by tag, the tag built to several digests   NOT proven (which one runs cannot be told)
        A tag that LOOKS right never passes on its own. @{ Ok; Text }.
    #>
    param([Parameter(Mandatory)][string]$Name, [string]$RunningDigest = '', [AllowEmptyCollection()][object[]]$Builds = @())
    $rd = "$RunningDigest".Trim().ToLowerInvariant()
    $dg = @(@($Builds) | Where-Object { $_ -and "$($_.Digest)" -match '^sha256:[0-9a-f]{64}$' } | ForEach-Object { "$($_.Digest)".ToLowerInvariant() } | Select-Object -Unique)
    $short = { param($d) if ("$d".Length -gt 19) { "$d".Substring(0, 19) } else { "$d" } }
    $runs = (@(@($Builds) | Where-Object { $_ -and "$($_.Run)" } | ForEach-Object { "$($_.Run)" } | Select-Object -Unique)) -join ','
    if (-not $dg.Count) { return [pscustomobject]@{ Ok = $false; Text = ('no build of {0} was read from the install''s registry runs -- NOT proven' -f $Name) } }
    if ($rd) {
        if ($dg -contains $rd) { return [pscustomobject]@{ Ok = $true; Text = ('{0} = the digest its build produced (run {1}) -- OK' -f (& $short $rd), $runs) } }
        return [pscustomobject]@{ Ok = $false; Text = ('runs {0}, but its build produced {1} (run {2}) -- another image under the same tag; NOT proven' -f (& $short $rd), (($dg | ForEach-Object { & $short $_ }) -join ', '), $runs) }
    }
    if ($dg.Count -eq 1) { return [pscustomobject]@{ Ok = $true; Text = ('{0} (by tag; its one build produced it, run {1}) -- OK' -f (& $short $dg[0]), $runs) } }
    [pscustomobject]@{ Ok = $false; Text = ('runs by tag, and the tag was built to {0} different digests -- which one runs cannot be told; NOT proven' -f $dg.Count) }
}

function Start-SIUpdaterQuiet {
    <# From now on Write-UpdLog HOLDS its lines (with their time) instead of writing them. #>
    $global:SI_UpdaterQuiet = New-Object System.Collections.Generic.List[string]
}

function Stop-SIUpdaterQuiet {
    <# Ends the hold. -Flush: the held lines are written now (a check that acts, or fails, shows everything); without it they
       are dropped (a check that found nothing). #>
    param([switch]$Flush)
    $held = $global:SI_UpdaterQuiet
    $global:SI_UpdaterQuiet = $null
    if ($Flush -and $held) { foreach ($l in @($held)) { Write-Host $l } }
}

function Get-SIImageCheckCandidate {
    <#
        PURE. Does this image check act on the code manifest result -Result (Request-SIInvardiaManifest; $null = not asked)
        with the decision -Decision (Get-SIUpdaterInvardiaCodeDecision) for an install that runs -Deployed on ring -Ring?
        Only an IMAGE-ONLY release of what runs (Test-SIImageOnlyVersion: a fourth version part on the running release) goes on;
        everything else is one plain INFO line. @{ Go; Line }.
    #>
    param($Result, $Decision, [AllowEmptyString()][string]$Deployed = '', $Ring = $null)
    $rt = if ($null -ne $Ring -and "$Ring".Trim()) { 'ring {0}' -f "$Ring".Trim() } else { 'its ring' }
    $no = { param($l) [pscustomobject]@{ Go = $false; Line = ('image check: ' + $l) } }
    if (-not $Result) { return (& $no ('Invardia was not asked this time -- the next check asks again')) }
    $act = "$($Result.Action)"
    if ($act -notin @('update', 'current')) { return (& $no ('nothing to install from {0} ({1}: {2})' -f $rt, $act, "$($Result.Reason)".Trim())) }
    if (-not $Decision -or -not $Decision.Act) { return (& $no ('nothing new -- this install runs the release of {0} ({1})' -f $rt, $(if ("$Deployed".Trim()) { "$Deployed".Trim() } else { "$($Result.Version)" }))) }
    $v = "$($Result.Version)".Trim()
    $io = if (Get-Command -Name Test-SIImageOnlyVersion -ErrorAction SilentlyContinue) { Test-SIImageOnlyVersion -Version $v -Running $Deployed } else { [pscustomobject]@{ Ok = $false; Why = 'this updater cannot tell an image-only release' } }
    if (-not $io.Ok) { return (& $no ('{0} has {1}, not an image-only release of the {2} this install runs ({3}) -- the nightly update installs it, this check does not' -f $rt, $v, "$Deployed".Trim(), $io.Why)) }
    [pscustomobject]@{ Go = $true; Line = ('image check: {0} has {1}, an image-only (security) release of the {2} this install runs -- it is installed now' -f $rt, $v, "$Deployed".Trim()) }
}

function Test-SIImageCheckAtUpdaterSlot {
    <#
        PURE. Is -NowUtc within -WindowMinutes after a start of the nightly update's timer -Cron ('m h * * *'; lists like
        '30 16,17 * * *' and '*' are read; '' or anything else = $false)? Then the image check steps aside: the update that
        starts now installs what is new. The window is the check's own tick (15 minutes) and the end is EXCLUSIVE, read in
        whole minutes: of the ticks every 15 minutes exactly ONE falls inside it per nightly start (the start's own tick,
        or the one right after a start between two ticks) -- the next tick always checks. (After that a check steps aside
        only while the update itself still runs.)
    #>
    param([Parameter(Mandatory)][datetime]$NowUtc, [AllowEmptyString()][string]$Cron = '', [int]$WindowMinutes = $(if (Get-Command -Name Get-SIImageCheckJobNames -ErrorAction SilentlyContinue) { [int](Get-SIImageCheckJobNames).TickMinutes } else { 15 }))
    $p = @(("$Cron".Trim()) -split '\s+' | Where-Object { $_ })
    if ($p.Count -ne 5 -or $p[2] -ne '*' -or $p[3] -ne '*' -or $p[4] -ne '*') { return $false }
    $nums = { param($f, $max) if ($f -eq '*') { 0..$max } elseif ($f -match '^\d{1,2}(,\d{1,2})*$') { @($f.Split(',') | ForEach-Object { [int]$_ }) } else { $null } }
    $mins = & $nums $p[0] 59; $hours = & $nums $p[1] 23
    if ($null -eq $mins -or $null -eq $hours) { return $false }
    $u = $NowUtc.ToUniversalTime(); $now = $u.Hour * 60 + $u.Minute
    foreach ($h in @($hours)) { foreach ($m in @($mins)) {
        $d = $now - ([int]$h * 60 + [int]$m); if ($d -lt 0) { $d += 1440 }
        if ($d -lt $WindowMinutes) { return $true }
    } }
    $false
}

function Get-SIImageCheckRunningOther {
    <# PURE. The name of an execution in -Executions (ARM shape) that runs now (Running / Processing, no end, started within
       -WithinHours), other than -Self; '' = none. #>
    param([AllowEmptyCollection()][object[]]$Executions = @(), [string]$Self = '', [datetime]$NowUtc = [datetime]::UtcNow, [int]$WithinHours = 24)
    foreach ($e in @($Executions)) {
        if (-not $e -or [string]$e.name -eq $Self) { continue }
        $p = $e.properties
        if (-not $p -or "$($p.status)" -notin @('Running', 'Processing') -or "$($p.endTime)".Trim()) { continue }
        $st = [datetime]::MinValue
        if ("$($p.startTime)".Trim() -and -not [datetime]::TryParse("$($p.startTime)", [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]'AdjustToUniversal,AssumeUniversal', [ref]$st)) { continue }
        if ($st -ne [datetime]::MinValue -and ($NowUtc.ToUniversalTime() - $st).TotalHours -gt $WithinHours) { continue }
        return [string]$e.name
    }
    ''
}

function ConvertFrom-SIImageCheckImageRef {
    <# PURE. '<registry>/<repo>:<tag>[@sha256:<d>]' -> @{ Registry; Repo; Tag; Digest; Name ('repo:tag') }. #>
    param([AllowEmptyString()][string]$Image)
    $i = "$Image".Trim(); $dg = ''
    if ($i -match '^(?<r>[^@]+)@(?<d>sha256:[0-9a-f]{64})$') { $i = $Matches['r']; $dg = $Matches['d'] }
    $reg = ''; $path = $i
    $first = ($i -split '/')[0]
    if ($i.Contains('/') -and ($first.Contains('.') -or $first.Contains(':'))) { $reg = $first.ToLowerInvariant(); $path = $i.Substring($first.Length + 1) }
    $repo = $path; $tag = ''
    $k = $path.LastIndexOf(':'); if ($k -gt 0) { $repo = $path.Substring(0, $k); $tag = $path.Substring($k + 1) }
    [pscustomobject]@{ Registry = $reg; Repo = $repo; Tag = $tag; Digest = $dg; Name = $(if ($tag) { '{0}:{1}' -f $repo, $tag } else { $repo }) }
}

function ConvertFrom-SIImageCheckRegistryRuns {
    <# PURE. The registry's runs (ARM GET <registry>/runs: value[].properties { runId; status; outputImages[{ repository; tag;
       digest }] }) -> @(@{ Repository; Tag; Digest; Run; Status }). #>
    param($Runs)
    $items = if ($null -eq $Runs) { @() } elseif ($Runs.PSObject.Properties['value']) { @($Runs.value) } else { @($Runs) }
    @(foreach ($r in $items) {
        if (-not $r -or -not $r.properties) { continue }
        foreach ($o in @($r.properties.outputImages)) {
            if (-not $o -or -not "$($o.digest)".Trim()) { continue }
            [pscustomobject]@{ Repository = [string]$o.repository; Tag = [string]$o.tag; Digest = ([string]$o.digest).ToLowerInvariant(); Run = [string]$r.properties.runId; Status = [string]$r.properties.status }
        }
    })
}

function Get-SIImageCheckDigestProof {
    <#
        PURE. Framework RELEASE-DRYRUN-1 case (h) after an image-only swap of -Version: EVERY job (-Jobs, ARM shape) that runs
        an image of a repository this release built (a Succeeded registry run, -Builds, of a tag 'v<Version>' / 'v<Version>-...')
        must run THAT build: its tag is a build of -Version, and its image digest is the one its build produced
        (Test-SIImageCheckBuildDigest -- a tag that LOOKS right never passes on its own). A job of another image (another
        registry, a repository the release did not build) is not this release's. No build of -Version read, or no job on one
        = NOT proven (fail closed). @{ Ok; Checked; Lines; Why }.
    #>
    param([AllowEmptyCollection()][object[]]$Jobs = @(), [AllowEmptyCollection()][object[]]$Builds = @(), [Parameter(Mandatory)][string]$Version, [string]$LoginServer = '')
    $vrx = '^v' + [regex]::Escape("$Version".Trim()) + '($|[-_+])'
    $ok = @(@($Builds) | Where-Object { $_ -and "$($_.Status)" -eq 'Succeeded' -and "$($_.Digest)" -match '^sha256:[0-9a-f]{64}$' })
    $repos = @($ok | Where-Object { "$($_.Tag)" -cmatch $vrx } | ForEach-Object { "$($_.Repository)" } | Select-Object -Unique)
    $lines = New-Object System.Collections.Generic.List[string]; $bad = New-Object System.Collections.Generic.List[string]
    if (-not $repos.Count) { return [pscustomobject]@{ Ok = $false; Checked = 0; Lines = @(); Why = ('no build of {0} was read from the install''s registry runs -- the job digests cannot be compared; NOT proven' -f $Version) } }
    $checked = 0
    foreach ($j in @($Jobs | Where-Object { $_ } | Sort-Object { [string]$_.name })) {
        $img = ''; try { $img = [string](@($j.properties.template.containers | Where-Object { $_ })[0].image) } catch { $img = '' }
        if (-not $img.Trim()) { continue }
        $r = ConvertFrom-SIImageCheckImageRef $img
        if ("$LoginServer".Trim() -and $r.Registry -and $r.Registry -ne "$LoginServer".Trim().ToLowerInvariant()) { continue }
        if ($repos -notcontains $r.Repo) { continue }
        $checked++
        if ($r.Tag -cnotmatch $vrx) { $bad.Add(('{0} runs {1}, not the build of {2}' -f $j.name, $r.Name, $Version)); $lines.Add(('{0}: {1} -- MISMATCH (not a build of {2})' -f $j.name, $r.Name, $Version)); continue }
        $mine = [object[]]@($ok | Where-Object { "$($_.Repository)" -eq $r.Repo -and "$($_.Tag)" -ceq $r.Tag } | ForEach-Object { [pscustomobject]@{ Digest = $_.Digest; Run = $_.Run } })
        $dg = Test-SIImageCheckBuildDigest -Name $r.Name -RunningDigest $r.Digest -Builds $mine
        $lines.Add(('{0}: {1} -- {2}' -f $j.name, $r.Name, $dg.Text))
        if (-not $dg.Ok) { $bad.Add(('{0}: {1}' -f $j.name, $dg.Text)) }
    }
    if (-not $checked) { return [pscustomobject]@{ Ok = $false; Checked = 0; Lines = $lines.ToArray(); Why = ('no job runs an image of {0} ({1} built) -- NOT proven' -f $Version, ($repos -join ', ')) } }
    if ($bad.Count) { return [pscustomobject]@{ Ok = $false; Checked = $checked; Lines = $lines.ToArray(); Why = ('{0} of {1} job(s) do not run the digest their build of {2} produced: {3}' -f $bad.Count, $checked, $Version, ($bad -join '; ')) } }
    [pscustomobject]@{ Ok = $true; Checked = $checked; Lines = $lines.ToArray(); Why = ('every job on an image of {0} ({1}) runs the digest its build produced -- read back' -f $Version, $checked) }
}

function Invoke-SIImageCheckDigestProof {
    <# The read-back of Get-SIImageCheckDigestProof against this install: every job of the resource group and the registry's
       runs (ARM). -Jobs { } / -Runs { } / -LoginServer: test seams. Never throws (a read that fails = NOT proven). #>
    param([Parameter(Mandatory)][string]$Version, [Parameter(Mandatory)][string]$ResourceGroup, [Parameter(Mandatory)][string]$AcrName,
          [Parameter(Mandatory)][string]$SubscriptionId, [string]$LoginServer = '', [scriptblock]$Jobs, [scriptblock]$Runs)
    try {
        $acrId = ''
        if (-not $Runs -or -not $LoginServer) { $acr = Get-SIUpdaterRegistry -AcrName $AcrName -SubscriptionId $SubscriptionId -ResourceGroup $ResourceGroup; $acrId = [string]$acr.id; if (-not $LoginServer) { $LoginServer = [string]$acr.loginServer } }
        $jl = if ($Jobs) { @(& $Jobs) } else { @(Get-SIUpdaterJobs -ResourceGroup $ResourceGroup -SubscriptionId $SubscriptionId) }
        $rl = if ($Runs) { & $Runs } else { Invoke-SIUpdaterArm -Path ($acrId.TrimEnd('/') + '/runs?$top=100') -ApiVersion '2019-06-01-preview' }
        Get-SIImageCheckDigestProof -Jobs $jl -Builds @(ConvertFrom-SIImageCheckRegistryRuns $rl) -Version $Version -LoginServer $LoginServer
    } catch { [pscustomobject]@{ Ok = $false; Checked = 0; Lines = @(); Why = ('the job digests could not be read back ({0}) -- NOT proven' -f $_.Exception.Message) } }
}

function Invoke-SIUpdaterImageCheckJob {
    <# caj-si-image-check kept present and on the updater's image (setup\_shared\SI-ImageCheckJob.ps1, read back) -- on every
       updater run and after an image check's swap. A job that is as it must be says nothing (-Quiet). Never throws. -Arm: seam. #>
    # -Rest (#1413): the SI REST seam the resource group's identities are read with (default: the updater's own; with -Arm = a test, only when given)
    param([Parameter(Mandatory)][string]$SubscriptionId, [Parameter(Mandatory)][string]$ResourceGroup, [string]$UpdaterJob = 'caj-si-updater', [scriptblock]$Arm, [switch]$Quiet, [scriptblock]$Rest)
    try {
        if (-not (Get-Command -Name Invoke-SIImageCheckJobEnsure -ErrorAction SilentlyContinue)) { return $null }
        if (-not $Rest -and -not $Arm -and (Get-Command -Name Get-SIUpdaterRest -ErrorAction SilentlyContinue)) { try { $Rest = Get-SIUpdaterRest } catch { $Rest = $null } }
        if (-not $Arm) { $Arm = { param([string]$Method, [string]$Path, $Body) Invoke-SIUpdaterArm -Method $Method -Path $Path -ApiVersion (Get-SIImageCheckJobNames).AppApi -Body $Body -AllowNotFound:($Method -eq 'GET') } }
        $ensure = @{ Arm = $Arm; SubscriptionId = $SubscriptionId; ResourceGroup = $ResourceGroup; UpdaterJob = $UpdaterJob }; if ($Rest) { $ensure.Rest = $Rest }
        $r = Invoke-SIImageCheckJobEnsure @ensure
        if (-not ($Quiet -and $r.Action -eq 'kept')) { Write-UpdLog $r.Reason }
        $r
    } catch { Write-UpdLog ('WARNING: the image check job could not be checked ({0}) -- the next update tries again' -f $_.Exception.Message); $null }
}

function Invoke-SIUpdaterDeadIdentities {
    <# #1413: a deleted user-assigned identity taken off SI's jobs and apps (setup\_shared\SI-LiveIdentities.ps1,
       Invoke-SIDeadIdentityCleanup: fail closed, identity-only PATCH, read back) -- on every updater run right after the image
       check job is kept present, and after an image check's swap. Each problem is a WARNING line and an updater failure report
       (step settings). Quiet when every identity exists. Never throws. -Rest: seam. #>
    # -Switch: the off-switch's value (default: SI_UPDATER_IDENTITY_CLEANUP of this job's environment; off = nothing checked)
    param([Parameter(Mandatory)][string]$SubscriptionId, [Parameter(Mandatory)][string]$ResourceGroup, [scriptblock]$Rest, [AllowNull()][string]$Switch = $([Environment]::GetEnvironmentVariable('SI_UPDATER_IDENTITY_CLEANUP')))
    $soft = { param($t) Write-UpdLog $t; if (Get-Command -Name Add-SIUpdaterFailure -ErrorAction SilentlyContinue) { Add-SIUpdaterFailure -Step 'settings' -Text $t } }
    try {
        if (-not (Get-Command -Name Invoke-SIDeadIdentityCleanup -ErrorAction SilentlyContinue)) { & $soft 'identities: the clean-up of deleted identities is not in this image (setup\_shared\SI-LiveIdentities.ps1 not loaded) -- nothing checked'; return $null }
        if (-not (Test-SIDeadIdentityCleanupOn $Switch)) { Write-UpdLog 'identities: the clean-up of deleted identities is switched off (SI_UPDATER_IDENTITY_CLEANUP = off) -- nothing checked'; return $null }
        if (-not $Rest) { if (-not (Get-Command -Name Get-SIUpdaterRest -ErrorAction SilentlyContinue)) { return $null }; $Rest = Get-SIUpdaterRest }
        $r = Invoke-SIDeadIdentityCleanup -Rest $Rest -SubscriptionId $SubscriptionId -ResourceGroup $ResourceGroup
        $quiet = (-not @($r.Removed).Count -and -not @($r.Problems).Count -and -not @($r.Held).Count -and -not @($r.Soft).Count -and -not @($r.Lines | Where-Object { $_ -match 'nothing removed|exists \(its own read' }).Count)
        if (-not $quiet) { foreach ($l in @($r.Lines)) { Write-UpdLog $l } }
        if (Get-Command -Name Add-SIUpdaterFailure -ErrorAction SilentlyContinue) { foreach ($p in @($r.Problems) + @($r.Soft)) { Add-SIUpdaterFailure -Step 'settings' -Text $p } }
        $r
    } catch { Write-UpdLog ('WARNING: identities: not checked ({0}) -- the next update checks again' -f $_.Exception.Message); $null }
}
function Wait-SIUpdaterImageCheckEnded {
    <# A NIGHTLY update waits for an image check that runs now to end (two runs never change the install at once; the image
       check steps aside at the update's own slot, so this is seconds -- or a swap it is finishing). Bounded by -MaxMinutes.
       -Executions { } -> caj-si-image-check's executions; -Sleep / -Now: seams. Returns the line ('' = none ran). Never throws. #>
    param([Parameter(Mandatory)][scriptblock]$Executions, [scriptblock]$Sleep = { param($s) Start-Sleep -Seconds $s }, [scriptblock]$Now = { [datetime]::UtcNow },
          [int]$PollSeconds = 15, [int]$MaxMinutes = 120)
    $t0 = & $Now; $first = ''
    while ($true) {
        $run = ''
        try { $run = Get-SIImageCheckRunningOther -Executions @(& $Executions) -NowUtc (& $Now) } catch { return '' }
        if (-not $run) { return $(if ($first) { 'the image check {0} has ended -- the update goes on' -f $first } else { '' }) }
        if (-not $first) { $first = $run }
        if (((& $Now) - $t0).TotalMinutes -ge $MaxMinutes) { return ('the image check {0} still runs after {1} min -- the update goes on (it was not stopped)' -f $run, $MaxMinutes) }
        & $Sleep $PollSeconds
    }
}

function Invoke-SIUpdaterImageCheckRun {
    <#
        ONE IMAGE CHECK (the file header, steps 1-5). Called by Start-SIUpdater.ps1 for SI_UPDATER_MODE = image-check, after
        the sign-in and the database, BEFORE every step of a normal update run (no secret hand-over, no support or identity
        step, no licence request, no size step, no template step -- the nightly update does those). Returns the exit code.
        -Seams (tests): UpdaterCron { } -> the nightly timer; UpdaterExecutions { } / OwnExecutions { } -> ARM executions;
        Deployed { } -> the release that runs; Invardia (the seams of Invoke-SIUpdaterFromInvardia). Never stops anything.
    #>
    param([hashtable]$Env = @{}, $Store, [string]$StoreError = '', [Parameter(Mandatory)][string]$SubscriptionId, [Parameter(Mandatory)][string]$ResourceGroup,
          [Parameter(Mandatory)][string]$AcrName, [string[]]$Blocked = @(), [hashtable]$Seams = @{}, [datetime]$NowUtc = [datetime]::UtcNow)
    $get = { param($k) $v = if ($Env.ContainsKey($k)) { $Env[$k] } else { [Environment]::GetEnvironmentVariable($k) }; if ([string]::IsNullOrWhiteSpace($v)) { '' } else { "$v".Trim() } }
    $n = Get-SIImageCheckJobNames
    $updJob = if (Get-Command -Name Get-SIUpdaterInstallName -ErrorAction SilentlyContinue) { Get-SIUpdaterInstallName -Role updater -Env $Env } elseif (& $get 'SI_UPDATER_JOB_NAME') { & $get 'SI_UPDATER_JOB_NAME' } else { 'caj-si-updater' }
    if ($null -eq $global:SI_UpdaterQuiet) { Start-SIUpdaterQuiet }
    $idle = { param($line) Stop-SIUpdaterQuiet; $global:SI_ImageCheckIdle = $true; Write-UpdLog $line; 0 }
    $global:SI_UpdaterStep = 'image-check'
    try {
        # 1. the nightly update starts now, an update runs, or an earlier check runs: step aside (nothing is stopped)
        $cron = if ($Seams['UpdaterCron']) { [string](& $Seams.UpdaterCron) } elseif (Get-Command -Name Get-SIUpdaterOwnTimer -ErrorAction SilentlyContinue) { [string](Get-SIUpdaterOwnTimer -SubscriptionId $SubscriptionId -ResourceGroup $ResourceGroup -JobName $updJob).Cron } else { '' }
        if (Test-SIImageCheckAtUpdaterSlot -NowUtc $NowUtc -Cron $cron) { return (& $idle ('image check: the nightly update starts now (''{0}'' UTC) -- it installs what is new; nothing checked here' -f $cron)) }
        $execOf = { param($job) @(Invoke-SIUpdaterArm -Path (Get-SIUpdaterRgPath -SubscriptionId $SubscriptionId -ResourceGroup $ResourceGroup -Provider ('Microsoft.App/jobs/{0}/executions' -f $job)) -List) }
        $updEx = if ($Seams['UpdaterExecutions']) { @(& $Seams.UpdaterExecutions) } else { @(& $execOf $updJob) }
        $run = Get-SIImageCheckRunningOther -Executions $updEx -NowUtc $NowUtc
        if ($run) { return (& $idle ('image check: the update {0} runs now -- nothing checked here; it was not stopped' -f $run)) }
        $ownEx = if ($Seams['OwnExecutions']) { @(& $Seams.OwnExecutions) } else { @(& $execOf $n.Job) }
        $run = Get-SIImageCheckRunningOther -Executions $ownEx -Self (& $get 'CONTAINER_APP_JOB_EXECUTION_NAME') -NowUtc $NowUtc
        if ($run) { return (& $idle ('image check: the earlier check {0} still runs -- nothing checked here; it was not stopped' -f $run)) }
        # 2. the install's names, and the customer's switch for updates from Invardia (off = no check either)
        if (Get-Command -Name Invoke-SIUpdaterInstallNames -ErrorAction SilentlyContinue) { $null = Invoke-SIUpdaterInstallNames -Env $Env -Store $Store }
        if (Get-Command -Name Get-SIUpdaterAutoSwitches -ErrorAction SilentlyContinue) {
            $sw = Get-SIUpdaterAutoSwitches -Env $Env -Store $Store -StoreFailed:([bool]$StoreError) -StoreError $StoreError
            if ($sw -and $sw['SI_InvardiaUpdate_Enabled'] -and -not $sw['SI_InvardiaUpdate_Enabled'].On) { return (& $idle ('image check: updates from Invardia are off on this install -- nothing checked ({0})' -f $sw['SI_InvardiaUpdate_Enabled'].Text)) }
        }
        # 3-5. the one update client, in its image-check mode (it says the one line itself when there is nothing to do)
        $dep = if ($Seams['Deployed']) { [string](& $Seams.Deployed) } else { Get-SIUpdaterDeployed -ResourceGroup $ResourceGroup -AcrName $AcrName -SubscriptionId $SubscriptionId -Env $Env }
        $fa = @{ Env = $Env; SubscriptionId = $SubscriptionId; ResourceGroup = $ResourceGroup; AcrName = $AcrName; Blocked = $Blocked; Store = $Store; Deployed = $dep }
        if ($Seams['Invardia']) { $fa.Seams = $Seams['Invardia'] }
        if ($Seams['SIRoot']) { $fa.SIRoot = [string]$Seams['SIRoot'] }
        if ($Seams['Work']) { $fa.Work = [string]$Seams['Work'] }
        @(Invoke-SIUpdaterFromInvardia @fa)[-1]
    } catch {
        Stop-SIUpdaterQuiet -Flush
        throw
    } finally {
        if ($global:SI_UpdaterQuiet) { Stop-SIUpdaterQuiet -Flush }
    }
}
