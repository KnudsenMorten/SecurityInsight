#Requires -Version 5.1
<#
    caj-si-updater -- THE SHORT IMAGE-ONLY UPDATE PATH (framework SEC-LANE-1, owner 2026-11-14: "they pull down as today" /
    "using sep swap image if possible"). Dot-sourced by _shared/SI-UpdaterInvardia.ps1, the one update client of both editions.

    WHEN: the release the install takes is IMAGE-ONLY -- an image patch of the release it runs, proven by what the release
    already carries (engine\_shared\SI-ImageOnlyRelease.ps1 Test-SIImageOnlyRelease): a fourth version part on the running
    release, the image patch's own What's new (type security), and the SAME engine code as the code the install recorded
    when it installed what runs now. Anything else -- or a release whose update script has no image-only mode -- takes the
    full update path, unchanged.

    WHAT IT DOES: the signed release is pulled and verified as today (the caller), then the images are BUILT in the install's
    OWN registry exactly as the release names them and SWAPPED IN one part after the other:
      1. the engine jobs -- the release's setup\Invoke-SIContainerUpdate.ps1 -Apply -ImageOnly: the engine image built, each
         job's template pointed at it BY DIGEST (one ARM PATCH per job, all at once, read back; a job that does not read back
         is put back), nothing else (none of the steps after the roll);
      2. the web app, its MCP server and the sign-in front -- a new revision each (Invoke-SIUpdaterAppRoll -ImagesOnly:
         built, rolled, health-checked, put back on failure; no sign-in or Entra change);
      3. the record of what now runs (tags si-installed on the updater job) -- only when 1 and 2 are healthy;
      4. the updater ITSELF, LAST (Invoke-SIUpdaterSelfRoll).
    THEN (owner 2026-11-14: "when swap works we remove old"): ONLY when every part read back healthy, the install's own
    registry keeps only what runs -- every template, active revision, the pending self-update image and every image a running
    execution started with (SI-UpdaterImagePrune.ps1 Invoke-SIUpdaterImageOnlyPruneStep, called by SI-UpdaterInvardia.ps1);
    each kept and each deleted image is said with its reason. A swap that is not proven deletes nothing.
    WHAT IT NEVER DOES: wait for, hold for or stop a running pipeline or execution (no run gate -- a running execution keeps
    the image it started with, the next one takes the new one); a database, schema, template or data step (none of the
    release script's steps after the roll, no database setup job, no size step).

    THE DRIFT REASON (owner 2026-11-14: "i must have report of any reason that drift"): every outcome is one plain line, a
    result (done | refused | build-failed | swap-failed), the component it stopped at and why -- in the update log, in
    cfg.InstallState 'ImageOnlyUpdate' (the web app and the support read it), and as the update's failure report to Invardia.
    A part that failed is retried by the next update run (the record of what runs is written only when the swap is whole).
    PowerShell 5.1 and 7. No PowerShell module.
#>

foreach ($__siIo in @('/si/engine/_shared/SI-ImageOnlyRelease.ps1', [IO.Path]::Combine($PSScriptRoot, '..', '..', '..', 'engine', '_shared', 'SI-ImageOnlyRelease.ps1'))) {
    if (-not (Get-Command -Name Test-SIImageOnlyRelease -ErrorAction SilentlyContinue) -and (Test-Path -LiteralPath $__siIo)) { . $__siIo }
}

function Read-SIUpdaterRecordedEngineHash {
    <# The engine fingerprint the install recorded for the code it runs (cfg.InstallState 'EngineFingerprint', its hash), ''
       when none or unreadable. Never throws. #>
    param($Store)
    if (-not $Store -or -not $Store.Invoke) { return '' }
    try {
        $row = @(& $Store.Invoke "IF OBJECT_ID('cfg.InstallState') IS NOT NULL SELECT Value FROM cfg.InstallState WHERE Name = N'EngineFingerprint'" @{} 'reader' | ForEach-Object { $_ } | Where-Object { $null -ne $_ }) | Select-Object -First 1
        if (-not $row) { return '' }
        $v = if ($row -is [System.Collections.IDictionary]) { [string]$row['Value'] } else { [string]$row.Value }
        $o = $v | ConvertFrom-Json -ErrorAction Stop
        if ($o -and $o.PSObject.Properties['hash']) { return ("$($o.hash)".Trim().ToLowerInvariant()) }
    } catch { }
    ''
}

function Get-SIUpdaterReleaseEngineHash {
    <# The engine fingerprint of the extracted release (-SIRoot), by the release's own rule (engine\_shared\SI-GuardStrict.ps1),
       else the one this image carries. '' when it cannot be made. Never throws. #>
    param([Parameter(Mandatory)][string]$SIRoot)
    try {
        if (-not (Get-Command -Name Get-SIEngineFingerprint -ErrorAction SilentlyContinue)) {
            foreach ($root in @($SIRoot, '/si')) { $f = [IO.Path]::Combine($root, 'engine', '_shared', 'SI-GuardStrict.ps1'); if (Test-Path -LiteralPath $f) { . $f; break } }
        }
        if (Get-Command -Name Get-SIEngineFingerprint -ErrorAction SilentlyContinue) { return ([string](Get-SIEngineFingerprint -SIRoot $SIRoot)).Trim().ToLowerInvariant() }
    } catch { }
    ''
}

function Test-SIUpdaterImageOnlyScript {
    <# Does the release's update script (setup\Invoke-SIContainerUpdate.ps1 under -SIRoot) have the image-only mode? Never throws. #>
    param([Parameter(Mandatory)][string]$SIRoot)
    $f = [IO.Path]::Combine($SIRoot, 'setup', 'Invoke-SIContainerUpdate.ps1')
    if (-not (Test-Path -LiteralPath $f)) { return $false }
    try { return [bool]((Get-Command -Name $f -ErrorAction Stop).Parameters.ContainsKey('ImageOnly')) } catch { return $false }
}

function Get-SIUpdaterImageOnlyDecision {
    <#
        Is the verified, extracted release (-SIRoot, -Version) IMAGE-ONLY for this install (-Deployed: the release it runs,
        -Store: the Pro database with the recorded engine fingerprint)? Test-SIImageOnlyRelease over the three proofs and the
        script's mode. -RecordedHash / -ReleaseHash: test seams. Returns @{ ImageOnly; Why }. Never throws.
    #>
    param([Parameter(Mandatory)][string]$SIRoot, [AllowEmptyString()][string]$Version, [AllowEmptyString()][string]$Deployed, $Store,
          [AllowNull()][string]$RecordedHash, [AllowNull()][string]$ReleaseHash)
    try {
        if (-not (Get-Command -Name Test-SIImageOnlyRelease -ErrorAction SilentlyContinue)) {
            $lib = [IO.Path]::Combine($SIRoot, 'engine', '_shared', 'SI-ImageOnlyRelease.ps1')
            if (Test-Path -LiteralPath $lib) { . $lib } else { return [pscustomobject]@{ ImageOnly = $false; Why = 'this updater cannot tell an image-only release' } }
        }
        # the cheap rule first: a code release never reads the fingerprints
        $vt = Test-SIImageOnlyVersion -Version $Version -Running $Deployed
        if (-not $vt.Ok) { return [pscustomobject]@{ ImageOnly = $false; Why = $vt.Why } }
        $rec = if ($PSBoundParameters.ContainsKey('RecordedHash')) { "$RecordedHash" } else { Read-SIUpdaterRecordedEngineHash -Store $Store }
        $rel = if ($PSBoundParameters.ContainsKey('ReleaseHash')) { "$ReleaseHash" } else { Get-SIUpdaterReleaseEngineHash -SIRoot $SIRoot }
        Test-SIImageOnlyRelease -Version $Version -Running $Deployed -Marker (Get-SIImageOnlyMarker -SIRoot $SIRoot -Version $Version) `
            -RecordedEngineHash $rec -ReleaseEngineHash $rel -ScriptReady (Test-SIUpdaterImageOnlyScript -SIRoot $SIRoot)
    } catch { [pscustomobject]@{ ImageOnly = $false; Why = ('whether it is image-only could not be decided ({0})' -f $_.Exception.Message) } }
}

function Get-SIUpdaterImageOnlyEngineResult {
    <# PURE. What the release script's image-only run ended with: -Code (its exit code), -Stage ($global:SI_UpdateStage), -Failures
       ($global:SI_UpdateFailures), -Thrown (a throw). Returns @{ Ok; Result (done | build-failed | swap-failed); Step; Why }. #>
    param([int]$Code = 0, [AllowEmptyString()][string]$Stage = '', [object[]]$Failures = @(), [AllowEmptyString()][string]$Thrown = '')
    if ($Code -eq 0 -and -not "$Thrown".Trim()) { return [pscustomobject]@{ Ok = $true; Result = 'done'; Step = ''; Why = 'the engine jobs run the patched image' } }
    $recorded = @(@($Failures) | Where-Object { $_ -and "$($_.Step)" -in @('roll', 'restore') })
    $first = @(@($Failures) | Where-Object { $_ -and "$($_.Text)".Trim() })[0]
    $why = if ("$Thrown".Trim()) { "$Thrown".Trim() } elseif ($first) { "$($first.Text)".Trim() } else { ('the engine update ended with exit code {0}' -f $Code) }
    if ($recorded.Count -or "$Stage" -match '(?i)ROLL|VERIFY|ROLLBACK') { return [pscustomobject]@{ Ok = $false; Result = 'swap-failed'; Step = 'roll'; Why = $why } }
    [pscustomobject]@{ Ok = $false; Result = 'build-failed'; Step = 'build'; Why = $why }
}

function ConvertTo-SIUpdaterImageOnlyValue {
    <# PURE. The cfg.InstallState 'ImageOnlyUpdate' value (at most 400 characters): { version, from, result, component, why, atUtc }. #>
    param([Parameter(Mandatory)]$Result, [AllowEmptyString()][string]$Version = '', [AllowEmptyString()][string]$From = '', [datetime]$NowUtc = [datetime]::UtcNow)
    $at = $NowUtc.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ', [Globalization.CultureInfo]::InvariantCulture)
    foreach ($max in 200, 120, 60, 0) {
        $why = "$($Result.Why)".Trim(); if ($why.Length -gt $max) { $why = if ($max -le 3) { '' } else { $why.Substring(0, $max - 3) + '...' } }
        $j = [ordered]@{ version = "$Version"; from = "$From"; result = "$($Result.Result)"; component = "$($Result.Component)"; why = $why; atUtc = $at } | ConvertTo-Json -Compress
        if ($j.Length -le 400) { return $j }
    }
    $j
}

function Invoke-SIUpdaterImageOnly {
    <#
        THE SHORT PATH (the file header). -SIRoot: the extracted, verified release; -Version / -Commit: its version and commit;
        -Environment: what the pre-roll read (Get-SIUpdaterEnvironment: LoginServer, UpdaterId, UpdaterImage). -Seams (tests):
          EngineSwap { param($SIRoot) } -> @{ Code; Stage; Failures; Error }
          AppSwap    { param($SIRoot, $Tag) } -> @{ Code; Text }
          Record     { param($Version, $Commit) } -> $true / $false
          SelfSwap   { param($SIRoot, $Tag) } -> @{ Action; Reason }
        Returns @{ Code (0 = the update is installed; 1 = a part failed, the next run tries again); Result (done | build-failed |
        swap-failed); Component (where it stopped, '' = nowhere); Why; Parts (the parts in the order they ran); SelfAction }.
        Never throws.
    #>
    param([Parameter(Mandatory)][string]$SIRoot, [Parameter(Mandatory)][string]$Version, [string]$Commit = '', $Environment,
          [Parameter(Mandatory)][string]$ResourceGroup, [Parameter(Mandatory)][string]$AcrName, [Parameter(Mandatory)][string]$SubscriptionId,
          [string]$UpdaterJob = 'caj-si-updater', [string]$WebApp = 'ca-si-management', [string]$McpApp = 'ca-si-mcp', [switch]$SelfOff, [hashtable]$Seams = @{})
    $parts = New-Object System.Collections.Generic.List[string]
    # every failure of the short path reaches Invardia's uplink with its step (Start-SIUpdater.ps1; absent = not recorded)
    $fail = { param($step, $text) if (Get-Command -Name Add-SIUpdaterFailureIf -ErrorAction SilentlyContinue) { Add-SIUpdaterFailureIf $step $text } }
    $out = { param([int]$code, $res, $comp, $why, $self = '') [pscustomobject]@{ Code = $code; Result = $res; Component = $comp; Why = $why; Parts = $parts.ToArray(); SelfAction = $self } }
    try {
        $tag = if (Get-Command -Name New-SIUpdaterBuildTag -ErrorAction SilentlyContinue) { New-SIUpdaterBuildTag -Version $Version -Commit $Commit } else { 'v' + $Version }
        # 1. THE ENGINE JOBS: built and swapped by digest, nothing after the roll (the release's own script, -ImageOnly)
        $global:SI_UpdaterStep = 'build'
        $parts.Add('engine jobs')
        Write-UpdLog 'image-only update: the engine jobs -- the image is built in this install''s registry and each job is pointed at it by its digest; a running execution keeps its image'
        $eng = $null
        if ($Seams['EngineSwap']) { $eng = & $Seams.EngineSwap $SIRoot }
        else {
            $global:SI_UpdateStage = ''; $global:SI_UpdateFirstWarn = ''; $global:SI_UpdateFailures = $null; $global:LASTEXITCODE = 0
            $err = ''
            try { & (Join-Path $SIRoot 'setup/Invoke-SIContainerUpdate.ps1') -Apply -ImageOnly -ResourceGroupName $ResourceGroup -AcrName $AcrName -SubscriptionId $SubscriptionId | Out-Host }
            catch { $err = $_.Exception.Message }
            $eng = [pscustomobject]@{ Code = $(if ($LASTEXITCODE) { [int]$LASTEXITCODE } elseif ($err) { 1 } else { 0 }); Stage = [string]$global:SI_UpdateStage
                                      Failures = @(if ($global:SI_UpdateFailures) { @($global:SI_UpdateFailures) }); Error = $err }
        }
        $er = Get-SIUpdaterImageOnlyEngineResult -Code ([int]$eng.Code) -Stage ([string]$eng.Stage) -Failures @($eng.Failures) -Thrown ([string]$eng.Error)
        if (-not $er.Ok) {
            $why = 'the engine jobs: {0} -- every job runs the image it ran before; the next update run tries again' -f $er.Why
            & $fail $er.Step ('image-only update {0}: {1}' -f $Version, $why)
            return (& $out 1 $er.Result 'engine jobs' $why)
        }
        Write-UpdLog ('image-only update: {0}' -f $er.Why)
        # 2. THE WEB APP, ITS MCP SERVER AND THE SIGN-IN FRONT: a new revision each, images only
        $global:SI_UpdaterStep = 'post-roll'
        $parts.Add('web app')
        $login = if ($Environment -and "$($Environment.LoginServer)") { [string]$Environment.LoginServer } else { '' }
        $apps = if ($Seams['AppSwap']) { & $Seams.AppSwap $SIRoot $tag }
                elseif (-not $login) { [pscustomobject]@{ Code = 0; Text = 'no environment record -- the web app was not rolled' } }
                elseif (Get-Command -Name Invoke-SIUpdaterAppRoll -ErrorAction SilentlyContinue) {
                    $ar = @{ SIRoot = $SIRoot; ResourceGroup = $ResourceGroup; AcrName = $AcrName; SubscriptionId = $SubscriptionId; LoginServer = $login; Tag = $tag; WebApp = $WebApp; McpApp = $McpApp }
                    if ((Get-Command -Name Invoke-SIUpdaterAppRoll).Parameters.ContainsKey('ImagesOnly')) { $ar['ImagesOnly'] = $true }
                    Invoke-SIUpdaterAppRoll @ar
                } else { [pscustomobject]@{ Code = 0; Text = 'no web app in this edition' } }
        Write-UpdLog ('image-only update: web app: {0}' -f $apps.Text)
        if ([int]$apps.Code -ne 0) {
            $res = if ("$($apps.Text)" -match '(?i)image build failed|could not be built') { 'build-failed' } else { 'swap-failed' }
            $why = 'the web app / MCP server / sign-in front: {0} -- the engine jobs run the patched image; the updater keeps its image; the next update run tries again' -f $apps.Text
            & $fail 'post-roll' ('image-only update {0}: {1}' -f $Version, $why)
            return (& $out 1 $res 'web app' $why)
        }
        # 3. what now runs -- only now that the swap is whole (a part that failed is tried again by the next run)
        if ($Seams['Record']) { $null = & $Seams.Record $Version $Commit }
        elseif ($Environment -and (Get-Command -Name Save-SIUpdaterInstalledRecord -ErrorAction SilentlyContinue)) { $null = Save-SIUpdaterInstalledRecord -ResourceId $Environment.UpdaterId -Version $Version -Commit $Commit -SubscriptionId $SubscriptionId }
        # 4. THE UPDATER ITSELF, LAST
        $parts.Add('updater')
        $self = if ($Seams['SelfSwap']) { & $Seams.SelfSwap $SIRoot $tag }
                elseif ($Environment -and $login -and (Get-Command -Name Invoke-SIUpdaterSelfRoll -ErrorAction SilentlyContinue)) {
                    Invoke-SIUpdaterSelfRoll -SIRoot $SIRoot -ResourceGroup $ResourceGroup -AcrName $AcrName -SubscriptionId $SubscriptionId -LoginServer $login `
                        -Tag $tag -JobName $UpdaterJob -JobId $Environment.UpdaterId -CurrentImage $Environment.UpdaterImage -Disabled:$SelfOff
                } else { [pscustomobject]@{ Action = 'skipped'; Reason = 'no environment record -- the updater keeps its image' } }
        $sa = if ($self) { [string]$self.Action } else { '' }
        if ($sa -eq 'failed') {
            $why = 'the updater itself: {0}' -f $self.Reason
            & $fail 'post-roll' ('image-only update {0}: {1}' -f $Version, $why)
            return (& $out 0 'swap-failed' 'updater' $why $sa)
        }
        & $out 0 'done' '' ('every part runs the patched images of {0}: the engine jobs (by digest), the web app, the MCP server, the sign-in front and the updater (last)' -f $Version) $sa
    } catch {
        $why = 'the image-only update stopped: {0} -- the next update run tries again' -f $_.Exception.Message
        & $fail $(if ("$global:SI_UpdaterStep".Trim()) { "$global:SI_UpdaterStep" } else { 'roll' }) ('image-only update {0}: {1}' -f $Version, $why)
        & $out 1 'swap-failed' $(if ($parts.Count) { $parts[$parts.Count - 1] } else { 'engine jobs' }) $why
    }
}
