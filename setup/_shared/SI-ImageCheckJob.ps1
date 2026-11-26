#Requires -Version 5.1
<#
    SecurityInsight -- THE IMAGE CHECK JOB caj-si-image-check (SI #1344; owner IMAGE-30MIN-1 2026-11-24: "chg security agent to
    chk img every30 min" / "goal is to get img upd faster when security cve detected in img"; then, the same day: "lets chg so
    agent checks ever 15 min and solutions checks every 15 min"; framework SEC-LANE-1 G5: every 15 minutes, was 30, hourly
    before).

    Every 15 minutes ('*/15 * * * *' UTC) the install asks Invardia ONE question: does its ring have a newer IMAGE-ONLY
    (security) release than the release the install runs? Only that release is applied here -- at once, through the updater's
    own image-only path (container\updater\_shared\SI-UpdaterImageOnly.ps1). A code release is never applied by this job; it
    stays on the nightly update (caj-si-updater, 18:30 in the region's zone).

    THE JOB IS A SECOND SCHEDULE OF THE UPDATER, not a new program: the SAME image (si-updater), the SAME identity, registry
    pull identity and Key Vault references as caj-si-updater, the same environment -- plus SI_UPDATER_MODE = image-check and
    SI_UPDATER_JOB_NAME = the updater job (so every part the update names is the updater's). No new right is given: it can
    do exactly what the updater can, and in this mode does less. Its size is the floor (2 CPU / 4 GiB -- the images are
    built by the registry, not in the job); one replica, no retry; it runs at most 2 hours.

    KEPT PRESENT (new installs and existing ones alike, read back): setup\Install-SIUpdaterJob.ps1 makes it with the updater;
    the release's update script (setup\Invoke-SIContainerUpdate.ps1, step 9c) and every updater run
    (container\updater\Start-SIUpdater.ps1) keep it as it must be -- also its IMAGE, which follows the updater's, so the
    check always runs the code the updater runs. A job that already is what it must be is left alone.
    PURE except Invoke-SIImageCheckJobEnsure (its ARM calls go through -Arm). PS 5.1 and 7. No module.
#>

# #1413: only live identities are carried into the job (Read-SILiveIdentities / Select-SILiveIdentityKeys)
if (-not (Get-Command -Name Select-SILiveIdentityKeys -ErrorAction SilentlyContinue)) { $__siLiF = Join-Path $PSScriptRoot 'SI-LiveIdentities.ps1'; if (Test-Path -LiteralPath $__siLiF) { . $__siLiF } }

function Get-SIImageCheckJobNames {
    <# PURE. The job's fixed names and values (a function: a caller that dot-sources this file inside a function sees it). #>
    [ordered]@{
        Job       = 'caj-si-image-check'
        Container = 'image-check'
        Mode      = 'image-check'
        Cron      = '*/15 * * * *'      # every 15 minutes, UTC (framework SEC-LANE-1 G5; IMAGE-30MIN-1)
        TickMinutes = 15                # the timer's interval: the step-aside window after a nightly start is SHORTER than it (one tick at most)
        TagName   = 'si-component'
        TagValue  = 'image-check'
        SpecTag   = 'si-image-check-spec'
        AppApi    = '2025-07-01'
        RunLimit  = 7200                # seconds: an image-only swap (the registry builds + the swap) fits well inside
        Cpu       = 2.0
        Memory    = '4Gi'
    }
}

function Get-SIImageCheckProp {
    <# PURE. A nested property (PSCustomObject or dictionary); $null when any step is missing. #>
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

function Get-SIImageCheckKeys {
    <# PURE. The keys of a dictionary or the property names of an object; @() for $null. #>
    param($Object)
    if ($null -eq $Object) { return @() }
    if ($Object -is [System.Collections.IDictionary]) { return @($Object.Keys | ForEach-Object { [string]$_ }) }
    @($Object.PSObject.Properties | ForEach-Object { $_.Name })
}

function Get-SIImageCheckJobBody {
    <#
        PURE. caj-si-image-check as the updater job (-UpdaterJob, ARM GET shape) describes it: its location, environment,
        identity, registries, Key Vault-referenced secrets, image and environment variables -- the trigger a timer of
        -Cron, the size the floor, SI_UPDATER_MODE = image-check, SI_UPDATER_JOB_NAME = the updater job. A secret of the
        updater that is NOT a Key Vault reference cannot be copied (its value is never read here): the job is then not made,
        said why. Returns @{ Ok; Body; Image; Problem }.
    #>
    # -LiveIdentities (#1413): Read-SILiveIdentities (setup\_shared\SI-LiveIdentities.ps1) -- an identity of the resource group
    # that no longer exists is not carried; not given / not read = every identity, as before
    param($UpdaterJob, [string]$UpdaterName = 'caj-si-updater', $LiveIdentities = $null)
    $n = Get-SIImageCheckJobNames
    $no = { param($p) [pscustomobject]@{ Ok = $false; Body = $null; Image = ''; Problem = $p } }
    if (-not $UpdaterJob) { return (& $no ('the updater job {0} is not there' -f $UpdaterName)) }
    $c0 = @(Get-SIImageCheckProp $UpdaterJob @('properties', 'template', 'containers'))[0]
    $image = [string](Get-SIImageCheckProp $c0 @('image'))
    if (-not $image.Trim()) { return (& $no 'the updater job has no image') }
    $envId = [string](Get-SIImageCheckProp $UpdaterJob @('properties', 'environmentId'))
    if (-not $envId.Trim()) { $envId = [string](Get-SIImageCheckProp $UpdaterJob @('properties', 'managedEnvironmentId')) }
    if (-not $envId.Trim()) { return (& $no 'the updater job names no Container Apps environment') }
    $cfg = Get-SIImageCheckProp $UpdaterJob @('properties', 'configuration')
    # the secrets: Key Vault references only (name + keyVaultUrl + identity), exactly as the updater carries them
    $secrets = New-Object System.Collections.Generic.List[object]
    foreach ($s in @(Get-SIImageCheckProp $cfg @('secrets'))) {
        if (-not $s) { continue }
        $sn = [string](Get-SIImageCheckProp $s @('name')); $kv = [string](Get-SIImageCheckProp $s @('keyVaultUrl'))
        if (-not $sn) { continue }
        if (-not $kv.Trim()) { return (& $no ('the updater''s secret {0} is not a Key Vault reference -- its value is never copied; run setup\Install-SIUpdaterJob.ps1 once (it keeps the certificate in the Key Vault)' -f $sn)) }
        $secrets.Add([ordered]@{ name = $sn; keyVaultUrl = $kv; identity = [string](Get-SIImageCheckProp $s @('identity')) })
    }
    $registries = @(@(Get-SIImageCheckProp $cfg @('registries')) | Where-Object { $_ } | ForEach-Object {
        $r = [ordered]@{ server = [string](Get-SIImageCheckProp $_ @('server')) }
        $ri = [string](Get-SIImageCheckProp $_ @('identity')); if ($ri) { $r.identity = $ri }
        $rp = [string](Get-SIImageCheckProp $_ @('passwordSecretRef')); if ($rp) { $r.passwordSecretRef = $rp; $r.username = [string](Get-SIImageCheckProp $_ @('username')) }
        $r })
    # the environment: the updater's, without the mode and the job name (set below)
    $env = New-Object System.Collections.Generic.List[object]
    foreach ($e in @(Get-SIImageCheckProp $c0 @('env'))) {
        if (-not $e) { continue }
        $en = [string](Get-SIImageCheckProp $e @('name'))
        if (-not $en -or $en -in @('SI_UPDATER_MODE', 'SI_UPDATER_JOB_NAME')) { continue }
        $sr = [string](Get-SIImageCheckProp $e @('secretRef'))
        if ($sr) { $env.Add([ordered]@{ name = $en; secretRef = $sr }) } else { $env.Add([ordered]@{ name = $en; value = [string](Get-SIImageCheckProp $e @('value')) }) }
    }
    $env.Add([ordered]@{ name = 'SI_UPDATER_MODE'; value = $n.Mode })
    $env.Add([ordered]@{ name = 'SI_UPDATER_JOB_NAME'; value = $UpdaterName })
    $ident = Get-SIImageCheckProp $UpdaterJob @('identity')
    # #1413: only the updater's identities that still exist (a deleted one makes Azure refuse the whole PUT)
    $uaKeys = @(Get-SIImageCheckKeys (Get-SIImageCheckProp $ident @('userAssignedIdentities')))
    $idLines = @()
    if ($LiveIdentities -and (Get-Command -Name Select-SILiveIdentityKeys -ErrorAction SilentlyContinue)) {
        $sel = Select-SILiveIdentityKeys -Keys $uaKeys -Live $LiveIdentities -Name $n.Job
        $uaKeys = @($sel.Keep); $idLines = @($sel.Lines)
    }
    $tags = [ordered]@{ product = 'securityinsight' }; $tags[$n.TagName] = $n.TagValue
    $c = [ordered]@{
        triggerType = 'Schedule'; replicaTimeout = $n.RunLimit; replicaRetryLimit = 0
        scheduleTriggerConfig = [ordered]@{ cronExpression = $n.Cron; parallelism = 1; replicaCompletionCount = 1 }
    }
    if ($registries.Count) { $c.registries = $registries }
    if ($secrets.Count) { $c.secrets = $secrets.ToArray() }
    $body = [ordered]@{ location = [string](Get-SIImageCheckProp $UpdaterJob @('location')); tags = $tags }
    if ($ident -and [string](Get-SIImageCheckProp $ident @('type'))) {
        $ua = [ordered]@{}; foreach ($k in $uaKeys) { $ua[$k] = [ordered]@{} }
        $id = [ordered]@{ type = [string](Get-SIImageCheckProp $ident @('type')) }; if ($ua.Count) { $id.userAssignedIdentities = $ua }
        $body.identity = $id
    }
    $body.properties = [ordered]@{
        environmentId = $envId
        configuration = $c
        template = [ordered]@{ containers = @([ordered]@{ name = $n.Container; image = $image; resources = [ordered]@{ cpu = $n.Cpu; memory = $n.Memory }; env = $env.ToArray() }) }
    }
    $tags[$n.SpecTag] = Get-SIImageCheckJobFingerprint -Body $body
    [pscustomobject]@{ Ok = $true; Body = $body; Image = $image; Problem = ''; IdentityLines = [string[]]$idLines }
}

function Get-SIImageCheckJobFingerprint {
    <# PURE. What the job must be, as one short hash: its identities, environment, secrets, registries, timer, run limit and
       size -- NOT its image (it follows the updater's image; Test-SIImageCheckJobReadBack compares that on its own). #>
    param([Parameter(Mandatory)]$Body)
    $ids = @(Get-SIImageCheckKeys (Get-SIImageCheckProp $Body @('identity', 'userAssignedIdentities')) | ForEach-Object { $_.ToLowerInvariant() } | Sort-Object)
    $c0 = @(Get-SIImageCheckProp $Body @('properties', 'template', 'containers'))[0]
    $env = @(@(Get-SIImageCheckProp $c0 @('env')) | Where-Object { $_ } | ForEach-Object {
        $sr = [string](Get-SIImageCheckProp $_ @('secretRef'))
        '{0}={1}' -f [string](Get-SIImageCheckProp $_ @('name')), $(if ($sr) { 'secretref:' + $sr } else { [string](Get-SIImageCheckProp $_ @('value')) }) } | Sort-Object)
    $cfg = Get-SIImageCheckProp $Body @('properties', 'configuration')
    $sec = @(@(Get-SIImageCheckProp $cfg @('secrets')) | Where-Object { $_ } | ForEach-Object { '{0}>{1}' -f [string](Get-SIImageCheckProp $_ @('name')), [string](Get-SIImageCheckProp $_ @('keyVaultUrl')) } | Sort-Object)
    $reg = @(@(Get-SIImageCheckProp $cfg @('registries')) | Where-Object { $_ } | ForEach-Object { '{0}>{1}' -f [string](Get-SIImageCheckProp $_ @('server')), ([string](Get-SIImageCheckProp $_ @('identity'))).ToLowerInvariant() } | Sort-Object)
    $txt = 'ids:{0}|env:{1}|sec:{2}|reg:{3}|cron:{4}|limit:{5}|cpu:{6}|mem:{7}|type:{8}' -f ($ids -join ','), ($env -join ';'), ($sec -join ','), ($reg -join ','),
           [string](Get-SIImageCheckProp $cfg @('scheduleTriggerConfig', 'cronExpression')), [string](Get-SIImageCheckProp $cfg @('replicaTimeout')),
           [string](Get-SIImageCheckProp $c0 @('resources', 'cpu')), [string](Get-SIImageCheckProp $c0 @('resources', 'memory')), [string](Get-SIImageCheckProp $Body @('identity', 'type'))
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try { (($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($txt)) | Select-Object -First 8 | ForEach-Object { $_.ToString('x2') }) -join '') } finally { $sha.Dispose() }
}

function Test-SIImageCheckJobReadBack {
    <# PURE. Is the job as ARM returns it the one -Body describes -- made, its spec, its timer, its mode and its image? @{ Ok; Problem }. #>
    param($Job, [Parameter(Mandatory)]$Body)
    $n = Get-SIImageCheckJobNames
    if (-not $Job) { return [pscustomobject]@{ Ok = $false; Problem = 'it is not there' } }
    $ps = [string](Get-SIImageCheckProp $Job @('properties', 'provisioningState'))
    if ($ps -and $ps -ne 'Succeeded') { return [pscustomobject]@{ Ok = $false; Problem = ('Azure shows {0}' -f $ps) } }
    if ([string](Get-SIImageCheckProp $Job @('tags', $n.SpecTag)) -ne [string](Get-SIImageCheckProp $Body @('tags', $n.SpecTag))) { return [pscustomobject]@{ Ok = $false; Problem = 'its settings are not the ones written' } }
    $cfg = Get-SIImageCheckProp $Job @('properties', 'configuration')
    if ([string](Get-SIImageCheckProp $cfg @('triggerType')) -ne 'Schedule' -or (([string](Get-SIImageCheckProp $cfg @('scheduleTriggerConfig', 'cronExpression'))).Trim() -replace '\s+', ' ') -ne $n.Cron) { return [pscustomobject]@{ Ok = $false; Problem = ('its timer is not ''{0}''' -f $n.Cron) } }
    $c0 = @(Get-SIImageCheckProp $Job @('properties', 'template', 'containers'))[0]
    if (-not @(@(Get-SIImageCheckProp $c0 @('env')) | Where-Object { $_ -and [string](Get-SIImageCheckProp $_ @('name')) -eq 'SI_UPDATER_MODE' -and [string](Get-SIImageCheckProp $_ @('value')) -eq $n.Mode }).Count) { return [pscustomobject]@{ Ok = $false; Problem = ('it does not carry SI_UPDATER_MODE = {0}' -f $n.Mode) } }
    $want = [string](@(Get-SIImageCheckProp $Body @('properties', 'template', 'containers'))[0].image)
    if ([string](Get-SIImageCheckProp $c0 @('image')) -ne $want) { return [pscustomobject]@{ Ok = $false; Problem = ('it does not run the updater''s image {0}' -f $want) } }
    [pscustomobject]@{ Ok = $true; Problem = '' }
}

function Invoke-SIImageCheckJobEnsure {
    <#
        KEEPS caj-si-image-check PRESENT (the file header): the updater job read, the job's body made from it, the job read;
        what it must be already = left alone ('kept', nothing said by a caller that is quiet about it); otherwise ONE PUT,
        then READ BACK until Azure has made it. -WhatIf: the plan only. Never throws; nothing here holds an update.
        -Arm { param([string]$Method, [string]$Path, $Body) } -- GET answers $null for not found; the path carries no
        api-version (the caller adds Get-SIImageCheckJobNames AppApi). -Sleep / -Polls: test seams.
        Returns @{ Ok; Action = kept | made | updated | plan | not-ready | failed; Reason; Cron }.
    #>
    param([Parameter(Mandatory)][scriptblock]$Arm, [Parameter(Mandatory)][string]$SubscriptionId, [Parameter(Mandatory)][string]$ResourceGroup,
          [string]$UpdaterJob = 'caj-si-updater', [switch]$WhatIf, [scriptblock]$Sleep = { param($s) Start-Sleep -Seconds $s }, [int]$Polls = 30,
          # #1413: the SI REST seam -- the resource group's identities are read once and a deleted one is not carried into the job
          [scriptblock]$Rest)
    $n = Get-SIImageCheckJobNames
    $res = { param($ok, $a, $why) [pscustomobject]@{ Ok = $ok; Action = $a; Reason = $why; Cron = $n.Cron } }
    try {
        $base = '/subscriptions/{0}/resourceGroups/{1}/providers/Microsoft.App/jobs' -f $SubscriptionId, $ResourceGroup
        $upd = & $Arm 'GET' ('{0}/{1}' -f $base, $UpdaterJob) $null
        $live = $null
        if ($Rest -and (Get-Command -Name Read-SILiveIdentities -ErrorAction SilentlyContinue)) { $live = Read-SILiveIdentities -Rest $Rest -SubscriptionId $SubscriptionId -ResourceGroup $ResourceGroup }
        $plan = Get-SIImageCheckJobBody -UpdaterJob $upd -UpdaterName $UpdaterJob -LiveIdentities $live
        if (-not $plan.Ok) { return (& $res $true 'not-ready' ('the image check job {0}: {1} -- checked again at the next update' -f $n.Job, $plan.Problem)) }
        $path = '{0}/{1}' -f $base, $n.Job
        $cur = & $Arm 'GET' $path $null
        if ($cur -and (Test-SIImageCheckJobReadBack -Job $cur -Body $plan.Body).Ok) { return (& $res $true 'kept' ('the image check job {0} is there as it must be (every 15 minutes, ''{1}'' UTC; read back)' -f $n.Job, $n.Cron)) }
        if ($WhatIf) { return (& $res $true 'plan' ('the image check job {0} would be {1}: every 15 minutes (''{2}'' UTC), the updater''s image, identity and settings, image-only releases of its ring only (re-run with -Apply)' -f $n.Job, $(if ($cur) { 'brought up to date' } else { 'made' }), $n.Cron)) }
        $null = & $Arm 'PUT' $path $plan.Body
        $rb = $null
        for ($i = 0; $i -lt [Math]::Max(1, $Polls); $i++) {
            $job = & $Arm 'GET' $path $null
            $rb = Test-SIImageCheckJobReadBack -Job $job -Body $plan.Body
            $ps = [string](Get-SIImageCheckProp $job @('properties', 'provisioningState'))
            if ($rb.Ok -or $ps -in 'Failed', 'Canceled') { break }
            & $Sleep 10
        }
        if (-not $rb.Ok) { return (& $res $false 'failed' ('WARNING: the image check job {0} did not read back right ({1}) -- the next update tries again; the nightly update still installs every release{2}' -f $n.Job, $rb.Problem, $(if (@($plan.IdentityLines).Count) { '; ' + (@($plan.IdentityLines) -join '; ') } else { '' }))) }
        & $res $true $(if ($cur) { 'updated' } else { 'made' }) ('the image check job {0} was {1} and read back: every 15 minutes (''{2}'' UTC) it asks Invardia for a newer image-only (security) release of its ring and installs only that, at once; it runs as the updater''s identity on the updater''s image{3}' -f $n.Job, $(if ($cur) { 'brought up to date' } else { 'made' }), $n.Cron, $(if (@($plan.IdentityLines).Count) { '; ' + (@($plan.IdentityLines) -join '; ') } else { '' }))
    } catch {
        & $res $false 'failed' ('WARNING: the image check job could not be kept present ({0}) -- the next update tries again' -f $_.Exception.Message)
    }
}
