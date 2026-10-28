#Requires -Version 5.1
<#
    SecurityInsight -- THE FAST ROLL (#416, operator 2026-10-06: "release must comedown to 10 min", "we solved the updater
    yesterday by the changes you made like paralle", "where did those learning go"). The learnings of the machine-local
    fast deploy (2026-10-05), now in the product, used by every install that builds its own images (operator, same day:
    "i dont ike that we deiver a image out" -- every install keeps building its images in its OWN registry from the signed
    source package; nothing prebuilt is delivered):

      (a) TWO-LAYER IMAGES. A Dockerfile whose expensive lines come before the first COPY (the updater image: apt) is
          split: <repo>-base:<hash> = the same FROM (pinned to its current digest) + those lines, built ONLY when that hash
          is not in the registry; the per-release image = FROM that base + the COPY lines -- the thin code layer. The hash
          covers the FROM digest, the base instructions, the newest gallery version of any -MinimumVersion module, and --
          when the base RUNs anything (apt) -- the ISO week, so OS patches still arrive weekly. A Dockerfile whose first
          instruction after FROM is a COPY has no base: it is built as it is.
      (b) THE JOBS SWAP IN PARALLEL. Every job gets the new image by ONE ARM PATCH of properties.template only -- never a PUT
          (ARM returns secrets without values; a PUT would drop them, see ConvertTo-SIArmJobTrigger in SI-JobFlow.ps1),
          never one job update after another (~40 s each, 16 jobs = 11 min, measured). All PATCHes go out back to back
          (ARM answers at once and provisions asynchronously), then ONE job list per poll reads every job back; each job is
          verified: the image, and that NOTHING else changed (trigger, schedule, secrets, env, resources, identity,
          registries, tags, volumes).
      (c) THE WEB APP AND MCP SERVER ARE BUILT ONLY WHEN THEIR SOURCES CHANGED. Their image tag is a hash of exactly what
          their Dockerfile copies (BUILD.json left out), so an app that already runs that tag is left alone. Every build of
          a release is QUEUED together and waited for together.

    #521 NO az CLI: every call is ARM / registry REST through ONE seam, -Rest { param([string]$Method, [string]$Uri, $Body,
    [string]$Resource, [hashtable]$Headers) } -> @{ Status; Body } (setup/_shared/SI-UpdateRest.ps1). An image build is the
    registry's own build over ARM (setup/_shared/SI-AcrBuild.ps1, ported from PIM4EntraPS). A caller that passes no -Rest
    gets SecurityInsight's own sign-in (Get-SIUpdateRestSeam). An updater image from before #521 still passes -Az to the
    build functions: it is accepted and IGNORED (the release builds over REST itself), so that image can still roll this
    release and, last, itself onto an image without the Azure CLI. The decisions are tested offline against a fake REST.
    PowerShell 5.1-compatible: the VM sync hook runs Invoke-SIContainerUpdate.ps1 on Windows PowerShell; the updater
    container runs pwsh 7.
#>

if (-not (Get-Command -Name Invoke-SIAcrQueueBuild -ErrorAction SilentlyContinue)) { . ([IO.Path]::Combine($PSScriptRoot, 'SI-AcrBuild.ps1')) }

# ONE api-version for the read AND the PATCH (live 2026-10-06, ring 1, first fast roll: all 16 PATCHes at 2024-03-01 were
# refused 400 "Unknown properties imageType in ContainerAppContainer are not supported" -- the template had been read by
# the CLI's job list, which read with its own newer api-version (2025-07-01 on azure-cli 2.85) and returned imageType; the
# round trip sent it back to an api-version that does not know it). The roll reads the jobs itself with this api-version,
# so a template always goes back in the schema it came out in.
$script:SIFastRollArmApi = '2025-07-01'

function Get-SISha256Hex {
    <# PURE. SHA-256 of a UTF-8 string, lower-case hex (5.1: no [Convert]::ToHexString / SHA256.HashData). #>
    param([AllowEmptyString()][string]$Text)
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try { $b = $sha.ComputeHash([System.Text.Encoding]::UTF8.GetBytes([string]$Text)) } finally { $sha.Dispose() }
    ([BitConverter]::ToString($b) -replace '-', '').ToLowerInvariant()
}

function Split-SIDockerfile {
    <#
        PURE. A single-stage Dockerfile's text -> @{ From; Base (instructions before the first COPY/ADD); App (the rest) }.
        Anything the split cannot map safely (a parser directive, several FROM lines, FROM with options, COPY --from, an
        instruction before the first COPY that is not RUN/ENV/ARG/SHELL/LABEL/USER/WORKDIR) THROWS -- the caller then builds
        the Dockerfile as it is, never a guessed split.
    #>
    param([Parameter(Mandatory)][AllowEmptyString()][string]$Text)
    $instr = New-Object System.Collections.Generic.List[object]
    $buf = New-Object System.Collections.Generic.List[string]
    $n = 0
    foreach ($l in ($Text -split "`r?`n")) {
        $n++
        if ($n -le 3 -and $buf.Count -eq 0 -and $instr.Count -eq 0 -and $l -match '^\s*#\s*(syntax|escape|check)\s*=') { throw ("parser directive '{0}' -- not split" -f $l.Trim()) }
        if ($l.Trim() -eq '' -or $l.TrimStart().StartsWith('#')) { continue }
        $buf.Add($l.TrimEnd())
        if ($l.TrimEnd().EndsWith('\')) { continue }
        $t = $buf -join "`n"; $buf.Clear()
        $instr.Add([pscustomobject]@{ Keyword = ($t.TrimStart() -split '\s+', 2)[0].ToUpperInvariant(); Text = $t })
    }
    if ($buf.Count) { throw 'the file ends inside a continued instruction' }
    if (-not $instr.Count -or $instr[0].Keyword -ne 'FROM') { throw 'the first instruction is not FROM' }
    if (@($instr | Where-Object { $_.Keyword -eq 'FROM' }).Count -ne 1) { throw 'several FROM lines (multi-stage) -- not split' }
    $fromParts = @($instr[0].Text.Trim() -split '\s+')
    if ($fromParts.Count -ne 2) { throw ("FROM with options or an alias ('{0}') -- not split" -f $instr[0].Text.Trim()) }
    $first = -1
    for ($i = 1; $i -lt $instr.Count; $i++) { if ($instr[$i].Keyword -in 'COPY', 'ADD') { $first = $i; break } }
    if ($first -lt 0) { throw 'no COPY -- nothing to split' }
    # 1..0 counts DOWN in PowerShell: a COPY right after FROM is an EMPTY base
    $base = if ($first -gt 1) { @($instr[1..($first - 1)]) } else { @() }
    $app = @($instr[$first..($instr.Count - 1)])
    foreach ($x in $base) { if ($x.Keyword -notin 'RUN', 'ENV', 'ARG', 'SHELL', 'LABEL', 'USER', 'WORKDIR') { throw ("'{0}' before the first COPY -- not split" -f $x.Keyword) } }
    foreach ($x in $app) { if ($x.Keyword -eq 'COPY' -and $x.Text -match '--from') { throw 'COPY --from -- not split' } }
    [pscustomobject]@{ From = $fromParts[1]; Base = $base; App = $app }
}

function Get-SIRegistryImageDigest {
    <# The registry's current manifest digest of <registry>/<repo>:<tag> (anonymous HEAD -- mcr.microsoft.com); '' when it cannot be read. Never throws. #>
    param([Parameter(Mandatory)][string]$Ref, [int]$TimeoutSec = 20)
    if ($Ref -notmatch '^(?<reg>[^/]+\.[^/]+)/(?<repo>[^:@]+):(?<tag>[^@]+)$') { return '' }
    try {
        $r = Invoke-WebRequest -Method Head -UseBasicParsing -TimeoutSec $TimeoutSec -Uri ('https://{0}/v2/{1}/manifests/{2}' -f $Matches.reg, $Matches.repo, $Matches.tag) `
            -Headers @{ Accept = 'application/vnd.docker.distribution.manifest.list.v2+json, application/vnd.oci.image.index.v1+json, application/vnd.docker.distribution.manifest.v2+json, application/vnd.oci.image.manifest.v1+json' }
        $d = $r.Headers['Docker-Content-Digest']
        if ($d -is [array]) { $d = $d[0] }
        "$d".Trim()
    } catch { '' }
}

function Get-SIIsoWeek {
    <# PURE. 'yyyy-Www' of a date (ISO 8601 week) -- the weekly refresh of a base that installs OS packages. #>
    param([datetime]$Date = [datetime]::UtcNow)
    $cal = [Globalization.CultureInfo]::InvariantCulture.Calendar
    $d = $Date.Date
    # ISO: the week of the Thursday of this week
    $dow = [int]$d.DayOfWeek; if ($dow -eq 0) { $dow = 7 }
    $thu = $d.AddDays(4 - $dow)
    '{0}-W{1:00}' -f $thu.Year, $cal.GetWeekOfYear($thu, [Globalization.CalendarWeekRule]::FirstFourDayWeek, [DayOfWeek]::Monday)
}

function New-SIImageLayerPlan {
    <#
        PURE. The two-layer plan of one Dockerfile's text. -FromDigest: the FROM image's current digest ('' = unknown: the
        hash covers the tag only). -Floating: 'Module=version' strings (the newest gallery version of every -MinimumVersion
        module). -Week: Get-SIIsoWeek (part of the hash only when the base RUNs something).
        Returns @{ HasBase; BaseRepo; BaseTag; BaseImage (repo:tag); BaseDockerfile; AppDockerfile (FROM <login>/<base>);
        Reason }. HasBase = $false -> build the original Dockerfile as it is (no base lines, or the split refused).
    #>
    param([Parameter(Mandatory)][string]$DockerfileText, [Parameter(Mandatory)][string]$BaseRepo, [Parameter(Mandatory)][string]$LoginServer,
          [AllowEmptyString()][string]$FromDigest = '', [string[]]$Floating = @(), [string]$Week = '')
    $none = { param($why) [pscustomobject]@{ HasBase = $false; BaseRepo = $BaseRepo; BaseTag = ''; BaseImage = ''; BaseDockerfile = ''; AppDockerfile = ''; Reason = $why } }
    try { $s = Split-SIDockerfile -Text $DockerfileText } catch { return (& $none ("built as it is: {0}" -f $_.Exception.Message)) }
    if (-not @($s.Base).Count) { return (& $none 'built as it is: no instruction before the first COPY (nothing to cache)') }
    $baseText = (@($s.Base | ForEach-Object { $_.Text }) -join "`n")
    $runs = [bool](@($s.Base | Where-Object { $_.Keyword -eq 'RUN' }).Count)
    $hashIn = "FROM $($s.From)@$FromDigest`n$baseText`n" + (@($Floating) -join "`n") + $(if ($runs -and $Week) { "`nweek=$Week" } else { '' })
    $tag = (Get-SISha256Hex -Text $hashIn).Substring(0, 16)
    $from = if ($FromDigest) { 'FROM {0}@{1}' -f $s.From, $FromDigest } else { 'FROM {0}' -f $s.From }
    $hdr = '# GENERATED from the release''s Dockerfile by setup/_shared/SI-FastRoll.ps1 -- do not edit'
    [pscustomobject]@{
        HasBase = $true; BaseRepo = $BaseRepo; BaseTag = $tag; BaseImage = ('{0}:{1}' -f $BaseRepo, $tag)
        BaseDockerfile = ((@($hdr, $from) + @($s.Base | ForEach-Object { $_.Text })) -join "`n") + "`n"
        AppDockerfile  = ((@($hdr, ('FROM {0}/{1}:{2}' -f $LoginServer, $BaseRepo, $tag)) + @($s.App | ForEach-Object { $_.Text })) -join "`n") + "`n"
        Reason = ('base {0}:{1} (FROM {2}{3})' -f $BaseRepo, $tag, $s.From, $(if ($FromDigest) { '@' + $FromDigest.Substring(0, [Math]::Min(19, $FromDigest.Length)) } else { ', digest unknown' }))
    }
}

function Get-SIImageLayerPlan {
    <# New-SIImageLayerPlan for a Dockerfile on disk, with the FROM digest and the floating module versions read live. Never throws. #>
    param([Parameter(Mandatory)][string]$DockerfilePath, [Parameter(Mandatory)][string]$BaseRepo, [Parameter(Mandatory)][string]$LoginServer)
    $text = [IO.File]::ReadAllText($DockerfilePath)
    $digest = ''; $floating = @()
    try {
        $s = Split-SIDockerfile -Text $text
        if (@($s.Base).Count) {
            $digest = Get-SIRegistryImageDigest -Ref $s.From
            $bt = (@($s.Base | ForEach-Object { $_.Text }) -join "`n")
            foreach ($m in [regex]::Matches($bt, '-Name\s+(?<n>[A-Za-z0-9_.-]+)\s+-MinimumVersion\s+(?<v>[0-9.]+)')) {
                $latest = ''
                try { $latest = [string]@(Invoke-RestMethod -TimeoutSec 20 -Uri ("https://www.powershellgallery.com/api/v2/FindPackagesById()?id='{0}'&`$filter=IsLatestVersion" -f $m.Groups['n'].Value))[0].properties.Version } catch { }
                $floating += ('{0}={1}' -f $m.Groups['n'].Value, $latest)
            }
        }
    } catch { }
    New-SIImageLayerPlan -DockerfileText $text -BaseRepo $BaseRepo -LoginServer $LoginServer -FromDigest $digest -Floating $floating -Week (Get-SIIsoWeek)
}

# ---- (c) a tag per SOURCE, so an image whose sources did not change is never rebuilt (the Pro web app / MCP server:
#      container/updater/_shared/SI-UpdaterWebApp.ps1 names their sources) -------------------------------------------------
function Get-SISourceHash {
    <#
        A stable hash of the files under -Paths (relative to -Root): relative path + SHA-256 per file, sorted ordinally.
        Left out: bin/ obj/ (local builds), customer files (*.custom.*), BUILD.json. '' when none of the paths exists.
    #>
    param([Parameter(Mandatory)][string]$Root, [Parameter(Mandatory)][string[]]$Paths)
    $rootFull = [IO.Path]::GetFullPath($Root).TrimEnd('\', '/')
    $lines = New-Object System.Collections.Generic.List[string]
    foreach ($p in $Paths) {
        $full = [IO.Path]::Combine($rootFull, ($p -replace '/', [IO.Path]::DirectorySeparatorChar))
        $files = if (Test-Path -LiteralPath $full -PathType Leaf) { @(Get-Item -LiteralPath $full) }
                 elseif (Test-Path -LiteralPath $full -PathType Container) { @(Get-ChildItem -LiteralPath $full -Recurse -File -Force -ErrorAction SilentlyContinue) }
                 else { @() }
        foreach ($f in $files) {
            $rel = $f.FullName.Substring($rootFull.Length).TrimStart('\', '/') -replace '\\', '/'
            if ($rel -match '(?i)(^|/)(bin|obj)/' -or ((Split-Path -Leaf $rel) -like '*.custom.*' -and (Split-Path -Leaf $rel) -notlike '*.custom.sample.*') -or (Split-Path -Leaf $rel) -eq 'BUILD.json') { continue }
            $lines.Add(('{0}|{1}' -f $rel, (Get-FileHash -LiteralPath $f.FullName -Algorithm SHA256).Hash))
        }
    }
    if (-not $lines.Count) { return '' }
    $arr = @($lines | Sort-Object -Unique); [Array]::Sort($arr, [StringComparer]::Ordinal)
    Get-SISha256Hex -Text ($arr -join "`n")
}

# ---- builds: queued together, waited for together (the registry's own build over ARM, setup/_shared/SI-AcrBuild.ps1) -----
$script:SIAcrDone = @('Succeeded', 'Failed', 'Canceled', 'Cancelled', 'Error', 'Timeout')

function Resolve-SIFastRollRest {
    <# The seam a build / roll function uses: the caller's -Rest, else SecurityInsight's own sign-in (Get-SIUpdateRestSeam). #>
    param([scriptblock]$Rest, [string]$SubscriptionId)
    if ($Rest) { return $Rest }
    Get-SIUpdateRestSeam -SubscriptionId $SubscriptionId
}

function Start-SIAcrBuild {
    <#
        Queues ONE image build in the registry from the CURRENT directory as the context (packed, .dockerignore applied,
        uploaded, scheduled -- Invoke-SIAcrQueueBuild) and returns @{ Image; RunId; File; Started; Status = Queued; LogTail }.
        -File may lie outside the context (a derived Dockerfile in a temp folder): it travels in the archive. The run id
        comes from the registry's answer, else from the newest run that names the image. Throws when the build cannot be
        queued. -Az: accepted from an updater image made before #521, and ignored.
    #>
    param([scriptblock]$Rest, [scriptblock]$Az, [Parameter(Mandatory)][string]$AcrName, [Parameter(Mandatory)][string]$Image, [Parameter(Mandatory)][string]$File,
          [string]$SubscriptionId, [string]$ResourceGroup)
    if (-not $SubscriptionId) { $SubscriptionId = Get-SIUpdateRestSubscription }
    $Rest = Resolve-SIFastRollRest -Rest $Rest -SubscriptionId $SubscriptionId
    $q = Invoke-SIAcrQueueBuild -Rest $Rest -SubscriptionId $SubscriptionId -AcrName $AcrName -ResourceGroup $ResourceGroup -ContextPath ((Get-Location).ProviderPath) -Image $Image -DockerfilePath $File
    $runId = [string]$q.RunId
    if (-not $runId) { $runId = Find-SIAcrRunId -Rest $Rest -Registry $q.Registry -Image $Image }
    [pscustomobject]@{ Image = $Image; RunId = $runId; File = $File; Started = [datetime]::UtcNow; Status = 'Queued'; LogTail = @() }
}

function Wait-SIAcrBuilds {
    <#
        Waits for every queued build (-Builds from Start-SIAcrBuild) together: GET runs/<id> per build per poll ('Queued',
        'Started', 'Running' = still going). Returns the builds with Status set. A build that ends in anything but Succeeded
        gets its log's tail (LogTail), and -Log prints it. Never throws -- the caller decides per image. -Az: ignored (see
        Start-SIAcrBuild).
    #>
    param([scriptblock]$Rest, [scriptblock]$Az, [Parameter(Mandatory)][string]$AcrName, [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Builds,
          [int]$TimeoutMinutes = 30, [int]$PollSeconds = 15, [scriptblock]$Log, [string]$SubscriptionId, [string]$ResourceGroup)
    if (-not $SubscriptionId) { $SubscriptionId = Get-SIUpdateRestSubscription }
    $reg = $null
    try { $Rest = Resolve-SIFastRollRest -Rest $Rest -SubscriptionId $SubscriptionId; $reg = Get-SIAcrRegistry -Rest $Rest -SubscriptionId $SubscriptionId -AcrName $AcrName -ResourceGroup $ResourceGroup }
    catch { if ($Log) { & $Log ("the registry {0} could not be read ({1}) -- the builds are not known" -f $AcrName, $_.Exception.Message) }; foreach ($b in @($Builds | Where-Object { $_.Status -notin $script:SIAcrDone })) { $b.Status = 'Error' }; return $Builds }
    $deadline = [datetime]::UtcNow.AddMinutes($TimeoutMinutes)
    while ($true) {
        foreach ($b in @($Builds | Where-Object { $_.Status -notin $script:SIAcrDone })) {
            if (-not $b.RunId) {
                $b.RunId = Find-SIAcrRunId -Rest $Rest -Registry $reg -Image $b.Image
                if (-not $b.RunId) { continue }
            }
            $s = Get-SIAcrRunStatus -Rest $Rest -Registry $reg -RunId $b.RunId
            if ($s) { $b.Status = $s }
            if ($b.Status -in $script:SIAcrDone) {
                if ($Log) { & $Log ("build {0}: {1} after {2:N0}s" -f $b.Image, $b.Status, ([datetime]::UtcNow - $b.Started).TotalSeconds) }
                if ($b.Status -ne 'Succeeded') {
                    $tail = @(Get-SIAcrRunLogTail -Rest $Rest -Registry $reg -RunId $b.RunId)
                    Add-Member -InputObject $b -NotePropertyName LogTail -NotePropertyValue $tail -Force
                    if ($Log -and $tail.Count) { & $Log ("the build log of {0} (run {1}) ends:" -f $b.Image, $b.RunId); foreach ($l in $tail) { & $Log ('  | ' + $l) } }
                }
            }
        }
        if (-not @($Builds | Where-Object { $_.Status -notin $script:SIAcrDone }).Count) { break }
        if ([datetime]::UtcNow -ge $deadline) {
            foreach ($b in @($Builds | Where-Object { $_.Status -notin $script:SIAcrDone })) { $b.Status = 'Timeout' }
            break
        }
        if ($PollSeconds -gt 0) { Start-Sleep -Seconds $PollSeconds }
    }
    $Builds
}

function Test-SIAcrTag {
    <#
        Is repo:tag in the registry? The registry's own data plane (Test-SIAcrManifest: HEAD of the manifest with a pull
        token). Never throws ($false on any error -- the image is then built). -Az: ignored (see Start-SIAcrBuild).
    #>
    param([scriptblock]$Rest, [scriptblock]$Az, [Parameter(Mandatory)][string]$AcrName, [Parameter(Mandatory)][string]$Repo, [Parameter(Mandatory)][string]$Tag,
          [string]$SubscriptionId, [string]$ResourceGroup, [string]$LoginServer, [scriptblock]$Token)
    try {
        if (-not $SubscriptionId) { $SubscriptionId = Get-SIUpdateRestSubscription }
        $Rest = Resolve-SIFastRollRest -Rest $Rest -SubscriptionId $SubscriptionId
        if (-not $LoginServer) { $LoginServer = (Get-SIAcrRegistry -Rest $Rest -SubscriptionId $SubscriptionId -AcrName $AcrName -ResourceGroup $ResourceGroup).LoginServer }
        [bool](Test-SIAcrManifest -Rest $Rest -LoginServer $LoginServer -Repo $Repo -Tag $Tag -Token $Token)
    } catch { $false }
}

# ---- (b) the jobs: one ARM PATCH of properties.template each, all at once, verified ---------------------------------
function Get-SIJobFingerprint {
    <# PURE. What an image swap must NOT change on a Container Apps job (ARM shape), as comparable strings. #>
    param([Parameter(Mandatory)]$Job)
    $c = $Job.properties.configuration; $t = $Job.properties.template
    $tags = @(); if ($Job.tags) { $tags = @($Job.tags.PSObject.Properties | Sort-Object Name | ForEach-Object { '{0}={1}' -f $_.Name, $_.Value }) }
    $js = { param($o) if ($null -eq $o) { '' } else { ConvertTo-Json -InputObject $o -Depth 20 -Compress } }
    [ordered]@{
        Trigger    = [string]$c.triggerType
        Schedule   = (& $js $c.scheduleTriggerConfig)
        Manual     = (& $js $c.manualTriggerConfig)
        Event      = (& $js $c.eventTriggerConfig)
        Timeout    = [string]$c.replicaTimeout
        Retry      = [string]$c.replicaRetryLimit
        Secrets    = (@(@($c.secrets) | Where-Object { $_ } | ForEach-Object { '{0}|{1}|{2}' -f $_.name, $_.keyVaultUrl, $_.identity }) | Sort-Object) -join ';'
        Registries = (& $js $c.registries)
        Identity   = $(if ($Job.identity -and $Job.identity.userAssignedIdentities) { (@($Job.identity.userAssignedIdentities.PSObject.Properties | ForEach-Object { $_.Name }) | Sort-Object) -join ';' } else { '' })
        Tags       = ($tags -join ';')
        Env        = (@(@($t.containers) | Where-Object { $_ } | ForEach-Object { $cn = $_.name; @(@($_.env) | Where-Object { $_ } | ForEach-Object { '{0}/{1}={2}{3}' -f $cn, $_.name, $_.value, $(if ($_.secretRef) { ' secretref:' + $_.secretRef } else { '' }) }) }) | Sort-Object) -join "`n"
        Command    = (@(@($t.containers) | Where-Object { $_ } | ForEach-Object { '{0}: {1} | {2}' -f $_.name, (@($_.command) -join ' '), (@($_.args) -join ' ') })) -join ';'
        Resources  = (@(@($t.containers) | Where-Object { $_ } | ForEach-Object { '{0}: {1}/{2}' -f $_.name, $_.resources.cpu, $_.resources.memory })) -join ';'
        Volumes    = (& $js $t.volumes)
        Init       = (@(@($t.initContainers) | Where-Object { $_ } | ForEach-Object { '{0}={1}' -f $_.name, $_.image })) -join ';'
    }
}

function Compare-SIJobFingerprint {
    <# PURE. The names of the fingerprint parts that differ (empty = nothing but the image changed). #>
    param([Parameter(Mandatory)]$Before, [Parameter(Mandatory)]$After)
    @($Before.Keys | Where-Object { [string]$Before[$_] -cne [string]$After[$_] })
}

function New-SIJobImagePatchBody {
    <#
        PURE. The ARM PATCH body that swaps a job's image: { properties: { template } } -- the job's OWN template (as read),
        with the image of every container that runs -RepoPrefix (e.g. <login>/si-orchestrator:) set to -Image. NEVER the
        configuration (secrets come back from ARM without values; sending them would drop them). Read-only fields removed.
        Returns the JSON text.
    #>
    param([Parameter(Mandatory)]$Job, [Parameter(Mandatory)][string]$Image, [string]$RepoPrefix = '')
    $tpl = ConvertTo-Json -InputObject $Job.properties.template -Depth 60 | ConvertFrom-Json
    foreach ($c in @($tpl.containers)) {
        if (-not $c) { continue }
        if (-not $RepoPrefix -or ([string]$c.image).ToLowerInvariant().StartsWith($RepoPrefix.ToLowerInvariant())) { $c.image = $Image }
        if ($c.resources -and $c.resources.PSObject.Properties['ephemeralStorage']) { $c.resources.PSObject.Properties.Remove('ephemeralStorage') }
    }
    # imageType = ContainerImage is the default and is unknown to older api-versions (the live 400 of 2026-10-06): never sent
    foreach ($c in (@($tpl.containers) + @($tpl.initContainers))) {
        if ($c -and $c.PSObject.Properties['imageType'] -and ([string]$c.imageType -in '', 'ContainerImage')) { $c.PSObject.Properties.Remove('imageType') }
    }
    ConvertTo-Json -InputObject ([ordered]@{ properties = [ordered]@{ template = $tpl } }) -Depth 60 -Compress
}

function Test-SIArmRetryable {
    <# PURE. An ARM answer that means "try again shortly" (another operation on the job, throttling). #>
    param([AllowEmptyString()][string]$Message)
    if ("$Message" -match '(?i)OperationInProgress|active provisioning operation|Conflict|\b409\b|\b429\b|TooManyRequests') { return $true }
    # SUP-2026-00198 (customer D 2026-10-19): Azure checks the new image against the registry while it takes the
    # PATCH, and a registry that does not answer at that moment is a 400 -- a TRANSIENT one, sent again like a 409
    Test-SIArmRegistryTransient -Message $Message
}

function Test-SIArmRegistryTransient {
    <#
        PURE. SUP-2026-00198 (customer D, ring 2, 2026-10-19 14:09Z): Container Apps checks a job's new image against
        its registry while it takes the PATCH. When the registry does not answer at that moment, ARM refuses the PATCH with
        400 InvalidParameterValueInContainerTemplate "Field 'template.containers.<job>.image' is invalid ... Get
        "https://<acr>/v2/": dial tcp <ip>:443: connect: connection refused" -- 2 of 22 PATCHes there, the 20 around them
        accepted. That is the registry's network, not the image: the same PATCH is accepted a few seconds later. $true ONLY
        for that shape (an image field refused AND a network failure reaching the registry); an image that does not exist
        (MANIFEST_UNKNOWN / NAME_UNKNOWN / not found) or a registry that refuses the identity (401 / 403 / UNAUTHORIZED)
        is not transient and is never sent again.
    #>
    param([AllowEmptyString()][string]$Message)
    $t = "$Message"
    if ($t -notmatch '(?i)InvalidParameterValueInContainerTemplate|InvalidContainerImage|\.image''? is invalid') { return $false }
    if ($t -match '(?i)MANIFEST_UNKNOWN|manifest unknown|NAME_UNKNOWN|\bnot found\b|UNAUTHORIZED|DENIED|\b401\b|\b403\b|authentication required') { return $false }
    [bool]($t -match '(?i)connection refused|connection reset|i/o timeout|TLS handshake timeout|no such host|context deadline exceeded|Client\.Timeout|network is unreachable|temporary failure|unexpected EOF|\b50[234]\b|Service Unavailable|Bad Gateway|Gateway Time-?out')
}

# SUP-2026-00198: the error catalogue's codes for the update's roll and restore (data-model/errors.locked.json) -- a failed
# update is reported to Invardia with one of these, never as 'unknown'
$script:SIUpdateErrorCodes = @{
    RollRejected  = 'si-upd-0803'   # Azure refused a job's image PATCH (the 400 InvalidParameterValueInContainerTemplate)
    RestoreFailed = 'si-upd-0804'   # a job could not be put back on its previous image after a failed update
    RollNotVerified = 'si-upd-0805' # a job took the PATCH but does not read back the new image alone (or never finished)
}
function Get-SIUpdateErrorCodes { $script:SIUpdateErrorCodes }

function Get-SIRollFailureCode {
    <# PURE. The catalogue code of one failed roll / restore result (Invoke-SIJobImageRoll): -Restore = si-upd-0804; else a
       PATCH Azure refused (Sent $false) = si-upd-0803, one it took that did not verify = si-upd-0805. '' for a result that is Ok. #>
    param([Parameter(Mandatory)]$Result, [switch]$Restore)
    if ($Result.Ok) { return '' }
    if ($Restore) { return $script:SIUpdateErrorCodes.RestoreFailed }
    if (-not $Result.Sent) { return $script:SIUpdateErrorCodes.RollRejected }
    $script:SIUpdateErrorCodes.RollNotVerified
}

function Get-SIArmJobList {
    <#
        Every Container Apps job of -ResourceGroup, read by ONE ARM list at $script:SIFastRollArmApi -- the api-version the
        PATCH is sent with (a template read in a newer schema is refused by an older one). Follows nextLink. Throws when the
        read fails.
    #>
    param([Parameter(Mandatory)][scriptblock]$Rest, [Parameter(Mandatory)][string]$SubscriptionId, [Parameter(Mandatory)][string]$ResourceGroup)
    $url = Get-SIArmUri -Path ('/subscriptions/{0}/resourceGroups/{1}/providers/Microsoft.App/jobs' -f $SubscriptionId, $ResourceGroup) -ApiVersion $script:SIFastRollArmApi
    @(Get-SIRestList -Rest $Rest -Uri $url -What ('the Container Apps jobs of {0}' -f $ResourceGroup) | Where-Object { $_ -and $_.PSObject.Properties['name'] })
}

function Invoke-SIJobImageRoll {
    <#
        THE PARALLEL SWAP. -Targets: @{ Name; Image } (the image each job must run). The jobs are read ONCE with
        Get-SIArmJobList (the PATCH's own api-version) -- the template each PATCH carries and the fingerprint before;
        -Jobs (ARM shape) is used only when that read fails. One ARM PATCH per job, sent back to back in this one process
        (409 / throttled = sent again in the next pass, max -MaxPasses), then ONE job list per poll (Get-SIArmJobList)
        until every target has finished provisioning. Each job is then verified: it runs its image and nothing else changed.
        Returns one @{ Name; Ok; Sent; Image; Changed; Error } per target. Never throws.
    #>
    param([Parameter(Mandatory)][scriptblock]$Rest, [Parameter(Mandatory)][string]$SubscriptionId, [Parameter(Mandatory)][string]$ResourceGroup,
          [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Targets, [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Jobs,
          [string]$RepoPrefix = '', [int]$MaxPasses = 18, [int]$RetrySeconds = 10, [int]$TimeoutMinutes = 8, [int]$PollSeconds = 5, [scriptblock]$Log)
    $armJobs = $null
    try { $armJobs = @(Get-SIArmJobList -Rest $Rest -SubscriptionId $SubscriptionId -ResourceGroup $ResourceGroup) }
    catch { if ($Log) { & $Log ("the jobs could not be read at api-version {0} ({1}) -- using the job list read before" -f $script:SIFastRollArmApi, $_.Exception.Message) } }
    if ($null -ne $armJobs -and $armJobs.Count) { $Jobs = $armJobs }
    $byName = @{}; foreach ($j in $Jobs) { if ($j) { $byName[[string]$j.name] = $j } }
    $res = @{}
    foreach ($t in $Targets) { $res[$t.Name] = [pscustomobject]@{ Name = $t.Name; Ok = $false; Sent = $false; Image = ''; Changed = @(); Error = ''; Want = $t.Image; Before = $null } }
    try {
        # 1. every PATCH, back to back
        $pending = @($Targets | ForEach-Object { $_.Name })
        for ($pass = 1; $pending.Count -and $pass -le $MaxPasses; $pass++) {
            if ($pass -gt 1) { if ($Log) { & $Log ("{0} job(s) busy with another operation, or their registry did not answer Azure -- sending again in {1}s (pass {2} of {3})" -f $pending.Count, $RetrySeconds, $pass, $MaxPasses) }; if ($RetrySeconds -gt 0) { Start-Sleep -Seconds $RetrySeconds } }
            $again = New-Object System.Collections.Generic.List[string]
            foreach ($name in $pending) {
                $r = $res[$name]; $job = $byName[$name]
                if (-not $job) { $r.Error = 'the job was not in the job list'; continue }
                if (-not $r.Before) { $r.Before = Get-SIJobFingerprint -Job $job }
                $url = Get-SIArmUri -Path ('/subscriptions/{0}/resourceGroups/{1}/providers/Microsoft.App/jobs/{2}' -f $SubscriptionId, $ResourceGroup, $name) -ApiVersion $script:SIFastRollArmApi
                $m = ''; $raw = ''
                try {
                    $ans = & $Rest 'PATCH' $url (New-SIJobImagePatchBody -Job $job -Image $r.Want -RepoPrefix $RepoPrefix) 'https://management.azure.com/' @{ 'Content-Type' = 'application/json' }
                    if ([int]$ans.Status -ge 200 -and [int]$ans.Status -lt 300) { $r.Sent = $true; $r.Error = '' } else { $m = Format-SIRestFailure -Response $ans; $raw = "$($ans.Body)" }
                } catch { $m = $_.Exception.Message }
                # the whole answer is classified, not the 400-character line (the registry's words come at its end)
                if ($m) { if (Test-SIArmRetryable -Message ("{0} {1}" -f $m, $raw)) { $again.Add($name) }; $r.Error = $m }
            }
            $pending = @($again)
        }
        $sent = @($res.Values | Where-Object { $_.Sent })
        if ($Log) { & $Log ("{0} of {1} job PATCH(es) accepted" -f $sent.Count, @($Targets).Count) }
        # 2. read every job back with ONE list per poll until each has finished provisioning
        $deadline = [datetime]::UtcNow.AddMinutes($TimeoutMinutes)
        $open = @($sent | ForEach-Object { $_.Name })
        while ($open.Count) {
            $list = @()
            try { $list = @(Get-SIArmJobList -Rest $Rest -SubscriptionId $SubscriptionId -ResourceGroup $ResourceGroup); $listErrors = 0 }
            catch {
                # a read that keeps failing is reported, never waited out for the whole timeout
                $listErrors = 1 + $(if ($listErrors) { $listErrors } else { 0 })
                if ($listErrors -ge 5) { foreach ($n in $open) { $res[$n].Error = ('the jobs could not be read back: {0}' -f $_.Exception.Message) }; break }
            }
            $now = @{}; foreach ($j in $list) { if ($j) { $now[[string]$j.name] = $j } }
            $still = New-Object System.Collections.Generic.List[string]
            foreach ($name in $open) {
                $j = $now[$name]; $r = $res[$name]
                if (-not $j) { $still.Add($name); continue }
                $state = "$($j.properties.provisioningState)"
                if ($state -in 'InProgress', 'Updating', 'Creating', 'Pending', 'Accepted') { $still.Add($name); continue }
                $imgs = @(@($j.properties.template.containers) | Where-Object { $_ } | ForEach-Object { [string]$_.image })
                $r.Image = (@($imgs | Where-Object { -not $RepoPrefix -or $_.ToLowerInvariant().StartsWith($RepoPrefix.ToLowerInvariant()) }) | Select-Object -First 1)
                $r.Changed = @(Compare-SIJobFingerprint -Before $r.Before -After (Get-SIJobFingerprint -Job $j))
                if ($state -eq 'Failed') { $r.Error = 'provisioning failed' }
                elseif ($r.Image -ne $r.Want) { $r.Error = ("reads back '{0}', expected '{1}'" -f $r.Image, $r.Want) }
                elseif ($r.Changed.Count) { $r.Error = ('more than the image changed: {0}' -f ($r.Changed -join ', ')) }
                else { $r.Ok = $true }
            }
            $open = @($still)
            if (-not $open.Count) { break }
            if ([datetime]::UtcNow -ge $deadline) { foreach ($n in $open) { $res[$n].Error = ('still provisioning after {0} min' -f $TimeoutMinutes) }; break }
            if ($PollSeconds -gt 0) { Start-Sleep -Seconds $PollSeconds }
        }
    } catch {
        foreach ($r in @($res.Values | Where-Object { -not $_.Ok -and -not $_.Error })) { $r.Error = $_.Exception.Message }
    }
    foreach ($t in $Targets) { $r = $res[$t.Name]; [pscustomobject]@{ Name = $r.Name; Ok = $r.Ok; Sent = $r.Sent; Image = $r.Image; Changed = @($r.Changed); Error = $r.Error } }
}
