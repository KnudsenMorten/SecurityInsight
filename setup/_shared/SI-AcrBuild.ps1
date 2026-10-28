#Requires -Version 5.1
<#
    SecurityInsight -- BUILD AN IMAGE IN THE INSTALL'S OWN REGISTRY OVER ARM REST (#521: no az CLI). Ported from PIM4EntraPS's
    proven engine/_shared/PIM-AcrBuild.ps1 (live since 2026-09). `az acr build` never built anything locally: it packed the
    folder, uploaded it and asked the registry to build. These are the same four HTTPS calls:

        1. POST  .../registries/<acr>/listBuildSourceUploadUrl   -> { uploadUrl; relativePath }
        2. PUT   <uploadUrl>                                     -> the .tar.gz build context
        3. POST  .../registries/<acr>/scheduleRun                -> a DockerBuildRequest
        4. GET   .../registries/<acr>/runs/<runId>               -> polled until it ends

    🪤 STEP 2 IS NOT AN ARM CALL. The upload URL is a blob SAS of the ACR task service: it takes NO bearer token (the SAS is
       the credential) and it REQUIRES `x-ms-blob-type: BlockBlob`. Both mistakes fail as a 40x from a storage host that
       reads like an identity problem and is not.
    🪤 IMAGE NAMES ARE REGISTRY-RELATIVE ("si-orchestrator:v3.0.1-abc"): a name with the login server in front becomes
       <acr>.azurecr.io/<acr>.azurecr.io/... and fails only at push time, minutes in.
    🪤 'Queued', 'Started' and 'Running' all mean STILL GOING; only Succeeded / Failed / Canceled / Error / Timeout end it.
    🪤 A registry with public access Disabled refuses ACR's shared build agents -- it needs an agent pool inside its network
       (SI_UPDATER_ACR_AGENT_POOL, else the registry's first agent pool).
    The runId of scheduleRun sits at the root or under .properties depending on the version -- both are read. The ACR tasks
    API version is PINNED (2019-06-01-preview, as PIM). A failed run's log is fetched (POST runs/<id>/listLogSasUrl, the
    SAS link read without a token) and its tail printed.

    THE BUILD CONTEXT is packed here with .NET -- no tar.exe, no Python: System.Formats.Tar (PowerShell 7 / .NET 7+: the
    updater container) and, on Windows PowerShell 5.1 (the VM sync hook), a small ustar writer of this file; both gzip with
    System.IO.Compression.GZipStream. The context's .dockerignore is applied BEFORE anything leaves the machine (as
    `az acr build` did): customer files (*.custom.*, config/) are never uploaded. .git is never packed. A Dockerfile outside
    the context (the two-layer build's derived file) travels in the archive as .si-build/<name>.

    THE TAG CHECK (was `az acr repository show-tags`) reads the registry itself: the identity's ARM token is exchanged for a
    registry token (POST https://<login>/oauth2/exchange, then /oauth2/token with scope repository:<repo>:pull) and the
    manifest is asked for (HEAD /v2/<repo>/manifests/<tag>: 200 = there, 404 = not). Same right as before (AcrPull).

    Every call goes through -Rest (setup/_shared/SI-UpdateRest.ps1); tests drive a fake registry. PowerShell 5.1-compatible.
#>

if (-not (Get-Command -Name Invoke-SIRestJson -ErrorAction SilentlyContinue)) { . ([IO.Path]::Combine($PSScriptRoot, 'SI-UpdateRest.ps1')) }

$script:SIAcrTasksApi = '2019-06-01-preview'
$script:SIAcrRegistryApi = '2023-07-01'
$script:SIAcrRunDone = @('Succeeded', 'Failed', 'Canceled', 'Cancelled', 'Error', 'Timeout')
if (-not ($script:SIAcrRegistryCache -is [hashtable])) { $script:SIAcrRegistryCache = @{} }

function Get-SIAcrRegistry {
    <#
        The registry -AcrName as ARM knows it: @{ Id; Name; ResourceGroup; LoginServer; PublicNetworkAccess }. Looked up in
        -ResourceGroup first, else among every registry of the subscription (as `az acr show --name`). Cached per run.
        Throws when it cannot be found or read.
    #>
    param([Parameter(Mandatory)][scriptblock]$Rest, [Parameter(Mandatory)][string]$SubscriptionId, [Parameter(Mandatory)][string]$AcrName, [string]$ResourceGroup)
    $key = ('{0}|{1}' -f $SubscriptionId, $AcrName).ToLowerInvariant()
    if ($script:SIAcrRegistryCache -is [hashtable] -and $script:SIAcrRegistryCache.ContainsKey($key)) { return $script:SIAcrRegistryCache[$key] }
    $reg = $null
    if ($ResourceGroup) {
        $reg = Invoke-SIRestJson -Rest $Rest -Uri (Get-SIArmUri -Path ('/subscriptions/{0}/resourceGroups/{1}/providers/Microsoft.ContainerRegistry/registries/{2}' -f $SubscriptionId, $ResourceGroup, $AcrName) -ApiVersion $script:SIAcrRegistryApi) `
                   -AllowNotFound -What ("the container registry '{0}'" -f $AcrName)
    }
    if (-not $reg) {
        $all = @(Get-SIRestList -Rest $Rest -Uri (Get-SIArmUri -Path ('/subscriptions/{0}/providers/Microsoft.ContainerRegistry/registries' -f $SubscriptionId) -ApiVersion $script:SIAcrRegistryApi) -What 'the container registries of the subscription')
        $reg = @($all | Where-Object { $_ -and ([string]$_.name) -ieq $AcrName }) | Select-Object -First 1
    }
    if (-not $reg) { throw ("the container registry '{0}' was not found in subscription {1} (or this identity cannot read it)" -f $AcrName, $SubscriptionId) }
    $id = [string]$reg.id
    $rg = if ($id -match '/resourceGroups/([^/]+)/') { $Matches[1] } else { $ResourceGroup }
    $p = $reg.properties
    $o = [pscustomobject]@{ Id = $id; Name = [string]$reg.name; ResourceGroup = $rg
        LoginServer = $(if ($p -and $p.PSObject.Properties['loginServer']) { [string]$p.loginServer } else { ('{0}.azurecr.io' -f $AcrName.ToLowerInvariant()) })
        PublicNetworkAccess = $(if ($p -and $p.PSObject.Properties['publicNetworkAccess']) { [string]$p.publicNetworkAccess } else { '' }) }
    if (-not ($script:SIAcrRegistryCache -is [hashtable])) { $script:SIAcrRegistryCache = @{} }
    $script:SIAcrRegistryCache[$key] = $o
    $o
}

# ---- the build context ----------------------------------------------------------------------------------------------
function ConvertTo-SIDockerIgnoreRegex {
    <# PURE. One .dockerignore pattern (Go filepath.Match plus **, as Docker reads it) -> an anchored regex over '/' paths. #>
    param([Parameter(Mandatory)][string]$Pattern)
    $p = $Pattern.Trim() -replace '\\', '/'
    while ($p.StartsWith('./')) { $p = $p.Substring(2) }
    $p = $p.TrimStart('/').TrimEnd('/')
    $sb = New-Object System.Text.StringBuilder
    $i = 0
    while ($i -lt $p.Length) {
        $ch = $p[$i]
        if ($ch -eq '*') {
            if ($i + 1 -lt $p.Length -and $p[$i + 1] -eq '*') {
                if ($i + 2 -lt $p.Length -and $p[$i + 2] -eq '/') { [void]$sb.Append('(?:.*/)?'); $i += 3; continue }
                [void]$sb.Append('.*'); $i += 2; continue
            }
            [void]$sb.Append('[^/]*'); $i++; continue
        }
        if ($ch -eq '?') { [void]$sb.Append('[^/]'); $i++; continue }
        if ($ch -eq '[') {
            $j = $p.IndexOf(']', $i + 1)
            if ($j -gt $i) {
                $cls = $p.Substring($i + 1, $j - $i - 1)
                if ($cls.StartsWith('!') -or $cls.StartsWith('^')) { $cls = '^' + $cls.Substring(1) }
                [void]$sb.Append('[' + ($cls -replace '\\', '\\') + ']'); $i = $j + 1; continue
            }
        }
        [void]$sb.Append([regex]::Escape([string]$ch)); $i++
    }
    '^' + $sb.ToString() + '$'
}

function Get-SIDockerIgnoreRules {
    <# PURE. The rules of a .dockerignore text, in order: @{ Regex; Negate; Pattern }. Comments and blank lines are skipped. #>
    param([AllowEmptyString()][string]$Text)
    $rules = New-Object System.Collections.Generic.List[object]
    foreach ($l in ("$Text" -split "`r?`n")) {
        $t = $l.Trim()
        if (-not $t -or $t.StartsWith('#')) { continue }
        $neg = $false
        if ($t.StartsWith('!')) { $neg = $true; $t = $t.Substring(1).Trim() }
        if (-not $t) { continue }
        $rules.Add([pscustomobject]@{ Regex = (ConvertTo-SIDockerIgnoreRegex -Pattern $t); Negate = $neg; Pattern = $t })
    }
    $rules.ToArray()
}

function Test-SIDockerIgnored {
    <#
        PURE. Is -RelativePath ('/' separated, from the context root) left out by -Rules? Docker's rule: a pattern matches the
        path itself or any folder above it; the LAST matching pattern decides (! = keep it).
    #>
    param([Parameter(Mandatory)][string]$RelativePath, [object[]]$Rules = @())
    $path = ($RelativePath -replace '\\', '/').TrimStart('/')
    $parts = $path.Split('/')
    $cands = New-Object System.Collections.Generic.List[string]
    for ($n = 1; $n -le $parts.Count; $n++) { $cands.Add(($parts[0..($n - 1)] -join '/')) }
    $ignored = $false
    foreach ($r in @($Rules)) {
        if (-not $r) { continue }
        $hit = $false
        foreach ($c in $cands) { if ($c -match $r.Regex) { $hit = $true; break } }
        if ($hit) { $ignored = -not $r.Negate }
    }
    $ignored
}

function Get-SIBuildContextFiles {
    <#
        The files of the build context -Path that are uploaded: everything but .git and what the context's own .dockerignore
        leaves out. Returns @(@{ Rel ('/' separated); Full }), sorted ordinally (a stable archive). -Keep: relative paths
        always packed (the Dockerfile the build names -- Docker never leaves it out either).
    #>
    param([Parameter(Mandatory)][string]$Path, [string[]]$Keep = @())
    $root = [IO.Path]::GetFullPath($Path).TrimEnd('\', '/')
    $diFile = [IO.Path]::Combine($root, '.dockerignore')
    $rules = if (Test-Path -LiteralPath $diFile) { @(Get-SIDockerIgnoreRules -Text ([IO.File]::ReadAllText($diFile))) } else { @() }
    $keepSet = @{}; foreach ($k in @($Keep)) { if ($k) { $keepSet[($k -replace '\\', '/').TrimStart('/').ToLowerInvariant()] = $true } }
    $out = New-Object System.Collections.Generic.List[object]
    foreach ($f in [IO.Directory]::EnumerateFiles($root, '*', [IO.SearchOption]::AllDirectories)) {
        $rel = $f.Substring($root.Length).TrimStart('\', '/') -replace '\\', '/'
        if ($rel -match '(^|/)\.git(/|$)') { continue }
        if (-not $keepSet.ContainsKey($rel.ToLowerInvariant()) -and $rules.Count -and (Test-SIDockerIgnored -RelativePath $rel -Rules $rules)) { continue }
        $out.Add([pscustomobject]@{ Rel = $rel; Full = $f })
    }
    $arr = $out.ToArray()
    [Array]::Sort($arr, [System.Collections.Generic.Comparer[object]]::Create([Comparison[object]] { param($a, $b) [string]::CompareOrdinal($a.Rel, $b.Rel) }))
    $arr
}

function Write-SIUstarEntry {
    <# One regular file into a ustar stream (a GNU long-name entry first when the name does not fit). 5.1 fallback writer. #>
    param([Parameter(Mandatory)][System.IO.Stream]$Stream, [Parameter(Mandatory)][string]$Name, [Parameter(Mandatory)][AllowEmptyCollection()][byte[]]$Data, [char]$Type = '0')
    $enc = [System.Text.Encoding]::UTF8
    $nb = $enc.GetBytes($Name)
    $prefix = [byte[]]@(); $short = $nb
    if ($nb.Length -gt 100) {
        $cut = -1
        for ($i = [Math]::Min($nb.Length - 1, 155); $i -gt 0; $i--) { if ($nb[$i] -eq 47 -and ($nb.Length - $i - 1) -le 100 -and ($nb.Length - $i - 1) -gt 0) { $cut = $i; break } }
        if ($cut -gt 0) { $prefix = $nb[0..($cut - 1)]; $short = $nb[($cut + 1)..($nb.Length - 1)] }
        else {
            # GNU long name: a '././@LongLink' entry of type L carries the full name
            Write-SIUstarEntry -Stream $Stream -Name '././@LongLink' -Data ([byte[]]($nb + [byte[]]@(0))) -Type 'L'
            $short = $nb[0..99]
        }
    }
    $h = New-Object byte[] 512
    [Array]::Copy([byte[]]$short, 0, $h, 0, [Math]::Min(100, $short.Length))
    $oct = { param([long]$v, [int]$len) $s = [Convert]::ToString($v, 8).PadLeft($len - 1, '0') + [char]0; $enc.GetBytes($s) }
    [Array]::Copy((& $oct 420 8), 0, $h, 100, 8)          # mode 0644
    [Array]::Copy((& $oct 0 8), 0, $h, 108, 8)            # uid
    [Array]::Copy((& $oct 0 8), 0, $h, 116, 8)            # gid
    [Array]::Copy((& $oct $Data.Length 12), 0, $h, 124, 12)
    [Array]::Copy((& $oct 1577836800 12), 0, $h, 136, 12) # mtime: fixed (a stable archive)
    for ($i = 148; $i -lt 156; $i++) { $h[$i] = 32 }      # checksum field = spaces while summing
    $h[156] = [byte][char]$Type
    [Array]::Copy($enc.GetBytes("ustar`0"), 0, $h, 257, 6)
    $h[263] = 48; $h[264] = 48                             # version '00'
    if ($prefix.Length) { [Array]::Copy([byte[]]$prefix, 0, $h, 345, [Math]::Min(155, $prefix.Length)) }
    $sum = 0; foreach ($b in $h) { $sum += $b }
    $cs = $enc.GetBytes(([Convert]::ToString($sum, 8).PadLeft(6, '0') + [char]0 + ' '))
    [Array]::Copy($cs, 0, $h, 148, 8)
    $Stream.Write($h, 0, 512)
    if ($Data.Length) { $Stream.Write($Data, 0, $Data.Length) }
    $pad = (512 - ($Data.Length % 512)) % 512
    if ($pad) { $Stream.Write((New-Object byte[] $pad), 0, $pad) }
}

function New-SIBuildContextArchive {
    <#
        Packs the build context -Path (Get-SIBuildContextFiles) plus -Extra (@{ '<relative name>' = '<file>' }) into the
        .tar.gz -OutFile. -Format: Auto (System.Formats.Tar when .NET has it, else the ustar writer) | Ustar. Returns
        @{ Path; Files; Bytes; Writer }.
    #>
    param([Parameter(Mandatory)][string]$Path, [Parameter(Mandatory)][string]$OutFile, [hashtable]$Extra = @{}, [string[]]$Keep = @(),
          [ValidateSet('Auto', 'Ustar')][string]$Format = 'Auto')
    $files = New-Object System.Collections.Generic.List[object]
    foreach ($f in @(Get-SIBuildContextFiles -Path $Path -Keep $Keep)) { $files.Add($f) }
    foreach ($k in @($Extra.Keys | Sort-Object)) { $files.Add([pscustomobject]@{ Rel = ([string]$k -replace '\\', '/').TrimStart('/'); Full = [string]$Extra[$k] }) }
    $useNet = ($Format -eq 'Auto') -and [bool]('System.Formats.Tar.TarWriter' -as [type])
    $fs = [IO.File]::Create($OutFile)
    try {
        $gz = New-Object System.IO.Compression.GZipStream($fs, [System.IO.Compression.CompressionLevel]::Optimal, $true)
        try {
            if ($useNet) {
                $tw = New-Object System.Formats.Tar.TarWriter($gz, [System.Formats.Tar.TarEntryFormat]::Pax, $true)
                try {
                    foreach ($f in $files) {
                        $e = New-Object System.Formats.Tar.PaxTarEntry([System.Formats.Tar.TarEntryType]::RegularFile, $f.Rel)
                        $e.Mode = [System.IO.UnixFileMode]420
                        $e.ModificationTime = [DateTimeOffset]::FromUnixTimeSeconds(1577836800)
                        $src = [IO.File]::OpenRead($f.Full)
                        try { $e.DataStream = $src; $tw.WriteEntry($e) } finally { $src.Dispose() }
                    }
                } finally { $tw.Dispose() }
            } else {
                foreach ($f in $files) { Write-SIUstarEntry -Stream $gz -Name $f.Rel -Data ([IO.File]::ReadAllBytes($f.Full)) }
                $gz.Write((New-Object byte[] 1024), 0, 1024)   # two empty blocks end the archive
            }
        } finally { $gz.Dispose() }
    } finally { $fs.Dispose() }
    [pscustomobject]@{ Path = $OutFile; Files = @($files | ForEach-Object { $_.Rel }); Bytes = (Get-Item -LiteralPath $OutFile).Length; Writer = $(if ($useNet) { 'System.Formats.Tar' } else { 'ustar' }) }
}

# ---- the four calls -------------------------------------------------------------------------------------------------
function ConvertTo-SIAcrRelativeImage {
    <# PURE. 'reg.azurecr.io/si-x:1' -> 'si-x:1' (a registry-relative name is what scheduleRun takes). #>
    param([Parameter(Mandatory)][string]$Image, [string]$LoginServer = '')
    $i = $Image.Trim()
    if ($LoginServer -and $i.ToLowerInvariant().StartsWith($LoginServer.ToLowerInvariant() + '/')) { return $i.Substring($LoginServer.Length + 1) }
    if ($i -match '^[^/]+\.azurecr\.io/(.+)$') { return $Matches[1] }
    $i
}

function New-SIAcrDockerBuildRequest {
    <# PURE. The scheduleRun body: a DockerBuildRequest, Linux / amd64, push on, cache allowed, the image registry-relative. #>
    param([Parameter(Mandatory)][string]$SourceLocation, [Parameter(Mandatory)][string]$Image, [Parameter(Mandatory)][string]$DockerfilePath,
          [string]$LoginServer = '', [int]$TimeoutSeconds = 3600, [string]$AgentPoolName = '')
    $b = [ordered]@{
        type           = 'DockerBuildRequest'
        isPushEnabled  = $true
        noCache        = $false
        dockerFilePath = ($DockerfilePath -replace '\\', '/')
        imageNames     = @(ConvertTo-SIAcrRelativeImage -Image $Image -LoginServer $LoginServer)
        sourceLocation = $SourceLocation
        platform       = [ordered]@{ os = 'Linux'; architecture = 'amd64' }
        timeout        = $TimeoutSeconds
    }
    if ("$AgentPoolName".Trim()) { $b['agentPoolName'] = "$AgentPoolName".Trim() }
    $b
}

function Get-SIAcrRunId {
    <# PURE. scheduleRun's run id: at the root or under .properties, depending on the API version. #>
    param($Run)
    if (-not $Run) { return '' }
    $id = ''
    if ($Run.PSObject.Properties['runId']) { $id = "$($Run.runId)".Trim() }
    if (-not $id -and $Run.PSObject.Properties['properties'] -and $Run.properties -and $Run.properties.PSObject.Properties['runId']) { $id = "$($Run.properties.runId)".Trim() }
    $id
}

function Resolve-SIAcrAgentPool {
    <#
        The agent pool a build runs on: SI_UPDATER_ACR_AGENT_POOL (or $global:SI_Bootstrap_AcrAgentPool) when set; else, for a
        registry with public access Disabled (the shared agents are refused there), its first agent pool; else '' (shared).
    #>
    param([Parameter(Mandatory)][scriptblock]$Rest, [Parameter(Mandatory)]$Registry)
    $set = "$([Environment]::GetEnvironmentVariable('SI_UPDATER_ACR_AGENT_POOL'))".Trim()
    if (-not $set) { $set = "$(Get-Variable -Name SI_Bootstrap_AcrAgentPool -Scope Global -ValueOnly -ErrorAction Ignore)".Trim() }
    if ($set) { return $set }
    if ([string]$Registry.PublicNetworkAccess -ine 'Disabled') { return '' }
    try {
        $pools = @(Get-SIRestList -Rest $Rest -Uri (Get-SIArmUri -Path ($Registry.Id + '/agentPools') -ApiVersion $script:SIAcrTasksApi) -What 'the registry''s agent pools')
        $p = @($pools | Where-Object { $_ }) | Select-Object -First 1
        if ($p) { return [string]$p.name }
    } catch { }
    ''
}

function Send-SIAcrBuildContext {
    <# PUT the .tar.gz to the upload SAS. NO bearer token (Resource ''), `x-ms-blob-type: BlockBlob` mandatory. Returns the bytes sent. #>
    param([Parameter(Mandatory)][scriptblock]$Rest, [Parameter(Mandatory)][string]$UploadUrl, [Parameter(Mandatory)][string]$Path)
    $bytes = [IO.File]::ReadAllBytes($Path)
    $r = & $Rest 'PUT' $UploadUrl $bytes '' @{ 'x-ms-blob-type' = 'BlockBlob'; 'Content-Type' = 'application/octet-stream' }
    if ([int]$r.Status -lt 200 -or [int]$r.Status -ge 300) { throw ('the build context upload failed: {0}' -f (Format-SIRestFailure -Response $r)) }
    $bytes.Length
}

function Invoke-SIAcrQueueBuild {
    <#
        Packs -ContextPath, uploads it and SCHEDULES the build of -Image (registry-relative) from -DockerfilePath (relative to the
        context, or a file outside it -- then packed as .si-build/<name>). Does not wait. Returns @{ RunId; Image; Bytes; Files;
        Writer; Registry }. Throws when a call fails.
    #>
    param([Parameter(Mandatory)][scriptblock]$Rest, [Parameter(Mandatory)][string]$SubscriptionId, [Parameter(Mandatory)][string]$AcrName,
          [Parameter(Mandatory)][string]$ContextPath, [Parameter(Mandatory)][string]$Image, [Parameter(Mandatory)][string]$DockerfilePath,
          [string]$ResourceGroup, [int]$TimeoutSeconds = 3600, [string]$WorkDir)
    $reg = Get-SIAcrRegistry -Rest $Rest -SubscriptionId $SubscriptionId -AcrName $AcrName -ResourceGroup $ResourceGroup
    $ctx = [IO.Path]::GetFullPath($ContextPath).TrimEnd('\', '/')
    $extra = @{}; $dfRel = ($DockerfilePath -replace '\\', '/')
    $dfFull = if ([IO.Path]::IsPathRooted($DockerfilePath)) { [IO.Path]::GetFullPath($DockerfilePath) } else { [IO.Path]::GetFullPath([IO.Path]::Combine($ctx, $DockerfilePath)) }
    $inside = $dfFull.StartsWith($ctx + [IO.Path]::DirectorySeparatorChar, [StringComparison]::OrdinalIgnoreCase)
    if (-not $inside) { $dfRel = '.si-build/' + [IO.Path]::GetFileName($dfFull); $extra[$dfRel] = $dfFull }
    else { $dfRel = $dfFull.Substring($ctx.Length + 1) -replace '\\', '/' }
    $own = -not $WorkDir
    if ($own) { $WorkDir = Join-Path ([IO.Path]::GetTempPath()) ('si-acr-' + [guid]::NewGuid().ToString('N').Substring(0, 8)) }
    New-Item -ItemType Directory -Force -Path $WorkDir | Out-Null
    try {
        $tgz = Join-Path $WorkDir 'context.tar.gz'
        $pack = New-SIBuildContextArchive -Path $ctx -OutFile $tgz -Extra $extra -Keep @($dfRel)
        $slot = Invoke-SIRestJson -Rest $Rest -Method POST -Uri (Get-SIArmUri -Path ($reg.Id + '/listBuildSourceUploadUrl') -ApiVersion $script:SIAcrTasksApi) -What 'the build upload slot'
        if (-not $slot -or -not "$($slot.uploadUrl)".Trim()) { throw ("registry '{0}' returned no upload URL" -f $AcrName) }
        $bytes = Send-SIAcrBuildContext -Rest $Rest -UploadUrl ([string]$slot.uploadUrl) -Path $tgz
        $pool = Resolve-SIAcrAgentPool -Rest $Rest -Registry $reg
        $body = New-SIAcrDockerBuildRequest -SourceLocation ([string]$slot.relativePath) -Image $Image -DockerfilePath $dfRel -LoginServer $reg.LoginServer -TimeoutSeconds $TimeoutSeconds -AgentPoolName $pool
        $run = Invoke-SIRestJson -Rest $Rest -Method POST -Uri (Get-SIArmUri -Path ($reg.Id + '/scheduleRun') -ApiVersion $script:SIAcrTasksApi) -Body (ConvertTo-Json -InputObject $body -Depth 10 -Compress) -What ('the build of {0}' -f $Image)
        [pscustomobject]@{ RunId = (Get-SIAcrRunId -Run $run); Image = $body.imageNames[0]; Bytes = $bytes; Files = @($pack.Files).Count; Writer = $pack.Writer; Registry = $reg }
    } finally { if ($own) { Remove-Item -LiteralPath $WorkDir -Recurse -Force -ErrorAction SilentlyContinue } }
}

function Get-SIAcrRunStatus {
    <# The status of run -RunId ('' when it cannot be read -- the caller polls again). Never throws. #>
    param([Parameter(Mandatory)][scriptblock]$Rest, [Parameter(Mandatory)]$Registry, [Parameter(Mandatory)][string]$RunId)
    try {
        $r = Invoke-SIRestJson -Rest $Rest -Uri (Get-SIArmUri -Path ($Registry.Id + '/runs/' + $RunId) -ApiVersion $script:SIAcrTasksApi) -What ('build run {0}' -f $RunId)
        $s = ''
        if ($r -and $r.PSObject.Properties['properties'] -and $r.properties) { $s = "$($r.properties.status)".Trim() }
        if (-not $s -and $r -and $r.PSObject.Properties['status']) { $s = "$($r.status)".Trim() }
        $s
    } catch { '' }
}

function Get-SIAcrRunLogTail {
    <# The last -Lines lines of a run's log (POST runs/<id>/listLogSasUrl, then the SAS link read WITHOUT a token). @() when unreadable. #>
    param([Parameter(Mandatory)][scriptblock]$Rest, [Parameter(Mandatory)]$Registry, [Parameter(Mandatory)][string]$RunId, [int]$Lines = 30)
    try {
        $l = Invoke-SIRestJson -Rest $Rest -Method POST -Uri (Get-SIArmUri -Path ($Registry.Id + '/runs/' + $RunId + '/listLogSasUrl') -ApiVersion $script:SIAcrTasksApi) -What ('the log link of run {0}' -f $RunId)
        $link = if ($l -and $l.PSObject.Properties['logLink']) { [string]$l.logLink } else { '' }
        if (-not $link) { return @() }
        $t = & $Rest 'GET' $link $null '' @{ Accept = 'text/plain' }
        if ([int]$t.Status -lt 200 -or [int]$t.Status -ge 300) { return @() }
        $all = @(("$($t.Body)" -split "`r?`n") | Where-Object { "$_".Trim() })
        if ($all.Count -le $Lines) { return $all }
        @($all[($all.Count - $Lines)..($all.Count - 1)])
    } catch { @() }
}

function Find-SIAcrRunId {
    <# The newest run of the registry whose output images name -Image (repo:tag); '' when none. Never throws. #>
    param([Parameter(Mandatory)][scriptblock]$Rest, [Parameter(Mandatory)]$Registry, [Parameter(Mandatory)][string]$Image)
    $img = ConvertTo-SIAcrRelativeImage -Image $Image -LoginServer $Registry.LoginServer
    $repo = ($img -split ':')[0]; $tag = ($img -split ':')[-1]
    try {
        $runs = @(Invoke-SIRestJson -Rest $Rest -Uri ((Get-SIArmUri -Path ($Registry.Id + '/runs') -ApiVersion $script:SIAcrTasksApi) + '&$top=10') -What 'the registry''s runs').value
        foreach ($r in @($runs)) {
            if (-not $r) { continue }
            $p = if ($r.PSObject.Properties['properties']) { $r.properties } else { $r }
            foreach ($o in @($p.outputImages)) { if ($o -and "$($o.repository)" -eq $repo -and "$($o.tag)" -eq $tag) { return [string]$p.runId } }
        }
    } catch { }
    ''
}

# ---- the tag check: the registry's own data plane -------------------------------------------------------------------
function Get-SIAcrPullToken {
    <#
        A registry token for -Repo: the identity's ARM token (-Token { param($Resource) }) exchanged at https://<login>/oauth2/exchange
        for a refresh token, then /oauth2/token with scope repository:<repo>:pull. Throws when either step is refused.
    #>
    param([Parameter(Mandatory)][scriptblock]$Rest, [Parameter(Mandatory)][string]$LoginServer, [Parameter(Mandatory)][string]$Repo, [scriptblock]$Token)
    if (-not $Token) { $Token = { param($Resource) Get-SIAzureToken -Resource $Resource } }
    $aad = [string](& $Token 'https://management.azure.com/')
    if (-not $aad) { throw 'no access token for the registry exchange' }
    $form = @{ 'Content-Type' = 'application/x-www-form-urlencoded' }
    $ex = & $Rest 'POST' ('https://{0}/oauth2/exchange' -f $LoginServer) ('grant_type=access_token&service={0}&access_token={1}' -f [uri]::EscapeDataString($LoginServer), [uri]::EscapeDataString($aad)) '' $form
    if ([int]$ex.Status -lt 200 -or [int]$ex.Status -ge 300) { throw ('the registry refused the token exchange: {0}' -f (Format-SIRestFailure -Response $ex)) }
    $refresh = [string](("$($ex.Body)" | ConvertFrom-Json).refresh_token)
    $tk = & $Rest 'POST' ('https://{0}/oauth2/token' -f $LoginServer) ('grant_type=refresh_token&service={0}&scope={1}&refresh_token={2}' -f [uri]::EscapeDataString($LoginServer), [uri]::EscapeDataString(('repository:{0}:pull' -f $Repo)), [uri]::EscapeDataString($refresh)) '' $form
    if ([int]$tk.Status -lt 200 -or [int]$tk.Status -ge 300) { throw ('the registry refused a pull token for {0}: {1}' -f $Repo, (Format-SIRestFailure -Response $tk)) }
    [string](("$($tk.Body)" | ConvertFrom-Json).access_token)
}

function Test-SIAcrManifest {
    <# Is <login>/<repo>:<tag> in the registry? HEAD /v2/<repo>/manifests/<tag>: 200 $true, 404 $false; anything else THROWS. #>
    param([Parameter(Mandatory)][scriptblock]$Rest, [Parameter(Mandatory)][string]$LoginServer, [Parameter(Mandatory)][string]$Repo, [Parameter(Mandatory)][string]$Tag, [scriptblock]$Token)
    $bearer = Get-SIAcrPullToken -Rest $Rest -LoginServer $LoginServer -Repo $Repo -Token $Token
    $acc = 'application/vnd.docker.distribution.manifest.v2+json, application/vnd.docker.distribution.manifest.list.v2+json, application/vnd.oci.image.manifest.v1+json, application/vnd.oci.image.index.v1+json'
    $r = & $Rest 'HEAD' ('https://{0}/v2/{1}/manifests/{2}' -f $LoginServer, $Repo, $Tag) $null '' @{ Authorization = ('Bearer ' + $bearer); Accept = $acc }
    if ([int]$r.Status -ge 200 -and [int]$r.Status -lt 300) { return $true }
    if ([int]$r.Status -eq 404) { return $false }
    throw ('the registry could not say whether {0}:{1} exists: {2}' -f $Repo, $Tag, (Format-SIRestFailure -Response $r))
}
