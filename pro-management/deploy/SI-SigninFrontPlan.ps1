#Requires -Version 5.1
<#
    SECURITYINSIGHT PRO -- THE WEB APP BEHIND THE ONE SHARED SIGN-IN FRONT (CR7, framework DOCS/REQUIREMENTS.md 12.11g). PURE.

    The front is FRAMEWORK/signin-front -- ONE component PIM and SecurityInsight both build from one source path, pinned by
    version (pro-management\signin-front.pin.json). It runs as a SIDECAR container in the SAME Container App revision as the
    web app and is the only container the ingress reaches; the web app listens on 127.0.0.1:<upstream port> and verifies the
    front's token on every request (SI.Management.Web, Auth\SigninFront.cs, switch SI_Web_SigninFront).

    This file holds the PURE half -- read the pin, find the component's source, the image tag, the settings of both
    containers, the template PATCH that adds / keeps / removes the front, and the read-back check. No HTTP, no sign-in, no
    dependency: the setup cutover (SI-ManagementSigninFront.ps1, Deploy-SIManagement.ps1 -SigninFront,
    setup\Set-SISigninFront.ps1) and the updater (container\updater\_shared\SI-UpdaterWebApp.ps1, from the release) both load
    it. Strict-mode safe; PS 5.1 + pwsh 7.

    SWITCH OFF (the default): none of this runs -- the web app is one container exactly as before.
#>

# #852: what the front 1.3.0 needs before it starts (its SQL store + Key Vault key) -- SI-SigninFrontStore.ps1, beside this file
$siSigninStoreLib = [IO.Path]::Combine($PSScriptRoot, 'SI-SigninFrontStore.ps1')
if ((Test-Path -LiteralPath $siSigninStoreLib) -and -not (Get-Command -Name Test-SISigninFrontNeedsStore -ErrorAction SilentlyContinue)) { . $siSigninStoreLib }
# #852: the web app's own API the front 1.4.0 asks an access token for (SIGNIN_UPSTREAM_SCOPE) -- SI-SigninFrontApi.ps1
$siSigninApiLib = [IO.Path]::Combine($PSScriptRoot, 'SI-SigninFrontApi.ps1')
if ((Test-Path -LiteralPath $siSigninApiLib) -and -not (Get-Command -Name Invoke-SISigninFrontApi -ErrorAction SilentlyContinue)) { . $siSigninApiLib }

$script:SISigninFrontSwitch = 'SI_Web_SigninFront'
$script:SISigninFrontWebSettings = @('SI_Web_SigninFront', 'SIGNIN_UPSTREAM_PORT')
# Container Apps on the Consumption profile: at most 4 CPU / 8 GiB for ALL containers of a revision together
$script:SISigninFrontAppMaxCpu = 4.0
$script:SISigninFrontAppMaxMemoryGi = 8.0

function Get-SISigninFrontPin {
    <# PURE (reads one shipped file). The pinned component (pro-management\signin-front.pin.json under -SIRoot). Throws when
       the file is missing or not the expected shape. #>
    param([Parameter(Mandatory)][string]$SIRoot)
    $p = [IO.Path]::Combine($SIRoot, 'pro-management', 'signin-front.pin.json')
    if (-not (Test-Path -LiteralPath $p)) { throw ('The sign-in front pin is missing: {0}' -f $p) }
    $j = [IO.File]::ReadAllText($p).TrimStart([char]0xFEFF) | ConvertFrom-Json
    foreach ($k in 'component', 'version', 'state', 'image', 'dockerfile', 'containerName', 'listenPort', 'upstreamPort', 'sessionHours', 'bearerPaths') {
        if (-not $j.PSObject.Properties[$k] -or "$($j.$k)".Trim() -eq '') { throw ('The sign-in front pin has no {0}: {1}' -f $k, $p) }
    }
    if ("$($j.version)" -notmatch '^\d+\.\d+\.\d+$') { throw ('The sign-in front pin''s version is not x.y.z: {0}' -f $j.version) }
    if ("$($j.state)" -notin 'contract', 'pinned') { throw ('The sign-in front pin''s state is neither contract nor pinned: {0}' -f $j.state) }
    if ("$($j.state)" -eq 'pinned' -and "$($j.commit)" -notmatch '^[0-9a-f]{7,40}$') { throw 'The sign-in front pin is pinned without a commit.' }
    if ([int]$j.upstreamPort -eq [int]$j.listenPort) { throw 'The sign-in front pin gives the front and the web app the same port.' }
    # the link paths (CR7, Option A): validated exactly as the front validates SIGNIN_ANONYMOUS_PATHS -- an invalid entry
    # would stop the front's container at start, so setup never writes one
    $ap = $(if ($j.PSObject.Properties['anonymousPaths']) { [string]$j.anonymousPaths } else { '' })
    $chk = Test-SISigninFrontAnonymousPaths -Value $ap -BearerPaths ([string]$j.bearerPaths)
    if (-not $chk.Ok) { throw ('The sign-in front pin''s anonymousPaths is not valid: {0}' -f $chk.Why) }
    $j
}

function Test-SISigninFrontAnonymousPaths {
    <#
        PURE. SIGNIN_ANONYMOUS_PATHS as signin-front 1.1.0 reads it (its README "Open paths"): comma-separated, whitespace
        around an entry ignored, empty = no open path. Each entry starts with "/", one trailing "/" is trimmed; refused: an
        empty entry, "/" alone, "*", "?", "..", braces, spaces, and anything equal to or under /signout, /signin-oidc,
        /signout-callback-oidc, /healthz or a bearer path. Matching
        is case-insensitive, so the comparisons here are too. Returns @{ Ok; Why; Paths (normalised); Value (the line to
        write: the normalised entries joined with ",") }.
    #>
    param([AllowEmptyString()][string]$Value, [AllowEmptyString()][string]$BearerPaths = '/mcp,/.well-known')
    $reserved = @('/signout', '/signin-oidc', '/signout-callback-oidc', '/healthz') + @("$BearerPaths" -split ',' | ForEach-Object { $_.Trim().TrimEnd('/') } | Where-Object { $_ })
    $paths = New-Object System.Collections.Generic.List[string]
    if ("$Value".Trim() -eq '') { return [pscustomobject]@{ Ok = $true; Why = ''; Paths = @(); Value = '' } }
    foreach ($raw in @("$Value" -split ',')) {
        $e = $raw.Trim()
        if ($e -eq '') { return [pscustomobject]@{ Ok = $false; Why = 'an empty entry'; Paths = @(); Value = '' } }
        if ($e.Length -gt 1 -and $e.EndsWith('/')) { $e = $e.Substring(0, $e.Length - 1) }
        $bad = $(
            if (-not $e.StartsWith('/')) { 'does not start with "/"' }
            elseif ($e -eq '/') { 'is "/" alone' }
            elseif ($e.Contains('*') -or $e.Contains('?')) { 'holds "*" or "?"' }
            elseif ($e.Contains('..')) { 'holds ".."' }
            elseif ($e.Contains('{') -or $e.Contains('}')) { 'holds a brace' }
            elseif ($e -match '\s') { 'holds a space' }
            elseif ($e.Contains('//')) { 'is not one clean path' }
            else {
                $hit = @($reserved | Where-Object { $e.Equals($_, [StringComparison]::OrdinalIgnoreCase) -or $e.StartsWith($_ + '/', [StringComparison]::OrdinalIgnoreCase) }) | Select-Object -First 1
                if ($hit) { 'is ' + $hit + ' or under it (the front''s own path)' } else { '' }
            })
        if ($bad) { return [pscustomobject]@{ Ok = $false; Why = ('"{0}" {1}' -f $raw.Trim(), $bad); Paths = @(); Value = '' } }
        if (-not @($paths | Where-Object { $_.Equals($e, [StringComparison]::OrdinalIgnoreCase) }).Count) { $paths.Add($e) }
    }
    [pscustomobject]@{ Ok = $true; Why = ''; Paths = $paths.ToArray(); Value = ($paths -join ',') }
}

function Get-SISigninFrontAnonymousPathsValue {
    <# PURE. The SIGNIN_ANONYMOUS_PATHS line SecurityInsight writes on the front: exactly the pin's list, normalised. #>
    param([Parameter(Mandatory)]$Pin)
    $ap = $(if ($Pin.PSObject.Properties['anonymousPaths']) { [string]$Pin.anonymousPaths } else { '' })
    $r = Test-SISigninFrontAnonymousPaths -Value $ap -BearerPaths ([string]$Pin.bearerPaths)
    if (-not $r.Ok) { throw ('The sign-in front pin''s anonymousPaths is not valid: {0}' -f $r.Why) }
    $r.Value
}

function Resolve-SISigninFrontSource {
    <#
        PURE (reads the disk). Where the component's source is, for -SIRoot:
          a release      <SIRoot>\pro-management\signin-front\   (Publish-SIRelease.ps1 packs the pinned tree there)
          the repository <SIRoot>\..\..\FRAMEWORK\signin-front\  (SOLUTIONS\SecurityInsight -> the repo root)
        It is usable only when its VERSION is the pinned version and it has its Dockerfile. Returns @{ Ok; Path; Version; Why }.
    #>
    param([Parameter(Mandatory)][string]$SIRoot, [Parameter(Mandatory)]$Pin)
    $cands = @(
        [IO.Path]::Combine($SIRoot, 'pro-management', 'signin-front'),
        [IO.Path]::GetFullPath([IO.Path]::Combine($SIRoot, '..', '..', ($Pin.component -replace '/', [IO.Path]::DirectorySeparatorChar)))
    )
    $why = New-Object System.Collections.Generic.List[string]
    foreach ($c in $cands) {
        if (-not (Test-Path -LiteralPath $c -PathType Container)) { continue }
        $vf = [IO.Path]::Combine($c, 'VERSION')
        $v = if (Test-Path -LiteralPath $vf) { ([IO.File]::ReadAllText($vf)).Trim() } else { '' }
        if ($v -ne [string]$Pin.version) { $why.Add(('{0} is version "{1}", not the pinned {2}' -f $c, $v, $Pin.version)); continue }
        # the image's build context (README: FRAMEWORK/signin-front/src) and its Dockerfile inside it
        $ctx = $(if ($Pin.PSObject.Properties['context'] -and "$($Pin.context)".Trim()) { [IO.Path]::Combine($c, "$($Pin.context)".Trim()) } else { $c })
        if (-not (Test-Path -LiteralPath ([IO.Path]::Combine($ctx, [string]$Pin.dockerfile)))) { $why.Add(('{0} has no {1}' -f $ctx, $Pin.dockerfile)); continue }
        return [pscustomobject]@{ Ok = $true; Path = $c; BuildPath = $ctx; Version = $v; Why = '' }
    }
    if (-not $why.Count) { $why.Add(('the component {0} {1} is not in this release or tree (pin state: {2})' -f $Pin.component, $Pin.version, $Pin.state)) }
    [pscustomobject]@{ Ok = $false; Path = ''; BuildPath = ''; Version = ''; Why = ($why -join '; ') }
}

function Get-SISigninFrontImageTag {
    <# PURE. The front's image tag: <version>-src-<16 hex of its sources> when the source hash is at hand (the fast roll's
       Get-SISourceHash), else <version>. The same source gives the same tag: an unchanged front is never rebuilt or rolled. #>
    param([Parameter(Mandatory)]$Pin, [string]$SourcePath = '')
    $v = [string]$Pin.version
    if ($SourcePath -and (Get-Command -Name Get-SISourceHash -ErrorAction SilentlyContinue)) {
        $h = ''; try { $h = [string](Get-SISourceHash -Root $SourcePath -Paths @('.')) } catch { $h = '' }
        if ($h.Length -ge 16) { return ('{0}-src-{1}' -f $v, $h.Substring(0, 16)) }
    }
    $v
}

function Get-SISigninFrontEnv {
    <# PURE. The front container's settings (the component's README is the truth for the names). No secret: the client
       assertion is the web app's managed identity as a federated credential on the SAME app registration. #>
    param([Parameter(Mandatory)][string]$TenantId, [Parameter(Mandatory)][string]$ClientId, [Parameter(Mandatory)][string]$ManagedIdentityClientId,
          [Parameter(Mandatory)]$Pin,
          # #852: the front's store settings (SIGNIN_SQL_SERVER / _DATABASE / SIGNIN_KEYVAULT_KEY_ID / SIGNIN_STATE_MI_CLIENT_ID)
          # from Invoke-SISigninFrontStore; not passed = the ones the update's step 9g made ready in this process, if any
          [string[]]$StoreEnv = $null)
    $store = @(Get-SISigninFrontStoreEnvInUse -StoreEnv $StoreEnv)
    @(
        ('SIGNIN_TENANT_ID={0}' -f $TenantId.Trim().ToLowerInvariant()),
        ('SIGNIN_CLIENT_ID={0}' -f $ClientId.Trim().ToLowerInvariant()),
        ('SIGNIN_FIC_MI_CLIENT_ID={0}' -f $ManagedIdentityClientId.Trim().ToLowerInvariant()),
        ('SIGNIN_UPSTREAM_PORT={0}' -f [int]$Pin.upstreamPort),
        ('SIGNIN_SESSION_HOURS={0}' -f [int]$Pin.sessionHours),
        ('SIGNIN_BEARER_PATHS={0}' -f [string]$Pin.bearerPaths),
        # CR7 Option A: the link pages the web app guards itself (its own single-use, short-lived, target-bound token)
        ('SIGNIN_ANONYMOUS_PATHS={0}' -f (Get-SISigninFrontAnonymousPathsValue -Pin $Pin))
    ) + $store
}

function Get-SISigninFrontStoreEnvInUse {
    <# #852. The front's store settings to write: -StoreEnv when given, else the ones the update's step 9g made ready in
       THIS process ($global:SI_SigninFrontStoreEnv, set only when every piece read back), else none. #>
    param([string[]]$StoreEnv = $null)
    if ($null -ne $StoreEnv) { return @($StoreEnv | Where-Object { "$_".Trim() }) }
    $g = Get-Variable -Scope Global -Name SI_SigninFrontStoreEnv -ValueOnly -ErrorAction Ignore
    if ($g) { return @(@($g) | Where-Object { "$_".Trim() }) }
    @()
}

function Test-SISigninFrontStoreReady {
    <# #852. PURE. May the pinned front run with these settings? A front before 1.3.0: always. 1.3.0 on: only with every
       required store setting (-Env: 'N=V' lines or ARM env entries). #>
    param([Parameter(Mandatory)]$Pin, [AllowNull()][object[]]$Env)
    if (-not (Get-Command -Name Test-SISigninFrontNeedsStore -ErrorAction SilentlyContinue)) { return $true }
    if (-not (Test-SISigninFrontNeedsStore -Pin $Pin)) { return $true }
    Test-SISigninStoreEnvComplete -Env $Env
}

function Get-SISigninFrontWebEnv {
    <# PURE. The web container's settings behind the front: the switch on, the loopback port. #>
    param([Parameter(Mandatory)]$Pin)
    @(('{0}=true' -f $script:SISigninFrontSwitch), ('SIGNIN_UPSTREAM_PORT={0}' -f [int]$Pin.upstreamPort))
}

function Get-SISigninFrontProp {
    <# PURE. A nested property of an ARM object (PSCustomObject or dictionary), $null when any step is missing. #>
    param($Object, [string[]]$Path)
    $o = $Object
    foreach ($p in $Path) {
        if ($null -eq $o) { return $null }
        if ($o -is [System.Collections.IDictionary]) { $o = $(if ($o.Contains($p)) { $o[$p] } else { $null }); continue }
        $pp = $o.PSObject.Properties[$p]
        $o = $(if ($pp) { $pp.Value } else { $null })
    }
    $o
}

function Get-SISigninFrontState {
    <# PURE. What the app (ARM, as read) runs: @{ HasFront; FrontImage; WebOn (the switch on the web container); WebImage;
       TargetPort; Containers }. The web container is the FIRST one (every other SI tool points at containers[0]). #>
    param([AllowNull()]$App, [string]$ContainerName = 'signin-front')
    $cs = @(@(Get-SISigninFrontProp $App @('properties', 'template', 'containers')) | Where-Object { $_ })
    $web = $(if ($cs.Count) { $cs[0] } else { $null })
    $front = @($cs | Where-Object { [string](Get-SISigninFrontProp $_ @('name')) -eq $ContainerName }) | Select-Object -First 1
    $on = $false
    foreach ($e in @(@(Get-SISigninFrontProp $web @('env')) | Where-Object { $_ })) {
        if ([string](Get-SISigninFrontProp $e @('name')) -eq $script:SISigninFrontSwitch) { $on = ("$(Get-SISigninFrontProp $e @('value'))".Trim() -match '^(?i:true|1|on|yes)$') }
    }
    # the front's SIGNIN_ANONYMOUS_PATHS as it runs ($null = not set)
    $anon = $null
    foreach ($e in @(@(Get-SISigninFrontProp $front @('env')) | Where-Object { $_ })) {
        if ([string](Get-SISigninFrontProp $e @('name')) -eq 'SIGNIN_ANONYMOUS_PATHS') { $anon = [string](Get-SISigninFrontProp $e @('value')) }
    }
    [pscustomobject]@{
        HasFront   = [bool]$front
        FrontImage = [string](Get-SISigninFrontProp $front @('image'))
        WebOn      = $on
        WebImage   = [string](Get-SISigninFrontProp $web @('image'))
        TargetPort = [int](0 + (Get-SISigninFrontProp $App @('properties', 'configuration', 'ingress', 'targetPort')))
        Containers = $cs.Count
        MaxReplicas = [int](0 + (Get-SISigninFrontProp $App @('properties', 'template', 'scale', 'maxReplicas')))
        MinReplicas = [int](0 + (Get-SISigninFrontProp $App @('properties', 'template', 'scale', 'minReplicas')))
        AnonymousPaths = $anon
    }
}

function ConvertTo-SISigninFrontPlain {
    <# PURE. An ARM object read back (PSCustomObject) as ordered dictionaries + arrays, so it can be changed and sent back. #>
    param($InputObject)
    if ($null -eq $InputObject) { return $null }
    if ($InputObject -is [string] -or $InputObject -is [ValueType]) { return $InputObject }
    if ($InputObject -is [System.Collections.IDictionary]) { $h = [ordered]@{}; foreach ($k in @($InputObject.Keys)) { $h[[string]$k] = ConvertTo-SISigninFrontPlain $InputObject[$k] }; return $h }
    if ($InputObject -is [System.Collections.IEnumerable]) { $l = New-Object System.Collections.Generic.List[object]; foreach ($i in $InputObject) { $l.Add((ConvertTo-SISigninFrontPlain $i)) }; return , $l.ToArray() }
    $h = [ordered]@{}; foreach ($pp in $InputObject.PSObject.Properties) { $h[$pp.Name] = ConvertTo-SISigninFrontPlain $pp.Value }; $h
}

function ConvertTo-SISigninFrontEnvEntry {
    <# PURE. 'N=V' as an ARM env entry. #>
    param([Parameter(Mandatory)][string]$Setting)
    $p = $Setting -split '=', 2
    [ordered]@{ name = $p[0]; value = $(if ($p.Count -gt 1) { $p[1] } else { '' }) }
}

function Set-SISigninFrontEnvList {
    <# PURE. -Env (ARM env entries) with -Set ('N=V', set / overwritten by name) and -Remove (names) applied. #>
    param([AllowNull()][object[]]$Env, [string[]]$Set = @(), [string[]]$Remove = @())
    $list = New-Object System.Collections.Generic.List[object]
    foreach ($e in @(@($Env) | Where-Object { $_ })) { if ($Remove -notcontains [string](Get-SISigninFrontProp $e @('name'))) { $list.Add($e) } }
    foreach ($s in @($Set | Where-Object { $_ })) {
        $n = ConvertTo-SISigninFrontEnvEntry -Setting $s
        $i = -1; for ($k = 0; $k -lt $list.Count; $k++) { if ([string](Get-SISigninFrontProp $list[$k] @('name')) -eq $n.name) { $i = $k } }
        if ($i -ge 0) { $list[$i] = $n } else { $list.Add($n) }
    }
    , $list.ToArray()
}

function ConvertTo-SISigninFrontGi {
    param([AllowEmptyString()][string]$Memory)
    $m = [regex]::Match("$Memory", '^\s*([0-9]+(?:\.[0-9]+)?)\s*Gi\s*$')
    if ($m.Success) { return [double]::Parse($m.Groups[1].Value, [Globalization.CultureInfo]::InvariantCulture) }
    0.0
}

function Clear-SISigninFrontTemplate {
    <# PURE. What ARM refuses to take back: the revision suffix (a reused one), the default imageType, ephemeralStorage. #>
    param([Parameter(Mandatory)]$Template)
    foreach ($c in @(@($(if ($Template.Contains('containers')) { $Template.containers })) + @($(if ($Template.Contains('initContainers')) { $Template.initContainers })) | Where-Object { $_ })) {
        if ($c.Contains('imageType') -and ([string]$c.imageType -in '', 'ContainerImage')) { $c.Remove('imageType') }
        if ($c.Contains('resources') -and $c.resources -is [System.Collections.IDictionary] -and $c.resources.Contains('ephemeralStorage')) { $c.resources.Remove('ephemeralStorage') }
    }
    if ($Template.Contains('revisionSuffix')) { $Template.Remove('revisionSuffix') }
}

function New-SISigninFrontPatch {
    <#
        PURE. The ONE read-modify-write PATCH that puts the front in front of the web app (-App, as read), or keeps it current:
          * the web container stays FIRST (its image untouched), its settings gain SI_Web_SigninFront=true + the port;
          * the front container (-FrontImage, -FrontEnv) is added second -- or, already there, gets that image and settings;
          * the app's CPU / memory stay within what one revision takes: the web container gives the front its share
            (4 CPU / 8 GiB together on Consumption);
          * the ingress targets the front's port (the only container the ingress reaches).
        Every other container, the scale, the volumes and the configuration's other parts are sent as read. Returns
        @{ Body; Changed }.
    #>
    param([Parameter(Mandatory)]$App, [Parameter(Mandatory)][string]$FrontImage, [Parameter(Mandatory)][AllowEmptyCollection()][string[]]$FrontEnv, [Parameter(Mandatory)]$Pin)
    $tpl = ConvertTo-SISigninFrontPlain (Get-SISigninFrontProp $App @('properties', 'template'))
    if ($null -eq $tpl -or -not $tpl.Contains('containers') -or -not @($tpl.containers | Where-Object { $_ }).Count) { throw 'The web app has no container to put the sign-in front in front of.' }
    # compared after the read-only parts ARM returns are dropped: only a real change counts
    Clear-SISigninFrontTemplate -Template $tpl
    $cs = @($tpl.containers | Where-Object { $_ })
    $before = ConvertTo-Json -InputObject $tpl -Depth 60 -Compress
    $web = $cs[0]
    $web.env = Set-SISigninFrontEnvList -Env @($(if ($web.Contains('env')) { $web.env })) -Set (Get-SISigninFrontWebEnv -Pin $Pin)
    $name = [string]$Pin.containerName
    $inv = [Globalization.CultureInfo]::InvariantCulture
    $fCpu = [double]::Parse([string]$Pin.cpu, $inv); $fMem = ConvertTo-SISigninFrontGi ([string]$Pin.memory)
    $front = @($cs | Where-Object { [string]$_.name -eq $name }) | Select-Object -First 1
    # #852: a front that needs its store (1.3.0 on) is never put in without its settings -- it would refuse to start
    $storeHave = @($FrontEnv) + @($(if ($front -and $front.Contains('env')) { @($front.env) | Where-Object { $_ } | ForEach-Object { '{0}={1}' -f $_.name, $_.value } }))
    if (-not (Test-SISigninFrontStoreReady -Pin $Pin -Env $storeHave)) {
        return [pscustomobject]@{ Body = $null; Changed = $false; Why = ('the sign-in front {0} needs its SQL store and Key Vault key settings, and they are not ready' -f $Pin.version) }
    }
    if ($front) {
        $front.image = $FrontImage
        $front.env = Set-SISigninFrontEnvList -Env @($(if ($front.Contains('env')) { $front.env })) -Set $FrontEnv
    } else {
        $front = [ordered]@{ name = $name; image = $FrontImage; env = (Set-SISigninFrontEnvList -Env @() -Set $FrontEnv)
                             resources = [ordered]@{ cpu = $fCpu; memory = [string]$Pin.memory }
                             # README 1.0.0: the health probe is the front's GET /healthz (the app gets none on its own port)
                             probes = @([ordered]@{ type = 'Liveness'; httpGet = [ordered]@{ path = '/healthz'; port = [int]$Pin.listenPort } },
                                        [ordered]@{ type = 'Readiness'; httpGet = [ordered]@{ path = '/healthz'; port = [int]$Pin.listenPort } }) }
        $cs = @($cs) + @($front)
    }
    # the revision's total stays within the profile: the web container gives up what the front takes
    $otherCpu = 0.0; $otherMem = 0.0
    for ($i = 1; $i -lt $cs.Count; $i++) {
        $r = $cs[$i].resources
        if ($r) { try { $otherCpu += [double]::Parse([string]$r.cpu, $inv) } catch { }; $otherMem += ConvertTo-SISigninFrontGi ([string]$r.memory) }
    }
    if ($web.Contains('resources') -and $web.resources) {
        $wCpu = 0.0; try { $wCpu = [double]::Parse([string]$web.resources.cpu, $inv) } catch { }
        $wMem = ConvertTo-SISigninFrontGi ([string]$web.resources.memory)
        if ($wCpu + $otherCpu -gt $script:SISigninFrontAppMaxCpu -or $wMem + $otherMem -gt $script:SISigninFrontAppMaxMemoryGi) {
            $nCpu = [Math]::Min($wCpu, $script:SISigninFrontAppMaxCpu - $otherCpu); $nMem = [Math]::Min($wMem, $script:SISigninFrontAppMaxMemoryGi - $otherMem)
            $web.resources.cpu = $nCpu; $web.resources.memory = ('{0}Gi' -f $nMem.ToString($inv))
        }
    }
    $cs[0] = $web
    $tpl.containers = $cs
    # ONE replica (signin-front 1.0.0 README: the cookie keys and the token cache are in memory -- a second replica would
    # sign users in again on every switch between replicas)
    if (-not $tpl.Contains('scale') -or -not ($tpl.scale -is [System.Collections.IDictionary])) { $tpl.scale = [ordered]@{} }
    $tpl.scale.maxReplicas = 1
    $tpl.scale.minReplicas = 1
    Clear-SISigninFrontTemplate -Template $tpl
    $after = ConvertTo-Json -InputObject $tpl -Depth 60 -Compress
    $port = [int]$Pin.listenPort
    $ingressChanged = ([int](0 + (Get-SISigninFrontProp $App @('properties', 'configuration', 'ingress', 'targetPort'))) -ne $port)
    $body = [ordered]@{ properties = [ordered]@{ template = $tpl } }
    if ($ingressChanged) { $body.properties.configuration = [ordered]@{ ingress = [ordered]@{ targetPort = $port } } }
    [pscustomobject]@{ Body = $body; Changed = ($ingressChanged -or $before -ne $after); Why = '' }
}

function New-SISigninFrontImagePatch {
    <# PURE. The updater's change on an app that IS behind the front: only the front container's image set to -FrontImage
       (its settings, the web container and everything else sent as read). $null when the app has no front or runs that
       image already -- the updater never adds or removes the front. #>
    param([Parameter(Mandatory)]$App, [Parameter(Mandatory)][string]$FrontImage, [Parameter(Mandatory)]$Pin)
    $tpl = ConvertTo-SISigninFrontPlain (Get-SISigninFrontProp $App @('properties', 'template'))
    if ($null -eq $tpl -or -not $tpl.Contains('containers')) { return $null }
    $front = @($tpl.containers | Where-Object { $_ -and [string]$_.name -eq [string]$Pin.containerName }) | Select-Object -First 1
    if (-not $front) { return $null }
    $one = ($tpl.Contains('scale') -and $tpl.scale -is [System.Collections.IDictionary] -and $tpl.scale.Contains('maxReplicas') -and [int]$tpl.scale.maxReplicas -eq 1 `
            -and $tpl.scale.Contains('minReplicas') -and [int]$tpl.scale.minReplicas -eq 1)
    # the link paths SecurityInsight guards itself (CR7 Option A) -- exactly the pin's list on the front, kept or put right
    $anonLine = 'SIGNIN_ANONYMOUS_PATHS={0}' -f (Get-SISigninFrontAnonymousPathsValue -Pin $Pin)
    $fenv = @($(if ($front.Contains('env')) { $front.env }))
    $anonNow = @($fenv | Where-Object { $_ -and [string](Get-SISigninFrontProp $_ @('name')) -eq 'SIGNIN_ANONYMOUS_PATHS' } | ForEach-Object { [string](Get-SISigninFrontProp $_ @('value')) })
    $anonOk = ($anonNow.Count -eq 1 -and $anonNow[0] -ceq ($anonLine -split '=', 2)[1])
    # #852: the front's store settings the update made ready (step 9g) -- written beside the others, every other setting kept
    $store = @(Get-SISigninFrontStoreEnvInUse)
    $storeOk = $true
    foreach ($l in $store) {
        $p = $l -split '=', 2
        $now = @($fenv | Where-Object { $_ -and [string](Get-SISigninFrontProp $_ @('name')) -eq $p[0] } | ForEach-Object { [string](Get-SISigninFrontProp $_ @('value')) })
        if ($now.Count -ne 1 -or $now[0] -cne $p[1]) { $storeOk = $false }
    }
    # a front that needs its store (1.3.0 on) stays on what it runs until its settings are there -- it would refuse to start
    $fenvLines = @($fenv | Where-Object { $_ } | ForEach-Object { '{0}={1}' -f (Get-SISigninFrontProp $_ @('name')), (Get-SISigninFrontProp $_ @('value')) })
    if (-not (Test-SISigninFrontStoreReady -Pin $Pin -Env (@($fenvLines) + @($store)))) { return $null }
    if ([string]$front.image -eq $FrontImage -and $one -and $anonOk -and $storeOk) { return $null }
    $front.image = $FrontImage
    $front.env = Set-SISigninFrontEnvList -Env $fenv -Set (@($anonLine) + @($store))
    # ONE replica behind the front 1.0.0 (its keys and token cache are in memory) -- kept, or put right
    if (-not ($tpl.Contains('scale') -and $tpl.scale -is [System.Collections.IDictionary])) { $tpl.scale = [ordered]@{} }
    $tpl.scale.maxReplicas = 1; $tpl.scale.minReplicas = 1
    Clear-SISigninFrontTemplate -Template $tpl
    [ordered]@{ properties = [ordered]@{ template = $tpl } }
}

function New-SISigninFrontRemovePatch {
    <#
        PURE. The way back (-Off, or a cutover that did not read back healthy): the front container removed, the web
        container's port setting removed and its switch written OFF (it listens on 8080 again with its own sign-in; the
        updater keeps that choice and never moves the app behind the front again), the ingress on 8080.
        The web container's size is left as it is. Returns @{ Body; Changed }.
    #>
    param([Parameter(Mandatory)]$App, [Parameter(Mandatory)]$Pin, [int]$WebPort = 8080)
    $tpl = ConvertTo-SISigninFrontPlain (Get-SISigninFrontProp $App @('properties', 'template'))
    if ($null -eq $tpl -or -not $tpl.Contains('containers')) { throw 'The web app has no containers.' }
    Clear-SISigninFrontTemplate -Template $tpl
    $before = ConvertTo-Json -InputObject $tpl -Depth 60 -Compress
    $hadFront = [bool](@($tpl.containers | Where-Object { $_ -and [string]$_.name -eq [string]$Pin.containerName }).Count)
    $cs = @($tpl.containers | Where-Object { $_ -and [string]$_.name -ne [string]$Pin.containerName })
    if (-not $cs.Count) { throw 'The web app would have no container left.' }
    # the switch is written OFF, not removed: the way back is a CHOICE (Get-SISigninFrontChoice 'own')
    $cs[0].env = Set-SISigninFrontEnvList -Env @($(if ($cs[0].Contains('env')) { $cs[0].env })) -Remove @('SIGNIN_UPSTREAM_PORT') -Set @(('{0}=false' -f $script:SISigninFrontSwitch))
    # without the front the web app may run two replicas again (its keys are shared in the Pro database), as a deploy sets it
    if ($hadFront -and $tpl.Contains('scale') -and $tpl.scale -is [System.Collections.IDictionary] -and [int](0 + $tpl.scale.maxReplicas) -eq 1) { $tpl.scale.maxReplicas = 2 }
    $tpl.containers = $cs
    Clear-SISigninFrontTemplate -Template $tpl
    $after = ConvertTo-Json -InputObject $tpl -Depth 60 -Compress
    $ingressChanged = ([int](0 + (Get-SISigninFrontProp $App @('properties', 'configuration', 'ingress', 'targetPort'))) -ne $WebPort)
    $body = [ordered]@{ properties = [ordered]@{ template = $tpl } }
    if ($ingressChanged) { $body.properties.configuration = [ordered]@{ ingress = [ordered]@{ targetPort = $WebPort } } }
    [pscustomobject]@{ Body = $body; Changed = ($ingressChanged -or $before -ne $after) }
}

function New-SISigninFrontRestorePatch {
    <# PURE. Put back EXACTLY what ran before (-Before = the app as read before the change): its whole template and its
       ingress port. Used when a change did not read back healthy. #>
    param([Parameter(Mandatory)]$Before)
    $tpl = ConvertTo-SISigninFrontPlain (Get-SISigninFrontProp $Before @('properties', 'template'))
    Clear-SISigninFrontTemplate -Template $tpl
    $body = [ordered]@{ properties = [ordered]@{ template = $tpl } }
    $port = [int](0 + (Get-SISigninFrontProp $Before @('properties', 'configuration', 'ingress', 'targetPort')))
    if ($port -gt 0) { $body.properties.configuration = [ordered]@{ ingress = [ordered]@{ targetPort = $port } } }
    $body
}

function Test-SISigninFrontReadBack {
    <#
        PURE. Does the app as read back run what was asked? -Want 'on': the front container with -FrontImage, the web
        container's switch on, the ingress on the front's port, the latest revision ready. -Want 'off': no front, switch off,
        ingress on -WebPort. Returns @{ Ok; Why }.
    #>
    param([AllowNull()]$App, [Parameter(Mandatory)]$Pin, [ValidateSet('on', 'off')][string]$Want = 'on', [string]$FrontImage = '', [int]$WebPort = 8080)
    if (-not $App) { return [pscustomobject]@{ Ok = $false; Why = 'the web app could not be read back' } }
    $s = Get-SISigninFrontState -App $App -ContainerName ([string]$Pin.containerName)
    if ($Want -eq 'on') {
        if (-not $s.HasFront) { return [pscustomobject]@{ Ok = $false; Why = 'the sign-in front container is not in the app' } }
        if ($FrontImage -and $s.FrontImage -ne $FrontImage) { return [pscustomobject]@{ Ok = $false; Why = ('the front runs {0}, not {1}' -f $s.FrontImage, $FrontImage) } }
        if (-not $s.WebOn) { return [pscustomobject]@{ Ok = $false; Why = 'the web container''s switch is not on' } }
        if ($s.TargetPort -ne [int]$Pin.listenPort) { return [pscustomobject]@{ Ok = $false; Why = ('the ingress targets port {0}, not the front''s {1}' -f $s.TargetPort, $Pin.listenPort) } }
        if ($s.MaxReplicas -ne 1 -or $s.MinReplicas -ne 1) { return [pscustomobject]@{ Ok = $false; Why = ('the app may run {0} to {1} replicas, not exactly one (the front keeps its keys in memory)' -f $s.MinReplicas, $s.MaxReplicas) } }
        $wantAnon = Get-SISigninFrontAnonymousPathsValue -Pin $Pin
        if ([string]$s.AnonymousPaths -cne $wantAnon) { return [pscustomobject]@{ Ok = $false; Why = ('the front''s SIGNIN_ANONYMOUS_PATHS is "{0}", not SecurityInsight''s "{1}"' -f $s.AnonymousPaths, $wantAnon) } }
    } else {
        if ($s.HasFront) { return [pscustomobject]@{ Ok = $false; Why = 'the sign-in front container is still in the app' } }
        if ($s.WebOn) { return [pscustomobject]@{ Ok = $false; Why = 'the web container''s switch is still on' } }
        if ($s.TargetPort -and $s.TargetPort -ne $WebPort) { return [pscustomobject]@{ Ok = $false; Why = ('the ingress targets port {0}, not {1}' -f $s.TargetPort, $WebPort) } }
    }
    $latest = [string](Get-SISigninFrontProp $App @('properties', 'latestRevisionName'))
    $ready = [string](Get-SISigninFrontProp $App @('properties', 'latestReadyRevisionName'))
    if ($latest -and $ready -ne $latest) { return [pscustomobject]@{ Ok = $false; Why = ('the new revision {0} is not ready yet (ready: {1})' -f $latest, $(if ($ready) { $ready } else { 'none' })) } }
    $ps = [string](Get-SISigninFrontProp $App @('properties', 'provisioningState'))
    if ($ps -and $ps -ne 'Succeeded') { return [pscustomobject]@{ Ok = $false; Why = ('provisioning is {0}' -f $ps) } }
    [pscustomobject]@{ Ok = $true; Why = '' }
}

function Get-SISigninFrontSecretIds {
    <# PURE. The client secrets (passwordCredentials) of the app registration -- the ones the switch makes unneeded. Only
       their key ids; never a value (Graph never returns one). #>
    param([AllowNull()][object[]]$PasswordCredentials)
    @(@($PasswordCredentials) | Where-Object { $_ -and "$(Get-SISigninFrontProp $_ @('keyId'))".Trim() } | ForEach-Object { "$(Get-SISigninFrontProp $_ @('keyId'))".Trim() })
}

function Get-SISigninFrontChoice {
    <#
        PURE. What the web app (-App, as read) says about the sign-in front:
          'front'      the front container is there, or the switch is on (the updater keeps it on the release's front);
          'own'        the web container carries SI_Web_SigninFront with a value that is not on -- a CHOICE (the way back,
                       setup\Set-SISigninFront.ps1 -Off, writes 'false'): the updater never moves it;
          'undecided'  no front and no switch at all (every install from before the front): the updater moves it behind
                       the front once everything the front needs reads back (Invoke-SIUpdaterSigninFrontAdopt).
    #>
    param([AllowNull()]$App, [string]$ContainerName = 'signin-front')
    $s = Get-SISigninFrontState -App $App -ContainerName $ContainerName
    if ($s.HasFront -or $s.WebOn) { return 'front' }
    $cs = @(@(Get-SISigninFrontProp $App @('properties', 'template', 'containers')) | Where-Object { $_ })
    $web = $(if ($cs.Count) { $cs[0] } else { $null })
    foreach ($e in @(@(Get-SISigninFrontProp $web @('env')) | Where-Object { $_ })) {
        if ([string](Get-SISigninFrontProp $e @('name')) -eq $script:SISigninFrontSwitch) { return 'own' }
    }
    'undecided'
}

function Get-SISigninFrontWebSetting {
    <# PURE. One setting of the web container (the first one) as read; '' when it is not there. #>
    param([AllowNull()]$App, [Parameter(Mandatory)][string]$Name)
    $cs = @(@(Get-SISigninFrontProp $App @('properties', 'template', 'containers')) | Where-Object { $_ })
    if (-not $cs.Count) { return '' }
    foreach ($e in @(@(Get-SISigninFrontProp $cs[0] @('env')) | Where-Object { $_ })) {
        if ([string](Get-SISigninFrontProp $e @('name')) -eq $Name) { return [string](Get-SISigninFrontProp $e @('value')) }
    }
    ''
}

function Get-SISigninFrontWebIdentity {
    <#
        PURE. The web app's user-assigned managed identity -- the front's client assertion -- from the app as read
        (identity.userAssignedIdentities): the one the web container already names as its sign-in credential
        (AzureAd__ClientCredentials__0__ManagedIdentityClientId), else the one named in -Names, else the only one.
        Returns @{ ClientId; PrincipalId; Name }, or $null when it cannot be told.
    #>
    param([AllowNull()]$App, [string[]]$Names = @('uami-si-management', 'id-si-web'))
    $ua = Get-SISigninFrontProp $App @('identity', 'userAssignedIdentities')
    if ($null -eq $ua) { return $null }
    $list = New-Object System.Collections.Generic.List[object]
    $keys = if ($ua -is [System.Collections.IDictionary]) { @($ua.Keys) } else { @($ua.PSObject.Properties | ForEach-Object { $_.Name }) }
    foreach ($k in $keys) {
        $v = if ($ua -is [System.Collections.IDictionary]) { $ua[$k] } else { $ua.$k }
        $cid = [string](Get-SISigninFrontProp $v @('clientId')); $prin = [string](Get-SISigninFrontProp $v @('principalId'))
        if ($cid -notmatch '^[0-9a-fA-F-]{36}$' -or $prin -notmatch '^[0-9a-fA-F-]{36}$') { continue }
        $list.Add([pscustomobject]@{ ClientId = $cid.ToLowerInvariant(); PrincipalId = $prin.ToLowerInvariant(); Name = ([string]$k -split '/')[-1] })
    }
    if (-not $list.Count) { return $null }
    $named = (Get-SISigninFrontWebSetting -App $App -Name 'AzureAd__ClientCredentials__0__ManagedIdentityClientId').Trim().ToLowerInvariant()
    if ($named) { $m = @($list | Where-Object { $_.ClientId -eq $named }); if ($m.Count) { return $m[0] } }
    foreach ($n in $Names) { $m = @($list | Where-Object { $_.Name -ieq $n }); if ($m.Count) { return $m[0] } }
    if ($list.Count -eq 1) { return $list[0] }
    $null
}
