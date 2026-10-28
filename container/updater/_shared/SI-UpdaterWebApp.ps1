#Requires -Version 5.1
<#
    caj-si-updater -- the web app and its MCP server follow the engine jobs (#350), in EVERY edition: the Community edition
    has the web app (owner 2026-10-18, #750 (a)) and the MCP server too -- the MCP server is Pro by its LICENCE GATE, not by
    being left out (owner 2026-10-27, #750 (3): it answers only while cfg.InstallState 'Licence' names a Pro edition in force,
    pro-management/src/SI.Management.Core/Licensing/McpLicenceGate.cs), so this roll keeps both on the release in both editions.
#>
function Get-SIAppImageSources {
    <# PURE. What each app image's Dockerfile copies (relative to the SecurityInsight folder; BUILD.json left out on purpose, #416). #>
    param([Parameter(Mandatory)][ValidateSet('si-management', 'si-management-mcp')][string]$Repo)
    if ($Repo -eq 'si-management') { return @('VERSION', 'config', 'pro-management/Dockerfile', 'pro-management/src/SI.Management.Core', 'pro-management/src/SI.Management.Web') }
    @('VERSION', 'config', 'pro-management/Dockerfile.mcp', 'pro-management/src/SI.Management.Core', 'pro-management/src/SI.Management.Mcp')
}

function Get-SIAppImageTag {
    <#
        #416: the tag of an app image built from -SIRoot = src-<16 hex of ITS sources> (Get-SISourceHash of the release's
        setup/_shared/SI-FastRoll.ps1, loaded by the caller). An app whose sources did not change keeps its image: no build,
        no roll. '' when the release does not carry the app or the hash function is not loaded.
    #>
    param([Parameter(Mandatory)][string]$SIRoot, [Parameter(Mandatory)][ValidateSet('si-management', 'si-management-mcp')][string]$Repo)
    if (-not (Get-Command -Name Get-SISourceHash -ErrorAction SilentlyContinue)) { return '' }
    $h = Get-SISourceHash -Root $SIRoot -Paths (Get-SIAppImageSources -Repo $Repo)
    if (-not $h) { return '' }
    'src-' + $h.Substring(0, 16)
}

function Get-SIUpdaterAppPrebuilds {
    <#
        #416: the app images this release needs BUILT, for Start-SIUpdaterPrebuilds to queue in parallel with the engine roll:
        an app that exists here, does not already run its src-<hash> tag, and whose tag is not in the registry. -Rest: the
        run's REST seam (#521). Returns @(@{ Image = repo:tag; File }).
    #>
    param([Parameter(Mandatory)][string]$SIRoot, [Parameter(Mandatory)][string]$ResourceGroup, [Parameter(Mandatory)][string]$AcrName,
          [Parameter(Mandatory)][string]$SubscriptionId, [Parameter(Mandatory)][string]$LoginServer, [Parameter(Mandatory)][scriptblock]$Rest,
          [string]$WebApp = 'ca-si-management', [string]$McpApp = 'ca-si-mcp')
    foreach ($p in @(
            [pscustomobject]@{ App = $WebApp; Repo = 'si-management'; File = 'pro-management/Dockerfile' },
            [pscustomobject]@{ App = $McpApp; Repo = 'si-management-mcp'; File = 'pro-management/Dockerfile.mcp' })) {
        if (-not $p.App -or -not (Test-Path -LiteralPath (Join-Path $SIRoot $p.File))) { continue }
        $tag = Get-SIAppImageTag -SIRoot $SIRoot -Repo $p.Repo
        if (-not $tag) { continue }
        $app = $null; try { $app = Get-SIUpdaterContainerApp -App $p.App -ResourceGroup $ResourceGroup -SubscriptionId $SubscriptionId } catch { $app = $null }
        if (-not $app) { continue }
        $cur = ''; try { $cur = [string]$app.properties.template.containers[0].image } catch { }
        if ($cur -eq ('{0}/{1}:{2}' -f $LoginServer, $p.Repo, $tag)) { Write-UpdLog ("{0}: its sources did not change -- it runs {1} already, nothing to build" -f $p.App, $tag); continue }
        if (Test-SIAcrTag -Rest $Rest -AcrName $AcrName -SubscriptionId $SubscriptionId -Repo $p.Repo -Tag $tag -LoginServer $LoginServer) { continue }
        [pscustomobject]@{ Image = ('{0}:{1}' -f $p.Repo, $tag); File = $p.File }
    }
}

function Invoke-SIUpdaterSigninFrontRoll {
    <#
        CR7 (framework 12.11g): the shared sign-in front of a web app that ALREADY runs behind it is kept on the front this
        release pins (pro-management\signin-front.pin.json; its source packed in the release as pro-management\signin-front\).
        This roll never adds or removes the front: an install from before the front is moved ONCE by
        Invoke-SIUpdaterSigninFrontAdopt (above it in the app roll), by setup\Set-SISigninFront.ps1 or by a new install's
        Deploy-SIManagement.ps1 -SigninFront; the updater never removes it. No front container: nothing at all.
        The image is built in the install's registry from the release's source (tag <version>-src-<hash>: an unchanged front
        is neither built nor rolled); ONE PATCH sets the front container's image only; the revision waited for, /healthz
        asked; on failure the template that ran before is put back. Returns @{ Code (0 ok / 1 failed); Text ('' = nothing). }
    #>
    param([Parameter(Mandatory)][string]$SIRoot, [Parameter(Mandatory)][string]$ResourceGroup, [Parameter(Mandatory)][string]$AcrName,
          [Parameter(Mandatory)][string]$SubscriptionId, [Parameter(Mandatory)][string]$LoginServer,
          [string]$WebApp = 'ca-si-management', [int]$TimeoutMinutes = 10, [int]$PollSeconds = 10)
    $none = [pscustomobject]@{ Code = 0; Text = '' }
    $planFile = [IO.Path]::Combine($SIRoot, 'pro-management', 'deploy', 'SI-SigninFrontPlan.ps1')
    if (-not $WebApp -or -not (Test-Path -LiteralPath $planFile)) { return $none }
    $app = $null
    try { $app = Get-SIUpdaterContainerApp -App $WebApp -ResourceGroup $ResourceGroup -SubscriptionId $SubscriptionId } catch { $app = $null }
    if (-not $app) { return $none }
    . $planFile
    $pin = $null
    try { $pin = Get-SISigninFrontPin -SIRoot $SIRoot } catch { Write-UpdLog ("{0}: the sign-in front pin could not be read ({1}) -- the front is left as it is" -f $WebApp, $_.Exception.Message); return $none }
    $state = Get-SISigninFrontState -App $app -ContainerName ([string]$pin.containerName)
    if (-not $state.HasFront) { return $none }
    $src = Resolve-SISigninFrontSource -SIRoot $SIRoot -Pin $pin
    if (-not $src.Ok) {
        Write-UpdLog ("{0}: this release carries no usable sign-in front ({1}) -- the front keeps {2}" -f $WebApp, $src.Why, ($state.FrontImage -split '/')[-1])
        return [pscustomobject]@{ Code = 0; Text = ('{0}: sign-in front kept at {1}' -f $WebApp, ($state.FrontImage -split '/')[-1]) }
    }
    $fast = [IO.Path]::Combine($SIRoot, 'setup', '_shared', 'SI-FastRoll.ps1')
    if ((Test-Path -LiteralPath $fast) -and -not (Get-Command -Name Get-SISourceHash -ErrorAction SilentlyContinue)) { . $fast }
    $tag = Get-SISigninFrontImageTag -Pin $pin -SourcePath $src.BuildPath
    $new = '{0}/{1}:{2}' -f $LoginServer, $pin.image, $tag
    # the same image: only the front's settings SecurityInsight owns (the link paths, one replica) may still need putting right
    $body = New-SISigninFrontImagePatch -App $app -FrontImage $new -Pin $pin
    if (-not $body) { return [pscustomobject]@{ Code = 0; Text = ('{0}: sign-in front already runs {1}' -f $WebApp, $tag) } }
    if ($state.FrontImage -ne $new -and -not (Test-SIUpdaterImageTag -LoginServer $LoginServer -Repo ([string]$pin.image) -Tag $tag)) {
        Write-UpdLog ("building {0}:{1} (the shared sign-in front {2})" -f $pin.image, $tag, $pin.version)
        try { Invoke-SIUpdaterAcrBuild -SIRoot $src.BuildPath -AcrName $AcrName -SubscriptionId $SubscriptionId -Image ('{0}:{1}' -f $pin.image, $tag) -File ([string]$pin.dockerfile) -LoginServer $LoginServer }
        catch { return [pscustomobject]@{ Code = 1; Text = ("{0}: the sign-in front's image build failed -- nothing changed: {1}" -f $WebApp, $_.Exception.Message) } }
    }
    $path = Get-SIUpdaterRgPath -SubscriptionId $SubscriptionId -ResourceGroup $ResourceGroup -Provider ('Microsoft.App/containerApps/' + $WebApp)
    Write-UpdLog ("{0}: sign-in front {1} -> {2}" -f $WebApp, ($state.FrontImage -split '/')[-1], ($new -split '/')[-1])
    $why = ''
    try {
        $null = Invoke-SIUpdaterArm -Method PATCH -Path $path -Body (ConvertTo-Json -InputObject $body -Depth 60 -Compress)
        $deadline = [datetime]::UtcNow.AddMinutes($TimeoutMinutes)
        $rb = [pscustomobject]@{ Ok = $false; Why = 'not read yet' }; $now = $null
        do {
            if ($PollSeconds -gt 0) { Start-Sleep -Seconds $PollSeconds }
            try { $now = Get-SIUpdaterContainerApp -App $WebApp -ResourceGroup $ResourceGroup -SubscriptionId $SubscriptionId; $rb = Test-SISigninFrontReadBack -App $now -Pin $pin -Want on -FrontImage $new }
            catch { $rb = [pscustomobject]@{ Ok = $false; Why = ('the last read failed: {0}' -f $_.Exception.Message) } }
        } until ($rb.Ok -or [datetime]::UtcNow -gt $deadline -or $PollSeconds -le 0)
        if (-not $rb.Ok) { throw ('not ready after {0} min ({1})' -f $TimeoutMinutes, $rb.Why) }
        $fqdn = ''; try { $fqdn = [string]$now.properties.configuration.ingress.fqdn } catch { }
        if ($fqdn) {
            $hc = 0
            foreach ($i in 1..4) {
                try { $hc = [int](Invoke-WebRequest -Uri "https://$fqdn/healthz" -UseBasicParsing -TimeoutSec 60).StatusCode } catch { $hc = 0 }
                if ($hc -eq 200) { break }
                if ($i -lt 4 -and $PollSeconds -gt 0) { Start-Sleep -Seconds ([Math]::Min(15, $PollSeconds)) }
            }
            if ($hc -ne 200) { throw '/healthz did not answer 200 (asked four times)' }
        }
    } catch { $why = $_.Exception.Message }
    if (-not $why) { return [pscustomobject]@{ Code = 0; Text = ('{0}: sign-in front runs {1} (healthy)' -f $WebApp, $tag) } }
    Write-UpdLog ("{0}: the sign-in front update FAILED ({1}) -- putting back what ran before" -f $WebApp, $why)
    try { $null = Invoke-SIUpdaterArm -Method PATCH -Path $path -Body (ConvertTo-Json -InputObject (New-SISigninFrontRestorePatch -Before $app) -Depth 60 -Compress) }
    catch { Write-UpdLog ("{0}: could NOT be put back: {1} -- restore it by hand" -f $WebApp, $_.Exception.Message) }
    [pscustomobject]@{ Code = 1; Text = ("{0}: the sign-in front was NOT updated: {1}" -f $WebApp, $why) }
}

function Invoke-SIUpdaterAnonymousProbe {
    <# One request WITHOUT a sign-in and without following a redirect: @{ Status (0 = no answer); Location }. Tests mock it. #>
    param([Parameter(Mandatory)][string]$Url)
    $h = New-Object System.Net.Http.HttpClientHandler
    $h.AllowAutoRedirect = $false
    $c = New-Object System.Net.Http.HttpClient($h)
    $c.Timeout = [TimeSpan]::FromSeconds(60)
    try {
        $r = $c.GetAsync($Url).GetAwaiter().GetResult()
        $loc = ''; if ($r.Headers.Location) { $loc = [string]$r.Headers.Location }
        [pscustomobject]@{ Status = [int]$r.StatusCode; Location = $loc }
    } catch { [pscustomobject]@{ Status = 0; Location = '' } } finally { $c.Dispose() }
}

function Test-SIUpdaterAnonymousRefused {
    <# PURE. An anonymous request is refused: a redirect to the Microsoft Entra sign-in, or 401 / 403. #>
    param([Parameter(Mandatory)]$Probe)
    $s = [int]$Probe.Status
    if ($s -in 401, 403) { return $true }
    if ($s -in 301, 302, 303, 307, 308) { return ([string]$Probe.Location -match '^https://login\.microsoftonline\.com/') }
    $false
}

function Test-SIUpdaterReadRefused {
    <# PURE. A Graph / ARM answer that says this identity MAY NOT read (401 / 403): the check could not run -- a note, never a
       customer action. #>
    param([AllowNull()][AllowEmptyString()][string]$Message)
    "$Message" -match '(?i)\b401\b|\b403\b|Forbidden|Unauthorized|Authorization_RequestDenied|Insufficient privileges|AuthorizationFailed'
}

function Invoke-SIUpdaterSigninFrontAdopt {
    <#
        The web app's sign-in session: at most 8 hours, fixed from the sign-in, code flow with PKCE, the customer's
        Conditional Access sign-in frequency on top -- what the ONE shared sign-in front gives (pro-management\
        signin-front.pin.json). An install from before the front reaches that state through its update, with no manual step:
        a web app that is NOT behind the front and has never chosen (Get-SISigninFrontChoice 'undecided') is moved behind it
        here -- only when everything the front needs is already in place and READ BACK:
          * the release carries the pinned front's source;
          * the web app's managed identity is trusted by its sign-in app registration (the federated credential);
          * the organisation-wide consent to openid profile offline_access User.Read;
          * Easy Auth is not on.
        The updater never writes to Microsoft Entra: what is missing there is said ONCE in the update result as a customer
        action naming setup\Set-SISigninFront.ps1 -Apply (which adds it and reads it back), and the web app is left exactly
        as it is. Then: the front's image built in the install's registry from the release's source, ONE PATCH (the front
        as the second container of the same revision, the ingress on it, one replica), read back, /healthz 200 and an
        anonymous request refused -- anything else PUTS BACK the template that ran before.
        An app whose web container says SI_Web_SigninFront=false (the way back, Set-SISigninFront.ps1 -Off) keeps its own
        sign-in: a choice, never overridden. Returns @{ Code (0 / 1 = moved and failed, put back); Text; Action ('' or the
        customer action's text) }.
    #>
    param([Parameter(Mandatory)][string]$SIRoot, [Parameter(Mandatory)][string]$ResourceGroup, [Parameter(Mandatory)][string]$AcrName,
          [Parameter(Mandatory)][string]$SubscriptionId, [Parameter(Mandatory)][string]$LoginServer,
          [string]$WebApp = 'ca-si-management', [int]$TimeoutMinutes = 10, [int]$PollSeconds = 10, [scriptblock]$Graph)
    $none = [pscustomobject]@{ Code = 0; Text = ''; Action = '' }
    $planFile = [IO.Path]::Combine($SIRoot, 'pro-management', 'deploy', 'SI-SigninFrontPlan.ps1')
    $credFile = [IO.Path]::Combine($SIRoot, 'pro-management', 'deploy', 'SI-ManagementSignInCredential.ps1')
    if (-not $WebApp -or -not (Test-Path -LiteralPath $planFile) -or -not (Test-Path -LiteralPath $credFile)) { return $none }
    $app = $null
    try { $app = Get-SIUpdaterContainerApp -App $WebApp -ResourceGroup $ResourceGroup -SubscriptionId $SubscriptionId } catch { $app = $null }
    if (-not $app) { return $none }
    . $planFile
    if (-not (Get-Command -Name Invoke-SISignInConsent -ErrorAction SilentlyContinue)) { . $credFile }
    $pin = $null
    try { $pin = Get-SISigninFrontPin -SIRoot $SIRoot } catch { return $none }
    $choice = Get-SISigninFrontChoice -App $app -ContainerName ([string]$pin.containerName)
    if ($choice -eq 'front') { return $none }
    if ($choice -eq 'own') { return [pscustomobject]@{ Code = 0; Text = ('{0}: keeps its own sign-in (chosen for this install)' -f $WebApp); Action = '' } }
    $src = Resolve-SISigninFrontSource -SIRoot $SIRoot -Pin $pin
    if (-not $src.Ok) { Write-UpdLog ("{0}: this release carries no usable sign-in front ({1}) -- the web app keeps its own sign-in" -f $WebApp, $src.Why); return $none }
    $say = { param([string]$Need)
        $t = ('{0} still signs users in itself; to move it to the shared sign-in front (an 8-hour session, sign-in with PKCE) {1}. Run setup\Set-SISigninFront.ps1 -Apply through the Support app (it adds what is missing and reads it back) -- the next update then moves the web app by itself.' -f $WebApp, $Need)
        [pscustomobject]@{ Code = 0; Text = $t; Action = $t } }
    # a check that could not RUN (the read was refused): said once as a note, never a customer action; the web app keeps its own sign-in
    $note = { param([string]$What)
        [pscustomobject]@{ Code = 0; Text = ("{0} still signs users in itself; {1} -- it stays as it is (setup\Set-SISigninFront.ps1 -Apply through the Support app moves it)" -f $WebApp, $What); Action = '' } }
    $tenant = (Get-SISigninFrontWebSetting -App $app -Name 'AzureAd__TenantId').Trim()
    $client = (Get-SISigninFrontWebSetting -App $app -Name 'AzureAd__ClientId').Trim()
    if ($tenant -notmatch '^[0-9a-fA-F-]{36}$' -or $client -notmatch '^[0-9a-fA-F-]{36}$') { return (& $say "its sign-in settings (AzureAd__TenantId / AzureAd__ClientId) must be readable") }
    $id = Get-SISigninFrontWebIdentity -App $app
    if (-not $id) { return (& $say "the web app needs ONE user-assigned managed identity it signs in with") }
    if (-not $Graph) { $Graph = { param([string]$Method, [string]$Uri, $Body) Invoke-SIRestJson -Rest (Get-SIUpdaterRest) -Method $Method -Uri $Uri -Resource 'https://graph.microsoft.com/' } }
    # the federated credential (READ ONLY)
    $fics = $null
    try {
        $reg = & $Graph 'GET' ("https://graph.microsoft.com/v1.0/applications(appId='{0}')?`$select=id" -f $client) $null
        if (-not $reg -or -not [string]$reg.id) { throw 'the app registration was not found' }
        $fics = @((& $Graph 'GET' ('https://graph.microsoft.com/v1.0/applications/{0}/federatedIdentityCredentials' -f $reg.id) $null).value)
    } catch {
        # a read the updater MAY NOT make (401 / 403) is not a missing customer action: the check could not run -- a NOTE, no
        # action (coordinator 2026-10-22: two installs reported config-missing on every update for a 403 on this read)
        if (Test-SIUpdaterReadRefused -Message $_.Exception.Message) { return (& $note ("whether its sign-in app registration trusts the web app's managed identity could not be checked -- this update may not read it ({0})" -f $_.Exception.Message)) }
        return (& $say ("the web app's managed identity must be trusted by its sign-in app registration, and this update could not read that ({0})" -f $_.Exception.Message))
    }
    if (-not (Test-SIManagementFederatedCredential -Credentials @($fics) -TenantId $tenant -PrincipalId $id.PrincipalId)) { return (& $say ("the web app's managed identity ({0}) must be trusted by its sign-in app registration (a federated credential -- no secret, no certificate)" -f $id.Name)) }
    # the organisation-wide sign-in consent (READ ONLY)
    $cn = Invoke-SISignInConsent -Graph $Graph -ClientId $client
    if ($cn.State -eq 'no-rights') { return (& $note 'whether the sign-in permissions are consented for the organisation could not be checked -- this update may not read consents') }
    if ($cn.State -ne 'in-place') {
        $why = if ($cn.State -eq 'planned') { 'missing: ' + (@($cn.Missing) -join ' ') } else { 'it could not be checked: ' + $(if ($cn.State -eq 'no-rights') { 'this update may not read consents' } else { [string]$cn.Error }) }
        return (& $say ("the sign-in permissions openid profile offline_access User.Read must be consented for the organisation ({0})" -f $why))
    }
    # Easy Auth (SecurityInsight never used it; an app that has it is left to the setup script, which turns it off)
    $path = Get-SIUpdaterRgPath -SubscriptionId $SubscriptionId -ResourceGroup $ResourceGroup -Provider ('Microsoft.App/containerApps/' + $WebApp)
    $auth = $null
    try { $auth = Invoke-SIUpdaterArm -Path ($path + '/authConfigs/current') -AllowNotFound } catch { $auth = $null }
    if ($auth -and [bool](Get-SISigninFrontProp $auth @('properties', 'platform', 'enabled'))) { return (& $say 'Easy Auth must be off (the front signs users in)') }
    # the front's image, from the release's source, in the install's own registry
    $fast = [IO.Path]::Combine($SIRoot, 'setup', '_shared', 'SI-FastRoll.ps1')
    if ((Test-Path -LiteralPath $fast) -and -not (Get-Command -Name Get-SISourceHash -ErrorAction SilentlyContinue)) { . $fast }
    $tag = Get-SISigninFrontImageTag -Pin $pin -SourcePath $src.BuildPath
    $image = '{0}/{1}:{2}' -f $LoginServer, $pin.image, $tag
    if (-not (Test-SIUpdaterImageTag -LoginServer $LoginServer -Repo ([string]$pin.image) -Tag $tag)) {
        Write-UpdLog ("building {0}:{1} (the shared sign-in front {2})" -f $pin.image, $tag, $pin.version)
        try { Invoke-SIUpdaterAcrBuild -SIRoot $src.BuildPath -AcrName $AcrName -SubscriptionId $SubscriptionId -Image ('{0}:{1}' -f $pin.image, $tag) -File ([string]$pin.dockerfile) -LoginServer $LoginServer }
        catch { return [pscustomobject]@{ Code = 1; Text = ("{0}: the sign-in front's image build failed -- the web app was not changed: {1}" -f $WebApp, $_.Exception.Message); Action = '' } }
    }
    $plan = New-SISigninFrontPatch -App $app -FrontImage $image -FrontEnv (Get-SISigninFrontEnv -TenantId $tenant -ClientId $client -ManagedIdentityClientId $id.ClientId -Pin $pin) -Pin $pin
    if (-not $plan.Changed) { return $none }
    Write-UpdLog ("{0}: moving the web app behind the shared sign-in front {1}" -f $WebApp, $tag)
    $why = ''
    try {
        $null = Invoke-SIUpdaterArm -Method PATCH -Path $path -Body (ConvertTo-Json -InputObject $plan.Body -Depth 60 -Compress)
        $deadline = [datetime]::UtcNow.AddMinutes($TimeoutMinutes)
        $rb = [pscustomobject]@{ Ok = $false; Why = 'not read yet' }; $now = $null
        do {
            if ($PollSeconds -gt 0) { Start-Sleep -Seconds $PollSeconds }
            try { $now = Get-SIUpdaterContainerApp -App $WebApp -ResourceGroup $ResourceGroup -SubscriptionId $SubscriptionId; $rb = Test-SISigninFrontReadBack -App $now -Pin $pin -Want on -FrontImage $image }
            catch { $rb = [pscustomobject]@{ Ok = $false; Why = ('the last read failed: {0}' -f $_.Exception.Message) } }
        } until ($rb.Ok -or [datetime]::UtcNow -gt $deadline -or $PollSeconds -le 0)
        if (-not $rb.Ok) { throw ('not ready after {0} min ({1})' -f $TimeoutMinutes, $rb.Why) }
        $fqdn = ''; try { $fqdn = [string]$now.properties.configuration.ingress.fqdn } catch { }
        if ($fqdn) {
            $hc = 0
            foreach ($i in 1..4) {
                try { $hc = [int](Invoke-WebRequest -Uri "https://$fqdn/healthz" -UseBasicParsing -TimeoutSec 60).StatusCode } catch { $hc = 0 }
                if ($hc -eq 200) { break }
                if ($i -lt 4 -and $PollSeconds -gt 0) { Start-Sleep -Seconds ([Math]::Min(15, $PollSeconds)) }
            }
            if ($hc -ne 200) { throw '/healthz did not answer 200 (asked four times)' }
            $probe = Invoke-SIUpdaterAnonymousProbe -Url ("https://$fqdn/")
            if (-not (Test-SIUpdaterAnonymousRefused -Probe $probe)) { throw ('a request without a sign-in was answered with HTTP {0}, not sent to the sign-in' -f $probe.Status) }
        }
    } catch { $why = $_.Exception.Message }
    if (-not $why) { return [pscustomobject]@{ Code = 0; Text = ('{0}: signs users in through the shared sign-in front {1} now (an 8-hour session, sign-in with PKCE; read back, healthy)' -f $WebApp, $tag); Action = '' } }
    Write-UpdLog ("{0}: the move to the sign-in front FAILED ({1}) -- putting back what ran before" -f $WebApp, $why)
    try { $null = Invoke-SIUpdaterArm -Method PATCH -Path $path -Body (ConvertTo-Json -InputObject (New-SISigninFrontRestorePatch -Before $app) -Depth 60 -Compress) }
    catch { Write-UpdLog ("{0}: could NOT be put back: {1} -- restore it by hand" -f $WebApp, $_.Exception.Message) }
    [pscustomobject]@{ Code = 1; Text = ("{0}: was NOT moved to the sign-in front ({1}); what ran before was put back" -f $WebApp, $why); Action = '' }
}

function Test-SIUpdaterSigninConsent {
    <#
        CR7 consent (2026-10-18). READ ONLY. A web app behind the shared sign-in front (SI_Web_SigninFront=true, or the
        front's container in its revision) needs the organisation-wide consent to openid profile offline_access User.Read on
        its sign-in application (AzureAd__ClientId) -- without it a tenant that does not let users consent shows "Approval
        required" at sign-in. The same check setup uses (pro-management\deploy\SI-ManagementSignInCredential.ps1,
        Invoke-SISignInConsent, read only): the updater NEVER consents. Returns @{ Missing ($true = say it in the update
        result); Text ('' = nothing to say) }. Never throws; never fails the update.
    #>
    param([Parameter(Mandatory)][string]$SIRoot, [Parameter(Mandatory)][string]$ResourceGroup, [Parameter(Mandatory)][string]$SubscriptionId,
          [string]$WebApp = 'ca-si-management', $App = $null, [scriptblock]$Graph)
    $none = [pscustomobject]@{ Missing = $false; Text = '' }
    try {
        $lib = [IO.Path]::Combine($SIRoot, 'pro-management', 'deploy', 'SI-ManagementSignInCredential.ps1')
        if (-not $WebApp -or -not (Test-Path -LiteralPath $lib)) { return $none }
        if (-not (Get-Command -Name Invoke-SISignInConsent -ErrorAction SilentlyContinue)) { . $lib }
        $a = if ($App) { $App } else { Get-SIUpdaterContainerApp -App $WebApp -ResourceGroup $ResourceGroup -SubscriptionId $SubscriptionId }
        if (-not $a) { return $none }
        $front = $false; $clientId = ''
        foreach ($c in @($a.properties.template.containers)) {
            if (-not $c) { continue }
            if ([string]$c.name -eq 'signin-front') { $front = $true }
            foreach ($e in @($c.env)) {
                if (-not $e) { continue }
                if ([string]$e.name -eq 'SI_Web_SigninFront' -and "$($e.value)".Trim() -match '^(?i)(true|1|yes|on)$') { $front = $true }
                if ([string]$e.name -eq 'AzureAd__ClientId' -and [string]$e.value -match '^[0-9a-fA-F-]{36}$') { $clientId = [string]$e.value }
            }
        }
        if (-not $front) { return $none }
        if (-not $clientId) { return [pscustomobject]@{ Missing = $false; Text = ('{0}: behind the sign-in front, but its sign-in application''s client id could not be read -- the sign-in consent was not checked' -f $WebApp) } }
        if (-not $Graph) { $Graph = { param([string]$Method, [string]$Uri, $Body) Invoke-SIRestJson -Rest (Get-SIUpdaterRest) -Method $Method -Uri $Uri -Resource 'https://graph.microsoft.com/' } }
        $r = Invoke-SISignInConsent -Graph $Graph -ClientId $clientId
        switch ($r.State) {
            'in-place' { return $none }
            'planned' {
                return [pscustomobject]@{ Missing = $true
                    Text = ('{0} runs behind the sign-in front, but the sign-in permissions are not consented for the organisation (missing: {1}): a tenant that does not let users consent shows "Approval required" at sign-in. Run setup\Set-SISigninFront.ps1 -Apply (it adds the consent and reads it back), or {2}' -f $WebApp, (@($r.Missing) -join ' '), ((Get-SISignInConsentAdminText -AppName $r.AppName -ClientId $clientId) -replace '^An administrator', 'an administrator')) }
            }
            default { return [pscustomobject]@{ Missing = $false; Text = ('{0}: the sign-in consent could not be checked ({1}) -- the update goes on' -f $WebApp, $(if ($r.State -eq 'no-rights') { 'this identity may not read consents' } else { $r.Error })) } }
        }
    } catch { [pscustomobject]@{ Missing = $false; Text = ('{0}: the sign-in consent could not be checked ({1}) -- the update goes on' -f $WebApp, $_.Exception.Message) } }
}

function Set-SIUpdaterSignInOpen {
    <#
        #765 (owner 2026-10-19, "SI decides"). An install from before reaches the new-install state: the web app's
        enterprise application (the service principal of AzureAd__ClientId) no longer requires an assignment, so a person a
        SuperAdmin adds on the Access page can sign in -- the web app itself refuses every page to a signed-in person it gives
        no role. ONE small Graph write: read appRoleAssignmentRequired; true -> PATCH it to false, read back. The updater's
        identity needs a right to change that service principal (Application.ReadWrite.OwnedBy as an owner of the app, or
        Application.ReadWrite.All); without it the step says so in ONE plain line (a customer action naming the setup script
        that holds the right) and the update goes on. Never throws; never fails the update; nothing else in Entra is touched.
        Returns @{ Changed; Missing ($true = say it as a customer action); Text ('' = nothing to say) }.
    #>
    param([Parameter(Mandatory)][string]$ResourceGroup, [Parameter(Mandatory)][string]$SubscriptionId,
          [string]$WebApp = 'ca-si-management', $App = $null, [scriptblock]$Graph)
    $none = [pscustomobject]@{ Changed = $false; Missing = $false; Text = '' }
    try {
        $a = if ($App) { $App } else { Get-SIUpdaterContainerApp -App $WebApp -ResourceGroup $ResourceGroup -SubscriptionId $SubscriptionId }
        if (-not $a) { return $none }
        $clientId = ''; $tenantId = ''
        foreach ($c in @($a.properties.template.containers)) {
            if (-not $c) { continue }
            foreach ($e in @($c.env)) {
                if (-not $e) { continue }
                if ([string]$e.name -eq 'AzureAd__ClientId' -and [string]$e.value -match '^[0-9a-fA-F-]{36}$') { $clientId = [string]$e.value }
                if ([string]$e.name -eq 'AzureAd__TenantId' -and [string]$e.value -match '^[0-9a-fA-F-]{36}$') { $tenantId = [string]$e.value }
            }
        }
        if (-not $clientId) { return $none }
        if (-not $Graph) { $Graph = { param([string]$Method, [string]$Uri, $Body) Invoke-SIRestJson -Rest (Get-SIUpdaterRest) -Method $Method -Uri $Uri -Body $Body -Resource 'https://graph.microsoft.com/' } }
        $rerun = 'pro-management\deploy\New-SIManagementAppRegistration.ps1 -TenantId {0} -AppId {1} -Apply' -f $(if ($tenantId) { $tenantId } else { '<tenant id>' }), $clientId
        $sp = $null
        try { $sp = @((& $Graph 'GET' ("https://graph.microsoft.com/v1.0/servicePrincipals?`$filter=appId eq '{0}'&`$select=id,appRoleAssignmentRequired" -f $clientId) $null).value) | Select-Object -First 1 }
        catch { return [pscustomobject]@{ Changed = $false; Missing = $false; Text = ('{0}: whether people added in SecurityInsight can sign in could not be checked ({1}) -- the update goes on' -f $WebApp, $_.Exception.Message) } }
        if (-not $sp -or -not [string]$sp.id) { return $none }
        if (-not [bool]$sp.appRoleAssignmentRequired) { return $none }
        try { $null = & $Graph 'PATCH' ('https://graph.microsoft.com/v1.0/servicePrincipals/{0}' -f $sp.id) @{ appRoleAssignmentRequired = $false } }
        catch {
            $m = [string]$_.Exception.Message
            $t = if ($m -match '(?i)\b403\b|Forbidden|Authorization_RequestDenied|Insufficient privileges') {
                '{0}: people added on the Access page cannot sign in yet -- Microsoft Entra still requires an assignment on the enterprise application, and this update may not change that. Run {1} once (through the Support app); it switches it off.' -f $WebApp, $rerun
            } else {
                '{0}: people added on the Access page cannot sign in yet -- switching off "assignment required" on the enterprise application failed ({1}). Run {2} once (through the Support app).' -f $WebApp, $m, $rerun
            }
            return [pscustomobject]@{ Changed = $false; Missing = $true; Text = $t }
        }
        $back = $null
        try { $back = & $Graph 'GET' ('https://graph.microsoft.com/v1.0/servicePrincipals/{0}?$select=appRoleAssignmentRequired' -f $sp.id) $null } catch { $back = $null }
        if ($back -and -not [bool]$back.appRoleAssignmentRequired) {
            return [pscustomobject]@{ Changed = $true; Missing = $false; Text = ('{0}: people added on the Access page can sign in now (the enterprise application no longer requires an assignment; SecurityInsight decides who sees what)' -f $WebApp) }
        }
        [pscustomobject]@{ Changed = $true; Missing = $false; Text = ('{0}: "assignment required" was switched off on the enterprise application; it does not read back yet -- the next update checks it again' -f $WebApp) }
    } catch { [pscustomobject]@{ Changed = $false; Missing = $false; Text = ('{0}: whether people added in SecurityInsight can sign in could not be checked ({1}) -- the update goes on' -f $WebApp, $_.Exception.Message) } }
}

function Invoke-SIUpdaterAppRoll {
    <#
        The web app (ca-si-management) and its MCP server (ca-si-mcp) -- both editions -- when this environment has them: the app image from
        the extracted release (context = the SecurityInsight folder, as the web deploy builds it), the app pointed at it, a
        healthy revision waited for (and /healthz for the web app), the previous image restored on failure.
        Returns @{ Code; Text }. An environment without the app (a container-only install from before 2026-10-18) = nothing to do.

        #416 (the fast roll): a release that carries setup/_shared/SI-FastRoll.ps1 tags each app image by ITS OWN SOURCES
        (src-<hash>) -- an app whose sources did not change already runs that tag and is left alone, with no build. A build
        queued at the start of the run (Start-SIUpdaterPrebuilds) is waited for, not started again. Both apps are built
        first, then updated TOGETHER and waited for together; nothing changes when a build fails.
    #>
    param([Parameter(Mandatory)][string]$SIRoot, [Parameter(Mandatory)][string]$ResourceGroup, [Parameter(Mandatory)][string]$AcrName,
          [Parameter(Mandatory)][string]$SubscriptionId, [Parameter(Mandatory)][string]$LoginServer, [Parameter(Mandatory)][string]$Tag,
          [string]$WebApp = 'ca-si-management', [string]$McpApp = 'ca-si-mcp', [int]$TimeoutMinutes = 10, [int]$PollSeconds = 10)
    $plan = @(
        [pscustomobject]@{ App = $WebApp; Repo = 'si-management';     File = 'pro-management/Dockerfile';     Health = $true }
        [pscustomobject]@{ App = $McpApp; Repo = 'si-management-mcp'; File = 'pro-management/Dockerfile.mcp'; Health = $false }
    )
    $fast = [IO.Path]::Combine($SIRoot, 'setup', '_shared', 'SI-FastRoll.ps1')
    if (Test-Path -LiteralPath $fast) { . $fast }
    $done = New-Object System.Collections.Generic.List[string]
    $todo = New-Object System.Collections.Generic.List[object]
    # 1. every image first (waiting for builds already queued) -- nothing is changed until all of them are there
    foreach ($p in $plan) {
        if (-not $p.App) { continue }
        $app = $null
        try { $app = Get-SIUpdaterContainerApp -App $p.App -ResourceGroup $ResourceGroup -SubscriptionId $SubscriptionId } catch { $app = $null }
        if (-not $app) { continue }
        if (-not (Test-Path -LiteralPath (Join-Path $SIRoot $p.File))) { Write-UpdLog ("{0}: this release carries no {1} -- not rolled" -f $p.App, $p.File); continue }
        $appTag = ''
        if (Get-Command -Name Get-SIAppImageTag -ErrorAction SilentlyContinue) { try { $appTag = Get-SIAppImageTag -SIRoot $SIRoot -Repo $p.Repo } catch { $appTag = '' } }
        if (-not $appTag) { $appTag = $Tag }
        $prev = [string]$app.properties.template.containers[0].image
        $new = '{0}/{1}:{2}' -f $LoginServer, $p.Repo, $appTag
        if ($prev -eq $new) { $done.Add(("{0} already runs {1}" -f $p.App, $appTag)); continue }
        if (-not (Test-SIUpdaterImageTag -LoginServer $LoginServer -Repo $p.Repo -Tag $appTag)) {
            Write-UpdLog ("building {0}:{1}" -f $p.Repo, $appTag)
            # the release's own build context (a short copy on a deep Windows path, #350) -- _shared/SI-UpdaterSelf.ps1
            try { Invoke-SIUpdaterAcrBuild -SIRoot $SIRoot -AcrName $AcrName -SubscriptionId $SubscriptionId -Image ('{0}:{1}' -f $p.Repo, $appTag) -File $p.File -LoginServer $LoginServer }
            catch { return [pscustomobject]@{ Code = 1; Text = ("{0}: the image build failed -- nothing changed: {1}" -f $p.App, $_.Exception.Message) } }
        }
        $todo.Add([pscustomobject]@{ App = $p.App; Health = $p.Health; Prev = $prev; New = $new; Tag = $appTag; Ok = $false; State = ''; Error = ''; Fqdn = '' })
    }
    # 2. every app updated at once, then waited for together
    foreach ($t in $todo) {
        Write-UpdLog ("{0}: {1} -> {2}" -f $t.App, ($t.Prev -split '/')[-1], ($t.New -split '/')[-1])
        # one read-modify-write ARM PATCH of the app's template (#521: was `az containerapp update --image --no-wait`); ARM
        # answers at once and provisions the new revision asynchronously -- waited for below
        try { Set-SIUpdaterImage -Kind containerApps -Name $t.App -ResourceGroup $ResourceGroup -SubscriptionId $SubscriptionId -Image $t.New }
        catch { $t.Error = $_.Exception.Message }
    }
    $deadline = [datetime]::UtcNow.AddMinutes($TimeoutMinutes)
    $readFails = @{}
    do {
        $open = @($todo | Where-Object { -not $_.Ok -and -not $_.Error })
        if (-not $open.Count) { break }
        if ($PollSeconds -gt 0) { Start-Sleep -Seconds $PollSeconds }
        foreach ($t in $open) {
            try {
                $a = Get-SIUpdaterContainerApp -App $t.App -ResourceGroup $ResourceGroup -SubscriptionId $SubscriptionId
                $rev = [string]$a.properties.latestRevisionName
                $r = Invoke-SIUpdaterArm -Path (Get-SIUpdaterRgPath -SubscriptionId $SubscriptionId -ResourceGroup $ResourceGroup -Provider ('Microsoft.App/containerApps/{0}/revisions/{1}' -f $t.App, $rev))
                $t.State = '{0}/{1}/{2}' -f $r.properties.provisioningState, $r.properties.healthState, $r.properties.runningState
                if ("$($r.properties.provisioningState)" -eq 'Failed') { $t.Error = ("revision {0} failed" -f $rev); continue }
                $t.Ok = ([string]$a.properties.latestReadyRevisionName -eq $rev) -and ("$($r.properties.healthState)" -eq 'Healthy') -and ([string]$r.properties.template.containers[0].image -eq $t.New)
                if ($t.Ok) { try { $t.Fqdn = [string]$a.properties.configuration.ingress.fqdn } catch { } }
            } catch {
                # ONE read that failed (the new revision not readable yet, a server error) is "not yet", never "the update
                # failed": it is read again until the deadline, which then says what the last read answered
                $t.State = ('the last read failed: {0}' -f $_.Exception.Message)
                # (without a pause between reads -- a test -- five failed reads in a row end it, so it cannot spin)
                $readFails[[string]$t.App] = 1 + [int]$readFails[[string]$t.App]
                if ($PollSeconds -le 0 -and [int]$readFails[[string]$t.App] -ge 5) { $t.Error = $t.State }
            }
        }
    } until ([datetime]::UtcNow -gt $deadline)
    foreach ($t in $todo) {
        if (-not $t.Ok -and -not $t.Error) { $t.Error = ("not healthy after {0} min ({1})" -f $TimeoutMinutes, $t.State) }
        if ($t.Ok -and $t.Health -and $t.Fqdn) {
            # asked up to four times: a revision that was healthy a second ago can still be taking its first request
            $hc = 0
            foreach ($hcTry in 1..4) {
                try { $hc = [int](Invoke-WebRequest -Uri "https://$($t.Fqdn)/healthz" -UseBasicParsing -TimeoutSec 60).StatusCode } catch { $hc = 0 }
                if ($hc -eq 200) { break }
                if ($hcTry -lt 4 -and $PollSeconds -gt 0) { Start-Sleep -Seconds ([Math]::Min(15, $PollSeconds)) }
            }
            if ($hc -ne 200) { $t.Ok = $false; $t.Error = '/healthz did not answer 200 (asked four times)' }
        }
        if ($t.Ok) { $done.Add(("{0} runs {1} (healthy)" -f $t.App, $t.Tag)) }
    }
    $failed = @($todo | Where-Object { -not $_.Ok })
    foreach ($t in $failed) {
        Write-UpdLog ("{0}: the update FAILED ({1}) -- restoring {2}" -f $t.App, $t.Error, ($t.Prev -split '/')[-1])
        try { Set-SIUpdaterImage -Kind containerApps -Name $t.App -ResourceGroup $ResourceGroup -SubscriptionId $SubscriptionId -Image $t.Prev }
        catch { Write-UpdLog ("{0}: could NOT be restored to {1}: {2} -- restore it by hand" -f $t.App, $t.Prev, $_.Exception.Message) }
    }
    if ($failed.Count) { return [pscustomobject]@{ Code = 1; Text = (($failed | ForEach-Object { '{0}: {1}' -f $_.App, $_.Error }) -join '; ') } }
    # the 8-hour session with PKCE: a web app from before the front is moved behind it once everything it needs reads back
    # (what is missing in Microsoft Entra = one customer action; a chosen own sign-in is kept)
    $ad = Invoke-SIUpdaterSigninFrontAdopt -SIRoot $SIRoot -ResourceGroup $ResourceGroup -AcrName $AcrName -SubscriptionId $SubscriptionId -LoginServer $LoginServer `
              -WebApp $WebApp -TimeoutMinutes $TimeoutMinutes -PollSeconds $PollSeconds
    if ($ad.Code -ne 0) { return [pscustomobject]@{ Code = 1; Text = $ad.Text } }
    if ($ad.Text) { $done.Add($ad.Text) }
    if ($ad.Action -and (Get-Command -Name Add-SIUpdaterCustomerAction -ErrorAction SilentlyContinue)) { Add-SIUpdaterCustomerAction -Step 'post-roll' -Text $ad.Action -Class 'config-missing' }
    # CR7: a web app that runs behind the shared sign-in front gets the release's pinned front too (one that does not: nothing)
    $sf = Invoke-SIUpdaterSigninFrontRoll -SIRoot $SIRoot -ResourceGroup $ResourceGroup -AcrName $AcrName -SubscriptionId $SubscriptionId -LoginServer $LoginServer `
              -WebApp $WebApp -TimeoutMinutes $TimeoutMinutes -PollSeconds $PollSeconds
    if ($sf.Code -ne 0) { return [pscustomobject]@{ Code = 1; Text = $sf.Text } }
    if ($sf.Text) { $done.Add($sf.Text) }
    # CR7 consent: behind the front without the organisation-wide sign-in consent = said in the update result (a customer
    # action, never a failure of the update); the updater never consents itself
    $cn = Test-SIUpdaterSigninConsent -SIRoot $SIRoot -ResourceGroup $ResourceGroup -SubscriptionId $SubscriptionId -WebApp $WebApp
    if ($cn.Text) { Write-UpdLog ('NOTE: ' + $cn.Text); $done.Add($cn.Text) }
    if ($cn.Missing -and (Get-Command -Name Add-SIUpdaterCustomerAction -ErrorAction SilentlyContinue)) { Add-SIUpdaterCustomerAction -Step 'post-roll' -Text $cn.Text -Class 'config-missing' }
    # #765: SecurityInsight decides who has access -- the enterprise application stops requiring an assignment, so a person
    # added on the Access page can sign in (AFTER the new web app is healthy: it is the one that refuses a person with no
    # role). No right to change it = one customer action, never a failure of the update.
    $so = Set-SIUpdaterSignInOpen -ResourceGroup $ResourceGroup -SubscriptionId $SubscriptionId -WebApp $WebApp
    if ($so.Text) { Write-UpdLog ('NOTE: ' + $so.Text); $done.Add($so.Text) }
    if ($so.Missing -and (Get-Command -Name Add-SIUpdaterCustomerAction -ErrorAction SilentlyContinue)) { Add-SIUpdaterCustomerAction -Step 'post-roll' -Text $so.Text -Class 'config-missing' }
    [pscustomobject]@{ Code = 0; Text = $(if ($done.Count) { $done -join '; ' } else { 'no web app in this environment' }) }
}
