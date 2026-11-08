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

$script:SIUpdaterAppRegistrationUrl = 'https://invardia.com/support/si/New-SIManagementAppRegistration.ps1'

function Get-SIUpdaterWebAppCandidates {
    <# PURE. The web app's container app names to try, in order: -WebApp when given; else the install record's name and
       SI_UPDATER_WEB_APP when set, then the framework name ca-si-web, then ca-si-management (the name installs still carry). #>
    param([string]$WebApp = '', [string]$RecordName = '', [string]$EnvName = '')
    if ("$WebApp".Trim()) { return "$WebApp".Trim() }
    $out = New-Object System.Collections.Generic.List[string]
    foreach ($n in @($RecordName, $EnvName, 'ca-si-web', 'ca-si-management')) {
        $v = "$n".Trim()
        if ($v -and -not @($out | Where-Object { $_ -ieq $v }).Count) { $out.Add($v) }
    }
    $out.ToArray()
}

function Get-SIUpdaterSignInOpenAction {
    <# PURE. The customer action of a sign-in that still needs an assignment: the PUBLISHED script with -TenantId and -AppId
       filled. -Kind: forbidden (this update may not change it) | failed (-Reason: the answer). #>
    param([Parameter(Mandatory)][string]$WebApp, [Parameter(Mandatory)][string]$ClientId, [string]$TenantId = '', [ValidateSet('forbidden', 'failed')][string]$Kind = 'forbidden', [string]$Reason = '')
    $run = 'download {0} and run it once with -TenantId {1} -AppId {2} -Apply (an administrator who may change the application, or Invardia support); it switches it off' -f $script:SIUpdaterAppRegistrationUrl, $(if ("$TenantId".Trim()) { "$TenantId".Trim() } else { '<tenant id>' }), $ClientId
    if ($Kind -eq 'forbidden') {
        return ('{0}: people added on the Access page cannot sign in yet -- Microsoft Entra still requires an assignment on the enterprise application, and this update may not change that. To switch it off, {1}.' -f $WebApp, $run)
    }
    '{0}: people added on the Access page cannot sign in yet -- switching off "assignment required" on the enterprise application failed ({1}). To switch it off, {2}.' -f $WebApp, $Reason, $run
}

function ConvertTo-SIUpdaterGraphBool {
    <# PURE. A Graph boolean as $true / $false; the text 'true' / 'false' (any case) likewise; anything else -- $null, an empty
       value, another text -- is $null (not known). Never [bool] of a text: [bool]'False' is $true. #>
    param([AllowNull()]$Value)
    if ($Value -is [bool]) { return $Value }
    if ($null -eq $Value) { return $null }
    $s = "$Value".Trim()
    if ($s -ieq 'true') { return $true }
    if ($s -ieq 'false') { return $false }
    $null
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
          [string]$WebApp = '', $App = $null, [scriptblock]$Graph)
    $none = [pscustomobject]@{ Changed = $false; Missing = $false; Text = '' }
    try {
        # the web app's name: the one given, else the install record's / SI_UPDATER_WEB_APP, else ca-si-web (the framework
        # name), else ca-si-management (the name installs still carry)
        $a = $App
        if (-not $a) {
            $rec = ''; if (Get-Command -Name Get-SIInstallNameProp -ErrorAction SilentlyContinue) { try { $rec = [string](Get-SIInstallNameProp -Record $global:SI_InstallNames -Role 'web') } catch { $rec = '' } }
            foreach ($cand in (Get-SIUpdaterWebAppCandidates -WebApp $WebApp -RecordName $rec -EnvName ([string][Environment]::GetEnvironmentVariable('SI_UPDATER_WEB_APP')))) {
                $a = Get-SIUpdaterContainerApp -App $cand -ResourceGroup $ResourceGroup -SubscriptionId $SubscriptionId
                if ($a) { $WebApp = $cand; break }
            }
        }
        if (-not $WebApp) { $WebApp = 'ca-si-web' }
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
        $sp = $null
        try { $sp = @((& $Graph 'GET' ("https://graph.microsoft.com/v1.0/servicePrincipals?`$filter=appId eq '{0}'&`$select=id,appRoleAssignmentRequired" -f $clientId) $null).value) | Select-Object -First 1 }
        catch { return [pscustomobject]@{ Changed = $false; Missing = $false; Text = ('{0}: whether people added in SecurityInsight can sign in could not be checked ({1}) -- the update goes on' -f $WebApp, $_.Exception.Message) } }
        if (-not $sp -or -not [string]$sp.id) { return $none }
        # ONLY a value that reads as TRUE is acted on: [bool] of the TEXT "False" is $true in PowerShell, and a value the
        # read did not carry ($null) is not known -- neither may ever become "still requires an assignment" (fix request,
        # 2026-11-07: an install whose enterprise application read false was told it still required one)
        $req = ConvertTo-SIUpdaterGraphBool -Value $(if ($sp.PSObject.Properties['appRoleAssignmentRequired']) { $sp.appRoleAssignmentRequired } else { $null })
        if ($req -ne $true) { return $none }
        try { $null = & $Graph 'PATCH' ('https://graph.microsoft.com/v1.0/servicePrincipals/{0}' -f $sp.id) @{ appRoleAssignmentRequired = $false } }
        catch {
            $m = [string]$_.Exception.Message
            # read once more before anything is said: switched off in the meantime (or not readable) = nothing to say
            $now = $null
            try { $r2 = & $Graph 'GET' ('https://graph.microsoft.com/v1.0/servicePrincipals/{0}?$select=appRoleAssignmentRequired' -f $sp.id) $null; if ($r2 -and $r2.PSObject.Properties['appRoleAssignmentRequired']) { $now = ConvertTo-SIUpdaterGraphBool -Value $r2.appRoleAssignmentRequired } } catch { $now = $null }
            if ($now -ne $true) { return $none }
            $kind = if ($m -match '(?i)\b403\b|Forbidden|Authorization_RequestDenied|Insufficient privileges') { 'forbidden' } else { 'failed' }
            $t = Get-SIUpdaterSignInOpenAction -WebApp $WebApp -ClientId $clientId -TenantId $tenantId -Kind $kind -Reason $m
            return [pscustomobject]@{ Changed = $false; Missing = $true; Text = $t }
        }
        $back = $null
        try { $back = & $Graph 'GET' ('https://graph.microsoft.com/v1.0/servicePrincipals/{0}?$select=appRoleAssignmentRequired' -f $sp.id) $null } catch { $back = $null }
        if ($back -and $back.PSObject.Properties['appRoleAssignmentRequired'] -and (ConvertTo-SIUpdaterGraphBool -Value $back.appRoleAssignmentRequired) -eq $false) {
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

# ---------------------------------------------------------------------------------------------------------------------------
# THE SIGN-IN APP OWNED BY THE INSTALL'S UPDATER, THEN THE WEB APP UNDER ITS FRAMEWORK NAME ca-si-web
# (framework SECAUDIT-1a item 2 and the framework's name table: Web = ca-si-web). Two idempotent steps at the end of an
# update that did not fail (Invoke-SIUpdaterWebAppSteps, called from Start-SIUpdater.ps1). Both are ON unless the updater
# job says SI_UPDATER_WEB_APP_MOVE=off. Neither ever throws or fails the update; each says ONE plain line per outcome and
# records its state in cfg.InstallState ('SignInAppOwner', 'WebAppName'). What the updater may not do itself is said as a
# Support-app step, never as a customer action.
# ---------------------------------------------------------------------------------------------------------------------------

function Get-SIUpdaterGraphRoleIds {
    <# PURE. The Microsoft Graph application permissions the owner step looks for on the updater's identity (the same ids in
       every tenant). A table in a function, so a caller that dot-sources this file from another scope still sees it. #>
    [ordered]@{
        OwnedBy = '18a4783c-866b-4cc7-a460-3d5e5662c884'   # Application.ReadWrite.OwnedBy
        All     = '1bfefb4e-e0b5-418b-a88f-73c46d2cc8e9'   # Application.ReadWrite.All
    }
}

function Test-SIUpdaterWebAppMoveOn {
    <# PURE. SI_UPDATER_WEB_APP_MOVE: both web app steps run unless it says off (off / 0 / false / no). Unset = ON. #>
    param([AllowNull()][AllowEmptyString()][string]$Value)
    -not ("$Value".Trim() -match '^(?i)(off|0|false|no)$')
}

function Get-SIUpdaterWebAppSetting {
    <# PURE. One setting (env) of an app's or job's containers ('' = none). #>
    param($App, [Parameter(Mandatory)][string]$Name)
    if (-not $App -or -not $App.properties -or -not $App.properties.template) { return '' }
    foreach ($c in @($App.properties.template.containers)) {
        if (-not $c) { continue }
        foreach ($e in @($c.env)) { if ($e -and [string]$e.name -eq $Name -and "$($e.value)".Trim()) { return "$($e.value)".Trim() } }
    }
    ''
}

function ConvertTo-SIUpdaterStepStateValue {
    <# PURE. A web app step's state row: compact JSON, at most 400 characters (cfg.InstallState.Value). #>
    param([Parameter(Mandatory)][string]$State, [hashtable]$More = @{}, [string]$Why = '', [datetime]$NowUtc = [datetime]::UtcNow)
    $o = [ordered]@{ state = $State }
    foreach ($k in @($More.Keys | Sort-Object)) { if ("$($More[$k])".Trim()) { $o[[string]$k] = "$($More[$k])".Trim() } }
    $w = "$Why".Trim(); if ($w.Length -gt 180) { $w = $w.Substring(0, 177) + '...' }
    if ($w) { $o['why'] = $w }
    $o['checkedUtc'] = $NowUtc.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ', [Globalization.CultureInfo]::InvariantCulture)
    $j = $o | ConvertTo-Json -Compress
    if ($j.Length -gt 400 -and $o.Contains('why')) { $o.Remove('why'); $j = $o | ConvertTo-Json -Compress }
    $j
}

function New-SIUpdaterOwnerNotes {
    <# PURE. The registration's notes with the updater's check as one line of its own: an earlier check line replaced, every
       other line kept. Never cuts the notes: when the line does not fit Microsoft Entra's 1024 characters, the notes are
       written back unchanged (the write is the proof either way). #>
    param([AllowNull()][AllowEmptyString()][string]$Notes, [datetime]$NowUtc = [datetime]::UtcNow)
    $mark = 'SecurityInsight updater: may change this registration as its owner (checked {0})' -f $NowUtc.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ', [Globalization.CultureInfo]::InvariantCulture)
    $keep = @("$Notes" -split "`r?`n" | Where-Object { "$_".Trim() -and "$_" -notmatch '^SecurityInsight updater: may change this registration' })
    $out = (@($keep) + @($mark)) -join "`n"
    if ($out.Length -gt 1024) { return "$Notes" }
    $out
}

function Get-SIUpdaterGraphIdentity {
    <# The updater's own Microsoft Graph sign-in, read from its token (-Token { } -> the token: a test seam; default the run's
       token function): @{ ObjectId (oid: its service principal); AppId; Roles (the application permissions it holds) }.
       $null when no token can be read. Never throws. #>
    param([scriptblock]$Token)
    try {
        $t = if ($Token) { & $Token } else { Get-SIAzureToken -Audience Graph }
        if ($t -is [securestring]) { $t = (New-Object System.Net.NetworkCredential('', $t)).Password }
        $parts = @("$t".Split('.'))
        if ($parts.Count -lt 2) { return $null }
        $p = $parts[1].Replace('-', '+').Replace('_', '/')
        switch ($p.Length % 4) { 2 { $p += '==' } 3 { $p += '=' } }
        $o = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($p)) | ConvertFrom-Json
        if (-not "$($o.oid)".Trim()) { return $null }
        [pscustomobject]@{ ObjectId = "$($o.oid)".Trim(); AppId = "$($o.appid)".Trim(); Roles = @(@($o.roles) | Where-Object { $_ } | ForEach-Object { [string]$_ }) }
    } catch { $null }
}

function Read-SIUpdaterSupportAppId {
    <# The Invardia Support app's client id the install records (cfg.InstallState 'SupportApp', written by the support setup);
       '' when none is recorded or it cannot be read. Never throws. #>
    param($Store)
    if (-not $Store -or -not $Store.Invoke) { return '' }
    try {
        $row = @(& $Store.Invoke "IF OBJECT_ID('cfg.InstallState') IS NOT NULL SELECT Value FROM cfg.InstallState WHERE Name = N'SupportApp';" ([ordered]@{}) 'reader' | ForEach-Object { $_ } | Where-Object { $_ }) | Select-Object -First 1
        if (-not $row) { return '' }
        $v = if ($row -is [System.Collections.IDictionary]) { [string]$row['Value'] } elseif ($row.PSObject.Properties['Value']) { [string]$row.Value } else { [string]$row }
        if ("$v".Trim() -match '^[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$') { return "$v".Trim() }
        ''
    } catch { '' }
}

function Invoke-SIUpdaterSignInAppOwner {
    <#
        THE WEB SIGN-IN APP OWNED BY THE INSTALL'S UPDATER (framework SECAUDIT-1a item 2). The sign-in app is the application
        registration of the web app's AzureAd__ClientId (shared with the MCP server). Idempotent, in this order:
          1. is the updater's identity (-UpdaterClientId, SI_UPDATER_CLIENT_ID) an owner? If not it adds itself -- which works
             only when it already holds the right; a refusal is ONE plain line that a Support-app step adds it (never a
             customer action), and nothing else is done. Read back.
          2. does it hold Application.ReadWrite.OwnedBy (the roles in its own Graph token, else its app role assignments)?
             Not held = one line, a Support-app step grants it. Not readable = the proof below decides.
             (Who the updater is comes from the same token -- its oid -- else from the directory; a registration the
             updater may not even read is the same Support-app line as in 1.)
          3. the PROOF, when there is something to change (-ProveWrite: the web app still has to move; or the Support app is an
             owner): a harmless change of the registration's notes as its owner, read back.
          4. only after the proof: every owner that is the Invardia Support app (the client id the install records,
             -SupportAppId) is removed, read back. Never a person, never any other identity, never the updater itself; never
             an owner whose removal would leave the updater out (the registration is never ownerless).
        Never throws, never fails the update. Returns @{ State ('' = nothing here: no web app sign-in | owned |
        owned-support-kept | needs-support-step | needs-permission | proof-failed | unknown); Owned ($true = the updater
        owns it and may change it); Text ('' = nothing to say); Why; ClientId; ObjectId }.
    #>
    param([string]$WebApp = 'ca-si-web', $App = $null, [string]$UpdaterClientId = '', [string]$SupportAppId = '',
          [switch]$ProveWrite, [scriptblock]$Graph, [scriptblock]$WhoAmI, [datetime]$NowUtc = [datetime]::UtcNow,
          # the wait between two read-backs of the proof (test seam: no real sleep)
          [scriptblock]$ProofSleep = { param([int]$s) Start-Sleep -Seconds $s })
    $clientId = ''; $objId = ''
    $res = { param([string]$State, [bool]$Owned, [string]$Text, [string]$Why = '')
        [pscustomobject]@{ State = $State; Owned = $Owned; Text = $Text; Why = $Why; ClientId = $clientId; ObjectId = $objId } }
    try {
        $clientId = Get-SIUpdaterWebAppSetting -App $App -Name 'AzureAd__ClientId'
        if ($clientId -notmatch '^[0-9a-fA-F-]{36}$') { $clientId = ''; return (& $res '' $false '') }
        if ("$UpdaterClientId".Trim() -notmatch '^[0-9a-fA-F-]{36}$') { return (& $res 'unknown' $false ("{0}: who owns its sign-in app ({1}) was not checked -- this updater's client id is not known" -f $WebApp, $clientId)) }
        if (-not $Graph) { $Graph = { param([string]$Method, [string]$Uri, $Body) Invoke-SIRestJson -Rest (Get-SIUpdaterRest) -Method $Method -Uri $Uri -Body $Body -Resource 'https://graph.microsoft.com/' } }
        $g = 'https://graph.microsoft.com/v1.0'
        # who the updater is and what it holds: its own Graph token first (oid + roles -- no directory right needed), the
        # directory as the fallback (an identity with Application.ReadWrite.OwnedBy alone may not read either)
        $tok = if ($WhoAmI) { & $WhoAmI } else { Get-SIUpdaterGraphIdentity }
        if ($tok -and "$($tok.AppId)".Trim() -and "$($tok.AppId)".Trim() -ine $UpdaterClientId.Trim()) { $tok = $null }
        $meId = if ($tok -and "$($tok.ObjectId)".Trim()) { "$($tok.ObjectId)".Trim() } else { '' }
        $who = $UpdaterClientId.Trim()
        $me = $null
        try { $me = @(@((& $Graph 'GET' ("$g/servicePrincipals?`$filter=appId eq '{0}'&`$select=id,appId,displayName" -f $UpdaterClientId.Trim()) $null).value) | Where-Object { $_ }) | Select-Object -First 1 } catch { $me = $null }
        if ($me -and [string]$me.id) {
            if (-not $meId) { $meId = [string]$me.id }
            if ("$($me.displayName)".Trim()) { $who = '{0} ({1})' -f "$($me.displayName)".Trim(), $UpdaterClientId.Trim() }
        }
        if (-not $meId) { return (& $res 'unknown' $false ("{0}: this updater's own identity ({1}) could not be read -- who owns its sign-in app ({2}) was not checked" -f $WebApp, $UpdaterClientId.Trim(), $clientId)) }
        $reg = $null
        try { $reg = & $Graph 'GET' ("$g/applications(appId='{0}')?`$select=id,appId,displayName,notes" -f $clientId) $null }
        catch {
            $m = [string]$_.Exception.Message
            # an identity that does not own the registration (and holds no directory-wide right) may not even read it
            if (Test-SIUpdaterReadRefused -Message $m) {
                return (& $res 'needs-support-step' $false ("{0}: its sign-in app ({1}) is not owned by this install's updater {2} yet, and the updater may not read or change it -- a Support-app step adds the updater as an owner; the next update takes it from there" -f $WebApp, $clientId, $who) $m)
            }
            return (& $res 'unknown' $false ("{0}: who owns its sign-in app ({1}) could not be read ({2}) -- nothing was changed; the next update checks again" -f $WebApp, $clientId, $m) $m)
        }
        if (-not $reg -or -not [string]$reg.id) { return (& $res 'unknown' $false ("{0}: its sign-in app ({1}) was not found in the directory -- nothing was changed" -f $WebApp, $clientId)) }
        $objId = [string]$reg.id
        # (no $select: the owners are directory objects of several kinds -- a person has no appId)
        $readOwners = { @(@((& $Graph 'GET' ("$g/applications/{0}/owners" -f $objId) $null).value) | Where-Object { $_ }) }
        $isOwner = { param($List) [bool]@(@($List) | Where-Object { $_ -and [string]$_.id -eq $meId }).Count }
        $owners = @(& $readOwners)
        $added = $false
        # 1. the updater an owner (it can add itself only when it already holds the right)
        if (-not (& $isOwner $owners)) {
            try { $null = & $Graph 'POST' ("$g/applications/{0}/owners/`$ref" -f $objId) @{ '@odata.id' = ("$g/directoryObjects/{0}" -f $meId) } }
            catch {
                $m = [string]$_.Exception.Message
                if (Test-SIUpdaterReadRefused -Message $m) {
                    return (& $res 'needs-support-step' $false ("{0}: its sign-in app ({1}) is not owned by this install's updater {2} yet, and the updater may not add itself -- a Support-app step adds the updater as an owner; the next update takes it from there" -f $WebApp, $clientId, $who) $m)
                }
                return (& $res 'unknown' $false ("{0}: this install's updater {1} could not be added as an owner of its sign-in app ({2}): {3} -- the next update tries again" -f $WebApp, $who, $clientId, $m) $m)
            }
            $owners = @(& $readOwners)
            if (-not (& $isOwner $owners)) { return (& $res 'unknown' $false ("{0}: this install's updater {1} was added as an owner of its sign-in app ({2}), but it does not read back yet -- the next update checks again" -f $WebApp, $who, $clientId)) }
            $added = $true
        }
        # 2. the right to change what it owns
        $ids = Get-SIUpdaterGraphRoleIds
        $right = 'unknown'
        if ($tok -and $tok.PSObject.Properties['Roles'] -and $null -ne $tok.Roles) {
            $names = @($tok.Roles | ForEach-Object { [string]$_ })
            $right = if ($names -contains 'Application.ReadWrite.OwnedBy') { 'owned-by' } elseif ($names -contains 'Application.ReadWrite.All') { 'all' } else { 'none' }
        } else {
            try {
                $roleIds = @(@((& $Graph 'GET' ("$g/servicePrincipals/{0}/appRoleAssignments" -f $meId) $null).value) | Where-Object { $_ } | ForEach-Object { [string]$_.appRoleId })
                $right = if ($roleIds -contains $ids.OwnedBy) { 'owned-by' } elseif ($roleIds -contains $ids.All) { 'all' } else { 'none' }
            } catch { $right = 'unknown' }
        }
        if ($right -eq 'none') {
            return (& $res 'needs-permission' $false ("{0}: this install's updater {1} owns its sign-in app ({2}) but does not hold the Microsoft Graph permission Application.ReadWrite.OwnedBy -- a Support-app step grants it; nothing else was changed" -f $WebApp, $who, $clientId))
        }
        $support = @()
        if ("$SupportAppId".Trim() -match '^[0-9a-fA-F-]{36}$') {
            $support = @($owners | Where-Object { [string]$_.appId -ieq "$SupportAppId".Trim() -and [string]$_.id -ne $meId -and [string]$_.'@odata.type' -ne '#microsoft.graph.user' })
        }
        $ownText = if ($added) { "{0}: its sign-in app ({1}) is owned by this install's updater {2} now (read back)" -f $WebApp, $clientId, $who } else { '' }
        if (-not $support.Count -and -not $ProveWrite) { return (& $res 'owned' $true $ownText) }
        # 3. the proof: a harmless change as the owner, read back -- nothing is removed before it
        try {
            $want = New-SIUpdaterOwnerNotes -Notes ([string]$reg.notes) -NowUtc $NowUtc
            $null = & $Graph 'PATCH' ("$g/applications/{0}" -f $objId) @{ notes = $want }
            # Microsoft Entra is eventually consistent: a read right after the write can still answer the old value (live
            # 2026-11-07: the change had landed, the immediate read missed it) -- read back a few times before it counts
            $back = $null
            foreach ($w in @(0, 3, 5, 10, 15)) {
                if ($w -gt 0) { & $ProofSleep $w }
                $back = & $Graph 'GET' ("$g/applications/{0}?`$select=notes" -f $objId) $null
                if ($back -and [string]$back.notes -ceq $want) { break }
            }
            if (-not $back -or [string]$back.notes -cne $want) { throw 'the change did not read back' }
        } catch {
            $m = [string]$_.Exception.Message
            $kept = if ($support.Count) { ' -- the Support app stays an owner' } else { '' }
            return (& $res 'proof-failed' $false ("{0}: this install's updater {1} could not prove it may change its sign-in app ({2}): {3}{4}; the next update tries again" -f $WebApp, $who, $clientId, $m, $kept) $m)
        }
        if (-not $support.Count) {
            $t = if ($added) { $ownText + ' and proved it may change it' } else { '' }
            if (-not "$SupportAppId".Trim() -and $t) { $t += ' (no Support app is recorded on this install, so no other owner was touched)' }
            return (& $res 'owned' $true $t)
        }
        # 4. the Support app removed as an owner -- never leaving the updater out, never ownerless
        $failed = ''
        foreach ($s in $support) {
            $left = @($owners | Where-Object { [string]$_.id -ne [string]$s.id })
            if (-not (& $isOwner $left)) { $failed = 'the updater would not be left as an owner'; break }
            try { $null = & $Graph 'DELETE' ("$g/applications/{0}/owners/{1}/`$ref" -f $objId, [string]$s.id) $null; $owners = $left }
            catch { $failed = [string]$_.Exception.Message; break }
        }
        $now = @(); $readOk = $true
        try { $now = @(& $readOwners) } catch { $readOk = $false; if (-not $failed) { $failed = 'the owners could not be read back' } }
        $still = @($now | Where-Object { [string]$_.appId -ieq "$SupportAppId".Trim() })
        if ($failed -or -not $readOk -or $still.Count -or -not (& $isOwner $now)) {
            $why = if ($failed) { $failed } elseif ($still.Count) { 'it still reads back as an owner' } else { 'the updater did not read back as an owner' }
            return (& $res 'owned-support-kept' $true ("{0}: this install's updater {1} owns its sign-in app ({2}) and proved it may change it; the Support app is still an owner ({3}) -- the next update tries again" -f $WebApp, $who, $clientId, $why) $why)
        }
        & $res 'owned' $true ("{0}: its sign-in app ({1}) is owned by this install's updater {2}, which proved it may change it; the Support app is no longer an owner (read back)" -f $WebApp, $clientId, $who)
    } catch { & $res 'unknown' $false ("{0}: who owns its sign-in app could not be checked ({1}) -- the update goes on; the next update checks again" -f $WebApp, $_.Exception.Message) $_.Exception.Message }
}

function New-SIUpdaterWebAppCopyBody {
    <#
        PURE. The ARM body that makes the new web app from the running one (-App, its ARM shape) and its secrets (-Secrets,
        the listSecrets answer's value[]): the same location, tags, user-assigned identity, Container Apps environment,
        workload profile, configuration (registries, every secret with its value or its Key Vault reference, the ingress
        without its address and custom domains, all traffic on the latest revision) and template (image, settings, secret
        references, resources, probes, scale, volumes; no revision suffix). Throws when the app has a system-assigned
        identity (its grants would not move), no user-assigned identity, or a secret that did not come back.
    #>
    param([Parameter(Mandatory)]$App, [object[]]$Secrets = @())
    $copy = ConvertTo-Json -InputObject $App -Depth 60 | ConvertFrom-Json
    $p = $copy.properties
    if (-not $p) { throw 'its properties could not be read' }
    $idType = if ($copy.identity) { "$($copy.identity.type)" } else { '' }
    if ($idType -match '(?i)SystemAssigned') { throw 'it has a system-assigned identity, whose grants would not move with it' }
    $uai = [ordered]@{}
    if ($copy.identity -and $copy.identity.userAssignedIdentities) { foreach ($n in @($copy.identity.userAssignedIdentities.PSObject.Properties.Name)) { $uai[$n] = @{} } }
    if (-not $uai.Count) { throw 'it has no user-assigned identity' }
    $envId = if ("$($p.environmentId)".Trim()) { [string]$p.environmentId } else { [string]$p.managedEnvironmentId }
    if (-not "$envId".Trim()) { throw 'its Container Apps environment could not be read' }
    $sec = @(foreach ($s in @($Secrets)) {
        if (-not $s -or -not "$($s.name)".Trim()) { continue }
        if ("$($s.keyVaultUrl)".Trim()) { [ordered]@{ name = [string]$s.name; keyVaultUrl = [string]$s.keyVaultUrl; identity = [string]$s.identity } }
        else { [ordered]@{ name = [string]$s.name; value = [string]$s.value } }
    })
    $cfg = $p.configuration
    $named = @(if ($cfg -and $cfg.PSObject.Properties['secrets']) { @($cfg.secrets) | Where-Object { $_ } | ForEach-Object { [string]$_.name } })
    $have = @($sec | ForEach-Object { [string]$_.name })
    $missing = @($named | Where-Object { $have -notcontains $_ })
    if ($missing.Count) { throw ('its secret(s) {0} could not be read' -f ($missing -join ', ')) }
    if ($cfg) {
        if ($cfg.PSObject.Properties['secrets']) { $cfg.secrets = $sec } elseif ($sec.Count) { $cfg | Add-Member -NotePropertyName secrets -NotePropertyValue $sec }
        if ($cfg.PSObject.Properties['ingress'] -and $cfg.ingress) {
            foreach ($n in 'fqdn', 'customDomains') { if ($cfg.ingress.PSObject.Properties[$n]) { $cfg.ingress.PSObject.Properties.Remove($n) } }
            if ($cfg.ingress.PSObject.Properties['traffic']) { $cfg.ingress.traffic = @([ordered]@{ latestRevision = $true; weight = 100 }) }
        }
    }
    $tpl = $p.template
    if ($tpl -and $tpl.PSObject.Properties['revisionSuffix']) { $tpl.PSObject.Properties.Remove('revisionSuffix') }
    # the old app's "moved to" setting never travels into the new app
    foreach ($c in @(if ($tpl) { @($tpl.containers) | Where-Object { $_ -and $_.PSObject.Properties['env'] } })) { $c.env = @(@($c.env) | Where-Object { $_ -and [string]$_.name -ne 'SIGNIN_FRONT_MOVED_TO' }) }
    $props = [ordered]@{ environmentId = $envId }
    if ("$($p.workloadProfileName)".Trim()) { $props['workloadProfileName'] = [string]$p.workloadProfileName }
    $props['configuration'] = $cfg
    $props['template'] = $tpl
    $body = [ordered]@{ location = [string]$copy.location }
    if ($copy.PSObject.Properties['tags'] -and $copy.tags) { $body['tags'] = $copy.tags }
    $body['identity'] = [ordered]@{ type = 'UserAssigned'; userAssignedIdentities = $uai }
    $body['properties'] = $props
    $body
}

function Test-SIUpdaterSignInStart {
    <# PURE. An anonymous page request on -Fqdn is sent to the Microsoft Entra sign-in with redirect_uri
       https://<fqdn>/signin-oidc (the web app's own address, not the old one). #>
    param([Parameter(Mandatory)]$Probe, [Parameter(Mandatory)][string]$Fqdn)
    if ([int]$Probe.Status -notin @(301, 302, 303, 307, 308)) { return $false }
    $loc = [string]$Probe.Location
    if ($loc -notmatch '^https://login\.microsoftonline\.com/') { return $false }
    $q = ''; if ($loc -match '\?(.*)$') { $q = $Matches[1] }
    $ru = ''
    foreach ($kv in @($q -split '&')) {
        $pair = @($kv -split '=', 2)
        if ($pair.Count -eq 2 -and $pair[0] -eq 'redirect_uri') { $ru = [uri]::UnescapeDataString($pair[1].Replace('+', ' ')) }
    }
    $ru -ieq ('https://{0}/signin-oidc' -f $Fqdn)
}

function New-SIUpdaterEnvPatchBody {
    <# PURE. A job's or app's template with ONE setting (-Name) set to -Value -- in every container that carries it, else in
       the first container -- as the ARM PATCH body { properties: { template } }. #>
    param([Parameter(Mandatory)]$Resource, [Parameter(Mandatory)][string]$Name, [Parameter(Mandatory)][string]$Value)
    $tpl = ConvertTo-Json -InputObject $Resource.properties.template -Depth 60 | ConvertFrom-Json
    $cs = @($tpl.containers | Where-Object { $_ })
    $hit = $false
    foreach ($c in $cs) { foreach ($e in @($c.env)) { if ($e -and [string]$e.name -eq $Name) { $e.value = $Value; $hit = $true } } }
    if (-not $hit -and $cs.Count) {
        $first = $cs[0]
        $list = @(@($first.env) | Where-Object { $_ }) + @([pscustomobject]@{ name = $Name; value = $Value })
        if ($first.PSObject.Properties['env']) { $first.env = $list } else { $first | Add-Member -NotePropertyName env -NotePropertyValue $list }
    }
    [ordered]@{ properties = [ordered]@{ template = $tpl } }
}

function Get-SIUpdaterFrontContainer {
    <# PURE. The sign-in front container (by name) of an app's template, $null when the app has none. #>
    param($App, [string]$Container = 'signin-front')
    $cs = @(if ($App -and $App.properties -and $App.properties.template) { @($App.properties.template.containers) | Where-Object { $_ } })
    @($cs | Where-Object { [string]$_.name -eq $Container })[0]
}

function New-SIUpdaterMovedToPatchBody {
    <#
        PURE. The OLD web app's PATCH that makes its sign-in front send every request to the new web app BEFORE any sign-in
        (signin-front 1.5.0 SIGNIN_FRONT_MOVED_TO, framework 12.11g "Moving a web app"): on the front container only, the
        setting = -BaseUrl and -- when given -- the front's image = -Image (the new web app's front, so the old app runs a front
        that knows the setting); every other container, setting and the scale sent as read. $null when the app has no front
        (it keeps the web app's own redirect, OldWebAppRedirect) or the front already says so.
    #>
    param([Parameter(Mandatory)]$App, [Parameter(Mandatory)][string]$BaseUrl, [string]$Image = '', [string]$Container = 'signin-front')
    $front = Get-SIUpdaterFrontContainer -App $App -Container $Container
    if (-not $front) { return $null }
    $have = @(@($front.env) | Where-Object { $_ -and [string]$_.name -eq 'SIGNIN_FRONT_MOVED_TO' } | ForEach-Object { [string]$_.value })
    if ($have.Count -eq 1 -and $have[0] -ceq $BaseUrl -and (-not $Image -or [string]$front.image -ceq $Image)) { return $null }
    $tpl = ConvertTo-Json -InputObject $App.properties.template -Depth 60 | ConvertFrom-Json
    if ($tpl.PSObject.Properties['revisionSuffix']) { $tpl.PSObject.Properties.Remove('revisionSuffix') }
    $f = @(@($tpl.containers) | Where-Object { $_ -and [string]$_.name -eq $Container })[0]
    $list = @(@(@($f.env) | Where-Object { $_ -and [string]$_.name -ne 'SIGNIN_FRONT_MOVED_TO' }) + @([pscustomobject]@{ name = 'SIGNIN_FRONT_MOVED_TO'; value = $BaseUrl }))
    if ($f.PSObject.Properties['env']) { $f.env = $list } else { $f | Add-Member -NotePropertyName env -NotePropertyValue $list }
    if ($Image) { $f.image = $Image }
    [ordered]@{ properties = [ordered]@{ template = $tpl } }
}

function Test-SIUpdaterMovedToReadBack {
    <# PURE. Does the old web app (as read) send every request to -BaseUrl: its front carries SIGNIN_FRONT_MOVED_TO = -BaseUrl
       (and runs -Image when given) and the app has finished provisioning? #>
    param($App, [Parameter(Mandatory)][string]$BaseUrl, [string]$Image = '', [string]$Container = 'signin-front')
    $front = Get-SIUpdaterFrontContainer -App $App -Container $Container
    if (-not $front) { return $false }
    $v = @(@($front.env) | Where-Object { $_ -and [string]$_.name -eq 'SIGNIN_FRONT_MOVED_TO' } | ForEach-Object { [string]$_.value })
    $ps = if ($App.properties.PSObject.Properties['provisioningState']) { [string]$App.properties.provisioningState } else { 'Succeeded' }
    ($v.Count -eq 1 -and $v[0] -ceq $BaseUrl -and (-not $Image -or [string]$front.image -ceq $Image) -and $ps -eq 'Succeeded')
}

function Set-SIUpdaterOldWebAppMovedTo {
    <#
        The SWITCH's last part: the OLD web app's sign-in front answers every request with a redirect to the new web app
        BEFORE any sign-in (a person signs in ONCE, on the new address), read back. -Arm: the move's ARM seam. The old app
        without a front keeps the web app's own redirect (OldWebAppRedirect, the fallback either way). Never throws:
        @{ Ok; Changed; Why }.
    #>
    param([Parameter(Mandatory)][scriptblock]$Arm, [Parameter(Mandatory)][string]$OldPath, [Parameter(Mandatory)][string]$NewPath,
          [Parameter(Mandatory)][string]$NewFqdn, [int]$Tries = 20, [int]$PollSeconds = 15)
    try {
        $base = 'https://' + $NewFqdn.Trim().TrimEnd('/').ToLowerInvariant()
        $old = & $Arm 'GET' $OldPath $null $true
        if (-not $old) { return [pscustomobject]@{ Ok = $true; Changed = $false; Why = 'the old web app is gone' } }
        if (-not (Get-SIUpdaterFrontContainer -App $old)) { return [pscustomobject]@{ Ok = $true; Changed = $false; Why = 'the old web app has no sign-in front: its own redirect answers' } }
        $new = & $Arm 'GET' $NewPath $null $true
        $nf = Get-SIUpdaterFrontContainer -App $new
        $img = if ($nf) { [string]$nf.image } else { '' }
        $body = New-SIUpdaterMovedToPatchBody -App $old -BaseUrl $base -Image $img
        if (-not $body) { return [pscustomobject]@{ Ok = $true; Changed = $false; Why = '' } }
        $null = & $Arm 'PATCH' $OldPath $body $false
        for ($i = 0; $i -lt [Math]::Max(1, $Tries); $i++) {
            $back = & $Arm 'GET' $OldPath $null $true
            if (Test-SIUpdaterMovedToReadBack -App $back -BaseUrl $base -Image $img) { return [pscustomobject]@{ Ok = $true; Changed = $true; Why = '' } }
            if ($PollSeconds -gt 0) { Start-Sleep -Seconds $PollSeconds }
        }
        [pscustomobject]@{ Ok = $false; Changed = $true; Why = ('its sign-in front does not read back with SIGNIN_FRONT_MOVED_TO = {0}' -f $base) }
    } catch { [pscustomobject]@{ Ok = $false; Changed = $false; Why = $_.Exception.Message } }
}

function Set-SIUpdaterWebAppName {
    <#
        The install's web app is -Name from now on, everywhere the updater and the heartbeat read it: the updater job's
        SI_UPDATER_WEB_APP (its own job, one read-modify-write PATCH, read back -- the job's variable is read before the
        install record), this process, the install record (cfg.InstallState 'InstallNames', read back) and the install's
        links for the heartbeat (cfg.InstallState 'Endpoints'). Writes nothing that already says -Name. Never throws:
        @{ Ok; Why }.
    #>
    param([Parameter(Mandatory)][string]$Name, [Parameter(Mandatory)][string]$ResourceGroup, [Parameter(Mandatory)][string]$SubscriptionId,
          $Store = $null, [string]$UpdaterJob = '', [hashtable]$Env = @{})
    # (names of their own: Invoke-SIUpdaterPatchWhenFree runs the PATCH block in its scope, where $Name is the job's name)
    $siWebNewName = $Name
    try {
        if (-not $UpdaterJob) { $UpdaterJob = if (Get-Command -Name Get-SIUpdaterInstallName -ErrorAction SilentlyContinue) { [string](Get-SIUpdaterInstallName -Role updater -Env $Env) } else { 'caj-si-updater' } }
        $siJobPath = Get-SIUpdaterRgPath -SubscriptionId $SubscriptionId -ResourceGroup $ResourceGroup -Provider ('Microsoft.App/jobs/' + $UpdaterJob)
        $job = Invoke-SIUpdaterArm -Path $siJobPath
        if ((Get-SIUpdaterWebAppSetting -App $job -Name 'SI_UPDATER_WEB_APP') -cne $siWebNewName) {
            Invoke-SIUpdaterPatchWhenFree -Name $UpdaterJob -Read { Invoke-SIUpdaterArm -Path $siJobPath } `
                -Patch { param($now) $null = Invoke-SIUpdaterArm -Method PATCH -Path $siJobPath -Body (New-SIUpdaterEnvPatchBody -Resource $now -Name 'SI_UPDATER_WEB_APP' -Value $siWebNewName) }
            $back = Invoke-SIUpdaterArm -Path $siJobPath
            if ((Get-SIUpdaterWebAppSetting -App $back -Name 'SI_UPDATER_WEB_APP') -cne $siWebNewName) { return [pscustomobject]@{ Ok = $false; Why = ("the updater job's SI_UPDATER_WEB_APP does not read back as {0}" -f $siWebNewName) } }
        }
        [Environment]::SetEnvironmentVariable('SI_UPDATER_WEB_APP', $siWebNewName)
        if ($Env.ContainsKey('SI_UPDATER_WEB_APP')) { $Env['SI_UPDATER_WEB_APP'] = $siWebNewName }
        if ($Store -and (Get-Command -Name New-SIInstallNamesRecord -ErrorAction SilentlyContinue)) {
            $cur = Read-SIInstallNamesRecord -Store $Store
            if ((Get-SIInstallNameProp -Record $cur -Role 'web') -cne $siWebNewName) {
                $rec = New-SIInstallNamesRecord -Names @{ web = $siWebNewName } -Current $cur
                if (-not (Save-SIInstallNamesRecord -Store $Store -Value $rec.Value)) { return [pscustomobject]@{ Ok = $false; Why = 'the install record could not be written' } }
                if ((Get-SIInstallNameProp -Record (Read-SIInstallNamesRecord -Store $Store) -Role 'web') -cne $siWebNewName) { return [pscustomobject]@{ Ok = $false; Why = 'the install record does not read back' } }
                $global:SI_InstallNames = [pscustomobject]$rec.Record
            }
        }
        if (Get-Command -Name Invoke-SIUpdaterRecordEndpoints -ErrorAction SilentlyContinue) {
            $mcp = if (Get-Command -Name Get-SIUpdaterInstallName -ErrorAction SilentlyContinue) { [string](Get-SIUpdaterInstallName -Role mcp -Env $Env) } else { 'ca-si-mcp' }
            $null = Invoke-SIUpdaterRecordEndpoints -Store $Store -SubscriptionId $SubscriptionId -ResourceGroup $ResourceGroup -WebApp $siWebNewName -McpApp $mcp
        }
        [pscustomobject]@{ Ok = $true; Why = '' }
    } catch { [pscustomobject]@{ Ok = $false; Why = $_.Exception.Message } }
}

function Read-SIUpdaterWebSignedInProof {
    <#
        The first sign-in on the web app -Name, as that web app recorded it itself (cfg.WebAppSignedInRecord): its OWN row
        cfg.InstallState 'WebAppSignedIn:<name>' = {"app":"<name>","at":"<utc>"} -- one row per app name, so the old web
        app's row never stands in the way and nothing is ever deleted. The updater cannot sign a PERSON in; the move waits
        for this row before the old web app is removed. @{ Ok; Why }. Never throws.
    #>
    param($Store, [Parameter(Mandatory)][string]$Name)
    $no = { param($w) [pscustomobject]@{ Ok = $false; Why = $w } }
    if (-not $Store -or -not $Store.Invoke) { return (& $no 'there is no database to read a sign-in from') }
    try {
        $row = @(& $Store.Invoke "IF OBJECT_ID('cfg.InstallState') IS NOT NULL SELECT Value FROM cfg.InstallState WHERE Name = @Name;" ([ordered]@{ Name = ('WebAppSignedIn:' + $Name.ToLowerInvariant()) }) 'reader' | ForEach-Object { $_ } | Where-Object { $_ }) | Select-Object -First 1
        if (-not $row) { return (& $no 'nobody has signed in on it yet') }
        $v = if ($row -is [System.Collections.IDictionary]) { [string]$row['Value'] } elseif ($row.PSObject.Properties['Value']) { [string]$row.Value } else { [string]$row }
        $o = $null; try { $o = $v | ConvertFrom-Json -ErrorAction Stop } catch { $o = $null }
        if ($o -and "$($o.app)".Trim() -ieq $Name) { return [pscustomobject]@{ Ok = $true; Why = '' } }
        & $no ('its sign-in row does not name {0}' -f $Name)
    } catch { & $no ('its sign-in row could not be read: {0}' -f $_.Exception.Message) }
}
function Read-SIUpdaterPublicAddress {
    <# The web app's public address setting (SIWeb_PublicBaseUrl, the links in mails); '' when not set or not readable. #>
    param($Store)
    if (-not $Store -or -not $Store.Invoke) { return '' }
    try {
        $row = @(& $Store.Invoke "IF OBJECT_ID('cfg.Setting') IS NOT NULL SELECT TOP (1) ValueJson AS Value FROM cfg.Setting WHERE Name = N'SIWeb_PublicBaseUrl' AND Scope = N'engine:management-web';" ([ordered]@{}) 'reader' | ForEach-Object { $_ } | Where-Object { $_ }) | Select-Object -First 1
        if (-not $row) { return '' }
        $v = if ($row -is [System.Collections.IDictionary]) { [string]$row['Value'] } elseif ($row.PSObject.Properties['Value']) { [string]$row.Value } else { [string]$row }
        $s = $null; try { $s = $v | ConvertFrom-Json -ErrorAction Stop } catch { $s = $v }
        "$s".Trim()
    } catch { '' }
}

function Get-SIUpdaterPublicAddressPlan {
    <# PURE. What the move does with the web app's public address setting (SIWeb_PublicBaseUrl): none (not set, or it
       names the new address already) | rewrite (it is exactly the old web app's default address https://<old fqdn>) |
       custom (any other value: a custom host -- left as it is, and the old web app is not removed). #>
    param([AllowNull()][AllowEmptyString()][string]$Value, [AllowEmptyString()][string]$OldFqdn, [AllowEmptyString()][string]$NewFqdn)
    $v = "$Value".Trim().TrimEnd('/')
    if (-not $v) { return 'none' }
    if ("$NewFqdn".Trim() -and $v -ieq ('https://' + "$NewFqdn".Trim())) { return 'none' }
    if ("$OldFqdn".Trim() -and $v -ieq ('https://' + "$OldFqdn".Trim())) { return 'rewrite' }
    'custom'
}

function Set-SIUpdaterPublicAddress {
    <# The web app's public address setting from -From (the old web app's default address) to -To, with its change-log row
       in the same transaction -- ONLY while it still says -From (a person's change in between is kept); read back. Never
       throws: @{ Ok; Why }. #>
    param($Store, [Parameter(Mandatory)][string]$From, [Parameter(Mandatory)][string]$To)
    try {
        if (-not $Store -or -not $Store.Invoke) { return [pscustomobject]@{ Ok = $false; Why = 'there is no database to change the public address in' } }
        $row = @(& $Store.Invoke "SELECT TOP (1) ValueJson AS Value FROM cfg.Setting WHERE Name = N'SIWeb_PublicBaseUrl' AND Scope = N'engine:management-web';" ([ordered]@{}) 'reader' | ForEach-Object { $_ } | Where-Object { $_ }) | Select-Object -First 1
        $raw = if (-not $row) { '' } elseif ($row -is [System.Collections.IDictionary]) { [string]$row['Value'] } elseif ($row.PSObject.Properties['Value']) { [string]$row.Value } else { [string]$row }
        $cur = $null; try { $cur = $raw | ConvertFrom-Json -ErrorAction Stop } catch { $cur = $raw }
        if ("$cur".Trim().TrimEnd('/') -ine $From.TrimEnd('/')) { return [pscustomobject]@{ Ok = $false; Why = 'the public address setting changed in the meantime' } }
        $json = ConvertTo-Json -InputObject $To.TrimEnd('/') -Compress
        $sql = @"
SET XACT_ABORT ON;
BEGIN TRAN;
UPDATE cfg.Setting SET ValueJson = @ValueJson, UpdatedAt = SYSUTCDATETIME(), UpdatedBy = N'caj-si-updater'
 WHERE Name = N'SIWeb_PublicBaseUrl' AND Scope = N'engine:management-web' AND ValueJson = @OldJson;
IF @@ROWCOUNT = 1
    INSERT cfg.ChangeLog (Name, Scope, Action, OldValue, NewValue, ChangedBy, Reason)
    VALUES (N'SIWeb_PublicBaseUrl', N'engine:management-web', N'Set', @OldJson, @ValueJson, N'caj-si-updater', N'the web app moved to its standard name');
COMMIT;
"@
        $null = & $Store.Invoke $sql ([ordered]@{ ValueJson = $json; OldJson = $raw }) 'nonquery'
        if ((Read-SIUpdaterPublicAddress -Store $Store).TrimEnd('/') -ine $To.TrimEnd('/')) { return [pscustomobject]@{ Ok = $false; Why = 'the public address setting does not read back' } }
        [pscustomobject]@{ Ok = $true; Why = '' }
    } catch { [pscustomobject]@{ Ok = $false; Why = $_.Exception.Message } }
}

function Invoke-SIUpdaterWebAppMove {
    <#
        THE WEB APP UNDER ITS FRAMEWORK NAME (-NewName, ca-si-web). Idempotent and resumable; any failure leaves the old web
        app (-OldName) serving and is tried again at the next update:
          * the new one runs and the old one does not: done (the install record named -NewName when it does not yet; a
            redirect URI the old address left on the sign-in app removed);
          * the updater does not own the sign-in app yet (-Owner, Invoke-SIUpdaterSignInAppOwner): nothing is made;
          * the new web app made from the old one's spec (New-SIUpdaterWebAppCopyBody: the same image, the SAME user-assigned
            identity, settings, secrets re-read through ARM listSecrets, scale, ingress) and waited for -- made again from
            the old one on every update until the name is switched, so it never falls behind the old one;
          * its redirect URI https://<fqdn>/signin-oidc added to the sign-in app BESIDE the old one, as its owner, read back;
          * read back: /healthz answers 200, and a request without a sign-in is sent to login.microsoftonline.com with the new
            redirect_uri;
          * a custom domain bound to the old web app: NOT moved -- said, and it stops here (the old app keeps serving);
          * the public address setting (the links in mails) names a custom host: left as it is, said, and it stops here;
          * the public address setting, when it is exactly the old web app's default address, rewritten to the new one and
            read back (-SetPublicAddress); then the install record, the updater job's variable and the heartbeat's links
            name -NewName (-SwitchName) -- from then on the old web app sends every page request to the new one;
          * the first sign-in on the new web app (-SignedInProof: its own row, recorded by the web app itself): none = it
            stops here, the old app redirecting; no timer;
          * only then the old web app removed (waited for), and its redirect URI removed from the sign-in app, read back.
        -CurrentName: the name the install resolves today (record, variable, default). Seams for tests: -Arm { param($Method,
        $Path, $Body, [bool]$AllowNotFound) }, -Graph, -Probe { param($Url) } -> @{ Status; Location }, -SignedInProof
        { param($Name) } -> @{ Ok; Why }, -SwitchName { param($Name) } -> @{ Ok; Why }, -ReadPublicAddress { },
        -SetPublicAddress { param($From, $To) } -> @{ Ok; Why }.
        Never throws. Returns @{ State ('' = nothing here | moved | waiting-owner | create-failed | redirect-failed |
        signin-failed | custom-domain | public-address | awaiting-signin-proof | switch-failed | delete-failed); Text; Why }.
    #>
    param([Parameter(Mandatory)][string]$ResourceGroup, [Parameter(Mandatory)][string]$SubscriptionId,
          [string]$OldName = 'ca-si-management', [string]$NewName = 'ca-si-web', [string]$CurrentName = '',
          $Owner = $null, $Store = $null, [hashtable]$Env = @{},
          [scriptblock]$Arm, [scriptblock]$Graph, [scriptblock]$Probe, [scriptblock]$SignedInProof, [scriptblock]$SwitchName,
          [scriptblock]$ReadPublicAddress, [scriptblock]$SetPublicAddress, [scriptblock]$Log, [int]$TimeoutMinutes = 15, [int]$PollSeconds = 15)
    $out = { param([string]$State, [string]$Text, [string]$Why = '') [pscustomobject]@{ State = $State; Text = $Text; Why = $Why } }
    try {
        if (-not $Arm) { $Arm = { param([string]$Method, [string]$Path, $Body, [bool]$AllowNotFound) Invoke-SIUpdaterArm -Method $Method -Path $Path -Body $Body -AllowNotFound:$AllowNotFound } }
        if (-not $Graph) { $Graph = { param([string]$Method, [string]$Uri, $Body) Invoke-SIRestJson -Rest (Get-SIUpdaterRest) -Method $Method -Uri $Uri -Body $Body -Resource 'https://graph.microsoft.com/' } }
        if (-not $Probe) { $Probe = { param([string]$Url) Invoke-SIUpdaterAnonymousProbe -Url $Url } }
        if (-not $SignedInProof) { $SignedInProof = { param([string]$Name) Read-SIUpdaterWebSignedInProof -Store $Store -Name $Name } }
        if (-not $SetPublicAddress) { $SetPublicAddress = { param([string]$From, [string]$To) Set-SIUpdaterPublicAddress -Store $Store -From $From -To $To } }
        if (-not $SwitchName) { $SwitchName = { param([string]$Name) Set-SIUpdaterWebAppName -Name $Name -ResourceGroup $ResourceGroup -SubscriptionId $SubscriptionId -Store $Store -Env $Env } }
        if (-not $ReadPublicAddress) { $ReadPublicAddress = { Read-SIUpdaterPublicAddress -Store $Store } }
        if (-not $Log) { $Log = { param($m) if (Get-Command -Name Write-UpdLog -ErrorAction SilentlyContinue) { Write-UpdLog $m } } }
        if (-not $OldName -or $OldName -ieq $NewName) { return (& $out '' '') }
        $pathOf = { param([string]$N) Get-SIUpdaterRgPath -SubscriptionId $SubscriptionId -ResourceGroup $ResourceGroup -Provider ('Microsoft.App/containerApps/' + $N) }
        $readApp = { param([string]$N) & $Arm 'GET' (& $pathOf $N) $null $true }
        $fqdnOf = { param($A) if ($A -and $A.properties -and $A.properties.configuration -and $A.properties.configuration.ingress) { "$($A.properties.configuration.ingress.fqdn)".Trim() } else { '' } }
        $old = & $readApp $OldName
        $new = & $readApp $NewName
        if (-not $old -and -not $new) { return (& $out '' '') }
        $g = 'https://graph.microsoft.com/v1.0'
        $owned = [bool]($Owner -and $Owner.Owned -and "$($Owner.ObjectId)".Trim())
        $objId = if ($Owner) { "$($Owner.ObjectId)".Trim() } else { '' }
        # the sign-in app's redirect URIs as its owner: -Add / -Remove, the sign-out address moved with them; read back.
        # $true = changed, $false = nothing to change; throws when it does not read back.
        $setUris = { param([string[]]$Add = @(), [string[]]$Remove = @(), [string]$LogoutFrom = '', [string]$LogoutTo = '')
            $a = & $Graph 'GET' ("$g/applications/{0}?`$select=id,web" -f $objId) $null
            $web = if ($a) { $a.web } else { $null }
            $uris = @(if ($web) { @($web.redirectUris) | Where-Object { $_ } | ForEach-Object { [string]$_ } })
            $want = @(@($uris | Where-Object { $u = $_; -not @($Remove | Where-Object { $_ -ieq $u }).Count }) + @($Add | Where-Object { $x = $_; -not @($uris | Where-Object { $_ -ieq $x }).Count }))
            $logout = if ($web) { "$($web.logoutUrl)" } else { '' }
            $wantLogout = if ($LogoutFrom -and $logout -ieq $LogoutFrom) { $LogoutTo } else { $logout }
            if ((@($uris | Sort-Object) -join '|') -eq (@($want | Sort-Object) -join '|') -and $wantLogout -eq $logout) { return $false }
            $w = [ordered]@{ redirectUris = @($want) }
            if ("$wantLogout".Trim()) { $w['logoutUrl'] = $wantLogout }
            if ($web -and $web.PSObject.Properties['implicitGrantSettings'] -and $web.implicitGrantSettings) { $w['implicitGrantSettings'] = $web.implicitGrantSettings }
            if ($web -and $web.PSObject.Properties['homePageUrl'] -and "$($web.homePageUrl)".Trim()) { $w['homePageUrl'] = [string]$web.homePageUrl }
            $null = & $Graph 'PATCH' ("$g/applications/{0}" -f $objId) @{ web = $w }
            $b = & $Graph 'GET' ("$g/applications/{0}?`$select=id,web" -f $objId) $null
            $now = @(if ($b -and $b.web) { @($b.web.redirectUris) | Where-Object { $_ } | ForEach-Object { [string]$_ } })
            foreach ($x in @($Add)) { if (-not @($now | Where-Object { $_ -ieq $x }).Count) { throw ('{0} does not read back on the sign-in app' -f $x) } }
            foreach ($x in @($Remove)) { if (@($now | Where-Object { $_ -ieq $x }).Count) { throw ('{0} is still on the sign-in app' -f $x) } }
            $true
        }
        $customAddress = { param([string]$Value) "{0}: {1} is ready beside it, but the web app's public address setting names a custom host ({2}) -- the update does not change it: it is moved with the host by a Support-app step, then the next update finishes the move. {0} keeps serving." -f $OldName, $NewName, $Value }
        $oldUriOf = { param([string]$NewFqdn) $o = $NewFqdn -replace ('^' + [regex]::Escape($NewName) + '\.'), ($OldName + '.'); if ($o -ieq $NewFqdn) { '' } else { $o } }

        # ALREADY MOVED (or made under the framework name)
        if ($new -and -not $old) {
            $said = New-Object System.Collections.Generic.List[string]
            if ($CurrentName -and $CurrentName -ine $NewName) {
                $sw = & $SwitchName $NewName
                if (-not $sw.Ok) { return (& $out 'switch-failed' ("{0} serves, but the install could not be named after it yet ({1}) -- the next update tries again" -f $NewName, $sw.Why) ([string]$sw.Why)) }
                $said.Add(('the install record names {0} now' -f $NewName))
            }
            if ($owned) {
                $nf = & $fqdnOf $new; $of = if ($nf) { & $oldUriOf $nf } else { '' }
                if ($of) {
                    try { if (& $setUris @() @("https://$of/signin-oidc") "https://$of/signout-callback-oidc" "https://$nf/signout-callback-oidc") { $said.Add(("the old address's redirect URI was removed from the sign-in app (read back)")) } }
                    catch { $said.Add(("the old address's redirect URI is still on the sign-in app ({0}) -- the next update removes it" -f $_.Exception.Message)) }
                }
            }
            $t = if ($said.Count) { '{0}: {1}' -f $NewName, ($said -join '; ') } else { '' }
            return (& $out 'moved' $t)
        }

        # THE OLD WEB APP RUNS
        $switched = [bool]($new -and $CurrentName -and $CurrentName -ieq $NewName)
        if (-not $switched) {
            if (-not $owned) { return (& $out 'waiting-owner' ("{0}: moves to {1} once this install's updater owns its sign-in app -- it keeps serving as it is" -f $OldName, $NewName)) }
            # 1. the new web app from the old one's spec (secrets re-read), waited for
            $body = $null
            try {
                $listed = & $Arm 'POST' ((& $pathOf $OldName) + '/listSecrets') $null $false
                $body = New-SIUpdaterWebAppCopyBody -App $old -Secrets @(if ($listed) { @($listed.value) })
            } catch { return (& $out 'create-failed' ("{0}: {1} was not made -- {2}; {0} keeps serving, the next update tries again" -f $OldName, $NewName, $_.Exception.Message) ([string]$_.Exception.Message)) }
            & $Log ("{0}: making {1} beside it (the same image, identity and settings) -- {0} keeps serving" -f $OldName, $NewName)
            $fqdn = ''; $why = 'not read yet'; $ready = $false
            try {
                $null = & $Arm 'PUT' (& $pathOf $NewName) $body $false
                $deadline = [datetime]::UtcNow.AddMinutes($TimeoutMinutes)
                do {
                    $cur = $null
                    try { $cur = & $readApp $NewName } catch { $why = ('the last read failed: {0}' -f $_.Exception.Message) }
                    if ($cur) {
                        $ps = "$($cur.properties.provisioningState)"
                        if ($ps -eq 'Failed') { $why = 'its provisioning failed'; break }
                        $fqdn = & $fqdnOf $cur
                        $rev = "$($cur.properties.latestRevisionName)"
                        $ready = ($ps -eq 'Succeeded') -and $fqdn -and $rev -and ("$($cur.properties.latestReadyRevisionName)" -eq $rev)
                        if ($ready) { break }
                        $why = ('provisioning {0}, ready revision {1} of {2}' -f $ps, "$($cur.properties.latestReadyRevisionName)", $rev)
                    }
                    if ($PollSeconds -gt 0) { Start-Sleep -Seconds $PollSeconds }
                } until ([datetime]::UtcNow -gt $deadline -or $PollSeconds -le 0)
            } catch { $why = $_.Exception.Message }
            if (-not $ready) { return (& $out 'create-failed' ("{0}: {1} is not ready ({2}) -- {0} keeps serving, the next update tries again" -f $OldName, $NewName, $why) $why) }
            # 2. its redirect URI beside the old one, as the owner
            try { $null = & $setUris @("https://$fqdn/signin-oidc") @() '' '' }
            catch { return (& $out 'redirect-failed' ("{0}: {1} runs, but its redirect URI could not be added to the sign-in app ({2}) -- {0} keeps serving, the next update tries again" -f $OldName, $NewName, $_.Exception.Message) ([string]$_.Exception.Message)) }
            # 3. read back: health, and the sign-in starts with the new address
            $hz = & $Probe ("https://$fqdn/healthz")
            if ([int]$hz.Status -ne 200) { return (& $out 'signin-failed' ("{0}: {1} does not answer its health check (HTTP {2}) -- {0} keeps serving, the next update tries again" -f $OldName, $NewName, [int]$hz.Status)) }
            $st = & $Probe ("https://$fqdn/")
            if (-not (Test-SIUpdaterSignInStart -Probe $st -Fqdn $fqdn)) { return (& $out 'signin-failed' ("{0}: {1} does not send a request without a sign-in to the Microsoft sign-in with its own address (HTTP {2}) -- {0} keeps serving, the next update tries again" -f $OldName, $NewName, [int]$st.Status)) }
            # 4. what the update does not move by itself
            $domains = @()
            if ($old.properties.configuration.ingress -and $old.properties.configuration.ingress.PSObject.Properties['customDomains']) { $domains = @(@($old.properties.configuration.ingress.customDomains) | Where-Object { $_ } | ForEach-Object { [string]$_.name } | Where-Object { $_ }) }
            if ($domains.Count) {
                return (& $out 'custom-domain' ("{0}: {1} is ready beside it (healthy, signs in with its own address), but {0} has the custom domain {2} -- the update does not move a domain: a Support-app step moves it (a short gap while the hostname moves), then the next update finishes the move. {0} keeps serving." -f $OldName, $NewName, ($domains -join ', ')))
            }
            $oldFqdn = & $fqdnOf $old
            $pa = ''; try { $pa = [string](& $ReadPublicAddress) } catch { $pa = '' }
            $paPlan = Get-SIUpdaterPublicAddressPlan -Value $pa -OldFqdn $oldFqdn -NewFqdn $fqdn
            if ($paPlan -eq 'custom') { return (& $out 'public-address' (& $customAddress $pa)) }
            # 5. the public address (only the old default address), then the install, its updater and the heartbeat -- from
            # here the old web app sends every page request to the new one (the web app reads the install record)
            if ($paPlan -eq 'rewrite') {
                $pr = & $SetPublicAddress ("https://$oldFqdn") ("https://$fqdn")
                if (-not $pr -or -not $pr.Ok) { $pw = if ($pr) { [string]$pr.Why } else { 'not known' }; return (& $out 'switch-failed' ("{0}: {1} is ready, but the public address setting could not be moved to https://{2} ({3}) -- {0} keeps serving, the next update tries again" -f $OldName, $NewName, $fqdn, $pw) $pw) }
            }
            $sw = & $SwitchName $NewName
            if (-not $sw.Ok) { return (& $out 'switch-failed' ("{0}: {1} is ready, but the install could not be named after it ({2}) -- {0} keeps serving, the next update tries again" -f $OldName, $NewName, $sw.Why) ([string]$sw.Why)) }
            $new = & $readApp $NewName
        }
        # 6. the first sign-in on the new web app (recorded by the web app itself); 7. only then the old web app removed,
        # then its redirect URI
        $newFqdn = & $fqdnOf $new
        $oldFqdn = & $fqdnOf $old
        if ($switched) {
            # resumed after the switch: the public address checked again before anything is removed
            $pa = ''; try { $pa = [string](& $ReadPublicAddress) } catch { $pa = '' }
            $paPlan = Get-SIUpdaterPublicAddressPlan -Value $pa -OldFqdn $oldFqdn -NewFqdn $newFqdn
            if ($paPlan -eq 'custom') { return (& $out 'public-address' (& $customAddress $pa)) }
            if ($paPlan -eq 'rewrite') {
                $pr = & $SetPublicAddress ("https://$oldFqdn") ("https://$newFqdn")
                if (-not $pr -or -not $pr.Ok) { $pw = if ($pr) { [string]$pr.Why } else { 'not known' }; return (& $out 'switch-failed' ("{0} serves and the install names it, but the public address setting could not be moved to https://{1} ({2}) -- {3} is not removed yet; the next update tries again" -f $NewName, $newFqdn, $pw, $OldName) $pw) }
            }
        }
        # the switch's last part (every update until the old app is gone, idempotent): the OLD app's sign-in front sends every
        # request to the new address BEFORE any sign-in (signin-front SIGNIN_FRONT_MOVED_TO), read back -- a person signs in
        # once, on the new address. Not read back = said; the web app's own redirect stays the fallback, nothing stops here.
        $mvNote = ''
        if ($newFqdn) {
            $mv = Set-SIUpdaterOldWebAppMovedTo -Arm $Arm -OldPath (& $pathOf $OldName) -NewPath (& $pathOf $NewName) -NewFqdn $newFqdn -PollSeconds $PollSeconds
            if ($mv.Changed -and $mv.Ok) { & $Log ("{0}: its sign-in front sends every request to https://{1} before any sign-in (read back)" -f $OldName, $newFqdn) }
            if (-not $mv.Ok) { $mvNote = ('; its sign-in front could not be pointed at the new address yet ({0}) -- the web app''s own redirect answers, the next update tries again' -f $mv.Why); & $Log ("{0}{1}" -f $OldName, $mvNote) }
        }
        $proof = & $SignedInProof $NewName
        if (-not $proof -or -not $proof.Ok) {
            $pw = if ($proof) { [string]$proof.Why } else { 'not known' }
            return (& $out 'awaiting-signin-proof' ("{1} serves and the install names it; {0} sends every page request there and is removed after the first sign-in on {1} ({2}){3}" -f $OldName, $NewName, $pw, $mvNote) $pw)
        }
        try {
            $null = & $Arm 'DELETE' (& $pathOf $OldName) $null $true
            $deadline = [datetime]::UtcNow.AddMinutes($TimeoutMinutes); $gone = $false
            do {
                $left = $null; try { $left = & $readApp $OldName } catch { $left = 'unread' }
                if (-not $left) { $gone = $true; break }
                if ($PollSeconds -gt 0) { Start-Sleep -Seconds $PollSeconds }
            } until ([datetime]::UtcNow -gt $deadline -or $PollSeconds -le 0)
            if (-not $gone) { throw 'it still exists' }
        } catch { return (& $out 'delete-failed' ("{0} serves and the install names it; {1} could not be removed yet ({2}) -- the next update removes it" -f $NewName, $OldName, $_.Exception.Message) ([string]$_.Exception.Message)) }
        $tail = ''
        if ($oldFqdn -and $owned) {
            try { $null = & $setUris @() @("https://$oldFqdn/signin-oidc") "https://$oldFqdn/signout-callback-oidc" $(if ($newFqdn) { "https://$newFqdn/signout-callback-oidc" } else { '' }); $tail = '; its redirect URI was removed from the sign-in app (read back)' }
            catch { $tail = ('; its redirect URI is still on the sign-in app ({0}) -- the next update removes it' -f $_.Exception.Message) }
        }
        & $out 'moved' ("{0} moved to {1}: {1} serves (healthy, signs in with its own address), the install record and the heartbeat name it, {0} was removed{2}" -f $OldName, $NewName, $tail)
    } catch { & $out '' ("{0}: the move to {1} could not be checked ({2}) -- {0} keeps serving, the next update tries again" -f $OldName, $NewName, $_.Exception.Message) ([string]$_.Exception.Message) }
}

function Invoke-SIUpdaterWebAppSteps {
    <#
        Both web app steps, in order, at the end of an update that did not fail: the sign-in app owned by the updater
        (Invoke-SIUpdaterSignInAppOwner), then the web app under the name ca-si-web (Invoke-SIUpdaterWebAppMove). Off only
        when the updater job says SI_UPDATER_WEB_APP_MOVE=off. One line per outcome, each step's state in cfg.InstallState
        ('SignInAppOwner', 'WebAppName'). Never throws, never fails the update. -GetApp { param($Name) } / -SaveState
        { param($Name, $Value) } / -Graph / -MoveSeams (Invoke-SIUpdaterWebAppMove's seams): tests.
    #>
    param([hashtable]$Env = @{}, $Store = $null, [Parameter(Mandatory)][string]$SubscriptionId, [Parameter(Mandatory)][string]$ResourceGroup,
          [scriptblock]$Graph, [scriptblock]$WhoAmI, [scriptblock]$GetApp, [scriptblock]$SaveState, [scriptblock]$Log, [hashtable]$MoveSeams = @{})
    $none = [pscustomobject]@{ Owner = $null; Move = $null }
    if (-not $Log) { $Log = { param($m) if (Get-Command -Name Write-UpdLog -ErrorAction SilentlyContinue) { Write-UpdLog $m } } }
    try {
        $get = { param($k) if ($Env.ContainsKey($k)) { "$($Env[$k])".Trim() } else { "$([Environment]::GetEnvironmentVariable($k))".Trim() } }
        if (-not (Test-SIUpdaterWebAppMoveOn -Value (& $get 'SI_UPDATER_WEB_APP_MOVE'))) {
            & $Log 'web app: the sign-in app owner check and the move to ca-si-web are switched off on this install (SI_UPDATER_WEB_APP_MOVE=off) -- nothing was checked'
            return $none
        }
        if (-not $SaveState) { $SaveState = { param($n, $v) if ($Store -and (Get-Command -Name Save-SIUpdaterInstallStateValue -ErrorAction SilentlyContinue)) { $null = Save-SIUpdaterInstallStateValue -Store $Store -Name $n -Value $v } } }
        if (-not $GetApp) { $GetApp = { param([string]$N) Get-SIUpdaterContainerApp -App $N -ResourceGroup $ResourceGroup -SubscriptionId $SubscriptionId } }
        $newName = 'ca-si-web'
        $cur = if (Get-Command -Name Get-SIUpdaterInstallName -ErrorAction SilentlyContinue) { [string](Get-SIUpdaterInstallName -Role web -Env $Env) } else { & $get 'SI_UPDATER_WEB_APP' }
        $oldName = if ("$cur".Trim() -and "$cur".Trim() -ine $newName) { "$cur".Trim() } else { 'ca-si-management' }
        $oldApp = & $GetApp $oldName
        $newApp = & $GetApp $newName
        $app = if ($oldApp) { $oldApp } else { $newApp }
        if (-not $app) { return $none }
        $o = Invoke-SIUpdaterSignInAppOwner -WebApp $(if ($oldApp) { $oldName } else { $newName }) -App $app -UpdaterClientId (& $get 'SI_UPDATER_CLIENT_ID') `
                 -SupportAppId (Read-SIUpdaterSupportAppId -Store $Store) -ProveWrite:([bool]$oldApp) -Graph $Graph -WhoAmI $WhoAmI
        if ($o.Text) { & $Log $o.Text }
        if ($o.State) { & $SaveState 'SignInAppOwner' (ConvertTo-SIUpdaterStepStateValue -State $o.State -More @{ app = $o.ClientId } -Why $o.Why) }
        $mv = @{ ResourceGroup = $ResourceGroup; SubscriptionId = $SubscriptionId; OldName = $oldName; NewName = $newName; CurrentName = "$cur".Trim(); Owner = $o; Store = $Store; Env = $Env; Log = $Log }
        if ($Graph) { $mv['Graph'] = $Graph }
        foreach ($k in @($MoveSeams.Keys)) { $mv[$k] = $MoveSeams[$k] }
        $m = Invoke-SIUpdaterWebAppMove @mv
        if ($m.Text) { & $Log $m.Text }
        if ($m.State) { & $SaveState 'WebAppName' (ConvertTo-SIUpdaterStepStateValue -State $m.State -More @{ from = $oldName; to = $newName } -Why $m.Why) }
        [pscustomobject]@{ Owner = $o; Move = $m }
    } catch { & $Log ('web app: the sign-in app owner and the web app name could not be checked ({0}) -- the update goes on' -f $_.Exception.Message); $none }
}
