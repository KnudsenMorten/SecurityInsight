#Requires -Version 5.1
<#
    SECURITYINSIGHT PRO -- PUT THE WEB APP BEHIND THE ONE SHARED SIGN-IN FRONT, OR TAKE IT BACK (CR7, framework 12.11g).

    Dot-sourced by Deploy-SIManagement.ps1 (-SigninFront: a new install, or a re-deploy) and setup\Set-SISigninFront.ps1 (an
    existing install, through the Invardia Support app, coordinated with the customer). Needs SI-ManagementArm.ps1 (the REST
    layer: no az CLI, no PowerShell module) and loads the pure half itself (SI-SigninFrontPlan.ps1) and the federated
    credential's spec (SI-ManagementSignInCredential.ps1).

    Invoke-SISigninFrontCutover -- ON, in this order, each step READ BACK before the next; idempotent (a second run changes
    nothing):
      1. the component: the pinned version's source must be in this release / tree (else nothing changes);
     1b. the sign-in permissions the front asks for (openid profile offline_access User.Read) consented for the whole
         organisation (Invoke-SISignInConsent): added when missing, read back; a sign-in that may not consent is a WARNING
         with what an administrator does, never a silent pass;
      2. the federated credential: the web app's user-assigned managed identity on the SAME app registration (issuer = the
         tenant's v2.0, subject = the identity's principal id, audience api://AzureADTokenExchange) -- added when missing,
         read back. No secret, no certificate;
     2b. (#852) the front's store (SI-SigninFrontStore.ps1): the key signin-front-dp in the install's Key Vault, the web
         identity's "Key Vault Crypto Service Encryption User" on that key only, its database user, its schema signin and
         CREATE TABLE -- each when missing, read back; the front then gets SIGNIN_SQL_SERVER / _DATABASE /
         SIGNIN_KEYVAULT_KEY_ID / SIGNIN_STATE_MI_CLIENT_ID. A front from 1.3.0 on without its store: nothing changes;
      3. the front's image, built in the install's own registry from that source (never a prebuilt image) unless the
         registry has its tag already;
      4. ONE read-modify-write PATCH: the front added as the second container of the SAME revision, the web container's
         switch on (it then listens on 127.0.0.1 only and verifies the front's token), the ingress on the front's port --
         then the new revision waited for and read back, /healthz must answer and an anonymous request must be refused;
         anything else PUTS BACK the template that ran before and stops;
      5. Easy Auth off on the app (SecurityInsight never used it; an app that has it gets it turned off and read back);
      6. ONLY THEN the app registration's client secrets deleted (none is needed any more: the front's client assertion is
         the managed identity) and read back as gone. -KeepClientSecrets leaves them.
    -Off: the way back -- the front removed, the switch off, the ingress on the web container again (its own in-app sign-in),
    read back; the template that ran before is put back on failure. The federated credential stays (Set up mail uses it).
    Without -Apply: the plan only (every step and call printed), nothing changed. PS 5.1 + pwsh 7.
#>

if (-not (Get-Command -Name Get-SISigninFrontPin -ErrorAction SilentlyContinue)) { . (Join-Path $PSScriptRoot 'SI-SigninFrontPlan.ps1') }
if (-not (Get-Command -Name Invoke-SISignInConsent -ErrorAction SilentlyContinue)) { . (Join-Path $PSScriptRoot 'SI-ManagementSignInCredential.ps1') }

function Invoke-SISigninFrontGraph {
    <# One Microsoft Graph call as setup's sign-in (Get-SIManagementToken), through Invoke-SIRestMethod (the support session's
       recorder when there is one). #>
    param([Parameter(Mandatory)][string]$Method, [Parameter(Mandatory)][string]$Uri, $Body = $null, [Parameter(Mandatory)][string]$TenantId)
    $tok = Get-SIManagementToken -Resource 'https://graph.microsoft.com'
    if (-not $tok) { throw 'the sign-in could not issue a Microsoft Graph token' }
    Assert-SIManagementTokenTenant -Token $tok -TenantId $TenantId -What 'The Microsoft Graph sign-in'
    $p = @{ Method = $Method; Uri = $Uri; Headers = @{ Authorization = 'Bearer ' + $tok }; ErrorAction = 'Stop' }
    if ($null -ne $Body) { $p.ContentType = 'application/json; charset=utf-8'; $p.Body = [Text.Encoding]::UTF8.GetBytes((ConvertTo-Json -InputObject $Body -Depth 10)) }
    Invoke-SIRestMethod @p
}

function Test-SISigninFrontImageInRegistry {
    <# Is <login>/<repo>:<tag> in the install's registry already (the registry's data plane over setup's REST seam)? Any
       doubt is $false: the image is then built (a build of an existing tag only costs time). #>
    param([Parameter(Mandatory)][string]$LoginServer, [Parameter(Mandatory)][string]$Repo, [Parameter(Mandatory)][string]$Tag)
    try {
        if (-not (Get-Command -Name Test-SIAcrManifest -ErrorAction SilentlyContinue)) { . ([IO.Path]::GetFullPath([IO.Path]::Combine($PSScriptRoot, '..', '..', 'setup', '_shared', 'SI-AcrBuild.ps1'))) }
        [bool](Test-SIAcrManifest -Rest (New-SIUpdateRestSeam) -LoginServer $LoginServer -Repo $Repo -Tag $Tag)
    } catch { $false }
}

function Wait-SISigninFrontApp {
    <# Reads the app until -Want reads back (Test-SISigninFrontReadBack) or -TimeoutSec passes. Returns @{ Ok; Why; App }. #>
    param([Parameter(Mandatory)][string]$SubscriptionId, [Parameter(Mandatory)][string]$ResourceGroup, [Parameter(Mandatory)][string]$AppName,
          [Parameter(Mandatory)]$Pin, [ValidateSet('on', 'off')][string]$Want, [string]$FrontImage = '', [int]$TimeoutSec = 600, [int]$PollSec = 10, [scriptblock]$Sleep)
    $deadline = (Get-Date).AddSeconds($TimeoutSec)
    $last = [pscustomobject]@{ Ok = $false; Why = 'not read yet' }; $app = $null
    do {
        try { $app = Get-SIManagementContainerApp -SubscriptionId $SubscriptionId -ResourceGroup $ResourceGroup -Name $AppName; $last = Test-SISigninFrontReadBack -App $app -Pin $Pin -Want $Want -FrontImage $FrontImage }
        catch { $last = [pscustomobject]@{ Ok = $false; Why = ('the read failed: {0}' -f $_.Exception.Message) } }
        if ($last.Ok) { break }
        if ((Get-Date) -ge $deadline) { break }
        if ($Sleep) { & $Sleep $PollSec } else { Start-Sleep -Seconds $PollSec }
    } while ($true)
    [pscustomobject]@{ Ok = [bool]$last.Ok; Why = [string]$last.Why; App = $app }
}

function Test-SISigninFrontServing {
    <# The address answers /healthz with 200 and refuses an anonymous request (a redirect to the Entra sign-in or 401 / 403).
       Returns @{ Ok ($true / $false / $null = could not be judged: internal ingress, no answer); Why }. #>
    param([AllowEmptyString()][string]$Fqdn)
    if (-not $Fqdn) { return [pscustomobject]@{ Ok = $null; Why = 'the app has no address' } }
    $h = Invoke-SIManagementAnonymousProbe -Url ('https://{0}/healthz' -f $Fqdn.TrimEnd('/'))
    if ([int]$h.StatusCode -eq 0) { return [pscustomobject]@{ Ok = $null; Why = ('https://{0}/healthz did not answer from here (internal ingress?)' -f $Fqdn) } }
    if ([int]$h.StatusCode -ne 200) { return [pscustomobject]@{ Ok = $false; Why = ('/healthz answered {0}, not 200' -f $h.StatusCode) } }
    $a = Test-SIManagementAnonymousRefused -Fqdn $Fqdn -Kind web -Tries 3 -WaitSec 10
    if ($a.Refused -eq $false) { return [pscustomobject]@{ Ok = $false; Why = ('an anonymous request was answered with HTTP {0}' -f $a.StatusCode) } }
    if ($null -eq $a.Refused) { return [pscustomobject]@{ Ok = $null; Why = ('the anonymous check could not be judged (HTTP {0})' -f $a.StatusCode) } }
    [pscustomobject]@{ Ok = $true; Why = '' }
}

function Invoke-SISigninFrontStoreAsCaller {
    <#
        #852: the sign-in front's store (SI-SigninFrontStore.ps1, Invoke-SISigninFrontStore) made as setup's sign-in -- the
        administrator who runs the install or the cutover: ARM through Invoke-SIArm, the Pro database with the caller's own
        database token (Get-SIManagementToken). -Apply:$false = the plan only. Never throws; returns the store's result.
    #>
    param([Parameter(Mandatory)][string]$SubscriptionId, [Parameter(Mandatory)][string]$ResourceGroup, [Parameter(Mandatory)][string]$KeyVaultName,
          [Parameter(Mandatory)][string]$SqlServer, [Parameter(Mandatory)][string]$SqlDatabase, [Parameter(Mandatory)]$Identity,
          [switch]$Apply, [scriptblock]$Sleep, [scriptblock]$Log = { param($m) $null = $m })
    $arm = { param([string]$Method, [string]$Path, $Body) Invoke-SIArm -Method $Method -Path $Path -Body $Body -AllowNotFound }
    $srv = Get-SISigninStoreSqlFqdn -Server $SqlServer
    $sql = {
        param([string]$Query, $Params, [string]$Mode)
        $tok = Get-SIManagementToken -Resource 'https://database.windows.net/'
        if (-not $tok) { throw 'the sign-in could not issue a database token' }
        $cn = New-Object System.Data.SqlClient.SqlConnection
        $cn.ConnectionString = ('Server=tcp:{0},1433;Database={1};Encrypt=True;TrustServerCertificate=False;Connection Timeout=30;' -f $srv, $SqlDatabase)
        $cn.AccessToken = $tok
        try {
            $cn.Open(); $cmd = $cn.CreateCommand(); $cmd.CommandText = $Query; $cmd.CommandTimeout = 0
            if ($Params) { foreach ($k in @($Params.Keys)) { $null = $cmd.Parameters.AddWithValue('@' + $k, [string]$Params[$k]) } }
            if ($Mode -eq 'nonquery') { return $cmd.ExecuteNonQuery() }
            $rd = $cmd.ExecuteReader()
            try { while ($rd.Read()) { $o = [ordered]@{}; for ($i = 0; $i -lt $rd.FieldCount; $i++) { $o[$rd.GetName($i)] = $rd.GetValue($i) }; [pscustomobject]$o } } finally { $rd.Dispose() }
        } finally { $cn.Dispose() }
    }   # dynamic scope: $srv, $SqlDatabase come from this function
    $a = @{ Arm = $arm; Sql = $sql; SubscriptionId = $SubscriptionId; ResourceGroup = $ResourceGroup; VaultName = $KeyVaultName
            SqlServer = $srv; SqlDatabase = $SqlDatabase; Identity = $Identity; Apply = [bool]$Apply; Log = $Log }
    if ($Sleep) { $a.Sleep = $Sleep }
    Invoke-SISigninFrontStore @a
}

function Invoke-SISigninFrontCutover {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$SubscriptionId, [Parameter(Mandatory)][string]$ResourceGroup,
        [Parameter(Mandatory)][ValidatePattern('^[0-9a-fA-F-]{36}$')][string]$TenantId,
        [Parameter(Mandatory)][ValidatePattern('^[0-9a-fA-F-]{36}$')][string]$SignInClientId,
        [Parameter(Mandatory)][string]$RegistryName,
        [string]$AppName = 'ca-si-management', [string]$IdentityName = 'uami-si-management',
        # the SecurityInsight folder of the release / tree (the pin and the component's source are found from it)
        [string]$SIRoot = ([IO.Path]::GetFullPath([IO.Path]::Combine($PSScriptRoot, '..', '..'))),
        [switch]$Off, [switch]$KeepClientSecrets, [switch]$Apply,
        # #852: the front's store -- the install's Key Vault (default: the only vault in the resource group) and the Pro
        # database (default: the web app's Estate__SqlServer / Estate__SqlDatabase)
        [string]$KeyVaultName = '', [string]$SqlServer = '', [string]$SqlDatabase = '',
        [int]$WaitSec = 600, [scriptblock]$Sleep, [scriptblock]$Log = { param($m) Write-Host $m }
    )
    $done = New-Object System.Collections.Generic.List[string]
    $say = { param($m) & $Log $m; $done.Add([string]$m) }
    $pin = Get-SISigninFrontPin -SIRoot $SIRoot
    $result = [ordered]@{ Mode = $(if ($Off) { 'off' } else { 'on' }); Applied = $false; Changed = $false; FrontImage = ''; SecretsRemoved = @(); SignInConsent = ''; Steps = $done }

    $before = Get-SIManagementContainerApp -SubscriptionId $SubscriptionId -ResourceGroup $ResourceGroup -Name $AppName
    if (-not $before) { throw ('The web app {0} was not found in {1}.' -f $AppName, $ResourceGroup) }
    $appPath = Get-SIManagementContainerAppPath -SubscriptionId $SubscriptionId -ResourceGroup $ResourceGroup -Name $AppName
    $state = Get-SISigninFrontState -App $before -ContainerName ([string]$pin.containerName)

    # ---------------------------------------------------------------------------------------------------- the way back
    if ($Off) {
        $plan = New-SISigninFrontRemovePatch -App $before -Pin $pin
        if (-not $plan.Changed) { & $say ('{0}: not behind the sign-in front, its own sign-in chosen already -- nothing to change' -f $AppName); return [pscustomobject]$result }
        if ($state.HasFront) { & $say ('PATCH {0}  (the sign-in front removed, the web app''s own sign-in on port 8080 again; the update keeps that choice)' -f $appPath) }
        else { & $say ('PATCH {0}  (SI_Web_SigninFront=false: this install keeps its own sign-in -- the update will not move it behind the front)' -f $appPath) }
        if (-not $Apply) { return [pscustomobject]$result }
        try {
            $null = Invoke-SIManagementArmWrite -Method PATCH -Path $appPath -Body $plan.Body -Sleep $Sleep
            $back = Wait-SISigninFrontApp -SubscriptionId $SubscriptionId -ResourceGroup $ResourceGroup -AppName $AppName -Pin $pin -Want off -TimeoutSec $WaitSec -Sleep $Sleep
            if (-not $back.Ok) { throw ('it did not read back: {0}' -f $back.Why) }
        } catch {
            $why = $_.Exception.Message
            & $say ('{0}: taking the front away FAILED ({1}) -- putting back what ran before' -f $AppName, $why)
            try { $null = Invoke-SIManagementArmWrite -Method PATCH -Path $appPath -Body (New-SISigninFrontRestorePatch -Before $before) -Sleep $Sleep }
            catch { & $say ('{0}: could NOT be put back: {1} -- contact Invardia support' -f $AppName, $_.Exception.Message) }
            throw ('The web app could not be taken out from behind the sign-in front: {0}' -f $why)
        }
        $result.Applied = $true; $result.Changed = $true
        & $say ('{0}: the sign-in front is removed and the web app signs users in itself again (read back)' -f $AppName)
        return [pscustomobject]$result
    }

    # ---------------------------------------------------------------------------------------------------- 1. the component
    $src = Resolve-SISigninFrontSource -SIRoot $SIRoot -Pin $pin
    if (-not $src.Ok) { throw ('The sign-in front {0} {1} cannot be used here: {2}. Nothing was changed.' -f $pin.component, $pin.version, $src.Why) }
    & $say ('component: {0} {1} from {2}' -f $pin.component, $src.Version, $src.Path)

    # ---------------------------------------------------------------------------------------------------- 1b. the sign-in consent
    # The front asks for openid profile offline_access User.Read; an app registered before step 2b of
    # New-SIManagementAppRegistration.ps1 had only "openid profile" for the organisation, and the first sign-in through the front
    # stopped at "Approval required" (2026-10-18). The same grant, made sure of here (SI-ManagementSignInCredential.ps1):
    # planned without -Apply; with -Apply written and read back. A sign-in that may not consent: a WARNING with what an
    # administrator does -- never a silent pass -- and the switch goes on (the grant is the administrator's one click).
    $consentGraph = { param([string]$Method, [string]$Uri, $Body) Invoke-SISigninFrontGraph -Method $Method -Uri $Uri -Body $Body -TenantId $TenantId }
    $consent = Invoke-SISignInConsent -Graph $consentGraph -ClientId $SignInClientId -Apply:$Apply -Sleep $Sleep
    $result.SignInConsent = $consent.State
    if ($consent.State -in 'no-rights', 'failed', 'unchecked') { Write-Warning $consent.Line; $done.Add(('WARNING: ' + $consent.Line)) }
    else { & $say $consent.Line }

    # ---------------------------------------------------------------------------------------------------- 2. the federated credential
    $id = Get-SIUserAssignedIdentity -ResourceGroupName $ResourceGroup -Name $IdentityName -SubscriptionId $SubscriptionId -ErrorAction SilentlyContinue
    if (-not $id) { throw ('The web app''s identity {0} was not found in {1}. Nothing was changed.' -f $IdentityName, $ResourceGroup) }
    $graph = 'https://graph.microsoft.com/v1.0'
    $appReg = Invoke-SISigninFrontGraph -Method Get -Uri ("$graph/applications(appId='{0}')?`$select=id,appId,passwordCredentials" -f $SignInClientId) -TenantId $TenantId
    if (-not $appReg -or -not [string]$appReg.id) { throw ('The app registration {0} could not be read. Nothing was changed.' -f $SignInClientId) }
    $ficUri = "$graph/applications/{0}/federatedIdentityCredentials" -f $appReg.id
    $fics = @((Invoke-SISigninFrontGraph -Method Get -Uri $ficUri -TenantId $TenantId).value)
    if (Test-SIManagementFederatedCredential -Credentials $fics -TenantId $TenantId -PrincipalId ([string]$id.PrincipalId)) {
        & $say ('federated credential: the web identity {0} is trusted by the app registration already' -f $IdentityName)
    } else {
        & $say ('POST {0}  (the web identity as a federated credential -- no secret, no certificate)' -f $ficUri)
        if ($Apply) {
            $null = Invoke-SISigninFrontGraph -Method Post -Uri $ficUri -Body (Get-SIManagementFederatedCredentialSpec -TenantId $TenantId -PrincipalId ([string]$id.PrincipalId)) -TenantId $TenantId
            $ok = $false
            for ($i = 1; $i -le 6 -and -not $ok; $i++) {
                $fics = @((Invoke-SISigninFrontGraph -Method Get -Uri $ficUri -TenantId $TenantId).value)
                $ok = Test-SIManagementFederatedCredential -Credentials $fics -TenantId $TenantId -PrincipalId ([string]$id.PrincipalId)
                if (-not $ok -and $i -lt 6) { if ($Sleep) { & $Sleep 10 } else { Start-Sleep -Seconds 10 } }
            }
            if (-not $ok) { throw 'The federated credential was added but does not read back. Nothing else was changed; run the same command again.' }
            & $say 'federated credential: added and read back'
        }
    }

    # ---------------------------------------------------------------------------------------------------- 2b. the front's store
    # #852: the front 1.3.0 keeps its sessions and keys in the Pro database and wraps the keys with a Key Vault key; it
    # refuses to start without them. Made here as the CALLER (an administrator): the key, the identity's right on that key
    # only, its database user, its own schema, CREATE TABLE -- each when missing, read back (SI-SigninFrontStore.ps1).
    $storeEnv = @()
    $needStore = Test-SISigninFrontNeedsStore -Pin $pin
    $sqlSrv = $(if ("$SqlServer".Trim()) { "$SqlServer".Trim() } else { (Get-SISigninFrontWebSetting -App $before -Name 'Estate__SqlServer').Trim() })
    $sqlDb = $(if ("$SqlDatabase".Trim()) { "$SqlDatabase".Trim() } else { (Get-SISigninFrontWebSetting -App $before -Name 'Estate__SqlDatabase').Trim() })
    $kvName = "$KeyVaultName".Trim()
    # a front before 1.3.0 needs no store: made here only when asked for (-KeyVaultName); the update makes it otherwise
    $wantStore = ($needStore -or [bool]$kvName)
    if ($wantStore -and -not $kvName) {
        # the install's own vault: the only Key Vault in its resource group
        try {
            $vs = @(Invoke-SIArm -Path ('/subscriptions/{0}/resourceGroups/{1}/providers/Microsoft.KeyVault/vaults' -f $SubscriptionId, $ResourceGroup) -ApiVersion '2023-07-01' -List)
            if ($vs.Count -eq 1) { $kvName = [string]$vs[0].name }
        } catch { $kvName = '' }
    }
    $storeWhy = ''
    if (-not $wantStore) { }
    elseif (-not $kvName) { $storeWhy = 'the install''s Key Vault could not be told (pass -KeyVaultName)' }
    elseif (-not $sqlSrv -or -not $sqlDb) { $storeWhy = 'the Pro database could not be read from the web app (Estate__SqlServer / Estate__SqlDatabase; pass -SqlServer / -SqlDatabase)' }
    else {
        $st = Invoke-SISigninFrontStoreAsCaller -SubscriptionId $SubscriptionId -ResourceGroup $ResourceGroup -KeyVaultName $kvName -SqlServer $sqlSrv -SqlDatabase $sqlDb `
                  -Identity ([pscustomobject]@{ ClientId = [string]$id.ClientId; PrincipalId = [string]$id.PrincipalId; Name = $IdentityName }) -Apply:$Apply -Sleep $Sleep
        foreach ($l in @($st.Lines)) { & $say $l }
        if ($st.Ok) { $storeEnv = @($st.Env) } elseif ($Apply) { $storeWhy = $st.Why }
    }
    if ($storeWhy) {
        if ($needStore) { throw ('The sign-in front {0} needs its store, and it is not ready: {1}. Nothing was changed on the web app.' -f $pin.version, $storeWhy) }
        Write-Warning ('sign-in front store: {0} -- the front {1} runs without it; a front from 1.3.0 on needs it' -f $storeWhy, $pin.version)
        $done.Add(('WARNING: sign-in front store: ' + $storeWhy))
    }

    # ---------------------------------------------------------------------------------------------------- 2c. the app's own API
    # #852 / front 1.4.0: the identifier URI, the scope user_impersonation and the app's organisation-wide consent to it
    # (SI-SigninFrontApi.ps1), read back -- only then does the front get SIGNIN_UPSTREAM_SCOPE (an access token for the app's
    # own API). Not in place: the front signs in with the ID token, as 1.3.0 does (a warning, never a stop).
    if ((Get-Command -Name Test-SISigninFrontWantsScope -ErrorAction SilentlyContinue) -and (Test-SISigninFrontWantsScope -Pin $pin)) {
        $fa = Invoke-SISigninFrontApi -Graph $consentGraph -ClientId $SignInClientId -Apply:$Apply -Sleep $(if ($Sleep) { $Sleep } else { { param($s) Start-Sleep -Seconds $s } })
        foreach ($l in @($fa.Lines)) { if ($fa.State -in 'no-read', 'no-rights', 'failed') { Write-Warning $l; $done.Add(('WARNING: ' + $l)) } else { & $say $l } }
        if ($fa.Ok -and @($storeEnv).Count) { $storeEnv = @($storeEnv) + @('SIGNIN_UPSTREAM_SCOPE={0}' -f $fa.Scope) }
    }

    # ---------------------------------------------------------------------------------------------------- 3. the image
    $registry =Get-SIContainerRegistry -ResourceGroupName $ResourceGroup -Name $RegistryName -SubscriptionId $SubscriptionId
    $login = if ($registry -and [string]$registry.loginServer) { [string]$registry.loginServer } else { '{0}.azurecr.io' -f $RegistryName }
    $tag = Get-SISigninFrontImageTag -Pin $pin -SourcePath $src.BuildPath
    $frontImage = '{0}/{1}:{2}' -f $login, $pin.image, $tag
    $result.FrontImage = $frontImage
    $have = ($state.FrontImage -eq $frontImage)
    if (-not $have) { $have = Test-SISigninFrontImageInRegistry -LoginServer $login -Repo ([string]$pin.image) -Tag $tag }
    if ($have) { & $say ('image: {0} is in the registry already' -f $frontImage) }
    else {
        & $say ('build: {0}:{1} in {2} from the component''s signed source ({3})' -f $pin.image, $tag, $RegistryName, $pin.dockerfile)
        if ($Apply) {
            $b = Invoke-SIAcrRestBuild -SubscriptionId $SubscriptionId -ResourceGroup $ResourceGroup -RegistryName $RegistryName -SourcePath $src.BuildPath `
                    -ImageNames @(('{0}:{1}' -f $pin.image, $tag)) -DockerFilePath ([string]$pin.dockerfile) -Sleep $Sleep
            if (-not $b.Ok) { throw ('The sign-in front image did not build (run {0}: {1}). Nothing was changed on the web app.' -f $b.RunId, $b.Status) }
        }
    }

    # ---------------------------------------------------------------------------------------------------- 4. the two-container revision
    $frontEnv = Get-SISigninFrontEnv -TenantId $TenantId -ClientId $SignInClientId -ManagedIdentityClientId ([string]$id.ClientId) -Pin $pin -StoreEnv $storeEnv
    $plan = New-SISigninFrontPatch -App $before -FrontImage $frontImage -FrontEnv $frontEnv -Pin $pin
    if (-not $plan.Changed -and "$($plan.Why)".Trim()) {
        if ($Apply) { throw ('{0}. Nothing was changed on the web app.' -f $plan.Why) }
        & $say ('{0}: {1} (plan: the store above is made first)' -f $AppName, $plan.Why)
    }
    elseif (-not $plan.Changed) { & $say ('{0}: behind the sign-in front {1} already' -f $AppName, $tag) }
    else {
        & $say ('PATCH {0}  (the sign-in front as the second container of the same revision; the web app on 127.0.0.1:{1}; the ingress on port {2})' -f $appPath, $pin.upstreamPort, $pin.listenPort)
        if ($Apply) {
            try {
                $null = Invoke-SIManagementArmWrite -Method PATCH -Path $appPath -Body $plan.Body -Sleep $Sleep
                $back = Wait-SISigninFrontApp -SubscriptionId $SubscriptionId -ResourceGroup $ResourceGroup -AppName $AppName -Pin $pin -Want on -FrontImage $frontImage -TimeoutSec $WaitSec -Sleep $Sleep
                if (-not $back.Ok) { throw ('it did not read back: {0}' -f $back.Why) }
                $serve = Test-SISigninFrontServing -Fqdn ([string](Get-SISigninFrontProp $back.App @('properties', 'configuration', 'ingress', 'fqdn')))
                if ($serve.Ok -eq $false) { throw $serve.Why }
                if ($null -eq $serve.Ok) { & $say ('NOTE: {0} -- open the address in a private browser window: it must ask you to sign in' -f $serve.Why) }
            } catch {
                $why = $_.Exception.Message
                & $say ('{0}: the switch to the sign-in front FAILED ({1}) -- putting back what ran before' -f $AppName, $why)
                try { $null = Invoke-SIManagementArmWrite -Method PATCH -Path $appPath -Body (New-SISigninFrontRestorePatch -Before $before) -Sleep $Sleep; & $say ('{0}: put back' -f $AppName) }
                catch { & $say ('{0}: could NOT be put back: {1} -- contact Invardia support' -f $AppName, $_.Exception.Message) }
                throw ('The web app was not switched to the sign-in front: {0}. The client secrets were not touched.' -f $why)
            }
            $result.Changed = $true
            & $say ('{0}: behind the sign-in front {1} (read back, healthy)' -f $AppName, $tag)
        }
    }

    # ---------------------------------------------------------------------------------------------------- 5. Easy Auth off
    $authPath = $appPath + '/authConfigs/current'
    $auth = $null
    try { $auth = Invoke-SIArm -Path $authPath -ApiVersion (Get-SIManagementAppApi) -AllowNotFound } catch { $auth = $null }
    if ($auth -and [bool](Get-SISigninFrontProp $auth @('properties', 'platform', 'enabled'))) {
        & $say ('PUT {0}  (Easy Auth off: the front signs users in)' -f $authPath)
        if ($Apply) {
            $body = ConvertTo-SISigninFrontPlain $auth
            foreach ($k in 'id', 'name', 'type', 'systemData') { if ($body.Contains($k)) { $body.Remove($k) } }
            $body.properties.platform.enabled = $false
            $null = Invoke-SIArm -Method PUT -Path $authPath -ApiVersion (Get-SIManagementAppApi) -Body $body
            $again = Invoke-SIArm -Path $authPath -ApiVersion (Get-SIManagementAppApi) -AllowNotFound
            if ($again -and [bool](Get-SISigninFrontProp $again @('properties', 'platform', 'enabled'))) { throw 'Easy Auth was turned off but reads back on. The client secrets were not touched.' }
            & $say 'Easy Auth: off (read back)'
        }
    } else { & $say 'Easy Auth: not on this app (SecurityInsight never used it)' }

    # ---------------------------------------------------------------------------------------------------- 6. the old client secrets
    if (-not $Apply) { & $say 'client secrets: deleted only after the switch reads back (plan)'; return [pscustomobject]$result }
    $result.Applied = $true
    if ($KeepClientSecrets) { & $say 'client secrets: kept (-KeepClientSecrets)'; return [pscustomobject]$result }
    $now = Wait-SISigninFrontApp -SubscriptionId $SubscriptionId -ResourceGroup $ResourceGroup -AppName $AppName -Pin $pin -Want on -FrontImage $frontImage -TimeoutSec 0 -Sleep $Sleep
    if (-not $now.Ok) { & $say ('client secrets: KEPT -- the switch does not read back ({0})' -f $now.Why); return [pscustomobject]$result }
    $ids = @(Get-SISigninFrontSecretIds -PasswordCredentials @($appReg.passwordCredentials))
    if (-not $ids.Count) { & $say 'client secrets: the app registration has none' ; return [pscustomobject]$result }
    foreach ($k in $ids) {
        & $say ('POST {0}/applications/{1}/removePassword  (key {2})' -f $graph, $appReg.id, $k)
        $null = Invoke-SISigninFrontGraph -Method Post -Uri ("$graph/applications/{0}/removePassword" -f $appReg.id) -Body ([ordered]@{ keyId = $k }) -TenantId $TenantId
    }
    $left = @(Get-SISigninFrontSecretIds -PasswordCredentials @((Invoke-SISigninFrontGraph -Method Get -Uri ("$graph/applications/{0}?`$select=passwordCredentials" -f $appReg.id) -TenantId $TenantId).passwordCredentials))
    $still = @($ids | Where-Object { $left -contains $_ })
    if ($still.Count) { throw ('Client secrets were removed but {0} still read back: {1}' -f $still.Count, ($still -join ', ')) }
    $result.SecretsRemoved = $ids
    & $say ('client secrets: {0} deleted (read back as gone)' -f $ids.Count)
    [pscustomobject]$result
}
