#Requires -Version 5.1
<#
    SecurityInsight -- THE UPDATE TALKS TO AZURE OVER REST ONLY (#521, operator 2026-10-09: "we dont support az modules. pure
    rest or arm only", "want to not be dependent on it", "modern single connect only"; framework section 12.17: ONE connect
    path -- the product's own REST token client; no az login, no Connect-AzAccount, not even as a fallback).

    The updater job (container/updater/Start-SIUpdater.ps1) and the update script it runs (setup/Invoke-SIContainerUpdate.ps1)
    sign in ONCE with SecurityInsight's own token client (engine/_shared/SI-AzRest.ps1 + auth/SI-ManagedIdentity.ps1):

      * SI_UPDATER_AUTH = ManagedIdentity  -> the job's user-assigned identity (SI_UPDATER_CLIENT_ID = its client id);
      * SI_UPDATER_AUTH = Certificate (the default) -> the SPN SI_UPDATER_CLIENT_ID in SI_UPDATER_TENANT_ID with the PFX in
        SI_UPDATER_CERT_PFX_B64 (+ SI_UPDATER_CERT_PASSWORD). The PFX goes into the X509 store the token signer reads; the
        temporary file is removed at once;
      * none of these set (the VM sync hook): the run's own sign-in -- the config's SI_SPN_* app or managed identity, as the
        engines sign in (Resolve-SIAzRestAuth).

    EVERY CALL goes through ONE seam with the shape setup/_shared/SI-KedaConvert.ps1 introduced:
        -Rest { param([string]$Method, [string]$Uri, $Body, [string]$Resource, [hashtable]$Headers) } -> @{ Status; Body; Headers }
    $Resource is the token audience (https://management.azure.com/, https://storage.azure.com/, https://graph.microsoft.com/,
    https://vault.azure.net/) -- or '' for a call that must carry NO bearer token (a SAS upload, a SAS log download, the
    registry's own token exchange). Every 4xx but 401 is an ANSWER for the caller (404 = not there, 409 = busy); 401 refreshes
    the token once; 429 / 5xx / no answer are retried. The seam never throws: no answer at all is Status 0.

    PowerShell 5.1-compatible (the VM sync hook); the updater container runs pwsh 7.
#>

$script:SIUpdateRestRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
if (-not (Get-Command -Name Invoke-SIAzRestRequest -ErrorAction SilentlyContinue)) { . ([IO.Path]::Combine($script:SIUpdateRestRoot, 'engine', '_shared', 'SI-AzRest.ps1')) }
if (-not (Get-Command -Name Get-SIManagedIdentityToken -ErrorAction SilentlyContinue)) {
    $siUpdMi = [IO.Path]::Combine($script:SIUpdateRestRoot, 'auth', 'SI-ManagedIdentity.ps1')
    if (Test-Path -LiteralPath $siUpdMi) { . $siUpdMi }
}
$script:SIUpdateArmBase = 'https://management.azure.com'
$script:SIUpdateArmResource = 'https://management.azure.com/'

function Get-SIUpdateRestSignIn {
    <#
        PURE. Which identity the update signs in as, from the updater job's settings (-Env first, then the process
        environment): @{ Mode = ManagedIdentity | Certificate | Config; ClientId; TenantId; PfxB64; PfxPassword; Reason }.
        Config = no updater identity is configured here: the run's own sign-in (the config's SI_SPN_* app / managed identity).
        Throws on an SI_UPDATER_AUTH that is neither ManagedIdentity nor Certificate, and on a certificate sign-in without its PFX.
    #>
    param([hashtable]$Env = @{})
    $g = { param($k) $v = if ($Env -and $Env.ContainsKey($k)) { $Env[$k] } else { [Environment]::GetEnvironmentVariable($k) }; "$v".Trim() }
    $client = & $g 'SI_UPDATER_CLIENT_ID'
    if (-not $client) { return [pscustomobject]@{ Mode = 'Config'; ClientId = ''; TenantId = ''; PfxB64 = ''; PfxPassword = ''; Reason = 'the run''s own sign-in (the config''s SI_SPN_* app or managed identity)' } }
    $auth = & $g 'SI_UPDATER_AUTH'
    if ($auth -ieq 'ManagedIdentity') { return [pscustomobject]@{ Mode = 'ManagedIdentity'; ClientId = $client; TenantId = (& $g 'SI_UPDATER_TENANT_ID'); PfxB64 = ''; PfxPassword = ''; Reason = ('the managed identity {0}' -f $client) } }
    if ($auth -and $auth -ine 'Certificate') { throw "SI_UPDATER_AUTH must be 'ManagedIdentity' or 'Certificate', not '$auth'." }
    $pfx = & $g 'SI_UPDATER_CERT_PFX_B64'
    if (-not $pfx) { throw 'SI_UPDATER_CERT_PFX_B64 is not set on the updater job (the certificate sign-in needs it; or set SI_UPDATER_AUTH = ManagedIdentity).' }
    [pscustomobject]@{ Mode = 'Certificate'; ClientId = $client; TenantId = (& $g 'SI_UPDATER_TENANT_ID'); PfxB64 = $pfx; PfxPassword = (& $g 'SI_UPDATER_CERT_PASSWORD'); Reason = ('the service principal {0} (certificate)' -f $client) }
}

function Connect-SIUpdateRest {
    <#
        THE ONE SIGN-IN of an update: records the identity in SecurityInsight's REST client (Connect-SIAzAccountRest; tokens
        are minted per call). A sign-in this process already recorded is kept (the updater signed in before it ran the
        release's update script). Returns one plain line naming the identity. No az, no PowerShell module.
    #>
    param([string]$SubscriptionId, [hashtable]$Env = @{})
    $st = Get-SIAzRestState
    if ($st.Connection -is [hashtable]) {
        if ($SubscriptionId -and -not $st.SubscriptionId) { $st.SubscriptionId = $SubscriptionId }
        return 'the sign-in this process already has'
    }
    $s = Get-SIUpdateRestSignIn -Env $Env
    switch ($s.Mode) {
        'ManagedIdentity' {
            $null = Connect-SIAzAccountRest -Identity -AccountId $s.ClientId -Tenant $s.TenantId -Subscription $SubscriptionId
        }
        'Certificate' {
            $pfxFile = Join-Path ([IO.Path]::GetTempPath()) ('si-upd-' + [guid]::NewGuid().ToString('N').Substring(0, 12) + '.pfx')
            [IO.File]::WriteAllBytes($pfxFile, [Convert]::FromBase64String($s.PfxB64))
            try {
                $c = @{ ServicePrincipal = $true; ApplicationId = $s.ClientId; CertificatePath = $pfxFile; Tenant = $s.TenantId; Subscription = $SubscriptionId }
                if ($s.PfxPassword) { $c['CertificatePassword'] = (ConvertTo-SecureString -String $s.PfxPassword -AsPlainText -Force) }
                $null = Connect-SIAzAccountRest @c
            } finally { [IO.File]::Delete($pfxFile) }
        }
        default {
            if ($SubscriptionId -and -not $st.SubscriptionId) { $st.SubscriptionId = $SubscriptionId }
        }
    }
    $s.Reason
}

function Get-SIUpdateRestSubscription {
    <# The subscription of this update: SI_UPDATER_SUBSCRIPTION_ID, else the one the sign-in recorded. '' when neither. #>
    $v = "$([Environment]::GetEnvironmentVariable('SI_UPDATER_SUBSCRIPTION_ID'))".Trim()
    if ($v) { return $v }
    try { $st = Get-SIAzRestState; if ($st.SubscriptionId) { return [string]$st.SubscriptionId } } catch { }
    ''
}

function Get-SIUpdateRestAudience {
    <# PURE. The REST client's audience for a token resource; '' = no bearer token at all (SAS / registry token exchange). #>
    param([AllowEmptyString()][string]$Resource)
    $r = "$Resource".Trim().ToLowerInvariant()
    if (-not $r) { return '' }
    if ($r -like 'https://management.*') { return 'Arm' }
    if ($r -like 'https://storage.*') { return 'Storage' }
    if ($r -like 'https://graph.*') { return 'Graph' }
    if ($r -like 'https://vault.*') { return 'KeyVault' }
    if ($r -like 'https://api.loganalytics.*') { return 'LaQuery' }
    if ($r -like 'https://monitor.*') { return 'Monitor' }
    throw ("no token audience is known for '{0}'" -f $Resource)
}

function Invoke-SIUpdateRestCall {
    <#
        The real seam behind New-SIUpdateRestSeam. Never throws: @{ Status (0 = no answer); Body (text); Headers }.
        A Content-Type in -Headers is the request's content type; a body that is not text or bytes is sent as JSON.
        #911 (c) (live 2026-10-27: an update was silent for an hour after a step): EVERY call with a token (ARM, Graph, Key
        Vault, Log Analytics) has a timeout (-TimeoutSec, 120 s: a control-plane answer takes seconds) and a bounded retry
        (4 attempts on 408 / 429 / 5xx / no answer), and when it gives up its answer NAMES the call ("<METHOD> <url> failed
        after 4 attempts" / "... timed out after 120 s"). A call without a token (a SAS upload or download) keeps its own
        longer timeout (it carries a build context or a log).
    #>
    param([string]$Method = 'GET', [Parameter(Mandatory)][string]$Uri, $Body, [AllowEmptyString()][string]$Resource = '', [hashtable]$Headers, [int]$TimeoutSec = 120)
    $ct = 'application/json'; $h = @{}
    if ($Headers) { foreach ($k in @($Headers.Keys)) { if ([string]$k -ieq 'Content-Type') { $ct = [string]$Headers[$k] } else { $h[[string]$k] = $Headers[$k] } } }
    if ($null -ne $Body -and -not ($Body -is [string]) -and -not ($Body -is [byte[]])) { $Body = ConvertTo-Json -InputObject $Body -Depth 60 -Compress }
    try { $aud = Get-SIUpdateRestAudience -Resource $Resource } catch { return [pscustomobject]@{ Status = 0; Body = $_.Exception.Message; Headers = @{} } }
    # #564 (PIM's install at customer I): an ARM POST action with no body (listSecrets, listBuildSourceUploadUrl, listLogSasUrl, a
    # revision restart) sends '{}' -- an empty body with a JSON content type was refused with HTTP 415
    if ($aud -eq 'Arm' -and "$Method".ToUpperInvariant() -eq 'POST' -and ($null -eq $Body -or ([string]$Body) -eq '')) { $Body = '{}' }
    if (-not $aud) {
        # NO bearer token: the SAS in the URL, or the caller's own Authorization header, is the credential.
        # Inside an Invardia Support session a URL that carries its own SAS (sig=) goes through the session's recording
        # command, which adds no token to such a URL -- so an upload to, or a download from, the environment is recorded.
        $viaSupport = ([string]$Uri -match '[?&]sig=') -and (Test-Path -LiteralPath 'Function:\Test-SISupportRequestRoute') -and (Test-SISupportRequestRoute -Audience Storage)
        for ($a = 1; $a -le 4; $a++) {
            if ($viaSupport) { $r = Invoke-SISupportHttp -Method $Method -Uri $Uri -Headers $h -Body $Body -ContentType $ct -Audience Storage }
            else { $r = Invoke-SIAzRestHttp -Method $Method -Uri $Uri -Headers $h -Body $Body -ContentType $ct }
            $code = [int]$r.StatusCode
            if (($code -eq 0 -or $code -eq 408 -or $code -eq 429 -or $code -ge 500) -and $a -lt 4) { Start-Sleep -Seconds ([int][Math]::Min(30, [Math]::Pow(2, $a))); continue }
            return [pscustomobject]@{ Status = $code; Body = [string]$r.Content; Headers = $r.Headers }
        }
    }
    try {
        $what = '{0} {1}' -f $Method, ($Uri -replace '\?.*$', '')
        $r = Invoke-SIAzRestRequest -Method $Method -Uri $Uri -Audience $aud -Body $Body -ContentType $ct -Headers $h -AllowStatus (@(400) + @(402..499)) -MaxAttempts 4 -TimeoutSec $TimeoutSec -What $what
        [pscustomobject]@{ Status = [int]$r.StatusCode; Body = [string]$r.Content; Headers = $r.Headers }
    } catch {
        $st = 0; $resp = $_.Exception.PSObject.Properties['Response']
        if ($resp -and $resp.Value -and $resp.Value.PSObject.Properties['StatusCode']) { try { $st = [int]$resp.Value.StatusCode } catch { $st = 0 } }
        # #911 (c): the answer names the call that gave up (and its timeout), never only what the network said
        $m = [string]$_.Exception.Message
        $w = '{0} {1}' -f $Method, ($Uri -replace '\?.*$', '')
        if ($m -notlike "*$w*") { $m = ('{0} gave up (timeout {1} s, 4 attempts): {2}' -f $w, $TimeoutSec, $m) }
        [pscustomobject]@{ Status = $st; Body = $m; Headers = @{} }
    }
}

function New-SIUpdateRestSeam {
    <# The REST seam of an update (see the file header), over SecurityInsight's own token client. Sign in first (Connect-SIUpdateRest). #>
    { param([string]$Method, [string]$Uri, $Body, [string]$Resource, [hashtable]$Headers) Invoke-SIUpdateRestCall -Method $Method -Uri $Uri -Body $Body -Resource $Resource -Headers $Headers }
}

function Get-SIUpdateRestSeam {
    <# Signs in (Connect-SIUpdateRest: the updater job's identity, else the run's own) and returns the seam. For a caller that passed none. #>
    param([string]$SubscriptionId)
    if (-not $SubscriptionId) { $SubscriptionId = Get-SIUpdateRestSubscription }
    $null = Connect-SIUpdateRest -SubscriptionId $SubscriptionId
    New-SIUpdateRestSeam
}

function Format-SIRestFailure {
    <# PURE. One readable line for a REST answer that is not a success: 'HTTP <code>: <ARM code: message | the body>' (max 400 characters). #>
    param($Response)
    $code = 0; try { $code = [int]$Response.Status } catch { }
    $body = ("$($Response.Body)" -replace '\s+', ' ').Trim()
    try {
        $j = $body | ConvertFrom-Json -ErrorAction Stop
        if ($j -and $j.PSObject.Properties['error'] -and $j.error) { $body = ('{0}: {1}' -f $j.error.code, $j.error.message) }
    } catch { }
    if ($body.Length -gt 400) { $body = $body.Substring(0, 397) + '...' }
    if ($code -le 0) { return ('no answer: {0}' -f $body) }
    'HTTP {0}: {1}' -f $code, $body
}

function Invoke-SIRestJson {
    <#
        One call through -Rest, the answer parsed. 2xx -> the parsed body ($null when it is empty); 404 with -AllowNotFound ->
        $null; anything else THROWS '<What> failed: HTTP <code>: <reason>' (the reason is what Azure said).
    #>
    param([Parameter(Mandatory)][scriptblock]$Rest, [string]$Method = 'GET', [Parameter(Mandatory)][string]$Uri, $Body,
          [AllowEmptyString()][string]$Resource = 'https://management.azure.com/', [hashtable]$Headers, [switch]$AllowNotFound, [string]$What = '')
    $r = & $Rest $Method $Uri $Body $Resource $Headers
    $code = 0; try { $code = [int]$r.Status } catch { }
    if ($code -eq 404 -and $AllowNotFound) { return $null }
    if ($code -lt 200 -or $code -ge 300) {
        throw ('{0} failed: {1}' -f $(if ($What) { $What } else { '{0} {1}' -f $Method, ($Uri -replace '\?.*$', '') }), (Format-SIRestFailure -Response $r))
    }
    $t = "$($r.Body)".Trim()
    if (-not $t) { return $null }
    ConvertFrom-Json -InputObject $t
}

function Get-SIRestList {
    <# Every item of an ARM list (value[]), following nextLink. Throws when a page cannot be read (Invoke-SIRestJson). #>
    param([Parameter(Mandatory)][scriptblock]$Rest, [Parameter(Mandatory)][string]$Uri, [string]$What = '', [int]$MaxPages = 50)
    $all = New-Object System.Collections.Generic.List[object]
    $url = $Uri
    for ($p = 0; $url -and $p -lt $MaxPages; $p++) {
        $page = Invoke-SIRestJson -Rest $Rest -Uri $url -What $What
        $url = ''
        if ($page -and $page.PSObject.Properties['value']) {
            foreach ($x in @($page.value)) { if ($null -ne $x) { $all.Add($x) } }
            if ($page.PSObject.Properties['nextLink']) { $url = [string]$page.nextLink }
        } elseif ($page) { $all.Add($page) }
    }
    $all.ToArray()   # enumerated: wrap the call in @( )
}

function Get-SIArmUri {
    <# PURE. https://management.azure.com<path>?api-version=<v> (a path that already names one keeps it). #>
    param([Parameter(Mandatory)][string]$Path, [Parameter(Mandatory)][string]$ApiVersion)
    # the base is written out here, NOT read from a script variable: a script that finds these functions already defined
    # by its caller does not dot-source this file again, so this file's script variables do not exist in its scope --
    # the URL then went out without a host (a new install in a Support session stopped at the registry, 2026-10-12)
    $u = if ($Path -match '^https://') { $Path } else { 'https://management.azure.com' + $Path }
    if ($u -match '[?&]api-version=') { return $u }
    $u + $(if ($u.Contains('?')) { '&' } else { '?' }) + 'api-version=' + $ApiVersion
}

function New-SITemplateImagePatchBody {
    <#
        PURE. The ARM PATCH body that points a Container Apps job's or app's FIRST container at -Image -- what
        `az containerapp (job) update --image` did, as ONE read-modify-write of properties.template: the resource's own
        template as read, only that image changed; never the configuration (ARM returns secrets without values). The
        default imageType and the read-only ephemeralStorage are left out (the live 400 of 2026-10-06). Returns the JSON text.
        -MinCpu / -MinMemoryGi (both or neither): the first container is RAISED to at least that size; a bigger one is kept.
    #>
    param([Parameter(Mandatory)]$Resource, [Parameter(Mandatory)][string]$Image, [double]$MinCpu = 0, [double]$MinMemoryGi = 0)
    $tpl = ConvertTo-Json -InputObject $Resource.properties.template -Depth 60 | ConvertFrom-Json
    $first = @($tpl.containers | Where-Object { $_ }) | Select-Object -First 1
    if (-not $first) { throw 'the resource has no container to point at the image' }
    $first.image = $Image
    if ($MinCpu -gt 0 -and $MinMemoryGi -gt 0) {
        $inv = [Globalization.CultureInfo]::InvariantCulture
        $cpuNow = 0.0; $memNow = 0.0
        if ($first.PSObject.Properties['resources'] -and $first.resources) {
            try { $cpuNow = [double]::Parse([string]$first.resources.cpu, $inv) } catch { $cpuNow = 0.0 }
            $m = [regex]::Match([string]$first.resources.memory, '^\s*([0-9]+(?:\.[0-9]+)?)\s*Gi\s*$')
            if ($m.Success) { $memNow = [double]::Parse($m.Groups[1].Value, $inv) }
        }
        if ($cpuNow -lt $MinCpu -or $memNow -lt $MinMemoryGi) {
            # Container Apps takes a cpu / memory PAIR it supports: both are set together, to the larger of now and the minimum
            $cpu = [Math]::Max($cpuNow, $MinCpu); $mem = [Math]::Max($memNow, $MinMemoryGi)
            $res = [ordered]@{ cpu = $cpu; memory = ('{0}Gi' -f $mem.ToString($inv)) }
            if ($first.PSObject.Properties['resources']) { $first.resources = [pscustomobject]$res } else { $first | Add-Member -NotePropertyName resources -NotePropertyValue ([pscustomobject]$res) }
        }
    }
    foreach ($c in (@($tpl.containers) + @($tpl.initContainers))) {
        if (-not $c) { continue }
        if ($c.PSObject.Properties['imageType'] -and ([string]$c.imageType -in '', 'ContainerImage')) { $c.PSObject.Properties.Remove('imageType') }
        if ($c.PSObject.Properties['resources'] -and $c.resources -and $c.resources.PSObject.Properties['ephemeralStorage']) { $c.resources.PSObject.Properties.Remove('ephemeralStorage') }
    }
    ConvertTo-Json -InputObject ([ordered]@{ properties = [ordered]@{ template = $tpl } }) -Depth 60 -Compress
}
