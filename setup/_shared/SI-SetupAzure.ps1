#Requires -Version 5.1
<#
    SecurityInsight SETUP -- Azure with NO PowerShell modules: native REST, ARM and .NET only.

    Dot-source this ONE file at the top of a setup script (setup\, setup\ConfigWizard\backend\, Bootstrap-*, Setup-*):

        . (Join-Path $PSScriptRoot 'setup\_shared\SI-SetupAzure.ps1')      # from the solution root
        . (Join-Path $PSScriptRoot '_shared\SI-SetupAzure.ps1')            # from setup\
        Connect-SISetupAzure -TenantId $tid -SubscriptionId $sub           # a person, or an app (see below)

    It loads the engine's REST layer (engine/_shared/SI-AzRest.ps1: Invoke-SIArm, Resource Graph, Key Vault secrets,
    storage data plane, the *-SIAz* REST twins), switches this process to REST (SI_AzureAccess_Engine = 'Rest'), adds the
    sign-in of a PERSON (SI-SetupSignIn.ps1: Azure Cloud Shell token endpoint, or the browser with code + PKCE), and adds
    what setup needs that the engines never did: Key Vault vaults and certificates, resource providers, deleting a role
    assignment, typed ARM reads (resources, VMs, managed identities, SQL, Azure OpenAI, tenants, Log Analytics tables)
    and storage management (tables, containers and queues through ARM, the lifecycle policy, name availability --
    never an account key).

    Every call goes through Invoke-SIAzRestHttp (the engine's one HTTP seam), so the offline tests run it against a fake.

    INSIDE AN INVARDIA SUPPORT SESSION (owner 2026-10-12) setup signs in to NOTHING itself: Connect-SISetupAzure and
    Get-SISetupAzureContext answer from the session (engine/_shared/SI-AzRest.ps1, Get-SISupportSession -- the one place
    that detects it), and every call goes through the session's recording command, so each change is in the
    environment's audit log. A subscription the session does not name is refused.
    PS 5.1 safe; pwsh 7 on Windows, Linux (Azure Cloud Shell) and macOS.
#>

# NO Set-StrictMode here -- it leaks into the caller's scope.

$__siSetupAzureRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
. ([IO.Path]::Combine($__siSetupAzureRoot, 'engine', '_shared', 'SI-AzRest.ps1'))
. ([IO.Path]::Combine($__siSetupAzureRoot, 'engine', '_shared', 'SI-LogIngest.ps1'))
. ([IO.Path]::Combine($__siSetupAzureRoot, 'auth', 'Find-SICertificate.ps1'))
. ([IO.Path]::Combine($__siSetupAzureRoot, 'auth', 'SI-ManagedIdentity.ps1'))
. ([IO.Path]::Combine($PSScriptRoot, 'SI-SetupSignIn.ps1'))
Remove-Variable -Name __siSetupAzureRoot -ErrorAction SilentlyContinue

# Setup never loads an Az module: every *-SIAz* wrapper takes its REST twin, and log ingestion its REST path.
$global:SI_AzureAccess_Engine = 'Rest'
$global:SI_LogIngest_Engine   = 'Rest'

function Get-SIAzureToken {
    <#
        THE token function of the REST layer, as setup needs it: a signed-in PERSON (Connect-SISetupUser) is answered
        from the setup sign-in; an app or a managed identity exactly as engine/_shared/SI-AzRest.ps1 does. Defined here,
        after that file, so every REST helper -- Invoke-SIArm, the *-SIAz* twins, Key Vault, storage, Graph -- runs as
        whoever signed in.
    #>
    param(
        [ValidateSet('Arm', 'LaQuery', 'Storage', 'KeyVault', 'Graph', 'Monitor')][string]$Audience = 'Arm',
        [string]$Resource,
        [hashtable]$Auth,
        [switch]$ForceRefresh
    )
    if (-not $Resource) { $Resource = Get-SIAzureAudience -Audience $Audience }
    if (-not $Auth) {
        # an Invardia Support session in the shell is setup's sign-in (never a person's or an app's beside it)
        $null = Sync-SISupportConnection -TakeOver
        $st = Get-SIAzRestState
        if ($st.Connection -is [hashtable] -and $st.Connection.Mode -eq 'User') { $Auth = $st.Connection }
    }
    if ($Auth -and $Auth.Mode -eq 'User') { return (Get-SISetupUserToken -Resource $Resource -ForceRefresh:$ForceRefresh) }
    # the engine's own hook ($global:SI_TokenProvider), exactly as engine/_shared/SI-AzRest.ps1 consults it
    if (-not $Auth) {
        $tp = Get-Variable -Scope Global -Name SI_TokenProvider -ValueOnly -ErrorAction Ignore
        if ($tp -is [scriptblock]) { $pt = [string](& $tp $Resource); if (-not [string]::IsNullOrWhiteSpace($pt)) { return $pt } }
    }
    Initialize-SIAzRestHelpers
    if (-not $Auth) { $Auth = Resolve-SIAzRestAuth }
    return (Get-SILogIngestToken -Resource $Resource -Auth $Auth -ForceRefresh:$ForceRefresh)
}
# published globally too: a child script that loads only the engine file still finds the setup sign-in
Set-Item -Path 'function:global:Get-SIAzureToken' -Value ${function:Get-SIAzureToken}

# =====================================================================================================================
#  Sign-in: one entry point for a person, an app or a managed identity
# =====================================================================================================================

function Connect-SISetupAzure {
    <#
        Signs this PowerShell process in to Azure for setup. No module, no Connect-AzAccount.
          -ApplicationId + -CertificateThumbprint   an app with a certificate (LocalMachine\My or CurrentUser\My)
          -ApplicationId + -ClientSecret            an app with a client secret (string or SecureString)
          -Identity [-ManagedIdentityClientId]      this host's managed identity
          (none of these)                           a PERSON: Azure Cloud Shell, else the browser (-UserSignIn)
        AN INVARDIA SUPPORT SESSION open in this shell IS the sign-in: nothing is signed in here (no browser, no
        certificate, no token request) -- the context is the session's: its tenant, and -SubscriptionId when the session
        names it, else its first subscription. A subscription or tenant the session does not name is refused, and so is
        -ApplicationId / -Identity (a sign-in beside the session would not be recorded there). One plain line says so.
        ONE connect path (#524): an existing Azure session of this process (Connect-AzAccount, az login) is never used.
        An existing sign-in in this process is REUSED (same tenant) unless -Force. -SubscriptionId selects the
        subscription every following call works in. The app/identity is proven by asking for an ARM token at once, so a
        wrong secret or certificate fails here, not three steps later. Returns Get-SISetupAzureContext.
    #>
    [CmdletBinding()]
    param(
        [string]$TenantId,
        [string]$SubscriptionId,
        [string]$ApplicationId,
        [string]$CertificateThumbprint,
        $ClientSecret,
        [switch]$Identity,
        [string]$ManagedIdentityClientId,
        [ValidateSet('Auto', 'CloudShell', 'Browser')][string]$UserSignIn = 'Auto',
        [string]$LoginHint,
        [int]$TimeoutSec = 300,
        [switch]$Force
    )
    $st = Get-SIAzRestState
    $app = ($ApplicationId -and ($CertificateThumbprint -or $ClientSecret))
    $sess = Get-SISupportSession
    if ($sess) {
        $name = Get-SISupportSessionName $sess
        if ($app -or $Identity) {
            $who = if ($Identity) { 'a managed identity' } else { 'the app {0}' -f $ApplicationId }
            throw ('An Invardia Support session for {0} is open in this PowerShell session: SecurityInsight setup works through it, so every change is recorded there. Signing in here as {1} would not be recorded -- refused. Run the same command without the sign-in parameters, or end the session first (Disconnect-InvardiaSupport).' -f $name, $who)
        }
        if ($TenantId -and $TenantId -ne $sess.TenantId) {
            throw ('The Invardia Support session for {0} is for tenant {1}, not {2} -- refused. Connect the support session of tenant {2}.' -f $name, $sess.TenantId, $TenantId)
        }
        if ($SubscriptionId) { Assert-SISupportSubscription -SubscriptionId $SubscriptionId -Session $sess }
        if (Test-SISetupUserSignedIn) { Disconnect-SISetupUser }
        return (Get-SISetupAzureContext -SubscriptionId $SubscriptionId)
    }
    $null = Sync-SISupportConnection   # a Support sign-in whose session was closed is dropped
    $existing = $st.Connection
    $reuse = (-not $Force) -and ($existing -is [hashtable]) -and (-not $app) -and (-not $Identity) -and
             ((-not $TenantId) -or ([string]$existing.TenantId -eq $TenantId) -or ($existing.Mode -eq 'ManagedIdentity'))
    if (-not $reuse) {
        if ($app -or $Identity) {
            if (Test-SISetupUserSignedIn) { Disconnect-SISetupUser }
            $c = @{}
            if ($Identity) {
                $c['Identity'] = $true
                if ($ManagedIdentityClientId) { $c['AccountId'] = $ManagedIdentityClientId }
            } elseif ($CertificateThumbprint) {
                $c['ServicePrincipal'] = $true; $c['ApplicationId'] = $ApplicationId; $c['CertificateThumbprint'] = $CertificateThumbprint; $c['Tenant'] = $TenantId
            } else {
                $sec = if ($ClientSecret -is [System.Security.SecureString]) { $ClientSecret } else { ConvertTo-SISecureString -Text ([string]$ClientSecret) }
                $c['ServicePrincipal'] = $true; $c['Credential'] = New-Object System.Management.Automation.PSCredential($ApplicationId, $sec); $c['Tenant'] = $TenantId
            }
            if ($SubscriptionId) { $c['Subscription'] = $SubscriptionId }
            $null = Connect-SIAzAccountRest @c
            if ($global:SI_LogIngestRunCache -is [hashtable]) { $global:SI_LogIngestRunCache.Tokens = @{} }
            try { $null = Get-SIAzureToken -Audience Arm -ForceRefresh }
            catch {
                $st.Connection = $null
                $who = if ($Identity) { 'the managed identity of this host' } else { 'app {0}' -f $ApplicationId }
                throw ('Signing in to Azure as {0} failed: {1}' -f $who, $_.Exception.Message)
            }
        } elseif ([string](Get-Variable -Scope Global -Name SI_AuthMethod -ValueOnly -ErrorAction Ignore) -eq 'AzContext') {
            # #524: the retired sign-in mode "AzContext" (borrow this process's Azure session) is refused -- never a silent fallback
            throw ('SI_AuthMethod = AzContext (use the current Azure session of this PowerShell process) is no longer supported: setup signs in itself -- a person (Azure Cloud Shell or the browser), or an app with -ApplicationId and -CertificateThumbprint or -ClientSecret, or -Identity. Supported sign-ins: {0}.' -f (Get-SISupportedSignInText))
        } else {
            $u = Connect-SISetupUser -TenantId $TenantId -Method $UserSignIn -LoginHint $LoginHint -TimeoutSec $TimeoutSec
            # #876: a sign-in handed over by the installation page may be an APPLICATION's (IsApp): it is then a service
            # principal for every check that asks who installs -- its object id is the service principal's
            $isApp = [bool]($u.PSObject.Properties['IsApp'] -and $u.IsApp)
            $st.Connection = @{ Mode = 'User'; AppId = $u.Account; TenantId = $u.TenantId; ObjectId = $u.ObjectId; Method = $u.Method; IsApp = $isApp }
            $st.TenantId = $u.TenantId
            $st.SubscriptionId = $null
            $st.Cache = @{}
        }
    }
    if ($SubscriptionId) { $st.SubscriptionId = $SubscriptionId }
    return (Get-SISetupAzureContext)
}

function ConvertTo-SISecureString {
    param([string]$Text)
    $s = New-Object System.Security.SecureString
    foreach ($ch in ([string]$Text).ToCharArray()) { $s.AppendChar($ch) }
    $s.MakeReadOnly()
    return $s
}

function Get-SISetupAzureContext {
    <#
        Who this process is signed in as -- the shape setup read from Get-AzContext: Account.Id / .Type ('User',
        'ServicePrincipal', 'ManagedService'), Account.ObjectId, Tenant.Id, Subscription.Id / .Name, SignInMethod.
        $null when nobody is signed in.
        In an Invardia Support session the context IS the session's (SignInMethod 'Support', read from the session -- no
        sign-in and no token request): its tenant, and -SubscriptionId when the session names it, else the install's
        configured subscription, else the session's first. THROWS only what a Support session refuses: a subscription it
        does not name, another tenant than the configured one, a session without its recording command.
        -SubscriptionId selects the subscription the following calls work in (as Connect-SISetupAzure -SubscriptionId).
    #>
    param([string]$SubscriptionId)
    $st = Get-SIAzRestState
    $sess = Sync-SISupportConnection -TakeOver
    $c = $st.Connection
    if (-not ($c -is [hashtable])) {
        # an app configured through the SI_SPN_* globals counts as signed in (the engines' own rule)
        try { $c = Resolve-SIAzRestAuth } catch { return $null }
    }
    if ($SubscriptionId) {
        if ($sess) { Assert-SISupportSubscription -SubscriptionId $SubscriptionId -Session $sess }
        $st.SubscriptionId = $SubscriptionId
    }
    $type = switch ([string]$c.Mode) { 'User' { $(if ($c['IsApp']) { 'ServicePrincipal' } else { 'User' }) } 'ManagedIdentity' { 'ManagedService' } default { 'ServicePrincipal' } }
    $id = switch ([string]$c.Mode) { 'ManagedIdentity' { $(if ($c.ClientId) { [string]$c.ClientId } else { 'MSI' }) } default { [string]$c.AppId } }
    $tid = [string]$st.TenantId
    if (-not $tid) { $tid = [string]$c.TenantId }
    if (-not $tid -and $c.Mode -ne 'User') { try { $tid = Get-SIAzRestTenantId } catch { } }
    $sub = $null
    try { $sub = Get-SIAzRestSubscriptionId } catch { }
    if ($sess -and $sub) {
        Assert-SISupportSubscription -SubscriptionId $sub -Session $sess
        # the session already knows its first subscription's name: no call for it
        if ($sess.SubscriptionName -and ([string]$sub).Trim().ToLowerInvariant() -eq $sess.SubscriptionId -and -not $st.Cache.ContainsKey('subname|' + $sub)) { $st.Cache['subname|' + $sub] = [string]$sess.SubscriptionName }
    }
    $subName = $sub
    if ($sub) {
        $k = 'subname|' + $sub
        if ($st.Cache.ContainsKey($k)) { $subName = $st.Cache[$k] }
        else {
            try { $s = Invoke-SIArm -Path ('/subscriptions/' + $sub) -ApiVersion '2022-12-01' -AllowNotFound; if ($s -and $s.displayName) { $subName = [string]$s.displayName } } catch { }
            $st.Cache[$k] = $subName
        }
    }
    return [pscustomobject]@{
        PSTypeName   = 'SI.Setup.AzureContext'
        Name         = ('{0} ({1})' -f $subName, $id)
        Account      = [pscustomobject]@{ Id = $id; Type = $type; ObjectId = $(if ($c.ObjectId) { [string]$c.ObjectId } else { $null }) }
        Tenant       = [pscustomobject]@{ Id = $tid; TenantId = $tid }
        Subscription = $(if ($sub) { [pscustomobject]@{ Id = $sub; SubscriptionId = $sub; Name = $subName; TenantId = $tid } } else { $null })
        SignInMethod = $(if ($c.Mode -eq 'User') { [string]$c.Method } else { [string]$c.Mode })
    }
}

function Disconnect-SISetupAzure {
    Disconnect-SISetupUser
    Disconnect-SIAzAccountRest
}

function Get-SISetupSignedInObjectId {
    <# The object id of whoever is signed in: the person (from their token), else the app's service principal. #>
    $st = Get-SIAzRestState
    $c = $st.Connection
    if ($c -is [hashtable] -and $c.ObjectId) { return [string]$c.ObjectId }
    try {
        $claims = ConvertFrom-SIJwtPayload (Get-SIAzureToken -Audience Arm)
        if ($claims -and $claims.oid) { return [string]$claims.oid }
    } catch { }
    return $null
}

# =====================================================================================================================
#  Small ARM helpers
# =====================================================================================================================

function Get-SISetupSubscriptionId {
    param([string]$SubscriptionId)
    if ($SubscriptionId) { return $SubscriptionId }
    $s = Get-SIAzRestSubscriptionId
    if (-not $s) { throw 'No Azure subscription is selected. Pass the subscription id (or sign in with access to one) and run the same command again.' }
    return $s
}

function Get-SIArmResourceGroupFromId {
    param([string]$Id)
    if ([string]$Id -match '/resourceGroups/([^/]+)/') { return $Matches[1] }
    return $null
}

# =====================================================================================================================
#  (2) Key Vault: vaults (ARM) and certificates (data plane)
# =====================================================================================================================

function ConvertTo-SIKeyVaultObject {
    param($V)
    [pscustomobject]@{
        VaultName                 = [string]$V.name
        ResourceId                = [string]$V.id
        ResourceGroupName         = (Get-SIArmResourceGroupFromId $V.id)
        Location                  = [string]$V.location
        VaultUri                  = [string]$V.properties.vaultUri
        TenantId                  = [string]$V.properties.tenantId
        Sku                       = [string]$V.properties.sku.name
        EnableRbacAuthorization   = [bool]$V.properties.enableRbacAuthorization
        EnableSoftDelete          = [bool]$V.properties.enableSoftDelete
        EnablePurgeProtection     = [bool]$V.properties.enablePurgeProtection
        PublicNetworkAccess       = [string]$V.properties.publicNetworkAccess
        ProvisioningState         = [string]$V.properties.provisioningState
        Tags                      = $V.tags
    }
}

function Get-SIKeyVault {
    <#
        A Key Vault by name, the way Get-AzKeyVault found it: in -ResourceGroupName, else anywhere in the subscription.
        -InRemovedState -Location: the soft-deleted vault of that name (DeletionDate, ScheduledPurgeDate). Not found is a
        non-terminating error (so -ErrorAction SilentlyContinue gives $null), as for the cmdlet.
    #>
    [CmdletBinding()]
    param([Alias('Name')][string]$VaultName, [string]$ResourceGroupName, [switch]$InRemovedState, [string]$Location, [string]$SubscriptionId)
    $sub = Get-SISetupSubscriptionId -SubscriptionId $SubscriptionId
    if ($InRemovedState) {
        if (-not $Location) { throw 'Get-SIKeyVault -InRemovedState needs -Location.' }
        $d = Invoke-SIArm -Path ("/subscriptions/$sub/providers/Microsoft.KeyVault/locations/$Location/deletedVaults/$VaultName") -ApiVersion '2023-07-01' -AllowNotFound
        if (-not $d) { Write-SIAzRestNotFound -Cmdlet $PSCmdlet -Message ("No deleted Key Vault '{0}' in {1}." -f $VaultName, $Location) -Target $VaultName; return }
        return [pscustomobject]@{
            VaultName = [string]$d.name; Id = [string]$d.id; Location = [string]$d.properties.location; ResourceId = [string]$d.properties.vaultId
            DeletionDate = $d.properties.deletionDate; ScheduledPurgeDate = $d.properties.scheduledPurgeDate; EnablePurgeProtection = [bool]$d.properties.purgeProtectionEnabled
        }
    }
    if ($VaultName -and $ResourceGroupName) {
        $v = Invoke-SIArm -Path ("/subscriptions/$sub/resourceGroups/$ResourceGroupName/providers/Microsoft.KeyVault/vaults/$VaultName") -ApiVersion '2023-07-01' -AllowNotFound
        if (-not $v) { Write-SIAzRestNotFound -Cmdlet $PSCmdlet -Message ("The Key Vault '{0}' was not found in resource group '{1}'." -f $VaultName, $ResourceGroupName) -Target $VaultName; return }
        return (ConvertTo-SIKeyVaultObject $v)
    }
    $path = if ($ResourceGroupName) { "/subscriptions/$sub/resourceGroups/$ResourceGroupName/providers/Microsoft.KeyVault/vaults" } else { "/subscriptions/$sub/providers/Microsoft.KeyVault/vaults" }
    $found = $false
    foreach ($v in @(Invoke-SIArm -Path $path -ApiVersion '2023-07-01' -List)) {
        if ($VaultName -and [string]$v.name -ne $VaultName) { continue }
        $found = $true
        ConvertTo-SIKeyVaultObject $v
    }
    if ($VaultName -and -not $found) { Write-SIAzRestNotFound -Cmdlet $PSCmdlet -Message ("The Key Vault '{0}' was not found in subscription {1}." -f $VaultName, $sub) -Target $VaultName }
}

function New-SIKeyVault {
    <# Creates (PUT) a Key Vault: soft delete on, Azure RBAC authorization by default, and waits until it is ready. #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][Alias('Name')][string]$VaultName,
        [Parameter(Mandatory)][string]$ResourceGroupName,
        [Parameter(Mandatory)][string]$Location,
        [ValidateSet('standard', 'premium', 'Standard', 'Premium')][string]$Sku = 'standard',
        [bool]$EnableRbacAuthorization = $true,
        [switch]$EnablePurgeProtection,
        [int]$SoftDeleteRetentionInDays = 90,
        [hashtable]$Tag,
        [string]$SubscriptionId,
        [string]$TenantId,
        # #866 (a private install; owner: "we will not allow fw option or exceptions"): 'Disabled' CREATES the vault with no
        # public access at all (its firewall Deny, trusted Microsoft services allowed) -- a policy that refuses a public
        # vault never sees one. Empty: Azure's default, as before.
        [ValidateSet('', 'Disabled')][string]$PublicNetworkAccess = ''
    )
    $sub = Get-SISetupSubscriptionId -SubscriptionId $SubscriptionId
    if (-not $TenantId) { $TenantId = Get-SIAzRestTenantId }
    $props = [ordered]@{
        tenantId                  = $TenantId
        sku                       = @{ family = 'A'; name = $Sku.ToLowerInvariant() }
        enableRbacAuthorization   = $EnableRbacAuthorization
        enableSoftDelete          = $true
        softDeleteRetentionInDays = $SoftDeleteRetentionInDays
        accessPolicies            = @()
    }
    if ($EnablePurgeProtection) { $props['enablePurgeProtection'] = $true }
    if ($PublicNetworkAccess -eq 'Disabled') {
        $props['publicNetworkAccess'] = 'Disabled'
        $props['networkAcls'] = [ordered]@{ defaultAction = 'Deny'; bypass = 'AzureServices'; ipRules = @(); virtualNetworkRules = @() }
    }
    $body = [ordered]@{ location = $Location; properties = $props }
    if ($Tag) { $body['tags'] = $Tag }
    $path = "/subscriptions/$sub/resourceGroups/$ResourceGroupName/providers/Microsoft.KeyVault/vaults/$VaultName"
    $v = Invoke-SIArm -Method PUT -Path $path -ApiVersion '2023-07-01' -Body $body
    for ($i = 0; $i -lt 30 -and $v -and [string]$v.properties.provisioningState -and [string]$v.properties.provisioningState -notin 'Succeeded', 'Failed'; $i++) {
        Start-Sleep -Seconds 5
        $v = Invoke-SIArm -Path $path -ApiVersion '2023-07-01' -AllowNotFound
    }
    if (-not $v) { throw ("The Key Vault '{0}' was requested but did not appear." -f $VaultName) }
    return (ConvertTo-SIKeyVaultObject $v)
}

function Test-SIKeyVaultNameAvailability {
    <# Microsoft.KeyVault checkNameAvailability: NameAvailable, Reason, Message. #>
    param([Parameter(Mandatory)][string]$Name, [string]$SubscriptionId)
    $sub = Get-SISetupSubscriptionId -SubscriptionId $SubscriptionId
    $r = Invoke-SIArm -Method POST -Path ("/subscriptions/$sub/providers/Microsoft.KeyVault/checkNameAvailability") -ApiVersion '2022-07-01' -Body @{ name = $Name; type = 'Microsoft.KeyVault/vaults' }
    return [pscustomobject]@{ NameAvailable = [bool]$r.nameAvailable; Reason = [string]$r.reason; Message = [string]$r.message }
}

function ConvertFrom-SIBase64UrlToHex {
    param([string]$Text)
    if (-not $Text) { return $null }
    $p = $Text.Replace('-', '+').Replace('_', '/')
    switch ($p.Length % 4) { 2 { $p += '==' } 3 { $p += '=' } }
    return (([Convert]::FromBase64String($p) | ForEach-Object { $_.ToString('X2') }) -join '')
}

function ConvertTo-SIKeyVaultCertificateObject {
    param($J, [string]$VaultName, [string]$Name)
    $x = $null
    if ($J.cer) { try { $x = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2(,[Convert]::FromBase64String([string]$J.cer)) } catch { } }
    $thumb = if ($x) { [string]$x.Thumbprint } else { ConvertFrom-SIBase64UrlToHex ([string]$J.x5t) }
    $exp = $null
    if ($J.attributes -and $J.attributes.exp) { try { $exp = [DateTimeOffset]::FromUnixTimeSeconds([long]$J.attributes.exp).UtcDateTime } catch { } }
    [pscustomobject]@{
        VaultName = $VaultName; Name = $Name; Id = [string]$J.id; SecretId = [string]$J.sid; KeyId = [string]$J.kid
        Thumbprint = $thumb; Certificate = $x; Enabled = $(if ($J.attributes) { [bool]$J.attributes.enabled } else { $null }); Expires = $exp
    }
}

function Get-SIKeyVaultCertificate {
    <# One certificate (current version) from a vault's data plane; $null (non-terminating error) when absent. #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$VaultName, [Parameter(Mandatory)][string]$Name)
    $uri = 'https://{0}.vault.azure.net/certificates/{1}?api-version=7.4' -f $VaultName, [uri]::EscapeDataString($Name)
    $r = Invoke-SIAzRestRequest -Method GET -Uri $uri -Audience KeyVault -AllowNotFound -What ("Key Vault certificate '{0}' in '{1}'" -f $Name, $VaultName)
    if (-not $r) { Write-SIAzRestNotFound -Cmdlet $PSCmdlet -Message ("The certificate '{0}' was not found in Key Vault '{1}'." -f $Name, $VaultName) -Target $Name; return }
    return (ConvertTo-SIKeyVaultCertificateObject -J ($r.Content | ConvertFrom-Json) -VaultName $VaultName -Name $Name)
}

function Import-SIKeyVaultCertificate {
    <# Imports a PFX (-FilePath or -CertificateBytes, optional -Password) into a vault as certificate -Name. #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$VaultName,
        [Parameter(Mandatory)][string]$Name,
        [string]$FilePath,
        [byte[]]$CertificateBytes,
        $Password
    )
    if (-not $CertificateBytes) {
        if (-not $FilePath) { throw 'Import-SIKeyVaultCertificate needs -FilePath or -CertificateBytes.' }
        $CertificateBytes = [System.IO.File]::ReadAllBytes($FilePath)
    }
    $pw = if ($Password -is [System.Security.SecureString]) { [System.Net.NetworkCredential]::new('', $Password).Password } else { [string]$Password }
    $body = [ordered]@{ value = [Convert]::ToBase64String($CertificateBytes); policy = @{ secret_props = @{ contentType = 'application/x-pkcs12' } } }
    if ($pw) { $body['pwd'] = $pw }
    $uri = 'https://{0}.vault.azure.net/certificates/{1}/import?api-version=7.4' -f $VaultName, [uri]::EscapeDataString($Name)
    $r = Invoke-SIAzRestRequest -Method POST -Uri $uri -Audience KeyVault -Body ($body | ConvertTo-Json -Depth 5 -Compress) -What ("Importing certificate '{0}' into Key Vault '{1}'" -f $Name, $VaultName)
    return (ConvertTo-SIKeyVaultCertificateObject -J ($r.Content | ConvertFrom-Json) -VaultName $VaultName -Name $Name)
}

# =====================================================================================================================
#  (3) Resource providers
# =====================================================================================================================

function Get-SIResourceProvider {
    <# A resource provider's registration in the subscription: ProviderNamespace, RegistrationState, ResourceTypes. #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$ProviderNamespace, [string]$SubscriptionId)
    $sub = Get-SISetupSubscriptionId -SubscriptionId $SubscriptionId
    $p = Invoke-SIArm -Path ("/subscriptions/$sub/providers/$ProviderNamespace") -ApiVersion '2021-04-01' -AllowNotFound
    if (-not $p) { Write-SIAzRestNotFound -Cmdlet $PSCmdlet -Message ("The resource provider '{0}' was not found." -f $ProviderNamespace) -Target $ProviderNamespace; return }
    return [pscustomobject]@{ ProviderNamespace = [string]$p.namespace; RegistrationState = [string]$p.registrationState; ResourceTypes = @($p.resourceTypes); Id = [string]$p.id }
}

function Get-SISetupResourceProviderList {
    <#
        PURE. #564: EVERY resource provider a SecurityInsight install WRITES to -- the guided install checks and registers
        these before the first resource. Container Apps (Microsoft.App), the registry, the workspace, diagnostic settings and
        data collection (Microsoft.Insights), the managed identities, the Key Vault, the storage account; Pro adds Azure SQL.
        Microsoft.Network is NOT listed: SecurityInsight creates no network resource (no virtual network, private endpoint
        or public IP; the Container Apps environment is a consumption one without a virtual network).
    #>
    param([switch]$Pro)
    $l = @('Microsoft.App', 'Microsoft.OperationalInsights', 'Microsoft.Insights', 'Microsoft.ContainerRegistry', 'Microsoft.ManagedIdentity', 'Microsoft.KeyVault', 'Microsoft.Storage')
    if ($Pro) { $l += 'Microsoft.Sql' }
    $l
}

function Register-SIResourceProvider {
    <# Registers a resource provider in the subscription (idempotent; Azure finishes it in the background). #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$ProviderNamespace, [string]$SubscriptionId)
    $sub = Get-SISetupSubscriptionId -SubscriptionId $SubscriptionId
    $p = Invoke-SIArm -Method POST -Path ("/subscriptions/$sub/providers/$ProviderNamespace/register") -ApiVersion '2021-04-01'
    return [pscustomobject]@{ ProviderNamespace = $ProviderNamespace; RegistrationState = $(if ($p) { [string]$p.registrationState } else { 'Registering' }) }
}

function Get-SIArmApiVersion {
    <# The newest non-preview api-version ARM offers for -ResourceType ('Microsoft.Sql/servers', 'Microsoft.Sql/servers/databases'). Cached. #>
    param([Parameter(Mandatory)][string]$ResourceType, [string]$SubscriptionId)
    $st = Get-SIAzRestState
    $key = 'apiver|' + $ResourceType.ToLowerInvariant()
    if ($st.Cache.ContainsKey($key)) { return $st.Cache[$key] }
    $ns, $rest = $ResourceType -split '/', 2
    $p = Get-SIResourceProvider -ProviderNamespace $ns -SubscriptionId $SubscriptionId -ErrorAction SilentlyContinue
    $rt = @($p.ResourceTypes | Where-Object { [string]$_.resourceType -eq $rest }) | Select-Object -First 1
    $v = @(@($rt.apiVersions) | Where-Object { $_ -and $_ -notmatch 'preview' } | Sort-Object -Descending) | Select-Object -First 1
    if (-not $v) { $v = @(@($rt.apiVersions) | Sort-Object -Descending) | Select-Object -First 1 }
    if (-not $v) { throw ("Azure does not offer the resource type '{0}' in this subscription." -f $ResourceType) }
    $st.Cache[$key] = [string]$v
    return [string]$v
}

# =====================================================================================================================
#  (4) Role assignments: delete, and "what does this principal hold, through its groups too"
# =====================================================================================================================

function Remove-SIRoleAssignment {
    <#
        Deletes a role assignment: -RoleAssignmentId, or every assignment of -RoleDefinitionName to -ObjectId exactly at
        -Scope. Returns what was removed. Absent = nothing to do (idempotent).
    #>
    [CmdletBinding()]
    param([string]$RoleAssignmentId, [string]$ObjectId, [string]$RoleDefinitionName, [string]$Scope)
    $ids = @()
    if ($RoleAssignmentId) { $ids = @($RoleAssignmentId) }
    else {
        if (-not ($ObjectId -and $RoleDefinitionName -and $Scope)) { throw 'Remove-SIRoleAssignment needs -RoleAssignmentId, or -ObjectId with -RoleDefinitionName and -Scope.' }
        $ids = @(Get-SIAzRoleAssignmentRest -ObjectId $ObjectId -Scope $Scope -RoleDefinitionName $RoleDefinitionName |
                 Where-Object { ([string]$_.Scope).TrimEnd('/') -ieq $Scope.TrimEnd('/') } | ForEach-Object { [string]$_.RoleAssignmentId })
    }
    foreach ($id in $ids) {
        $null = Invoke-SIArm -Method DELETE -Path $id -ApiVersion '2022-04-01' -AllowNotFound
        [pscustomobject]@{ RoleAssignmentId = $id; ObjectId = $ObjectId; RoleDefinitionName = $RoleDefinitionName; Scope = $Scope }
    }
}

function New-SIRoleAssignment {
    <#
        Assigns -RoleDefinitionName to -ObjectId at -Scope, with the principal's type stated (-PrincipalType, default
        ServicePrincipal) -- what New-AzRoleAssignment -ObjectType did: ARM then accepts a principal that was created
        seconds ago and has not replicated yet. Same output shape as New-SIAzRoleAssignment.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$ObjectId,
        [Parameter(Mandatory)][string]$Scope,
        [Parameter(Mandatory)][string]$RoleDefinitionName,
        [ValidateSet('ServicePrincipal', 'User', 'Group', 'ForeignGroup', 'Device')][string]$PrincipalType = 'ServicePrincipal'
    )
    $subScope = if ($Scope -match '^(/subscriptions/[^/]+)') { $Matches[1] } else { $Scope }
    $def = @(Get-SIAzRestRoleDefinitions -Scope $subScope | Where-Object { [string]$_.properties.roleName -eq $RoleDefinitionName }) | Select-Object -First 1
    if (-not $def) { throw ("The role definition '{0}' was not found at scope '{1}'." -f $RoleDefinitionName, $subScope) }
    $body = @{ properties = @{ roleDefinitionId = [string]$def.id; principalId = $ObjectId; principalType = $PrincipalType } }
    $a = Invoke-SIArm -Method PUT -Path ($Scope.TrimEnd('/') + '/providers/Microsoft.Authorization/roleAssignments/' + [guid]::NewGuid().ToString()) -ApiVersion '2022-04-01' -Body $body
    return [pscustomobject]@{ RoleAssignmentId = [string]$a.id; RoleAssignmentName = [string]$a.name; Scope = $Scope; RoleDefinitionName = $RoleDefinitionName; RoleDefinitionId = [string]$def.name; ObjectId = $ObjectId; ObjectType = $PrincipalType }
}

function Get-SIRoleAssignmentAssignedTo {
    <#
        The role assignments that apply to -ObjectId at or above -Scope, INCLUDING those it holds through a group
        (ARM's assignedTo() filter -- what Get-AzRoleAssignment -ExpandPrincipalGroups returned). Same object shape as
        Get-SIAzRoleAssignment.
    #>
    param([Parameter(Mandatory)][string]$ObjectId, [string]$Scope, [string]$RoleDefinitionName)
    if (-not $Scope) { $Scope = '/subscriptions/' + (Get-SISetupSubscriptionId) }
    $path = $Scope.TrimEnd('/') + '/providers/Microsoft.Authorization/roleAssignments?$filter=' + [uri]::EscapeDataString(("assignedTo('{0}')" -f $ObjectId))
    $items = @(Invoke-SIArm -Path $path -ApiVersion '2022-04-01' -List)
    $subScope = if ($Scope -match '^(/subscriptions/[^/]+)') { $Matches[1] } else { $Scope }
    $defs = @{}
    foreach ($d in @(Get-SIAzRestRoleDefinitions -Scope $subScope)) { $defs[([string]$d.name).ToLowerInvariant()] = [string]$d.properties.roleName }
    foreach ($a in $items) {
        $rdId = ([string]$a.properties.roleDefinitionId -split '/')[-1]
        $rdName = $defs[$rdId.ToLowerInvariant()]
        if ($RoleDefinitionName -and $rdName -ne $RoleDefinitionName) { continue }
        [pscustomobject]@{
            RoleAssignmentId = [string]$a.id; RoleAssignmentName = [string]$a.name; Scope = [string]$a.properties.scope
            RoleDefinitionName = $rdName; RoleDefinitionId = $rdId; ObjectId = [string]$a.properties.principalId; ObjectType = [string]$a.properties.principalType
        }
    }
}

# =====================================================================================================================
#  (5) Typed ARM reads
# =====================================================================================================================

function Get-SIArmResource {
    <#
        One resource by -ResourceId (api-version given, or the newest ARM offers for its type), or every resource of
        -ResourceType (and -Name / -ResourceGroupName) in the subscription -- what Get-AzResource did. Objects carry
        ResourceId, Id, Name, ResourceGroupName, ResourceType, Location, Tags, Properties, Identity.
    #>
    [CmdletBinding()]
    param([string]$ResourceId, [string]$ResourceType, [string]$Name, [string]$ResourceGroupName, [string]$ApiVersion, [string]$SubscriptionId)
    $conv = {
        param($R)
        [pscustomobject]@{
            ResourceId = [string]$R.id; Id = [string]$R.id; Name = [string]$R.name; ResourceGroupName = (Get-SIArmResourceGroupFromId $R.id)
            ResourceType = [string]$R.type; Type = [string]$R.type; Location = [string]$R.location; Tags = $R.tags; Kind = [string]$R.kind
            Sku = $R.sku; Properties = $R.properties; Identity = $R.identity
        }
    }
    if ($ResourceId) {
        if (-not $ApiVersion) {
            $t = if ($ResourceId -match '/providers/([^/]+)/(.+)$') {
                $segs = $Matches[2] -split '/'
                $Matches[1] + '/' + ((0..($segs.Count - 1) | Where-Object { $_ % 2 -eq 0 } | ForEach-Object { $segs[$_] }) -join '/')
            } else { $null }
            if (-not $t) { throw ("Not an Azure resource id: {0}" -f $ResourceId) }
            $ApiVersion = Get-SIArmApiVersion -ResourceType $t
        }
        $r = Invoke-SIArm -Path $ResourceId -ApiVersion $ApiVersion -AllowNotFound
        if (-not $r) { Write-SIAzRestNotFound -Cmdlet $PSCmdlet -Message ("The resource '{0}' was not found." -f $ResourceId) -Target $ResourceId; return }
        return (& $conv $r)
    }
    $sub = Get-SISetupSubscriptionId -SubscriptionId $SubscriptionId
    $f = @()
    if ($ResourceType) { $f += ("resourceType eq '{0}'" -f $ResourceType) }
    if ($Name) { $f += ("name eq '{0}'" -f $Name) }
    $base = if ($ResourceGroupName) { "/subscriptions/$sub/resourceGroups/$ResourceGroupName/resources" } else { "/subscriptions/$sub/resources" }
    if ($f.Count) { $base += '?$filter=' + [uri]::EscapeDataString(($f -join ' and ')) }
    foreach ($r in @(Invoke-SIArm -Path $base -ApiVersion '2021-04-01' -List)) {
        if ($Name -and [string]$r.name -ne $Name) { continue }
        & $conv $r
    }
}

function Get-SIVirtualMachine {
    <# A VM: Name, Id, ResourceGroupName, Location, Identity (type, principalId, userAssignedIdentities), VmId. #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$ResourceGroupName, [Parameter(Mandatory)][string]$Name, [string]$SubscriptionId)
    $sub = Get-SISetupSubscriptionId -SubscriptionId $SubscriptionId
    $v = Invoke-SIArm -Path ("/subscriptions/$sub/resourceGroups/$ResourceGroupName/providers/Microsoft.Compute/virtualMachines/$Name") -ApiVersion '2023-09-01' -AllowNotFound
    if (-not $v) { Write-SIAzRestNotFound -Cmdlet $PSCmdlet -Message ("The virtual machine '{0}' was not found in resource group '{1}'." -f $Name, $ResourceGroupName) -Target $Name; return }
    [pscustomobject]@{ Name = [string]$v.name; Id = [string]$v.id; ResourceGroupName = $ResourceGroupName; Location = [string]$v.location; VmId = [string]$v.properties.vmId; Identity = $v.identity; Tags = $v.tags }
}

function Get-SIUserAssignedIdentity {
    <# A user-assigned managed identity: Name, Id, ClientId, PrincipalId, TenantId, Location. #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$ResourceGroupName, [Parameter(Mandatory)][string]$Name, [string]$SubscriptionId)
    $sub = Get-SISetupSubscriptionId -SubscriptionId $SubscriptionId
    $u = Invoke-SIArm -Path ("/subscriptions/$sub/resourceGroups/$ResourceGroupName/providers/Microsoft.ManagedIdentity/userAssignedIdentities/$Name") -ApiVersion '2023-01-31' -AllowNotFound
    if (-not $u) { Write-SIAzRestNotFound -Cmdlet $PSCmdlet -Message ("The managed identity '{0}' was not found in resource group '{1}'." -f $Name, $ResourceGroupName) -Target $Name; return }
    [pscustomobject]@{
        Name = [string]$u.name; Id = [string]$u.id; ResourceGroupName = $ResourceGroupName; Location = [string]$u.location
        ClientId = [string]$u.properties.clientId; PrincipalId = [string]$u.properties.principalId; TenantId = [string]$u.properties.tenantId
    }
}

function New-SIUserAssignedIdentity {
    <# Creates (or returns) a user-assigned managed identity. Idempotent: an existing one is returned unchanged. #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$ResourceGroupName, [Parameter(Mandatory)][string]$Name, [Parameter(Mandatory)][string]$Location,
          [string]$SubscriptionId, [hashtable]$Tag)
    $have = Get-SIUserAssignedIdentity -ResourceGroupName $ResourceGroupName -Name $Name -SubscriptionId $SubscriptionId -ErrorAction SilentlyContinue
    if ($have) { return $have }
    $sub = Get-SISetupSubscriptionId -SubscriptionId $SubscriptionId
    $body = @{ location = $Location }
    if ($Tag -and $Tag.Count) { $body.tags = $Tag }
    $path = "/subscriptions/$sub/resourceGroups/$ResourceGroupName/providers/Microsoft.ManagedIdentity/userAssignedIdentities/$Name"
    # The create's own answer carries the two ids; a read right after it can still say "not found", or come without them.
    # So: the answer first, then the identity re-read (6 x 5 s) until BOTH ids are there -- and a clear stop when they
    # never come: everything after this (role assignments, the jobs' sign-in) needs them.
    $u = Invoke-SIArm -Method PUT -Path $path -ApiVersion '2023-01-31' -Body $body
    $sleep = Get-Variable -Scope Global -Name SI_ArmBusySleep -ValueOnly -ErrorAction Ignore
    for ($i = 0; $i -lt 6; $i++) {
        if ($u -and $u.properties -and [string]$u.properties.clientId -and [string]$u.properties.principalId) { break }
        if ($sleep -is [scriptblock]) { & $sleep 5 } else { Start-Sleep -Seconds 5 }
        $u = Invoke-SIArm -Path $path -ApiVersion '2023-01-31' -AllowNotFound
    }
    if (-not $u -or -not $u.properties -or -not [string]$u.properties.clientId -or -not [string]$u.properties.principalId) {
        throw ("The managed identity '{0}' was created in resource group '{1}', but Azure does not show its client id and principal id yet -- run the same command again in a minute." -f $Name, $ResourceGroupName)
    }
    [pscustomobject]@{
        Name = [string]$u.name; Id = [string]$u.id; ResourceGroupName = $ResourceGroupName; Location = [string]$u.location
        ClientId = [string]$u.properties.clientId; PrincipalId = [string]$u.properties.principalId; TenantId = [string]$u.properties.tenantId
    }
}

function Get-SIVmIdentityPatchBody {
    <#
        PURE. The 'identity' body that ADDS a user-assigned identity to a VM and keeps every identity it already has: a
        system-assigned identity stays (type 'SystemAssigned, UserAssigned'), other user-assigned ones stay listed.
        Returns $null when the identity is already attached (nothing to change).
    #>
    param([AllowNull()]$CurrentIdentity, [Parameter(Mandatory)][string]$IdentityResourceId)
    $type = if ($CurrentIdentity -and $CurrentIdentity.PSObject.Properties['type']) { [string]$CurrentIdentity.type } else { '' }
    $ids = [ordered]@{}
    if ($CurrentIdentity -and $CurrentIdentity.PSObject.Properties['userAssignedIdentities'] -and $CurrentIdentity.userAssignedIdentities) {
        foreach ($p in $CurrentIdentity.userAssignedIdentities.PSObject.Properties) { $ids[$p.Name] = @{} }
    }
    if (@($ids.Keys | Where-Object { "$_" -ieq $IdentityResourceId }).Count) { return $null }
    $ids[$IdentityResourceId] = @{}
    $newType = if ($type -match '(?i)SystemAssigned') { 'SystemAssigned, UserAssigned' } else { 'UserAssigned' }
    @{ identity = @{ type = $newType; userAssignedIdentities = $ids } }
}

function Add-SIVmUserAssignedIdentity {
    <# Attaches a user-assigned identity to an Azure VM, keeping the identities it has. Returns $true when it changed. #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$ResourceGroupName, [Parameter(Mandatory)][string]$VmName,
          [Parameter(Mandatory)][string]$IdentityResourceId, [string]$SubscriptionId)
    $vm = Get-SIVirtualMachine -ResourceGroupName $ResourceGroupName -Name $VmName -SubscriptionId $SubscriptionId -ErrorAction Stop
    $body = Get-SIVmIdentityPatchBody -CurrentIdentity $vm.Identity -IdentityResourceId $IdentityResourceId
    if (-not $body) { return $false }
    $null = Invoke-SIArm -Method PATCH -Path $vm.Id -ApiVersion '2023-09-01' -Body $body
    $true
}

function Get-SISqlServer {
    <# Azure SQL logical servers: ServerName, ResourceId, ResourceGroupName, Location, FullyQualifiedDomainName, Administrators. #>
    [CmdletBinding()]
    param([string]$ResourceGroupName, [string]$ServerName, [string]$SubscriptionId)
    $sub = Get-SISetupSubscriptionId -SubscriptionId $SubscriptionId
    $conv = {
        param($S)
        [pscustomobject]@{
            ServerName = [string]$S.name; ResourceId = [string]$S.id; ResourceGroupName = (Get-SIArmResourceGroupFromId $S.id); Location = [string]$S.location
            FullyQualifiedDomainName = [string]$S.properties.fullyQualifiedDomainName; Administrators = $S.properties.administrators
            PublicNetworkAccess = [string]$S.properties.publicNetworkAccess; Tags = $S.tags
        }
    }
    if ($ResourceGroupName -and $ServerName) {
        $s = Invoke-SIArm -Path ("/subscriptions/$sub/resourceGroups/$ResourceGroupName/providers/Microsoft.Sql/servers/$ServerName") -ApiVersion '2021-11-01' -AllowNotFound
        if (-not $s) { Write-SIAzRestNotFound -Cmdlet $PSCmdlet -Message ("The SQL server '{0}' was not found in resource group '{1}'." -f $ServerName, $ResourceGroupName) -Target $ServerName; return }
        return (& $conv $s)
    }
    $path = if ($ResourceGroupName) { "/subscriptions/$sub/resourceGroups/$ResourceGroupName/providers/Microsoft.Sql/servers" } else { "/subscriptions/$sub/providers/Microsoft.Sql/servers" }
    foreach ($s in @(Invoke-SIArm -Path $path -ApiVersion '2021-11-01' -List)) { if (-not $ServerName -or [string]$s.name -eq $ServerName) { & $conv $s } }
}

function Get-SISqlDatabase {
    <# Databases of an Azure SQL server: DatabaseName, ResourceId, ServerName, Status, SkuName. #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$ResourceGroupName, [Parameter(Mandatory)][string]$ServerName, [string]$DatabaseName, [string]$SubscriptionId)
    $sub = Get-SISetupSubscriptionId -SubscriptionId $SubscriptionId
    $base = "/subscriptions/$sub/resourceGroups/$ResourceGroupName/providers/Microsoft.Sql/servers/$ServerName/databases"
    $conv = { param($D) [pscustomobject]@{ DatabaseName = [string]$D.name; ResourceId = [string]$D.id; ServerName = $ServerName; ResourceGroupName = $ResourceGroupName; Location = [string]$D.location; Status = [string]$D.properties.status; SkuName = [string]$D.sku.name } }
    if ($DatabaseName) {
        $d = Invoke-SIArm -Path ($base + '/' + $DatabaseName) -ApiVersion '2021-11-01' -AllowNotFound
        if (-not $d) { Write-SIAzRestNotFound -Cmdlet $PSCmdlet -Message ("The database '{0}' was not found on SQL server '{1}'." -f $DatabaseName, $ServerName) -Target $DatabaseName; return }
        return (& $conv $d)
    }
    foreach ($d in @(Invoke-SIArm -Path $base -ApiVersion '2021-11-01' -List)) { & $conv $d }
}

function Get-SICognitiveServicesAccount {
    <# Azure OpenAI / Cognitive Services accounts: AccountName, Id, ResourceGroupName, Kind, Endpoint, Location. #>
    [CmdletBinding()]
    param([string]$ResourceGroupName, [string]$Name, [string]$SubscriptionId)
    $sub = Get-SISetupSubscriptionId -SubscriptionId $SubscriptionId
    $conv = { param($A) [pscustomobject]@{ AccountName = [string]$A.name; Id = [string]$A.id; ResourceGroupName = (Get-SIArmResourceGroupFromId $A.id); Kind = [string]$A.kind; Location = [string]$A.location; Endpoint = [string]$A.properties.endpoint; Sku = [string]$A.sku.name } }
    if ($ResourceGroupName -and $Name) {
        $a = Invoke-SIArm -Path ("/subscriptions/$sub/resourceGroups/$ResourceGroupName/providers/Microsoft.CognitiveServices/accounts/$Name") -ApiVersion '2023-05-01' -AllowNotFound
        if (-not $a) { Write-SIAzRestNotFound -Cmdlet $PSCmdlet -Message ("The Azure AI account '{0}' was not found in resource group '{1}'." -f $Name, $ResourceGroupName) -Target $Name; return }
        return (& $conv $a)
    }
    $path = if ($ResourceGroupName) { "/subscriptions/$sub/resourceGroups/$ResourceGroupName/providers/Microsoft.CognitiveServices/accounts" } else { "/subscriptions/$sub/providers/Microsoft.CognitiveServices/accounts" }
    foreach ($a in @(Invoke-SIArm -Path $path -ApiVersion '2023-05-01' -List)) { if (-not $Name -or [string]$a.name -eq $Name) { & $conv $a } }
}

function Get-SITenant {
    <# The tenants the signed-in account can see: Id, TenantId, Name, DefaultDomain, Domains. -TenantId picks one. #>
    [CmdletBinding()]
    param([string]$TenantId)
    $found = $false
    foreach ($t in @(Invoke-SIArm -Path '/tenants' -ApiVersion '2022-12-01' -List)) {
        if ($TenantId -and [string]$t.tenantId -ne $TenantId) { continue }
        $found = $true
        [pscustomobject]@{ Id = [string]$t.tenantId; TenantId = [string]$t.tenantId; Name = [string]$t.displayName; DefaultDomain = [string]$t.defaultDomain; Domains = @($t.domains); TenantCategory = [string]$t.tenantCategory }
    }
    if ($TenantId -and -not $found) { Write-SIAzRestNotFound -Cmdlet $PSCmdlet -Message ("The tenant '{0}' is not visible to the signed-in account." -f $TenantId) -Target $TenantId }
}

function Get-SILogAnalyticsTable {
    <# One Log Analytics table (or all): Name, Id, Plan, RetentionInDays, TotalRetentionInDays, Schema (columns). #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$ResourceGroupName, [Parameter(Mandatory)][string]$WorkspaceName, [string]$TableName, [string]$SubscriptionId)
    $sub = Get-SISetupSubscriptionId -SubscriptionId $SubscriptionId
    $base = "/subscriptions/$sub/resourceGroups/$ResourceGroupName/providers/Microsoft.OperationalInsights/workspaces/$WorkspaceName/tables"
    $conv = { param($T) [pscustomobject]@{ Name = [string]$T.name; Id = [string]$T.id; Plan = [string]$T.properties.plan; RetentionInDays = $T.properties.retentionInDays; TotalRetentionInDays = $T.properties.totalRetentionInDays; Schema = $T.properties.schema; ProvisioningState = [string]$T.properties.provisioningState } }
    if ($TableName) {
        $t = Invoke-SIArm -Path ($base + '/' + $TableName) -ApiVersion '2022-10-01' -AllowNotFound
        if (-not $t) { Write-SIAzRestNotFound -Cmdlet $PSCmdlet -Message ("The table '{0}' was not found in workspace '{1}'." -f $TableName, $WorkspaceName) -Target $TableName; return }
        return (& $conv $t)
    }
    foreach ($t in @(Invoke-SIArm -Path $base -ApiVersion '2022-10-01' -List)) { & $conv $t }
}

# =====================================================================================================================
#  (7) Storage management through ARM (no data-plane role and no account key needed)
# =====================================================================================================================

function Get-SIStorageArmChildPath {
    param([string]$SubscriptionId, [string]$ResourceGroupName, [string]$AccountName, [ValidateSet('Table', 'Container', 'Queue')][string]$Kind, [string]$Name)
    $sub = Get-SISetupSubscriptionId -SubscriptionId $SubscriptionId
    $svc = switch ($Kind) { 'Table' { 'tableServices/default/tables' } 'Container' { 'blobServices/default/containers' } 'Queue' { 'queueServices/default/queues' } }
    return ('/subscriptions/{0}/resourceGroups/{1}/providers/Microsoft.Storage/storageAccounts/{2}/{3}/{4}' -f $sub, $ResourceGroupName, $AccountName, $svc, $Name)
}

function Get-SIStorageArmChild {
    <# A table / blob container / queue of a storage account, read through ARM; non-terminating not-found. #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$ResourceGroupName, [Parameter(Mandatory)][string]$AccountName,
          [Parameter(Mandatory)][ValidateSet('Table', 'Container', 'Queue')][string]$Kind, [Parameter(Mandatory)][string]$Name, [string]$SubscriptionId)
    $p = Get-SIStorageArmChildPath -SubscriptionId $SubscriptionId -ResourceGroupName $ResourceGroupName -AccountName $AccountName -Kind $Kind -Name $Name
    $r = Invoke-SIArm -Path $p -ApiVersion '2023-01-01' -AllowNotFound
    if (-not $r) { Write-SIAzRestNotFound -Cmdlet $PSCmdlet -Message ("The {0} '{1}' was not found in storage account '{2}'." -f $Kind.ToLowerInvariant(), $Name, $AccountName) -Target $Name; return }
    return [pscustomobject]@{ Name = [string]$r.name; Id = [string]$r.id; Kind = $Kind; Properties = $r.properties }
}

function New-SIStorageArmChild {
    <# Creates (PUT, idempotent) a table / private blob container / queue through ARM. #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$ResourceGroupName, [Parameter(Mandatory)][string]$AccountName,
          [Parameter(Mandatory)][ValidateSet('Table', 'Container', 'Queue')][string]$Kind, [Parameter(Mandatory)][string]$Name, [string]$SubscriptionId)
    $p = Get-SIStorageArmChildPath -SubscriptionId $SubscriptionId -ResourceGroupName $ResourceGroupName -AccountName $AccountName -Kind $Kind -Name $Name
    $body = if ($Kind -eq 'Container') { @{ properties = @{ publicAccess = 'None' } } } else { @{ properties = @{} } }
    $r = Invoke-SIArm -Method PUT -Path $p -ApiVersion '2023-01-01' -Body $body
    return [pscustomobject]@{ Name = $(if ($r) { [string]$r.name } else { $Name }); Id = $(if ($r) { [string]$r.id } else { $p }); Kind = $Kind }
}

function Get-SIStorageLifecyclePolicy {
    <# The account's lifecycle management policy: .Rules (the raw ARM rules: name, enabled, type, definition); $null when there is none. #>
    param([Parameter(Mandatory)][string]$ResourceGroupName, [Parameter(Mandatory)][string]$AccountName, [string]$SubscriptionId)
    $sub = Get-SISetupSubscriptionId -SubscriptionId $SubscriptionId
    $p = Invoke-SIArm -Path ("/subscriptions/$sub/resourceGroups/$ResourceGroupName/providers/Microsoft.Storage/storageAccounts/$AccountName/managementPolicies/default") -ApiVersion '2023-01-01' -AllowNotFound
    if (-not $p) { return $null }
    return [pscustomobject]@{ Id = [string]$p.id; Rules = @($p.properties.policy.rules | Where-Object { $_ }); LastModifiedTime = $p.properties.lastModifiedTime }
}

function Set-SIStorageLifecyclePolicy {
    <# REPLACES the account's lifecycle policy with -Rules (raw ARM rule objects). Callers merge, see New-SIStorageLifecycleDeleteRule. #>
    param([Parameter(Mandatory)][string]$ResourceGroupName, [Parameter(Mandatory)][string]$AccountName, [Parameter(Mandatory)][object[]]$Rules, [string]$SubscriptionId)
    $sub = Get-SISetupSubscriptionId -SubscriptionId $SubscriptionId
    $p = Invoke-SIArm -Method PUT -Path ("/subscriptions/$sub/resourceGroups/$ResourceGroupName/providers/Microsoft.Storage/storageAccounts/$AccountName/managementPolicies/default") -ApiVersion '2023-01-01' `
             -Body @{ properties = @{ policy = @{ rules = @($Rules) } } }
    return [pscustomobject]@{ Id = [string]$p.id; Rules = @($p.properties.policy.rules | Where-Object { $_ }) }
}

function New-SIStorageLifecycleDeleteRule {
    <# PURE. A lifecycle rule that deletes block blobs under -PrefixMatch N days after their last modification. #>
    param([Parameter(Mandatory)][string]$Name, [Parameter(Mandatory)][string[]]$PrefixMatch, [Parameter(Mandatory)][int]$DaysAfterModification)
    return [ordered]@{
        enabled    = $true
        name       = $Name
        type       = 'Lifecycle'
        definition = [ordered]@{
            actions = @{ baseBlob = @{ delete = @{ daysAfterModificationGreaterThan = $DaysAfterModification } } }
            filters = [ordered]@{ blobTypes = @('blockBlob'); prefixMatch = @($PrefixMatch) }
        }
    }
}

function Get-SIStorageLifecycleRuleDeleteDays {
    <# PURE. The delete-after-modification days of a raw lifecycle rule ($null when it has none). #>
    param($Rule)
    try { return $Rule.definition.actions.baseBlob.delete.daysAfterModificationGreaterThan } catch { return $null }
}

function Test-SIStorageAccountNameAvailability {
    <# Microsoft.Storage checkNameAvailability: NameAvailable, Reason, Message. #>
    param([Parameter(Mandatory)][string]$Name, [string]$SubscriptionId)
    $sub = Get-SISetupSubscriptionId -SubscriptionId $SubscriptionId
    $r = Invoke-SIArm -Method POST -Path ("/subscriptions/$sub/providers/Microsoft.Storage/checkNameAvailability") -ApiVersion '2023-01-01' -Body @{ name = $Name; type = 'Microsoft.Storage/storageAccounts' }
    return [pscustomobject]@{ NameAvailable = [bool]$r.nameAvailable; Reason = [string]$r.reason; Message = [string]$r.message }
}
