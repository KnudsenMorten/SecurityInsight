#Requires -Version 5.1
<#
    SecurityInsight SETUP -- HOW A SERVER INSTALL SIGNS IN (the unattended setup
    Setup-SecurityInsight-Unattended.ps1 when its JSON names no sign-in).

    Operator decision 2026-10-07 (wizard: "Server setup: managed identity"): the same default as the local setup wizard
    (setup\ConfigWizard\backend\SI-WizardSignIn.ps1) --
      an Azure VM               -> a USER-ASSIGNED managed identity, created in the install's resource group, attached
                                   to the VM and granted the read-only permissions (the wizard's own steps:
                                   New-SIUserAssignedIdentity, Add-SIVmUserAssignedIdentity, New-SISpn -CredKind
                                   ManagedIdentity)
      an Azure Arc server       -> its own SYSTEM-ASSIGNED identity (an Arc server cannot carry a user-assigned one);
                                   granted with setup\Grant-SIIdentity.ps1 -ArcMachineName
      a server outside Azure    -> NO managed identity can exist there: it is said, and a service principal is offered
                                   -- by CERTIFICATE first, then by client SECRET
    A service principal by certificate or by client secret stays a supported, explicit choice (never removed). An
    install that already signs in a certain way keeps it when nothing else is asked for -- an upgrade never changes the
    sign-in by itself.

    PURE functions apart from Get-SIServerAzureHost (it asks the instance metadata endpoint, 2 seconds at most) and
    Invoke-SIServerManagedIdentitySetup (Azure). No PowerShell modules. PS 5.1 and 7: no ?. / ??.
#>

function ConvertTo-SIServerSignInMethod {
    <# PURE. ManagedIdentity | Certificate | Secret from the spellings people use; '' for nothing; throws on anything else. #>
    param([AllowNull()][AllowEmptyString()][string]$Value)
    $v = "$Value".Trim()
    switch -Regex ($v) {
        '^$'                                                { return '' }
        '^(?i)(ManagedIdentity|MI|Identity|azureVMMI)$'     { return 'ManagedIdentity' }
        '^(?i)(Certificate|Cert|SpnCertificate|certThumb)$' { return 'Certificate' }
        '^(?i)(Secret|ClientSecret|SpnSecret)$'             { return 'Secret' }
        default { throw ("'{0}' is not a sign-in -- use ManagedIdentity (default), Certificate or Secret." -f $Value) }
    }
}

function Get-SIServerAzureHost {
    <#
        Where this server runs: AzureVm | Arc | Outside, with what the Azure instance metadata says about it (VmName,
        ResourceGroupName, SubscriptionId, Location). Never throws; a probe that does not answer = Outside.
        Seams: -GetEnv { param($name) } and -Imds { } (returns the compute metadata object, or $null).
    #>
    param([scriptblock]$GetEnv, [scriptblock]$Imds)
    if (-not $GetEnv) { $GetEnv = { param($n) [Environment]::GetEnvironmentVariable($n) } }
    $r = [pscustomobject]@{ Kind = 'Outside'; VmName = ''; ResourceGroupName = ''; SubscriptionId = ''; Location = '' }
    try {
        $ep = [string](& $GetEnv 'IDENTITY_ENDPOINT'); $hd = [string](& $GetEnv 'IDENTITY_HEADER'); $imdsEp = [string](& $GetEnv 'IMDS_ENDPOINT')
        if ($ep -and $imdsEp -and -not $hd) {
            # the Azure Connected Machine agent sets both, machine-wide (auth\SI-ManagedIdentity.ps1, Get-SIManagedIdentityHost)
            $r.Kind = 'Arc'; $r.VmName = [string](& $GetEnv 'COMPUTERNAME')
            return $r
        }
        if (-not $Imds) {
            $Imds = {
                $req = [System.Net.HttpWebRequest]::Create('http://169.254.169.254/metadata/instance/compute?api-version=2021-02-01')
                $req.Headers.Add('Metadata', 'true'); $req.Proxy = $null; $req.Timeout = 2000; $req.ReadWriteTimeout = 2000
                $resp = $req.GetResponse()
                try { $sr = New-Object System.IO.StreamReader($resp.GetResponseStream()); $sr.ReadToEnd() | ConvertFrom-Json } finally { $resp.Close() }
            }
        }
        $c = & $Imds
        if ($c -and $c.PSObject.Properties['name'] -and "$($c.name)") {
            $r.Kind = 'AzureVm'; $r.VmName = [string]$c.name
            if ($c.PSObject.Properties['resourceGroupName']) { $r.ResourceGroupName = [string]$c.resourceGroupName }
            if ($c.PSObject.Properties['subscriptionId'])    { $r.SubscriptionId = [string]$c.subscriptionId }
            if ($c.PSObject.Properties['location'])          { $r.Location = [string]$c.location }
        }
    } catch { }
    $r
}

function Get-SIServerNoManagedIdentityNote {
    'This server is not in Azure, so it cannot have a managed identity. SecurityInsight signs in as a service principal instead: by certificate (recommended), or by client secret. (An Azure Arc-enabled server does have one: install the Azure Connected Machine agent first, then run setup again.)'
}

function Resolve-SIServerSignIn {
    <#
        PURE. The sign-in a server install gets. First match wins:
          1. -Choice (the -SignIn switch, or the JSON's CredKind)          -> that one (a managed identity outside Azure is refused)
          2. a certificate / a secret given on this run                   -> that one
          3. -ExistingMethod: what the install's configuration already uses (an upgrade) -> kept (wherever it runs)
          4. nothing: Azure VM -> a user-assigned managed identity; Arc -> its system-assigned identity;
             outside Azure -> a certificate, and it says why
        Returns @{ Method (ManagedIdentity|Certificate|Secret); Identity (user-assigned|system-assigned|none); DefaultUsed;
                   Source (choice|input|existing|default); Note; Offer (the methods to offer, the recommended first) }.
    #>
    param([ValidateSet('AzureVm', 'Arc', 'Outside')][string]$HostKind = 'Outside',
          [AllowEmptyString()][string]$Choice = '', [bool]$HasCertificateInput = $false, [bool]$HasSecretInput = $false,
          [AllowEmptyString()][string]$ExistingMethod = '')
    $offer = if ($HostKind -eq 'Outside') { @('Certificate', 'Secret') } else { @('ManagedIdentity', 'Certificate', 'Secret') }
    $mi = { param($src, $def, $note)
        $idk = if ($HostKind -eq 'Arc') { 'system-assigned' } else { 'user-assigned' }
        $n = if ($note) { $note } elseif ($HostKind -eq 'Arc') { "the Azure Arc server's own (system-assigned) managed identity" } else { 'a user-assigned managed identity, attached to this VM' }
        [pscustomobject]@{ Method = 'ManagedIdentity'; Identity = $idk; DefaultUsed = [bool]$def; Source = $src; Note = $n; Offer = $offer } }
    $spn = { param($m, $src, $def, $note) [pscustomobject]@{ Method = $m; Identity = 'none'; DefaultUsed = [bool]$def; Source = $src; Note = $note; Offer = $offer } }
    $c = ConvertTo-SIServerSignInMethod $Choice
    if ($c -eq 'ManagedIdentity') {
        if ($HostKind -eq 'Outside') { throw (Get-SIServerNoManagedIdentityNote) }
        return (& $mi 'choice' $false '')
    }
    if ($c) { return (& $spn $c 'choice' $false $(if ($c -eq 'Secret') { 'a service principal by client secret (your explicit choice)' } else { 'a service principal by certificate' })) }
    if ($HasCertificateInput) { return (& $spn 'Certificate' 'input' $false 'a service principal by certificate (given on this run)') }
    if ($HasSecretInput)      { return (& $spn 'Secret' 'input' $false 'a service principal by client secret (given on this run)') }
    $e = ''
    try { $e = ConvertTo-SIServerSignInMethod $ExistingMethod } catch { $e = '' }
    if ($e -eq 'ManagedIdentity') { return (& $mi 'existing' $false 'kept: this install already signs in as a managed identity') }
    if ($e -eq 'Certificate' -or $e -eq 'Secret') { return (& $spn $e 'existing' $false ('kept: this install already signs in as a service principal by {0}' -f $(if ($e -eq 'Secret') { 'client secret' } else { 'certificate' }))) }
    if ($HostKind -eq 'Outside') { return (& $spn 'Certificate' 'default' $true (Get-SIServerNoManagedIdentityNote)) }
    & $mi 'default' $true ''
}

function Get-SIServerSignInMenu {
    <# PURE. The lines of the sign-in question; the first offered method is the recommended one (ENTER). #>
    param([Parameter(Mandatory)]$Decision)
    $label = @{
        ManagedIdentity = 'Managed identity (recommended) -- no password or certificate to look after'
        Certificate     = 'Service principal with a certificate'
        Secret          = 'Service principal with a client secret (supported; it expires and must be renewed)'
    }
    if (@($Decision.Offer)[0] -eq 'Certificate') { $label.Certificate = 'Service principal with a certificate (recommended here)' }
    $lines = New-Object System.Collections.Generic.List[string]
    $lines.Add('How should SecurityInsight sign in on this server?')
    $i = 0
    foreach ($m in @($Decision.Offer)) { $i++; $lines.Add(('  {0}) {1}{2}' -f $i, $label[$m], $(if ($m -eq $Decision.Method) { '   [ENTER]' } else { '' }))) }
    @($lines)
}

function Select-SIServerSignIn {
    <# PURE. The method an answer to the menu picks: ENTER = the decision's method; a number from the menu; or a name.
       Throws on anything else, and on a managed identity where none is offered. #>
    param([Parameter(Mandatory)]$Decision, [AllowNull()][AllowEmptyString()][string]$Answer)
    $a = "$Answer".Trim()
    if (-not $a) { return [string]$Decision.Method }
    $offer = @($Decision.Offer)
    $n = 0
    if ([int]::TryParse($a, [ref]$n)) {
        if ($n -ge 1 -and $n -le $offer.Count) { return [string]$offer[$n - 1] }
        throw ("'{0}' is not one of the choices 1-{1}." -f $a, $offer.Count)
    }
    $m = ConvertTo-SIServerSignInMethod $a
    if ($offer -notcontains $m) { throw (Get-SIServerNoManagedIdentityNote) }
    $m
}

function ConvertTo-SIServerPsLiteral([AllowNull()][object]$Value) {
    <# PURE. A value as a PowerShell single-quoted literal (the quote characters PowerShell accepts are doubled). #>
    $s = if ($null -eq $Value) { '' } else { [string]$Value }
    foreach ($q in @([char]0x27, [char]0x2018, [char]0x2019, [char]0x201A, [char]0x201B)) { $s = $s.Replace([string]$q, [string]$q + [string]$q) }
    "'" + $s + "'"
}

function Get-SIServerSignInConfigLines {
    <#
        PURE. The AUTH block of config\SecurityInsight.custom.ps1 for the chosen sign-in. SI_AuthMethod is always said
        explicitly (auth\SI-AuthMethod.ps1: every engine, launcher and Bootstrap read that one setting).
          ManagedIdentity: tenant, the identity's client id (empty = the host's system-assigned identity), its principal
                           id when known, the managed identity switches -- and no service principal app id or secret
          Certificate:     tenant, app id, the certificate thumbprint (LocalMachine\My or CurrentUser\My)
          Secret:          tenant, app id, the secret from Key Vault (-KeyVaultName) or written inline
    #>
    param([Parameter(Mandatory)][ValidateSet('ManagedIdentity', 'Certificate', 'Secret')][string]$Method,
          [AllowEmptyString()][string]$TenantId = '', [AllowEmptyString()][string]$AppId = '',
          [AllowEmptyString()][string]$CertificateThumbprint = '', [AllowEmptyString()][string]$Secret = '',
          [AllowEmptyString()][string]$KeyVaultName = '', [AllowEmptyString()][string]$KeyVaultSecretName = '',
          [AllowEmptyString()][string]$ManagedIdentityClientId = '', [AllowEmptyString()][string]$PrincipalId = '')
    $q = { param($v) ConvertTo-SIServerPsLiteral $v }
    $l = New-Object System.Collections.Generic.List[string]
    $l.Add('# ----- AUTH (one identity for Defender, Microsoft Graph, Azure and the Log Analytics ingest) -----')
    $l.Add(("`$global:SI_AuthMethod   = {0}   # ManagedIdentity (default) | Certificate | Secret" -f (& $q $Method)))
    $l.Add(("`$global:SI_SPN_TenantId = {0}" -f (& $q $TenantId)))
    switch ($Method) {
        'ManagedIdentity' {
            $l.Add(("`$global:SI_ManagedIdentityClientId = {0}   # empty = this server's system-assigned identity" -f (& $q $ManagedIdentityClientId)))
            $l.Add('$global:SI_SPN_UseManagedIdentity = $true')
            $l.Add(("`$global:SI_SPN_ManagedIdentityClientId = {0}" -f (& $q $ManagedIdentityClientId)))
            if ($PrincipalId) { $l.Add(("`$global:SI_SPN_ObjectId = {0}" -f (& $q $PrincipalId))) }
        }
        'Certificate' {
            $l.Add(("`$global:SI_SPN_AppId    = {0}" -f (& $q $AppId)))
            $l.Add(("`$global:SI_SPN_CertThumbprint = {0}" -f (& $q $CertificateThumbprint)))
        }
        'Secret' {
            $l.Add(("`$global:SI_SPN_AppId    = {0}" -f (& $q $AppId)))
            if ($KeyVaultName) {
                $kvSecret = if ($KeyVaultSecretName) { $KeyVaultSecretName } else { 'SecurityInsight-Secret' }
                $l.Add(("`$global:SpnKeyVaultName = {0}" -f (& $q $KeyVaultName)))
                $l.Add(("`$global:SpnSecretName   = {0}" -f (& $q $kvSecret)))
                # The names alone were resolved by nothing -- the engines then ran without an SPN secret.
                # Emit the names the helpers read, and read the secret into memory on every load.
                $l.Add('$global:SI_KeyVaultName     = $global:SpnKeyVaultName')
                $l.Add('$global:SI_SPN_KvSecretName = $global:SpnSecretName')
                $l.Add('if (-not $global:SI_SPN_Secret) {')
                $l.Add('    try {')
                $l.Add("        . (Join-Path `$PSScriptRoot '..\auth\Get-SIKvSecret.ps1')")
                $l.Add('        $global:SI_SPN_Secret = Get-SIKvSecret -VaultName $global:SI_KeyVaultName -SecretName $global:SI_SPN_KvSecretName')
                $l.Add('    } catch { Write-Warning ("SI custom: the SPN secret could not be read from Key Vault: {0}" -f $_.Exception.Message) }')
                $l.Add('}')
            } elseif ($Secret) {
                $l.Add(("`$global:SI_SPN_Secret   = {0}" -f (& $q $Secret)))
            }
        }
    }
    @($l)
}

function Resolve-SIUnattendedSignIn {
    <#
        PURE. The sign-in the UNATTENDED setup (Setup-SecurityInsight-Unattended.ps1, Community flavour) sets up from the
        JSON's Auth_Community block. CredKind given (ManagedIdentity | Cert | Secret, or the long names) = that one.
        CredKind empty / null = the same default as the wizard and -Phase Config:
          Container.Enabled           -> the Container Apps jobs' managed identity (granted by the container setup)
          an Azure VM                 -> a user-assigned managed identity (created, attached to the VM, granted)
          an Azure Arc server         -> its own system-assigned identity
          outside Azure               -> a service principal by certificate (no managed identity can exist there)
        Returns @{ CredKind (ManagedIdentity|Cert|Secret: what New-SISpn / Write-SICustomConfig call it); Identity
                   (container-jobs|user-assigned|system-assigned|none); CredStorage (the JSON's, else LocalCertStore for a
                   certificate, Inline for a secret); DefaultUsed; Note }.
    #>
    param([AllowNull()][AllowEmptyString()][string]$CredKind = '', [AllowNull()][AllowEmptyString()][string]$CredStorage = '',
          [bool]$ContainerEnabled = $false, [ValidateSet('AzureVm', 'Arc', 'Outside')][string]$HostKind = 'Outside')
    $m = ConvertTo-SIServerSignInMethod $CredKind
    $kindOf = @{ ManagedIdentity = 'ManagedIdentity'; Certificate = 'Cert'; Secret = 'Secret' }
    $storeOf = { param($k) if ("$CredStorage".Trim()) { "$CredStorage".Trim() } elseif ($k -eq 'Cert') { 'LocalCertStore' } elseif ($k -eq 'Secret') { 'Inline' } else { '' } }
    $o = { param($k, $id, $def, $note) [pscustomobject]@{ CredKind = $k; Identity = $id; CredStorage = (& $storeOf $k); DefaultUsed = [bool]$def; Note = $note } }
    if ($ContainerEnabled) {
        if (-not $m -or $m -eq 'ManagedIdentity') { return (& $o 'ManagedIdentity' 'container-jobs' (-not $m) 'the Container Apps jobs sign in as their user-assigned managed identity') }
        return (& $o $kindOf[$m] 'none' $false ('a service principal by {0} (Auth_Community.CredKind)' -f $(if ($m -eq 'Secret') { 'client secret' } else { 'certificate' })))
    }
    $d = Resolve-SIServerSignIn -HostKind $HostKind -Choice $m
    $k = $kindOf[[string]$d.Method]
    & $o $k $(if ($k -eq 'ManagedIdentity') { [string]$d.Identity } else { 'none' }) $d.DefaultUsed ([string]$d.Note)
}

function Get-SIServerArcGrantHint {
    <# PURE. The ready-to-run grant for an Azure Arc server's own identity. #>
    param([AllowEmptyString()][string]$MachineName = '', [AllowEmptyString()][string]$ResourceGroupName = '')
    $m = if ($MachineName) { $MachineName } else { '<arc machine name>' }
    $g = if ($ResourceGroupName) { $ResourceGroupName } else { '<its resource group>' }
    ('Grant the Arc server''s identity once the workspace exists (after -Phase LA): .\setup\Grant-SIIdentity.ps1 -ArcMachineName {0} -ArcResourceGroup {1} -Apply' -f $m, $g)
}

function Invoke-SIServerManagedIdentitySetup {
    <#
        The Azure VM's managed identity, the way the local setup wizard makes it (Start-SetupWizard.ps1 phases 2 + 1b):
          1. the resource group (created when missing, tagged -Tag)
          2. the user-assigned identity in it (New-SIUserAssignedIdentity; an existing one is re-used)
          3. attached to the VM, keeping every identity the VM has (Add-SIVmUserAssignedIdentity) -- when -VmName is given
          4. granted the read-only Microsoft Graph / Defender / Azure permissions (New-SISpn -CredKind ManagedIdentity:
             no app registration is created)
        Needs an Azure sign-in (Connect-SISetupAzure) with rights to create the identity, change the VM and grant
        application permissions. A grant that fails does NOT undo 1-3: Grants = 'failed' and GrantError say what to
        re-run. A NEW identity can take a minute to appear in Entra ID: the grant is retried while its service principal
        is not found yet (-GrantAttempts x -RetrySeconds). The identity stays READ ONLY -- asset tagging gets its own
        (setup\Grant-SIIdentity.ps1 -Tagging).
        Returns @{ Name; ClientId; PrincipalId; ResourceId; Attached (attached|already-attached|no);
                   Grants (ok|consent-pending|failed); GrantError; PendingPermissions; GrantResult (New-SISpn's answer) }.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$TenantId, [Parameter(Mandatory)][string]$SubscriptionId,
          [Parameter(Mandatory)][string]$ResourceGroupName, [Parameter(Mandatory)][string]$Location,
          [Parameter(Mandatory)][string]$IdentityName, [string]$VmName, [string]$VmResourceGroup,
          [Parameter(Mandatory)][string]$NewSISpnPath, [hashtable]$Tag, [int]$GrantAttempts = 6, [int]$RetrySeconds = 10)
    $rg = $null
    try { $rg = Get-SIAzResourceGroup -Name $ResourceGroupName -ErrorAction SilentlyContinue } catch { $rg = $null }
    if (-not $rg) { $null = New-SIAzResourceGroup -Name $ResourceGroupName -Location $Location -Tag $Tag -ErrorAction Stop }
    $id = New-SIUserAssignedIdentity -ResourceGroupName $ResourceGroupName -Name $IdentityName -Location $Location -SubscriptionId $SubscriptionId
    if (-not $id -or -not $id.ClientId) { throw ("The managed identity '{0}' could not be created in resource group '{1}'." -f $IdentityName, $ResourceGroupName) }
    $out = [pscustomobject]@{ Name = [string]$id.Name; ClientId = [string]$id.ClientId; PrincipalId = [string]$id.PrincipalId; ResourceId = [string]$id.Id
                              Attached = 'no'; Grants = 'failed'; GrantError = ''; PendingPermissions = @(); GrantResult = $null }
    if ($VmName) {
        $vmRg = if ($VmResourceGroup) { $VmResourceGroup } else { $ResourceGroupName }
        $changed = Add-SIVmUserAssignedIdentity -ResourceGroupName $vmRg -VmName $VmName -IdentityResourceId ([string]$id.Id) -SubscriptionId $SubscriptionId
        $out.Attached = if ($changed) { 'attached' } else { 'already-attached' }
    }
    $a = @{ TenantId = $TenantId; SubscriptionId = $SubscriptionId; CredKind = 'ManagedIdentity'; ManagedIdentityClientId = [string]$id.ClientId; DisplayName = $IdentityName }
    if ($GrantAttempts -lt 1) { $GrantAttempts = 1 }
    for ($i = 1; $i -le $GrantAttempts; $i++) {
        try {
            $g = & $NewSISpnPath @a
            $cs = if ($g -and $g.PSObject.Properties['ConsentStatus']) { [string]$g.ConsentStatus } else { 'granted' }
            $out.Grants = if ($cs -and $cs -ne 'granted') { 'consent-pending' } else { 'ok' }
            if ($g -and $g.PSObject.Properties['PendingPermissions']) { $out.PendingPermissions = @($g.PendingPermissions) }
            $out.GrantResult = $g; $out.GrantError = ''
            break
        } catch {
            $out.Grants = 'failed'; $out.GrantError = $_.Exception.Message
            # only "not there yet" is waited for; any other failure is final
            if ($i -ge $GrantAttempts -or $out.GrantError -notmatch '(?i)not found') { break }
            if ($RetrySeconds -gt 0) { Start-Sleep -Seconds $RetrySeconds }
        }
    }
    $out
}
