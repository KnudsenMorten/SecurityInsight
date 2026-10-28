#Requires -Version 5.1
<#
    ENGINE CONTAINERS SIGN IN WITH THE JOB'S MANAGED IDENTITY (#209) -- and the secret stays.

    Engine containers could only sign in with an SPN client SECRET, so a certificate-only install (internal; and
    Pro, which is container only) could not run in containers at all. The order is now
        managed identity (IDENTITY_ENDPOINT + SI_UAMI_CLIENTID)  >  certificate (PFX from Key Vault)  >  secret
    exactly as PIM's containers sign in. These tests hold:
      * the order (pure), on the container side and the Bootstrap side;
      * the identity endpoint request (resource, api-version 2019-08-01, client_id, X-IDENTITY-HEADER);
      * that NO managed-identity branch is taken without the run's one switch (a VM is unchanged);
      * the X509Store fallback where there is no Cert: drive (a Linux container);
      * the AzLogDcrIngestPS token bridge -- answers only the two requests it owns;
      * Bootstrap: a managed-identity job carries no secret; a secret job carries exactly what it did;
      * the grant plan: the right roles, and never a write permission.
#>

BeforeAll {
    $script:SIRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
    . (Join-Path $script:SIRoot 'container\_shared\SI-ContainerConfig.ps1')
    . (Join-Path $script:SIRoot 'auth\SI-ManagedIdentity.ps1')
    . (Join-Path $script:SIRoot 'auth\Get-SIGraphToken.ps1')
    # SI-ManagedIdentity.ps1 loads the certificate helpers only when Get-SICertificateFromStore is not yet known -- in a
    # combined run another suite may have made it known while the rest of the file (Get-SICertStoreLocation,
    # Import-SIContainerCertificate) is not in this scope. This suite tests those helpers, so it loads them itself.
    . (Join-Path $script:SIRoot 'auth\Find-SICertificate.ps1')

    function script:Get-Code([string]$Rel) {
        ((Get-Content -LiteralPath (Join-Path $script:SIRoot $Rel)) | Where-Object { $_ -notmatch '^\s*#' }) -join "`n"
    }
    function script:New-SITestCert {
        $rsa = [System.Security.Cryptography.RSA]::Create(2048)
        $req = New-Object System.Security.Cryptography.X509Certificates.CertificateRequest('CN=si-209-test', $rsa,
                   [System.Security.Cryptography.HashAlgorithmName]::SHA256, [System.Security.Cryptography.RSASignaturePadding]::Pkcs1)
        $req.CreateSelfSigned([DateTimeOffset]::UtcNow.AddMinutes(-5), [DateTimeOffset]::UtcNow.AddHours(1))
    }
    $script:AuthGlobals = 'SI_UseManagedIdentity', 'SI_UAMI_ClientId', 'SI_PreferUami', 'SI_SPN_AppId', 'SI_SPN_Secret',
        'SI_SPN_TenantId', 'SI_SPN_ObjectId', 'SI_SPN_CertThumbprint', 'SI_SPN_CertStoreLocation', 'SI_Graph_AppId',
        'SI_Graph_Secret', 'SI_Graph_TenantId', 'HighPriv_Modern_CertificateThumbprint_Azure', 'SpnCertificateThumbprint',
        'SpnClientId', 'SpnTenantId', 'SpnClientSecret'
    $script:AuthEnv = 'IDENTITY_ENDPOINT', 'IDENTITY_HEADER', 'SI_UAMI_CLIENTID', 'SI_SPN_APPID', 'SI_SPN_SECRET',
        'SI_SPN_TENANTID', 'SI_SPN_OBJECTID', 'SI_SPN_CERT_PFX_B64'
    function script:Reset-SIAuthState {
        foreach ($n in $script:AuthGlobals) { Remove-Variable -Name $n -Scope Global -ErrorAction SilentlyContinue }
        foreach ($n in $script:AuthEnv) { [Environment]::SetEnvironmentVariable($n, $null) }
        $script:SIManagedIdentityTokenCache = @{}
        $script:SIGraphTokenCache = @{}
    }
    Reset-SIAuthState
}

AfterAll { Reset-SIAuthState }

Describe 'the sign-in order: managed identity > certificate > secret (container side, pure)' {

    It 'the managed identity wins when the job has an identity endpoint AND Bootstrap named the identity' {
        $r = Resolve-SIContainerAuthMode -Environment @{ IDENTITY_ENDPOINT = 'http://localhost:42356/msi/token'; SI_UAMI_CLIENTID = 'cid-1'
                                                         SI_SPN_SECRET = 's'; SI_SPN_APPID = 'a'; SI_SPN_TENANTID = 't'; SI_SPN_CERT_PFX_B64 = 'x' }
        $r.Mode | Should -Be 'ManagedIdentity'
        $r.ClientId | Should -Be 'cid-1'
    }
    It 'the certificate wins over the secret' {
        (Resolve-SIContainerAuthMode -Environment @{ SI_SPN_CERT_PFX_B64 = 'x'; SI_SPN_APPID = 'a'; SI_SPN_TENANTID = 't'; SI_SPN_SECRET = 's' }).Mode | Should -Be 'Certificate'
    }
    It 'the secret alone is the secret -- the Community job is unchanged' {
        (Resolve-SIContainerAuthMode -Environment @{ SI_SPN_SECRET = 's'; SI_SPN_APPID = 'a'; SI_SPN_TENANTID = 't'; SI_SPN_OBJECTID = 'o' }).Mode | Should -Be 'Secret'
    }
    It 'an identity endpoint without SI_UAMI_CLIENTID is NOT the managed identity (the secret job keeps its secret)' {
        (Resolve-SIContainerAuthMode -Environment @{ IDENTITY_ENDPOINT = 'http://x'; SI_SPN_SECRET = 's' }).Mode | Should -Be 'Secret'
    }
    It 'SI_UAMI_CLIENTID without an identity endpoint is NOT the managed identity' {
        (Resolve-SIContainerAuthMode -Environment @{ SI_UAMI_CLIENTID = 'cid'; SI_SPN_SECRET = 's' }).Mode | Should -Be 'Secret'
        $none = Resolve-SIContainerAuthMode -Environment @{ SI_UAMI_CLIENTID = 'cid' }
        $none.Mode | Should -Be 'None'
        $none.Reason | Should -Match 'IDENTITY_ENDPOINT'
    }
    It 'a certificate without its app id or tenant is not a certificate sign-in' {
        (Resolve-SIContainerAuthMode -Environment @{ SI_SPN_CERT_PFX_B64 = 'x'; SI_SPN_APPID = 'a' }).Mode | Should -Be 'None'
    }
}

Describe 'the sign-in order (Bootstrap side, pure)' {

    It 'no switch = the managed identity (default since 2026-10-07); a config that carries a client secret keeps the secret' {
        Resolve-SIBootstrapAuthMode | Should -Be 'ManagedIdentity'
        Resolve-SIBootstrapAuthMode -HasConfiguredSecret $true | Should -Be 'Secret'
        Resolve-SIBootstrapAuthMode -UseClientSecret $true | Should -Be 'Secret'
    }
    It '-UseManagedIdentity = managed identity (and it wins over certificate settings)' {
        Resolve-SIBootstrapAuthMode -UseManagedIdentity $true -CertificateKeyVaultName 'kv' -CertificateSecretName 'c' | Should -Be 'ManagedIdentity'
    }
    It 'a Key Vault AND a certificate secret name = certificate; half of it is an error, never a silent secret' {
        Resolve-SIBootstrapAuthMode -CertificateKeyVaultName 'kv' -CertificateSecretName 'c' | Should -Be 'Certificate'
        { Resolve-SIBootstrapAuthMode -CertificateKeyVaultName 'kv' } | Should -Throw '*BOTH*'
        { Resolve-SIBootstrapAuthMode -CertificateSecretName 'c' } | Should -Throw '*BOTH*'
    }
    It 'the config must carry a secret ONLY in secret mode' {
        Get-SIBootstrapRequiredSpnGlobals -Mode Secret | Should -Be @('SI_SPN_AppId', 'SI_SPN_Secret', 'SI_SPN_TenantId', 'SI_SPN_ObjectId')
        @(Get-SIBootstrapRequiredSpnGlobals -Mode ManagedIdentity).Count | Should -Be 0
        Get-SIBootstrapRequiredSpnGlobals -Mode Certificate | Should -Not -Contain 'SI_SPN_Secret'
    }
}

Describe 'the identity endpoint request' {

    BeforeEach {
        Reset-SIAuthState
        $env:IDENTITY_ENDPOINT = 'http://localhost:42356/msi/token'
        $env:IDENTITY_HEADER   = 'hdr-209'
        $script:calls = New-Object System.Collections.Generic.List[object]
        $script:fake = { param($Uri, $Headers) $script:calls.Add(@{ Uri = $Uri; Headers = $Headers }); @{ access_token = 'mi-token'; expires_on = [string]([DateTimeOffset]::UtcNow.AddHours(1).ToUnixTimeSeconds()) } }
    }
    AfterEach { Reset-SIAuthState }

    It 'asks IDENTITY_ENDPOINT for the resource, api-version 2019-08-01, with the identity''s client_id and the header' {
        $t = Get-SIManagedIdentityToken -Resource 'https://graph.microsoft.com' -ClientId 'cid-209' -Invoke $script:fake
        $t | Should -Be 'mi-token'
        $script:calls.Count | Should -Be 1
        $u = [string]$script:calls[0].Uri
        $u | Should -BeLike 'http://localhost:42356/msi/token?*'
        $u | Should -Match 'resource=https%3A%2F%2Fgraph\.microsoft\.com(&|$)'
        $u | Should -Match 'api-version=2019-08-01'
        $u | Should -Match 'client_id=cid-209'
        $script:calls[0].Headers['X-IDENTITY-HEADER'] | Should -Be 'hdr-209'
    }
    It 'defaults the client id to $global:SI_UAMI_ClientId, strips /.default, and caches per identity + resource' {
        $global:SI_UAMI_ClientId = 'cid-global'
        $null = Get-SIManagedIdentityToken -Resource 'https://management.azure.com/.default' -Invoke $script:fake
        $null = Get-SIManagedIdentityToken -Resource 'https://management.azure.com/.default' -Invoke $script:fake
        $script:calls.Count | Should -Be 1 -Because 'the second call is served from the cache'
        [string]$script:calls[0].Uri | Should -Match 'client_id=cid-global'
        [string]$script:calls[0].Uri | Should -Not -Match '\.default'
    }
    It 'outside a container (no IDENTITY_ENDPOINT) it asks the Azure VM endpoint, never a guessed container URL (#222)' {
        $env:IDENTITY_ENDPOINT = $null
        $script:vmUri = $null
        $vm = { param($u, $h) $script:vmUri = $u; [pscustomobject]@{ access_token = 'vm'; expires_in = '3600' } }
        Get-SIManagedIdentityToken -Resource 'https://graph.microsoft.com' -ClientId 'c' -Invoke $vm | Should -Be 'vm'
        $script:vmUri | Should -Match '^http://169\.254\.169\.254/metadata/identity/oauth2/token\?'
    }
    It 'an empty answer is an error naming the identity, not an empty token' {
        { Get-SIManagedIdentityToken -Resource 'https://graph.microsoft.com' -ClientId 'cid-x' -Invoke { param($u, $h) @{} } } | Should -Throw '*cid-x*'
    }
}

Describe 'the Shodan key reaches the publicip job as a Key Vault reference (#185, live 2026-10-02)' {
    BeforeAll { . (Join-Path $script:SIRoot 'container\_shared\SI-ContainerConfig.ps1') }
    It 'a vault + the job''s identity -> a Key Vault reference (the value never passes through setup); else the value; else nothing' {
        Get-SIShodanSecretArg -VaultUri 'https://kv1.vault.azure.net/' -SecretName 'SI-Shodan-ApiKey' -IdentityResourceId '/sub/x/uami' -Value 'v' |
            Should -Be 'shodan-key=keyvaultref:https://kv1.vault.azure.net/secrets/SI-Shodan-ApiKey,identityref:/sub/x/uami'
        Get-SIShodanSecretArg -VaultUri 'https://kv1.vault.azure.net' -IdentityResourceId '/sub/x/uami' | Should -Match '^shodan-key=keyvaultref:https://kv1\.vault\.azure\.net/secrets/SI-Shodan-ApiKey,'
        Get-SIShodanSecretArg -VaultUri '' -IdentityResourceId '/sub/x/uami' -Value 'v' | Should -Be 'shodan-key=v'
        Get-SIShodanSecretArg -VaultUri 'https://kv1.vault.azure.net/' -IdentityResourceId '' -Value '' | Should -BeNullOrEmpty
    }
    It 'the identity gets Key Vault Secrets User on the Shodan vault -- once when it is also the certificate vault' {
        $p = @(Get-SIContainerIdentityGrantPlan -Mode ManagedIdentity -ShodanKeyVaultId '/sub/s/kv-shodan')
        @($p | Where-Object { $_.Role -eq 'Key Vault Secrets User' -and $_.Scope -eq '/sub/s/kv-shodan' }).Count | Should -Be 1
        $c = @(Get-SIContainerIdentityGrantPlan -Mode Certificate -KeyVaultId '/sub/s/kv1' -ShodanKeyVaultId '/sub/s/kv1')
        @($c | Where-Object { $_.Role -eq 'Key Vault Secrets User' }).Count | Should -Be 1
    }
    It 'WIRING -- setup resolves the vault for publicip, passes it to the grant plan, and builds the secret with the helper' {
        $b = Get-Content -Raw (Join-Path $script:SIRoot 'Bootstrap-ContainerAppJob.ps1')
        $b | Should -Match "\`$Engines -contains 'publicip' -and -not \[string\]::IsNullOrWhiteSpace\(\`$ShodanKeyVaultName\)"
        $b | Should -Match '-ShodanKeyVaultId '
        $b | Should -Match "Resolve-SIJobKeyVaultSecret -Alias 'shodan-key'"
        $b | Should -Not -Match "'shodan-key=\{0\}' -f \`$shodanForJobs"
    }
}

Describe 'a job references a Key Vault secret only when the vault holds it (live 2026-10-06, caj-si-publicip never created)' {
    BeforeAll {
        . (Join-Path $script:SIRoot 'container\_shared\SI-ContainerConfig.ps1')
        $script:kvArgs = @{ VaultName = 'kv-si-x'; VaultUri = 'https://kv-si-x.vault.azure.net/'; IdentityResourceId = '/sub/x/uami' }
    }
    It 'an optional secret the vault HOLDS is referenced (names compare case-insensitively)' {
        $p = Resolve-SIJobKeyVaultSecret -Alias 'shodan-key' -SecretName 'SI-Shodan-ApiKey' -VaultSecretNames @('si-shodan-apikey', 'SI-License') -Feature 'Shodan' @script:kvArgs
        $p.Status | Should -Be 'Reference'
        $p.SecretArg | Should -Be 'shodan-key=keyvaultref:https://kv-si-x.vault.azure.net/secrets/SI-Shodan-ApiKey,identityref:/sub/x/uami'
        $p.Message | Should -BeNullOrEmpty
    }
    It 'an optional secret the vault does NOT hold is omitted, with a plain message -- the job is still created' {
        $p = Resolve-SIJobKeyVaultSecret -Alias 'shodan-key' -SecretName 'SI-Shodan-ApiKey' -VaultSecretNames @('SI-License') -Feature 'Shodan' @script:kvArgs
        $p.Status | Should -Be 'Omitted'
        $p.SecretArg | Should -BeNullOrEmpty
        $p.Message | Should -Match "holds no secret 'SI-Shodan-ApiKey'"
        $p.Message | Should -Match 'runs without Shodan'
    }
    It 'an EMPTY vault is "absent", not "unknown"' {
        (Resolve-SIJobKeyVaultSecret -Alias 'shodan-key' -SecretName 'SI-Shodan-ApiKey' -VaultSecretNames @() @script:kvArgs).Status | Should -Be 'Omitted'
    }
    It 'an optional secret absent from the vault falls back to a configured value' {
        $p = Resolve-SIJobKeyVaultSecret -Alias 'shodan-key' -SecretName 'SI-Shodan-ApiKey' -VaultSecretNames @() -Value 'v' @script:kvArgs
        $p.Status | Should -Be 'Value'
        $p.SecretArg | Should -Be 'shodan-key=v'
    }
    It 'an optional secret whose vault cannot be listed is omitted (never a job Container Apps refuses), and says why' {
        $p = Resolve-SIJobKeyVaultSecret -Alias 'openai-apikey' -SecretName 'OpenAI-ApiKey' -VaultSecretNames $null -Feature 'Azure OpenAI' @script:kvArgs
        $p.Status | Should -Be 'Omitted'
        $p.Message | Should -Match 'could not be listed'
    }
    It 'no vault and no value = omitted (the old "nothing"), with a message' {
        $p = Resolve-SIJobKeyVaultSecret -Alias 'shodan-key' -SecretName 'SI-Shodan-ApiKey' -Feature 'Shodan'
        $p.Status | Should -Be 'Omitted'
        $p.Message | Should -Match 'no Key Vault is known'
    }
    It 'a REQUIRED secret the vault does not hold is a clear failure naming the secret and the vault' {
        { Resolve-SIJobKeyVaultSecret -Alias 'si-spn-cert' -SecretName 'si-spn-pfx' -VaultSecretNames @('other') -Required -Feature 'the SPN certificate' @script:kvArgs } |
            Should -Throw "*the SPN certificate is required*'si-spn-pfx'*kv-si-x*"
        { Resolve-SIJobKeyVaultSecret -Alias 'si-spn-cert' -SecretName 'si-spn-pfx' -Required } | Should -Throw '*required*'
    }
    It 'a REQUIRED secret the vault holds is referenced; unlistable = referenced unchecked, with a note' {
        (Resolve-SIJobKeyVaultSecret -Alias 'si-spn-cert' -SecretName 'si-spn-pfx' -VaultSecretNames @('si-spn-pfx') -Required @script:kvArgs).Status | Should -Be 'Reference'
        $u = Resolve-SIJobKeyVaultSecret -Alias 'si-spn-cert' -SecretName 'si-spn-pfx' -VaultSecretNames $null -Required @script:kvArgs
        $u.Status | Should -Be 'Reference'
        $u.Message | Should -Match 'unchecked'
    }
    It 'an empty name list survives the way setup passes it ($( ) around a ,-returned array) -- empty stays "absent"' {
        function script:Get-Names { param($n) if ($null -eq $n) { return $null }; return ,([string[]]$n) }
        (Resolve-SIJobKeyVaultSecret -Alias 'a' -SecretName 's' -VaultSecretNames $(if ($true) { Get-Names @() }) @script:kvArgs).Message | Should -Match 'holds no secret'
        (Resolve-SIJobKeyVaultSecret -Alias 'a' -SecretName 's' -VaultSecretNames $(if ($true) { Get-Names @('s') }) @script:kvArgs).Status | Should -Be 'Reference'
        (Resolve-SIJobKeyVaultSecret -Alias 'a' -SecretName 's' -VaultSecretNames $(if ($false) { Get-Names @('s') }) @script:kvArgs).Message | Should -Match 'could not be listed'
    }
    It 'WIRING -- setup lists each vault''s secret NAMES once and resolves Shodan, OpenAI, SMTP and the certificate through the helper' {
        $b = Get-Content -Raw (Join-Path $script:SIRoot 'Bootstrap-ContainerAppJob.ps1')
        $b | Should -Match 'Get-SIKeyVaultSecretNames -VaultName \$VaultName'
        $b | Should -Not -Match "'keyvault','secret','show'" -Because 'setup never reads a secret VALUE'
        foreach ($a in 'shodan-key', 'openai-apikey', 'smtp-password', 'si-spn-cert') { $b | Should -Match "Resolve-SIJobKeyVaultSecret -Alias '$a'" }
        $b | Should -Match "-Alias 'si-spn-cert'[^\r\n]*\r?\n[^\r\n]*-Required"
    }
    It 'a re-run (resume) drops an optional secret the job carries but no longer gets -- never a required or unrelated one' {
        $job = [pscustomobject]@{ properties = [pscustomobject]@{ configuration = [pscustomobject]@{ secrets = @(
            [pscustomobject]@{ name = 'shodan-key' }, [pscustomobject]@{ name = 'openai-apikey' }, [pscustomobject]@{ name = 'si-spn-cert' }) } } }
        @(Get-SIUnwiredOptionalJobSecretNames -Job $job -SecretArgs @('openai-apikey=keyvaultref:https://kv/secrets/x,identityref:/u', 'si-spn-cert=keyvaultref:x')) | Should -Be @('shodan-key')
        @(Get-SIUnwiredOptionalJobSecretNames -Job $null -SecretArgs @()).Count | Should -Be 0
        $b = Get-Content -Raw (Join-Path $script:SIRoot 'Bootstrap-ContainerAppJob.ps1')
        $b | Should -Match 'Get-SIUnwiredOptionalJobSecretNames -Job \$existing -SecretArgs \$secretArgs'
        $b | Should -Match "\`$verb = if \(\`$existing\) \{ 'update' \} else \{ 'create' \}" -Because 'a job that failed to create is created on the re-run; an existing one is updated'
    }
    It 'the publicip engine says plainly in its log when it runs without Shodan' {
        Get-Content -Raw (Join-Path $script:SIRoot 'container\Start-SIInContainer.ps1') | Should -Match 'collected WITHOUT Shodan enrichment'
    }
}

Describe 'the Azure OpenAI key reaches the jobs as a Key Vault reference (#215, live 2026-10-02)' {
    BeforeAll { . (Join-Path $script:SIRoot 'container\_shared\SI-ContainerConfig.ps1') }
    It 'the generic helper: a reference with vault + identity, else the value, else nothing' {
        Get-SIKeyVaultSecretArg -Alias 'openai-apikey' -VaultUri 'https://kv1.vault.azure.net/' -SecretName 'OpenAI-ApiKey' -IdentityResourceId '/sub/x/uami' |
            Should -Be 'openai-apikey=keyvaultref:https://kv1.vault.azure.net/secrets/OpenAI-ApiKey,identityref:/sub/x/uami'
        Get-SIKeyVaultSecretArg -Alias 'openai-apikey' -Value 'v' | Should -Be 'openai-apikey=v'
        Get-SIKeyVaultSecretArg -Alias 'openai-apikey' | Should -BeNullOrEmpty
    }
    It 'one Key Vault Secrets User grant per vault: Shodan and OpenAI in the same vault = one grant; a second vault = a second' {
        @(Get-SIContainerIdentityGrantPlan -Mode ManagedIdentity -ShodanKeyVaultId '/kv/a' -OpenAIKeyVaultId '/kv/a' | Where-Object { $_.Role -eq 'Key Vault Secrets User' }).Count | Should -Be 1
        @(Get-SIContainerIdentityGrantPlan -Mode ManagedIdentity -ShodanKeyVaultId '/kv/a' -OpenAIKeyVaultId '/kv/b' | Where-Object { $_.Role -eq 'Key Vault Secrets User' }).Count | Should -Be 2
    }
    It 'WIRING -- setup decides AI from the endpoint / deployment / version, builds the key with the helper, and never needs the key value' {
        $b = Get-Content -Raw (Join-Path $script:SIRoot 'Bootstrap-ContainerAppJob.ps1')
        $b | Should -Match '\$haveOpenAiSettings = -not \(@\(''OpenAI_endpoint'',''OpenAI_deployment'',''OpenAI_apiVersion''\)'
        $b | Should -Match "Resolve-SIJobKeyVaultSecret -Alias 'openai-apikey'"
        $b | Should -Not -Match "'openai-apikey=\{0\}' -f"
        $b | Should -Match '-OpenAIKeyVaultId '
    }
}

Describe 'the Pro licence is read from the install''s vault at run time, never copied into a job (live 2026-10-03)' {
    BeforeAll { . (Join-Path $script:SIRoot 'container\_shared\SI-ContainerConfig.ps1') }
    It 'the collection identity reads the licence vault -- one grant per vault, shared with the Shodan / OpenAI vault' {
        $kv = @(Get-SIContainerIdentityGrantPlan -Mode ManagedIdentity -LicenceKeyVaultId '/kv/a' | Where-Object { $_.Role -eq 'Key Vault Secrets User' })
        $kv.Count | Should -Be 1
        $kv[0].Scope | Should -Be '/kv/a'
        $kv[0].Why | Should -Match 'SI-License'
        @(Get-SIContainerIdentityGrantPlan -Mode ManagedIdentity -ShodanKeyVaultId '/kv/a' -LicenceKeyVaultId '/kv/a' | Where-Object { $_.Role -eq 'Key Vault Secrets User' }).Count | Should -Be 1
    }
    It 'asset tagging''s own identity reads the licence vault too -- and gains no other Key Vault role' {
        $kv = @(Get-SIAssetTaggingIdentityGrantPlan -LicenceKeyVaultId '/kv/a' | Where-Object { $_.Role -like 'Key Vault*' })
        $kv.Count | Should -Be 1
        $kv[0].Role | Should -Be 'Key Vault Secrets User'
        @(Get-SIAssetTaggingIdentityGrantPlan | Where-Object { $_.Role -like 'Key Vault*' }).Count | Should -Be 0
    }
    It 'WIRING -- Bootstrap copies the licence into a job only when the install has no vault, and grants both identities the vault' {
        $b = Get-Content -Raw (Join-Path $script:SIRoot 'Bootstrap-ContainerAppJob.ps1')
        $b | Should -Match '\$licensedEngines -contains \$engine -and -not \$licenceVault -and'
        $b | Should -Match '\[string\]\$global:SI_KeyVaultName'
        ([regex]::Matches($b, '-LicenceKeyVaultId \$\(if \(\$licenceVault\)')).Count | Should -Be 2
        # the job update REPLACES the environment, so a job set up with a copy loses it on the next Bootstrap run
        $b | Should -Match ([regex]::Escape('Env = @($envArgs)'))
    }
}

Describe 'the token works from a scope that never ran the file''s setup (live 2026-10-02)' {
    # The ingestion bridge calls Get-SIManagedIdentityToken from inside AzLogDcrIngestPS, where `$script:` is the
    # module's scope and the file-level token cache does not exist. Live, every token failed with "You cannot call a
    # method on a null-valued expression" and every Log Analytics post on the identity was lost.
    It 'the function alone, in a fresh module scope without the cache, still issues and caches a token' {
        $ast = [System.Management.Automation.Language.Parser]::ParseFile((Join-Path $script:SIRoot 'auth\SI-ManagedIdentity.ps1'), [ref]$null, [ref]$null)
        $fn = $ast.Find({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq 'Get-SIManagedIdentityToken' }, $true)
        $mod = New-Module -Name 'si-mi-scope-test' -ScriptBlock ([scriptblock]::Create($fn.Extent.Text + "`nExport-ModuleMember -Function Get-SIManagedIdentityToken"))
        $env:IDENTITY_ENDPOINT = 'http://localhost:42356/msi/token'; $env:IDENTITY_HEADER = 'h'
        try {
            $script:calls = 0
            $fake = { param($u, $h) $script:calls++; [pscustomobject]@{ access_token = 'tok-123'; expires_on = '' } }
            & $mod { param($f) Get-SIManagedIdentityToken -Resource 'https://monitor.azure.com' -ClientId 'cid' -Invoke $f } $fake | Should -Be 'tok-123'
            & $mod { param($f) Get-SIManagedIdentityToken -Resource 'https://monitor.azure.com' -ClientId 'cid' -Invoke $f } $fake | Should -Be 'tok-123'
            $script:calls | Should -Be 1 -Because 'the second call is served from the cache the function created itself'
        } finally {
            Remove-Item Env:IDENTITY_ENDPOINT, Env:IDENTITY_HEADER -ErrorAction SilentlyContinue
            Remove-Module $mod -ErrorAction SilentlyContinue
        }
    }
}

Describe 'Get-SIGraphToken: the managed identity only with the switch (WIRING)' {

    BeforeEach {
        Reset-SIAuthState
        $env:IDENTITY_ENDPOINT = 'http://localhost:42356/msi/token'
        $env:IDENTITY_HEADER   = 'hdr-209'
        Mock Invoke-RestMethod {
            @{ access_token = ('tok-for-' + ([uri]$Uri).AbsoluteUri); expires_in = 3600; expires_on = [string]([DateTimeOffset]::UtcNow.AddHours(1).ToUnixTimeSeconds()) }
        }
    }
    AfterEach { Reset-SIAuthState }

    It 'switch on -> Graph, Defender and the data lake come from the identity endpoint' {
        $global:SI_UseManagedIdentity = $true; $global:SI_UAMI_ClientId = 'cid-209'
        # a secret is configured too -- the switch still wins, as in the container
        $global:SI_SPN_AppId = 'app'; $global:SI_SPN_Secret = 'sec'; $global:SI_SPN_TenantId = 'ten'
        Get-SIGraphToken -Resource Graph    | Should -BeLike 'tok-for-http://localhost:42356/msi/token?resource=https%3A%2F%2Fgraph.microsoft.com*'
        Get-SIGraphToken -Resource Defender | Should -BeLike '*resource=https%3A%2F%2Fapi.securitycenter.microsoft.com*'
        Get-SIGraphToken -Resource SentinelDataLake | Should -BeLike '*resource=4500ebfb-89b6-4b14-a480-7f749797bfcd*'
        Should -Invoke Invoke-RestMethod -Times 0 -ParameterFilter { [string]$Uri -like 'https://login.microsoftonline.com/*' }
    }
    It 'switch OFF -> the secret path, exactly as before, even inside a container that HAS an identity endpoint' {
        $global:SI_SPN_AppId = 'app'; $global:SI_SPN_Secret = 'sec'; $global:SI_SPN_TenantId = 'ten'
        $global:SI_UAMI_ClientId = 'cid-209'    # set, but the switch is not -- not the managed identity
        $t = Get-SIGraphToken -Resource Graph
        $t | Should -Be 'tok-for-https://login.microsoftonline.com/ten/oauth2/v2.0/token'
        Should -Invoke Invoke-RestMethod -Times 1 -Exactly -ParameterFilter { $Method -eq 'Post' -and $Body.client_secret -eq 'sec' -and $Body.scope -eq 'https://graph.microsoft.com/.default' }
        Should -Invoke Invoke-RestMethod -Times 0 -ParameterFilter { [string]$Uri -like 'http://localhost:42356/*' }
    }
    It 'the switch is the flag; the client id is optional (empty = the host''s system-assigned identity, #222)' {
        $global:SI_UseManagedIdentity = $true
        Test-SIUseManagedIdentity | Should -BeTrue
        $global:SI_UAMI_ClientId = 'cid'
        Test-SIUseManagedIdentity | Should -BeTrue
        Remove-Variable -Name SI_UseManagedIdentity -Scope Global
        Test-SIUseManagedIdentity | Should -BeFalse
    }
}

Describe 'no managed-identity branch without the switch (WIRING over the engine code)' {

    It 'only the container entry points and the one sign-in decision (#222) turn the switch on' {
        # Real assignments only (the AST), not prose in a comment.
        $setters = @(Get-ChildItem -LiteralPath $script:SIRoot -Recurse -File -Filter '*.ps1' |
            Where-Object { $_.FullName -notmatch '\\tests\\' } |
            Where-Object {
                $ast = [System.Management.Automation.Language.Parser]::ParseFile($_.FullName, [ref]$null, [ref]$null)
                @($ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.AssignmentStatementAst] -and
                                 "$($n.Left)" -eq '$global:SI_UseManagedIdentity' }, $true)).Count -gt 0
            } |
            ForEach-Object { $_.FullName.Substring($script:SIRoot.Length + 1).Replace('\', '/') } | Sort-Object)
        # + the guided install's Pro steps, which lend the installer's own token for the length of one SQL script and restore
        # the switch -- only where that file exists (the Community copy does not carry it; SI-CommunityPayload guards this name).
        $want = @('auth/SI-AuthMethod.ps1', 'container/Start-RiskAnalysisInContainer.ps1', 'container/Start-SIInContainer.ps1')
        # (since 2026-10-18 the database steps -- and this hook -- are in SI-GuidedInstallData.ps1, which both versions carry)
        $proSteps = 'setup/_shared/SI-GuidedInstallData.ps1'
        if (Test-Path -LiteralPath (Join-Path $script:SIRoot $proSteps)) { $want += $proSteps }
        $setters | Should -Be @($want | Sort-Object)
    }
    It 'every new managed-identity branch in the engines is guarded by the switch' {
        # (The Pro ledger's guard is the same line; a free test may not name a Pro file -- SI-CommunityPayload.)
        foreach ($rel in 'engine\risk-analysis\Invoke-RiskAnalysis.ps1', 'engine\privilege-tier-classifier\Invoke-PrivilegeTierClassifier.ps1',
                         'auth\Get-SIGraphToken.ps1') {
            $c = Get-Code $rel
            $c | Should -Match 'Get-Command -Name Test-SIUseManagedIdentity -ErrorAction SilentlyContinue\) -and \(Test-SIUseManagedIdentity\)' -Because $rel
        }
        Get-Code 'engine\asset-trend\Invoke-SITrend.ps1' | Should -Match '\$authParams = if \(\$global:SI_UseManagedIdentity\) \{'
    }
    It 'the engines never load the managed-identity helper themselves (a VM never has it)' {
        $loaders = @(Get-ChildItem -LiteralPath (Join-Path $script:SIRoot 'engine') -Recurse -File -Filter '*.ps1' |
            Where-Object { (Get-Code $_.FullName.Substring($script:SIRoot.Length + 1)) -match 'SI-ManagedIdentity\.ps1' })
        $loaders | Should -BeNullOrEmpty
    }
}

Describe 'the container entry points set the switch only from IDENTITY_ENDPOINT + SI_UAMI_CLIENTID (executed)' {

    BeforeAll {
        # The entry's sign-in block, executed as written: from the decision to the "[auth] signing in as" line.
        function script:Get-EntryAuthBlock([string]$Rel) {
            $src = Get-Content -Raw -LiteralPath (Join-Path $script:SIRoot $Rel)
            $m = [regex]::Match($src, '(?s)\$siAuth = Resolve-SIContainerAuthMode\r?\n.*?\r?\nWrite-Host \(''\[auth\] signing in as')
            $m.Success | Should -BeTrue -Because "$Rel carries the sign-in block"
            $m.Value.Substring(0, $m.Value.LastIndexOf('Write-Host'))
        }
        function script:Invoke-EntryAuth([string]$Rel) {
            $block = Get-EntryAuthBlock $Rel
            function Get-RequiredEnv([string]$Name) { $v = [Environment]::GetEnvironmentVariable($Name); if ([string]::IsNullOrWhiteSpace($v)) { throw "Required env var $Name is missing" }; $v }
            function Get-OptionalEnv([string]$Name, $Default = $null) { $v = [Environment]::GetEnvironmentVariable($Name); if ([string]::IsNullOrWhiteSpace($v)) { $Default } else { $v } }
            . ([scriptblock]::Create($block))
            $siAuth
        }
    }
    BeforeEach { Reset-SIAuthState }
    AfterEach { Reset-SIAuthState }

    It '<_>: identity endpoint + SI_UAMI_CLIENTID -> the switch, the identity, the ingest switch; no secret' -ForEach @('container\Start-SIInContainer.ps1', 'container\Start-RiskAnalysisInContainer.ps1') {
        $env:IDENTITY_ENDPOINT = 'http://localhost:42356/msi/token'; $env:SI_UAMI_CLIENTID = 'cid-209'; $env:SI_SPN_TENANTID = 'ten'
        $env:SI_SPN_SECRET = 'left-over-secret'
        $a = Invoke-EntryAuth $_
        $a.Mode | Should -Be 'ManagedIdentity'
        $global:SI_UseManagedIdentity | Should -BeTrue
        $global:SI_UAMI_ClientId | Should -Be 'cid-209'
        $global:SI_PreferUami | Should -BeTrue
        $global:SI_SPN_Secret | Should -BeNullOrEmpty
        $global:SpnClientSecret | Should -BeNullOrEmpty
    }
    It '<_>: a secret job (no identity) never gets the switch, and reads its secret as before' -ForEach @('container\Start-SIInContainer.ps1', 'container\Start-RiskAnalysisInContainer.ps1') {
        $env:SI_SPN_APPID = 'app'; $env:SI_SPN_SECRET = 'sec'; $env:SI_SPN_TENANTID = 'ten'; $env:SI_SPN_OBJECTID = 'obj'
        $env:SI_UAMI_CLIENTID = 'cid-209'   # without an identity endpoint
        $a = Invoke-EntryAuth $_
        $a.Mode | Should -Be 'Secret'
        (Get-Variable -Name SI_UseManagedIdentity -Scope Global -ErrorAction SilentlyContinue) | Should -BeNullOrEmpty
        ([string]$global:SI_SPN_Secret + [string]$global:SpnClientSecret) | Should -Be 'sec'
    }
    It 'Start-SIInContainer: the legacy UAMI override is read in secret mode only' {
        $c = Get-Code 'container\Start-SIInContainer.ps1'
        $c | Should -Match "(?s)if \(\`$siAuth\.Mode -eq 'Secret'\) \{\s*\`$global:SI_UAMI_ClientId = Get-OptionalEnv 'SI_UAMI_CLIENTID'"
    }
    It 'both entries sign in as the identity, and neither loads an ingestion module (#305)' {
        foreach ($rel in 'container\Start-SIInContainer.ps1', 'container\Start-RiskAnalysisInContainer.ps1') {
            $c = Get-Code $rel
            $c | Should -Match "if \(\`$siAuth\.Mode -eq 'ManagedIdentity'\) \{\s*(#[^\n]*\s*)?Connect-SIAzAccount -Identity -AccountId \`$global:SI_UAMI_ClientId"
            $c | Should -Not -Match 'Import-Module'
            $c | Should -Match 'CertificatePath = \$siCertPfxPath'
        }
    }
}

Describe 'the X509Store fallback where there is no Cert: drive' {

    BeforeAll { $script:cert = New-SITestCert }
    AfterEach { Reset-SIAuthState }

    It 'finds the certificate in CurrentUser\My through the store when the drive is absent' {
        $c = $script:cert
        $hit = Get-SICertificateFromStore -Thumbprint $c.Thumbprint -HasCertDrive { $false } -OpenStore { param($loc) if ($loc -eq 'CurrentUser') { , @($c) } else { , @() } }
        $hit.StoreLocation | Should -Be 'CurrentUser'
        $hit.Certificate.Thumbprint | Should -Be $c.Thumbprint
        Get-SICertStoreLocation -Thumbprint $c.Thumbprint -HasCertDrive { $false } -OpenStore { param($loc) if ($loc -eq 'CurrentUser') { , @($c) } else { , @() } } | Should -Be 'CurrentUser'
    }
    It 'LocalMachine is tried first (the order every engine used), and nothing found -> LocalMachine, as before' {
        $c = $script:cert
        (Get-SICertificateFromStore -Thumbprint $c.Thumbprint -HasCertDrive { $false } -OpenStore { param($loc) , @($c) }).StoreLocation | Should -Be 'LocalMachine'
        Get-SICertStoreLocation -Thumbprint 'AB CD' -HasCertDrive { $false } -OpenStore { param($loc) , @() } | Should -Be 'LocalMachine'
        Get-SICertificateFromStore -Thumbprint '' | Should -BeNullOrEmpty
    }
    It 'an unreadable store is a miss, not a crash' {
        Get-SICertificateFromStore -Thumbprint 'AA' -HasCertDrive { $false } -OpenStore { param($loc) throw 'denied' } | Should -BeNullOrEmpty
    }
    It 'the five ingest sites keep the Cert: drive where it exists and fall back to the store where it does not' {
        foreach ($rel in 'engine\_shared\SI-LogIngest.ps1', 'engine\asset-profiling\stages\Invoke-Output.ps1', 'engine\asset-profiling\stages\Invoke-SchemaOutput.ps1',
                         'engine\asset-profiling\stages\Invoke-Tagging.ps1', 'engine\asset-profiling\shared\Send-SIRunHealthRow.ps1') {
            $c = Get-Code $rel
            $c | Should -Match '(?s)if \(Get-PSDrive -Name Cert -ErrorAction SilentlyContinue\) \{\s*\$_?resolved = ''LocalMachine''.{0,600}\} else \{.{0,400}Get-SICertStoreLocation -Thumbprint' -Because $rel
            $c | Should -Match "auth/Find-SICertificate\.ps1" -Because $rel
        }
    }
    It 'EXECUTED: the correlation ingest resolver picks CurrentUser when the Cert: drive is absent' {
        . (Join-Path $script:SIRoot 'engine\_shared\SI-LogIngest.ps1')
        Mock Get-PSDrive { $null } -ParameterFilter { $Name -eq 'Cert' }
        Mock Get-SICertStoreLocation { 'CurrentUser' }
        $global:SI_SPN_AppId = 'app'; $global:SI_SPN_TenantId = 'ten'; $global:SI_SPN_CertThumbprint = 'AB12'
        $p = Resolve-SICorrelationAuthParams
        $p.AzAppCertificateStoreLocation | Should -Be 'CurrentUser'
        $p.AzAppCertificateThumbprint | Should -Be 'AB12'
        Should -Invoke Get-SICertStoreLocation -Times 1 -Exactly
    }
    It 'EXECUTED: with the drive present the resolver never touches the fallback' {
        . (Join-Path $script:SIRoot 'engine\_shared\SI-LogIngest.ps1')
        Mock Get-SICertStoreLocation { 'CurrentUser' }
        $global:SI_SPN_AppId = 'app'; $global:SI_SPN_TenantId = 'ten'; $global:SI_SPN_CertThumbprint = '0000NOTINSTALLED0000'
        if (Get-PSDrive -Name Cert -ErrorAction SilentlyContinue) {
            (Resolve-SICorrelationAuthParams).AzAppCertificateStoreLocation | Should -Be 'LocalMachine'
            Should -Invoke Get-SICertStoreLocation -Times 0
        } else { Set-ItResult -Skipped -Because 'this host has no Cert: drive' }
    }
    It 'a PFX from Key Vault becomes a PFX file + its thumbprint (store write skipped here)' {
        $pfx = [Convert]::ToBase64String($script:cert.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Pfx, 'pw-209'))
        # A Windows session signed in by SSH KEY (the gate on Invardia's test VM) has no DPAPI master key: persisting a
        # private key (PersistKeySet, what the container does) is "Access denied" there. Measured 2026-10-07; the
        # container (Linux) and an interactive Windows session persist it. Said as a skip, never a silent pass.
        try { $probe = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new([Convert]::FromBase64String($pfx), 'pw-209', [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::PersistKeySet); $probe.Dispose() }
        catch { if ("$($_.Exception.Message)" -match 'Access denied|Access is denied') { Set-ItResult -Skipped -Because 'this Windows session cannot persist a private key (SSH key logon: no DPAPI master key)'; return }; throw }
        $r = Import-SIContainerCertificate -PfxBase64 $pfx -Password 'pw-209' -Directory $TestDrive -SkipStore
        $r.Thumbprint | Should -Be $script:cert.Thumbprint
        Test-Path -LiteralPath $r.PfxPath | Should -BeTrue
    }
    It 'the certificate client token is a signed assertion -- never a secret' {
        $c = $script:cert
        Mock Get-SICertificateFromStore { [pscustomobject]@{ Certificate = $c; StoreLocation = 'CurrentUser' } }
        $script:sent = $null
        $t = Get-SICertificateClientToken -TenantId 'ten' -ClientId 'app' -Thumbprint $c.Thumbprint -Resource 'https://management.azure.com/' `
                 -Invoke { param($u, $b) $script:sent = @{ Uri = $u; Body = $b }; @{ access_token = 'cert-token' } }
        $t | Should -Be 'cert-token'
        $script:sent.Uri | Should -Be 'https://login.microsoftonline.com/ten/oauth2/v2.0/token'
        $script:sent.Body.scope | Should -Be 'https://management.azure.com/.default'
        $script:sent.Body.client_assertion_type | Should -Be 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer'
        @($script:sent.Body.client_assertion -split '\.').Count | Should -Be 3
        $script:sent.Body.ContainsKey('client_secret') | Should -BeFalse
    }
}

Describe 'log ingestion in a container needs no token bridge -- no PowerShell module is loaded (#305)' {

    It 'the bridge that patched the ingestion module is gone' {
        foreach ($n in 'Test-SIDcrTokenBridgeNeeded', 'Get-SIDcrBridgeToken', 'Install-SIDcrIngestTokenBridge') {
            Get-Command -Name $n -ErrorAction SilentlyContinue | Should -BeNullOrEmpty -Because $n
        }
    }
    It 'neither container entry point imports a module or installs a bridge' {
        foreach ($rel in 'container\Start-SIInContainer.ps1', 'container\Start-RiskAnalysisInContainer.ps1', 'container\Invoke-ShardProducer.ps1') {
            $code = Get-Code $rel
            $code | Should -Not -Match 'Import-Module' -Because $rel
            $code | Should -Not -Match 'Install-SIDcrIngestTokenBridge' -Because $rel
        }
    }
    It 'the managed identity token for ingestion comes from IDENTITY_ENDPOINT with the identity''s client id (not the VM metadata endpoint)' {
        Reset-SIAuthState
        $env:IDENTITY_ENDPOINT = 'http://localhost:42356/msi/token'
        $env:IDENTITY_HEADER   = 'hdr-209'
        try {
            Mock Invoke-RestMethod { @{ access_token = ('mi:' + ([uri]$Uri).AbsoluteUri); expires_in = 3600 } }
            $t = Get-SIManagedIdentityToken -Resource 'https://monitor.azure.com/' -ClientId 'cid-209' -ForceRefresh
            $t | Should -BeLike 'mi:http://localhost:42356/msi/token?resource=https%3A%2F%2Fmonitor.azure.com%2F&api-version=2019-08-01&client_id=cid-209'
            Should -Invoke Invoke-RestMethod -Times 0 -ParameterFilter { [string]$Uri -like '*169.254.169.254*' }
        } finally { Reset-SIAuthState }
    }
}
Describe 'Bootstrap: what each job carries to sign in' {

    It 'secret mode: exactly what every job carried before #209' {
        $a = Get-SIContainerJobAuthArgs -Mode Secret -SpnAppId 'app' -SpnSecret 'sec' -SpnTenantId 'ten' -SpnObjectId 'obj'
        @($a.SecretArgs) | Should -Be @('si-spn-secret=sec')
        @($a.EnvArgs) | Should -Be @('SI_SPN_APPID=app', 'SI_SPN_SECRET=secretref:si-spn-secret', 'SI_SPN_TENANTID=ten', 'SI_SPN_OBJECTID=obj')
        $a.IdentityResourceId | Should -BeNullOrEmpty
    }
    It 'managed identity mode: NO secret and no SI_SPN_SECRET; the identity is named and assigned' {
        $a = Get-SIContainerJobAuthArgs -Mode ManagedIdentity -SpnTenantId 'ten' -SpnSecret 'must-not-travel' `
                 -IdentityClientId 'cid' -IdentityPrincipalId 'pid' -IdentityResourceId '/subscriptions/s/resourceGroups/r/providers/Microsoft.ManagedIdentity/userAssignedIdentities/u'
        @($a.SecretArgs).Count | Should -Be 0
        ($a.EnvArgs -join ' ') | Should -Not -Match 'SI_SPN_SECRET|must-not-travel'
        @($a.EnvArgs) | Should -Contain 'SI_UAMI_CLIENTID=cid'
        @($a.EnvArgs) | Should -Contain 'SI_SPN_OBJECTID=pid'
        $a.IdentityResourceId | Should -BeLike '*/userAssignedIdentities/u'
    }
    It 'certificate mode: the PFX is a Key Vault REFERENCE resolved by the identity; no secret value' {
        $a = Get-SIContainerJobAuthArgs -Mode Certificate -SpnAppId 'app' -SpnTenantId 'ten' -SpnObjectId 'obj' -SpnSecret 'must-not-travel' `
                 -KeyVaultUri 'https://kv-x.vault.azure.net' -CertificateSecretName 'si-spn-pfx' -IdentityResourceId '/id/u'
        @($a.SecretArgs) | Should -Be @('si-spn-cert=keyvaultref:https://kv-x.vault.azure.net/secrets/si-spn-pfx,identityref:/id/u')
        @($a.EnvArgs) | Should -Contain 'SI_SPN_CERT_PFX_B64=secretref:si-spn-cert'
        ($a.EnvArgs + $a.SecretArgs -join ' ') | Should -Not -Match 'SI_SPN_SECRET|must-not-travel'
    }
    It 'managed identity / certificate without what they need is an error, not a half-configured job' {
        { Get-SIContainerJobAuthArgs -Mode ManagedIdentity -SpnTenantId 'ten' } | Should -Throw
        { Get-SIContainerJobAuthArgs -Mode Certificate -SpnAppId 'a' -SpnTenantId 't' -IdentityResourceId '/id' } | Should -Throw
    }
    It 'WIRING: the worker and the producer take the sign-in of the job; the producer carries the worker''s whole environment' {
        $c = Get-Code 'Bootstrap-ContainerAppJob.ps1'
        $c | Should -Match 'Resolve-SIBootstrapAuthChoice -UseManagedIdentity \(\[bool\]\$UseManagedIdentity\)'
        $c | Should -Match '\$spnRequired = @\(Get-SIBootstrapRequiredSpnGlobals -Mode \$authMode\)'
        # #236: the worker takes the sign-in of ITS job -- the collection $jobAuth, or asset tagging's own identity
        $c | Should -Match '\$engAuth     = if \(\$isAssetTagging\) \{ \$taggingAuth \} else \{ \$jobAuth \}'
        $c | Should -Match '\$secretArgs \+= @\(\$engAuth\.SecretArgs\)'
        $c | Should -Match '\$envArgs    \+= @\(\$engAuth\.EnvArgs\)'
        # #475: the producer discovers (it runs the engine), so it takes the worker's environment and secrets -- the sign-in
        # included -- without the queue-only settings (queue scaling refuses the secret sign-in, so no secret branch is left)
        $c | Should -Match ([regex]::Escape('$producerEnvArgs = @(Get-SIKedaProducerEnvArgs -EnvArgs $envArgs -Parallelism $parallelism)'))
        (Get-Code 'container\_shared\SI-ContainerConfig.ps1') | Should -Match ([regex]::Escape("@(@(`$EnvArgs | Where-Object { [string]`$_ -notmatch '^(SI_TRIGGER_FROM_QUEUE|SI_ROLE|SI_QUEUE_LEASE_SECONDS|SI_SHARD_COUNT)=' })"))
        $c | Should -Match ([regex]::Escape('$producerSecretArgs = @($secretArgs)'))
        $c | Should -Match "if \(\`$secretArgs\.Count -gt 0\) \{ \`$createArgs \+= @\('--secrets'\)"
        # no job hard-codes the secret any more: the sign-in comes from Get-SIContainerJobAuthArgs
        ([regex]::Matches($c, "'SI_SPN_SECRET=secretref:si-spn-secret'")).Count | Should -Be 0
        # the old per-engine identity with automatic grants is gone; grants are a plan, applied on request
        $c | Should -Not -Match "uami-si-\{0\}"
        $c | Should -Match 'Invoke-SIIdentityGrantPlan -Plan \$grantPlan -PrincipalId \$jobIdentity\.principalId -Apply:\$GrantIdentityRoles'
        # a job moved off the secret drops the stale secret
        $c | Should -Match ([regex]::Escape("if (`$haveJobSecrets -contains 'si-spn-secret') { `$removeSecrets.Add('si-spn-secret')"))
        $c | Should -Match ([regex]::Escape('RemoveSecrets = $removeSecrets.ToArray()'))
    }
}

Describe 'the managed identity''s grant plan' {

    BeforeAll {
        $script:plan = Get-SIContainerIdentityGrantPlan -Mode ManagedIdentity -ReaderScopes @('/subscriptions/s1', '/subscriptions/s2') `
            -DcrResourceGroupId '/subscriptions/s1/resourceGroups/rg-dcr' -WorkspaceResourceId '/subscriptions/s1/resourceGroups/rg-la/providers/Microsoft.OperationalInsights/workspaces/la' `
            -StorageAccountId '/subscriptions/s1/resourceGroups/rg/providers/Microsoft.Storage/storageAccounts/st'
    }

    It 'Azure RBAC: Reader at each collection scope, Metrics Publisher on the DCRs, LA Reader on the workspace, storage data on SI''s account' {
        $az = @($script:plan | Where-Object { $_.Kind -eq 'AzureRole' })
        @($az | Where-Object { $_.Role -eq 'Reader' } | ForEach-Object Scope) | Should -Be @('/subscriptions/s1', '/subscriptions/s2')
        ($az | Where-Object { $_.Role -eq 'Monitoring Metrics Publisher' }).Scope | Should -Be '/subscriptions/s1/resourceGroups/rg-dcr'
        ($az | Where-Object { $_.Role -eq 'Log Analytics Reader' }).Scope | Should -BeLike '*/workspaces/la'
        ($az | Where-Object { $_.Role -eq 'Storage Blob Data Contributor' }).Scope | Should -BeLike '*/storageAccounts/st'
        # nothing that can change the customer's estate
        @($az.Role | Where-Object { $_ -notin 'Reader', 'Monitoring Metrics Publisher', 'Log Analytics Reader',
                                              'Storage Blob Data Contributor', 'Storage Queue Data Contributor', 'Storage Table Data Contributor' }) | Should -BeNullOrEmpty
    }
    It 'application permissions: what the engines read -- Graph, advanced hunting, MDE machines' {
        $ap = @($script:plan | Where-Object { $_.Kind -eq 'AppRole' })
        $ap.Role | Should -Contain 'ThreatHunting.Read.All'
        $ap.Role | Should -Contain 'User.Read.All'
        $ap.Role | Should -Contain 'Device.Read.All'
        $ap.Role | Should -Contain 'RoleManagement.Read.Directory'
        ($ap | Where-Object { $_.Role -eq 'AdvancedHunting.Read.All' }).ResourceAppId | Should -Be '8ee8fdad-f234-4243-8f3b-15c294843740'
        ($ap | Where-Object { $_.Role -eq 'Machine.Read.All' }).ResourceAppId | Should -Be 'fc780465-2017-40d4-a0c5-307022471b92'
    }
    It 'READ ONLY: never Machine.ReadWrite.All, never any write permission' {
        $ap = @($script:plan | Where-Object { $_.Kind -eq 'AppRole' })
        $ap.Role | Should -Not -Contain 'Machine.ReadWrite.All'
        @($ap.Role | Where-Object { $_ -match '(?i)write|fullcontrol|\.Send\b|\.Manage' }) | Should -BeNullOrEmpty
        @($ap.Role | Where-Object { $_ -notmatch '\.Read(\.|$)' }) | Should -BeNullOrEmpty -Because 'every application permission is a Read'
    }
    It 'certificate mode: the identity only reads the PFX reference -- Key Vault Secrets User on that vault, nothing else' {
        $p = @(Get-SIContainerIdentityGrantPlan -Mode Certificate -KeyVaultId '/subscriptions/s/resourceGroups/r/providers/Microsoft.KeyVault/vaults/kv' -ReaderScopes @('/subscriptions/s'))
        $p.Count | Should -Be 1
        $p[0].Role | Should -Be 'Key Vault Secrets User'
        $p[0].Scope | Should -BeLike '*/vaults/kv'
    }
    It 'Bootstrap applies the plan only with -GrantIdentityRoles' {
        $c = Get-Code 'Bootstrap-ContainerAppJob.ps1'
        $fn = [regex]::Match($c, '(?s)function Invoke-SIIdentityGrantPlan \{.*?\n\}').Value
        $fn | Should -Not -BeNullOrEmpty
        # every create sits behind $Apply
        $fn | Should -Match "(?s)elseif \(\`$Apply\) \{.{0,250}New-SIRoleAssignment -ObjectId \`$PrincipalId -Scope \`$g\.Scope -RoleDefinitionName \`$g\.Role"
        $fn | Should -Match "(?s)elseif \(\`$Apply\) \{\s*try \{.{0,200}& \`$graph 'POST'"
        $fn | Should -Not -Match 'Invoke-Az\b|Invoke-SIAzCli'
    }
}

Describe '#446: the Pro web app''s own identity reads names in Entra -- read only, and the lookup is switched on only once granted' {
    It 'the plan is exactly three Microsoft Graph READ permissions -- nothing that writes, nothing broader' {
        $p = @(Get-SIWebAppIdentityGrantPlan)
        @($p | ForEach-Object Role) | Should -Be @('User.ReadBasic.All', 'GroupMember.Read.All', 'Application.Read.All')
        @($p | Where-Object { $_.Kind -ne 'AppRole' -or $_.ResourceAppId -ne '00000003-0000-0000-c000-000000000000' }) | Should -BeNullOrEmpty
        @($p | Where-Object { $_.Role -match 'Write|\.All$' -and $_.Role -notmatch 'Read' }) | Should -BeNullOrEmpty
        @($p | ForEach-Object Why) | Should -Not -Contain $null
    }
    It 'Grant-SIIdentity -WebApp uses that plan and needs no install config' {
        $g = [IO.File]::ReadAllText((Join-Path $script:SIRoot 'setup\Grant-SIIdentity.ps1'))
        $g | Should -Match '\[switch\]\$WebApp'
        $g | Should -Match '(?s)\$plan = if \(\$WebApp\) \{.{0,300}Get-SIWebAppIdentityGrantPlan'
        $g | Should -Match 'if \(\$WebApp\) \{ \$sub = '
    }
    It 'the guided install grants it to uami-si-management and sets Access__GraphLookup=true only when every grant is present (exit 0)' {
        # the web app step is in the database and web app steps' file (both versions, 2026-10-18)
        $i = [IO.File]::ReadAllText((Join-Path $script:SIRoot 'setup\_shared\SI-GuidedInstallData.ps1'))
        $i | Should -Match "(?s)setup/Grant-SIIdentity\.ps1'.{0,300}IdentityName = (?:'uami-si-management'|\(Get-SISetupComponentName -Names \`$n -Key WebIdentity\)).{0,200}WebApp = \`$true; Apply = \`$true"
        $i | Should -Match "(?s)if \(-not \`$grant\.ExitCode\) \{.{0,400}'Access__GraphLookup=true'"
    }
}
