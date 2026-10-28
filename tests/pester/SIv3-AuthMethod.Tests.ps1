#Requires -Version 5.1
<#
    ONE SIGN-IN DECISION, MANAGED IDENTITY FIRST, ON EVERY HOST (#222, operator 2026-10-03).
    auth/SI-AuthMethod.ps1 decides; auth/SI-ManagedIdentity.ps1 gets the token from the host's identity endpoint:
    a container (IDENTITY_ENDPOINT + IDENTITY_HEADER), an Azure VM (169.254.169.254), an Azure Arc server
    (IDENTITY_ENDPOINT + IMDS_ENDPOINT, 401 challenge file). Existing SPN installs keep their SPN.
#>

BeforeAll {
    $script:SIRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
    . (Join-Path $script:SIRoot 'auth\SI-AuthMethod.ps1')
    . (Join-Path $script:SIRoot 'auth\SI-ManagedIdentity.ps1')
    $script:EnvNames = 'IDENTITY_ENDPOINT', 'IDENTITY_HEADER', 'IMDS_ENDPOINT'
    function script:Save-Env { $h = @{}; foreach ($n in $script:EnvNames) { $h[$n] = [Environment]::GetEnvironmentVariable($n) }; $h }
    function script:Restore-Env($h) { foreach ($n in $script:EnvNames) { [Environment]::SetEnvironmentVariable($n, $h[$n]) } }
    function script:Set-HostEnv([string]$Kind) {
        foreach ($n in $script:EnvNames) { [Environment]::SetEnvironmentVariable($n, $null) }
        switch ($Kind) {
            'Container' { [Environment]::SetEnvironmentVariable('IDENTITY_ENDPOINT', 'http://localhost:42356/msi/token'); [Environment]::SetEnvironmentVariable('IDENTITY_HEADER', 'hdr') }
            'Arc'       { [Environment]::SetEnvironmentVariable('IDENTITY_ENDPOINT', 'http://localhost:40342/metadata/identity/oauth2/token'); [Environment]::SetEnvironmentVariable('IMDS_ENDPOINT', 'http://localhost:40342') }
        }
    }
    function script:Reset-MiState {
        foreach ($n in 'SI_UseManagedIdentity', 'SI_UAMI_ClientId', 'SI_PreferUami', 'UseManagedIdentity', 'SI_AuthMethodResolved') { Remove-Variable -Name $n -Scope Global -ErrorAction SilentlyContinue }
        $script:SIManagedIdentityTokenCache = @{}
    }
}

Describe 'the decision: explicit wins; without it, existing SPN installs keep their SPN; otherwise managed identity' {
    It 'an explicit SI_AuthMethod wins, in its short forms too' {
        (Resolve-SIAuthMethod -Globals @{ SI_AuthMethod = 'ManagedIdentity'; SI_SPN_AppId = 'a'; SI_SPN_CertThumbprint = 't' }).Mode | Should -Be 'ManagedIdentity'
        (Resolve-SIAuthMethod -Globals @{ SI_AuthMethod = 'mi' }).Mode | Should -Be 'ManagedIdentity'
        (Resolve-SIAuthMethod -Globals @{ SI_AuthMethod = 'Cert' }).Mode | Should -Be 'Certificate'
        (Resolve-SIAuthMethod -Globals @{ SI_AuthMethod = 'Secret' }).Mode | Should -Be 'Secret'
        (Resolve-SIAuthMethod -Globals @{ SI_AuthMethod = 'ManagedIdentity' }).Explicit | Should -BeTrue
    }
    It 'an unknown value is refused, not guessed' {
        { Resolve-SIAuthMethod -Globals @{ SI_AuthMethod = 'Kerberos' } } | Should -Throw '*not a sign-in method*'
    }
    It 'unset: an internal install keeps its platform identity; a configured SPN keeps that SPN' {
        (Resolve-SIAuthMethod -Globals @{ AutomationFramework = $true }).Mode | Should -Be 'AutomationFramework'
        (Resolve-SIAuthMethod -Globals @{ SI_SPN_AppId = 'a'; SI_SPN_CertThumbprint = 't' }).Mode | Should -Be 'Certificate'
        (Resolve-SIAuthMethod -Globals @{ SI_SPN_AppId = 'a'; SI_SPN_Secret = 's' }).Mode | Should -Be 'Secret'
        (Resolve-SIAuthMethod -Globals @{ SpnClientId = 'a'; SpnSecretName = 'kv-secret' }).Mode | Should -Be 'Secret'
    }
    It 'unset with no SPN: the managed identity is the default' {
        $d = Resolve-SIAuthMethod -Globals @{}
        $d.Mode | Should -Be 'ManagedIdentity'
        $d.Reason | Should -Match 'default'
        (Resolve-SIAuthMethod -Globals @{ SI_ManagedIdentityClientId = 'cid' }).ClientId | Should -Be 'cid'
        (Resolve-SIAuthMethod -Globals @{ SI_UAMI_ClientId = 'legacy' }).ClientId | Should -Be 'legacy'
    }
    It 'managed identity sets every switch the rest of SI reads; an explicit SPN choice clears them' {
        Reset-MiState
        try {
            $null = Set-SIAuthMethodGlobals -Globals @{ SI_AuthMethod = 'ManagedIdentity'; SI_ManagedIdentityClientId = 'cid' }
            $global:SI_UseManagedIdentity | Should -BeTrue
            $global:SI_UAMI_ClientId | Should -Be 'cid'
            $global:SI_PreferUami | Should -BeTrue
            $global:UseManagedIdentity | Should -BeTrue
            Test-SIUseManagedIdentity | Should -BeTrue
            $null = Set-SIAuthMethodGlobals -Globals @{ SI_AuthMethod = 'Certificate' }
            $global:SI_UseManagedIdentity | Should -BeFalse
            $global:UseManagedIdentity | Should -BeFalse
        } finally { Reset-MiState }
    }
}

Describe 'the host''s identity endpoint' {
    BeforeEach { $script:SavedEnv = Save-Env; Reset-MiState }
    AfterEach  { Restore-Env $script:SavedEnv; Reset-MiState }
    It 'detects container, Arc and Azure VM' {
        Set-HostEnv 'Container'; Get-SIManagedIdentityHost | Should -Be 'Container'
        Set-HostEnv 'Arc';       Get-SIManagedIdentityHost | Should -Be 'Arc'
        Set-HostEnv 'AzureVm';   Get-SIManagedIdentityHost | Should -Be 'AzureVm'
    }
    It 'Azure VM: the metadata endpoint with Metadata: true, client_id only when one is set' {
        Set-HostEnv 'AzureVm'
        $script:calls = New-Object System.Collections.Generic.List[object]
        $inv = { param($u, $h) $script:calls.Add(@{ U = $u; H = $h }); [pscustomobject]@{ access_token = 'vm-tok'; expires_in = '3600' } }
        Get-SIManagedIdentityToken -Resource 'https://management.azure.com/' -Invoke $inv | Should -Be 'vm-tok'
        $script:calls[0].U | Should -Match '^http://169\.254\.169\.254/metadata/identity/oauth2/token\?api-version=2018-02-01&resource=https%3A%2F%2Fmanagement\.azure\.com%2F$'
        $script:calls[0].H['Metadata'] | Should -Be 'true'
        Get-SIManagedIdentityToken -Resource 'https://graph.microsoft.com' -ClientId 'uami' -Invoke $inv | Out-Null
        $script:calls[1].U | Should -Match '&client_id=uami$'
    }
    It 'Arc: the 401 challenge names a file whose content is the secret for the second call' {
        Set-HostEnv 'Arc'
        $script:calls = New-Object System.Collections.Generic.List[object]
        $inv = {
            param($u, $h)
            $script:calls.Add(@{ U = $u; H = $h })
            if ($h.ContainsKey('Authorization')) { [pscustomobject]@{ Status = 200; Body = '{"access_token":"arc-tok","expires_in":"3600"}'; WwwAuthenticate = '' } }
            else { [pscustomobject]@{ Status = 401; Body = ''; WwwAuthenticate = 'Basic realm=C:\ProgramData\AzureConnectedMachineAgent\Tokens\abc.key' } }
        }
        $read = { param($p) if ($p -ne 'C:\ProgramData\AzureConnectedMachineAgent\Tokens\abc.key') { throw "wrong file $p" }; 'SECRET' }
        Get-SIManagedIdentityToken -Resource 'https://database.windows.net/' -Invoke $inv -ReadFile $read | Should -Be 'arc-tok'
        $script:calls.Count | Should -Be 2
        $script:calls[0].U | Should -Match '^http://localhost:40342/metadata/identity/oauth2/token\?api-version=2020-06-01&resource='
        $script:calls[1].H['Authorization'] | Should -Be 'Basic SECRET'
    }
    It 'Arc: an unreadable challenge file says which group the run needs' {
        Set-HostEnv 'Arc'
        $inv = { param($u, $h) [pscustomobject]@{ Status = 401; Body = ''; WwwAuthenticate = 'Basic realm=C:\x.key' } }
        { Get-SIManagedIdentityToken -Resource 'https://graph.microsoft.com' -Invoke $inv -ReadFile { throw 'access denied' } } | Should -Throw "*Hybrid agent extension applications*"
    }
    It 'the container path is unchanged (X-IDENTITY-HEADER, api-version 2019-08-01)' {
        Set-HostEnv 'Container'
        $script:calls = New-Object System.Collections.Generic.List[object]
        $inv = { param($u, $h) $script:calls.Add(@{ U = $u; H = $h }); [pscustomobject]@{ access_token = 'ctr-tok'; expires_on = '9999999999' } }
        Get-SIManagedIdentityToken -Resource 'https://graph.microsoft.com' -ClientId 'c1' -Invoke $inv | Should -Be 'ctr-tok'
        $script:calls[0].U | Should -Match 'api-version=2019-08-01&client_id=c1$'
        $script:calls[0].H['X-IDENTITY-HEADER'] | Should -Be 'hdr'
    }
    It 'ingestion needs no bridge on any host: there is no ingestion module to patch, it mints its token here (#305)' {
        foreach ($n in 'Test-SIDcrTokenBridgeNeeded', 'Get-SIDcrBridgeToken', 'Install-SIDcrIngestTokenBridge') {
            Get-Command -Name $n -ErrorAction SilentlyContinue | Should -BeNullOrEmpty -Because "$n patched a PowerShell module that SecurityInsight no longer uses"
        }
    }
}

Describe 'WIRING -- every host decides once, before any engine runs' {
    It 'the VM launchers load the identity helpers and apply the decision in the config loader' {
        $c = Get-Content -Raw -LiteralPath (Join-Path $script:SIRoot 'launcher\_lib\Initialize-LauncherConfig.ps1')
        $c | Should -Match "\. \(Join-Path \`$__siAuthDir 'SI-AuthMethod\.ps1'\)"
        $c | Should -Match "\. \(Join-Path \`$__siAuthDir 'SI-ManagedIdentity\.ps1'\)"
        $c | Should -Match '\$__auth = Set-SIAuthMethodGlobals'
    }
    It 'the helpers land in the LAUNCHER''s scope (file level, not inside the function) -- executed' {
        $script:lc = Join-Path $script:SIRoot 'launcher\_lib\Initialize-LauncherConfig.ps1'
        $probe = & { . $script:lc; [bool](Get-Command Set-SIAuthMethodGlobals -ErrorAction SilentlyContinue) -and [bool](Get-Command Get-SIManagedIdentityToken -ErrorAction SilentlyContinue) }
        $probe | Should -BeTrue
    }
    It 'the auth state puts the managed identity FIRST and does not require a client id' {
        $c = Get-Content -Raw -LiteralPath (Join-Path $script:SIRoot 'launcher\_lib\Get-SIAuthState.ps1')
        $c.IndexOf('# ---- Managed Identity branch ----') | Should -BeLessThan $c.IndexOf('# ---- AutomationFramework branch')
        $c | Should -Match 'if \(\[bool\]\$global:SI_UseManagedIdentity\)'
    }
    It 'the auth state, executed: no client id = system-assigned; an internal install is NOT moved by a leftover container flag' {
        . (Join-Path $script:SIRoot 'launcher\_lib\Get-SIAuthState.ps1')
        $names = 'SI_UseManagedIdentity', 'SI_UAMI_ClientId', 'SI_PreferUami', 'AutomationFramework', 'SpnTenantId', 'SpnClientId', 'SpnCertificateThumbprint'
        $saved = @{}; foreach ($n in $names) { $saved[$n] = Get-Variable -Name $n -Scope Global -ValueOnly -ErrorAction SilentlyContinue; Remove-Variable -Name $n -Scope Global -ErrorAction SilentlyContinue }
        try {
            $global:SI_UseManagedIdentity = $true
            $s = Get-SIAuthState
            $s.AuthMode | Should -Be 'MI'
            $s.AuthParams.ContainsKey('ManagedIdentityClientId') | Should -BeFalse
            $global:SI_UAMI_ClientId = 'uami-1'
            (Get-SIAuthState).AuthParams['ManagedIdentityClientId'] | Should -Be 'uami-1'
            Remove-Variable -Name SI_UseManagedIdentity -Scope Global
            $global:SI_PreferUami = $true; $global:AutomationFramework = $true
            $global:SpnTenantId = 't'; $global:SpnClientId = 'a'; $global:SpnCertificateThumbprint = 'th'
            (Get-SIAuthState).AuthMode | Should -Be 'AF'
            $global:AutomationFramework = $false
            (Get-SIAuthState).AuthMode | Should -Be 'MI' -Because 'the legacy flag + client id still means managed identity on a non-internal install'
        } finally {
            foreach ($n in $names) { Remove-Variable -Name $n -Scope Global -ErrorAction SilentlyContinue; if ($null -ne $saved[$n]) { Set-Variable -Name $n -Scope Global -Value $saved[$n] } }
        }
    }
    It 'a VM or Arc identity is granted from the SAME plan as a container job, and nothing changes without -Apply' {
        $c = Get-Content -Raw -LiteralPath (Join-Path $script:SIRoot 'setup\Grant-SIIdentity.ps1')
        $c | Should -Match 'Get-SIContainerIdentityGrantPlan -Mode ManagedIdentity'
        $c | Should -Match "ParameterSetName = 'Vm'"
        $c | Should -Match "ParameterSetName = 'Arc'"
        $c | Should -Match "ParameterSetName = 'Uami'"
        foreach ($w in 'New-SIRoleAssignment', 'New-SIGraphAppRoleAssignment') {
            $i = $c.IndexOf($w); $i | Should -BeGreaterThan 0
            $c.Substring([Math]::Max(0, $i - 260), 260) | Should -Match 'elseif \(\$Apply\)' -Because "$w only under -Apply"
        }
        $err = $null; [void][System.Management.Automation.Language.Parser]::ParseFile((Join-Path $script:SIRoot 'setup\Grant-SIIdentity.ps1'), [ref]$null, [ref]$err)
        @($err).Count | Should -Be 0
    }
    It 'no engine passes a raw environment variable as upload column data -- a Linux container has no COMPUTERNAME / USERNAME (live 2026-10-03)' {
        $hits = @(Get-ChildItem -LiteralPath (Join-Path $script:SIRoot 'engine') -Recurse -File -Filter '*.ps1' |
            Select-String -Pattern '-Column\dData\s+\$env:' | ForEach-Object { '{0}:{1}' -f $_.Filename, $_.LineNumber })
        $hits | Should -BeNullOrEmpty -Because 'an empty value fails the parameter binding and the whole upload is lost'
    }
    It 'Risk Analysis uploads as the managed identity on a VM too: every ingest call passes the decided id, never an empty SPN id (live 2026-10-03)' {
        $c = Get-Content -Raw -LiteralPath (Join-Path $script:SIRoot 'engine\risk-analysis\Invoke-RiskAnalysis.ps1')
        $c | Should -Match "elseif \(\`$__raMi\) \{ '00000000-0000-0000-0000-000000000000' \}" -Because 'a system-assigned identity has no client id'
        $s = $c.IndexOf('$__raIngestAppId = if'); $e = $c.IndexOf('Uploading export files to:')
        $s | Should -BeGreaterThan 0; $e | Should -BeGreaterThan $s
        $section = $c.Substring($s, $e - $s)
        ([regex]::Matches($section, '-AzAppId\s+\$__raIngestAppId')).Count | Should -Be 4
        ([regex]::Matches($section, '-AzAppId\s+\$global:SpnClientId')).Count | Should -Be 0
    }
    It 'the Invardia Support app gets only what SI can grant, by level, and -Remove takes it all back (#227)' {
        $f = Join-Path $script:SIRoot 'setup\Grant-SISupportAccess.ps1'
        $err = $null; [void][System.Management.Automation.Language.Parser]::ParseFile($f, [ref]$null, [ref]$err); @($err).Count | Should -Be 0
        $c = Get-Content -Raw -LiteralPath $f
        $c | Should -Match 'SupportsShouldProcess' -Because '-WhatIf shows the plan and changes nothing'
        $c | Should -Match "ValidateSet\('troubleshoot', 'setup'\)"
        $c | Should -Match "'Key Vault Reader'" ; $c | Should -Match "'Key Vault Secrets Officer'"
        # framework 4.1b (owner 2026-10-18, superseding "group only"): BOTH parts at both levels -- the admin GROUP and its
        # own database user from the SID of its client id with db_owner; never FROM EXTERNAL PROVIDER (SIv3-SupportAppDatabase)
        $c | Should -Match 'CREATE USER \[\$un\] WITH SID = \$sid, TYPE = E' -Because 'the Support app gets its own database user (part b)'
        $c | Should -Match 'ALTER ROLE db_owner ADD MEMBER' -Because 'with the owner role the setup scripts need'
        $c | Should -Not -Match 'FROM EXTERNAL PROVIDER' -Because 'never FROM EXTERNAL PROVIDER'
        $c | Should -Not -Match 'GRANT VIEW DEFINITION|db_datawriter|db_ddladmin' -Because 'db_owner is the one role'
        $c | Should -Match '\$should = -not \$Remove' -Because 'the membership is added at both levels and taken away only by -Remove'
        $c | Should -Match '/owners/`\$ref' ; $c | Should -Match '/members/`\$ref'
        foreach ($w in 'DROP USER', 'Remove-SIRoleAssignment', 'Invoke-Graph Delete') { $c | Should -Match ([regex]::Escape($w)) -Because "-Remove undoes it ($w)" }
        $c | Should -Match 'exit 1' -Because 'anything not done is reported and fails the run'
    }
    It 'the Pro SQL admin is ONE product group, named the same everywhere, members checked from the member''s side (operator 2026-10-03)' {
        $f = Join-Path $script:SIRoot 'setup\Set-SISqlAdminGroup.ps1'
        $err = $null; [void][System.Management.Automation.Language.Parser]::ParseFile($f, [ref]$null, [ref]$err); @($err).Count | Should -Be 0
        $c = Get-Content -Raw -LiteralPath $f
        $c | Should -Match "\[string\]\`$GroupName = 'grp-si-sql-admins'" -Because 'one product-level name, no environment or ring in it (framework 5.5: product si, like grp-pim-sql-admins)'
        $c | Should -Match 'SupportsShouldProcess'
        $c | Should -Match 'the current admin first' -Because 'switching the admin never locks anyone out'
        foreach ($s in 'Set-SISqlAdminGroup.ps1', 'Grant-SISupportAccess.ps1') {
            $x = Get-Content -Raw -LiteralPath (Join-Path $script:SIRoot "setup\$s")
            $x | Should -Match 'checkMemberGroups' -Because "$s must ask the member (a /members listing hides service principals)"
            $x | Should -Not -Match '/members\?`\$select=id"' -Because "$s must not decide membership from a plain /members listing"
        }
    }
    It 'the guided install asks for the support app and its level, never anything secret (#227)' {
        $j = Get-Content -Raw -LiteralPath (Join-Path $script:SIRoot 'setup\install-parameters.json') | ConvertFrom-Json
        $sa = @($j.parameters | Where-Object key -eq 'supportAppId'); $sa.Count | Should -Be 1; $sa[0].type | Should -Be 'guid'; [bool]$sa[0].required | Should -BeFalse
        $lv = @($j.parameters | Where-Object key -eq 'supportAccess'); $lv[0].default | Should -Be 'troubleshoot'
        @($lv[0].options | ForEach-Object value) | Should -Be @('troubleshoot', 'setup')
        @($j.parameters | Where-Object { $_.key -match '(?i)secret|password|apikey|token' }).Count | Should -Be 0
    }
    It 'secrets read at config load sign in as the install''s managed identity (SI_ManagedIdentityClientId first)' {
        $c = Get-Content -Raw -LiteralPath (Join-Path $script:SIRoot 'auth\Get-SIKvSecret.ps1')
        $c.IndexOf('SI_ManagedIdentityClientId') | Should -BeLessThan $c.IndexOf('elseif ($global:SI_KvMiClientId)')
        $c | Should -Match 'Connect-SIAzAccount -Identity -AccountId \$kvMi'
    }
    It 'every Community launcher signs in as the user-assigned identity when a client id is set (asset-tagging is SPN-only and says so)' {
        foreach ($f in Get-ChildItem -LiteralPath (Join-Path $script:SIRoot 'launcher') -Recurse -Filter 'launcher.community-vm.ps1' | Where-Object { $_.Directory.Name -ne 'asset-tagging' }) {
            (Get-Content -Raw -LiteralPath $f.FullName) | Should -Match 'Connect-SIAzAccount -Identity @miArgs' -Because $f.FullName
        }
    }
}
