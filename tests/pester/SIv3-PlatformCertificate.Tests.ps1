#Requires -Version 5.1
<#
    THE PLATFORM CERTIFICATE CHECK READS THE CERTIFICATE, NOT ITS WRAPPER (#395) -- auth/SI-PlatformConnect.ps1.

    Found by the v3 release-readiness upgrade test on the internal path: "The platform certificate 78E4... is installed but
    EXPIRED on ." for a certificate valid until 2028 with its private key. Get-SICertificateFromStore returns a wrapper
    { Certificate; StoreLocation }; Test-SIPlatformCertificateUsable read NotAfter on the WRAPPER ($null), and
    `$null -le (Get-Date)` is true -- so every certificate was "expired", the sign-in fell back to a client secret the
    internal installs do not have, and every SI run on every internal customer failed. The offline tests passed a -Find
    seam returning a bare certificate, so they never saw the real shape.

    These tests use REAL self-signed certificates, created in CurrentUser\My by the test and removed afterwards (with their
    key containers), and the REAL Get-SICertificateFromStore:
      valid + private key -> usable (the wrapper shape, the live failure);  expired -> not usable, said once with the date;
      not yet valid -> not usable;  no private key -> not found by the store lookup, and a bare key-less certificate
      handed in is refused;  a wrapper and a bare certificate are judged the same;
      Connect-SIPlatform with Key Vault mocked: a valid installed certificate signs in by certificate and the secret is
      never read; an expired one falls back to the secret.
    PS 5.1 + pwsh 7 (.NET CertificateRequest; no PKI module).
#>

BeforeDiscovery {
    # These tests persist real certificates WITH their keys in CurrentUser\My. A session without a loaded user profile (the
    # test VM's SSH session, #447) cannot ("Access denied"): the suite is skipped there, saying why -- never a red gate
    # for the host, never a silent pass. mgmt1 and any desktop session run it.
    $script:CertStoreUsable = $false
    try {
        $rsa = [System.Security.Cryptography.RSA]::Create(2048)
        $req = New-Object System.Security.Cryptography.X509Certificates.CertificateRequest('CN=si-store-probe', $rsa, [System.Security.Cryptography.HashAlgorithmName]::SHA256, [System.Security.Cryptography.RSASignaturePadding]::Pkcs1)
        $tmp = $req.CreateSelfSigned([DateTimeOffset](Get-Date).AddMinutes(-5), [DateTimeOffset](Get-Date).AddMinutes(5))
        $flags = [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::PersistKeySet -bor [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::UserKeySet
        $c = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2 -ArgumentList @($tmp.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Pfx), [string]$null, $flags)
        $st = New-Object System.Security.Cryptography.X509Certificates.X509Store('My', 'CurrentUser'); $st.Open('ReadWrite'); $st.Add($c); $st.Remove($c); $st.Close()
        try { ([System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($c)).Key.Delete() } catch { }
        $script:CertStoreUsable = $true
    } catch { $script:CertStoreUsable = $false }
}

BeforeAll {
    $script:SIRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
    . (Join-Path $script:SIRoot 'engine\_shared\SI-AzRest.ps1')
    . (Join-Path $script:SIRoot 'auth\SI-PlatformConnect.ps1')

    $script:Made = New-Object System.Collections.Generic.List[object]

    function script:New-TestCertificate {
        <# A self-signed RSA certificate. -Store: persisted with its key in CurrentUser\My. -PublicOnly: the certificate
           without its key (in the store when -Store). Returns the X509Certificate2 as stored. #>
        param([datetime]$NotBefore, [datetime]$NotAfter, [switch]$Store, [switch]$PublicOnly)
        $rsa = [System.Security.Cryptography.RSA]::Create(2048)
        try {
            $req = New-Object System.Security.Cryptography.X509Certificates.CertificateRequest(
                ('CN=SI-395-test-{0}' -f [guid]::NewGuid().ToString('N').Substring(0, 8)), $rsa,
                [System.Security.Cryptography.HashAlgorithmName]::SHA256, [System.Security.Cryptography.RSASignaturePadding]::Pkcs1)
            $tmp = $req.CreateSelfSigned([DateTimeOffset]$NotBefore, [DateTimeOffset]$NotAfter)
            $pw = [guid]::NewGuid().ToString('N')
            $flags = [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::PersistKeySet -bor
                     [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::UserKeySet
            $cert = if ($PublicOnly) {
                New-Object System.Security.Cryptography.X509Certificates.X509Certificate2(, $tmp.RawData)
            } else {
                New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($tmp.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Pfx, $pw), $pw, $flags)
            }
            if ($Store) {
                $s = New-Object System.Security.Cryptography.X509Certificates.X509Store('My', 'CurrentUser')
                try { $s.Open('ReadWrite'); $s.Add($cert) } finally { $s.Close() }
                $script:Made.Add($cert)
            }
            return $cert
        } finally { $rsa.Dispose() }
    }

    function script:Remove-TestCertificates {
        # every certificate this suite ever made (also one left behind by a run that was killed): by its subject prefix
        $all = New-Object System.Collections.Generic.List[object]
        foreach ($c in $script:Made.ToArray()) { $all.Add($c) }
        try {
            $s = New-Object System.Security.Cryptography.X509Certificates.X509Store('My', 'CurrentUser')
            try {
                $s.Open('ReadOnly')
                foreach ($x in @($s.Certificates | Where-Object { $_.Subject -like 'CN=SI-395-test-*' })) {
                    if (-not @($all | Where-Object { $_.Thumbprint -eq $x.Thumbprint }).Count) { $all.Add($x) }
                }
            } finally { $s.Close() }
        } catch { }
        foreach ($c in $all.ToArray()) {
            try {
                $s = New-Object System.Security.Cryptography.X509Certificates.X509Store('My', 'CurrentUser')
                try {
                    $s.Open('ReadWrite')
                    foreach ($x in @($s.Certificates | Where-Object { $_.Thumbprint -eq $c.Thumbprint })) { $s.Remove($x) }
                } finally { $s.Close() }
            } catch { }
            # the persisted key container goes too, not only the store entry
            try {
                if ($c.HasPrivateKey) {
                    $k = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($c)
                    if ($k -is [System.Security.Cryptography.RSACng]) { $k.Key.Delete() }
                    elseif ($k -is [System.Security.Cryptography.RSACryptoServiceProvider]) { $k.PersistKeyInCsp = $false; $k.Clear() }
                }
            } catch { }
        }
        $script:Made.Clear()
    }

    function script:Invoke-Usable {
        <# Test-SIPlatformCertificateUsable with its warnings captured: @{ Ok; Warnings }. #>
        param([string]$Thumbprint, [scriptblock]$Find)
        $a = @{ Thumbprint = $Thumbprint }; if ($Find) { $a.Find = $Find }
        $all = @(Test-SIPlatformCertificateUsable @a 3>&1)
        [pscustomobject]@{ Ok = @($all | Where-Object { $_ -isnot [System.Management.Automation.WarningRecord] })[0]
                           Warnings = (@($all | Where-Object { $_ -is [System.Management.Automation.WarningRecord] } | ForEach-Object { $_.Message }) -join ' ') }
    }

    function script:Test-InStore([string]$Thumbprint) {
        $s = New-Object System.Security.Cryptography.X509Certificates.X509Store('My', 'CurrentUser')
        try { $s.Open('ReadOnly'); return [bool]@($s.Certificates | Where-Object { $_.Thumbprint -eq $Thumbprint }).Count } finally { $s.Close() }
    }

    $script:Now = Get-Date
    $script:Valid     = New-TestCertificate -NotBefore $script:Now.AddDays(-1)   -NotAfter $script:Now.AddYears(2)  -Store
    $script:Expired   = New-TestCertificate -NotBefore $script:Now.AddDays(-400) -NotAfter $script:Now.AddDays(-2)  -Store
    $script:NotYet    = New-TestCertificate -NotBefore $script:Now.AddDays(10)   -NotAfter $script:Now.AddYears(1)  -Store
    $script:NoKey     = New-TestCertificate -NotBefore $script:Now.AddDays(-1)   -NotAfter $script:Now.AddYears(1)  -Store -PublicOnly
}

AfterAll { Remove-TestCertificates }

Describe 'SIv3-PlatformCertificate -- the check reads the certificate, never the wrapper (#395)' -Skip:(-not $script:CertStoreUsable) {
    It 'the test certificates are really in CurrentUser\My (valid / expired / not yet valid with keys; one without its key)' {
        foreach ($c in $script:Valid, $script:Expired, $script:NotYet, $script:NoKey) { Test-InStore $c.Thumbprint | Should -BeTrue }
        $script:Valid.HasPrivateKey | Should -BeTrue
        $script:NoKey.HasPrivateKey | Should -BeFalse
    }

    It 'the store lookup returns a WRAPPER { Certificate; StoreLocation } -- the shape the check must read through' {
        $hit = Get-SICertificateFromStore -Thumbprint $script:Valid.Thumbprint
        $hit | Should -Not -BeNullOrEmpty
        $hit.PSObject.Properties.Name | Should -Contain 'Certificate'
        $hit.PSObject.Properties.Name | Should -Contain 'StoreLocation'
        $hit.StoreLocation | Should -Be 'CurrentUser'
        $hit.Certificate.Thumbprint | Should -Be $script:Valid.Thumbprint
        $hit.PSObject.Properties['NotAfter'] | Should -BeNullOrEmpty -Because 'reading NotAfter on the wrapper is what reported every certificate as expired'
    }

    It 'a valid certificate with its private key is usable -- through the real store lookup (the live failure)' {
        $r = Invoke-Usable -Thumbprint $script:Valid.Thumbprint
        $r.Ok | Should -BeTrue
        $r.Warnings | Should -BeNullOrEmpty -Because 'a valid certificate was reported "EXPIRED on ." before the fix'
        # the thumbprint as a vault may hold it: lower case, with spaces
        $spaced = (($script:Valid.Thumbprint.ToLowerInvariant() -split '(.{4})' | Where-Object { $_ }) -join ' ')
        (Invoke-Usable -Thumbprint $spaced).Ok | Should -BeTrue
    }

    It 'an expired certificate is not usable, and the warning names the real date' {
        $r = Invoke-Usable -Thumbprint $script:Expired.Thumbprint
        $r.Ok | Should -BeFalse
        $r.Warnings | Should -Match 'EXPIRED'
        $r.Warnings | Should -Match ([regex]::Escape($script:Expired.NotAfter.ToString('yyyy-MM-dd')))
    }

    It 'a certificate that is not valid yet is not usable' {
        $r = Invoke-Usable -Thumbprint $script:NotYet.Thumbprint
        $r.Ok | Should -BeFalse
        $r.Warnings | Should -Match 'not valid before'
    }

    It 'a certificate installed without its private key is not usable (the store lookup skips it; a bare key-less one is refused)' {
        Get-SICertificateFromStore -Thumbprint $script:NoKey.Thumbprint | Should -BeNullOrEmpty
        (Invoke-Usable -Thumbprint $script:NoKey.Thumbprint).Ok | Should -BeFalse
        $r = Invoke-Usable -Thumbprint $script:NoKey.Thumbprint -Find { param($t) $script:NoKey }
        $r.Ok | Should -BeFalse
        $r.Warnings | Should -Match 'WITHOUT its private key'
    }

    It 'a certificate that is not installed is not usable, silently' {
        $r = Invoke-Usable -Thumbprint ('0' * 40)
        $r.Ok | Should -BeFalse
        $r.Warnings | Should -BeNullOrEmpty
        (Invoke-Usable -Thumbprint '').Ok | Should -BeFalse
    }

    It 'a wrapper and a bare certificate are judged the same' {
        foreach ($c in $script:Valid, $script:Expired) {
            $expect = ($c.NotAfter -gt (Get-Date))
            (Invoke-Usable -Thumbprint $c.Thumbprint -Find { param($t) [pscustomobject]@{ Certificate = $c; StoreLocation = 'CurrentUser' } }.GetNewClosure()).Ok | Should -Be $expect
            (Invoke-Usable -Thumbprint $c.Thumbprint -Find { param($t) $c }.GetNewClosure()).Ok | Should -Be $expect
        }
    }

    It 'anything else handed back is refused with a clear warning, never read as a date' {
        $r = Invoke-Usable -Thumbprint 'AA11' -Find { param($t) [pscustomobject]@{ Thumbprint = 'AA11' } }
        $r.Ok | Should -BeFalse
        $r.Warnings | Should -Match 'could not be read'
    }
}

Describe 'SIv3-PlatformCertificate -- the internal sign-in with a real installed certificate (#395)' -Skip:(-not $script:CertStoreUsable) {
    BeforeAll {
        $script:GlobalNames = 'Context', 'AzureTenantId', 'HighPriv_Modern_ApplicationID_Azure', 'HighPriv_Modern_Secret_Azure', 'HighPriv_Modern_AuthMethod',
                              'HighPriv_Modern_CertificateThumbprint_Azure', 'KV_HighPriv_KeyVaultName', 'KV_HighPriv_SubscriptionId', 'AutomationFramework',
                              'SI_SPN_TenantId', 'SI_SPN_AppId', 'SI_SPN_Secret', 'SI_SPN_CertThumbprint', 'SpnTenantId', 'SpnClientId', 'SpnClientSecret',
                              'SpnCertificateThumbprint', 'SI_AzRestState', 'SI_LogIngestRunCache'
    }
    BeforeEach {
        $script:keep = @{}
        foreach ($n in $script:GlobalNames) { $script:keep[$n] = Get-Variable -Scope Global -Name $n -ValueOnly -ErrorAction SilentlyContinue; Remove-Variable -Scope Global -Name $n -ErrorAction SilentlyContinue }
        $script:Reads = New-Object System.Collections.Generic.List[string]
        $script:Root = Join-Path ([System.IO.Path]::GetTempPath()) ('si395-' + [guid]::NewGuid().ToString('N'))
        $null = New-Item -ItemType Directory -Force -Path (Join-Path $script:Root 'bootstrap')
        (@{ TenantId = 'ten-1'; SubscriptionId = 'sub-1'; KeyVaultName = 'kv-plat'; BootstrapAppId = 'boot-app'; BootstrapThumbprint = 'BB00'; BootstrapAuth = 'Certificate' } | ConvertTo-Json) |
            Set-Content -LiteralPath (Join-Path $script:Root 'bootstrap\platform-config.json') -Encoding UTF8
        Mock Get-SIKeyVaultSecretValue {
            $script:Reads.Add($Name)
            if ($script:Vault.ContainsKey($Name)) { return $script:Vault[$Name] }
            return $null
        }
    }
    AfterEach {
        foreach ($n in $script:GlobalNames) { Set-Variable -Scope Global -Name $n -Value $script:keep[$n] }
        Remove-Item -LiteralPath $script:Root -Recurse -Force -ErrorAction SilentlyContinue
    }

    It 'a valid certificate in the store: signs in by CERTIFICATE and never reads the secret (internal installs have none)' {
        $script:Vault = @{ 'Modern-AppId' = 'modern-app'; 'Modern-Thumbprint' = $script:Valid.Thumbprint }
        $w = $null
        $null = Connect-SIPlatform -ConfigPath (Join-Path $script:Root 'bootstrap\platform-config.json') -WarningVariable w -WarningAction SilentlyContinue
        $global:HighPriv_Modern_AuthMethod | Should -Be 'Cert'
        $global:HighPriv_Modern_CertificateThumbprint_Azure | Should -Be $script:Valid.Thumbprint
        $global:HighPriv_Modern_Secret_Azure | Should -BeNullOrEmpty
        @($script:Reads | Where-Object { $_ -eq 'Modern-Secret' }).Count | Should -Be 0
        ($w -join ' ') | Should -Not -Match 'EXPIRED|client secret'
        (Get-SIAzRestState).Connection.Mode | Should -Be 'Certificate'
    }

    It 'an expired certificate in the store: falls back to the secret, and says why' {
        $script:Vault = @{ 'Modern-AppId' = 'modern-app'; 'Modern-Thumbprint' = $script:Expired.Thumbprint; 'Modern-Secret' = 'm0dern' }
        $w = $null
        $null = Connect-SIPlatform -ConfigPath (Join-Path $script:Root 'bootstrap\platform-config.json') -WarningVariable w -WarningAction SilentlyContinue
        $global:HighPriv_Modern_AuthMethod | Should -Be 'Secret'
        ($w -join ' ') | Should -Match 'EXPIRED'
    }
}
