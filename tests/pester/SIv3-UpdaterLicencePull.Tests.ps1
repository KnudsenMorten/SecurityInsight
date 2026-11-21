#Requires -Version 5.1
<#
    SI_UPDATER_LICENCE_PULL -- SUPPORT ASKS FOR A LICENCE OF AN EDITION THROUGH THE UPDATE (Invardia design 2026-11-20, revised:
    the licence API stays locked, NO licence id is ever sent; nobody writes the licence secret by hand: ruling 2026-11-15).
    container\updater\_shared\SI-UpdaterLicencePull.ps1:
      * request:pro-business / request:pro-enterprise: a licence request of that edition FILED ONCE with the normal knock
        (edition 'pro-business' / 'pro-single-tenant'; no licence id, no proof of possession), then PULLED on this and every
        later update until Invardia delivers -- waiting = a pull only;
      * request:previous: SI-License-Previous restored (no request);
      * THE GUARD: verified offline (a trusted signer AND that signer is CN=Invardia-Licensing or CN=AutomateIT-Licensing-
        Service; THIS tenant; valid today; the EDITION asked for: Business = limits, Enterprise = none);
      * the licence in force kept as SI-License-Previous first; read back; one plain line; audited + cfg.ChangeLog;
      * ONCE PER VALUE: done once the matching licence is installed; a usable SI_UPDATER_CONTROLPLANE_REASON required;
      * NEVER fails the update: a refusal or failure is one warning line and the licence in force stays;
      * WIRING: the updater runs it before the licence request step; the image carries every file it needs.
    OFFLINE: every HTTP call is a fake; licences are signed with THROWAWAY keys minted in memory.
#>

BeforeAll {
    $script:SIRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
    $script:TestBase = 'https://licence-requests.test.invalid'
    . (Join-Path $script:SIRoot 'engine\_shared\SI-LicenceRequest.ps1')
    . (Join-Path $script:SIRoot 'setup\_shared\SI-ControlPlaneValues.ps1')
    . (Join-Path $script:SIRoot 'container\updater\_shared\SI-UpdaterLicence.ps1')
    . (Join-Path $script:SIRoot 'container\updater\_shared\SI-UpdaterLicencePull.ps1')

    $mkCert = { param([string]$Cn, $Rsa)
        $req = New-Object System.Security.Cryptography.X509Certificates.CertificateRequest($Cn, $Rsa, [System.Security.Cryptography.HashAlgorithmName]::SHA256, [System.Security.Cryptography.RSASignaturePadding]::Pkcs1)
        $c = $req.CreateSelfSigned([DateTimeOffset]::UtcNow.AddDays(-1), [DateTimeOffset]::UtcNow.AddYears(1))
        [Convert]::ToBase64String($c.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Cert)) }
    # a throwaway key under the trusted signer's NAME (the real private key never leaves Invardia), one under a foreign name
    $script:Rsa = [System.Security.Cryptography.RSA]::Create(2048)
    $script:TrustedB64 = & $mkCert 'CN=Invardia-Licensing' $script:Rsa
    $script:ForeignRsa = [System.Security.Cryptography.RSA]::Create(2048)
    $script:ForeignB64 = & $mkCert 'CN=Evil-Licensing' $script:ForeignRsa
    $script:OtherRsa = [System.Security.Cryptography.RSA]::Create(2048)      # in no trusted list: a bad signature

    $script:Tenant = '11111111-2222-3333-4444-555555555555'
    $script:OtherTenant = '99999999-8888-7777-6666-555555555555'
    $script:T0 = [datetime]::new(2026, 11, 20, 10, 0, 0, [DateTimeKind]::Utc)
    $script:NewId = '83561abd-5168-4458-8801-129b79a51795'
    $script:OldId = 'aaaaaaaa-0000-0000-0000-000000000001'
    $script:Who = 'Invardia support: prove the Pro Business limits live on the internal install'
    $script:Biz = 'request:pro-business'

    function script:New-LicText {
        param([string]$LicenseId, [string[]]$TenantIds = @($script:Tenant), [int]$FromDays = -1, [int]$ToDays = 60, $Key = $script:Rsa, [switch]$Business)
        $payload = [ordered]@{ licenseId = $LicenseId; customer = 'Test Customer'; sku = 'Pro'; features = @('correlation'); tenantIds = $TenantIds
            validFrom = $script:T0.Date.AddDays($FromDays).ToString('yyyy-MM-dd', [Globalization.CultureInfo]::InvariantCulture)
            validTo = $script:T0.Date.AddDays($ToDays).ToString('yyyy-MM-dd', [Globalization.CultureInfo]::InvariantCulture); graceDays = 30 }
        if ($Business) { $payload['limits'] = [ordered]@{ devices = 250 } }
        $bytes = [Text.Encoding]::UTF8.GetBytes(($payload | ConvertTo-Json -Compress))
        $sig = $Key.SignData($bytes, [System.Security.Cryptography.HashAlgorithmName]::SHA256, [System.Security.Cryptography.RSASignaturePadding]::Pkcs1)
        [ordered]@{ product = 'SecurityInsight'; payloadB64 = [Convert]::ToBase64String($bytes); signature = [Convert]::ToBase64String($sig) } | ConvertTo-Json -Compress
    }
    # the install: an Enterprise licence in force (no limits), its install id and install key; Invardia: a fake
    function script:New-World {
        param([string]$Delivered, [string]$PullStatus = 'Approved')
        @{ Secrets = @{ 'SI-License' = (New-LicText -LicenseId $script:OldId -ToDays 300); 'SI-InstallId' = 'bbbbbbbb-0000-0000-0000-000000000002'; 'SI-Invardia-InstallKey' = 'inv-installkey-123456' }
           Knocks = (New-Object System.Collections.Generic.List[object]); Pulls = (New-Object System.Collections.Generic.List[object]); Installs = 0; State = @{}
           Audit = (New-Object System.Collections.Generic.List[object]); ChangeLog = (New-Object System.Collections.Generic.List[object])
           Delivered = $Delivered; PullStatus = $PullStatus; KnockStatus = 202; PullCode = 200; InstallThrows = $false; N = 0 }
    }
    function script:New-Seams($W) {
        @{
            Http = { param($u, $b, $t, $k, $i)
                if ($u -like '*/api/licence-requests/pull') {
                    $W.Pulls.Add([pscustomobject]@{ Uri = $u; Body = $b; Token = $t })
                    if ($W.PullCode -ne 200) { return [pscustomobject]@{ Status = $W.PullCode; Body = '{"error":"token"}'; RetryAfter = 0; Error = "HTTP $($W.PullCode)" } }
                    $o = @{ requestId = 'req-1'; status = $W.PullStatus }
                    if ($W.PullStatus -eq 'Rejected') { $o.reason = 'not for this tenant' }
                    if ($W.PullStatus -eq 'Approved' -and $W.Delivered) {
                        $bb = [Text.Encoding]::UTF8.GetBytes($W.Delivered)
                        $h = [System.Security.Cryptography.SHA256]::Create(); $sha = ([BitConverter]::ToString($h.ComputeHash($bb)) -replace '-', '').ToLowerInvariant(); $h.Dispose()
                        $o.licence = @{ fileName = 'si.silicense'; sha256 = $sha; contentBase64 = [Convert]::ToBase64String($bb) } }
                    return [pscustomobject]@{ Status = 200; Body = ($o | ConvertTo-Json -Compress -Depth 5); RetryAfter = 0; Error = '' }
                }
                $W.Knocks.Add([pscustomobject]@{ Uri = $u; Body = $b; Token = $t; Key = $k; Iid = $i })
                if ($W.KnockStatus -eq 0) { return [pscustomobject]@{ Status = 0; Body = ''; RetryAfter = 0; Error = 'The remote name could not be resolved' } }
                $W.N++
                [pscustomobject]@{ Status = $W.KnockStatus; Body = (@{ requestId = 'req-1'; pullToken = ('lr-PULLTOKEN-{0}' -f $W.N); status = 'Pending'; pollAfterSeconds = 1800 } | ConvertTo-Json -Compress); RetryAfter = 0; Error = '' }
            }.GetNewClosure()
            ReadSecret = { param($n) $W.Secrets[$n] }.GetNewClosure()
            WriteSecret = { param($n, $v) $W.Secrets[$n] = $v }.GetNewClosure()
            TenantId = { $script:Tenant }
            Install = { param($text, $tid) if ($W.InstallThrows) { throw 'the vault refused the write' }; $W.Installs++; $W.Secrets['SI-License'] = $text; [pscustomobject]@{ Ok = $true; Message = 'installed' } }.GetNewClosure()
            Now = { $script:T0 }
        }
    }
    function script:New-Store($W) {
        $inv = { param([string]$sql, $p, [string]$mode)
            if ($sql -match 'SELECT Value FROM cfg\.InstallState') { if ($W.State.ContainsKey($p.Name)) { return , @(@{ Value = $W.State[$p.Name] }) }; return , @() }
            if ($sql -match 'MERGE cfg\.InstallState') { $W.State[$p.Name] = $p.Value; return }
            if ($sql -match 'INSERT cfg\.AuditEvent') { $W.Audit.Add([pscustomobject]@{ Action = [string]$p.Action; Outcome = [string]$p.Outcome; Reason = [string]$p.Reason; Text = [string]$p.OutcomeText }); return 'Saved' }
            if ($sql -match 'INSERT cfg\.ChangeLog') { $W.ChangeLog.Add([pscustomobject]@{ Old = $p.Old; New = $p.New; By = $p.By; Reason = $p.Reason }); return }
            throw ('the fake store does not know this statement: ' + $sql) }.GetNewClosure()
        [pscustomobject]@{ Invoke = $inv }
    }
    function script:Run($W, [string]$Value = $script:Biz, [string]$Reason = $script:Who, [string[]]$Certs = @($script:TrustedB64), [bool]$Connected = $true, $Switch) {
        $envh = @{ SI_UPDATER_LICENCE_PULL = $Value; SI_UPDATER_CONTROLPLANE_REASON = $Reason; SI_LICENSE_REQUEST_BASE_URL = $script:TestBase }
        Invoke-SIUpdaterLicencePull -Env $envh -Store (New-Store $W) -SIRoot $script:SIRoot -Seams (New-Seams $W) -TrustedCertsB64 $Certs -Connected $Connected -Switch $Switch -Log { param($m) }
    }
    function script:Warnings($r) { @($r.Lines | Where-Object { $_ -like 'WARNING:*' }) }
    function script:InForce($W) { (Get-SILicense -SecretText $W.Secrets['SI-License'] -TrustedCertsB64 @($script:TrustedB64) -Now $script:T0).LicenseId }
}

Describe 'the value names an EDITION; the licence-id form is gone' {
    It '<_> is understood' -ForEach @('request:pro-business', 'REQUEST:Pro-Enterprise', 'request:previous') {
        (ConvertFrom-SIUpdaterLicencePullValue $_).Kind | Should -BeIn @('request', 'restore')
    }
    It 'the edition on the knock: pro-business / pro-single-tenant (Invardia''s Pro Enterprise)' {
        (ConvertFrom-SIUpdaterLicencePullValue 'request:pro-business').Edition | Should -Be 'pro-business'
        (ConvertFrom-SIUpdaterLicencePullValue 'request:pro-enterprise').Edition | Should -Be 'pro-single-tenant'
    }
    It 'a licence id, plain "previous" or anything else is refused in one line, nothing asked (<_>)' -ForEach @('83561abd-5168-4458-8801-129b79a51795', 'previous', 'request:pro-msp') {
        $W = New-World
        $r = Run $W -Value $_
        $r.Action | Should -Be 'refused'; @($r.Lines) | Should -HaveCount 1
        $r.Lines[0] | Should -Match 'is not request:pro-business, request:pro-enterprise or request:previous'
        $W.Knocks.Count + $W.Pulls.Count | Should -Be 0
    }
}

Describe 'the request is filed ONCE with the normal knock; then each update only pulls until Invardia delivers' {
    It 'filed once (edition, no licence id, no proof); waiting = a pull only; approved = installed; then nothing' {
        $W = New-World -PullStatus 'Pending'
        $r1 = Run $W
        $r1.Action | Should -Be 'requested'
        $W.Knocks.Count | Should -Be 1; $W.Pulls.Count | Should -Be 1
        $r1.Lines[0] | Should -Match '^licence pull: a licence request for Pro Business filed with Invardia \(request req-1'
        $r1.Lines[1] | Should -Match 'request req-1 for Pro Business is waiting for Invardia''s approval'
        $W.Audit[0].Action | Should -Be 'licence.request.send'
        $W.State.ContainsKey('ControlPlaneLicencePull') | Should -BeFalse
        # a second and third update while it waits: no knock, one pull each, with the request's own token
        $r2 = Run $W; $null = Run $W
        $r2.Action | Should -Be 'waiting'
        $W.Knocks.Count | Should -Be 1; $W.Pulls.Count | Should -Be 3
        @($W.Pulls | ForEach-Object Token | Select-Object -Unique) | Should -Be @('lr-PULLTOKEN-1')
        InForce $W | Should -Be $script:OldId
        # the owner approves it with that edition
        $W.PullStatus = 'Approved'; $W.Delivered = New-LicText -LicenseId $script:NewId -Business
        $r4 = Run $W
        $r4.Action | Should -Be 'installed'
        $W.Knocks.Count | Should -Be 1
        InForce $W | Should -Be $script:NewId
        $W.State['ControlPlaneLicencePull'] | Should -Be 'request:pro-business'
        $W.Secrets['SI-LicencePull-PullToken'] | Should -Be '-'
        # done: the same value again asks nothing
        $r5 = Run $W
        $r5.Action | Should -Be 'already'; $W.Knocks.Count | Should -Be 1; $W.Pulls.Count | Should -Be 4
    }
    It 'NO licence id is ever sent: the knock is exactly product, version, tenant, install id and the edition -- no install key, no current licence, no hash' {
        $W = New-World -PullStatus 'Pending'
        $null = Run $W
        $k = $W.Knocks[0]
        $k.Uri | Should -Be "$($script:TestBase)/api/licence-requests"
        @(($k.Body | ConvertFrom-Json).PSObject.Properties.Name) | Should -Be @('product', 'version', 'tenantId', 'installId', 'edition')
        ($k.Body | ConvertFrom-Json).edition | Should -Be 'pro-business'
        ($k.Body | ConvertFrom-Json).tenantId | Should -Be $script:Tenant
        $k.Body | Should -Not -Match ([regex]::Escape($script:OldId))
        $k.Key | Should -BeNullOrEmpty
        $k.Iid | Should -Be 'bbbbbbbb-0000-0000-0000-000000000002'
        $W.Pulls[0].Uri | Should -Be "$($script:TestBase)/api/licence-requests/pull"; $W.Pulls[0].Body | Should -Be '{}'
        $W.Secrets['SI-LicencePull-PullToken'] | Should -Be 'lr-PULLTOKEN-1'
    }
    It 'Invardia no longer knows the request (401): one warning, the next update files a new one' {
        $W = New-World -PullStatus 'Pending'
        $null = Run $W
        $W.PullCode = 401
        $r = Run $W
        $r.Action | Should -Be 'failed'; @(Warnings $r) | Should -HaveCount 1
        $W.PullCode = 200
        $null = Run $W
        $W.Knocks.Count | Should -Be 2
    }
    It 'rejected: one warning, the licence in force stays, not done' {
        $W = New-World -PullStatus 'Rejected'
        $r = Run $W
        $r.Action | Should -Be 'refused'
        @(Warnings $r)[0] | Should -Match 'Invardia REJECTED request req-1: not for this tenant'
        InForce $W | Should -Be $script:OldId
        $W.State.ContainsKey('ControlPlaneLicencePull') | Should -BeFalse
    }
}

Describe 'EDITION: only a licence of the edition asked for is installed' {
    It 'request:pro-business + a Business licence (limits): installed, the one before kept as SI-License-Previous, one plain line, audited' {
        $W = New-World -Delivered (New-LicText -LicenseId $script:NewId -Business)
        $r = Run $W
        $r.Action | Should -Be 'installed'
        InForce $W | Should -Be $script:NewId
        (Get-SILicense -SecretText $W.Secrets['SI-License-Previous'] -TrustedCertsB64 @($script:TrustedB64) -Now $script:T0).LicenseId | Should -Be $script:OldId
        @($r.Lines | Where-Object { $_ -match '^licence pull: licence ' }) | Should -HaveCount 1
        $r.Lines[-1] | Should -Match ('^licence pull: licence {0} installed -- Pro Business, valid to 2027-01-19 .*the licence before it kept as SI-License-Previous' -f [regex]::Escape($script:NewId))
        @($W.Audit | ForEach-Object Action) | Should -Be @('licence.request.send', 'licence.request.install')
        $W.Audit[1].Reason | Should -Be $script:Who
        $W.ChangeLog[0].Old | Should -Be $script:OldId; $W.ChangeLog[0].New | Should -Be $script:NewId
    }
    It 'request:pro-business + an Enterprise licence (no limits): refused, the licence in force stays, the next update pulls again' {
        $W = New-World -Delivered (New-LicText -LicenseId $script:NewId)
        $r = Run $W
        $r.Action | Should -Be 'refused'; @(Warnings $r) | Should -HaveCount 1
        @(Warnings $r)[0] | Should -Match 'the licence is Pro Enterprise, not the Pro Business asked for'
        InForce $W | Should -Be $script:OldId
        $W.Secrets.ContainsKey('SI-License-Previous') | Should -BeFalse
        $W.Installs | Should -Be 0
        $W.State.ContainsKey('ControlPlaneLicencePull') | Should -BeFalse
        $null = Run $W
        $W.Knocks.Count | Should -Be 1; $W.Pulls.Count | Should -Be 2
    }
    It 'request:pro-enterprise: the knock asks pro-single-tenant; an Enterprise licence is installed, a Business one refused' {
        $W = New-World -Delivered (New-LicText -LicenseId $script:NewId -Business)
        $W.Secrets['SI-License'] = New-LicText -LicenseId $script:OldId -ToDays 300 -Business
        $r = Run $W -Value 'request:pro-enterprise'
        ($W.Knocks[0].Body | ConvertFrom-Json).edition | Should -Be 'pro-single-tenant'
        $r.Action | Should -Be 'refused'; @(Warnings $r)[0] | Should -Match 'the licence is Pro Business, not the Pro Enterprise asked for'
        $W.Delivered = New-LicText -LicenseId $script:NewId
        $r2 = Run $W -Value 'request:pro-enterprise'
        $r2.Action | Should -Be 'installed'; $r2.Lines[-1] | Should -Match 'installed -- Pro Enterprise, valid to'
    }
    It 'the licence in force is of that edition already: nothing asked, done' {
        $W = New-World
        $r = Run $W -Value 'request:pro-enterprise'
        $r.Action | Should -Be 'already'; $W.Knocks.Count + $W.Pulls.Count | Should -Be 0
        $W.State['ControlPlaneLicencePull'] | Should -Be 'request:pro-enterprise'
    }
}

Describe 'THE GUARD: not this install''s, not trusted or not valid today = refused, the licence in force stays' {
    It 'wrong tenant: refused in one warning line; nothing written, not done' {
        $W = New-World -Delivered (New-LicText -LicenseId $script:NewId -Business -TenantIds @($script:OtherTenant))
        $r = Run $W
        $r.Action | Should -Be 'refused'; @(Warnings $r) | Should -HaveCount 1
        @(Warnings $r)[0] | Should -Match 'not for this tenant'
        InForce $W | Should -Be $script:OldId
        $W.Installs | Should -Be 0
        $W.Audit[-1].Action | Should -Be 'licence.request.fail'
    }
    It 'foreign signer: a signature that verifies against a certificate NOT named CN=Invardia-Licensing / CN=AutomateIT-Licensing-Service is refused' {
        $W = New-World -Delivered (New-LicText -LicenseId $script:NewId -Business -Key $script:ForeignRsa)
        $r = Run $W -Certs @($script:TrustedB64, $script:ForeignB64)
        $r.Action | Should -Be 'refused'
        @(Warnings $r)[0] | Should -Match 'signed by CN=Evil-Licensing, not by CN=Invardia-Licensing or CN=AutomateIT-Licensing-Service'
        $W.Installs | Should -Be 0
    }
    It 'bad signature (a key no trusted signer holds): refused' {
        $W = New-World -Delivered (New-LicText -LicenseId $script:NewId -Business -Key $script:OtherRsa)
        $r = Run $W
        $r.Action | Should -Be 'refused'; @(Warnings $r)[0] | Should -Match 'does not verify'
        $W.Installs | Should -Be 0
    }
    It 'expired: refused' {
        $W = New-World -Delivered (New-LicText -LicenseId $script:NewId -Business -FromDays -400 -ToDays -40)
        $r = Run $W
        $r.Action | Should -Be 'refused'; @(Warnings $r)[0] | Should -Match 'not valid today'
        $W.Installs | Should -Be 0
    }
    It 'the trusted signers in production are exactly the framework verifier''s two (never configuration)' {
        $certs = @(Get-SIUpdaterLicencePullTrustedCerts -SIRoot $script:SIRoot)
        $certs | Should -HaveCount 2
        @($certs | ForEach-Object { (New-Object System.Security.Cryptography.X509Certificates.X509Certificate2(, [Convert]::FromBase64String($_))).Subject }) | Should -Be @('CN=AutomateIT-Licensing-Service', 'CN=Invardia-Licensing')
        $W = New-World -Delivered (New-LicText -LicenseId $script:NewId -Business)
        $envh = @{ SI_UPDATER_LICENCE_PULL = $script:Biz; SI_UPDATER_CONTROLPLANE_REASON = $script:Who; SI_LICENSE_REQUEST_BASE_URL = $script:TestBase }
        $r = Invoke-SIUpdaterLicencePull -Env $envh -Store (New-Store $W) -SIRoot $script:SIRoot -Seams (New-Seams $W) -Log { param($m) }
        $r.Action | Should -Be 'refused'; $W.Installs | Should -Be 0
    }
}

Describe 'RESTORE: request:previous installs SI-License-Previous again (no request), verified the same way' {
    It 'restored, read back, one line, once per value; no call to Invardia' {
        $W = New-World
        $W.Secrets['SI-License-Previous'] = New-LicText -LicenseId $script:NewId -Business
        $r = Run $W -Value 'request:previous'
        $r.Action | Should -Be 'restored'
        InForce $W | Should -Be $script:NewId
        $r.Lines[0] | Should -Match ('^licence pull: licence {0} restored from SI-License-Previous -- Pro Business' -f [regex]::Escape($script:NewId))
        $W.Knocks.Count + $W.Pulls.Count | Should -Be 0
        $W.State['ControlPlaneLicencePull'] | Should -Be 'request:previous'
        (Run $W -Value 'request:previous').Action | Should -Be 'already'
    }
    It 'a request then request:previous: back to the licence before' {
        $W = New-World -Delivered (New-LicText -LicenseId $script:NewId -Business)
        (Run $W).Action | Should -Be 'installed'
        (Run $W -Value 'request:previous').Action | Should -Be 'restored'
        InForce $W | Should -Be $script:OldId
    }
    It 'wrong tenant on the way back: refused' {
        $W = New-World
        $W.Secrets['SI-License-Previous'] = New-LicText -LicenseId $script:NewId -TenantIds @($script:OtherTenant)
        $r = Run $W -Value 'request:previous'
        $r.Action | Should -Be 'refused'; $r.Lines[0] | Should -Match 'not for this tenant'
        InForce $W | Should -Be $script:OldId
    }
    It 'foreign signer on the way back: refused' {
        $W = New-World
        $W.Secrets['SI-License-Previous'] = New-LicText -LicenseId $script:NewId -Key $script:ForeignRsa
        $r = Run $W -Value 'request:previous' -Certs @($script:TrustedB64, $script:ForeignB64)
        $r.Action | Should -Be 'refused'; $r.Lines[0] | Should -Match 'signed by CN=Evil-Licensing'
        InForce $W | Should -Be $script:OldId
    }
    It 'nothing kept to restore: refused' {
        (Run (New-World) -Value 'request:previous').Lines[0] | Should -Match 'there is no SI-License-Previous'
    }
}

Describe 'who asked; never a failed update' {
    It 'no usable reason (<_>): refused in ONE warning line, nothing asked, not recorded' -ForEach @('', 'update', 'x') {
        $W = New-World -Delivered (New-LicText -LicenseId $script:NewId -Business)
        $r = Run $W -Reason $_
        $r.Action | Should -Be 'refused'
        @($r.Lines) | Should -HaveCount 1
        $r.Lines[0] | Should -Match '^WARNING: licence pull: SI_UPDATER_LICENCE_PULL=request:pro-business -- it needs SI_UPDATER_CONTROLPLANE_REASON'
        $W.Knocks.Count + $W.Pulls.Count | Should -Be 0
        $W.State.Count | Should -Be 0
    }
    It 'a failure leaves the licence in force: the install fails / Invardia away -- one warning, never a throw, tried again' {
        $W = New-World -Delivered (New-LicText -LicenseId $script:NewId -Business); $W.InstallThrows = $true
        $r = Run $W
        $r.Action | Should -Be 'failed'; @(Warnings $r) | Should -HaveCount 1
        InForce $W | Should -Be $script:OldId
        $W.State.ContainsKey('ControlPlaneLicencePull') | Should -BeFalse
        $W2 = New-World; $W2.KnockStatus = 0
        $r2 = Run $W2
        $r2.Action | Should -Be 'failed'; $r2.Lines[0] | Should -Match 'could not be reached'
        $W2.KnockStatus = 202
        $null = Run $W2
        $W2.Knocks.Count | Should -Be 2 -Because 'a request that was never filed is filed on the next update'
    }
    It 'a store that throws: one warning line, never a throw' {
        $W = New-World -Delivered (New-LicText -LicenseId $script:NewId -Business)
        $envh = @{ SI_UPDATER_LICENCE_PULL = $script:Biz; SI_UPDATER_CONTROLPLANE_REASON = $script:Who }
        $r = Invoke-SIUpdaterLicencePull -Env $envh -Store ([pscustomobject]@{ Invoke = { param($s, $p, $m) throw 'the database is away' } }) -SIRoot $script:SIRoot -Seams (New-Seams $W) -TrustedCertsB64 @($script:TrustedB64) -Log { param($m) }
        $r.Action | Should -Be 'failed'; @(Warnings $r) | Should -HaveCount 1
        InForce $W | Should -Be $script:OldId
    }
    It 'not connected to Invardia, or licence requests switched off: nothing asked (a restore still works)' {
        $W = New-World -Delivered (New-LicText -LicenseId $script:NewId -Business)
        (Run $W -Connected $false).Lines[0] | Should -Match 'not connected to Invardia'
        (Run $W -Switch ([pscustomobject]@{ On = $false; Text = 'off' })).Lines[0] | Should -Match 'switched off'
        $W.Knocks.Count + $W.Pulls.Count | Should -Be 0
        $W.Secrets['SI-License-Previous'] = New-LicText -LicenseId $script:NewId
        (Run $W -Value 'request:previous' -Connected $false).Action | Should -Be 'restored'
    }
    It 'the env absent: nothing at all' {
        $W = New-World
        $r = Run $W -Value ''
        $r.Action | Should -Be 'none'; @($r.Lines) | Should -HaveCount 0; $W.Knocks.Count | Should -Be 0
    }
}

Describe 'WIRING: the updater runs it before the licence request step; the image carries what it needs' {
    BeforeAll { $script:Upd = [IO.File]::ReadAllText((Join-Path $script:SIRoot 'container\updater\Start-SIUpdater.ps1')) }
    It 'Start-SIUpdater loads the file and calls the step before Invoke-SIUpdaterLicenceRequest, with the store, connection and switch -- never a test signer' {
        $script:Upd | Should -Match ([regex]::Escape(". (Join-Path `$PSScriptRoot '_shared/SI-UpdaterLicencePull.ps1')"))
        $call = $script:Upd.IndexOf('$null = Invoke-SIUpdaterLicencePull -Env $Env -Store $proStore')
        $call | Should -BeGreaterThan 0
        $call | Should -BeLessThan $script:Upd.IndexOf('$lr = Invoke-SIUpdaterLicenceRequest -Env $Env')
        $line = $script:Upd.Substring($call, 300)
        $line | Should -Match '-Connected \$licenceAsk'
        $line | Should -Match "SI_LicenseRequest_Auto"
        $line | Should -Not -Match 'TrustedCertsB64|-Seams'
    }
    It 'the updater image carries the step, the licence client, the verifier and the control-plane helpers' {
        $df = [IO.File]::ReadAllText((Join-Path $script:SIRoot 'container\updater\Dockerfile'))
        foreach ($c in 'COPY container/updater/_shared/ ./_shared/', 'COPY engine/_shared/ /si/engine/_shared/', 'COPY setup/ /si/setup/', 'COPY engine/SI-FeatureCatalog.ps1 /si/engine/', 'COPY VERSION /si/') {
            $df | Should -Match ([regex]::Escape($c))
        }
        foreach ($f in 'container\updater\_shared\SI-UpdaterLicencePull.ps1', 'engine\_shared\SI-LicenceRequest.ps1', 'engine\_shared\AitLicense.ps1', 'setup\_shared\SI-ControlPlaneValues.ps1') {
            Test-Path -LiteralPath (Join-Path $script:SIRoot $f) | Should -BeTrue -Because $f
        }
    }
    It 'the audit actions used are on the closed list' {
        $acts = @(([IO.File]::ReadAllText((Join-Path $script:SIRoot 'config\audit-actions.locked.json')) | ConvertFrom-Json).actions | ForEach-Object { $_.action })
        foreach ($a in 'licence.request.send', 'licence.request.install', 'licence.request.fail') { $acts | Should -Contain $a }
    }
}
