#Requires -Version 5.1
<#
    THE INSTALL REQUESTS AND RENEWS ITS OWN LICENCE (#239) -- the PRODUCT CONTRACT with Invardia's licence requests.

    Pins the client (engine/_shared/SI-LicenceRequest.ps1) to the contract Invardia publishes (licence requests, owner GO
    2026-10-03, with the clarifications of 2026-10-04): the knock's JSON shape and field names, the tenant taken from the
    identity TOKEN and never from config, when to knock (none / <= 30 days / > 30 days), pollAfterSeconds, token rotation,
    the pull header and its "{}" JSON body, offline verification BEFORE Set-SILicense, every refusal, Rejected, 401, 422,
    429, other 4xx, network failures, and that the pull token never reaches any output.

    🔒 OFFLINE ONLY. Every HTTP call is a fake; the base URL is a test host (https://licence-requests.test.invalid) set
    explicitly AND in the environment, and the last Describe asserts that nothing here ever reached invardia.com -- every
    new request there emails the owner. Licences are signed with a THROWAWAY key minted in memory for this run.
#>

BeforeAll {
    $script:SIRoot   = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
    $script:RepoRoot = Split-Path -Parent (Split-Path -Parent $script:SIRoot)
    $script:TestBase = 'https://licence-requests.test.invalid'
    $script:PrevEnvBase = $env:SI_LICENSE_REQUEST_BASE_URL
    $env:SI_LICENSE_REQUEST_BASE_URL = $script:TestBase          # backstop: even a default seam would go to the test host
    . (Join-Path $script:SIRoot 'engine\_shared\SI-LicenceRequest.ps1')
    . (Join-Path $script:SIRoot 'container\updater\_shared\SI-UpdaterLicence.ps1')

    # Every real HTTP cmdlet call made by this file is recorded; anything not aimed at the test host fails loudly.
    $script:RealHttp = New-Object System.Collections.Generic.List[string]

    # Throwaway signer, in memory only.
    $script:Rsa = [System.Security.Cryptography.RSA]::Create(2048)
    $req = New-Object System.Security.Cryptography.X509Certificates.CertificateRequest('CN=SI-Test-Licensing', $script:Rsa,
        [System.Security.Cryptography.HashAlgorithmName]::SHA256, [System.Security.Cryptography.RSASignaturePadding]::Pkcs1)
    $cert = $req.CreateSelfSigned([DateTimeOffset]::UtcNow.AddDays(-1), [DateTimeOffset]::UtcNow.AddYears(1))
    $script:TestCertB64 = [Convert]::ToBase64String($cert.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Cert))
    $script:OtherRsa = [System.Security.Cryptography.RSA]::Create(2048)

    $script:Tenant      = '11111111-2222-3333-4444-555555555555'   # the tenant in the identity TOKEN
    $script:ConfigTenant = '99999999-8888-7777-6666-555555555555'  # what a (copied / edited) config claims
    $script:T0 = [datetime]::new(2026, 10, 4, 10, 0, 0, [DateTimeKind]::Utc)

    function script:New-TestJwt([string]$Tid) {
        $enc = { param($o) [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes(($o | ConvertTo-Json -Compress))).TrimEnd('=').Replace('+', '-').Replace('/', '_') }
        '{0}.{1}.sig' -f (& $enc @{ alg = 'RS256'; typ = 'JWT' }), (& $enc @{ tid = $Tid; aud = 'https://management.azure.com/' })
    }
    function script:New-LicText {
        param([string[]]$TenantIds = @($script:Tenant), [int]$FromDays = -1, [int]$ToDays = 365, [string]$Product = 'SecurityInsight',
              [string[]]$Features = @('correlation', 'servicenow-connector'), [switch]$OtherSigner, [string]$LicenseId = ([guid]::NewGuid().ToString()), [string]$Sku = 'Pro')
        $payload = [ordered]@{
            licenseId = $LicenseId; customer = 'Test Customer'; sku = $Sku; features = $Features; tenantIds = $TenantIds
            validFrom = $script:T0.Date.AddDays($FromDays).ToString('yyyy-MM-dd', [Globalization.CultureInfo]::InvariantCulture)
            validTo   = $script:T0.Date.AddDays($ToDays).ToString('yyyy-MM-dd', [Globalization.CultureInfo]::InvariantCulture)
            graceDays = 30
        } | ConvertTo-Json -Compress
        $bytes = [Text.Encoding]::UTF8.GetBytes($payload)
        $key = if ($OtherSigner) { $script:OtherRsa } else { $script:Rsa }
        $sig = $key.SignData($bytes, [System.Security.Cryptography.HashAlgorithmName]::SHA256, [System.Security.Cryptography.RSASignaturePadding]::Pkcs1)
        [ordered]@{ product = $Product; payloadB64 = [Convert]::ToBase64String($bytes); signature = [Convert]::ToBase64String($sig) } | ConvertTo-Json -Compress
    }
    function script:New-LicFile([string]$Text, [string]$Sha) {
        $b = [Text.Encoding]::UTF8.GetBytes($Text)
        [pscustomobject]@{ fileName = 'securityinsight.silicense'; sha256 = $(if ($Sha) { $Sha } else { Get-SILicenceRequestSha256 -Bytes $b }); contentBase64 = [Convert]::ToBase64String($b) }
    }
    function script:Ok([int]$Status, $Obj, [int]$RetryAfter = 0) {
        [pscustomobject]@{ Status = $Status; Body = $(if ($null -eq $Obj) { '' } elseif ($Obj -is [string]) { $Obj } else { $Obj | ConvertTo-Json -Compress -Depth 6 }); RetryAfter = $RetryAfter; Error = $(if ($Status -eq 0) { 'The remote name could not be resolved' } else { '' }) }
    }

    # ---- the world: a fake Key Vault, a fake Invardia, a clock ----
    function script:Reset-World {
        $script:Secrets = @{}
        $script:Calls = New-Object System.Collections.Generic.List[object]
        $script:Installed = New-Object System.Collections.Generic.List[object]
        $script:LogLines = New-Object System.Collections.Generic.List[string]
        $script:Clock = $script:T0
        $script:TokenN = 0
        $script:TokenTid = $script:Tenant
        $script:Pull = { Ok 200 @{ status = 'Pending' } }
        $script:Knock = { $script:TokenN++; Ok 202 @{ requestId = 'req-1'; pullToken = ('PULLTOKEN-SECRET-{0}' -f $script:TokenN); status = 'Pending'; pollAfterSeconds = 1800 } }
    }
    function script:New-Seams {
        @{
            Http        = { param($u, $b, $t, $k)
                            $script:Calls.Add([pscustomobject]@{ Uri = $u; Body = $b; Token = $t; Key = $k; At = $script:Clock })
                            if ($u -like '*/api/licence-requests/pull') { & $script:Pull $b $t } elseif ($u -like '*/api/licence-requests') { & $script:Knock $b } else { throw "unexpected uri $u" } }
            ReadSecret  = { param($n) $script:Secrets[$n] }
            WriteSecret = { param($n, $v) $script:Secrets[$n] = $v }
            TenantId    = { Get-SILicenceRequestTenantFromToken -AccessToken (New-TestJwt $script:TokenTid) }
            Install     = { param($text, $tid) $script:Installed.Add([pscustomobject]@{ Text = $text; Tenant = $tid }); $script:Secrets['SI-License'] = $text; [pscustomobject]@{ Ok = $true; Message = 'installed' } }
            Now         = { $script:Clock }
            Log         = { param($l, $t) $script:LogLines.Add("$l $t") }
        }
    }
    function script:Run([switch]$Force, [string]$Contact, [string]$Edition) {
        Invoke-SILicenceRequest -Seams (New-Seams) -Version '3.0.1' -BaseUrl $script:TestBase -TrustedCertsB64 @($script:TestCertB64) -Force:$Force -ContactEmail $Contact -Edition $Edition
    }
    function script:Knocks { @($script:Calls | Where-Object { $_.Uri -like '*/api/licence-requests' }) }
    function script:Pulls  { @($script:Calls | Where-Object { $_.Uri -like '*/api/licence-requests/pull' }) }
    function script:State  { ConvertFrom-SILicenceRequestState -Json $script:Secrets['SI-LicenceRequest-State'] }
}
AfterAll {
    $env:SI_LICENSE_REQUEST_BASE_URL = $script:PrevEnvBase
    foreach ($n in 'SI_SPN_TenantId', 'AzureTenantId', 'TenantId') { Remove-Variable -Name $n -Scope Global -ErrorAction SilentlyContinue }
}

Describe 'the knock: JSON shape and field names' {
    BeforeEach { Reset-World }
    It 'a first knock sends exactly product, version, tenantId, installId -- in that order -- and nothing optional that is not set' {
        $r = Run
        $r.Action | Should -Be 'knocked'
        @(Knocks).Count | Should -Be 1
        $k = (Knocks)[0]
        $k.Uri | Should -Be "$($script:TestBase)/api/licence-requests"
        $k.Token | Should -BeNullOrEmpty
        $o = $k.Body | ConvertFrom-Json
        @($o.PSObject.Properties.Name) -join ',' | Should -Be 'product,version,tenantId,installId'
        $o.product | Should -BeExactly 'securityinsight'
        $o.version | Should -Be '3.0.1'
        $o.tenantId | Should -Be $script:Tenant
        $o.installId | Should -Match '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
    }
    It 'a renewal also sends edition, contactEmail (only when configured), currentLicenceId and currentValidTo as yyyy-MM-dd' {
        $script:Secrets['SI-License'] = New-LicText -ToDays 20 -LicenseId 'lic-current-1'
        $null = Run -Contact 'secops@contoso.test' -Edition 'pro'
        $o = (Knocks)[0].Body | ConvertFrom-Json
        @($o.PSObject.Properties.Name) -join ',' | Should -Be 'product,version,tenantId,installId,edition,contactEmail,currentLicenceId,currentLicenceSha256,currentValidTo'
        $o.contactEmail | Should -Be 'secops@contoso.test'
        $o.edition | Should -Be 'pro'
        $o.currentLicenceId | Should -Be 'lic-current-1'
        $o.currentValidTo | Should -BeExactly ($script:T0.Date.AddDays(20).ToString('yyyy-MM-dd', [Globalization.CultureInfo]::InvariantCulture))
    }
    It 'a renewal proves it holds the licence: currentLicenceSha256 = SHA-256 of the licence as kept (UTF-8, no BOM, trimmed), and the install key in the header when there is one' {
        $lic = New-LicText -ToDays 20 -LicenseId 'lic-current-1'
        $script:Secrets['SI-License'] = $lic
        $script:Secrets['SI-Invardia-InstallKey'] = 'inv-TESTKEY-0123456789'
        $null = Run
        $k = (Knocks)[0]
        $sha = Get-SILicenceRequestSha256 -Bytes ([System.Text.Encoding]::UTF8.GetBytes($lic.TrimStart([char]0xFEFF).Trim()))
        ($k.Body | ConvertFrom-Json).currentLicenceSha256 | Should -BeExactly $sha
        $k.Key | Should -BeExactly 'inv-TESTKEY-0123456789'
        $k.Body | Should -Not -Match 'inv-TESTKEY' -Because 'the install key travels in the header only'
        # a malformed key is not sent; no licence = no hash
        Reset-World; $script:Secrets['SI-Invardia-InstallKey'] = 'not-a-key'
        $null = Run
        (Knocks)[0].Key | Should -BeNullOrEmpty
        ((Knocks)[0].Body | ConvertFrom-Json).PSObject.Properties.Name | Should -Not -Contain 'currentLicenceSha256'
    }
    It 'contactEmail is never sent when it is not configured -- renewals included' {
        $script:Secrets['SI-License'] = New-LicText -ToDays 10
        $null = Run
        ((Knocks)[0].Body | ConvertFrom-Json).PSObject.Properties.Name | Should -Not -Contain 'contactEmail'
    }
    It 'the installId is created once, kept in Key Vault next to the licence (SI-InstallId), and reused' {
        $null = Run
        $id = $script:Secrets['SI-InstallId']
        $id | Should -Match '^[0-9a-f-]{36}$'
        $script:Calls.Clear(); $script:Secrets['SI-LicenceRequest-PullToken'] = '-'; $script:Secrets['SI-LicenceRequest-State'] = $null
        $null = Run
        ((Knocks)[0].Body | ConvertFrom-Json).installId | Should -Be $id
    }
}

Describe 'the tenant comes from the identity TOKEN, never from config' {
    BeforeEach { Reset-World; $global:SI_SPN_TenantId = $script:ConfigTenant; $global:AzureTenantId = $script:ConfigTenant; $global:TenantId = $script:ConfigTenant }
    AfterEach { foreach ($n in 'SI_SPN_TenantId', 'AzureTenantId', 'TenantId') { Remove-Variable -Name $n -Scope Global -ErrorAction SilentlyContinue } }
    It 'the tenant sent is the token''s tid, whatever the config says' {
        $null = Run
        ((Knocks)[0].Body | ConvertFrom-Json).tenantId | Should -Be $script:Tenant
        (Knocks)[0].Body | Should -Not -Match $script:ConfigTenant
    }
    It 'an unproven tenant (no token, or a token without a tid) sends NOTHING' {
        $script:TokenTid = ''
        $r = Run
        $r.Action | Should -Be 'refused'
        $r.Message | Should -Match 'could not be proven'
        $script:Calls.Count | Should -Be 0
    }
    It 'the client reads no configured tenant at all' {
        $code = ((Get-Content -LiteralPath (Join-Path $script:SIRoot 'engine\_shared\SI-LicenceRequest.ps1')) | Where-Object { $_ -notmatch '^\s*#' }) -join "`n"
        $code | Should -Not -Match 'SI_SPN_TenantId|AzureTenantId|\$global:TenantId|Get-SIRunTenantId|SI_UPDATER_TENANT_ID'
    }
    It 'the token''s tid is decoded from the token itself' {
        Get-SILicenceRequestTenantFromToken -AccessToken (New-TestJwt 'AAAAAAAA-1111-2222-3333-444444444444') | Should -Be 'aaaaaaaa-1111-2222-3333-444444444444'
        Get-SILicenceRequestTenantFromToken -AccessToken 'not-a-token' | Should -BeNullOrEmpty
    }
}

Describe 'when to knock: none, 30 days or less, more than 30 days' {
    BeforeEach { Reset-World }
    It 'no licence -> knock' { (Run).Action | Should -Be 'knocked'; @(Knocks).Count | Should -Be 1 }
    It 'a licence ending in exactly 30 days -> knock' {
        $script:Secrets['SI-License'] = New-LicText -ToDays 30
        (Run).Action | Should -Be 'knocked'
    }
    It 'a licence ending in 31 days -> NO knock, no call at all' {
        $script:Secrets['SI-License'] = New-LicText -ToDays 31
        $r = Run
        $r.Action | Should -Be 'none'
        $script:Calls.Count | Should -Be 0
        (State).validTo | Should -Be ($script:T0.Date.AddDays(31).ToString('yyyy-MM-dd'))
    }
    It 'the threshold is in UTC dates: late on the day 31 days before the end is still "31 days"' {
        $script:Secrets['SI-License'] = New-LicText -ToDays 31
        $script:Clock = $script:T0.Date.AddHours(23).AddMinutes(59)
        (Run).Action | Should -Be 'none'
    }
    It 'an expired licence, or another tenant''s, is "no valid licence" -> knock' {
        $script:Secrets['SI-License'] = New-LicText -FromDays -400 -ToDays -60
        (Run).Action | Should -Be 'knocked'
        Reset-World
        $script:Secrets['SI-License'] = New-LicText -TenantIds @('99999999-9999-9999-9999-999999999999')
        (Run).Action | Should -Be 'knocked'
    }
}

Describe 'pull: pollAfterSeconds, the header, the {} body' {
    BeforeEach { Reset-World }
    It 'never faster than pollAfterSeconds (Invardia sends 1800): +10 min no call, +31 min one pull' {
        $null = Run
        $script:Calls.Clear()
        $script:Clock = $script:T0.AddMinutes(10)
        (Run).Action | Should -Be 'waiting'
        $script:Calls.Count | Should -Be 0
        $script:Clock = $script:T0.AddMinutes(31)
        (Run).Action | Should -Be 'pending'
        @(Pulls).Count | Should -Be 1
        (State).nextPollUtc | Should -Be $script:T0.AddMinutes(31).AddSeconds(1800)
    }
    It 'a knock without pollAfterSeconds waits the 1800 s default' {
        $script:Knock = { Ok 202 @{ requestId = 'r'; pullToken = 'PULLTOKEN-SECRET-X'; status = 'Pending' } }
        $null = Run
        (State).nextPollUtc | Should -Be $script:T0.AddSeconds(1800)
    }
    It 'the pull carries the stored token, to /api/licence-requests/pull, with the body "{}"' {
        $null = Run
        $script:Clock = $script:T0.AddHours(1)
        $null = Run
        $p = (Pulls)[0]
        $p.Uri | Should -Be "$($script:TestBase)/api/licence-requests/pull"
        $p.Token | Should -Be 'PULLTOKEN-SECRET-1'
        $p.Body | Should -BeExactly '{}'
    }
    It 'on the wire: header X-Invardia-Pull-Token, Content-Type application/json, body "{}" (Invoke-SILicenceRequestHttp)' {
        Mock Invoke-WebRequest {
            $script:RealHttp.Add([string]$Uri)
            if ([string]$Uri -notlike "$($script:TestBase)/*") { throw "a test tried to reach $Uri" }
            $script:Wire = [pscustomobject]@{ Uri = $Uri; Headers = $Headers; Body = $Body; ContentType = $ContentType; Method = $Method; Timeout = $TimeoutSec }
            [pscustomobject]@{ StatusCode = 200; Content = '{"status":"Pending"}' }
        }
        $r = Invoke-SILicenceRequestHttp -Uri "$($script:TestBase)/api/licence-requests/pull" -Body '{}' -Token 'PULLTOKEN-SECRET-W' -TimeoutSec 17
        $r.Status | Should -Be 200
        $script:Wire.Headers.Keys | Should -Contain 'X-Invardia-Pull-Token'
        $script:Wire.Headers['X-Invardia-Pull-Token'] | Should -Be 'PULLTOKEN-SECRET-W'
        $script:Wire.Body | Should -BeExactly '{}'
        $script:Wire.ContentType | Should -Be 'application/json'
        "$($script:Wire.Method)" | Should -Be 'Post'
        $script:Wire.Timeout | Should -Be 17
    }
    It 'a knock on the wire carries no token header' {
        Mock Invoke-WebRequest {
            $script:RealHttp.Add([string]$Uri)
            if ([string]$Uri -notlike "$($script:TestBase)/*") { throw "a test tried to reach $Uri" }
            $script:Wire = [pscustomobject]@{ Headers = $Headers }
            [pscustomobject]@{ StatusCode = 202; Content = '{}' }
        }
        $null = Invoke-SILicenceRequestHttp -Uri "$($script:TestBase)/api/licence-requests" -Body '{"product":"securityinsight"}' -Token $null
        $script:Wire.Headers.Keys | Should -Not -Contain 'X-Invardia-Pull-Token'
    }
}

Describe 'token rotation and 401' {
    BeforeEach { Reset-World }
    It 'a repeat knock returns the same request with a NEW token, which overwrites the stored one' {
        $null = Run
        $script:Secrets['SI-LicenceRequest-PullToken'] | Should -Be 'PULLTOKEN-SECRET-1'
        $script:Clock = $script:T0.AddHours(1)
        $script:Pull = { Ok 401 @{ error = 'token' } }
        $null = Run
        @(Knocks).Count | Should -Be 2
        $script:Secrets['SI-LicenceRequest-PullToken'] | Should -Be 'PULLTOKEN-SECRET-2'
        (State).requestId | Should -Be 'req-1'
    }
    It '401 {error:"token"} on pull -> knock again in the same run' {
        $null = Run
        $script:Clock = $script:T0.AddHours(1)
        $script:Pull = { Ok 401 @{ error = 'token' } }
        $r = Run
        $r.Action | Should -Be 'knocked'
        @(Pulls).Count | Should -Be 1
        @(Knocks).Count | Should -Be 2
    }
    It 'a token older than 30 days is not used: the run knocks instead of pulling' {
        $null = Run
        $script:Clock = $script:T0.AddDays(31)
        $null = Run
        @(Pulls).Count | Should -Be 0
        @(Knocks).Count | Should -Be 2
    }
}

Describe 'approved: verify OFFLINE, then Set-SILicense, then read back' {
    BeforeEach { Reset-World }
    It 'Approved -> verified -> installed (once, with the token tenant) -> state approved, valid-to recorded, token retired' {
        $text = New-LicText -ToDays 365
        $script:LicText = $text; $script:Pull = { Ok 200 @{ status = 'Approved'; licence = (New-LicFile $script:LicText) } }
        $null = Run
        $script:Clock = $script:T0.AddHours(1)
        $r = Run
        $r.Action | Should -Be 'installed'
        $script:Installed.Count | Should -Be 1
        $script:Installed[0].Text | Should -Be $text
        $script:Installed[0].Tenant | Should -Be $script:Tenant
        (State).status | Should -Be 'approved'
        (State).validTo | Should -Be $script:T0.Date.AddDays(365).ToString('yyyy-MM-dd')
        $script:Secrets['SI-LicenceRequest-PullToken'] | Should -Be '-'
        # the next run needs nothing
        $script:Calls.Clear(); $script:Clock = $script:T0.AddDays(1)
        (Run).Action | Should -Be 'none'
        $script:Calls.Count | Should -Be 0
    }
    It 'Approved in the knock''s own answer is pulled at once' {
        $text = New-LicText
        $script:Knock = { Ok 202 @{ requestId = 'r'; pullToken = 'PULLTOKEN-SECRET-A'; status = 'Approved'; pollAfterSeconds = 1800 } }
        $script:LicText = $text; $script:Pull = { Ok 200 @{ status = 'Approved'; licence = (New-LicFile $script:LicText) } }
        (Run).Action | Should -Be 'installed'
        $script:Installed.Count | Should -Be 1
    }
    It 'refused and NOT installed: <Case>' -ForEach @(
        @{ Case = 'a bad sha256';       Expect = 'SHA-256' }
        @{ Case = 'a wrong tenant';     Expect = 'not for this tenant' }
        @{ Case = 'a bad signature';    Expect = 'does not verify' }
        @{ Case = 'expired dates';      Expect = 'dates are not valid' }
        @{ Case = 'not valid yet';      Expect = 'dates are not valid' }
        @{ Case = 'another product';    Expect = 'product' }
        @{ Case = 'a Community sku';    Expect = 'names no SecurityInsight Pro edition' }   # #510: the edition decides, features[] does not
    ) {
        $file = switch ($Case) {
            'a bad sha256'     { New-LicFile (New-LicText) ('0' * 64) }
            'a wrong tenant'   { New-LicFile (New-LicText -TenantIds @('99999999-9999-9999-9999-999999999999')) }
            'a bad signature'  { New-LicFile (New-LicText -OtherSigner) }
            'expired dates'    { New-LicFile (New-LicText -FromDays -400 -ToDays -40) }
            'not valid yet'    { New-LicFile (New-LicText -FromDays 5 -ToDays 400) }
            'another product'  { New-LicFile (New-LicText -Product 'PIM4EntraPS') }
            'a Community sku'  { New-LicFile (New-LicText -Features @('*') -Sku 'Community') }
        }
        $script:File = $file; $script:Pull = { Ok 200 @{ status = 'Approved'; licence = $script:File } }
        $null = Run
        $script:Clock = $script:T0.AddHours(1)
        $r = Run
        $r.Action | Should -Be 'refused'
        ($r.Problems -join ' ') | Should -Match $Expect
        $script:Installed.Count | Should -Be 0
        $script:Secrets.ContainsKey('SI-License') | Should -BeFalse
        (State).lastError | Should -Match 'NOT installed'
        (State).status | Should -Be 'pending'
        ($script:LogLines -join "`n") | Should -Match 'warn the licence Invardia sent was NOT installed'
    }
    It 'a real Invardia-signed file (the dual-signer fixture) verifies its SIGNATURE but is refused: it is another product''s' {
        $fx = Join-Path $script:RepoRoot 'sync\tests\fixtures\pime2e-dual-signer.aitlicense'
        if (-not (Test-Path -LiteralPath $fx)) { Set-ItResult -Skipped -Because 'sync/ is not in this checkout'; return }
        $text = [IO.File]::ReadAllText($fx)
        $v = Test-SILicenceRequestFile -Licence (New-LicFile $text) -TenantId '00000000-0000-0000-0000-000000000001' -Now ([datetime]'2026-10-04')
        $v.License.Status | Should -Be 'Valid'                       # the real trusted signers, no test key
        $v.Ok | Should -BeFalse
        ($v.Problems -join ' ') | Should -Match "product 'PIM4EntraPS'"
    }
    It 'the default Install seam is setup/Set-SILicense.ps1 with the token tenant and the vault -- over REST on the updater too (#521: no az)' {
        $root = Join-Path $TestDrive 'si'
        New-Item -ItemType Directory -Force (Join-Path $root 'setup') | Out-Null
        Set-Content -LiteralPath (Join-Path $root 'setup\Set-SILicense.ps1') -Value @'
param($Path, $VaultName, $TenantId, [switch]$Confirm)
$global:SILrSetterCall = [pscustomobject]@{ Text = [IO.File]::ReadAllText($Path); Vault = $VaultName; Tenant = $TenantId; Args = @($PSBoundParameters.Keys) }
'@
        $s = New-SILicenceRequestSeams -VaultName 'kv-test' -Mode Rest -SIRoot $root
        $r = & $s.Install '{"payloadB64":"x"}' $script:Tenant
        $r.Ok | Should -BeTrue
        $global:SILrSetterCall.Text | Should -Be '{"payloadB64":"x"}'
        $global:SILrSetterCall.Vault | Should -Be 'kv-test'
        $global:SILrSetterCall.Tenant | Should -Be $script:Tenant
        $global:SILrSetterCall.Args | Should -Not -Contain 'UseAzCli'
        Remove-Variable -Name SILrSetterCall -Scope Global
        { New-SILicenceRequestSeams -VaultName 'kv-test' -Mode AzCli -SIRoot $root } | Should -Throw -Because 'the az CLI mode is gone (#521)'
    }
    It 'the Rest seams read and write the vault through SecurityInsight''s REST client -- never az' {
        $src = Get-Content -Raw -LiteralPath (Join-Path $script:SIRoot 'engine\_shared\SI-LicenceRequest.ps1')
        $fn = [regex]::Match($src, '(?s)function New-SILicenceRequestSeams \{.*?\n\}').Value
        $fn | Should -Match '\$\{function:Get-SIAzKeyVaultSecret\}'
        $fn | Should -Match '\$\{function:Set-SIAzKeyVaultSecret\}'
        $fn | Should -Not -Match '& az|UseAzCli'
        $setter = Get-Content -Raw -LiteralPath (Join-Path $script:SIRoot 'setup\Set-SILicense.ps1')
        $setter | Should -Not -Match '& az|UseAzCli'
    }
    It 'a setter that refuses is reported, and the request stays open' {
        $text = New-LicText
        $script:LicText = $text; $script:Pull = { Ok 200 @{ status = 'Approved'; licence = (New-LicFile $script:LicText) } }
        $null = Run
        $script:Clock = $script:T0.AddHours(1)
        $s = New-Seams; $s.Install = { param($t, $tid) [pscustomobject]@{ Ok = $false; Message = 'The licence was NOT installed -- nothing was written.' } }
        $r = Invoke-SILicenceRequest -Seams $s -Version '3.0.1' -BaseUrl $script:TestBase -TrustedCertsB64 @($script:TestCertB64)
        $r.Action | Should -Be 'error'
        (State).status | Should -Be 'pending'
        (State).lastError | Should -Match 'could not be installed'
    }
}

Describe 'rejected, 422, 429, other 4xx, network' {
    BeforeEach { Reset-World }
    It 'Rejected is stored with its reason and reported; NOT re-knocked automatically for 7 days; -Force asks at once' {
        $null = Run
        $script:Clock = $script:T0.AddHours(1)
        $script:Pull = { Ok 200 @{ status = 'Rejected'; reason = 'unknown company' } }
        $r = Run
        $r.Action | Should -Be 'rejected'
        (State).status | Should -Be 'rejected'
        (State).reason | Should -Be 'unknown company'
        ($script:LogLines -join "`n") | Should -Match 'warn the licence request was REJECTED by Invardia: unknown company'
        (Get-SILicenceRequestStatus -Json $script:Secrets['SI-LicenceRequest-State']).Summary | Should -Match 'REJECTED.*unknown company'
        $script:Calls.Clear()
        $script:Clock = $script:T0.AddDays(6)
        (Run).Action | Should -Be 'rejected'
        $script:Calls.Count | Should -Be 0
        (Run -Force).Action | Should -Be 'knocked'
        @(Knocks).Count | Should -Be 1
    }
    It 'after 7 days a rejected install asks again by itself' {
        $null = Run
        $script:Clock = $script:T0.AddHours(1)
        $script:Pull = { Ok 200 @{ status = 'Rejected' } }
        $null = Run
        $script:Calls.Clear()
        $script:Clock = $script:T0.AddHours(1).AddDays(7)
        (Run).Action | Should -Be 'knocked'
    }
    It '422 {error:"invalid", fields} -> the fields are reported, and the knock is NOT repeated in a loop (not for a day)' {
        $script:Knock = { Ok 422 @{ error = 'invalid'; fields = @('version', 'tenantId') } }
        $r = Run
        $r.Action | Should -Be 'invalid'
        $r.Problems | Should -Contain 'invalid field: version'
        $r.Problems | Should -Contain 'invalid field: tenantId'
        (State).lastError | Should -Match 'fields: version, tenantId'
        foreach ($h in 1, 6, 23) { $script:Clock = $script:T0.AddHours($h); $null = Run }
        @(Knocks).Count | Should -Be 1
        $script:Clock = $script:T0.AddHours(25)
        $null = Run
        @(Knocks).Count | Should -Be 2
    }
    It '429 with Retry-After 60 -> the next try is at least 60 s later (pull: and never before pollAfterSeconds)' {
        $script:Knock = { Ok 429 @{ error = 'rate' } 60 }
        $r = Run
        $r.Action | Should -Be 'waiting'
        ((State).nextKnockUtc - $script:T0).TotalSeconds | Should -BeGreaterOrEqual 60
        $script:Clock = $script:T0.AddSeconds(30); $null = Run
        @(Knocks).Count | Should -Be 1
        $script:Clock = $script:T0.AddSeconds(61); $null = Run
        @(Knocks).Count | Should -Be 2
        # on pull
        Reset-World
        $null = Run
        $script:Clock = $script:T0.AddHours(1)
        $script:Pull = { Ok 429 $null 3600 }
        $null = Run
        ((State).nextPollUtc - $script:Clock).TotalSeconds | Should -BeGreaterOrEqual 3600
    }
    It 'another 4xx is a warning, not a failure' {
        $script:Knock = { Ok 403 @{ error = 'forbidden' } }
        $r = Run
        $r.Action | Should -Be 'error'
        ($script:LogLines -join "`n") | Should -Match 'warn Invardia answered 403'
    }
    It 'a network failure never throws: it is a warning, and the next try waits' {
        $script:Knock = { Ok 0 $null }
        { $script:R = Run } | Should -Not -Throw
        $script:R.Action | Should -Be 'network'
        ($script:LogLines -join "`n") | Should -Match 'warn Invardia could not be reached'
    }
    It 'even a seam that THROWS does not fail the caller' {
        $script:Knock = { throw 'socket closed' }
        { $script:R = Run } | Should -Not -Throw
        $script:R.Action | Should -Be 'error'
    }
}

Describe 'the pull token never reaches any output' {
    It 'knock, pending, 401 + re-knock, approved: no output stream, log line, result or state carries a token' {
        Reset-World
        $text = New-LicText
        $all = New-Object System.Collections.Generic.List[string]
        $all.Add((Run *>&1 | Out-String))
        $script:Clock = $script:T0.AddHours(1); $all.Add((Run *>&1 | Out-String))
        $script:Pull = { Ok 401 @{ error = 'token' } }
        $script:Clock = $script:T0.AddHours(2); $all.Add((Run *>&1 | ConvertTo-Json -Depth 6 | Out-String))
        $script:LicText = $text; $script:Pull = { Ok 200 @{ status = 'Approved'; licence = (New-LicFile $script:LicText) } }
        $script:Clock = $script:T0.AddHours(3); $all.Add((Run *>&1 | ConvertTo-Json -Depth 6 | Out-String))
        $script:TokenN | Should -Be 2
        $blob = ($all -join "`n") + ($script:LogLines -join "`n") + $script:Secrets['SI-LicenceRequest-State']
        $blob | Should -Not -Match 'PULLTOKEN-SECRET'
        (Get-SILicenceRequestStatus -Json $script:Secrets['SI-LicenceRequest-State'] | ConvertTo-Json) | Should -Not -Match 'PULLTOKEN'
    }
    It 'the token is kept ONLY in its own Key Vault secret' {
        Reset-World
        $null = Run
        @($script:Secrets.Keys | Where-Object { "$($script:Secrets[$_])" -match 'PULLTOKEN-SECRET' }) | Should -Be @('SI-LicenceRequest-PullToken')
    }
}

Describe 'where it runs: the updater job' {
    BeforeEach { Reset-World }
    It 'the updater runs the licence step right after signing in, and the step is wired to its REST sign-in' {
        $c = ((Get-Content -LiteralPath (Join-Path $script:SIRoot 'container\updater\Start-SIUpdater.ps1')) | Where-Object { $_ -notmatch '^\s*#' }) -join "`n"
        $c | Should -Match "_shared/SI-UpdaterLicence\.ps1"
        $c.IndexOf('$who = Connect-SIUpdaterRest') | Should -BeGreaterThan 0
        $c.IndexOf('Invoke-SIUpdaterLicenceRequest') | Should -BeGreaterThan $c.IndexOf('$who = Connect-SIUpdaterRest')
        (Get-Content -Raw -LiteralPath (Join-Path $script:SIRoot 'container\updater\_shared\SI-UpdaterLicence.ps1')) | Should -Match '-Mode Rest'
        $c.IndexOf('Invoke-SIUpdaterLicenceRequest') | Should -BeLessThan $c.IndexOf('Invoke-SIUpdaterFromInvardia -Env')
    }
    It 'the updater image carries the client, the verifier and the setter; the job is told its vault' {
        $d = Get-Content -Raw -LiteralPath (Join-Path $script:SIRoot 'container\updater\Dockerfile')
        foreach ($x in 'COPY engine/_shared/ /si/engine/_shared/', 'COPY setup/ /si/setup/', 'COPY engine/SI-FeatureCatalog.ps1 /si/engine/', 'COPY VERSION /si/') { $d | Should -Match ([regex]::Escape($x)) }
        $i = Get-Content -Raw -LiteralPath (Join-Path $script:SIRoot 'setup\Install-SIUpdaterJob.ps1')
        $i | Should -Match ([regex]::Escape("-DockerFilePath 'container/updater/Dockerfile'"))   # #521: the registry build over REST
        $i | Should -Match 'SI_UPDATER_KEY_VAULT=\$KeyVaultName'
    }
    It 'without SI_UPDATER_KEY_VAULT the step is off: one line, no call' {
        $lines = New-Object System.Collections.Generic.List[string]
        $r = Invoke-SIUpdaterLicenceRequest -Env @{ SI_UPDATER_KEY_VAULT = '' } -Log { param($m) $lines.Add($m) }.GetNewClosure() -Seams (New-Seams)
        $r | Should -BeNullOrEmpty
        ($lines -join ' ') | Should -Match 'licence requests: off'
        $script:Calls.Count | Should -Be 0
    }
    It 'with a vault it runs one cycle with the job''s settings (base URL, contact) -- against the test host only' {
        $lines = New-Object System.Collections.Generic.List[string]
        $r = Invoke-SIUpdaterLicenceRequest -Env @{ SI_UPDATER_KEY_VAULT = 'kv-test'; SI_LICENSE_REQUEST_BASE_URL = $script:TestBase; SI_LICENSE_REQUEST_CONTACT_EMAIL = 'ops@contoso.test' } `
                -SubscriptionId 'sub' -SIRoot $script:SIRoot -Log { param($m) $lines.Add($m) }.GetNewClosure() -Seams (New-Seams)
        $r.Action | Should -Be 'knocked'
        (Knocks)[0].Uri | Should -Be "$($script:TestBase)/api/licence-requests"
        ((Knocks)[0].Body | ConvertFrom-Json).contactEmail | Should -Be 'ops@contoso.test'
        ((Knocks)[0].Body | ConvertFrom-Json).version | Should -Be ([IO.File]::ReadAllText((Join-Path $script:SIRoot 'VERSION')).Trim())
        ($lines -join "`n") | Should -Match 'licence request: knocked'
        ($lines -join "`n") | Should -Not -Match 'PULLTOKEN'
    }
    It 'inside the real updater script, the step''s lines reach the updater log (Write-UpdLog), a network failure included' {
        . (Join-Path $script:SIRoot 'container\updater\Start-SIUpdater.ps1') -DefineOnly
        $script:Knock = { Ok 0 $null }
        $s = New-Seams; $s.Remove('Log')      # the updater's own log, not the test's
        $out = @(Invoke-SIUpdaterLicenceRequest -Env @{ SI_UPDATER_KEY_VAULT = 'kv-test'; SI_LICENSE_REQUEST_BASE_URL = $script:TestBase } -SIRoot $script:SIRoot `
                    -Log { param($m) Write-UpdLog $m } -Seams $s 6>&1 | ForEach-Object { "$_" }) -join "`n"
        $out | Should -Match 'licence request WARNING: Invardia could not be reached'
        $out | Should -Match 'licence request: network'
    }
    It 'a failure inside the step never fails the update run' {
        $s = New-Seams; $s.ReadSecret = { throw 'vault unreachable' }
        { Invoke-SIUpdaterLicenceRequest -Env @{ SI_UPDATER_KEY_VAULT = 'kv-test' } -SIRoot $script:SIRoot -Log { param($m) } -Seams $s } | Should -Not -Throw
    }
    It 'the Pro mirror (cfg.InstallState LicenceRequest) gets the compact state, never the token' {
        $script:Sql = New-Object System.Collections.Generic.List[object]
        $store = [pscustomobject]@{ Name = 'fake'; Invoke = { param($sql, $p, $mode) $script:Sql.Add([pscustomobject]@{ Sql = $sql; P = $p; Mode = $mode }) } }
        $script:Store = $store
        $s = New-Seams; $s.SaveState = { param($json) Save-SILicenceRequestProState -Store $script:Store -Json $json }
        $null = Invoke-SILicenceRequest -Seams $s -Version '3.0.1' -BaseUrl $script:TestBase
        $script:Sql.Count | Should -Be 1
        $script:Sql[0].Sql | Should -Match "Name = N'LicenceRequest'"
        $v = $script:Sql[0].P['Value']
        $v.Length | Should -BeLessOrEqual 400
        ($v | ConvertFrom-Json).status | Should -Be 'requested'
        $v | Should -Not -Match 'PULLTOKEN'
    }
}

Describe 'the real Az-mode seams work from a NESTED script (setup\Request-SILicense.ps1 run from a prompt or another script)' {
    It 'ReadSecret and WriteSecret reach the vault functions -- a closure cannot see a caller''s script-scope functions' {
        # Found live on ring 1 (2026-10-05): "Get-SIAzKeyVaultSecret is not recognized" -- only when the script that
        # dot-sources the client is itself called from a script. The vault REST layer is stubbed; nothing leaves the host.
        $dir = Join-Path ([IO.Path]::GetTempPath()) ('si-lr-nested-' + [guid]::NewGuid().ToString('N'))
        New-Item -ItemType Directory -Path $dir | Out-Null
        try {
            $child = Join-Path $dir 'child.ps1'
            $lib = Join-Path $script:SIRoot 'engine\_shared\SI-LicenceRequest.ps1'
            Set-Content -LiteralPath $child -Encoding UTF8 -Value @"
param([string]`$Lib, [string]`$SIRoot)
. `$Lib
`$script:Written = @{}
function Get-SIAzKeyVaultSecretRest { param([string]`$VaultName, [string]`$Name, [switch]`$AsPlainText)
    `$sec = New-Object System.Security.SecureString; foreach (`$ch in ("`$VaultName/`$Name").ToCharArray()) { `$sec.AppendChar(`$ch) }
    [pscustomobject]@{ SecretValue = `$sec } }
function Set-SIAzKeyVaultSecretRest { param([string]`$VaultName, [string]`$Name, `$SecretValue, [string]`$ContentType)
    `$script:Written[`$Name] = "`$VaultName|" + [System.Net.NetworkCredential]::new('', `$SecretValue).Password }
`$s = New-SILicenceRequestSeams -VaultName 'kv-nested' -Mode Az -SIRoot `$SIRoot
`$read = & `$s.ReadSecret 'SI-InstallId'
& `$s.WriteSecret 'SI-LicenceRequest-State' '{}'
[pscustomobject]@{ Read = `$read; Written = `$script:Written['SI-LicenceRequest-State'] }
"@
            $r = & $child -Lib $lib -SIRoot $script:SIRoot
            $r.Read | Should -Be 'kv-nested/SI-InstallId'
            $r.Written | Should -Be 'kv-nested|{}'
        } finally { Remove-Item -LiteralPath $dir -Recurse -Force -ErrorAction SilentlyContinue }
    }
    It 'TenantId under a managed identity calls the token function captured as a VALUE -- it works after the name is gone' {
        # The closure called Get-SIManagedIdentityToken by NAME and only worked by load order; when the name was not visible it
        # silently took the run token's tenant instead. Now the function travels in, and a missing one is a plain error.
        $hadVar = Test-Path -Path 'variable:global:SI_UseManagedIdentity'; $oldVar = $null; if ($hadVar) { $oldVar = $global:SI_UseManagedIdentity }
        $oldFn = $null; $have = Get-Command -Name Get-SIManagedIdentityToken -CommandType Function -ErrorAction SilentlyContinue; if ($have) { $oldFn = $have.ScriptBlock }
        try {
            $global:SI_UseManagedIdentity = $true
            Set-Item -Path 'function:global:Get-SIManagedIdentityToken' -Value { param([string]$Resource) $global:SI_IdentityTokenTenantId = '11111111-2222-3333-4444-555555555555'; 'tok' }
            $s = New-SILicenceRequestSeams -VaultName 'kv-test' -Mode Rest -SIRoot $script:SIRoot
            Remove-Item -Path 'function:Get-SIManagedIdentityToken' -Force -ErrorAction SilentlyContinue
            Get-Command -Name Get-SIManagedIdentityToken -CommandType Function -ErrorAction SilentlyContinue | Should -BeNullOrEmpty
            & $s.TenantId | Should -Be '11111111-2222-3333-4444-555555555555'
        } finally {
            Remove-Item -Path 'function:Get-SIManagedIdentityToken' -Force -ErrorAction SilentlyContinue
            if ($oldFn) { Set-Item -Path 'function:global:Get-SIManagedIdentityToken' -Value $oldFn }
            if ($hadVar) { $global:SI_UseManagedIdentity = $oldVar } else { Remove-Variable -Name SI_UseManagedIdentity -Scope Global -ErrorAction SilentlyContinue }
        }
    }
    It 'TenantId under a managed identity with no token function loaded is a plain error naming it -- never another sign-in path' {
        $hadVar = Test-Path -Path 'variable:global:SI_UseManagedIdentity'; $oldVar = $null; if ($hadVar) { $oldVar = $global:SI_UseManagedIdentity }
        $oldFn = $null; $have = Get-Command -Name Get-SIManagedIdentityToken -CommandType Function -ErrorAction SilentlyContinue; if ($have) { $oldFn = $have.ScriptBlock }
        try {
            Remove-Item -Path 'function:Get-SIManagedIdentityToken' -Force -ErrorAction SilentlyContinue
            $global:SI_UseManagedIdentity = $true
            $s = New-SILicenceRequestSeams -VaultName 'kv-test' -Mode Rest -SIRoot $script:SIRoot
            { & $s.TenantId } | Should -Throw -ExpectedMessage '*Get-SIManagedIdentityToken is not loaded*'
        } finally {
            if ($oldFn) { Set-Item -Path 'function:global:Get-SIManagedIdentityToken' -Value $oldFn }
            if ($hadVar) { $global:SI_UseManagedIdentity = $oldVar } else { Remove-Variable -Name SI_UseManagedIdentity -Scope Global -ErrorAction SilentlyContinue }
        }
    }
}

Describe 'the state for the health check and the web app' {
    It 'every state reads as a sentence the admin understands' {
        (Get-SILicenceRequestStatus -Json $null).Status | Should -Be 'none'
        (Get-SILicenceRequestStatus -Json '{"status":"pending","requestedUtc":"2026-10-04T10:00:00Z","nextPollUtc":"2026-10-04T10:30:00Z"}').Summary | Should -Match 'requested on 2026-10-04 10:00Z, waiting for Invardia'
        (Get-SILicenceRequestStatus -Json '{"status":"approved","validTo":"2027-10-04"}').Summary | Should -Match 'valid until 2027-10-04'
        (Get-SILicenceRequestStatus -Json 'garbage').Status | Should -Be 'none'
    }
    It 'Test-SIInstall: a REJECTED request is a finding, with its reason; the state is read from the install''s vault' {
        . (Join-Path $script:SIRoot 'diagnostics\_SIInstallDiagnostics.ps1')
        $t = Get-SIInstallTargetFromConfig -Values @{ SI_WorkspaceResourceId = '/subscriptions/s1/resourceGroups/rg1/providers/Microsoft.OperationalInsights/workspaces/ws1'; SI_KeyVaultName = 'kv-si' }
        $t.KeyVaultName | Should -Be 'kv-si'
        $script:AskedVault = $null
        $seams = Merge-SIDiagnosticsSeams -Seams @{
            Arm = { param($Method, $Path, $ApiVersion, [switch]$List, $Body) if ($List) { @() } else { [pscustomobject]@{ properties = [pscustomobject]@{ customerId = 'g' } } } }
            LaQuery = { param($w, $q) [pscustomobject]@{ Results = @() } }
            Graph = { param($q, $s) @() }
            Print = { param($t, $c) }
            LicenceState = { param($v) $script:AskedVault = $v; '{"status":"rejected","rejectedUtc":"2026-10-04T10:00:00Z","reason":"unknown company","lastCheckUtc":"2026-10-04T11:00:00Z"}' }
            UpdateState  = { param($v) $null }   # #240's update section -- no vault is read in a test
        }
        $r = Invoke-SIInstallCheck -Target $t -Seams $seams -PrincipalId 'p1'
        $script:AskedVault | Should -Be 'kv-si'
        $r.LicenceRequest.Status | Should -Be 'rejected'
        @($r.Findings | Where-Object { $_.Area -eq 'licence' }).Count | Should -Be 1
        (@($r.Findings | Where-Object { $_.Area -eq 'licence' })[0].Text) | Should -Match 'unknown company'
    }
}

Describe 'the installed licence for the web app''s Licence card (cfg.InstallState Licence)' {
    # The web app never reads SI-License: the updater verifies it with the engines' own checks and writes these facts.
    BeforeEach { Reset-World }
    function script:Summary([string]$Text, [string]$Tid = $script:Tenant, [datetime]$Now = $script:T0) {
        $lic = Get-SILicense -SecretText $Text -TrustedCertsB64 @($script:TestCertB64) -Now $Now
        ConvertTo-SILicenceSummaryJson -License $lic -TenantId $Tid -NowUtc $Now | ConvertFrom-Json
    }
    It 'a valid licence for this tenant: customer, edition, dates and tenantOk -- never the licence text or its signature' {
        $text = New-LicText -LicenseId 'lic-42'
        $j = ConvertTo-SILicenceSummaryJson -License (Get-SILicense -SecretText $text -TrustedCertsB64 @($script:TestCertB64) -Now $script:T0) -TenantId $script:Tenant -NowUtc $script:T0
        $j.Length | Should -BeLessOrEqual 400
        $j | Should -Not -Match 'payloadB64|signature'
        $o = $j | ConvertFrom-Json
        $o.status | Should -Be 'Valid'
        $o.customer | Should -Be 'Test Customer'
        $o.sku | Should -Be 'Pro'
        $o.licenceId | Should -Be 'lic-42'
        $o.tenantOk | Should -BeTrue
        $o.validTo | Should -Be $script:T0.Date.AddDays(365).ToString('yyyy-MM-dd', [Globalization.CultureInfo]::InvariantCulture)
        $o.graceUntil | Should -Be $script:T0.Date.AddDays(395).ToString('yyyy-MM-dd', [Globalization.CultureInfo]::InvariantCulture)
        $j | Should -Match '"verifiedUtc":"2026-10-04T10:00:00Z"'     # (pwsh 7's ConvertFrom-Json would turn it into a date)
    }
    It 'each verifier state reaches the card: Grace, Expired, NotYetValid, Invalid (another signer), Missing; another tenant is tenantOk false' {
        (Summary (New-LicText -FromDays -400 -ToDays -10)).status | Should -Be 'Grace'
        (Summary (New-LicText -FromDays -400 -ToDays -60)).status | Should -Be 'Expired'
        (Summary (New-LicText -FromDays 10)).status | Should -Be 'NotYetValid'
        (Summary (New-LicText -OtherSigner)).status | Should -Be 'Invalid'
        (Summary '').status | Should -Be 'Missing'
        (Summary (New-LicText -TenantIds @($script:ConfigTenant))).tenantOk | Should -BeFalse
        (Summary (New-LicText -TenantIds @())).tenantOk | Should -BeTrue
        (Summary (New-LicText) -Tid '').tenantOk | Should -BeNullOrEmpty
        (ConvertTo-SILicenceSummaryJson -License $null -TenantId $script:Tenant -NowUtc $script:T0 | ConvertFrom-Json).status | Should -Be 'Missing'
    }
    It 'the updater writes it to cfg.InstallState Licence after its cycle, and with automatic requests off too -- with no call to Invardia' {
        $script:Sql = New-Object System.Collections.Generic.List[object]
        $store = [pscustomobject]@{ Name = 'fake'; Invoke = { param($sql, $p, $mode) $script:Sql.Add([pscustomobject]@{ Sql = $sql; P = $p }) } }
        $script:Secrets['SI-License'] = New-LicText
        $s = New-Seams; $s.CurrentLicence = { Get-SILicense -SecretText $script:Secrets['SI-License'] -TrustedCertsB64 @($script:TestCertB64) -Now $script:T0 }
        $null = Invoke-SIUpdaterLicenceRequest -Env @{ SI_UPDATER_KEY_VAULT = 'kv-test'; SI_LICENSE_REQUEST_BASE_URL = $script:TestBase } -SIRoot $script:SIRoot -Log { param($m) } -Seams $s -Store $store `
            -Mail { param($n) $true } -Audit { param($n) $true }
        $w = @($script:Sql | Where-Object { $_.Sql -match "Name = N'Licence'" })
        $w.Count | Should -Be 1
        ($w[0].P.Value | ConvertFrom-Json).status | Should -Be 'Valid'
        $script:Sql.Clear(); $script:Calls.Clear()
        $null = Invoke-SIUpdaterLicenceRequest -Env @{ SI_UPDATER_KEY_VAULT = 'kv-test' } -SIRoot $script:SIRoot -Log { param($m) } -Seams $s -Store $store `
            -Switch ([pscustomobject]@{ On = $false; Text = 'off (SI_LicenseRequest_Auto)' })
        @($script:Sql | Where-Object { $_.Sql -match "Name = N'Licence'" }).Count | Should -Be 1
        $script:Calls.Count | Should -Be 0
    }
    It 'a summary that would not fit drops its free text first' {
        $script:Sql = New-Object System.Collections.Generic.List[object]
        $store = [pscustomobject]@{ Name = 'fake'; Invoke = { param($sql, $p, $mode) $script:Sql.Add($p) } }
        $long = [ordered]@{ status = 'Valid'; customer = ('c' * 60); features = ('f' * 200); reason = ('r' * 200) } | ConvertTo-Json -Compress
        Save-SILicenceProSummary -Store $store -Json $long
        $script:Sql[0].Value.Length | Should -BeLessOrEqual 400
        ($script:Sql[0].Value | ConvertFrom-Json).customer | Should -Be ('c' * 60)
    }
}

Describe 'GUARD: no test ever reaches invardia.com' {
    It 'the base URL is a setting: explicit wins, then the global, then the environment, else https://invardia.com' {
        $prev = $env:SI_LICENSE_REQUEST_BASE_URL
        try {
            Get-SILicenceRequestBaseUrl -BaseUrl 'https://a.test.invalid/' | Should -Be 'https://a.test.invalid'
            $env:SI_LICENSE_REQUEST_BASE_URL = 'https://env.test.invalid'
            Get-SILicenceRequestBaseUrl | Should -Be 'https://env.test.invalid'
            $env:SI_LICENSE_REQUEST_BASE_URL = $null
            Get-SILicenceRequestBaseUrl | Should -Be 'https://invardia.com'      # computed only -- nothing is called
            { Get-SILicenceRequestBaseUrl -BaseUrl 'http://plain.test.invalid' } | Should -Throw '*https*'
        } finally { $env:SI_LICENSE_REQUEST_BASE_URL = $prev }
    }
    It 'every fake call in this file went to the test host, and no real HTTP call left for invardia.com' {
        $env:SI_LICENSE_REQUEST_BASE_URL | Should -Be $script:TestBase
        @($script:RealHttp | Where-Object { $_ -match 'invardia\.com' }).Count | Should -Be 0
        @($script:RealHttp | Where-Object { $_ -notlike "$($script:TestBase)/*" }).Count | Should -Be 0
    }
    It 'no test file sends the client to a real Invardia host' {
        $hits = @(Get-ChildItem -LiteralPath (Join-Path $script:SIRoot 'tests\pester') -Filter '*.ps1' | Where-Object { $_.Name -ne 'SIv3-LicenceRequest.Tests.ps1' } |
            Select-String -Pattern '\bInvoke-SILicenceRequest\b|&\s*[^#\r\n]*Request-SILicense\.ps1' |
            # another suite may drive the client only through its fake seams AND an explicit reserved, never-resolving host
            # on the same call (RFC 2606 '.invalid', e.g. SIv3-LicenceSuperseded): such a call cannot reach Invardia
            Where-Object { $_.Line -notmatch "-Seams\s+\S+.*-BaseUrl\s+'https://[a-z0-9.-]+\.invalid'" })
        $hits.Count | Should -Be 0 -Because 'a test drives the licence request client only offline: this suite, or fake seams plus a .invalid host'
    }
}
