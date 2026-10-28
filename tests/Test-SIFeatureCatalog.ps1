#Requires -Version 5.1
<#
.SYNOPSIS
    LIC-1 -- offline tests for SecurityInsight's feature catalog and licence gate.

.DESCRIPTION
    The assertion that matters most is the operator's rule, and it is a STRUCTURAL one:
    a free feature must never consult a licence. It is not enough that a free feature is
    allowed -- it must be allowed WITHOUT the licence path running, so that a missing,
    expired, corrupt or wrong-tenant licence cannot affect the ~6000 community users.

    Proven by sabotage rather than by reading: the framework verifier is pointed at a
    directory that cannot exist and a licence that cannot verify, and every free feature
    must still come back allowed.
#>
[CmdletBinding()] param()
$ErrorActionPreference = 'Stop'
$here = if ($PSScriptRoot) { $PSScriptRoot } else { Split-Path -Parent $MyInvocation.MyCommand.Path }
. (Join-Path (Split-Path -Parent $here) 'engine\SI-FeatureCatalog.ps1')

$script:pass = 0; $script:fail = 0
function A([bool]$c, [string]$m) { if ($c) { $script:pass++ } else { $script:fail++; Write-Host "  - $m" -ForegroundColor Red } }
function Eq($e, $a, [string]$m) { A ("$e" -eq "$a") "$m (expected '$e', got '$a')" }

Write-Host "`n=== A. the catalog: paid is opt-IN, free is the default ===" -ForegroundColor Cyan
$cat = Get-SIFeatureCatalog
A (@($cat).Count -ge 2) 'the catalog has entries'
A (@($cat | Where-Object { $_.Edition -notin @('Pro', 'MSP') }).Count -eq 0) 'every catalog entry is Pro (or MSP) -- the catalog lists ONLY paid features'
A (Test-SIFeatureIsPaid -Feature 'servicenow-connector')   'the OUTBOUND connector is Pro'
A (-not (Test-SIFeatureIsPaid -Feature 'correlation'))     'cross-engine correlation and the full asset properties are FREE (Community edition, owner 2026-10-27, #750 (1))'
# 🪤 The trap that would have broken the 30 and the 6000 at once: the INBOUND CSV import is free.
A (-not (Test-SIFeatureIsPaid -Feature 'servicenow-cmdb')) 'the INBOUND CMDB CSV import is FREE -- not caught by a loose "ServiceNow = Pro"'
A (-not (Test-SIFeatureIsPaid -Feature 'code'))            'code is free (and is a required CAPABILITY, which may never be Pro)'
A (-not (Test-SIFeatureIsPaid -Feature 'risk-analysis'))   'the engines are free'
A (-not (Test-SIFeatureIsPaid -Feature 'typo-nobody-declared')) 'an UNKNOWN feature is FREE -- a typo must never gate a shipped feature'
# v3 (operator ruling 2026-09-29): Pro = the ServiceNow connector + correlation; 2026-10-02 added the settings database (Pro-1);
# 2026-10-18 (owner): the database and the web app are in BOTH versions -- the settings database and the data backend are free;
# the database chain's paid features are governance and the CMDB connectors. 2026-10-27 (owner, #750 (1)): correlation is free.
Eq 'cmdb-connectors,governance,servicenow-connector' ((@($cat | ForEach-Object { $_.Name }) | Sort-Object) -join ',') 'Pro is exactly the ServiceNow connector, governance and the CMDB connectors'
A (-not (Test-SIFeatureIsPaid -Feature 'settings-database')) 'the settings database is FREE (the database is in both versions, 2026-10-18)'
A (-not (Test-SIFeatureIsPaid -Feature 'data-backend'))      'the data backend is FREE (the database is in both versions, 2026-10-18)'
A (@($cat | Where-Object { -not $_.Built }).Count -eq 0) 'every Pro feature is built'

Write-Host "=== B. THE RULE: a free feature never consults a licence ===" -ForegroundColor Cyan
# Enforcement ON, a licence directory that cannot exist, and no tenant. If a free feature
# consulted the licence path at all, these would refuse.
$hostile = 'Z:\no\such\place\at\all'
foreach ($f in @('risk-analysis','asset-profiling','servicenow-cmdb','anything-at-all')) {
    $r = Test-SIFeatureAvailable -Feature $f -Enforce $true -LicenseDirectory $hostile
    A $r.Allowed "free feature '$f' is allowed with enforcement ON and no licence anywhere"
    Eq 'Free' $r.Edition "  ...and is reported as Free"
    A ($r.Reason -match 'no licence is required or consulted') "  ...and SAYS the licence was never consulted"
}

Write-Host "=== C. v3: enforcement is ON by default, and a config global cannot switch it off ===" -ForegroundColor Cyan
$prev = $global:SI_EnforceProLicense
try {
    $global:SI_EnforceProLicense = $false      # a customer config trying to turn Pro into free
    $r = Test-SIFeatureAvailable -Feature 'servicenow-connector' -LicenseDirectory ([IO.Path]::GetTempPath())
    A (-not $r.Allowed) 'a PAID feature with no licence is refused by default, even with SI_EnforceProLicense = false'
    Eq 'Pro' $r.Edition '  ...and is reported as Pro'
} finally { $global:SI_EnforceProLicense = $prev }

Write-Host "=== D. enforcement ON, paid feature, no licence -> refused ===" -ForegroundColor Cyan
$r = Test-SIFeatureAvailable -Feature 'servicenow-connector' -Enforce $true -LicenseDirectory ([IO.Path]::GetTempPath())
A (-not $r.Allowed) 'a paid feature with no licence is refused once enforcement is on'
Eq 'Pro' $r.Edition '  ...and is reported as Pro'
A ("$($r.Reason)".Length -gt 0) '  ...with a reason, never a bare false'

Write-Host "=== E. it really does reach the FRAMEWORK verifier (not a private copy) ===" -ForegroundColor Cyan
$core = Get-SIFrameworkLicensePath
if ($core) {
    # SI loads its BYTE-IDENTICAL copy of the framework verifier (sync/ is absent in a container image and the
    # public mirror); SIv3-License.Tests.ps1 fails on any drift from sync/_AitLicense.ps1.
    A ($core -match '(engine[\\/]_shared[\\/]AitLicense|sync[\\/]_AitLicense)\.ps1$') 'resolves the framework verifier (SI''s identical copy, else sync/)'
    . $core
    A ((Get-Command Resolve-AitLicenseStatus -ErrorAction SilentlyContinue) -ne $null) 'and the framework functions load'
    # End to end with a real signed licence: catalog decides PAID, framework decides ENTITLED.
    $rsa  = [System.Security.Cryptography.RSA]::Create(2048)
    $dn   = [System.Security.Cryptography.X509Certificates.X500DistinguishedName]::new('CN=SI-TEST')
    $req  = [System.Security.Cryptography.X509Certificates.CertificateRequest]::new($dn, $rsa, [System.Security.Cryptography.HashAlgorithmName]::SHA256, [System.Security.Cryptography.RSASignaturePadding]::Pkcs1)
    $cB64 = [Convert]::ToBase64String($req.CreateSelfSigned([DateTimeOffset]::UtcNow.AddDays(-1), [DateTimeOffset]::UtcNow.AddYears(5)).Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Cert))
    $pl   = @{ licenseId='si-1'; customer='Contoso'; sku='Pro'; features=@('servicenow-connector'); tenantIds=@('11111111-2222-3333-4444-555555555555'); validFrom='2026-01-01'; validTo='2026-12-31'; graceDays=30 }
    $b    = [System.Text.Encoding]::UTF8.GetBytes(($pl | ConvertTo-Json -Compress))
    $doc  = [pscustomobject]@{ product='SecurityInsight'; payloadB64=[Convert]::ToBase64String($b)
             signature=[Convert]::ToBase64String($rsa.SignData($b,[System.Security.Cryptography.HashAlgorithmName]::SHA256,[System.Security.Cryptography.RSASignaturePadding]::Pkcs1)) }
    $lic  = Resolve-AitLicenseStatus -Document $doc -TrustedCertsB64 @($cB64) -Now '2026-06-01'
    Eq 'Valid' $lic.Status 'the fixture licence is valid'
    A     (Test-AitLicenseFeature -License $lic -Feature 'servicenow-connector' -TenantId '11111111-2222-3333-4444-555555555555' -Enforce).Allowed 'licensed paid feature -> entitled'
    A (-not (Test-AitLicenseFeature -License $lic -Feature 'correlation' -TenantId '11111111-2222-3333-4444-555555555555' -Enforce).Allowed) 'the shared verifier''s own feature match does not cover a DIFFERENT feature'
    # #510 (framework section 12.6a LICENCE-FEATURES): SI does not ask that feature match -- the EDITION decides, so the
    # same sku=Pro licence covers governance too, and every Pro feature added after it was signed.
    A (Test-SIFeatureAvailable -Feature 'governance' -License $lic -TenantId '11111111-2222-3333-4444-555555555555').Allowed '#510 SI''s gate: the Pro edition covers governance although features[] lists only the connector'
} else {
    Write-Host "  SKIP -- sync/_AitLicense.ps1 not reachable (expected on a stripped community tree)" -ForegroundColor Yellow
    # And the degradation must be safe: free features still run without the framework file.
    A (Test-SIFeatureAvailable -Feature 'risk-analysis' -Enforce $true).Allowed 'free features survive a missing framework verifier'
}

Write-Host ""
if ($script:fail) { Write-Host "FAILED: $script:pass passed, $script:fail failed" -ForegroundColor Red; exit 1 }
Write-Host "ALL $script:pass PASSED" -ForegroundColor Green
exit 0
