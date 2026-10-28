#Requires -Version 5.1
<#
.SYNOPSIS
    LIC-1 -- SecurityInsight's feature catalog and the one gate its engines call.

.DESCRIPTION
    The licence FORMAT, signature and validity rules are FRAMEWORK-level (sync/_AitLicense.ps1 -- one
    implementation, every solution). This file owns only the half that is genuinely SecurityInsight's:
    WHICH FEATURES ARE PAID, where an install's licence comes from, and what a refused feature does.

    🔒 THE RULE THIS FILE EXISTS TO ENFORCE (operator, 2026-09-08):
        "license is only needed if not free" / "so license req is not for all a req"
    A FREE feature never touches the licence path at all -- Test-SIFeatureAvailable returns for a free
    feature BEFORE any licence is loaded, so a missing, expired, corrupt or wrong-tenant licence cannot
    affect anything free. Community users hold no licence and must never be able to notice licensing.

    🔒 v3 EDITIONS (operator rulings 2026-09-29, SI #159):
      * Pro = the ServiceNow connector, the CMDB in SQL and its connectors, governance (departments, governance mails,
        the task digest). Everything else is the Community edition: profilers, tier classifier, cross-engine
        correlation and the full asset properties (owner 2026-10-27, #750 (1)), every Risk Analysis report, the AI
        summary, trend, all outputs, the generic CSV CMDB, VM and container hosting, Shodan, asset tagging (#750 (2)),
        verification and data health (#750 (8)).
      * ENFORCED from v3 launch -- SI Pro is PAID. This replaces the 2026-09-08 ship-OFF default on
        purpose. There is deliberately no customer switch: the only config an install has is the
        customer's own, and a switch there would be a free Pro edition. (-Enforce stays for tests.)
      * THE DATABASE AND THE WEB APP ARE IN BOTH VERSIONS (owner 2026-10-18, #750 (a); #477, #480, #678): the settings
        database ('settings-database') and the data backend ('data-backend' -- the data sync, the Risk Analysis store, the
        CIs in SQL) are no longer paid. They are not in the catalog any more, so they are free by the rule below (their
        call sites keep their gate call: a no-op for a free feature). The paid features of the database chain are named
        instead: 'governance' (departments, governance mails, the task digest) and 'cmdb-connectors' (the CMDB in SQL).
      * Delivered as the Key Vault secret 'SI-License' (the signed file as JSON or base64), read at runtime
        on VM and container alike; a licence file in config\ is the fallback.

    🔑 TWO GATES, DIFFERENT QUESTIONS (LIC-3). ring = WHEN a version reaches you; licence = WHETHER you may
    run a feature. And a CAPABILITY is not a FEATURE: capabilities in solution.deploy.json are ring-gated
    INSTALL units; features here are licence-gated BEHAVIOUR. A required capability may never be Pro.

    🔑 THE VERIFIER IS LOADED FROM SI's OWN COPY (engine/_shared/AitLicense.ps1, byte-identical to
    sync/_AitLicense.ps1 -- a test fails on drift). sync/ is not in a container image or the public mirror,
    so the previous "search upward for sync/" found nothing there and would have refused every Pro feature.

    🔒 THE EDITION DECIDES, NOT features[] (framework §12.6a LICENCE-FEATURES, SI #510; owner 2026-10-09: "but does that
    mean we have to sign licenses when new features are released, that is not smart"). The signed licence names the
    EDITION in its `sku`; THIS file maps edition -> features:
      * a Pro edition (sku Pro / Pro-Business / Pro-DesignPartner / Trial / any Pro-*) = EVERY catalog entry with
        Edition 'Pro', current and future -- a Pro licence issued before a feature existed already covers it;
      * an MSP edition (sku naming MSP) = the Pro features + the entries with Edition 'MSP' (multi-tenant; none today);
      * Pro Business vs Pro Enterprise differ by the signed `limits`, never by features;
      * features[] is informational, and counts ONLY for an entry marked AddOn = $true (an explicit paid add-on, which
        needs its own id in features[]; '*' does not cover an add-on). There are NO add-ons today.
    A licence that is not valid / in grace, not bound to this tenant, or whose sku names no Pro edition (Community,
    Core, empty) gives Community. The shared verifier (AitLicense.ps1) is unchanged: SI asks it for the status and the
    tenant binding, and applies the edition rule here, at its own call site.

    🔴 ABSENCE IS NOT REMEDIATION (working rule 4). A refused Pro engine SKIPS and says why; it never
    publishes an empty result, and no close path acts on the absence of its output.
#>

# Azure access: plain REST, no PowerShell modules (engine/_shared/SI-AzRest.ps1).
if (-not (Get-Command -Name Invoke-SIArm -ErrorAction SilentlyContinue)) { . (Join-Path $PSScriptRoot '_shared/SI-AzRest.ps1') }

Set-StrictMode -Off

# ---------------------------------------------------------------------------
# THE CATALOG. Everything not listed here is FREE -- the default is free, so a
# feature can never become paid by omission or typo, only by a deliberate entry.
#
# 🪤 NAME THE CONNECTOR PRECISELY. SI's INBOUND CSV provider was called
# `servicenow-cmdb` until v2.2.421, it is FREE, and ~510 report references depend on
# it. A loosely worded "ServiceNow = Pro" would gate the free CSV importer.
#
# Edition = 'Pro' (every Pro edition has it) | 'MSP' (multi-tenant; the MSP edition only).
# AddOn   = $true only for an explicit paid add-on that the licence must LIST in features[] (#510). None today.
# ---------------------------------------------------------------------------
$script:SIFeatureCatalog = @(
    [pscustomobject]@{
        Name        = 'servicenow-connector'
        Edition     = 'Pro'
        Built       = $true
        Title       = 'The ServiceNow CMDB connector'   # short name for the one-line skip message customers see
        Description = 'ServiceNow CMDB connector (match and create CIs, vulnerability close-loop). Distinct from the free inbound CMDB CSV import.'
    }
    # 'correlation' (cross-engine correlation and the full asset properties) is NOT here any more: it is in the Community
    # edition (owner 2026-10-27, SI #750 (1) / #678 -- "data in, data correlation, ra + data out to excel are part of
    # community"). Unknown = free, so every call site that still names it runs in both editions.
    [pscustomobject]@{
        Name        = 'governance'
        Edition     = 'Pro'
        Built       = $true
        Title       = 'Departments, governance and follow-up tasks'
        Description = 'Asset responsibility put to work: the department reports, the governance mails (exemptions, remediation flows, vendor escalation) and the daily task digest.'
    }
    [pscustomobject]@{
        Name        = 'cmdb-connectors'
        Edition     = 'Pro'
        Built       = $true
        Title       = 'The CMDB in SQL and its connectors'
        Description = 'The CMDB kept in the SecurityInsight database: the SQL CMDB connector and the CMDB import. Distinct from the free inbound CMDB CSV file.'
    }
)

function Get-SIFeatureCatalog {
    <# .SYNOPSIS Every PAID feature SI knows about. Everything else is free by default. #>
    [CmdletBinding()] param()
    return @($script:SIFeatureCatalog)
}

function Test-SIFeatureIsPaid {
    <#
    .SYNOPSIS
        PURE. Is this feature paid? Unknown names are FREE.
    .DESCRIPTION
        🔒 UNKNOWN => FREE, deliberately. Guessing the other way means a typo in a call site silently
        gates a shipped free feature for every customer at once. A typo in a PAID call site costs an
        ungated paid feature -- recoverable, and the wiring tests name every paid call site.
    #>
    [CmdletBinding()] param([Parameter(Mandatory)][string]$Feature)
    foreach ($f in $script:SIFeatureCatalog) {
        if ("$($f.Name)" -ieq "$Feature".Trim()) { return ("$($f.Edition)" -in @('Pro', 'MSP')) }
    }
    return $false
}

function Get-SILicenceEdition {
    <#
    .SYNOPSIS
        PURE. The EDITION a licence's signed sku names: 'MSP' | 'Pro' | 'Community' (framework §12.6a, SI #510).
    .DESCRIPTION
        Reads only the sku -- not the status, the tenant or features[] (Test-SIFeatureAvailable checks those).
        Pro = a sku that starts with 'Pro' or 'Trial' as a word: Pro, Pro-Business, Pro Enterprise, Pro-DesignPartner,
        pro-single-tenant, Trial. MSP = a sku naming 'msp' as a word (Pro-MSP, pro-msp). Anything else -- Community,
        the verifier's 'Core' for no licence, an empty sku -- is Community.
    #>
    param([AllowNull()]$License)
    if ($null -eq $License) { return 'Community' }
    $sku = "$($License.Sku)".Trim()
    if ($sku -match '(?i)(^|[^a-z])msp([^a-z]|$)') { return 'MSP' }
    if ($sku -match '(?i)^(pro|trial)([^a-z]|$)') { return 'Pro' }
    return 'Community'
}

function Test-SILicenceCoversFeature {
    <#
    .SYNOPSIS
        PURE. Does a licence that is ALREADY valid/grace and bound to this tenant cover this paid catalog entry?
        Returns @{ Allowed; Reason }. The edition decides; features[] only for an add-on (#510).
    #>
    param([AllowNull()]$License, [Parameter(Mandatory)][object]$Entry)
    $name = "$($Entry.Name)"
    if ([bool]$Entry.AddOn) {
        foreach ($f in @($License.Features | Where-Object { $_ })) {
            if ("$f".Trim() -ieq $name) { return [pscustomobject]@{ Allowed = $true; Reason = "the licence lists the add-on '$name'" } }
        }
        return [pscustomobject]@{ Allowed = $false; Reason = "'$name' is an add-on and the licence does not list it" }
    }
    $ed = Get-SILicenceEdition -License $License
    $need = if ("$($Entry.Edition)" -ieq 'MSP') { 'MSP' } else { 'Pro' }
    if ($ed -eq 'MSP' -or ($need -eq 'Pro' -and $ed -eq 'Pro')) {
        return [pscustomobject]@{ Allowed = $true; Reason = "the $ed edition covers '$name'" }
    }
    $skuText = "$($License.Sku)".Trim(); if (-not $skuText) { $skuText = 'none' }
    if ($need -eq 'MSP' -and $ed -eq 'Pro') { return [pscustomobject]@{ Allowed = $false; Reason = "'$name' is part of the MSP edition; this licence is $skuText" } }
    return [pscustomobject]@{ Allowed = $false; Reason = "the licence names no SecurityInsight Pro edition (sku $skuText)" }
}

function Get-SIFrameworkLicensePath {
    <#
    .SYNOPSIS
        The framework licence verifier for this install: SI's own copy first, then sync/ upward.
    .DESCRIPTION
        Returns $null when neither exists rather than throwing -- a free feature must still run.
    #>
    [CmdletBinding()] param([string]$StartPath)
    $own = [IO.Path]::Combine($PSScriptRoot, '_shared', 'AitLicense.ps1')
    if (-not "$StartPath".Trim() -and (Test-Path -LiteralPath $own)) { return $own }
    $p = if ("$StartPath".Trim()) { $StartPath } elseif ($PSScriptRoot) { $PSScriptRoot } else { (Get-Location).Path }
    for ($i = 0; $i -lt 6; $i++) {
        # [IO.Path]::Combine, not Join-Path: Join-Path throws on a missing drive.
        $cand = [IO.Path]::Combine($p, 'sync', '_AitLicense.ps1')
        if (Test-Path -LiteralPath $cand) { return $cand }
        $parent = Split-Path -Parent $p
        if (-not $parent -or $parent -eq $p) { break }
        $p = $parent
    }
    return $null
}

function ConvertFrom-SILicenseText {
    <# The secret holds the licence file as raw JSON or base64 of it. Returns the parsed document or $null. #>
    param([AllowNull()][string]$Text)
    if ([string]::IsNullOrWhiteSpace($Text)) { return $null }
    $t = $Text.Trim()
    if (-not $t.StartsWith('{')) {
        try { $t = [System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($t)).Trim() } catch { return $null }
    }
    try { return ($t | ConvertFrom-Json -ErrorAction Stop) } catch { return $null }
}

function Get-SILicenseSecretText {
    <# The SI-License secret, without the customer having to edit their config. Never throws. #>
    if ($global:SI_License) { return [string]$global:SI_License }
    # an internal install: the platform Key Vault (signed in by SecurityInsight itself -- auth/SI-PlatformConnect.ps1)
    if ($global:Context -and $global:KV_HighPriv_KeyVaultName) {
        try {
            if (-not (Get-Command -Name Get-SIPlatformSecret -ErrorAction SilentlyContinue)) { . ([IO.Path]::Combine((Split-Path -Parent $PSScriptRoot), 'auth', 'SI-PlatformConnect.ps1')) }
            return [string](Get-SIPlatformSecret -Context $global:Context -Name 'SI-License' -AsPlainText -ErrorAction Stop)
        } catch { }
    }
    # The vault is resolved the way every other SI component resolves it (#173): SI_KeyVaultName, then the
    # 2.2.x name SpnKeyVaultName, ... -- an upgraded install carrying only the older name was otherwise
    # "unlicensed" while its licence sat in the vault it already uses for its SPN secret.
    if (-not (Get-Command -Name Get-SIVaultName -ErrorAction SilentlyContinue)) {
        $vaultHelper = [IO.Path]::Combine((Split-Path -Parent $PSScriptRoot), 'auth', 'Get-SIVaultName.ps1')
        if (Test-Path -LiteralPath $vaultHelper) { . $vaultHelper }
    }
    $vault = $null
    if (Get-Command -Name Get-SIVaultName -ErrorAction SilentlyContinue) { try { $vault = Get-SIVaultName -AllowMissing } catch { } }
    elseif ($global:SI_KeyVaultName) { $vault = [string]$global:SI_KeyVaultName }
    if ($vault) {
        if (-not (Get-Command -Name Get-SIKvSecret -ErrorAction SilentlyContinue)) {
            $kvHelper = [IO.Path]::Combine((Split-Path -Parent $PSScriptRoot), 'auth', 'Get-SIKvSecret.ps1')
            if (Test-Path -LiteralPath $kvHelper) { . $kvHelper }
        }
        if (Get-Command -Name Get-SIKvSecret -ErrorAction SilentlyContinue) {
            try { return [string](Get-SIKvSecret -VaultName $vault -SecretName 'SI-License') } catch { }
        }
    }
    return $null
}

# Load the framework verifier ONCE, at file scope, so its functions outlive any one call. (Dot-sourcing it
# inside a function defines them in that function's scope, and they vanish when it returns.) Loading the
# verifier's CODE is not consulting a licence: a free feature still never reads one.
$script:SIFrameworkLicensePath = Get-SIFrameworkLicensePath
if ($script:SIFrameworkLicensePath) { . $script:SIFrameworkLicensePath }

$script:SILicenseCache  = $null
$script:SILicenseWarned = @{}

# Framework LICENCE-DIMENSION (owner 2026-10-08): Pro has two dimensions, decided by the SIGNED licence -- Pro Business =
# the payload carries a `limits` object (SecurityInsight reads `devices`), Pro Enterprise = no `limits`. Community has no
# limits. A limit is a WARNING, never a stop: nothing here gates a feature or a run (the web app shows the banner).
function ConvertTo-SILicenceLimits {
    <#
        PURE. The payload's `limits` value -> an ordered map name (lower-case) -> whole number, or $null when it is not an
        object (absent / null / text / a number = no limits = Pro Enterprise). A value that is not a whole number is dropped,
        never guessed; an empty object stays an empty map (the licence IS Business, without a SecurityInsight limit).
    #>
    param([AllowNull()]$Value)
    if ($null -eq $Value -or $Value -isnot [System.Management.Automation.PSCustomObject]) { return $null }
    $m = [ordered]@{}
    foreach ($p in $Value.PSObject.Properties) {
        $v = $p.Value
        if (($v -is [int] -or $v -is [long]) -and $v -ge 0 -and $v -le [int]::MaxValue) { $m[$p.Name.ToLowerInvariant()] = [int]$v }
    }
    return $m
}

function Get-SILicenceLimitsOf {
    <#
        The limits of a VERIFIED licence, read ONLY from its signed payload bytes (payloadB64): a `limits` on the outer
        document is not signed and is never read. $null for a licence that did not verify, or that names no limits.
    #>
    param([AllowNull()]$Document, [AllowNull()]$License)
    if ($null -eq $Document -or $null -eq $License) { return $null }
    if ("$($License.Status)" -notin @('Valid', 'Grace', 'NotYetValid', 'Expired')) { return $null }
    try {
        $p = [System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String("$($Document.payloadB64)")) | ConvertFrom-Json -ErrorAction Stop
        if ("$($p.licenseId)" -ne "$($License.LicenseId)") { return $null }
        if ($p.PSObject.Properties.Name -contains 'limits') { return (ConvertTo-SILicenceLimits -Value $p.limits) }
    } catch { }
    return $null
}

function Get-SILicenceDimension {
    <# PURE. 'Pro Business' | 'Pro Enterprise' | 'Community' for a licence: Pro while it is valid or in grace. #>
    param([AllowNull()]$License)
    if ($null -eq $License -or "$($License.Status)" -notin @('Valid', 'Grace')) { return 'Community' }
    if ((Get-SILicenceEdition -License $License) -eq 'Community') { return 'Community' }   # #510: the sku names the edition
    if ($License.PSObject.Properties['Limits'] -and $null -ne $License.Limits) { return 'Pro Business' }
    return 'Pro Enterprise'
}

function Get-SILicense {
    <#
    .SYNOPSIS
        This install's licence status (cached per process): Key Vault secret first, then config\.
        Always a status object (Missing / Invalid / NotYetValid / Valid / Grace / Expired), never a throw.
    #>
    [CmdletBinding()]
    param(
        [AllowNull()][string]$SecretText,          # tests inject; absent = read the real sources
        [AllowNull()][string]$LicenseDirectory,    # tests inject; absent = the solution's config\
        [AllowNull()][string[]]$TrustedCertsB64,   # tests inject a throwaway signer
        [AllowNull()][object]$Now,
        [switch]$Refresh
    )
    $injected = $PSBoundParameters.ContainsKey('SecretText') -or $PSBoundParameters.ContainsKey('LicenseDirectory') -or
                $PSBoundParameters.ContainsKey('TrustedCertsB64') -or $PSBoundParameters.ContainsKey('Now')
    if ($script:SILicenseCache -and -not $Refresh -and -not $injected) { return $script:SILicenseCache }

    if (-not (Get-Command -Name Resolve-AitLicenseStatus -ErrorAction SilentlyContinue)) {
        return [pscustomobject]@{ Status = 'Missing'; Reason = 'the framework licence verifier is not installed'; Customer = ''; Features = @(); TenantIds = @(); Source = 'none'; Limits = $null }
    }

    $text = if ($PSBoundParameters.ContainsKey('SecretText')) { $SecretText } else { Get-SILicenseSecretText }
    if (-not [string]::IsNullOrWhiteSpace($text)) {
        $doc = ConvertFrom-SILicenseText -Text $text
        $lic = Resolve-AitLicenseStatus -Document $doc -TrustedCertsB64 $TrustedCertsB64 -Now $Now
        if ($null -eq $doc) { $lic.Status = 'Invalid'; $lic.Reason = 'the SI-License secret is neither licence JSON nor base64 of it' }
        Add-Member -InputObject $lic -NotePropertyName Source -NotePropertyValue 'Key Vault secret SI-License' -Force
        Add-Member -InputObject $lic -NotePropertyName Limits -NotePropertyValue (Get-SILicenceLimitsOf -Document $doc -License $lic) -Force
    } else {
        $dir = if ("$LicenseDirectory".Trim()) { $LicenseDirectory } else { [IO.Path]::Combine((Split-Path -Parent $PSScriptRoot), 'config') }
        $lic = Get-AitLicense -Directory $dir -TrustedCertsB64 $TrustedCertsB64 -Now $Now
        Add-Member -InputObject $lic -NotePropertyName Source -NotePropertyValue $(if ($lic.Path) { "file $($lic.Path)" } else { 'none' }) -Force
        # the file is read again for its limits -- and verified again, so a file swapped in between gives none
        $limits = $null
        if ($lic.Path) {
            try {
                $fdoc = Get-Content -LiteralPath $lic.Path -Raw -Encoding UTF8 | ConvertFrom-Json -ErrorAction Stop
                $again = Resolve-AitLicenseStatus -Document $fdoc -TrustedCertsB64 $TrustedCertsB64 -Now $Now
                if ($again.Status -eq $lic.Status) { $limits = Get-SILicenceLimitsOf -Document $fdoc -License $again }
            } catch { $limits = $null }
        }
        Add-Member -InputObject $lic -NotePropertyName Limits -NotePropertyValue $limits -Force
    }
    if (-not $injected) { $script:SILicenseCache = $lic }
    return $lic
}

function Get-SIRunTenantId {
    # #232 (operator: "validate license against the tenant so license can not be copied to other tenants" -- "must also
    # work if customer use spn"). A MANAGED IDENTITY's token always comes from its home tenant, so the tenant is the
    # 'tid' of the identity's own token (recorded by Get-SIManagedIdentityToken), never a configured value the customer
    # controls. Unprovable = a value no licence names, so a tenant-bound licence fails CLOSED.
    # An SPN's token is issued by the configured tenant, so for an SPN the configured tenant IS where the engine runs.
    if ([bool]$global:SI_UseManagedIdentity) {
        if (-not $global:SI_IdentityTokenTenantId -and (Get-Command -Name Get-SIManagedIdentityToken -ErrorAction SilentlyContinue)) {
            try { $null = Get-SIManagedIdentityToken -Resource 'https://management.azure.com/' } catch { }
        }
        if ($global:SI_IdentityTokenTenantId) { return [string]$global:SI_IdentityTokenTenantId }
        return 'unproven-managed-identity-tenant'
    }
    $t = @($global:SI_SPN_TenantId, $global:AzureTenantId, $global:TenantId) | Where-Object { $_ } | Select-Object -First 1
    if (-not $t) { try { $t = [string](Get-SIAzContext -ErrorAction Stop).Tenant.Id } catch { } }
    return [string]$t
}

function Test-SIFeatureAvailable {
    <#
    .SYNOPSIS
        THE call-site gate. May this feature run? Returns @{ Allowed; Edition; Reason }.
    .DESCRIPTION
        🔒 ORDER IS THE CONTRACT, and it is asserted in tests:
          1. FREE feature          -> allowed IMMEDIATELY. No licence is loaded, looked for, or consulted.
          2. paid, -Enforce $false -> allowed (TESTS ONLY -- production has no such switch).
          3. paid                  -> the framework verifier gives the status and the tenant binding (valid or
                                      grace, bound to this tenant); then the EDITION the sku names decides
                                      (§12.6a, #510): a Pro edition runs every Pro entry, current and future,
                                      whatever features[] says. features[] counts only for an AddOn entry.
        Grace runs, with one warning per feature per process.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Feature,
        [Parameter()][AllowNull()][string]$TenantId,
        [Parameter()][AllowNull()][string]$LicenseDirectory,
        [Parameter()][AllowNull()][object]$License,
        [Parameter()][AllowNull()][object]$Enforce
    )

    # 1. FREE -- return before anything licence-shaped happens.
    if (-not (Test-SIFeatureIsPaid -Feature $Feature)) {
        return [pscustomobject]@{ Allowed = $true; Edition = 'Free'; Reason = "'$Feature' is a free feature -- no licence is required or consulted" }
    }
    if ($null -ne $Enforce -and -not [bool]$Enforce) {
        return [pscustomobject]@{ Allowed = $true; Edition = 'Pro'; Reason = "enforcement is OFF for this call -- '$Feature' runs unlicensed" }
    }

    if ($null -eq $License) {
        $License = if ("$LicenseDirectory".Trim()) { Get-SILicense -LicenseDirectory $LicenseDirectory -SecretText '' } else { Get-SILicense }
    }
    if (-not (Get-Command -Name Test-AitLicenseTenant -ErrorAction SilentlyContinue)) {
        return [pscustomobject]@{ Allowed = $false; Edition = 'Pro'; Reason = "the framework licence verifier is not installed -- cannot establish entitlement for '$Feature'" }
    }
    if (-not "$TenantId".Trim()) { $TenantId = Get-SIRunTenantId }
    # the verifier's status + tenant binding, then the edition (never features[] for an edition feature -- #510)
    if ($null -eq $License -or "$($License.Status)" -notin @('Valid', 'Grace')) {
        $st = if ($License) { "$($License.Status)" } else { 'Missing' }
        $res = [pscustomobject]@{ Allowed = $false; Reason = "no entitlement: licence status is $st" }
    } elseif (-not (Test-AitLicenseTenant -License $License -TenantId $TenantId)) {
        $res = [pscustomobject]@{ Allowed = $false; Reason = "licence '$($License.Customer)' is not valid for tenant $TenantId" }
    } else {
        $entry = $script:SIFeatureCatalog | Where-Object { "$($_.Name)" -ieq "$Feature".Trim() } | Select-Object -First 1
        $res = Test-SILicenceCoversFeature -License $License -Entry $entry
    }
    if ($res.Allowed -and "$($License.Status)" -eq 'Grace' -and -not $script:SILicenseWarned[$Feature]) {
        $script:SILicenseWarned[$Feature] = $true
        Write-Warning ("Your SecurityInsight Pro licence {0}. '{1}' keeps running until the grace period ends." -f $License.Reason, $Feature)
    }
    return [pscustomobject]@{ Allowed = [bool]$res.Allowed; Edition = 'Pro'; Reason = "$($res.Reason)" }
}

function Get-SIEdition {
    <# 'Pro' when the licence entitles any paid EDITION feature for this tenant, else 'Community'. An add-on alone (#510)
       does not make an install Pro. #>
    param([AllowNull()][object]$License, [AllowNull()][string]$TenantId)
    foreach ($f in @($script:SIFeatureCatalog | Where-Object { -not [bool]$_.AddOn })) {
        if ((Test-SIFeatureAvailable -Feature $f.Name -License $License -TenantId $TenantId).Allowed) { return 'Pro' }
    }
    return 'Community'
}

function Assert-SIFeatureOrSkip {
    <#
    .SYNOPSIS
        The one call a paid engine makes at its start. $true = run. $false = one plain line saying the feature
        is part of SecurityInsight Pro and why it did not run; the engine then ends successfully WITHOUT
        producing output, so nothing downstream reads an empty result as "everything was resolved".
    #>
    param([Parameter(Mandatory)][string]$Feature, [AllowNull()][string]$TenantId)
    $r = Test-SIFeatureAvailable -Feature $Feature -TenantId $TenantId
    # #277: a licence in its grace period, or an installed licence that does not let a Pro job run, is a guard trip
    # (mail + telemetry, once per feature per process). No licence at all is the Community edition -- not a trip.
    if ((Get-Command -Name Send-SIGuardEvent -ErrorAction SilentlyContinue) -and (Test-SIFeatureIsPaid -Feature $Feature)) {
        if ($null -eq $script:SILicenseGuardSent) { $script:SILicenseGuardSent = @{} }
        if (-not $script:SILicenseGuardSent.ContainsKey($Feature)) {
            try {
                $lic = Get-SILicense 3>$null
                $st = if ($lic) { [string]$lic.Status } else { 'Missing' }
                if ($r.Allowed -and $st -eq 'Grace') {
                    $script:SILicenseGuardSent[$Feature] = $true
                    $null = Send-SIGuardEvent -GuardId 'licence.state.grace' -Outcome 'warning' -Subject $Feature -Detail ('The SecurityInsight Pro licence {0}.' -f $lic.Reason)
                } elseif (-not $r.Allowed -and $st -notin @('Missing', '')) {
                    $script:SILicenseGuardSent[$Feature] = $true
                    $null = Send-SIGuardEvent -GuardId 'licence.state.invalid' -Outcome 'refused' -Subject $Feature -Detail ('{0} did not run: {1}' -f $Feature, $r.Reason)
                }
            } catch { }
        }
    }
    if ($r.Allowed) { return $true }
    $entry = $script:SIFeatureCatalog | Where-Object { $_.Name -ieq $Feature } | Select-Object -First 1
    $what = $null
    if ($entry) { $what = $entry.Title; if (-not $what) { $what = $entry.Description } }
    if (-not $what) { $what = $Feature }
    Write-Host (" [INFO] {0} is part of SecurityInsight Pro and did not run ({1}). Nothing was changed or published; the previous results stay as they were." -f $what, $r.Reason)
    return $false
}

function Test-SILicenseForInstall {
    <#
      PURE (#173). May this licence be INSTALLED? Checked by setup\Set-SILicense.ps1 before anything is written,
      so a bad licence is refused at the desk instead of discovered as "Pro silently skipped" on the next run.
        * the signature/dates must verify: Valid, Grace (renew now) or NotYetValid (starts later) -- never
          Invalid / Expired / Missing;
        * it must unlock something (#510, framework §12.6a): its sku names a Pro edition, or it lists an add-on
          SecurityInsight has. features[] is informational for an edition licence, so a Pro licence with an empty or
          old features[] installs; feature ids SecurityInsight does not have are a NOTE, never a refusal. (The first
          licence issued granted 'SI.ServiceNow' / 'SI.Correlation' -- under the edition rule its sku Pro covers SI.)
        * when it is bound to tenants and the tenant is known, this tenant must be one of them.
      Returns @{ Ok; Problems; Notes; Edition; Summary }.
    #>
    param(
        [Parameter(Mandatory)][object]$License,          # Get-SILicense / Resolve-AitLicenseStatus output
        [AllowEmptyCollection()][string[]]$KnownFeatures = @(),
        [AllowNull()][string]$TenantId
    )
    $problems = New-Object System.Collections.Generic.List[string]
    $notes = New-Object System.Collections.Generic.List[string]
    $st = "$($License.Status)"
    if ($st -notin 'Valid', 'Grace', 'NotYetValid') { $problems.Add(("the licence does not verify: {0} ({1})" -f $st, $License.Reason)) }
    $feats = @($License.Features | Where-Object { $_ } | ForEach-Object { "$_".Trim() })
    $edition = Get-SILicenceEdition -License $License
    $addOns = @($script:SIFeatureCatalog | Where-Object { [bool]$_.AddOn } | ForEach-Object { "$($_.Name)" })
    $listedAddOns = @($feats | Where-Object { $addOns -contains $_ })
    if ($edition -eq 'Community' -and -not $listedAddOns.Count) {
        $skuText = "$($License.Sku)".Trim(); if (-not $skuText) { $skuText = 'none' }
        $problems.Add(("the licence names no SecurityInsight Pro edition (sku {0}) and lists no add-on, so it unlocks nothing" -f $skuText))
    }
    $unknown = @($feats | Where-Object { $_ -ne '*' -and ($KnownFeatures -notcontains $_) })
    if ($unknown.Count) { $notes.Add(("features[] names ids SecurityInsight does not have: {0} -- informational only, the edition decides" -f ($unknown -join ', '))) }
    $ids = @($License.TenantIds | Where-Object { $_ })
    if ($ids.Count -and "$TenantId".Trim() -and -not (@($ids | Where-Object { "$_".Trim() -ieq "$TenantId".Trim() }).Count)) {
        $problems.Add(("it is bound to tenant(s) {0}, not to this tenant {1}" -f ($ids -join ', '), $TenantId))
    }
    $summary = "{0} -- {1}; edition: {2}; features: {3}; tenants: {4}" -f $License.Customer, $License.Reason, $edition, $(if ($feats.Count) { $feats -join ', ' } else { 'none listed' }), $(if ($ids.Count) { $ids -join ', ' } else { 'any' })
    [pscustomobject]@{ Ok = ($problems.Count -eq 0); Problems = $problems.ToArray(); Notes = $notes.ToArray(); Edition = $edition; Summary = $summary }
}
