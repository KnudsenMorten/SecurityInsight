#Requires -Version 5.1
<#
    Get-SIRiskFactors.ps1

    Profile-time derivation of risk-relevant boolean / count flags. Moves
    "did this OS appear on the legacy list?" / "is this SPN cred about to
    expire?" / "does this NSG allow internet on 3389?" logic OUT of every
    Risk Analysis kusto query and INTO the row builder. The query then
    just reads the flat column.

    Why move it here:
      * one canonical definition (no drift across 50 queries)
      * faster queries (no parse_json on hot path)
      * reusable in YAML rules + dashboards + workbooks
      * customer can override individual derivations via a -RiskFactorOverride
        hashtable on $global:SI_*  (TODO: hook in )

    All functions:
      * accept a $Record (post-Classify staging shape)
      * return $true / $false / [int] / [string]
      * never throw -- bad input -> $false / 0 / null
      * are PURE (no side effects, safe to call N times per row)

    Output columns surfaced:
      ENDPOINT  UnsupportedOSDetected, UnsupportedOSReason, DefenderAvOutOfDate,
                IsStaleAsset, DaysInactive, IsCmdbOrphan
      IDENTITY  IsOrphanSPN, HasExpiringCredentials, CredentialExpiryDays,
                HasNoMfa, HasPasswordNeverExpires, IsExternalIdentity,
                IsHighRiskPermissionGrant, DaysInactive, IsCmdbOrphan
      AZURE     HasOpenAdminPort, IsPubliclyExposed, HasNoSoftDelete,
                UnencryptedTraffic, IsCmdbOrphan

    Cross-engine link columns (LinkedAzureResourceId, LinkedEndpointDeviceId,
    IsCrossEngineAsset) live on the row already from Collect; this file just
    ensures they're emitted when the source data is present.
#>

# ----------------------------------------------------------------------------
# Shared helpers
# ----------------------------------------------------------------------------

function Get-SIDaysInactive {
    <# Days since the most-recent of EgLastSeen / LastSeen / LastSignInDateTime
       on the asset. Returns 9999 when no signal is available (sortable
       sentinel for "never seen"). #>
    param([Parameter(Mandatory)]$Record)
    $candidates = @(
        Get-SIRecordValue -Record $Record -Name 'LastSignInDateTime'
        Get-SIRecordValue -Record $Record -Name 'LastSeen'
        Get-SIRecordValue -Record $Record -Name 'EgLastSeen'
        Get-SIRecordValue -Record $Record -Name 'MDE_LastSeen'
        Get-SIRecordValue -Record $Record -Name 'EG_LastSeen'
    )
    $best = $null
    foreach ($c in $candidates) {
        if ([string]::IsNullOrWhiteSpace([string]$c)) { continue }
        try {
            $dt = [DateTimeOffset]::Parse([string]$c).UtcDateTime
            if ($null -eq $best -or $dt -gt $best) { $best = $dt }
        } catch {}
    }
    if ($null -eq $best) { return 9999 }
    return [int]([Math]::Max(0, ([datetime]::UtcNow - $best).TotalDays))
}

function Get-SIRecordValue {
    <# Record / Verdict / Metadata top-level field reader -- shape-tolerant.
       Walks $Record.<Name>, $Record.Verdict.<Name>, $Record.Metadata.<Name>. #>
    param([Parameter(Mandatory)]$Record, [Parameter(Mandatory)][string]$Name)
    if ($null -eq $Record) { return $null }
    foreach ($holder in @($Record, $Record.Verdict, $Record.Metadata)) {
        if ($null -eq $holder) { continue }
        if ($holder -is [System.Collections.IDictionary]) {
            if ($holder.Contains($Name)) {
                $v = $holder[$Name]
                if ($null -ne $v -and "$v" -ne '') { return $v }
            }
        } else {
            $p = $holder.PSObject.Properties[$Name]
            if ($p -and $null -ne $p.Value -and "$($p.Value)" -ne '') { return $p.Value }
        }
    }
    return $null
}

# ----------------------------------------------------------------------------
# ENDPOINT derivations
# ----------------------------------------------------------------------------

# Legacy / out-of-support OS list. Update as Microsoft / distro vendors EOL releases.
$script:_SIUnsupportedOS = @{
    Windows = @(
        '(?i)^Windows7',     '(?i)^Windows8($|\.)','(?i)^Windows8\.1',
        '(?i)WindowsServer2003','(?i)WindowsServer2008','(?i)WindowsServer2012'
    )
    LinuxLiterals = @(
        'CentOS 6','CentOS 7','RHEL 6','RHEL 7','SLES 11','SLES 12',
        'Ubuntu 14.04','Ubuntu 16.04','Ubuntu 18.04','Debian 8','Debian 9','Debian 10',
        'Fedora 30','Fedora 31','Fedora 32','Fedora 33','Fedora 34','Fedora 35'
    )
    macOSMajorBelow = 13   # macOS 12 (Monterey) and earlier are out of vendor security support
}

function Test-SIEndpointUnsupportedOS {
    <# Returns @{ Unsupported=$true|$false; Reason='<vendor-EOL-text>' or '' } #>
    param([Parameter(Mandatory)]$Record)
    $os    = [string](Get-SIRecordValue -Record $Record -Name 'OsPlatform')
    if (-not $os) { $os = [string](Get-SIRecordValue -Record $Record -Name 'MDE_OSPlatform') }
    if (-not $os) { $os = [string](Get-SIRecordValue -Record $Record -Name 'EG_OS') }
    if (-not $os) { $os = [string](Get-SIRecordValue -Record $Record -Name 'ENTRA_OS') }
    $ver   = [string](Get-SIRecordValue -Record $Record -Name 'OsVersion')
    if (-not $ver) { $ver = [string](Get-SIRecordValue -Record $Record -Name 'MDE_OSVersion') }
    if (-not $ver) { $ver = [string](Get-SIRecordValue -Record $Record -Name 'EG_OSVersion') }

    $combined = ($os + ' ' + $ver).Trim()
    if ([string]::IsNullOrWhiteSpace($combined)) { return @{ Unsupported = $false; Reason = '' } }

    foreach ($pat in $script:_SIUnsupportedOS.Windows) {
        if ($combined -match $pat) { return @{ Unsupported = $true; Reason = ('Windows EOL: ' + $combined) } }
    }
    foreach ($lit in $script:_SIUnsupportedOS.LinuxLiterals) {
        if ($combined -like ('*' + $lit + '*')) { return @{ Unsupported = $true; Reason = ('Linux EOL: ' + $lit) } }
    }
    if ($os -match '(?i)^macOS|^OSX|^Mac\sOS') {
        if ($ver -match '^(\d+)') {
            $major = [int]$matches[1]
            if ($major -gt 0 -and $major -lt $script:_SIUnsupportedOS.macOSMajorBelow) {
                return @{ Unsupported = $true; Reason = ('macOS EOL: ' + $combined) }
            }
        }
    }
    return @{ Unsupported = $false; Reason = '' }
}

function Test-SIDefenderAvOutOfDate {
    param([Parameter(Mandatory)]$Record)
    $st = [string](Get-SIRecordValue -Record $Record -Name 'DefenderAvStatus')
    if (-not $st) { $st = [string](Get-SIRecordValue -Record $Record -Name 'MDE_DefenderAvStatus') }
    if (-not $st) { return $false }
    return ($st -inotmatch '^(Updated|Up\s*to\s*date|GoodHealth|HealthyAndUpToDate)$')
}

function Test-SIEndpointExcludedByTag {
    <# Returns $true when any of the device's EG-supplied tag arrays contains
       the '--Excluded--SI' marker. Operator-driven opt-out -- a device tagged
       with that marker stays out of RA reports without code or query edits.
       Reads EG manual + dynamic tag arrays (and the EG tags.tags fallback);
       tolerates string-array, semicolon-joined-string, or single-string shapes. #>
    param([Parameter(Mandatory)]$Record)
    $marker = '--Excluded--SI'
    foreach ($field in @('EG_DeviceManualTags','EG_DeviceDynamicTags','EG_Tags','DeviceManualTags','DeviceDynamicTags')) {
        $val = Get-SIRecordValue -Record $Record -Name $field
        if ($null -eq $val) { continue }
        $items = @()
        if     ($val -is [System.Array]) { $items = @($val) }
        elseif ($val -is [string])       { $items = @($val -split ';') }
        else                             { $items = @([string]$val) }
        foreach ($item in $items) {
            if ([string]$item -like ('*' + $marker + '*')) { return $true }
        }
    }
    return $false
}

function Get-SIEndpointRiskFactors {
    <# Returns ordered hashtable of all endpoint-engine derived risk columns.
       Caller stamps each entry on the row. #>
    param([Parameter(Mandatory)]$Record)
    $unsupported = Test-SIEndpointUnsupportedOS -Record $Record
    $days        = Get-SIDaysInactive -Record $Record
    # simplified -- old form ($days >= 30 -and $days < 9999) -or $days -eq 9999
    # was equivalent to just $days >= 30 since 9999 is the "never seen" sentinel.
    # Threshold 30d is aggressive; consider raising to 60-90 if false-positive rate is too high.
    $stale       = ($days -ge 30)

    $CmdbMatchPhase = [string](Get-SIRecordValue -Record $Record -Name 'CmdbMatchPhase')
    $tierVal    = Get-SIRecordValue -Record $Record -Name 'Tier'
    $tier       = if ($null -ne $tierVal) { try { [int]$tierVal } catch { 3 } } else { 3 }
    $cmdbOrphan = ($CmdbMatchPhase -eq 'orphan' -and $tier -le 1)

    $avOutOfDate = Test-SIDefenderAvOutOfDate -Record $Record

    # final: dropped IsTenantTakeoverRisk -- Tier 0 designation
    # already implies tenant-takeover risk (rules / AI promote DC / ADCS /
    # EntraSync to T0 anyway, and customer-promoted T0 is crown-jewel by
    # definition). The RA weighted-score formula uses Tier directly.

    # dropped RiskFactorCount -- queries derive the count via
    # sum-of-iffs on the same risk-bool fields they already display.
    [ordered]@{
        UnsupportedOSDetected = [bool]$unsupported.Unsupported
        UnsupportedOSReason   = [string]$unsupported.Reason
        DefenderAvOutOfDate   = [bool]$avOutOfDate
        DaysInactive          = [int64]$days   # Long, not Int -- matches existing DCR transform output type (avoids InvalidTransformOutput on schema migration)
        IsStaleAsset          = [bool]$stale
        IsCmdbOrphan          = [bool]$cmdbOrphan
        IsExcludedByTag       = [bool](Test-SIEndpointExcludedByTag -Record $Record)
    }
}

# ----------------------------------------------------------------------------
# IDENTITY derivations
# ----------------------------------------------------------------------------

$script:_SIHighRiskAppPerms = @(
    'Directory.ReadWrite.All','RoleManagement.ReadWrite.Directory',
    'Application.ReadWrite.All','AppRoleAssignment.ReadWrite.All',
    'Mail.ReadWrite','Mail.Send','Files.ReadWrite.All',
    'User.ReadWrite.All','Group.ReadWrite.All',
    'PrivilegedAccess.ReadWrite.AzureAD','Sites.FullControl.All',
    'DeviceManagementConfiguration.ReadWrite.All',
    'IdentityRiskyUser.ReadWrite.All'
)

function Get-SIIdentityRiskFactors {
    param([Parameter(Mandatory)]$Record)
    $upn      = [string](Get-SIRecordValue -Record $Record -Name 'Upn')
    $isSpn    = [bool](Get-SIRecordValue -Record $Record -Name 'IsServicePrincipal')
    $owner    = [string](Get-SIRecordValue -Record $Record -Name 'Owner')
    $mfaState = [string](Get-SIRecordValue -Record $Record -Name 'MfaState')
    $pwdPolicy= [string](Get-SIRecordValue -Record $Record -Name 'PasswordPolicies')

    $isExternal = ($upn -match '#EXT#@' -or $upn -like '*#ext#*')
    $isOrphanSpn = ($isSpn -and [string]::IsNullOrWhiteSpace($owner))
    # precedence bug fix. Was: A -or (B -and C) which made
    # the SPN-exclusion guard ONLY apply to the empty-mfaState branch -- so
    # an SPN with mfaState="notCapable" wrongly got HasNoMfa=true. Now the
    # SPN guard wraps both conditions: not-an-SPN AND (no MFA registered).
    $hasNoMfa = ((-not $isSpn) -and (
        $mfaState -match '(?i)none|notRegistered|notCapable' -or
        [string]::IsNullOrWhiteSpace($mfaState)))
    $hasPwdNeverExpires = ($pwdPolicy -match '(?i)DisablePasswordExpiration|DisableExpiration')

    # Credential expiry (days). SPNs publish keyCredentials / passwordCredentials
    # with EndDateTime values; profiling stores the closest expiry as
    # NextCredentialExpiryDateTime (when set upstream).
    $nextExpiry = [string](Get-SIRecordValue -Record $Record -Name 'NextCredentialExpiryDateTime')
    $credDays = $null
    if ($nextExpiry) {
        try { $credDays = [int](([DateTimeOffset]::Parse($nextExpiry).UtcDateTime - [datetime]::UtcNow).TotalDays) } catch {}
    }
    $hasExpiringCreds = ($null -ne $credDays -and $credDays -ge 0 -and $credDays -le 30)

    # High-risk permissions — intersect EntraAppPermissions_Application (SPN)
    # OR EntraRoles_Permanent (user/SPN) with the high-risk list.
    $isHighRisk = $false
    foreach ($listField in @('EntraAppPermissions_Application','EntraRoles_Permanent','EntraRoles_Eligible')) {
        $raw = Get-SIRecordValue -Record $Record -Name $listField
        if (-not $raw) { continue }
        $arr = if ($raw -is [string]) { try { $raw | ConvertFrom-Json } catch { @($raw -split '[,;]\s*') } } else { @($raw) }
        foreach ($x in $arr) {
            if ([string]$x -in $script:_SIHighRiskAppPerms) { $isHighRisk = $true; break }
        }
        if ($isHighRisk) { break }
    }

    $days = Get-SIDaysInactive -Record $Record

    $CmdbMatchPhase = [string](Get-SIRecordValue -Record $Record -Name 'CmdbMatchPhase')
    $tierVal    = Get-SIRecordValue -Record $Record -Name 'Tier'
    $tier       = if ($null -ne $tierVal) { try { [int]$tierVal } catch { 3 } } else { 3 }
    $cmdbOrphan = ($CmdbMatchPhase -eq 'orphan' -and $tier -le 1)

    # final: dropped IsTenantTakeoverRisk -- Tier 0 implies it.
    # Identity catalog already promotes Global Admin, Privileged Role Admin,
    # Hybrid Sync, etc. to Tier 0; the RA weighted-score uses Tier directly.

    # dropped RiskFactorCount -- queries derive the count via
    # sum-of-iffs on the same risk-bool fields they already display.
    [ordered]@{
        IsOrphanSPN              = [bool]$isOrphanSpn
        HasExpiringCredentials   = [bool]$hasExpiringCreds
        CredentialExpiryDays     = if ($null -ne $credDays) { [int]$credDays } else { $null }
        HasNoMfa                 = [bool]$hasNoMfa
        HasPasswordNeverExpires  = [bool]$hasPwdNeverExpires
        IsExternalIdentity       = [bool]$isExternal
        IsHighRiskPermissionGrant= [bool]$isHighRisk
        DaysInactive             = [int64]$days   # Long, not Int -- matches existing DCR transform output type
        IsCmdbOrphan             = [bool]$cmdbOrphan
    }
}

# ----------------------------------------------------------------------------
# AZURE derivations
# ----------------------------------------------------------------------------

function Test-SIAzurePubliclyExposed {
    <# Type-aware: each public-access posture flag has a different column
       depending on the Azure resource type. Returns $true if ANY of them
       indicates the resource is reachable from the public internet. #>
    param([Parameter(Mandatory)]$Record)
    foreach ($f in @(
        'AllowBlobPublicAccess','StPublicNetworkAccess','AcrPublicNetworkAccess',
        'AoaiPublicNetworkAccess','CogPublicNetworkAccess','FuncPublicNetworkAccess',
        'KvPublicNetworkAccess','PublicNetworkAccess','SqlSrvPublicNetworkAccess',
        'StPublicNetworkAccess','WebPublicNetworkAccess','PipAddress',
        'EG_FuncAllowsPublicAccess','EG_WebAllowsPublicAccess'
    )) {
        $v = Get-SIRecordValue -Record $Record -Name $f
        if ($null -eq $v) { continue }
        if ($v -is [bool]) { if ($v) { return $true }; continue }
        $s = [string]$v
        if ($s -ieq 'true' -or $s -ieq 'enabled' -or ($s -match '^\d+\.\d+\.\d+\.\d+$')) { return $true }
    }
    return $false
}

function Test-SIAzureNoSoftDelete {
    param([Parameter(Mandatory)]$Record)
    $rt = [string](Get-SIRecordValue -Record $Record -Name 'ResourceType')
    if ($rt -inotmatch 'keyvault') { return $false }
    foreach ($f in @('KvEnableSoftDelete','EnableSoftDelete')) {
        $v = Get-SIRecordValue -Record $Record -Name $f
        if ($null -ne $v) {
            if ($v -is [bool]) { return -not $v }
            return ([string]$v -ieq 'false')
        }
    }
    return $false   # field not stamped == unknown, not a finding
}

function Test-SIAzureUnencryptedTraffic {
    param([Parameter(Mandatory)]$Record)
    foreach ($f in @('AppHttpAllowed','SupportsHttpsTrafficOnly','StSupportsHttpsTrafficOnly','FuncHttpsOnly','WebHttpsOnly')) {
        $v = Get-SIRecordValue -Record $Record -Name $f
        if ($null -eq $v) { continue }
        $b = if ($v -is [bool]) { $v } else { ([string]$v -ieq 'true') }
        # AppHttpAllowed is "true means BAD" -- HTTPS-only flags are "false means BAD"
        if ($f -eq 'AppHttpAllowed' -and $b)         { return $true }
        if ($f -ne 'AppHttpAllowed' -and -not $b)    { return $true }
    }
    return $false
}

function Test-SIAzureOpenAdminPort {
    <# True when the resource is an NSG that permits inbound traffic from
       Internet / 0.0.0.0/0 / Any source on a management port (22, 3389, 5985).
       Walks parsed AZ_PropertiesJson.securityRules[].properties for direction
       == Inbound, access == Allow, sourceAddressPrefix in {Internet, *,
       0.0.0.0/0}, and destinationPortRange overlapping 22|3389|5985. #>
    param([Parameter(Mandatory)]$Record)
    $rt = [string](Get-SIRecordValue -Record $Record -Name 'ResourceType')
    if ($rt -inotmatch 'networksecuritygroups') { return $false }
    $propsJson = [string](Get-SIRecordValue -Record $Record -Name 'AZ_PropertiesJson')
    if (-not $propsJson) { return $false }
    try { $p = $propsJson | ConvertFrom-Json -ErrorAction Stop } catch { return $false }
    $rules = @()
    if ($p.PSObject.Properties['securityRules'])        { $rules += @($p.securityRules) }
    if ($p.PSObject.Properties['defaultSecurityRules']) { $rules += @($p.defaultSecurityRules) }
    foreach ($r in $rules) {
        $rp = if ($r.PSObject.Properties['properties']) { $r.properties } else { $r }
        if ([string]$rp.access      -inotmatch '^Allow$')   { continue }
        if ([string]$rp.direction   -inotmatch '^Inbound$') { continue }
        $src = [string]$rp.sourceAddressPrefix
        if ($src -notin @('Internet','*','0.0.0.0/0')) { continue }
        $dst = [string]$rp.destinationPortRange
        if ($dst -in @('22','3389','5985','*')) { return $true }
        if ($dst -match '^(\d+)-(\d+)$') {
            $lo = [int]$matches[1]; $hi = [int]$matches[2]
            foreach ($p2 in @(22,3389,5985)) { if ($p2 -ge $lo -and $p2 -le $hi) { return $true } }
        }
    }
    return $false
}

function Get-SIAzureRiskFactors {
    param([Parameter(Mandatory)]$Record)
    $publicExposed = Test-SIAzurePubliclyExposed -Record $Record
    $noSoftDelete  = Test-SIAzureNoSoftDelete   -Record $Record
    $unencTraffic  = Test-SIAzureUnencryptedTraffic -Record $Record
    $openAdmin     = Test-SIAzureOpenAdminPort  -Record $Record

    $CmdbMatchPhase = [string](Get-SIRecordValue -Record $Record -Name 'CmdbMatchPhase')
    $tierVal    = Get-SIRecordValue -Record $Record -Name 'Tier'
    $tier       = if ($null -ne $tierVal) { try { [int]$tierVal } catch { 3 } } else { 3 }
    $cmdbOrphan = ($CmdbMatchPhase -eq 'orphan' -and $tier -le 1)

    # final: dropped IsTenantTakeoverRisk -- Tier 0 implies it.
    # KeyVault/ManagementGroups/PolicyDefinitions get promoted to T0 by the
    # azure rule catalog; the RA weighted-score uses Tier directly.

    # dropped RiskFactorCount -- queries derive the count via
    # sum-of-iffs on the same risk-bool fields they already display.
    [ordered]@{
        IsPubliclyExposed   = [bool]$publicExposed
        HasNoSoftDelete     = [bool]$noSoftDelete
        UnencryptedTraffic  = [bool]$unencTraffic
        HasOpenAdminPort    = [bool]$openAdmin
        IsCmdbOrphan        = [bool]$cmdbOrphan
    }
}
