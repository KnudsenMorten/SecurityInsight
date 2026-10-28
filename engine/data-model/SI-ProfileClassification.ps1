#Requires -Version 5.1
<#
    SecurityInsight -- THE PROFILE TABLES' AssetType / AssetSubtype FROM THE ONE CLASSIFICATION (REQUIREMENTS #562).

    🔴 WHY THIS EXISTS. Measured live 2026-10-10 on the first ring: SI_Endpoint_Profile_CL carried AssetType = the
    Classify stage's free-text service type (the AI verdict, its error fallback 'Workstation', its budget fallback
    'Unknown', or a hostname/OS heuristic) -- half the devices Unknown, domain controllers and servers 'Workstation',
    switches and routers 'Unknown', AssetSubtype empty on every row. SI_Azure_Profile_CL carried the RAW ARM type
    ('microsoft.insights/datacollectionrules') or 'AzureResource'. The CI build meanwhile classified the same assets
    with data-model/classification.locked.json. Two vocabularies for one column.

    🔑 THE FIX: a profile row is turned into the SAME SI fields the CI build classifies (si_class, si_asset_type from the
    device type through the SAME value map, si_device_category, si_device_subtype, si_os_platform, si_device_roles,
    si_azure_resource_type) and run through the SAME engine (Invoke-SIAssetClassification over the merged templates,
    customer overrides included). AssetType = si_asset_type, AssetSubtype = si_asset_subtype. The raw values stay in
    their own columns (DeviceType / DeviceSubtype on endpoints, ResourceType on Azure). No vocabulary lives here.

    What the profile knows and the CI does not (and the reverse): the profile adds its own role detections (the
    asset-profiling rules in SIRules, e.g. MicrosoftSqlServer, ADDomainController) through the value map
    profile_rule_roles into si_device_roles; the CI adds Defender's software inventory and the SQL IaaS link. Both feed
    the same rows, so a SQL host reads Server / SQL Server in both wherever either source sees it.

    PowerShell 5.1: no ?. / ??, no ternary. Never throws: a classification that cannot run returns $null and the
    caller keeps its previous value.
#>

if (-not (Get-Command -Name Invoke-SIAssetClassification -ErrorAction SilentlyContinue)) { . (Join-Path $PSScriptRoot 'SI-Classification.ps1') }
if (-not (Get-Command -Name Get-SIValueMapResult -ErrorAction SilentlyContinue)) { . (Join-Path $PSScriptRoot 'SI-FieldMapper.ps1') }

# The ARM type inside an Exposure Graph node label ('microsoft.web/sites_webapp', 'azure-microsoft.cognitiveservices/...').
# The SAME expression the eg mapping applies to si_azure_resource_type (regex_extract), so both read one type.
$script:SIAzureResourceTypePattern = '(microsoft\.[a-z0-9]+/[a-z0-9/]+)'

function ConvertTo-SIAzureResourceTypeName {
    <# PURE. A resource type or an Exposure Graph node label -> the lower-case ARM type; '' when there is none. #>
    param([AllowNull()][AllowEmptyString()][string]$Type)
    if ([string]::IsNullOrWhiteSpace($Type)) { return '' }
    $m = [regex]::Match($Type.Trim().ToLowerInvariant(), $script:SIAzureResourceTypePattern)
    if ($m.Success) { return $m.Groups[1].Value }
    return ''
}

$script:SIProfileValueMapsCache = $null

function Get-SIProfileValueMaps {
    <# The merged value maps (shipped + customer), read once per process; $null when they cannot be read. #>
    param([string]$Root, [switch]$Refresh)
    if ($script:SIProfileValueMapsCache -and -not $Refresh -and -not $Root) { return $script:SIProfileValueMapsCache }
    try {
        if (-not (Get-Command -Name Get-SIDataModelTemplate -ErrorAction SilentlyContinue)) { . (Join-Path $PSScriptRoot 'SI-DataModelTemplates.ps1') }
        $r = Get-SIDataModelRoot $Root
        if (-not (Test-Path -LiteralPath (Join-Path $r 'value-maps.locked.json'))) { $r = Join-Path (Split-Path -Parent (Split-Path -Parent $PSScriptRoot)) 'data-model' }
        $maps = Get-SIItemValue ((Get-SIDataModelTemplate -Name 'value-maps' -Root $r -OverlayRoot $global:SI_DataModelOverlayRoot).Document) 'maps'
        if (-not $Root) { $script:SIProfileValueMapsCache = $maps }
        return $maps
    } catch { return $null }
}

function Get-SIProfileMappedValue {
    <# PURE. One value through a value map (enum:<map>); $null when the map has no answer. #>
    param($Maps, [string]$Map, $Value)
    if ($null -eq $Value -or [string]::IsNullOrWhiteSpace([string]$Value)) { return $null }
    $m = Get-SIItemValue $Maps $Map
    if ($null -eq $m) { return $null }
    $r = Get-SIValueMapResult -Map $m -Value $Value
    if ($r.Found -and $null -ne $r.Value) { return $r.Value }
    return $null
}

function ConvertTo-SIProfileValueList {
    <# PURE. A profile cell that may be a list, a JSON array text or one value -> a list of non-empty strings. #>
    param($Value)
    $out = New-Object System.Collections.Generic.List[string]
    if ($null -eq $Value) { return , $out.ToArray() }
    $v = $Value
    if ($v -is [string]) {
        $s = $v.Trim()
        if (-not $s) { return , $out.ToArray() }
        if ($s.StartsWith('[')) { try { $v = @($s | ConvertFrom-Json) } catch { $v = @($s) } } else { $v = @($s) }
    }
    if ($v -is [System.Collections.IDictionary]) { $v = @($v) }
    foreach ($x in @($v)) {
        if ($null -eq $x) { continue }
        if ($x -is [string]) { if ($x.Trim()) { $out.Add($x.Trim()) } }
        else {
            # a rule hit object: its RuleId
            $id = Get-SIItemValue $x 'RuleId'
            if ($null -ne $id) { if (([string]$id).Trim()) { $out.Add(([string]$id).Trim()) } } else { $out.Add([string]$x) }
        }
    }
    , $out.ToArray()
}

function ConvertTo-SIEndpointClassificationItem {
    <#
    .SYNOPSIS  PURE. An endpoint profile's source values -> the SI fields the classification rows read, through the same
               value maps as the mde / eg mappings (device_type, device_category, os_family, eg_device_roles) plus the
               profile's own role detections (profile_rule_roles over the SIRules rule ids). A value the profile does not
               carry is absent -- unknown, never guessed.
    #>
    param($Maps, [string]$DeviceType, [string]$DeviceCategory, [string]$DeviceSubtype, [string]$OsPlatform, $DeviceRoles,
          [bool]$IsDomainController, [bool]$IsExchangeServer, [bool]$IsAdfsServer, $RuleIds)
    $item = [ordered]@{ si_class = 'device' }
    $t = Get-SIProfileMappedValue $Maps 'device_type' $DeviceType; if ($null -ne $t) { $item['si_asset_type'] = [string]$t }
    $c = Get-SIProfileMappedValue $Maps 'device_category' $DeviceCategory; if ($null -ne $c) { $item['si_device_category'] = [string]$c }
    if (-not [string]::IsNullOrWhiteSpace($DeviceSubtype) -and $DeviceSubtype.Trim() -ne 'Unknown') { $item['si_device_subtype'] = $DeviceSubtype.Trim() }
    $o = Get-SIProfileMappedValue $Maps 'os_family' $OsPlatform; if ($null -ne $o) { $item['si_os_platform'] = [string]$o }
    $roles = New-Object System.Collections.Generic.List[string]
    foreach ($r in (ConvertTo-SIProfileValueList $DeviceRoles)) { $v = Get-SIProfileMappedValue $Maps 'eg_device_roles' $r; if ($v -and -not $roles.Contains([string]$v)) { $roles.Add([string]$v) } }
    if ($IsDomainController -and -not $roles.Contains('domain_controller')) { $roles.Add('domain_controller') }
    if ($IsExchangeServer -and -not $roles.Contains('exchange')) { $roles.Add('exchange') }
    if ($IsAdfsServer -and -not $roles.Contains('adfs')) { $roles.Add('adfs') }
    foreach ($r in (ConvertTo-SIProfileValueList $RuleIds)) { $v = Get-SIProfileMappedValue $Maps 'profile_rule_roles' $r; if ($v -and -not $roles.Contains([string]$v)) { $roles.Add([string]$v) } }
    if ($roles.Count) { $item['si_device_roles'] = [string[]]$roles.ToArray() }
    $item
}

function ConvertTo-SIAzureClassificationItem {
    <# PURE. An Azure profile's resource type (ARM type or Exposure Graph label) -> the SI fields the rows read. #>
    param([string]$ResourceType)
    $item = [ordered]@{ si_class = 'cloud_resource' }
    $rt = ConvertTo-SIAzureResourceTypeName $ResourceType
    if ($rt) {
        $item['si_azure_resource_type'] = $rt
        # the source type as the azure mapping gives it (the last segment), kept in si_asset_type_source
        $item['si_asset_type'] = @($rt.Split('/'))[-1]
    }
    $item
}

function ConvertTo-SIIdentityClassificationItem {
    <#
    .SYNOPSIS  PURE. An identity profile's Entra kind -> the SI fields the rows read, through the same value maps as the entra
               mapping (identity_type_user over userType, identity_type_sp over servicePrincipalType). The finer Classify
               labels (first-party / multi-tenant / disabled) stay in their own columns (IsFirstPartyMicrosoftSpn,
               IsThirdPartyMultiTenantSpn, AccountEnabled); the asset type is the dimension's.
    #>
    param($Maps, [string]$Kind, [string]$UserType, [string]$ServicePrincipalType)
    $item = [ordered]@{ si_class = 'identity' }
    $k = ([string]$Kind).Trim()
    $v = $null
    if ($k -eq 'ServicePrincipal') {
        $sp = $ServicePrincipalType; if ([string]::IsNullOrWhiteSpace($sp)) { $sp = 'Application' }
        $v = Get-SIProfileMappedValue $Maps 'identity_type_sp' $sp
    } elseif ($k -eq 'User' -or $k -eq '') {
        $u = $UserType; if ([string]::IsNullOrWhiteSpace($u)) { $u = 'Member' }
        $v = Get-SIProfileMappedValue $Maps 'identity_type_user' $u
    } else { $v = $k.ToLowerInvariant() }   # Group / ServiceAccount / Computer: the source kind, kept in si_asset_type_source
    if ($null -ne $v) { $item['si_asset_type'] = [string]$v }
    $item
}

function ConvertTo-SIPublicIpClassificationItem {
    <# PURE. A public IP profile row -> the SI fields the rows read (its class; the shodan mapping's class). #>
    [ordered]@{ si_class = 'public_ip' }
}

function Get-SIProfileAssetClassification {
    <#
    .SYNOPSIS  One profile item -> @{ Type; Subtype; Components; Rules } from the classification index (default: the
               cached merged templates). $null when there is no index or the classification fails -- never throws.
    #>
    param([Parameter(Mandatory)]$Item, $Index)
    try {
        if ($null -eq $Index) { $Index = Get-SIClassificationIndex }
        if ($null -eq $Index) { return $null }
        # the same fields classify the same way: one evaluation per distinct item per index (an estate repeats them --
        # many Azure resources share a handful of resource types)
        $ck = ((@($Item.Keys | ForEach-Object { [string]$_ } | Sort-Object) | ForEach-Object { '{0}={1}' -f $_, ((@($Item[$_]) | ForEach-Object { [string]$_ }) -join ';') }) -join '|')
        if ($null -eq $Index.PSObject.Properties['ProfileCache']) { $Index | Add-Member -NotePropertyName ProfileCache -NotePropertyValue @{} -Force }
        if ($Index.ProfileCache.ContainsKey($ck)) { return $Index.ProfileCache[$ck] }
        $ci = [ordered]@{}; foreach ($k in @($Item.Keys)) { $ci[[string]$k] = $Item[$k] }
        $null = Invoke-SIAssetClassification -Ci $ci -Index $Index -Context @{ Now = [datetime]::UtcNow }
        if (-not $ci.Contains('si_asset_type')) { return $null }
        $sub = ''; if ($ci.Contains('si_asset_subtype')) { $sub = [string]$ci['si_asset_subtype'] }
        $comp = @(); if ($ci.Contains('si_components')) { $comp = @($ci['si_components'] | ForEach-Object { [string]$_ }) }
        $res = @{ Type = [string]$ci['si_asset_type']; Subtype = $sub; Components = $comp; Rules = $ci['si_classified_by'] }
        if ($Index.ProfileCache.Count -ge 20000) { $Index.ProfileCache.Clear() }
        $Index.ProfileCache[$ck] = $res
        return $res
    } catch {
        Write-Warning ('profile asset type not classified -- {0}' -f $_.Exception.Message)
        return $null
    }
}
