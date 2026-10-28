#Requires -Version 5.1
<#
    THE CI GRAPH (V3-DATA-MODEL 2.8.4 / 2.8.5, REQUIREMENTS #493 + #496) -- what a CI is related to and who owns it.

      SERVICES     #496 business services OWN CIs (CMDB-style). A CI belongs to a service by, in this order:
                     cmdb_link      a link on the CMDB page (cfg.vCmdbAssetService -- the authoritative CMDB's links, audited
                                    there; the CI id is the asset key)
                     service_model  a binding rule of the service model (config\service-model.locked.json; Pro: the
                                    servicemodel template, changed through Template conformance) -- first match wins
                     cmdb           the CI's own CMDB record (si_cmdb_id / si_cmdb_service, the CMDB join and the rules)
                   The service's owner, criticality, data sensitivity, environment and department come from the service
                   catalog (cfg.vCmdbService; a service model service; else the CI's own CMDB values). The CI INHERITS them
                   (si_service_*): a CI in several services takes the STRICTEST -- criticality and data sensitivity by the
                   criticality mapping's factor, environment by the list service_environment_order -- and the owner and
                   department of its most critical service. A CI no service owns is UNOWNED (si_service_orphan; the CI
                   grid's filter and the view sidata.vCiUnowned list them). The criticality factor of the CI takes the
                   inherited criticality when it is stricter than the CI's own (Set-SICiCriticality), so the findings of
                   the CI inherit it too.
      RELATIONS    #493 typed, directional relations CI -> CI with a source and a confidence, declared as data
                   (data-model\relations.locked.json, the template kind 'relation'): each relation turns one SI field of a
                   CI into claims (owner, logged-on users, public IP, subscription, resource group, management group, group
                   memberships, Azure and Entra roles, the app registration of a service principal). The CI build writes
                   the claims of every CI it rebuilt (sidata.CiRelationClaim); ONE set-based statement after the build
                   resolves their targets (a CI that carries the identifier, else the identifier itself) into
                   sidata.CiRelation (first seen, last seen, active | gone) -- queryable both ways (sidata.vCiRelation) --
                   records what was added / ended in sidata.CiChange, and posts the changes to SI_CIRelation_CL for Risk
                   Analysis (a full refresh with the weekly full SI_CI_CL refresh).

    Both editions (SQL in every v3 install, #477); the CMDB links exist in Pro only. Writes only SecurityInsight's own
    database and its own Log Analytics table -- no system outside SecurityInsight is changed.
    PowerShell 5.1: no ?. / ??, no ternary.
#>

# =====================================================================================================================
# SERVICES (#496)
# =====================================================================================================================

function Get-SICiServiceSourceSql {
    <#
        READ-ONLY. The service catalog and the CMDB links of the authoritative CMDB (Pro: cfg.vCmdbService /
        cfg.vCmdbAssetService). A database without them (Community, or a Pro database the updater has not updated yet)
        answers no rows.
    #>
    @'
SET NOCOUNT ON;
IF OBJECT_ID(N'cfg.vCmdbService') IS NULL OR OBJECT_ID(N'cfg.vCmdbAssetService') IS NULL
    SELECT CAST(NULL AS NVARCHAR(16)) AS Kind, CAST(NULL AS NVARCHAR(256)) AS ServiceKey, CAST(NULL AS NVARCHAR(128)) AS ExternalId, CAST(NULL AS NVARCHAR(400)) AS Name,
           CAST(NULL AS NVARCHAR(256)) AS Owner, CAST(NULL AS NVARCHAR(64)) AS Criticality, CAST(NULL AS NVARCHAR(64)) AS DataSensitivity,
           CAST(NULL AS NVARCHAR(64)) AS Environment, CAST(NULL AS NVARCHAR(128)) AS Department, CAST(NULL AS NVARCHAR(400)) AS CiId,
           CAST(NULL AS NVARCHAR(MAX)) AS ExtraJson
    WHERE 1 = 0;
ELSE IF COL_LENGTH(N'cfg.vCmdbService', N'ExtraJson') IS NULL
    -- a service view from before the extra facts were kept: the services as before, without them
    SELECT N'service' AS Kind, s.ServiceNumber AS ServiceKey, s.ExternalId, s.Name, COALESCE(NULLIF(s.Owner, N''), s.OwnerMail) AS Owner, s.Criticality, s.DataSensitivity,
           s.Environment, s.Department, CAST(NULL AS NVARCHAR(400)) AS CiId, CAST(NULL AS NVARCHAR(MAX)) AS ExtraJson
    FROM cfg.vCmdbService AS s
    UNION ALL
    SELECT N'link', a.ServiceNumber, NULL, a.ServiceName, NULL, NULL, NULL, NULL, NULL, a.AssetKey, NULL
    FROM cfg.vCmdbAssetService AS a;
ELSE
    -- the service's extra facts (ExtraJson: support group, assignment group, location, cost center, company -- id AND name)
    -- travel with it; read through EXEC so a view without the column never fails the statement above
    EXEC (N'SELECT N''service'' AS Kind, s.ServiceNumber AS ServiceKey, s.ExternalId, s.Name, COALESCE(NULLIF(s.Owner, N''''), s.OwnerMail) AS Owner, s.Criticality, s.DataSensitivity,
           s.Environment, s.Department, CAST(NULL AS NVARCHAR(400)) AS CiId, s.ExtraJson
    FROM cfg.vCmdbService AS s
    UNION ALL
    SELECT N''link'', a.ServiceNumber, NULL, a.ServiceName, NULL, NULL, NULL, NULL, NULL, a.AssetKey, NULL
    FROM cfg.vCmdbAssetService AS a;');
'@
}

# The extra facts of a business service a CI inherits (rich context): each a NAME with its ID next to it where the CMDB
# has one. Kept with the service by the CMDB import (ExtraJson; the ServiceNow read writes exactly these keys).
function Get-SICiServiceExtraKeys {
    <# PURE. The extra facts' keys: a name key is followed by its '<name>_id' key where the CMDB has one. #>
    'owner_id', 'support_group', 'support_group_id', 'assignment_group', 'assignment_group_id', 'assigned_to', 'assigned_to_id',
    'location', 'location_id', 'cost_center', 'cost_center_id', 'company', 'company_id', 'operational_status'
}

function ConvertTo-SICiServiceExtra {
    <# PURE. A service's ExtraJson (text or object) -> the extra facts the CI build uses (Get-SICiServiceExtraKeys), as
       trimmed text; a key the service does not carry, or anything that is not a JSON object, is left out. #>
    param($ExtraJson)
    $out = [ordered]@{}
    $o = $ExtraJson
    if ($o -is [System.DBNull]) { $o = $null }
    if ($o -is [string]) { $s = $o.Trim(); if ($s.StartsWith('{')) { try { $o = $s | ConvertFrom-Json } catch { $o = $null } } else { $o = $null } }
    if ($null -eq $o) { return $out }
    foreach ($k in @(Get-SICiServiceExtraKeys)) {
        $v = ([string](Get-SIItemValue $o $k)).Trim()
        if ($v) { $out[$k] = $v }
    }
    return $out
}

function New-SICiServiceIndex {
    <#
        PURE. The service catalog rows (Get-SICiServiceSourceSql) and the service model (Get-SIServiceModel: Services,
        Bindings) -> the lookups the CI build uses:
          Services    key -> @{ key; name; owner; criticality; data_sensitivity; environment; department; origin }
          ByExternal  a service's id in its source (a migrated service's old CMDB id) -> key
          ByName      a service's name -> key (a binding names its service by name; a CMDB record by name)
          Links       CI id -> [keys] (the CMDB page's links)
          Bindings    the service model's binding rules, in order
        A service model service with the name of a catalog service IS that service (one catalog).
    #>
    param([AllowEmptyCollection()][object[]]$Rows = @(), $ServiceModel)
    $cmp = [StringComparer]::OrdinalIgnoreCase
    $svc = New-Object System.Collections.Hashtable ($cmp); $ext = New-Object System.Collections.Hashtable ($cmp)
    $byName = New-Object System.Collections.Hashtable ($cmp); $links = New-Object System.Collections.Hashtable ($cmp)
    foreach ($r in @($Rows)) {
        if ($null -eq $r) { continue }
        $kind = [string](Get-SIItemValue $r 'Kind'); $key = ([string](Get-SIItemValue $r 'ServiceKey')).Trim()
        if (-not $key) { continue }
        if ($kind -eq 'service') {
            $name = [string](Get-SIItemValue $r 'Name'); if (-not $name) { $name = $key }
            $svc[$key] = [ordered]@{ key = $key; name = $name; owner = [string](Get-SIItemValue $r 'Owner'); criticality = [string](Get-SIItemValue $r 'Criticality')
                data_sensitivity = [string](Get-SIItemValue $r 'DataSensitivity'); environment = [string](Get-SIItemValue $r 'Environment')
                department = [string](Get-SIItemValue $r 'Department'); origin = 'cmdb' }
            # rich context: the service's extra facts (who supports it, where it sits) -- ids AND names, only those it carries
            $extra = ConvertTo-SICiServiceExtra (Get-SIItemValue $r 'ExtraJson')
            foreach ($xk in @($extra.Keys)) { $svc[$key][$xk] = $extra[$xk] }
            $x = ([string](Get-SIItemValue $r 'ExternalId')).Trim(); if ($x) { $ext[$x] = $key }
            if (-not $byName.ContainsKey($name)) { $byName[$name] = $key }
        } elseif ($kind -eq 'link') {
            $ci = ([string](Get-SIItemValue $r 'CiId')).Trim(); if (-not $ci) { continue }
            if (-not $links.ContainsKey($ci)) { $links[$ci] = New-Object System.Collections.Generic.List[string] }
            if (-not $links[$ci].Contains($key)) { $links[$ci].Add($key) }
        }
    }
    $bindings = @()
    if ($ServiceModel) {
        foreach ($s in @(Get-SIItemValue $ServiceModel 'Services')) {
            if ($null -eq $s) { continue }
            $name = ([string](Get-SIItemValue $s 'name')).Trim(); if (-not $name -or $byName.ContainsKey($name)) { continue }
            $crit = [string](Get-SIItemValue $s 'businessCriticality'); if (-not $crit) { $crit = [string](Get-SIItemValue $s 'criticality') }
            $svc[$name] = [ordered]@{ key = $name; name = $name; owner = [string](Get-SIItemValue $s 'owner'); criticality = $crit
                data_sensitivity = [string](Get-SIItemValue $s 'dataSensitivity'); environment = [string](Get-SIItemValue $s 'environment')
                department = [string](Get-SIItemValue $s 'department'); origin = 'service_model' }
            $byName[$name] = $name
        }
        $bindings = @(@(Get-SIItemValue $ServiceModel 'Bindings') | Where-Object { $null -ne $_ })
    }
    @{ Services = $svc; ByExternal = $ext; ByName = $byName; Links = $links; Bindings = $bindings; Count = ($svc.Count + $links.Count + $bindings.Count) }
}

function Get-SICiServiceModelForBuild {
    <#
        The service model (levels 1 and 2 of the CMDB model) as the CMDB engine reads it (engine\asset-cmdb\_shared\
        SI-ServiceModel.ps1: the shipped file, the customer's custom file, or the Pro model materialised for the run). An
        install without that engine, or a model that cannot be read, gives no model -- said once, never fatal.
    #>
    param([scriptblock]$Log)
    try {
        if (-not (Get-Command -Name Get-SIServiceModel -ErrorAction SilentlyContinue)) {
            $p = [System.IO.Path]::Combine((Split-Path -Parent $PSScriptRoot), 'asset-cmdb', '_shared', 'SI-ServiceModel.ps1')
            if (-not [System.IO.File]::Exists($p)) { return $null }
            . $p
        }
        return (Get-SIServiceModel 3>$null)
    } catch {
        if ($Log) { & $Log 'WARN' ("CIs: the service model could not be read ({0}) -- services come from the CMDB only this run." -f $_.Exception.Message) }
        return $null
    }
}

function Get-SICiNoServiceText {
    <# PURE. #496: the plain sentence when this install defines NO business service at all -- no service in the catalog, no
       CI linked to one on the CMDB page, no service model rule (the shipped model has none). '' when any of them exists.
       Not an error: the CIs then belong to no service, so the Services view stays empty and nothing is grouped by service. #>
    param([int]$Services = 0, [int]$Links = 0, [int]$Bindings = 0)
    if ($Services -gt 0 -or $Links -gt 0 -or $Bindings -gt 0) { return '' }
    'no business services are defined on this install, so no CI belongs to a service and the Services view stays empty. To group CIs by service: link CIs to a service on the CMDB page, or add service rules (by tag, resource group or name) to the service model.'
}

function Get-SICiServiceIndex {
    <# The service index of this build: the catalog + links from the database (-Sql) and the service model. Never throws. #>
    param([scriptblock]$Sql, [scriptblock]$Log, $ServiceModel)
    $rows = @()
    if ($Sql) {
        try { $rows = @(& $Sql (Get-SICiServiceSourceSql) @{} 'rows') }
        catch { if ($Log) { & $Log 'WARN' ("CIs: the CMDB services could not be read ({0}) -- services come from the service model and the CIs' own CMDB values this run." -f $_.Exception.Message) } }
    }
    if ($null -eq $ServiceModel) { $ServiceModel = Get-SICiServiceModelForBuild -Log $Log }
    New-SICiServiceIndex -Rows $rows -ServiceModel $ServiceModel
}

function Get-SICiServiceBindingValue {
    <#
        PURE. The value one binding rule reads on a CI (the service model's four sources, on SI fields):
          resourceGroup  si_azure_resource_group      namePattern  si_asset_name
          tag            si_tags (key=value, key:value, or { key/name; value } objects)
          cmdbField      the CMDB field it names (cmdbName -> si_cmdb_name, cmdbCriticality -> si_cmdb_criticality ..., or an
                         si_ field by its own name)
    #>
    param($Ci, $Match)
    if ($null -eq $Ci -or $null -eq $Match) { return '' }
    switch (([string](Get-SIItemValue $Match 'source')).Trim().ToLowerInvariant()) {
        'resourcegroup' { return [string](Get-SIItemValue $Ci 'si_azure_resource_group') }
        'namepattern' { return [string](Get-SIItemValue $Ci 'si_asset_name') }
        'cmdbfield' {
            $k = ([string](Get-SIItemValue $Match 'key')).Trim()
            if (-not $k) { return '' }
            if (-not $k.StartsWith('si_')) {
                $k = 'si_' + (($k -creplace '([a-z0-9])([A-Z])', '$1_$2').ToLowerInvariant())
            }
            $v = Get-SIItemValue $Ci $k
            if ($null -eq $v -or ($v -isnot [string] -and $v -isnot [ValueType])) { return '' }
            return [string]$v
        }
        'tag' {
            $key = ([string](Get-SIItemValue $Match 'key')).Trim()
            if (-not $key) { return '' }
            foreach ($t in (Get-SIValueList (Get-SIItemValue $Ci 'si_tags'))) {
                if ($null -eq $t) { continue }
                if ($t -is [string]) {
                    $kv = $t -split '[=:]', 2
                    if ($kv.Count -eq 2 -and $kv[0].Trim() -ieq $key) { return $kv[1].Trim() }
                    continue
                }
                $tk = [string](Get-SIItemValue $t 'key'); if (-not $tk) { $tk = [string](Get-SIItemValue $t 'name') }
                if ($tk -and $tk.Trim() -ieq $key) { return [string](Get-SIItemValue $t 'value') }
            }
            return ''
        }
    }
    ''
}

function Get-SICiServiceBinding {
    <#
        PURE. The first binding rule of the service model that matches the CI (equals: case-insensitive; matches: a
        pattern) -> @{ Service; Rule } or $null. A rule with a pattern that is not valid matches nothing (the CMDB engine's
        report names it).
    #>
    param($Ci, [AllowEmptyCollection()][object[]]$Bindings = @())
    foreach ($b in @($Bindings)) {
        if ($null -eq $b) { continue }
        $m = Get-SIItemValue $b 'match'; if ($null -eq $m) { continue }
        $val = Get-SICiServiceBindingValue -Ci $Ci -Match $m
        if ([string]::IsNullOrWhiteSpace($val)) { continue }
        $eq = [string](Get-SIItemValue $m 'equals'); $rx = [string](Get-SIItemValue $m 'matches')
        $hit = $false
        if (-not [string]::IsNullOrWhiteSpace($eq)) { $hit = ($val -ieq $eq) }
        elseif (-not [string]::IsNullOrWhiteSpace($rx)) { try { $hit = ($val -match $rx) } catch { $hit = $false } }
        if ($hit) { return [pscustomobject]@{ Service = [string](Get-SIItemValue $b 'service'); Rule = [string](Get-SIItemValue $b 'rule') } }
    }
    $null
}

function Get-SICiCriticalityEntry {
    <#
        PURE. The criticality mapping's entry for a value (-Section criticality | dataSensitivity): the CMDB owner's
        vocabulary first, then every other one (a service from SI's own catalog says "High" while the owner is ServiceNow).
        $null when no vocabulary knows the value.
    #>
    param($Mapping, [string]$Section = 'criticality', [string]$Value, [string]$Owner = 'cmdb')
    if ($null -eq $Mapping -or [string]::IsNullOrWhiteSpace($Value)) { return $null }
    $sect = Get-SIItemValue $Mapping $Section
    if ($null -eq $sect) { return $null }
    $order = New-Object System.Collections.Generic.List[string]
    if ($Owner) { $order.Add($Owner) }
    foreach ($p in $sect.PSObject.Properties) { if (-not $p.Name.StartsWith('$') -and -not $order.Contains($p.Name)) { $order.Add($p.Name) } }
    if ($sect -is [System.Collections.IDictionary]) { foreach ($k in $sect.Keys) { if (-not $order.Contains([string]$k)) { $order.Add([string]$k) } } }
    foreach ($o in $order) {
        foreach ($e in @(Get-SIItemValue $sect $o)) {
            if ($null -eq $e) { continue }
            if ([string]::Equals(([string](Get-SIItemValue $e 'value')).Trim(), $Value.Trim(), [StringComparison]::OrdinalIgnoreCase)) { return $e }
        }
    }
    $null
}

function Get-SICiEnvironmentRank {
    <# PURE. A service environment's place in the list (0 = strictest); a value not in the list after every listed one; none = [int]::MaxValue. #>
    param([string]$Value, [AllowEmptyCollection()][string[]]$Order = @())
    if ([string]::IsNullOrWhiteSpace($Value)) { return [int]::MaxValue }
    $v = $Value.Trim()
    for ($i = 0; $i -lt @($Order).Count; $i++) { if ([string]::Equals([string]$Order[$i], $v, [StringComparison]::OrdinalIgnoreCase)) { return $i } }
    return @($Order).Count
}

function Set-SICiServices {
    <#
        PURE. #496 the business services that own the CI (CMDB link, service model binding, the CI's own CMDB record -- in
        that order; one membership per service) and what the CI inherits from them -- the STRICTEST:
          si_services                 every membership: key, name, source, matched_by, owner, criticality, data_sensitivity,
                                      environment, department, strictest (the membership that decided the criticality)
          si_service_keys / _count    the services' keys (sorted) / how many; si_service_orphan = none
          si_service_criticality      the highest criticality factor of the criticality mapping (+ _level)
          si_service_data_sensitivity the highest data sensitivity factor
          si_service_environment      the first in service_environment_order
          si_service_owner / _department  of the most critical service (the first one that names an owner)
        -Index: New-SICiServiceIndex. -Mapping: the criticality mapping. Answers the CI.
    #>
    param([Parameter(Mandatory)]$Ci, [hashtable]$Index, $Mapping, [AllowEmptyCollection()][string[]]$EnvironmentOrder = @(), [string]$CmdbOwner = 'cmdb')
    if ($null -eq $Index) { $Index = New-SICiServiceIndex }
    $members = New-Object System.Collections.Generic.List[object]
    $seen = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    $add = {
        param([string]$Key, [string]$Source, [string]$By, $Fallback)
        if ([string]::IsNullOrWhiteSpace($Key) -or -not $seen.Add($Key.Trim())) { return }
        $s = $null
        if ($Index.Services.ContainsKey($Key.Trim())) { $s = $Index.Services[$Key.Trim()] } else { $s = $Fallback }
        if ($null -eq $s) { $s = @{ name = $Key.Trim() } }
        $m = [ordered]@{ key = $Key.Trim(); name = [string]$s.name; source = $Source; matched_by = $By; owner = [string]$s.owner; criticality = [string]$s.criticality
                data_sensitivity = [string]$s.data_sensitivity; environment = [string]$s.environment; department = [string]$s.department; strictest = $false }
        # rich context: the service's extra facts (support group, assignment group, location, cost center, company ... id AND name)
        foreach ($xk in @(Get-SICiServiceExtraKeys)) { $xv = [string](Get-SIItemValue $s $xk); if ($xv) { $m[$xk] = $xv } }
        $members.Add($m)
    }
    # 1. the CMDB page's links (the CI id is the asset key)
    $id = ([string](Get-SIItemValue $Ci 'si_ci_id')).Trim()
    if ($id -and $Index.Links.ContainsKey($id)) { foreach ($k in @($Index.Links[$id])) { & $add $k 'cmdb_link' 'linked to the service on the CMDB page' $null } }
    # 2. the service model's binding rules (first match wins)
    $b = Get-SICiServiceBinding -Ci $Ci -Bindings @($Index.Bindings)
    if ($b -and $b.Service) {
        $k = $b.Service
        if ($Index.ByName.ContainsKey($k)) { $k = [string]$Index.ByName[$k] }
        & $add $k 'service_model' ("the service model rule '{0}'" -f $b.Rule) $null
    }
    # 3. the CI's own CMDB record: a catalog service by id, by its old id or by name; else the record's own values
    $cid = ([string](Get-SIItemValue $Ci 'si_cmdb_id')).Trim(); $cname = ([string](Get-SIItemValue $Ci 'si_cmdb_service')).Trim()
    $own = [ordered]@{ name = $(if ($cname) { $cname } elseif ([string](Get-SIItemValue $Ci 'si_cmdb_name')) { [string](Get-SIItemValue $Ci 'si_cmdb_name') } else { $cid })
        owner = [string](Get-SIItemValue $Ci 'si_cmdb_owner'); criticality = [string](Get-SIItemValue $Ci 'si_cmdb_criticality')
        data_sensitivity = [string](Get-SIItemValue $Ci 'si_cmdb_data_sensitivity'); environment = [string](Get-SIItemValue $Ci 'si_cmdb_environment')
        department = [string](Get-SIItemValue $Ci 'si_cmdb_owner_department') }
    $by = 'the CI''s own CMDB record'
    if ($cid -and $Index.Services.ContainsKey($cid)) { & $add $cid 'cmdb' $by $own }
    elseif ($cid -and $Index.ByExternal.ContainsKey($cid)) { & $add ([string]$Index.ByExternal[$cid]) 'cmdb' $by $own }
    elseif ($cname -and $Index.ByName.ContainsKey($cname)) { & $add ([string]$Index.ByName[$cname]) 'cmdb' $by $own }
    elseif ($cname) { & $add $cname 'cmdb' $by $own }
    elseif ($cid -and $CmdbOwner -eq 'cmdb') { & $add $cid 'cmdb' $by $own }

    foreach ($f in 'si_services', 'si_service_keys', 'si_service_owner', 'si_service_criticality', 'si_service_criticality_level', 'si_service_data_sensitivity',
                   'si_service_environment', 'si_service_department') { if ($Ci.Contains($f)) { $Ci.Remove($f) } }
    foreach ($xk in @(Get-SICiServiceExtraKeys)) { if ($Ci.Contains('si_service_' + $xk)) { $Ci.Remove('si_service_' + $xk) } }
    $Ci['si_service_count'] = $members.Count
    $Ci['si_service_orphan'] = ($members.Count -eq 0)
    if ($members.Count -eq 0) { return $Ci }

    # the strictest: criticality and data sensitivity by the mapping's factor (a value the mapping does not know counts
    # above none and below every known one), environment by the list, owner + department of the most critical service
    $best = $null; $bestF = [double]::NegativeInfinity; $bestLevel = ''
    foreach ($m in $members) {
        if ([string]::IsNullOrWhiteSpace($m.criticality)) { continue }
        $e = Get-SICiCriticalityEntry -Mapping $Mapping -Section 'criticality' -Value $m.criticality -Owner $CmdbOwner
        $f = -1.0; if ($e) { $f = [double](Get-SIItemValue $e 'factor') }
        if ($f -gt $bestF) { $bestF = $f; $best = $m; $bestLevel = $(if ($e) { [string](Get-SIItemValue $e 'level') } else { '' }) }
    }
    if ($best) { $best.strictest = $true; $Ci['si_service_criticality'] = $best.criticality; if ($bestLevel) { $Ci['si_service_criticality_level'] = $bestLevel } }
    $sens = $null; $sensF = [double]::NegativeInfinity
    foreach ($m in $members) {
        if ([string]::IsNullOrWhiteSpace($m.data_sensitivity)) { continue }
        $e = Get-SICiCriticalityEntry -Mapping $Mapping -Section 'dataSensitivity' -Value $m.data_sensitivity -Owner $CmdbOwner
        $f = -1.0; if ($e) { $f = [double](Get-SIItemValue $e 'factor') }
        if ($f -gt $sensF) { $sensF = $f; $sens = $m.data_sensitivity }
    }
    if ($sens) { $Ci['si_service_data_sensitivity'] = $sens }
    $env = $null; $envR = [int]::MaxValue
    foreach ($m in $members) {
        $r = Get-SICiEnvironmentRank -Value $m.environment -Order $EnvironmentOrder
        if ($r -lt $envR) { $envR = $r; $env = $m.environment }
    }
    if ($env) { $Ci['si_service_environment'] = $env }
    # the most critical service first, then every membership in order -- a typed list: @($best) on an ordered dictionary
    # throws "Argument types do not match" in pwsh 7 (its array binder cannot wrap an OrderedDictionary)
    $order = New-Object System.Collections.Generic.List[object]
    if ($null -ne $best) { $order.Add($best) }
    foreach ($m in $members) { $order.Add($m) }
    foreach ($m in $order) { if (-not [string]::IsNullOrWhiteSpace([string]$m.owner)) { $Ci['si_service_owner'] = [string]$m.owner; break } }
    foreach ($m in $order) { if (-not [string]::IsNullOrWhiteSpace([string]$m.department)) { $Ci['si_service_department'] = [string]$m.department; break } }
    # rich context: who supports the CI's service and where it sits -- of the most critical service that names it; an id
    # is taken from the SAME service as its name (never the name of one service next to the id of another)
    foreach ($xk in @(Get-SICiServiceExtraKeys)) {
        if ($xk.EndsWith('_id') -and $xk -ne 'owner_id') { continue }
        foreach ($m in $order) {
            $xv = ''; if ($m.Contains($xk)) { $xv = [string]$m[$xk] }
            if ([string]::IsNullOrWhiteSpace($xv)) { continue }
            $Ci['si_service_' + $xk] = $xv
            $idk = $xk + '_id'
            if ($xk -ne 'owner_id' -and $xk -ne 'operational_status' -and $m.Contains($idk) -and [string]$m[$idk]) { $Ci['si_service_' + $idk] = [string]$m[$idk] }
            break
        }
    }
    [string[]]$keys = @($members | ForEach-Object { [string]$_.key }); [Array]::Sort($keys, [StringComparer]::Ordinal)
    $Ci['si_service_keys'] = $keys
    $Ci['si_services'] = @($members.ToArray())
    return $Ci
}

function Get-SICiServiceKeyText {
    <# PURE. One business-service lookup key: '<kind>|<value>' in lower case (the CMDB key form, Get-SICiCmdbKey, when loaded). #>
    param([Parameter(Mandatory)][string]$Kind, [AllowNull()][AllowEmptyString()][string]$Value)
    if (Get-Command -Name Get-SICiCmdbKey -ErrorAction SilentlyContinue) { return (Get-SICiCmdbKey -Kind $Kind -Value $Value) }
    $v = ([string]$Value).Trim().ToLowerInvariant()
    if (-not $v) { return '' }
    $Kind + '|' + $v
}

function Get-SICiServiceKeyHashes {
    <#
        PURE. #496 + #534: the business-service index as lookup keys with the hash of what is behind each -- the same
        mechanism as the owning CMDB's keys (sidata.CiCmdbKey / CiCmdbUse): a key whose content is new, changed or gone since
        the last build dirties ONLY the CIs that used it (Get-SICiServiceRefKeys), never every CI.
          bsvc|<service key>      the service's name, owner, criticality, data sensitivity, environment, department
          bsvclink|<CI id>        the services the CMDB page links to the CI
          bsvcext|<old id>        which service a migrated service's old CMDB id names
          bsvcname|<name>         which service a name names
        The service model's binding rules can place any CI, so they are part of the build fingerprint instead (Invoke-SICiBuild).
        Answers [{ k; h }] in ordinal key order.
    #>
    param([hashtable]$Index)
    if ($null -eq $Index) { return @() }
    $out = New-Object 'System.Collections.Generic.SortedDictionary[string,string]' ([StringComparer]::Ordinal)
    $h = { param($o) (Get-SIContentHash -Item $o).Substring(0, 32) }
    foreach ($k in @($Index.Services.Keys)) {
        $s = $Index.Services[$k]
        $key = Get-SICiServiceKeyText -Kind 'bsvc' -Value ([string]$k)
        if ($key) { $out[$key] = & $h ([ordered]@{ n = [string]$s.name; o = [string]$s.owner; c = [string]$s.criticality; d = [string]$s.data_sensitivity; e = [string]$s.environment; p = [string]$s.department }) }
    }
    foreach ($k in @($Index.Links.Keys)) {
        [string[]]$v = @($Index.Links[$k] | ForEach-Object { ([string]$_).ToLowerInvariant() }); [Array]::Sort($v, [StringComparer]::Ordinal)
        $key = Get-SICiServiceKeyText -Kind 'bsvclink' -Value ([string]$k)
        if ($key) { $out[$key] = & $h ([ordered]@{ l = ($v -join ',') }) }
    }
    foreach ($k in @($Index.ByExternal.Keys)) { $key = Get-SICiServiceKeyText -Kind 'bsvcext' -Value ([string]$k); if ($key) { $out[$key] = & $h ([ordered]@{ s = ([string]$Index.ByExternal[$k]).ToLowerInvariant() }) } }
    foreach ($k in @($Index.ByName.Keys)) { $key = Get-SICiServiceKeyText -Kind 'bsvcname' -Value ([string]$k); if ($key) { $out[$key] = & $h ([ordered]@{ s = ([string]$Index.ByName[$k]).ToLowerInvariant() }) } }
    @(foreach ($e in $out.GetEnumerator()) { [ordered]@{ k = $e.Key; h = $e.Value } })
}

function Get-SICiServiceRefKeys {
    <#
        PURE. #496 + #534: the business-service keys a built CI used -- its CMDB page links (always, so a link added later
        dirties it), every service it is in, and the old id / name its own CMDB record names (whether a service was found or
        not: a service that appears later for the key dirties the CI).
    #>
    param([Parameter(Mandatory)]$Ci)
    $keys = New-Object System.Collections.Generic.List[string]
    $add = { param($kind, $v) if ($null -eq $v -or -not ($v -is [string] -or $v -is [ValueType])) { return }; $k = Get-SICiServiceKeyText -Kind $kind -Value ([string]$v); if ($k -and -not $keys.Contains($k)) { $keys.Add($k) } }
    $id = [string](Get-SIItemValue $Ci 'si_ci_id'); if (-not $id) { return }
    & $add 'bsvclink' $id
    foreach ($m in @(Get-SIItemValue $Ci 'si_services')) { if ($null -ne $m) { & $add 'bsvc' (Get-SIItemValue $m 'key') } }
    $cid = Get-SIItemValue $Ci 'si_cmdb_id'; & $add 'bsvc' $cid; & $add 'bsvcext' $cid
    & $add 'bsvcname' (Get-SIItemValue $Ci 'si_cmdb_service')
    $keys.ToArray()
}

# =====================================================================================================================
# RELATIONS (#493)
# =====================================================================================================================

function Get-SICiRelationRules {
    <# PURE. The relations of the data model that are written: stage production (a relation without a stage is production). #>
    param($Model)
    if ($null -eq $Model) { return @() }
    $doc = $Model['relations']
    @(@(Get-SIItemValue $doc 'relations') | Where-Object {
            $null -ne $_ -and [string]$_.id -and [string]$_.field -and ((-not [string](Get-SIItemValue $_ 'stage')) -or [string](Get-SIItemValue $_ 'stage') -eq 'production')
        })
}

function Get-SICiRelationValues {
    <#
        PURE. The values one field holds for a relation: a text (or number) as it is; an object by the first non-empty of
        -ValuePath; each with its detail (-DetailPath). Values over 400 characters are cut; empty ones are left out.
    #>
    param($Value, [AllowEmptyCollection()][string[]]$ValuePath = @(), [AllowEmptyCollection()][string[]]$DetailPath = @())
    $out = New-Object System.Collections.Generic.List[object]
    foreach ($v in (Get-SIValueList $Value)) {
        if ($null -eq $v) { continue }
        $val = ''; $det = ''
        if ($v -is [string] -or $v -is [ValueType]) { $val = [string]$v }
        else {
            foreach ($p in @($ValuePath)) { $x = Get-SIItemValue $v $p; if ($null -ne $x -and ($x -is [string] -or $x -is [ValueType]) -and "$x".Trim()) { $val = [string]$x; break } }
            foreach ($p in @($DetailPath)) { $x = Get-SIItemValue $v $p; if ($null -ne $x -and ($x -is [string] -or $x -is [ValueType]) -and "$x".Trim()) { $det = [string]$x; break } }
        }
        $val = $val.Trim(); if (-not $val) { continue }
        if ($val.Length -gt 400) { $val = $val.Substring(0, 400) }
        if ($det.Length -gt 400) { $det = $det.Substring(0, 400) }
        $out.Add([pscustomobject]@{ Value = $val; Detail = $det.Trim() })
    }
    , $out.ToArray()
}

function Get-SICiRelationClaims {
    <#
        PURE. The relation claims of one CI: per relation of -Rules whose 'from' holds the CI's class, per value of its field:
        OwnerCiId (the CI whose build made the claim), RelationId, Kind, FromCiId, ToType (ci | the identifier type | the
        node type), ToValue, Detail, Source, Confidence. An identifier or a node is lower case (the record identifiers are);
        a reversed relation runs from the value's CI to this one; a CI is never related to itself.
    #>
    param([Parameter(Mandatory)]$Ci, [AllowEmptyCollection()][object[]]$Rules = @())
    $out = New-Object System.Collections.Generic.List[object]
    $id = ([string](Get-SIItemValue $Ci 'si_ci_id')).Trim(); $cls = [string](Get-SIItemValue $Ci 'si_class')
    if (-not $id) { return }
    $seen = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::Ordinal)
    foreach ($r in @($Rules)) {
        if ($null -eq $r) { continue }
        # (a loop, not a pipeline: every relation rule of every CI of the build; the same case-insensitive test as -contains)
        $fromHit = $false; foreach ($fx in @($r.from)) { if ([string]$fx -eq $cls) { $fromHit = $true; break } }
        if (-not $fromHit) { continue }
        $raw = Get-SIItemValue $Ci ([string]$r.field)
        if (Test-SIValueEmpty $raw) { continue }
        $vp = [string[]]@(foreach ($x in @(Get-SIItemValue $r 'valuePath')) { if ($x) { [string]$x } })
        $dp = [string[]]@(foreach ($x in @(Get-SIItemValue $r 'detailPath')) { if ($x) { [string]$x } })
        $qual = ''
        $qf = [string](Get-SIItemValue $r 'qualifyWith'); if ($qf) { $qual = ([string](Get-SIItemValue $Ci $qf)).Trim().ToLowerInvariant() }
        foreach ($v in (Get-SICiRelationValues -Value $raw -ValuePath $vp -DetailPath $dp)) {
            $from = $id; $toType = ''; $toValue = ''
            switch ([string]$r.target) {
                'ci' { $toType = 'ci'; $toValue = $v.Value }
                'id' { $toType = [string]$r.idType; $toValue = $v.Value.ToLowerInvariant() }
                'node' {
                    $toType = [string]$r.nodeType; $toValue = $v.Value.ToLowerInvariant()
                    if ($qual) { $toValue = $qual + '/' + $toValue; if ($toValue.Length -gt 400) { $toValue = $toValue.Substring(0, 400) } }
                }
            }
            # an unknown target (Test-SIDataModel refuses one) makes no claim
            if (-not $toType) { continue }
            if ((Get-SIItemValue $r 'reverse') -eq $true) { $from = $v.Value; $toType = 'ci'; $toValue = $id }
            if ($toType -eq 'ci' -and ($from.Length -gt 64 -or $toValue.Length -gt 64)) { continue }
            if ($toType -eq 'ci' -and [string]::Equals($from, $toValue, [StringComparison]::OrdinalIgnoreCase)) { continue }
            $sig = '{0}|{1}|{2}|{3}' -f $from, [string]$r.kind, $toType, $toValue
            if (-not $seen.Add($sig)) { continue }
            $out.Add([ordered]@{ OwnerCiId = $id; RelationId = [string]$r.id; Kind = [string]$r.kind; FromCiId = $from; ToType = $toType; ToValue = $toValue
                    Detail = $v.Detail; Source = [string]$r.source; Confidence = [string]$r.confidence })
        }
    }
    # the claims as items: @(Get-SICiRelationClaims ...) and a pipeline filter see each claim, never one array
    $out.ToArray()
}

function ConvertTo-SICiGraphItems {
    <#
        PURE. One batch's CI documents -> what the graph write replaces: CiIds (the CIs whose services and claims are
        replaced), Services ([{ CiId; ServiceKey; ServiceName; Source; MatchedBy; Criticality; DataSensitivity; Environment;
        Owner; Department; Strictest }]) and Claims (Get-SICiRelationClaims). -Only: the CI ids to take (an incremental
        build: the CIs whose content changed -- an unchanged CI's services and claims are what they were); $null = every CI.
    #>
    param([AllowEmptyCollection()][object[]]$Docs = @(), [AllowEmptyCollection()][object[]]$Rules = @(), $Only)
    $ids = New-Object System.Collections.Generic.List[string]
    $svc = New-Object System.Collections.Generic.List[object]
    $claims = New-Object System.Collections.Generic.List[object]
    $taken = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    foreach ($d in @($Docs)) {
        if ($null -eq $d) { continue }
        $id = ([string](Get-SIItemValue $d 'si_ci_id')).Trim(); if (-not $id) { continue }
        if ($null -ne $Only -and -not $Only.Contains($id)) { continue }
        if (-not $taken.Add($id)) { continue }
        $ids.Add($id)
        foreach ($m in @(Get-SIItemValue $d 'si_services')) {
            if ($null -eq $m) { continue }
            $k = [string](Get-SIItemValue $m 'key'); if (-not $k) { continue }
            $svc.Add([ordered]@{ CiId = $id; ServiceKey = $k; ServiceName = [string](Get-SIItemValue $m 'name'); Source = [string](Get-SIItemValue $m 'source')
                    MatchedBy = [string](Get-SIItemValue $m 'matched_by'); Criticality = [string](Get-SIItemValue $m 'criticality')
                    DataSensitivity = [string](Get-SIItemValue $m 'data_sensitivity'); Environment = [string](Get-SIItemValue $m 'environment')
                    Owner = [string](Get-SIItemValue $m 'owner'); Department = [string](Get-SIItemValue $m 'department')
                    Strictest = $(if ((Get-SIItemValue $m 'strictest') -eq $true) { 1 } else { 0 }) })
        }
        foreach ($c in (Get-SICiRelationClaims -Ci $d -Rules $Rules)) { $claims.Add($c) }
    }
    [pscustomobject]@{ CiIds = $ids.ToArray(); Services = $svc.ToArray(); Claims = $claims.ToArray() }
}

function Get-SICiGraphSchemaSql {
    <# READ-ONLY. Whether the database carries the graph tables (si-data-schema.sql): 1 / 0. #>
    "SELECT CASE WHEN OBJECT_ID('sidata.CiService') IS NOT NULL AND OBJECT_ID('sidata.CiRelationClaim') IS NOT NULL AND OBJECT_ID('sidata.CiRelation') IS NOT NULL THEN 1 ELSE 0 END AS HasGraph;"
}

function Get-SICiGraphWriteSql {
    <#
        One batch: the services and relation claims of the CIs in @ids are REPLACED, ONE transaction. @s = services, @c = claims
        (ConvertTo-SICiGraphItems), @now = the build's time, @seeded = 1 once the graph was written before (the first build
        records no history: every membership would read as new), @run = the run id. With @seeded, sidata.CiChange gets one
        row per membership added / removed (#495). A database without the tables answers Skipped = 1.
    #>
    @'
SET NOCOUNT ON;
SET XACT_ABORT ON;
IF OBJECT_ID('sidata.CiService') IS NULL OR OBJECT_ID('sidata.CiRelationClaim') IS NULL
BEGIN
    SELECT 0 AS Services, 0 AS Claims, 0 AS ServiceChanges, 1 AS Skipped;
    RETURN;
END
DECLARE @t DATETIME2(3) = ISNULL(TRY_CONVERT(DATETIME2(3), @now, 127), SYSUTCDATETIME());
DECLARE @i TABLE (CiId NVARCHAR(64) NOT NULL PRIMARY KEY);
INSERT @i SELECT DISTINCT LEFT(x.value, 64) FROM OPENJSON(@ids) x WHERE x.value IS NOT NULL AND x.value <> N'';
DECLARE @ns TABLE (CiId NVARCHAR(64) NOT NULL, ServiceKey NVARCHAR(256) NOT NULL, ServiceName NVARCHAR(400) NULL, Source NVARCHAR(32) NULL, MatchedBy NVARCHAR(400) NULL,
    Criticality NVARCHAR(64) NULL, DataSensitivity NVARCHAR(64) NULL, Environment NVARCHAR(64) NULL, Owner NVARCHAR(256) NULL, Department NVARCHAR(128) NULL, Strictest BIT NOT NULL,
    PRIMARY KEY (CiId, ServiceKey));
INSERT @ns
SELECT x.CiId, LEFT(x.ServiceKey, 256), MAX(LEFT(x.ServiceName, 400)), MAX(LEFT(x.Source, 32)), MAX(LEFT(x.MatchedBy, 400)), MAX(LEFT(x.Criticality, 64)),
       MAX(LEFT(x.DataSensitivity, 64)), MAX(LEFT(x.Environment, 64)), MAX(LEFT(x.Owner, 256)), MAX(LEFT(x.Department, 128)), CAST(MAX(ISNULL(x.Strictest, 0)) AS BIT)
FROM OPENJSON(@s) WITH (CiId NVARCHAR(64), ServiceKey NVARCHAR(MAX), ServiceName NVARCHAR(MAX), Source NVARCHAR(MAX), MatchedBy NVARCHAR(MAX), Criticality NVARCHAR(MAX),
     DataSensitivity NVARCHAR(MAX), Environment NVARCHAR(MAX), Owner NVARCHAR(MAX), Department NVARCHAR(MAX), Strictest INT) x
JOIN @i i ON i.CiId = x.CiId
WHERE x.ServiceKey IS NOT NULL AND LTRIM(RTRIM(x.ServiceKey)) <> N''
GROUP BY x.CiId, LEFT(x.ServiceKey, 256);
DECLARE @nSvc INT = 0, @nClaims INT = 0, @nChg INT = 0;
BEGIN TRANSACTION;
IF @seeded = N'1' AND OBJECT_ID('sidata.CiChange') IS NOT NULL
BEGIN
    INSERT sidata.CiChange (CiId, Field, OldValue, NewValue, Source, Reason, RunId)
    SELECT s.CiId, N'service', LEFT(CONCAT(s.ServiceKey, N' -- ', s.ServiceName), 1000), NULL, LEFT(s.Source, 64), N'removed', LEFT(@run, 64)
    FROM sidata.CiService s JOIN @i i ON i.CiId = s.CiId
    WHERE NOT EXISTS (SELECT 1 FROM @ns n WHERE n.CiId = s.CiId AND n.ServiceKey = s.ServiceKey);
    SET @nChg += @@ROWCOUNT;
    INSERT sidata.CiChange (CiId, Field, OldValue, NewValue, Source, Reason, RunId)
    SELECT n.CiId, N'service', NULL, LEFT(CONCAT(n.ServiceKey, N' -- ', n.ServiceName), 1000), LEFT(n.Source, 64), LEFT(CONCAT(N'added: ', n.MatchedBy), 512), LEFT(@run, 64)
    FROM @ns n
    WHERE NOT EXISTS (SELECT 1 FROM sidata.CiService s WHERE s.CiId = n.CiId AND s.ServiceKey = n.ServiceKey);
    SET @nChg += @@ROWCOUNT;
END;
WITH t AS (SELECT s.* FROM sidata.CiService s WHERE s.CiId IN (SELECT CiId FROM @i))
MERGE t USING @ns AS n ON t.CiId = n.CiId AND t.ServiceKey = n.ServiceKey
WHEN MATCHED THEN UPDATE SET ServiceName = n.ServiceName, Source = n.Source, MatchedBy = n.MatchedBy, Criticality = n.Criticality, DataSensitivity = n.DataSensitivity,
     Environment = n.Environment, Owner = n.Owner, Department = n.Department, Strictest = n.Strictest, UpdatedAt = @t
WHEN NOT MATCHED BY TARGET THEN INSERT (CiId, ServiceKey, ServiceName, Source, MatchedBy, Criticality, DataSensitivity, Environment, Owner, Department, Strictest, FirstSeen, UpdatedAt)
     VALUES (n.CiId, n.ServiceKey, n.ServiceName, n.Source, n.MatchedBy, n.Criticality, n.DataSensitivity, n.Environment, n.Owner, n.Department, n.Strictest, @t, @t)
WHEN NOT MATCHED BY SOURCE THEN DELETE;
SET @nSvc = @@ROWCOUNT;
DELETE c FROM sidata.CiRelationClaim c JOIN @i i ON i.CiId = c.OwnerCiId;
INSERT sidata.CiRelationClaim (OwnerCiId, RelationId, Kind, FromCiId, ToType, ToValue, Detail, Source, Confidence)
SELECT DISTINCT x.OwnerCiId, LEFT(x.RelationId, 48), LEFT(x.Kind, 48), LEFT(x.FromCiId, 64), LEFT(x.ToType, 48), LEFT(x.ToValue, 400), LEFT(x.Detail, 400), LEFT(x.Source, 32), LEFT(x.Confidence, 16)
FROM OPENJSON(@c) WITH (OwnerCiId NVARCHAR(64), RelationId NVARCHAR(MAX), Kind NVARCHAR(MAX), FromCiId NVARCHAR(MAX), ToType NVARCHAR(MAX), ToValue NVARCHAR(MAX), Detail NVARCHAR(MAX),
     Source NVARCHAR(MAX), Confidence NVARCHAR(MAX)) x
JOIN @i i ON i.CiId = x.OwnerCiId
WHERE x.Kind IS NOT NULL AND x.FromCiId IS NOT NULL AND x.ToType IS NOT NULL AND x.ToValue IS NOT NULL AND x.ToValue <> N'';
SET @nClaims = @@ROWCOUNT;
COMMIT TRANSACTION;
SELECT @nSvc AS Services, @nClaims AS Claims, @nChg AS ServiceChanges, 0 AS Skipped;
'@
}

function Get-SICiRelationResolveSql {
    <#
        After the build, ONE statement: every claim (sidata.CiRelationClaim, one relation per from / kind / target) is
        resolved -- a target of type 'ci' is that CI; an identifier points at the CI that carries it (sidata.RecordIdentifier
        -> sidata.CiRecord.CiId, the smallest id when two do), else stays the identifier; a node stays a node -- and MERGEd
        into sidata.CiRelation: a new one is active from now (first seen), a claimed one is seen again (last seen, at most once
        every 20 hours unless something about it changed), one no claim holds any more is GONE (never deleted; claimed again,
        it is active again). @seeded = 1: sidata.CiChange gets 'relation' (on the from CI) and 'relation_in' (on the to CI)
        rows for every relation added, ended or pointing at another CI (#495). Answers one row of counts; Skipped = 1 when
        the database has no graph tables.
    #>
    @'
SET NOCOUNT ON;
SET XACT_ABORT ON;
IF OBJECT_ID('sidata.CiRelation') IS NULL OR OBJECT_ID('sidata.CiRelationClaim') IS NULL
BEGIN
    SELECT 0 AS Active, 0 AS Added, 0 AS Removed, 0 AS Retargeted, 0 AS Resolved, 0 AS Unresolved, 1 AS Skipped;
    RETURN;
END
DECLARE @t DATETIME2(3) = ISNULL(TRY_CONVERT(DATETIME2(3), @now, 127), SYSUTCDATETIME());
CREATE TABLE #r (RelKey VARBINARY(32) NOT NULL PRIMARY KEY, FromCiId NVARCHAR(64) NOT NULL, Kind NVARCHAR(48) NOT NULL, ToType NVARCHAR(48) NOT NULL, ToValue NVARCHAR(400) NOT NULL,
    ToCiId NVARCHAR(64) NULL, Detail NVARCHAR(400) NULL, Source NVARCHAR(32) NULL, Confidence NVARCHAR(16) NULL);
WITH c AS (
    SELECT x.FromCiId, x.Kind, x.ToType, x.ToValue, x.Detail, x.Source, x.Confidence,
           ROW_NUMBER() OVER (PARTITION BY x.FromCiId, x.Kind, x.ToType, x.ToValue ORDER BY x.OwnerCiId, x.RelationId) AS rn
    FROM sidata.CiRelationClaim x
    -- only the claims of a CI that still holds records: a CI merged into another (its records now carry the surviving id)
    -- claims nothing any more, so its relations end
    WHERE EXISTS (SELECT 1 FROM sidata.CiRecord cr WHERE cr.CiId = x.OwnerCiId))
INSERT #r (RelKey, FromCiId, Kind, ToType, ToValue, Detail, Source, Confidence)
SELECT HASHBYTES('SHA2_256', CONCAT(c.FromCiId, N'|', c.Kind, N'|', c.ToType, N'|', c.ToValue)), c.FromCiId, c.Kind, c.ToType, c.ToValue, c.Detail, c.Source, c.Confidence
FROM c WHERE c.rn = 1;
UPDATE #r SET ToCiId = LEFT(ToValue, 64) WHERE ToType = N'ci';
UPDATE r SET ToCiId = m.CiId
FROM #r r
CROSS APPLY (SELECT MIN(cr.CiId) AS CiId FROM sidata.RecordIdentifier ri JOIN sidata.CiRecord cr ON cr.RecordKey = ri.RecordKey
             WHERE ri.IdType = r.ToType AND ri.IdValue = (CASE WHEN LEN(r.ToValue) > 128 THEN N'sha256:' + LOWER(CONVERT(NVARCHAR(64), HASHBYTES('SHA2_256', CAST(LOWER(LTRIM(RTRIM(r.ToValue))) AS NVARCHAR(4000))), 2)) ELSE LOWER(LTRIM(RTRIM(r.ToValue))) END) AND cr.CiId IS NOT NULL) m
WHERE r.ToType <> N'ci' AND m.CiId IS NOT NULL;
-- a CI is never related to itself (a service principal and its app registration in one CI)
DELETE FROM #r WHERE ToCiId IS NOT NULL AND ToCiId = FromCiId;
DECLARE @chg TABLE (Act NVARCHAR(10), FromCiId NVARCHAR(64), Kind NVARCHAR(48), ToValue NVARCHAR(400), ToCiId NVARCHAR(64), Source NVARCHAR(32),
    NewState NVARCHAR(8), OldState NVARCHAR(8), OldToCiId NVARCHAR(64));
BEGIN TRANSACTION;
MERGE sidata.CiRelation AS t USING #r AS s ON t.RelKey = s.RelKey
WHEN MATCHED AND (t.State <> N'active' OR ISNULL(t.ToCiId, N'') <> ISNULL(s.ToCiId, N'') OR ISNULL(t.Detail, N'') <> ISNULL(s.Detail, N'')
                  OR ISNULL(t.Source, N'') <> ISNULL(s.Source, N'') OR ISNULL(t.Confidence, N'') <> ISNULL(s.Confidence, N'') OR t.LastSeen < DATEADD(hour, -20, @t)) THEN
    UPDATE SET ToCiId = s.ToCiId, Detail = s.Detail, Source = s.Source, Confidence = s.Confidence, LastSeen = @t, State = N'active', GoneAt = NULL,
               ChangedAt = CASE WHEN t.State <> N'active' OR ISNULL(t.ToCiId, N'') <> ISNULL(s.ToCiId, N'') THEN @t ELSE t.ChangedAt END
WHEN NOT MATCHED BY TARGET THEN
    INSERT (RelKey, FromCiId, Kind, ToType, ToValue, ToCiId, Detail, Source, Confidence, State, FirstSeen, LastSeen, ChangedAt)
    VALUES (s.RelKey, s.FromCiId, s.Kind, s.ToType, s.ToValue, s.ToCiId, s.Detail, s.Source, s.Confidence, N'active', @t, @t, @t)
WHEN NOT MATCHED BY SOURCE AND t.State = N'active' THEN
    UPDATE SET State = N'gone', GoneAt = @t, ChangedAt = @t
OUTPUT $action, inserted.FromCiId, inserted.Kind, inserted.ToValue, inserted.ToCiId, inserted.Source, inserted.State, deleted.State, deleted.ToCiId INTO @chg;
DECLARE @added INT = (SELECT COUNT(*) FROM @chg WHERE Act = N'INSERT' OR (Act = N'UPDATE' AND OldState = N'gone' AND NewState = N'active'));
DECLARE @removed INT = (SELECT COUNT(*) FROM @chg WHERE Act = N'UPDATE' AND OldState = N'active' AND NewState = N'gone');
DECLARE @retarget INT = (SELECT COUNT(*) FROM @chg WHERE Act = N'UPDATE' AND OldState = N'active' AND NewState = N'active' AND ISNULL(OldToCiId, N'') <> ISNULL(ToCiId, N''));
IF @seeded = N'1' AND OBJECT_ID('sidata.CiChange') IS NOT NULL
BEGIN
    INSERT sidata.CiChange (CiId, Field, OldValue, NewValue, Source, Reason, RunId)
    SELECT v.CiId, v.Field, LEFT(v.OldV, 1000), LEFT(v.NewV, 1000), LEFT(x.Source, 64), v.Reason, LEFT(@run, 64)
    FROM @chg x
    LEFT JOIN sidata.Ci tn ON tn.CiId = x.ToCiId
    LEFT JOIN sidata.Ci fn ON fn.CiId = x.FromCiId
    CROSS APPLY (SELECT CASE WHEN x.Act = N'INSERT' OR (x.OldState = N'gone' AND x.NewState = N'active') THEN N'added'
                             WHEN x.OldState = N'active' AND x.NewState = N'gone' THEN N'removed'
                             WHEN ISNULL(x.OldToCiId, N'') <> ISNULL(x.ToCiId, N'') THEN N'points at another CI' END AS What) w
    CROSS APPLY (VALUES
        (x.FromCiId, N'relation', CONCAT(x.Kind, N': ', COALESCE(tn.Name, x.ToCiId, x.ToValue))),
        (COALESCE(x.ToCiId, x.OldToCiId), N'relation_in', CONCAT(x.Kind, N' from: ', COALESCE(fn.Name, x.FromCiId)))
    ) v0(CiId, Field, Label)
    CROSS APPLY (SELECT v0.CiId AS CiId, v0.Field AS Field,
                        CASE WHEN w.What = N'added' THEN NULL ELSE v0.Label END AS OldV,
                        CASE WHEN w.What = N'removed' THEN NULL ELSE v0.Label END AS NewV, w.What AS Reason) v
    WHERE w.What IS NOT NULL AND v.CiId IS NOT NULL;
END
COMMIT TRANSACTION;
SELECT (SELECT COUNT(*) FROM sidata.CiRelation WHERE State = N'active') AS Active, @added AS Added, @removed AS Removed, @retarget AS Retargeted,
       (SELECT COUNT(*) FROM #r WHERE ToCiId IS NOT NULL) AS Resolved, (SELECT COUNT(*) FROM #r WHERE ToCiId IS NULL) AS Unresolved, 0 AS Skipped;
'@
}

function Get-SICiRelationPostSql {
    <#
        READ-ONLY, one page (5,000) of the relations to post to SI_CIRelation_CL, in key order after @after (hex, '' = from
        the start): the ones that changed in this build (ChangedAt >= @since -- added, ended, pointing at another CI) and,
        with @full = 1, every active one (the weekly full refresh).
    #>
    @'
SET NOCOUNT ON;
DECLARE @a VARBINARY(32) = CASE WHEN ISNULL(@after, N'') = N'' THEN 0x00 ELSE CONVERT(VARBINARY(32), @after, 2) END;
DECLARE @s DATETIME2(3) = ISNULL(TRY_CONVERT(DATETIME2(3), @since, 127), SYSUTCDATETIME());
SELECT TOP (5000) CONVERT(VARCHAR(64), r.RelKey, 2) AS RelKeyHex, r.FromCiId, r.Kind, r.ToType, r.ToValue, r.ToCiId, r.Detail, r.Source, r.Confidence, r.State,
       r.FirstSeen, r.LastSeen, r.GoneAt, CASE WHEN r.ChangedAt >= @s THEN N'change' ELSE N'full' END AS RowKind
FROM sidata.CiRelation r
WHERE r.RelKey > @a AND (r.ChangedAt >= @s OR (@full = N'1' AND r.State = N'active'))
ORDER BY r.RelKey;
'@
}

function ConvertTo-SICiRelationPostRow {
    <# PURE. One sidata.CiRelation row -> its SI_CIRelation_CL row (the columns Risk Analysis reads; readers take the latest row per from / kind / target). #>
    param([Parameter(Mandatory)]$Row, [datetime]$Now = [datetime]::UtcNow)
    $iso = { param($v) if ($v -is [datetime]) { [datetime]::SpecifyKind($v, [DateTimeKind]::Utc).ToString('o') } elseif ($v) { [string]$v } else { $null } }
    [pscustomobject][ordered]@{
        si_from_ci_id          = [string](Get-SIItemValue $Row 'FromCiId')
        si_relation_kind       = [string](Get-SIItemValue $Row 'Kind')
        si_to_type             = [string](Get-SIItemValue $Row 'ToType')
        si_to_value            = [string](Get-SIItemValue $Row 'ToValue')
        si_to_ci_id            = [string](Get-SIItemValue $Row 'ToCiId')
        si_relation_detail     = [string](Get-SIItemValue $Row 'Detail')
        si_relation_source     = [string](Get-SIItemValue $Row 'Source')
        si_relation_confidence = [string](Get-SIItemValue $Row 'Confidence')
        si_relation_state      = [string](Get-SIItemValue $Row 'State')
        si_first_seen          = (& $iso (Get-SIItemValue $Row 'FirstSeen'))
        si_last_seen           = (& $iso (Get-SIItemValue $Row 'LastSeen'))
        si_gone_at             = (& $iso (Get-SIItemValue $Row 'GoneAt'))
        si_row_kind            = [string](Get-SIItemValue $Row 'RowKind')
        si_collection_time     = $Now.ToUniversalTime().ToString('o')
    }
}

function Invoke-SICiRelationStep {
    <#
        After the CI build's batches: resolve the claims into sidata.CiRelation (Get-SICiRelationResolveSql) and post the
        changed relations -- every active one with -Full -- to SI_CIRelation_CL. -Post { param($Rows) } -> rows accepted
        (tests); without it Send-SIObjectMapRows. -NoPost: resolve only. Never throws; answers a summary
        (Skipped = the database has no graph tables; PostFailed = some rows did not reach Log Analytics -- the next build
        posts every active relation).
    #>
    param([Parameter(Mandatory)][scriptblock]$Sql, [scriptblock]$Post, [switch]$NoPost, [datetime]$Now = [datetime]::UtcNow, [bool]$Full = $false, [bool]$Seeded = $false,
          [string]$RunId = '', [scriptblock]$Log)
    if (-not $Log) { $Log = { param($l, $m) Write-Host ('[' + $l + '] ' + $m) } }
    $out = [ordered]@{ Skipped = $false; Active = 0; Added = 0; Removed = 0; Retargeted = 0; Resolved = 0; Unresolved = 0; Posted = 0; PostFailed = $false; Error = '' }
    try {
        $nowIso = $Now.ToUniversalTime().ToString('o')
        $r = @(& $Sql (Get-SICiRelationResolveSql) @{ now = $nowIso; seeded = $(if ($Seeded) { '1' } else { '0' }); run = $RunId } 'rows') | Select-Object -First 1
        if ($null -eq $r) { throw 'the relation statement answered no result' }
        if ([int](Get-SIItemValue $r 'Skipped') -eq 1) {
            $out.Skipped = $true
            & $Log 'INFO' 'CIs: the relations between CIs were not written -- the database is not updated yet (run the updater).'
            return [pscustomobject]$out
        }
        foreach ($k in 'Active', 'Added', 'Removed', 'Retargeted', 'Resolved', 'Unresolved') { $out[$k] = [int](Get-SIItemValue $r $k) }
        if (-not $NoPost) {
            if (-not $Post -and -not (Get-Command -Name Send-SIObjectMapRows -ErrorAction SilentlyContinue)) {
                . (Join-Path (Split-Path -Parent $PSScriptRoot) '_shared\SI-LogIngest.ps1')
            }
            $after = ''
            while ($true) {
                $page = @(& $Sql (Get-SICiRelationPostSql) @{ after = $after; since = $nowIso; full = $(if ($Full) { '1' } else { '0' }) } 'rows')
                if ($page.Count -eq 0) { break }
                $rows = @($page | ForEach-Object { ConvertTo-SICiRelationPostRow -Row $_ -Now $Now })
                $sent = 0
                try {
                    if ($Post) { $sent = [int](& $Post $rows) }
                    else { $sent = [int](Send-SIObjectMapRows -Rows $rows -TableName 'SI_CIRelation' -DcrName $(if ($global:SI_CIRelation_DcrName) { [string]$global:SI_CIRelation_DcrName } else { 'dcr-si-cirelation' })) }
                } catch { & $Log 'WARN' ("CIs: relations could not be posted to SI_CIRelation_CL -- {0}. Every active relation is posted on the next build." -f $_.Exception.Message); $sent = 0 }
                if ($sent -ge $rows.Count) { $out.Posted += $rows.Count } else { $out.PostFailed = $true; break }
                $after = [string](Get-SIItemValue $page[$page.Count - 1] 'RelKeyHex')
                if ($page.Count -lt 5000) { break }
            }
        }
        & $Log 'INFO' ("CIs: {0} relation(s) between CIs ({1} new, {2} ended, {3} now point at another CI); {4} point at something that is not a CI (a subscription, a group, a role); SI_CIRelation_CL: {5} row(s){6}" -f `
            $out.Active, $out.Added, $out.Removed, $out.Retargeted, $out.Unresolved, $out.Posted, $(if ($Full) { ' (full refresh)' } else { '' }))
    } catch {
        $out.Error = $_.Exception.Message; $out.PostFailed = $true
        & $Log 'WARN' ("CIs: the relations between CIs were not updated this run -- {0}. The CIs are built; the next build tries again." -f $_.Exception.Message)
    }
    [pscustomobject]$out
}
