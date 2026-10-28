#Requires -Version 5.1
<#
    AZURE CONTEXT -- what Azure knows about a resource beyond its own properties, read ONCE per run and written as parts on
    the Azure records the discovery already captured (owner 2026-10-11: "go back to each of the data sources and figure out
    if you can extend the query results with more context ... this is the whole value of si").

    Every read is a Resource Graph query SUMMARISED IN THE QUERY (one row per resource, never the raw table), paged to the
    end and throttle-safe (Invoke-SIArgPaged). Every read is its own try: one that fails is said once and leaves its part
    out -- an unknown value is never written as "no". READ-ONLY: nothing here writes to Azure, the directory or anywhere
    outside SecurityInsight.

      part 'backup'    recoveryservicesresources (Recovery Services protected items + Backup vault instances), the newest
                       item per protected resource: protected, last status, last time, vault (id + name), policy (id + name).
                       A virtual machine without an item is { protected = false } when the read completed.
      part 'access'    authorizationresources: who holds Owner / Contributor / User Access Administrator / Role Based
                       Access Control Administrator DIRECTLY at the resource or at its resource group -- principal id + name
                       + type, role id + name, where it is assigned. (Inherited from the subscription or a management
                       group is not listed here: that is the same for every resource of the subscription.)
      part 'policy'    policyresources (policy states): how many policies the resource does not comply with, and up to
                       three of them (id + name).
      part 'change'    resourcechanges, the last 14 days: when the resource was last changed, by whom (id + name), how,
                       and how many changes.
      part 'patch'     patchassessmentresources: pending critical / security updates, reboot pending, when assessed.
      part 'defender'  securityresources (pricings): the Defender for Cloud plan that covers the resource's type in its
                       subscription, its tier and sub-plan, and the subscription's posture (CSPM) tier.
      part 'attached'  a public IP address: the resource it is attached to (id + name + type) -- through its IP
                       configuration and the capture's child map (a network interface -> its virtual machine).
      part 'diag'      diagnostic settings, TIER 0 AND 1 ONLY (one Azure Resource Manager call per resource, so only where
                       it matters most): enabled, and each setting's destinations (Add-SIRecordDiagnosticParts, called
                       from the record publish with the profile rows that carry the tier).

    Rights: Reader (Resource Graph, diagnostic settings); Directory.Read.All for the principal names (already held).
    No PowerShell modules. PowerShell 5.1 safe: no ?. / ??, no ternary.
#>

# Azure access: plain REST, no PowerShell modules (engine/_shared/SI-AzRest.ps1).
if (-not (Get-Command -Name Invoke-SIArm -ErrorAction SilentlyContinue)) { . (Join-Path $PSScriptRoot '../../_shared/SI-AzRest.ps1') }
if (-not (Get-Command -Name Invoke-SIArgPaged -ErrorAction SilentlyContinue)) { . (Join-Path $PSScriptRoot 'Invoke-SIArgPaged.ps1') }
# ARM id parsing and the Azure CI scope (Get-SIArmIdInfo, Resolve-SIAzurePlacement)
if (-not (Get-Command -Name Get-SIArmIdInfo -ErrorAction SilentlyContinue)) { . (Join-Path $PSScriptRoot '../../data-model/SI-AzureChildren.ps1') }
# #727 the on-disk lookups of the context reads (the access scopes, the backed-up resources)
if (-not (Get-Command -Name New-SIDiskTextLookup -ErrorAction SilentlyContinue)) { . (Join-Path $PSScriptRoot '../../_shared/SI-DiskLookup.ps1') }

# The built-in roles that let a principal change the resource or hand out access to it (role definition id -> name). The
# ids are the same in every tenant. A custom role is not listed here.
$script:SIAzurePrivilegedRoles = [ordered]@{
    '8e3af657-a8ff-443c-a75c-2fe8c4bcb635' = 'Owner'
    'b24988ac-6180-42a0-ab88-20f7382dd24c' = 'Contributor'
    '18d7d88d-d35e-4fb5-a5c3-7773c20a72d9' = 'User Access Administrator'
    'f58310d9-a9f6-439a-9e8d-f62e7b41a168' = 'Role Based Access Control Administrator'
}

# The Defender for Cloud plan (the pricing's name) that covers a resource type.
$script:SIAzureDefenderPlanByType = @{
    'microsoft.compute/virtualmachines'              = 'VirtualMachines'
    'microsoft.compute/virtualmachinescalesets'      = 'VirtualMachines'
    'microsoft.hybridcompute/machines'               = 'VirtualMachines'
    'microsoft.storage/storageaccounts'              = 'StorageAccounts'
    'microsoft.sql/servers'                          = 'SqlServers'
    'microsoft.sql/managedinstances'                 = 'SqlServers'
    'microsoft.sqlvirtualmachine/sqlvirtualmachines' = 'SqlServerVirtualMachines'
    'microsoft.keyvault/vaults'                      = 'KeyVaults'
    'microsoft.web/sites'                            = 'AppServices'
    'microsoft.web/serverfarms'                      = 'AppServices'
    'microsoft.containerservice/managedclusters'     = 'Containers'
    'microsoft.containerregistry/registries'         = 'Containers'
    'microsoft.documentdb/databaseaccounts'          = 'CosmosDbs'
    'microsoft.dbforpostgresql/flexibleservers'      = 'OpenSourceRelationalDatabases'
    'microsoft.dbforpostgresql/servers'              = 'OpenSourceRelationalDatabases'
    'microsoft.dbformysql/flexibleservers'           = 'OpenSourceRelationalDatabases'
    'microsoft.dbformysql/servers'                   = 'OpenSourceRelationalDatabases'
    'microsoft.dbformariadb/servers'                 = 'OpenSourceRelationalDatabases'
    'microsoft.cognitiveservices/accounts'           = 'AI'
    'microsoft.machinelearningservices/workspaces'   = 'AI'
    'microsoft.apimanagement/service'                = 'Api'
}

# ---------------------------------------------------------------------------------------------------------------------
#  The queries (PURE)
# ---------------------------------------------------------------------------------------------------------------------

function Get-SIAzureBackupKql {
    <# PURE. The newest backup item per protected resource (Recovery Services vaults and Backup vaults). #>
    @"
recoveryservicesresources
| where type in~ ('microsoft.recoveryservices/vaults/backupfabrics/protectioncontainers/protecteditems', 'microsoft.dataprotection/backupvaults/backupinstances')
| extend p = properties, ItemId = tolower(id)
| extend ResourceId = tolower(coalesce(tostring(p.sourceResourceId), tostring(p.dataSourceInfo.resourceID), tostring(p.virtualMachineId)))
| where isnotempty(ResourceId)
| extend LastTime = todatetime(coalesce(tostring(p.lastBackupTime), tostring(p.lastRecoveryPoint)))
| extend LastStatus = coalesce(tostring(p.lastBackupStatus), tostring(p.protectionStatus.status))
| extend State = coalesce(tostring(p.protectionState), tostring(p.currentProtectionState))
| extend PolicyId = tolower(coalesce(tostring(p.policyId), tostring(p.policyInfo.policyId)))
| extend PolicyName = coalesce(tostring(p.policyName), tostring(split(PolicyId, '/')[-1]))
| extend VaultId = tostring(split(tostring(split(ItemId, '/backupfabrics/')[0]), '/backupinstances/')[0])
| extend VaultName = tostring(split(VaultId, '/')[-1])
| summarize arg_max(LastTime, LastStatus, State, PolicyId, PolicyName, VaultId, VaultName), Items = count() by ResourceId
| order by ResourceId asc
"@
}

function Get-SIAzureAccessKql {
    <# PURE. The privileged role assignments made at a resource group or below it, one row per scope. #>
    $ids = (@($script:SIAzurePrivilegedRoles.Keys) | ForEach-Object { "'$_'" }) -join ', '
    @"
authorizationresources
| where type =~ 'microsoft.authorization/roleassignments'
| extend Scope = tolower(tostring(properties.scope)), RoleId = tolower(tostring(split(tostring(properties.roleDefinitionId), '/')[-1]))
| where RoleId in ($ids)
| where Scope contains '/resourcegroups/'
| summarize Assignments = make_set(bag_pack('p', tolower(tostring(properties.principalId)), 't', tostring(properties.principalType), 'r', RoleId)) by Scope
| order by Scope asc
"@
}

function Get-SIAzurePolicyKql {
    <# PURE. Per resource: how many policies it does not comply with, and up to three of them (id + name). #>
    @"
policyresources
| where type =~ 'microsoft.policyinsights/policystates'
| where tostring(properties.complianceState) =~ 'NonCompliant'
| extend ResourceId = tolower(tostring(properties.resourceId)), PolicyId = tolower(tostring(properties.policyDefinitionId))
| where isnotempty(ResourceId) and isnotempty(PolicyId)
| summarize by ResourceId, PolicyId
| join kind=leftouter (
    policyresources
    | where type =~ 'microsoft.authorization/policydefinitions'
    | project PolicyId = tolower(id), PolicyName = tostring(properties.displayName)
  ) on PolicyId
| order by ResourceId asc, PolicyName asc
| summarize NonCompliant = count(), Top = make_list(bag_pack('id', PolicyId, 'name', PolicyName), 3) by ResourceId
| order by ResourceId asc
"@
}

function Get-SIAzurePolicyNameKql {
    <# PURE. Every policy definition's display name (asked without a subscription filter: the built-in definitions live
       at the tenant, and a query limited to subscriptions does not return them). #>
    @"
policyresources
| where type =~ 'microsoft.authorization/policydefinitions'
| project PolicyId = tolower(id), PolicyName = tostring(properties.displayName)
| order by PolicyId asc
"@
}

function Get-SIAzureChangeKql {
    <# PURE. Per resource: its newest change of the last -Days days (when, by whom, how) and the number of changes. #>
    param([int]$Days = 14)
    if ($Days -lt 1) { $Days = 14 }
    @"
resourcechanges
| extend ChangeTime = todatetime(properties.changeAttributes.timestamp), ResourceId = tolower(tostring(properties.targetResourceId))
| where ChangeTime > ago($($Days)d) and isnotempty(ResourceId)
| summarize arg_max(ChangeTime, ChangedBy = tostring(properties.changeAttributes.changedBy), ChangedByType = tostring(properties.changeAttributes.changedByType), ChangeType = tostring(properties.changeType), ClientType = tostring(properties.changeAttributes.clientType)), Changes = count() by ResourceId
| order by ResourceId asc
"@
}

function Get-SIAzurePatchKql {
    <# PURE. Per machine (Azure VM, Azure Arc): the newest update assessment -- pending critical / security updates. #>
    @"
patchassessmentresources
| where type in~ ('microsoft.compute/virtualmachines/patchassessmentresults', 'microsoft.hybridcompute/machines/patchassessmentresults')
| extend ResourceId = tostring(split(tolower(id), '/patchassessmentresults/')[0])
| where isnotempty(ResourceId)
| extend AssessedAt = todatetime(properties.lastModifiedDateTime),
         Critical = toint(properties.availablePatchCountByClassification.critical),
         Security = toint(properties.availablePatchCountByClassification.security),
         RebootPending = tobool(properties.rebootPending),
         Status = tostring(properties.status)
| summarize arg_max(AssessedAt, Critical, Security, RebootPending, Status) by ResourceId
| order by ResourceId asc
"@
}

function Get-SIAzureDefenderPlanKql {
    <# PURE. Every Defender for Cloud plan of every subscription: name, tier (Free / Standard), sub-plan. #>
    @"
securityresources
| where type =~ 'microsoft.security/pricings'
| project SubscriptionId = tolower(subscriptionId), Plan = tostring(name), Tier = tostring(properties.pricingTier), SubPlan = tostring(properties.subPlan)
| order by SubscriptionId asc, Plan asc
"@
}

# ---------------------------------------------------------------------------------------------------------------------
#  Rows -> parts (PURE)
# ---------------------------------------------------------------------------------------------------------------------

function Get-SIAzureContextValue {
    <# PURE. A named value of a row (PSObject or dictionary), or $null. #>
    param($Row, [string]$Name)
    if ($null -eq $Row) { return $null }
    if ($Row -is [System.Collections.IDictionary]) { if ($Row.Contains($Name)) { return $Row[$Name] }; return $null }
    $p = $Row.PSObject.Properties[$Name]; if ($p) { return $p.Value }
    return $null
}

function ConvertTo-SIAzureContextTime {
    <# PURE. A Resource Graph time value as UTC ISO text ('2026-10-01T21:03:27Z'), or '' when there is none. #>
    param($Value)
    if ($null -eq $Value -or [string]$Value -eq '') { return '' }
    $t = $null
    if ($Value -is [datetime]) { $t = $Value.ToUniversalTime() }
    else {
        $d = [datetimeoffset]::MinValue
        if ([datetimeoffset]::TryParse([string]$Value, [System.Globalization.CultureInfo]::InvariantCulture, [System.Globalization.DateTimeStyles]::AssumeUniversal, [ref]$d)) { $t = $d.UtcDateTime }
    }
    if ($null -eq $t -or $t.Year -lt 1990) { return '' }
    return $t.ToString("yyyy-MM-ddTHH:mm:ssZ", [System.Globalization.CultureInfo]::InvariantCulture)
}

function ConvertTo-SIAzureBackupParts {
    <# PURE. Backup rows -> @{ <resource id> = part }: protected, lastStatus, lastTime, state, vaultId + vaultName,
       policyId + policyName, items. #>
    param([AllowEmptyCollection()][object[]]$Rows = @())
    $map = @{}
    foreach ($r in $Rows) {
        $id = ([string](Get-SIAzureContextValue $r 'ResourceId')).Trim().ToLowerInvariant()
        if (-not $id) { continue }
        $o = [ordered]@{ protected = $true }
        $state = ([string](Get-SIAzureContextValue $r 'State')).Trim()
        # an item whose protection was stopped is still listed: it keeps its recovery points, but nothing new is backed up
        if ($state -match '(?i)stopped|notprotected|softdeleted') { $o['protected'] = $false }
        if ($state) { $o['state'] = $state }
        $ls = ([string](Get-SIAzureContextValue $r 'LastStatus')).Trim(); if ($ls) { $o['lastStatus'] = $ls }
        $lt = ConvertTo-SIAzureContextTime (Get-SIAzureContextValue $r 'LastTime'); if ($lt) { $o['lastTime'] = $lt }
        foreach ($pair in @(@('vaultId', 'VaultId'), @('vaultName', 'VaultName'), @('policyId', 'PolicyId'), @('policyName', 'PolicyName'))) {
            $v = ([string](Get-SIAzureContextValue $r $pair[1])).Trim(); if ($v) { $o[$pair[0]] = $v }
        }
        $n = Get-SIAzureContextValue $r 'Items'; if ($null -ne $n -and "$n" -ne '') { $o['items'] = [int]$n }
        $map[$id] = [pscustomobject]$o
    }
    return $map
}

function ConvertTo-SIAzureAccessIndex {
    <# PURE. Access rows -> @{ Scopes = @{ <scope> = [ @{ p; t; r } ] }; PrincipalIds = [distinct ids] }. #>
    param([AllowEmptyCollection()][object[]]$Rows = @())
    $scopes = @{}
    $ids = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    foreach ($r in $Rows) {
        $scope = ([string](Get-SIAzureContextValue $r 'Scope')).Trim().TrimEnd('/').ToLowerInvariant()
        if (-not $scope) { continue }
        $list = Get-SIAzureContextValue $r 'Assignments'
        if ($list -is [string]) { try { $list = $list | ConvertFrom-Json } catch { $list = @() } }
        $items = New-Object System.Collections.Generic.List[object]
        foreach ($a in @($list)) {
            if ($null -eq $a) { continue }
            $p = ([string](Get-SIAzureContextValue $a 'p')).Trim().ToLowerInvariant(); if (-not $p) { continue }
            $items.Add(@{ p = $p; t = [string](Get-SIAzureContextValue $a 't'); r = ([string](Get-SIAzureContextValue $a 'r')).Trim().ToLowerInvariant() })
            [void]$ids.Add($p)
        }
        if ($items.Count -gt 0) { $scopes[$scope] = $items.ToArray() }
    }
    return @{ Scopes = $scopes; PrincipalIds = @($ids) }
}

function Get-SIAzureResourceGroupScope {
    <# PURE. The resource group scope of an ARM id ('/subscriptions/<id>/resourcegroups/<name>'), lower case; ''. #>
    param([AllowNull()][AllowEmptyString()][string]$Id)
    $m = [regex]::Match(([string]$Id).Trim().ToLowerInvariant(), '^(/subscriptions/[^/]+/resourcegroups/[^/]+)')
    if ($m.Success) { return $m.Groups[1].Value }
    return ''
}

function Get-SIAzureAccessPart {
    <#
        PURE. The 'access' part of one resource: the privileged assignments made at the resource itself and at its resource
        group -- principal id + name + type, role id + name, where assigned. $null when there is none (the read found
        nothing direct: privileged access then comes only from the subscription or above).
    #>
    param([Parameter(Mandatory)][string]$ResourceId, [hashtable]$Scopes = @{}, [hashtable]$PrincipalNames = @{})
    $rid = $ResourceId.Trim().TrimEnd('/').ToLowerInvariant()
    $rg = Get-SIAzureResourceGroupScope $rid
    $out = New-Object System.Collections.Generic.List[object]
    $seen = New-Object 'System.Collections.Generic.HashSet[string]'
    foreach ($lvl in @(@($rid, 'resource'), @($rg, 'resource group'))) {
        $scope = [string]$lvl[0]
        if (-not $scope -or -not $Scopes.ContainsKey($scope)) { continue }
        if ($lvl[1] -eq 'resource group' -and $scope -eq $rid) { continue }
        foreach ($a in @($Scopes[$scope])) {
            $key = '{0}|{1}|{2}' -f $a.p, $a.r, $lvl[1]
            if (-not $seen.Add($key)) { continue }
            $role = [string]$a.r; if ($script:SIAzurePrivilegedRoles.Contains($role)) { $role = [string]$script:SIAzurePrivilegedRoles[$role] }
            $item = [ordered]@{ principal_id = [string]$a.p }
            if ($PrincipalNames -and $PrincipalNames.ContainsKey([string]$a.p) -and [string]$PrincipalNames[[string]$a.p]) { $item['principal_name'] = [string]$PrincipalNames[[string]$a.p] }
            if ([string]$a.t) { $item['principal_type'] = [string]$a.t }
            $item['role'] = $role; $item['role_id'] = [string]$a.r; $item['assigned_at'] = [string]$lvl[1]
            $out.Add([pscustomobject]$item)
        }
    }
    if ($out.Count -eq 0) { return $null }
    $sorted = @($out.ToArray() | Sort-Object { [string]$_.assigned_at }, { [string]$_.role }, { [string]$_.principal_id })
    return [pscustomobject][ordered]@{ total = $sorted.Count; assignments = $sorted }
}

function ConvertTo-SIAzurePolicyParts {
    <# PURE. Policy rows -> @{ <resource id> = { nonCompliant; top = [ { id; name } ] } }. A policy whose display name the
       query did not return takes it from -Names (policy id -> name), else it is listed by its id alone. #>
    param([AllowEmptyCollection()][object[]]$Rows = @(), [hashtable]$Names = @{})
    $map = @{}
    foreach ($r in $Rows) {
        $id = ([string](Get-SIAzureContextValue $r 'ResourceId')).Trim().ToLowerInvariant()
        if (-not $id) { continue }
        $top = Get-SIAzureContextValue $r 'Top'
        if ($top -is [string]) { try { $top = $top | ConvertFrom-Json } catch { $top = @() } }
        $items = New-Object System.Collections.Generic.List[object]
        foreach ($t in @($top)) {
            if ($null -eq $t) { continue }
            $pid_ = ([string](Get-SIAzureContextValue $t 'id')).Trim().ToLowerInvariant(); if (-not $pid_) { continue }
            $pn = ([string](Get-SIAzureContextValue $t 'name')).Trim()
            if (-not $pn -and $Names -and $Names.ContainsKey($pid_)) { $pn = [string]$Names[$pid_] }
            $it = [ordered]@{ id = $pid_ }; if ($pn) { $it['name'] = $pn }
            $items.Add([pscustomobject]$it)
        }
        $n = 0; $nv = Get-SIAzureContextValue $r 'NonCompliant'; if ($null -ne $nv -and "$nv" -ne '') { $n = [int]$nv }
        if ($n -lt $items.Count) { $n = $items.Count }
        if ($n -le 0) { continue }
        $map[$id] = [pscustomobject][ordered]@{ nonCompliant = $n; top = $items.ToArray() }
    }
    return $map
}

function Get-SIAzurePolicyUnnamedIds {
    <# PURE. The policy ids of the rows whose display name the query did not return. #>
    param([AllowEmptyCollection()][object[]]$Rows = @())
    $ids = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    foreach ($r in $Rows) {
        $top = Get-SIAzureContextValue $r 'Top'
        if ($top -is [string]) { try { $top = $top | ConvertFrom-Json } catch { $top = @() } }
        foreach ($t in @($top)) {
            if ($null -eq $t) { continue }
            $i = ([string](Get-SIAzureContextValue $t 'id')).Trim().ToLowerInvariant()
            if ($i -and -not ([string](Get-SIAzureContextValue $t 'name')).Trim()) { [void]$ids.Add($i) }
        }
    }
    foreach ($i in $ids) { $i }
}

function ConvertTo-SIAzureChangeParts {
    <# PURE. Change rows -> @{ <resource id> = { lastTime; changedBy; changedByName; changedByType; changeType; client;
       changes } }. changedBy is what Azure recorded (a user's sign-in name, or an application's id); its display name
       comes from -PrincipalNames when the id is known there. #>
    param([AllowEmptyCollection()][object[]]$Rows = @(), [hashtable]$PrincipalNames = @{})
    $map = @{}
    foreach ($r in $Rows) {
        $id = ([string](Get-SIAzureContextValue $r 'ResourceId')).Trim().ToLowerInvariant()
        if (-not $id) { continue }
        $o = [ordered]@{}
        $lt = ConvertTo-SIAzureContextTime (Get-SIAzureContextValue $r 'ChangeTime'); if ($lt) { $o['lastTime'] = $lt }
        $by = ([string](Get-SIAzureContextValue $r 'ChangedBy')).Trim()
        if ($by) {
            $o['changedBy'] = $by
            $k = $by.ToLowerInvariant()
            if ($PrincipalNames -and $PrincipalNames.ContainsKey($k) -and [string]$PrincipalNames[$k]) { $o['changedByName'] = [string]$PrincipalNames[$k] }
        }
        foreach ($pair in @(@('changedByType', 'ChangedByType'), @('changeType', 'ChangeType'), @('client', 'ClientType'))) {
            $v = ([string](Get-SIAzureContextValue $r $pair[1])).Trim(); if ($v) { $o[$pair[0]] = $v }
        }
        $n = Get-SIAzureContextValue $r 'Changes'; if ($null -ne $n -and "$n" -ne '') { $o['changes'] = [int]$n }
        if ($o.Count -gt 0) { $map[$id] = [pscustomobject]$o }
    }
    return $map
}

function ConvertTo-SIAzurePatchParts {
    <# PURE. Patch assessment rows -> @{ <machine id> = { critical; security; rebootPending; status; assessedAt } }. A count
       the assessment does not carry is left out (never 0). #>
    param([AllowEmptyCollection()][object[]]$Rows = @())
    $map = @{}
    foreach ($r in $Rows) {
        $id = ([string](Get-SIAzureContextValue $r 'ResourceId')).Trim().ToLowerInvariant()
        if (-not $id) { continue }
        $o = [ordered]@{}
        foreach ($pair in @(@('critical', 'Critical'), @('security', 'Security'))) {
            $v = Get-SIAzureContextValue $r $pair[1]
            if ($null -ne $v -and "$v" -ne '') { $n = 0; if ([int]::TryParse([string]$v, [ref]$n)) { $o[$pair[0]] = $n } }
        }
        $rb = Get-SIAzureContextValue $r 'RebootPending'
        if ($rb -is [bool]) { $o['rebootPending'] = $rb } elseif ([string]$rb -match '^(?i)(true|false)$') { $o['rebootPending'] = ([string]$rb -match '^(?i)true$') }
        $st = ([string](Get-SIAzureContextValue $r 'Status')).Trim(); if ($st) { $o['status'] = $st }
        $at = ConvertTo-SIAzureContextTime (Get-SIAzureContextValue $r 'AssessedAt'); if ($at) { $o['assessedAt'] = $at }
        if ($o.Count -gt 0) { $map[$id] = [pscustomobject]$o }
    }
    return $map
}

function ConvertTo-SIAzureDefenderPlanIndex {
    <# PURE. Pricing rows -> @{ <subscription id> = @{ <plan name, lower> = @{ name; tier; subPlan } } }. #>
    param([AllowEmptyCollection()][object[]]$Rows = @())
    $map = @{}
    foreach ($r in $Rows) {
        $sub = ([string](Get-SIAzureContextValue $r 'SubscriptionId')).Trim().ToLowerInvariant()
        $plan = ([string](Get-SIAzureContextValue $r 'Plan')).Trim()
        if (-not $sub -or -not $plan) { continue }
        if (-not $map.ContainsKey($sub)) { $map[$sub] = @{} }
        $map[$sub][$plan.ToLowerInvariant()] = @{ name = $plan; tier = ([string](Get-SIAzureContextValue $r 'Tier')).Trim(); subPlan = ([string](Get-SIAzureContextValue $r 'SubPlan')).Trim() }
    }
    return $map
}

function Get-SIAzureDefenderPart {
    <# PURE. The 'defender' part of one resource: the plan covering its type in its subscription (plan, tier, subPlan) and
       the subscription's posture tier (cspmTier). $null when the subscription's plans are not known. #>
    param([Parameter(Mandatory)][string]$ResourceId, [AllowEmptyString()][string]$ResourceType = '', [hashtable]$Plans = @{})
    $m = [regex]::Match($ResourceId.Trim().ToLowerInvariant(), '^/subscriptions/([^/]+)')
    if (-not $m.Success -or -not $Plans.ContainsKey($m.Groups[1].Value)) { return $null }
    $sub = $Plans[$m.Groups[1].Value]
    $o = [ordered]@{}
    $t = ([string]$ResourceType).Trim().ToLowerInvariant()
    if ($t -and $script:SIAzureDefenderPlanByType.ContainsKey($t)) {
        $name = [string]$script:SIAzureDefenderPlanByType[$t]
        $o['plan'] = $name
        if ($sub.ContainsKey($name.ToLowerInvariant())) {
            $p = $sub[$name.ToLowerInvariant()]
            if ([string]$p.tier) { $o['tier'] = [string]$p.tier }
            if ([string]$p.subPlan) { $o['subPlan'] = [string]$p.subPlan }
        }
    }
    if ($sub.ContainsKey('cloudposture') -and [string]$sub['cloudposture'].tier) { $o['cspmTier'] = [string]$sub['cloudposture'].tier }
    if ($o.Count -eq 0) { return $null }
    return [pscustomobject]$o
}

function Get-SIAzureAttachedResourceId {
    <#
        PURE. What a public IP address is attached to: its IP configuration (properties.ipConfiguration.id, else a NAT
        gateway) walked up to the resource that owns it (a network interface, a load balancer, a gateway ...), then through
        -ChildOf (the capture's child map: a network interface -> its virtual machine). @{ Id; Via } or $null.
    #>
    param($Resource, $ChildOf = @{})
    if ($null -eq $Resource) { return $null }
    return (Resolve-SIAzureAttachedVia -Via (Get-SIAzurePipVia -Resource $Resource) -ChildOf $ChildOf)
}

function Resolve-SIAzureAttachedVia {
    <# PURE. A public IP's attachment (Get-SIAzurePipVia) walked up to the resource that owns it, then through -ChildOf (a
       hashtable or the producer's on-disk child map, #727). @{ Id; Via } or $null. #>
    param([AllowNull()][AllowEmptyString()][string]$Via, $ChildOf = @{})
    $via = ([string]$Via).Trim().ToLowerInvariant()
    if (-not $via) { return $null }
    $id = $via
    for ($i = 0; $i -lt 6; $i++) {
        $info = Get-SIArmIdInfo $id
        if ($null -eq $info -or -not $info.Parent) { break }
        $id = [string]$info.Parent
    }
    for ($i = 0; $i -lt 4 -and $ChildOf -and $ChildOf.ContainsKey($id); $i++) { $id = [string]$ChildOf[$id] }
    return @{ Id = $id; Via = $via }
}

# ---------------------------------------------------------------------------------------------------------------------
#  The reads
# ---------------------------------------------------------------------------------------------------------------------

function Resolve-SIAzurePrincipalNames {
    <#
        The display name of each principal id, best effort: Microsoft Graph POST /directoryObjects/getByIds (object ids, 1000
        per call), then -- for the ids still unknown -- GET /servicePrincipals filtered on appId (an application is recorded
        by its client id in the change history). A user answers with its sign-in name. Returns @{ <id, lower> = name }; an
        id that does not resolve is left out. Never throws: a name is context, never a reason to fail the read.
        -Post / -Get (tests): { param($Uri, $Body) } / { param($Uri) } -> the parsed answer.
    #>
    param([AllowEmptyCollection()][string[]]$Ids = @(), [scriptblock]$Post, [scriptblock]$Get)
    $map = @{}
    $guid = '^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$'
    $list = @(@($Ids) | Where-Object { $_ -and ([string]$_).Trim() -match $guid } | ForEach-Object { ([string]$_).Trim().ToLowerInvariant() } | Select-Object -Unique)
    if ($list.Count -eq 0) { return $map }
    if (-not $Post) {
        $Post = {
            param($Uri, $Body)
            $r = Invoke-SIAzRestRequest -Method POST -Uri $Uri -Audience Graph -Body $Body -What 'Microsoft Graph getByIds' -MaxAttempts 3
            return ($r.Content | ConvertFrom-Json)
        }
    }
    if (-not $Get) {
        $Get = {
            param($Uri)
            $r = Invoke-SIAzRestRequest -Method GET -Uri $Uri -Audience Graph -What 'Microsoft Graph service principals' -MaxAttempts 3
            return ($r.Content | ConvertFrom-Json)
        }
    }
    for ($i = 0; $i -lt $list.Count; $i += 1000) {
        $chunk = @($list[$i..([Math]::Min($i + 999, $list.Count - 1))])
        try {
            # LIST KEPT: a name look-up -- id + name + sign-in name of the principals a role assignment names
            $resp = & $Post 'https://graph.microsoft.com/v1.0/directoryObjects/getByIds?$select=id,displayName,userPrincipalName' (@{ ids = $chunk; types = @('user', 'group', 'servicePrincipal') } | ConvertTo-Json -Compress)
            foreach ($o in @($resp.value)) {
                if ($null -eq $o -or -not $o.id) { continue }
                $name = ''
                if ($o.PSObject.Properties['userPrincipalName'] -and [string]$o.userPrincipalName) { $name = [string]$o.userPrincipalName }
                elseif ($o.PSObject.Properties['displayName']) { $name = [string]$o.displayName }
                if ($name) { $map[([string]$o.id).ToLowerInvariant()] = $name }
            }
        } catch { Write-Verbose ('principal names: not resolved ({0})' -f $_.Exception.Message) }
    }
    $left = @($list | Where-Object { -not $map.ContainsKey($_) })
    for ($i = 0; $i -lt $left.Count; $i += 15) {
        $chunk = @($left[$i..([Math]::Min($i + 14, $left.Count - 1))])
        try {
            $filter = 'appId in ({0})' -f ((@($chunk) | ForEach-Object { "'$_'" }) -join ',')
            # LIST KEPT: a name look-up -- application id + name
            $resp = & $Get ('https://graph.microsoft.com/v1.0/servicePrincipals?$select=appId,displayName&$filter=' + [uri]::EscapeDataString($filter))
            foreach ($o in @($resp.value)) { if ($null -ne $o -and $o.appId -and [string]$o.displayName) { $map[([string]$o.appId).ToLowerInvariant()] = [string]$o.displayName } }
        } catch { Write-Verbose ('application names: not resolved ({0})' -f $_.Exception.Message) }
    }
    return $map
}

function Get-SIAzureContextRecords {
    <# The captured Azure records that hold their own resource (part 'resource'): @{ <resource id> = record }. #>
    param($State = $global:SIRecordCaptureState)
    $map = @{}
    if ($null -eq $State -or $null -eq $State.Records) { return $map }
    foreach ($r in @($State.Records.Values)) {
        if ([string]$r.Provider -ne 'azure' -or $null -eq $r.Parts -or -not $r.Parts.Contains('resource')) { continue }
        $map[[string]$r.Key] = $r
    }
    return $map
}

# ---------------------------------------------------------------------------------------------------------------------
#  #727 THE AZURE RECORDS THE CONTEXT IS ADDED TO -- held (a part's process, the tests) or STREAMED (the producer, every
#  tenant: owner 2026-10-16 "tenants can have millions of azure obj"). One view over both: the producer reads the stream's
#  record index (on disk, SI-RecordCapture.ps1) and writes each part as a line of the record; nothing of a record is held.
# ---------------------------------------------------------------------------------------------------------------------

function Get-SIAzureContextView {
    <# The Azure records of this capture: @{ Stream (the producer's record stream) | Recs (the held records by resource id) }. #>
    param($State)
    if ($null -ne $State -and $State.PSObject.Properties['Stream'] -and $null -ne $State.Stream -and $State.Stream.PSObject.Properties['AzureIndex'] -and $null -ne $State.Stream.AzureIndex) {
        return [pscustomobject]@{ Stream = $State.Stream; Recs = $null }
    }
    return [pscustomobject]@{ Stream = $null; Recs = (Get-SIAzureContextRecords -State $State) }
}

function Get-SIAzureContextViewCount {
    <# How many Azure records hold their own resource. #>
    param([Parameter(Mandatory)]$View)
    if ($View.Stream) { return [long]$View.Stream.AzureResources }
    return [long]$View.Recs.Count
}

function Get-SIAzureContextViewInfo {
    <# The Azure record of a resource id that holds its own resource: @{ Id; RecordType; Key; ResourceType; Name; Via }, or $null. #>
    param([Parameter(Mandatory)]$View, [AllowEmptyString()][string]$Key)
    if (-not $Key) { return $null }
    if ($View.Stream) {
        foreach ($rt in 'azure_resource', 'public_ip') {
            $i = Get-SIRecordStreamAzureInfo -Stream $View.Stream -Id ('azure|{0}|{1}' -f $rt, $Key)
            if ($null -ne $i -and $i.HasResource) { return $i }
        }
        return $null
    }
    if (-not $View.Recs.ContainsKey($Key)) { return $null }
    $r = $View.Recs[$Key]
    $res = Get-SIAzureContextPartObject $r.Parts['resource']
    $via = ''; if ([string]$r.RecordType -eq 'public_ip') { $via = Get-SIAzurePipVia -Resource $res }
    return @{ Id = ('azure|{0}|{1}' -f $r.RecordType, $r.Key); RecordType = [string]$r.RecordType; Key = [string]$r.Key; ResourceType = [string]$r.ResourceType
        Name = [string](Get-SIAzureContextValue $res 'name'); Via = $via; Record = $r }
}

function Invoke-SIAzureContextViewEach {
    <# -Do once for every Azure record that holds its own resource ({ param($Info) } -- Info as Get-SIAzureContextViewInfo;
       Name / Via only when -WithResource). One at a time: the producer's records are read from its index, never all held. #>
    param([Parameter(Mandatory)]$View, [Parameter(Mandatory)][scriptblock]$Do, [switch]$WithResource)
    if ($View.Stream) {
        $s = $View.Stream
        foreach ($id in $s.AzureIndex.Keys) {
            $i = Get-SIRecordStreamAzureInfo -Stream $s -Id $id
            if ($null -ne $i -and $i.HasResource) { $null = & $Do $i }
        }
        return
    }
    foreach ($k in @($View.Recs.Keys)) {
        if ($WithResource) { $null = & $Do (Get-SIAzureContextViewInfo -View $View -Key $k); continue }
        $r = $View.Recs[$k]
        $null = & $Do @{ Id = ('azure|{0}|{1}' -f $r.RecordType, $r.Key); RecordType = [string]$r.RecordType; Key = [string]$r.Key; ResourceType = [string]$r.ResourceType; Record = $r }
    }
}

function Set-SIAzureContextViewPart {
    <# A part on the Azure record of -Info (Get-SIAzureContextViewInfo): set on the held record, or a line of the streamed one. #>
    param([Parameter(Mandatory)]$View, [Parameter(Mandatory)]$Info, [Parameter(Mandatory)][string]$Part, $Object)
    if ($View.Stream) { Add-SIRecordStreamPart -Stream $View.Stream -Id ([string]$Info.Id) -Part $Part -Object $Object; return }
    $Info.Record.Parts[$Part] = $Object
}

# A read's rows kept on local disk until the rest of what they need is known (the principal names of the change history,
# the policy names): one compressed line per row, read back one row at a time.
function New-SIAzureContextSpill {
    param([string]$What = 'rows')
    if (-not ('System.IO.Compression.GZipStream' -as [type])) { Add-Type -AssemblyName System.IO.Compression }
    $path = [IO.Path]::Combine([IO.Path]::GetTempPath(), ('si-azctx-{0}-{1}.jsonl.gz' -f ($What -replace '[^A-Za-z0-9-]', ''), [guid]::NewGuid().ToString('N')))
    $w = New-Object System.IO.StreamWriter((New-Object System.IO.Compression.GZipStream([IO.File]::Create($path), [System.IO.Compression.CompressionLevel]::Fastest)), (New-Object System.Text.UTF8Encoding($false)))
    [pscustomobject]@{ Path = $path; Writer = $w; Count = 0L }
}
function Add-SIAzureContextSpillRow {
    param([Parameter(Mandatory)]$Spill, $Row)
    if ($null -eq $Row) { return }
    $Spill.Writer.WriteLine((ConvertTo-Json -InputObject $Row -Compress -Depth 8)); $Spill.Count++
}
function Read-SIAzureContextSpill {
    param([Parameter(Mandatory)]$Spill, [Parameter(Mandatory)][scriptblock]$OnRow)
    if ($Spill.Writer) { $Spill.Writer.Dispose(); $Spill.Writer = $null }
    $r = New-Object System.IO.StreamReader((New-Object System.IO.Compression.GZipStream([IO.File]::OpenRead($Spill.Path), [System.IO.Compression.CompressionMode]::Decompress)), (New-Object System.Text.UTF8Encoding($false)))
    try { while ($null -ne ($line = $r.ReadLine())) { if ($line) { $null = & $OnRow (ConvertFrom-Json -InputObject $line) } } } finally { $r.Dispose() }
}
function Remove-SIAzureContextSpill {
    param($Spill)
    if ($null -eq $Spill) { return }
    try { if ($Spill.Writer) { $Spill.Writer.Dispose(); $Spill.Writer = $null } } catch { }
    try { [IO.File]::Delete($Spill.Path) } catch { }
}

function Invoke-SIAzureContextCapture {
    <#
    .SYNOPSIS  Reads the Azure context (see the header) and adds it as parts to the Azure records this run captured.
               Returns @{ <part> = records decorated }. Never throws: each read is its own try, and a read that fails or is
               partial is said once -- its part is then left out (partial rows are still used where a row is a fact about
               one resource, never where absence would be read as "no").
               #727 PAGE BY PAGE, AT EVERY SIZE: every Resource Graph read is taken a page at a time and let go (a row per
               resource is written as its part at once); the change history and the policy rows wait on local disk for the
               names they need; the access scopes and the backed-up resources are on-disk lookups. The records are the
               capture's -- held, or the producer's stream (its index on disk): nothing here holds every resource.
    .PARAMETER Query           (tests) { param($Kql, $Label, $Unscoped) } -> @{ Rows; Complete } (the whole answer, one page).
                               Default: Resource Graph, page by page (Invoke-SIArgPaged -OnPage).
    .PARAMETER PrincipalNames  (tests) { param([string[]]$Ids) } -> @{ id = name } -- default: Resolve-SIAzurePrincipalNames.
    #>
    param([string[]]$SubscriptionIds = @(), [scriptblock]$Query, [scriptblock]$PrincipalNames, $State = $global:SIRecordCaptureState,
          [scriptblock]$Log)
    $done = [ordered]@{ backup = 0; access = 0; policy = 0; change = 0; patch = 0; defender = 0; attached = 0 }
    if ($null -eq $State -or $null -eq $State.Records) { return $done }
    if (-not (Get-Command -Name Add-SIRecordPart -ErrorAction SilentlyContinue)) { return $done }   # no record capture in this process
    if (-not $Log) { $Log = { param($Level, $Message) if ($Level -eq 'WARN') { Write-Warning $Message } else { Write-Host ('[INFO] ' + $Message) } } }
    $view = Get-SIAzureContextView -State $State
    if ((Get-SIAzureContextViewCount -View $view) -eq 0) { return $done }
    $subs = @($SubscriptionIds)
    if (-not $PrincipalNames) { $PrincipalNames = { param([string[]]$Ids) Resolve-SIAzurePrincipalNames -Ids $Ids } }
    # one read, PAGE BY PAGE: -OnRows gets each page's rows and lets them go. @{ Complete; Failed; Rows (how many) }
    $read = {
        param([string]$What, [string]$Kql, [bool]$Unscoped, [scriptblock]$OnRows)
        try {
            $complete = $true; $n = 0L; $why = ''
            if ($Query) {
                $res = & $Query $Kql ('Azure context: ' + $What) $Unscoped
                $rows = @()
                if ($null -ne $res -and $res.PSObject.Properties['Rows']) {
                    $rows = @($res.Rows); if ($res.PSObject.Properties['Complete']) { $complete = [bool]$res.Complete }
                    if ($res.PSObject.Properties['Error'] -and [string]$res.Error) { $why = [string]$res.Error }
                } elseif ($null -ne $res) { $rows = @($res) }
                $n = $rows.Count
                if ($complete -or $n -gt 0) { $null = & $OnRows $rows }
                $rows = $null
            } else {
                $a = @{ Query = $Kql; SourceLabel = ('Azure context: ' + $What); OnPage = { param($PageRows) & $OnRows @($PageRows) } }
                if (-not $Unscoped -and @($subs).Count -gt 0) { $a['SubscriptionIds'] = $subs }
                $res = Invoke-SIArgPaged @a -WarningAction SilentlyContinue
                $complete = [bool]$res.Complete; $n = [long]$res.RowCount
                if ([string]$res.Error) { $why = [string]$res.Error }
            }
            if (-not $complete -and $n -eq 0) {
                if ($why) { $why = ' (' + $why + ')' }
                & $Log 'WARN' ('Azure context: {0} could not be read{1} -- left out this run.' -f $What, $why)
                return @{ Rows = 0L; Complete = $false; Failed = $true }
            }
            if (-not $complete) { & $Log 'WARN' ('Azure context: {0} could not be read completely -- the resources not read keep an unknown value this run.' -f $What) }
            return @{ Rows = $n; Complete = $complete; Failed = $false }
        } catch {
            & $Log 'WARN' ('Azure context: {0} could not be read ({1}) -- left out this run.' -f $What, $_.Exception.Message)
            return @{ Rows = 0L; Complete = $false; Failed = $true }
        }
    }
    $set = {
        param([string]$Id, [string]$Part, $Object)
        if ($null -eq $Object) { return $false }
        $info = Get-SIAzureContextViewInfo -View $view -Key $Id
        if ($null -eq $info) { return $false }
        Set-SIAzureContextViewPart -View $view -Info $info -Part $Part -Object $Object
        return $true
    }
    $backed = $null; $scopes = $null; $changes = $null; $policies = $null
    try {
        # ---- backup -----------------------------------------------------------------------------------------------------
        $backed = New-SIDiskTextLookup -Name 'azure-backup'
        $q = & $read 'backup' (Get-SIAzureBackupKql) $false {
            param($Rows)
            $parts = ConvertTo-SIAzureBackupParts -Rows $Rows
            foreach ($id in @($parts.Keys)) { $backed[[string]$id] = ''; if (& $set $id 'backup' $parts[$id]) { $done.backup++ } }
        }
        # a virtual machine no backup item names is NOT protected -- said only when the whole read came back
        if (-not $q.Failed -and $q.Complete) {
            Invoke-SIAzureContextViewEach -View $view -Do {
                param($i)
                if ([string]$i.ResourceType -eq 'microsoft.compute/virtualmachines' -and -not $backed.ContainsKey([string]$i.Key)) {
                    Set-SIAzureContextViewPart -View $view -Info $i -Part 'backup' -Object ([pscustomobject]@{ protected = $false }); $done.backup++
                }
            }
        }

        # ---- the change history (its "changed by" ids get their names with the access principals, in one look-up) ---------
        $ids = New-Object 'System.Collections.Generic.HashSet[string]'
        $changes = New-SIAzureContextSpill -What 'changes'
        $qc = & $read 'the change history' (Get-SIAzureChangeKql) $false {
            param($Rows)
            foreach ($r in $Rows) {
                if ($null -eq $r) { continue }
                $by = [string](Get-SIAzureContextValue $r 'ChangedBy'); if ($by) { [void]$ids.Add($by) }
                # the values the part needs, the time already as its text (a row waits on disk for the names)
                Add-SIAzureContextSpillRow -Spill $changes -Row ([ordered]@{ ResourceId = [string](Get-SIAzureContextValue $r 'ResourceId')
                        ChangeTime = (ConvertTo-SIAzureContextTime (Get-SIAzureContextValue $r 'ChangeTime')); ChangedBy = $by
                        ChangedByType = [string](Get-SIAzureContextValue $r 'ChangedByType'); ChangeType = [string](Get-SIAzureContextValue $r 'ChangeType')
                        ClientType = [string](Get-SIAzureContextValue $r 'ClientType'); Changes = (Get-SIAzureContextValue $r 'Changes') })
            }
        }
        $scopes = New-SIDiskTextLookup -Name 'azure-access'
        $qa = & $read 'role assignments' (Get-SIAzureAccessKql) $false {
            param($Rows)
            $access = ConvertTo-SIAzureAccessIndex -Rows $Rows
            foreach ($sc in @($access.Scopes.Keys)) { $scopes[[string]$sc] = (ConvertTo-Json -InputObject @($access.Scopes[$sc]) -Compress -Depth 4) }
            foreach ($i in @($access.PrincipalIds)) { if (-not $ids.Contains([string]$i)) { [void]$ids.Add([string]$i) } }
        }
        $names = @{}
        if ($ids.Count -gt 0) { try { $names = & $PrincipalNames ([string[]]@($ids)); if ($null -eq $names) { $names = @{} } } catch { $names = @{} } }
        if (-not $qc.Failed) {
            Read-SIAzureContextSpill -Spill $changes -OnRow {
                param($r)
                $parts = ConvertTo-SIAzureChangeParts -Rows @($r) -PrincipalNames $names
                foreach ($id in @($parts.Keys)) { if (& $set $id 'change' $parts[$id]) { $done.change++ } }
            }
        }
        Remove-SIAzureContextSpill $changes; $changes = $null
        # ---- who has access (complete reads only: a partial list would read as "nobody else has access") -----------------
        if (-not $qa.Failed -and $qa.Complete -and $scopes.Count -gt 0) {
            Invoke-SIAzureContextViewEach -View $view -Do {
                param($i)
                $rid = ([string]$i.Key).Trim().TrimEnd('/').ToLowerInvariant()
                $near = @{}
                foreach ($sc in @($rid, (Get-SIAzureResourceGroupScope $rid))) {
                    if ($sc -and -not $near.ContainsKey($sc) -and $scopes.ContainsKey($sc)) { $near[$sc] = @(ConvertFrom-Json -InputObject $scopes[$sc]) }
                }
                if ($near.Count -eq 0) { return }
                $p = Get-SIAzureAccessPart -ResourceId ([string]$i.Key) -Scopes $near -PrincipalNames $names
                if ($null -ne $p) { Set-SIAzureContextViewPart -View $view -Info $i -Part 'access' -Object $p; $done.access++ }
            }
        }
        $scopes.Dispose(); $scopes = $null

        # ---- policy non-compliance ---------------------------------------------------------------------------------------
        $policies = New-SIAzureContextSpill -What 'policy'
        $unnamed = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
        $q = & $read 'policy compliance' (Get-SIAzurePolicyKql) $false {
            param($Rows)
            foreach ($u in @(Get-SIAzurePolicyUnnamedIds -Rows $Rows)) { [void]$unnamed.Add([string]$u) }
            foreach ($r in $Rows) { Add-SIAzureContextSpillRow -Spill $policies -Row $r }
        }
        if (-not $q.Failed -and $q.Rows -gt 0) {
            $pn = @{}
            # the built-in definitions are not returned by a query limited to subscriptions: their names are read once, unscoped
            if ($unnamed.Count -gt 0) {
                $null = & $read 'policy names' (Get-SIAzurePolicyNameKql) $true {
                    param($Rows)
                    foreach ($r in $Rows) {
                        $k = ([string](Get-SIAzureContextValue $r 'PolicyId')).Trim().ToLowerInvariant(); $v = ([string](Get-SIAzureContextValue $r 'PolicyName')).Trim()
                        if ($k -and $v) { $pn[$k] = $v }
                    }
                }
            }
            Read-SIAzureContextSpill -Spill $policies -OnRow {
                param($r)
                $parts = ConvertTo-SIAzurePolicyParts -Rows @($r) -Names $pn
                foreach ($id in @($parts.Keys)) { if (& $set $id 'policy' $parts[$id]) { $done.policy++ } }
            }
        }
        Remove-SIAzureContextSpill $policies; $policies = $null

        # ---- pending updates ---------------------------------------------------------------------------------------------
        $null = & $read 'update assessments' (Get-SIAzurePatchKql) $false {
            param($Rows)
            $parts = ConvertTo-SIAzurePatchParts -Rows $Rows
            foreach ($id in @($parts.Keys)) { if (& $set $id 'patch' $parts[$id]) { $done.patch++ } }
        }

        # ---- Defender for Cloud plans (one row per subscription and plan) -------------------------------------------------
        $planRows = New-Object System.Collections.Generic.List[object]
        $q = & $read 'Defender for Cloud plans' (Get-SIAzureDefenderPlanKql) $false { param($Rows) foreach ($r in $Rows) { $planRows.Add($r) } }
        if (-not $q.Failed -and $planRows.Count -gt 0) {
            $plans = ConvertTo-SIAzureDefenderPlanIndex -Rows $planRows.ToArray()
            Invoke-SIAzureContextViewEach -View $view -Do {
                param($i)
                $p = Get-SIAzureDefenderPart -ResourceId ([string]$i.Key) -ResourceType ([string]$i.ResourceType) -Plans $plans
                if ($null -ne $p) { Set-SIAzureContextViewPart -View $view -Info $i -Part 'defender' -Object $p; $done.defender++ }
            }
        }

        # ---- a public IP address: what it is attached to (no read: the captured resources and the child map) ----------------
        try {
            $childOf = @{}
            if ($State.PSObject.Properties['ChildOf'] -and $null -ne $State.ChildOf) { $childOf = $State.ChildOf }
            Invoke-SIAzureContextViewEach -View $view -WithResource -Do {
                param($i)
                if ([string]$i.RecordType -ne 'public_ip') { return }
                $att = Resolve-SIAzureAttachedVia -Via ([string]$i.Via) -ChildOf $childOf
                if ($null -eq $att) { return }
                $info = Get-SIArmIdInfo $att.Id
                $o = [ordered]@{ id = [string]$att.Id }
                $name = ''
                $target = Get-SIAzureContextViewInfo -View $view -Key ([string]$att.Id)
                if ($null -ne $target) { $name = [string]$target.Name }
                if (-not $name -and $info) { $name = [string]$info.Name }
                if ($name) { $o['name'] = $name }
                if ($info) { $o['type'] = [string]$info.Type }
                if ([string]$att.Via -ne [string]$att.Id) { $o['via'] = [string]$att.Via }
                Set-SIAzureContextViewPart -View $view -Info $i -Part 'attached' -Object ([pscustomobject]$o); $done.attached++
            }
        } catch { & $Log 'WARN' ('Azure context: what the public IP addresses are attached to could not be worked out ({0}).' -f $_.Exception.Message) }
    } finally {
        foreach ($l in @($backed, $scopes)) { if ($l -is [System.IDisposable]) { try { $l.Dispose() } catch { } } }
        Remove-SIAzureContextSpill $changes; Remove-SIAzureContextSpill $policies
    }

    & $Log 'INFO' ('Azure context: backup on {0}, direct privileged access on {1}, policy non-compliance on {2}, a change in the last 14 days on {3}, update assessment on {4}, Defender plan on {5} resource(s); {6} public IP address(es) with what they are attached to' -f $done.backup, $done.access, $done.policy, $done.change, $done.patch, $done.defender, $done.attached)
    return $done
}

function Get-SIAzureContextPartObject {
    <# PURE. A captured part as an object: a part kept as JSON text (Add-SIRecordPart) is parsed, any other is itself. #>
    param($Part)
    if ($null -eq $Part) { return $null }
    if ($Part -is [psobject] -and $Part.PSObject.Properties['SIJson'] -and @($Part.PSObject.Properties).Count -eq 1) {
        if (-not [string]$Part.SIJson) { return $null }
        try { return ([string]$Part.SIJson | ConvertFrom-Json) } catch { return $null }
    }
    return $Part
}

# ---------------------------------------------------------------------------------------------------------------------
#  Diagnostic settings -- tier 0 and 1 only
# ---------------------------------------------------------------------------------------------------------------------

function ConvertTo-SIAzureDiagnosticPart {
    <#
        PURE. The diagnostic settings of one resource (the 'value' list Azure Resource Manager answers) -> the 'diag' part:
        { enabled; count; settings = [ { name; workspace_id; workspace_name; storage_account_id; storage_account_name;
        event_hub; categories } ] }. No setting = { enabled = false; count = 0 }.
    #>
    param([AllowEmptyCollection()][object[]]$Settings = @())
    $items = New-Object System.Collections.Generic.List[object]
    foreach ($s in @($Settings)) {
        if ($null -eq $s) { continue }
        $p = Get-SIAzureContextValue $s 'properties'
        $o = [ordered]@{ name = [string](Get-SIAzureContextValue $s 'name') }
        $ws = ([string](Get-SIAzureContextValue $p 'workspaceId')).Trim()
        if ($ws) { $o['workspace_id'] = $ws.ToLowerInvariant(); $o['workspace_name'] = ($ws.TrimEnd('/') -split '/')[-1] }
        $sa = ([string](Get-SIAzureContextValue $p 'storageAccountId')).Trim()
        if ($sa) { $o['storage_account_id'] = $sa.ToLowerInvariant(); $o['storage_account_name'] = ($sa.TrimEnd('/') -split '/')[-1] }
        $eh = ([string](Get-SIAzureContextValue $p 'eventHubAuthorizationRuleId')).Trim()
        if ($eh) { $o['event_hub'] = $eh.ToLowerInvariant() }
        $cats = New-Object System.Collections.Generic.List[string]
        foreach ($l in @(Get-SIAzureContextValue $p 'logs')) {
            if ($null -eq $l -or (Get-SIAzureContextValue $l 'enabled') -ne $true) { continue }
            $c = [string](Get-SIAzureContextValue $l 'category'); if (-not $c) { $c = [string](Get-SIAzureContextValue $l 'categoryGroup') }
            if ($c -and -not $cats.Contains($c)) { $cats.Add($c) }
        }
        if ($cats.Count -gt 0) { $o['categories'] = $cats.ToArray() }
        $items.Add([pscustomobject]$o)
    }
    return [pscustomobject][ordered]@{ enabled = ($items.Count -gt 0); count = $items.Count; settings = $items.ToArray() }
}

function Get-SIAzureDiagnosticTargets {
    <# PURE. The Azure resource ids of the profile rows whose tier is 0 or 1 (lower case, once each). #>
    param([AllowEmptyCollection()][object[]]$Rows = @())
    $seen = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    foreach ($row in @($Rows)) {
        if ($null -eq $row) { continue }
        $t = Get-SIAzureContextValue $row 'Tier'
        if ($null -eq $t -or "$t" -eq '') { continue }
        $n = -1; if (-not [int]::TryParse([string]$t, [ref]$n) -or $n -notin 0, 1) { continue }
        $id = ([string](Get-SIAzureContextValue $row 'AzureResourceId')).Trim().ToLowerInvariant()
        if ($id.StartsWith('/subscriptions/') -and $id.Contains('/providers/') -and $seen.Add($id)) { $id }
    }
}

function Add-SIRecordDiagnosticParts {
    <#
    .SYNOPSIS  Diagnostic settings of the TIER 0 AND 1 Azure resources of this run -> part 'diag' on their Azure record.
               One Azure Resource Manager call per resource (GET <id>/providers/Microsoft.Insights/diagnosticSettings), so
               it is asked only where it matters most. A resource whose type has no diagnostic settings, or whose settings
               cannot be read, gets no part (unknown, never "off"). Returns the number of records decorated. Never throws.
    .PARAMETER InParts  this process is a part of a run collected in parts: the record itself was captured by discovery in
                        another process, so the part is kept without it and joins its record when the run is merged.
    .PARAMETER Fetch    (tests) { param($ResourceId) } -> the settings list, or $null when there is none to read.
    #>
    param([AllowEmptyCollection()][object[]]$Rows = @(), [Nullable[bool]]$InParts = $null, [scriptblock]$Fetch, $State = $global:SIRecordCaptureState)
    $n = 0
    try {
        $targets = @(Get-SIAzureDiagnosticTargets -Rows $Rows)
        if ($targets.Count -eq 0 -or $null -eq $State) { return 0 }
        if ($null -eq $InParts) { $InParts = ([string][Environment]::GetEnvironmentVariable('SI_COLLECT_PHASE') -eq 'parts') }
        if (-not $Fetch) {
            $Fetch = {
                param($Id)
                $r = Invoke-SIArm -Path ($Id + '/providers/Microsoft.Insights/diagnosticSettings') -ApiVersion '2021-05-01-preview' -AllowNotFound
                if ($null -eq $r) { return $null }
                return , @($r.value)
            }
        }
        $scope = $null; if (Get-Command -Name Get-SIAzureCiScope -ErrorAction SilentlyContinue) { $scope = Get-SIAzureCiScope }
        $failed = 0
        foreach ($id in $targets) {
            $rt = 'azure_resource'
            $info = Get-SIArmIdInfo $id
            if ($info -and [string]$info.Type -eq 'microsoft.network/publicipaddresses') { $rt = 'public_ip' }
            # only a resource that is a record of its own: a child resource (an extension, a disk) is part of its parent
            if ($null -ne $scope -and (Get-Command -Name Resolve-SIAzurePlacement -ErrorAction SilentlyContinue)) {
                if ((Resolve-SIAzurePlacement -Id $id -Scope $scope).Action -ne 'record') { continue }
            }
            $key = 'azure|{0}|{1}' -f $rt, $id
            $rec = $null
            $have = $State.Records.TryGetValue($key, [ref]$rec)
            if (-not $have -and -not $InParts) { continue }
            $settings = $null
            try { $settings = & $Fetch $id } catch { $failed++; continue }
            if ($null -eq $settings) { continue }
            $part = ConvertTo-SIAzureDiagnosticPart -Settings @($settings)
            if ($have) { $rec.Parts['diag'] = $part }
            else {
                $rec = [pscustomobject]@{ Provider = 'azure'; RecordType = $rt; Key = $id; ResourceType = ''; Parts = [ordered]@{}; Engines = New-Object 'System.Collections.Generic.HashSet[string]' }
                [void]$rec.Engines.Add([string]$State.Engine)
                $rec.Parts['diag'] = $part
                $State.Records[$key] = $rec
            }
            $n++
        }
        if ($n -gt 0 -or $failed -gt 0) {
            $msg = 'diagnostic settings read for {0} tier 0 / tier 1 Azure resource(s)' -f $n
            if ($failed -gt 0) { $msg += ('; {0} could not be read (their resource type has none, or the read was refused) and stay unknown' -f $failed) }
            Write-Host ('[INFO] ' + $msg)
        }
    } catch { Write-Warning ('diagnostic settings could not be read this run -- {0}. The records are unaffected.' -f $_.Exception.Message) }
    return $n
}
