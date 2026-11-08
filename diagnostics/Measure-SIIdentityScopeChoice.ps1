#Requires -Version 5.1
<#
.SYNOPSIS
    READ-ONLY: how many Exposure Graph objects each identity choice would leave out in one tenant, before it is switched on
    (REQUIREMENTS #1056 -- SI_Identity_SkipNeverSyncedAd, SI_Identity_SkipNeverSyncedDisabledAd, SI_Identity_SkipDeletedGroups).

.DESCRIPTION
    Nothing is written anywhere: two advanced hunting queries (Microsoft Graph /security/runHuntingQuery) and two paged
    reads of Entra ID's group ids (/groups, /directory/deletedItems/microsoft.graph.group).

      SI_Identity_SkipNeverSyncedAd /
      SI_Identity_SkipNeverSyncedDisabledAd  one summarize over the Exposure Graph user nodes, with the same rules as the
                                             collection (engine\asset-profiling\shared\SI-IdentityScopeChoice.ps1):
                                             never synced = no Entra object id; an on-premises AD identity (a domain SID,
                                             an account name + domain, critical AD groups or an admin count); disabled =
                                             accountEnabled / isEnabled / enabled false or ACCOUNTDISABLE in
                                             userAccountControl; privileged = admin count, critical AD group, a tier 0/1
                                             group of the privilege tier catalog, an assigned role, a service account, a
                                             sensitive account or a Microsoft criticality level.
                                             LeftOutBySkipNeverSyncedAd: never synced, AD and not privileged, whatever the
                                             enabled state (the wider switch); LeftOutBySkipNeverSyncedDisabledAd: the same,
                                             but only the disabled ones (what the narrower switch leaves out while the wider
                                             one is off).
      SI_Identity_SkipDeletedGroups          the Entra object ids of the Exposure Graph group nodes (read in hash buckets),
                                             against the ids Entra ID returns (active + deleted items).
    The query mirrors the code; the identity run's own log line ("Exposure Graph identities: ... got no asset") is the
    exact count once a switch is on.

    The token: a Microsoft Graph access token for the tenant with ThreatHunting.Read.All and Group.Read.All (or
    Directory.Read.All) -- e.g. the SecurityInsight engine identity's, or the support connection's. -ShowKql prints the
    two queries only (to run them in the Defender portal's advanced hunting by hand) and needs no token.

.EXAMPLE
    .\diagnostics\Measure-SIIdentityScopeChoice.ps1 -GraphToken $token
.EXAMPLE
    .\diagnostics\Measure-SIIdentityScopeChoice.ps1 -ShowKql
#>
[CmdletBinding()]
param(
    [string]$GraphToken,
    [switch]$ShowKql,
    [switch]$SkipGroups,
    # the group nodes are read in this many hash buckets (each answer stays below the API's row cap)
    [ValidateRange(1, 256)][int]$GroupBuckets = 8
)
$ErrorActionPreference = 'Stop'
$siRoot = Split-Path -Parent $PSScriptRoot
. (Join-Path $siRoot 'engine\asset-profiling\shared\SI-IdentityScopeChoice.ps1')

$tier = @((Get-SIIdentityCriticalAdGroupNames -SIRoot $siRoot) | ForEach-Object { [string]$_ })
# RE2 (KQL): the metacharacters escaped, a space as it is
$tierRx = (@($tier | ForEach-Object { ([regex]::Escape($_.ToLowerInvariant())).Replace('\ ', ' ') }) -join '|')
if (-not $tierRx) { $tierRx = 'x^' }
$raw = 'iff(isnotnull(NodeProperties.rawData), NodeProperties.rawData, NodeProperties)'
$guid = '[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}'

$usersKql = @"
ExposureGraphNodes
| where NodeLabel == "user"
| extend raw = $raw, ids = tostring(EntityIds)
| extend rawOid = extract(@"($guid)", 1, strcat(tostring(raw.aadId), " ", tostring(raw.accountObjectId), " ", tostring(raw.objectId), " ", tostring(raw.aadObjectId), " ", tostring(raw.groupId), " ", tostring(raw.principalId), " ", tostring(raw.userId), " ", tostring(raw.id)))
| extend hasEntra = ids matches regex @"(?i)aadobjectid[^}]*$guid" or isnotempty(rawOid)
| extend sid = coalesce(extract(@"(?i)securityidentifier[^}]*?(S-1-[0-9-]+)", 1, ids), tostring(raw.adSid), tostring(raw.accountSid), tostring(raw.onPremSid), tostring(raw.onPremisesSecurityIdentifier), tostring(raw.securityIdentifier), tostring(raw.sid))
| extend critText = tostring(raw.nestedCriticalAdGroups)
| extend hasCrit = isnotempty(critText) and critText !in ("[]", "{}") and not(critText matches regex @'"data"\s*:\s*\[\s*\]')
| extend isAd = sid startswith "S-1-5-21-" or (isnotempty(tostring(raw.accountName)) and isnotempty(tostring(raw.accountDomain))) or (isnotempty(critText) and critText != "[]") or toint(raw.adminCount) > 0
| extend uac = tostring(raw.userAccountControl)
| extend disabled = tostring(raw.accountEnabled) =~ "false" or tostring(raw.isEnabled) =~ "false" or tostring(raw.enabled) =~ "false"
    or uac matches regex @"(?i)\b(AccountDisabled|ACCOUNTDISABLE|Account_Disabled|Disabled)\b" or binary_and(tolong(uac), 2) == 2
| extend privileged = toint(raw.adminCount) > 0 or hasCrit
    or tolower(tostring(raw.nestedAdGroupNames)) matches regex @'"($tierRx)"'
    or array_length(todynamic(raw.assignedRoles)) > 0
    or tostring(raw.hasServicePrincipalName) =~ "true" or tostring(raw.isServiceAccount) =~ "true" or tostring(raw.isSensitive) =~ "true"
    or isnotempty(tostring(coalesce(raw.criticalityLevel.criticalityLevel, iff(tostring(raw.criticalityLevel) startswith "{", dynamic(null), raw.criticalityLevel))))
| summarize UserNodes = count(), NeverSyncedAd = countif(not(hasEntra) and isAd),
            NeverSyncedDisabled = countif(not(hasEntra) and isAd and disabled),
            NeverSyncedDisabledPrivileged = countif(not(hasEntra) and isAd and disabled and privileged),
            LeftOutBySkipNeverSyncedDisabledAd = countif(not(hasEntra) and isAd and disabled and not(privileged)),
            LeftOutBySkipNeverSyncedAd = countif(not(hasEntra) and isAd and not(privileged))
"@

$groupsKql = {
    param([int]$N, [int]$B)
@"
ExposureGraphNodes
| where NodeLabel == "group"
| extend _bucket = hash(NodeId, $N) | where _bucket == $B
| extend raw = $raw, ids = tostring(EntityIds)
| extend eid = coalesce(extract(@"(?i)aadobjectid[^}]*?objectid=($guid)", 1, ids), extract(@"(?i)aadobjectid[^}]*?($guid)", 1, ids))
| extend rawOid = extract(@"($guid)", 1, strcat(tostring(raw.aadId), " ", tostring(raw.accountObjectId), " ", tostring(raw.objectId), " ", tostring(raw.aadObjectId), " ", tostring(raw.groupId), " ", tostring(raw.principalId), " ", tostring(raw.userId), " ", tostring(raw.id)))
| extend oid = tolower(coalesce(eid, rawOid))
| where isnotempty(oid)
| project oid
"@
}

if ($ShowKql) {
    Write-Output '--- SI_Identity_SkipNeverSyncedAd / SI_Identity_SkipNeverSyncedDisabledAd (Exposure Graph user nodes) ---'
    Write-Output $usersKql
    Write-Output ''
    Write-Output ('--- SI_Identity_SkipDeletedGroups (Exposure Graph group nodes with an Entra id; bucket 0 of {0} shown) ---' -f $GroupBuckets)
    Write-Output (& $groupsKql $GroupBuckets 0)
    return
}
if (-not $GraphToken) { throw 'Give -GraphToken (Microsoft Graph, ThreatHunting.Read.All + Group.Read.All), or -ShowKql to print the queries.' }

$headers = @{ Authorization = 'Bearer ' + $GraphToken }
function Invoke-Hunting([string]$Kql) {
    $body = @{ Query = $Kql } | ConvertTo-Json -Compress
    $r = Invoke-RestMethod -Method Post -Uri 'https://graph.microsoft.com/v1.0/security/runHuntingQuery' -Headers $headers -ContentType 'application/json' -Body $body
    @($r.results)
}
function Read-GraphIds([string]$Url) {
    $ids = New-Object System.Collections.Generic.List[string]
    $u = 'https://graph.microsoft.com/v1.0' + $Url
    while ($u) {
        $r = Invoke-RestMethod -Method Get -Uri $u -Headers $headers
        foreach ($v in @($r.value)) { if ($v.id) { $ids.Add(([string]$v.id).ToLowerInvariant()) } }
        $u = $r.'@odata.nextLink'
    }
    $ids
}

$out = [ordered]@{ Tenant = ''; MeasuredUtc = [datetime]::UtcNow.ToString('yyyy-MM-dd HH:mm') + ' UTC' }
try { $org = Invoke-RestMethod -Method Get -Uri 'https://graph.microsoft.com/v1.0/organization?$select=id,displayName' -Headers $headers; $out.Tenant = ('{0} ({1})' -f @($org.value)[0].displayName, @($org.value)[0].id) } catch { }

$u = @(Invoke-Hunting $usersKql)[0]
foreach ($k in 'UserNodes', 'NeverSyncedAd', 'NeverSyncedDisabled', 'NeverSyncedDisabledPrivileged', 'LeftOutBySkipNeverSyncedDisabledAd', 'LeftOutBySkipNeverSyncedAd') { $out[$k] = [long]$u.$k }
$out['KeptBySkipNeverSyncedDisabledAd'] = [long]$u.NeverSyncedAd - [long]$u.LeftOutBySkipNeverSyncedDisabledAd
$out['KeptBySkipNeverSyncedAd'] = [long]$u.NeverSyncedAd - [long]$u.LeftOutBySkipNeverSyncedAd

if (-not $SkipGroups) {
    $entra = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    $active = Read-GraphIds '/groups?$select=id&$top=999'
    foreach ($i in $active) { [void]$entra.Add($i) }
    $deleted = Read-GraphIds '/directory/deletedItems/microsoft.graph.group?$select=id&$top=999'
    foreach ($i in $deleted) { [void]$entra.Add($i) }
    $egOids = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    for ($b = 0; $b -lt $GroupBuckets; $b++) {
        $rows = @(Invoke-Hunting (& $groupsKql $GroupBuckets $b))
        if ($rows.Count -ge 100000) { throw ('bucket {0} of {1} came back at the row cap -- run again with -GroupBuckets {2}' -f $b, $GroupBuckets, ($GroupBuckets * 2)) }
        foreach ($r in $rows) { if ($r.oid) { [void]$egOids.Add([string]$r.oid) } }
    }
    $gone = 0L; foreach ($o in $egOids) { if (-not $entra.Contains($o)) { $gone++ } }
    $out['EntraGroupsActive'] = $active.Count
    $out['EntraGroupsDeletedItems'] = $deleted.Count
    $out['GroupNodesWithEntraId'] = $egOids.Count
    $out['LeftOutBySkipDeletedGroups'] = $gone
    $out['KeptBySkipDeletedGroups'] = $egOids.Count - $gone
}
[pscustomobject]$out
