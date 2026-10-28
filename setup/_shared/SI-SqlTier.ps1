#Requires -Version 5.1
<#
    SecurityInsight -- THE SQL DATABASE SIZE (#507, operator 2026-10-09: "default must be s1 or s2, newer basic. it must be
    fixed for all prod customers").

    Measured on a customer tenant 2026-10-09 (about 23,000 users, 97,000 records a run): the Basic tier (5 DTU) averaged 14 % DTU with log-write
    peaks up to 98 % while the records were written, and Basic's 2 GB cap cannot hold a large tenant. So:

      * THE RULE (Get-SISqlDatabaseTier, one function, tested): never Basic. #509 (operator 2026-10-09: "it is very
        little money"): the Pro database (sqldb-si-pro, and any data database the install is configured with) is
        Standard S3 (100 DTU) for EVERY install, whatever the tenant's size (S2 until 2026-10-11 -- owner, approved: the CIs page
        was slow on S2; reliability over cost); the identity ledger (sqldb-si-identity) stays
        Standard S1 (20 DTU). (Until #509 the Pro database was S1 below 5,000 directory objects.) Max size 250 GB, the
        Standard tier's default. A size the customer set (SI_Bootstrap_SqlServiceObjective, or the updater job's
        SI_UPDATER_SQL_SERVICE_OBJECTIVE) wins.
      * NEW INSTALLS: the guided install creates its databases at that size (SI-GuidedInstallPro.ps1, step pro-sql).
      * EXISTING INSTALLS: every update (setup\Invoke-SIContainerUpdate.ps1 -Apply, which both the updater job and the VM
        sync hook run from the release) raises a smaller database to it by ONE ARM PATCH of its sku -- online, no data
        loss, a short reconnect when Azure switches over (Invoke-SISqlTierUpgrade). The rule NEVER lowers a database, and
        never touches one the customer put above S3, on Premium, on vCore or in an elastic pool (Get-SISqlTierChange).
      * A SIZE THE CUSTOMER SET LOWERS TOO (owner 2026-10-18 -- small installs' Pro database is idle about 98 % of the week
        on S3): SI_Bootstrap_SqlServiceObjective (the Pro database's setting -- the Settings page, or support through
        setup\Set-SIProSetting.ps1 -- then the config, then SI_UPDATER_SQL_SERVICE_OBJECTIVE) applies in BOTH directions: S2
        on an S3 database lowers it, by the same one online PATCH. Standard only, and the Pro database never below S1 (no
        Basic, no S0). Not set: the rule above, raise only. No default changes. The Pro database and a data database ONLY:
        the identity ledger is S1 everywhere, whatever is set (owner 2026-10-18: "identity database: keep S1 everywhere").
        One plain line per database goes to the run log; the updater records it in the Pro database (cfg.InstallState
        'SqlTier').
      * RIGHTS: the PATCH needs Microsoft.Sql/servers/databases/write on the database. The updater's identity has it
        through Contributor on the install's resource group (Install-SIUpdaterJob -GrantSpnRoles), where the guided install
        puts the server. A server elsewhere: the run reads the identity's permissions first and says what is missing
        ('SQL DB Contributor' on the server) -- it grants nothing itself.

    #521 NO az CLI on the update: every call goes through the REST seam -Rest { param($Method, $Uri, $Body, $Resource,
    $Headers) } -> @{ Status; Body } (setup/_shared/SI-UpdateRest.ps1): ARM Microsoft.Sql servers / databases list, the
    permissions read, the sku PATCH; Microsoft Graph $count for the tenant's size. The guided install passes -Rest too:
    the old az seam (-Az) is gone, there is no az path left. The decisions are tested offline against the REST seam.
    PowerShell 5.1-compatible (the VM sync hook runs
    Invoke-SIContainerUpdate.ps1 on Windows PowerShell).
#>

if (-not (Get-Command -Name Invoke-SIRestJson -ErrorAction SilentlyContinue)) { . ([IO.Path]::Combine($PSScriptRoot, 'SI-UpdateRest.ps1')) }

# The tenant size the collection-job fallback reports (Get-SISqlTierObjectsFromJobs). Since #509 the Pro database is S2 (S3 since 2026-10-11) at
# any size, so this only feeds the log line.
$script:SISqlTierLargeTenantObjects = 5000
# The Standard tier's default (and largest without extra storage) max size: 250 GB.
$script:SISqlTierStandardMaxBytes = [long]268435456000
# The ARM api-version of the database read and the PATCH.
$script:SISqlTierArmApi = '2021-11-01'
# The DTU ladder (service objective -> DTU). Basic and Standard are the tiers this sizing raises; Premium is the customer's.
$script:SISqlTierDtu = [ordered]@{
    'Basic' = 5; 'S0' = 10; 'S1' = 20; 'S2' = 50; 'S3' = 100; 'S4' = 200; 'S6' = 400; 'S7' = 800; 'S9' = 1600; 'S12' = 3000
    'P1' = 125; 'P2' = 250; 'P4' = 500; 'P6' = 1000; 'P11' = 1750; 'P15' = 4000
}
# The database names SecurityInsight creates or is configured with (only these are ever sized on a server).
$script:SISqlTierKnownDatabases = @('sqldb-si-pro', 'sqldb-si-identity')

function Get-SISqlTierObjectCount {
    <# PURE. Users + groups + service principals + devices from -Counts (Graph $count); $null when no count is known. #>
    param([hashtable]$Counts)
    if (-not $Counts) { return $null }
    $n = 0L; $any = $false
    foreach ($k in 'Users', 'Groups', 'ServicePrincipals', 'Devices') {
        if ($Counts.ContainsKey($k) -and $null -ne $Counts[$k] -and "$($Counts[$k])".Trim() -ne '') { $n += [long]$Counts[$k]; $any = $true }
    }
    if ($any) { $n } else { $null }
}

function Get-SISqlServiceObjectiveSku {
    <# PURE. A DTU service objective name ('S2', 'basic', 'P1') -> @{ Name; Tier; Capacity }, or $null when it is not one. #>
    param([AllowEmptyString()][string]$Name)
    $k = "$Name".Trim()
    if (-not $k) { return $null }
    $hit = @($script:SISqlTierDtu.Keys | Where-Object { $_ -ieq $k }) | Select-Object -First 1
    if (-not $hit) { return $null }
    $tier = if ($hit -eq 'Basic') { 'Basic' } elseif ($hit -like 'S*') { 'Standard' } else { 'Premium' }
    [pscustomobject]@{ Name = $hit; Tier = $tier; Capacity = [int]$script:SISqlTierDtu[$hit] }
}

function Get-SISqlDatabaseTier {
    <#
        PURE. THE RULE: the size an SI database should have. Role Data (the Pro database): S3 at any tenant size (#509; S2 until
        2026-10-11, owner: the CIs page was slow on S2's 50 DTU).
        -Objects = users + groups + service principals + devices ($null = not known) -- carried on the result for the
        logs, it no longer decides the size. -Override = a size the customer set (a DTU service objective: Basic, S0-S12,
        P1-P15); a valid one wins (the Pro database never below S1), anything else is ignored with a note. Returns @{ Name; Tier; Capacity; MaxSizeBytes
        (0 = the tier's own default); Objects; Source = every-install | customer | ledger; Reason; Note }.
        -Role Ledger: the identity ledger database (sqldb-si-identity) is S1 whatever the tenant's size -- it holds only the
        object identifiers (si.ObjectIdentity, written per CI-build batch); the records, the CIs and the findings -- the
        writes Basic could not take -- are in the Pro database (Role Data). -Override NEVER applies to it (owner 2026-10-18:
        "identity database: keep S1 everywhere"): SI_Bootstrap_SqlServiceObjective sizes the Pro and data databases only.
    #>
    param([AllowNull()]$Objects, [AllowEmptyString()][string]$Override, [ValidateSet('Data', 'Ledger')][string]$Role = 'Data')
    $note = ''
    # THE IDENTITY LEDGER IS S1 EVERYWHERE (owner 2026-10-18: "identity database: keep S1 everywhere"): a size the customer set
    # is for the Pro database (and a data database) only -- never for the ledger, which keeps its own rule.
    if ($Role -eq 'Ledger') {
        return [pscustomobject]@{ Name = 'S1'; Tier = 'Standard'; Capacity = 20; MaxSizeBytes = $script:SISqlTierStandardMaxBytes; Objects = $Objects
            Source = 'ledger'; Reason = 'S1 (the identity ledger: identifiers only, S1 at any tenant size)'; Note = '' }
    }
    # THE PRO DATABASE NEVER BELOW S1 (owner 2026-10-18: a size the customer set now LOWERS too -- "S2 on an S3 database lowers
    # it" -- so the floor matters): a Basic or S0 override of the Pro database becomes S1 + 250 GB, said.
    $low = Get-SISqlServiceObjectiveSku -Name $Override
    if ($Role -eq 'Data' -and $low -and $low.Tier -ne 'Premium' -and $low.Capacity -lt 20) {
        return [pscustomobject]@{ Name = 'S1'; Tier = 'Standard'; Capacity = 20; MaxSizeBytes = $script:SISqlTierStandardMaxBytes; Objects = $Objects
            Source = 'customer'; Reason = ('S1, the minimum (the size this install set, {0}, is below it)' -f $low.Name)
            Note = ('the database size {0} that was set is never used for the Pro database -- S1 with 250 GB is its minimum' -f $low.Name) }
    }
    # NEVER Basic: S0 is the minimum for every SI database, a size the customer set included (owner 2026-10-09, framework
    # §12.15: "newer basic. s0 as minimum"). Basic's 2 GB filled ring 1; a Basic override becomes S0 + 250 GB, said.
    $basic = Get-SISqlServiceObjectiveSku -Name $Override
    if ($basic -and $basic.Tier -eq 'Basic') {
        return [pscustomobject]@{ Name = 'S0'; Tier = 'Standard'; Capacity = 10; MaxSizeBytes = $script:SISqlTierStandardMaxBytes; Objects = $Objects
            Source = 'customer'; Reason = 'S0, the minimum (the size this install set, Basic, is never used)'
            Note = 'the database size Basic that was set is never used -- S0 with 250 GB is the minimum for every SecurityInsight database' }
    }
    if ("$Override".Trim()) {
        $o = Get-SISqlServiceObjectiveSku -Name $Override
        if ($o) {
            $max = if ($o.Tier -eq 'Standard') { $script:SISqlTierStandardMaxBytes } else { 0L }
            return [pscustomobject]@{ Name = $o.Name; Tier = $o.Tier; Capacity = $o.Capacity; MaxSizeBytes = [long]$max; Objects = $Objects
                Source = 'customer'; Reason = ('{0}, the size this install set' -f $o.Name); Note = '' }
        }
        $note = ("the database size '{0}' that was set is not a DTU size (Basic, S0-S12, P1-P15) -- it is ignored" -f "$Override".Trim())
    }
    # #509: S3 (was S2) at ANY tenant size. -Objects is kept on the result (the logs show it) but decides nothing any more.
    $n = if ($null -eq $Objects -or "$Objects".Trim() -eq '') { $null } else { [long]$Objects }
    [pscustomobject]@{ Name = 'S3'; Tier = 'Standard'; Capacity = 100; MaxSizeBytes = $script:SISqlTierStandardMaxBytes; Objects = $n
        Source = 'every-install'; Reason = 'S3 (every SecurityInsight Pro database, at any tenant size)'; Note = $note }
}

function Get-SISqlTierObjectsFromJobs {
    <#
        PURE. A fallback for an updater that cannot read the directory: the collection jobs that setup SIZED for the tenant
        (Get-SITenantSizedJobResources gives caj-si-identity / caj-si-endpoint 4 GiB or more from
        5,000 objects; their own default is 2 GiB) say the tenant has at least 5,000 objects. -Jobs in ARM shape (job list).
        Returns 5000 when one of them carries 4 GiB or more, else $null (not known).
    #>
    param([object[]]$Jobs = @())
    foreach ($j in @($Jobs)) {
        if (-not $j) { continue }
        $name = [string]$j.name
        if ($name -notin @('caj-si-identity', 'caj-si-endpoint')) { continue }
        $mem = $null
        try { $mem = [string]$j.properties.template.containers[0].resources.memory } catch { $mem = $null }
        if (-not $mem) { continue }
        $gi = 0.0
        if ([double]::TryParse(($mem -replace '(?i)gi$', ''), [Globalization.NumberStyles]::Float, [Globalization.CultureInfo]::InvariantCulture, [ref]$gi) -and $gi -ge 4) { return [long]$script:SISqlTierLargeTenantObjects }
    }
    $null
}

function Get-SISqlTierChange {
    <#
        PURE. What to do with ONE database. -Current: the ARM database (sku.name / sku.tier / sku.capacity,
        properties.maxSizeBytes / elasticPoolId / currentServiceObjectiveName). -Target: Get-SISqlDatabaseTier's result.
        Returns @{ Action = raise | lower | keep; Reason; From; Body (the PATCH body as an ordered hashtable, raise / lower) }.
        The product's rule never lowers. A size the CUSTOMER set (-Target.Source 'customer'; owner 2026-10-18: "S2 on an S3
        database lowers it") applies both ways: a Standard database above it is lowered to it -- a Standard size of at least
        S1, never Basic or S0. Never changes: an elastic pool member, vCore / Premium / any tier but Basic and Standard, a
        database already at the target, or (without a size the customer set) one at or above the target or above S3.
    #>
    param([Parameter(Mandatory)]$Current, [Parameter(Mandatory)]$Target)
    $p = { param($o, $n) if ($o -and $o.PSObject.Properties[$n]) { $o.$n } else { $null } }
    $sku = & $p $Current 'sku'; $props = & $p $Current 'properties'
    # A DTU database's sku is { name = 'Standard', tier = 'Standard', capacity = 20 } (Basic: name 'Basic'); its service
    # objective (S1) is properties.currentServiceObjectiveName. vCore: { name = 'GP_Gen5', tier = 'GeneralPurpose' }.
    $tier = [string](& $p $sku 'tier'); $cap = & $p $sku 'capacity'; $skuName = [string](& $p $sku 'name')
    $name = [string](& $p $props 'currentServiceObjectiveName')
    if (-not (Get-SISqlServiceObjectiveSku -Name $name)) {
        if (Get-SISqlServiceObjectiveSku -Name $skuName) { $name = $skuName }
        elseif ($tier -in @('Basic', 'Standard', 'Premium') -and $null -ne $cap -and "$cap".Trim()) {
            $hit = @($script:SISqlTierDtu.Keys | Where-Object { (Get-SISqlServiceObjectiveSku -Name $_).Tier -eq $tier -and $script:SISqlTierDtu[$_] -eq [int]$cap }) | Select-Object -First 1
            if ($hit) { $name = $hit } elseif (-not $name) { $name = $skuName }
        } elseif (-not $name) { $name = $skuName }
    }
    $from = if ($name) { $name } else { 'unknown' }
    $keep = { param($why) [pscustomobject]@{ Action = 'keep'; Reason = $why; From = $from; Body = $null } }
    if ([string](& $p $props 'elasticPoolId') -or $name -ieq 'ElasticPool') { return (& $keep 'in an elastic pool -- the pool''s size is the customer''s; left as it is') }
    $cur = Get-SISqlServiceObjectiveSku -Name $name
    if (-not $cur -or ($tier -and $tier -notin @('Basic', 'Standard', 'Premium'))) { return (& $keep ('{0} ({1}) is a vCore or other size the customer chose; left as it is' -f $from, $(if ($tier) { $tier } else { 'not a DTU tier' }))) }
    if ($cur.Tier -eq 'Premium') { return (& $keep ('{0} is Premium, sized by the customer; left as it is' -f $cur.Name)) }
    $curMax = [long]0; $m = & $p $props 'maxSizeBytes'
    if ($null -ne $m) { [void][long]::TryParse("$m", [ref]$curMax) }
    # A SIZE THE CUSTOMER SET LOWERS TOO (owner 2026-10-18): a Standard target of at least S1 below the database's size. The
    # storage limit is kept, unless the smaller size cannot hold it (above the target's own maximum: it becomes that maximum).
    $src = if ($Target.PSObject.Properties['Source']) { [string]$Target.Source } else { '' }
    if ($src -eq 'customer' -and [string]$Target.Tier -eq 'Standard' -and [int]$Target.Capacity -ge 20 -and $cur.Capacity -gt [int]$Target.Capacity) {
        $body = [ordered]@{ sku = [ordered]@{ name = [string]$Target.Name; tier = [string]$Target.Tier } }
        if ([long]$Target.MaxSizeBytes -gt 0 -and [int]$Target.Capacity -lt 100 -and $curMax -gt [long]$Target.MaxSizeBytes) { $body['properties'] = [ordered]@{ maxSizeBytes = [long]$Target.MaxSizeBytes } }
        return [pscustomobject]@{ Action = 'lower'; Reason = ('{0} -> {1}: {2}' -f $cur.Name, $Target.Name, $Target.Reason); From = $cur.Name; Body = $body }
    }
    if ($cur.Capacity -gt 100 -and $src -ne 'customer') { return (& $keep ('{0} is above S3, sized by the customer; left as it is' -f $cur.Name)) }
    if ($cur.Capacity -ge [int]$Target.Capacity) {
        # the size is right, the STORAGE LIMIT is not: a Standard database still at Basic's 2 GB (a raise that kept the old
        # limit) fills up and every write fails (ring 1 2026-10-09: S2 at 2 GB, "reached its size quota"). The limit
        # grows alone -- the service objective is untouched, and Standard includes 250 GB at no extra cost.
        if ($cur.Tier -eq 'Standard' -and [long]$Target.MaxSizeBytes -gt 0 -and $curMax -gt 0 -and $curMax -lt [long]$Target.MaxSizeBytes) {
            return [pscustomobject]@{ Action = 'raise'; From = $cur.Name
                Reason = ('{0} keeps its size; its storage limit grows {1:N0} GB -> {2:N0} GB' -f $cur.Name, ($curMax / 1GB), ([long]$Target.MaxSizeBytes / 1GB))
                Body = [ordered]@{ properties = [ordered]@{ maxSizeBytes = [long]$Target.MaxSizeBytes } } }
        }
        return (& $keep ('{0} is already at or above {1}; never lowered' -f $cur.Name, $Target.Name))
    }
    # the service objective by name (ARM's own example: { "sku": { "name": "S2", "tier": "Standard" } })
    $body = [ordered]@{ sku = [ordered]@{ name = [string]$Target.Name; tier = [string]$Target.Tier } }
    if ([long]$Target.MaxSizeBytes -gt 0 -and $curMax -lt [long]$Target.MaxSizeBytes) { $body['properties'] = [ordered]@{ maxSizeBytes = [long]$Target.MaxSizeBytes } }
    [pscustomobject]@{ Action = 'raise'; Reason = ('{0} -> {1}: {2}' -f $cur.Name, $Target.Name, $Target.Reason); From = $cur.Name; Body = $body }
}

function ConvertTo-SISqlTierPatchJson {
    <# PURE. The PATCH body as compact JSON (the sku, and the max size when it grows). #>
    param([Parameter(Mandatory)][System.Collections.IDictionary]$Body)
    $Body | ConvertTo-Json -Compress -Depth 4
}

function Get-SISqlDatabaseCreateArgs {
    <# PURE. The `az sql db create` size arguments for a new database at -Target (Get-SISqlDatabaseTier). #>
    param([Parameter(Mandatory)]$Target)
    $a = @('--service-objective', [string]$Target.Name)
    if ([long]$Target.MaxSizeBytes -gt 0) { $a += @('--max-size', ('{0}GB' -f [long]([long]$Target.MaxSizeBytes / 1GB))) }
    $a
}

function Test-SISqlTierPermission {
    <#
        PURE. Does an ARM permissions list (GET <scope>/providers/Microsoft.Authorization/permissions: value[].actions /
        notActions) allow Microsoft.Sql/servers/databases/write? $true / $false; $null when the list says nothing usable.
    #>
    param([object[]]$Permissions = @())
    $want = 'Microsoft.Sql/servers/databases/write'
    $match = { param($pat) $rx = '^' + ([regex]::Escape([string]$pat) -replace '\\\*', '.*') + '$'; $want -match "(?i)$rx" }
    $allow = $false; $deny = $false; $seen = $false
    foreach ($perm in @($Permissions)) {
        if (-not $perm) { continue }
        $seen = $true
        foreach ($a in @($perm.actions)) { if ($a -and (& $match $a)) { $allow = $true } }
        foreach ($n in @($perm.notActions)) { if ($n -and (& $match $n)) { $deny = $true } }
    }
    if (-not $seen) { return $null }
    $allow -and -not $deny
}

function Get-SISqlTierTenantCounts {
    <#
        The tenant's directory counts (Microsoft Graph $count, ConsistencyLevel eventual) -- $null when they cannot be read
        (an identity without directory read: the updater's managed identity has none). An answer that is not a plain number
        is not a count. -Rest: the update's REST seam (setup/_shared/SI-UpdateRest.ps1, #521).
    #>
    param([Parameter(Mandatory)][scriptblock]$Rest, [string]$SubscriptionId)
    $c = @{}
    foreach ($k in @(@{ N = 'Users'; P = 'users' }, @{ N = 'Groups'; P = 'groups' }, @{ N = 'ServicePrincipals'; P = 'servicePrincipals' }, @{ N = 'Devices'; P = 'devices' })) {
        $r = & $Rest 'GET' ('https://graph.microsoft.com/v1.0/{0}/$count' -f $k.P) $null 'https://graph.microsoft.com/' @{ ConsistencyLevel = 'eventual'; Accept = 'text/plain' }
        if (-not $r -or [int]$r.Status -lt 200 -or [int]$r.Status -ge 300) { return $null }
        $t = "$($r.Body)".Trim().TrimStart([char]0xFEFF)
        $n = 0L
        if ($t -notmatch '^\d+$' -or -not [long]::TryParse($t, [ref]$n)) { return $null }
        $c[$k.N] = $n
    }
    $c
}

function Get-SISqlTierServerFqdn {
    <# PURE. A SQL server's host name from its ARM shape (properties.fullyQualifiedDomainName) or a flattened one. #>
    param($Server)
    if (-not $Server) { return '' }
    if ($Server.PSObject.Properties['properties'] -and $Server.properties -and $Server.properties.PSObject.Properties['fullyQualifiedDomainName']) { return ([string]$Server.properties.fullyQualifiedDomainName).ToLowerInvariant() }
    if ($Server.PSObject.Properties['fullyQualifiedDomainName']) { return ([string]$Server.fullyQualifiedDomainName).ToLowerInvariant() }
    ''
}

function Invoke-SISqlTierRead {
    <#
        One read of the size step. -Kind: ServersInRg | ServersAll | Databases (of -Server) | Permissions (on -Server).
        Lists come back as items (@() when they cannot be read), Permissions as the parsed answer ($null when unreadable).
        Over -Rest (ARM; #521 -- there is no az path).
    #>
    param([Parameter(Mandatory)][scriptblock]$Rest, [Parameter(Mandatory)][string]$SubscriptionId,
          [Parameter(Mandatory)][ValidateSet('ServersInRg', 'ServersAll', 'Databases', 'Permissions')][string]$Kind, [string]$ResourceGroup, $Server)
    $path = switch ($Kind) {
        'ServersInRg' { '/subscriptions/{0}/resourceGroups/{1}/providers/Microsoft.Sql/servers' -f $SubscriptionId, $ResourceGroup }
        'ServersAll'  { '/subscriptions/{0}/providers/Microsoft.Sql/servers' -f $SubscriptionId }
        'Databases'   { [string]$Server.id + '/databases' }
        'Permissions' { [string]$Server.id + '/providers/Microsoft.Authorization/permissions' }
    }
    if ($Kind -eq 'Permissions') { try { return (Invoke-SIRestJson -Rest $Rest -Uri (Get-SIArmUri -Path $path -ApiVersion '2022-04-01') -What 'the permissions on the SQL server') } catch { return $null } }
    try { return @(Get-SIRestList -Rest $Rest -Uri (Get-SIArmUri -Path $path -ApiVersion $script:SISqlTierArmApi) -What ('SQL {0}' -f $Kind)) } catch { return @() }
}

function Invoke-SISqlTierPatch {
    <# One online ARM PATCH of a database's sku over -Rest: @{ Ok; Text (what Azure said when it refused) }. -WorkDir / -Name:
       kept for callers, unused (the az path that wrote a body file is gone). #>
    param([Parameter(Mandatory)][scriptblock]$Rest, [Parameter(Mandatory)][string]$SubscriptionId, [Parameter(Mandatory)][string]$Url, [Parameter(Mandatory)][string]$Json,
          [string]$WorkDir, [string]$Name)
    $r = & $Rest 'PATCH' $Url $Json 'https://management.azure.com/' @{ 'Content-Type' = 'application/json' }
    $ok = ($r -and [int]$r.Status -ge 200 -and [int]$r.Status -lt 300)
    [pscustomobject]@{ Ok = $ok; Text = $(if ($ok) { '' } else { Format-SIRestFailure -Response $r }) }
}

function Invoke-SISqlTierUpgrade {
    <#
        EXISTING INSTALLS: raise this install's SI databases to the rule's size. -Rest: the update's REST seam
        (setup/_shared/SI-UpdateRest.ps1 -- ARM only, #521); the update and the guided install both pass it. No az path.
        -ServerFqdns: the SQL servers the install is configured with (SI_ProSqlServer, SI_LedgerSqlServer, ...); the servers
        in -ResourceGroup are looked at too. -DatabaseNames: the databases the install is configured with; the names SI
        creates (sqldb-si-pro, sqldb-si-identity) are always included. No other database on a server is ever touched.
        -Objects / -Override: Get-SISqlDatabaseTier. -WhatIf: plan only.
        Returns @{ Results = @(@{ Server; Database; Action = raised | lowered | keep | would-raise | would-lower | missing-right | failed; Line });
        Lines; Target }. NEVER throws: a database that cannot be read or changed is a line, and the update goes on.
    #>
    param([scriptblock]$Rest, [Parameter(Mandatory)][string]$SubscriptionId, [string]$ResourceGroup,
          [string[]]$ServerFqdns = @(), [string[]]$DatabaseNames = @(), [AllowNull()]$Objects, [AllowEmptyString()][string]$Override,
          # the identity ledger databases (always S1 -- a size the customer set never applies to them; sqldb-si-identity is always one); a name
          # also in -DatabaseNames (a ledger kept in the Pro database) is sized as data
          [string[]]$LedgerDatabaseNames = @(),
          [switch]$WhatIf, [string]$WorkDir)
    if (-not $Rest) { throw 'Invoke-SISqlTierUpgrade: pass -Rest (the REST seam of setup\_shared\SI-UpdateRest.ps1).' }
    $target = Get-SISqlDatabaseTier -Objects $Objects -Override $Override
    $ledgerTarget = Get-SISqlDatabaseTier -Objects $Objects -Override $Override -Role Ledger
    $dataNames = @(@('sqldb-si-pro') + @($DatabaseNames) | Where-Object { "$_".Trim() } | ForEach-Object { "$_".Trim().ToLowerInvariant() })
    $ledgerNames = @(@('sqldb-si-identity') + @($LedgerDatabaseNames) | Where-Object { "$_".Trim() } | ForEach-Object { "$_".Trim().ToLowerInvariant() } | Where-Object { $_ -notin $dataNames })
    $results = New-Object System.Collections.Generic.List[object]
    $lines = New-Object System.Collections.Generic.List[string]
    if ($target.Note) { $lines.Add(('SQL database size: {0}' -f $target.Note)) }
    $add = { param($srv, $db, $act, $line, $want = '') $results.Add([pscustomobject]@{ Server = $srv; Database = $db; Action = $act; Line = $line; Target = $want }); $lines.Add($line) }
    $read = @{ Rest = $Rest; SubscriptionId = $SubscriptionId }

    # ---- the servers: in the install's resource group, and the configured ones found by their host name ----
    $servers = New-Object System.Collections.Generic.List[object]
    $seen = @{}
    $keepSrv = { param($s) if ($s -and $s.id -and -not $seen.ContainsKey(([string]$s.id).ToLowerInvariant())) { $seen[([string]$s.id).ToLowerInvariant()] = $true; $servers.Add($s) } }
    if ($ResourceGroup) { foreach ($s in @(Invoke-SISqlTierRead @read -Kind ServersInRg -ResourceGroup $ResourceGroup)) { & $keepSrv $s } }
    $fqdns = @($ServerFqdns | Where-Object { "$_".Trim() } | ForEach-Object { "$_".Trim().ToLowerInvariant() } | Select-Object -Unique)
    $missing = @($fqdns | Where-Object { $f = $_; -not @($servers | Where-Object { (Get-SISqlTierServerFqdn $_) -eq $f }).Count })
    if ($missing.Count) {
        foreach ($s in @(Invoke-SISqlTierRead @read -Kind ServersAll)) {
            if ($s -and (Get-SISqlTierServerFqdn $s) -in $missing) { & $keepSrv $s }
        }
        foreach ($f in $missing) {
            if (-not @($servers | Where-Object { (Get-SISqlTierServerFqdn $_) -eq $f }).Count) {
                & $add $f '' 'failed' ('SQL database size: the server {0} was not found in subscription {1} (or this identity cannot read it) -- its databases were not checked' -f $f, $SubscriptionId)
            }
        }
    }
    $names = @(@($script:SISqlTierKnownDatabases) + $dataNames + $ledgerNames | Where-Object { "$_".Trim() } | ForEach-Object { "$_".Trim().ToLowerInvariant() } | Select-Object -Unique)
    if (-not $servers.Count) { if (-not $results.Count) { & $add '' '' 'keep' 'SQL database size: no SQL server for this install was found -- nothing to size' }; return [pscustomobject]@{ Results = $results.ToArray(); Lines = $lines.ToArray(); Target = $target } }
    if (-not $WorkDir) { $WorkDir = Join-Path ([IO.Path]::GetTempPath()) ('si-sqltier-' + [guid]::NewGuid().ToString('N').Substring(0, 8)) }

    foreach ($srv in $servers) {
        $srvName = [string]$srv.name; $srvRg = [string]$srv.resourceGroup
        if (-not $srvRg -and [string]$srv.id -match '/resourceGroups/([^/]+)/') { $srvRg = $Matches[1] }
        $dbs = @(Invoke-SISqlTierRead @read -Kind Databases -Server $srv)
        $dbs = @($dbs | Where-Object { $_ -and ([string]$_.name).ToLowerInvariant() -in $names })
        if (-not $dbs.Count) { continue }
        # the right to change them: read once per server (a list that says nothing usable = try, and read the answer)
        $canWrite = $null
        $perm = Invoke-SISqlTierRead @read -Kind Permissions -Server $srv
        if ($perm -and $perm.PSObject.Properties['value']) { $canWrite = Test-SISqlTierPermission -Permissions @($perm.value) }
        foreach ($db in $dbs) {
            $dbName = [string]$db.name
            # ARM keeps the size under .properties (the az list flattened it): the decision reads the ARM shape
            $dp = if ($db.PSObject.Properties['properties'] -and $db.properties) { $db.properties } else { $db }
            $dv = { param($n) if ($dp.PSObject.Properties[$n]) { $dp.$n } else { $null } }
            $cur = [pscustomobject]@{
                sku = $(if ($db.PSObject.Properties['sku'] -and $db.sku) { $db.sku } else { [pscustomobject]@{ name = [string](& $dv 'currentServiceObjectiveName'); tier = [string](& $dv 'edition'); capacity = (& $dv 'capacity') } })
                properties = [pscustomobject]@{ maxSizeBytes = (& $dv 'maxSizeBytes'); elasticPoolId = [string](& $dv 'elasticPoolId'); currentServiceObjectiveName = [string](& $dv 'currentServiceObjectiveName') }
            }
            $want = if ($dbName.ToLowerInvariant() -in $ledgerNames) { $ledgerTarget } else { $target }
            $ch = Get-SISqlTierChange -Current $cur -Target $want
            if ($ch.Action -eq 'keep') { & $add $srvName $dbName 'keep' ('SQL database size: {0}/{1} stays {2} -- {3}' -f $srvName, $dbName, $ch.From, $ch.Reason) $want.Name; continue }
            # a size the customer set may LOWER a database (owner 2026-10-18); the product's rule only raises
            $vb = if ($ch.Action -eq 'lower') { 'lowered' } else { 'raised' }
            if ($WhatIf) { & $add $srvName $dbName $(if ($ch.Action -eq 'lower') { 'would-lower' } else { 'would-raise' }) ('SQL database size: {0}/{1} would be {3} {2} (an online change, re-run with -Apply)' -f $srvName, $dbName, $ch.Reason, $vb) $want.Name; continue }
            if ($canWrite -eq $false) {
                & $add $srvName $dbName 'missing-right' ('SQL database size: {0}/{1} should be {4} {2}, but this identity may not change it (it lacks Microsoft.Sql/servers/databases/write) -- give it the role ''SQL DB Contributor'' on server {0} (or Contributor on resource group {3}); nothing was changed' -f $srvName, $dbName, $ch.Reason, $srvRg, $vb) $want.Name
                continue
            }
            $id = if ($db.PSObject.Properties['id'] -and $db.id) { [string]$db.id } else { '{0}/databases/{1}' -f [string]$srv.id, $dbName }
            $url = 'https://management.azure.com{0}?api-version={1}' -f $id, $script:SISqlTierArmApi
            $r = Invoke-SISqlTierPatch @read -Url $url -Json (ConvertTo-SISqlTierPatchJson -Body $ch.Body) -WorkDir $WorkDir -Name $dbName
            if ($r.Ok) {
                & $add $srvName $dbName $vb ('SQL database size: {0}/{1} {3} {2} -- an online change (no data loss; open connections reconnect once when Azure switches over, within minutes)' -f $srvName, $dbName, $ch.Reason, $vb) $want.Name
            } elseif ("$($r.Text)" -match '(?i)AuthorizationFailed|\b403\b|Forbidden|does not have authorization') {
                & $add $srvName $dbName 'missing-right' ('SQL database size: {0}/{1} should be {4} {2}, but Azure refused this identity (Microsoft.Sql/servers/databases/write) -- give it the role ''SQL DB Contributor'' on server {0} (or Contributor on resource group {3}); nothing was changed' -f $srvName, $dbName, $ch.Reason, $srvRg, $vb)
            } else {
                $why = ("$($r.Text)" -replace '\s+', ' ').Trim(); if ($why.Length -gt 300) { $why = $why.Substring(0, 297) + '...' }
                & $add $srvName $dbName 'failed' ('SQL database size: {0}/{1} was NOT {4} {2}: {3} -- the next update tries again' -f $srvName, $dbName, $ch.Reason, $why, $vb)
            }
        }
    }
    Remove-Item -LiteralPath $WorkDir -Recurse -Force -ErrorAction SilentlyContinue
    if (-not $results.Count) { & $add '' '' 'keep' 'SQL database size: no SecurityInsight database was found on this install''s SQL servers -- nothing to size' }
    [pscustomobject]@{ Results = $results.ToArray(); Lines = $lines.ToArray(); Target = $target }
}

function Get-SISqlTierSummaryLine {
    <# PURE. ONE plain line for the run log / the Pro database (cfg.InstallState 'SqlTier'), at most 400 characters. #>
    param([Parameter(Mandatory)]$Upgrade)
    $r = @($Upgrade.Results)
    $parts = foreach ($x in $r) {
        if (-not $x.Database) { continue }
        $to = if ($x.PSObject.Properties['Target'] -and $x.Target) { $x.Target } else { $Upgrade.Target.Name }
        '{0} {1}' -f $x.Database, $(switch ($x.Action) { 'raised' { 'raised to ' + $to } 'lowered' { 'lowered to ' + $to } 'keep' { 'kept' } 'would-raise' { 'would be raised to ' + $to } 'would-lower' { 'would be lowered to ' + $to } 'missing-right' { 'NOT raised (missing right)' } default { 'NOT raised (failed)' } })
    }
    $t = if (@($parts).Count) { 'SQL database size {0}: {1}' -f $Upgrade.Target.Reason, (@($parts) -join ', ') } else { (@($Upgrade.Lines) | Select-Object -First 1) }
    $t = "$t"; if ($t.Length -gt 400) { $t = $t.Substring(0, 397) + '...' }
    $t
}
