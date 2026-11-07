#Requires -Version 5.1
<#
    PRIVATE NETWORKING AS AN OPTION (#681). ONE library for both ways it reaches an install:
      - a NEW install: the guided install, only when the install asks for it (privateNetwork = true; default OFF -- the
        default install is unchanged): the two subnets before the container setup (the Container Apps environment is
        created IN the customer's virtual network, internal), the private endpoints, the private DNS zones and closing the
        public endpoints at the end of the install;
      - an EXISTING install: setup\Set-SIPrivateNetworking.ps1 (PLAN by default, idempotent steps, read back after every
        change, ONE rollback record per run), through the Invardia Support app, one environment at a time.

    What "private" means here:
      * the Container Apps environment runs in the customer's subnet (delegated to Microsoft.App/environments), INTERNAL:
        the web app is reachable from the customer's network only (an internal environment has no public address);
      * private endpoints for the Pro database server (sqlServer), the Key Vault (vault), the storage account (blob, queue,
        table) and the container registry (registry; the registry must be Premium for that);
      * the private DNS zones of those endpoints (privatelink.*), linked to the virtual network -- in the install's resource
        group, or in the resource group the customer keeps its central zones in;
      * the environment's own DNS zone (its default domain -> its internal address), linked to the virtual network;
      * the public endpoints CLOSED: the database server and the storage account publicNetworkAccess = Disabled; the Key
        Vault's firewall Deny with "trusted Microsoft services" allowed (so a customer-managed key keeps working -- a vault
        with publicNetworkAccess Disabled refuses even those). The registry's public endpoint is closed only on its own,
        explicit step (its image builds run on Azure's build service).

    OWNER 2026-10-19: "same config as pim. when we say it is private, it stays that way". The design is PIM's private
    topology (PIM docs/DESIGN.md "Convert public to private", §27.11 "From inside: a private database"):
      * NO PUBLIC OPENING, EVER, once closed -- not for support, not for a setup re-run, not "for a few minutes" (PIM's
        MSP build window is NOT taken over). Set-SIPublicAccess refuses to put an open endpoint back unless the caller says
        -AllowReopen, which only the cut-over's rollback passes, and only with the customer's own -ReopenPublicAccess.
      * The Invardia Support app's database access is made BEFORE the public endpoint closes (its own user, db_owner, and
        its membership of the admin group, read back) -- the cut-over refuses to close otherwise.
      * After the close, support reaches the database ONLY FROM INSIDE: a one-time job in the install's own private
        environment (setup\Invoke-SISupportSqlAccessJob.ps1), signed in as the in-network SQL identity id-si-sql (PIM:
        id-pim-sql-<token>), a member of the database server's admin group. No firewall rule, no jump host.
      * The registry's public endpoint closes only when image builds run INSIDE the network: an agent pool of the
        registry in the endpoints subnet (PIM: the ACR agent pool), and the registry's own private endpoint approved.

    Every function that talks to Azure takes -Arm, a script block  { param([string]$Method, [string]$Path, $Body) }:
    -Path is '/subscriptions/...?api-version=...'; it returns the parsed answer, $null for "not found" on a GET, and
    THROWS on any other error. Setup passes Invoke-SIArm; the cut-over passes the Support session's recording seam; the
    tests pass a fake. No module, no az, no native exe. After every create or change: wait, and READ IT BACK.
    PS 5.1 safe.
#>

# NO Set-StrictMode here -- it leaks into the caller's scope.

$script:SIPnNetApi  = '2024-05-01'
$script:SIPnDnsApi  = '2020-06-01'
$script:SIPnAppApi  = '2025-07-01'
$script:SIPnSqlApi  = '2021-11-01'
$script:SIPnKvApi   = '2023-07-01'
$script:SIPnStApi   = '2023-05-01'
$script:SIPnAcrApi  = '2023-07-01'
$script:SIPnAuthApi = '2022-04-01'
$script:SIPnDiagApi = '2021-05-01-preview'
$script:SIPnMiApi   = '2023-01-31'
$script:SIPnAcrTasksApi = '2019-06-01-preview'
$script:SIPnAppsDelegation = 'Microsoft.App/environments'

# The private endpoint kinds: the sub-resource (group id) each one connects to and its private DNS zone (Azure public cloud).
# The three storage zones share one pattern (privatelink.<service>.core.windows.net), built from the service name.
$script:SIPnStorageZone = 'privatelink.{0}.core.windows.net'
$script:SIPnKinds = [ordered]@{
    sql      = @{ GroupId = 'sqlServer'; Zone = 'privatelink.database.windows.net'; Suffix = 'database.windows.net';         Type = 'Microsoft.Sql/servers';                  Label = 'database server' }
    vault    = @{ GroupId = 'vault';     Zone = 'privatelink.vaultcore.azure.net'; Suffix = 'vault.azure.net';          Type = 'Microsoft.KeyVault/vaults';              Label = 'Key Vault' }
    blob     = @{ GroupId = 'blob';      Zone = ($script:SIPnStorageZone -f 'blob'); Suffix = 'blob.core.windows.net';         Type = 'Microsoft.Storage/storageAccounts';      Label = 'storage (blobs)' }
    queue    = @{ GroupId = 'queue';     Zone = ($script:SIPnStorageZone -f 'queue'); Suffix = 'queue.core.windows.net';        Type = 'Microsoft.Storage/storageAccounts';      Label = 'storage (queues)' }
    table    = @{ GroupId = 'table';     Zone = ($script:SIPnStorageZone -f 'table'); Suffix = 'table.core.windows.net';        Type = 'Microsoft.Storage/storageAccounts';      Label = 'storage (tables)' }
    registry = @{ GroupId = 'registry';  Zone = 'privatelink.azurecr.io'; Suffix = 'azurecr.io';             Type = 'Microsoft.ContainerRegistry/registries'; Label = 'container registry' }
}

function Get-SIPrivateNetworkNames {
    <# PURE. The names this option gives what it creates. No ring or environment in them (framework 12.11c): the resource
       group and its tags say which install they belong to. PrivateEnvironment is the environment an EXISTING install moves
       to (a Container Apps environment cannot be moved into a virtual network; a new install's environment is created
       there under its usual name). #>
    [ordered]@{
        # #866: SecurityInsight's own spoke network, made when the customer gives an address range instead of a network
        Vnet               = 'vnet-si'
        AppsSubnet         = 'snet-si-apps'
        EndpointsSubnet    = 'snet-si-endpoints'
        PrivateEnvironment = 'cae-si-private'
        EndpointPrefix     = 'pe-si-'
        ZoneGroup          = 'default'
        # the in-network SQL identity (PIM: id-pim-sql-<token>): a member of the server's admin group, carried ONLY by a
        # one-time job while it runs (setup\Invoke-SISupportSqlAccessJob.ps1) -- no standing job carries it
        SqlIdentity        = 'id-si-sql'
        SupportSqlJob      = 'caj-si-supportsql'
        # #866: the one-time job that checks, from inside the environment, that the names resolve to private addresses
        InsideCheckJob     = 'caj-si-insidecheck'
        # the registry's agent pool in the endpoints subnet: image builds run inside the network (PIM: the ACR agent pool)
        AgentPool          = 'si-vnet-pool'
    }
}

function Get-SIPnProp {
    <# PURE. A nested property (PSCustomObject or hashtable), $null when any step is missing. #>
    param($Object, [string[]]$Names)
    $o = $Object
    foreach ($n in $Names) {
        if ($null -eq $o) { return $null }
        if ($o -is [System.Collections.IDictionary]) { if ($o.Contains($n)) { $o = $o[$n] } else { return $null }; continue }
        $p = $o.PSObject.Properties[$n]
        if (-not $p) { return $null }
        $o = $p.Value
    }
    $o
}

function ConvertTo-SIPnHashtable {
    <# PURE. A parsed ARM answer (PSCustomObjects, arrays) as ordered hashtables and arrays, so a body can be changed and
       sent back. Strings, numbers and booleans stay as they are. #>
    param($Object)
    if ($null -eq $Object) { return $null }
    if ($Object -is [string] -or $Object -is [ValueType]) { return $Object }
    if ($Object -is [System.Collections.IDictionary]) {
        $h = [ordered]@{}; foreach ($k in @($Object.Keys)) { $h[[string]$k] = ConvertTo-SIPnHashtable $Object[$k] }; return $h
    }
    if ($Object -is [System.Collections.IEnumerable]) { return , @(foreach ($i in $Object) { ConvertTo-SIPnHashtable $i }) }
    $h = [ordered]@{}
    foreach ($p in $Object.PSObject.Properties) { $h[$p.Name] = ConvertTo-SIPnHashtable $p.Value }
    $h
}

function ConvertFrom-SIPnResourceId {
    <# PURE. /subscriptions/<s>/resourceGroups/<g>/providers/<ns>/<type>/<name>[/...] as its parts; $null when it is not one. #>
    param([AllowEmptyString()][AllowNull()][string]$Id)
    $m = [regex]::Match("$Id".Trim(), '(?i)^/subscriptions/([^/]+)/resourceGroups/([^/]+)(?:/providers/([^/]+)/([^/]+)/([^/]+))?')
    if (-not $m.Success) { return $null }
    [pscustomobject]@{ SubscriptionId = $m.Groups[1].Value; ResourceGroup = $m.Groups[2].Value; Namespace = $m.Groups[3].Value
                       Type = $(if ($m.Groups[4].Success) { '{0}/{1}' -f $m.Groups[3].Value, $m.Groups[4].Value } else { '' }); Name = $m.Groups[5].Value
                       ResourceGroupId = ('/subscriptions/{0}/resourceGroups/{1}' -f $m.Groups[1].Value, $m.Groups[2].Value) }
}

function Get-SIPnArmList {
    <# Every item of an ARM list (follows nextLink). -Path includes the api-version. #>
    param([Parameter(Mandatory)][scriptblock]$Arm, [Parameter(Mandatory)][string]$Path)
    $items = New-Object System.Collections.Generic.List[object]
    $next = $Path
    for ($i = 0; $next -and $i -lt 50; $i++) {
        $page = & $Arm 'GET' $next $null
        if (-not $page) { break }
        foreach ($v in @(Get-SIPnProp $page @('value'))) { if ($null -ne $v) { $items.Add($v) } }
        $nl = [string](Get-SIPnProp $page @('nextLink'))
        $next = if ($nl) { $nl -replace '^https://management\.azure\.com', '' } else { '' }
    }
    $items.ToArray()
}

function Read-SIPnBack {
    <# Reads -Path back until -Test is true about it (an ARM change finishes after its answer), at most -Tries reads,
       -PauseSeconds apart. Returns the last read ($null = not there). #>
    param([Parameter(Mandatory)][scriptblock]$Arm, [Parameter(Mandatory)][string]$Path, [Parameter(Mandatory)][scriptblock]$Test,
          [scriptblock]$Sleep = { param($s) Start-Sleep -Seconds $s }, [int]$Tries = 24, [int]$PauseSeconds = 10)
    $o = $null
    for ($i = 1; $i -le $Tries; $i++) {
        $o = & $Arm 'GET' $Path $null
        if (& $Test $o) { return $o }
        if ($i -lt $Tries) { & $Sleep $PauseSeconds }
    }
    $o
}

function Test-SIPnSucceeded { param($Resource) [string](Get-SIPnProp $Resource @('properties', 'provisioningState')) -eq 'Succeeded' }

function Test-SIPnSameId {
    <# PURE. Two resource ids are the same resource (case does not matter, a trailing slash neither). #>
    param([AllowNull()][string]$A, [AllowNull()][string]$B)
    $x = "$A".Trim().TrimEnd('/'); $y = "$B".Trim().TrimEnd('/')
    [bool]($x -and $y -and [string]::Equals($x, $y, [System.StringComparison]::OrdinalIgnoreCase))
}

function Get-SIPnPrefixLength { param([AllowNull()][string]$Prefix) $m = [regex]::Match("$Prefix", '/(\d{1,2})$'); if ($m.Success) { [int]$m.Groups[1].Value } else { -1 } }

function ConvertTo-SICidrRange {
    <# PURE. An IPv4 range a.b.c.d/n as @{ Start; End; Bits } (unsigned), $null when it is not one. The address is taken
       as given (10.0.0.5/24 = 10.0.0.0 .. 10.0.0.255). #>
    param([AllowNull()][string]$Cidr)
    $m = [regex]::Match("$Cidr".Trim(), '^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})/(\d{1,2})$')
    if (-not $m.Success) { return $null }
    $o = @(1..4 | ForEach-Object { [uint64]$m.Groups[$_].Value }); if (@($o | Where-Object { $_ -gt 255 }).Count) { return $null }
    $bits = [int]$m.Groups[5].Value; if ($bits -gt 32) { return $null }
    $ip = ($o[0] * 16777216) + ($o[1] * 65536) + ($o[2] * 256) + $o[3]
    $size = [uint64][math]::Pow(2, 32 - $bits)
    $start = $ip - ($ip % $size)
    @{ Start = [uint64]$start; End = [uint64]($start + $size - 1); Bits = $bits }
}

function ConvertFrom-SICidrStart {
    <# PURE. The range a.b.c.d/-Bits starting at -Start (an unsigned address). #>
    param([uint64]$Start, [int]$Bits)
    $o = @(([uint64][math]::Floor($Start / 16777216) % 256), ([uint64][math]::Floor($Start / 65536) % 256), ([uint64][math]::Floor($Start / 256) % 256), ($Start % 256))
    ('{0}.{1}.{2}.{3}/{4}' -f $o[0], $o[1], $o[2], $o[3], $Bits)
}

function Test-SICidrOverlap {
    <# PURE. Do two ranges overlap? $null when either is not a range (unknown -- NOT "no overlap"). #>
    param([AllowNull()][string]$A, [AllowNull()][string]$B)
    $x = ConvertTo-SICidrRange $A; $y = ConvertTo-SICidrRange $B
    if ($null -eq $x -or $null -eq $y) { return $null }
    [bool](($x.Start -le $y.End) -and ($y.Start -le $x.End))
}

function Test-SICidrInside {
    <# PURE. Is -Inner wholly inside -Outer? $null when either is not a range. #>
    param([AllowNull()][string]$Inner, [AllowNull()][string]$Outer)
    $i = ConvertTo-SICidrRange $Inner; $o = ConvertTo-SICidrRange $Outer
    if ($null -eq $i -or $null -eq $o) { return $null }
    [bool](($i.Start -ge $o.Start) -and ($i.End -le $o.End))
}

function Get-SISpokeSubnetDefaults {
    <# PURE. The subnets of a network SecurityInsight makes from -AddressPrefix (PIM's spoke: a /26 delegated to Container
       Apps + a /26 for the private endpoints): the FIRST /26 for the environment, the SECOND for the endpoints. A range
       smaller than /25 has no room for both: @{ Ok = $false; Reason }. #>
    param([Parameter(Mandatory)][string]$AddressPrefix)
    $r = ConvertTo-SICidrRange $AddressPrefix
    if (-not $r) { return @{ Ok = $false; Reason = ('{0} is not an address range (e.g. 10.212.24.0/24)' -f $AddressPrefix); Apps = ''; Endpoints = '' } }
    if ($r.Bits -gt 25) { return @{ Ok = $false; Reason = ('{0} is too small: SecurityInsight''s network needs at least a /25 (two /26 subnets)' -f $AddressPrefix); Apps = ''; Endpoints = '' } }
    @{ Ok = $true; Reason = ''; Apps = (ConvertFrom-SICidrStart -Start $r.Start -Bits 26); Endpoints = (ConvertFrom-SICidrStart -Start ($r.Start + 64) -Bits 26) }
}

function Get-SIVnetPrefixes { param($Vnet) @(Get-SIPnProp $Vnet @('properties', 'addressSpace', 'addressPrefixes') | Where-Object { $_ } | ForEach-Object { [string]$_ }) }

function Set-SIVnet {
    <# #866: SecurityInsight's own spoke network -VnetId (in its own resource group), made from -AddressPrefix when it is
       not there, READ BACK. A network that is there is NEVER changed (its address space untouched; a different range given
       is said). Returns @{ Ok; Created; Line; Vnet }. #>
    param([Parameter(Mandatory)][scriptblock]$Arm, [Parameter(Mandatory)][string]$VnetId, [Parameter(Mandatory)][string]$Location,
          [Parameter(Mandatory)][string]$AddressPrefix, [scriptblock]$Sleep = { param($s) Start-Sleep -Seconds $s })
    $path = '{0}?api-version={1}' -f $VnetId.TrimEnd('/'), $script:SIPnNetApi
    $name = ($VnetId.TrimEnd('/') -split '/')[-1]
    $have = & $Arm 'GET' $path $null
    if ($have) {
        $sp = @(Get-SIVnetPrefixes $have)
        $note = if ($sp -notcontains $AddressPrefix.Trim()) { (' -- it keeps its own address space {0}; the range given, {1}, is not used' -f ($sp -join ', '), $AddressPrefix) } else { '' }
        return @{ Ok = $true; Created = $false; Vnet = $have; Line = ('the virtual network {0} ({1}) is there{2}' -f $name, ($sp -join ', '), $note) }
    }
    if (-not (ConvertTo-SICidrRange $AddressPrefix)) { throw ('Private network: {0} is not an address range. Nothing was changed.' -f $AddressPrefix) }
    $null = & $Arm 'PUT' $path ([ordered]@{ location = $Location; tags = [ordered]@{ purpose = 'securityinsight-private-network' }; properties = [ordered]@{ addressSpace = [ordered]@{ addressPrefixes = @($AddressPrefix.Trim()) } } })
    $back = Read-SIPnBack -Arm $Arm -Path $path -Sleep $Sleep -Test { param($o) Test-SIPnSucceeded $o }
    $ok = Test-SIPnSucceeded $back
    @{ Ok = [bool]$ok; Created = $true; Vnet = $back; Line = $(if ($ok) { 'the virtual network {0} ({1}) made in SecurityInsight''s resource group (read back)' -f $name, $AddressPrefix } else { 'the virtual network {0} does not read back as ready' -f $name }) }
}

# ============================================================================================================== SUBNETS

function Get-SISubnetDecision {
    <#
        PURE. What to do with one subnet of the customer's virtual network. -Subnet: the subnet as ARM returns it ($null =
        not there). -Prefix: the address range for a subnet that is not there yet. -Delegate: the subnet of the Container
        Apps environment (delegated to Microsoft.App/environments, at least a /27).
        @{ Action = 'none' | 'create' | 'delegate' | 'fail'; Reason }.
    #>
    param($Subnet, [AllowEmptyString()][AllowNull()][string]$Prefix, [Parameter(Mandatory)][string]$Name, [switch]$Delegate,
          # #866: the virtual network as ARM returns it -- a new subnet must lie in its address space and overlap none of its
          # other subnets (refused with the reason; the network is never changed)
          $Vnet = $null)
    $p = "$Prefix".Trim()
    if (-not $Subnet) {
        if (-not $p) { return @{ Action = 'fail'; Reason = ('the subnet {0} is not in the virtual network, and no address range was given for it -- give one (for example 10.20.0.0/27), or create the subnet first' -f $Name) } }
        if ($Delegate -and (Get-SIPnPrefixLength $p) -gt 27) { return @{ Action = 'fail'; Reason = ('the Container Apps environment needs at least a /27 subnet; {0} is too small for {1}' -f $p, $Name) } }
        if ($Vnet) {
            $space = @(Get-SIVnetPrefixes $Vnet)
            if ($space.Count -and -not @($space | Where-Object { Test-SICidrInside $p $_ }).Count) { return @{ Action = 'fail'; Reason = ('{0} for {1} is not inside the virtual network''s address space ({2}) -- the network is never changed; give a range inside it' -f $p, $Name, ($space -join ', ')) } }
            foreach ($s in @(Get-SIPnProp $Vnet @('properties', 'subnets') | Where-Object { $_ })) {
                if ([string](Get-SIPnProp $s @('name')) -eq $Name) { continue }
                $sp = @(@([string](Get-SIPnProp $s @('properties', 'addressPrefix'))) + @(Get-SIPnProp $s @('properties', 'addressPrefixes')) | Where-Object { $_ })
                foreach ($x in $sp) { if (Test-SICidrOverlap $p $x) { return @{ Action = 'fail'; Reason = ('{0} for {1} overlaps the subnet {2} ({3}) of the virtual network -- give a free range' -f $p, $Name, [string](Get-SIPnProp $s @('name')), $x) } } }
            }
        }
        return @{ Action = 'create'; Reason = ('the subnet {0} ({1}) is created{2}' -f $Name, $p, $(if ($Delegate) { ', delegated to Container Apps' } else { ' for the private endpoints and the build agent pool, with default outbound access (outbound only)' })) }
    }
    $have = "$(Get-SIPnProp $Subnet @('properties', 'addressPrefix'))".Trim()
    if (-not $have) { $have = (@(Get-SIPnProp $Subnet @('properties', 'addressPrefixes')) | Where-Object { $_ } | Select-Object -First 1) }
    $note = if ($p -and $have -and $p -ne $have) { (' (it keeps its own range {0}; the range given, {1}, is not used)' -f $have, $p) } else { '' }
    if (-not $Delegate) { return @{ Action = 'none'; Reason = ('the subnet {0} ({1}) is there{2}' -f $Name, $have, $note) } }
    if ((Get-SIPnPrefixLength $have) -gt 27) { return @{ Action = 'fail'; Reason = ('the subnet {0} ({1}) is too small: the Container Apps environment needs at least a /27' -f $Name, $have) } }
    $dels = @(Get-SIPnProp $Subnet @('properties', 'delegations') | Where-Object { $_ } | ForEach-Object { [string](Get-SIPnProp $_ @('properties', 'serviceName')) })
    if ($dels -contains $script:SIPnAppsDelegation) { return @{ Action = 'none'; Reason = ('the subnet {0} ({1}) is delegated to Container Apps{2}' -f $Name, $have, $note) } }
    if ($dels.Count) { return @{ Action = 'fail'; Reason = ('the subnet {0} is delegated to {1}: a subnet takes one delegation -- give another subnet for the Container Apps environment' -f $Name, ($dels -join ', ')) } }
    $used = @(Get-SIPnProp $Subnet @('properties', 'ipConfigurations') | Where-Object { $_ }).Count + @(Get-SIPnProp $Subnet @('properties', 'privateEndpoints') | Where-Object { $_ }).Count
    if ($used) { return @{ Action = 'fail'; Reason = ('the subnet {0} is in use ({1} address(es)): only an empty subnet can be delegated to Container Apps -- give an empty one' -f $Name, $used) } }
    @{ Action = 'delegate'; Reason = ('the subnet {0} ({1}) is delegated to Container Apps{2}' -f $Name, $have, $note) }
}

function Get-SISubnetBody {
    <# PURE. The PUT body of a subnet. A subnet PUT REPLACES the subnet, so an existing one keeps everything it has (its
       network security group, route table, NAT gateway, service endpoints, policies) and only gains the delegation. #>
    param($Subnet, [AllowEmptyString()][AllowNull()][string]$Prefix, [switch]$Delegate)
    $props = [ordered]@{}
    if ($Subnet) {
        foreach ($k in 'addressPrefix', 'addressPrefixes', 'networkSecurityGroup', 'routeTable', 'natGateway', 'serviceEndpoints', 'serviceEndpointPolicies',
                       'delegations', 'privateEndpointNetworkPolicies', 'privateLinkServiceNetworkPolicies', 'defaultOutboundAccess') {
            $v = Get-SIPnProp $Subnet @('properties', $k)
            if ($null -ne $v) { $props[$k] = ConvertTo-SIPnHashtable $v }
        }
    } else {
        $props['addressPrefix'] = "$Prefix".Trim()
        if (-not $Delegate) {
            $props['privateEndpointNetworkPolicies'] = 'Disabled'
            # #1087: the endpoints subnet is also where the registry's build agent pool runs (PIM's design: the pool in the
            # PE subnet). Azure makes NEW subnets private (defaultOutboundAccess false) since late 2025 -- without NAT or a
            # route the pool's machines have no way out and Azure's own pool deployment fails. Outbound only: nothing here
            # becomes reachable from outside; the endpoints, vault, storage, SQL and registry stay private.
            $props['defaultOutboundAccess'] = $true
        }
    }
    if ($Delegate) {
        $d = @(@($props['delegations']) | Where-Object { $_ })
        $props['delegations'] = @($d + @([ordered]@{ name = 'Microsoft.App.environments'; properties = [ordered]@{ serviceName = $script:SIPnAppsDelegation } }))
    }
    [ordered]@{ properties = $props }
}

function Set-SISubnet {
    <# One subnet as Get-SISubnetDecision says, READ BACK. Returns @{ Ok; Action; Line; Id; Before } -- Before: $null for a
       subnet this created (a rollback removes it), else the subnet as it was. Throws when the decision is 'fail'. #>
    param([Parameter(Mandatory)][scriptblock]$Arm, [Parameter(Mandatory)][string]$VnetId, [Parameter(Mandatory)][string]$Name,
          [AllowEmptyString()][string]$Prefix = '', [switch]$Delegate, $Vnet = $null, [scriptblock]$Sleep = { param($s) Start-Sleep -Seconds $s })
    $id = '{0}/subnets/{1}' -f $VnetId.TrimEnd('/'), $Name
    $path = '{0}?api-version={1}' -f $id, $script:SIPnNetApi
    $have = & $Arm 'GET' $path $null
    $d = Get-SISubnetDecision -Subnet $have -Prefix $Prefix -Name $Name -Delegate:$Delegate -Vnet $Vnet
    if ($d.Action -eq 'fail') { throw ('Private network: {0}. Nothing was changed.' -f $d.Reason) }
    if ($d.Action -eq 'none') { return @{ Ok = $true; Action = 'none'; Line = $d.Reason; Id = [string](Get-SIPnProp $have @('id')); Before = $have } }
    $body = Get-SISubnetBody -Subnet $have -Prefix $Prefix -Delegate:$Delegate
    # #1087 / framework rule 11b: a subnet created with defaultOutboundAccess = true must READ BACK true
    $wantOut = [bool](Test-SISubnetOutboundSet $body)
    $null = & $Arm 'PUT' $path $body
    $back = Read-SIPnBack -Arm $Arm -Path $path -Sleep $Sleep -Test { param($o) (Test-SIPnSucceeded $o) -and (-not $wantOut -or (Test-SISubnetOutboundSet $o)) -and (-not $Delegate -or (@(Get-SIPnProp $o @('properties', 'delegations') | ForEach-Object { [string](Get-SIPnProp $_ @('properties', 'serviceName')) }) -contains $script:SIPnAppsDelegation)) }
    if ($wantOut -and (Test-SIPnSucceeded $back) -and -not (Test-SISubnetOutboundSet $back)) {
        throw ('Private network: the subnet {0} was created with default outbound access, but it does not read back true (Azure shows: {1}). The registry''s build agent pool needs it. Run the install again: it checks the subnet again before the pool is made.' -f $Name, $(if ($null -eq (Get-SIPnProp $back @('properties', 'defaultOutboundAccess'))) { 'not set' } else { [string](Get-SIPnProp $back @('properties', 'defaultOutboundAccess')) }))
    }
    $ok = [bool](Test-SIPnSucceeded $back)
    @{ Ok = $ok; Action = $d.Action; Id = $(if ($back) { [string](Get-SIPnProp $back @('id')) } else { $id }); Before = $have
       Line = $(if ($ok) { $d.Reason + ' (read back)' } else { ('the subnet {0} does not read back as ready after the change (Azure shows: {1})' -f $Name, [string](Get-SIPnProp $back @('properties', 'provisioningState'))) }) }
}

# ============================================================================================================== PRIVATE ENDPOINTS

function Get-SIPrivateEndpointTargets {
    <# PURE. The private endpoints an install gets: one per kind of each resource that is there (the database server only
       for Pro). @( @{ Kind; Name; GroupId; Zone; ResourceId; Label } ). #>
    param([string]$SqlServerId = '', [string]$KeyVaultId = '', [string]$StorageAccountId = '', [string]$RegistryId = '')
    $prefix = (Get-SIPrivateNetworkNames).EndpointPrefix
    $map = [ordered]@{ sql = $SqlServerId; vault = $KeyVaultId; blob = $StorageAccountId; queue = $StorageAccountId; table = $StorageAccountId; registry = $RegistryId }
    foreach ($k in $map.Keys) {
        $rid = "$($map[$k])".Trim()
        if (-not $rid) { continue }
        $kind = $script:SIPnKinds[$k]
        [pscustomobject]@{ Kind = $k; Name = ($prefix + $k); GroupId = $kind.GroupId; Zone = $kind.Zone; ResourceId = $rid; Label = $kind.Label }
    }
}

function Get-SIPrivateEndpointBody {
    <# PURE. The PUT body of one private endpoint (auto-approved: the install's own resource). #>
    param([Parameter(Mandatory)][string]$Location, [Parameter(Mandatory)][string]$SubnetId, [Parameter(Mandatory)]$Target)
    [ordered]@{ location = $Location; properties = [ordered]@{
        subnet = [ordered]@{ id = $SubnetId }
        privateLinkServiceConnections = @([ordered]@{ name = [string]$Target.Name; properties = [ordered]@{ privateLinkServiceId = [string]$Target.ResourceId; groupIds = @([string]$Target.GroupId) } }) } }
}

function Test-SIPrivateEndpointMatch {
    <# PURE. Is -Endpoint (as ARM returns it) the endpoint -Target asks for, in -SubnetId? #>
    param($Endpoint, [Parameter(Mandatory)]$Target, [Parameter(Mandatory)][string]$SubnetId)
    if (-not $Endpoint) { return $false }
    if (-not (Test-SIPnSameId ([string](Get-SIPnProp $Endpoint @('properties', 'subnet', 'id'))) $SubnetId)) { return $false }
    foreach ($c in @(@(Get-SIPnProp $Endpoint @('properties', 'privateLinkServiceConnections')) + @(Get-SIPnProp $Endpoint @('properties', 'manualPrivateLinkServiceConnections')) | Where-Object { $_ })) {
        if ((Test-SIPnSameId ([string](Get-SIPnProp $c @('properties', 'privateLinkServiceId'))) ([string]$Target.ResourceId)) -and
            @(Get-SIPnProp $c @('properties', 'groupIds')) -contains [string]$Target.GroupId) { return $true }
    }
    $false
}

function Get-SIPrivateEndpointState {
    <# PURE. 'Approved' when the endpoint's connection to its resource is approved, else what Azure says. #>
    param($Endpoint)
    $c = @(@(Get-SIPnProp $Endpoint @('properties', 'privateLinkServiceConnections')) | Where-Object { $_ })[0]
    [string](Get-SIPnProp $c @('properties', 'privateLinkServiceConnectionState', 'status'))
}

function Set-SIPrivateEndpoint {
    <# One private endpoint in -ResourceGroupId, idempotent, READ BACK until it is provisioned and its connection approved.
       An endpoint of that name that points elsewhere is NEVER replaced (it is said; nothing is changed).
       Returns @{ Ok; Action = 'none' | 'create'; Line; Id; Created }. #>
    param([Parameter(Mandatory)][scriptblock]$Arm, [Parameter(Mandatory)][string]$ResourceGroupId, [Parameter(Mandatory)][string]$Location,
          [Parameter(Mandatory)][string]$SubnetId, [Parameter(Mandatory)]$Target, [scriptblock]$Sleep = { param($s) Start-Sleep -Seconds $s })
    $id = '{0}/providers/Microsoft.Network/privateEndpoints/{1}' -f $ResourceGroupId.TrimEnd('/'), $Target.Name
    $path = '{0}?api-version={1}' -f $id, $script:SIPnNetApi
    $have = & $Arm 'GET' $path $null
    if ($have) {
        if (-not (Test-SIPrivateEndpointMatch -Endpoint $have -Target $Target -SubnetId $SubnetId)) {
            return @{ Ok = $false; Action = 'none'; Id = $id; Created = $false; Line = ('the private endpoint {0} exists but connects to something else or sits in another subnet -- it is not changed; remove or rename it, then run again' -f $Target.Name) }
        }
        if ((Test-SIPnSucceeded $have) -and (Get-SIPrivateEndpointState $have) -eq 'Approved') {
            return @{ Ok = $true; Action = 'none'; Id = $id; Created = $false; Line = ('private endpoint {0} for the {1} is there' -f $Target.Name, $Target.Label) }
        }
    }
    if (-not $have) { $null = & $Arm 'PUT' $path (Get-SIPrivateEndpointBody -Location $Location -SubnetId $SubnetId -Target $Target) }
    $back = Read-SIPnBack -Arm $Arm -Path $path -Sleep $Sleep -Test { param($o) (Test-SIPnSucceeded $o) -and (Get-SIPrivateEndpointState $o) -eq 'Approved' }
    $ok = (Test-SIPnSucceeded $back) -and (Get-SIPrivateEndpointState $back) -eq 'Approved'
    @{ Ok = [bool]$ok; Action = 'create'; Id = $id; Created = (-not $have)
       Line = $(if ($ok) { 'private endpoint {0} for the {1} (read back, approved)' -f $Target.Name, $Target.Label } else { 'private endpoint {0} for the {1} does not read back as ready (Azure shows: {2}, connection {3})' -f $Target.Name, $Target.Label, [string](Get-SIPnProp $back @('properties', 'provisioningState')), (Get-SIPrivateEndpointState $back) }) }
}

# ============================================================================================================== PRIVATE DNS

function Set-SIPrivateDnsZone {
    <# One private DNS zone in -ResourceGroupId (global), idempotent, READ BACK. Returns @{ Ok; Line; Id; Created }. #>
    param([Parameter(Mandatory)][scriptblock]$Arm, [Parameter(Mandatory)][string]$ResourceGroupId, [Parameter(Mandatory)][string]$Zone, [scriptblock]$Sleep = { param($s) Start-Sleep -Seconds $s })
    $id = '{0}/providers/Microsoft.Network/privateDnsZones/{1}' -f $ResourceGroupId.TrimEnd('/'), $Zone
    $path = '{0}?api-version={1}' -f $id, $script:SIPnDnsApi
    $have = & $Arm 'GET' $path $null
    if ($have) { return @{ Ok = $true; Line = ('private DNS zone {0} is there' -f $Zone); Id = $id; Created = $false } }
    $null = & $Arm 'PUT' $path ([ordered]@{ location = 'global' })
    $back = Read-SIPnBack -Arm $Arm -Path $path -Sleep $Sleep -Test { param($o) Test-SIPnSucceeded $o }
    $ok = Test-SIPnSucceeded $back
    @{ Ok = [bool]$ok; Id = $id; Created = $true; Line = $(if ($ok) { 'private DNS zone {0} (read back)' -f $Zone } else { 'private DNS zone {0} does not read back as ready' -f $Zone }) }
}

function Find-SIVnetLinkedZone {
    <# READ ONLY. A private DNS zone named -Zone that -VnetId is ALREADY linked to (any resource group of -SubscriptionIds):
       its id, '' = none. Azure refuses a second zone of the same name on one network ("A virtual network cannot be linked
       to multiple zones with overlapping namespaces"), so such a zone is USED, never doubled. Azure Resource Graph first;
       when it gives no answer, the zones of that name in each subscription and their links. #>
    param([Parameter(Mandatory)][scriptblock]$Arm, [Parameter(Mandatory)][string]$VnetId, [Parameter(Mandatory)][string]$Zone, [string[]]$SubscriptionIds = @())
    $z = $Zone.ToLowerInvariant(); $subs = @($SubscriptionIds | Where-Object { $_ } | ForEach-Object { $_.ToLowerInvariant() } | Select-Object -Unique)
    $zoneOf = { param($linkId) $m = [regex]::Match([string]$linkId, '(?i)^(.*/providers/Microsoft\.Network/privateDnsZones/([^/]+))/virtualNetworkLinks/'); if ($m.Success -and $m.Groups[2].Value.ToLowerInvariant() -eq $z) { $m.Groups[1].Value } else { '' } }
    $ans = $null
    try {
        $q = "resources | where type =~ 'microsoft.network/privatednszones/virtualnetworklinks' | where tolower(tostring(properties.virtualNetwork.id)) == '{0}' | project id, vnet = tostring(properties.virtualNetwork.id)" -f $VnetId.TrimEnd('/').ToLowerInvariant()
        $ans = & $Arm 'POST' '/providers/Microsoft.ResourceGraph/resources?api-version=2022-10-01' ([ordered]@{ subscriptions = $subs; query = $q })
    } catch { $ans = $null }
    if ($ans -and $null -ne (Get-SIPnProp $ans @('data'))) {
        foreach ($row in @(Get-SIPnProp $ans @('data') | Where-Object { $_ })) {
            if (-not (Test-SIPnSameId ([string](Get-SIPnProp $row @('vnet'))) $VnetId)) { continue }
            $zid = & $zoneOf ([string](Get-SIPnProp $row @('id'))); if ($zid) { return $zid }
        }
        return ''
    }
    foreach ($s in $subs) {
        foreach ($zo in @(Get-SIPnArmList -Arm $Arm -Path ('/subscriptions/{0}/providers/Microsoft.Network/privateDnsZones?api-version={1}' -f $s, $script:SIPnDnsApi) | Where-Object { ([string](Get-SIPnProp $_ @('name'))).ToLowerInvariant() -eq $z })) {
            $zid = [string](Get-SIPnProp $zo @('id'))
            if (@(Get-SIPnArmList -Arm $Arm -Path ('{0}/virtualNetworkLinks?api-version={1}' -f $zid, $script:SIPnDnsApi) | Where-Object { Test-SIPnSameId ([string](Get-SIPnProp $_ @('properties', 'virtualNetwork', 'id'))) $VnetId }).Count) { return $zid }
        }
    }
    ''
}

function Resolve-SIPrivateDnsZone {
    <#
        #866 item 6 -- WHICH zone of -Zone an install uses, never two of a name on one network:
          * a central resource group is given (-CentralResourceGroupId, the customer's): its zone is USED; one that is not
            there is a HAND-OFF line -- SecurityInsight NEVER makes a zone in the customer's resource group (PIM's rule);
          * else SecurityInsight's own resource group: its zone when there; else a zone of that name the network is ALREADY
            linked to elsewhere is used (Azure refuses a second); else it is made there, read back.
        Returns @{ Ok; ZoneId; Created; Elsewhere; HandOff; Line }.
    #>
    param([Parameter(Mandatory)][scriptblock]$Arm, [Parameter(Mandatory)][string]$Zone, [Parameter(Mandatory)][string]$ResourceGroupId,
          [string]$CentralResourceGroupId = '', [string]$VnetId = '', [string[]]$SubscriptionIds = @(), [scriptblock]$Sleep = { param($s) Start-Sleep -Seconds $s })
    $central = "$CentralResourceGroupId".Trim().TrimEnd('/')
    if ($central -and -not (Test-SIPnSameId $central $ResourceGroupId)) {
        $zid = '{0}/providers/Microsoft.Network/privateDnsZones/{1}' -f $central, $Zone
        if (& $Arm 'GET' ('{0}?api-version={1}' -f $zid, $script:SIPnDnsApi) $null) { return @{ Ok = $true; ZoneId = $zid; Created = $false; Elsewhere = $true; HandOff = $false; Line = ('private DNS zone {0} in your central resource group {1} is used' -f $Zone, ($central -split '/')[-1]) } }
        return @{ Ok = $false; ZoneId = ''; Created = $false; Elsewhere = $true; HandOff = $true
                  Line = ('the zone {0} is NOT in your central resource group {1} -- SecurityInsight never makes a zone there: your network team creates it (or leave the central resource group empty and SecurityInsight uses its own)' -f $Zone, ($central -split '/')[-1]) }
    }
    $own = '{0}/providers/Microsoft.Network/privateDnsZones/{1}' -f $ResourceGroupId.TrimEnd('/'), $Zone
    if (& $Arm 'GET' ('{0}?api-version={1}' -f $own, $script:SIPnDnsApi) $null) { return @{ Ok = $true; ZoneId = $own; Created = $false; Elsewhere = $false; HandOff = $false; Line = ('private DNS zone {0} is there' -f $Zone) } }
    if ($VnetId) {
        $found = Find-SIVnetLinkedZone -Arm $Arm -VnetId $VnetId -Zone $Zone -SubscriptionIds $SubscriptionIds
        if ($found -and -not (Test-SIPnSameId $found $own)) {
            return @{ Ok = $true; ZoneId = $found; Created = $false; Elsewhere = $true; HandOff = $false
                      Line = ('the network is already linked to a zone {0} ({1}) -- it is used: Azure refuses a second zone of that name on one network' -f $Zone, ((ConvertFrom-SIPnResourceId $found).ResourceGroup)) }
        }
    }
    $z = Set-SIPrivateDnsZone -Arm $Arm -ResourceGroupId $ResourceGroupId -Zone $Zone -Sleep $Sleep
    @{ Ok = [bool]$z.Ok; ZoneId = $z.Id; Created = [bool]$z.Created; Elsewhere = $false; HandOff = $false; Line = $z.Line }
}

function Get-SIZoneSearchSubscriptions {
    <# PURE. The subscriptions a same-name zone is looked for in: the install's, the network's, the central zones'. #>
    param([string[]]$Ids = @())
    @($Ids | Where-Object { $_ } | ForEach-Object { $p = ConvertFrom-SIPnResourceId $_; if ($p) { $p.SubscriptionId.ToLowerInvariant() } } | Select-Object -Unique)
}

function Get-SIPrivateDnsLinkName {
    <# PURE. The name of a zone's link to a virtual network: the network's name (one link per network per zone). #>
    param([Parameter(Mandatory)][string]$VnetId)
    $n = (($VnetId.TrimEnd('/') -split '/')[-1]).ToLowerInvariant() -replace '[^a-z0-9_.-]', '-'
    if ($n.Length -gt 80) { $n = $n.Substring(0, 80) }
    $n
}

function Get-SIPrivateDnsLinkPlan {
    <# PURE (#866 item 7, PIM's Get-PimZoneLinkPlan). Should -VnetId be linked to the zone, given its existing -Links (ARM
       objects)? A network linked under ANY name is left alone ('skip'). Otherwise 'create' under the network's name -- or,
       when a link of THAT name points at ANOTHER network (two networks of one name in different groups / subscriptions),
       under <name>-<hash>: a PUT under the taken name would REPOINT the other network's link and cut its resolution.
       @{ Action = 'skip' | 'create'; Name }. #>
    param([Parameter(Mandatory)][string]$VnetId, [object[]]$Links = @())
    foreach ($l in @($Links | Where-Object { $_ })) {
        if (Test-SIPnSameId ([string](Get-SIPnProp $l @('properties', 'virtualNetwork', 'id'))) $VnetId) { return @{ Action = 'skip'; Name = [string](Get-SIPnProp $l @('name')) } }
    }
    $name = Get-SIPrivateDnsLinkName -VnetId $VnetId
    if (@($Links | Where-Object { $_ -and ([string](Get-SIPnProp $_ @('name'))) -ieq $name }).Count) {
        $sha = [Security.Cryptography.SHA256]::Create()
        try { $hx = -join (@($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($VnetId.TrimEnd('/').ToLowerInvariant()))[0..3]) | ForEach-Object { $_.ToString('x2') }) } finally { $sha.Dispose() }
        $base = if ($name.Length -gt 71) { $name.Substring(0, 71) } else { $name }
        $name = '{0}-{1}' -f $base, $hx
    }
    @{ Action = 'create'; Name = $name }
}

function Set-SIPrivateDnsLink {
    <# The zone's link to the virtual network, idempotent (any link of the zone to that network counts -- matched by the
       NETWORK, never by the link's name), READ BACK. -HandOffOnError (the customer's hub network, #866): a link SecurityInsight
       may not write is NOT a failure -- it is returned as a hand-off line (HandOff = $true) for the customer's network team.
       Returns @{ Ok; Line; Id; Created; HandOff }. #>
    param([Parameter(Mandatory)][scriptblock]$Arm, [Parameter(Mandatory)][string]$ZoneId, [Parameter(Mandatory)][string]$VnetId, [switch]$HandOffOnError,
          [scriptblock]$Sleep = { param($s) Start-Sleep -Seconds $s })
    $zone = ($ZoneId.TrimEnd('/') -split '/')[-1]
    $vn = ($VnetId.TrimEnd('/') -split '/')[-1]
    $links = @(Get-SIPnArmList -Arm $Arm -Path ('{0}/virtualNetworkLinks?api-version={1}' -f $ZoneId.TrimEnd('/'), $script:SIPnDnsApi))
    $same = @($links | Where-Object { Test-SIPnSameId ([string](Get-SIPnProp $_ @('properties', 'virtualNetwork', 'id'))) $VnetId })[0]
    if ($same) { return @{ Ok = $true; Created = $false; HandOff = $false; Id = [string](Get-SIPnProp $same @('id')); Line = ('{0} is linked to {1}' -f $zone, $vn) } }
    # #866 item 7: a link of the network's name that points at ANOTHER network is never repointed -- a hash suffix instead
    $id = '{0}/virtualNetworkLinks/{1}' -f $ZoneId.TrimEnd('/'), (Get-SIPrivateDnsLinkPlan -VnetId $VnetId -Links $links).Name
    $path = '{0}?api-version={1}' -f $id, $script:SIPnDnsApi
    try { $null = & $Arm 'PUT' $path ([ordered]@{ location = 'global'; properties = [ordered]@{ virtualNetwork = [ordered]@{ id = $VnetId }; registrationEnabled = $false } }) }
    catch {
        if (-not $HandOffOnError) { throw }
        return @{ Ok = $false; Created = $false; HandOff = $true; Id = ''
                  Line = ('{0} is NOT linked to {1}: SecurityInsight may not do it ({2}) -- the customer''s network team links it (or gives the rights), see the network hand-off' -f $zone, $vn, $_.Exception.Message) }
    }
    $back = Read-SIPnBack -Arm $Arm -Path $path -Sleep $Sleep -Test { param($o) Test-SIPnSucceeded $o }
    $ok = Test-SIPnSucceeded $back
    @{ Ok = [bool]$ok; Created = $true; HandOff = $false; Id = $id; Line = $(if ($ok) { '{0} linked to {1} (read back)' -f $zone, $vn } else { 'the link of {0} to {1} does not read back as ready' -f $zone, $vn }) }
}

function Test-SIActionAllowed {
    <# PURE. Do -Permissions (ARM's permissions answer: @{ actions; notActions }, each a list with * wildcards) allow
       -Action? Allowed by one entry's actions and not taken away by that entry's notActions. #>
    param([object[]]$Permissions = @(), [Parameter(Mandatory)][string]$Action)
    foreach ($p in @($Permissions | Where-Object { $_ })) {
        $in = @(@(Get-SIPnProp $p @('actions')) | Where-Object { $_ -and $Action -like [string]$_ }).Count
        $out = @(@(Get-SIPnProp $p @('notActions')) | Where-Object { $_ -and $Action -like [string]$_ }).Count
        if ($in -and -not $out) { return $true }
    }
    $false
}

function Get-SIHubRightsProblem {
    <# READ ONLY. Why the signed-in identity may NOT do -Actions on -Scope ('' = it may): ARM's own permissions answer for
       that scope. The text names the role and the scope to grant. Nothing is written. #>
    param([Parameter(Mandatory)][scriptblock]$Arm, [Parameter(Mandatory)][string]$Scope, [Parameter(Mandatory)][string[]]$Actions, [string]$Role = 'Network Contributor')
    $perm = $null
    try { $perm = & $Arm 'GET' ('{0}/providers/Microsoft.Authorization/permissions?api-version={1}' -f $Scope.TrimEnd('/'), $script:SIPnAuthApi) $null }
    catch { return ('the rights on {0} could not be read ({1}) -- grant {2} on it' -f $Scope, $_.Exception.Message, $Role) }
    $list = @(Get-SIPnProp $perm @('value') | Where-Object { $_ })
    $missing = @($Actions | Where-Object { -not (Test-SIActionAllowed -Permissions $list -Action $_) })
    if (-not $missing.Count) { return '' }
    ('the installing identity may not {0} on {1} -- grant it {2} on that scope (or let your network team do it)' -f ($missing -join ', '), $Scope, $Role)
}

function Get-SIHubLinkDecision {
    <# READ ONLY. Is the environment's zone linked to the hub? Only when the customer turned it on (LinkZonesToHub) AND
       the identity may join the hub network (checked BEFORE any change). @{ HubVnetId ('' = not linked); Line }. #>
    param([Parameter(Mandatory)][scriptblock]$Arm, [Parameter(Mandatory)][System.Collections.IDictionary]$Target)
    $hub = [string]$Target['HubVnetId']
    if (-not $hub) { return @{ HubVnetId = ''; Line = '' } }
    if (-not [bool]$Target['LinkZonesToHub']) { return @{ HubVnetId = ''; Line = '' } }
    $why = Get-SIHubRightsProblem -Arm $Arm -Scope $hub -Actions @('Microsoft.Network/virtualNetworks/join/action')
    if ($why) { return @{ HubVnetId = ''; Line = ('linkZonesToHub REFUSED before any change: {0}' -f $why) } }
    @{ HubVnetId = $hub; Line = '' }
}

function Get-SIDnsLinkVnetIds {
    <# PURE. The networks the environment's own zone is linked to: SecurityInsight's network (the spoke) and -- when given
       -- the customer's hub, so clients resolving through the hub (its private DNS resolver, other spokes, on-premises)
       find the web app. Each once (the same network given twice, in any case, is linked once). #>
    param([AllowEmptyString()][AllowNull()][string]$VnetId, [AllowEmptyString()][AllowNull()][string]$HubVnetId)
    $out = New-Object System.Collections.Generic.List[string]
    foreach ($v in @($VnetId, $HubVnetId)) {
        $t = "$v".Trim().TrimEnd('/')
        if (-not $t) { continue }
        if (@($out | Where-Object { Test-SIPnSameId $_ $t }).Count) { continue }
        $out.Add($t)
    }
    $out.ToArray()
}

function Get-SIPrivateDnsZoneGroupBody {
    <# PURE. The endpoint's DNS zone group: Azure keeps the zone's A record(s) for the endpoint itself. #>
    param([Parameter(Mandatory)][string]$ZoneId)
    $zone = ($ZoneId.TrimEnd('/') -split '/')[-1]
    [ordered]@{ properties = [ordered]@{ privateDnsZoneConfigs = @([ordered]@{ name = ($zone -replace '\.', '-'); properties = [ordered]@{ privateDnsZoneId = $ZoneId } }) } }
}

function Set-SIPrivateDnsZoneGroup {
    <# The endpoint's zone group pointing at -ZoneId, idempotent, READ BACK. Returns @{ Ok; Line; Created }. #>
    param([Parameter(Mandatory)][scriptblock]$Arm, [Parameter(Mandatory)][string]$EndpointId, [Parameter(Mandatory)][string]$ZoneId, [scriptblock]$Sleep = { param($s) Start-Sleep -Seconds $s })
    $path = '{0}/privateDnsZoneGroups/{1}?api-version={2}' -f $EndpointId.TrimEnd('/'), (Get-SIPrivateNetworkNames).ZoneGroup, $script:SIPnNetApi
    $pe = ($EndpointId.TrimEnd('/') -split '/')[-1]
    $has = { param($o) @(Get-SIPnProp $o @('properties', 'privateDnsZoneConfigs') | Where-Object { $_ } | Where-Object { Test-SIPnSameId ([string](Get-SIPnProp $_ @('properties', 'privateDnsZoneId'))) $ZoneId }).Count -gt 0 }
    $have = & $Arm 'GET' $path $null
    if ($have -and (& $has $have)) { return @{ Ok = $true; Created = $false; Line = ('{0} keeps its address in its private DNS zone' -f $pe) } }
    $null = & $Arm 'PUT' $path (Get-SIPrivateDnsZoneGroupBody -ZoneId $ZoneId)
    $back = Read-SIPnBack -Arm $Arm -Path $path -Sleep $Sleep -Test { param($o) (Test-SIPnSucceeded $o) -and (& $has $o) }
    $ok = (Test-SIPnSucceeded $back) -and (& $has $back)
    @{ Ok = [bool]$ok; Created = (-not $have); Line = $(if ($ok) { '{0}: its address is in the private DNS zone (read back)' -f $pe } else { '{0}: its DNS zone group does not read back as ready' -f $pe }) }
}

# ============================================================================================================== PUBLIC ENDPOINTS

function Get-SIPublicAccessKind {
    <# PURE. The kind of a resource id for the public-endpoint rules: sql | vault | storage | registry ('' = not one). #>
    param([AllowNull()][string]$ResourceId)
    switch -Regex ("$ResourceId") {
        '(?i)/providers/Microsoft\.Sql/servers/' { return 'sql' }
        '(?i)/providers/Microsoft\.KeyVault/vaults/' { return 'vault' }
        '(?i)/providers/Microsoft\.Storage/storageAccounts/' { return 'storage' }
        '(?i)/providers/Microsoft\.ContainerRegistry/registries/' { return 'registry' }
    }
    ''
}

function Get-SIPublicAccessApi { param([string]$Kind) switch ($Kind) { 'sql' { $script:SIPnSqlApi } 'vault' { $script:SIPnKvApi } 'storage' { $script:SIPnStApi } 'registry' { $script:SIPnAcrApi } } }

function Test-SIPublicAccessClosed {
    <# PURE. Is the resource's public endpoint closed the way this option closes it? A Key Vault counts as closed when its
       firewall denies by default (trusted Microsoft services allowed) or its public access is off. #>
    param([Parameter(Mandatory)][string]$Kind, $Resource)
    if (-not $Resource) { return $false }
    # #866 (owner 2026-10-21: "we will not allow fw option or exceptions"): a Key Vault counts as closed only with its public
    # access DISABLED, like the others -- a firewall that denies by default is not the end state any more
    if ([string](Get-SIPnProp $Resource @('properties', 'publicNetworkAccess')) -ne 'Disabled') { return $false }
    # Framework installer rule 11: a vault ALSO needs trusted Microsoft services allowed (bypass AzureServices) -- under
    # bypass None (what a RECOVERED vault comes back with) ARM key / secret calls fail with ForbiddenByConnection. Such a
    # vault is not closed "the way this option closes it": Set-SIPublicAccess PATCHes it to the close body, which has it.
    if ($Kind -eq 'vault' -and [string](Get-SIPnProp $Resource @('properties', 'networkAcls', 'bypass')) -ne 'AzureServices') { return $false }
    $true
}

function Get-SIPublicAccessBefore {
    <# PURE. What a rollback puts back: the public-endpoint settings of the resource as they are now. #>
    param([Parameter(Mandatory)][string]$Kind, $Resource)
    $p = [ordered]@{ publicNetworkAccess = [string](Get-SIPnProp $Resource @('properties', 'publicNetworkAccess')) }
    if ($Kind -in 'vault', 'storage', 'registry') {
        $acl = Get-SIPnProp $Resource @('properties', $(if ($Kind -eq 'registry') { 'networkRuleSet' } else { 'networkAcls' }))
        if ($null -ne $acl) { $p[$(if ($Kind -eq 'registry') { 'networkRuleSet' } else { 'networkAcls' })] = ConvertTo-SIPnHashtable $acl }
    }
    if ($Kind -eq 'registry') { $b = Get-SIPnProp $Resource @('properties', 'networkRuleBypassOptions'); if ($b) { $p['networkRuleBypassOptions'] = [string]$b } }
    $p
}

function Get-SIPublicAccessCloseBody {
    <# PURE. The PATCH body that closes the public endpoint of a resource of -Kind.
         sql / storage   publicNetworkAccess Disabled (the private endpoint is the only way in)
         vault           publicNetworkAccess Disabled (#866, owner: no firewall option, no exceptions) and its firewall Deny,
                         trusted Microsoft services allowed, no IP or network rules
         registry        publicNetworkAccess Disabled, trusted Microsoft services allowed #>
    param([Parameter(Mandatory)][ValidateSet('sql', 'vault', 'storage', 'registry')][string]$Kind, $Resource)
    switch ($Kind) {
        'sql' { return [ordered]@{ properties = [ordered]@{ publicNetworkAccess = 'Disabled' } } }
        'storage' { return [ordered]@{ properties = [ordered]@{ publicNetworkAccess = 'Disabled' } } }
        'vault' { return [ordered]@{ properties = [ordered]@{ publicNetworkAccess = 'Disabled'; networkAcls = [ordered]@{ defaultAction = 'Deny'; bypass = 'AzureServices'; ipRules = @(); virtualNetworkRules = @() } } } }
        'registry' { return [ordered]@{ properties = [ordered]@{ publicNetworkAccess = 'Disabled'; networkRuleBypassOptions = 'AzureServices' } } }
    }
}

function Test-SIPublicAccessReopen {
    <# PURE. Would putting -Before back OPEN the public endpoint of a resource of -Kind? (publicNetworkAccess Enabled or not
       set -- Azure's default is Enabled -- or a firewall that allows by default.) The never-reopen guard asks this. #>
    param([Parameter(Mandatory)][string]$Kind, [AllowNull()][System.Collections.IDictionary]$Before)
    if ($null -eq $Before) { return $false }
    $pna = [string]$Before['publicNetworkAccess']
    $aclKey = if ($Kind -eq 'registry') { 'networkRuleSet' } else { 'networkAcls' }
    $acl = $Before[$aclKey]
    $def = if ($acl -is [System.Collections.IDictionary]) { [string]$acl['defaultAction'] } elseif ($acl) { [string](Get-SIPnProp $acl @('defaultAction')) } else { '' }
    ($pna -ne 'Disabled')
}

function Set-SIPublicAccess {
    <# Closes (or, with -Before, puts back) the public endpoint of -ResourceId, READ BACK. Returns @{ Ok; Line; Action }.
       NEVER-REOPEN GUARD (owner 2026-10-19: "when we say it is private, it stays that way"): a -Before that would open the
       endpoint again is REFUSED (nothing is sent) unless -AllowReopen is given -- and only the cut-over's rollback passes
       it, and only on the customer's own -ReopenPublicAccess. No support step, no setup re-run, no updater ever does. #>
    param([Parameter(Mandatory)][scriptblock]$Arm, [Parameter(Mandatory)][string]$ResourceId, [System.Collections.IDictionary]$Before, [switch]$AllowReopen,
          [scriptblock]$Sleep = { param($s) Start-Sleep -Seconds $s })
    $kind = Get-SIPublicAccessKind -ResourceId $ResourceId
    if (-not $kind) { throw ('Not a resource whose public endpoint this closes: {0}' -f $ResourceId) }
    $path = '{0}?api-version={1}' -f $ResourceId.TrimEnd('/'), (Get-SIPublicAccessApi $kind)
    $name = ($ResourceId.TrimEnd('/') -split '/')[-1]
    if ($Before -and -not $AllowReopen -and (Test-SIPublicAccessReopen -Kind $kind -Before $Before)) {
        return @{ Ok = $false; Action = 'refused'; Line = ('{0}: its public endpoint STAYS CLOSED -- putting it back would open it, and a private install stays private (only the customer''s own decision to leave private networking, -ReopenPublicAccess, opens it)' -f $name) }
    }
    $have = & $Arm 'GET' $path $null
    if (-not $have) { return @{ Ok = $false; Action = 'none'; Line = ('{0} was not found' -f $name) } }
    if ($Before) {
        $body = [ordered]@{ properties = [ordered]@{} }
        foreach ($k in $Before.Keys) { if ($null -ne $Before[$k] -and "$($Before[$k])" -ne '') { $body.properties[$k] = $Before[$k] } }
        $null = & $Arm 'PATCH' $path $body
        $want = [string]$Before['publicNetworkAccess']
        $back = Read-SIPnBack -Arm $Arm -Path $path -Sleep $Sleep -Tries 12 -Test { param($o) -not $want -or [string](Get-SIPnProp $o @('properties', 'publicNetworkAccess')) -eq $want }
        return @{ Ok = $true; Action = 'restore'; Line = ('{0}: its public endpoint is back as it was (read back: {1})' -f $name, [string](Get-SIPnProp $back @('properties', 'publicNetworkAccess'))) }
    }
    if (Test-SIPublicAccessClosed -Kind $kind -Resource $have) { return @{ Ok = $true; Action = 'none'; Line = ('{0}: its public endpoint is already closed' -f $name) } }
    $null = & $Arm 'PATCH' $path (Get-SIPublicAccessCloseBody -Kind $kind -Resource $have)
    $back = Read-SIPnBack -Arm $Arm -Path $path -Sleep $Sleep -Tries 12 -Test { param($o) Test-SIPublicAccessClosed -Kind $kind -Resource $o }
    $ok = Test-SIPublicAccessClosed -Kind $kind -Resource $back
    @{ Ok = [bool]$ok; Action = 'close'; Line = $(if ($ok) { '{0}: its public endpoint is closed{1} (read back)' -f $name, $(if ($kind -eq 'vault') { ' (public access disabled; its firewall denies, trusted Microsoft services allowed)' } else { '' }) } else { '{0}: its public endpoint still reads open after the change' -f $name }) }
}

# ============================================================================================================== REGISTRY SKU

function Get-SIRegistrySkuDecision {
    <# PURE. A registry takes a private endpoint only on the Premium tier. @{ Action = 'none' | 'upgrade'; Reason; Sku }. #>
    param($Registry)
    $sku = [string](Get-SIPnProp $Registry @('sku', 'name'))
    if (-not $Registry) { return @{ Action = 'none'; Reason = 'no container registry was found'; Sku = '' } }
    if ($sku -eq 'Premium') { return @{ Action = 'none'; Reason = 'the container registry is Premium (it takes a private endpoint)'; Sku = $sku } }
    @{ Action = 'upgrade'; Sku = $sku; Reason = ('the container registry is {0}: a private endpoint needs Premium -- it is changed to Premium (a higher daily price; nothing in it changes)' -f $(if ($sku) { $sku } else { 'not Premium' })) }
}

function Set-SIRegistrySku {
    <# The registry's tier, READ BACK. Returns @{ Ok; Line }. #>
    param([Parameter(Mandatory)][scriptblock]$Arm, [Parameter(Mandatory)][string]$RegistryId, [Parameter(Mandatory)][string]$Sku, [scriptblock]$Sleep = { param($s) Start-Sleep -Seconds $s })
    $path = '{0}?api-version={1}' -f $RegistryId.TrimEnd('/'), $script:SIPnAcrApi
    $null = & $Arm 'PATCH' $path ([ordered]@{ sku = [ordered]@{ name = $Sku } })
    $back = Read-SIPnBack -Arm $Arm -Path $path -Sleep $Sleep -Tries 12 -Test { param($o) [string](Get-SIPnProp $o @('sku', 'name')) -eq $Sku }
    $now = [string](Get-SIPnProp $back @('sku', 'name'))
    @{ Ok = ($now -eq $Sku); Line = ('container registry {0}: {1}{2}' -f ($RegistryId -split '/')[-1], $now, $(if ($now -eq $Sku) { ' (read back)' } else { ' -- NOT ' + $Sku + ' after the change' })) }
}

# ============================================================================================================== BUILDS INSIDE THE NETWORK

function Get-SIAcrAgentPoolBody {
    <# PURE. The registry's agent pool in -SubnetId: image builds run there, inside the network, so the registry's public
       endpoint can be closed (Azure's shared build agents are refused by a closed registry). Framework rule 11g: tier S2,
       0 agents -- the pool is scaled to 2 only while images are built (setup\_shared\SI-AcrBuildPool.ps1), Linux. #>
    param([Parameter(Mandatory)][string]$Location, [Parameter(Mandatory)][string]$SubnetId)
    # HOTFIX 2026-11-05: Azure refuses to CREATE a pool at count 0 (AgentPoolInvalidCount: at least 1) -- made at 1, then scaled to 0
    # and read back by Set-SIAcrAgentPool once Azure reads it Succeeded
    [ordered]@{ location = $Location; properties = [ordered]@{ count = 1; tier = 'S2'; os = 'Linux'; virtualNetworkSubnetResourceId = $SubnetId } }
}

function Test-SIAcrAgentPoolInNetwork {
    <# PURE. Is -Pool (as ARM returns it) provisioned and in a subnet of -VnetId (any network when not given)? #>
    param($Pool, [string]$VnetId = '')
    if (-not (Test-SIPnSucceeded $Pool)) { return $false }
    $s = [string](Get-SIPnProp $Pool @('properties', 'virtualNetworkSubnetResourceId'))
    if (-not $s) { return $false }
    if (-not $VnetId) { return $true }
    $s.ToLowerInvariant().StartsWith($VnetId.TrimEnd('/').ToLowerInvariant() + '/subnets/')
}

# How long setup / the updater wait for Azure to make the registry's agent pool in the network. Azure documents the creation
# of a pool in a virtual network in MINUTES (the agents are deployed into the subnet); a live private install (3.0.31) read
# 'Creating' after the earlier 15 min of read-backs and failed the step although Azure was still at work. 30 min: twice what
# was seen not to be enough, and still a bound that is said in the output -- a pool still 'Creating' after it is a re-run.
$script:SIAcrAgentPoolWaitMinutes = 30

function Get-SIAcrAgentPoolError {
    <# PURE. Azure's words for why -Pool did not provision ('' = none on the resource). #>
    param($Pool)
    foreach ($p in @(@('properties', 'error', 'message'), @('properties', 'provisioningError', 'message'), @('error', 'message'), @('properties', 'statusMessage'))) {
        $m = [string](Get-SIPnProp $Pool $p); if ($m.Trim()) { return $m.Trim() }
    }
    ''
}

function Wait-SIAcrAgentPool {
    <# Waits for the agent pool at -Path until Azure reads it Succeeded / Failed / Canceled, or -LimitMinutes pass (the clock
       is -Now, so tests do not wait). Says what it waits for and how long at most, then one progress line every
       -ProgressSeconds. Reuses Read-SIPnBack (the read-back of every other resource) with the pool's own, longer bound.
       Returns @{ Pool = <last read>; State; TimedOut; Minutes }. #>
    param([Parameter(Mandatory)][scriptblock]$Arm, [Parameter(Mandatory)][string]$Path, [Parameter(Mandatory)][string]$Name,
          [scriptblock]$Sleep = { param($s) Start-Sleep -Seconds $s }, [scriptblock]$Now = { [datetime]::UtcNow },
          [scriptblock]$Say = { param($t) Write-Host $t }, [int]$LimitMinutes = $script:SIAcrAgentPoolWaitMinutes,
          [int]$PauseSeconds = 15, [int]$ProgressSeconds = 60, [string]$FirstState = '')
    $start = [datetime](& $Now); $deadline = $start.AddMinutes($LimitMinutes)
    $st = @{ Said = $start; Announced = $false; TimedOut = $false }
    $first = $(if ($FirstState) { $FirstState } else { 'Creating' })
    & $Say ('  waiting for the build agent pool {0} (Azure: {1}) -- up to {2} min; Azure takes several minutes to place it in the network' -f $Name, $first, $LimitMinutes)
    $tries = [int][math]::Ceiling(($LimitMinutes * 60) / [math]::Max(1, $PauseSeconds)) + 1
    $back = Read-SIPnBack -Arm $Arm -Path $Path -Sleep $Sleep -Tries $tries -PauseSeconds $PauseSeconds -Test {
        param($o)
        $s = [string](Get-SIPnProp $o @('properties', 'provisioningState'))
        if ($s -in 'Succeeded', 'Failed', 'Canceled') { return $true }
        $t = [datetime](& $Now)
        if ($t -ge $deadline) { $st.TimedOut = $true; return $true }
        if (($t - $st.Said).TotalSeconds -ge $ProgressSeconds) {
            $st.Said = $t
            & $Say ('  still waiting for the build agent pool {0} (Azure: {1}) -- {2} of up to {3} min' -f $Name, $(if ($s) { $s } else { 'not readable yet' }), [int][math]::Floor(($t - $start).TotalMinutes), $LimitMinutes)
        }
        $false
    }
    $state = [string](Get-SIPnProp $back @('properties', 'provisioningState'))
    if ($state -notin 'Succeeded', 'Failed', 'Canceled' -and -not $st.TimedOut) { $st.TimedOut = $true }   # the tries ran out first
    @{ Pool = $back; State = $state; TimedOut = [bool]$st.TimedOut; Minutes = [int][math]::Floor((([datetime](& $Now)) - $start).TotalMinutes) }
}

function Set-SIAcrAgentPool {
    <# The registry's agent pool -Name in -SubnetId, idempotent, READ BACK -- Azure takes several minutes to make a pool in a
       network, so it WAITS for it (Wait-SIAcrAgentPool, up to $script:SIAcrAgentPoolWaitMinutes, said in the output). A pool
       Azure left Failed / Canceled is asked for again. A pool of that name in another network is never changed (said).
       Returns @{ Ok; Line; Id; Created; State; TimedOut }. #>
    param([Parameter(Mandatory)][scriptblock]$Arm, [Parameter(Mandatory)][string]$RegistryId, [Parameter(Mandatory)][string]$Name,
          [Parameter(Mandatory)][string]$Location, [Parameter(Mandatory)][string]$SubnetId, [scriptblock]$Sleep = { param($s) Start-Sleep -Seconds $s },
          [scriptblock]$Now = { [datetime]::UtcNow }, [scriptblock]$Say = { param($t) Write-Host $t }, [int]$LimitMinutes = $script:SIAcrAgentPoolWaitMinutes)
    $id = '{0}/agentPools/{1}' -f $RegistryId.TrimEnd('/'), $Name
    $path = '{0}?api-version={1}' -f $id, $script:SIPnAcrTasksApi
    $have = & $Arm 'GET' $path $null
    $haveState = [string](Get-SIPnProp $have @('properties', 'provisioningState'))
    if ($have) {
        if (-not (Test-SIPnSameId ([string](Get-SIPnProp $have @('properties', 'virtualNetworkSubnetResourceId'))) $SubnetId)) {
            return @{ Ok = $false; Created = $false; Id = $id; State = $haveState; TimedOut = $false; Line = ('the agent pool {0} exists in another subnet -- it is not changed' -f $Name) }
        }
        if (Test-SIPnSucceeded $have) { return @{ Ok = $true; Created = $false; Id = $id; State = $haveState; TimedOut = $false; Line = ('the registry''s agent pool {0} runs in the network' -f $Name) } }
        # Azure gave up on it earlier: ask again (the same body; a PUT of the same pool is idempotent)
        if ($haveState -in 'Failed', 'Canceled') { $null = & $Arm 'PUT' $path (Get-SIAcrAgentPoolBody -Location $Location -SubnetId $SubnetId); $haveState = 'Creating' }
    } else { $null = & $Arm 'PUT' $path (Get-SIAcrAgentPoolBody -Location $Location -SubnetId $SubnetId); $haveState = 'Creating' }
    $w = Wait-SIAcrAgentPool -Arm $Arm -Path $path -Name $Name -Sleep $Sleep -Now $Now -Say $Say -LimitMinutes $LimitMinutes -FirstState $haveState
    $ok = $w.State -eq 'Succeeded'
    # HOTFIX 2026-11-05 (rule 11g: 0 agents between builds): a pool made or made again here starts at 1 agent (Azure's least
    # at creation) -- scaled to 0 now and read back; a pool that cannot be scaled stays at 1 (it works; it costs one agent) and that is said
    $scaleNote = ''
    if ($ok -and [int](Get-SIPnProp $w.Pool @('properties', 'count')) -gt 0) {
        try {
            $null = & $Arm 'PATCH' $path ([ordered]@{ properties = [ordered]@{ count = 0 } })
            $zb = Read-SIPnBack -Arm $Arm -Path $path -Sleep $Sleep -Tries 40 -PauseSeconds 15 -Test { param($o) [string](Get-SIPnProp $o @('properties', 'provisioningState')) -eq 'Succeeded' -and [int](Get-SIPnProp $o @('properties', 'count')) -eq 0 }
            $scaleNote = if ([int](Get-SIPnProp $zb @('properties', 'count')) -eq 0) { '; scaled to 0 agents between builds (read back)' } else { '; it still has 1 agent -- the next update scales it to 0' }
        } catch { $scaleNote = ('; it still has 1 agent (the scale to 0 was refused: {0}) -- the next update scales it to 0' -f $_.Exception.Message) }
    }
    $line = if ($ok) { 'the registry''s agent pool {0} in the network: image builds run inside it (read back, after {1} min){2}' -f $Name, $w.Minutes, $scaleNote }
            elseif ($w.State -in 'Failed', 'Canceled') {
                $err = Get-SIAcrAgentPoolError $w.Pool
                'Azure could not make the agent pool {0} (Azure shows: {1}{2})' -f $Name, $w.State, $(if ($err) { ': ' + $err } else { '; Azure gives no reason on the pool -- the registry''s Activity log has it' })
            }
            else { 'the agent pool {0} does not read back as ready after {1} min of waiting (Azure shows: {2}) -- Azure is still making it' -f $Name, $LimitMinutes, $(if ($w.State) { $w.State } else { 'not readable' }) }
    @{ Ok = [bool]$ok; Created = (-not $have); Id = $id; State = $w.State; TimedOut = [bool]$w.TimedOut; Line = $line }
}

# #1087 (3.0.33): a live private install's agent pool FAILED twice inside Azure's own deployment -- the endpoints subnet SI
# made read defaultOutboundAccess = false (Azure's default for NEW subnets since late 2025), with no NAT gateway and no
# route table, so the pool's machines had no way out. PIM's working pool at the same customer sits in its older PE subnet
# (defaultOutboundAccess unset = implicit outbound). The design stays PIM's (the pool in the PE subnet); the subnet must
# have an outbound path. Never a pool that is certain to fail.

function Get-SISubnetOutboundPath {
    <# PURE. The outbound path of -Subnet (as ARM returns it): 'default' (defaultOutboundAccess true, or unset = the
       implicit outbound of an older subnet), 'nat' (a NAT gateway), 'route' (-RouteTable, the route table the subnet
       names, has a 0.0.0.0/0 route to a next hop other than None), '' = none. #>
    param($Subnet, $RouteTable = $null)
    if (-not $Subnet) { return '' }
    $doa = Get-SIPnProp $Subnet @('properties', 'defaultOutboundAccess')
    if ($null -eq $doa -or "$doa" -eq '' -or "$doa" -eq 'True') { return 'default' }
    if ([string](Get-SIPnProp $Subnet @('properties', 'natGateway', 'id'))) { return 'nat' }
    foreach ($r in @(Get-SIPnProp $RouteTable @('properties', 'routes') | Where-Object { $_ })) {
        if ([string](Get-SIPnProp $r @('properties', 'addressPrefix')) -eq '0.0.0.0/0' -and [string](Get-SIPnProp $r @('properties', 'nextHopType')) -ne 'None') { return 'route' }
    }
    ''
}

function Test-SISubnetOutboundSet { <# PURE. Does -Subnet read defaultOutboundAccess = true (explicitly)? #> param($Subnet) "$(Get-SIPnProp $Subnet @('properties', 'defaultOutboundAccess'))" -eq 'True' }

function Test-SIOwnSpokeVnet {
    <# PURE. Is -Vnet (as ARM returns it) SecurityInsight's OWN spoke network -- the one Set-SIVnet makes from vnetAddressPrefix:
       in the install's resource group -ResourceGroupId AND tagged purpose = securityinsight-private-network? A customer's
       network (vnetId given) is never this. #>
    param($Vnet, [string]$ResourceGroupId = '')
    if (-not $Vnet -or -not "$ResourceGroupId".Trim()) { return $false }
    $id = [string](Get-SIPnProp $Vnet @('id'))
    $inRg = $id -and $id.TrimEnd('/').StartsWith($ResourceGroupId.TrimEnd('/') + '/providers/', [System.StringComparison]::OrdinalIgnoreCase)
    [bool]($inRg -and [string](Get-SIPnProp $Vnet @('tags', 'purpose')) -eq 'securityinsight-private-network')
}

function Get-SIBuildSubnetOutboundStep {
    <# PURE. The one customer step when the build subnet of a CUSTOMER'S network has no outbound path. #>
    param([Parameter(Mandatory)][string]$SubnetName)
    'the build subnet {0} has no outbound path; give it outbound access (defaultOutboundAccess, a NAT gateway or a route to your firewall that allows the Azure services an ACR agent pool needs), then run the install again' -f $SubnetName
}

function Set-SIBuildSubnetOutbound {
    <#
        #1087. READS the subnet -SubnetId the registry's agent pool goes in, BEFORE the pool is made. An outbound path
        (Get-SISubnetOutboundPath) = fine, nothing written. None:
          SecurityInsight's own spoke (-OwnNetwork, or the network reads as its own: Test-SIOwnSpokeVnet)
              defaultOutboundAccess set true (the subnet PUT keeps everything else it has), READ BACK;
          a customer's network
              NOTHING is changed: Blocked, with the one customer step (Get-SIBuildSubnetOutboundStep).
        A subnet that cannot be read is not guessed at: said, not blocked (the pool step reports what Azure does).
        -ReportOnly (the updater's -WhatIf): the plan, nothing written.
        Returns @{ Ok; Blocked; Fixed; Path; Own; Line; Step }.
    #>
    param([Parameter(Mandatory)][scriptblock]$Arm, [Parameter(Mandatory)][string]$SubnetId, [bool]$OwnNetwork = $false,
          [string]$ResourceGroupId = '', [switch]$ReportOnly, [scriptblock]$Sleep = { param($s) Start-Sleep -Seconds $s })
    $name = ($SubnetId.TrimEnd('/') -split '/')[-1]
    $path = '{0}?api-version={1}' -f $SubnetId.TrimEnd('/'), $script:SIPnNetApi
    $sn = & $Arm 'GET' $path $null
    if (-not $sn) { return @{ Ok = $true; Blocked = $false; Fixed = $false; Path = ''; Own = $OwnNetwork; Step = ''; Line = ('the build subnet {0} could not be read, so its outbound path is not checked' -f $name) } }
    $rtId = [string](Get-SIPnProp $sn @('properties', 'routeTable', 'id'))
    $rt = if ($rtId) { & $Arm 'GET' ('{0}?api-version={1}' -f $rtId.TrimEnd('/'), $script:SIPnNetApi) $null } else { $null }
    $via = Get-SISubnetOutboundPath -Subnet $sn -RouteTable $rt
    $what = @{ default = 'default outbound access'; nat = 'a NAT gateway'; route = 'a route table with a 0.0.0.0/0 route' }
    if ($via) { return @{ Ok = $true; Blocked = $false; Fixed = $false; Path = $via; Own = $OwnNetwork; Step = ''; Line = ('the build subnet {0} has an outbound path ({1})' -f $name, $what[$via]) } }
    $own = [bool]$OwnNetwork
    if (-not $own) {
        $vnet = & $Arm 'GET' ('{0}?api-version={1}' -f ($SubnetId.TrimEnd('/') -replace '(?i)/subnets/[^/]+$', ''), $script:SIPnNetApi) $null
        $own = Test-SIOwnSpokeVnet -Vnet $vnet -ResourceGroupId $ResourceGroupId
    }
    if (-not $own) {
        $step = Get-SIBuildSubnetOutboundStep -SubnetName $name
        return @{ Ok = $false; Blocked = $true; Fixed = $false; Path = ''; Own = $false; Step = $step
                  Line = ('the build subnet {0} is in your network and has no outbound path (no default outbound access, no NAT gateway, no 0.0.0.0/0 route) -- the agent pool is NOT made (it would fail); SecurityInsight does not change your network: {1}' -f $name, $step) }
    }
    if ($ReportOnly) { return @{ Ok = $true; Blocked = $false; Fixed = $false; Path = ''; Own = $true; Step = ''; Line = ('the build subnet {0} would get default outbound access (SecurityInsight''s own network; outbound only)' -f $name) } }
    $body = Get-SISubnetBody -Subnet $sn
    $body.properties['defaultOutboundAccess'] = $true
    $null = & $Arm 'PUT' $path $body
    # read back EXPLICITLY true (framework rule 11b, the build-pool outbound rule) -- unset is not what was written
    $back = Read-SIPnBack -Arm $Arm -Path $path -Sleep $Sleep -Tries 12 -Test { param($o) (Test-SIPnSucceeded $o) -and (Test-SISubnetOutboundSet $o) }
    $ok = [bool]((Test-SIPnSucceeded $back) -and (Test-SISubnetOutboundSet $back))
    @{ Ok = $ok; Blocked = (-not $ok); Fixed = $ok; Path = $(if ($ok) { 'default' } else { '' }); Own = $true
       Step = $(if ($ok) { '' } else { 'run the install again: SecurityInsight sets default outbound access on its own build subnet {0} and reads it back' -f $name })
       Line = $(if ($ok) { 'the build subnet {0} (SecurityInsight''s own network) had no outbound path: default outbound access turned on (outbound only; read back)' -f $name }
                else { 'the build subnet {0} (SecurityInsight''s own network) does not read back with default outbound access after the change -- the agent pool is NOT made' -f $name }) }
}

function Invoke-SIAcrAgentPoolStep {
    <# #1087. The registry's agent pool -Name in -SubnetId, never one that is certain to fail: a pool that already runs there
       is kept as it is; otherwise the subnet's outbound path is checked first (Set-SIBuildSubnetOutbound) and the pool is
       made (Set-SIAcrAgentPool: a Failed / Canceled one is asked for again) only when there is one. Returns
       Set-SIAcrAgentPool's hashtable plus Blocked, Step and OutboundLine. #>
    param([Parameter(Mandatory)][scriptblock]$Arm, [Parameter(Mandatory)][string]$RegistryId, [Parameter(Mandatory)][string]$Name,
          [Parameter(Mandatory)][string]$Location, [Parameter(Mandatory)][string]$SubnetId, [bool]$OwnNetwork = $false, [string]$ResourceGroupId = '',
          [scriptblock]$Sleep = { param($s) Start-Sleep -Seconds $s }, [scriptblock]$Now = { [datetime]::UtcNow }, [scriptblock]$Say = { param($t) Write-Host $t })
    $id = '{0}/agentPools/{1}' -f $RegistryId.TrimEnd('/'), $Name
    $have = & $Arm 'GET' ('{0}?api-version={1}' -f $id, $script:SIPnAcrTasksApi) $null
    $runs = $have -and (Test-SIPnSucceeded $have) -and (Test-SIPnSameId ([string](Get-SIPnProp $have @('properties', 'virtualNetworkSubnetResourceId'))) $SubnetId)
    $o = @{ Ok = $true; Line = ''; Step = '' }
    if (-not $runs) {
        $o = Set-SIBuildSubnetOutbound -Arm $Arm -SubnetId $SubnetId -OwnNetwork $OwnNetwork -ResourceGroupId $ResourceGroupId -Sleep $Sleep
        if ($o.Blocked) { return @{ Ok = $false; Blocked = $true; Created = $false; Id = $id; State = [string](Get-SIPnProp $have @('properties', 'provisioningState')); TimedOut = $false; Line = $o.Line; Step = $o.Step; OutboundLine = $o.Line } }
    }
    $p = Set-SIAcrAgentPool -Arm $Arm -RegistryId $RegistryId -Name $Name -Location $Location -SubnetId $SubnetId -Sleep $Sleep -Now $Now -Say $Say
    $p['Blocked'] = $false; $p['Step'] = ''; $p['OutboundLine'] = [string]$o.Line
    $p
}

# ============================================================================================================== RETURN ROUTE (#1095)
# LIVE 2026-11-04 (a private install in a hub-and-spoke network with a firewall in the hub): DNS resolved, the peering read
# Connected, and the browser on the customer's internal network still timed out. The requests reached the web app through
# the hub's firewall, but the apps subnet had NO route table: the replies to the customer's own address ranges took Azure's
# default route and were dropped. The cure (made by hand that day, and it worked) is a route table on the apps subnet: each
# range the customer's people browse from -> the hub firewall's private IP as VirtualAppliance, BGP route propagation off.
#   * Made ONLY on SecurityInsight's OWN spoke (the network it creates) and ONLY from the customer's own answers
#     (returnRouteRanges + returnRouteNextHop) -- the next hop is a customer value SecurityInsight can never guess.
#   * A CUSTOMER-PROVIDED network is never changed: the network hand-off carries the item for the customer's network team.
#   * Framework rule 11d (Invardia 301d9d81): the table is rt-si in the install's resource group. A table already attached
#     to the apps subnet (an earlier hand-made one) is REUSED as it is -- never a second table, never renamed -- and routes
#     SecurityInsight did not make are kept, never removed.
#   * NOT on the endpoints subnet, on purpose: the private endpoints are reached by SecurityInsight's own jobs and web app
#     inside its network, and Azure answers a private endpoint's traffic symmetrically without a user route (its network
#     policies are Disabled, so a route table there would not even apply to them). The registry's build pool in that subnet
#     needs a way OUT (rule 11b, Set-SIBuildSubnetOutbound), not a way back to the customer's ranges.

function Get-SIReturnRouteTableName { <# PURE. The name of the route table SecurityInsight makes (framework rule 11d). #> 'rt-si' }

function Get-SIReturnRouteName {
    <# PURE. The name SecurityInsight gives the route for -Range: si-return-<range with / as ->, e.g. si-return-10.0.0.0-16. #>
    param([Parameter(Mandatory)][string]$Range)
    'si-return-' + ($Range.Trim() -replace '/', '-')
}

function ConvertTo-SIReturnRouteRanges {
    <# PURE. The answer returnRouteRanges -- text ("10.0.0.0/16, 10.2.0.0/16") or a list -- as @{ Ranges; Bad }: each range in
       its network form (10.0.0.5/16 -> 10.0.0.0/16), each once, in the order given; Bad = what is not an IPv4 range. #>
    param([AllowNull()]$Value)
    $ranges = New-Object System.Collections.Generic.List[string]; $bad = New-Object System.Collections.Generic.List[string]
    foreach ($v in @($Value)) {
        foreach ($p in ("$v" -split '[,;\s]+')) {
            $x = $p.Trim(); if (-not $x) { continue }
            $r = ConvertTo-SICidrRange $x
            if ($r) { $n = ConvertFrom-SICidrStart -Start $r.Start -Bits $r.Bits; if (-not $ranges.Contains($n)) { $ranges.Add($n) } } else { $bad.Add($x) }
        }
    }
    @{ Ranges = $ranges.ToArray(); Bad = $bad.ToArray() }
}

function Test-SIIpv4Address {
    <# PURE. Is -Ip one IPv4 address (a.b.c.d, each 0-255)? #>
    param([AllowNull()][string]$Ip)
    $m = [regex]::Match("$Ip".Trim(), '^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$')
    [bool]($m.Success -and -not @(1..4 | Where-Object { [int]$m.Groups[$_].Value -gt 255 }).Count)
}

function Get-SIReturnRouteCoverage {
    <# PURE. Does -RouteTable (as ARM returns it) send every one of -Ranges to -NextHop as VirtualAppliance? With no
       -NextHop, any VirtualAppliance next hop counts. @{ Ok; Missing (ranges without such a route); Conflicts (ranges whose
       prefix a route sends elsewhere -- 'range -> hop (route name)') }. #>
    param($RouteTable, [string[]]$Ranges = @(), [string]$NextHop = '')
    $routes = @(Get-SIPnProp $RouteTable @('properties', 'routes') | Where-Object { $_ })
    $missing = New-Object System.Collections.Generic.List[string]; $conflicts = New-Object System.Collections.Generic.List[string]
    foreach ($rg in @($Ranges | Where-Object { $_ })) {
        $same = @($routes | Where-Object { [string](Get-SIPnProp $_ @('properties', 'addressPrefix')) -eq $rg })
        $good = @($same | Where-Object { [string](Get-SIPnProp $_ @('properties', 'nextHopType')) -eq 'VirtualAppliance' -and (-not $NextHop -or [string](Get-SIPnProp $_ @('properties', 'nextHopIpAddress')) -eq $NextHop) })
        if ($good.Count) { continue }
        $missing.Add($rg)
        foreach ($s in $same) { $conflicts.Add(('{0} -> {1} {2} ({3})' -f $rg, [string](Get-SIPnProp $s @('properties', 'nextHopType')), [string](Get-SIPnProp $s @('properties', 'nextHopIpAddress')), [string](Get-SIPnProp $s @('name')))) }
    }
    @{ Ok = ($missing.Count -eq 0); Missing = $missing.ToArray(); Conflicts = $conflicts.ToArray() }
}

function Get-SIReturnRouteTableBody {
    <#
        PURE. The PUT body of the route table that sends each of -Ranges to -NextHop (VirtualAppliance), BGP route
        propagation off. -Existing: the table as ARM returns it ($null = a new table, made in -Location, tagged as
        SecurityInsight's). A route table PUT REPLACES its routes, so EVERY route that is there is carried over unchanged --
        a route SecurityInsight did not make is never removed or changed. Per range: a route that already sends it to the next
        hop is kept; SecurityInsight's own route (si-return-<range>) with another next hop is corrected; a range a FOREIGN route
        sends elsewhere is NOT overwritten (Azure takes one route per prefix) -- it is a Conflict, said, for the customer.
        @{ Body; Added; Updated; Kept (foreign routes carried over); Conflicts; Changed }.
    #>
    param($Existing, [Parameter(Mandatory)][string[]]$Ranges, [Parameter(Mandatory)][string]$NextHop, [string]$Location = '')
    $routes = New-Object System.Collections.Generic.List[object]
    $added = New-Object System.Collections.Generic.List[string]; $updated = New-Object System.Collections.Generic.List[string]
    $kept = New-Object System.Collections.Generic.List[string]; $conflicts = New-Object System.Collections.Generic.List[string]
    $conflictRanges = New-Object System.Collections.Generic.List[string]
    $own = @{}; foreach ($rg in $Ranges) { $own[(Get-SIReturnRouteName -Range $rg)] = $rg }
    foreach ($r in @(Get-SIPnProp $Existing @('properties', 'routes') | Where-Object { $_ })) {
        $nm = [string](Get-SIPnProp $r @('name'))
        $p = [ordered]@{ addressPrefix = [string](Get-SIPnProp $r @('properties', 'addressPrefix')); nextHopType = [string](Get-SIPnProp $r @('properties', 'nextHopType')) }
        $hop = [string](Get-SIPnProp $r @('properties', 'nextHopIpAddress')); if ($hop) { $p['nextHopIpAddress'] = $hop }
        if ($own.ContainsKey($nm) -and $p.addressPrefix -eq $own[$nm] -and -not ($p.nextHopType -eq 'VirtualAppliance' -and $hop -eq $NextHop)) {
            $p = [ordered]@{ addressPrefix = $own[$nm]; nextHopType = 'VirtualAppliance'; nextHopIpAddress = $NextHop }; $updated.Add($own[$nm])
        } elseif (-not $own.ContainsKey($nm)) { $kept.Add($nm) }
        $routes.Add([ordered]@{ name = $nm; properties = $p })
    }
    foreach ($rg in $Ranges) {
        $same = @($routes | Where-Object { [string]$_.properties.addressPrefix -eq $rg })
        if ($same.Count) {
            $ok = @($same | Where-Object { $_.properties.nextHopType -eq 'VirtualAppliance' -and [string]$_.properties.nextHopIpAddress -eq $NextHop })
            if (-not $ok.Count) { $conflictRanges.Add($rg); foreach ($s in $same) { $conflicts.Add(('{0} -> {1} {2} (route {3}, not SecurityInsight''s: kept)' -f $rg, $s.properties.nextHopType, [string]$s.properties.nextHopIpAddress, $s.name)) } }
            continue
        }
        $routes.Add([ordered]@{ name = (Get-SIReturnRouteName -Range $rg); properties = [ordered]@{ addressPrefix = $rg; nextHopType = 'VirtualAppliance'; nextHopIpAddress = $NextHop } }); $added.Add($rg)
    }
    $bgpOff = "$(Get-SIPnProp $Existing @('properties', 'disableBgpRoutePropagation'))" -eq 'True'
    $body = [ordered]@{}
    if ($Existing) {
        $body['location'] = [string](Get-SIPnProp $Existing @('location'))
        $tags = Get-SIPnProp $Existing @('tags'); if ($null -ne $tags) { $body['tags'] = ConvertTo-SIPnHashtable $tags }
    } else { $body['location'] = $Location; $body['tags'] = [ordered]@{ purpose = 'securityinsight-private-network' } }
    $body['properties'] = [ordered]@{ disableBgpRoutePropagation = $true; routes = @($routes.ToArray()) }
    @{ Body = $body; Added = $added.ToArray(); Updated = $updated.ToArray(); Kept = $kept.ToArray(); Conflicts = $conflicts.ToArray(); ConflictRanges = $conflictRanges.ToArray()
       Changed = [bool](-not $Existing -or $added.Count -or $updated.Count -or -not $bgpOff) }
}

function Get-SIReturnRouteFacts {
    <# READ ONLY. The return route of -Target's apps subnet: its answers (returnRouteRanges / returnRouteNextHop), whether
       the network is SecurityInsight's own, the route table attached to the apps subnet and whether it covers the ranges.
       @{ SubnetName; SubnetId; SubnetRead; Own; Ranges; Bad; NextHop; Answers; RouteTableId; RouteTableName; Covered; Missing;
          Conflicts; HasApplianceRoute; ResourceGroup; VnetId }. Never writes, never throws for a read that fails. #>
    param([Parameter(Mandatory)][scriptblock]$Arm, [Parameter(Mandatory)][System.Collections.IDictionary]$Target)
    $vnetId = ([string]$Target['VnetId']).TrimEnd('/'); $snName = [string]$Target['AppsSubnetName']; if (-not $snName) { $snName = (Get-SIPrivateNetworkNames).AppsSubnet }
    $rr = ConvertTo-SIReturnRouteRanges $Target['ReturnRouteRanges']; $hop = ([string]$Target['ReturnRouteNextHop']).Trim()
    $rgId = ([string]$Target['ResourceGroupId']).TrimEnd('/')
    $f = [ordered]@{ SubnetName = $snName; SubnetId = $(if ($vnetId) { '{0}/subnets/{1}' -f $vnetId, $snName } else { '' }); SubnetRead = $false; Own = [bool]$Target['CreateVnet']
                     Ranges = @($rr.Ranges); Bad = @($rr.Bad); NextHop = $hop; Answers = [bool](@($rr.Ranges).Count -and (Test-SIIpv4Address $hop))
                     RouteTableId = ''; RouteTableName = ''; Covered = $false; Missing = @($rr.Ranges); Conflicts = @(); HasApplianceRoute = $false
                     ResourceGroup = $(if ($rgId) { ($rgId -split '/')[-1] } else { '' }); VnetId = $vnetId }
    if (-not $vnetId) { return $f }
    try {
        if (-not $f.Own) { $f.Own = [bool](Test-SIOwnSpokeVnet -Vnet (& $Arm 'GET' ('{0}?api-version={1}' -f $vnetId, $script:SIPnNetApi) $null) -ResourceGroupId $rgId) }
        $sn = & $Arm 'GET' ('{0}?api-version={1}' -f $f.SubnetId, $script:SIPnNetApi) $null
        if (-not $sn) { return $f }
        $f.SubnetRead = $true
        $f.RouteTableId = [string](Get-SIPnProp $sn @('properties', 'routeTable', 'id'))
        if (-not $f.RouteTableId) { return $f }
        $f.RouteTableName = ($f.RouteTableId.TrimEnd('/') -split '/')[-1]
        $rt = & $Arm 'GET' ('{0}?api-version={1}' -f $f.RouteTableId.TrimEnd('/'), $script:SIPnNetApi) $null
        $f.HasApplianceRoute = [bool]@(Get-SIPnProp $rt @('properties', 'routes') | Where-Object { $_ } | Where-Object { [string](Get-SIPnProp $_ @('properties', 'nextHopType')) -eq 'VirtualAppliance' -or [string](Get-SIPnProp $_ @('properties', 'addressPrefix')) -eq '0.0.0.0/0' }).Count
        if (@($f.Ranges).Count) { $c = Get-SIReturnRouteCoverage -RouteTable $rt -Ranges @($f.Ranges) -NextHop $(if (Test-SIIpv4Address $hop) { $hop } else { '' }); $f.Covered = [bool]$c.Ok; $f.Missing = @($c.Missing); $f.Conflicts = @($c.Conflicts) }
    } catch { }
    $f
}

function Get-SIReturnRouteHandOff {
    <# PURE. The network hand-off's RETURN ROUTE item from -Facts (Get-SIReturnRouteFacts; $null = not read: the item is
       said in general). -Number: its number in the list. @{ Open (it counts as an open item); Done; Lines }. Open when the apps
       subnet reads WITHOUT a route table, or a table that misses one of the ranges given; not counted when it was not read,
       or a table is attached and no ranges are known (it is then a check for the network team). #>
    param($Facts, [string]$Number = '6')
    $L = New-Object System.Collections.Generic.List[string]
    $sn = if ($Facts -and [string]$Facts['SubnetName']) { [string]$Facts['SubnetName'] } else { (Get-SIPrivateNetworkNames).AppsSubnet }
    $ranges = if ($Facts) { @($Facts['Ranges'] | Where-Object { $_ }) } else { @() }; $hop = if ($Facts -and (Test-SIIpv4Address ([string]$Facts['NextHop']))) { [string]$Facts['NextHop'] } else { '' }
    if ($Facts -and [bool]$Facts['SubnetRead'] -and [string]$Facts['RouteTableId'] -and $ranges.Count -and [bool]$Facts['Covered']) {
        $L.Add(('{0}. RETURN ROUTE: done -- route table {1} on the apps subnet {2} sends {3} to {4} (VirtualAppliance).' -f $Number, $Facts['RouteTableName'], $sn, ($ranges -join ', '), $(if ($hop) { $hop } else { 'your firewall' })))
        return @{ Open = $false; Done = $true; Lines = $L.ToArray() }
    }
    $r1 = if ($ranges.Count) { $ranges[0] } else { '<a range your people browse from>' }
    $h1 = if ($hop) { $hop } else { '<its private IP>' }
    $L.Add(('{0}. RETURN ROUTE: the apps subnet {1} needs a route for each range your people browse from (e.g. a route table: {2} -> your firewall {3} as VirtualAppliance), or replies time out.' -f $Number, $sn, $r1, $h1))
    if ($ranges.Count) { foreach ($x in $ranges) { $L.Add(('        {0,-20} -> VirtualAppliance {1}' -f $x, $h1)) } }
    if ($Facts -and [string]$Facts['RouteTableId']) {
        $L.Add(('   the apps subnet has the route table {0}{1}' -f $Facts['RouteTableName'], $(if ($ranges.Count) { ' -- it has no such route for: ' + (@($Facts['Missing']) -join ', ') } else { ': check that it has these routes' })))
        foreach ($c in @($Facts['Conflicts'] | Where-Object { $_ })) { $L.Add(('   a route there sends {0} -- your team decides which way it goes' -f $c)) }
    } elseif ($Facts -and [bool]$Facts['SubnetRead']) { $L.Add('   the apps subnet has NO route table now: replies to your own ranges take Azure''s default route and are dropped by your firewall.') }
    if ($Facts -and [bool]$Facts['Own'] -and -not [bool]$Facts['Answers']) {
        $L.Add('   This is SecurityInsight''s own network: SecurityInsight makes the route table itself once it has the two answers. Give them and run again:')
        $L.Add(('     the install command with -ReturnRouteRanges ''{0}'' -ReturnRouteNextHop ''{1}'' -Resume, or' -f $(if ($ranges.Count) { $ranges -join ',' } else { '<range>[,<range>]' }), $(if ($hop) { $hop } else { '<firewall private IP>' })))
        $L.Add(('     ./setup/Set-SIPrivateNetworking.ps1 -ResourceGroup {0} -VnetId {1} -ReturnRouteRanges <range>[,<range>] -ReturnRouteNextHop <firewall private IP> -Apply -Steps return-route' -f $(if ([string]$Facts['ResourceGroup']) { $Facts['ResourceGroup'] } else { '<resource group>' }), $(if ([string]$Facts['VnetId']) { $Facts['VnetId'] } else { '<vnet id>' })))
    }
    $open = [bool]($Facts -and [bool]$Facts['SubnetRead'] -and (-not [string]$Facts['RouteTableId'] -or ($ranges.Count -and -not [bool]$Facts['Covered'])))
    @{ Open = $open; Done = $false; Lines = $L.ToArray() }
}

function Set-SIReturnRoute {
    <#
        #1095. The return route of SecurityInsight's OWN spoke: with both answers given, the route table (the one attached to
        the apps subnet, else rt-si in the install's resource group) sends each range to the next hop as VirtualAppliance, BGP
        route propagation off; attached to the apps subnet. Every change READ BACK (the routes AND the attachment).
        Idempotent: a table that is right is not written; routes SecurityInsight did not make are kept.
        Changes NOTHING when the network is the customer's, or an answer is missing -- the hand-off item instead (HandOff).
        -ReportOnly: the plan, nothing written.
        Returns @{ Ok; Own; HandOff; Changed; Created; Attached; AttachedNow (attached by THIS call); RouteTableId; AddedRanges; Conflicts; Line; Lines }.
    #>
    param([Parameter(Mandatory)][scriptblock]$Arm, [Parameter(Mandatory)][System.Collections.IDictionary]$Target, [string]$Location = '',
          [switch]$ReportOnly, [scriptblock]$Sleep = { param($s) Start-Sleep -Seconds $s })
    $f = Get-SIReturnRouteFacts -Arm $Arm -Target $Target
    $out = { param($ok, $line, $extra) $h = @{ Ok = [bool]$ok; Own = [bool]$f.Own; HandOff = $false; Changed = $false; Created = $false; Attached = $false; RouteTableId = [string]$f.RouteTableId; AddedRanges = @(); Conflicts = @(); Line = $line; Lines = @($line) }; if ($extra) { foreach ($k in $extra.Keys) { $h[$k] = $extra[$k] } }; $h }
    $sn = $f.SubnetName
    if (-not $f.VnetId) { return (& $out $true 'return route: no network is named -- nothing to do' @{ HandOff = $true }) }
    if (-not $f.Own) { return (& $out $true ('return route: the apps subnet {0} is in YOUR network -- SecurityInsight changes nothing there; the route is on the network hand-off (RETURN ROUTE)' -f $sn) @{ HandOff = $true }) }
    if (@($f.Bad).Count) { return (& $out $false ('return route: returnRouteRanges holds what is not an address range ({0}) -- nothing was changed' -f (@($f.Bad) -join ', ')) $null) }
    if (-not @($f.Ranges).Count -or -not "$($f.NextHop)") { return (& $out $true ('return route: not made -- the answers returnRouteRanges and returnRouteNextHop are not both given; it is on the network hand-off (RETURN ROUTE) with how to give them') @{ HandOff = $true }) }
    if (-not (Test-SIIpv4Address $f.NextHop)) { return (& $out $false ('return route: returnRouteNextHop {0} is not an IPv4 address -- nothing was changed' -f $f.NextHop) $null) }
    if (-not $f.SubnetRead) { return (& $out $false ('return route: the apps subnet {0} was not found -- nothing was changed (the subnets step makes it first)' -f $sn) $null) }
    $rgId = ([string]$Target['ResourceGroupId']).TrimEnd('/')
    # framework rule 11d: the table ATTACHED to the apps subnet is the one (never a second, never renamed); else rt-si
    $rtId = if ($f.RouteTableId) { $f.RouteTableId.TrimEnd('/') } else { '{0}/providers/Microsoft.Network/routeTables/{1}' -f $rgId, (Get-SIReturnRouteTableName) }
    $rtName = ($rtId -split '/')[-1]
    $rtPath = '{0}?api-version={1}' -f $rtId, $script:SIPnNetApi
    $have = & $Arm 'GET' $rtPath $null
    $loc = $Location; if (-not $loc) { $loc = [string](Get-SIPnProp (& $Arm 'GET' ('{0}?api-version={1}' -f $f.VnetId, $script:SIPnNetApi) $null) @('location')) }
    $b = Get-SIReturnRouteTableBody -Existing $have -Ranges @($f.Ranges) -NextHop $f.NextHop -Location $loc
    $attached = [bool]$f.RouteTableId
    $routeText = ((@($f.Ranges) | ForEach-Object { '{0} -> {1}' -f $_, $f.NextHop }) -join ', ')
    if ($ReportOnly) {
        $plan = @(); if ($b.Changed) { $plan += $(if ($have) { 'route table {0}: {1} (VirtualAppliance), BGP route propagation off' -f $rtName, $routeText } else { 'route table {0} made: {1} (VirtualAppliance), BGP route propagation off' -f $rtName, $routeText }) }
        if (-not $attached) { $plan += ('attached to {0}' -f $sn) }
        return (& $out $true $(if ($plan.Count) { 'return route WOULD be: ' + ($plan -join '; ') } else { 'return route: route table {0} on {1} sends {2} (VirtualAppliance) -- nothing to do' -f $rtName, $sn, $routeText }) @{ RouteTableId = $rtId; Conflicts = @($b.Conflicts) })
    }
    if (-not $loc) { return (& $out $false 'return route: the region of the network could not be read -- nothing was changed' $null) }
    # the ranges SecurityInsight may route: a range a foreign route sends elsewhere stays the customer's (a Conflict, said)
    $want = @(@($f.Ranges) | Where-Object { @($b.ConflictRanges) -notcontains $_ })
    $isRight = { param($o) [bool]((Test-SIPnSucceeded $o) -and "$(Get-SIPnProp $o @('properties', 'disableBgpRoutePropagation'))" -eq 'True' -and (Get-SIReturnRouteCoverage -RouteTable $o -Ranges $want -NextHop $f.NextHop).Ok) }
    $lines = New-Object System.Collections.Generic.List[string]
    $ok = $true; $rtOk = $true
    if ($b.Changed) {
        $null = & $Arm 'PUT' $rtPath $b.Body
        $back = Read-SIPnBack -Arm $Arm -Path $rtPath -Sleep $Sleep -Tries 12 -Test $isRight
        $rtOk = [bool](& $isRight $back)
        if ($rtOk) {
            $lines.Add(('route table {0} {1}: {2} (VirtualAppliance), BGP route propagation off{3} (read back)' -f $rtName, $(if ($have) { 'converged' } else { 'made in the install''s resource group' }),
                ((@($want) | ForEach-Object { '{0} -> {1}' -f $_, $f.NextHop }) -join ', '), $(if (@($b.Kept).Count) { '; routes it did not make kept: ' + (@($b.Kept) -join ', ') } else { '' })))
        } else { $ok = $false; $lines.Add(('route table {0} does not read back with the routes {1} and BGP route propagation off after the change' -f $rtName, $routeText)) }
    } else { $lines.Add(('route table {0} sends {1} (VirtualAppliance), BGP route propagation off -- nothing to change' -f $rtName, ((@($want) | ForEach-Object { '{0} -> {1}' -f $_, $f.NextHop }) -join ', '))) }
    foreach ($c in @($b.Conflicts)) { $ok = $false; $lines.Add(('return route: a route that SecurityInsight did not make sends {0} -- not changed; your team decides which way it goes' -f $c)) }
    $didAttach = $false
    # attached once the table reads back right (a Conflict on one range does not keep the others from working)
    if ($rtOk -and -not $attached) {
        $snPath = '{0}?api-version={1}' -f $f.SubnetId, $script:SIPnNetApi
        $snNow = & $Arm 'GET' $snPath $null
        # a subnet PUT REPLACES the subnet: everything it has is carried over (its delegation, NSG, ...), the table added
        $sb = Get-SISubnetBody -Subnet $snNow
        $sb.properties['routeTable'] = [ordered]@{ id = $rtId }
        $null = & $Arm 'PUT' $snPath $sb
        $snBack = Read-SIPnBack -Arm $Arm -Path $snPath -Sleep $Sleep -Tries 12 -Test { param($o) (Test-SIPnSucceeded $o) -and (Test-SIPnSameId ([string](Get-SIPnProp $o @('properties', 'routeTable', 'id'))) $rtId) }
        if ((Test-SIPnSucceeded $snBack) -and (Test-SIPnSameId ([string](Get-SIPnProp $snBack @('properties', 'routeTable', 'id'))) $rtId)) { $didAttach = $true; $lines.Add(('route table {0} attached to the apps subnet {1} (read back)' -f $rtName, $sn)) }
        else { $ok = $false; $lines.Add(('route table {0} is NOT attached to the apps subnet {1} after the change -- run again' -f $rtName, $sn)) }
    } elseif ($attached) { $lines.Add(('route table {0} is the one attached to the apps subnet {1} (reused as it is, never a second one)' -f $rtName, $sn)) }
    $line = if ($ok) { 'return route: {0}' -f ($lines -join '; ') } else { 'return route NOT complete: {0}' -f ($lines -join '; ') }
    @{ Ok = $ok; Own = $true; HandOff = (-not $ok); Changed = [bool]($b.Changed -or $didAttach); Created = [bool](-not $have); Attached = [bool]($attached -or $didAttach); AttachedNow = $didAttach
       RouteTableId = $rtId; AddedRanges = @($b.Added); Conflicts = @($b.Conflicts); Line = $line; Lines = $lines.ToArray() }
}

function Invoke-SIPrivateNetworkReturnRoute {
    <# Setup's call (#1095, the guided install's private-network step, every run until it is done): Set-SIReturnRoute over
       setup's own ARM sign-in (Invoke-SIArm unless -Arm is given). Never throws for what it cannot do: said in the answer. #>
    param([Parameter(Mandatory)][System.Collections.IDictionary]$Target, [string]$Location = '', [scriptblock]$Arm, [scriptblock]$Sleep, [string]$SubscriptionId)
    if (-not $Arm) { $Arm = { param([string]$Method, [string]$Path, $Body) if ($Method -eq 'GET') { Invoke-SIArm -Path $Path -AllowNotFound } else { Invoke-SIArm -Method $Method -Path $Path -Body $Body } } }
    if (-not $Sleep) { $Sleep = { param($s) Start-Sleep -Seconds $s } }
    try { Set-SIReturnRoute -Arm $Arm -Target $Target -Location $Location -Sleep $Sleep }
    catch { @{ Ok = $false; Own = $true; HandOff = $true; Changed = $false; Created = $false; Attached = $false; RouteTableId = ''; AddedRanges = @(); Conflicts = @(); Line = ('return route: {0} -- run again' -f $_.Exception.Message); Lines = @(('return route: {0}' -f $_.Exception.Message)) } }
}

function Get-SIPrivateNetworkReturnRouteCheck {
    <# READ ONLY (#1095, the install's end check): on a private install WITH the answers, is the route table attached to the
       apps subnet and does it send every range to the next hop? @{ Checked; Ok; Line; Fix }. Not read = not checked (never
       reported as missing). #>
    param([Parameter(Mandatory)][System.Collections.IDictionary]$Target, [scriptblock]$Arm, [string]$SubscriptionId)
    if (-not $Arm) { $Arm = { param([string]$Method, [string]$Path, $Body) if ($Method -eq 'GET') { Invoke-SIArm -Path $Path -AllowNotFound } else { Invoke-SIArm -Method $Method -Path $Path -Body $Body } } }
    $f = Get-SIReturnRouteFacts -Arm $Arm -Target $Target
    if (-not $f.Answers -or -not $f.SubnetRead) { return @{ Checked = $false; Ok = $true; Line = ''; Fix = '' } }
    if ($f.RouteTableId -and $f.Covered) { return @{ Checked = $true; Ok = $true; Line = ('the return route is in place: route table {0} on {1} sends {2} to {3}' -f $f.RouteTableName, $f.SubnetName, (@($f.Ranges) -join ', '), $f.NextHop); Fix = '' } }
    $what = if (-not $f.RouteTableId) { 'the apps subnet {0} has no route table' -f $f.SubnetName } else { 'the route table {0} on {1} has no route to {2} for {3}' -f $f.RouteTableName, $f.SubnetName, $f.NextHop, (@($f.Missing) -join ', ') }
    $fix = if ($f.Own) { './setup/Set-SIPrivateNetworking.ps1 -ResourceGroup {0} -VnetId {1} -ReturnRouteRanges {2} -ReturnRouteNextHop {3} -Apply -Steps return-route' -f $f.ResourceGroup, $f.VnetId, (@($f.Ranges) -join ','), $f.NextHop }
           else { 'your network team: the RETURN ROUTE item of the network hand-off (a route table on {0}: each range -> {1} as VirtualAppliance)' -f $f.SubnetName, $f.NextHop }
    @{ Checked = $true; Ok = $false; Line = ('{0} -- replies to your people''s ranges time out' -f $what); Fix = $fix }
}

function Get-SIUpdateReturnRouteReport {
    <# THE UPDATER'S CALL (#1095), REPORT ONLY: a PRIVATE install (Get-SIInstallPrivateState) whose apps subnet has no route
       table, or a table with neither a 0.0.0.0/0 route nor a VirtualAppliance route, is said as a warning -- NEVER made: the
       next hop is a customer value the updater cannot know. @{ Private; Warn; Line }. Never writes; never throws. #>
    param([Parameter(Mandatory)][scriptblock]$Arm, [Parameter(Mandatory)][string]$ResourceGroupId)
    try {
        $st = Get-SIInstallPrivateState -Arm $Arm -ResourceGroupId $ResourceGroupId
        if (-not $st.Private -or -not $st.SubnetId) { return @{ Private = [bool]$st.Private; Warn = $false; Line = '' } }
        $f = Get-SIReturnRouteFacts -Arm $Arm -Target ([ordered]@{ VnetId = $st.VnetId; AppsSubnetName = (($st.SubnetId -split '/')[-1]); ResourceGroupId = $ResourceGroupId })
        if (-not $f.SubnetRead) { return @{ Private = $true; Warn = $false; Line = ('return route: the apps subnet {0} could not be read -- not checked' -f $f.SubnetName) } }
        if ($f.RouteTableId -and $f.HasApplianceRoute) { return @{ Private = $true; Warn = $false; Line = ('return route: the apps subnet {0} has the route table {1}' -f $f.SubnetName, $f.RouteTableName) } }
        $why = if ($f.RouteTableId) { 'its route table {0} has no 0.0.0.0/0 or VirtualAppliance route' -f $f.RouteTableName } else { 'it has no route table' }
        @{ Private = $true; Warn = $true; Line = ('return route: the apps subnet {0} of this private install: {1}. Behind a firewall in a hub, replies to your people''s ranges time out. NOT changed by the updater (the firewall''s IP is yours): give the ranges and the firewall IP -- ./setup/Set-SIPrivateNetworking.ps1 -ReturnRouteRanges <range>[,<range>] -ReturnRouteNextHop <firewall private IP> -Apply -Steps return-route (SecurityInsight''s own network), or your network team adds the route (your network)' -f $f.SubnetName, $why) }
    } catch { @{ Private = $false; Warn = $false; Line = ('return route: not checked ({0})' -f $_.Exception.Message) } }
}

function Get-SIRegistryCloseProblem {
    <# PURE. Why the registry's public endpoint may NOT close yet ('' = it may): its private endpoint approved, and an agent
       pool of it provisioned in the network (PIM: refused until the registry has an approved private endpoint and the build
       pool runs in the VNet). Without both, the next image build -- the updater's -- has no way in. #>
    param($RegistryEndpoint, [object[]]$Pools = @(), [string]$VnetId = '')
    $why = @()
    if (-not ((Test-SIPnSucceeded $RegistryEndpoint) -and (Get-SIPrivateEndpointState $RegistryEndpoint) -eq 'Approved')) { $why += 'the registry''s private endpoint (pe-si-registry) is not there and approved -- run private-endpoints and private-dns' }
    if (-not @($Pools | Where-Object { Test-SIAcrAgentPoolInNetwork -Pool $_ -VnetId $VnetId }).Count) { $why += 'no agent pool of the registry runs in the network, so image builds could not reach a closed registry -- run registry-agent-pool' }
    $why -join '; '
}

# ============================================================================================================== THE REGISTRY, PRIVATE FROM BIRTH

# Framework installer rule 11b (Invardia 2026-11-04): "The container registry of a private install is private from birth
# too ... On a private install: Premium + private endpoint + the azurecr zone in the preflight from the first create, images
# built inside the network, admin user OFF, pulls by managed identity." Rule 11 (made general the same day): made, recovered
# OR FOUND, every resource of a private install ends private, read back. A registry an earlier release made Basic, public,
# admin user on (a customer's private install stopped before its image build, 2026-11-04) is CONVERGED to this shape.

function Get-SIPrivateRegistryBody {
    <# PURE. A private install's container registry as it is CREATED: Premium (a private endpoint needs it), public network
       access Disabled, trusted Azure services allowed (networkRuleBypassOptions AzureServices), the admin user OFF. #>
    param([Parameter(Mandatory)][string]$Location)
    [ordered]@{ location = $Location; sku = [ordered]@{ name = 'Premium' }; properties = [ordered]@{
        adminUserEnabled = $false; publicNetworkAccess = 'Disabled'; networkRuleBypassOptions = 'AzureServices' } }
}

function Get-SIRegistryPrivateGap {
    <# PURE. What keeps -Registry (as ARM returns it) from the private shape: a subset of 'sku', 'public', 'bypass', 'admin'
       (none = private). A registry that is not there has every gap. #>
    param($Registry)
    $gap = @()
    if ([string](Get-SIPnProp $Registry @('sku', 'name')) -ne 'Premium') { $gap += 'sku' }
    if ([string](Get-SIPnProp $Registry @('properties', 'publicNetworkAccess')) -ne 'Disabled') { $gap += 'public' }
    if ([string](Get-SIPnProp $Registry @('properties', 'networkRuleBypassOptions')) -ne 'AzureServices') { $gap += 'bypass' }
    if (-not $Registry -or [bool](Get-SIPnProp $Registry @('properties', 'adminUserEnabled'))) { $gap += 'admin' }
    $gap
}

function Get-SIRegistryPasswordUsers {
    <# PURE. The jobs / container apps (as ARM returns them) that sign in to the registry -LoginServer with its admin
       password (configuration.registries[].passwordSecretRef). Turning the admin user off would stop their pulls. #>
    param([object[]]$Apps = @(), [string]$LoginServer = '')
    $server = "$LoginServer".Trim().ToLowerInvariant()
    @(foreach ($a in @($Apps | Where-Object { $null -ne $_ })) {
        foreach ($r in @(Get-SIPnProp $a @('properties', 'configuration', 'registries') | Where-Object { $_ })) {
            $rs = ([string](Get-SIPnProp $r @('server'))).Trim().ToLowerInvariant()
            if ([string](Get-SIPnProp $r @('passwordSecretRef')) -and (-not $server -or -not $rs -or $rs -eq $server)) { [string](Get-SIPnProp $a @('name')); break }
        }
    })
}

function Set-SIPrivateRegistry {
    <#
        The container registry -RegistryId in its PRIVATE shape (Get-SIPrivateRegistryBody), idempotent, READ BACK:
          not there   created private (Premium, public access Disabled, trusted services allowed, admin user off)
          found       converged: the tier to Premium first (Azure takes publicNetworkAccess Disabled on Premium only), then
                      public access Disabled + trusted services allowed + the admin user off -- nothing in it changes
        -PasswordUsers: jobs / apps that still pull with the admin password -- the admin user then STAYS on (said, Ok false):
        it is never pulled out from under a running pull. Returns @{ Ok; Created; Changed; Gap; Line; Registry }.
    #>
    param([Parameter(Mandatory)][scriptblock]$Arm, [Parameter(Mandatory)][string]$RegistryId, [Parameter(Mandatory)][string]$Location,
          [string[]]$PasswordUsers = @(), [scriptblock]$Sleep = { param($s) Start-Sleep -Seconds $s })
    $path = '{0}?api-version={1}' -f $RegistryId.TrimEnd('/'), $script:SIPnAcrApi
    $name = ($RegistryId.TrimEnd('/') -split '/')[-1]
    $users = @($PasswordUsers | Where-Object { $_ })
    $have = & $Arm 'GET' $path $null
    $created = $false; $changed = @()
    if (-not $have) {
        $null = & $Arm 'PUT' $path (Get-SIPrivateRegistryBody -Location $Location)
        $created = $true
    } else {
        $gap = @(Get-SIRegistryPrivateGap $have)
        if ($gap -contains 'sku') {
            $null = & $Arm 'PATCH' $path ([ordered]@{ sku = [ordered]@{ name = 'Premium' } })
            $null = Read-SIPnBack -Arm $Arm -Path $path -Sleep $Sleep -Tries 12 -Test { param($o) [string](Get-SIPnProp $o @('sku', 'name')) -eq 'Premium' }
            $changed += 'Premium'
        }
        $props = [ordered]@{}
        if ($gap -contains 'public') { $props['publicNetworkAccess'] = 'Disabled'; $changed += 'public access Disabled' }
        if ($gap -contains 'bypass') { $props['networkRuleBypassOptions'] = 'AzureServices'; $changed += 'trusted Azure services allowed' }
        if ($gap -contains 'admin' -and -not $users.Count) { $props['adminUserEnabled'] = $false; $changed += 'admin user off' }
        if ($props.Count) { $null = & $Arm 'PATCH' $path ([ordered]@{ properties = $props }) }
    }
    $want = { param($o) $g = @(Get-SIRegistryPrivateGap $o); if ($users.Count) { $g = @($g | Where-Object { $_ -ne 'admin' }) }; $o -and -not $g.Count -and (Test-SIPnSucceeded $o) }
    $back = Read-SIPnBack -Arm $Arm -Path $path -Sleep $Sleep -Tries 30 -Test $want
    $left = @(Get-SIRegistryPrivateGap $back)
    $ok = [bool]($back -and -not $left.Count -and (Test-SIPnSucceeded $back))
    $what = 'Premium, public access Disabled, trusted Azure services allowed, admin user off'
    $line = if ($ok -and $created) { 'container registry {0} created private ({1}; read back)' -f $name, $what }
            elseif ($ok -and $changed.Count) { 'container registry {0} made private: {1} (read back: {2})' -f $name, ($changed -join ', '), $what }
            elseif ($ok) { 'container registry {0} is private ({1})' -f $name, $what }
            elseif (-not $back) { 'container registry {0} does not read back after it was created' -f $name }
            elseif ($left.Count -eq 1 -and $left[0] -eq 'admin' -and $users.Count) { 'container registry {0} is private, but its admin user STAYS ON: {1} still pull(s) with its password -- they must pull as their managed identity first' -f $name, ($users -join ', ') }
            else { 'container registry {0} does not read back private yet (still: {1})' -f $name, ($left -join ', ') }
    @{ Ok = $ok; Created = $created; Changed = @($changed); Gap = $left; Line = $line; Registry = $back }
}

function Get-SIRegistryDnsNames {
    <# PURE. The names of -Registry that its private endpoint answers for: the login server and the data endpoint of its
       region (<name>.<region>.data.azurecr.io -- the image layers come from there), or the data endpoints Azure names. #>
    param($Registry)
    if (-not $Registry) { return @() }
    $out = New-Object System.Collections.Generic.List[string]
    $ls = ([string](Get-SIPnProp $Registry @('properties', 'loginServer'))).Trim().ToLowerInvariant()
    $nm = ([string](Get-SIPnProp $Registry @('name'))).Trim().ToLowerInvariant()
    if (-not $ls -and $nm) { $ls = '{0}.azurecr.io' -f $nm }
    if ($ls) { $out.Add($ls) }
    $data = @(Get-SIPnProp $Registry @('properties', 'dataEndpointHostNames') | Where-Object { $_ } | ForEach-Object { ([string]$_).Trim().ToLowerInvariant() })
    if (-not $data.Count) {
        $loc = (([string](Get-SIPnProp $Registry @('location'))) -replace '\s', '').ToLowerInvariant()
        $short = if ($ls) { ($ls -split '\.')[0] } else { $nm }
        if ($short -and $loc) { $data = @('{0}.{1}.data.azurecr.io' -f $short, $loc) }
    }
    foreach ($d in $data) { if (-not $out.Contains($d)) { $out.Add($d) } }
    $out.ToArray()
}

function Invoke-SIPrivateNetworkRegistry {
    <#
        Setup's call AND the updater's (framework installer rule 11b; owner 2026-11-04: "if we have leftovers that are wrong,
        then we must handle that"): the registry of a private install private BEFORE its first image build --
          1. the registry created private, or a found one converged (Set-SIPrivateRegistry; the admin user stays on only
             while a job or app still pulls with its password, named);
          2. its private endpoint pe-si-registry + the privatelink.azurecr.io zone + link + zone group (the vault's and the
             storage's mechanism: a central group's zone is used, a write SecurityInsight may not make is a hand-off line);
          3. its agent pool in the network (si-vnet-pool, the endpoints subnet): image builds run inside it from the first;
          4. the DNS check FROM THIS MACHINE for the registry's names (login server + data endpoint) -- -SkipDnsGate for
             the updater, which runs inside the environment.
        Returns @{ Ok; Lines; HandOff; Gate; RegistryOk; NetworkShapeOk; EndpointsOk; PoolOk; AgentPool; LoginServer; PasswordUsers }.
    #>
    param([Parameter(Mandatory)][System.Collections.IDictionary]$Target, [Parameter(Mandatory)][string]$Location, [Parameter(Mandatory)][string]$RegistryId,
          [string]$EndpointsSubnetId = '', [scriptblock]$Resolve, [switch]$SkipDnsGate, [switch]$SkipAgentPool,
          # where a registry that is not there yet is created (the install's region); -Location is the endpoint's (the network's)
          [string]$RegistryLocation = '',
          [scriptblock]$Arm, [scriptblock]$Sleep, [string]$SubscriptionId)
    if (-not $Arm) { $Arm = { param([string]$Method, [string]$Path, $Body) if ($Method -eq 'GET') { Invoke-SIArm -Path $Path -AllowNotFound } else { Invoke-SIArm -Method $Method -Path $Path -Body $Body } } }
    if (-not $Sleep) { $Sleep = { param($s) Start-Sleep -Seconds $s } }
    if (-not $EndpointsSubnetId) { $EndpointsSubnetId = '{0}/subnets/{1}' -f ([string]$Target['VnetId']).TrimEnd('/'), [string]$Target['EndpointsSubnetName'] }
    $lines = New-Object System.Collections.Generic.List[string]; $handOff = New-Object System.Collections.Generic.List[string]
    $rg = ([string]$Target['ResourceGroupId']).TrimEnd('/')
    # who still pulls with the registry's password (an install from before the managed identity) -- read, never guessed
    $pulls = @()
    foreach ($t in 'Microsoft.App/jobs', 'Microsoft.App/containerApps') { $pulls += @(Get-SIPnArmList -Arm $Arm -Path ('{0}/providers/{1}?api-version={2}' -f $rg, $t, $script:SIPnAppApi)) }
    $regNow = & $Arm 'GET' ('{0}?api-version={1}' -f $RegistryId, $script:SIPnAcrApi) $null
    $users = @(Get-SIRegistryPasswordUsers -Apps $pulls -LoginServer ([string](Get-SIPnProp $regNow @('properties', 'loginServer'))))
    $regLoc = [string](Get-SIPnProp $regNow @('location')); if (-not $regLoc) { $regLoc = $(if ($RegistryLocation) { $RegistryLocation } else { $Location }) }
    $r = Set-SIPrivateRegistry -Arm $Arm -RegistryId $RegistryId -Location $regLoc -PasswordUsers $users -Sleep $Sleep
    $lines.Add($r.Line)
    $regOk = [bool]$r.Ok
    # the shape that matters for the network (Premium, closed) may be there while the admin user waits for a pull to move
    $netOk = $r.Registry -and -not @(@($r.Gap) | Where-Object { $_ -ne 'admin' }).Count
    $ep = @{ Ok = $false; Lines = @(); HandOff = @() }
    if ($netOk) { $ep = Set-SIPrivateEndpointsWithDns -Arm $Arm -Target $Target -Location $Location -EndpointsSubnetId $EndpointsSubnetId -RegistryId $RegistryId -Sleep $Sleep }
    foreach ($x in @($ep.Lines)) { $lines.Add($x) }; foreach ($x in @($ep.HandOff)) { $handOff.Add($x) }
    $poolName = (Get-SIPrivateNetworkNames).AgentPool
    $pool = @{ Ok = [bool]$SkipAgentPool; Line = ''; Blocked = $false; Step = '' }
    if ($netOk -and -not $SkipAgentPool) {
        # #1087: the build subnet's outbound path first -- SecurityInsight's own spoke (vnetAddressPrefix, no vnetId: CreateVnet)
        # gets it, a customer's network is never changed (the one customer step); never a pool that is certain to fail
        try { $pool = Invoke-SIAcrAgentPoolStep -Arm $Arm -RegistryId $RegistryId -Name $poolName -Location $regLoc -SubnetId $EndpointsSubnetId -OwnNetwork ([bool]$Target['CreateVnet']) -ResourceGroupId $rg -Sleep $Sleep }
        catch { $pool = @{ Ok = $false; Blocked = $false; Step = ''; Line = ('the registry''s agent pool {0} could not be made in the network: {1}' -f $poolName, $_.Exception.Message) } }
        if ([string]$pool.OutboundLine -and [string]$pool.OutboundLine -ne [string]$pool.Line) { $lines.Add([string]$pool.OutboundLine) }
        $lines.Add($pool.Line)
    }
    $gate = @{ Ok = $true; Lines = @(); Failed = @(); Records = @(); Names = @() }
    if (-not $SkipDnsGate -and $ep.Ok) {
        $gate = Invoke-SIPrivateNetworkDnsGate -Arm $Arm -Target $Target -RegistryId $RegistryId -Resolve $Resolve
        foreach ($x in @($gate.Lines)) { $lines.Add($x) }
    }
    @{ Ok = [bool]($netOk -and $ep.Ok -and $pool.Ok -and $gate.Ok); Lines = $lines.ToArray(); HandOff = $handOff.ToArray(); Gate = $gate
       RegistryOk = $regOk; NetworkShapeOk = [bool]$netOk; EndpointsOk = [bool]$ep.Ok; PoolOk = [bool]$pool.Ok
       PoolBlocked = [bool]$pool.Blocked; OutboundStep = [string]$pool.Step; AgentPool = $(if ($pool.Ok -and -not $SkipAgentPool) { $poolName } else { '' })
       LoginServer = [string](Get-SIPnProp $r.Registry @('properties', 'loginServer')); PasswordUsers = $users }
}

function Get-SIInstallPrivateState {
    <# READ ONLY. Is the install in -ResourceGroupId PRIVATE -- does the environment its jobs run in sit internal in a
       subnet? @{ Private; EnvironmentId; SubnetId; VnetId }. No job, or an environment that cannot be read = not private
       (nothing is changed for it). #>
    param([Parameter(Mandatory)][scriptblock]$Arm, [Parameter(Mandatory)][string]$ResourceGroupId)
    $no = @{ Private = $false; EnvironmentId = ''; SubnetId = ''; VnetId = '' }
    $jobs = @(Get-SIPnArmList -Arm $Arm -Path ('{0}/providers/Microsoft.App/jobs?api-version={1}' -f $ResourceGroupId.TrimEnd('/'), $script:SIPnAppApi))
    $envId = @($jobs | ForEach-Object { [string](Get-SIPnProp $_ @('properties', 'environmentId')) } | Where-Object { $_ } | Select-Object -Unique)[0]
    if (-not $envId) { return $no }
    $env = & $Arm 'GET' ('{0}?api-version={1}' -f $envId, $script:SIPnAppApi) $null
    if (-not (Test-SIEnvironmentPrivate -Environment $env)) { return $no }
    $sn = [string](Get-SIPnProp $env @('properties', 'vnetConfiguration', 'infrastructureSubnetId'))
    @{ Private = $true; EnvironmentId = $envId; SubnetId = $sn; VnetId = ($sn -replace '(?i)/subnets/[^/]+$', '') }
}

function Invoke-SIUpdatePrivateRegistry {
    <#
        THE UPDATER'S CALL (framework installer rule 11, general since 2026-11-04: made, recovered OR FOUND, every resource
        of a private install ends private, read back; the owner the same day: "if we have leftovers that are wrong, then we
        must handle that" -- existing installs reach the new-install state through the updater). Runs INSIDE the install's
        environment, so it checks name resolution from where the jobs pull. For a PRIVATE install only (Get-SIInstallPrivateState);
        a public install is not touched (rule 11b covers private installs; a public one keeps its Basic registry).
          1. the registry Premium (a private endpoint needs it; nothing in it changes);
          2. the admin user OFF -- only when no job or app still pulls with its password (they are named otherwise);
          3. its private endpoint pe-si-registry (+ zone, link, zone group) when it has none -- in the endpoints subnet of the
             install's other private endpoints;
          4. its agent pool in that subnet, so image builds run inside the network;
          5. public network access CLOSED (Disabled, trusted Azure services allowed) -- ONLY when 3 and 4 read back AND the
             registry's names resolve to private addresses HERE, inside (never a closed registry the jobs cannot reach).
        -WhatIf: the plan only. Never throws for a step it cannot make: said, the next update tries again.
        Returns @{ Private; Ok; Lines; Closed; Changed }.
    #>
    param([Parameter(Mandatory)][scriptblock]$Arm, [Parameter(Mandatory)][string]$ResourceGroupId, [Parameter(Mandatory)][string]$RegistryId,
          [scriptblock]$Resolve, [switch]$WhatIf, [scriptblock]$Sleep = { param($s) Start-Sleep -Seconds $s })
    $lines = New-Object System.Collections.Generic.List[string]; $changed = New-Object System.Collections.Generic.List[string]
    $st = Get-SIInstallPrivateState -Arm $Arm -ResourceGroupId $ResourceGroupId
    if (-not $st.Private) { return @{ Private = $false; Ok = $true; Lines = @(); Closed = $false; Changed = @() } }
    $rgId = $ResourceGroupId.TrimEnd('/')
    $regPath = '{0}?api-version={1}' -f $RegistryId.TrimEnd('/'), $script:SIPnAcrApi
    $reg = & $Arm 'GET' $regPath $null
    $name = ($RegistryId.TrimEnd('/') -split '/')[-1]
    if (-not $reg) { return @{ Private = $true; Ok = $false; Lines = @(('container registry {0} was not found' -f $name)); Closed = $false; Changed = @() } }
    $gap = @(Get-SIRegistryPrivateGap $reg)
    # #1087: a private registry whose agent pool does not run (Azure left it Failed -- e.g. a build subnet without an
    # outbound path) is not done: it goes on to the pool step (the outbound check first), so the next build has its pool
    $poolNow = & $Arm 'GET' ('{0}/agentPools/{1}?api-version={2}' -f $RegistryId.TrimEnd('/'), (Get-SIPrivateNetworkNames).AgentPool, $script:SIPnAcrTasksApi) $null
    if (-not $gap.Count -and (Test-SIPnSucceeded $poolNow)) { return @{ Private = $true; Ok = $true; Lines = @(('container registry {0} is private (Premium, public access Disabled, trusted Azure services allowed, admin user off)' -f $name)); Closed = $true; Changed = @() } }
    $pulls = @()
    foreach ($t in 'Microsoft.App/jobs', 'Microsoft.App/containerApps') { $pulls += @(Get-SIPnArmList -Arm $Arm -Path ('{0}/providers/{1}?api-version={2}' -f $rgId, $t, $script:SIPnAppApi)) }
    $users = @(Get-SIRegistryPasswordUsers -Apps $pulls -LoginServer ([string](Get-SIPnProp $reg @('properties', 'loginServer'))))
    $prefix = (Get-SIPrivateNetworkNames).EndpointPrefix
    $peOf = { param($k) & $Arm 'GET' ('{0}/providers/Microsoft.Network/privateEndpoints/{1}{2}?api-version={3}' -f $rgId, $prefix, $k, $script:SIPnNetApi) $null }
    $regPe = & $peOf 'registry'
    # the endpoints subnet: the one the registry's endpoint -- else the vault's, the storage's -- sits in (the install made them)
    $peSubnet = ''
    foreach ($k in 'registry', 'vault', 'blob', 'sql') { $p = $(if ($k -eq 'registry') { $regPe } else { & $peOf $k }); $s = [string](Get-SIPnProp $p @('properties', 'subnet', 'id')); if ($s) { $peSubnet = $s; break } }
    if ($WhatIf) {
        $plan = @()
        if ($gap -contains 'sku') { $plan += 'Premium' }
        if ($gap -contains 'admin') { $plan += $(if ($users.Count) { 'admin user stays on ({0} pull with its password)' -f ($users -join ', ') } else { 'admin user off' }) }
        if (-not $regPe) { $plan += 'its private endpoint' }
        if ($peSubnet) { $ob = Set-SIBuildSubnetOutbound -Arm $Arm -SubnetId $peSubnet -ResourceGroupId $rgId -ReportOnly; if (-not $ob.Path -and ($ob.Blocked -or $ob.Line -match 'would get')) { $plan += $ob.Line } }
        $plan += 'its agent pool in the network'
        if ($gap -contains 'public' -or $gap -contains 'bypass') { $plan += 'public access closed once its names resolve to private addresses inside' }
        return @{ Private = $true; Ok = $true; Lines = @(('container registry {0} would be made private: {1}' -f $name, ($plan -join '; '))); Closed = $false; Changed = @() }
    }
    $ok = $true
    try {
        if ($gap -contains 'sku') { $x = Set-SIRegistrySku -Arm $Arm -RegistryId $RegistryId -Sku 'Premium' -Sleep $Sleep; $lines.Add($x.Line); if ($x.Ok) { $changed.Add('Premium') } else { $ok = $false } }
        if ($gap -contains 'admin') {
            if ($users.Count) { $lines.Add(('container registry {0}: its admin user STAYS ON -- {1} still pull(s) with its password (they must pull as their managed identity first)' -f $name, ($users -join ', '))); $ok = $false }
            else {
                $null = & $Arm 'PATCH' $regPath ([ordered]@{ properties = [ordered]@{ adminUserEnabled = $false } })
                $back = Read-SIPnBack -Arm $Arm -Path $regPath -Sleep $Sleep -Tries 12 -Test { param($o) $o -and -not [bool](Get-SIPnProp $o @('properties', 'adminUserEnabled')) }
                if (-not [bool](Get-SIPnProp $back @('properties', 'adminUserEnabled'))) { $lines.Add(('container registry {0}: admin user off (read back)' -f $name)); $changed.Add('admin user off') } else { $lines.Add(('container registry {0}: the admin user still reads on after the change' -f $name)); $ok = $false }
            }
        }
        if (-not $peSubnet) {
            $lines.Add(('container registry {0}: no private endpoint of this install was found to place its own beside -- its public access stays as it is (Invardia support: setup\Set-SIPrivateNetworking.ps1 -Steps private-endpoints,private-dns,registry-agent-pool,registry-public-off)' -f $name))
            return @{ Private = $true; Ok = $false; Lines = $lines.ToArray(); Closed = $false; Changed = $changed.ToArray() }
        }
        $vnet = $peSubnet -replace '(?i)/subnets/[^/]+$', ''
        $target = Get-SIInstallPrivateNetworkTarget -Values ([ordered]@{ vnetId = $vnet; endpointsSubnetName = (($peSubnet -split '/')[-1]) }) -ResourceGroupId $rgId
        $regLoc = [string](Get-SIPnProp $reg @('location'))
        if (-not ((Test-SIPnSucceeded $regPe) -and (Get-SIPrivateEndpointState $regPe) -eq 'Approved')) {
            $vnetObj = & $Arm 'GET' ('{0}?api-version={1}' -f $vnet, $script:SIPnNetApi) $null
            $peLoc = [string](Get-SIPnProp $vnetObj @('location')); if (-not $peLoc) { $peLoc = $regLoc }
            $ep = Set-SIPrivateEndpointsWithDns -Arm $Arm -Target $target -Location $peLoc -EndpointsSubnetId $peSubnet -RegistryId $RegistryId -Sleep $Sleep
            foreach ($l in @($ep.Lines)) { $lines.Add($l) }
            if ($ep.Ok) { $changed.Add('private endpoint') } else { $ok = $false }
            $regPe = & $peOf 'registry'
        }
        # #1087: the same outbound check as setup before the pool (own spoke = read from the network: in this resource
        # group, tagged by SecurityInsight); a customer's subnet without a path is REPORTED, the update goes on
        $pool = Invoke-SIAcrAgentPoolStep -Arm $Arm -RegistryId $RegistryId -Name (Get-SIPrivateNetworkNames).AgentPool -Location $regLoc -SubnetId $peSubnet -ResourceGroupId $rgId -Sleep $Sleep
        if ([string]$pool.OutboundLine -and [string]$pool.OutboundLine -ne [string]$pool.Line) { $lines.Add([string]$pool.OutboundLine); if ($pool.OutboundLine -match 'turned on') { $changed.Add('build subnet outbound') } }
        $lines.Add($pool.Line); if ($pool.Created -and $pool.Ok) { $changed.Add('agent pool') }; if (-not $pool.Ok) { $ok = $false }
        $closed = $false
        if ($gap -contains 'public' -or $gap -contains 'bypass') {
            $why = Get-SIRegistryCloseProblem -RegistryEndpoint $regPe -Pools @(& $Arm 'GET' ('{0}/agentPools/{1}?api-version={2}' -f $RegistryId.TrimEnd('/'), (Get-SIPrivateNetworkNames).AgentPool, $script:SIPnAcrTasksApi) $null) -VnetId $vnet
            $names = @(Get-SIRegistryDnsNames -Registry (& $Arm 'GET' $regPath $null))
            $res = Test-SIInsideResolution -Names $names -Resolve $Resolve
            if ($why) { $lines.Add(('container registry {0}: its public access stays open for now -- {1}' -f $name, $why)); $ok = $false }
            elseif (-not $res.Ok) {
                $lines.Add(('container registry {0}: its public access stays open for now -- its names do not resolve to private addresses inside the network yet ({1}); the network hand-off lists the records' -f $name, (@($res.Failed) -join ', ')))
                $ok = $false
            } elseif ($gap -contains 'public') {
                $c = Set-SIPublicAccess -Arm $Arm -ResourceId $RegistryId -Sleep $Sleep
                $lines.Add($c.Line); if ($c.Ok) { $closed = $true; $changed.Add('public access closed') } else { $ok = $false }
            } else {
                # closed already, only trusted Azure services not allowed yet
                $null = & $Arm 'PATCH' $regPath ([ordered]@{ properties = [ordered]@{ networkRuleBypassOptions = 'AzureServices' } })
                $b2 = Read-SIPnBack -Arm $Arm -Path $regPath -Sleep $Sleep -Tries 12 -Test { param($o) [string](Get-SIPnProp $o @('properties', 'networkRuleBypassOptions')) -eq 'AzureServices' }
                $closed = [string](Get-SIPnProp $b2 @('properties', 'networkRuleBypassOptions')) -eq 'AzureServices'
                $lines.Add(('container registry {0}: trusted Azure services allowed{1}' -f $name, $(if ($closed) { ' (read back)' } else { ' -- NOT after the change' }))); if (-not $closed) { $ok = $false }
            }
        } else { $closed = $true }
    } catch { $lines.Add(('container registry {0}: {1} -- the next update tries again' -f $name, $_.Exception.Message)); $ok = $false; $closed = $false }
    @{ Private = $true; Ok = $ok; Lines = $lines.ToArray(); Closed = $closed; Changed = $changed.ToArray() }
}

# ============================================================================================================== THE IN-NETWORK SQL IDENTITY

function Set-SISqlIdentity {
    <# The in-network SQL identity (user-assigned, -Name, default id-si-sql) in -ResourceGroupId, idempotent, READ BACK until
       Azure shows its principal and client id. Returns @{ Ok; Line; Id; PrincipalId; ClientId; Created }. #>
    param([Parameter(Mandatory)][scriptblock]$Arm, [Parameter(Mandatory)][string]$ResourceGroupId, [Parameter(Mandatory)][string]$Location,
          [string]$Name = '', [scriptblock]$Sleep = { param($s) Start-Sleep -Seconds $s })
    if (-not $Name) { $Name = (Get-SIPrivateNetworkNames).SqlIdentity }
    $id = '{0}/providers/Microsoft.ManagedIdentity/userAssignedIdentities/{1}' -f $ResourceGroupId.TrimEnd('/'), $Name
    $path = '{0}?api-version={1}' -f $id, $script:SIPnMiApi
    $have = & $Arm 'GET' $path $null
    if (-not $have) { $null = & $Arm 'PUT' $path ([ordered]@{ location = $Location; tags = [ordered]@{ purpose = 'securityinsight-sql-in-network' } }) }
    $back = Read-SIPnBack -Arm $Arm -Path $path -Sleep $Sleep -Tries 12 -PauseSeconds 5 -Test { param($o) [string](Get-SIPnProp $o @('properties', 'principalId')) -and [string](Get-SIPnProp $o @('properties', 'clientId')) }
    $pid_ = [string](Get-SIPnProp $back @('properties', 'principalId')); $cid = [string](Get-SIPnProp $back @('properties', 'clientId'))
    @{ Ok = [bool]($pid_ -and $cid); Created = (-not $have); Id = $id; PrincipalId = $pid_; ClientId = $cid
       Line = $(if ($pid_ -and $cid) { 'the in-network SQL identity {0}{1} (client {2}; read back)' -f $Name, $(if ($have) { ' is there' } else { '' }), $cid } else { 'the in-network SQL identity {0} does not read back with its ids' -f $Name }) }
}

# ============================================================================================================== THE ENVIRONMENT

function Get-SIPrivateEnvironmentBody {
    <# PURE. A Container Apps environment in -SubnetId, INTERNAL (no public address), the Consumption workload profile,
       logs through Azure Monitor (the diagnostic setting sends them to the install's workspace). #>
    param([Parameter(Mandatory)][string]$Location, [Parameter(Mandatory)][string]$SubnetId)
    [ordered]@{ location = $Location; properties = [ordered]@{
        appLogsConfiguration = [ordered]@{ destination = 'azure-monitor' }
        vnetConfiguration    = [ordered]@{ infrastructureSubnetId = $SubnetId; internal = $true }
        workloadProfiles     = @([ordered]@{ name = 'Consumption'; workloadProfileType = 'Consumption' }) } }
}

function Test-SIEnvironmentPrivate {
    <# PURE. Is -Environment in -SubnetId (any subnet when not given) and internal? #>
    param($Environment, [string]$SubnetId = '')
    $s = [string](Get-SIPnProp $Environment @('properties', 'vnetConfiguration', 'infrastructureSubnetId'))
    if (-not $s) { return $false }
    if ($SubnetId -and -not (Test-SIPnSameId $s $SubnetId)) { return $false }
    [bool](Get-SIPnProp $Environment @('properties', 'vnetConfiguration', 'internal'))
}

function Set-SIPrivateEnvironment {
    <# The private Container Apps environment -Name in -ResourceGroupId, idempotent, READ BACK until Azure has made it (up
       to 30 minutes). An environment of that name that is NOT private is never changed (it is said). Its logs get the same
       diagnostic settings as -LogsLikeId (the environment the install runs in now). Returns @{ Ok; Line; Environment; Created }. #>
    param([Parameter(Mandatory)][scriptblock]$Arm, [Parameter(Mandatory)][string]$ResourceGroupId, [Parameter(Mandatory)][string]$Name,
          [Parameter(Mandatory)][string]$Location, [Parameter(Mandatory)][string]$SubnetId, [string]$LogsLikeId = '', [scriptblock]$Sleep = { param($s) Start-Sleep -Seconds $s })
    $id = '{0}/providers/Microsoft.App/managedEnvironments/{1}' -f $ResourceGroupId.TrimEnd('/'), $Name
    $path = '{0}?api-version={1}' -f $id, $script:SIPnAppApi
    $have = & $Arm 'GET' $path $null
    if ($have -and -not (Test-SIEnvironmentPrivate -Environment $have -SubnetId $SubnetId)) {
        return @{ Ok = $false; Created = $false; Environment = $have; Line = ('the Container Apps environment {0} exists but is not in the subnet as an internal environment -- it is not changed' -f $Name) }
    }
    if ($have -and (Test-SIPnSucceeded $have)) { return @{ Ok = $true; Created = $false; Environment = $have; Line = ('the private Container Apps environment {0} is there' -f $Name) } }
    if (-not $have) { $null = & $Arm 'PUT' $path (Get-SIPrivateEnvironmentBody -Location $Location -SubnetId $SubnetId) }
    $back = Read-SIPnBack -Arm $Arm -Path $path -Sleep $Sleep -Tries 120 -PauseSeconds 15 -Test { param($o) [string](Get-SIPnProp $o @('properties', 'provisioningState')) -in 'Succeeded', 'Failed', 'Canceled' }
    $ok = Test-SIPnSucceeded $back
    $lines = @()
    if ($ok -and $LogsLikeId) { $lines += (Copy-SIDiagnosticSettings -Arm $Arm -FromId $LogsLikeId -ToId $id).Line }
    @{ Ok = [bool]$ok; Created = (-not $have); Environment = $back
       Line = $(if ($ok) { (@(('the private Container Apps environment {0} (internal, in the subnet; read back)' -f $Name)) + $lines) -join '; ' } else { 'Azure did not make the environment {0} (it shows: {1})' -f $Name, [string](Get-SIPnProp $back @('properties', 'provisioningState')) }) }
}

function Copy-SIDiagnosticSettings {
    <# The diagnostic settings of -FromId put on -ToId (same names, same destinations), each read back. Returns @{ Ok; Line }. #>
    param([Parameter(Mandatory)][scriptblock]$Arm, [Parameter(Mandatory)][string]$FromId, [Parameter(Mandatory)][string]$ToId)
    $from = @(Get-SIPnArmList -Arm $Arm -Path ('{0}/providers/Microsoft.Insights/diagnosticSettings?api-version={1}' -f $FromId.TrimEnd('/'), $script:SIPnDiagApi))
    if (-not $from.Count) { return @{ Ok = $true; Line = 'no diagnostic setting to carry over' } }
    $done = @()
    foreach ($d in $from) {
        $n = [string](Get-SIPnProp $d @('name')); if (-not $n) { continue }
        $p = '{0}/providers/Microsoft.Insights/diagnosticSettings/{1}?api-version={2}' -f $ToId.TrimEnd('/'), $n, $script:SIPnDiagApi
        $null = & $Arm 'PUT' $p ([ordered]@{ properties = (ConvertTo-SIPnHashtable (Get-SIPnProp $d @('properties'))) })
        if (& $Arm 'GET' $p $null) { $done += $n }
    }
    @{ Ok = ($done.Count -eq $from.Count); Line = ('its logs go where the current environment''s go ({0})' -f ($done -join ', ')) }
}

function Get-SIEnvironmentDnsRecordNames {
    <# PURE. The A records of the environment's own zone, each -> its static IP (PIM's Get-PimPrivateDnsPlan): '@' the zone
       apex, '*' every app's name, '*.internal' the environment-internal ingress names (<app>.internal.<domain>) -- a
       wildcard matches ONE label, so '*' alone leaves those unresolved. #>
    @('@', '*', '*.internal')
}

function Get-SIEnvironmentDnsMissing {
    <# READ ONLY. What the environment's own zone still lacks in -ZoneResourceGroupId: the zone, a record, a link to one of
       -LinkVnetIds (matched by the network). @() = complete. #>
    param([Parameter(Mandatory)][scriptblock]$Arm, [Parameter(Mandatory)][string]$ZoneResourceGroupId, $Environment, [string[]]$LinkVnetIds = @())
    $domain = [string](Get-SIPnProp $Environment @('properties', 'defaultDomain')); $ip = [string](Get-SIPnProp $Environment @('properties', 'staticIp'))
    if (-not $domain -or -not $ip) { return @('the environment shows no default domain or internal address yet') }
    $zid = '{0}/providers/Microsoft.Network/privateDnsZones/{1}' -f $ZoneResourceGroupId.TrimEnd('/'), $domain
    if (-not (& $Arm 'GET' ('{0}?api-version={1}' -f $zid, $script:SIPnDnsApi) $null)) { return @(('the zone {0}' -f $domain)) }
    $miss = New-Object System.Collections.Generic.List[string]
    foreach ($rec in (Get-SIEnvironmentDnsRecordNames)) {
        $have = & $Arm 'GET' ('{0}/A/{1}?api-version={2}' -f $zid, $rec, $script:SIPnDnsApi) $null
        if (@(Get-SIPnProp $have @('properties', 'aRecords') | Where-Object { $_ } | ForEach-Object { [string](Get-SIPnProp $_ @('ipv4Address')) }) -notcontains $ip) { $miss.Add(('the record {0} -> {1}' -f $rec, $ip)) }
    }
    $links = @(Get-SIPnArmList -Arm $Arm -Path ('{0}/virtualNetworkLinks?api-version={1}' -f $zid, $script:SIPnDnsApi))
    foreach ($v in @($LinkVnetIds | Where-Object { $_ })) {
        if (-not @($links | Where-Object { Test-SIPnSameId ([string](Get-SIPnProp $_ @('properties', 'virtualNetwork', 'id'))) $v }).Count) { $miss.Add(('the link to {0}' -f ($v -split '/')[-1])) }
    }
    $miss.ToArray()
}

function Set-SIEnvironmentDns {
    <# An internal environment's addresses resolve in the virtual network: the private DNS zone of its default domain, the
       records '@', '*' and '*.internal' -> its internal address, linked to SecurityInsight's network -- and to the customer's
       hub network ONLY when -HubVnetId is given (#866: the callers pass it only when the customer turned linkZonesToHub on
       and the rights read back: by default SecurityInsight writes nothing on the hub) -- each network once. A hub link SecurityInsight may not write is a
       hand-off line (HandOff), never a failure. Each read back. Returns @{ Ok; Lines; ZoneId; Created; Domain; StaticIp;
       LinksCreated; HandOff }. #>
    param([Parameter(Mandatory)][scriptblock]$Arm, [Parameter(Mandatory)][string]$ZoneResourceGroupId, [Parameter(Mandatory)]$Environment,
          [Parameter(Mandatory)][string]$VnetId, [string]$HubVnetId = '', [scriptblock]$Sleep = { param($s) Start-Sleep -Seconds $s })
    $domain = [string](Get-SIPnProp $Environment @('properties', 'defaultDomain'))
    $ip = [string](Get-SIPnProp $Environment @('properties', 'staticIp'))
    if (-not $domain -or -not $ip) { return @{ Ok = $false; ZoneId = ''; Created = $false; Domain = $domain; StaticIp = $ip; LinksCreated = @(); HandOff = @(); Lines = @('the environment shows no default domain or internal address yet -- run again in a few minutes') } }
    $lines = New-Object System.Collections.Generic.List[string]
    # #866 item 6: SecurityInsight's own zone -- or the one of that name the network is already linked to (never two)
    $zr = Resolve-SIPrivateDnsZone -Arm $Arm -Zone $domain -ResourceGroupId $ZoneResourceGroupId -VnetId $VnetId -SubscriptionIds (Get-SIZoneSearchSubscriptions @($ZoneResourceGroupId, $VnetId)) -Sleep $Sleep
    $z = @{ Ok = $zr.Ok; Id = $zr.ZoneId; Created = $zr.Created; Line = $zr.Line }; $lines.Add($z.Line)
    $ok = [bool]$z.Ok
    foreach ($rec in (Get-SIEnvironmentDnsRecordNames)) {
        $p = '{0}/A/{1}?api-version={2}' -f $z.Id, $rec, $script:SIPnDnsApi
        $have = & $Arm 'GET' $p $null
        $ips = @(Get-SIPnProp $have @('properties', 'aRecords') | Where-Object { $_ } | ForEach-Object { [string](Get-SIPnProp $_ @('ipv4Address')) })
        if ($ips -contains $ip) { $lines.Add(('{0} {1} -> {2}' -f $rec, $domain, $ip)); continue }
        $null = & $Arm 'PUT' $p ([ordered]@{ properties = [ordered]@{ ttl = 3600; aRecords = @([ordered]@{ ipv4Address = $ip }) } })
        $back = & $Arm 'GET' $p $null
        $bi = @(Get-SIPnProp $back @('properties', 'aRecords') | Where-Object { $_ } | ForEach-Object { [string](Get-SIPnProp $_ @('ipv4Address')) })
        if ($bi -contains $ip) { $lines.Add(('{0} {1} -> {2} (read back)' -f $rec, $domain, $ip)) } else { $ok = $false; $lines.Add(('the record {0} of {1} does not read back' -f $rec, $domain)) }
    }
    $made = New-Object System.Collections.Generic.List[string]; $hand = New-Object System.Collections.Generic.List[string]
    foreach ($v in @(Get-SIDnsLinkVnetIds -VnetId $VnetId -HubVnetId $HubVnetId)) {
        $isHub = [bool]($HubVnetId -and (Test-SIPnSameId $v $HubVnetId) -and -not (Test-SIPnSameId $v $VnetId))
        $l = Set-SIPrivateDnsLink -Arm $Arm -ZoneId $z.Id -VnetId $v -HandOffOnError:$isHub -Sleep $Sleep; $lines.Add($l.Line)
        if ($l.Created) { $made.Add([string]$l.Id) }
        if ($l.HandOff) { $hand.Add($l.Line) } elseif (-not $l.Ok) { $ok = $false }
    }
    @{ Ok = $ok; Lines = $lines.ToArray(); ZoneId = $z.Id; Created = [bool]$z.Created; Domain = $domain; StaticIp = $ip; LinksCreated = $made.ToArray(); HandOff = $hand.ToArray() }
}

# ============================================================================================================== THE INSIDE CHECK
# #866 (PIM: Convert-PimToPrivate verify-inside, exit 10 until it passes): the public endpoints close only once the names
# SecurityInsight and its users need resolve to PRIVATE addresses from inside -- from the machine that runs the install /
# cut-over when it is inside, else from a one-time job in the install's own environment (the support SQL job's pattern).
# A spoke whose virtual network asks the hub's DNS resolver (custom DNS servers) does NOT see SecurityInsight's spoke-linked
# zones until the hub side is done: closing then would leave a database nothing can reach -- SecurityInsight's own jobs
# included. Refused unless the check passes or the operator confirms it from inside (-ConfirmedFromInside).

function Test-SIPrivateIpv4 {
    <# PURE. Is -Ip an RFC1918 IPv4 address (10/8, 172.16/12, 192.168/16)? #>
    param([AllowNull()][string]$Ip)
    $m = [regex]::Match("$Ip".Trim(), '^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$')
    if (-not $m.Success) { return $false }
    $a = [int]$m.Groups[1].Value; $b = [int]$m.Groups[2].Value
    foreach ($g in 1..4) { if ([int]$m.Groups[$g].Value -gt 255) { return $false } }
    ($a -eq 10) -or ($a -eq 172 -and $b -ge 16 -and $b -le 31) -or ($a -eq 192 -and $b -eq 168)
}

function Get-SIPnHost { param([AllowNull()][string]$Url) $u = "$Url".Trim(); if (-not $u) { return '' }; ($u -replace '^[a-z]+://', '' -split '[/:]')[0].ToLowerInvariant() }

function Get-SIInsideCheckNames {
    <# PURE. The names that must resolve to private addresses before the public endpoints close: the web app's (and every
       app's) address, the database server, the Key Vault and the storage account's blob / queue / table endpoints -- each
       from what Azure says about the resource, each once. #>
    param([string[]]$AppFqdns = @(), $SqlServer, $Vault, $Storage,
          # rule 11b: the container registry's login server and data endpoint (Get-SIRegistryDnsNames)
          $Registry)
    $out = New-Object System.Collections.Generic.List[string]
    $add = { param($n) $h = Get-SIPnHost $n; if ($h -and -not $out.Contains($h)) { $out.Add($h) } }
    foreach ($f in @($AppFqdns)) { & $add $f }
    foreach ($f in @(Get-SIRegistryDnsNames -Registry $Registry)) { & $add $f }
    & $add ([string](Get-SIPnProp $SqlServer @('properties', 'fullyQualifiedDomainName')))
    & $add ([string](Get-SIPnProp $Vault @('properties', 'vaultUri')))
    if ($Storage) {
        $sn = [string](Get-SIPnProp $Storage @('name'))
        foreach ($k in 'blob', 'queue', 'table') {
            $e = [string](Get-SIPnProp $Storage @('properties', 'primaryEndpoints', $k))
            if (-not $e -and $sn) { $e = '{0}.{1}.core.windows.net' -f $sn, $k }
            & $add $e
        }
    }
    $out.ToArray()
}

function Test-SIInsideResolution {
    <# Do -Names resolve to private addresses HERE (the machine this runs on)? -Resolve { param([string]$Name) } returns the
       addresses (default: the system resolver). A name passes when it resolves and every IPv4 address it has is RFC1918.
       Returns @{ Ok; Lines; Failed }. Read-only. #>
    param([string[]]$Names = @(), [scriptblock]$Resolve)
    if (-not $Resolve) { $Resolve = { param([string]$Name) @([System.Net.Dns]::GetHostAddresses($Name) | ForEach-Object { $_.IPAddressToString }) } }
    $lines = New-Object System.Collections.Generic.List[string]; $failed = New-Object System.Collections.Generic.List[string]
    foreach ($n in @($Names | Where-Object { $_ })) {
        $ips = @(); try { $ips = @(& $Resolve $n | Where-Object { $_ } | ForEach-Object { [string]$_ }) } catch { $ips = @() }
        $v4 = @($ips | Where-Object { $_ -match '^\d{1,3}(\.\d{1,3}){3}$' })
        if ($v4.Count -and -not @($v4 | Where-Object { -not (Test-SIPrivateIpv4 $_) }).Count) { $lines.Add(('{0} -> {1} (private)' -f $n, ($v4 -join ', '))) }
        else { $failed.Add($n); $lines.Add(('{0} -> {1}' -f $n, $(if ($ips.Count) { ($ips -join ', ') + ' -- NOT a private address' } else { 'does not resolve' }))) }
    }
    @{ Ok = [bool](@($Names | Where-Object { $_ }).Count -and -not $failed.Count); Lines = $lines.ToArray(); Failed = $failed.ToArray() }
}

function Get-SIInsideCheckJobScript {
    <# PURE. What the one-time inside-check job runs (PowerShell 7 in the engine image): resolve each name of
       SI_INSIDE_NAMES, one line per name, exit 0 only when every name resolves to private (RFC1918) addresses. #>
    $fn = (Get-Command -Name Test-SIPrivateIpv4 -CommandType Function).ScriptBlock.ToString()
    (@('$ErrorActionPreference = ''Stop''', ('function Test-SIPrivateIpv4 {{{0}}}' -f $fn), @'
$names = @(([string]$env:SI_INSIDE_NAMES) -split ';' | ForEach-Object { $_.Trim() } | Where-Object { $_ })
$bad = 0
foreach ($n in $names) {
    $ips = @(); try { $ips = @([System.Net.Dns]::GetHostAddresses($n) | ForEach-Object { $_.IPAddressToString }) } catch { $ips = @() }
    $v4 = @($ips | Where-Object { $_ -match '^\d{1,3}(\.\d{1,3}){3}$' })
    $ok = $v4.Count -and -not @($v4 | Where-Object { -not (Test-SIPrivateIpv4 $_) }).Count
    if (-not $ok) { $bad++ }
    Write-Output ('[insidecheck] {0} -> {1} {2}' -f $n, ($ips -join ','), $(if ($ok) { 'private' } else { 'NOT PRIVATE' }))
}
if (-not $names.Count) { Write-Output '[insidecheck] no names given'; exit 1 }
if ($bad) { exit 1 } else { exit 0 }
'@)) -join "`n"
}

function Get-SIInsideCheckJobBody {
    <# PURE. The one-time job: manual trigger, one replica, no retry, ONLY the identity the image is pulled with, tagged
       as a one-time job; the names in SI_INSIDE_NAMES. #>
    param([Parameter(Mandatory)][string]$Location, [Parameter(Mandatory)][string]$EnvironmentId, [Parameter(Mandatory)][string]$Image,
          [Parameter(Mandatory)][string]$RegistryServer, [Parameter(Mandatory)][string]$PullIdentityId, [Parameter(Mandatory)][string[]]$Names, [int]$TimeoutSeconds = 300)
    $ua = [ordered]@{}; $ua[$PullIdentityId] = [ordered]@{}
    $cmd = @('pwsh', '-NoProfile', '-NonInteractive', '-EncodedCommand', [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes((Get-SIInsideCheckJobScript))))
    [ordered]@{
        location = $Location; tags = [ordered]@{ 'si-one-time-job' = 'inside-check' }
        identity = [ordered]@{ type = 'UserAssigned'; userAssignedIdentities = $ua }
        properties = [ordered]@{
            environmentId = $EnvironmentId
            configuration = [ordered]@{ triggerType = 'Manual'; replicaTimeout = $TimeoutSeconds; replicaRetryLimit = 0
                                        manualTriggerConfig = [ordered]@{ parallelism = 1; replicaCompletionCount = 1 }
                                        registries = @([ordered]@{ server = $RegistryServer; identity = $PullIdentityId }) }
            template = [ordered]@{ containers = @([ordered]@{ name = 'insidecheck'; image = $Image; command = $cmd; resources = [ordered]@{ cpu = 0.25; memory = '0.5Gi' }
                                                              env = @([ordered]@{ name = 'SI_INSIDE_NAMES'; value = (@($Names) -join ';') }) }) }
        }
    }
}

function Get-SIInsideCheckJobPlan {
    <# READ ONLY. What the one-time inside-check job takes from an install job in -EnvironmentId: its image, its registry
       and the user-assigned identity it pulls with (never a password, never another identity). @{ Ok; Problem; ... }. #>
    param([Parameter(Mandatory)][scriptblock]$Arm, [Parameter(Mandatory)][string]$ResourceGroupId, [Parameter(Mandatory)][string]$EnvironmentId, [string]$JobName = '')
    if (-not $JobName) { $JobName = (Get-SIPrivateNetworkNames).InsideCheckJob }
    $p = [ordered]@{ Ok = $false; Problem = ''; JobName = $JobName; JobId = ('{0}/providers/Microsoft.App/jobs/{1}' -f $ResourceGroupId.TrimEnd('/'), $JobName)
                     EnvironmentId = $EnvironmentId; Location = ''; Image = ''; RegistryServer = ''; PullIdentityId = ''; Leftover = $false }
    $jobs = @(Get-SIPnArmList -Arm $Arm -Path ('{0}/providers/Microsoft.App/jobs?api-version={1}' -f $ResourceGroupId.TrimEnd('/'), $script:SIPnAppApi))
    foreach ($j in $jobs) {
        if ([string](Get-SIPnProp $j @('tags', 'si-one-time-job'))) { continue }
        $reg = @(Get-SIPnProp $j @('properties', 'configuration', 'registries') | Where-Object { $_ })[0]
        $pull = [string](Get-SIPnProp $reg @('identity'))
        $img = [string](Get-SIPnProp @(Get-SIPnProp $j @('properties', 'template', 'containers'))[0] @('image'))
        if (-not $img -or [string](Get-SIPnProp $reg @('passwordSecretRef')) -or $pull -notmatch '(?i)/providers/Microsoft\.ManagedIdentity/userAssignedIdentities/') { continue }
        $p.Image = $img; $p.RegistryServer = [string](Get-SIPnProp $reg @('server')); $p.PullIdentityId = $pull; $p.Location = [string](Get-SIPnProp $j @('location'))
        break
    }
    if (-not $p.Image) { $p.Problem = 'no job of the install pulls its image with a user-assigned identity -- the one-time check job has nothing to run'; return $p }
    $have = & $Arm 'GET' ('{0}?api-version={1}' -f $p.JobId, $script:SIPnAppApi) $null
    if ($have) {
        if ([string](Get-SIPnProp $have @('tags', 'si-one-time-job')) -eq 'inside-check') { $p.Leftover = $true }
        else { $p.Problem = ('a job named {0} is there that this check did not make -- it is not touched' -f $JobName); return $p }
    }
    $p.Ok = $true
    $p
}

function Invoke-SIInsideCheckJob {
    <# The one-time inside-check job: made, started once, waited for (bounded), its execution read -- and ALWAYS (finally)
       removed and read back gone. PASS = the execution Succeeded (every name resolved private INSIDE the environment).
       Returns @{ Ok; Lines; Status; Removed }. #>
    param([Parameter(Mandatory)][scriptblock]$Arm, [Parameter(Mandatory)]$Plan, [Parameter(Mandatory)][string[]]$Names,
          [int]$TimeoutSeconds = 300, [int]$PollSeconds = 10, [scriptblock]$Sleep = { param($s) Start-Sleep -Seconds $s })
    $lines = New-Object System.Collections.Generic.List[string]
    $path = '{0}?api-version={1}' -f $Plan.JobId, $script:SIPnAppApi
    $status = ''; $made = $false; $removed = $false
    try {
        if ($Plan.Leftover) {
            $null = & $Arm 'DELETE' $path $null
            if (Read-SIPnBack -Arm $Arm -Path $path -Sleep $Sleep -Tries 30 -PauseSeconds 10 -Test { param($o) $null -eq $o }) { throw ('the leftover {0} is still there' -f $Plan.JobName) }
        }
        $null = & $Arm 'PUT' $path (Get-SIInsideCheckJobBody -Location $Plan.Location -EnvironmentId $Plan.EnvironmentId -Image $Plan.Image -RegistryServer $Plan.RegistryServer -PullIdentityId $Plan.PullIdentityId -Names $Names -TimeoutSeconds $TimeoutSeconds)
        $made = $true
        $back = Read-SIPnBack -Arm $Arm -Path $path -Sleep $Sleep -Tries 30 -PauseSeconds 10 -Test { param($o) [string](Get-SIPnProp $o @('properties', 'provisioningState')) -in 'Succeeded', 'Failed', 'Canceled' }
        if (-not (Test-SIPnSucceeded $back)) { throw ('the one-time job {0} was not made' -f $Plan.JobName) }
        $start = & $Arm 'POST' ('{0}/start?api-version={1}' -f $Plan.JobId, $script:SIPnAppApi) ([ordered]@{})
        $exec = [string](Get-SIPnProp $start @('name')); if (-not $exec) { $exec = (([string](Get-SIPnProp $start @('id'))) -split '/')[-1] }
        if (-not $exec) { throw 'the job was started but Azure named no execution' }
        $deadline = [datetime]::UtcNow.AddSeconds($TimeoutSeconds + 120)
        while ($true) {
            $e = & $Arm 'GET' ('{0}/executions/{1}?api-version={2}' -f $Plan.JobId, $exec, $script:SIPnAppApi) $null
            $status = [string](Get-SIPnProp $e @('properties', 'status'))
            if ($status -in 'Succeeded', 'Failed', 'Stopped', 'Degraded') { break }
            if ([datetime]::UtcNow -ge $deadline) { $status = 'TimedOut'; break }
            & $Sleep $PollSeconds
        }
        $lines.Add(('the one-time job {0} in {1} resolved {2} name(s): {3}' -f $Plan.JobName, ($Plan.EnvironmentId -split '/')[-1], @($Names).Count,
                    $(if ($status -eq 'Succeeded') { 'every one to a private address' } else { 'NOT every one to a private address (' + $status + ') -- its log ([insidecheck] lines) names which' })))
    } catch { $lines.Add(('the one-time check job FAILED: {0}' -f $_.Exception.Message)) }
    finally {
        if ($made -or $Plan.Leftover) {
            try { $null = & $Arm 'DELETE' $path $null; $removed = ($null -eq (Read-SIPnBack -Arm $Arm -Path $path -Sleep $Sleep -Tries 30 -PauseSeconds 10 -Test { param($o) $null -eq $o })) } catch { $removed = $false }
            if (-not $removed) { $lines.Add(('the one-time job {0} is STILL THERE -- delete it in the resource group' -f $Plan.JobName)) }
        } else { $removed = $true }
    }
    @{ Ok = [bool]($status -eq 'Succeeded'); Lines = $lines.ToArray(); Status = $status; Removed = $removed }
}

function Invoke-SIInsideCheck {
    <#
        THE GATE before any public endpoint closes. Passes when -Names resolve to private addresses
          1. from THIS machine (it is inside the customer's network), or
          2. from a one-time job in the install's own environment (-EnvironmentId; -UseJob), or
          3. the operator confirms it from inside (-ConfirmedFromInside) -- said in the lines.
        Returns @{ Ok; Via = machine | job | confirmed | ''; Lines; Failed }.
    #>
    param([Parameter(Mandatory)][scriptblock]$Arm, [string[]]$Names = @(), [scriptblock]$Resolve, [string]$ResourceGroupId = '', [string]$EnvironmentId = '',
          [switch]$UseJob, [switch]$ConfirmedFromInside, [scriptblock]$Sleep = { param($s) Start-Sleep -Seconds $s })
    $lines = New-Object System.Collections.Generic.List[string]
    if (-not @($Names | Where-Object { $_ }).Count) { return @{ Ok = $false; Via = ''; Failed = @(); Lines = @('the inside check has no names to resolve') } }
    $m = Test-SIInsideResolution -Names $Names -Resolve $Resolve
    if ($m.Ok) { return @{ Ok = $true; Via = 'machine'; Failed = @(); Lines = @(@('inside check (this machine): every name resolves to a private address') + @($m.Lines)) } }
    $lines.Add('inside check (this machine): not every name resolves to a private address here')
    foreach ($l in $m.Lines) { $lines.Add('  ' + $l) }
    if ($UseJob -and $EnvironmentId -and $ResourceGroupId) {
        $jp = Get-SIInsideCheckJobPlan -Arm $Arm -ResourceGroupId $ResourceGroupId -EnvironmentId $EnvironmentId
        if (-not $jp.Ok) { $lines.Add(('inside check (one-time job): not run -- {0}' -f $jp.Problem)) }
        else {
            $j = Invoke-SIInsideCheckJob -Arm $Arm -Plan $jp -Names $Names -Sleep $Sleep
            foreach ($l in $j.Lines) { $lines.Add('inside check (one-time job): ' + $l) }
            if ($j.Ok) { return @{ Ok = $true; Via = 'job'; Failed = @(); Lines = $lines.ToArray() } }
        }
    }
    if ($ConfirmedFromInside) { $lines.Add('-ConfirmedFromInside: the operator confirmed from inside the network that these names resolve to their private addresses'); return @{ Ok = $true; Via = 'confirmed'; Failed = @($m.Failed); Lines = $lines.ToArray() } }
    @{ Ok = $false; Via = ''; Failed = @($m.Failed); Lines = $lines.ToArray() }
}

# ============================================================================================================== MOVING JOBS AND APPS

function Get-SIContainerMoveProblem {
    <# PURE. Why -Resource (a Container Apps job or app) cannot be moved now ('' = it can): a secret that is NOT a Key
       Vault reference (its value is never read, written down or carried -- make it a Key Vault reference first), a
       registry signed in to with a password, or a run still going (a job). #>
    param([Parameter(Mandatory)]$Resource, [object[]]$Executions = @())
    $name = [string](Get-SIPnProp $Resource @('name'))
    $plain = @(Get-SIPnProp $Resource @('properties', 'configuration', 'secrets') | Where-Object { $_ -and -not [string](Get-SIPnProp $_ @('keyVaultUrl')) } | ForEach-Object { [string](Get-SIPnProp $_ @('name')) })
    if ($plain.Count) { return ('{0} holds secret(s) that are not Key Vault references ({1}) -- they are never copied; make them Key Vault references first' -f $name, ($plain -join ', ')) }
    $pw = @(Get-SIPnProp $Resource @('properties', 'configuration', 'registries') | Where-Object { $_ -and [string](Get-SIPnProp $_ @('passwordSecretRef')) })
    if ($pw.Count) { return ('{0} pulls its image with a password -- it must pull as its managed identity first' -f $name) }
    $run = @($Executions | Where-Object { $_ -and [string](Get-SIPnProp $_ @('properties', 'status')) -in 'Running', 'Processing' })
    if ($run.Count) { return ('{0} is running now ({1}) -- moved when it is not running' -f $name, [string](Get-SIPnProp $run[0] @('name'))) }
    ''
}

function Get-SIContainerMoveBody {
    <#
        PURE. The PUT body that creates -Resource again in -EnvironmentId: its location, tags, identities, configuration and
        template exactly as they are, with the new environment. What Azure fills in itself is left out (its address, its
        provisioning state, its revisions). -External (apps only): the ingress' external flag in the new environment -- in an
        INTERNAL environment "external" means "reachable from the virtual network", never from the internet.
    #>
    param([Parameter(Mandatory)]$Resource, [Parameter(Mandatory)][string]$EnvironmentId, [ValidateSet('job', 'app')][string]$Kind = 'job', $External = $null)
    $r = ConvertTo-SIPnHashtable $Resource
    $body = [ordered]@{ location = [string]$r['location'] }
    if ($r.Contains('tags') -and $r['tags']) { $body['tags'] = $r['tags'] }
    if ($r.Contains('identity') -and $r['identity']) {
        $idn = [ordered]@{ type = [string]$r['identity']['type'] }
        $ua = $r['identity']['userAssignedIdentities']
        if ($ua) { $u = [ordered]@{}; foreach ($k in @($ua.Keys)) { $u[$k] = [ordered]@{} }; $idn['userAssignedIdentities'] = $u }
        $body['identity'] = $idn
    }
    $src = $r['properties']; $props = [ordered]@{}
    if ($Kind -eq 'app') { $props['managedEnvironmentId'] = $EnvironmentId }
    $props['environmentId'] = $EnvironmentId
    if ($src.Contains('workloadProfileName') -and $src['workloadProfileName']) { $props['workloadProfileName'] = $src['workloadProfileName'] }
    $cfg = $src['configuration']
    if ($cfg) {
        if ($cfg.Contains('ingress') -and $cfg['ingress']) {
            foreach ($ro in 'fqdn') { if ($cfg['ingress'].Contains($ro)) { $cfg['ingress'].Remove($ro) } }
            if ($null -ne $External) { $cfg['ingress']['external'] = [bool]$External }
        }
        $props['configuration'] = $cfg
    }
    if ($src.Contains('template') -and $src['template']) { $props['template'] = $src['template'] }
    $body['properties'] = $props
    $body
}

function Get-SIScopedRoleAssignments {
    <# The role assignments made AT -Scope itself (not inherited) -- they go with the resource when it is removed. #>
    param([Parameter(Mandatory)][scriptblock]$Arm, [Parameter(Mandatory)][string]$Scope)
    @(Get-SIPnArmList -Arm $Arm -Path ('{0}/providers/Microsoft.Authorization/roleAssignments?$filter=atScope()&api-version={1}' -f $Scope.TrimEnd('/'), $script:SIPnAuthApi) |
      Where-Object { Test-SIPnSameId ([string](Get-SIPnProp $_ @('properties', 'scope'))) $Scope })
}

function Move-SIContainerResource {
    <#
        Moves ONE Container Apps job or app to -EnvironmentId. Azure cannot move one, and a name is unique per resource group,
        so it is REMOVED and CREATED AGAIN under the same name, with the same identities, configuration and template (Get-
        SIContainerMoveBody), and the role assignments made on it are made again. Every part is read back. Refused up front
        (nothing removed) when Get-SIContainerMoveProblem names a problem. -Definition: the definition to create (a
        rollback passes the recorded one). Returns @{ Ok; Lines; Fqdn; Roles }.
    #>
    param([Parameter(Mandatory)][scriptblock]$Arm, [Parameter(Mandatory)]$Resource, [Parameter(Mandatory)][string]$EnvironmentId,
          [ValidateSet('job', 'app')][string]$Kind = 'job', $External = $null, [object[]]$RoleAssignments = $null, [scriptblock]$Sleep = { param($s) Start-Sleep -Seconds $s })
    $id = [string](Get-SIPnProp $Resource @('id')); $name = [string](Get-SIPnProp $Resource @('name'))
    $path = '{0}?api-version={1}' -f $id, $script:SIPnAppApi
    $lines = New-Object System.Collections.Generic.List[string]
    $exec = @(); if ($Kind -eq 'job') { $exec = @(Get-SIPnArmList -Arm $Arm -Path ('{0}/executions?api-version={1}' -f $id, $script:SIPnAppApi)) }
    $why = Get-SIContainerMoveProblem -Resource $Resource -Executions $exec
    if ($why) { return @{ Ok = $false; Lines = @(('NOT moved: {0}. Nothing was removed.' -f $why)); Fqdn = ''; Roles = @() } }
    $roles = if ($null -ne $RoleAssignments) { @($RoleAssignments) } else { @(Get-SIScopedRoleAssignments -Arm $Arm -Scope $id) }
    $body = Get-SIContainerMoveBody -Resource $Resource -EnvironmentId $EnvironmentId -Kind $Kind -External $External
    # a resource that is not there (a move that stopped half-way; a rollback from the record) is only created
    if (& $Arm 'GET' $path $null) {
        $null = & $Arm 'DELETE' $path $null
        $gone = Read-SIPnBack -Arm $Arm -Path $path -Sleep $Sleep -Tries 60 -PauseSeconds 10 -Test { param($o) $null -eq $o }
        if ($gone) { return @{ Ok = $false; Lines = @(('{0} is still there after its removal was asked for -- not created again; run the step again' -f $name)); Fqdn = ''; Roles = @() } }
        $lines.Add(('{0} removed from its old environment' -f $name))
    } else { $lines.Add(('{0} is not there -- it is created from its definition' -f $name)) }
    $null = & $Arm 'PUT' $path $body
    $envProp = if ($Kind -eq 'app') { 'managedEnvironmentId' } else { 'environmentId' }
    $back = Read-SIPnBack -Arm $Arm -Path $path -Sleep $Sleep -Tries 90 -PauseSeconds 10 -Test { param($o) (Test-SIPnSucceeded $o) -and (Test-SIPnSameId ([string](Get-SIPnProp $o @('properties', $envProp))) $EnvironmentId) }
    $ok = (Test-SIPnSucceeded $back) -and (Test-SIPnSameId ([string](Get-SIPnProp $back @('properties', $envProp))) $EnvironmentId)
    $lines.Add($(if ($ok) { '{0} created again in {1} (read back)' -f $name, ($EnvironmentId -split '/')[-1] } else { '{0} does NOT read back in {1} (Azure shows: {2}) -- the rollback record holds its definition' -f $name, ($EnvironmentId -split '/')[-1], [string](Get-SIPnProp $back @('properties', 'provisioningState')) }))
    $made = New-Object System.Collections.Generic.List[string]
    foreach ($ra in $roles) {
        $rd = [string](Get-SIPnProp $ra @('properties', 'roleDefinitionId')); $prin = [string](Get-SIPnProp $ra @('properties', 'principalId'))
        if (-not $rd -or -not $prin) { continue }
        $aid = '{0}/providers/Microsoft.Authorization/roleAssignments/{1}' -f $id, ([guid]::NewGuid().ToString())
        $ap = '{0}?api-version={1}' -f $aid, $script:SIPnAuthApi
        $rb = [ordered]@{ properties = [ordered]@{ roleDefinitionId = $rd; principalId = $prin } }
        $pt = [string](Get-SIPnProp $ra @('properties', 'principalType')); if ($pt) { $rb.properties['principalType'] = $pt }
        try {
            $null = & $Arm 'PUT' $ap $rb
            $rback = Read-SIPnBack -Arm $Arm -Path $ap -Sleep $Sleep -Tries 6 -PauseSeconds 5 -Test { param($o) $null -ne $o }
            if ($rback) { $made.Add($aid); $lines.Add(('{0}: role {1} for {2} made again (read back)' -f $name, ($rd -split '/')[-1], $prin)) } else { $ok = $false; $lines.Add(('{0}: role {1} for {2} does not read back' -f $name, ($rd -split '/')[-1], $prin)) }
        } catch { $ok = $false; $lines.Add(('{0}: role {1} for {2} could not be made again: {3}' -f $name, ($rd -split '/')[-1], $prin, $_.Exception.Message)) }
    }
    @{ Ok = [bool]$ok; Lines = $lines.ToArray(); Fqdn = [string](Get-SIPnProp $back @('properties', 'configuration', 'ingress', 'fqdn')); Roles = $made.ToArray() }
}

function Get-SIMoveRecord {
    <# PURE. What the rollback record keeps of a resource before it is moved: its id, name, kind, environment, definition
       (no secret values exist in it -- a resource with a plain secret is never moved) and the role assignments made on it. #>
    param([Parameter(Mandatory)]$Resource, [ValidateSet('job', 'app')][string]$Kind, [object[]]$RoleAssignments = @())
    $envProp = if ($Kind -eq 'app') { 'managedEnvironmentId' } else { 'environmentId' }
    [ordered]@{ id = [string](Get-SIPnProp $Resource @('id')); name = [string](Get-SIPnProp $Resource @('name')); kind = $Kind
                environmentId = [string](Get-SIPnProp $Resource @('properties', $envProp))
                external = Get-SIPnProp $Resource @('properties', 'configuration', 'ingress', 'external')
                definition = (ConvertTo-SIPnHashtable $Resource)
                roles = @($RoleAssignments | ForEach-Object { [ordered]@{ roleDefinitionId = [string](Get-SIPnProp $_ @('properties', 'roleDefinitionId')); principalId = [string](Get-SIPnProp $_ @('properties', 'principalId')); principalType = [string](Get-SIPnProp $_ @('properties', 'principalType')) } }) }
}

# ============================================================================================================== THE WEB APP'S SIGN-IN ADDRESS

function Add-SIWebSignInAddress {
    <# The web app's new address ADDED to its sign-in registration (the old ones stay -- add before remove), READ BACK.
       -Graph { param($Method, $Uri, $Body) }. Returns @{ Ok; Line; Before = @{ objectId; redirectUris; logoutUrl } }. #>
    param([Parameter(Mandatory)][scriptblock]$Graph, [Parameter(Mandatory)][string]$ClientId, [Parameter(Mandatory)][string]$Fqdn)
    $h = $Fqdn.Trim().TrimEnd('/') -replace '^https?://', ''
    $list = & $Graph 'GET' ("https://graph.microsoft.com/v1.0/applications?`$filter=appId eq '{0}'&`$select=id,appId,web" -f $ClientId) $null
    $app = @(Get-SIPnProp $list @('value') | Where-Object { $_ })[0]
    if (-not $app) { return @{ Ok = $false; Before = $null; Line = ('the sign-in registration {0} was not found -- the new address https://{1}/ must be added to it by hand' -f $ClientId, $h) } }
    $oid = [string](Get-SIPnProp $app @('id'))
    $uris = @(Get-SIPnProp $app @('web', 'redirectUris') | Where-Object { $_ })
    $before = [ordered]@{ objectId = $oid; redirectUris = $uris; logoutUrl = [string](Get-SIPnProp $app @('web', 'logoutUrl')) }
    $want = "https://$h/signin-oidc"
    if ($uris -contains $want) { return @{ Ok = $true; Before = $before; Line = ('the sign-in registration already knows https://{0}/' -f $h) } }
    $web = [ordered]@{ redirectUris = @($uris + @($want) | Select-Object -Unique); logoutUrl = "https://$h/signout-callback-oidc" }
    $ig = Get-SIPnProp $app @('web', 'implicitGrantSettings'); if ($ig) { $web['implicitGrantSettings'] = ConvertTo-SIPnHashtable $ig }
    $null = & $Graph 'PATCH' ('https://graph.microsoft.com/v1.0/applications/{0}' -f $oid) ([ordered]@{ web = $web })
    $back = & $Graph 'GET' ('https://graph.microsoft.com/v1.0/applications/{0}?$select=id,web' -f $oid) $null
    $ok = @(Get-SIPnProp $back @('web', 'redirectUris')) -contains $want
    @{ Ok = [bool]$ok; Before = $before; Line = $(if ($ok) { 'the sign-in registration knows the new address https://{0}/ (read back; the old addresses stay)' -f $h } else { 'the new address https://{0}/ does not read back on the sign-in registration' -f $h }) }
}

# ============================================================================================================== THE NETWORK HAND-OFF
# #866 (owner 2026-10-21: "that is where everything must be added by the customer"; "we are not allowed to"): SecurityInsight
# does the spoke; the customer's network team does the hub. The install and the cut-over end with ONE exact list for that
# team -- real names, ids, addresses -- and a script the hub owner can read or run (PIM's New-PimHubPrepareScript).

function Get-SIVnetShortName {
    <# PURE. A network's short name for a peering name (PIM's Get-PimVnetShortName): vnet-x / x-vnet -> x. #>
    param([Parameter(Mandatory)][string]$VnetId)
    $n = (($VnetId.TrimEnd('/') -split '/')[-1]).ToLowerInvariant()
    if ($n -like 'vnet-*') { $n = $n.Substring(5) } elseif ($n -like '*-vnet') { $n = $n.Substring(0, $n.Length - 5) }
    $n.Trim('-')
}

function Get-SIPeeringBody {
    <# PURE. One side of the peering, PIM's settings (Set-PimVnetPeering / its hub owner's script), the same both ways:
       network access on, forwarded traffic off, gateway transit off, remote gateways off. #>
    param([Parameter(Mandatory)][string]$RemoteVnetId)
    [ordered]@{ properties = [ordered]@{ remoteVirtualNetwork = [ordered]@{ id = $RemoteVnetId }; allowVirtualNetworkAccess = $true; allowForwardedTraffic = $false; allowGatewayTransit = $false; useRemoteGateways = $false } }
}

function Get-SIPeeringPlan {
    <# PURE. Both directions of the peering of SecurityInsight's network (-SpokeVnetId) with the hub, ALWAYS both (a
       one-sided peering reads Initiated and carries nothing). Refused: the same network, or address spaces that overlap
       (when both are known). @{ Ok; Reason; Pairs = @( @{ Direction; VnetId; Name; RemoteVnetId; Path } ); CrossSubscription }. #>
    param([Parameter(Mandatory)][string]$SpokeVnetId, [Parameter(Mandatory)][string]$HubVnetId, [string[]]$SpokePrefixes = @(), [string[]]$HubPrefixes = @())
    if (Test-SIPnSameId $SpokeVnetId $HubVnetId) { return @{ Ok = $false; Pairs = @(); CrossSubscription = $false; Reason = 'the hub and SecurityInsight''s network are the SAME network -- a network cannot be peered to itself' } }
    foreach ($s in @($SpokePrefixes | Where-Object { $_ })) { foreach ($h in @($HubPrefixes | Where-Object { $_ })) {
        if (Test-SICidrOverlap $s $h) { return @{ Ok = $false; Pairs = @(); CrossSubscription = $false; Reason = ('the address spaces OVERLAP (SecurityInsight {0}, hub {1}) -- Azure cannot peer them; SecurityInsight needs a range that is free in your network' -f $s, $h) } }
    } }
    $ss = Get-SIVnetShortName $SpokeVnetId; $hs = Get-SIVnetShortName $HubVnetId
    $mk = { param($v, $name, $remote, $dir) @{ Direction = $dir; VnetId = $v.TrimEnd('/'); Name = $name; RemoteVnetId = $remote.TrimEnd('/'); Path = ('{0}/virtualNetworkPeerings/{1}' -f $v.TrimEnd('/'), $name) } }
    $sub = { param($id) (ConvertFrom-SIPnResourceId $id).SubscriptionId }
    @{ Ok = $true; Reason = ''; CrossSubscription = [bool]((& $sub $SpokeVnetId) -ne (& $sub $HubVnetId))
       Pairs = @((& $mk $SpokeVnetId ('{0}-to-{1}' -f $ss, $hs) $HubVnetId 'spoke-to-hub'), (& $mk $HubVnetId ('{0}-to-{1}' -f $hs, $ss) $SpokeVnetId 'hub-to-spoke')) }
}

function Get-SIPeeringState {
    <# READ ONLY. The state of the peering of -VnetId with -RemoteVnetId: the peeringState of ANY peering on -VnetId that
       points at -RemoteVnetId ('' = none; 'unreadable' = this identity may not read that network -- the hub, usually). #>
    param([Parameter(Mandatory)][scriptblock]$Arm, [Parameter(Mandatory)][string]$VnetId, [Parameter(Mandatory)][string]$RemoteVnetId)
    try { $list = @(Get-SIPnArmList -Arm $Arm -Path ('{0}/virtualNetworkPeerings?api-version={1}' -f $VnetId.TrimEnd('/'), $script:SIPnNetApi)) } catch { return 'unreadable' }
    $p = @($list | Where-Object { Test-SIPnSameId ([string](Get-SIPnProp $_ @('properties', 'remoteVirtualNetwork', 'id'))) $RemoteVnetId })[0]
    if (-not $p) { return '' }
    [string](Get-SIPnProp $p @('properties', 'peeringState'))
}

function Set-SIVnetPeering {
    <#
        #866 item 5 (owner: "i would ask si to do the peering to hub, but i must get approval first"): the peering of
        SecurityInsight's network with the hub, BOTH directions (PIM's Set-PimVnetPeering), ONLY when the customer turned
        it on (peerToHub / the cut-over's peer-to-hub step). Before ANY change: both networks readable, no overlap, no
        same-name peering pointing elsewhere, and the rights on BOTH networks (peerings/write + peer/action) read back --
        else REFUSED, nothing written, the role and the scope named. NEVER HALF A PEERING: when the second side cannot be
        made, the first side this made is removed again (and said). Done = both sides read Connected.
        Returns @{ Ok; Refused; Lines; Created (peering ids this made) }.
    #>
    param([Parameter(Mandatory)][scriptblock]$Arm, [Parameter(Mandatory)][string]$SpokeVnetId, [Parameter(Mandatory)][string]$HubVnetId,
          [scriptblock]$Sleep = { param($s) Start-Sleep -Seconds $s })
    $lines = New-Object System.Collections.Generic.List[string]; $created = New-Object System.Collections.Generic.List[string]
    $refuse = { param($why) @{ Ok = $false; Refused = $true; Created = @(); Lines = @(('peering REFUSED before any change: {0} -- it stays on the network hand-off list' -f $why)) } }
    $get = { param($id) try { & $Arm 'GET' ('{0}?api-version={1}' -f $id, $script:SIPnNetApi) $null } catch { $null } }
    $spoke = & $get $SpokeVnetId; $hub = & $get $HubVnetId
    if (-not $spoke) { return (& $refuse ('SecurityInsight''s network {0} cannot be read' -f $SpokeVnetId)) }
    if (-not $hub) { return (& $refuse ('the hub {0} cannot be read by the installing identity -- grant it Network Contributor on the hub virtual network' -f $HubVnetId)) }
    $plan = Get-SIPeeringPlan -SpokeVnetId $SpokeVnetId -HubVnetId $HubVnetId -SpokePrefixes @(Get-SIVnetPrefixes $spoke) -HubPrefixes @(Get-SIVnetPrefixes $hub)
    if (-not $plan.Ok) { return (& $refuse $plan.Reason) }
    foreach ($v in @($SpokeVnetId, $HubVnetId)) {
        $why = Get-SIHubRightsProblem -Arm $Arm -Scope $v -Actions @('Microsoft.Network/virtualNetworks/virtualNetworkPeerings/write', 'Microsoft.Network/virtualNetworks/peer/action')
        if ($why) { return (& $refuse $why) }
    }
    $todo = @()
    foreach ($p in $plan.Pairs) {
        $have = & $Arm 'GET' ('{0}?api-version={1}' -f $p.Path, $script:SIPnNetApi) $null
        if ($have) {
            $rv = [string](Get-SIPnProp $have @('properties', 'remoteVirtualNetwork', 'id'))
            if (-not (Test-SIPnSameId $rv $p.RemoteVnetId)) { return (& $refuse ('the peering ''{0}'' on {1} already points at {2}, not at {3} -- remove or rename it' -f $p.Name, ($p.VnetId -split '/')[-1], $rv, $p.RemoteVnetId)) }
            $lines.Add(('peering ''{0}'' on {1} is there' -f $p.Name, ($p.VnetId -split '/')[-1]))
        } else { $todo += , $p }
    }
    foreach ($p in $todo) {
        $path = '{0}?api-version={1}' -f $p.Path, $script:SIPnNetApi
        try {
            $null = & $Arm 'PUT' $path (Get-SIPeeringBody -RemoteVnetId $p.RemoteVnetId)
            $back = Read-SIPnBack -Arm $Arm -Path $path -Sleep $Sleep -Tries 30 -PauseSeconds 5 -Test { param($o) [string](Get-SIPnProp $o @('properties', 'provisioningState')) -in 'Succeeded', 'Failed', 'Canceled' }
            if (-not (Test-SIPnSucceeded $back)) { throw ('it does not read back as made (Azure shows: {0})' -f [string](Get-SIPnProp $back @('properties', 'provisioningState'))) }
            $created.Add($p.Path); $lines.Add(('peering ''{0}'' on {1} -> {2} made (read back)' -f $p.Name, ($p.VnetId -split '/')[-1], ($p.RemoteVnetId -split '/')[-1]))
        } catch {
            $lines.Add(('peering ''{0}'' on {1} could NOT be made: {2}' -f $p.Name, ($p.VnetId -split '/')[-1], $_.Exception.Message))
            # never half a peering: what this run made is removed again
            foreach ($c in @($created.ToArray())) {
                try { $null = & $Arm 'DELETE' ('{0}?api-version={1}' -f $c, $script:SIPnNetApi) $null; $lines.Add(('the side made a moment ago (''{0}'') is REMOVED again -- no half peering is left' -f ($c -split '/')[-1])) }
                catch { $lines.Add(('the side made a moment ago (''{0}'') could NOT be removed: {1} -- remove it by hand' -f ($c -split '/')[-1], $_.Exception.Message)) }
            }
            return @{ Ok = $false; Refused = $false; Created = @(); Lines = $lines.ToArray() }
        }
    }
    # both sides Connected -- Initiated is the shape of a half-built peering, indistinguishable unless read
    $bad = @()
    foreach ($p in $plan.Pairs) {
        $st = [string](Get-SIPnProp (Read-SIPnBack -Arm $Arm -Path ('{0}?api-version={1}' -f $p.Path, $script:SIPnNetApi) -Sleep $Sleep -Tries 12 -PauseSeconds 5 -Test { param($o) [string](Get-SIPnProp $o @('properties', 'peeringState')) -eq 'Connected' }) @('properties', 'peeringState'))
        $lines.Add(('{0}: {1}' -f $p.Name, $(if ($st) { $st } else { 'unreadable' })))
        if ($st -ne 'Connected') { $bad += $p.Name }
    }
    if ($bad.Count) { $lines.Add(('the peering is NOT Connected in both directions ({0}) -- the hub has no route to SecurityInsight yet' -f ($bad -join ', '))) }
    @{ Ok = (-not $bad.Count); Refused = $false; Created = $created.ToArray(); Lines = $lines.ToArray() }
}

function Invoke-SIPrivateNetworkPeering {
    <# Setup's call (the guided install's subnets step, only when peerToHub is on and a hub is given): Set-SIVnetPeering
       over setup's own ARM sign-in. Returns its answer. #>
    param([Parameter(Mandatory)][System.Collections.IDictionary]$Target, [scriptblock]$Arm, [scriptblock]$Sleep, [string]$SubscriptionId)
    if (-not $Arm) { $Arm = { param([string]$Method, [string]$Path, $Body) if ($Method -eq 'GET') { Invoke-SIArm -Path $Path -AllowNotFound } else { Invoke-SIArm -Method $Method -Path $Path -Body $Body } } }
    if (-not $Sleep) { $Sleep = { param($s) Start-Sleep -Seconds $s } }
    Set-SIVnetPeering -Arm $Arm -SpokeVnetId ([string]$Target['VnetId']) -HubVnetId ([string]$Target['HubVnetId']) -Sleep $Sleep
}

function Get-SIPrivateEndpointNicPairs {
    <# READ ONLY. The (name, address) pairs of one private endpoint, read from ITS NETWORK INTERFACE -- the source of truth
       for the address: properties.networkInterfaces[].id -> GET the interface -> each ipConfigurations[].properties
       .privateIPAddress, named by that configuration's privateLinkConnectionProperties.fqdns. Azure leaves the endpoint's
       customDnsConfigs EMPTY once a private DNS zone group is attached, so the endpoint itself is not enough.
       Returns @( ,@(<fqdn>, @(<ip>)) ... ); an interface that cannot be read gives nothing (the caller falls back). #>
    param([Parameter(Mandatory)][scriptblock]$Arm, $Endpoint)
    $pairs = @()
    foreach ($nr in @(Get-SIPnProp $Endpoint @('properties', 'networkInterfaces') | Where-Object { $_ })) {
        $nid = [string](Get-SIPnProp $nr @('id'))
        if (-not $nid) { continue }
        $nic = $null
        try { $nic = & $Arm 'GET' ('{0}?api-version={1}' -f $nid, $script:SIPnNetApi) $null } catch { $nic = $null }
        foreach ($ic in @(Get-SIPnProp $nic @('properties', 'ipConfigurations') | Where-Object { $_ })) {
            $ip = [string](Get-SIPnProp $ic @('properties', 'privateIPAddress'))
            if (-not $ip) { continue }
            foreach ($fq in @(Get-SIPnProp $ic @('properties', 'privateLinkConnectionProperties', 'fqdns') | Where-Object { $_ })) { $pairs += , @([string]$fq, @($ip)) }
        }
    }
    , $pairs
}

function Get-SIPrivateLinkRecords {
    <# READ ONLY. The A records of the install's private endpoints (pe-si-*) in -ResourceGroupId, as the customer adds them
       in the hub's zones: @( @{ Zone; Name; Fqdn; Ip; Source; ZoneGroupIp } ).
       The address comes from the endpoint's NETWORK INTERFACE (Get-SIPrivateEndpointNicPairs) -- the source of truth.
       The zone group's record sets are a cross-check (ZoneGroupIp is set when Azure's zone record says something else) and
       the source only when the interface cannot be read; the endpoint's customDnsConfigs are the last fallback, because
       Azure leaves them empty once a zone group is attached. Source = 'nic' | 'zonegroup' | 'customdns'. #>
    param([Parameter(Mandatory)][scriptblock]$Arm, [Parameter(Mandatory)][string]$ResourceGroupId)
    $prefix = (Get-SIPrivateNetworkNames).EndpointPrefix
    $out = New-Object System.Collections.Generic.List[object]
    # the record's name in the privatelink zone: the name before the service's public suffix (a zone group's fqdn already
    # names the privatelink zone)
    $nameOf = { param($fq, $kind) if ($fq.EndsWith('.' + $kind.Zone)) { $fq.Substring(0, $fq.Length - $kind.Zone.Length - 1) } elseif ($fq.EndsWith('.' + $kind.Suffix)) { $fq.Substring(0, $fq.Length - $kind.Suffix.Length - 1) } else { ($fq -split '\.')[0] } }
    $toMap = {
        param($pairs, $kind)
        $m = [ordered]@{}
        foreach ($p in @($pairs)) {
            $fq = ([string]$p[0]).TrimEnd('.').ToLowerInvariant()
            $ip = [string](@($p[1] | Where-Object { $_ })[0])
            if (-not $fq -or -not $ip) { continue }
            $n = & $nameOf $fq $kind
            if (-not $m.Contains($n)) { $m[$n] = $ip }
        }
        $m
    }
    foreach ($k in @($script:SIPnKinds.Keys)) {
        $kind = $script:SIPnKinds[$k]
        $id = '{0}/providers/Microsoft.Network/privateEndpoints/{1}{2}' -f $ResourceGroupId.TrimEnd('/'), $prefix, $k
        $pe = & $Arm 'GET' ('{0}?api-version={1}' -f $id, $script:SIPnNetApi) $null
        if (-not $pe) { continue }
        # 1. the network interface -- the source of truth
        $nicMap = & $toMap (Get-SIPrivateEndpointNicPairs -Arm $Arm -Endpoint $pe) $kind
        # 2. the zone group's record sets -- the cross-check
        $zgPairs = @()
        $zg = & $Arm 'GET' ('{0}/privateDnsZoneGroups/{1}?api-version={2}' -f $id, (Get-SIPrivateNetworkNames).ZoneGroup, $script:SIPnNetApi) $null
        foreach ($c in @(Get-SIPnProp $zg @('properties', 'privateDnsZoneConfigs') | Where-Object { $_ })) {
            foreach ($rs in @(Get-SIPnProp $c @('properties', 'recordSets') | Where-Object { $_ })) { $zgPairs += , @([string](Get-SIPnProp $rs @('fqdn')), @(Get-SIPnProp $rs @('ipAddresses'))) }
        }
        $zgMap = & $toMap $zgPairs $kind
        $use = $nicMap; $src = 'nic'
        if (-not $use.Count) { $use = $zgMap; $src = 'zonegroup' }
        # 3. the endpoint's customDnsConfigs -- the last fallback (empty once a zone group is attached)
        if (-not $use.Count) {
            $cd = @(); foreach ($c in @(Get-SIPnProp $pe @('properties', 'customDnsConfigs') | Where-Object { $_ })) { $cd += , @([string](Get-SIPnProp $c @('fqdn')), @(Get-SIPnProp $c @('ipAddresses'))) }
            $use = & $toMap $cd $kind; $src = 'customdns'
        }
        foreach ($name in @($use.Keys)) {
            if (@($out | Where-Object { $_.Zone -eq $kind.Zone -and $_.Name -eq $name }).Count) { continue }
            $ip = [string]$use[$name]
            $zgIp = if ($src -eq 'nic' -and $zgMap.Contains($name) -and [string]$zgMap[$name] -ne $ip) { [string]$zgMap[$name] } else { '' }
            $out.Add(@{ Zone = $kind.Zone; Name = $name; Fqdn = ('{0}.{1}' -f $name, $kind.Suffix); Ip = $ip; Source = $src; ZoneGroupIp = $zgIp })
        }
    }
    $out.ToArray()
}

function Get-SINetworkHandOffFacts {
    <# READ ONLY. What the hand-off list says, read from Azure: SecurityInsight's network (its id, address space,
       subscription, DNS servers), the hub (when given and readable), both sides of the peering, the environment's zone
       (its records' address, whether the hub is linked), the private endpoints' records. Never writes. #>
    param([Parameter(Mandatory)][scriptblock]$Arm, [Parameter(Mandatory)][System.Collections.IDictionary]$Target, [string]$EnvironmentId = '', [string[]]$InsideNames = @(), [string[]]$Notes = @())
    $spokeId = [string]$Target['VnetId']; $hubId = [string]$Target['HubVnetId']
    $spoke = if ($spokeId) { & $Arm 'GET' ('{0}?api-version={1}' -f $spokeId, $script:SIPnNetApi) $null } else { $null }
    $hub = $null; $hubReadable = $false
    if ($hubId) { try { $hub = & $Arm 'GET' ('{0}?api-version={1}' -f $hubId, $script:SIPnNetApi) $null; $hubReadable = [bool]$hub } catch { $hub = $null } }
    $f = [ordered]@{
        SpokeVnetId = $spokeId; SpokePrefixes = @(Get-SIVnetPrefixes $spoke); SpokeSubscription = $(if ($spokeId) { [string](ConvertFrom-SIPnResourceId $spokeId).SubscriptionId } else { '' })
        SpokeDnsServers = @(Get-SIPnProp $spoke @('properties', 'dhcpOptions', 'dnsServers') | Where-Object { $_ })
        HubVnetId = $hubId; HubReadable = $hubReadable; HubPrefixes = @(Get-SIVnetPrefixes $hub)
        SpokeSide = ''; HubSide = ''
        EnvZone = ''; EnvZoneId = ''; EnvIp = ''; EnvLinkedToHub = $false
        PrivateLinkRecords = @(Get-SIPrivateLinkRecords -Arm $Arm -ResourceGroupId ([string]$Target['ResourceGroupId']))
        InsideNames = @($InsideNames | Where-Object { $_ }); Notes = @($Notes | Where-Object { $_ })
        CloseCommand = ''
        # #1095: the apps subnet's return route (its route table, the answers returnRouteRanges / returnRouteNextHop)
        ReturnRoute = (Get-SIReturnRouteFacts -Arm $Arm -Target $Target)
    }
    if ($spokeId -and $hubId) {
        $f.SpokeSide = Get-SIPeeringState -Arm $Arm -VnetId $spokeId -RemoteVnetId $hubId
        $f.HubSide = if ($hubReadable) { Get-SIPeeringState -Arm $Arm -VnetId $hubId -RemoteVnetId $spokeId } else { 'unreadable' }
    }
    if ($EnvironmentId) {
        $env = & $Arm 'GET' ('{0}?api-version={1}' -f $EnvironmentId, $script:SIPnAppApi) $null
        $f.EnvZone = [string](Get-SIPnProp $env @('properties', 'defaultDomain')); $f.EnvIp = [string](Get-SIPnProp $env @('properties', 'staticIp'))
        if ($f.EnvZone) {
            foreach ($rg in @([string]$Target['ResourceGroupId'], [string]$Target['DnsResourceGroupId']) | Where-Object { $_ } | Select-Object -Unique) {
                $zid = '{0}/providers/Microsoft.Network/privateDnsZones/{1}' -f $rg.TrimEnd('/'), $f.EnvZone
                if (& $Arm 'GET' ('{0}?api-version={1}' -f $zid, $script:SIPnDnsApi) $null) {
                    $f.EnvZoneId = $zid
                    if ($hubId) { $f.EnvLinkedToHub = [bool]@(Get-SIPnArmList -Arm $Arm -Path ('{0}/virtualNetworkLinks?api-version={1}' -f $zid, $script:SIPnDnsApi) | Where-Object { Test-SIPnSameId ([string](Get-SIPnProp $_ @('properties', 'virtualNetwork', 'id'))) $hubId }).Count }
                    break
                }
            }
        }
    }
    $f
}

function Get-SINetworkHandOff {
    <#
        PURE. THE list for the customer's network team, from -Facts (Get-SINetworkHandOffFacts): what is still theirs, with
        real names, ids and addresses -- the peering (both directions, PIM's settings, both must read Connected), the DNS
        zones and A records (link to the hub, or add in the hub's zones / on the resolver), the DNS servers SecurityInsight's
        network asks, the rights SecurityInsight would need to do it itself, the test from the customer's network, and the
        command that then closes the public endpoints. @{ Open (hub items still open); Lines; Items; Text }.
    #>
    param([Parameter(Mandatory)][System.Collections.IDictionary]$Facts)
    $L = New-Object System.Collections.Generic.List[string]; $open = 0; $items = New-Object System.Collections.Generic.List[object]
    $spokeId = [string]$Facts['SpokeVnetId']; $hubId = [string]$Facts['HubVnetId']
    $space = (@($Facts['SpokePrefixes']) | Where-Object { $_ }) -join ', '; if (-not $space) { $space = '(address space not read)' }
    $hubName = if ($hubId) { $hubId } else { '<your hub virtual network>' }
    $L.Add('NETWORK HAND-OFF -- for your network team. SecurityInsight wrote only in its own network and resource group; nothing on your hub.')
    # 1. the peering
    if ([string]$Facts['SpokeSide'] -eq 'Connected') { $L.Add(('1. PEERING: done -- {0} reads Connected with {1}.' -f ($spokeId -split '/')[-1], ($hubName -split '/')[-1])) }
    else {
        $open++
        $plan = if ($hubId -and $spokeId) { Get-SIPeeringPlan -SpokeVnetId $spokeId -HubVnetId $hubId -SpokePrefixes @($Facts['SpokePrefixes']) -HubPrefixes @($Facts['HubPrefixes']) } else { $null }
        $L.Add(('1. PEERING -- peer {0} ({1}) with your hub, BOTH directions; both sides must read Connected.' -f $spokeId, $space))
        $L.Add(('   SecurityInsight''s network: subscription {0}, address space {1}' -f [string]$Facts['SpokeSubscription'], $space))
        if ($plan -and -not $plan.Ok) { $L.Add(('   NOT POSSIBLE AS IT IS: {0}' -f $plan.Reason)) }
        $nm = if ($plan -and $plan.Ok) { @{ s = @($plan.Pairs | Where-Object { $_.Direction -eq 'spoke-to-hub' })[0].Name; h = @($plan.Pairs | Where-Object { $_.Direction -eq 'hub-to-spoke' })[0].Name } } else { @{ s = '<name>'; h = '<name>' } }
        $L.Add(('   a) SecurityInsight -> hub: on {0}, peering ''{1}'' -> {2}' -f ($spokeId -split '/')[-1], $nm.s, $hubName))
        $L.Add(('   b) hub -> SecurityInsight: on {0}, peering ''{1}'' -> {2}' -f ($hubName -split '/')[-1], $nm.h, $spokeId))
        $L.Add('      both directions: allowVirtualNetworkAccess = true, allowForwardedTraffic = false, allowGatewayTransit = false, useRemoteGateways = false')
        $L.Add('      (PIM4EntraPS''s settings. If your on-premises network reaches SecurityInsight through the hub''s VPN / ExpressRoute gateway, your team sets gateway transit on the hub side and remote gateways on SecurityInsight''s side.)')
        $L.Add(('   state now: SecurityInsight''s side {0}; hub side {1}' -f $(if ($Facts['SpokeSide']) { $Facts['SpokeSide'] } else { 'not made' }), $(if ($Facts['HubSide'] -eq 'unreadable') { 'not readable by SecurityInsight' } elseif ($Facts['HubSide']) { $Facts['HubSide'] } else { 'not made' })))
        $items.Add(@{ Kind = 'peering'; Done = $false })
    }
    # 2. the environment's own zone
    if ([string]$Facts['EnvZone']) {
        $z = [string]$Facts['EnvZone']; $ip = [string]$Facts['EnvIp']
        if ($hubId -and [bool]$Facts['EnvLinkedToHub']) { $L.Add(('2. DNS, the web app''s zone {0}: done -- linked to the hub.' -f $z)) }
        else {
            $open++
            $L.Add(('2. DNS, the web app''s zone {0} (its address {1}) -- EITHER:' -f $z, $ip))
            $L.Add(('   a) link SecurityInsight''s zone {0}' -f $(if ($Facts['EnvZoneId']) { $Facts['EnvZoneId'] } else { $z })))
            $L.Add(('      to {0} (registration off) -- the network your private DNS resolver is in; OR' -f $hubName))
            $L.Add(('   b) make the zone {0} in your DNS / on your resolver with these A records:' -f $z))
            foreach ($rec in (Get-SIEnvironmentDnsRecordNames)) { $L.Add(('        {0,-12} A  {1}' -f $rec, $ip)) }
            $items.Add(@{ Kind = 'environment-zone'; Done = $false })
        }
    }
    # 3. the private endpoints' records
    $recs = @($Facts['PrivateLinkRecords'] | Where-Object { $_ })
    if ($recs.Count) {
        $open++
        $L.Add('3. DNS, the private endpoints -- add these A records in YOUR zones of these names that the hub resolves (a network takes only one zone of a name, so SecurityInsight''s zones cannot also be linked where yours are):')
        foreach ($g in @($recs | Group-Object { $_.Zone })) {
            $L.Add(('   zone {0}' -f $g.Name))
            foreach ($r in $g.Group) {
                $L.Add(('        {0,-40} A  {1}   ({2})' -f $r.Name, $r.Ip, $r.Fqdn))
                $zgIp = [string](Get-SIPnProp $r @('ZoneGroupIp'))
                if ($zgIp) { $L.Add(('          note: Azure''s own zone record still says {0}; the endpoint''s network interface says {1} -- use {1}' -f $zgIp, $r.Ip)) }
            }
        }
        $L.Add('   (when your hub has no zone of that name: link SecurityInsight''s zone of that name, in its resource group, to the hub instead)')
        $items.Add(@{ Kind = 'privatelink-records'; Done = $false })
    }
    # 4. which DNS SecurityInsight's own network asks
    $dns = @($Facts['SpokeDnsServers'] | Where-Object { $_ })
    if ($dns.Count) { $L.Add(('4. SecurityInsight''s network asks the DNS server(s) {0} (not Azure''s): they must answer every name above with its private address (your resolver, forwarding to Azure DNS from a network the zones are linked to) -- until then SecurityInsight''s own jobs cannot reach its private database.' -f ($dns -join ', '))) }
    else { $L.Add('4. SecurityInsight''s network uses Azure''s DNS: its own jobs resolve these names already (its zones are linked to it).') }
    # 5. the rights, if SecurityInsight should do the hub side itself
    $L.Add(('5. Only if SecurityInsight should do 1 and 2a itself (answers peerToHub / linkZonesToHub, with your approval): the installing identity needs Network Contributor on {0}; for records in your zones, Private DNS Zone Contributor on their resource group.' -f $hubName))
    # 6. the return route (#1095): replies from the apps subnet to your people's ranges go back through your firewall
    $rr = Get-SIReturnRouteHandOff -Facts $Facts['ReturnRoute'] -Number '6'
    foreach ($x in @($rr.Lines)) { $L.Add($x) }
    if ($rr.Open) { $open++; $items.Add(@{ Kind = 'return-route'; Done = $false }) }
    # 7. the test
    $L.Add('7. CHECK from a machine in your network (each must answer with the private address shown):')
    foreach ($n in @($Facts['InsideNames'] | Where-Object { $_ })) {
        $exp = @($recs | Where-Object { $_.Fqdn -eq $n } | ForEach-Object { $_.Ip })[0]
        if (-not $exp -and $Facts['EnvZone'] -and $n.EndsWith('.' + [string]$Facts['EnvZone'])) { $exp = [string]$Facts['EnvIp'] }
        $L.Add(('        Resolve-DnsName {0} -Type A        # expect {1}' -f $n, $(if ($exp) { $exp } else { 'a private (10.x / 172.16-31.x / 192.168.x) address' })))
    }
    $web = @($Facts['InsideNames'] | Where-Object { $Facts['EnvZone'] -and $_.EndsWith('.' + [string]$Facts['EnvZone']) })[0]
    if ($web) { $L.Add(('        Test-NetConnection {0} -Port 443' -f $web)) }
    foreach ($nt in @($Facts['Notes'])) { $L.Add(('NOTE: {0}' -f $nt)) }
    if ([string]$Facts['CloseCommand']) { $L.Add(('8. THEN close the public endpoints: {0}' -f $Facts['CloseCommand'])) }
    @{ Open = $open; Lines = $L.ToArray(); Items = $items.ToArray(); Text = ($L.ToArray() -join "`n") }
}

function New-SIHubOwnerScript {
    <#
        PURE (returns text). The hub owner's script (PIM's New-PimHubPrepareScript, framework 12.17): ONE self-contained file
        the customer's network team reads or runs -- no Azure CLI, no PowerShell module, a browser sign-in (auth code + PKCE
        on a loopback port; never a device code), Azure Resource Manager REST. PLAN FIRST: without -Apply it prints what it
        would do. With -Apply: (1) the hub side of the peering, PIM's settings, a same-name peering pointing elsewhere is
        refused; (2) with -HubZonesResourceGroupId: the A records of the hand-off list in the EXISTING zones there (a zone
        that is not there is said, never made); (3) with -LinkSecurityInsightZone: SecurityInsight's environment zone linked
        to the hub; (4) the state of both sides of the peering and every name resolved from the machine it runs on. It
        never deletes anything; running it twice is safe. Returns @{ Ok; Reason; FileName; Text }.
    #>
    param([Parameter(Mandatory)][System.Collections.IDictionary]$Facts, [string]$TenantId = '', [datetime]$NowUtc = [datetime]::UtcNow)
    $spokeId = [string]$Facts['SpokeVnetId']; $hubId = [string]$Facts['HubVnetId']
    if (-not $spokeId) { return @{ Ok = $false; Reason = 'SecurityInsight''s network is not known'; FileName = ''; Text = '' } }
    $hubGiven = [bool]$hubId
    $plan = if ($hubGiven) { Get-SIPeeringPlan -SpokeVnetId $spokeId -HubVnetId $hubId -SpokePrefixes @($Facts['SpokePrefixes']) -HubPrefixes @($Facts['HubPrefixes']) } else { $null }
    if ($plan -and -not $plan.Ok) { return @{ Ok = $false; Reason = $plan.Reason; FileName = ''; Text = '' } }
    $q = { param($s) "'" + ([string]$s).Replace("'", "''") + "'" }
    foreach ($v in @($spokeId, $hubId, $Facts['EnvZone'], $Facts['EnvZoneId'], $Facts['EnvIp'])) { if ("$v" -match "[`r`n``]") { return @{ Ok = $false; Reason = ('a value holds a line break: {0}' -f $v); FileName = ''; Text = '' } } }
    $recs = @(@($Facts['PrivateLinkRecords'] | Where-Object { $_ }) | ForEach-Object { '@{{ Zone = {0}; Name = {1}; Ip = {2} }}' -f (& $q $_.Zone), (& $q $_.Name), (& $q $_.Ip) })
    if ([string]$Facts['EnvZone'] -and [string]$Facts['EnvIp']) { foreach ($r in (Get-SIEnvironmentDnsRecordNames)) { $recs += ('@{{ Zone = {0}; Name = {1}; Ip = {2} }}' -f (& $q $Facts['EnvZone']), (& $q $r), (& $q $Facts['EnvIp'])) } }
    $hubPeer = if ($plan) { @($plan.Pairs | Where-Object { $_.Direction -eq 'hub-to-spoke' })[0] } else { $null }
    $spokePeer = if ($plan) { @($plan.Pairs | Where-Object { $_.Direction -eq 'spoke-to-hub' })[0] } else { $null }
    $L = New-Object System.Collections.Generic.List[string]
    $L.Add('#Requires -Version 5.1')
    $L.Add('<#')
    $L.Add('.SYNOPSIS')
    $L.Add(('    SecurityInsight -- the HUB SIDE of a private install, for the hub''s network team. Generated {0} UTC by SecurityInsight setup.' -f $NowUtc.ToUniversalTime().ToString('yyyy-MM-dd HH:mm')))
    $L.Add('.DESCRIPTION')
    $L.Add('    Read it, or run it as someone who may change the hub network. PowerShell 7 or Windows PowerShell 5.1, a browser sign-in --')
    $L.Add('    no Azure CLI, no PowerShell module, nothing to install. WITHOUT -Apply IT ONLY SHOWS WHAT IT WOULD DO.')
    $L.Add('    -Apply: (1) the hub side of the peering with SecurityInsight''s network (PIM4EntraPS''s settings); (2) with')
    $L.Add('    -HubZonesResourceGroupId: the A records below in the EXISTING private DNS zones of that resource group (a zone that is')
    $L.Add('    not there is said, never made); (3) with -LinkSecurityInsightZone: SecurityInsight''s web app zone linked to the hub;')
    $L.Add('    (4) the state of both sides of the peering, and every name resolved from this machine. It never deletes anything.')
    $L.Add('.EXAMPLE')
    $L.Add('    ./prepare-hub-securityinsight.ps1                                   # the plan only')
    $L.Add('    ./prepare-hub-securityinsight.ps1 -Apply -HubZonesResourceGroupId /subscriptions/<s>/resourceGroups/<your zones>')
    $L.Add('#>')
    $L.Add('[CmdletBinding()] param([switch]$Apply, [string]$HubZonesResourceGroupId = '''', [switch]$LinkSecurityInsightZone, [string]$TenantId = ' + (& $q $TenantId) + ')')
    $L.Add('$ErrorActionPreference = ''Stop''')
    $L.Add(('$SpokeId      = {0}' -f (& $q $spokeId)))
    $L.Add(('$SpokeSpace   = {0}' -f (& $q ((@($Facts['SpokePrefixes']) | Where-Object { $_ }) -join ', '))))
    $L.Add(('$HubId        = {0}' -f (& $q $hubId)))
    $L.Add(('$HubPeering   = {0}' -f (& $q $(if ($hubPeer) { $hubPeer.Name } else { '' }))))
    $L.Add(('$SpokePeering = {0}' -f (& $q $(if ($spokePeer) { $spokePeer.Name } else { '' }))))
    $L.Add(('$EnvZoneId    = {0}' -f (& $q $Facts['EnvZoneId'])))
    $L.Add(('$Records      = @({0})' -f ($recs -join ', ')))
    $L.Add(('$Names        = @({0})' -f ((@($Facts['InsideNames'] | Where-Object { $_ }) | ForEach-Object { & $q $_ }) -join ', ')))
    $L.Add(((Get-SIHubOwnerScriptBody) -replace "`r`n", "`n"))
    @{ Ok = $true; Reason = ''; FileName = 'prepare-hub-securityinsight.ps1'; Text = (($L.ToArray() -join "`n").TrimEnd("`n") + "`n") }
}

function Get-SIHubOwnerScriptBody {
    # the constant part of the hub owner's script (nothing in it is expanded by the generator)
    return @'

$Arm = 'https://management.azure.com'; $NetApi = '2024-05-01'; $DnsApi = '2020-06-01'
# The Microsoft Azure CLI first-party public client APP ID, pre-authorised for Azure Resource Manager in every tenant, used
# over REST for the browser sign-in -- the Azure CLI program is NOT needed and NOT used.
$SignInClientId = '04b07795-8ddb-461a-bbee-02f9e1bf7b46'
$Token = ''
try { [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12 } catch { }
function Get-Sub([string]$Id) { ($Id -split '/')[2] }
function ConvertTo-B64Url([byte[]]$B) { [Convert]::ToBase64String($B).TrimEnd('=').Replace('+', '-').Replace('/', '_') }

function Find-Tenant {
    if ("$TenantId".Trim()) { return "$TenantId".Trim() }
    try { $null = Invoke-RestMethod -Method GET -Uri "$Arm/subscriptions/$(Get-Sub $(if ($HubId) { $HubId } else { $SpokeId }))?api-version=2022-12-01" -ErrorAction Stop } catch {
        $h = ''; try { $h = "$($_.Exception.Response.Headers['WWW-Authenticate'])" } catch { }
        if (-not $h) { try { $h = (@($_.Exception.Response.Headers.WwwAuthenticate) | ForEach-Object { "$_" }) -join ', ' } catch { } }
        if ($h -match 'authorization_uri="?https://login\.(?:windows\.net|microsoftonline\.com)/([0-9a-fA-F-]{36})') { return $Matches[1] }
    }
    throw 'Could not find the hub''s tenant -- run again with -TenantId <the tenant id>.'
}

function Get-ArmToken([string]$Tenant) {
    $b = New-Object byte[] 32; [Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($b)
    $verifier = ConvertTo-B64Url $b
    $challenge = ConvertTo-B64Url ([Security.Cryptography.SHA256]::Create().ComputeHash([Text.Encoding]::ASCII.GetBytes($verifier)))
    $state = [guid]::NewGuid().ToString('N')
    $tcp = New-Object System.Net.Sockets.TcpListener([System.Net.IPAddress]::Loopback, 0); $tcp.Start()
    $redirect = "http://localhost:$(([System.Net.IPEndPoint]$tcp.LocalEndpoint).Port)/"
    $scope = "$Arm/.default offline_access openid profile"
    $url = "https://login.microsoftonline.com/$Tenant/oauth2/v2.0/authorize?client_id=$SignInClientId&response_type=code&response_mode=query&redirect_uri=$([uri]::EscapeDataString($redirect))&scope=$([uri]::EscapeDataString($scope))&state=$state&code_challenge=$challenge&code_challenge_method=S256&prompt=select_account"
    Write-Host "Sign in as the hub network's owner (tenant $Tenant). If no browser opens, open this address:" -ForegroundColor Yellow
    Write-Host "  $url" -ForegroundColor DarkGray
    try { Start-Process $url } catch { }
    $query = $null
    try {
        $deadline = (Get-Date).AddMinutes(5)
        while (-not $query) {
            if ((Get-Date) -gt $deadline) { throw 'Timed out (5 min) waiting for the sign-in.' }
            if (-not $tcp.Pending()) { Start-Sleep -Milliseconds 200; continue }
            $c = $tcp.AcceptTcpClient()
            try {
                $s = $c.GetStream(); $line = (New-Object System.IO.StreamReader($s)).ReadLine()
                $html = '<html><body style="font-family:sans-serif"><h3>Sign-in complete.</h3>Return to PowerShell.</body></html>'
                $w = New-Object System.IO.StreamWriter($s); $w.Write("HTTP/1.1 200 OK`r`nContent-Type: text/html`r`nContent-Length: $($html.Length)`r`nConnection: close`r`n`r`n$html"); $w.Flush()
                if ($line -match '^GET /\?(\S+) HTTP') { $query = $Matches[1] }
            } finally { $c.Close() }
        }
    } finally { $tcp.Stop() }
    $kv = @{}; foreach ($p in ($query -split '&')) { $k, $v = $p -split '=', 2; $kv[$k] = if ($null -ne $v) { [uri]::UnescapeDataString(($v -replace '\+', ' ')) } else { '' } }
    if ($kv['error']) { throw "Sign-in failed: $($kv['error']) -- $($kv['error_description'])" }
    if ($kv['state'] -ne $state -or -not $kv['code']) { throw 'The sign-in answer did not match this request -- run the script again.' }
    $r = Invoke-RestMethod -Method POST -Uri "https://login.microsoftonline.com/$Tenant/oauth2/v2.0/token" -ContentType 'application/x-www-form-urlencoded' -Body @{
        client_id = $SignInClientId; grant_type = 'authorization_code'; code = $kv['code']; redirect_uri = $redirect; code_verifier = $verifier; scope = $scope }
    "$($r.access_token)"
}

function Invoke-Arm([string]$Method, [string]$Path, $Body = $null, [switch]$NotFoundOk) {
    $p = @{ Method = $Method; Uri = ($Arm + $Path); Headers = @{ Authorization = "Bearer $Token" }; ErrorAction = 'Stop' }
    if ($null -ne $Body) { $p.ContentType = 'application/json'; $p.Body = [Text.Encoding]::UTF8.GetBytes(($Body | ConvertTo-Json -Depth 10 -Compress)) }
    try { Invoke-RestMethod @p } catch {
        $code = 0; try { $code = [int]$_.Exception.Response.StatusCode } catch { }
        if ($NotFoundOk -and $code -eq 404) { return $null }
        throw "$Method $Path -> HTTP $code $($_.ErrorDetails.Message)"
    }
}

function Wait-Succeeded([string]$Path) {
    for ($i = 0; $i -lt 60; $i++) { $o = Invoke-Arm GET $Path -NotFoundOk; if ("$($o.properties.provisioningState)" -eq 'Succeeded') { return $o }; Start-Sleep -Seconds 5 }
    throw "$Path did not reach Succeeded -- run the script again."
}

# ---- the plan --------------------------------------------------------------------------------------------------------
Write-Host 'SecurityInsight -- the hub side of a private install' -ForegroundColor Cyan
Write-Host "  SecurityInsight's network: $SpokeId ($SpokeSpace)"
if ($HubId) {
    Write-Host "  PLAN 1. on the hub $HubId : peering '$HubPeering' -> SecurityInsight's network (allowVirtualNetworkAccess true, allowForwardedTraffic false, allowGatewayTransit false, useRemoteGateways false)"
} else { Write-Host '  PLAN 1. (no hub was named to SecurityInsight: make the peering of your hub with the network above, both directions, the settings above)' -ForegroundColor Yellow }
if ($HubZonesResourceGroupId) { Write-Host "  PLAN 2. in the EXISTING zones of $HubZonesResourceGroupId : the A records" } else { Write-Host '  PLAN 2. (add -HubZonesResourceGroupId to write these A records in your existing zones):' }
foreach ($r in $Records) { Write-Host ("           {0,-50} A {1,-12} in {2}" -f $r.Name, $r.Ip, $r.Zone) }
if ($LinkSecurityInsightZone -and $EnvZoneId) { Write-Host "  PLAN 3. link SecurityInsight's zone $EnvZoneId to the hub" }
Write-Host '  PLAN 4. read both sides of the peering; resolve every name from this machine'
if (-not $Apply) { Write-Host 'Plan only -- nothing was changed. Run it with -Apply to make these changes (a browser sign-in).' -ForegroundColor Yellow; return }

# ---- apply ------------------------------------------------------------------------------------------------------------
$Token = Get-ArmToken -Tenant (Find-Tenant)
if ($HubId) {
    $pp = "$HubId/virtualNetworkPeerings/$($HubPeering)?api-version=$NetApi"
    $have = Invoke-Arm GET $pp -NotFoundOk
    if ($have -and "$($have.properties.remoteVirtualNetwork.id)".ToLowerInvariant() -ne $SpokeId.ToLowerInvariant()) { throw "a peering named $HubPeering already points at $($have.properties.remoteVirtualNetwork.id) -- nothing was changed." }
    if (-not $have) {
        $null = Invoke-Arm PUT $pp @{ properties = @{ remoteVirtualNetwork = @{ id = $SpokeId }; allowVirtualNetworkAccess = $true; allowForwardedTraffic = $false; allowGatewayTransit = $false; useRemoteGateways = $false } }
        $null = Wait-Succeeded $pp; Write-Host "peering $HubPeering made" -ForegroundColor Green
    } else { Write-Host "peering $HubPeering is there" }
}
if ($HubZonesResourceGroupId) {
    foreach ($r in $Records) {
        $zp = "$($HubZonesResourceGroupId.TrimEnd('/'))/providers/Microsoft.Network/privateDnsZones/$($r.Zone)"
        if (-not (Invoke-Arm GET "$($zp)?api-version=$DnsApi" -NotFoundOk)) { Write-Host "  zone $($r.Zone) is not in $HubZonesResourceGroupId -- skipped (this script makes no zone)" -ForegroundColor Yellow; continue }
        $rp = "$zp/A/$($r.Name)?api-version=$DnsApi"
        $cur = Invoke-Arm GET $rp -NotFoundOk
        if (@($cur.properties.aRecords | ForEach-Object { "$($_.ipv4Address)" }) -contains $r.Ip) { Write-Host "  $($r.Name).$($r.Zone) -> $($r.Ip) is there"; continue }
        $null = Invoke-Arm PUT $rp @{ properties = @{ ttl = 3600; aRecords = @(@{ ipv4Address = $r.Ip }) } }
        Write-Host "  $($r.Name).$($r.Zone) -> $($r.Ip) written" -ForegroundColor Green
    }
}
if ($LinkSecurityInsightZone -and $EnvZoneId -and $HubId) {
    $links = @((Invoke-Arm GET "$EnvZoneId/virtualNetworkLinks?api-version=$DnsApi").value)
    if (@($links | Where-Object { "$($_.properties.virtualNetwork.id)".ToLowerInvariant() -eq $HubId.ToLowerInvariant() }).Count) { Write-Host '  the zone is linked to the hub' }
    else {
        $ln = 'link-' + ($HubId -split '/')[-1]
        if (@($links | Where-Object { "$($_.name)" -eq $ln }).Count) { $ln = $ln + '-hub' }
        $lp = "$EnvZoneId/virtualNetworkLinks/$($ln)?api-version=$DnsApi"
        $null = Invoke-Arm PUT $lp @{ location = 'global'; properties = @{ virtualNetwork = @{ id = $HubId }; registrationEnabled = $false } }
        $null = Wait-Succeeded $lp; Write-Host "  the zone is linked to the hub ($ln)" -ForegroundColor Green
    }
}
# ---- the check ----------------------------------------------------------------------------------------------------------
if ($HubId) {
    $h = Invoke-Arm GET "$HubId/virtualNetworkPeerings/$($HubPeering)?api-version=$NetApi" -NotFoundOk
    $s = $null; try { $s = Invoke-Arm GET "$SpokeId/virtualNetworkPeerings/$($SpokePeering)?api-version=$NetApi" -NotFoundOk } catch { }
    Write-Host ("hub side             {0}: {1}" -f $HubPeering, $(if ($h) { $h.properties.peeringState } else { 'not there' }))
    Write-Host ("SecurityInsight side {0}: {1}" -f $SpokePeering, $(if ($s) { $s.properties.peeringState } else { 'not readable from here / not made yet' }))
    Write-Host 'Both sides must read Connected. SecurityInsight''s side is made by SecurityInsight setup (or by you, with its settings above).'
}
foreach ($n in $Names) {
    $ips = @(); try { $ips = @([System.Net.Dns]::GetHostAddresses($n) | ForEach-Object { $_.IPAddressToString }) } catch { }
    $ok = $ips.Count -and -not @($ips | Where-Object { $_ -notmatch '^(10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.)' }).Count
    Write-Host ("  {0} -> {1}" -f $n, $(if ($ips.Count) { $ips -join ', ' } else { 'does not resolve' })) -ForegroundColor $(if ($ok) { 'Green' } else { 'Yellow' })
}
'@
}

function Write-SINetworkHandOffFiles {
    <# The hand-off as files next to -BasePath: <base>.txt (the list) and prepare-hub-securityinsight.ps1 (the hub owner's
       script) -- for the customer's network team and for Invardia. Returns @{ ListPath; ScriptPath }; a file that cannot be
       written is ''. #>
    param([Parameter(Mandatory)][string]$Directory, [Parameter(Mandatory)]$HandOff, $Script)
    $out = @{ ListPath = ''; ScriptPath = '' }
    try {
        if (-not (Test-Path -LiteralPath $Directory)) { $null = New-Item -ItemType Directory -Force -Path $Directory }
        $out.ListPath = [IO.Path]::Combine($Directory, 'network-hand-off.txt'); [IO.File]::WriteAllText($out.ListPath, [string]$HandOff.Text, (New-Object Text.UTF8Encoding $false))
        if ($Script -and $Script.Ok) { $out.ScriptPath = [IO.Path]::Combine($Directory, $Script.FileName); [IO.File]::WriteAllText($out.ScriptPath, [string]$Script.Text, (New-Object Text.UTF8Encoding $false)) }
    } catch { }
    $out
}

# ============================================================================================================== SETUP'S CALLS

function Get-SIInstallPrivateNetworkTarget {
    <# PURE. The private-network answers of the guided install as one target. #>
    param([Parameter(Mandatory)][System.Collections.IDictionary]$Values, [Parameter(Mandatory)][string]$ResourceGroupId)
    $n = Get-SIPrivateNetworkNames
    $dns = "$($Values['privateDnsZonesResourceGroupId'])".Trim().TrimEnd('/')
    $vnet = "$($Values['vnetId'])".Trim().TrimEnd('/')
    # #866 (PIM's New-PimHostingPrerequisites): no network given but an address range -- SecurityInsight makes its OWN spoke
    # network in its resource group (vnetName, default vnet-si); its subnets default to the first and second /26 of it
    $vPrefix = "$($Values['vnetAddressPrefix'])".Trim()
    $create = [bool](-not $vnet -and $vPrefix)
    $vName = if ("$($Values['vnetName'])".Trim()) { "$($Values['vnetName'])".Trim() } else { $n.Vnet }
    if ($create) { $vnet = '{0}/providers/Microsoft.Network/virtualNetworks/{1}' -f $ResourceGroupId.TrimEnd('/'), $vName }
    $split = if ($create) { Get-SISpokeSubnetDefaults -AddressPrefix $vPrefix } else { @{ Ok = $false; Apps = ''; Endpoints = '' } }
    # #866: the customer's hub network (optional; may be in another subscription). OWNER 2026-10-21 ("we are not allowed
    # to"): SecurityInsight writes NOTHING on the hub by default -- the hub id only makes the network hand-off exact. Only
    # when the customer turns it on (and the rights read back first) does SecurityInsight link its zones to the hub
    # (linkZonesToHub) or peer the networks (peerToHub).
    $hub = "$($Values['hubVnetId'])".Trim().TrimEnd('/')
    if ($hub -and (Test-SIPnSameId $hub $vnet)) { $hub = '' }
    $yes = { param($x) [bool]($x -eq $true -or "$x" -eq 'True') }
    $linkHub = [bool]($hub -and (& $yes $Values['linkZonesToHub']))
    [ordered]@{
        VnetId = $vnet
        HubVnetId = $hub
        LinkZonesToHub = $linkHub
        PeerToHub = [bool]($hub -and (& $yes $Values['peerToHub']))
        LinkVnetIds = @(Get-SIDnsLinkVnetIds -VnetId $vnet -HubVnetId $(if ($linkHub) { $hub } else { '' }))
        CreateVnet = $create
        VnetAddressPrefix = $vPrefix
        AppsSubnetName = $(if ("$($Values['appsSubnetName'])".Trim()) { "$($Values['appsSubnetName'])".Trim() } else { $n.AppsSubnet })
        AppsSubnetPrefix = $(if ("$($Values['appsSubnetPrefix'])".Trim()) { "$($Values['appsSubnetPrefix'])".Trim() } else { [string]$split.Apps })
        EndpointsSubnetName = $(if ("$($Values['endpointsSubnetName'])".Trim()) { "$($Values['endpointsSubnetName'])".Trim() } else { $n.EndpointsSubnet })
        EndpointsSubnetPrefix = $(if ("$($Values['endpointsSubnetPrefix'])".Trim()) { "$($Values['endpointsSubnetPrefix'])".Trim() } else { [string]$split.Endpoints })
        DnsResourceGroupId = $(if ($dns) { $dns } else { $ResourceGroupId })
        ResourceGroupId = $ResourceGroupId
        # #1095: the return route of the apps subnet -- the ranges the customer's people browse from and the hub firewall's
        # private IP (both the customer's answers; SecurityInsight makes the route only on its own spoke)
        # (as given, one item per range; Get-SIReturnRouteFacts normalises them and names what is not a range)
        ReturnRouteRanges = @(@($Values['returnRouteRanges']) | Where-Object { $_ } | ForEach-Object { "$_" -split '[,;\s]+' } | Where-Object { $_ })
        ReturnRouteNextHop = "$($Values['returnRouteNextHop'])".Trim()
    }
}

function Invoke-SIPrivateNetworkSubnets {
    <# Setup's call (the guided install, before the container setup): the two subnets, over setup's own ARM sign-in
       (Invoke-SIArm unless -Arm is given). Returns @{ Ok; Lines; AppsSubnetId; EndpointsSubnetId }; throws when a subnet
       cannot be used (the reason, nothing changed). #>
    param([Parameter(Mandatory)][System.Collections.IDictionary]$Target, [scriptblock]$Arm, [scriptblock]$Sleep, [string]$SubscriptionId,
          # #866: where SecurityInsight's own network is made (vnetAddressPrefix without vnetId): the install's region
          [string]$Location = '')
    if (-not $Arm) { $Arm = { param([string]$Method, [string]$Path, $Body) if ($Method -eq 'GET') { Invoke-SIArm -Path $Path -AllowNotFound } else { Invoke-SIArm -Method $Method -Path $Path -Body $Body } } }
    if (-not $Sleep) { $Sleep = { param($s) Start-Sleep -Seconds $s } }
    if (-not "$($Target['VnetId'])") { throw 'Private network: no virtual network was given (vnetId), nor an address range for SecurityInsight''s own (vnetAddressPrefix). Nothing was changed.' }
    $lines = New-Object System.Collections.Generic.List[string]; $created = $false
    $vnetPath = '{0}?api-version={1}' -f $Target['VnetId'], $script:SIPnNetApi
    if ([bool]$Target['CreateVnet']) {
        $sd = Get-SISpokeSubnetDefaults -AddressPrefix ([string]$Target['VnetAddressPrefix'])
        if (-not $sd.Ok) { throw ('Private network: {0}. Nothing was changed.' -f $sd.Reason) }
        if (Test-SICidrOverlap ([string]$Target['AppsSubnetPrefix']) ([string]$Target['EndpointsSubnetPrefix'])) { throw ('Private network: the two subnets overlap ({0}, {1}). Nothing was changed.' -f $Target['AppsSubnetPrefix'], $Target['EndpointsSubnetPrefix']) }
        if (-not $Location) { throw 'Private network: the region for SecurityInsight''s network is not known. Nothing was changed.' }
        $v = Set-SIVnet -Arm $Arm -VnetId ([string]$Target['VnetId']) -Location $Location -AddressPrefix ([string]$Target['VnetAddressPrefix']) -Sleep $Sleep
        $lines.Add($v.Line); $created = [bool]$v.Created
        if (-not $v.Ok) { return @{ Ok = $false; Lines = $lines.ToArray(); AppsSubnetId = ''; EndpointsSubnetId = ''; Location = $Location; VnetId = [string]$Target['VnetId']; VnetCreated = $created } }
    }
    $vnet = & $Arm 'GET' $vnetPath $null
    if (-not $vnet) { throw ('Private network: the virtual network {0} was not found, or this account cannot read it. Nothing was changed.' -f $Target['VnetId']) }
    $a = Set-SISubnet -Arm $Arm -VnetId $Target['VnetId'] -Name $Target['AppsSubnetName'] -Prefix $Target['AppsSubnetPrefix'] -Delegate -Vnet $vnet -Sleep $Sleep
    $vnet = & $Arm 'GET' $vnetPath $null
    $e = Set-SISubnet -Arm $Arm -VnetId $Target['VnetId'] -Name $Target['EndpointsSubnetName'] -Prefix $Target['EndpointsSubnetPrefix'] -Vnet $vnet -Sleep $Sleep
    $lines.Add($a.Line); $lines.Add($e.Line)
    @{ Ok = ($a.Ok -and $e.Ok); Lines = $lines.ToArray(); AppsSubnetId = $a.Id; EndpointsSubnetId = $e.Id
       Location = [string](Get-SIPnProp $vnet @('location')); VnetId = [string]$Target['VnetId']; VnetCreated = $created }
}

function Invoke-SIPrivateNetworkHandOff {
    <# Setup's call (#866, the end of the guided install's private-network step): the network hand-off -- read from Azure
       (never a write), the list, the hub owner's script, both written to -Directory when given. Returns @{ HandOff;
       Script; ListPath; ScriptPath; Facts }. #>
    param([Parameter(Mandatory)][System.Collections.IDictionary]$Target, [string]$EnvironmentId = '', [string[]]$InsideNames = @(), [string[]]$Notes = @(),
          [string]$CloseCommand = '', [string]$Directory = '', [string]$TenantId = '', [scriptblock]$Arm, [string]$SubscriptionId)
    if (-not $Arm) { $Arm = { param([string]$Method, [string]$Path, $Body) if ($Method -eq 'GET') { Invoke-SIArm -Path $Path -AllowNotFound } else { Invoke-SIArm -Method $Method -Path $Path -Body $Body } } }
    $f = Get-SINetworkHandOffFacts -Arm $Arm -Target $Target -EnvironmentId $EnvironmentId -InsideNames $InsideNames -Notes $Notes
    $f.CloseCommand = $CloseCommand
    $h = Get-SINetworkHandOff -Facts $f
    $s = New-SIHubOwnerScript -Facts $f -TenantId $TenantId
    $w = if ($Directory) { Write-SINetworkHandOffFiles -Directory $Directory -HandOff $h -Script $s } else { @{ ListPath = ''; ScriptPath = '' } }
    @{ HandOff = $h; Script = $s; ListPath = $w.ListPath; ScriptPath = $w.ScriptPath; Facts = $f }
}

function Invoke-SIPrivateNetworkSqlIdentity {
    <# Setup's call (the guided install's private-network step, Pro, BEFORE the public endpoints close): the in-network
       SQL identity id-si-sql, over setup's own ARM sign-in (Invoke-SIArm unless -Arm is given). Its membership of the
       admin group is the step's own Graph call. Returns Set-SISqlIdentity's answer. #>
    param([Parameter(Mandatory)][string]$ResourceGroupId, [Parameter(Mandatory)][string]$Location, [scriptblock]$Arm, [scriptblock]$Sleep, [string]$SubscriptionId)
    if (-not $Arm) { $Arm = { param([string]$Method, [string]$Path, $Body) if ($Method -eq 'GET') { Invoke-SIArm -Path $Path -AllowNotFound } else { Invoke-SIArm -Method $Method -Path $Path -Body $Body } } }
    if (-not $Sleep) { $Sleep = { param($s) Start-Sleep -Seconds $s } }
    Set-SISqlIdentity -Arm $Arm -ResourceGroupId $ResourceGroupId -Location $Location -Sleep $Sleep
}

function Set-SIPrivateEndpointsWithDns {
    <# The private endpoints of the given resources, each with its zone (Resolve-SIPrivateDnsZone: SecurityInsight's own,
       a central group's existing one, or the one of that name the network is already linked to), the zone's link to
       SecurityInsight's network and the endpoint's zone group -- each read back. Returns @{ Ok; Lines; HandOff }. #>
    param([Parameter(Mandatory)][scriptblock]$Arm, [Parameter(Mandatory)][System.Collections.IDictionary]$Target, [Parameter(Mandatory)][string]$Location,
          [Parameter(Mandatory)][string]$EndpointsSubnetId, [string]$SqlServerId = '', [string]$KeyVaultId = '', [string]$StorageAccountId = '', [string]$RegistryId = '',
          [scriptblock]$Sleep = { param($s) Start-Sleep -Seconds $s })
    $lines = New-Object System.Collections.Generic.List[string]; $handOff = New-Object System.Collections.Generic.List[string]; $ok = $true
    $zones = @{}
    $zSubs = Get-SIZoneSearchSubscriptions @([string]$Target['ResourceGroupId'], [string]$Target['VnetId'], [string]$Target['DnsResourceGroupId'])
    foreach ($t in @(Get-SIPrivateEndpointTargets -SqlServerId $SqlServerId -KeyVaultId $KeyVaultId -StorageAccountId $StorageAccountId -RegistryId $RegistryId)) {
        $pe = Set-SIPrivateEndpoint -Arm $Arm -ResourceGroupId $Target['ResourceGroupId'] -Location $Location -SubnetId $EndpointsSubnetId -Target $t -Sleep $Sleep
        $lines.Add($pe.Line); if (-not $pe.Ok) { $ok = $false; continue }
        if (-not $zones.ContainsKey($t.Zone)) {
            # #866 item 6: a central resource group's zone is used, never made; a same-name zone the network is already
            # linked to is used; a write SecurityInsight may not make on a zone that is not its own is a hand-off line
            $z = Resolve-SIPrivateDnsZone -Arm $Arm -Zone $t.Zone -ResourceGroupId $Target['ResourceGroupId'] -CentralResourceGroupId $Target['DnsResourceGroupId'] -VnetId $Target['VnetId'] -SubscriptionIds $zSubs -Sleep $Sleep
            $lines.Add($z.Line); $zones[$t.Zone] = ''
            if (-not $z.Ok) { $ok = $false; if ($z.HandOff) { $handOff.Add($z.Line) }; continue }
            $l = Set-SIPrivateDnsLink -Arm $Arm -ZoneId $z.ZoneId -VnetId $Target['VnetId'] -HandOffOnError:([bool]$z.Elsewhere) -Sleep $Sleep; $lines.Add($l.Line)
            if ($l.HandOff) { $handOff.Add($l.Line); $ok = $false } elseif (-not $l.Ok) { $ok = $false }
            $zones[$t.Zone] = $z.ZoneId
        }
        if (-not $zones[$t.Zone]) { continue }
        try { $g = Set-SIPrivateDnsZoneGroup -Arm $Arm -EndpointId $pe.Id -ZoneId $zones[$t.Zone] -Sleep $Sleep; $lines.Add($g.Line); if (-not $g.Ok) { $ok = $false } }
        catch { $ok = $false; $gl = ('{0}: its address could not be written into the zone {1} ({2}) -- the record is on the network hand-off list' -f $t.Name, $t.Zone, $_.Exception.Message); $lines.Add($gl); $handOff.Add($gl) }
    }
    @{ Ok = $ok; Lines = $lines.ToArray(); HandOff = $handOff.ToArray() }
}

function Invoke-SIPrivateNetworkDataEndpoints {
    <#
        Setup's call (#866, owner 2026-10-21: "we will not allow fw option or exceptions"): RIGHT AFTER a data resource is
        created private (the Key Vault and the storage account in the infrastructure step, the database server in pro-sql),
        its private endpoint(s), zone(s) and zone group(s) -- BEFORE anything reads or writes it. Then the DNS GATE
        (Invoke-SIPrivateNetworkDnsGate). Returns @{ Ok; Lines; HandOff; Gate }.
    #>
    param([Parameter(Mandatory)][System.Collections.IDictionary]$Target, [Parameter(Mandatory)][string]$Location, [string]$EndpointsSubnetId = '',
          [string]$SqlServerId = '', [string]$KeyVaultId = '', [string]$StorageAccountId = '', [scriptblock]$Resolve,
          [scriptblock]$Arm, [scriptblock]$Sleep, [string]$SubscriptionId)
    if (-not $Arm) { $Arm = { param([string]$Method, [string]$Path, $Body) if ($Method -eq 'GET') { Invoke-SIArm -Path $Path -AllowNotFound } else { Invoke-SIArm -Method $Method -Path $Path -Body $Body } } }
    if (-not $Sleep) { $Sleep = { param($s) Start-Sleep -Seconds $s } }
    if (-not $EndpointsSubnetId) { $EndpointsSubnetId = '{0}/subnets/{1}' -f ([string]$Target['VnetId']).TrimEnd('/'), [string]$Target['EndpointsSubnetName'] }
    $ep = Set-SIPrivateEndpointsWithDns -Arm $Arm -Target $Target -Location $Location -EndpointsSubnetId $EndpointsSubnetId -SqlServerId $SqlServerId -KeyVaultId $KeyVaultId -StorageAccountId $StorageAccountId -Sleep $Sleep
    $gate = Invoke-SIPrivateNetworkDnsGate -Arm $Arm -Target $Target -SqlServerId $SqlServerId -KeyVaultId $KeyVaultId -StorageAccountId $StorageAccountId -Resolve $Resolve
    @{ Ok = [bool]($ep.Ok -and $gate.Ok); Lines = @(@($ep.Lines) + @($gate.Lines)); HandOff = @($ep.HandOff); Gate = $gate; EndpointsOk = [bool]$ep.Ok }
}

function Invoke-SIPrivateNetworkDnsGate {
    <#
        THE PAUSE (#866): the machine that runs the install is inside the customer's network but resolves through the hub's
        DNS resolver, so the private endpoints' names resolve there only once the customer's network team has added them.
        This resolves each name of the given resources FROM THIS MACHINE and passes only when every one answers with its
        private address. Not passing: Records = the exact A records (zone, name, private address) for the hub, so the
        install stops with ONE customer action and a resume continues from here. Never a write to a resource this machine
        cannot reach. Returns @{ Ok; Lines; Failed; Records; Names }. Read only.
    #>
    param([Parameter(Mandatory)][scriptblock]$Arm, [Parameter(Mandatory)][System.Collections.IDictionary]$Target, [string]$SqlServerId = '', [string]$KeyVaultId = '',
          [string]$StorageAccountId = '', [scriptblock]$Resolve,
          # rule 11b: the container registry's names too (login server + data endpoint), before its first image build
          [string]$RegistryId = '')
    $get = { param($id, $api) if ($id) { & $Arm 'GET' ('{0}?api-version={1}' -f $id, $api) $null } else { $null } }
    $names = @(Get-SIInsideCheckNames -SqlServer (& $get $SqlServerId $script:SIPnSqlApi) -Vault (& $get $KeyVaultId $script:SIPnKvApi) -Storage (& $get $StorageAccountId $script:SIPnStApi) -Registry (& $get $RegistryId $script:SIPnAcrApi))
    $recs = @(Get-SIPrivateLinkRecords -Arm $Arm -ResourceGroupId ([string]$Target['ResourceGroupId']) | Where-Object { $names -contains $_.Fqdn })
    $m = Test-SIInsideResolution -Names $names -Resolve $Resolve
    $lines = New-Object System.Collections.Generic.List[string]
    $lines.Add($(if ($m.Ok) { 'DNS check (this machine): every name resolves to its private address -- the install goes on' } else { 'DNS check (this machine): NOT every name resolves to its private address yet -- the install waits for the hub DNS records' }))
    foreach ($l in $m.Lines) { $lines.Add('  ' + $l) }
    if (-not $m.Ok) {
        $lines.Add('ADD THESE A RECORDS where your network resolves (your hub''s private DNS zones of these names, or forward them on your resolver):')
        foreach ($r in $recs) { $lines.Add(('  zone {0,-36} {1,-36} A  {2}   ({3})' -f $r.Zone, $r.Name, $r.Ip, $r.Fqdn)) }
    }
    @{ Ok = [bool]$m.Ok; Lines = $lines.ToArray(); Failed = @($m.Failed); Records = $recs; Names = $names }
}

function Invoke-SIPrivateNetworkEndpoints {
    <#
        Setup's call (the guided install, after the database, the web app and the updater, before the first run): the
        registry to Premium, the private endpoints, their DNS zones (+ links, zone groups), the environment's DNS zone, and
        the public endpoints of the database server, the storage account and the Key Vault closed. Every change read back.
        -ClosePublic:$false leaves the public endpoints as they are. Returns @{ Ok; Lines }.
    #>
    param([Parameter(Mandatory)][System.Collections.IDictionary]$Target, [Parameter(Mandatory)][string]$Location, [Parameter(Mandatory)][string]$EndpointsSubnetId,
          [string]$SqlServerId = '', [string]$KeyVaultId = '', [string]$StorageAccountId = '', [string]$RegistryId = '', [string]$EnvironmentId = '',
          [bool]$ClosePublic = $true,
          # #866 the inside check before the close: -Resolve (test seam; default the system resolver), -UseInsideJob (a
          # one-time job in -EnvironmentId when this machine is not inside), -ConfirmedFromInside (the operator's word)
          [scriptblock]$Resolve, [bool]$UseInsideJob = $true, [switch]$ConfirmedFromInside,
          [scriptblock]$Arm, [scriptblock]$Sleep, [string]$SubscriptionId)
    if (-not $Arm) { $Arm = { param([string]$Method, [string]$Path, $Body) if ($Method -eq 'GET') { Invoke-SIArm -Path $Path -AllowNotFound } else { Invoke-SIArm -Method $Method -Path $Path -Body $Body } } }
    if (-not $Sleep) { $Sleep = { param($s) Start-Sleep -Seconds $s } }
    $lines = New-Object System.Collections.Generic.List[string]; $ok = $true
    if ($RegistryId) {
        $reg = & $Arm 'GET' ('{0}?api-version={1}' -f $RegistryId, $script:SIPnAcrApi) $null
        $d = Get-SIRegistrySkuDecision -Registry $reg
        if ($d.Action -eq 'upgrade') { $x = Set-SIRegistrySku -Arm $Arm -RegistryId $RegistryId -Sku 'Premium' -Sleep $Sleep; $lines.Add($x.Line); if (-not $x.Ok) { $ok = $false } }
    }
    $handOff = New-Object System.Collections.Generic.List[string]
    $ep = Set-SIPrivateEndpointsWithDns -Arm $Arm -Target $Target -Location $Location -EndpointsSubnetId $EndpointsSubnetId -SqlServerId $SqlServerId -KeyVaultId $KeyVaultId -StorageAccountId $StorageAccountId -RegistryId $RegistryId -Sleep $Sleep
    foreach ($x in $ep.Lines) { $lines.Add($x) }; foreach ($x in $ep.HandOff) { $handOff.Add($x) }; if (-not $ep.Ok) { $ok = $false }
    if ($EnvironmentId) {
        $env = & $Arm 'GET' ('{0}?api-version={1}' -f $EnvironmentId, $script:SIPnAppApi) $null
        if (Test-SIEnvironmentPrivate -Environment $env) {
            $hubLink = Get-SIHubLinkDecision -Arm $Arm -Target $Target
            if ($hubLink.Line) { $lines.Add($hubLink.Line); if (-not $hubLink.HubVnetId) { $handOff.Add($hubLink.Line) } }
            # the environment's own zone is ALWAYS in SecurityInsight's resource group (PIM's design) -- never the customer's
            $ed = Set-SIEnvironmentDns -Arm $Arm -ZoneResourceGroupId $Target['ResourceGroupId'] -Environment $env -VnetId $Target['VnetId'] -HubVnetId $hubLink.HubVnetId -Sleep $Sleep
            foreach ($x in $ed.Lines) { $lines.Add($x) }; if (-not $ed.Ok) { $ok = $false }
            foreach ($x in @($ed.HandOff)) { $handOff.Add($x) }
        } else { $ok = $false; $lines.Add('the Container Apps environment is not in the virtual network -- the web app is not private (an existing install moves with setup\Set-SIPrivateNetworking.ps1)') }
    }
    # the public endpoints closed only when every private way in reads back AND (#866) the names resolve to private
    # addresses from inside -- never a closed resource nothing can reach
    $closed = $false; $inside = $null
    $names = @()
    # #866 (owner: "we will not allow fw option or exceptions"): a private install CREATES its data resources private --
    # when every one reads closed already, nothing is left to close (its names were checked from this machine before any
    # write, Invoke-SIPrivateNetworkDnsGate)
    $openNow = @(foreach ($rid in @($SqlServerId, $StorageAccountId, $KeyVaultId) | Where-Object { $_ }) { $k = Get-SIPublicAccessKind $rid; if (-not (Test-SIPublicAccessClosed -Kind $k -Resource (& $Arm 'GET' ('{0}?api-version={1}' -f $rid, (Get-SIPublicAccessApi $k)) $null))) { $rid } })
    if ($ClosePublic -and $ok -and -not $openNow.Count) {
        $lines.Add('the database server, the storage account and the Key Vault were created private: no public endpoint to close')
        $apps0 = @(Get-SIPnArmList -Arm $Arm -Path ('{0}/providers/Microsoft.App/containerApps?api-version={1}' -f ([string]$Target['ResourceGroupId']).TrimEnd('/'), $script:SIPnAppApi) | ForEach-Object { [string](Get-SIPnProp $_ @('properties', 'configuration', 'ingress', 'fqdn')) } | Where-Object { $_ })
        $get0 = { param($id, $api) if ($id) { & $Arm 'GET' ('{0}?api-version={1}' -f $id, $api) $null } else { $null } }
        $names = @(Get-SIInsideCheckNames -AppFqdns $apps0 -SqlServer (& $get0 $SqlServerId $script:SIPnSqlApi) -Vault (& $get0 $KeyVaultId $script:SIPnKvApi) -Storage (& $get0 $StorageAccountId $script:SIPnStApi))
        return @{ Ok = $ok; Lines = $lines.ToArray(); HandOff = $handOff.ToArray(); Closed = $true; InsideCheck = @{ Ok = $true; Via = 'created-private'; Lines = @(); Failed = @() }; InsideNames = $names }
    }
    if ($ClosePublic -and $ok) {
        $apps = @(Get-SIPnArmList -Arm $Arm -Path ('{0}/providers/Microsoft.App/containerApps?api-version={1}' -f ([string]$Target['ResourceGroupId']).TrimEnd('/'), $script:SIPnAppApi) |
                  ForEach-Object { [string](Get-SIPnProp $_ @('properties', 'configuration', 'ingress', 'fqdn')) } | Where-Object { $_ })
        $get = { param($id, $api) if ($id) { & $Arm 'GET' ('{0}?api-version={1}' -f $id, $api) $null } else { $null } }
        $names = @(Get-SIInsideCheckNames -AppFqdns $apps -SqlServer (& $get $SqlServerId $script:SIPnSqlApi) -Vault (& $get $KeyVaultId $script:SIPnKvApi) -Storage (& $get $StorageAccountId $script:SIPnStApi))
        $inside = Invoke-SIInsideCheck -Arm $Arm -Names $names -Resolve $Resolve -ResourceGroupId ([string]$Target['ResourceGroupId']) -EnvironmentId $EnvironmentId -UseJob:$UseInsideJob -ConfirmedFromInside:$ConfirmedFromInside -Sleep $Sleep
        foreach ($x in $inside.Lines) { $lines.Add($x) }
    }
    if ($ClosePublic -and $ok -and $inside.Ok) {
        foreach ($rid in @($SqlServerId, $StorageAccountId, $KeyVaultId) | Where-Object { $_ }) {
            $c = Set-SIPublicAccess -Arm $Arm -ResourceId $rid -Sleep $Sleep; $lines.Add($c.Line); if (-not $c.Ok) { $ok = $false }
        }
        $closed = $ok
    } elseif ($ClosePublic -and $ok) {
        $lines.Add('the public endpoints are STILL OPEN: the names do not resolve to private addresses from inside yet -- nothing is closed that nothing could reach. Do the network hand-off, then run again (or confirm it from inside: -ConfirmedFromInside)')
        # a resource the customer's policy keeps closed already (e.g. a Key Vault with public access denied) is said: it is
        # reached from inside only, until the hub side is done
        foreach ($rid in @($SqlServerId, $StorageAccountId, $KeyVaultId) | Where-Object { $_ }) {
            $k = Get-SIPublicAccessKind $rid
            if (Test-SIPublicAccessClosed -Kind $k -Resource (& $Arm 'GET' ('{0}?api-version={1}' -f $rid, (Get-SIPublicAccessApi $k)) $null)) {
                $lines.Add(('{0}: its public endpoint is already closed (your policy) -- it is reached ONLY from inside SecurityInsight''s network until the hub side is done' -f ($rid -split '/')[-1]))
            }
        }
    } elseif ($ClosePublic) { $lines.Add('the public endpoints were NOT closed: a private way in did not read back (run again; nothing is closed before every private endpoint is ready)') }
    @{ Ok = $ok; Lines = $lines.ToArray(); HandOff = $handOff.ToArray(); Closed = $closed; InsideCheck = $inside; InsideNames = $names }
}
