<#
.SYNOPSIS
    SecurityInsight: moves ONE existing install onto private networking -- the Container Apps environment in your virtual
    network (internal), private endpoints for the database server, Key Vault, storage and the container registry, their
    private DNS zones, the web app reachable from your network only, the public endpoints closed. Through the Invardia
    Support app.

.DESCRIPTION
    A NEW install gets private networking from setup when it asks for it (privateNetwork in the guided install). An
    EXISTING install moves by this scripted cut-over, one environment at a time, run inside that environment's Support
    session (the pattern of setup\_shared\SI-SupportCutover.ps1; the library is setup\_shared\SI-PrivateNetwork.ps1).

    PLAN BY DEFAULT: prints the install's shape and what each step WOULD change. Nothing is changed.
      -Apply -Steps <list>   makes exactly those steps (string names, in this order; every step is idempotent -- one
                             with nothing to do says so and writes nothing; every change is read back):
        proof                read-only: the virtual network, the resources the jobs name, the environment they run in
        subnets              the environment's subnet (delegated to Container Apps, at least /27) and the private endpoints'
                             subnet -- created when they are not there (-AppsSubnetPrefix / -EndpointsSubnetPrefix), an
                             existing empty subnet delegated; a subnet in use or delegated elsewhere is never changed
        peer-to-hub          #866, ONLY on the customer's approval (naming this step IS that approval; -HubVnetId given):
                             SecurityInsight's network peered with the hub in BOTH directions (PIM's settings), both read
                             back Connected. The rights on both networks are read first -- missing = refused before any
                             change; never half a peering (a second side that fails removes the first). Without it the
                             peering stays on the network hand-off list. The rollback removes the peerings it made.
        registry-premium     the container registry to Premium (a private endpoint needs it; a higher daily price)
        private-endpoints    pe-si-sql, pe-si-vault, pe-si-blob, pe-si-queue, pe-si-table, pe-si-registry in the
                             endpoints' subnet (an endpoint of that name pointing elsewhere is never replaced)
        private-dns          the privatelink.* zones (in the install's resource group, or -DnsZonesResourceGroupId), each
                             linked to the virtual network, and each endpoint's address kept in its zone
        private-environment  the environment cae-si-private in the environment's subnet, INTERNAL, its logs to where the
                             current environment's go, and its own DNS zone (its default domain -> its internal address)
        move-jobs            every job moved to cae-si-private. Azure cannot move a job: it is REMOVED and CREATED AGAIN
                             under the same name with the same identities, settings and schedule, and the role assignments
                             made on it are made again. A job that is running, or holds a secret that is not a Key Vault
                             reference, is not touched (said). The old environment is left as it is (empty).
        move-apps            the web app and the MCP server the same way; the web app reachable from the virtual network
                             (in an internal environment "external" ingress has no public address), its new address ADDED
                             to its sign-in registration (the old one stays)
        sql-identity         the in-network SQL identity id-si-sql (user-assigned) and its membership of the database
                             server's admin group, read back from the member's side. No job carries it: only the one-time
                             job of setup\Invoke-SISupportSqlAccessJob.ps1 does, while it runs (PIM: id-pim-sql-<token>)
        support-sql          the Invardia Support app's own database user (db_owner) in every database on the server and
                             its membership of the admin group -- made NOW, while the database still has its public
                             endpoint, and read back (framework 4.1b). Never removed by anything here.
        public-access-off    the public endpoints of the database server and the storage account closed (Disabled), the
                             Key Vault's firewall Deny with trusted Microsoft services allowed. Only after the private
                             endpoints read back, AND only when the Support app's database access reads back (support-sql)
                             -- -WithoutSupportSqlAccess closes without it (support then reaches the database only from
                             inside, through Invoke-SISupportSqlAccessJob.ps1) -- AND (#866, PIM's verify-inside) only
                             when the names (web app, database, Key Vault, storage) resolve to private addresses from
                             inside: from this machine, else a one-time job in the environment (caj-si-insidecheck, always
                             removed), else -ConfirmedFromInside. Otherwise nothing closes and the network hand-off says
                             what the customer's network team still does. From then on the install is reached from
                             your network only, and it STAYS that way: nothing in SecurityInsight opens it again.
        registry-agent-pool  an agent pool of the registry (si-vnet-pool) in the endpoints subnet: image builds -- setup's
                             and the updater's -- run inside the network (they find it themselves once the registry is closed)
        registry-public-off  the registry's public endpoint closed too -- REFUSED until the registry's private endpoint is
                             approved and its agent pool runs in the network (PIM's rule).
      -Rollback <record> -Apply   puts back what that record says (newest first): the jobs and apps moved back to the
                             environment they came from, and what this run CREATED removed (endpoints, zone groups, links,
                             zones, the private environment when it is empty, subnets, the agent pool, the SQL identity and
                             its membership). The registry's tier goes back where Azure allows it. The Support app's
                             database access is never taken away.
                             OWNER 2026-10-19: "when we say it is private, it stays that way". A record that CLOSED a public
                             endpoint is REFUSED (nothing changed) unless -ReopenPublicAccess is given: that is the
                             customer's own decision to leave private networking, and it is said in the output.
    ONE rollback record per run: a JSON file here (the path is printed) and a short copy in the install
    (cfg.InstallState 'PrivateNetworkCutover'). After -Apply the script waits -ObserveMinutes (default 6), then counts the
    install's runs since the cut-over and the failures.

    Every later setup run finds the private environment by name (cae-si-private) and keeps using it.

.EXAMPLE
    . C:\claude-sessions\Invardia\tools\Connect-InvardiaSupport.ps1 -Environment <handle> -Reason 'private networking'
    .\Set-SIPrivateNetworking.ps1 -ResourceGroup <rg> -VnetId <vnet id> -AppsSubnetPrefix 10.20.0.0/27 -EndpointsSubnetPrefix 10.20.0.32/28
    .\Set-SIPrivateNetworking.ps1 -ResourceGroup <rg> -VnetId <vnet id> -Apply -Steps subnets,registry-premium,private-endpoints,private-dns
    .\Set-SIPrivateNetworking.ps1 -ResourceGroup <rg> -VnetId <vnet id> -Apply -Steps private-environment,move-jobs,move-apps
    .\Set-SIPrivateNetworking.ps1 -ResourceGroup <rg> -VnetId <vnet id> -Apply -Steps sql-identity,support-sql,public-access-off
    .\Set-SIPrivateNetworking.ps1 -ResourceGroup <rg> -VnetId <vnet id> -Apply -Steps registry-agent-pool,registry-public-off
    .\Set-SIPrivateNetworking.ps1 -Rollback <record.json> -Apply

.LINK
    https://invardia.com/docs/si/scripts/Set-SIPrivateNetworking/
#>
[CmdletBinding()]
param(
    [string]$ResourceGroup,
    [string]$SubscriptionId,
    # the customer's virtual network (resource id)
    [string]$VnetId = '',
    # #866: OR an address range for SecurityInsight's OWN spoke network, made in the install's resource group by the subnets
    # step (-VnetName, default vnet-si); the subnets then default to its first and second /26. An existing network is
    # never changed.
    [string]$VnetAddressPrefix = '',
    [string]$VnetName = '',
    [string]$AppsSubnetName = '',
    [string]$AppsSubnetPrefix = '',
    [string]$EndpointsSubnetName = '',
    [string]$EndpointsSubnetPrefix = '',
    # the resource group (id) of the customer's central private DNS zones; default: the install's resource group
    [string]$DnsZonesResourceGroupId = '',
    # #866: the customer's hub virtual network (resource id; may be in another subscription). OWNER 2026-10-21: by default
    # NOTHING is written on the hub -- the id only makes the network hand-off exact (names, ids, the hub owner's script)
    [ValidatePattern('(?i)^$|/providers/Microsoft\.Network/virtualNetworks/[^/]+$')][string]$HubVnetId = '',
    # the customer's choice: link the environment's DNS zone to the hub too (the rights are read first; missing = refused
    # before any change, a hand-off line)
    [switch]$LinkZonesToHub,
    [switch]$Apply,
    [string[]]$Steps = @(),
    [string]$Rollback = '',
    # overrides when the jobs do not name them (never guessed from a name pattern)
    [string]$KeyVaultName = '',
    [string]$StorageAccountName = '',
    [string]$RegistryName = '',
    [string]$SqlServerName = '',
    # the Invardia Support app's client id (support-sql); default: the Support session's own application
    [ValidatePattern('^$|^[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$')][string]$SupportAppId = '',
    [string]$SupportDbUserName = 'invardia-support-app',
    # public-access-off without the Support app's database access read back (support then reaches it only from inside)
    [switch]$WithoutSupportSqlAccess,
    # #866 public-access-off only once the names resolve to private addresses from inside (this machine, else a one-time
    # job in the environment) -- or the operator confirms it from inside the network
    [switch]$ConfirmedFromInside,
    # -Rollback of a record that closed a public endpoint: the customer's own decision to leave private networking
    [switch]$ReopenPublicAccess,
    [string]$Reason = 'SecurityInsight private networking',
    [string]$Environment = '',
    [string]$RecordDirectory = '',
    [ValidateRange(0, 30)][int]$ObserveMinutes = 6,
    # TEST SEAMS (setup\_shared\SI-SupportCutover.ps1): replace the Support session
    [scriptblock]$Arm, [scriptblock]$Sql, [scriptblock]$Graph,
    # TEST SEAM (#866): the name resolver of the inside check { param([string]$Name) } -> addresses; default: the system's
    [scriptblock]$Resolve,
    [scriptblock]$Sleep = { param($s) Start-Sleep -Seconds $s }
)

$ErrorActionPreference = 'Stop'
. ([IO.Path]::Combine($PSScriptRoot, '_shared', 'SI-SupportCutover.ps1'))
. ([IO.Path]::Combine($PSScriptRoot, '_shared', 'SI-PrivateNetwork.ps1'))
# the Support app's database access (Pro: the support-sql step) -- loaded only where it is shipped; the Community copy has no
# Support app, so its support-sql step cannot run there (a cut-over in the Community copy skips that step: -Steps)
$__siSad = [IO.Path]::Combine($PSScriptRoot, '_shared', 'SI-SupportAppDatabase.ps1')
if ([IO.File]::Exists($__siSad)) { . $__siSad }
$script:SIPnSteps = @('proof', 'subnets', 'peer-to-hub', 'registry-premium', 'private-endpoints', 'private-dns', 'private-environment', 'move-jobs', 'move-apps',
                      'sql-identity', 'support-sql', 'public-access-off', 'registry-agent-pool', 'registry-public-off')
$names = Get-SIPrivateNetworkNames

function Write-SIPnLine { param([string]$Text, [string]$Color = 'Gray') Write-Host $Text -ForegroundColor $Color }

$seams = New-SICutoverSeams -Arm $Arm -Sql $Sql -Graph $Graph -Reason $Reason
$A = $seams.Arm
$sess = $null; if (Get-Command -Name Get-SISupportSession -ErrorAction SilentlyContinue) { try { $sess = Get-SISupportSession } catch { $sess = $null } }
if (-not $Environment) { $Environment = if ($sess -and [string]$sess.Environment) { [string]$sess.Environment } else { 'environment' } }
if (-not $RecordDirectory) { $RecordDirectory = [IO.Path]::Combine([Environment]::GetFolderPath('CommonApplicationData'), 'si', 'logs', 'cutover') }

function Remove-SIPnCreated {
    <# DELETE one resource this run created (the record names it), read back gone. Returns a line. #>
    param([string]$Id, [string]$Api, [string]$Label)
    if (-not $Id) { return '' }
    $p = '{0}?api-version={1}' -f $Id, $Api
    try {
        $null = & $A 'DELETE' $p $null
        $gone = Read-SIPnBack -Arm $A -Path $p -Sleep $Sleep -Tries 30 -PauseSeconds 10 -Test { param($o) $null -eq $o }
        if ($null -eq $gone) { return ('{0} {1} removed (read back)' -f $Label, ($Id -split '/')[-1]) }
        return ('{0} {1} is still there' -f $Label, ($Id -split '/')[-1])
    } catch { return ('{0} {1} could not be removed: {2}' -f $Label, ($Id -split '/')[-1], $_.Exception.Message) }
}

# ---------------------------------------------------------------------------------------------------- ROLLBACK
if ($Rollback.Trim()) {
    $rb = [IO.File]::ReadAllText($Rollback) | ConvertFrom-Json
    Write-SIPnLine ('== ROLLBACK of {0} ({1}) from {2} -- applied: {3}' -f $rb.environment, $rb.resourceGroup, $Rollback, (@($rb.applied) -join ', ')) 'Yellow'
    # NEVER-REOPEN (owner 2026-10-19): a record that closed a public endpoint is not rolled back -- not even in part: the
    # moves and the endpoints are what keep a closed install reachable -- unless the customer decides to leave private
    # networking (-ReopenPublicAccess)
    $closedIn = @(@($rb.applied) | Where-Object { $_ -in 'public-access-off', 'registry-public-off' })
    if ($closedIn.Count -and -not $ReopenPublicAccess) {
        Write-SIPnLine ('REFUSED -- this record closed public endpoints ({0}). A private install stays private: nothing was changed. Only the customer''s own decision to leave private networking opens them again: -ReopenPublicAccess.' -f ($closedIn -join ', ')) 'Red'
        return [pscustomobject]@{ Mode = 'rollback-refused'; Results = @([pscustomobject]@{ Step = 'rollback'; Ok = $false; Lines = @('refused: the record closed public endpoints; -ReopenPublicAccess is the customer''s decision to leave private networking') }) }
    }
    if ($closedIn.Count) { Write-SIPnLine ('-ReopenPublicAccess: the customer leaves private networking -- the public endpoints closed by this record ({0}) are OPENED again.' -f ($closedIn -join ', ')) 'Yellow' }
    if (-not $Apply) { Write-SIPnLine 'PLAN ONLY -- nothing was changed. Add -Apply to put the recorded values back.' 'Yellow'; return [pscustomobject]@{ Mode = 'rollback-plan'; Results = @() } }
    $results = New-Object System.Collections.Generic.List[object]
    $order = @($rb.applied); [array]::Reverse($order)
    foreach ($step in $order) {
        $b = $rb.before.$step
        $lines = New-Object System.Collections.Generic.List[string]; $okAll = $true
        try {
            switch ([string]$step) {
                { $_ -in 'public-access-off', 'registry-public-off' } {
                    foreach ($r in @($b.resources)) { if (-not [string]$r.id) { continue }; $x = Set-SIPublicAccess -Arm $A -ResourceId ([string]$r.id) -Before (ConvertTo-SIPnHashtable $r.before) -AllowReopen:$ReopenPublicAccess -Sleep $Sleep; $lines.Add($x.Line); if (-not $x.Ok) { $okAll = $false } }
                }
                'support-sql' { $lines.Add('the Support app''s database access is kept (it is never taken away -- framework 4.1b)') }
                'sql-identity' {
                    if ([string]$b.groupId -and [string]$b.memberAdded) {
                        try { $null = & $seams.Graph 'DELETE' ('https://graph.microsoft.com/v1.0/groups/{0}/members/{1}/$ref' -f [string]$b.groupId, [string]$b.memberAdded) $null; $lines.Add('the in-network SQL identity left the admin group') }
                        catch { $okAll = $false; $lines.Add(('the in-network SQL identity could not leave the admin group: {0}' -f $_.Exception.Message)) }
                    }
                    if ([string]$b.created) { $lines.Add((Remove-SIPnCreated -Id ([string]$b.created) -Api $script:SIPnMiApi -Label 'identity')) }
                }
                'registry-agent-pool' { if ([string]$b.created) { $lines.Add((Remove-SIPnCreated -Id ([string]$b.created) -Api $script:SIPnAcrTasksApi -Label 'agent pool')) } }
                { $_ -in 'move-jobs', 'move-apps' } {
                    foreach ($m in @($b.moved)) {
                        $cur = & $A 'GET' ('{0}?api-version={1}' -f [string]$m.id, $script:SIPnAppApi) $null
                        if (-not $cur) { $cur = $m.definition }
                        $x = Move-SIContainerResource -Arm $A -Resource $cur -EnvironmentId ([string]$m.environmentId) -Kind ([string]$m.kind) -External $m.external -Sleep $Sleep
                        foreach ($l in $x.Lines) { $lines.Add($l) }; if (-not $x.Ok) { $okAll = $false }
                    }
                    if ($b.signIn -and [string]$b.signIn.objectId) {
                        $web = [ordered]@{ redirectUris = @($b.signIn.redirectUris); logoutUrl = [string]$b.signIn.logoutUrl }
                        try { $null = & $seams.Graph 'PATCH' ('https://graph.microsoft.com/v1.0/applications/{0}' -f [string]$b.signIn.objectId) ([ordered]@{ web = $web }); $lines.Add('the sign-in registration''s addresses are back as they were') }
                        catch { $okAll = $false; $lines.Add(('the sign-in registration''s addresses could not be put back: {0}' -f $_.Exception.Message)) }
                    }
                }
                'private-environment' {
                    foreach ($l in @($b.dnsLinksCreated)) { if ([string]$l) { $lines.Add((Remove-SIPnCreated -Id ([string]$l) -Api $script:SIPnDnsApi -Label 'DNS link')) } }
                    foreach ($z in @($b.dnsCreated)) { $lines.Add((Remove-SIPnCreated -Id ([string]$z) -Api $script:SIPnDnsApi -Label 'DNS')) }
                    if ([string]$b.created) {
                        $inUse = @(@(Get-SIPnArmList -Arm $A -Path ('/subscriptions/{0}/resourceGroups/{1}/providers/Microsoft.App/jobs?api-version={2}' -f $rb.subscriptionId, $rb.resourceGroup, $script:SIPnAppApi)) + @(Get-SIPnArmList -Arm $A -Path ('/subscriptions/{0}/resourceGroups/{1}/providers/Microsoft.App/containerApps?api-version={2}' -f $rb.subscriptionId, $rb.resourceGroup, $script:SIPnAppApi)) |
                                   Where-Object { (Test-SIPnSameId ([string](Get-SIPnProp $_ @('properties', 'environmentId'))) ([string]$b.created)) -or (Test-SIPnSameId ([string](Get-SIPnProp $_ @('properties', 'managedEnvironmentId'))) ([string]$b.created)) })
                        if ($inUse.Count) { $okAll = $false; $lines.Add(('the private environment still holds {0} -- it is not removed (roll back the moves first)' -f ((@($inUse | ForEach-Object { [string]$_.name })) -join ', '))) }
                        else { $lines.Add((Remove-SIPnCreated -Id ([string]$b.created) -Api $script:SIPnAppApi -Label 'environment')) }
                    }
                }
                'private-dns' {
                    foreach ($g in @($b.groupsCreated)) { $lines.Add((Remove-SIPnCreated -Id ([string]$g) -Api $script:SIPnNetApi -Label 'DNS zone group')) }
                    foreach ($l in @($b.linksCreated)) { $lines.Add((Remove-SIPnCreated -Id ([string]$l) -Api $script:SIPnDnsApi -Label 'DNS link')) }
                    foreach ($z in @($b.zonesCreated)) { $lines.Add((Remove-SIPnCreated -Id ([string]$z) -Api $script:SIPnDnsApi -Label 'DNS zone')) }
                }
                'peer-to-hub' { foreach ($pp in @($b.created)) { if ([string]$pp) { $lines.Add((Remove-SIPnCreated -Id ([string]$pp) -Api $script:SIPnNetApi -Label 'peering')) } } }
                'private-endpoints' { foreach ($e in @($b.created)) { $lines.Add((Remove-SIPnCreated -Id ([string]$e) -Api $script:SIPnNetApi -Label 'private endpoint')) } }
                'registry-premium' {
                    if ([string]$b.registryId -and [string]$b.sku) { try { $x = Set-SIRegistrySku -Arm $A -RegistryId ([string]$b.registryId) -Sku ([string]$b.sku) -Sleep $Sleep; $lines.Add($x.Line); if (-not $x.Ok) { $okAll = $false } } catch { $okAll = $false; $lines.Add(('the registry stays Premium: {0}' -f $_.Exception.Message)) } }
                }
                'subnets' {
                    foreach ($s in @($b.created)) { $lines.Add((Remove-SIPnCreated -Id ([string]$s) -Api $script:SIPnNetApi -Label 'subnet')) }
                    if ([string]$b.vnetCreated) { $lines.Add((Remove-SIPnCreated -Id ([string]$b.vnetCreated) -Api $script:SIPnNetApi -Label 'virtual network')) }
                    foreach ($s in @($b.delegated)) {
                        try {
                            $p = '{0}?api-version={1}' -f [string]$s.id, $script:SIPnNetApi
                            $body = Get-SISubnetBody -Subnet $s.before
                            $null = & $A 'PUT' $p $body; $lines.Add(('subnet {0}: its delegation is back as it was' -f ([string]$s.id -split '/')[-1]))
                        } catch { $okAll = $false; $lines.Add(('subnet {0}: its delegation could not be put back: {1}' -f ([string]$s.id -split '/')[-1], $_.Exception.Message)) }
                    }
                }
                default { $okAll = $false; $lines.Add('not a step of this script') }
            }
        } catch { $okAll = $false; $lines.Add(('rollback FAILED: {0}' -f $_.Exception.Message)) }
        foreach ($l in @($lines | Where-Object { $_ })) { Write-SIPnLine ('{0,-20} {1}' -f $step, $l) $(if ($okAll) { 'Green' } else { 'Red' }) }
        $results.Add([pscustomobject]@{ Step = [string]$step; Ok = $okAll; Lines = @($lines | Where-Object { $_ }) })
    }
    return [pscustomobject]@{ Mode = 'rollback'; Results = $results.ToArray() }
}

# ---------------------------------------------------------------------------------------------------- SHAPE
if (-not $ResourceGroup) { throw 'Give -ResourceGroup: the install''s resource group (where its jobs are).' }
if (-not $SubscriptionId) { $SubscriptionId = if ($sess) { [string]$sess.SubscriptionId } else { '' } }
if (-not $SubscriptionId) { throw 'Give -SubscriptionId: the Support session names no subscription.' }
$want = @(Resolve-SICutoverSteps -Steps $Steps -Known $script:SIPnSteps)
if ($Apply -and -not $want.Count) { throw ('-Apply needs -Steps: name the steps to make ({0}). Nothing was changed.' -f ($script:SIPnSteps -join ', ')) }

$shape = Get-SIInstallShape -Arm $A -SubscriptionId $SubscriptionId -ResourceGroup $ResourceGroup -SqlServerName $SqlServerName -FindSqlInResourceGroup
if (-not @($shape.Jobs).Count) { throw ('No Container Apps job was found in {0} (subscription {1}) -- is this the install''s resource group? Nothing was changed.' -f $ResourceGroup, $SubscriptionId) }
Write-SIPnLine ('== {0}' -f $Environment) 'Cyan'
foreach ($l in (Format-SIInstallShape -Shape $shape)) { Write-SIPnLine ('   ' + $l) $(if ($l -like 'NOT READ*') { 'Yellow' } else { 'Gray' }) }
$rgId = '/subscriptions/{0}/resourceGroups/{1}' -f $SubscriptionId, $ResourceGroup
$all = @($shape.Jobs) + @($shape.Apps)

# the install's resources: named by the jobs, else the ONE of its kind in the resource group (never a name pattern)
function Find-SIPnOne {
    param([string]$Type, [string]$Api, [string]$Name)
    if ($Name) { return (& $A 'GET' ('{0}/providers/{1}/{2}?api-version={3}' -f $rgId, $Type, $Name, $Api) $null) }
    $l = @(Get-SIPnArmList -Arm $A -Path ('{0}/providers/{1}?api-version={2}' -f $rgId, $Type, $Api))
    if ($l.Count -eq 1) { return $l[0] }
    $null
}
$kvN = if ($KeyVaultName) { $KeyVaultName } else { $shape.KeyVaultName }
$vault = Find-SIPnOne -Type 'Microsoft.KeyVault/vaults' -Api $script:SIPnKvApi -Name $kvN
$stN = if ($StorageAccountName) { $StorageAccountName } else { Get-SICutoverEnv -Resources $all -Name 'SI_StorageAccount' }
$storage = Find-SIPnOne -Type 'Microsoft.Storage/storageAccounts' -Api $script:SIPnStApi -Name $stN
$registry = $null
if ($RegistryName) { $registry = Find-SIPnOne -Type 'Microsoft.ContainerRegistry/registries' -Api $script:SIPnAcrApi -Name $RegistryName }
else {
    $servers = @($all | ForEach-Object { @(Get-SIPnProp $_ @('properties', 'configuration', 'registries')) } | Where-Object { $_ } | ForEach-Object { ([string](Get-SIPnProp $_ @('server'))).ToLowerInvariant() } | Where-Object { $_ } | Select-Object -Unique)
    if ($servers.Count -eq 1) { $registry = @(Get-SIPnArmList -Arm $A -Path ('/subscriptions/{0}/providers/Microsoft.ContainerRegistry/registries?api-version={1}' -f $SubscriptionId, $script:SIPnAcrApi) | Where-Object { ([string](Get-SIPnProp $_ @('properties', 'loginServer'))).ToLowerInvariant() -eq $servers[0] })[0] }
}
$ids = [ordered]@{ SqlServerId = [string]$shape.SqlServerId; KeyVaultId = [string](Get-SIPnProp $vault @('id')); StorageAccountId = [string](Get-SIPnProp $storage @('id')); RegistryId = [string](Get-SIPnProp $registry @('id')) }
$targets = @(Get-SIPrivateEndpointTargets @ids)
$currentEnvId = @($shape.Jobs | ForEach-Object { [string](Get-SIPnProp $_ @('properties', 'environmentId')) } | Where-Object { $_ } | Select-Object -First 1)[0]
$currentEnv = if ($currentEnvId) { & $A 'GET' ('{0}?api-version={1}' -f $currentEnvId, $script:SIPnAppApi) $null } else { $null }
$location = if ($currentEnv) { [string]$currentEnv.location } else { [string](Get-SIPnProp @($shape.Jobs)[0] @('location')) }
$tgt = Get-SIInstallPrivateNetworkTarget -Values ([ordered]@{ vnetId = $VnetId; appsSubnetName = $AppsSubnetName; appsSubnetPrefix = $AppsSubnetPrefix; endpointsSubnetName = $EndpointsSubnetName; endpointsSubnetPrefix = $EndpointsSubnetPrefix; privateDnsZonesResourceGroupId = $DnsZonesResourceGroupId; hubVnetId = $HubVnetId; linkZonesToHub = [bool]$LinkZonesToHub
                                                            vnetAddressPrefix = $VnetAddressPrefix; vnetName = $VnetName }) -ResourceGroupId $rgId
$appsSubnetId = if ($tgt.VnetId) { '{0}/subnets/{1}' -f $tgt.VnetId, $tgt.AppsSubnetName } else { '' }
$peSubnetId = if ($tgt.VnetId) { '{0}/subnets/{1}' -f $tgt.VnetId, $tgt.EndpointsSubnetName } else { '' }
$privEnvId = '{0}/providers/Microsoft.App/managedEnvironments/{1}' -f $rgId, $names.PrivateEnvironment
Write-SIPnLine ('   environment    : {0}{1}' -f $(if ($currentEnvId) { ($currentEnvId -split '/')[-1] } else { '(the jobs name none)' }), $(if (Test-SIEnvironmentPrivate -Environment $currentEnv) { ' (private)' } else { '' })) 'Gray'
foreach ($k in 'KeyVaultId', 'StorageAccountId', 'RegistryId') { Write-SIPnLine ('   {0,-15}: {1}' -f ($k -replace 'Id$', ''), $(if ($ids[$k]) { ($ids[$k] -split '/')[-1] } else { '(not found -- give its name)' })) $(if ($ids[$k]) { 'Gray' } else { 'Yellow' }) }

# ---------------------------------------------------------------------------------------------------- PROOF + PLAN (read-only)
$plan = [ordered]@{}
$vnet = if ($tgt.VnetId) { & $A 'GET' ('{0}?api-version={1}' -f $tgt.VnetId, $script:SIPnNetApi) $null } else { $null }
$noVnet = if (-not $tgt.VnetId) { 'give -VnetId (the virtual network the install moves into) or -VnetAddressPrefix (SecurityInsight makes its own)' } elseif (-not $vnet -and $tgt.CreateVnet) { '' } elseif (-not $vnet) { ('the virtual network {0} was not found, or the Support app cannot read it' -f $tgt.VnetId) } else { '' }
if ($noVnet) { foreach ($s in 'subnets', 'private-endpoints', 'private-dns', 'private-environment') { $plan[$s] = @{ Action = 'skip'; Reason = $noVnet } } }
else {
    $sa = Get-SISubnetDecision -Subnet (& $A 'GET' ('{0}?api-version={1}' -f $appsSubnetId, $script:SIPnNetApi) $null) -Prefix $tgt.AppsSubnetPrefix -Name $tgt.AppsSubnetName -Delegate -Vnet $vnet
    $se = Get-SISubnetDecision -Subnet (& $A 'GET' ('{0}?api-version={1}' -f $peSubnetId, $script:SIPnNetApi) $null) -Prefix $tgt.EndpointsSubnetPrefix -Name $tgt.EndpointsSubnetName -Vnet $vnet
    $vnetWhy = if ($tgt.CreateVnet -and -not $vnet) { $sd = Get-SISpokeSubnetDefaults -AddressPrefix $tgt.VnetAddressPrefix; if ($sd.Ok) { 'the virtual network {0} ({1}) is made in the install''s resource group; ' -f ($tgt.VnetId -split '/')[-1], $tgt.VnetAddressPrefix } else { 'FAIL ' + $sd.Reason } } else { '' }
    $plan['subnets'] = @{ Action = $(if ($sa.Action -eq 'fail' -or $se.Action -eq 'fail' -or $vnetWhy -like 'FAIL *') { 'skip' } elseif ($sa.Action -eq 'none' -and $se.Action -eq 'none') { 'none' } else { 'change' }); Reason = ($vnetWhy + $sa.Reason + '; ' + $se.Reason) }
    $missing = @($targets | Where-Object { -not (Test-SIPrivateEndpointMatch -Endpoint (& $A 'GET' ('{0}/providers/Microsoft.Network/privateEndpoints/{1}?api-version={2}' -f $rgId, $_.Name, $script:SIPnNetApi) $null) -Target $_ -SubnetId $peSubnetId) } | ForEach-Object { $_.Name })
    $plan['private-endpoints'] = @{ Action = $(if ($missing.Count) { 'change' } else { 'none' }); Reason = $(if ($missing.Count) { 'made: ' + ($missing -join ', ') } else { 'every private endpoint is there' }) }
    $plan['private-dns'] = @{ Action = 'change'; Reason = ('the zones {0} in {1}, linked to the virtual network, each endpoint''s address in its zone (what is there is kept)' -f ((@($targets | ForEach-Object { $_.Zone } | Select-Object -Unique)) -join ', '), ($tgt.DnsResourceGroupId -split '/')[-1]) }
    $pe = & $A 'GET' ('{0}?api-version={1}' -f $privEnvId, $script:SIPnAppApi) $null
    # #866: an environment that is there still needs its own zone complete: its records, the links to the spoke AND the hub
    $envDnsMissing = if (Test-SIEnvironmentPrivate -Environment $pe -SubnetId $appsSubnetId) { @(Get-SIEnvironmentDnsMissing -Arm $A -ZoneResourceGroupId $rgId -Environment $pe -LinkVnetIds $tgt.LinkVnetIds) } else { @() }
    $plan['private-environment'] = @{ Action = $(if ((Test-SIEnvironmentPrivate -Environment $pe -SubnetId $appsSubnetId) -and -not $envDnsMissing.Count) { 'none' } else { 'change' })
                                      Reason = $(if ($pe -and $envDnsMissing.Count) { 'the environment {0} is there; its DNS zone still needs: {1}' -f $names.PrivateEnvironment, ($envDnsMissing -join ', ') } elseif ($pe) { 'the environment {0} is there, its DNS zone complete' -f $names.PrivateEnvironment } else { 'the environment {0} is made in {1}, internal (Azure takes up to 30 minutes)' -f $names.PrivateEnvironment, $tgt.AppsSubnetName }) }
}
$plan['peer-to-hub'] = if (-not $tgt.HubVnetId) { @{ Action = 'skip'; Reason = 'no hub is named (-HubVnetId): the peering is on the network hand-off list' } }
    elseif ($noVnet) { @{ Action = 'skip'; Reason = $noVnet } }
    elseif (-not $vnet) { @{ Action = 'change'; Reason = 'SecurityInsight''s network is made first (subnets); then the peering with the hub, both directions' } }
    else {
        $pst = Get-SIPeeringState -Arm $A -VnetId $tgt.VnetId -RemoteVnetId $tgt.HubVnetId
        if ($pst -eq 'Connected') { @{ Action = 'none'; Reason = 'the peering with the hub reads Connected' } }
        else { @{ Action = 'change'; Reason = ('the peering with {0}, BOTH directions -- only on the customer''s approval; the rights are read first (state now: {1})' -f ($tgt.HubVnetId -split '/')[-1], $(if ($pst) { $pst } else { 'not made' })) } }
    }
$plan['registry-premium'] = Get-SIRegistrySkuDecision -Registry $registry
if ($plan['registry-premium'].Action -eq 'upgrade') { $plan['registry-premium'].Action = 'change' }
foreach ($kind in 'job', 'app') {
    $step = if ($kind -eq 'job') { 'move-jobs' } else { 'move-apps' }
    $list = if ($kind -eq 'job') { @($shape.Jobs) } else { @($shape.Apps) }
    $prop = if ($kind -eq 'app') { 'managedEnvironmentId' } else { 'environmentId' }
    $todo = @($list | Where-Object { -not (Test-SIPnSameId ([string](Get-SIPnProp $_ @('properties', $prop))) $privEnvId) })
    $probs = @($todo | ForEach-Object { Get-SIContainerMoveProblem -Resource $_ } | Where-Object { $_ })
    $plan[$step] = @{ Action = $(if ($todo.Count) { 'change' } else { 'none' }); Reason = $(if ($todo.Count) { ('{0} moved to {1} (removed and created again under the same name): {2}{3}' -f $todo.Count, $names.PrivateEnvironment, ((@($todo | ForEach-Object { [string]$_.name })) -join ', '), $(if ($probs.Count) { ' -- NOT moved: ' + ($probs -join '; ') } else { '' })) } else { 'every {0} runs in {1}' -f $kind, $names.PrivateEnvironment }) }
}
$openNow = @(foreach ($rid in @($ids.SqlServerId, $ids.StorageAccountId, $ids.KeyVaultId) | Where-Object { $_ }) { $k = Get-SIPublicAccessKind $rid; $r = & $A 'GET' ('{0}?api-version={1}' -f $rid, (Get-SIPublicAccessApi $k)) $null; if (-not (Test-SIPublicAccessClosed -Kind $k -Resource $r)) { ($rid -split '/')[-1] } })
$plan['public-access-off'] = @{ Action = $(if ($openNow.Count) { 'change' } else { 'none' }); Reason = $(if ($openNow.Count) { 'closed: ' + ($openNow -join ', ') + ' -- only once every private endpoint reads back' } else { 'the public endpoints are closed' }) }
$regClosed = if ($registry) { Test-SIPublicAccessClosed -Kind 'registry' -Resource $registry } else { $true }

# the in-network SQL identity, the Support app's database access, the registry's agent pool (#681, PIM's design)
$adminGroupId = if ($shape.EntraAdmin -and [string]$shape.EntraAdmin.Type -eq 'Group') { [string]$shape.EntraAdmin.Sid } else { '' }
if (-not $SupportAppId) { $SupportAppId = if ($sess) { [string]$sess.AppId } else { '' } }
$miPath = '{0}/providers/Microsoft.ManagedIdentity/userAssignedIdentities/{1}?api-version={2}' -f $rgId, $names.SqlIdentity, $script:SIPnMiApi
$sqlMi = & $A 'GET' $miPath $null
$sqlMiMember = $null
if ($sqlMi -and $adminGroupId) { try { $sqlMiMember = Test-SISupportAppGroupMember -Graph $seams.Graph -GroupId $adminGroupId -ServicePrincipalId ([string](Get-SIPnProp $sqlMi @('properties', 'principalId'))) } catch { $sqlMiMember = $null } }
$plan['sql-identity'] = if (-not $ids.SqlServerId) { @{ Action = 'skip'; Reason = 'no database server (Community, or give -SqlServerName)' } }
    elseif (-not $adminGroupId) { @{ Action = 'skip'; Reason = 'the database server''s administrator is not a group -- run setup\Set-SISqlAdminGroup.ps1 first' } }
    elseif ($sqlMi -and $sqlMiMember -eq $true) { @{ Action = 'none'; Reason = ('{0} is there and a member of the admin group' -f $names.SqlIdentity) } }
    else { @{ Action = 'change'; Reason = ('{0}{1} made a member of the admin group (read back from its side); no job carries it' -f $names.SqlIdentity, $(if ($sqlMi) { ' is there --' } else { ' made,' })) } }
$dbNames = @()
if ($ids.SqlServerId) { $dbNames = @(Get-SIPnArmList -Arm $A -Path ('{0}/databases?api-version={1}' -f $ids.SqlServerId, $script:SIPnSqlApi) | ForEach-Object { [string](Get-SIPnProp $_ @('name')) } | Where-Object { $_ -and $_ -ne 'master' } | Sort-Object -Unique) }
$sqlScalar = { param([string]$Database, [string]$Query) $rows = @(& $seams.Sql ([string]$shape.SqlFqdn) $Database $Query $Reason $false | ForEach-Object { $_ }); [string](Get-SICutoverProp @($rows | Where-Object { $null -ne $_ })[0] @('Value')) }
$sqlScalarRead = { param([string]$Database, [string]$Query) $rows = @(& $seams.Sql ([string]$shape.SqlFqdn) $Database $Query $Reason $true | ForEach-Object { $_ }); [string](Get-SICutoverProp @($rows | Where-Object { $null -ne $_ })[0] @('Value')) }
$supportRows = @()
if (-not $ids.SqlServerId) { $plan['support-sql'] = @{ Action = 'skip'; Reason = 'no database server' } }
elseif (-not $SupportAppId) { $plan['support-sql'] = @{ Action = 'skip'; Reason = 'no Support app is named (-SupportAppId; the Support session names none)' } }
elseif (-not $dbNames.Count) { $plan['support-sql'] = @{ Action = 'skip'; Reason = 'no database was found on the server' } }
else {
    $supportRows = @(Invoke-SISupportAppDatabaseAccess -Sql $sqlScalarRead -Databases $dbNames -ClientId $SupportAppId -UserName $SupportDbUserName)
    $unread = @($supportRows | Where-Object { $_.State -eq 'unchecked' })
    $plan['support-sql'] = if (-not @($supportRows | Where-Object { $_.State -ne 'present' }).Count) { @{ Action = 'none'; Reason = ('the Support app has its own database user with db_owner in {0}' -f ($dbNames -join ', ')) } }
        elseif ($unread.Count -and (Test-SIPublicAccessClosed -Kind 'sql' -Resource $shape.SqlServer)) { @{ Action = 'skip'; Reason = 'the database is private already -- the Support app''s database user is given FROM INSIDE: setup\the support SQL access job' } }
        else { @{ Action = 'change'; Reason = ('the Support app''s own database user with db_owner made in {0} and its membership of the admin group, while the public endpoint is still there (read back)' -f ((@($supportRows | Where-Object { $_.State -ne 'present' } | ForEach-Object { $_.Database })) -join ', ')) } }
}
$pools = @(); if ($registry) { $pools = @(Get-SIPnArmList -Arm $A -Path ('{0}/agentPools?api-version={1}' -f $ids.RegistryId, $script:SIPnAcrTasksApi)) }
$poolIn = @($pools | Where-Object { Test-SIAcrAgentPoolInNetwork -Pool $_ -VnetId $tgt.VnetId })
$plan['registry-agent-pool'] = if (-not $registry) { @{ Action = 'skip'; Reason = 'the install''s container registry was not found (give -RegistryName)' } }
    elseif ($noVnet) { @{ Action = 'skip'; Reason = $noVnet } }
    elseif ($poolIn.Count) { @{ Action = 'none'; Reason = ('the registry''s agent pool {0} runs in the network' -f [string](Get-SIPnProp $poolIn[0] @('name'))) } }
    else { @{ Action = 'change'; Reason = ('the agent pool {0} (one S1 agent) in {1}: image builds run inside the network' -f $names.AgentPool, $tgt.EndpointsSubnetName) } }
$regPe = & $A 'GET' ('{0}/providers/Microsoft.Network/privateEndpoints/{1}registry?api-version={2}' -f $rgId, $names.EndpointPrefix, $script:SIPnNetApi) $null
$regWhy = Get-SIRegistryCloseProblem -RegistryEndpoint $regPe -Pools $pools -VnetId $tgt.VnetId
$plan['registry-public-off'] = @{ Action = $(if (-not $registry) { 'skip' } elseif ($regClosed) { 'none' } else { 'change' }); Reason = $(if (-not $registry) { 'the install''s container registry was not found (give -RegistryName)' } elseif ($regClosed) { 'the registry''s public endpoint is closed' } elseif ($regWhy) { 'NOT YET: ' + $regWhy } else { 'the registry''s public endpoint is closed (its builds run on the agent pool in the network)' }) }

Write-SIPnLine ('{0,-20} read-only: {1}' -f 'proof', $(if ($noVnet) { $noVnet } else { 'virtual network {0} ({1}); {2} private endpoint(s) planned' -f ($tgt.VnetId -split '/')[-1], [string](Get-SIPnProp $vnet @('location')), $targets.Count })) 'DarkGray'
foreach ($k in @($script:SIPnSteps | Where-Object { $plan.Contains($_) })) {
    $d = $plan[$k]
    $what = switch ([string]$d.Action) { 'none' { 'nothing to do' } 'skip' { 'SKIPPED' } default { 'WOULD CHANGE' } }
    Write-SIPnLine ('{0,-20} {1}: {2}' -f $k, $what, $d.Reason) $(switch ([string]$d.Action) { 'none' { 'DarkGray' } 'skip' { 'Yellow' } default { 'White' } })
}
# #866: THE NETWORK HAND-OFF -- the exact list for the customer's network team (read only), printed after the plan and after
# every run; after a run also written next to the record with the hub owner's script, and kept in the record for Invardia
function Show-SIPnHandOff {
    param([string[]]$Notes = @(), [string]$Directory = '')
    if (-not $tgt.VnetId -or -not (& $A 'GET' ('{0}?api-version={1}' -f $tgt.VnetId, $script:SIPnNetApi) $null)) { return $null }
    $appsNow = @(Get-SIPnArmList -Arm $A -Path ('{0}/providers/Microsoft.App/containerApps?api-version={1}' -f $rgId, $script:SIPnAppApi))
    $fq = @($appsNow | ForEach-Object { [string](Get-SIPnProp $_ @('properties', 'configuration', 'ingress', 'fqdn')) } | Where-Object { $_ })
    $envNow = if (& $A 'GET' ('{0}?api-version={1}' -f $privEnvId, $script:SIPnAppApi) $null) { $privEnvId } elseif (Test-SIEnvironmentPrivate -Environment $currentEnv) { $currentEnvId } else { '' }
    $sqlNow = if ($ids.SqlServerId) { & $A 'GET' ('{0}?api-version={1}' -f $ids.SqlServerId, $script:SIPnSqlApi) $null } else { $null }
    $hoNames = @(Get-SIInsideCheckNames -AppFqdns $fq -SqlServer $sqlNow -Vault $vault -Storage $storage)
    $stillOpen = @(foreach ($rid in @($ids.SqlServerId, $ids.StorageAccountId, $ids.KeyVaultId) | Where-Object { $_ }) { $k = Get-SIPublicAccessKind $rid; if (-not (Test-SIPublicAccessClosed -Kind $k -Resource (& $A 'GET' ('{0}?api-version={1}' -f $rid, (Get-SIPublicAccessApi $k)) $null))) { $rid } })
    $close = if ($stillOpen.Count) { './setup/Set-SIPrivateNetworking.ps1 -ResourceGroup {0} -VnetId {1} -Apply -Steps public-access-off' -f $ResourceGroup, $tgt.VnetId } else { '' }
    # the hand-off only reads and prints: a failure here is said, never stops or fails the run
    try { $ho = Invoke-SIPrivateNetworkHandOff -Arm $A -Target $tgt -EnvironmentId $envNow -InsideNames $hoNames -Notes $Notes -CloseCommand $close -Directory $Directory }
    catch { Write-SIPnLine ('the network hand-off could not be made: {0}' -f $_.Exception.Message) 'Yellow'; return $null }
    foreach ($l in @($ho.HandOff.Lines)) { Write-SIPnLine $l 'Yellow' }
    if ($ho.ListPath) { Write-SIPnLine ('network hand-off written: {0}{1}' -f $ho.ListPath, $(if ($ho.ScriptPath) { '; the hub owner''s script: ' + $ho.ScriptPath } else { '' })) 'Cyan' }
    $ho
}

if (-not $Apply) {
    $hoPlan = Show-SIPnHandOff
    Write-SIPnLine ('PLAN ONLY -- nothing was changed. Apply: -Apply -Steps <{0}>' -f ($script:SIPnSteps[1..($script:SIPnSteps.Count - 1)] -join ',')) 'Yellow'
    return [pscustomobject]@{ Mode = 'plan'; Shape = $shape; Plan = $plan; RecordPath = $null; Results = @(); HandOff = $(if ($hoPlan) { $hoPlan.HandOff } else { $null }) }
}

# ---------------------------------------------------------------------------------------------------- APPLY
$started = [datetime]::UtcNow
$record = New-SICutoverRecord -Script 'Set-SIPrivateNetworking' -Environment $Environment -Shape $shape -Now $started
$recPath = Get-SICutoverRecordPath -Directory $RecordDirectory -Script 'Set-SIPrivateNetworking' -Environment $Environment -Now $started
$script:SIPnSaved = $null
$save = { $script:SIPnSaved = Save-SICutoverRecord -Record $record -Path $recPath -Sql $seams.Sql -StateName 'PrivateNetworkCutover' }
$results = New-Object System.Collections.Generic.List[object]
$handOffLines = New-Object System.Collections.Generic.List[string]
foreach ($k in $want) {
    if ($k -eq 'proof') { continue }
    $d = $plan[$k]
    if ([string]$d.Action -in 'none', 'skip') { Write-SIPnLine ('{0,-20} nothing to do: {1}' -f $k, $d.Reason) 'DarkGray'; continue }
    $lines = New-Object System.Collections.Generic.List[string]; $okAll = $true
    try {
        # the before-values are written FIRST and grow as each part is made (a step that fails half-way is rolled back too)
        $bf = [ordered]@{}
        $record.before[$k] = $bf
        $record.applied = @($record.applied) + @($k)
        & $save
        switch ($k) {
            'subnets' {
                $bf['created'] = @(); $bf['delegated'] = @(); $bf['vnetCreated'] = ''
                if ($tgt.CreateVnet) {
                    $v = Set-SIVnet -Arm $A -VnetId $tgt.VnetId -Location $location -AddressPrefix $tgt.VnetAddressPrefix -Sleep $Sleep
                    if ($v.Created) { $bf['vnetCreated'] = $tgt.VnetId }
                    & $save; $lines.Add($v.Line); if (-not $v.Ok) { throw 'the virtual network is not ready -- no subnet was made' }
                }
                foreach ($s in @(@{ N = $tgt.AppsSubnetName; P = $tgt.AppsSubnetPrefix; D = $true }, @{ N = $tgt.EndpointsSubnetName; P = $tgt.EndpointsSubnetPrefix; D = $false })) {
                    $vnow = & $A 'GET' ('{0}?api-version={1}' -f $tgt.VnetId, $script:SIPnNetApi) $null
                    $x = Set-SISubnet -Arm $A -VnetId $tgt.VnetId -Name $s.N -Prefix $s.P -Delegate:([bool]$s.D) -Vnet $vnow -Sleep $Sleep
                    if ($x.Action -eq 'create') { $bf['created'] = @($bf['created']) + @($x.Id) }
                    elseif ($x.Action -eq 'delegate') { $bf['delegated'] = @($bf['delegated']) + @([ordered]@{ id = $x.Id; before = (ConvertTo-SIPnHashtable $x.Before) }) }
                    & $save; $lines.Add($x.Line); if (-not $x.Ok) { $okAll = $false }
                }
            }
            'peer-to-hub' {
                $bf['created'] = @()
                $x = Set-SIVnetPeering -Arm $A -SpokeVnetId $tgt.VnetId -HubVnetId $tgt.HubVnetId -Sleep $Sleep
                if (@($x.Created).Count) { $bf['created'] = @($x.Created) }
                & $save
                foreach ($l in $x.Lines) { $lines.Add($l) }; if (-not $x.Ok) { $okAll = $false; foreach ($l in $x.Lines) { $handOffLines.Add($l) } }
            }
            'registry-premium' {
                $bf['registryId'] = $ids.RegistryId; $bf['sku'] = [string]$plan['registry-premium'].Sku; & $save
                $x = Set-SIRegistrySku -Arm $A -RegistryId $ids.RegistryId -Sku 'Premium' -Sleep $Sleep; $lines.Add($x.Line); if (-not $x.Ok) { $okAll = $false }
            }
            'private-endpoints' {
                $bf['created'] = @()
                foreach ($t in $targets) {
                    $x = Set-SIPrivateEndpoint -Arm $A -ResourceGroupId $rgId -Location ([string](Get-SIPnProp $vnet @('location'))) -SubnetId $peSubnetId -Target $t -Sleep $Sleep
                    if ($x.Created) { $bf['created'] = @($bf['created']) + @($x.Id); & $save }
                    $lines.Add($x.Line); if (-not $x.Ok) { $okAll = $false }
                }
            }
            'private-dns' {
                $bf['zonesCreated'] = @(); $bf['linksCreated'] = @(); $bf['groupsCreated'] = @(); $zones = @{}
                foreach ($t in $targets) {
                    $peId = '{0}/providers/Microsoft.Network/privateEndpoints/{1}' -f $rgId, $t.Name
                    if (-not (& $A 'GET' ('{0}?api-version={1}' -f $peId, $script:SIPnNetApi) $null)) { $okAll = $false; $lines.Add(('{0} is not there -- run private-endpoints first' -f $t.Name)); continue }
                    if (-not $zones.ContainsKey($t.Zone)) {
                        # #866 item 6: a central resource group's zone is used, never made (missing = hand-off); a same-name
                        # zone the network is already linked to is used (Azure refuses a second)
                        $z = Resolve-SIPrivateDnsZone -Arm $A -Zone $t.Zone -ResourceGroupId $rgId -CentralResourceGroupId $tgt.DnsResourceGroupId -VnetId $tgt.VnetId -SubscriptionIds (Get-SIZoneSearchSubscriptions @($rgId, $tgt.VnetId, $tgt.DnsResourceGroupId)) -Sleep $Sleep
                        if ($z.Created) { $bf['zonesCreated'] = @($bf['zonesCreated']) + @($z.ZoneId); & $save }
                        $lines.Add($z.Line); $zones[$t.Zone] = ''
                        if (-not $z.Ok) { $okAll = $false; if ($z.HandOff) { $handOffLines.Add($z.Line) }; continue }
                        $l = Set-SIPrivateDnsLink -Arm $A -ZoneId $z.ZoneId -VnetId $tgt.VnetId -HandOffOnError:([bool]$z.Elsewhere) -Sleep $Sleep
                        if ($l.Created) { $bf['linksCreated'] = @($bf['linksCreated']) + @($l.Id); & $save }
                        $lines.Add($l.Line); if ($l.HandOff) { $handOffLines.Add($l.Line); $okAll = $false } elseif (-not $l.Ok) { $okAll = $false }
                        $zones[$t.Zone] = $z.ZoneId
                    }
                    if (-not $zones[$t.Zone]) { continue }
                    $g = Set-SIPrivateDnsZoneGroup -Arm $A -EndpointId $peId -ZoneId $zones[$t.Zone] -Sleep $Sleep
                    if ($g.Created) { $bf['groupsCreated'] = @($bf['groupsCreated']) + @(('{0}/privateDnsZoneGroups/{1}' -f $peId, $names.ZoneGroup)); & $save }
                    $lines.Add($g.Line); if (-not $g.Ok) { $okAll = $false }
                }
            }
            'private-environment' {
                $bf['created'] = ''; $bf['dnsCreated'] = @(); $bf['dnsLinksCreated'] = @()
                $x = Set-SIPrivateEnvironment -Arm $A -ResourceGroupId $rgId -Name $names.PrivateEnvironment -Location $location -SubnetId $appsSubnetId -LogsLikeId $currentEnvId -Sleep $Sleep
                if ($x.Created) { $bf['created'] = $privEnvId; & $save }
                $lines.Add($x.Line); if (-not $x.Ok) { $okAll = $false }
                else {
                    $hubLink = Get-SIHubLinkDecision -Arm $A -Target $tgt
                    if ($hubLink.Line) { $lines.Add($hubLink.Line); $handOffLines.Add($hubLink.Line) }
                    $dn = Set-SIEnvironmentDns -Arm $A -ZoneResourceGroupId $rgId -Environment $x.Environment -VnetId $tgt.VnetId -HubVnetId $hubLink.HubVnetId -Sleep $Sleep
                    # the record remembers EVERY link it made (the hub's too): a zone with links cannot be removed, so the
                    # rollback removes the links first
                    if ($dn.Created) { $bf['dnsCreated'] = @($dn.ZoneId) }
                    if (@($dn.LinksCreated).Count) { $bf['dnsLinksCreated'] = @($dn.LinksCreated) }
                    & $save
                    foreach ($l in $dn.Lines) { $lines.Add($l) }; if (-not $dn.Ok) { $okAll = $false }
                    foreach ($l in @($dn.HandOff)) { $handOffLines.Add($l) }
                }
            }
            { $_ -in 'move-jobs', 'move-apps' } {
                $kind = if ($k -eq 'move-jobs') { 'job' } else { 'app' }
                $prop = if ($kind -eq 'app') { 'managedEnvironmentId' } else { 'environmentId' }
                $penv = & $A 'GET' ('{0}?api-version={1}' -f $privEnvId, $script:SIPnAppApi) $null
                if (-not (Test-SIEnvironmentPrivate -Environment $penv) -or -not (Test-SIPnSucceeded $penv)) { throw ('the private environment {0} is not ready -- run private-environment first. Nothing was moved.' -f $names.PrivateEnvironment) }
                $bf['moved'] = @()
                $list = if ($kind -eq 'job') { @($shape.Jobs) } else { @($shape.Apps) }
                foreach ($r in @($list | Where-Object { -not (Test-SIPnSameId ([string](Get-SIPnProp $_ @('properties', $prop))) $privEnvId) })) {
                    $isWeb = ($kind -eq 'app' -and [string]$r.name -notmatch '(?i)mcp' -and [string]$r.name -match '(?i)management|web')
                    $roles = @(Get-SIScopedRoleAssignments -Arm $A -Scope ([string]$r.id))
                    $bf['moved'] = @($bf['moved']) + @(Get-SIMoveRecord -Resource $r -Kind $kind -RoleAssignments $roles); & $save
                    $x = Move-SIContainerResource -Arm $A -Resource $r -EnvironmentId $privEnvId -Kind $kind -External $(if ($isWeb) { $true } else { $null }) -RoleAssignments $roles -Sleep $Sleep
                    foreach ($l in $x.Lines) { $lines.Add($l) }; if (-not $x.Ok) { $okAll = $false }
                    if ($x.Ok -and $isWeb -and $x.Fqdn) {
                        $cid = Get-SICutoverEnv -Resources @($r) -Name 'AzureAd__ClientId'
                        if ($cid) {
                            $si = Add-SIWebSignInAddress -Graph $seams.Graph -ClientId $cid -Fqdn $x.Fqdn
                            if ($si.Before) { $bf['signIn'] = $si.Before; & $save }
                            $lines.Add($si.Line); if (-not $si.Ok) { $okAll = $false }
                        } else { $okAll = $false; $lines.Add(('the web app names no sign-in registration (AzureAd__ClientId) -- add https://{0}/signin-oidc to it by hand' -f $x.Fqdn)) }
                        $lines.Add(('the web app now answers at https://{0}/ -- from your network only' -f $x.Fqdn))
                    }
                }
            }
            'sql-identity' {
                $bf['created'] = ''; $bf['groupId'] = $adminGroupId; $bf['memberAdded'] = ''
                $x = Set-SISqlIdentity -Arm $A -ResourceGroupId $rgId -Location $location -Name $names.SqlIdentity -Sleep $Sleep
                if ($x.Created) { $bf['created'] = $x.Id; & $save }
                $lines.Add($x.Line); if (-not $x.Ok) { throw ('the in-network SQL identity {0} is not ready' -f $names.SqlIdentity) }
                $was = $false; try { $was = Test-SISupportAppGroupMember -Graph $seams.Graph -GroupId $adminGroupId -ServicePrincipalId $x.PrincipalId } catch { $was = $false }
                $m = Set-SISupportAppGroupMember -Graph $seams.Graph -GroupId $adminGroupId -ServicePrincipalId $x.PrincipalId -Apply -Sleep $Sleep
                if ($m.State -eq 'added' -or ($m.State -eq 'unchecked' -and -not $was)) { $bf['memberAdded'] = $x.PrincipalId; & $save }
                $lines.Add(('{0}, the admin group: {1}' -f $names.SqlIdentity, $m.Detail)); if ($m.State -notin 'present', 'added') { $okAll = $false }
            }
            'support-sql' {
                # framework 4.1b, made while the public endpoint is still there: its own user with db_owner in every
                # database, and its membership of the admin group -- each read back; NOTHING is ever removed
                $sp = & $seams.Graph 'GET' ("https://graph.microsoft.com/v1.0/servicePrincipals?`$filter=appId eq '{0}'&`$select=id" -f $SupportAppId) $null
                $spId = [string](Get-SIPnProp @(Get-SIPnProp $sp @('value') | Where-Object { $_ })[0] @('id'))
                if (-not $spId) { throw ('the Support app {0} is not in this tenant' -f $SupportAppId) }
                if ($adminGroupId) { $m = Set-SISupportAppGroupMember -Graph $seams.Graph -GroupId $adminGroupId -ServicePrincipalId $spId -Apply -Sleep $Sleep; $lines.Add(('the Support app, the admin group: {0}' -f $m.Detail)); if ($m.State -notin 'present', 'added') { $okAll = $false } }
                foreach ($row in @(Invoke-SISupportAppDatabaseAccess -Sql $sqlScalar -Databases $dbNames -ClientId $SupportAppId -UserName $SupportDbUserName -Apply)) {
                    $lines.Add(('{0}: {1}' -f $row.Database, $row.Detail)); if ($row.State -notin 'present', 'granted') { $okAll = $false }
                }
            }
            'registry-agent-pool' {
                $bf['created'] = ''
                $x = Set-SIAcrAgentPool -Arm $A -RegistryId $ids.RegistryId -Name $names.AgentPool -Location ([string](Get-SIPnProp $registry @('location'))) -SubnetId $peSubnetId -Sleep $Sleep
                if ($x.Created) { $bf['created'] = $x.Id; & $save }
                $lines.Add($x.Line); if (-not $x.Ok) { $okAll = $false }
            }
            { $_ -in 'public-access-off', 'registry-public-off' } {
                $bf['resources'] = @()
                $rids = if ($k -eq 'registry-public-off') { @($ids.RegistryId) } else { @($ids.SqlServerId, $ids.StorageAccountId, $ids.KeyVaultId) }
                if ($k -eq 'public-access-off') {
                    # never closed before every private way in reads back
                    $notReady = @($targets | Where-Object { $_.Kind -ne 'registry' } | Where-Object { $e = & $A 'GET' ('{0}/providers/Microsoft.Network/privateEndpoints/{1}?api-version={2}' -f $rgId, $_.Name, $script:SIPnNetApi) $null; -not ((Test-SIPnSucceeded $e) -and (Get-SIPrivateEndpointState $e) -eq 'Approved') } | ForEach-Object { $_.Name })
                    if ($notReady.Count) { throw ('not every private endpoint is ready ({0}) -- nothing was closed. Run private-endpoints and private-dns first.' -f ($notReady -join ', ')) }
                    # ... nor before the Support app's database access reads back (after the close it is reached only from inside)
                    if ($ids.SqlServerId -and -not $WithoutSupportSqlAccess) {
                        if (-not $SupportAppId) { throw 'no Support app is named, so its database access cannot be read back -- nothing was closed. Give -SupportAppId, or -WithoutSupportSqlAccess (support then reaches the database only from inside).' }
                        $now = @(Invoke-SISupportAppDatabaseAccess -Sql $sqlScalarRead -Databases $dbNames -ClientId $SupportAppId -UserName $SupportDbUserName)
                        $short = @($now | Where-Object { $_.State -ne 'present' } | ForEach-Object { '{0} ({1})' -f $_.Database, $_.State })
                        if (-not $dbNames.Count -or $short.Count) { throw ('the Support app''s database access does not read back ({0}) -- nothing was closed. Run support-sql first, or -WithoutSupportSqlAccess (support then reaches the database only from inside: setup\the support SQL access job).' -f $(if ($short.Count) { $short -join ', ' } else { 'no database found' })) }
                        $lines.Add(('the Support app''s own database user with db_owner reads back in {0}' -f ($dbNames -join ', ')))
                    } elseif ($WithoutSupportSqlAccess) { $lines.Add('-WithoutSupportSqlAccess: closed without reading back the Support app''s database access -- support reaches the database only from inside (setup\the support SQL access job)') }
                    # #866 (PIM's verify-inside): the names resolve to private addresses from inside -- from this machine, else a
                    # one-time job in the environment the apps run in -- or the operator confirms it. Otherwise nothing closes.
                    $appsNow = @(Get-SIPnArmList -Arm $A -Path ('{0}/providers/Microsoft.App/containerApps?api-version={1}' -f $rgId, $script:SIPnAppApi))
                    $fqdns = @($appsNow | ForEach-Object { [string](Get-SIPnProp $_ @('properties', 'configuration', 'ingress', 'fqdn')) } | Where-Object { $_ })
                    $runEnv = @($appsNow | ForEach-Object { [string](Get-SIPnProp $_ @('properties', 'managedEnvironmentId')) } | Where-Object { $_ } | Select-Object -First 1)[0]
                    if (-not $runEnv) { $runEnv = $currentEnvId }
                    $insideNames = @(Get-SIInsideCheckNames -AppFqdns $fqdns -SqlServer $(if ($ids.SqlServerId) { & $A 'GET' ('{0}?api-version={1}' -f $ids.SqlServerId, $script:SIPnSqlApi) $null }) -Vault $vault -Storage $storage)
                    $ic = Invoke-SIInsideCheck -Arm $A -Names $insideNames -Resolve $Resolve -ResourceGroupId $rgId -EnvironmentId $runEnv -UseJob -ConfirmedFromInside:$ConfirmedFromInside -Sleep $Sleep
                    foreach ($l in $ic.Lines) { $lines.Add($l) }
                    $bf['insideCheck'] = [ordered]@{ via = $ic.Via; failed = @($ic.Failed) }; & $save
                    if (-not $ic.Ok) { throw ('the names do not resolve to private addresses from inside ({0}) -- nothing was closed. Do the network hand-off below, then run again; or, when it is checked from inside the network, -ConfirmedFromInside.' -f ((@($ic.Failed)) -join ', ')) }
                    if ($ids.SqlServerId -and -not ($sqlMi -and $sqlMiMember -eq $true) -and -not (@($record.applied) -contains 'sql-identity')) { $lines.Add(('note: the in-network SQL identity {0} is not in place -- support''s way in from inside needs it (step sql-identity)' -f $names.SqlIdentity)) }
                }
                if ($k -eq 'registry-public-off') {
                    $poolsNow = @(Get-SIPnArmList -Arm $A -Path ('{0}/agentPools?api-version={1}' -f $ids.RegistryId, $script:SIPnAcrTasksApi))
                    $peNow = & $A 'GET' ('{0}/providers/Microsoft.Network/privateEndpoints/{1}registry?api-version={2}' -f $rgId, $names.EndpointPrefix, $script:SIPnNetApi) $null
                    $why = Get-SIRegistryCloseProblem -RegistryEndpoint $peNow -Pools $poolsNow -VnetId $tgt.VnetId
                    if ($why) { throw ('the registry''s public endpoint is NOT closed: {0}.' -f $why) }
                }
                foreach ($rid in @($rids | Where-Object { $_ })) {
                    $kd = Get-SIPublicAccessKind $rid
                    $cur = & $A 'GET' ('{0}?api-version={1}' -f $rid, (Get-SIPublicAccessApi $kd)) $null
                    if (Test-SIPublicAccessClosed -Kind $kd -Resource $cur) { $lines.Add(('{0}: its public endpoint is already closed' -f ($rid -split '/')[-1])); continue }
                    $bf['resources'] = @($bf['resources']) + @([ordered]@{ id = $rid; before = (Get-SIPublicAccessBefore -Kind $kd -Resource $cur) }); & $save
                    $x = Set-SIPublicAccess -Arm $A -ResourceId $rid -Sleep $Sleep; $lines.Add($x.Line); if (-not $x.Ok) { $okAll = $false }
                }
            }
        }
    } catch { $okAll = $false; $lines.Add(('FAILED: {0}' -f $_.Exception.Message)) }
    foreach ($l in @($lines | Where-Object { $_ })) { Write-SIPnLine ('{0,-20} {1}' -f $k, $l) $(if ($okAll) { 'Green' } else { 'Red' }) }
    $results.Add([pscustomobject]@{ Step = $k; Ok = $okAll; Lines = @($lines | Where-Object { $_ }) })
}
$obs = $null
$hoRun = Show-SIPnHandOff -Notes @($handOffLines) -Directory $(if (@($record.applied).Count) { [IO.Path]::Combine((Split-Path -Parent $recPath), ('network-hand-off-{0}' -f ($Environment -replace '[^A-Za-z0-9_.-]', '_'))) } else { '' })
if ($hoRun -and @($record.applied).Count) { $record['handOff'] = [ordered]@{ open = [int]$hoRun.HandOff.Open; lines = @($hoRun.HandOff.Lines); list = $hoRun.ListPath; script = $hoRun.ScriptPath }; & $save }
if (@($record.applied).Count) {
    Write-SIPnLine ('rollback record: {0}{1}' -f $recPath, $(if ($script:SIPnSaved -and $script:SIPnSaved.InstallLine) { ' -- ' + $script:SIPnSaved.InstallLine } else { '' })) 'Cyan'
    Write-SIPnLine ('waiting {0} minute(s), then counting the runs since the cut-over ...' -f $ObserveMinutes) 'DarkGray'
    $obs = Wait-SICutoverObservation -Arm $A -Shape $shape -Since $started -Minutes $ObserveMinutes -Sleep $Sleep
    Write-SIPnLine $obs.Line $(if ($obs.Failed) { 'Red' } elseif ($obs.Runs) { 'Green' } else { 'Yellow' })
    foreach ($l in @($obs.Lines)) { Write-SIPnLine ('   ' + $l) 'Red' }
} else { Write-SIPnLine 'nothing was changed -- no rollback record was written.' 'DarkGray' }
[pscustomobject]@{ Mode = 'apply'; Shape = $shape; Plan = $plan; RecordPath = $(if (@($record.applied).Count) { $recPath } else { $null }); Results = $results.ToArray(); Observation = $obs; HandOff = $(if ($hoRun) { $hoRun.HandOff } else { $null }) }
