#Requires -Version 5.1
<#
.SYNOPSIS
    The names and tags setup gives the Azure resources it CREATES for a new SecurityInsight install.

.DESCRIPTION
    NEW GUIDED INSTALLS (framework section 5.5, owner 2026-11-04): <type>-si[-<purpose>] with no ring / edition / hosting, and
    <t> (SHA-256 of the install id) on the globally unique names -- Get-SISetupInstallNames. Everything below is the EARLIER
    pattern: what every existing install runs with, the server / unattended setup, and a resource group named in it.
    Pattern: <type>-si-<ring>-<edition>-<hosting>, for example rg-si-prod-community-ca.
      ring    : r0 | r1 | r2 | prod (prod = a single production install, the default)
      edition : community | pro (spelled out)
      hosting : ca (Azure Container Apps) | vm (a Windows server or Azure Arc machine). Always present: a VM install
                and a container install of the same edition can run side by side.
    Registry, storage account, Key Vault and SQL server names must be unique in ALL of Azure (they are DNS names:
    <name>.database.windows.net, <name>.vault.azure.net, ...). Without a subscription they carry the instance number 01
    (stsiprodcommunityca01) -- every install of the same edition then wants the SAME name. With -SubscriptionId they
    carry a short STABLE per-install suffix instead: the first 6 hex characters of SHA-256(subscription id, lower case),
    e.g. sql-si-prod-pro-ca-1a2b3c. Live 2026-10-07: a second customer's Pro install failed preflight because another
    tenant's install already held sql-si-prod-pro-ca. An EXISTING install keeps its names: the guided install looks for
    its resources first (Resolve-SIInstallExistingNames), the server / unattended / container setup the same way
    (Resolve-SISetupDefaultGlobalName), and only a resource none of them finds gets a new name.

    ONLY FOR NEW RESOURCES. The engines and launchers find an EXISTING install through the names in its config, and
    fall back to the names older releases created (rg-securityinsight, dce-securityinsight, ...). Those fallbacks are
    deliberately NOT here and NOT changed: an install that never wrote a name into its config depends on them.
    A customer may always choose their own names; these are only the defaults.

    Every function here is pure except Resolve-SITenantTag (one read of the signed-in Az context).
#>

$script:SISetupRings     = @('r0', 'r1', 'r2', 'prod')
$script:SISetupEditions  = @('community', 'pro')
$script:SISetupHostings  = @('ca', 'vm')

function Get-SISetupEnvLabel {
    <# PURE. '<ring>-<edition>-<hosting>', e.g. 'prod-community-ca'. Used in resource names and, in brackets, in Entra display names. #>
    param(
        [ValidateSet('r0', 'r1', 'r2', 'prod')][string]$Ring = 'prod',
        [Parameter(Mandatory)][ValidateSet('community', 'pro')][string]$Edition,
        [Parameter(Mandatory)][ValidateSet('ca', 'vm')][string]$Hosting
    )
    '{0}-{1}-{2}' -f $Ring.ToLowerInvariant(), $Edition.ToLowerInvariant(), $Hosting.ToLowerInvariant()
}

function Test-SISetupNewInstallNames {
    <#
        REMOVE-ME once a fresh install has proven the CR5 names (#655 step 2). PURE. Is SI_Setup_NewInstallNames ON for this
        install? Read from the install's values (-Values: the guided install's answers), else the environment (-Env, default
        the process). ON BY DEFAULT since 2026-10-18 (owner: CR1-CR8 delivered; framework 12.11c -- a NEW install gets the
        new names): only 'false' / '0' / 'no' / 'off' turns it off.
          ON   a NEW install gets the CR5 names (Get-SISetupComponentNames -New, the engine identity id-si-engine, the sign-in
               app "SecurityInsight", the SQL admin group shown as "SecurityInsight SQL admins");
          OFF  a new install gets TODAY's names (ca-si-management, uami-si-*, id-si-<ring>-<edition>-<hosting>, the sign-in
               app "SecurityInsight Management") -- exactly as before step 2.
        An EXISTING install keeps today's resource names either way (Resolve-SIInstallExistingNames): Azure cannot rename them.
    #>
    param([System.Collections.IDictionary]$Values, [System.Collections.IDictionary]$Env)
    $name = 'SI_Setup_NewInstallNames'
    $v = $null
    if ($Values -and $Values.Contains($name)) { $v = $Values[$name] }
    if ($null -eq $v -or "$v".Trim() -eq '') { $v = if ($Env) { if ($Env.Contains($name)) { $Env[$name] } else { $null } } else { [Environment]::GetEnvironmentVariable($name) } }
    -not ("$v".Trim() -match '^(?i)(false|0|no|off)$')
}

function Get-SISetupComponentNames {
    <#
        PURE. The names setup gives the components INSIDE a new install's resource group (the web app, its MCP server, the
        updater job and their identities, asset tagging's identity). No ring or environment in them: the resource group and
        its tags already say which environment they belong to (owner: find apps by id, never by an environment in a name).
        Without -New: TODAY's names -- what every existing install runs with, and a new install's names with
        SI_Setup_NewInstallNames off (REMOVE-ME; ON by default since 2026-10-18). -New: the CR5 names for NEW installs (#655 step 2; framework 12.11c):
        purpose words web / mcp / updater, identities id-si-<role>. The MCP server and the updater job already fit and keep
        their names. Nothing FINDS a resource by these: a running install reads its names from its install record
        (engine/_shared/SI-InstallNames.ps1); setup passes these to the scripts that create the components.
    #>
    param([switch]$New)
    if ($New) {
        return [ordered]@{
            # the web app keeps ca-si-management for every install, new ones too (framework 5.5, owner 2026-11-09: identities
            # get standard names, web app names / addresses are not aligned)
            WebApp          = 'ca-si-management'
            McpApp          = 'ca-si-mcp'
            UpdaterJob      = 'caj-si-updater'
            WebIdentity     = 'id-si-web'
            McpIdentity     = 'id-si-mcp'
            UpdaterIdentity = 'id-si-updater'
            TaggingIdentity = 'id-si-tagging'
        }
    }
    [ordered]@{
        WebApp          = 'ca-si-management'
        McpApp          = 'ca-si-mcp'
        UpdaterJob      = 'caj-si-updater'
        WebIdentity     = 'uami-si-management'
        McpIdentity     = 'uami-si-mcp'
        UpdaterIdentity = 'uami-si-updater'
        TaggingIdentity = 'uami-securityinsight-tagging'
    }
}

function Get-SISetupDisplayNames {
    <# PURE. The names people read for a new install's directory objects. Without -New: today's ("SecurityInsight" for the
       engine's own app registration, "SecurityInsight Management" for the web app's sign-in registration, grp-si-sql-admins
       for the SQL admin group); -New: the CR5 names (framework 12.11c item 5: the full name where people read) --
       "SecurityInsight Engine", "SecurityInsight" -- and the SQL admin group keeps its STANDARD name grp-si-sql-admins (framework
       5.5, Invardia ruling 2026-11-07: groups follow grp-<code>-<purpose>; an older install's group is renamed back in place by
       the update's identity-names step).
       An existing install's objects get the same names from the update (setup\_shared\SI-DisplayNames.ps1).
       ONE SET OF NAMES FOR BOTH EDITIONS (framework PRO-COMMUNITY-SAME, Invardia C1 2026-11-11): a NEW install gets the same
       tenant-wide names in either edition -- the edition is not part of any name. (From 2026-10-27 to 2026-11-11 a new
       Community install got names of its own -- "SecurityInsight Community Engine", "SecurityInsight Community",
       grp-si-community-sql-admins; an EXISTING install keeps the names it has until it moves: its objects are found by the
       names recorded for it and are never renamed by this function.) -Edition is kept for callers and changes nothing.
       SqlAdminGroupName = the name the admin group is looked up and created by (setup\Set-SISqlAdminGroup.ps1 -GroupName).
       Without -New (an existing install, or SI_Setup_NewInstallNames off) both editions keep today's names, exactly as before. #>
    param([switch]$New, [ValidateSet('community', 'pro')][string]$Edition = 'pro')
    [ordered]@{
        SpnDisplayName           = $(if ($New) { 'SecurityInsight Engine' } else { 'SecurityInsight' })
        WebAppDisplayName        = $(if ($New) { 'SecurityInsight' } else { 'SecurityInsight Management' })
        SqlAdminGroupDisplayName = 'grp-si-sql-admins'
        SqlAdminGroupName        = 'grp-si-sql-admins'
    }
}

function Get-SISetupComponentName {
    <# PURE. One component's name from a names table (Get-SISetupResourceNames), else the default of Get-SISetupComponentNames
       (a table built before the component names were part of it). An unknown -Key throws. #>
    # -Names: a hashtable / ordered table, or an object with the key as a property (a context built elsewhere)
    param([AllowNull()]$Names, [Parameter(Mandatory)][string]$Key)
    $d = Get-SISetupComponentNames
    if (-not $d.Contains($Key)) { throw ("Get-SISetupComponentName: unknown component '{0}' (known: {1})" -f $Key, (@($d.Keys) -join ', ')) }
    $v = $null
    if ($Names -is [System.Collections.IDictionary]) { if ($Names.Contains($Key)) { $v = $Names[$Key] } }
    elseif ($null -ne $Names -and $Names.PSObject.Properties[$Key]) { $v = $Names.$Key }
    if ("$v".Trim()) { return "$v".Trim() }
    [string]$d[$Key]
}

function Get-SISetupResourceNames {
    <#
        PURE. The default name of every environment-level resource setup creates, for one install, plus the names of the
        components inside the resource group (Get-SISetupComponentNames: WebApp, McpApp, UpdaterJob, WebIdentity,
        McpIdentity, UpdaterIdentity, TaggingIdentity). The engine jobs keep caj-si-<engine>.
    #>
    param(
        [ValidateSet('r0', 'r1', 'r2', 'prod')][string]$Ring = 'prod',
        [Parameter(Mandatory)][ValidateSet('community', 'pro')][string]$Edition,
        [Parameter(Mandatory)][ValidateSet('ca', 'vm')][string]$Hosting,
        [ValidatePattern('^[0-9]{2}$')][string]$Instance = '01',
        # given: the globally unique names carry the subscription's suffix (Get-SISetupSubscriptionSuffix), not the instance
        [AllowEmptyString()][AllowNull()][string]$SubscriptionId,
        # CR5 (#655 step 2; SI_Setup_NewInstallNames, REMOVE-ME): the NEW-install names for the components, the engine's
        # identity (id-si-engine) and the sign-in app's display name. Off: today's names, exactly as before.
        [switch]$NewNames
    )
    $label   = Get-SISetupEnvLabel -Ring $Ring -Edition $Edition -Hosting $Hosting
    $flat    = ($label -replace '[^a-z0-9]', '')
    $kv      = 'kv-si-{0}{1}' -f $label, $Instance
    if ($kv.Length -gt 24) { $kv = 'kvsi{0}{1}' -f $flat, $Instance }     # Key Vault: 3-24 characters
    $n = [ordered]@{
        EnvLabel        = $label
        ResourceGroup   = 'rg-si-{0}' -f $label
        Workspace       = 'log-si-{0}' -f $label
        Dce             = 'dce-si-{0}' -f $label
        StorageAccount  = 'stsi{0}{1}' -f $flat, $Instance                 # 3-24, lowercase letters and digits
        Acr             = 'acrsi{0}{1}' -f $flat, $Instance                # 5-50, letters and digits
        KeyVault        = $kv
        ContainerEnv    = 'cae-si-{0}' -f $label
        # the engine's identity: today id-si-<label>; CR5 (new installs, the setting on) id-si-engine -- no ring in the name
        ManagedIdentity = $(if ($NewNames) { 'id-si-engine' } else { 'id-si-{0}' -f $label })
        SqlServer       = 'sql-si-{0}' -f $label
    }
    # directory objects users see (consent, enterprise apps): ONE product-level name, no ring / environment in it
    $d = Get-SISetupDisplayNames -New:$NewNames -Edition $Edition; foreach ($k in $d.Keys) { $n[$k] = $d[$k] }
    $c = Get-SISetupComponentNames -New:$NewNames; foreach ($k in $c.Keys) { $n[$k] = $c[$k] }
    Set-SISetupGlobalNames -Names $n -SubscriptionId $SubscriptionId
    $n
}

function Get-SISetupSubscriptionSuffix {
    <# PURE. The per-install suffix for globally unique names: the first 6 hex characters of SHA-256 of the subscription
       id (trimmed, lower case). The same subscription always gives the same suffix; '' without a subscription. #>
    param([AllowEmptyString()][AllowNull()][string]$SubscriptionId)
    $id = "$SubscriptionId".Trim().ToLowerInvariant()
    if (-not $id) { return '' }
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try { $h = $sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($id)) } finally { $sha.Dispose() }
    (-join ($h[0..2] | ForEach-Object { $_.ToString('x2') }))
}

# ------------------------------------------------------------------------------------------------------------------------
# Framework section 5.5 (owner 2026-11-04, OPEN-30: "i hate the si method, and love the pim method"): the names a NEW guided install
# gets. <type>-si[-<purpose>] -- no edition, ring, prod or hosting in any name (the 7 resource-group tags carry those) -- and
# the globally unique names end in <t> = 6 hex characters of SHA-256 of the install id (PIM's Get-PimInstallToken, the
# reference). NEW INSTALLS ONLY: an existing install keeps every name it has (Resolve-SIInstallDefaultResourceGroup,
# Resolve-SIInstallExistingNames); the updater never derives a name.
# ------------------------------------------------------------------------------------------------------------------------

$script:SISetupDefaultInstallId = 'securityinsight'

function Get-SISetupInstallToken {
    <# PURE. <t>: the first 6 hex characters (lower case) of SHA-256 over the install id, trimmed and lower-cased, UTF-8 --
       byte for byte PIM's Get-PimInstallToken (framework section 5.5). The same install id always gives the same <t>. #>
    param([Parameter(Mandatory)][string]$InstallId)
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try { $h = $sha.ComputeHash([Text.Encoding]::UTF8.GetBytes("$InstallId".Trim().ToLowerInvariant())) } finally { $sha.Dispose() }
    (-join ($h[0..2] | ForEach-Object { $_.ToString('x2') }))
}

function Get-SISetupDerivedInstallId {
    <# PURE. The install id of an install that was not given one of its own (PIM's Get-PimInstallDerivedId, same form):
       'si-' + 12 hex characters of SHA-256 of 'tenant|subscription|resource group' (lower case). The same three answers give
       the same id on every run and resume; another tenant, subscription or resource group gives another one. #>
    param([Parameter(Mandatory)][string]$TenantId, [Parameter(Mandatory)][string]$SubscriptionId, [string]$ResourceGroup = 'rg-si')
    $rg = if ("$ResourceGroup".Trim()) { "$ResourceGroup".Trim() } else { 'rg-si' }
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try { $h = $sha.ComputeHash([Text.Encoding]::UTF8.GetBytes(('{0}|{1}|{2}' -f "$TenantId".Trim(), "$SubscriptionId".Trim(), $rg).ToLowerInvariant())) } finally { $sha.Dispose() }
    'si-' + (-join ($h[0..5] | ForEach-Object { $_.ToString('x2') }))
}

function Get-SISetupNamingInstallId {
    <# PURE. The install id <t> is made from: the install's own id (Invardia's, or -InstallId given by the customer), else --
       when it is SecurityInsight's default id 'securityinsight', which EVERY install without its own id shares and which would
       give every customer the same SQL server / Key Vault / storage / registry name -- the derived id
       (Get-SISetupDerivedInstallId). #>
    param([AllowEmptyString()][AllowNull()][string]$InstallId, [AllowEmptyString()][AllowNull()][string]$TenantId,
          [AllowEmptyString()][AllowNull()][string]$SubscriptionId, [AllowEmptyString()][AllowNull()][string]$ResourceGroup)
    $id = "$InstallId".Trim()
    if ($id -and $id -ine $script:SISetupDefaultInstallId) { return $id }
    if ("$TenantId".Trim() -and "$SubscriptionId".Trim()) { return (Get-SISetupDerivedInstallId -TenantId $TenantId -SubscriptionId $SubscriptionId -ResourceGroup $ResourceGroup) }
    if ($id) { return $id }
    $script:SISetupDefaultInstallId
}

function Get-SISetupInstallNames {
    <#
        PURE. Framework section 5.5 "THE AGREED LIST" for SecurityInsight -- the names a NEW guided install gets:
          ResourceGroup rg-si, ContainerEnv cae-si, Workspace log-si, Dce dce-si, Vnet vnet-si (in the install's own group),
          SqlServer sql-si-<t>, KeyVault kv-si-<t>, StorageAccount stsi<t>, Acr acrsi<t>, the engine identity id-si-engine,
          the components of Get-SISetupComponentNames -New (ca-si-management, ca-si-mcp, caj-si-updater, id-si-web / -mcp /
          -updater / -tagging) and the -New display names (grp-si-sql-admins). -ResourceGroup: the customer's own group wins.
        Length rules: storage 3-24 lower-case letters and digits, Key Vault 3-24, registry 5-50 letters and digits, SQL 1-63
        -- every name here is 13 characters or fewer.
    #>
    param(
        [Parameter(Mandatory)][ValidateSet('community', 'pro')][string]$Edition,
        [Parameter(Mandatory)][ValidatePattern('^[0-9a-f]{6}$')][string]$InstallToken,
        [AllowEmptyString()][AllowNull()][string]$ResourceGroup
    )
    $t = $InstallToken
    $n = [ordered]@{
        EnvLabel        = ''
        InstallToken    = $t
        ResourceGroup   = $(if ("$ResourceGroup".Trim()) { "$ResourceGroup".Trim() } else { 'rg-si' })
        Workspace       = 'log-si'
        Dce             = 'dce-si'
        StorageAccount  = 'stsi{0}' -f $t
        Acr             = 'acrsi{0}' -f $t
        KeyVault        = 'kv-si-{0}' -f $t
        ContainerEnv    = 'cae-si'
        Vnet            = 'vnet-si'
        ManagedIdentity = 'id-si-engine'
        SqlServer       = 'sql-si-{0}' -f $t
    }
    $d = Get-SISetupDisplayNames -New -Edition $Edition; foreach ($k in $d.Keys) { $n[$k] = $d[$k] }
    $c = Get-SISetupComponentNames -New; foreach ($k in $c.Keys) { $n[$k] = $c[$k] }
    $n
}

function Get-SISetupGlobalName {
    <#
        PURE. A globally unique name for one resource kind, within that kind's rules:
          StorageAccount  3-24, lower-case letters and digits only                       stsi<label><suffix>
          Acr             5-50, letters and digits only                                  acrsi<label><suffix>
          KeyVault        3-24, letters, digits, dashes; starts with a letter, no '--', no dash at the end
                                                       kv-si-<label>-<suffix>, or kvsi<label><suffix> when that is longer than 24
          SqlServer       1-63, lower-case letters, digits, dashes; no dash at either end sql-si-<label>-<suffix>
        A label too long for the kind is shortened -- never the suffix, which is what keeps the name unique.
    #>
    param(
        [Parameter(Mandatory)][ValidateSet('StorageAccount', 'Acr', 'KeyVault', 'SqlServer')][string]$Kind,
        [Parameter(Mandatory)][string]$Label,
        [Parameter(Mandatory)][ValidatePattern('^[a-z0-9]{1,12}$')][string]$Suffix
    )
    $lbl  = (($Label.ToLowerInvariant() -replace '[^a-z0-9-]', '') -replace '-{2,}', '-').Trim('-')
    $flat = $lbl -replace '-', ''
    $cut = { param([string]$Base, [int]$Max) if ($Base.Length -gt $Max) { $Base.Substring(0, $Max).TrimEnd('-') } else { $Base } }
    switch ($Kind) {
        'StorageAccount' { return ((& $cut ('stsi' + $flat) (24 - $Suffix.Length)) + $Suffix) }
        'Acr'            { return ((& $cut ('acrsi' + $flat) (50 - $Suffix.Length)) + $Suffix) }
        'KeyVault' {
            $d = 'kv-si-{0}-{1}' -f $lbl, $Suffix
            if ($d.Length -le 24) { return $d }
            return ((& $cut ('kvsi' + $flat) (24 - $Suffix.Length)) + $Suffix)
        }
        'SqlServer'      { return ('{0}-{1}' -f (& $cut ('sql-si-' + $lbl) (63 - $Suffix.Length - 1)), $Suffix) }
    }
}

function Set-SISetupGlobalNames {
    <# PURE (changes the table it is given). With a subscription, the globally unique names follow its suffix and the label. #>
    param([Parameter(Mandatory)][System.Collections.IDictionary]$Names, [AllowEmptyString()][AllowNull()][string]$SubscriptionId)
    $sfx = Get-SISetupSubscriptionSuffix -SubscriptionId $SubscriptionId
    if (-not $sfx) { return }
    foreach ($k in 'StorageAccount', 'Acr', 'KeyVault', 'SqlServer') { $Names[$k] = Get-SISetupGlobalName -Kind $k -Label ([string]$Names['EnvLabel']) -Suffix $sfx }
}

$script:SISetupGlobalNameTypes = [ordered]@{
    StorageAccount = 'Microsoft.Storage/storageAccounts'
    KeyVault       = 'Microsoft.KeyVault/vaults'
    Acr            = 'Microsoft.ContainerRegistry/registries'
    SqlServer      = 'Microsoft.Sql/servers'
}
$script:SISetupGlobalNamePrefixes = @{ StorageAccount = '^stsi'; KeyVault = '^(kv-si-|kvsi)'; Acr = '^acrsi'; SqlServer = '^sql-si-' }

function Select-SISetupExistingName {
    <#
        PURE. Which existing resource of one kind in the install's resource group IS the install's: the name this release
        would give it, else a name older releases gave it (-Legacy, in order), else the only one of that kind whose name
        is SecurityInsight's (-Prefix: stsi, kv-si / kvsi, acrsi, sql-si) -- a customer's own resource that happens to
        share the group is never taken over. Two or more candidates: none -- the new name is used.
    #>
    param([AllowEmptyCollection()][string[]]$Existing = @(), [string]$Wanted, [AllowEmptyCollection()][string[]]$Legacy = @(), [string]$Prefix = '^$')
    $e = @($Existing | Where-Object { $_ })
    foreach ($c in @(@($Wanted) + @($Legacy))) { if ($c) { $hit = @($e | Where-Object { $_ -eq $c }); if ($hit.Count) { return [string]$hit[0] } } }
    $si = @($e | Where-Object { $_ -match $Prefix })
    if ($si.Count -eq 1) { return [string]$si[0] }
    $null
}

function Resolve-SISetupDefaultGlobalName {
    <#
        PURE. The name a DEFAULTED globally unique resource gets on a run of the server / unattended / container setup
        (the guided install has its own, Resolve-SIInstallExistingNames): the resource of that kind already in the
        install's resource group (Select-SISetupExistingName) -- an existing install keeps its name; else, when the
        group could not be read (-ReadFailed), the name older releases gave it (the first -Legacy) -- never a second
        storage account or registry next to an install setup could not see; else the new name (-Wanted).
    #>
    param(
        [Parameter(Mandatory)][ValidateSet('StorageAccount', 'Acr', 'KeyVault', 'SqlServer')][string]$Kind,
        [Parameter(Mandatory)][string]$Wanted,
        [AllowEmptyCollection()][string[]]$Legacy = @(),
        [AllowEmptyCollection()][string[]]$Existing = @(),
        [switch]$ReadFailed
    )
    $old = @($Legacy | Where-Object { $_ })
    if ($ReadFailed) { if ($old.Count) { return [string]$old[0] }; return $Wanted }
    $pick = Select-SISetupExistingName -Existing $Existing -Wanted $Wanted -Legacy $old -Prefix $script:SISetupGlobalNamePrefixes[$Kind]
    if ($pick) { return $pick }
    $Wanted
}

function Get-SISetupNamesFromResourceGroup {
    <#
        PURE. When setup is handed a resource group that follows the pattern (rg-si-<label>), the names of the
        resources it creates INSIDE it follow the same label. Any other resource group name (rg-securityinsight, a
        customer's own) returns $null -- the caller then keeps the names it has always used there, so a re-run
        against an existing install never creates a second registry, environment or identity next to the first.
    #>
    param([AllowEmptyString()][AllowNull()][string]$ResourceGroupName, [ValidatePattern('^[0-9]{2}$')][string]$Instance = '01',
        [AllowEmptyString()][AllowNull()][string]$SubscriptionId,
        # CR5 new-install names (Get-SISetupResourceNames -NewNames); the engine identity id-si-engine then carries no suffix
        # either: it lives inside the resource group, like every other component
        [switch]$NewNames)
    # An optional naming suffix (rg-si-prod-community-ca-test) carries over to every name.
    if ("$ResourceGroupName" -cnotmatch '^rg-si-(r0|r1|r2|prod)-(community|pro)-(ca|vm)(-[a-z0-9][a-z0-9-]*)?$') { return $null }
    $sfx = [string]$Matches[4]
    $n = Get-SISetupResourceNames -Ring $Matches[1] -Edition $Matches[2] -Hosting $Matches[3] -Instance $Instance -NewNames:$NewNames
    if ($sfx) {
        $flat = ($sfx -replace '[^a-z0-9]', '')
        $withSfx = @('ResourceGroup', 'Workspace', 'Dce', 'ContainerEnv', 'SqlServer'); if (-not $NewNames) { $withSfx += 'ManagedIdentity' }
        foreach ($k in $withSfx) { $n[$k] = $n[$k] + $sfx }
        $n.EnvLabel = $n.EnvLabel + $sfx
        foreach ($k in 'StorageAccount', 'Acr') {
            $base = ($n[$k] -replace ([regex]::Escape($Instance) + '$'), '') + $flat
            if ($base.Length -gt 22) { $base = $base.Substring(0, 22) }
            $n[$k] = $base + $Instance
        }
        $n.KeyVault = ('kvsi{0}{1}' -f ($n.EnvLabel -replace '[^a-z0-9]', ''), '')
        if ($n.KeyVault.Length -gt 22) { $n.KeyVault = $n.KeyVault.Substring(0, 22) }
        $n.KeyVault += $Instance
        # directory object names stay product-level with a suffix too (no ring / environment in them)
    }
    Set-SISetupGlobalNames -Names $n -SubscriptionId $SubscriptionId
    $n
}

function Resolve-SISetupEdition {
    <#
        PURE apart from looking for a licence file. Which edition a NEW install is: an explicit -Edition wins; a licence
        (a path given to setup, a licence file in the install's config folder, or SI_License already set) means
        'pro'; otherwise 'community'. The licence decides, not the presence of Pro code: the private sync ships the
        Pro code to every customer.
    #>
    param(
        [AllowEmptyString()][string]$Edition,
        [AllowEmptyString()][AllowNull()][string]$LicencePath,
        [AllowEmptyString()][AllowNull()][string]$SIRoot,
        [AllowEmptyString()][AllowNull()][string]$LicenceValue
    )
    if ("$Edition".Trim()) {
        $e = "$Edition".Trim().ToLowerInvariant()
        if ($e -eq 'com') { throw "Edition 'com' is not a name: use 'community' or 'pro'." }
        if ($script:SISetupEditions -notcontains $e) { throw ("Edition '{0}' is not known: use 'community' or 'pro'." -f $Edition) }
        return $e
    }
    if ("$LicencePath".Trim()) { return 'pro' }
    if ("$LicenceValue".Trim()) { return 'pro' }
    if ("$SIRoot".Trim()) {
        $cfg = Join-Path $SIRoot 'config'
        if (Test-Path -LiteralPath $cfg) {
            if (@(Get-ChildItem -LiteralPath $cfg -File -ErrorAction SilentlyContinue | Where-Object { $_.Extension -in '.silicense', '.aitlicense' }).Count) { return 'pro' }
        }
    }
    'community'
}

function Get-SIResourceGroupTags {
    <#
        PURE. The seven tags every resource group setup creates carries: product, ring, edition, hosting, tenant,
        owner, purpose. Owner is whatever the customer passes (empty by default -- never a name baked into code).
    #>
    param(
        [ValidateSet('r0', 'r1', 'r2', 'prod')][string]$Ring = 'prod',
        [Parameter(Mandatory)][ValidateSet('community', 'pro')][string]$Edition,
        [Parameter(Mandatory)][ValidateSet('ca', 'vm')][string]$Hosting,
        [AllowEmptyString()][AllowNull()][string]$Tenant,
        [AllowEmptyString()][AllowNull()][string]$Owner
    )
    [ordered]@{
        product = 'si'
        ring    = $Ring.ToLowerInvariant()
        edition = $Edition.ToLowerInvariant()
        hosting = $Hosting.ToLowerInvariant()
        tenant  = "$Tenant".Trim()
        owner   = "$Owner".Trim()
        purpose = 'SecurityInsight'
    }
}

function ConvertTo-SIAzCliTagArgs {
    <# PURE. The tags as az CLI arguments: --tags key=value ... (an empty value is passed as key=). #>
    param([Parameter(Mandatory)][System.Collections.IDictionary]$Tags)
    $a = @('--tags')
    foreach ($k in $Tags.Keys) { $a += ('{0}={1}' -f $k, [string]$Tags[$k]) }
    $a
}

function ConvertTo-SIAzTagHashtable {
    <# PURE. A resource group's tags as a plain string hashtable (what an ARM PUT of the group takes). #>
    param([Parameter(Mandatory)][System.Collections.IDictionary]$Tags)
    $h = @{}; foreach ($k in $Tags.Keys) { $h[[string]$k] = [string]$Tags[$k] }; $h
}

function Resolve-SITenantTag {
    <#
        The value of the 'tenant' tag: the tenant's default verified domain when the setup sign-in
        (setup\_shared\SI-SetupAzure.ps1, REST) can read it, otherwise the tenant id. Never signs anyone in and never
        fails setup -- a tag is not worth stopping an install for.
    #>
    param([AllowEmptyString()][AllowNull()][string]$TenantId)
    $tid = "$TenantId".Trim()
    $signedIn = $false
    if (Get-Command -Name Get-SISetupAzureContext -ErrorAction SilentlyContinue) {
        try { $c = Get-SISetupAzureContext; if ($c) { $signedIn = $true; if (-not $tid) { $tid = [string]$c.Tenant.Id } } } catch { }
    }
    if (-not $tid) { return '' }
    try {
        if ($signedIn -and (Get-Command -Name Get-SITenant -ErrorAction SilentlyContinue)) {
            $t = Get-SITenant -TenantId $tid -ErrorAction Stop | Select-Object -First 1
            if ($t -and $t.PSObject.Properties['DefaultDomain'] -and "$($t.DefaultDomain)".Trim()) { return "$($t.DefaultDomain)".Trim() }
        }
    } catch { }
    $tid
}
