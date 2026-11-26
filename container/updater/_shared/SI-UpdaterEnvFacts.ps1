#Requires -Version 5.1
<#
    THE ENVIRONMENT REPORT'S AZURE FACTS, READ BY THE UPDATER (SI #1268, the owner's approved rights list 2026-11-15).

    The web app's environment report (pro-management\src\SI.Management.Web\EnvReport) shows the install's Azure resources
    (name, type, location, network facts, identities) and the role assignments AT the install's resource group. The web app
    holds NO Reader on the resource group (setup\_shared\si-identity-rights.json: web.azure.ReaderInstallRg retired) and never
    calls ARM for them: the UPDATER reads them on every run with its own rights (Contributor on the resource group: read
    included) and writes them to the Pro database -- cfg.EnvironmentFacts row 'install', compact JSON
    { readUtc, subscriptionId, resourceGroup, resources, roles, error } -- READ BACK. The web reads that row from SQL only
    and shows its age.

    The same reads the web app made before: one list of the resource group, one GET per resource whose network facts the
    report shows (only these types), the role assignments atScope() and each role's name. ONLY NAMED FACTS are taken from an
    answer -- never a key, a secret, a connection string or a setting value.

    -Arm { param([string]$Path, [string]$ApiVersion, [switch]$List) } -> the parsed answer (List: the items); a GET of
    something that is not there = $null; anything else that fails THROWS. Default: the updater's own ARM seam
    (Invoke-SIUpdaterArm). PS 5.1 + pwsh 7, no module.
#>

$script:SIEnvFactsMaxResources = 120

function Get-SIUpdaterEnvFactsApiVersion {
    <# PURE. The api-version to GET a resource type with -- only the types whose network facts the report shows ('' = none). #>
    param([string]$Type)
    switch ("$Type".ToLowerInvariant()) {
        { $_ -in 'microsoft.app/containerapps', 'microsoft.app/jobs' } { return '2024-03-01' }
        'microsoft.sql/servers' { return '2023-08-01-preview' }
        'microsoft.keyvault/vaults' { return '2023-07-01' }
        'microsoft.containerregistry/registries' { return '2023-07-01' }
        'microsoft.storage/storageaccounts' { return '2023-05-01' }
        'microsoft.managedidentity/userassignedidentities' { return '2023-01-31' }
        default { return '' }
    }
}

function Get-SIUpdaterEnvFactsProp {
    param($Object, [string[]]$Path)
    $o = $Object
    foreach ($p in $Path) {
        if ($null -eq $o) { return $null }
        if ($o -is [System.Collections.IDictionary]) { $o = if ($o.Contains($p)) { $o[$p] } else { $null }; continue }
        $pp = $o.PSObject.Properties[$p]; $o = if ($pp) { $pp.Value } else { $null }
    }
    $o
}

function ConvertTo-SIUpdaterEnvResource {
    <# PURE. The NAMED facts of one resource (its list entry, and its full GET when there is one) -- the shape the web app's
       report reads (SqlAzureFactsReader): id, name, type, location, network [{fact, value}], principalId, userAssigned,
       clientId. Nothing else of the answer is kept. #>
    param([Parameter(Mandatory)]$ListEntry, $Full = $null)
    $g = { param($o, [string[]]$p) Get-SIUpdaterEnvFactsProp $o $p }
    $id = [string](& $g $ListEntry @('id')); $type = [string](& $g $ListEntry @('type'))
    $src = if ($null -ne $Full) { $Full } else { $ListEntry }
    $p = & $g $src @('properties')
    $net = New-Object System.Collections.Generic.List[object]
    # a fact is a plain value (text, true / false, a number) -- an object or a list is never taken
    $add = { param([string]$fact, $v) if ($v -is [string] -or $v -is [ValueType]) { $net.Add([ordered]@{ fact = $fact; value = $(if ($v -is [bool]) { "$v".ToLowerInvariant() } else { [string]$v }) }) } }
    switch ($type.ToLowerInvariant()) {
        'microsoft.app/containerapps' {
            $ing = & $g $p @('configuration', 'ingress')
            & $add 'external ingress' (& $g $ing @('external'))
            $ips = & $g $ing @('ipSecurityRestrictions')
            if ($null -ne $ips) { $net.Add([ordered]@{ fact = 'IP restrictions'; value = [string]@($ips).Count }) }
            elseif ($null -ne $ing) { $net.Add([ordered]@{ fact = 'IP restrictions'; value = '0' }) }
        }
        { $_ -in 'microsoft.sql/servers', 'microsoft.containerregistry/registries' } { & $add 'public network access' (& $g $p @('publicNetworkAccess')) }
        'microsoft.keyvault/vaults' {
            & $add 'public network access' (& $g $p @('publicNetworkAccess'))
            & $add 'default network rule' (& $g $p @('networkAcls', 'defaultAction'))
        }
        'microsoft.storage/storageaccounts' {
            & $add 'public network access' (& $g $p @('publicNetworkAccess'))
            & $add 'default network rule' (& $g $p @('networkAcls', 'defaultAction'))
            & $add 'anonymous blob access' (& $g $p @('allowBlobPublicAccess'))
        }
    }
    $ident = & $g $src @('identity')
    $uaObj = & $g $ident @('userAssignedIdentities')
    $ua = @()
    if ($uaObj -is [System.Collections.IDictionary]) { $ua = @($uaObj.Keys | ForEach-Object { ([string]$_ -split '/')[-1] }) }
    elseif ($null -ne $uaObj) { $ua = @($uaObj.PSObject.Properties | ForEach-Object { ([string]$_.Name -split '/')[-1] }) }
    $principal = [string](& $g $ident @('principalId')); if (-not $principal) { $principal = [string](& $g $p @('principalId')) }
    $name = [string](& $g $ListEntry @('name')); if (-not $name) { $name = ($id -split '/')[-1] }
    [ordered]@{
        id = $id; name = $name; type = $type; location = [string](& $g $ListEntry @('location'))
        network = $net.ToArray()
        principalId = $(if ($principal) { $principal } else { $null })
        userAssigned = @($ua | Where-Object { $_ })
        clientId = $(if ([string](& $g $p @('clientId'))) { [string](& $g $p @('clientId')) } else { $null })
    }
}

function Read-SIUpdaterEnvFacts {
    <#
        The install's resource group read through -Arm: the resources (at most 120; a full GET only of the types the report
        shows), the role assignments atScope() and each role's name (looked up once per role). A part that cannot be read is
        said in error; the other part is still kept. Returns the ordered facts (the row's JSON shape). Never throws.
    #>
    param([Parameter(Mandatory)][scriptblock]$Arm, [Parameter(Mandatory)][string]$SubscriptionId, [Parameter(Mandatory)][string]$ResourceGroup, [datetime]$NowUtc = [datetime]::UtcNow)
    $rg = '/subscriptions/{0}/resourceGroups/{1}' -f $SubscriptionId, $ResourceGroup
    $resources = New-Object System.Collections.Generic.List[object]
    $roles = New-Object System.Collections.Generic.List[object]
    $errors = New-Object System.Collections.Generic.List[string]
    $short = { param($m) $t = ([string]$m -replace '\s+', ' ').Trim(); if ($t.Length -gt 200) { $t = $t.Substring(0, 197) + '...' }; $t }
    try {
        foreach ($r in @(& $Arm ($rg + '/resources') '2021-04-01' -List | Where-Object { $_ } | Select-Object -First $script:SIEnvFactsMaxResources)) {
            $full = $null
            $v = Get-SIUpdaterEnvFactsApiVersion -Type ([string](Get-SIUpdaterEnvFactsProp $r @('type')))
            if ($v) { try { $full = & $Arm ([string](Get-SIUpdaterEnvFactsProp $r @('id'))) $v } catch { $full = $null } }
            $resources.Add((ConvertTo-SIUpdaterEnvResource -ListEntry $r -Full $full))
        }
    } catch { $errors.Add(('the resources could not be read: {0}' -f (& $short $_.Exception.Message))) }
    try {
        $names = @{}
        foreach ($a in @(& $Arm ($rg + '/providers/Microsoft.Authorization/roleAssignments?$filter=atScope()') '2022-04-01' -List | Where-Object { $_ })) {
            $p = Get-SIUpdaterEnvFactsProp $a @('properties')
            $def = [string](Get-SIUpdaterEnvFactsProp $p @('roleDefinitionId'))
            if (-not $names.ContainsKey($def)) {
                $n = $def
                try { $d = & $Arm $def '2022-04-01'; $rn = [string](Get-SIUpdaterEnvFactsProp $d @('properties', 'roleName')); if ($rn) { $n = $rn } } catch { $n = $def }
                $names[$def] = $n
            }
            $roles.Add([ordered]@{ principalId = [string](Get-SIUpdaterEnvFactsProp $p @('principalId')); principalType = [string](Get-SIUpdaterEnvFactsProp $p @('principalType')); role = [string]$names[$def]; scope = [string](Get-SIUpdaterEnvFactsProp $p @('scope')) })
        }
    } catch { $errors.Add(('the role assignments could not be read: {0}' -f (& $short $_.Exception.Message))) }
    [ordered]@{
        readUtc = $NowUtc.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ', [Globalization.CultureInfo]::InvariantCulture)
        subscriptionId = $SubscriptionId; resourceGroup = $ResourceGroup
        resources = $resources.ToArray(); roles = $roles.ToArray()
        error = $(if ($errors.Count) { $errors -join '; ' } else { $null })
    }
}

function Get-SIUpdaterEnvFactsSaveSql {
    <# PURE. The row cfg.EnvironmentFacts 'install' written or replaced (@Facts, @ReadUtc, @By), then read back (its ReadUtc). #>
    @'
IF OBJECT_ID('cfg.EnvironmentFacts') IS NOT NULL
BEGIN
    SET XACT_ABORT ON;
    BEGIN TRAN;
    IF EXISTS (SELECT 1 FROM cfg.EnvironmentFacts WITH (UPDLOCK, HOLDLOCK) WHERE Name = N'install')
        UPDATE cfg.EnvironmentFacts SET Facts = @Facts, ReadUtc = @ReadUtc, UpdatedBy = @By WHERE Name = N'install';
    ELSE
        INSERT cfg.EnvironmentFacts (Name, Facts, ReadUtc, UpdatedBy) VALUES (N'install', @Facts, @ReadUtc, @By);
    COMMIT;
    SELECT CONVERT(nvarchar(20), ReadUtc, 126) AS ReadUtc, LEN(Facts) AS Chars FROM cfg.EnvironmentFacts WHERE Name = N'install';
END
'@
}

function Invoke-SIUpdaterEnvFactsStep {
    <#
        THE STEP (every updater run with a Pro database, both editions): the facts read (Read-SIUpdaterEnvFacts), written to
        cfg.EnvironmentFacts 'install' and READ BACK (the row's ReadUtc is this read's). One plain line. NEVER throws, never
        fails or holds the update. -Arm: the test seam (default Invoke-SIUpdaterArm). Returns @{ Ok; Line }.
    #>
    param($Store, [Parameter(Mandatory)][string]$SubscriptionId, [Parameter(Mandatory)][string]$ResourceGroup, [scriptblock]$Arm, [datetime]$NowUtc = [datetime]::UtcNow)
    $res = { param($ok, $line) [pscustomobject]@{ Ok = [bool]$ok; Line = [string]$line } }
    try {
        if (-not $Store -or -not $Store.Invoke) { return (& $res $true 'System Documentation facts: no Pro database on this install -- nothing to record') }
        if (-not $Arm) {
            $Arm = { param([string]$Path, [string]$ApiVersion, [switch]$List) if ($List) { @(Invoke-SIUpdaterArm -Path $Path -ApiVersion $ApiVersion -List) } else { Invoke-SIUpdaterArm -Path $Path -ApiVersion $ApiVersion -AllowNotFound } }
        }
        $f = Read-SIUpdaterEnvFacts -Arm $Arm -SubscriptionId $SubscriptionId -ResourceGroup $ResourceGroup -NowUtc $NowUtc
        $json = ConvertTo-Json -InputObject $f -Depth 12 -Compress
        $row = @(& $Store.Invoke (Get-SIUpdaterEnvFactsSaveSql) ([ordered]@{ Facts = $json; ReadUtc = $f.readUtc.TrimEnd('Z').Replace('T', ' '); By = 'caj-si-updater' }) 'reader' | ForEach-Object { $_ } | Where-Object { $null -ne $_ }) | Select-Object -First 1
        $back = [string](Get-SIUpdaterEnvFactsProp $row @('ReadUtc'))
        $want = $f.readUtc.TrimEnd('Z')
        if (-not $back -or -not $back.StartsWith($want.Substring(0, 16))) {
            return (& $res $false ('WARNING: System Documentation facts: written, but the row does not read back ({0}) -- the next update writes it again' -f $(if ($back) { 'read ' + $back } else { 'no row: the release''s schema has no cfg.EnvironmentFacts yet' })))
        }
        & $res $true ('System Documentation facts recorded: {0} resource(s), {1} role assignment(s) at the resource group{2} (read back)' -f @($f.resources).Count, @($f.roles).Count, $(if ($f.error) { ' -- ' + $f.error } else { '' }))
    } catch { & $res $false ('WARNING: System Documentation facts: not recorded ({0}) -- the next update tries again' -f ([string]$_.Exception.Message -replace '\s+', ' ')) }
}
