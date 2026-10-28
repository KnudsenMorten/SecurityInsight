#Requires -Version 5.1
<#
    SI v3 -- FULL ASSET PROPERTIES: publish to SI_AssetProperties_CL.

    DESIGN: docs/V3-ARCHITECTURE.md 3.6b.

    🔒 THE DCE **AND** DCR SCOPE PINS BELOW ARE LOAD-BEARING, NOT BOILERPLATE. Finding #80 cost a
    session and made correlation look like it had never worked: three DCEs named `dce-securityinsight`
    exist across this tenant, `Post-*` resolves the DCE by NAME ONLY, and posting this workspace's DCR
    immutableId to an endpoint in another subscription is answered with HTTP 403 -- AFTER the engine
    has done all of its real work. Any new engine that publishes to Log Analytics needs BOTH pins.
    Copied from SI-CorrelationIngest.ps1 rather than shared, per CLAUDE.md: never widen a shared path
    to serve one solution's add-on.

    NO Set-StrictMode here -- it leaks into the caller's scope (measured 2026-08-12).
#>
# SI's log-ingest wrappers (Send-SILogData, Update-SILogTableSchema, Get-SIDceList, ...): plain REST,
# no PowerShell modules. Loaded once; a caller that already has them keeps its own.
if (-not (Get-Command -Name Send-SILogData -ErrorAction SilentlyContinue)) {
    . (Join-Path (Split-Path -Parent (Split-Path -Parent $PSScriptRoot)) '_shared/SI-LogIngest.ps1')
}

function Select-SIAssetPropertiesIngestTarget {
    <#
        #199 -- make the endpoint AzLogDcrIngestPS will use the RIGHT one, before it touches the rule and again
        before the post. The module resolves the endpoint by NAME ONLY -- the first match in $global:AzDceDetails,
        or in a tenant-wide Resource Graph query when that cache is empty. Measured 2026-10-01: three endpoints
        named dce-securityinsight in two subscriptions; a rule created on the right one was re-bound to another
        one minute later by the engine's own post (#198); four rules on this tenant were bound to the other
        subscription's endpoint.
        The endpoint is chosen as follows:
          - a rule that EXISTS posts through the endpoint it is bound to, when that endpoint has the configured
            name. Ingestion accepts a post only through the rule's own endpoint, and moving a rule is not an
            option -- measured 2026-10-01, a re-bound rule was still refused (HTTP 403) more than 10 minutes later.
          - otherwise (a new rule) this install's endpoint -- subscription + resource group + name -- so the
            module creates the rule there and not on a same-named endpoint elsewhere.
          - ONE endpoint of that name anywhere is unambiguous and used (an endpoint outside the rules' resource
            group has always worked that way). Several and none here: refused, nothing is posted.
        The DCR cache is narrowed to this install's rule (or, before it exists, cleared of same-named rules
        elsewhere). An empty cache is built first. Without a subscription id there is nothing to pin to.
    #>
    param([hashtable]$AuthParams, [Parameter(Mandatory)][string]$DcrName)
    $sub = [string]$global:SI_AzSubscriptionId
    if (-not $sub -or -not $global:SI_DceName) { return }
    $dceRg = if ($global:SI_DceResourceGroup) { [string]$global:SI_DceResourceGroup } else { [string]$global:SI_DcrResourceGroup }
    $dcrRg = [string]$global:SI_DcrResourceGroup
    $rebuilt = $false
    $rebuild = {
        if ($rebuilt -or -not $AuthParams) { return }
        try { $global:AzDceDetails = Get-SIDceList @AuthParams -Verbose:$false 4>$null } catch { }
        try { $global:AzDcrDetails = Get-SIDcrList @AuthParams -Verbose:$false 4>$null } catch { }
        $rebuilt = $true   # dot-sourced: this IS the function's scope
    }
    $findHere = { @($global:AzDceDetails | Where-Object { $_ -and $_.name -eq $global:SI_DceName -and [string]$_.id -like "/subscriptions/$sub/resourceGroups/$dceRg/*" }) | Select-Object -First 1 }
    $findRule = { if ($dcrRg) { @($global:AzDcrDetails | Where-Object { $_ -and $_.name -eq $DcrName -and [string]$_.id -like "/subscriptions/$sub/resourceGroups/$dcrRg/*" }) | Select-Object -First 1 } }

    if (-not $global:AzDceDetails) { . $rebuild }
    $dce = . $findHere
    $dcr = . $findRule
    if (-not $dce -or ($dcrRg -and -not $dcr)) { . $rebuild; $dce = . $findHere; $dcr = . $findRule }
    if (-not $dce) {
        $same = @($global:AzDceDetails | Where-Object { $_ -and $_.name -eq $global:SI_DceName })
        if ($same.Count -ne 1) {
            throw ("Data collection endpoint '{0}' was not found in resource group '{1}' of subscription '{2}'. {3} endpoint(s) of that name exist elsewhere, so nothing was posted -- set SI_DceResourceGroup to the one this install uses." -f $global:SI_DceName, $dceRg, $sub, $same.Count)
        }
        $dce = $same[0]
    }
    $bound = if ($dcr -and $dcr.properties) { [string]$dcr.properties.dataCollectionEndpointId } else { '' }
    if ($bound -and $bound -ne [string]$dce.id) {
        $b = @($global:AzDceDetails | Where-Object { $_ -and [string]$_.id -eq $bound }) | Select-Object -First 1
        if (-not $b) { . $rebuild; $b = @($global:AzDceDetails | Where-Object { $_ -and [string]$_.id -eq $bound }) | Select-Object -First 1 }
        if ($b -and $b.name -eq $global:SI_DceName) {
            Write-Verbose ("Data collection rule '{0}' is bound to {1}; posting through it." -f $DcrName, $bound)
            $dce = $b
        }
    }
    $global:AzDceDetails = @($dce)
    if ($dcr) { $global:AzDcrDetails = @($dcr) }
    elseif ($global:AzDcrDetails) { $global:AzDcrDetails = @($global:AzDcrDetails | Where-Object { $_ -and $_.name -ne $DcrName }) }
}
function Resolve-SIAssetPropertiesAuthParams {
    <#
        Same three-way credential resolution every SI engine uses. Cert wins over secret; managed
        identity is the third path. The auth BRIDGE (HighPriv_Modern_* -> SI_SPN_*) lives in the entry
        point, because it must run before anything reads these globals.
    #>
    param()
    if ($global:SI_PreferUami -and $global:SI_UAMI_ClientId) {
        # #209: this branch named NO credential at all (AzAppId/AzAppSecret = $null, no -UseManagedIdentity),
        # so AzLogDcrIngestPS had nothing to sign in with. It now says "managed identity", like every sibling.
        return @{ UseManagedIdentity = $true; ManagedIdentityClientId = [string]$global:SI_UAMI_ClientId; TenantId = [string]$global:SI_SPN_TenantId }
    }
    $appId  = [string]$global:SI_SPN_AppId
    $tenant = [string]$global:SI_SPN_TenantId
    if (-not [string]::IsNullOrWhiteSpace([string]$global:SI_SPN_CertThumbprint)) {
        return @{ AzAppId = $appId; AzAppCertificateThumbprint = [string]$global:SI_SPN_CertThumbprint; TenantId = $tenant }
    }
    @{ AzAppId = $appId; AzAppSecret = [string]$global:SI_SPN_Secret; TenantId = $tenant }
}

function Send-SIAssetPropertyRows {
    <#
        Publish the wide-pull rows.

        NOT best-effort. This IS the add-on's output: a swallowed failure would leave the CMDB
        connector reading a stale or absent table while every run reported success -- the failure shape
        this project has now paid for five times (#78/#80/#81/#86/#88), where a thing that is not
        running looks exactly like a thing with nothing to report.
    #>
    param(
        [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Rows,
        [string]$TableName = 'SI_AssetProperties',
        [string]$DcrName
    )

    if (@($Rows).Count -eq 0) {
        Write-Warning 'assetprops: nothing to publish -- 0 rows. Not posting.'
        return 0
    }
    if ([string]::IsNullOrWhiteSpace($DcrName)) {
        $DcrName = if (-not [string]::IsNullOrWhiteSpace([string]$global:SI_AssetProperties_DcrName)) {
            [string]$global:SI_AssetProperties_DcrName
        } else { 'dcr-si-assetproperties' }
    }

    $savedVerbose = $global:VerbosePreference
    $global:VerbosePreference = 'SilentlyContinue'
    try {
        $authParams = Resolve-SIAssetPropertiesAuthParams
        $spnObjectId = if ($global:SI_SPN_ObjectId) { $global:SI_SPN_ObjectId } else { $global:SI_LogIngest_ObjectId }

        # 🔴 THE WHOLE SET DECIDES THE SCHEMA, NOT ONE ROW -- CORRECTED 2026-08-31 (operator:
        # *"is something wrong with the sampling of dcr/la table. it must contain all needed columns"*).
        #
        # This passed `Select-Object -First 1`, copied from Send-SIObjectMapRows. AzLogDcrIngestPS
        # INFERS the table + DCR column set from what it is handed, so a single row defines the schema
        # for the entire table -- and if that row happens to lack an optional field, the column is never
        # created and every other row's value for it is DROPPED AT INGEST, silently, on every future run.
        #
        # 🪤 It is worse than a missing column: nothing errors. The engine reports rows posted, the
        # table exists, and the field is simply absent -- indistinguishable from "no asset had a value".
        # 📌 The four PROFILERS already do this correctly: Invoke-Output.ps1 builds `$schemaSample` from
        # the FULL dataset, commented "full dataset for type inference". Only the two v3 engines that
        # publish their own tables had the one-row shortcut.
        $sample = @($Rows)

        # #199 -- pin BEFORE the create/update, not only before the post.
        Select-SIAssetPropertiesIngestTarget -AuthParams $authParams -DcrName $DcrName

        $null = Update-SILogTableSchema `
            -AzLogWorkspaceResourceId                   $global:SI_WorkspaceResourceId `
            @authParams `
            -DceName                                    $global:SI_DceName `
            -DcrName                                    $DcrName `
            -DcrResourceGroup                           $global:SI_DcrResourceGroup `
            -TableName                                  $TableName `
            -Data                                       $sample `
            -LogIngestServicePricipleObjectId           $spnObjectId `
            -AzDcrSetLogIngestApiAppPermissionsDcrLevel $false `
            -AzLogDcrTableCreateFromAnyMachine          $true `
            -AzLogDcrTableCreateFromReferenceMachine    @() 4>$null

        # Re-sync the cache so a freshly created DCR's immutableId is known before the name-only lookup
        # inside Post-*. Without it the module falls back to the DCE's location field as a bogus
        # immutableId and the ingestion API answers 404 'westeurope'.
        try {
            $ensureFn = Get-Command -Name 'Ensure-SecurityInsightAzDceDcrCache' -ErrorAction SilentlyContinue
            if ($ensureFn) {
                & $ensureFn @authParams `
                    -SubscriptionId   $global:SI_AzSubscriptionId `
                    -DceResourceGroup $global:SI_DceResourceGroup `
                    -DcrResourceGroup $global:SI_DcrResourceGroup `
                    -Force 4>$null
            }
        } catch { }

        # DCR name-collision guard -- pin to (sub + RG + name) before posting.
        if ($global:AzDcrDetails -and $global:SI_AzSubscriptionId -and $global:SI_DcrResourceGroup) {
            $picked = @($global:AzDcrDetails | Where-Object {
                $_.name -eq $DcrName -and
                $_.id   -like "*/subscriptions/$($global:SI_AzSubscriptionId)/resourceGroups/$($global:SI_DcrResourceGroup)/*"
            }) | Select-Object -First 1
            if ($picked) { $global:AzDcrDetails = @($picked) }
        }

        # 🔴 AND THE SAME PIN FOR THE **DCE** -- its absence is finding #80, and it presents as a 403
        # that reads like an auth problem and is not.
        $_dceRg = if ($global:SI_DceResourceGroup) { [string]$global:SI_DceResourceGroup }
                  else { [string]$global:SI_DcrResourceGroup }
        if ($global:AzDceDetails -and $global:SI_AzSubscriptionId -and $_dceRg) {
            $_pickedDce = @($global:AzDceDetails | Where-Object {
                $_.id -like "*/subscriptions/$($global:SI_AzSubscriptionId)/resourceGroups/$_dceRg/*"
            })
            if ($_pickedDce.Count -gt 0) { $global:AzDceDetails = @($_pickedDce) }
        }

        # #199 -- again before the post: the cache refresh above narrowed it to this install's endpoint, which is
        # not the rule's own when the rule is bound elsewhere.
        Select-SIAssetPropertiesIngestTarget -AuthParams $authParams -DcrName $DcrName
        $data = @($Rows)
        $data = Repair-SILogColumnName -Data $data 4>$null
        $data = Format-SILogRowsToSchema -Data $data 4>$null
        $null = Send-SILogData `
            -DceName   $global:SI_DceName `
            -DcrName   $DcrName `
            -Data      $data `
            -TableName $TableName `
            @authParams 4>$null

        @($data).Count
    }
    finally {
        if ($null -ne $savedVerbose) { $global:VerbosePreference = $savedVerbose }
    }
}
