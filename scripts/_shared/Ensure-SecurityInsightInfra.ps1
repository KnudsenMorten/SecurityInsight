<#
.SYNOPSIS
    Ensure the SecurityInsight DCE / DCR RG exist and the SecurityInsight SPN has the RBAC
    roles required to send data. Mirrors the provisioning logic from
    Onboarding_IdentityAssets_LogAnalytics.ps1 so ingestion engines (RiskAnalysis,
    IdentityAssetsCollectDefineTierIngestLog) can self-heal when infra is missing.

    Caller responsibilities:
      - Set Az context (Connect-AzAccount, Set-AzContext) to the target subscription
        BEFORE calling these functions.
      - Populate $global:AzDceDetails / $global:AzDcrDetails, or accept that
        Ensure-SecurityInsightDce will build the cache on first use.

    Dot-source this file from the engine:
        . (Join-Path $PSScriptRoot '_shared\Ensure-SecurityInsightInfra.ps1')
#>

function Ensure-SecurityInsightAzDceDcrCache {
    <#
    Builds $global:AzDceDetails and $global:AzDcrDetails using the user's
    AzLogDcrIngestPS module if either is empty.

    When $SubscriptionId is supplied, the resulting caches are FILTERED to only
    entries in that subscription. This is essential when the same DCE/DCR name
    exists in multiple subscriptions (e.g. the SecurityInsight solution deployed
    to both an internal platform sub AND a community test sub): without the
    filter, the module's internal name-based lookup inside
    Post-AzLogAnalyticsLogIngestCustomLogDcrDce-Output picks the first match
    across all subs and the ingestion API rejects the call with:
      "The data collection endpoint FQDN '...' is not associated with the
       data collection rule with immutable Id '...'."

    Safe to call repeatedly.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string] $AzAppId,
        [Parameter(Mandatory)] [string] $AzAppSecret,
        [Parameter(Mandatory)] [string] $TenantId,
        [string] $SubscriptionId,
        [switch] $Force
    )
    if ($Force -or -not $global:AzDceDetails) {
        $global:AzDceDetails = Get-AzDceListAll -AzAppId $AzAppId -AzAppSecret $AzAppSecret -TenantId $TenantId -Verbose:$false
    }
    if ($Force -or -not $global:AzDcrDetails) {
        $global:AzDcrDetails = Get-AzDcrListAll -AzAppId $AzAppId -AzAppSecret $AzAppSecret -TenantId $TenantId -Verbose:$false
    }

    # Filter to target subscription so duplicate-name lookups across subs don't
    # pick the wrong resource. Both DCE and DCR objects carry a subscriptionId
    # property; fall back to parsing it from the ARM .id string when absent.
    if (-not [string]::IsNullOrWhiteSpace($SubscriptionId)) {
        $__filterToSub = {
            param($item, [string]$sub)
            $s = [string]$item.subscriptionId
            if ([string]::IsNullOrWhiteSpace($s) -and $item.id -match '/subscriptions/([^/]+)/') { $s = $Matches[1] }
            return ($s -eq $sub)
        }
        if ($global:AzDceDetails) {
            $global:AzDceDetails = @($global:AzDceDetails | Where-Object { & $__filterToSub $_ $SubscriptionId })
        }
        if ($global:AzDcrDetails) {
            $global:AzDcrDetails = @($global:AzDcrDetails | Where-Object { & $__filterToSub $_ $SubscriptionId })
        }
    }
}

function Ensure-SecurityInsightRg {
    <#
    Creates a resource group if missing and assigns Monitoring Metrics Publisher +
    Contributor to the SecurityInsight SPN at the RG scope. Returns $true when either the
    RG was created or new RBAC was assigned (so the caller can decide to sleep for
    RBAC propagation).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string] $ResourceGroup,
        [Parameter(Mandatory)] [string] $Location,
        [Parameter(Mandatory)] [string] $SubscriptionId,
        [string] $IngestionSpnObjectId,
        [string[]] $Roles = @('Monitoring Metrics Publisher', 'Contributor')
    )
    $changed = $false
    $rg = Get-AzResourceGroup -Name $ResourceGroup -ErrorAction SilentlyContinue
    if (-not $rg) {
        New-AzResourceGroup -Name $ResourceGroup -Location $Location -ErrorAction Stop | Out-Null
        Write-Host "[OK]   Created RG: $ResourceGroup ($Location)" -ForegroundColor Green
        $changed = $true
    } else {
        Write-Host "[INFO] RG exists: $ResourceGroup ($($rg.Location))" -ForegroundColor Gray
    }

    if ($IngestionSpnObjectId) {
        $rgScope = "/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroup"
        foreach ($role in $Roles) {
            $existing = Get-AzRoleAssignment -ObjectId $IngestionSpnObjectId -Scope $rgScope -RoleDefinitionName $role -ErrorAction SilentlyContinue |
                Where-Object { $_.Scope -eq $rgScope -and $_.RoleDefinitionName -eq $role }
            if (-not $existing) {
                try {
                    New-AzRoleAssignment -ObjectId $IngestionSpnObjectId -RoleDefinitionName $role -Scope $rgScope -ErrorAction Stop | Out-Null
                    Write-Host "[OK]   Assigned '$role' at $rgScope" -ForegroundColor Green
                    $changed = $true
                } catch {
                    Write-Host "[WARN] Could not assign '$role' at ${rgScope}: $($_.Exception.Message)" -ForegroundColor Yellow
                }
            }
        }
    }
    return $changed
}

function Ensure-SecurityInsightDce {
    <#
    Ensures a DCE exists with the given name. If missing, creates the RG + DCE and
    assigns RBAC to the SecurityInsight SPN. Refreshes $global:AzDceDetails at the end.
    Returns the DCE object from the cache.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string] $DceName,
        [Parameter(Mandatory)] [string] $DceResourceGroup,
        [Parameter(Mandatory)] [string] $Location,
        [Parameter(Mandatory)] [string] $SubscriptionId,
        [Parameter(Mandatory)] [string] $TenantId,
        [Parameter(Mandatory)] [string] $AzAppId,
        [Parameter(Mandatory)] [string] $AzAppSecret,
        [string] $IngestionSpnObjectId
    )
    Ensure-SecurityInsightAzDceDcrCache -AzAppId $AzAppId -AzAppSecret $AzAppSecret -TenantId $TenantId -SubscriptionId $SubscriptionId

    $dce = @($global:AzDceDetails | Where-Object { $_.name -eq $DceName }) | Select-Object -First 1
    if ($dce) {
        Write-Host "[OK]   DCE exists: $DceName (rg=$($dce.resourceGroup), location=$($dce.location))" -ForegroundColor Green
        return $dce
    }

    Write-Host "[STEP] DCE '$DceName' not found -- auto-provisioning in RG '$DceResourceGroup' ($Location)" -ForegroundColor Cyan

    $rgChanged = Ensure-SecurityInsightRg -ResourceGroup $DceResourceGroup -Location $Location -SubscriptionId $SubscriptionId -IngestionSpnObjectId $IngestionSpnObjectId

    try {
        New-AzDataCollectionEndpoint `
            -ResourceGroupName              $DceResourceGroup `
            -Name                           $DceName `
            -Location                       $Location `
            -NetworkAclsPublicNetworkAccess "Enabled" `
            -ErrorAction                    Stop | Out-Null
        Write-Host "[OK]   Created DCE: $DceName" -ForegroundColor Green
    } catch {
        Write-Host "[ERR]  DCE provisioning failed: $($_.Exception.Message)" -ForegroundColor Red
        throw
    }

    if ($rgChanged) {
        Write-Host "[INFO] Waiting 60s for RBAC propagation..." -ForegroundColor Gray
        Start-Sleep -Seconds 60
    } else {
        Start-Sleep -Seconds 10
    }

    Ensure-SecurityInsightAzDceDcrCache -AzAppId $AzAppId -AzAppSecret $AzAppSecret -TenantId $TenantId -SubscriptionId $SubscriptionId -Force
    $dce = @($global:AzDceDetails | Where-Object { $_.name -eq $DceName }) | Select-Object -First 1
    if (-not $dce) {
        throw "DCE '$DceName' was created but did not appear in the refreshed cache -- provisioning state may still be 'Creating'"
    }
    return $dce
}

function Resolve-SecurityInsightWorkspaceResourceId {
    <#
    Resolves a Log Analytics workspace to its full resource ID given either a
    resource ID (wins when set) or a workspace name (tenant-wide / subscription-wide
    search). Returns $null if not found -- caller can then choose to create it via
    Ensure-SecurityInsightWorkspace.

    Inputs hierarchy:
        $WorkspaceResourceId  -- wins, validated to exist
        $WorkspaceName        -- looked up in the current Az context
    #>
    [CmdletBinding()]
    param(
        [string] $WorkspaceResourceId,
        [string] $WorkspaceName
    )
    if (-not [string]::IsNullOrWhiteSpace($WorkspaceResourceId)) {
        # Validate it actually exists; return the canonical resource ID from Azure
        if ($WorkspaceResourceId -match '/subscriptions/([^/]+)/resourceGroups/([^/]+)/providers/[Mm]icrosoft\.[Oo]perational[Ii]nsights/workspaces/([^/]+)') {
            $subId = $Matches[1]; $rgName = $Matches[2]; $wsName = $Matches[3]
            try {
                $ctx = Get-AzContext -ErrorAction SilentlyContinue
                if ($ctx -and $ctx.Subscription.Id -ne $subId) {
                    Set-AzContext -SubscriptionId $subId -ErrorAction Stop | Out-Null
                }
                $ws = Get-AzOperationalInsightsWorkspace -ResourceGroupName $rgName -Name $wsName -ErrorAction SilentlyContinue
                if ($ws) { return [string]$ws.ResourceId }
            } catch { }
        }
        # ID was set but couldn't be validated -- hand it back anyway (caller will try to use it)
        return [string]$WorkspaceResourceId
    }
    if (-not [string]::IsNullOrWhiteSpace($WorkspaceName)) {
        try {
            $ws = Get-AzOperationalInsightsWorkspace -ErrorAction SilentlyContinue |
                  Where-Object { $_.Name -eq $WorkspaceName } | Select-Object -First 1
            if ($ws) { return [string]$ws.ResourceId }
        } catch { }
    }
    return $null
}

function Ensure-SecurityInsightWorkspace {
    <#
    Ensures a Log Analytics workspace exists. Returns its full resource ID.
    Hierarchy: explicit resource ID > name lookup in current subscription > create.
    When creating, uses $WorkspaceResourceGroup (default 'rg-securityinsight') and
    $Location. Also assigns Contributor to the SecurityInsight SPN on the workspace scope
    so it can create/update custom tables.
    #>
    [CmdletBinding()]
    param(
        [string] $WorkspaceResourceId,
        [string] $WorkspaceName,
        [string] $WorkspaceResourceGroup = 'rg-securityinsight',
        [Parameter(Mandatory)] [string] $Location,
        [Parameter(Mandatory)] [string] $SubscriptionId,
        [string] $IngestionSpnObjectId,
        [int]    $RetentionDays = 90
    )

    # Try to resolve first (no creation)
    $resolved = Resolve-SecurityInsightWorkspaceResourceId -WorkspaceResourceId $WorkspaceResourceId -WorkspaceName $WorkspaceName
    if ($resolved) {
        # Validate it's actually reachable; if the ID was stale, fall through and create.
        if ($resolved -match '/subscriptions/([^/]+)/resourceGroups/([^/]+)/providers/[Mm]icrosoft\.[Oo]perational[Ii]nsights/workspaces/([^/]+)') {
            $subId = $Matches[1]; $rgName = $Matches[2]; $wsName = $Matches[3]
            try {
                $ctx = Get-AzContext -ErrorAction SilentlyContinue
                if ($ctx -and $ctx.Subscription.Id -ne $subId) {
                    Set-AzContext -SubscriptionId $subId -ErrorAction Stop | Out-Null
                }
                $ws = Get-AzOperationalInsightsWorkspace -ResourceGroupName $rgName -Name $wsName -ErrorAction SilentlyContinue
                if ($ws) {
                    Write-Host "[OK]   Workspace exists: $wsName (rg=$rgName)" -ForegroundColor Green
                    return [string]$ws.ResourceId
                }
            } catch { }
        }
    }

    # Create path: need a name to proceed
    if ([string]::IsNullOrWhiteSpace($WorkspaceName)) {
        throw "Ensure-SecurityInsightWorkspace: cannot create -- no WorkspaceName provided (WorkspaceResourceId was '$WorkspaceResourceId')"
    }

    Write-Host "[STEP] Log Analytics workspace '$WorkspaceName' not found -- auto-provisioning in RG '$WorkspaceResourceGroup' ($Location)" -ForegroundColor Cyan

    $rgChanged = Ensure-SecurityInsightRg `
                    -ResourceGroup        $WorkspaceResourceGroup `
                    -Location             $Location `
                    -SubscriptionId       $SubscriptionId `
                    -IngestionSpnObjectId $null  # workspace-scope RBAC assigned separately below

    try {
        New-AzOperationalInsightsWorkspace `
            -ResourceGroupName $WorkspaceResourceGroup `
            -Name              $WorkspaceName `
            -Location          $Location `
            -Sku               "PerGB2018" `
            -RetentionInDays   $RetentionDays `
            -ErrorAction       Stop | Out-Null
        Write-Host "[OK]   Created workspace: $WorkspaceName (rg=$WorkspaceResourceGroup)" -ForegroundColor Green
    } catch {
        throw "Workspace provisioning failed: $($_.Exception.Message)"
    }

    # Wait for workspace to be fully provisioned
    $ws = $null
    for ($i = 0; $i -lt 10; $i++) {
        $ws = Get-AzOperationalInsightsWorkspace -ResourceGroupName $WorkspaceResourceGroup -Name $WorkspaceName -ErrorAction SilentlyContinue
        if ($ws -and $ws.CustomerId -and $ws.ResourceId) { break }
        Start-Sleep -Seconds 5
    }
    if (-not $ws -or -not $ws.ResourceId) {
        throw "Workspace was created but did not become queryable within 50s"
    }

    # Assign Contributor on workspace so the SecurityInsight SPN can manage tables/DCRs
    if ($IngestionSpnObjectId) {
        try {
            $existing = Get-AzRoleAssignment -ObjectId $IngestionSpnObjectId -Scope $ws.ResourceId -RoleDefinitionName 'Contributor' -ErrorAction SilentlyContinue |
                Where-Object { $_.Scope -eq $ws.ResourceId }
            if (-not $existing) {
                New-AzRoleAssignment -ObjectId $IngestionSpnObjectId -RoleDefinitionName 'Contributor' -Scope $ws.ResourceId -ErrorAction Stop | Out-Null
                Write-Host "[OK]   Assigned 'Contributor' at $($ws.ResourceId)" -ForegroundColor Green
            }
        } catch {
            Write-Host "[WARN] Could not assign 'Contributor' at workspace scope: $($_.Exception.Message)" -ForegroundColor Yellow
        }
    }

    return [string]$ws.ResourceId
}

function Resolve-SecurityInsightDceIngestionUri {
    <#
    Returns the LogIngestion endpoint URI for a DCE by name using
    $global:AzDceDetails. Returns $null if not found (cache must be populated).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string] $DceName
    )
    if (-not $global:AzDceDetails) { return $null }
    $dce = @($global:AzDceDetails | Where-Object { $_.name -eq $DceName }) | Select-Object -First 1
    if ($dce -and $dce.properties -and $dce.properties.logsIngestion -and $dce.properties.logsIngestion.endpoint) {
        return [string]$dce.properties.logsIngestion.endpoint
    }
    return $null
}
