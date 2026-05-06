function Invoke-SIPrestageInfra {
    <#
        Idempotent pre-stage of the LA-ingest infra. Runs once per ingest call
        when the LA sink is enabled. Ensures (read-then-write -- existing
        resources are no-ops):

          1. Workspace RG exists (creates if missing)
          2. LA workspace exists (creates if missing, SKU PerGB2018, retention 90d)
          3. DCE RG exists (creates if missing)
          4. DCR RG exists (creates if missing)
          5. SPN has 'Contributor' on the workspace
          6. SPN has 'Contributor' + 'Monitoring Metrics Publisher' on the
             DCE RG (Contributor = needed to create DCE; MMP = belt-and-
             suspenders so any DCR auto-created here later inherits MMP)
          7. SPN has 'Contributor' + 'Monitoring Metrics Publisher' on the
             DCR RG (Contributor = needed for CheckCreateUpdate-TableDcr-
             Structure; MMP = needed for ingest)
          8. DCE exists (creates if missing)

        Each step is read-then-write; per-step failures log a WARN and
        continue (one missing role shouldn't fail the whole pre-stage).

        Caller (Write-SIClassificationToLogAnalytics) gates the entire call
        behind $global:SI_PrestageInfra (default ON when LA sink enabled).
        Operators who manage infra via IaC and don't want the engine
        touching ARM should set $global:SI_PrestageInfra = $false.

        Requires the engine SPN to hold 'User Access Administrator' OR
        'Owner' somewhere in the scope hierarchy (sub or higher) for the
        New-AzRoleAssignment calls + 'Contributor' for resource creation.
        If the SPN can't perform a step, that step logs a WARN; ingest may
        still 403 later if MMP isn't present -- but the operator sees WHY
        in the transcript.
    #>
    [CmdletBinding()]
    param(
        # Workspace identity (parsed from $global:SI_WorkspaceResourceId at the call site)
        [Parameter(Mandatory)][string]$WorkspaceName,
        [Parameter(Mandatory)][string]$WorkspaceResourceGroup,
        [Parameter(Mandatory)][string]$WorkspaceResourceId,

        # DCR / DCE
        [Parameter(Mandatory)][string]$DcrResourceGroup,
        [Parameter(Mandatory)][string]$DceResourceGroup,
        [Parameter(Mandatory)][string]$DceName,

        # Common
        [Parameter(Mandatory)][string]$Location,
        [Parameter(Mandatory)][string]$SubscriptionId,
        [Parameter(Mandatory)][string]$SpnObjectId
    )

    Write-SIStep 'Prestage infra (workspace + DCE/DCR RGs + RBAC + DCE -- idempotent)'
    Write-SIInfo ('  sub          : {0}' -f $SubscriptionId)
    Write-SIInfo ('  workspace    : {0}  (rg={1})' -f $WorkspaceName, $WorkspaceResourceGroup)
    Write-SIInfo ('  DCE          : {0}  (rg={1})' -f $DceName, $DceResourceGroup)
    Write-SIInfo ('  DCR RG       : {0}' -f $DcrResourceGroup)
    Write-SIInfo ('  Location     : {0}' -f $Location)

    $changed = $false

    # ---- 0. Set subscription context ----
    try {
        $ctx = Get-AzContext -ErrorAction SilentlyContinue
        if (-not $ctx -or [string]$ctx.Subscription.Id -ne $SubscriptionId) {
            $null = Set-AzContext -Subscription $SubscriptionId -ErrorAction Stop
            Write-SIInfo ("  switched Az context -> sub '{0}'" -f $SubscriptionId)
        }
    } catch {
        Write-Warning ('Prestage: could not set sub context to {0}: {1} (continuing on default ctx)' -f $SubscriptionId, $_.Exception.Message)
    }

    # ---- 1. Workspace RG ----
    try {
        if (-not (Get-AzResourceGroup -Name $WorkspaceResourceGroup -ErrorAction SilentlyContinue)) {
            Write-SIInfo ("  creating workspace RG '{0}' in {1}" -f $WorkspaceResourceGroup, $Location)
            $null = New-AzResourceGroup -Name $WorkspaceResourceGroup -Location $Location -ErrorAction Stop
            $changed = $true
        }
    } catch { Write-Warning ('Prestage: workspace RG ensure failed: {0}' -f $_.Exception.Message) }

    # ---- 2. LA Workspace ----
    try {
        $ws = Get-AzOperationalInsightsWorkspace -ResourceGroupName $WorkspaceResourceGroup -Name $WorkspaceName -ErrorAction SilentlyContinue
        if (-not $ws) {
            Write-SIInfo ("  creating LA workspace '{0}' in {1}/{2} (SKU PerGB2018, retention 90d)" -f $WorkspaceName, $WorkspaceResourceGroup, $Location)
            $null = New-AzOperationalInsightsWorkspace -ResourceGroupName $WorkspaceResourceGroup -Name $WorkspaceName -Location $Location -Sku 'PerGB2018' -RetentionInDays 90 -ErrorAction Stop
            $changed = $true
        }
    } catch { Write-Warning ('Prestage: workspace ensure failed: {0}' -f $_.Exception.Message) }

    # ---- 3. DCE RG ----
    try {
        if (-not (Get-AzResourceGroup -Name $DceResourceGroup -ErrorAction SilentlyContinue)) {
            Write-SIInfo ("  creating DCE RG '{0}' in {1}" -f $DceResourceGroup, $Location)
            $null = New-AzResourceGroup -Name $DceResourceGroup -Location $Location -ErrorAction Stop
            $changed = $true
        }
    } catch { Write-Warning ('Prestage: DCE RG ensure failed: {0}' -f $_.Exception.Message) }

    # ---- 4. DCR RG (skip if same as DCE RG) ----
    if ($DcrResourceGroup -ne $DceResourceGroup) {
        try {
            if (-not (Get-AzResourceGroup -Name $DcrResourceGroup -ErrorAction SilentlyContinue)) {
                Write-SIInfo ("  creating DCR RG '{0}' in {1}" -f $DcrResourceGroup, $Location)
                $null = New-AzResourceGroup -Name $DcrResourceGroup -Location $Location -ErrorAction Stop
                $changed = $true
            }
        } catch { Write-Warning ('Prestage: DCR RG ensure failed: {0}' -f $_.Exception.Message) }
    }

    # ---- 5. RBAC: Contributor on workspace ----
    try {
        $existing = Get-AzRoleAssignment -ObjectId $SpnObjectId -Scope $WorkspaceResourceId -ErrorAction SilentlyContinue |
                      Where-Object { $_.RoleDefinitionName -eq 'Contributor' -and $_.Scope -eq $WorkspaceResourceId }
        if (-not $existing) {
            Write-SIInfo ('  granting ''Contributor'' on workspace to SPN')
            $null = New-AzRoleAssignment -ObjectId $SpnObjectId -RoleDefinitionName 'Contributor' -Scope $WorkspaceResourceId -ErrorAction Stop
            $changed = $true
        }
    } catch { Write-Warning ("Prestage: could not grant 'Contributor' on workspace: {0}" -f $_.Exception.Message) }

    # ---- 6+7. RBAC: Contributor + MMP on each RG ----
    $rgsToGrant = @($DcrResourceGroup)
    if ($DceResourceGroup -ne $DcrResourceGroup) { $rgsToGrant += $DceResourceGroup }

    foreach ($rg in $rgsToGrant) {
        $scope = "/subscriptions/$SubscriptionId/resourceGroups/$rg"
        foreach ($role in @('Contributor','Monitoring Metrics Publisher')) {
            try {
                $existing = Get-AzRoleAssignment -ObjectId $SpnObjectId -Scope $scope -ErrorAction SilentlyContinue |
                              Where-Object { $_.RoleDefinitionName -eq $role -and $_.Scope -eq $scope }
                if (-not $existing) {
                    Write-SIInfo ("  granting '{0}' on RG '{1}' to SPN" -f $role, $rg)
                    $null = New-AzRoleAssignment -ObjectId $SpnObjectId -RoleDefinitionName $role -Scope $scope -ErrorAction Stop
                    $changed = $true
                }
            } catch {
                Write-Warning ("Prestage: could not grant '{0}' on '{1}': {2}" -f $role, $rg, $_.Exception.Message)
            }
        }
    }

    # ---- 8. DCE ----
    try {
        $dce = Get-AzDataCollectionEndpoint -ResourceGroupName $DceResourceGroup -Name $DceName -ErrorAction SilentlyContinue
        if (-not $dce) {
            Write-SIInfo ("  creating DCE '{0}' in {1}/{2}" -f $DceName, $DceResourceGroup, $Location)
            $null = New-AzDataCollectionEndpoint -ResourceGroupName $DceResourceGroup -Name $DceName -Location $Location -NetworkAclsPublicNetworkAccess 'Enabled' -ErrorAction Stop
            $changed = $true
        }
    } catch { Write-Warning ('Prestage: DCE ensure failed: {0}' -f $_.Exception.Message) }

    # ---- 9. Propagation sleep (only when something was created/granted) ----
    if ($changed) {
        Write-SIInfo '  sleeping 30s for ARM/RBAC propagation ...'
        Start-Sleep -Seconds 30
    } else {
        Write-SIInfo '  all infra + RBAC already in place -- no changes'
    }

    Write-SIInfo '  prestage done'
}
