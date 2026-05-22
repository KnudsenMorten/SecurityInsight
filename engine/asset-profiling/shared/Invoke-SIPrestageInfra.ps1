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

        # Storage account for engine staging (sistaging container, fingerprint
        # cache, CMDB tables). Optional -- when StorageAccountName is empty,
        # the storage step is skipped (engine still works for LA-only flows
        # but staging features will fail downstream).
        [string]$StorageAccountName,
        [string]$StorageResourceGroup,

        # Common
        [Parameter(Mandatory)][string]$Location,
        [Parameter(Mandatory)][string]$SubscriptionId,
        [Parameter(Mandatory)][string]$SpnObjectId
    )

    Write-SIStep 'Infrastructure check (workspace + DCE/DCR RGs + RBAC + DCE + storage -- idempotent)'
    Write-SIInfo ('  sub          : {0}' -f $SubscriptionId)
    Write-SIInfo ('  workspace    : {0}  (rg={1})' -f $WorkspaceName, $WorkspaceResourceGroup)
    Write-SIInfo ('  DCE          : {0}  (rg={1})' -f $DceName, $DceResourceGroup)
    Write-SIInfo ('  DCR RG       : {0}' -f $DcrResourceGroup)
    Write-SIInfo ('  Location     : {0}' -f $Location)
    Write-Host ''

    $changed = $false

    # Aligned label format: " [OK]   <label, 22 wide> : <value> [<status>]"
    $_lbl = '{0,-22} : {1}'
    function _Si_Status([bool]$Created) { if ($Created) { '[CREATED]' } else { '[exists]' } }

    # ---- 0. Set subscription context ----
    try {
        $ctx = Get-AzContext -ErrorAction SilentlyContinue
        if (-not $ctx -or [string]$ctx.Subscription.Id -ne $SubscriptionId) {
            $null = Set-AzContext -Subscription $SubscriptionId -ErrorAction Stop
            Write-SIOk ($_lbl -f 'Az context', "$SubscriptionId  [SWITCHED]")
        } else {
            Write-SIOk ($_lbl -f 'Az context', "$SubscriptionId")
        }
    } catch {
        Write-Warning ('could not set sub context to {0}: {1} (continuing on default ctx)' -f $SubscriptionId, $_.Exception.Message)
    }

    # ---- 1. Workspace RG ----
    try {
        if (Get-AzResourceGroup -Name $WorkspaceResourceGroup -ErrorAction SilentlyContinue) {
            Write-SIOk ($_lbl -f 'Workspace RG', "$WorkspaceResourceGroup  $(_Si_Status $false)")
        } else {
            $null = New-AzResourceGroup -Name $WorkspaceResourceGroup -Location $Location -ErrorAction Stop
            Write-SIOk ($_lbl -f 'Workspace RG', "$WorkspaceResourceGroup  $(_Si_Status $true)")
            $changed = $true
        }
    } catch { Write-Warning ('workspace RG ensure failed: {0}' -f $_.Exception.Message) }

    # ---- 2. LA Workspace ----
    try {
        $ws = Get-AzOperationalInsightsWorkspace -ResourceGroupName $WorkspaceResourceGroup -Name $WorkspaceName -ErrorAction SilentlyContinue
        if ($ws) {
            Write-SIOk ($_lbl -f 'LA workspace', "$WorkspaceName  $(_Si_Status $false)")
        } else {
            $null = New-AzOperationalInsightsWorkspace -ResourceGroupName $WorkspaceResourceGroup -Name $WorkspaceName -Location $Location -Sku 'PerGB2018' -RetentionInDays 90 -ErrorAction Stop
            Write-SIOk ($_lbl -f 'LA workspace', "$WorkspaceName  $(_Si_Status $true) (PerGB2018, 90d)")
            $changed = $true
        }
    } catch { Write-Warning ('workspace ensure failed: {0}' -f $_.Exception.Message) }

    # ---- 3. DCE RG ----
    try {
        if (Get-AzResourceGroup -Name $DceResourceGroup -ErrorAction SilentlyContinue) {
            Write-SIOk ($_lbl -f 'DCE RG', "$DceResourceGroup  $(_Si_Status $false)")
        } else {
            $null = New-AzResourceGroup -Name $DceResourceGroup -Location $Location -ErrorAction Stop
            Write-SIOk ($_lbl -f 'DCE RG', "$DceResourceGroup  $(_Si_Status $true)")
            $changed = $true
        }
    } catch { Write-Warning ('DCE RG ensure failed: {0}' -f $_.Exception.Message) }

    # ---- 4. DCR RG (skip if same as DCE RG) ----
    if ($DcrResourceGroup -eq $DceResourceGroup) {
        Write-SIOk ($_lbl -f 'DCR RG', "$DcrResourceGroup  [same as DCE RG]")
    } else {
        try {
            if (Get-AzResourceGroup -Name $DcrResourceGroup -ErrorAction SilentlyContinue) {
                Write-SIOk ($_lbl -f 'DCR RG', "$DcrResourceGroup  $(_Si_Status $false)")
            } else {
                $null = New-AzResourceGroup -Name $DcrResourceGroup -Location $Location -ErrorAction Stop
                Write-SIOk ($_lbl -f 'DCR RG', "$DcrResourceGroup  $(_Si_Status $true)")
                $changed = $true
            }
        } catch { Write-Warning ('DCR RG ensure failed: {0}' -f $_.Exception.Message) }
    }

    # ---- 5. RBAC: Contributor on workspace ----
    try {
        $existing = Get-AzRoleAssignment -ObjectId $SpnObjectId -Scope $WorkspaceResourceId -ErrorAction SilentlyContinue |
                      Where-Object { $_.RoleDefinitionName -eq 'Contributor' -and $_.Scope -eq $WorkspaceResourceId }
        if ($existing) {
            Write-SIOk ($_lbl -f 'RBAC workspace', 'Contributor  [already granted]')
        } else {
            $null = New-AzRoleAssignment -ObjectId $SpnObjectId -RoleDefinitionName 'Contributor' -Scope $WorkspaceResourceId -ErrorAction Stop
            Write-SIOk ($_lbl -f 'RBAC workspace', 'Contributor  [GRANTED]')
            $changed = $true
        }
    } catch { Write-Warning ("could not grant 'Contributor' on workspace: {0}" -f $_.Exception.Message) }

    # ---- 6+7. RBAC: Contributor + MMP on each RG ----
    $rgsToGrant = @($DcrResourceGroup)
    if ($DceResourceGroup -ne $DcrResourceGroup) { $rgsToGrant += $DceResourceGroup }

    foreach ($rg in $rgsToGrant) {
        $scope = "/subscriptions/$SubscriptionId/resourceGroups/$rg"
        foreach ($role in @('Contributor','Monitoring Metrics Publisher')) {
            try {
                $existing = Get-AzRoleAssignment -ObjectId $SpnObjectId -Scope $scope -ErrorAction SilentlyContinue |
                              Where-Object { $_.RoleDefinitionName -eq $role -and $_.Scope -eq $scope }
                $label = "RBAC RG $rg"
                if ($existing) {
                    Write-SIOk ($_lbl -f $label, "$role  [already granted]")
                } else {
                    $null = New-AzRoleAssignment -ObjectId $SpnObjectId -RoleDefinitionName $role -Scope $scope -ErrorAction Stop
                    Write-SIOk ($_lbl -f $label, "$role  [GRANTED]")
                    $changed = $true
                }
            } catch {
                Write-Warning ("could not grant '{0}' on '{1}': {2}" -f $role, $rg, $_.Exception.Message)
            }
        }
    }

    # ---- 8. DCE ----
    try {
        $dce = Get-AzDataCollectionEndpoint -ResourceGroupName $DceResourceGroup -Name $DceName -ErrorAction SilentlyContinue
        if ($dce) {
            Write-SIOk ($_lbl -f 'DCE', "$DceName  ($($dce.Location))  $(_Si_Status $false)")
        } else {
            $null = New-AzDataCollectionEndpoint -ResourceGroupName $DceResourceGroup -Name $DceName -Location $Location -NetworkAclsPublicNetworkAccess 'Enabled' -ErrorAction Stop
            Write-SIOk ($_lbl -f 'DCE', "$DceName  ($Location)  $(_Si_Status $true)")
            $changed = $true
        }
    } catch { Write-Warning ('DCE ensure failed: {0}' -f $_.Exception.Message) }

    # ---- 9. Storage account + sistaging container (engine staging) ----
    # Skipped when -StorageAccountName is empty (LA-only deployments).
    if (-not [string]::IsNullOrWhiteSpace($StorageAccountName)) {
        $stRg = if (-not [string]::IsNullOrWhiteSpace($StorageResourceGroup)) { $StorageResourceGroup } else { $WorkspaceResourceGroup }
        # Storage RG (might be a 4th distinct RG or shared with workspace)
        try {
            if (Get-AzResourceGroup -Name $stRg -ErrorAction SilentlyContinue) {
                Write-SIOk ($_lbl -f 'Storage RG', "$stRg  $(_Si_Status $false)")
            } else {
                $null = New-AzResourceGroup -Name $stRg -Location $Location -ErrorAction Stop
                Write-SIOk ($_lbl -f 'Storage RG', "$stRg  $(_Si_Status $true)")
                $changed = $true
            }
        } catch { Write-Warning ('storage RG ensure failed: {0}' -f $_.Exception.Message) }

        # Storage account (Standard_LRS, HTTPS only, TLS 1.2+, public access on)
        $saCreated = $false   # tracked separately from $changed so writeback fires only on first-create
        try {
            $sa = Get-AzStorageAccount -ResourceGroupName $stRg -Name $StorageAccountName -ErrorAction SilentlyContinue
            if ($sa) {
                Write-SIOk ($_lbl -f 'Storage account', "$StorageAccountName  $(_Si_Status $false)")
            } else {
                # v2.2.353 -- before assuming the storage account doesn't exist (and
                # trying to create), probe ACROSS all subs/RGs the SPN can see. The
                # storage account name is GLOBALLY unique; if it exists anywhere the
                # SPN has read access we should adopt it rather than fail with
                # "already taken" on the create. Covers the common case: customer's
                # storage account was provisioned earlier under a different RG (or a
                # sibling subscription) than the one we picked from defaults.
                $existingElsewhere = $null
                try {
                    $existingElsewhere = Get-AzStorageAccount -ErrorAction SilentlyContinue |
                                          Where-Object { $_.StorageAccountName -eq $StorageAccountName } |
                                          Select-Object -First 1
                } catch {}
                if ($existingElsewhere) {
                    $foundRg  = $existingElsewhere.ResourceGroupName
                    $foundSub = ($existingElsewhere.Id -split '/')[2]
                    if ($foundSub -ne $SubscriptionId -or $foundRg -ne $stRg) {
                        Write-SIInfo ('  storage account ''{0}'' found in sub={1} rg={2} (not in expected sub={3} rg={4}) -- adopting existing.' -f `
                            $StorageAccountName, $foundSub, $foundRg, $SubscriptionId, $stRg)
                    }
                    $sa = $existingElsewhere
                    # Realign $stRg to where the storage account actually lives so
                    # the RBAC-scope string below targets the right resource.
                    $stRg = $foundRg
                    Write-SIOk ($_lbl -f 'Storage account', "$StorageAccountName  $(_Si_Status $false) (in $foundRg)")
                } else {
                    # Name is free everywhere the SPN can see -- proceed with create.
                    try {
                        $sa = New-AzStorageAccount -ResourceGroupName $stRg -Name $StorageAccountName -Location $Location -SkuName 'Standard_LRS' -Kind 'StorageV2' -EnableHttpsTrafficOnly $true -MinimumTlsVersion 'TLS1_2' -AllowBlobPublicAccess $false -ErrorAction Stop
                        Write-SIOk ($_lbl -f 'Storage account', "$StorageAccountName  $(_Si_Status $true) (Standard_LRS, TLS1_2)")
                        $changed   = $true
                        $saCreated = $true
                    } catch {
                        if ($_.Exception.Message -match 'already taken') {
                            Write-Warning ("storage account '$StorageAccountName' is GLOBALLY taken but not visible to the SPN (probably owned by a different tenant, or the SPN lacks 'Reader' on the sub where it lives). Either rename `$global:SI_StorageAccount in custom.ps1, or grant the SPN Reader on the owning subscription so the prestage can adopt it. Re-throwing.")
                        }
                        throw
                    }
                }
            }
            # Storage Blob Data Contributor on the storage account (engine reads/writes blobs via OAuth when SI_UseStorageOAuth, otherwise uses key)
            $stScope = "/subscriptions/$SubscriptionId/resourceGroups/$stRg/providers/Microsoft.Storage/storageAccounts/$StorageAccountName"
            foreach ($role in @('Storage Blob Data Contributor','Storage Table Data Contributor','Storage Queue Data Contributor')) {
                try {
                    $existing = Get-AzRoleAssignment -ObjectId $SpnObjectId -Scope $stScope -ErrorAction SilentlyContinue |
                                  Where-Object { $_.RoleDefinitionName -eq $role -and $_.Scope -eq $stScope }
                    if ($existing) {
                        Write-SIOk ($_lbl -f 'RBAC storage', "$role  [already granted]")
                    } else {
                        $null = New-AzRoleAssignment -ObjectId $SpnObjectId -RoleDefinitionName $role -Scope $stScope -ErrorAction Stop
                        Write-SIOk ($_lbl -f 'RBAC storage', "$role  [GRANTED]")
                        $changed = $true
                    }
                } catch { Write-Warning ("could not grant '{0}' on storage: {1}" -f $role, $_.Exception.Message) }
            }
            # v2.2.314 -- OAuth-only. Pre-v2.2.314 had a SharedKey branch here
            # that called Get-AzStorageAccountKey + auto-persisted the result to
            # custom.ps1. Both are gone: SharedKey is no longer a supported auth
            # path, listKeys is no longer probed, and nothing is appended to the
            # operator's custom.ps1. The Storage Data Contributor RBAC granted
            # above is the only authorization the engine needs.
            Write-SIInfo '  OAuth-on-storage enforced (v2.2.314+) -- no SI_StorageKey fetch, no writeback to custom.ps1'

            # Storage containers:
            #   - sistaging        : engine shard blobs (Discover/Collect/Enrich/Classify/Output stages)
            #   - securityinsight  : RA xlsx/json export upload target (default for $global:ExportDestination)
            $stCtx = $sa.Context
            foreach ($cn in @('sistaging','securityinsight')) {
                try {
                    if ($stCtx) {
                        $container = Get-AzStorageContainer -Name $cn -Context $stCtx -ErrorAction SilentlyContinue
                        if ($container) {
                            Write-SIOk ($_lbl -f 'Storage container', "$cn  $(_Si_Status $false)")
                        } else {
                            $null = New-AzStorageContainer -Name $cn -Context $stCtx -Permission Off -ErrorAction Stop
                            Write-SIOk ($_lbl -f 'Storage container', "$cn  $(_Si_Status $true)")
                            $changed = $true
                        }
                    }
                } catch { Write-Warning ("'{0}' container ensure failed: {1}" -f $cn, $_.Exception.Message) }
            }
        } catch { Write-Warning ('storage account ensure failed: {0}' -f $_.Exception.Message) }
    }

    # ---- 10. Propagation sleep (only when something was created/granted) ----
    if ($changed) {
        Write-SIInfo '  sleeping 30s for ARM/RBAC propagation ...'
        Start-Sleep -Seconds 30
    } else {
        Write-SIInfo '  all infra + RBAC already in place -- no changes'
    }

    Write-SIInfo '  prestage done'
}
