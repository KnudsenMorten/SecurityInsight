#Requires -Version 5.1
<#
    Tagging stage.

    READ-ONLY by design (v2.2 invariant). This stage:
      1. Loads RuleType: AssetTag rules for the engine.
      2. Runs each rule's query (DefenderGraph or LA) to compute WHICH
         assets WOULD receive WHICH tag.
      3. Emits a row per (asset, tag) to SI_AssetTagActivity_CL with
         Status='WouldApply'.

    NO write-back. v2.2 NEVER calls MDE machine-tags API, Entra Custom
    Security Attributes, or ARM tag PATCH endpoints. The downstream
    consumer of SI_AssetTagActivity_CL (customer's existing tagger,
    a separate tagger solution, or a manual review workflow) decides
    what to actually push.

    Mode: Test       -- the only legal value. Engines run the rule
                        + log the intent.
    Mode: Production -- REJECTED with a clear error pointing to the
                        v2.2 read-only invariant. A future tagger
                        solution outside v2.2 may consume the audit
                        rows and apply.
#>

function Invoke-SITagging {
    [CmdletBinding()]
    param([Parameter(Mandatory)][object]$RunContext)

    if ($RunContext.StorageContext.Mode -eq 'Mock') {
        return [pscustomobject]@{
            Stage   = 'Tagging'
            Skipped = 'mock mode'
            Summary = 'skipped (mock)'
        }
    }

    $rules = @(Get-SIPostureRules -Engine $RunContext.Engine | Where-Object { $_.RuleType -in 'AssetTag','Both' })
    if ($rules.Count -eq 0) {
        return [pscustomobject]@{
            Stage   = 'Tagging'
            Rules   = 0
            Summary = 'no AssetTag rules for engine ' + $RunContext.Engine
        }
    }

    $activity = New-Object System.Collections.ArrayList
    $stats = @{ WouldApply=0; Rejected=0; QueryFailed=0 }

    foreach ($rule in $rules) {
        # v2.2 invariant: only Mode: Test is legal. Refuse Production loudly --
        # a future v2.3 tagger may consume these rows and apply, but v2.2
        # itself NEVER writes back to source-of-truth.
        if ($rule.Mode -ne 'Test') {
            Write-Warning ("    Tagging rule '{0}' has Mode={1} -- REJECTED. v2.2 is read-only; only Mode: Test is legal. Skipping." -f $rule.AssetTagName, $rule.Mode)
            $stats.Rejected++
            continue
        }

        Write-SIInfo ("   Tagging rule: {0}  [Test/read-only]" -f $rule.AssetTagName)

        $rows = Invoke-SIHuntingQuery -Query $rule.Query -QueryEngine $rule.QueryEngine
        if (@($rows).Count -eq 0) {
            Write-SIInfo '     -> 0 rows (no candidates / all already tagged via leftanti)'
            continue
        }

        foreach ($row in $rows) {
            $assetTag    = [string]$row.AssetTag
            $assetTagId  = if ($row.NodeId) { [string]$row.NodeId } else { '' }
            $targetId    = if ($row.DeviceId) { [string]$row.DeviceId }
                           elseif ($row.UserId) { [string]$row.UserId }
                           elseif ($row.AzureResourceId) { [string]$row.AzureResourceId }
                           else { '<unknown>' }

            $stats.WouldApply++

            [void]$activity.Add([pscustomobject]@{
                CollectionTime = $RunContext.CollectionTime
                SI_RunId       = $RunContext.RunId
                SI_Engine      = $RunContext.Engine
                AssetTagName   = $rule.AssetTagName
                Mode           = $rule.Mode
                QueryEngine    = $rule.QueryEngine
                TargetId       = $targetId
                AssetTag       = $assetTag
                AssetTagType   = if ($row.AssetTagType) { [string]$row.AssetTagType } else { '' }
                AssetTierLevel = if ($null -ne $row.AssetTierLevel) { [int]$row.AssetTierLevel } else { -1 }
                Status         = 'WouldApply'
                NodeId         = $assetTagId
            })
        }
    }

    # Ship audit rows to SI_AssetTagActivity_CL via the same AzLogDcrIngestPS
    # path used by Stage Output. Reuses the auth + DCR cache already warmed
    # by the upstream stage.
    if ($activity.Count -gt 0 -and ($RunContext.Sinks -contains 'LA')) {
        try {
            $auditTable = if ($global:SI_AssetTagActivityTable) { [string]$global:SI_AssetTagActivityTable } else { 'SI_AssetTagActivity' }
            $auditDcr   = if ($global:SI_AssetTagActivityDcr)   { [string]$global:SI_AssetTagActivityDcr }   else { 'dcr-si-assettag-activity' }
            # v2.2.237 -- mirror Invoke-Output.ps1 auth resolution. Prefer SI_SPN_*
            # (unified Bootstrap-Auth output) with cert OR secret; fall back to
            # SI_LogIngest_* legacy globals; MI when SI_UAMI_ClientId is set.
            $_appId   = if ($global:SI_SPN_AppId)           { $global:SI_SPN_AppId }           else { $global:SI_LogIngest_AppId }
            $_secret  = if ($global:SI_SPN_Secret)          { $global:SI_SPN_Secret }          else { $global:SI_LogIngest_Secret }
            $_tenant  = if ($global:SI_SPN_TenantId)        { $global:SI_SPN_TenantId }        else { $global:SI_LogIngest_TenantId }
            $_certThumb = [string]$global:SI_SPN_CertThumbprint
            # v2.2.243 -- auto-detect cert store (LocalMachine vs CurrentUser).
            $_certStore = if ($global:SI_SPN_CertStoreLocation) { [string]$global:SI_SPN_CertStoreLocation }
                          elseif ($_certThumb) {
                              $_clean = $_certThumb -replace '\s',''
                              $_resolved = 'LocalMachine'
                              foreach ($_s in 'LocalMachine','CurrentUser') {
                                  $_c = Get-ChildItem "Cert:\$_s\My" -ErrorAction SilentlyContinue |
                                        Where-Object { $_.Thumbprint -eq $_clean -and $_.HasPrivateKey } |
                                        Select-Object -First 1
                                  if ($_c) { $_resolved = $_s; break }
                              }
                              $_resolved
                          } else { 'LocalMachine' }
            $useMi      = -not [string]::IsNullOrWhiteSpace($global:SI_UAMI_ClientId)
            $useCert    = -not $useMi -and -not [string]::IsNullOrWhiteSpace($_certThumb)
            $authParams = if ($useMi) {
                @{ UseManagedIdentity = $true; ManagedIdentityClientId = $global:SI_UAMI_ClientId }
            } elseif ($useCert) {
                @{ AzAppId = $_appId; AzAppCertificateThumbprint = $_certThumb; AzAppCertificateStoreLocation = $_certStore; TenantId = $_tenant }
            } else {
                @{ AzAppId = $_appId; AzAppSecret = $_secret; TenantId = $_tenant }
            }

            Write-SIInfo ('audit table : {0}_CL  /  DCR : {1}' -f $auditTable, $auditDcr)
            Write-SIInfo ('audit rows  : {0}' -f $activity.Count)
            Write-SIInfo '-> CheckCreateUpdate-TableDcr-Structure'
            $null = CheckCreateUpdate-TableDcr-Structure `
                -AzLogWorkspaceResourceId                   $global:SI_WorkspaceResourceId `
                @authParams `
                -DceName                                    $global:SI_DceName `
                -DcrName                                    $auditDcr `
                -DcrResourceGroup                           $global:SI_DcrResourceGroup `
                -TableName                                  $auditTable `
                -Data                                       (@($activity | Select-Object -First 50)) `
                -LogIngestServicePricipleObjectId           $global:SI_LogIngest_ObjectId `
                -AzDcrSetLogIngestApiAppPermissionsDcrLevel $false `
                -AzLogDcrTableCreateFromAnyMachine          $true `
                -AzLogDcrTableCreateFromReferenceMachine    @()
            Write-SIInfo '-> waiting 15s for ARM eventual consistency...'
            Start-Sleep -Seconds 15

            $payload = @($activity)
            $payload = Add-ColumnDataToAllEntriesInArray -Data $payload `
                            -Column1Name Computer     -Column1Data $env:COMPUTERNAME `
                            -Column2Name ComputerFqdn -Column2Data $env:COMPUTERNAME `
                            -Column3Name UserLoggedOn -Column3Data 'container'
            $payload = ValidateFix-AzLogAnalyticsTableSchemaColumnNames -Data $payload
            $payload = Build-DataArrayToAlignWithSchema -Data $payload

            Write-SIInfo ('-> Post-AzLogAnalyticsLogIngestCustomLogDcrDce-Output (rows={0})' -f $payload.Count)
            $null = Post-AzLogAnalyticsLogIngestCustomLogDcrDce-Output `
                -DceName     $global:SI_DceName `
                -DcrName     $auditDcr `
                -Data        $payload `
                -TableName   $auditTable `
                @authParams
        } catch {
            Write-Warning ('SI_AssetTagActivity ingest failed: {0}' -f $_.Exception.Message)
        }
    }

    [pscustomobject]@{
        Stage         = 'Tagging'
        Rules         = $rules.Count
        WouldApply    = $stats.WouldApply
        Rejected      = $stats.Rejected
        Summary       = ('{0} rule(s) -- {1} would-apply rows logged to SI_AssetTagActivity_CL ({2} rejected for non-Test mode -- v2.2 is read-only)' -f $rules.Count, $stats.WouldApply, $stats.Rejected)
    }
}
