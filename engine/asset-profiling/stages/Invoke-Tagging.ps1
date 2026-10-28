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
                              if (Get-PSDrive -Name Cert -ErrorAction SilentlyContinue) {
                                  $_resolved = 'LocalMachine'
                                  foreach ($_s in 'LocalMachine','CurrentUser') {
                                      $_c = Get-ChildItem "Cert:\$_s\My" -ErrorAction SilentlyContinue |
                                            Where-Object { $_.Thumbprint -eq $_clean -and $_.HasPrivateKey } |
                                            Select-Object -First 1
                                      if ($_c) { $_resolved = $_s; break }
                                  }
                                  $_resolved
                              } else {
                                  # #209: no Cert: drive (a Linux container) -- read the X509Store instead.
                                  if (-not (Get-Command Get-SICertStoreLocation -ErrorAction SilentlyContinue)) {
                                      . (Join-Path (Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSScriptRoot))) 'auth/Find-SICertificate.ps1')
                                  }
                                  Get-SICertStoreLocation -Thumbprint $_clean
                              }
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
            # 🔴 THE CAP IS GONE, AND ITS WARNING WAS FALSE -- 2026-08-31, same as its twin in
            # Invoke-SchemaOutput.ps1. The POST sends `@($activity)` -- every row -- so nothing was
            # being dropped by row. The cap applied only to the SCHEMA sample, where it dropped
            # COLUMNS instead (audit #48).
            if ($global:SI_TagActivityRowCap -gt 0) {
                Write-SIWarn ('audit rows  : $global:SI_TagActivityRowCap is set ({0}) but no longer caps anything. It only ever limited the SCHEMA sample, which silently dropped columns; all {1} row(s) are ingested.' -f `
                    [int]$global:SI_TagActivityRowCap, $activity.Count)
            }
            # v2.2.246 -- DCR/DCE scope filter (see Invoke-Output.ps1 for rationale).
            $global:AzDceDetails = Get-SIDceList @authParams -Verbose:$false 4>$null
            $global:AzDcrDetails = Get-SIDcrList @authParams -Verbose:$false 4>$null
            if (Get-Command Apply-SIDcrScopeFilter -ErrorAction SilentlyContinue) {
                Apply-SIDcrScopeFilter -Scope 'tag-pre-create' -DcrName $auditDcr -DceName $global:SI_DceName `
                                       -SubscriptionId $global:SI_AzSubscriptionId `
                                       -DceResourceGroup $global:SI_DceResourceGroup `
                                       -DcrResourceGroup $global:SI_DcrResourceGroup
            }
            Write-SIInfo '-> CheckCreateUpdate-TableDcr-Structure'
            # 🔴 THE FULL SET DECIDES THE SCHEMA -- CORRECTED 2026-08-31, same defect as its twin
            # in Invoke-SchemaOutput.ps1 and as AUDIT #48. `-Data` was capped at $auditCap (default
            # 50) while the POST below sends `@($activity)` -- all of them. The module declares the
            # UNION of property names across what it is HANDED, so a column first appearing on row
            # 51 was never declared and its values were silently DROPPED AT INGEST.
            #
            # 🔴 ABOVE THE CALL, NOT INSIDE IT (audit #102, 2026-09-02). Written between two
            # backtick-continued argument lines, **a comment TERMINATES the continuation** and every
            # argument after it is dropped -- including the `-Data` it was added to explain.
            $null = Update-SILogTableSchema `
                -AzLogWorkspaceResourceId                   $global:SI_WorkspaceResourceId `
                @authParams `
                -DceName                                    $global:SI_DceName `
                -DcrName                                    $auditDcr `
                -DcrResourceGroup                           $global:SI_DcrResourceGroup `
                -TableName                                  $auditTable `
                -Data                                       @($activity) `
                -LogIngestServicePricipleObjectId           (Get-SILogIngestObjectId) `
                -AzDcrSetLogIngestApiAppPermissionsDcrLevel $false `
                -AzLogDcrTableCreateFromAnyMachine          $true `
                -AzLogDcrTableCreateFromReferenceMachine    @()
            Write-SIInfo '-> waiting 15s for ARM eventual consistency...'
            Start-Sleep -Seconds 15
            $global:AzDceDetails = Get-SIDceList @authParams -Verbose:$false 4>$null
            $global:AzDcrDetails = Get-SIDcrList @authParams -Verbose:$false 4>$null
            if (Get-Command Apply-SIDcrScopeFilter -ErrorAction SilentlyContinue) {
                Apply-SIDcrScopeFilter -Scope 'tag-post-create' -DcrName $auditDcr -DceName $global:SI_DceName `
                                       -SubscriptionId $global:SI_AzSubscriptionId `
                                       -DceResourceGroup $global:SI_DceResourceGroup `
                                       -DcrResourceGroup $global:SI_DcrResourceGroup
            }

            $payload = @($activity)
            # a Linux container has no COMPUTERNAME, and an empty value fails the parameter binding
            $__siHost = if ($env:COMPUTERNAME) { [string]$env:COMPUTERNAME } else { [System.Net.Dns]::GetHostName() }
            $payload = Add-SIColumnData -Data $payload `
                            -Column1Name Computer     -Column1Data $__siHost `
                            -Column2Name ComputerFqdn -Column2Data $__siHost `
                            -Column3Name UserLoggedOn -Column3Data 'container'
            $payload = Repair-SILogColumnName -Data $payload
            $payload = Format-SILogRowsToSchema -Data $payload

            Write-SIInfo ('-> Post-AzLogAnalyticsLogIngestCustomLogDcrDce-Output (rows={0})' -f $payload.Count)
            $null = Send-SILogData `
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
