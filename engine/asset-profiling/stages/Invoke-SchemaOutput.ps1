#Requires -Version 5.1
<#
    SchemaOutput stage. Three sinks:
      1. posture-rules-pending/<engine>/<NewRuleName>.yaml  -- AI drafts
         (NEVER auto-promoted; opt-in via $global:SI_LoadPendingRules to
         load pending rules at runtime; promotion = move to -locked/)
      2. risk-queries-pending/<NewRuleName>.kql              -- standalone
         risk-analysis KQL for review
      3. SI_SchemaCatalog_CL                                 -- audit row
         per finding (proposed or skipped) so KQL can answer "what new
         properties has Microsoft shipped lately + what did we draft for them"
      4. schema-baseline.json (staging blob) -- updated baseline so next
         run's diff is correct.
#>

function Invoke-SISchemaOutput {
    [CmdletBinding()]
    param([Parameter(Mandatory)][object]$RunContext)

    if ($RunContext.StorageContext.Mode -eq 'Mock') {
        return [pscustomobject]@{ Stage='SchemaOutput'; Summary='mock (skipped)' }
    }
    if (-not $RunContext.SchemaCatalog) {
        return [pscustomobject]@{ Stage='SchemaOutput'; Summary='no catalog -- skipped' }
    }

    $siRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSScriptRoot))
    $proposals = @($RunContext.SchemaProposals)

    # ---- Sink 1: write YAML drafts to posture-rules-pending/<engine>/ ----
    $drafted = 0
    foreach ($p in $proposals) {
        if ([string]::IsNullOrWhiteSpace($p.PostureRuleYaml)) { continue }
        $engine = if ($p.Engine -in 'endpoint','identity','azure','crossengine') { $p.Engine } else { 'endpoint' }
        $folder = Join-Path $siRoot (Join-Path 'posture-rules-pending' $engine)
        if (-not (Test-Path $folder)) { New-Item -Path $folder -ItemType Directory -Force | Out-Null }

        # Filename derived from finding -- deterministic so the same finding
        # next sweep updates the same file (reviewers see proper diffs).
        $key = switch ($p.Finding.Type) {
            'newProperty' { ('Property_{0}_{1}' -f $p.Finding.Label, ($p.Finding.Path -replace '[^A-Za-z0-9]','_')) }
            'newEdge'     { ('Edge_{0}'         -f ($p.Finding.EdgeLabel -replace '[^A-Za-z0-9]','_')) }
            'newTriple'   { ('Triple_{0}__{1}__{2}' -f $p.Finding.Source, ($p.Finding.Edge -replace '[^A-Za-z0-9]','_'), $p.Finding.Target) }
            'newColumn'   { ('Column_{0}_{1}'   -f $p.Finding.Table, $p.Finding.Column) }
            default       { 'Unknown_{0}' -f [guid]::NewGuid().ToString().Substring(0,8) }
        }
        $path = Join-Path $folder ($key + '.yaml')
        try {
            Set-Content -Path $path -Value $p.PostureRuleYaml -Encoding utf8 -Force
            $drafted++
        } catch {
            Write-Warning ('Failed to write draft {0}: {1}' -f $path, $_.Exception.Message)
        }

        # Sink 2: companion .kql when AI provided one
        if (-not [string]::IsNullOrWhiteSpace($p.RiskQueryKql)) {
            $kqlFolder = Join-Path $siRoot 'risk-queries-pending'
            if (-not (Test-Path $kqlFolder)) { New-Item -Path $kqlFolder -ItemType Directory -Force | Out-Null }
            $kqlPath = Join-Path $kqlFolder ($key + '.kql')
            try { Set-Content -Path $kqlPath -Value $p.RiskQueryKql -Encoding utf8 -Force } catch { }
        }
    }

    # ---- Sink 3: SI_SchemaCatalog_CL audit ----
    $auditRows = New-Object System.Collections.ArrayList
    foreach ($p in $proposals) {
        $f = $p.Finding
        [void]$auditRows.Add([pscustomobject]@{
            CollectionTime  = $RunContext.CollectionTime
            SI_RunId        = $RunContext.RunId
            FindingType     = $f.Type
            Label           = if ($f.Label) { $f.Label } elseif ($f.EdgeLabel) { $f.EdgeLabel } elseif ($f.Source) { $f.Source } elseif ($f.Table) { $f.Table } else { '' }
            Detail          = if ($f.Path) { $f.Path } elseif ($f.Edge) { ('{0} -> {1}' -f $f.Edge, $f.Target) } elseif ($f.Column) { ('{0} ({1})' -f $f.Column, $f.ColumnType) } else { '' }
            Relevance       = $p.Relevance
            ProposedEngine  = $p.Engine
            ProposedRuleType= $p.RuleType
            DraftWritten    = -not [string]::IsNullOrWhiteSpace($p.PostureRuleYaml)
            Reasoning       = $p.Reasoning
        })
    }

    if ($auditRows.Count -gt 0 -and ($RunContext.Sinks -contains 'LA')) {
        try {
            $auditTable = if ($global:SI_SchemaCatalogTable) { [string]$global:SI_SchemaCatalogTable } else { 'SI_SchemaCatalog' }
            $auditDcr   = if ($global:SI_SchemaCatalogDcr)   { [string]$global:SI_SchemaCatalogDcr }   else { 'dcr-si-schema-catalog' }
            # v2.2.237 -- mirror Invoke-Output.ps1 auth resolution. Prefer SI_SPN_*
            # (unified Bootstrap-Auth output) with cert OR secret; fall back to
            # SI_LogIngest_* legacy globals; MI when SI_UAMI_ClientId is set.
            $_appId   = if ($global:SI_SPN_AppId)           { $global:SI_SPN_AppId }           else { $global:SI_LogIngest_AppId }
            $_secret  = if ($global:SI_SPN_Secret)          { $global:SI_SPN_Secret }          else { $global:SI_LogIngest_Secret }
            $_tenant  = if ($global:SI_SPN_TenantId)        { $global:SI_SPN_TenantId }        else { $global:SI_LogIngest_TenantId }
            $_certThumb = [string]$global:SI_SPN_CertThumbprint
            $_certStore = if ($global:SI_SPN_CertStoreLocation) { [string]$global:SI_SPN_CertStoreLocation } else { 'LocalMachine' }
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
            Write-SIInfo ('audit rows  : {0}' -f $auditRows.Count)
            Write-SIInfo '-> CheckCreateUpdate-TableDcr-Structure'
            $null = CheckCreateUpdate-TableDcr-Structure `
                -AzLogWorkspaceResourceId                   $global:SI_WorkspaceResourceId `
                @authParams `
                -DceName                                    $global:SI_DceName `
                -DcrName                                    $auditDcr `
                -DcrResourceGroup                           $global:SI_DcrResourceGroup `
                -TableName                                  $auditTable `
                -Data                                       (@($auditRows | Select-Object -First 50)) `
                -LogIngestServicePricipleObjectId           $global:SI_LogIngest_ObjectId `
                -AzDcrSetLogIngestApiAppPermissionsDcrLevel $false `
                -AzLogDcrTableCreateFromAnyMachine          $true `
                -AzLogDcrTableCreateFromReferenceMachine    @()
            Write-SIInfo '-> waiting 15s for ARM eventual consistency...'
            Start-Sleep -Seconds 15

            $payload = @($auditRows)
            $payload = Add-ColumnDataToAllEntriesInArray -Data $payload `
                            -Column1Name Computer     -Column1Data $env:COMPUTERNAME `
                            -Column2Name ComputerFqdn -Column2Data $env:COMPUTERNAME `
                            -Column3Name UserLoggedOn -Column3Data 'container'
            $payload = ValidateFix-AzLogAnalyticsTableSchemaColumnNames -Data $payload
            $payload = Build-DataArrayToAlignWithSchema -Data $payload
            Write-SIInfo ('-> Post-AzLogAnalyticsLogIngestCustomLogDcrDce-Output (rows={0})' -f $payload.Count)
            $null = Post-AzLogAnalyticsLogIngestCustomLogDcrDce-Output `
                -DceName $global:SI_DceName -DcrName $auditDcr -Data $payload -TableName $auditTable @authParams
        } catch {
            Write-Warning ('SI_SchemaCatalog ingest failed: {0}' -f $_.Exception.Message)
        }
    }

    # ---- Sink 4: update baseline blob so next run can diff ----
    try {
        $tmp = New-TemporaryFile
        $RunContext.SchemaCatalog | ConvertTo-Json -Depth 12 -Compress | Set-Content -Path $tmp.FullName -Encoding utf8
        Set-AzStorageBlobContent -File $tmp.FullName -Container $RunContext.StagingContainer -Blob 'schema-baseline.json' -Context $RunContext.StorageContext.AzContext -Force | Out-Null
        Remove-Item -Path $tmp.FullName -Force
    } catch {
        Write-Warning ('Failed to write schema baseline: {0}' -f $_.Exception.Message)
    }

    [pscustomobject]@{
        Stage         = 'SchemaOutput'
        DraftsWritten = $drafted
        AuditRows     = $auditRows.Count
        Summary       = ('{0} drafts -> posture-rules-pending/, {1} audit rows -> SI_SchemaCatalog_CL' -f $drafted, $auditRows.Count)
    }
}
