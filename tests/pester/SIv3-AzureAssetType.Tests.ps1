#Requires -Version 5.1
<#
    AssetType MUST BE DERIVED BY THE AZURE BUILDER, NOT MERELY DECLARED -- AND IT IS THE SI ASSET TYPE (#562).

    🔴 HISTORY. 2026-08-30: AssetType was declared "derived" in azure.schema.locked.json and assigned by nothing --
    EMPTY on all 10,122 rows. It was then set to the raw ARM type. 2026-10-10, measured live on the first ring: the
    column mixed the raw ARM type ('microsoft.insights/datacollectionrules', 'microsoft.app/jobs', ...) with the generic
    'AzureResource' -- two vocabularies in one column, and neither the one the CI build uses. #562: ONE normalised SI
    asset type (+ subtype) for every source, from the ONE classification (data-model/classification.locked.json); the
    raw ARM type stays in its own column, ResourceType.

    🔑 SO THIS TEST EXECUTES THE BUILDER rather than asserting its source text: a source-shape assertion cannot tell a
    derivation that runs from one that was deleted.
#>

BeforeAll {
    $script:SIRoot  = (Resolve-Path (Join-Path (Split-Path -Parent (Split-Path -Parent $PSCommandPath)) '..')).Path
    $script:Builder = Join-Path $script:SIRoot 'engine\asset-profiling\shared\Build-AzureProfileRow.ps1'
    $script:Schema  = Join-Path $script:SIRoot 'asset-profiling-schema\azure.schema.locked.json'
    . $script:Builder

    function script:AzRow([string]$Type, [string]$Name = 'res1', [switch]$EgOnly) {
        $meta = @{}
        if ($EgOnly) { $meta['AZ_NodeId'] = 'a1b2c3d4e5f60718293a4b5c6d7e8f90'; $meta['AZ_NodeLabel'] = $Type }
        else {
            $id = '/subscriptions/00000000-0000-0000-0000-000000000001/resourceGroups/rg1/providers/{0}/{1}' -f $Type, $Name
            $meta['AZ_ResourceId'] = $id; $meta['AZ_Type'] = $Type.ToLowerInvariant(); $meta['AZ_Name'] = $Name
        }
        $rec = [pscustomobject]@{ AssetId = $(if ($EgOnly) { $meta['AZ_NodeId'] } else { $meta['AZ_ResourceId'] }); Metadata = $meta; Verdict = $null; TimeGenerated = '2026-10-10T04:00:00Z' }
        Build-SIAzureProfileRow -Record $rec -RunContext ([pscustomobject]@{ RunId = 'r1'; CollectionTime = '2026-10-10T04:00:00Z' })
    }
}

Describe 'Azure profile rows carry the SI asset type and subtype (#562)' {

    It 'the schema declares AssetType and AssetSubtype as derived from the classification' {
        $json = Get-Content -Raw -Encoding UTF8 $script:Schema | ConvertFrom-Json
        foreach ($n in 'AssetType', 'AssetSubtype') {
            $col = @($json.fields | Where-Object { $_.name -eq $n })
            $col.Count | Should -Be 1 -Because $n
            $col[0].source | Should -BeExactly 'derived'
            $col[0].derivation.algorithm | Should -Match 'classification'
        }
    }

    It 'the builder ASSIGNS it from the one classification -- declared-but-never-built is the defect being guarded' {
        $txt = Get-Content -Raw -Encoding UTF8 $script:Builder
        $txt | Should -Match "\`$row\['AssetType'\]\s*="
        $txt | Should -Match 'Get-SIProfileAssetClassification -Item \(ConvertTo-SIAzureClassificationItem'
    }

    It '<t> -> <type> / <sub>, the raw type kept in ResourceType' -ForEach @(
        @{ t = 'microsoft.insights/datacollectionrules'; type = 'Monitoring'; sub = 'Data collection rule' }
        @{ t = 'microsoft.app/jobs'; type = 'Container'; sub = 'Container app job' }
        @{ t = 'microsoft.sql/servers/databases'; type = 'Database'; sub = 'SQL Database' }
        @{ t = 'microsoft.sql/servers'; type = 'Database'; sub = 'SQL logical server' }
        @{ t = 'Microsoft.Storage/storageAccounts'; type = 'Storage'; sub = 'Storage account' }
        @{ t = 'microsoft.keyvault/vaults'; type = 'Key vault'; sub = 'Key vault' }
        @{ t = 'microsoft.compute/virtualmachines'; type = 'Server'; sub = 'Virtual machine' }
        @{ t = 'microsoft.network/publicipaddresses'; type = 'Public IP'; sub = 'Public IP address' }
        @{ t = 'microsoft.managedidentity/userassignedidentities'; type = 'Managed identity'; sub = 'User-assigned identity' }
    ) {
        $row = AzRow $t
        $row.AssetType | Should -Be $type
        $row.AssetSubtype | Should -Be $sub
        $row.ResourceType | Should -Be $t.ToLowerInvariant()
        $row.ServiceType | Should -Be $sub -Because 'ServiceType is the SI subtype now, never the AI guess (Workstation on a data collection rule, found live)'
    }

    It 'an Exposure Graph-only resource (node label) gets the same SI type as its ARM twin' {
        $row = AzRow 'microsoft.web/sites_webapp' -EgOnly
        $row.AssetType | Should -Be 'Web app'
        $row.AssetSubtype | Should -Be 'App Service'
        $row.ResourceType | Should -Be 'microsoft.web/sites_webapp' -Because 'the raw label stays in its own column'
    }

    It 'ServiceType: the AI''s guess is replaced by the SI subtype; a deterministic rule''s ServiceType stands' {
        $id = '/subscriptions/00000000-0000-0000-0000-000000000001/resourceGroups/rg1/providers/microsoft.insights/datacollectionrules/dcr1'
        $mk = { param([string]$status, [string]$svc)
            $rec = [pscustomobject]@{ AssetId = $id; Metadata = @{ AZ_ResourceId = $id; AZ_Type = 'microsoft.insights/datacollectionrules'; AZ_Name = 'dcr1' }
                                      Verdict = [pscustomobject]@{ SI_Tier = 2; SI_ServiceType = $svc; SI_ServiceName = 'dcr1' }; SI_Classify_Status = $status; TimeGenerated = '2026-10-10T04:00:00Z' }
            Build-SIAzureProfileRow -Record $rec -RunContext ([pscustomobject]@{ RunId = 'r1'; CollectionTime = '2026-10-10T04:00:00Z' }) }
        (& $mk 'error' 'Workstation').ServiceType | Should -Be 'Data collection rule' -Because 'the AI error fallback said Workstation'
        (& $mk 'ai' 'Workstation').ServiceType | Should -Be 'Data collection rule'
        (& $mk 'deterministic' 'PayrollTelemetry').ServiceType | Should -Be 'PayrollTelemetry' -Because 'a customer rule''s ServiceType is a decision'
    }
    It 'a type no row names is Other / General -- never the raw ARM type, never blank' {
        $row = AzRow 'microsoft.contoso/widgets'
        $row.AssetType | Should -Be 'Other'
        $row.AssetSubtype | Should -Be 'General'
        $row.ResourceType | Should -Be 'microsoft.contoso/widgets'
    }
}
