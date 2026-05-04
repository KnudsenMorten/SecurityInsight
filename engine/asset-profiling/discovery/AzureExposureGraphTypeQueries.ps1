#Requires -Version 5.1
<#
    Per-resource-type Defender Exposure Graph (EG) hunting queries for the
    AZURE engine.

    Companion to the parallel ARG provider (AZ_* fields).

    Each entry pulls NodeProperties.rawData verbatim for one canonical
    Azure resource type out of the XDR Advanced Hunting ExposureGraphNodes
    table. The orchestrator's Stage Discover/Collect dot-sources this file,
    iterates the 22 entries, and for each entry runs Invoke-SIHuntingQuery
    via the shared HuntingQuery.ps1 helper.

    Schema field naming convention: EG_<ShortType><Property> -- mirrors
    the EG rawData path. Example: EG_KvPublicNetworkAccess maps to
    NodeProperties.rawData.publicNetworkAccess on a Key Vault node.

    Failure modes are non-fatal at the call site -- the helper returns @()
    on Graph error and the engine continues with the ARG provider's data.

    Read-only at collection time per SI v2.2 invariant.
#>

# ---- Module-scope catalog ---------------------------------------------------
# Keyed by canonical EG NodeLabel. Each value is a hashtable:
#   Type     -- canonical NodeLabel (matches NodeLabel column in EG)
#   Hint     -- short label used by Stage Discover for asset type pivot
#   Kql      -- KQL string sent to runHuntingQuery
#   FieldMap -- ordered hashtable mapping
#                 <flat-schema-field-name>  ->  <rawData JSON path>
#               Stage Collect walks each row's NodePropertiesJson,
#               descends rawData by the path, and writes the leaf to the
#               named flat field. Missing paths land as $null.
$script:_AzureEgTypeQueries = @{}

# Universal projection clause -- every per-type query selects the same
# columns so the row-iterator in Stage Collect doesn't need a per-type
# projection switch.
$_egProject = '| project NodeId, NodeLabel, NodeName, Categories, EntityIds, NodePropertiesJson = tostring(NodeProperties)'

# Universal EG envelope fields (already covered by azure.schema.json
# core EG fields like ExposedToInternet / EgTags / EnvironmentName /
# IdentifiedResourceUsers / ExposureSourceCidrs); per-type FieldMaps
# below add ONLY the type-specific rawData paths to avoid double-mapping.

# === microsoft.compute/virtualmachines ======================================
$script:_AzureEgTypeQueries['microsoft.compute/virtualmachines'] = @{
    Type = 'microsoft.compute/virtualmachines'
    Hint = 'virtual-machine'
    Kql  = @"
ExposureGraphNodes
| where NodeLabel == 'microsoft.compute/virtualmachines'
$_egProject
"@
    FieldMap = [ordered]@{
        EG_VmOsPlatform                       = 'osPlatform'
        EG_VmOsName                           = 'osName'
        EG_VmOsVersion                        = 'osVersion'
        EG_VmVmSize                           = 'vmSize'
        EG_VmPowerState                       = 'powerState'
        EG_VmProvisioningState                = 'provisioningState'
        EG_VmJustInTimeAccessEnabled          = 'justInTimeAccess.enabled'
        EG_VmJustInTimeAccessStatus           = 'justInTimeAccess.status'
        EG_VmIsApplicableForMdeThroughDfS     = 'isApplicableForMdeThroughDefenderForServers.value'
        EG_VmIsApplicableForMdeReason         = 'isApplicableForMdeThroughDefenderForServers.reason'
        EG_VmIsUsiServer                      = 'isUsiServer'
        EG_VmHasDefenderForCloudPlan          = 'hasDefenderForCloudPlan'
        EG_VmDefenderForCloudPlanTier         = 'defenderForCloudPlan.tier'
        EG_VmHasMdeOnboarded                  = 'hasMdeOnboarded'
        EG_VmHybridMachineKind                = 'hybridMachineKind'
        EG_VmVulnerableSoftwareCount          = 'vulnerableSoftwareCount'
        EG_VmHighSeverityVulnCount            = 'highSeverityVulnerabilityCount'
        EG_VmCriticalSeverityVulnCount        = 'criticalSeverityVulnerabilityCount'
        EG_VmHandlesSensitiveData             = 'handlesSensitiveData'
    }
}

# === microsoft.network/publicipaddresses ====================================
$script:_AzureEgTypeQueries['microsoft.network/publicipaddresses'] = @{
    Type = 'microsoft.network/publicipaddresses'
    Hint = 'public-ip'
    Kql  = @"
ExposureGraphNodes
| where NodeLabel == 'microsoft.network/publicipaddresses'
$_egProject
"@
    FieldMap = [ordered]@{
        EG_PipIpAddress                       = 'ipAddress'
        EG_PipIpAddressVersion                = 'publicIPAddressVersion'
        EG_PipAllocationMethod                = 'publicIPAllocationMethod'
        EG_PipFqdn                            = 'dnsSettings.fqdn'
        EG_PipReverseFqdn                     = 'dnsSettings.reverseFqdn'
        EG_PipDomainNameLabel                 = 'dnsSettings.domainNameLabel'
        EG_PipSkuName                         = 'sku.name'
        EG_PipSkuTier                         = 'sku.tier'
        EG_PipIdleTimeoutMinutes              = 'idleTimeoutInMinutes'
        EG_PipAttachedResourceId              = 'attachedResourceId'
        EG_PipAttachedResourceType            = 'attachedResourceType'
    }
}

# === microsoft.network/networkinterfaces ====================================
$script:_AzureEgTypeQueries['microsoft.network/networkinterfaces'] = @{
    Type = 'microsoft.network/networkinterfaces'
    Hint = 'network-interface'
    Kql  = @"
ExposureGraphNodes
| where NodeLabel == 'microsoft.network/networkinterfaces'
$_egProject
"@
    FieldMap = [ordered]@{
        EG_NicEnableIpForwarding              = 'enableIPForwarding'
        EG_NicEnableAcceleratedNetworking     = 'enableAcceleratedNetworking'
        EG_NicMacAddress                      = 'macAddress'
        EG_NicPrimaryPrivateIp                = 'ipConfigurations[0].privateIPAddress'
        EG_NicPrimaryPublicIpId               = 'ipConfigurations[0].publicIPAddress.id'
        EG_NicSubnetId                        = 'ipConfigurations[0].subnet.id'
        EG_NicNsgId                           = 'networkSecurityGroup.id'
        EG_NicVirtualMachineId                = 'virtualMachine.id'
        EG_NicProvisioningState               = 'provisioningState'
        EG_NicEffectiveSecurityRulesCount     = 'networkingComponentMetadata.securityRules.count'
    }
}

# === microsoft.compute/virtualmachines/extensions ===========================
$script:_AzureEgTypeQueries['microsoft.compute/virtualmachines/extensions'] = @{
    Type = 'microsoft.compute/virtualmachines/extensions'
    Hint = 'vm-extension'
    Kql  = @"
ExposureGraphNodes
| where NodeLabel == 'microsoft.compute/virtualmachines/extensions'
$_egProject
"@
    FieldMap = [ordered]@{
        EG_ExtPublisher                       = 'publisher'
        EG_ExtType                            = 'type'
        EG_ExtTypeHandlerVersion              = 'typeHandlerVersion'
        EG_ExtAutoUpgradeMinorVersion         = 'autoUpgradeMinorVersion'
        EG_ExtEnableAutomaticUpgrade          = 'enableAutomaticUpgrade'
        EG_ExtProvisioningState               = 'provisioningState'
        EG_ExtParentVmId                      = 'parentVirtualMachineId'
        EG_ExtIsSecurityExtension             = 'isSecurityExtension'
    }
}

# === microsoft.network/virtualnetworks/subnets ==============================
$script:_AzureEgTypeQueries['microsoft.network/virtualnetworks/subnets'] = @{
    Type = 'microsoft.network/virtualnetworks/subnets'
    Hint = 'subnet'
    Kql  = @"
ExposureGraphNodes
| where NodeLabel == 'microsoft.network/virtualnetworks/subnets'
$_egProject
"@
    FieldMap = [ordered]@{
        EG_SubnetAddressPrefix                = 'addressPrefix'
        EG_SubnetAddressPrefixes              = 'addressPrefixes'
        EG_SubnetNsgId                        = 'networkSecurityGroup.id'
        EG_SubnetRouteTableId                 = 'routeTable.id'
        EG_SubnetNatGatewayId                 = 'natGateway.id'
        EG_SubnetServiceEndpointsCount        = 'serviceEndpoints.count'
        EG_SubnetPrivateEndpointsCount        = 'privateEndpoints.count'
        EG_SubnetPrivateEndpointNetworkPolicies   = 'privateEndpointNetworkPolicies'
        EG_SubnetPrivateLinkServiceNetworkPolicies = 'privateLinkServiceNetworkPolicies'
        EG_SubnetParentVNetId                 = 'parentVirtualNetworkId'
    }
}

# === microsoft.operationalinsights/workspaces ===============================
$script:_AzureEgTypeQueries['microsoft.operationalinsights/workspaces'] = @{
    Type = 'microsoft.operationalinsights/workspaces'
    Hint = 'log-analytics-workspace'
    Kql  = @"
ExposureGraphNodes
| where NodeLabel == 'microsoft.operationalinsights/workspaces'
$_egProject
"@
    FieldMap = [ordered]@{
        EG_LawSkuName                         = 'sku.name'
        EG_LawRetentionInDays                 = 'retentionInDays'
        EG_LawPublicNetworkAccessForIngestion = 'publicNetworkAccessForIngestion'
        EG_LawPublicNetworkAccessForQuery     = 'publicNetworkAccessForQuery'
        EG_LawCustomerId                      = 'customerId'
        EG_LawWorkspaceCapping                = 'workspaceCapping.dailyQuotaGb'
        EG_LawDisableLocalAuth                = 'features.disableLocalAuth'
        EG_LawEnableLogAccessUsingOnlyResourcePermissions = 'features.enableLogAccessUsingOnlyResourcePermissions'
    }
}

# === microsoft.network/virtualnetworks ======================================
$script:_AzureEgTypeQueries['microsoft.network/virtualnetworks'] = @{
    Type = 'microsoft.network/virtualnetworks'
    Hint = 'virtual-network'
    Kql  = @"
ExposureGraphNodes
| where NodeLabel == 'microsoft.network/virtualnetworks'
$_egProject
"@
    FieldMap = [ordered]@{
        EG_VnetAddressSpaces                  = 'addressSpace.addressPrefixes'
        EG_VnetSubnetCount                    = 'subnets.count'
        EG_VnetEnableDdosProtection           = 'enableDdosProtection'
        EG_VnetDdosProtectionPlanId           = 'ddosProtectionPlan.id'
        EG_VnetEnableVmProtection             = 'enableVmProtection'
        EG_VnetPeeringCount                   = 'virtualNetworkPeerings.count'
        EG_VnetDnsServers                     = 'dhcpOptions.dnsServers'
    }
}

# === microsoft.sql/servers/databases ========================================
$script:_AzureEgTypeQueries['microsoft.sql/servers/databases'] = @{
    Type = 'microsoft.sql/servers/databases'
    Hint = 'sql-database'
    Kql  = @"
ExposureGraphNodes
| where NodeLabel == 'microsoft.sql/servers/databases'
$_egProject
"@
    FieldMap = [ordered]@{
        EG_SqlDbStatus                        = 'status'
        EG_SqlDbZoneRedundant                 = 'zoneRedundant'
        EG_SqlDbReadScale                     = 'readScale'
        EG_SqlDbCurrentSkuName                = 'currentSku.name'
        EG_SqlDbCurrentSkuTier                = 'currentSku.tier'
        EG_SqlDbMaxSizeBytes                  = 'maxSizeBytes'
        EG_SqlDbCollation                     = 'collation'
        EG_SqlDbCatalogCollation              = 'catalogCollation'
        EG_SqlDbTransparentDataEncryption     = 'transparentDataEncryption.state'
        EG_SqlDbParentServerId                = 'parentServerId'
        EG_SqlDbHandlesSensitiveData          = 'handlesSensitiveData'
        EG_SqlDbDataClassificationLabels      = 'dataSensitivity.classificationLabels'
    }
}

# === microsoft.keyvault/vaults ==============================================
$script:_AzureEgTypeQueries['microsoft.keyvault/vaults'] = @{
    Type = 'microsoft.keyvault/vaults'
    Hint = 'key-vault'
    Kql  = @"
ExposureGraphNodes
| where NodeLabel == 'microsoft.keyvault/vaults'
$_egProject
"@
    FieldMap = [ordered]@{
        EG_KvSkuName                          = 'sku.name'
        EG_KvSkuFamily                        = 'sku.family'
        EG_KvPublicNetworkAccess              = 'publicNetworkAccess'
        EG_KvEnableRbacAuthorization          = 'enableRbacAuthorization'
        EG_KvEnableSoftDelete                 = 'enableSoftDelete'
        EG_KvSoftDeleteRetentionInDays        = 'softDeleteRetentionInDays'
        EG_KvEnablePurgeProtection            = 'enablePurgeProtection'
        EG_KvEnabledForDeployment             = 'enabledForDeployment'
        EG_KvEnabledForTemplateDeployment     = 'enabledForTemplateDeployment'
        EG_KvEnabledForDiskEncryption         = 'enabledForDiskEncryption'
        EG_KvNetworkAclDefaultAction          = 'networkAcls.defaultAction'
        EG_KvNetworkAclBypass                 = 'networkAcls.bypass'
        EG_KvAccessPoliciesCount              = 'accessPolicies.count'
        EG_KvSecretCount                      = 'secretCount'
        EG_KvKeyCount                         = 'keyCount'
        EG_KvCertificateCount                 = 'certificateCount'
    }
}

# === microsoft.logic/workflows ==============================================
$script:_AzureEgTypeQueries['microsoft.logic/workflows'] = @{
    Type = 'microsoft.logic/workflows'
    Hint = 'logic-app'
    Kql  = @"
ExposureGraphNodes
| where NodeLabel == 'microsoft.logic/workflows'
$_egProject
"@
    FieldMap = [ordered]@{
        EG_LogicAppState                      = 'state'
        EG_LogicAppAccessEndpoint             = 'accessEndpoint'
        EG_LogicAppTriggerType                = 'triggers[0].type'
        EG_LogicAppTriggerKind                = 'triggers[0].kind'
        EG_LogicAppHttpTriggerExposed         = 'hasExposedHttpTrigger'
        EG_LogicAppIntegrationAccountId       = 'integrationAccount.id'
        EG_LogicAppEndpointsConfigPublic      = 'endpointsConfiguration.workflow.outgoingIpAddresses.count'
        EG_LogicAppAccessControlAction        = 'accessControl.triggers.allowedCallerIpAddresses.action'
    }
}

# === microsoft.network/networksecuritygroups ================================
$script:_AzureEgTypeQueries['microsoft.network/networksecuritygroups'] = @{
    Type = 'microsoft.network/networksecuritygroups'
    Hint = 'network-security-group'
    Kql  = @"
ExposureGraphNodes
| where NodeLabel == 'microsoft.network/networksecuritygroups'
$_egProject
"@
    FieldMap = [ordered]@{
        EG_NsgSecurityRulesCount              = 'securityRules.count'
        EG_NsgDefaultSecurityRulesCount       = 'defaultSecurityRules.count'
        EG_NsgInboundAnyToAnyAllowCount       = 'inboundAnyToAnyAllowRulesCount'
        EG_NsgInboundInternetAllowCount       = 'inboundInternetAllowRulesCount'
        EG_NsgInboundSshOpenToInternet        = 'hasInboundSshOpenToInternet'
        EG_NsgInboundRdpOpenToInternet        = 'hasInboundRdpOpenToInternet'
        EG_NsgAttachedSubnetCount             = 'subnets.count'
        EG_NsgAttachedNicCount                = 'networkInterfaces.count'
    }
}

# === microsoft.cognitiveservices/accounts/deployments =======================
$script:_AzureEgTypeQueries['microsoft.cognitiveservices/accounts/deployments'] = @{
    Type = 'microsoft.cognitiveservices/accounts/deployments'
    Hint = 'cognitive-deployment'
    Kql  = @"
ExposureGraphNodes
| where NodeLabel == 'microsoft.cognitiveservices/accounts/deployments'
$_egProject
"@
    FieldMap = [ordered]@{
        EG_CogDepModelName                    = 'model.name'
        EG_CogDepModelVersion                 = 'model.version'
        EG_CogDepModelFormat                  = 'model.format'
        EG_CogDepProvisioningState            = 'provisioningState'
        EG_CogDepRaiPolicyName                = 'raiPolicyName'
        EG_CogDepCapacity                     = 'sku.capacity'
        EG_CogDepSkuName                      = 'sku.name'
        EG_CogDepParentAccountId              = 'parentAccountId'
        EG_CogDepVersionUpgradeOption         = 'versionUpgradeOption'
    }
}

# === microsoft.storage/storageaccounts ======================================
$script:_AzureEgTypeQueries['microsoft.storage/storageaccounts'] = @{
    Type = 'microsoft.storage/storageaccounts'
    Hint = 'storage-account'
    Kql  = @"
ExposureGraphNodes
| where NodeLabel == 'microsoft.storage/storageaccounts'
$_egProject
"@
    FieldMap = [ordered]@{
        EG_StSkuName                          = 'sku.name'
        EG_StSkuTier                          = 'sku.tier'
        EG_StKind                             = 'kind'
        EG_StAccessTier                       = 'accessTier'
        EG_StPublicNetworkAccess              = 'publicNetworkAccess'
        EG_StAllowBlobPublicAccess            = 'allowBlobPublicAccess'
        EG_StAllowSharedKeyAccess             = 'allowSharedKeyAccess'
        EG_StSupportsHttpsTrafficOnly         = 'supportsHttpsTrafficOnly'
        EG_StMinimumTlsVersion                = 'minimumTlsVersion'
        EG_StAllowCrossTenantReplication      = 'allowCrossTenantReplication'
        EG_StIsHnsEnabled                     = 'isHnsEnabled'
        EG_StIsSftpEnabled                    = 'isSftpEnabled'
        EG_StIsLocalUserEnabled               = 'isLocalUserEnabled'
        EG_StNetworkAclDefaultAction          = 'networkAcls.defaultAction'
        EG_StNetworkAclBypass                 = 'networkAcls.bypass'
        EG_StBlobAnonymousContainerCount      = 'blobAnonymousContainerCount'
        EG_StKeySource                        = 'encryption.keySource'
        EG_StRequireInfrastructureEncryption  = 'encryption.requireInfrastructureEncryption'
        EG_StHandlesSensitiveData             = 'handlesSensitiveData'
        EG_StDataClassificationLabels         = 'dataSensitivity.classificationLabels'
    }
}

# === microsoft.web/serverfarms ==============================================
$script:_AzureEgTypeQueries['microsoft.web/serverfarms'] = @{
    Type = 'microsoft.web/serverfarms'
    Hint = 'app-service-plan'
    Kql  = @"
ExposureGraphNodes
| where NodeLabel == 'microsoft.web/serverfarms'
$_egProject
"@
    FieldMap = [ordered]@{
        EG_PlanSkuName                        = 'sku.name'
        EG_PlanSkuTier                        = 'sku.tier'
        EG_PlanSkuSize                        = 'sku.size'
        EG_PlanWorkerCount                    = 'numberOfWorkers'
        EG_PlanKind                           = 'kind'
        EG_PlanReserved                       = 'reserved'
        EG_PlanIsXenon                        = 'isXenon'
        EG_PlanZoneRedundant                  = 'zoneRedundant'
        EG_PlanHostedSiteCount                = 'numberOfSites'
    }
}

# === microsoft.cognitiveservices/accounts (kind == 'OpenAI') ================
$script:_AzureEgTypeQueries['microsoft.cognitiveservices/accounts_openai'] = @{
    Type = 'microsoft.cognitiveservices/accounts'
    Hint = 'azure-openai'
    Kql  = @"
ExposureGraphNodes
| where NodeLabel == 'microsoft.cognitiveservices/accounts'
| where tostring(parse_json(tostring(NodeProperties)).rawData.kind) =~ 'OpenAI'
   or  tostring(parse_json(tostring(NodeProperties)).rawData.resourceTypeIsAzureOpenAI) =~ 'true'
$_egProject
"@
    FieldMap = [ordered]@{
        EG_AoaiKind                           = 'kind'
        EG_AoaiSkuName                        = 'sku.name'
        EG_AoaiCustomSubDomainName            = 'customSubDomainName'
        EG_AoaiPublicNetworkAccess            = 'publicNetworkAccess'
        EG_AoaiDisableLocalAuth               = 'disableLocalAuth'
        EG_AoaiNetworkAclDefaultAction        = 'networkAcls.defaultAction'
        EG_AoaiNetworkAclBypass               = 'networkAcls.bypass'
        EG_AoaiAiServiceType                  = 'azureAiServicesResourceType.aiServiceType'
        EG_AoaiResourceTypeIsAzureOpenAI      = 'resourceTypeIsAzureOpenAI'
        EG_AoaiDeploymentCount                = 'deployments.count'
        EG_AoaiHandlesSensitiveData           = 'handlesSensitiveData'
        EG_AoaiAllowedFqdnList                = 'allowedFqdnList'
    }
}

# === microsoft.sql/firewallrules ============================================
$script:_AzureEgTypeQueries['microsoft.sql/firewallrules'] = @{
    Type = 'microsoft.sql/firewallrules'
    Hint = 'sql-firewall-rule'
    Kql  = @"
ExposureGraphNodes
| where NodeLabel == 'microsoft.sql/firewallrules'
$_egProject
"@
    FieldMap = [ordered]@{
        EG_SqlFwStartIpAddress                = 'startIpAddress'
        EG_SqlFwEndIpAddress                  = 'endIpAddress'
        EG_SqlFwIsAllowAllAzureServices       = 'isAllowAllAzureServices'
        EG_SqlFwIsOpenToInternet              = 'isOpenToInternet'
        EG_SqlFwParentServerId                = 'parentServerId'
        EG_SqlFwRuleScope                     = 'ruleScope'
    }
}

# === microsoft.web/sites (kind contains 'functionapp') ======================
$script:_AzureEgTypeQueries['microsoft.web/sites_azurefunction'] = @{
    Type = 'microsoft.web/sites'
    Hint = 'function-app'
    Kql  = @"
ExposureGraphNodes
| where NodeLabel == 'microsoft.web/sites'
| where tostring(parse_json(tostring(NodeProperties)).rawData.kind) contains 'functionapp'
$_egProject
"@
    FieldMap = [ordered]@{
        EG_FuncKind                           = 'kind'
        EG_FuncState                          = 'state'
        EG_FuncEnabled                        = 'enabled'
        EG_FuncRuntimeStack                   = 'azureComputeServerlessMetadata.runtimeStack'
        EG_FuncPublishModel                   = 'azureComputeServerlessMetadata.publishModel'
        EG_FuncDomain                         = 'azureComputeServerlessMetadata.domain'
        EG_FuncCustomDomains                  = 'azureComputeServerlessMetadata.customDomains'
        EG_FuncIdentityProvider               = 'azureComputeServerlessMetadata.identityProvider'
        EG_FuncElasticScaleEnabled            = 'azureComputeServerlessMetadata.elasticScaleEnabled'
        EG_FuncHttpsOnly                      = 'httpsOnly'
        EG_FuncMinTlsVersion                  = 'siteConfig.minTlsVersion'
        EG_FuncFtpsState                      = 'siteConfig.ftpsState'
        EG_FuncClientAffinityEnabled          = 'clientAffinityEnabled'
        EG_FuncPublicNetworkAccess            = 'publicNetworkAccess'
        EG_FuncAuthEnabled                    = 'authSettings.enabled'
        EG_FuncAllowsPublicAccess             = 'allowsPublicAccess'
        EG_FuncAppServicePlanId               = 'azureComputeServerlessMetadata.appServicePlan'
    }
}

# === microsoft.sql/servers ==================================================
$script:_AzureEgTypeQueries['microsoft.sql/servers'] = @{
    Type = 'microsoft.sql/servers'
    Hint = 'sql-server'
    Kql  = @"
ExposureGraphNodes
| where NodeLabel == 'microsoft.sql/servers'
$_egProject
"@
    FieldMap = [ordered]@{
        EG_SqlSrvVersion                      = 'version'
        EG_SqlSrvAdministratorLogin           = 'administratorLogin'
        EG_SqlSrvAdministratorType            = 'administrators.administratorType'
        EG_SqlSrvAzureADOnlyAuthentication    = 'administrators.azureADOnlyAuthentication'
        EG_SqlSrvPublicNetworkAccess          = 'publicNetworkAccess'
        EG_SqlSrvMinimalTlsVersion            = 'minimalTlsVersion'
        EG_SqlSrvRestrictOutboundNetworkAccess = 'restrictOutboundNetworkAccess'
        EG_SqlSrvFullyQualifiedDomainName     = 'fullyQualifiedDomainName'
        EG_SqlSrvFirewallRuleCount            = 'firewallRules.count'
        EG_SqlSrvHasOpenToInternetFirewallRule = 'hasOpenToInternetFirewallRule'
        EG_SqlSrvDatabaseCount                = 'databases.count'
    }
}

# === microsoft.web/sites (kind == 'app') ====================================
$script:_AzureEgTypeQueries['microsoft.web/sites_webapp'] = @{
    Type = 'microsoft.web/sites'
    Hint = 'web-app'
    Kql  = @"
ExposureGraphNodes
| where NodeLabel == 'microsoft.web/sites'
| where tostring(parse_json(tostring(NodeProperties)).rawData.kind) =~ 'app'
   or  tostring(parse_json(tostring(NodeProperties)).rawData.kind) =~ 'app,linux'
$_egProject
"@
    FieldMap = [ordered]@{
        EG_WebKind                            = 'kind'
        EG_WebState                           = 'state'
        EG_WebEnabled                         = 'enabled'
        EG_WebDomain                          = 'azureComputeServerlessMetadata.domain'
        EG_WebCustomDomains                   = 'azureComputeServerlessMetadata.customDomains'
        EG_WebIdentityProvider                = 'azureComputeServerlessMetadata.identityProvider'
        EG_WebRuntimeStack                    = 'azureComputeServerlessMetadata.runtimeStack'
        EG_WebPublishModel                    = 'azureComputeServerlessMetadata.publishModel'
        EG_WebHttpsOnly                       = 'httpsOnly'
        EG_WebMinTlsVersion                   = 'siteConfig.minTlsVersion'
        EG_WebFtpsState                       = 'siteConfig.ftpsState'
        EG_WebClientCertEnabled               = 'clientCertEnabled'
        EG_WebClientCertMode                  = 'clientCertMode'
        EG_WebPublicNetworkAccess             = 'publicNetworkAccess'
        EG_WebAuthEnabled                     = 'authSettings.enabled'
        EG_WebAllowsPublicAccess              = 'allowsPublicAccess'
        EG_WebAppServicePlanId                = 'azureComputeServerlessMetadata.appServicePlan'
    }
}

# === microsoft.cognitiveservices/accounts (general -- non-OpenAI) ===========
$script:_AzureEgTypeQueries['microsoft.cognitiveservices/accounts'] = @{
    Type = 'microsoft.cognitiveservices/accounts'
    Hint = 'cognitive-services'
    Kql  = @"
ExposureGraphNodes
| where NodeLabel == 'microsoft.cognitiveservices/accounts'
| where tostring(parse_json(tostring(NodeProperties)).rawData.kind) !~ 'OpenAI'
   and (isempty(tostring(parse_json(tostring(NodeProperties)).rawData.resourceTypeIsAzureOpenAI))
        or tostring(parse_json(tostring(NodeProperties)).rawData.resourceTypeIsAzureOpenAI) !~ 'true')
$_egProject
"@
    FieldMap = [ordered]@{
        EG_CogKind                            = 'kind'
        EG_CogSkuName                         = 'sku.name'
        EG_CogCustomSubDomainName             = 'customSubDomainName'
        EG_CogPublicNetworkAccess             = 'publicNetworkAccess'
        EG_CogDisableLocalAuth                = 'disableLocalAuth'
        EG_CogNetworkAclDefaultAction         = 'networkAcls.defaultAction'
        EG_CogNetworkAclBypass                = 'networkAcls.bypass'
        EG_CogAiServiceType                   = 'azureAiServicesResourceType.aiServiceType'
        EG_CogResourceTypeIsAzureAiServices   = 'resourceTypeIsAzureAiServices'
        EG_CogAllowedFqdnList                 = 'allowedFqdnList'
        EG_CogHandlesSensitiveData            = 'handlesSensitiveData'
    }
}

# === microsoft.containerregistry/registries =================================
$script:_AzureEgTypeQueries['microsoft.containerregistry/registries'] = @{
    Type = 'microsoft.containerregistry/registries'
    Hint = 'container-registry'
    Kql  = @"
ExposureGraphNodes
| where NodeLabel == 'microsoft.containerregistry/registries'
$_egProject
"@
    FieldMap = [ordered]@{
        EG_AcrSkuName                         = 'sku.name'
        EG_AcrSkuTier                         = 'sku.tier'
        EG_AcrAdminUserEnabled                = 'adminUserEnabled'
        EG_AcrAnonymousPullEnabled            = 'anonymousPullEnabled'
        EG_AcrPublicNetworkAccess             = 'publicNetworkAccess'
        EG_AcrNetworkRuleBypassOptions        = 'networkRuleBypassOptions'
        EG_AcrNetworkRuleSetDefaultAction     = 'networkRuleSet.defaultAction'
        EG_AcrZoneRedundancy                  = 'zoneRedundancy'
        EG_AcrDataEndpointEnabled             = 'dataEndpointEnabled'
        EG_AcrLoginServer                     = 'loginServer'
        EG_AcrPolicyExportPolicyStatus        = 'policies.exportPolicy.status'
        EG_AcrPolicyTrustPolicyStatus         = 'policies.trustPolicy.status'
        EG_AcrPolicyQuarantinePolicyStatus    = 'policies.quarantinePolicy.status'
        EG_AcrPolicyRetentionPolicyStatus     = 'policies.retentionPolicy.status'
        EG_AcrEncryptionStatus                = 'encryption.status'
        EG_AcrRepositoryCount                 = 'repositoryCount'
    }
}

# === microsoft.network/applicationgateways ==================================
$script:_AzureEgTypeQueries['microsoft.network/applicationgateways'] = @{
    Type = 'microsoft.network/applicationgateways'
    Hint = 'application-gateway'
    Kql  = @"
ExposureGraphNodes
| where NodeLabel == 'microsoft.network/applicationgateways'
$_egProject
"@
    FieldMap = [ordered]@{
        EG_AgwSkuName                         = 'sku.name'
        EG_AgwSkuTier                         = 'sku.tier'
        EG_AgwOperationalState                = 'operationalState'
        EG_AgwEnableHttp2                     = 'enableHttp2'
        EG_AgwEnableFips                      = 'enableFips'
        EG_AgwWafEnabled                      = 'webApplicationFirewallConfiguration.enabled'
        EG_AgwWafFirewallMode                 = 'webApplicationFirewallConfiguration.firewallMode'
        EG_AgwWafRuleSetType                  = 'webApplicationFirewallConfiguration.ruleSetType'
        EG_AgwWafRuleSetVersion               = 'webApplicationFirewallConfiguration.ruleSetVersion'
        EG_AgwFirewallPolicyId                = 'firewallPolicy.id'
        EG_AgwSslPolicyName                   = 'sslPolicy.policyName'
        EG_AgwSslPolicyMinProtocolVersion     = 'sslPolicy.minProtocolVersion'
        EG_AgwForceFirewallPolicyAssociation  = 'forceFirewallPolicyAssociation'
        EG_AgwListenerCount                   = 'httpListeners.count'
        EG_AgwBackendAddressPoolCount         = 'backendAddressPools.count'
        EG_AgwHasPublicFrontendIp             = 'hasPublicFrontendIp'
    }
}

# ---- Public functions -------------------------------------------------------

function Get-SIAzureEgTypeCatalog {
    <#
        Returns the full catalog (read-only view). Useful for Stage Discover
        to enumerate types + FieldMaps without touching $script: scope.
    #>
    [CmdletBinding()]
    param()
    return $script:_AzureEgTypeQueries
}

function Get-SIAzureEgFieldMapForType {
    <#
        Returns the FieldMap (ordered hashtable: schemaField -> rawData path)
        for a single canonical resource type, or $null if unknown.

        Lookup uses the catalog key. For the 3 cognitiveservices variants /
        2 web/sites variants the keys are 'microsoft.cognitiveservices/accounts',
        'microsoft.cognitiveservices/accounts_openai',
        'microsoft.web/sites_webapp', 'microsoft.web/sites_azurefunction'.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$ResourceType)

    if ($script:_AzureEgTypeQueries.ContainsKey($ResourceType)) {
        return $script:_AzureEgTypeQueries[$ResourceType].FieldMap
    }
    return $null
}

function Invoke-SIAzureEgQueryByType {
    <#
        Runs the per-type EG hunting query and returns the raw rows
        (as an array of PSCustomObjects).

        Each row carries: NodeId, NodeLabel, NodeName, Categories,
        EntityIds, NodePropertiesJson. Stage Collect parses
        NodePropertiesJson, looks up rawData paths via FieldMap, and writes
        flat fields onto the asset row.

        Returns @() on Graph failure -- engine continues with the ARG
        provider's data (read-only invariant; no retries on collection).
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$ResourceType)

    if (-not $script:_AzureEgTypeQueries.ContainsKey($ResourceType)) {
        Write-Warning ("Invoke-SIAzureEgQueryByType: unknown resource type '{0}'" -f $ResourceType)
        return @()
    }

    $entry = $script:_AzureEgTypeQueries[$ResourceType]

    # Dot-source the shared submitter relative to this file's parent
    # (../engine/shared/). Stage Collect already loads it once per
    # run; loading again is idempotent.
    $sharedPath = Join-Path (Split-Path -Parent $PSScriptRoot) 'asset-profiling\shared\HuntingQuery.ps1'
    if (-not (Test-Path $sharedPath)) {
        Write-Warning ("Invoke-SIAzureEgQueryByType: shared submitter not found at {0}" -f $sharedPath)
        return @()
    }
    . $sharedPath

    return Invoke-SIHuntingQuery -Query $entry.Kql -QueryEngine DefenderGraph
}
