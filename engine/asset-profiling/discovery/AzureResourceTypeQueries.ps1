#Requires -Version 5.1
<#
    AzureResourceTypeQueries.ps1
    ----------------------------
    Per-type Azure Resource Graph (ARG) discovery queries for the AZURE engine.

    The default discovery (Get-DiscoveryFromAzureResources.ps1) pulls the FULL
    inventory and projects properties verbatim as a JSON blob -- Stage Collect
    then asks the per-type-profile cache which fields matter. That works, but
    leaves security-critical fields buried inside the JSON until the profile
    cache catches up.

    This file is the FAST PATH: for the ~23 resource types that account for
    >90% of customer security blast radius, we ship hand-curated KQL queries
    that pre-project every security-relevant property as a flat ARG column,
    and a FieldMap that tells the discovery loop which projected column maps
    to which AZ_<Field> emit-key.

    Two public functions:

      Invoke-SIAzureSecurityQuery -ResourceType <type> -SubscriptionIds <sub[]>
        Looks up the entry, runs the KQL with paging, returns raw rows.

      Get-SIAzureSecurityFieldsForType -ResourceType <type>
        Returns the FieldMap so the caller can iterate + emit AZ_<Field> keys.

    Field-map convention:
        Key   = emit key the discovery row will use     (e.g. AZ_PublicNetworkAccess)
        Value = ARG-projected column name in the row    (e.g. publicNetworkAccess)

    The matching schema entry in azure.schema.json drops the AZ_ prefix --
    the LA column is PublicNetworkAccess, not AZ_PublicNetworkAccess.
#>

# -----------------------------------------------------------------------------
# Lookup table -- module-scope so multiple callers in one session share it.
# Keys are lowercase canonical ARM type names. cognitiveservices/accounts has
# THREE entries (general / openai / project) keyed by suffix because the KQL
# filter and field set differ per kind.
# -----------------------------------------------------------------------------
$script:_AzureResourceTypeQueries = @{}

# -----------------------------------------------------------------------------
# 1) microsoft.compute/virtualmachines
# -----------------------------------------------------------------------------
$script:_AzureResourceTypeQueries['microsoft.compute/virtualmachines'] = @{
    Type    = 'microsoft.compute/virtualmachines'
    Hint    = 'virtual-machine'
    FieldMap = @{
        'AZ_VmSize'                          = 'vmSize'
        'AZ_OsType'                          = 'osType'
        'AZ_OsPublisher'                     = 'osPublisher'
        'AZ_OsOffer'                         = 'osOffer'
        'AZ_OsSku'                           = 'osSku'
        'AZ_LicenseType'                     = 'licenseType'
        'AZ_VmId'                            = 'vmId'
        'AZ_AvailabilityZone'                = 'availabilityZone'
        'AZ_BootDiagnosticsEnabled'          = 'bootDiagnosticsEnabled'
        'AZ_OsDiskEncryptionAtHost'          = 'encryptionAtHost'
        'AZ_OsDiskEncryptionType'            = 'osDiskEncryptionType'
        'AZ_OsDiskEncryptionDiskSetId'       = 'osDiskEncryptionDiskSetId'
        'AZ_SecurityType'                    = 'securityType'
        'AZ_SecureBootEnabled'               = 'secureBootEnabled'
        'AZ_VTpmEnabled'                     = 'vTpmEnabled'
        'AZ_HibernationEnabled'              = 'hibernationEnabled'
        'AZ_GuestAttestationExtensionPresent'= 'guestAttestationExtensionPresent'
        'AZ_NetworkInterfaceCount'           = 'networkInterfaceCount'
        'AZ_DataDiskCount'                   = 'dataDiskCount'
        'AZ_AdminUsername'                   = 'adminUsername'
        'AZ_AllowExtensionOperations'        = 'allowExtensionOperations'
        'AZ_AssignedHostId'                  = 'assignedHostId'
        'AZ_PriorityType'                    = 'priorityType'
        'AZ_EvictionPolicy'                  = 'evictionPolicy'
        'AZ_PowerState'                      = 'powerState'
        'AZ_ProvisioningState'               = 'provisioningState'
        'AZ_TimeCreated'                     = 'timeCreated'
        'AZ_ProximityPlacementGroupId'       = 'proximityPlacementGroupId'
        'AZ_AvailabilitySetId'               = 'availabilitySetId'
        'AZ_VirtualMachineScaleSetId'        = 'virtualMachineScaleSetId'
        'AZ_HostGroupId'                     = 'hostGroupId'
        'AZ_PatchModeWindows'                = 'patchModeWindows'
        'AZ_PatchModeLinux'                  = 'patchModeLinux'
        'AZ_AutomaticByPlatformBypass'       = 'automaticByPlatformBypass'
        'AZ_AssessmentMode'                  = 'assessmentMode'
        'AZ_HotpatchingEnabled'              = 'hotpatchingEnabled'
        'AZ_EnableAutomaticUpdates'          = 'enableAutomaticUpdates'
        'AZ_DisablePasswordAuthentication'   = 'disablePasswordAuthentication'
    }
    Kql = @"
resources
| where type =~ 'microsoft.compute/virtualmachines'
| extend props = properties
| project id, name, type, location, subscriptionId, resourceGroup, tags, identity,
    vmSize                              = tostring(props.hardwareProfile.vmSize),
    osType                              = tostring(props.storageProfile.osDisk.osType),
    osPublisher                         = tostring(props.storageProfile.imageReference.publisher),
    osOffer                             = tostring(props.storageProfile.imageReference.offer),
    osSku                               = tostring(props.storageProfile.imageReference.sku),
    licenseType                         = tostring(props.licenseType),
    vmId                                = tostring(props.vmId),
    availabilityZone                    = tostring(zones),
    bootDiagnosticsEnabled              = tobool(props.diagnosticsProfile.bootDiagnostics.enabled),
    encryptionAtHost                    = tobool(props.securityProfile.encryptionAtHost),
    osDiskEncryptionType                = tostring(props.storageProfile.osDisk.managedDisk.securityProfile.securityEncryptionType),
    osDiskEncryptionDiskSetId           = tostring(props.storageProfile.osDisk.managedDisk.diskEncryptionSet.id),
    securityType                        = tostring(props.securityProfile.securityType),
    secureBootEnabled                   = tobool(props.securityProfile.uefiSettings.secureBootEnabled),
    vTpmEnabled                         = tobool(props.securityProfile.uefiSettings.vTpmEnabled),
    hibernationEnabled                  = tobool(props.additionalCapabilities.hibernationEnabled),
    guestAttestationExtensionPresent    = isnotnull(props.securityProfile.uefiSettings),
    networkInterfaceCount               = array_length(props.networkProfile.networkInterfaces),
    dataDiskCount                       = array_length(props.storageProfile.dataDisks),
    adminUsername                       = tostring(props.osProfile.adminUsername),
    allowExtensionOperations            = tobool(props.osProfile.allowExtensionOperations),
    assignedHostId                      = tostring(props.host.id),
    priorityType                        = tostring(props.priority),
    evictionPolicy                      = tostring(props.evictionPolicy),
    powerState                          = tostring(props.extended.instanceView.powerState.code),
    provisioningState                   = tostring(props.provisioningState),
    timeCreated                         = tostring(props.timeCreated),
    proximityPlacementGroupId           = tostring(props.proximityPlacementGroup.id),
    availabilitySetId                   = tostring(props.availabilitySet.id),
    virtualMachineScaleSetId            = tostring(props.virtualMachineScaleSet.id),
    hostGroupId                         = tostring(props.hostGroup.id),
    patchModeWindows                    = tostring(props.osProfile.windowsConfiguration.patchSettings.patchMode),
    patchModeLinux                      = tostring(props.osProfile.linuxConfiguration.patchSettings.patchMode),
    automaticByPlatformBypass           = tostring(props.osProfile.windowsConfiguration.patchSettings.automaticByPlatformSettings.bypassPlatformSafetyChecksOnUserSchedule),
    assessmentMode                      = tostring(coalesce(props.osProfile.windowsConfiguration.patchSettings.assessmentMode, props.osProfile.linuxConfiguration.patchSettings.assessmentMode)),
    hotpatchingEnabled                  = tobool(props.osProfile.windowsConfiguration.patchSettings.enableHotpatching),
    enableAutomaticUpdates              = tobool(props.osProfile.windowsConfiguration.enableAutomaticUpdates),
    disablePasswordAuthentication       = tobool(props.osProfile.linuxConfiguration.disablePasswordAuthentication)
"@
}

# -----------------------------------------------------------------------------
# 2) microsoft.network/publicipaddresses
# -----------------------------------------------------------------------------
$script:_AzureResourceTypeQueries['microsoft.network/publicipaddresses'] = @{
    Type    = 'microsoft.network/publicipaddresses'
    Hint    = 'public-ip'
    FieldMap = @{
        'AZ_PipAddress'                = 'ipAddress'
        'AZ_PipAddressVersion'         = 'publicIPAddressVersion'
        'AZ_PipAllocationMethod'       = 'publicIPAllocationMethod'
        'AZ_PipDdosProtectionMode'     = 'ddosProtectionMode'
        'AZ_PipDdosPlanId'             = 'ddosPlanId'
        'AZ_PipIdleTimeoutMinutes'     = 'idleTimeoutInMinutes'
        'AZ_PipFqdn'                   = 'fqdn'
        'AZ_PipReverseFqdn'            = 'reverseFqdn'
        'AZ_PipDomainNameLabel'        = 'domainNameLabel'
        'AZ_PipAttachedResourceId'     = 'ipConfigurationId'
        'AZ_PipNatGatewayId'           = 'natGatewayId'
        'AZ_PipPublicIPPrefixId'       = 'publicIPPrefixId'
        'AZ_PipSkuName'                = 'skuName'
        'AZ_PipSkuTier'                = 'skuTier'
        'AZ_PipZones'                  = 'zones'
        'AZ_PipMigrationPhase'         = 'migrationPhase'
        'AZ_PipServicePublicIPAddress' = 'servicePublicIPAddress'
        'AZ_PipDeleteOption'           = 'deleteOption'
    }
    Kql = @"
resources
| where type =~ 'microsoft.network/publicipaddresses'
| extend props = properties
| project id, name, type, location, subscriptionId, resourceGroup, tags, sku,
    ipAddress                = tostring(props.ipAddress),
    publicIPAddressVersion   = tostring(props.publicIPAddressVersion),
    publicIPAllocationMethod = tostring(props.publicIPAllocationMethod),
    ddosProtectionMode       = tostring(props.ddosSettings.protectionMode),
    ddosPlanId               = tostring(props.ddosSettings.ddosProtectionPlan.id),
    idleTimeoutInMinutes     = toint(props.idleTimeoutInMinutes),
    fqdn                     = tostring(props.dnsSettings.fqdn),
    reverseFqdn              = tostring(props.dnsSettings.reverseFqdn),
    domainNameLabel          = tostring(props.dnsSettings.domainNameLabel),
    ipConfigurationId        = tostring(props.ipConfiguration.id),
    natGatewayId             = tostring(props.natGateway.id),
    publicIPPrefixId         = tostring(props.publicIPPrefix.id),
    skuName                  = tostring(sku.name),
    skuTier                  = tostring(sku.tier),
    zones                    = tostring(zones),
    migrationPhase           = tostring(props.migrationPhase),
    servicePublicIPAddress   = tostring(props.servicePublicIPAddress.id),
    deleteOption             = tostring(props.deleteOption)
"@
}

# -----------------------------------------------------------------------------
# 3) microsoft.network/networkinterfaces
# -----------------------------------------------------------------------------
$script:_AzureResourceTypeQueries['microsoft.network/networkinterfaces'] = @{
    Type    = 'microsoft.network/networkinterfaces'
    Hint    = 'network-interface'
    FieldMap = @{
        'AZ_NicEnableAcceleratedNetworking' = 'enableAcceleratedNetworking'
        'AZ_NicEnableIPForwarding'          = 'enableIPForwarding'
        'AZ_NicNsgId'                       = 'networkSecurityGroupId'
        'AZ_NicVirtualMachineId'            = 'virtualMachineId'
        'AZ_NicMacAddress'                  = 'macAddress'
        'AZ_NicPrimary'                     = 'primary'
        'AZ_NicIpConfigCount'               = 'ipConfigCount'
        'AZ_NicHasPublicIp'                 = 'hasPublicIp'
        'AZ_NicPublicIpIds'                 = 'publicIpIds'
        'AZ_NicSubnetIds'                   = 'subnetIds'
        'AZ_NicPrivateIpAddresses'          = 'privateIpAddresses'
        'AZ_NicDnsServers'                  = 'dnsServers'
        'AZ_NicAppliedDnsServers'           = 'appliedDnsServers'
        'AZ_NicInternalDnsNameLabel'        = 'internalDnsNameLabel'
        'AZ_NicAuxiliaryMode'               = 'auxiliaryMode'
        'AZ_NicAuxiliarySku'                = 'auxiliarySku'
        'AZ_NicDisableTcpStateTracking'     = 'disableTcpStateTracking'
        'AZ_NicMigrationPhase'              = 'migrationPhase'
        'AZ_NicNicType'                     = 'nicType'
    }
    Kql = @"
resources
| where type =~ 'microsoft.network/networkinterfaces'
| extend props = properties
| project id, name, type, location, subscriptionId, resourceGroup, tags,
    enableAcceleratedNetworking = tobool(props.enableAcceleratedNetworking),
    enableIPForwarding          = tobool(props.enableIPForwarding),
    networkSecurityGroupId      = tostring(props.networkSecurityGroup.id),
    virtualMachineId            = tostring(props.virtualMachine.id),
    macAddress                  = tostring(props.macAddress),
    primary                     = tobool(props.primary),
    ipConfigCount               = array_length(props.ipConfigurations),
    hasPublicIp                 = isnotnull(props.ipConfigurations[0].properties.publicIPAddress.id),
    publicIpIds                 = tostring(props.ipConfigurations),
    subnetIds                   = tostring(props.ipConfigurations),
    privateIpAddresses          = tostring(props.ipConfigurations),
    dnsServers                  = tostring(props.dnsSettings.dnsServers),
    appliedDnsServers           = tostring(props.dnsSettings.appliedDnsServers),
    internalDnsNameLabel        = tostring(props.dnsSettings.internalDnsNameLabel),
    auxiliaryMode               = tostring(props.auxiliaryMode),
    auxiliarySku                = tostring(props.auxiliarySku),
    disableTcpStateTracking     = tobool(props.disableTcpStateTracking),
    migrationPhase              = tostring(props.migrationPhase),
    nicType                     = tostring(props.nicType)
"@
}

# -----------------------------------------------------------------------------
# 4) microsoft.compute/virtualmachines/extensions
# -----------------------------------------------------------------------------
$script:_AzureResourceTypeQueries['microsoft.compute/virtualmachines/extensions'] = @{
    Type    = 'microsoft.compute/virtualmachines/extensions'
    Hint    = 'vm-extension'
    FieldMap = @{
        'AZ_ExtPublisher'              = 'publisher'
        'AZ_ExtType'                   = 'extType'
        'AZ_ExtTypeHandlerVersion'     = 'typeHandlerVersion'
        'AZ_ExtAutoUpgradeMinorVersion'= 'autoUpgradeMinorVersion'
        'AZ_ExtEnableAutomaticUpgrade' = 'enableAutomaticUpgrade'
        'AZ_ExtForceUpdateTag'         = 'forceUpdateTag'
        'AZ_ExtProvisioningState'      = 'provisioningState'
        'AZ_ExtSettingsJson'           = 'settingsJson'
        'AZ_ExtParentVmId'             = 'parentVmId'
        'AZ_ExtSuppressFailures'       = 'suppressFailures'
        'AZ_ExtInstanceView'           = 'instanceView'
    }
    Kql = @"
resources
| where type =~ 'microsoft.compute/virtualmachines/extensions'
| extend props = properties, parentVmIdComputed = strcat_array(array_slice(split(id, '/'), 0, 8), '/')
| project id, name, type, location, subscriptionId, resourceGroup, tags,
    publisher                = tostring(props.publisher),
    extType                  = tostring(props.type),
    typeHandlerVersion       = tostring(props.typeHandlerVersion),
    autoUpgradeMinorVersion  = tobool(props.autoUpgradeMinorVersion),
    enableAutomaticUpgrade   = tobool(props.enableAutomaticUpgrade),
    forceUpdateTag           = tostring(props.forceUpdateTag),
    provisioningState        = tostring(props.provisioningState),
    settingsJson             = tostring(props.settings),
    parentVmId               = tostring(parentVmIdComputed),
    suppressFailures         = tobool(props.suppressFailures),
    instanceView             = tostring(props.instanceView)
"@
}

# -----------------------------------------------------------------------------
# 5) microsoft.network/virtualnetworks/subnets
# -----------------------------------------------------------------------------
$script:_AzureResourceTypeQueries['microsoft.network/virtualnetworks/subnets'] = @{
    Type    = 'microsoft.network/virtualnetworks/subnets'
    Hint    = 'subnet'
    FieldMap = @{
        'AZ_SubnetAddressPrefix'                          = 'addressPrefix'
        'AZ_SubnetAddressPrefixes'                        = 'addressPrefixes'
        'AZ_SubnetNsgId'                                  = 'nsgId'
        'AZ_SubnetRouteTableId'                           = 'routeTableId'
        'AZ_SubnetNatGatewayId'                           = 'natGatewayId'
        'AZ_SubnetServiceEndpoints'                       = 'serviceEndpoints'
        'AZ_SubnetServiceEndpointPolicies'                = 'serviceEndpointPolicies'
        'AZ_SubnetDelegations'                            = 'delegations'
        'AZ_SubnetPrivateEndpointNetworkPolicies'         = 'privateEndpointNetworkPolicies'
        'AZ_SubnetPrivateLinkServiceNetworkPolicies'      = 'privateLinkServiceNetworkPolicies'
        'AZ_SubnetIpConfigCount'                          = 'ipConfigurationCount'
        'AZ_SubnetPrivateEndpointCount'                   = 'privateEndpointCount'
        'AZ_SubnetDefaultOutboundAccess'                  = 'defaultOutboundAccess'
        'AZ_SubnetSharingScope'                           = 'sharingScope'
        'AZ_SubnetParentVnetId'                           = 'parentVnetId'
    }
    Kql = @"
resources
| where type =~ 'microsoft.network/virtualnetworks/subnets'
| extend props = properties, parentVnetIdComputed = strcat_array(array_slice(split(id, '/'), 0, 9), '/')
| project id, name, type, location, subscriptionId, resourceGroup, tags,
    addressPrefix                       = tostring(props.addressPrefix),
    addressPrefixes                     = tostring(props.addressPrefixes),
    nsgId                               = tostring(props.networkSecurityGroup.id),
    routeTableId                        = tostring(props.routeTable.id),
    natGatewayId                        = tostring(props.natGateway.id),
    serviceEndpoints                    = tostring(props.serviceEndpoints),
    serviceEndpointPolicies             = tostring(props.serviceEndpointPolicies),
    delegations                         = tostring(props.delegations),
    privateEndpointNetworkPolicies      = tostring(props.privateEndpointNetworkPolicies),
    privateLinkServiceNetworkPolicies   = tostring(props.privateLinkServiceNetworkPolicies),
    ipConfigurationCount                = array_length(props.ipConfigurations),
    privateEndpointCount                = array_length(props.privateEndpoints),
    defaultOutboundAccess               = tobool(props.defaultOutboundAccess),
    sharingScope                        = tostring(props.sharingScope),
    parentVnetId                        = tostring(parentVnetIdComputed)
"@
}

# -----------------------------------------------------------------------------
# 6) microsoft.operationalinsights/workspaces
# -----------------------------------------------------------------------------
$script:_AzureResourceTypeQueries['microsoft.operationalinsights/workspaces'] = @{
    Type    = 'microsoft.operationalinsights/workspaces'
    Hint    = 'log-analytics-workspace'
    FieldMap = @{
        'AZ_LawSkuName'                          = 'skuName'
        'AZ_LawCustomerId'                       = 'customerId'
        'AZ_LawRetentionInDays'                  = 'retentionInDays'
        'AZ_LawDailyQuotaGb'                     = 'dailyQuotaGb'
        'AZ_LawPublicNetworkAccessForIngestion'  = 'publicNetworkAccessForIngestion'
        'AZ_LawPublicNetworkAccessForQuery'      = 'publicNetworkAccessForQuery'
        'AZ_LawForceCmkForQuery'                 = 'forceCmkForQuery'
        'AZ_LawDisableLocalAuth'                 = 'disableLocalAuth'
        'AZ_LawEnableLogAccessUsingOnlyResourcePermissions' = 'enableLogAccessUsingOnlyResourcePermissions'
        'AZ_LawEnableDataExport'                 = 'enableDataExport'
        'AZ_LawImmediatePurgeDataOn30Days'       = 'immediatePurgeDataOn30Days'
        'AZ_LawCmkKeyVaultUri'                   = 'cmkKeyVaultUri'
        'AZ_LawCapacityReservationLevel'         = 'capacityReservationLevel'
        'AZ_LawProvisioningState'                = 'provisioningState'
        'AZ_LawCreatedDate'                      = 'createdDate'
        'AZ_LawModifiedDate'                     = 'modifiedDate'
    }
    Kql = @"
resources
| where type =~ 'microsoft.operationalinsights/workspaces'
| extend props = properties
| project id, name, type, location, subscriptionId, resourceGroup, tags, identity, sku,
    skuName                                     = tostring(props.sku.name),
    customerId                                  = tostring(props.customerId),
    retentionInDays                             = toint(props.retentionInDays),
    dailyQuotaGb                                = toreal(props.workspaceCapping.dailyQuotaGb),
    publicNetworkAccessForIngestion             = tostring(props.publicNetworkAccessForIngestion),
    publicNetworkAccessForQuery                 = tostring(props.publicNetworkAccessForQuery),
    forceCmkForQuery                            = tobool(props.forceCmkForQuery),
    disableLocalAuth                            = tobool(props.features.disableLocalAuth),
    enableLogAccessUsingOnlyResourcePermissions = tobool(props.features.enableLogAccessUsingOnlyResourcePermissions),
    enableDataExport                            = tobool(props.features.enableDataExport),
    immediatePurgeDataOn30Days                  = tobool(props.features.immediatePurgeDataOn30Days),
    cmkKeyVaultUri                              = tostring(props.features.clusterResourceId),
    capacityReservationLevel                    = toint(props.sku.capacityReservationLevel),
    provisioningState                           = tostring(props.provisioningState),
    createdDate                                 = tostring(props.createdDate),
    modifiedDate                                = tostring(props.modifiedDate)
"@
}

# -----------------------------------------------------------------------------
# 7) microsoft.network/virtualnetworks
# -----------------------------------------------------------------------------
$script:_AzureResourceTypeQueries['microsoft.network/virtualnetworks'] = @{
    Type    = 'microsoft.network/virtualnetworks'
    Hint    = 'vnet'
    FieldMap = @{
        'AZ_VnetAddressSpace'                          = 'addressSpace'
        'AZ_VnetDhcpOptionsDnsServers'                 = 'dhcpDnsServers'
        'AZ_VnetSubnetCount'                           = 'subnetCount'
        'AZ_VnetEnableDdosProtection'                  = 'enableDdosProtection'
        'AZ_VnetDdosProtectionPlanId'                  = 'ddosProtectionPlanId'
        'AZ_VnetEnableVmProtection'                    = 'enableVmProtection'
        'AZ_VnetPeeringCount'                          = 'peeringCount'
        'AZ_VnetPeeringIds'                            = 'peeringIds'
        'AZ_VnetEncryptionEnabled'                     = 'encryptionEnabled'
        'AZ_VnetEncryptionEnforcement'                 = 'encryptionEnforcement'
        'AZ_VnetFlowTimeoutInMinutes'                  = 'flowTimeoutInMinutes'
        'AZ_VnetBgpCommunities'                        = 'bgpCommunities'
        'AZ_VnetIpAllocationCount'                     = 'ipAllocationCount'
        'AZ_VnetProvisioningState'                     = 'provisioningState'
    }
    Kql = @"
resources
| where type =~ 'microsoft.network/virtualnetworks'
| extend props = properties
| project id, name, type, location, subscriptionId, resourceGroup, tags,
    addressSpace          = tostring(props.addressSpace.addressPrefixes),
    dhcpDnsServers        = tostring(props.dhcpOptions.dnsServers),
    subnetCount           = array_length(props.subnets),
    enableDdosProtection  = tobool(props.enableDdosProtection),
    ddosProtectionPlanId  = tostring(props.ddosProtectionPlan.id),
    enableVmProtection    = tobool(props.enableVmProtection),
    peeringCount          = array_length(props.virtualNetworkPeerings),
    peeringIds            = tostring(props.virtualNetworkPeerings),
    encryptionEnabled     = tobool(props.encryption.enabled),
    encryptionEnforcement = tostring(props.encryption.enforcement),
    flowTimeoutInMinutes  = toint(props.flowTimeoutInMinutes),
    bgpCommunities        = tostring(props.bgpCommunities),
    ipAllocationCount     = array_length(props.ipAllocations),
    provisioningState     = tostring(props.provisioningState)
"@
}

# -----------------------------------------------------------------------------
# 8) microsoft.sql/servers/databases
# -----------------------------------------------------------------------------
$script:_AzureResourceTypeQueries['microsoft.sql/servers/databases'] = @{
    Type    = 'microsoft.sql/servers/databases'
    Hint    = 'sql-database'
    FieldMap = @{
        'AZ_SqlDbCollation'                       = 'collation'
        'AZ_SqlDbCatalogCollation'                = 'catalogCollation'
        'AZ_SqlDbDatabaseId'                      = 'databaseId'
        'AZ_SqlDbStatus'                          = 'status'
        'AZ_SqlDbZoneRedundant'                   = 'zoneRedundant'
        'AZ_SqlDbReadScale'                       = 'readScale'
        'AZ_SqlDbHighAvailabilityReplicaCount'    = 'highAvailabilityReplicaCount'
        'AZ_SqlDbRequestedBackupStorageRedundancy'= 'requestedBackupStorageRedundancy'
        'AZ_SqlDbCurrentBackupStorageRedundancy'  = 'currentBackupStorageRedundancy'
        'AZ_SqlDbIsLedgerOn'                      = 'isLedgerOn'
        'AZ_SqlDbIsInfraEncryptionEnabled'        = 'isInfraEncryptionEnabled'
        'AZ_SqlDbEncryptionProtector'             = 'encryptionProtector'
        'AZ_SqlDbAutoPauseDelay'                  = 'autoPauseDelay'
        'AZ_SqlDbMinCapacity'                     = 'minCapacity'
        'AZ_SqlDbCurrentSku'                      = 'currentSku'
        'AZ_SqlDbCurrentServiceObjective'         = 'currentServiceObjective'
        'AZ_SqlDbMaintenanceConfigurationId'      = 'maintenanceConfigurationId'
        'AZ_SqlDbElasticPoolId'                   = 'elasticPoolId'
        'AZ_SqlDbCreateMode'                      = 'createMode'
        'AZ_SqlDbSourceDatabaseId'                = 'sourceDatabaseId'
        'AZ_SqlDbParentServerId'                  = 'parentServerId'
        'AZ_SqlDbCreationDate'                    = 'creationDate'
    }
    Kql = @"
resources
| where type =~ 'microsoft.sql/servers/databases'
| extend props = properties, parentServerIdComputed = strcat_array(array_slice(split(id, '/'), 0, 9), '/')
| project id, name, type, location, subscriptionId, resourceGroup, tags, sku,
    collation                          = tostring(props.collation),
    catalogCollation                   = tostring(props.catalogCollation),
    databaseId                         = tostring(props.databaseId),
    status                             = tostring(props.status),
    zoneRedundant                      = tobool(props.zoneRedundant),
    readScale                          = tostring(props.readScale),
    highAvailabilityReplicaCount       = toint(props.highAvailabilityReplicaCount),
    requestedBackupStorageRedundancy   = tostring(props.requestedBackupStorageRedundancy),
    currentBackupStorageRedundancy     = tostring(props.currentBackupStorageRedundancy),
    isLedgerOn                         = tobool(props.isLedgerOn),
    isInfraEncryptionEnabled           = tobool(props.isInfraEncryptionEnabled),
    encryptionProtector                = tostring(props.encryptionProtector),
    autoPauseDelay                     = toint(props.autoPauseDelay),
    minCapacity                        = toreal(props.minCapacity),
    currentSku                         = tostring(props.currentSku.name),
    currentServiceObjective            = tostring(props.currentServiceObjectiveName),
    maintenanceConfigurationId         = tostring(props.maintenanceConfigurationId),
    elasticPoolId                      = tostring(props.elasticPoolId),
    createMode                         = tostring(props.createMode),
    sourceDatabaseId                   = tostring(props.sourceDatabaseId),
    parentServerId                     = tostring(parentServerIdComputed),
    creationDate                       = tostring(props.creationDate)
"@
}

# -----------------------------------------------------------------------------
# 9) microsoft.keyvault/vaults
# -----------------------------------------------------------------------------
$script:_AzureResourceTypeQueries['microsoft.keyvault/vaults'] = @{
    Type    = 'microsoft.keyvault/vaults'
    Hint    = 'key-vault'
    FieldMap = @{
        'AZ_KvPublicNetworkAccess'           = 'publicNetworkAccess'
        'AZ_KvNetworkAclsBypass'             = 'networkAclsBypass'
        'AZ_KvNetworkAclsDefaultAction'      = 'networkAclsDefaultAction'
        'AZ_KvNetworkAclsIpRulesCount'       = 'networkAclsIpRulesCount'
        'AZ_KvNetworkAclsVnetRulesCount'     = 'networkAclsVnetRulesCount'
        'AZ_KvEnableRbacAuthorization'       = 'enableRbacAuthorization'
        'AZ_KvEnableSoftDelete'              = 'enableSoftDelete'
        'AZ_KvSoftDeleteRetentionInDays'     = 'softDeleteRetentionInDays'
        'AZ_KvEnablePurgeProtection'         = 'enablePurgeProtection'
        'AZ_KvEnabledForDeployment'          = 'enabledForDeployment'
        'AZ_KvEnabledForTemplateDeployment'  = 'enabledForTemplateDeployment'
        'AZ_KvEnabledForDiskEncryption'      = 'enabledForDiskEncryption'
        'AZ_KvSkuName'                       = 'skuName'
        'AZ_KvSkuFamily'                     = 'skuFamily'
        'AZ_KvTenantId'                      = 'tenantId'
        'AZ_KvAccessPolicyCount'             = 'accessPolicyCount'
        'AZ_KvAccessPolicyPrincipalIds'      = 'accessPolicyPrincipalIds'
        'AZ_KvVaultUri'                      = 'vaultUri'
        'AZ_KvHsmPoolResourceId'             = 'hsmPoolResourceId'
        'AZ_KvPrivateEndpointConnectionCount'= 'privateEndpointConnectionCount'
        'AZ_KvProvisioningState'             = 'provisioningState'
        'AZ_KvCreateMode'                    = 'createMode'
    }
    Kql = @"
resources
| where type =~ 'microsoft.keyvault/vaults'
| extend props = properties
| project id, name, type, location, subscriptionId, resourceGroup, tags,
    publicNetworkAccess            = tostring(props.publicNetworkAccess),
    networkAclsBypass              = tostring(props.networkAcls.bypass),
    networkAclsDefaultAction       = tostring(props.networkAcls.defaultAction),
    networkAclsIpRulesCount        = array_length(props.networkAcls.ipRules),
    networkAclsVnetRulesCount      = array_length(props.networkAcls.virtualNetworkRules),
    enableRbacAuthorization        = tobool(props.enableRbacAuthorization),
    enableSoftDelete               = tobool(props.enableSoftDelete),
    softDeleteRetentionInDays      = toint(props.softDeleteRetentionInDays),
    enablePurgeProtection          = tobool(props.enablePurgeProtection),
    enabledForDeployment           = tobool(props.enabledForDeployment),
    enabledForTemplateDeployment   = tobool(props.enabledForTemplateDeployment),
    enabledForDiskEncryption       = tobool(props.enabledForDiskEncryption),
    skuName                        = tostring(props.sku.name),
    skuFamily                      = tostring(props.sku.family),
    tenantId                       = tostring(props.tenantId),
    accessPolicyCount              = array_length(props.accessPolicies),
    accessPolicyPrincipalIds       = tostring(props.accessPolicies),
    vaultUri                       = tostring(props.vaultUri),
    hsmPoolResourceId              = tostring(props.hsmPoolResourceId),
    privateEndpointConnectionCount = array_length(props.privateEndpointConnections),
    provisioningState              = tostring(props.provisioningState),
    createMode                     = tostring(props.createMode)
"@
}

# -----------------------------------------------------------------------------
# 10) microsoft.logic/workflows
# -----------------------------------------------------------------------------
$script:_AzureResourceTypeQueries['microsoft.logic/workflows'] = @{
    Type    = 'microsoft.logic/workflows'
    Hint    = 'logic-app'
    FieldMap = @{
        'AZ_LaState'                        = 'state'
        'AZ_LaVersion'                      = 'version'
        'AZ_LaProvisioningState'            = 'provisioningState'
        'AZ_LaIntegrationAccountId'         = 'integrationAccountId'
        'AZ_LaIntegrationServiceEnvId'      = 'integrationServiceEnvironmentId'
        'AZ_LaSkuName'                      = 'skuName'
        'AZ_LaAccessControlActionsAllowed'  = 'accessControlActionsAllowedCallerIpAddresses'
        'AZ_LaAccessControlContents'        = 'accessControlContents'
        'AZ_LaAccessControlTriggers'        = 'accessControlTriggers'
        'AZ_LaAccessControlWorkflowMgmt'    = 'accessControlWorkflowManagement'
        'AZ_LaEndpointsSchemeAccessEndpts'  = 'endpointsAccessSchemeEndpoints'
        'AZ_LaEndpointsConnector'           = 'endpointsConnector'
        'AZ_LaParameters'                   = 'parameters'
        'AZ_LaTriggerCount'                 = 'triggerCount'
        'AZ_LaActionCount'                  = 'actionCount'
        'AZ_LaCreatedTime'                  = 'createdTime'
        'AZ_LaChangedTime'                  = 'changedTime'
        'AZ_LaDefinitionSchema'             = 'definitionSchema'
    }
    Kql = @"
resources
| where type =~ 'microsoft.logic/workflows'
| extend props = properties
| project id, name, type, location, subscriptionId, resourceGroup, tags, identity, sku, kind,
    state                                       = tostring(props.state),
    version                                     = tostring(props.version),
    provisioningState                           = tostring(props.provisioningState),
    integrationAccountId                        = tostring(props.integrationAccount.id),
    integrationServiceEnvironmentId             = tostring(props.integrationServiceEnvironment.id),
    skuName                                     = tostring(props.sku.name),
    accessControlActionsAllowedCallerIpAddresses= tostring(props.accessControl.actions.allowedCallerIpAddresses),
    accessControlContents                       = tostring(props.accessControl.contents.allowedCallerIpAddresses),
    accessControlTriggers                       = tostring(props.accessControl.triggers.allowedCallerIpAddresses),
    accessControlWorkflowManagement             = tostring(props.accessControl.workflowManagement.allowedCallerIpAddresses),
    endpointsAccessSchemeEndpoints              = tostring(props.endpointsConfiguration.workflow.accessEndpointIpAddresses),
    endpointsConnector                          = tostring(props.endpointsConfiguration.connector.outgoingIpAddresses),
    parameters                                  = tostring(props.parameters),
    triggerCount                                = array_length(props.definition.triggers),
    actionCount                                 = array_length(props.definition.actions),
    createdTime                                 = tostring(props.createdTime),
    changedTime                                 = tostring(props.changedTime),
    definitionSchema                            = tostring(props.definition['$schema'])
"@
}

# -----------------------------------------------------------------------------
# 11) microsoft.network/networksecuritygroups
# -----------------------------------------------------------------------------
$script:_AzureResourceTypeQueries['microsoft.network/networksecuritygroups'] = @{
    Type    = 'microsoft.network/networksecuritygroups'
    Hint    = 'network-security-group'
    FieldMap = @{
        'AZ_NsgSecurityRuleCount'              = 'securityRuleCount'
        'AZ_NsgDefaultSecurityRuleCount'       = 'defaultSecurityRuleCount'
        'AZ_NsgFlushConnection'                = 'flushConnection'
        'AZ_NsgInboundAllowAnyCount'           = 'inboundAllowAnyCount'
        'AZ_NsgInboundAllowInternetCount'      = 'inboundAllowInternetCount'
        'AZ_NsgInboundAllowRdpCount'           = 'inboundAllowRdpCount'
        'AZ_NsgInboundAllowSshCount'           = 'inboundAllowSshCount'
        'AZ_NsgOutboundDenyAnyCount'           = 'outboundDenyAnyCount'
        'AZ_NsgAttachedNicCount'               = 'attachedNicCount'
        'AZ_NsgAttachedSubnetCount'            = 'attachedSubnetCount'
        'AZ_NsgAttachedNicIds'                 = 'attachedNicIds'
        'AZ_NsgAttachedSubnetIds'              = 'attachedSubnetIds'
        'AZ_NsgSecurityRulesJson'              = 'securityRulesJson'
        'AZ_NsgProvisioningState'              = 'provisioningState'
    }
    Kql = @"
resources
| where type =~ 'microsoft.network/networksecuritygroups'
| extend props = properties
| extend rules = props.securityRules
| project id, name, type, location, subscriptionId, resourceGroup, tags,
    securityRuleCount         = array_length(rules),
    defaultSecurityRuleCount  = array_length(props.defaultSecurityRules),
    flushConnection           = tobool(props.flushConnection),
    inboundAllowAnyCount      = toint(array_length(rules)),
    inboundAllowInternetCount = toint(array_length(rules)),
    inboundAllowRdpCount      = toint(array_length(rules)),
    inboundAllowSshCount      = toint(array_length(rules)),
    outboundDenyAnyCount      = toint(array_length(rules)),
    attachedNicCount          = array_length(props.networkInterfaces),
    attachedSubnetCount       = array_length(props.subnets),
    attachedNicIds            = tostring(props.networkInterfaces),
    attachedSubnetIds         = tostring(props.subnets),
    securityRulesJson         = tostring(rules),
    provisioningState         = tostring(props.provisioningState)
"@
}

# -----------------------------------------------------------------------------
# 12) microsoft.cognitiveservices/accounts/deployments
# -----------------------------------------------------------------------------
$script:_AzureResourceTypeQueries['microsoft.cognitiveservices/accounts/deployments'] = @{
    Type    = 'microsoft.cognitiveservices/accounts/deployments'
    Hint    = 'cognitive-deployment'
    FieldMap = @{
        'AZ_DeplModelName'              = 'modelName'
        'AZ_DeplModelVersion'           = 'modelVersion'
        'AZ_DeplModelFormat'            = 'modelFormat'
        'AZ_DeplProvisioningState'      = 'provisioningState'
        'AZ_DeplVersionUpgradeOption'   = 'versionUpgradeOption'
        'AZ_DeplRaiPolicyName'          = 'raiPolicyName'
        'AZ_DeplCallRateLimitCount'     = 'callRateLimitCount'
        'AZ_DeplScaleType'              = 'scaleType'
        'AZ_DeplScaleCapacity'          = 'scaleCapacity'
        'AZ_DeplDynamicThrottlingEnabled'= 'dynamicThrottlingEnabled'
        'AZ_DeplCurrentCapacity'        = 'currentCapacity'
        'AZ_DeplParentAccountId'        = 'parentAccountId'
        'AZ_DeplCreationDate'           = 'creationDate'
        'AZ_DeplCapabilities'           = 'capabilities'
    }
    Kql = @"
resources
| where type =~ 'microsoft.cognitiveservices/accounts/deployments'
| extend props = properties, parentAccountIdComputed = strcat_array(array_slice(split(id, '/'), 0, 9), '/')
| project id, name, type, location, subscriptionId, resourceGroup, tags, sku,
    modelName                = tostring(props.model.name),
    modelVersion             = tostring(props.model.version),
    modelFormat              = tostring(props.model.format),
    provisioningState        = tostring(props.provisioningState),
    versionUpgradeOption     = tostring(props.versionUpgradeOption),
    raiPolicyName            = tostring(props.raiPolicyName),
    callRateLimitCount       = toint(props.callRateLimit.count),
    scaleType                = tostring(props.scaleSettings.scaleType),
    scaleCapacity            = toint(props.scaleSettings.capacity),
    dynamicThrottlingEnabled = tobool(props.dynamicThrottlingEnabled),
    currentCapacity          = toint(props.currentCapacity),
    parentAccountId          = tostring(parentAccountIdComputed),
    creationDate             = tostring(props.creationDate),
    capabilities             = tostring(props.capabilities)
"@
}

# -----------------------------------------------------------------------------
# 13) microsoft.storage/storageaccounts
# -----------------------------------------------------------------------------
$script:_AzureResourceTypeQueries['microsoft.storage/storageaccounts'] = @{
    Type    = 'microsoft.storage/storageaccounts'
    Hint    = 'storage-account'
    FieldMap = @{
        'AZ_StPublicNetworkAccess'        = 'publicNetworkAccess'
        'AZ_StAllowBlobPublicAccess'      = 'allowBlobPublicAccess'
        'AZ_StAllowSharedKeyAccess'       = 'allowSharedKeyAccess'
        'AZ_StAllowCrossTenantReplication'= 'allowCrossTenantReplication'
        'AZ_StMinimumTlsVersion'          = 'minimumTlsVersion'
        'AZ_StSupportsHttpsTrafficOnly'   = 'supportsHttpsTrafficOnly'
        'AZ_StNetworkAclsBypass'          = 'networkAclsBypass'
        'AZ_StNetworkAclsDefaultAction'   = 'networkAclsDefaultAction'
        'AZ_StNetworkAclsIpRulesCount'    = 'networkAclsIpRulesCount'
        'AZ_StNetworkAclsVnetRulesCount'  = 'networkAclsVnetRulesCount'
        'AZ_StNetworkAclsResourceAccessCount' = 'networkAclsResourceAccessCount'
        'AZ_StEncryptionKeySource'        = 'encryptionKeySource'
        'AZ_StRequireInfraEncryption'     = 'requireInfrastructureEncryption'
        'AZ_StEncryptionKeyVaultUri'      = 'encryptionKeyVaultUri'
        'AZ_StEncryptionKeyName'          = 'encryptionKeyName'
        'AZ_StEncryptionKeyVersion'       = 'encryptionKeyVersion'
        'AZ_StIsHnsEnabled'               = 'isHnsEnabled'
        'AZ_StIsNfsV3Enabled'             = 'isNfsV3Enabled'
        'AZ_StIsSftpEnabled'              = 'isSftpEnabled'
        'AZ_StIsLocalUserEnabled'         = 'isLocalUserEnabled'
        'AZ_StLargeFileSharesState'       = 'largeFileSharesState'
        'AZ_StAzureFilesIdentityBased'    = 'azureFilesIdentityBased'
        'AZ_StKeyPolicyExpirationDays'    = 'keyPolicyExpirationDays'
        'AZ_StSasPolicyExpirationPeriod'  = 'sasPolicyExpirationPeriod'
        'AZ_StSasPolicyExpirationAction'  = 'sasPolicyExpirationAction'
        'AZ_StImmutableStorageEnabled'    = 'immutableStorageEnabled'
        'AZ_StPublicEndpointPrivCount'    = 'privateEndpointConnectionCount'
        'AZ_StAccessTier'                 = 'accessTier'
        'AZ_StRoutingPreference'          = 'routingPreference'
        'AZ_StDefaultToOAuthAuth'         = 'defaultToOAuthAuthentication'
        'AZ_StDnsEndpointType'            = 'dnsEndpointType'
        'AZ_StAllowedCopyScope'           = 'allowedCopyScope'
        'AZ_StSkuName'                    = 'skuName'
        'AZ_StSkuTier'                    = 'skuTier'
        'AZ_StKind'                       = 'stKind'
        'AZ_StProvisioningState'          = 'provisioningState'
        'AZ_StCreationTime'               = 'creationTime'
    }
    Kql = @"
resources
| where type =~ 'microsoft.storage/storageaccounts'
| extend props = properties
| project id, name, type, location, subscriptionId, resourceGroup, tags, identity,
    publicNetworkAccess              = tostring(props.publicNetworkAccess),
    allowBlobPublicAccess            = tobool(props.allowBlobPublicAccess),
    allowSharedKeyAccess             = tobool(props.allowSharedKeyAccess),
    allowCrossTenantReplication      = tobool(props.allowCrossTenantReplication),
    minimumTlsVersion                = tostring(props.minimumTlsVersion),
    supportsHttpsTrafficOnly         = tobool(props.supportsHttpsTrafficOnly),
    networkAclsBypass                = tostring(props.networkAcls.bypass),
    networkAclsDefaultAction         = tostring(props.networkAcls.defaultAction),
    networkAclsIpRulesCount          = array_length(props.networkAcls.ipRules),
    networkAclsVnetRulesCount        = array_length(props.networkAcls.virtualNetworkRules),
    networkAclsResourceAccessCount   = array_length(props.networkAcls.resourceAccessRules),
    encryptionKeySource              = tostring(props.encryption.keySource),
    requireInfrastructureEncryption  = tobool(props.encryption.requireInfrastructureEncryption),
    encryptionKeyVaultUri            = tostring(props.encryption.keyvaultproperties.keyvaulturi),
    encryptionKeyName                = tostring(props.encryption.keyvaultproperties.keyname),
    encryptionKeyVersion             = tostring(props.encryption.keyvaultproperties.keyversion),
    isHnsEnabled                     = tobool(props.isHnsEnabled),
    isNfsV3Enabled                   = tobool(props.isNfsV3Enabled),
    isSftpEnabled                    = tobool(props.isSftpEnabled),
    isLocalUserEnabled               = tobool(props.isLocalUserEnabled),
    largeFileSharesState             = tostring(props.largeFileSharesState),
    azureFilesIdentityBased          = tostring(props.azureFilesIdentityBasedAuthentication.directoryServiceOptions),
    keyPolicyExpirationDays          = toint(props.keyPolicy.keyExpirationPeriodInDays),
    sasPolicyExpirationPeriod        = tostring(props.sasPolicy.sasExpirationPeriod),
    sasPolicyExpirationAction        = tostring(props.sasPolicy.expirationAction),
    immutableStorageEnabled          = tobool(props.immutableStorageWithVersioning.enabled),
    privateEndpointConnectionCount   = array_length(props.privateEndpointConnections),
    accessTier                       = tostring(props.accessTier),
    routingPreference                = tostring(props.routingPreference.routingChoice),
    defaultToOAuthAuthentication     = tobool(props.defaultToOAuthAuthentication),
    dnsEndpointType                  = tostring(props.dnsEndpointType),
    allowedCopyScope                 = tostring(props.allowedCopyScope),
    skuName                          = tostring(sku.name),
    skuTier                          = tostring(sku.tier),
    stKind                           = tostring(kind),
    provisioningState                = tostring(props.provisioningState),
    creationTime                     = tostring(props.creationTime)
"@
}

# -----------------------------------------------------------------------------
# 14) microsoft.web/serverfarms
# -----------------------------------------------------------------------------
$script:_AzureResourceTypeQueries['microsoft.web/serverfarms'] = @{
    Type    = 'microsoft.web/serverfarms'
    Hint    = 'app-service-plan'
    FieldMap = @{
        'AZ_PlanSkuName'             = 'skuName'
        'AZ_PlanSkuTier'             = 'skuTier'
        'AZ_PlanSkuSize'             = 'skuSize'
        'AZ_PlanSkuFamily'           = 'skuFamily'
        'AZ_PlanSkuCapacity'         = 'skuCapacity'
        'AZ_PlanWorkerTier'          = 'workerTier'
        'AZ_PlanWorkerSize'          = 'workerSize'
        'AZ_PlanReserved'            = 'reserved'
        'AZ_PlanIsXenon'             = 'isXenon'
        'AZ_PlanHyperV'              = 'hyperV'
        'AZ_PlanZoneRedundant'       = 'zoneRedundant'
        'AZ_PlanPerSiteScaling'      = 'perSiteScaling'
        'AZ_PlanElasticScaleEnabled' = 'elasticScaleEnabled'
        'AZ_PlanMaxElasticWorkers'   = 'maximumElasticWorkerCount'
        'AZ_PlanMaximumNumberOfWorkers' = 'maximumNumberOfWorkers'
        'AZ_PlanNumberOfSites'       = 'numberOfSites'
        'AZ_PlanTargetWorkerCount'   = 'targetWorkerCount'
        'AZ_PlanTargetWorkerSizeId'  = 'targetWorkerSizeId'
        'AZ_PlanProvisioningState'   = 'provisioningState'
        'AZ_PlanStatus'              = 'status'
        'AZ_PlanKind'                = 'planKind'
        'AZ_PlanFreeOfferExpiration' = 'freeOfferExpirationTime'
    }
    Kql = @"
resources
| where type =~ 'microsoft.web/serverfarms'
| extend props = properties
| project id, name, type, location, subscriptionId, resourceGroup, tags,
    skuName                  = tostring(sku.name),
    skuTier                  = tostring(sku.tier),
    skuSize                  = tostring(sku.size),
    skuFamily                = tostring(sku.family),
    skuCapacity              = toint(sku.capacity),
    workerTier               = tostring(props.workerTier),
    workerSize               = tostring(props.workerSize),
    reserved                 = tobool(props.reserved),
    isXenon                  = tobool(props.isXenon),
    hyperV                   = tobool(props.hyperV),
    zoneRedundant            = tobool(props.zoneRedundant),
    perSiteScaling           = tobool(props.perSiteScaling),
    elasticScaleEnabled      = tobool(props.elasticScaleEnabled),
    maximumElasticWorkerCount= toint(props.maximumElasticWorkerCount),
    maximumNumberOfWorkers   = toint(props.maximumNumberOfWorkers),
    numberOfSites            = toint(props.numberOfSites),
    targetWorkerCount        = toint(props.targetWorkerCount),
    targetWorkerSizeId       = toint(props.targetWorkerSizeId),
    provisioningState        = tostring(props.provisioningState),
    status                   = tostring(props.status),
    planKind                 = tostring(kind),
    freeOfferExpirationTime  = tostring(props.freeOfferExpirationTime)
"@
}

# -----------------------------------------------------------------------------
# 15) microsoft.cognitiveservices/accounts (filter: kind == 'OpenAI')
# -----------------------------------------------------------------------------
$script:_AzureResourceTypeQueries['microsoft.cognitiveservices/accounts_openai'] = @{
    Type    = 'microsoft.cognitiveservices/accounts'   # ARM type is the same; kind filter narrows
    Hint    = 'azure-openai'
    FieldMap = @{
        'AZ_AoaiPublicNetworkAccess'    = 'publicNetworkAccess'
        'AZ_AoaiDisableLocalAuth'       = 'disableLocalAuth'
        'AZ_AoaiCustomSubDomainName'    = 'customSubDomainName'
        'AZ_AoaiNetworkAclsDefaultAct'  = 'networkAclsDefaultAction'
        'AZ_AoaiNetworkAclsBypass'      = 'networkAclsBypass'
        'AZ_AoaiNetworkAclsIpRulesCount'= 'networkAclsIpRulesCount'
        'AZ_AoaiNetworkAclsVnetCount'   = 'networkAclsVnetRulesCount'
        'AZ_AoaiPrivateEndpointCount'   = 'privateEndpointConnectionCount'
        'AZ_AoaiRestrictOutboundAccess' = 'restrictOutboundNetworkAccess'
        'AZ_AoaiAllowedFqdnList'        = 'allowedFqdnList'
        'AZ_AoaiEncryptionKeySource'    = 'encryptionKeySource'
        'AZ_AoaiEncryptionKeyVaultUri'  = 'encryptionKeyVaultUri'
        'AZ_AoaiEncryptionKeyName'      = 'encryptionKeyName'
        'AZ_AoaiUserOwnedStorage'       = 'userOwnedStorageCount'
        'AZ_AoaiApiProperties'          = 'apiProperties'
        'AZ_AoaiSkuName'                = 'skuName'
        'AZ_AoaiKind'                   = 'aoaiKind'
        'AZ_AoaiEndpoint'               = 'endpoint'
        'AZ_AoaiEndpoints'              = 'endpoints'
        'AZ_AoaiDeploymentCount'        = 'deploymentCount'
        'AZ_AoaiAbusePenaltyEnabled'    = 'abusePenaltyEnabled'
        'AZ_AoaiCommitmentPlanCount'    = 'commitmentPlanCount'
        'AZ_AoaiDateCreated'            = 'dateCreated'
        'AZ_AoaiProvisioningState'      = 'provisioningState'
    }
    Kql = @"
resources
| where type =~ 'microsoft.cognitiveservices/accounts'
| where kind =~ 'OpenAI'
| extend props = properties
| project id, name, type, location, subscriptionId, resourceGroup, tags, identity, sku,
    publicNetworkAccess            = tostring(props.publicNetworkAccess),
    disableLocalAuth               = tobool(props.disableLocalAuth),
    customSubDomainName            = tostring(props.customSubDomainName),
    networkAclsDefaultAction       = tostring(props.networkAcls.defaultAction),
    networkAclsBypass              = tostring(props.networkAcls.bypass),
    networkAclsIpRulesCount        = array_length(props.networkAcls.ipRules),
    networkAclsVnetRulesCount      = array_length(props.networkAcls.virtualNetworkRules),
    privateEndpointConnectionCount = array_length(props.privateEndpointConnections),
    restrictOutboundNetworkAccess  = tobool(props.restrictOutboundNetworkAccess),
    allowedFqdnList                = tostring(props.allowedFqdnList),
    encryptionKeySource            = tostring(props.encryption.keySource),
    encryptionKeyVaultUri          = tostring(props.encryption.keyVaultProperties.keyVaultUri),
    encryptionKeyName              = tostring(props.encryption.keyVaultProperties.keyName),
    userOwnedStorageCount          = array_length(props.userOwnedStorage),
    apiProperties                  = tostring(props.apiProperties),
    skuName                        = tostring(sku.name),
    aoaiKind                       = tostring(kind),
    endpoint                       = tostring(props.endpoint),
    endpoints                      = tostring(props.endpoints),
    deploymentCount                = array_length(props.deletedAccountDeployments),
    abusePenaltyEnabled            = tobool(props.abusePenalty.action),
    commitmentPlanCount            = array_length(props.commitmentPlanAssociations),
    dateCreated                    = tostring(props.dateCreated),
    provisioningState              = tostring(props.provisioningState)
"@
}

# -----------------------------------------------------------------------------
# 16) microsoft.sql/servers/firewallrules
# (Listed by user as 'microsoft.sql/firewallrules' but the canonical type is
#  microsoft.sql/servers/firewallrules; they're a sub-resource of SQL servers.)
# -----------------------------------------------------------------------------
$script:_AzureResourceTypeQueries['microsoft.sql/servers/firewallrules'] = @{
    Type    = 'microsoft.sql/servers/firewallrules'
    Hint    = 'sql-firewall-rule'
    FieldMap = @{
        'AZ_SqlFwStartIpAddress'   = 'startIpAddress'
        'AZ_SqlFwEndIpAddress'     = 'endIpAddress'
        'AZ_SqlFwAllowsAllAzureIPs'= 'allowsAllAzureIps'
        'AZ_SqlFwAllowsAllIPv4'    = 'allowsAllIpv4'
        'AZ_SqlFwParentServerId'   = 'parentServerId'
        'AZ_SqlFwKind'             = 'fwKind'
    }
    Kql = @"
resources
| where type =~ 'microsoft.sql/servers/firewallrules'
| extend props = properties, parentServerIdComputed = strcat_array(array_slice(split(id, '/'), 0, 9), '/')
| project id, name, type, location, subscriptionId, resourceGroup, tags,
    startIpAddress    = tostring(props.startIpAddress),
    endIpAddress      = tostring(props.endIpAddress),
    allowsAllAzureIps = tobool(tostring(props.startIpAddress) == '0.0.0.0' and tostring(props.endIpAddress) == '0.0.0.0'),
    allowsAllIpv4     = tobool(tostring(props.startIpAddress) == '0.0.0.0' and tostring(props.endIpAddress) == '255.255.255.255'),
    parentServerId    = tostring(parentServerIdComputed),
    fwKind            = tostring(kind)
"@
}

# -----------------------------------------------------------------------------
# 17) microsoft.web/sites (kind contains 'functionapp' -- Azure Functions)
# -----------------------------------------------------------------------------
$script:_AzureResourceTypeQueries['microsoft.web/sites_azurefunction'] = @{
    Type    = 'microsoft.web/sites'   # ARM type same; kind filter narrows
    Hint    = 'azure-function'
    FieldMap = @{
        'AZ_FuncHttpsOnly'                              = 'httpsOnly'
        'AZ_FuncPublicNetworkAccess'                    = 'publicNetworkAccess'
        'AZ_FuncClientCertEnabled'                      = 'clientCertEnabled'
        'AZ_FuncClientCertMode'                         = 'clientCertMode'
        'AZ_FuncClientAffinityEnabled'                  = 'clientAffinityEnabled'
        'AZ_FuncMinTlsVersion'                          = 'minTlsVersion'
        'AZ_FuncFtpsState'                              = 'ftpsState'
        'AZ_FuncScmIpRestrictionsDefaultAction'         = 'scmIpRestrictionsDefaultAction'
        'AZ_FuncIpRestrictionsDefaultAction'            = 'ipRestrictionsDefaultAction'
        'AZ_FuncScmIpRestrictionCount'                  = 'scmIpRestrictionCount'
        'AZ_FuncIpRestrictionCount'                     = 'ipRestrictionCount'
        'AZ_FuncRemoteDebuggingEnabled'                 = 'remoteDebuggingEnabled'
        'AZ_FuncHttp20Enabled'                          = 'http20Enabled'
        'AZ_FuncDetailedErrorLoggingEnabled'            = 'detailedErrorLoggingEnabled'
        'AZ_FuncAlwaysOn'                               = 'alwaysOn'
        'AZ_FuncVnetSubnetId'                           = 'virtualNetworkSubnetId'
        'AZ_FuncVnetRouteAllEnabled'                    = 'vnetRouteAllEnabled'
        'AZ_FuncVnetImagePullEnabled'                   = 'vnetImagePullEnabled'
        'AZ_FuncStorageAccountRequired'                 = 'storageAccountRequired'
        'AZ_FuncFunctionsRuntimeScaleMonitoringEnabled' = 'functionsRuntimeScaleMonitoringEnabled'
        'AZ_FuncManagedEnvironmentId'                   = 'managedEnvironmentId'
        'AZ_FuncKeyVaultReferenceIdentity'              = 'keyVaultReferenceIdentity'
        'AZ_FuncCustomDomainCount'                      = 'customDomainCount'
        'AZ_FuncEnabled'                                = 'enabled'
        'AZ_FuncState'                                  = 'state'
        'AZ_FuncReserved'                               = 'reserved'
        'AZ_FuncServerFarmId'                           = 'serverFarmId'
        'AZ_FuncFunctionRuntime'                        = 'functionRuntime'
        'AZ_FuncKind'                                   = 'funcKind'
        'AZ_FuncLinuxFxVersion'                         = 'linuxFxVersion'
        'AZ_FuncWindowsFxVersion'                       = 'windowsFxVersion'
        'AZ_FuncCorsAllowedOrigins'                     = 'corsAllowedOrigins'
        'AZ_FuncCorsSupportCredentials'                 = 'corsSupportCredentials'
        'AZ_FuncAuthEnabled'                            = 'authEnabled'
        'AZ_FuncRedundancyMode'                         = 'redundancyMode'
    }
    Kql = @"
resources
| where type =~ 'microsoft.web/sites'
| where kind contains 'functionapp'
| extend props = properties, sc = properties.siteConfig
| project id, name, type, location, subscriptionId, resourceGroup, tags, identity,
    httpsOnly                              = tobool(props.httpsOnly),
    publicNetworkAccess                    = tostring(props.publicNetworkAccess),
    clientCertEnabled                      = tobool(props.clientCertEnabled),
    clientCertMode                         = tostring(props.clientCertMode),
    clientAffinityEnabled                  = tobool(props.clientAffinityEnabled),
    minTlsVersion                          = tostring(sc.minTlsVersion),
    ftpsState                              = tostring(sc.ftpsState),
    scmIpRestrictionsDefaultAction         = tostring(sc.scmIpSecurityRestrictionsDefaultAction),
    ipRestrictionsDefaultAction            = tostring(sc.ipSecurityRestrictionsDefaultAction),
    scmIpRestrictionCount                  = array_length(sc.scmIpSecurityRestrictions),
    ipRestrictionCount                     = array_length(sc.ipSecurityRestrictions),
    remoteDebuggingEnabled                 = tobool(sc.remoteDebuggingEnabled),
    http20Enabled                          = tobool(sc.http20Enabled),
    detailedErrorLoggingEnabled            = tobool(sc.detailedErrorLoggingEnabled),
    alwaysOn                               = tobool(sc.alwaysOn),
    virtualNetworkSubnetId                 = tostring(props.virtualNetworkSubnetId),
    vnetRouteAllEnabled                    = tobool(sc.vnetRouteAllEnabled),
    vnetImagePullEnabled                   = tobool(props.vnetImagePullEnabled),
    storageAccountRequired                 = tobool(props.storageAccountRequired),
    functionsRuntimeScaleMonitoringEnabled = tobool(sc.functionsRuntimeScaleMonitoringEnabled),
    managedEnvironmentId                   = tostring(props.managedEnvironmentId),
    keyVaultReferenceIdentity              = tostring(props.keyVaultReferenceIdentity),
    customDomainCount                      = array_length(props.hostNames),
    enabled                                = tobool(props.enabled),
    state                                  = tostring(props.state),
    reserved                               = tobool(props.reserved),
    serverFarmId                           = tostring(props.serverFarmId),
    functionRuntime                        = tostring(sc.appSettings),
    funcKind                               = tostring(kind),
    linuxFxVersion                         = tostring(sc.linuxFxVersion),
    windowsFxVersion                       = tostring(sc.windowsFxVersion),
    corsAllowedOrigins                     = tostring(sc.cors.allowedOrigins),
    corsSupportCredentials                 = tobool(sc.cors.supportCredentials),
    authEnabled                            = tobool(props.siteAuthEnabled),
    redundancyMode                         = tostring(props.redundancyMode)
"@
}

# -----------------------------------------------------------------------------
# 18) microsoft.sql/servers
# -----------------------------------------------------------------------------
$script:_AzureResourceTypeQueries['microsoft.sql/servers'] = @{
    Type    = 'microsoft.sql/servers'
    Hint    = 'sql-server'
    FieldMap = @{
        'AZ_SqlSrvAdministratorLogin'              = 'administratorLogin'
        'AZ_SqlSrvVersion'                         = 'version'
        'AZ_SqlSrvMinimalTlsVersion'               = 'minimalTlsVersion'
        'AZ_SqlSrvPublicNetworkAccess'             = 'publicNetworkAccess'
        'AZ_SqlSrvRestrictOutboundNetworkAccess'   = 'restrictOutboundNetworkAccess'
        'AZ_SqlSrvAdminAzureADOnlyAuth'            = 'adminAzureADOnlyAuthentication'
        'AZ_SqlSrvAdminAdministratorType'          = 'adminAdministratorType'
        'AZ_SqlSrvAdminPrincipalType'              = 'adminPrincipalType'
        'AZ_SqlSrvAdminLogin'                      = 'adminLogin'
        'AZ_SqlSrvAdminSid'                        = 'adminSid'
        'AZ_SqlSrvAdminTenantId'                   = 'adminTenantId'
        'AZ_SqlSrvFederatedClientId'               = 'federatedClientId'
        'AZ_SqlSrvKeyId'                           = 'keyId'
        'AZ_SqlSrvPrimaryUserAssignedId'           = 'primaryUserAssignedIdentityId'
        'AZ_SqlSrvFqdn'                            = 'fullyQualifiedDomainName'
        'AZ_SqlSrvWorkspaceFeature'                = 'workspaceFeature'
        'AZ_SqlSrvPrivateEndpointCount'            = 'privateEndpointConnectionCount'
        'AZ_SqlSrvState'                           = 'state'
    }
    Kql = @"
resources
| where type =~ 'microsoft.sql/servers'
| extend props = properties
| project id, name, type, location, subscriptionId, resourceGroup, tags, identity,
    administratorLogin                  = tostring(props.administratorLogin),
    version                             = tostring(props.version),
    minimalTlsVersion                   = tostring(props.minimalTlsVersion),
    publicNetworkAccess                 = tostring(props.publicNetworkAccess),
    restrictOutboundNetworkAccess       = tostring(props.restrictOutboundNetworkAccess),
    adminAzureADOnlyAuthentication      = tobool(props.administrators.azureADOnlyAuthentication),
    adminAdministratorType              = tostring(props.administrators.administratorType),
    adminPrincipalType                  = tostring(props.administrators.principalType),
    adminLogin                          = tostring(props.administrators.login),
    adminSid                            = tostring(props.administrators.sid),
    adminTenantId                       = tostring(props.administrators.tenantId),
    federatedClientId                   = tostring(props.federatedClientId),
    keyId                               = tostring(props.keyId),
    primaryUserAssignedIdentityId       = tostring(props.primaryUserAssignedIdentityId),
    fullyQualifiedDomainName            = tostring(props.fullyQualifiedDomainName),
    workspaceFeature                    = tostring(props.workspaceFeature),
    privateEndpointConnectionCount      = array_length(props.privateEndpointConnections),
    state                               = tostring(props.state)
"@
}

# -----------------------------------------------------------------------------
# 19) microsoft.web/sites (kind == 'app' -- Web Apps)
# -----------------------------------------------------------------------------
$script:_AzureResourceTypeQueries['microsoft.web/sites_webapp'] = @{
    Type    = 'microsoft.web/sites'
    Hint    = 'web-app'
    FieldMap = @{
        'AZ_WebHttpsOnly'                       = 'httpsOnly'
        'AZ_WebPublicNetworkAccess'             = 'publicNetworkAccess'
        'AZ_WebClientCertEnabled'               = 'clientCertEnabled'
        'AZ_WebClientCertMode'                  = 'clientCertMode'
        'AZ_WebClientAffinityEnabled'           = 'clientAffinityEnabled'
        'AZ_WebMinTlsVersion'                   = 'minTlsVersion'
        'AZ_WebScmMinTlsVersion'                = 'scmMinTlsVersion'
        'AZ_WebFtpsState'                       = 'ftpsState'
        'AZ_WebScmIpRestrictionsDefaultAction'  = 'scmIpRestrictionsDefaultAction'
        'AZ_WebIpRestrictionsDefaultAction'     = 'ipRestrictionsDefaultAction'
        'AZ_WebScmIpRestrictionCount'           = 'scmIpRestrictionCount'
        'AZ_WebIpRestrictionCount'              = 'ipRestrictionCount'
        'AZ_WebRemoteDebuggingEnabled'          = 'remoteDebuggingEnabled'
        'AZ_WebHttp20Enabled'                   = 'http20Enabled'
        'AZ_WebDetailedErrorLoggingEnabled'     = 'detailedErrorLoggingEnabled'
        'AZ_WebAlwaysOn'                        = 'alwaysOn'
        'AZ_WebVnetSubnetId'                    = 'virtualNetworkSubnetId'
        'AZ_WebVnetRouteAllEnabled'             = 'vnetRouteAllEnabled'
        'AZ_WebSiteAuthEnabled'                 = 'siteAuthEnabled'
        'AZ_WebManagedEnvironmentId'            = 'managedEnvironmentId'
        'AZ_WebKeyVaultReferenceIdentity'       = 'keyVaultReferenceIdentity'
        'AZ_WebHostNamesDisabled'               = 'hostNamesDisabled'
        'AZ_WebRedundancyMode'                  = 'redundancyMode'
        'AZ_WebHostNameSslStateCount'           = 'hostNameSslStateCount'
        'AZ_WebKind'                            = 'webKind'
        'AZ_WebState'                           = 'state'
        'AZ_WebEnabled'                         = 'enabled'
        'AZ_WebServerFarmId'                    = 'serverFarmId'
        'AZ_WebReserved'                        = 'reserved'
        'AZ_WebLinuxFxVersion'                  = 'linuxFxVersion'
        'AZ_WebWindowsFxVersion'                = 'windowsFxVersion'
        'AZ_WebJavaVersion'                     = 'javaVersion'
        'AZ_WebPhpVersion'                      = 'phpVersion'
        'AZ_WebPythonVersion'                   = 'pythonVersion'
        'AZ_WebNodeVersion'                     = 'nodeVersion'
        'AZ_WebCorsAllowedOrigins'              = 'corsAllowedOrigins'
        'AZ_WebCorsSupportCredentials'          = 'corsSupportCredentials'
        'AZ_WebDefaultDocuments'                = 'defaultDocuments'
    }
    Kql = @"
resources
| where type =~ 'microsoft.web/sites'
| where kind == 'app' or kind == 'app,linux'
| extend props = properties, sc = properties.siteConfig
| project id, name, type, location, subscriptionId, resourceGroup, tags, identity,
    httpsOnly                       = tobool(props.httpsOnly),
    publicNetworkAccess             = tostring(props.publicNetworkAccess),
    clientCertEnabled               = tobool(props.clientCertEnabled),
    clientCertMode                  = tostring(props.clientCertMode),
    clientAffinityEnabled           = tobool(props.clientAffinityEnabled),
    minTlsVersion                   = tostring(sc.minTlsVersion),
    scmMinTlsVersion                = tostring(sc.scmMinTlsVersion),
    ftpsState                       = tostring(sc.ftpsState),
    scmIpRestrictionsDefaultAction  = tostring(sc.scmIpSecurityRestrictionsDefaultAction),
    ipRestrictionsDefaultAction     = tostring(sc.ipSecurityRestrictionsDefaultAction),
    scmIpRestrictionCount           = array_length(sc.scmIpSecurityRestrictions),
    ipRestrictionCount              = array_length(sc.ipSecurityRestrictions),
    remoteDebuggingEnabled          = tobool(sc.remoteDebuggingEnabled),
    http20Enabled                   = tobool(sc.http20Enabled),
    detailedErrorLoggingEnabled     = tobool(sc.detailedErrorLoggingEnabled),
    alwaysOn                        = tobool(sc.alwaysOn),
    virtualNetworkSubnetId          = tostring(props.virtualNetworkSubnetId),
    vnetRouteAllEnabled             = tobool(sc.vnetRouteAllEnabled),
    siteAuthEnabled                 = tobool(props.siteAuthEnabled),
    managedEnvironmentId            = tostring(props.managedEnvironmentId),
    keyVaultReferenceIdentity       = tostring(props.keyVaultReferenceIdentity),
    hostNamesDisabled               = tobool(props.hostNamesDisabled),
    redundancyMode                  = tostring(props.redundancyMode),
    hostNameSslStateCount           = array_length(props.hostNameSslStates),
    webKind                         = tostring(kind),
    state                           = tostring(props.state),
    enabled                         = tobool(props.enabled),
    serverFarmId                    = tostring(props.serverFarmId),
    reserved                        = tobool(props.reserved),
    linuxFxVersion                  = tostring(sc.linuxFxVersion),
    windowsFxVersion                = tostring(sc.windowsFxVersion),
    javaVersion                     = tostring(sc.javaVersion),
    phpVersion                      = tostring(sc.phpVersion),
    pythonVersion                   = tostring(sc.pythonVersion),
    nodeVersion                     = tostring(sc.nodeVersion),
    corsAllowedOrigins              = tostring(sc.cors.allowedOrigins),
    corsSupportCredentials          = tobool(sc.cors.supportCredentials),
    defaultDocuments                = tostring(sc.defaultDocuments)
"@
}

# -----------------------------------------------------------------------------
# 20) microsoft.cognitiveservices/accounts (general -- non-OpenAI)
# -----------------------------------------------------------------------------
$script:_AzureResourceTypeQueries['microsoft.cognitiveservices/accounts'] = @{
    Type    = 'microsoft.cognitiveservices/accounts'
    Hint    = 'cognitive-account'
    FieldMap = @{
        'AZ_CogPublicNetworkAccess'    = 'publicNetworkAccess'
        'AZ_CogDisableLocalAuth'       = 'disableLocalAuth'
        'AZ_CogCustomSubDomainName'    = 'customSubDomainName'
        'AZ_CogNetworkAclsDefaultAct'  = 'networkAclsDefaultAction'
        'AZ_CogNetworkAclsBypass'      = 'networkAclsBypass'
        'AZ_CogNetworkAclsIpRulesCount'= 'networkAclsIpRulesCount'
        'AZ_CogNetworkAclsVnetCount'   = 'networkAclsVnetRulesCount'
        'AZ_CogPrivateEndpointCount'   = 'privateEndpointConnectionCount'
        'AZ_CogRestrictOutboundAccess' = 'restrictOutboundNetworkAccess'
        'AZ_CogAllowedFqdnList'        = 'allowedFqdnList'
        'AZ_CogEncryptionKeySource'    = 'encryptionKeySource'
        'AZ_CogEncryptionKeyVaultUri'  = 'encryptionKeyVaultUri'
        'AZ_CogUserOwnedStorageCount'  = 'userOwnedStorageCount'
        'AZ_CogApiProperties'          = 'apiProperties'
        'AZ_CogSkuName'                = 'skuName'
        'AZ_CogKind'                   = 'cogKind'
        'AZ_CogEndpoint'               = 'endpoint'
        'AZ_CogProvisioningState'      = 'provisioningState'
        'AZ_CogDateCreated'            = 'dateCreated'
    }
    Kql = @"
resources
| where type =~ 'microsoft.cognitiveservices/accounts'
| where kind !~ 'OpenAI'
| extend props = properties
| project id, name, type, location, subscriptionId, resourceGroup, tags, identity, sku,
    publicNetworkAccess            = tostring(props.publicNetworkAccess),
    disableLocalAuth               = tobool(props.disableLocalAuth),
    customSubDomainName            = tostring(props.customSubDomainName),
    networkAclsDefaultAction       = tostring(props.networkAcls.defaultAction),
    networkAclsBypass              = tostring(props.networkAcls.bypass),
    networkAclsIpRulesCount        = array_length(props.networkAcls.ipRules),
    networkAclsVnetRulesCount      = array_length(props.networkAcls.virtualNetworkRules),
    privateEndpointConnectionCount = array_length(props.privateEndpointConnections),
    restrictOutboundNetworkAccess  = tobool(props.restrictOutboundNetworkAccess),
    allowedFqdnList                = tostring(props.allowedFqdnList),
    encryptionKeySource            = tostring(props.encryption.keySource),
    encryptionKeyVaultUri          = tostring(props.encryption.keyVaultProperties.keyVaultUri),
    userOwnedStorageCount          = array_length(props.userOwnedStorage),
    apiProperties                  = tostring(props.apiProperties),
    skuName                        = tostring(sku.name),
    cogKind                        = tostring(kind),
    endpoint                       = tostring(props.endpoint),
    provisioningState              = tostring(props.provisioningState),
    dateCreated                    = tostring(props.dateCreated)
"@
}

# -----------------------------------------------------------------------------
# 21) microsoft.containerregistry/registries
# -----------------------------------------------------------------------------
$script:_AzureResourceTypeQueries['microsoft.containerregistry/registries'] = @{
    Type    = 'microsoft.containerregistry/registries'
    Hint    = 'container-registry'
    FieldMap = @{
        'AZ_AcrAdminUserEnabled'             = 'adminUserEnabled'
        'AZ_AcrPublicNetworkAccess'          = 'publicNetworkAccess'
        'AZ_AcrAnonymousPullEnabled'         = 'anonymousPullEnabled'
        'AZ_AcrNetworkRuleBypassOptions'     = 'networkRuleBypassOptions'
        'AZ_AcrNetworkRuleSetDefaultAction'  = 'networkRuleSetDefaultAction'
        'AZ_AcrNetworkRuleIpCount'           = 'networkRuleIpCount'
        'AZ_AcrNetworkRuleVnetCount'         = 'networkRuleVnetCount'
        'AZ_AcrQuarantinePolicyStatus'       = 'quarantinePolicyStatus'
        'AZ_AcrTrustPolicyStatus'            = 'trustPolicyStatus'
        'AZ_AcrTrustPolicyType'              = 'trustPolicyType'
        'AZ_AcrRetentionPolicyStatus'        = 'retentionPolicyStatus'
        'AZ_AcrRetentionPolicyDays'          = 'retentionPolicyDays'
        'AZ_AcrExportPolicyStatus'           = 'exportPolicyStatus'
        'AZ_AcrSoftDeletePolicyStatus'       = 'softDeletePolicyStatus'
        'AZ_AcrSoftDeleteRetentionDays'      = 'softDeleteRetentionDays'
        'AZ_AcrAzureADAuthAsArmPolicyStatus' = 'azureADAuthAsArmPolicyStatus'
        'AZ_AcrEncryptionStatus'             = 'encryptionStatus'
        'AZ_AcrEncryptionKeyVaultId'         = 'encryptionKeyVaultId'
        'AZ_AcrDataEndpointEnabled'          = 'dataEndpointEnabled'
        'AZ_AcrDedicatedDataEndpoints'       = 'dedicatedDataEndpoints'
        'AZ_AcrZoneRedundancy'               = 'zoneRedundancy'
        'AZ_AcrPrivateEndpointCount'         = 'privateEndpointConnectionCount'
        'AZ_AcrSkuName'                      = 'skuName'
        'AZ_AcrSkuTier'                      = 'skuTier'
        'AZ_AcrLoginServer'                  = 'loginServer'
        'AZ_AcrCreationDate'                 = 'creationDate'
        'AZ_AcrProvisioningState'            = 'provisioningState'
        'AZ_AcrStatus'                       = 'status'
    }
    Kql = @"
resources
| where type =~ 'microsoft.containerregistry/registries'
| extend props = properties
| project id, name, type, location, subscriptionId, resourceGroup, tags, identity,
    adminUserEnabled                = tobool(props.adminUserEnabled),
    publicNetworkAccess             = tostring(props.publicNetworkAccess),
    anonymousPullEnabled            = tobool(props.anonymousPullEnabled),
    networkRuleBypassOptions        = tostring(props.networkRuleBypassOptions),
    networkRuleSetDefaultAction     = tostring(props.networkRuleSet.defaultAction),
    networkRuleIpCount              = array_length(props.networkRuleSet.ipRules),
    networkRuleVnetCount            = array_length(props.networkRuleSet.virtualNetworkRules),
    quarantinePolicyStatus          = tostring(props.policies.quarantinePolicy.status),
    trustPolicyStatus               = tostring(props.policies.trustPolicy.status),
    trustPolicyType                 = tostring(props.policies.trustPolicy.type),
    retentionPolicyStatus           = tostring(props.policies.retentionPolicy.status),
    retentionPolicyDays             = toint(props.policies.retentionPolicy.days),
    exportPolicyStatus              = tostring(props.policies.exportPolicy.status),
    softDeletePolicyStatus          = tostring(props.policies.softDeletePolicy.status),
    softDeleteRetentionDays         = toint(props.policies.softDeletePolicy.retentionDays),
    azureADAuthAsArmPolicyStatus    = tostring(props.policies.azureADAuthenticationAsArmPolicy.status),
    encryptionStatus                = tostring(props.encryption.status),
    encryptionKeyVaultId            = tostring(props.encryption.keyVaultProperties.keyIdentifier),
    dataEndpointEnabled             = tobool(props.dataEndpointEnabled),
    dedicatedDataEndpoints          = tostring(props.dataEndpointHostNames),
    zoneRedundancy                  = tostring(props.zoneRedundancy),
    privateEndpointConnectionCount  = array_length(props.privateEndpointConnections),
    skuName                         = tostring(sku.name),
    skuTier                         = tostring(sku.tier),
    loginServer                     = tostring(props.loginServer),
    creationDate                    = tostring(props.creationDate),
    provisioningState               = tostring(props.provisioningState),
    status                          = tostring(props.status)
"@
}

# -----------------------------------------------------------------------------
# 22) microsoft.cognitiveservices/accounts ('project' kind -- Azure AI Foundry projects)
# Many tenants don't have this kind yet; query is safe (returns empty if none).
# -----------------------------------------------------------------------------
$script:_AzureResourceTypeQueries['microsoft.cognitiveservices/accounts_project'] = @{
    Type    = 'microsoft.cognitiveservices/accounts'
    Hint    = 'azure-ai-project'
    FieldMap = @{
        'AZ_AiProjPublicNetworkAccess'  = 'publicNetworkAccess'
        'AZ_AiProjDisableLocalAuth'     = 'disableLocalAuth'
        'AZ_AiProjAllowProjectMgmt'     = 'allowProjectManagement'
        'AZ_AiProjDefaultProject'       = 'defaultProject'
        'AZ_AiProjAssociatedProjects'   = 'associatedProjects'
        'AZ_AiProjEncryptionKeySource'  = 'encryptionKeySource'
        'AZ_AiProjEncryptionKeyVaultUri'= 'encryptionKeyVaultUri'
        'AZ_AiProjNetworkAclsDefaultAct'= 'networkAclsDefaultAction'
        'AZ_AiProjNetworkAclsBypass'    = 'networkAclsBypass'
        'AZ_AiProjPrivateEndpointCount' = 'privateEndpointConnectionCount'
        'AZ_AiProjEndpoint'             = 'endpoint'
        'AZ_AiProjEndpoints'            = 'endpoints'
        'AZ_AiProjSkuName'              = 'skuName'
        'AZ_AiProjKind'                 = 'aiProjKind'
        'AZ_AiProjProvisioningState'    = 'provisioningState'
    }
    Kql = @"
resources
| where type =~ 'microsoft.cognitiveservices/accounts'
| where kind in~ ('AIServices', 'Hub', 'Project')
| extend props = properties
| project id, name, type, location, subscriptionId, resourceGroup, tags, identity, sku,
    publicNetworkAccess            = tostring(props.publicNetworkAccess),
    disableLocalAuth               = tobool(props.disableLocalAuth),
    allowProjectManagement         = tobool(props.allowProjectManagement),
    defaultProject                 = tostring(props.defaultProject),
    associatedProjects             = tostring(props.associatedProjects),
    encryptionKeySource            = tostring(props.encryption.keySource),
    encryptionKeyVaultUri          = tostring(props.encryption.keyVaultProperties.keyVaultUri),
    networkAclsDefaultAction       = tostring(props.networkAcls.defaultAction),
    networkAclsBypass              = tostring(props.networkAcls.bypass),
    privateEndpointConnectionCount = array_length(props.privateEndpointConnections),
    endpoint                       = tostring(props.endpoint),
    endpoints                      = tostring(props.endpoints),
    skuName                        = tostring(sku.name),
    aiProjKind                     = tostring(kind),
    provisioningState              = tostring(props.provisioningState)
"@
}

# -----------------------------------------------------------------------------
# 23) microsoft.network/applicationgateways
# -----------------------------------------------------------------------------
$script:_AzureResourceTypeQueries['microsoft.network/applicationgateways'] = @{
    Type    = 'microsoft.network/applicationgateways'
    Hint    = 'application-gateway'
    FieldMap = @{
        'AZ_AgwSkuName'                          = 'skuName'
        'AZ_AgwSkuTier'                          = 'skuTier'
        'AZ_AgwSkuCapacity'                      = 'skuCapacity'
        'AZ_AgwAutoscaleMinCapacity'             = 'autoscaleMinCapacity'
        'AZ_AgwAutoscaleMaxCapacity'             = 'autoscaleMaxCapacity'
        'AZ_AgwOperationalState'                 = 'operationalState'
        'AZ_AgwProvisioningState'                = 'provisioningState'
        'AZ_AgwEnableHttp2'                      = 'enableHttp2'
        'AZ_AgwEnableFips'                       = 'enableFips'
        'AZ_AgwForceFirewallPolicyAssoc'         = 'forceFirewallPolicyAssociation'
        'AZ_AgwWafEnabled'                       = 'wafEnabled'
        'AZ_AgwWafFirewallMode'                  = 'wafFirewallMode'
        'AZ_AgwWafRuleSetType'                   = 'wafRuleSetType'
        'AZ_AgwWafRuleSetVersion'                = 'wafRuleSetVersion'
        'AZ_AgwWafFileUploadLimitMb'             = 'wafFileUploadLimitInMb'
        'AZ_AgwWafMaxRequestBodySizeKb'          = 'wafMaxRequestBodySizeInKb'
        'AZ_AgwWafRequestBodyCheck'              = 'wafRequestBodyCheck'
        'AZ_AgwWafExclusionsCount'               = 'wafExclusionsCount'
        'AZ_AgwWafDisabledRuleGroupsCount'       = 'wafDisabledRuleGroupsCount'
        'AZ_AgwFirewallPolicyId'                 = 'firewallPolicyId'
        'AZ_AgwSslPolicyType'                    = 'sslPolicyType'
        'AZ_AgwSslPolicyName'                    = 'sslPolicyName'
        'AZ_AgwSslMinProtocolVersion'            = 'sslMinProtocolVersion'
        'AZ_AgwSslCipherSuites'                  = 'sslCipherSuites'
        'AZ_AgwSslDisabledProtocols'             = 'sslDisabledProtocols'
        'AZ_AgwHttpListenerCount'                = 'httpListenerCount'
        'AZ_AgwHttpListenerProtocols'            = 'httpListenerProtocols'
        'AZ_AgwFrontendIpCount'                  = 'frontendIpCount'
        'AZ_AgwFrontendPublicIpCount'            = 'frontendPublicIpCount'
        'AZ_AgwFrontendPrivateIpCount'           = 'frontendPrivateIpCount'
        'AZ_AgwBackendPoolCount'                 = 'backendPoolCount'
        'AZ_AgwBackendHttpSettingsCount'         = 'backendHttpSettingsCount'
        'AZ_AgwSslCertificateCount'              = 'sslCertificateCount'
        'AZ_AgwTrustedRootCertCount'             = 'trustedRootCertificateCount'
        'AZ_AgwTrustedClientCertCount'           = 'trustedClientCertificateCount'
        'AZ_AgwAuthenticationCertCount'          = 'authenticationCertificateCount'
        'AZ_AgwUrlPathMapCount'                  = 'urlPathMapCount'
        'AZ_AgwRedirectConfigCount'              = 'redirectConfigurationCount'
        'AZ_AgwRequestRoutingRuleCount'          = 'requestRoutingRuleCount'
        'AZ_AgwRewriteRuleSetCount'              = 'rewriteRuleSetCount'
        'AZ_AgwCustomErrorConfigCount'           = 'customErrorConfigurationCount'
        'AZ_AgwPrivateEndpointCount'             = 'privateEndpointConnectionCount'
        'AZ_AgwZones'                            = 'agwZones'
    }
    Kql = @"
resources
| where type =~ 'microsoft.network/applicationgateways'
| extend props = properties, waf = properties.webApplicationFirewallConfiguration, ssl = properties.sslPolicy
| project id, name, type, location, subscriptionId, resourceGroup, tags, identity,
    skuName                          = tostring(props.sku.name),
    skuTier                          = tostring(props.sku.tier),
    skuCapacity                      = toint(props.sku.capacity),
    autoscaleMinCapacity             = toint(props.autoscaleConfiguration.minCapacity),
    autoscaleMaxCapacity             = toint(props.autoscaleConfiguration.maxCapacity),
    operationalState                 = tostring(props.operationalState),
    provisioningState                = tostring(props.provisioningState),
    enableHttp2                      = tobool(props.enableHttp2),
    enableFips                       = tobool(props.enableFips),
    forceFirewallPolicyAssociation   = tobool(props.forceFirewallPolicyAssociation),
    wafEnabled                       = tobool(waf.enabled),
    wafFirewallMode                  = tostring(waf.firewallMode),
    wafRuleSetType                   = tostring(waf.ruleSetType),
    wafRuleSetVersion                = tostring(waf.ruleSetVersion),
    wafFileUploadLimitInMb           = toint(waf.fileUploadLimitInMb),
    wafMaxRequestBodySizeInKb        = toint(waf.maxRequestBodySizeInKb),
    wafRequestBodyCheck              = tobool(waf.requestBodyCheck),
    wafExclusionsCount               = array_length(waf.exclusions),
    wafDisabledRuleGroupsCount       = array_length(waf.disabledRuleGroups),
    firewallPolicyId                 = tostring(props.firewallPolicy.id),
    sslPolicyType                    = tostring(ssl.policyType),
    sslPolicyName                    = tostring(ssl.policyName),
    sslMinProtocolVersion            = tostring(ssl.minProtocolVersion),
    sslCipherSuites                  = tostring(ssl.cipherSuites),
    sslDisabledProtocols             = tostring(ssl.disabledSslProtocols),
    httpListenerCount                = array_length(props.httpListeners),
    httpListenerProtocols            = tostring(props.httpListeners),
    frontendIpCount                  = array_length(props.frontendIPConfigurations),
    frontendPublicIpCount            = toint(0),
    frontendPrivateIpCount           = toint(0),
    backendPoolCount                 = array_length(props.backendAddressPools),
    backendHttpSettingsCount         = array_length(props.backendHttpSettingsCollection),
    sslCertificateCount              = array_length(props.sslCertificates),
    trustedRootCertificateCount      = array_length(props.trustedRootCertificates),
    trustedClientCertificateCount    = array_length(props.trustedClientCertificates),
    authenticationCertificateCount   = array_length(props.authenticationCertificates),
    urlPathMapCount                  = array_length(props.urlPathMaps),
    redirectConfigurationCount       = array_length(props.redirectConfigurations),
    requestRoutingRuleCount          = array_length(props.requestRoutingRules),
    rewriteRuleSetCount              = array_length(props.rewriteRuleSets),
    customErrorConfigurationCount    = array_length(props.customErrorConfigurations),
    privateEndpointConnectionCount   = array_length(props.privateEndpointConnections),
    agwZones                         = tostring(zones)
"@
}

# =============================================================================
# Public functions
# =============================================================================

function Invoke-SIAzureSecurityQuery {
    <#
    .SYNOPSIS
        Run a per-type Azure Resource Graph security-projection query.
    .PARAMETER ResourceType
        Canonical lowercase ARM type, OR one of the synthetic suffix keys for
        the cognitiveservices/accounts variants ('microsoft.cognitiveservices/
        accounts_openai', 'microsoft.cognitiveservices/accounts_project') OR
        the web/sites variants ('microsoft.web/sites_webapp',
        'microsoft.web/sites_azurefunction').
    .PARAMETER SubscriptionIds
        Optional subscription scope. Empty = all visible subs.
    .OUTPUTS
        Raw rows from Search-AzGraph (caller projects to AZ_<Field> emit shape).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$ResourceType,
        [Parameter()][string[]]$SubscriptionIds = @()
    )

    $key = $ResourceType.ToLowerInvariant()
    if (-not $script:_AzureResourceTypeQueries.ContainsKey($key)) {
        Write-Warning ("Invoke-SIAzureSecurityQuery: no entry for resource type '{0}'" -f $ResourceType)
        return @()
    }

    $entry = $script:_AzureResourceTypeQueries[$key]
    if (-not (Get-Command -Name Search-AzGraph -ErrorAction SilentlyContinue)) {
        Write-Warning "Invoke-SIAzureSecurityQuery: Search-AzGraph not available (Az.ResourceGraph not loaded)."
        return @()
    }

    $rows = New-Object System.Collections.ArrayList
    $skipToken = $null
    do {
        $params = @{ Query = $entry.Kql; First = 1000 }
        if ($SubscriptionIds.Count -gt 0) { $params['Subscription'] = $SubscriptionIds }
        if ($skipToken)                    { $params['SkipToken']    = $skipToken }
        try {
            $page = Search-AzGraph @params
        } catch {
            Write-Warning ("Invoke-SIAzureSecurityQuery: Search-AzGraph failed for '{0}' -- {1}" -f $ResourceType, $_.Exception.Message)
            break
        }
        foreach ($r in $page) { [void]$rows.Add($r) }
        $skipToken = $page.SkipToken
    } while ($skipToken)

    return $rows
}

function Get-SIAzureSecurityFieldsForType {
    <#
    .SYNOPSIS
        Return the FieldMap (AZ_EmitKey -> ARG-projected-column-name) for a
        registered resource type. Discovery iterates this to build emit rows.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$ResourceType
    )
    $key = $ResourceType.ToLowerInvariant()
    if (-not $script:_AzureResourceTypeQueries.ContainsKey($key)) {
        return @{}
    }
    return $script:_AzureResourceTypeQueries[$key].FieldMap
}

function Get-SIAzureSecurityQueryEntry {
    <#
    .SYNOPSIS
        Return the full entry (Type/Hint/Kql/FieldMap) for a registered type.
        Useful for the orchestrator's wiring/inventory step.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$ResourceType
    )
    $key = $ResourceType.ToLowerInvariant()
    if (-not $script:_AzureResourceTypeQueries.ContainsKey($key)) {
        return $null
    }
    return $script:_AzureResourceTypeQueries[$key]
}

function Get-SIAzureSecurityQueryKeys {
    <#
    .SYNOPSIS
        List all registered query keys (24 entries: 22 types + 2 synthetic
        cognitiveservices variants beyond the base entry, +1 web/sites variant
        beyond the base, depending on count).
    #>
    [CmdletBinding()]
    param()
    return @($script:_AzureResourceTypeQueries.Keys | Sort-Object)
}
