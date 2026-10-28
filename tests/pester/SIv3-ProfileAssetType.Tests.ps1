#Requires -Version 5.1
<#
    #562 THE PROFILE TABLES' AssetType / AssetSubtype COME FROM THE ONE CLASSIFICATION -- the rows the CI build uses.

    Found live 2026-10-10 on the first ring (latest row per asset): SI_Endpoint_Profile_CL had about half its devices
    'Unknown', domain controllers / servers 'Workstation' (the Classify stage's AI error fallback), switches and routers
    'Unknown', a WLAN access point 'IoT', AssetSubtype empty on every row; SI_Azure_Profile_CL mixed raw ARM types with
    'AzureResource'. The fixtures below are those rows' shapes (Defender / Exposure Graph spellings as they arrive).

    What these keep true:
      1. EVERY ENDPOINT A REAL TYPE where the source allows it -- device type, then device category, then the operating
         system; Unknown ONLY when the sources say nothing (no type, no category, an OS that names no kind of device).
      2. THE SUBTYPE IS FILLED -- server role (SQL Server first, then Domain controller ...), device subtype (Switch,
         Router, Printer ...), else the OS family.
      3. THE SQL TAG -- a SQL host found by the profile's own detection rules is Server / SQL Server with component SQL;
         an Azure SQL resource Database / SQL Database with SQL.
      4. ONE MAPPING -- the profile reads the same value maps and rows as the CI build; the Exposure Graph label
         normalisation is the same expression in the eg mapping and the profile.
    Offline; PS 7 (v3 gate). Nothing is sent anywhere.
#>

BeforeAll {
    $script:SIRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    . (Join-Path $script:SIRoot 'engine\data-model\SI-DataModelTemplates.ps1')
    . (Join-Path $script:SIRoot 'engine\data-model\SI-ProfileClassification.ps1')
    $script:Model = Get-SIDataModel
    $script:Index = New-SIClassificationIndex -Dimensions $script:Model['dimensions'] -Classification $script:Model['classification']
    $script:Maps = $script:Model['value-maps'].maps

    function script:Ep {
        param([string]$DeviceType = '', [string]$DeviceCategory = '', [string]$DeviceSubtype = '', [string]$OsPlatform = '', $DeviceRole = $null, $SIRules = $null, [switch]$Dc)
        $it = ConvertTo-SIEndpointClassificationItem -Maps $script:Maps -DeviceType $DeviceType -DeviceCategory $DeviceCategory -DeviceSubtype $DeviceSubtype `
            -OsPlatform $OsPlatform -DeviceRoles $DeviceRole -IsDomainController ([bool]$Dc) -RuleIds $SIRules
        Get-SIProfileAssetClassification -Item $it -Index $script:Index
    }
    function script:Az([string]$Type) { Get-SIProfileAssetClassification -Item (ConvertTo-SIAzureClassificationItem -ResourceType $Type) -Index $script:Index }
}

Describe 'endpoints: a real type wherever the source allows it (#562)' {
    It 'Defender device type <dt> / <sub> (<os>) -> <type> / <subtype>' -ForEach @(
        @{ dt = 'Workstation'; cat = 'Endpoint'; sub = 'Workstation'; os = 'Windows11'; type = 'Workstation'; subtype = 'Windows' }
        @{ dt = 'Workstation'; cat = 'Endpoint'; sub = 'Workstation'; os = 'MacOs'; type = 'Workstation'; subtype = 'macOS' }
        @{ dt = 'Server'; cat = 'Endpoint'; sub = 'Server'; os = 'WindowsServer2022'; type = 'Server'; subtype = 'Windows Server' }
        @{ dt = 'Mobile'; cat = 'Endpoint'; sub = 'Unknown'; os = 'iOS'; type = 'Mobile'; subtype = 'iOS' }
        @{ dt = 'NetworkDevice'; cat = 'NetworkDevice'; sub = 'Switch'; os = 'Linux'; type = 'Network device'; subtype = 'Switch' }
        @{ dt = 'NetworkDevice'; cat = 'NetworkDevice'; sub = 'Router'; os = 'UnifiOS'; type = 'Network device'; subtype = 'Router' }
        @{ dt = 'NetworkDevice'; cat = 'NetworkDevice'; sub = 'WLANAccessPoint'; os = 'Linux'; type = 'Network device'; subtype = 'Wireless access point' }
        @{ dt = 'NetworkDevice'; cat = 'NetworkDevice'; sub = 'Unknown'; os = 'CiscoXR'; type = 'Network device'; subtype = 'General' }
        @{ dt = 'Printer'; cat = 'IoT'; sub = 'AllInOne'; os = 'EmbeddedOs'; type = 'Printer'; subtype = 'Multifunction printer' }
        @{ dt = 'Printer'; cat = 'IoT'; sub = 'Printer'; os = 'EmbeddedOs'; type = 'Printer'; subtype = 'Printer' }
        @{ dt = 'AudioAndVideo'; cat = 'IoT'; sub = 'SmartTV'; os = 'Tizen'; type = 'IoT'; subtype = 'Smart TV' }
        @{ dt = 'AudioAndVideo'; cat = 'IoT'; sub = 'Speaker'; os = 'Linux'; type = 'IoT'; subtype = 'Speaker' }
        @{ dt = 'SmartAppliance'; cat = 'IoT'; sub = 'SmartHome'; os = 'Debian'; type = 'IoT'; subtype = 'Smart home device' }
        @{ dt = 'AudioAndVideo'; cat = 'IoT'; sub = 'Unknown'; os = 'Other'; type = 'IoT'; subtype = 'General' }
    ) {
        $c = Ep -DeviceType $dt -DeviceCategory $cat -DeviceSubtype $sub -OsPlatform $os
        $c.Type | Should -Be $type
        $c.Subtype | Should -Be $subtype
    }

    It 'a discovered server Defender has no device type for (CanBeOnboarded) is a Server, from its OS' {
        $c = Ep -OsPlatform 'WindowsServer2019'
        $c.Type | Should -Be 'Server'; $c.Subtype | Should -Be 'Windows Server'
    }
    It 'an onboarded Windows 11 / Android device with no device type: Workstation / Mobile from the OS' {
        (Ep -OsPlatform 'Windows11').Type | Should -Be 'Workstation'
        $a = Ep -OsPlatform 'Android'; $a.Type | Should -Be 'Mobile'; $a.Subtype | Should -Be 'Android'
    }
    It 'a device whose category alone is known takes it (Network device / IoT)' {
        (Ep -DeviceType 'Unknown' -DeviceCategory 'NetworkDevice' -OsPlatform 'Other').Type | Should -Be 'Network device'
        (Ep -DeviceType 'Unknown' -DeviceCategory 'IoT' -OsPlatform 'Other').Type | Should -Be 'IoT'
    }
    It 'Unknown ONLY when the sources say nothing (InsufficientInfo: type, category and subtype Unknown, OS Other or Linux)' {
        $c = Ep -DeviceType 'Unknown' -DeviceCategory 'Unknown' -DeviceSubtype 'Unknown' -OsPlatform 'Other'
        $c.Type | Should -Be 'Unknown'; $c.Subtype | Should -Be 'General'
        (Ep -DeviceType 'Unknown' -DeviceCategory 'Unknown' -OsPlatform 'Linux').Type | Should -Be 'Unknown' -Because 'Linux alone names no kind of device'
        (Ep).Type | Should -Be 'Unknown'
    }
    It 'every endpoint value is a value of the asset_type dimension (never the Classify stage''s free text)' {
        $vals = @(@($script:Model['dimensions'].dimensions | Where-Object { $_.id -eq 'asset_type' })[0].values)
        foreach ($dt in 'Workstation', 'Server', 'Mobile', 'NetworkDevice', 'Printer', 'IoT', 'AudioAndVideo', 'SmartAppliance', 'Unknown', '', 'SomethingNew') {
            $vals | Should -Contain (Ep -DeviceType $dt -OsPlatform 'Other').Type -Because $dt
        }
        $vals | Should -Not -Contain 'DomainController'
    }
}

Describe 'endpoints: roles and the SQL tag' {
    It 'a domain controller (Exposure Graph deviceRole) is Server / Domain controller -- the live dc rows read Workstation before' {
        $c = Ep -DeviceType 'Server' -DeviceCategory 'Endpoint' -DeviceSubtype 'Server' -OsPlatform 'WindowsServer2019' -DeviceRole '["DomainController"]' -SIRules @([pscustomobject]@{ RuleId = 'ADDomainController'; DetectionId = 'ADDomainController'; Tier = 0 })
        $c.Type | Should -Be 'Server'; $c.Subtype | Should -Be 'Domain controller'
    }
    It 'the Exposure Graph isDomainController flag alone makes it a Domain controller' {
        (Ep -DeviceType 'Server' -OsPlatform 'WindowsServer2022' -Dc).Subtype | Should -Be 'Domain controller'
    }
    It 'a server the profile''s own detection rules see as SQL Server: Server / SQL Server, component SQL (SQL first, over the DC role)' {
        $rules = @([pscustomobject]@{ RuleId = 'MicrosoftSqlServer'; DetectionId = 'MicrosoftSqlServer'; Tier = 2 })
        $c = Ep -DeviceType 'Server' -DeviceCategory 'Endpoint' -OsPlatform 'WindowsServer2022' -SIRules $rules
        $c.Type | Should -Be 'Server'; $c.Subtype | Should -Be 'SQL Server'; @($c.Components) | Should -Contain 'SQL'
        $both = Ep -DeviceType 'Server' -OsPlatform 'WindowsServer2022' -DeviceRole '["DomainController"]' -SIRules @([pscustomobject]@{ RuleId = 'SQLServerHostingSensitiveDatabases' })
        $both.Subtype | Should -Be 'SQL Server'; @($both.Components) | Should -Be @('OS', 'SQL')
    }
    It 'the rule hits arrive as JSON text too (the SIRules column read back)' {
        (Ep -DeviceType 'Server' -OsPlatform 'WindowsServer2022' -SIRules '[{"RuleId":"MicrosoftSqlServer","DetectionId":"MicrosoftSqlServer","Tier":2}]').Subtype | Should -Be 'SQL Server'
    }
    It 'a host NAME is no role: a thermostat called Nest-DC14 stays IoT (the IsDomainController column''s hostname guess is not read)' {
        $c = Ep -DeviceType 'SmartAppliance' -DeviceCategory 'IoT' -DeviceSubtype 'SmartHome' -OsPlatform 'Debian'
        $c.Type | Should -Be 'IoT'; $c.Subtype | Should -Not -Be 'Domain controller'
    }
    It 'a rule hit that names no role changes nothing' {
        (Ep -DeviceType 'Server' -OsPlatform 'WindowsServer2022' -SIRules @([pscustomobject]@{ RuleId = 'AssetProfileByLogonUser' })).Subtype | Should -Be 'Windows Server'
    }
}

Describe 'Azure: one SI type + subtype for every resource type, the raw type kept' {
    It '<t> -> <type> / <sub>' -ForEach @(
        @{ t = 'microsoft.insights/datacollectionrules'; type = 'Monitoring'; sub = 'Data collection rule' }
        @{ t = 'microsoft.insights/metricalerts'; type = 'Monitoring'; sub = 'Alert rule' }
        @{ t = 'microsoft.operationalinsights/workspaces'; type = 'Monitoring'; sub = 'Log Analytics workspace' }
        @{ t = 'microsoft.app/jobs'; type = 'Container'; sub = 'Container app job' }
        @{ t = 'microsoft.app/containerapps'; type = 'Container'; sub = 'Container app' }
        @{ t = 'microsoft.containerregistry/registries'; type = 'Container'; sub = 'Container registry' }
        @{ t = 'microsoft.sql/servers/databases'; type = 'Database'; sub = 'SQL Database' }
        @{ t = 'microsoft.sql/servers'; type = 'Database'; sub = 'SQL logical server' }
        @{ t = 'microsoft.sql/managedinstances'; type = 'Database'; sub = 'SQL Managed Instance' }
        @{ t = 'microsoft.sql/firewallrules'; type = 'Database'; sub = 'SQL firewall rule' }
        @{ t = 'microsoft.dbforpostgresql/flexibleservers'; type = 'Database'; sub = 'PostgreSQL' }
        @{ t = 'microsoft.sqlvirtualmachine/sqlvirtualmachines'; type = 'Server'; sub = 'SQL Server' }
        @{ t = 'microsoft.compute/virtualmachines'; type = 'Server'; sub = 'Virtual machine' }
        @{ t = 'microsoft.compute/virtualmachines/extensions'; type = 'Compute'; sub = 'VM extension' }
        @{ t = 'microsoft.compute/disks'; type = 'Compute'; sub = 'Disk' }
        @{ t = 'microsoft.compute/restorepointcollections'; type = 'Backup'; sub = 'Restore points' }
        @{ t = 'microsoft.network/virtualnetworks/subnets'; type = 'Network'; sub = 'Subnet' }
        @{ t = 'microsoft.network/networksecuritygroups'; type = 'Network'; sub = 'Network security group' }
        @{ t = 'microsoft.network/publicipaddresses'; type = 'Public IP'; sub = 'Public IP address' }
        @{ t = 'microsoft.storage/storageaccounts'; type = 'Storage'; sub = 'Storage account' }
        @{ t = 'microsoft.keyvault/vaults'; type = 'Key vault'; sub = 'Key vault' }
        @{ t = 'microsoft.web/sites'; type = 'Web app'; sub = 'App Service' }
        @{ t = 'microsoft.web/sites/slots'; type = 'Web app'; sub = 'App Service' }
        @{ t = 'microsoft.web/serverfarms'; type = 'Web app'; sub = 'App Service plan' }
        @{ t = 'microsoft.web/connections'; type = 'Integration'; sub = 'API connection' }
        @{ t = 'microsoft.logic/workflows'; type = 'Integration'; sub = 'Logic app' }
        @{ t = 'microsoft.eventgrid/systemtopics'; type = 'Integration'; sub = 'Event Grid' }
        @{ t = 'microsoft.cognitiveservices/accounts'; type = 'AI'; sub = 'AI service' }
        @{ t = 'microsoft.managedidentity/userassignedidentities'; type = 'Managed identity'; sub = 'User-assigned identity' }
        @{ t = 'microsoft.recoveryservices/vaults'; type = 'Backup'; sub = 'Recovery Services vault' }
        @{ t = 'microsoft.purview/accounts'; type = 'Security'; sub = 'Purview account' }
        @{ t = 'microsoft.maintenance/maintenanceconfigurations'; type = 'Management'; sub = 'Maintenance configuration' }
        @{ t = 'microsoft.portal/dashboards'; type = 'Monitoring'; sub = 'Dashboard' }
    ) {
        $c = Az $t
        $c.Type | Should -Be $type
        $c.Subtype | Should -Be $sub
    }
    It 'Exposure Graph node labels read as their ARM type (<l>)' -ForEach @(
        @{ l = 'microsoft.web/sites_webapp'; type = 'Web app'; rt = 'microsoft.web/sites' }
        @{ l = 'microsoft.cognitiveservices/accounts_openai'; type = 'AI'; rt = 'microsoft.cognitiveservices/accounts' }
        @{ l = 'azure-microsoft.cognitiveservices/accounts/project'; type = 'AI'; rt = 'microsoft.cognitiveservices/accounts/project' }
    ) {
        ConvertTo-SIAzureResourceTypeName $l | Should -Be $rt
        (Az $l).Type | Should -Be $type
    }
    It 'Azure SQL resources carry the SQL component; other resources do not' {
        foreach ($t in 'microsoft.sql/servers/databases', 'microsoft.sql/servers', 'microsoft.sql/firewallrules', 'microsoft.sqlvirtualmachine/sqlvirtualmachines') { @((Az $t).Components) | Should -Contain 'SQL' -Because $t }
        @((Az 'microsoft.insights/datacollectionrules').Components) | Should -Not -Contain 'SQL'
    }
    It 'a type no row names is Other / General, an empty type Other -- never the raw type' {
        $c = Az 'microsoft.contoso/widgets'; $c.Type | Should -Be 'Other'; $c.Subtype | Should -Be 'General'
        (Az '').Type | Should -Be 'Other'
    }
}

Describe 'identities and public IPs speak the same vocabulary (no more ManagedIdentity / MultiTenantSP / PublicIP)' {
    It 'an Entra <kind> (<ut><spt>) -> <type> / <sub>' -ForEach @(
        @{ kind = 'User'; ut = 'Member'; spt = ''; type = 'User'; sub = 'Member' }
        @{ kind = 'User'; ut = 'Guest'; spt = ''; type = 'Guest'; sub = 'Guest' }
        @{ kind = 'User'; ut = ''; spt = ''; type = 'User'; sub = 'Member' }
        @{ kind = 'ServicePrincipal'; ut = ''; spt = 'Application'; type = 'Service principal'; sub = 'Application' }
        @{ kind = 'ServicePrincipal'; ut = ''; spt = 'ManagedIdentity'; type = 'Managed identity'; sub = 'Managed identity' }
        @{ kind = 'ServicePrincipal'; ut = ''; spt = 'Legacy'; type = 'Service principal'; sub = 'Application' }
        @{ kind = 'ServicePrincipal'; ut = ''; spt = 'SocialIdp'; type = 'Service principal'; sub = 'Application' }
        # a directory group is typed Group / Group since 2026-10-12; a kind no row names stays Other / General
        @{ kind = 'Group'; ut = ''; spt = ''; type = 'Group'; sub = 'Group' }
        @{ kind = 'Computer'; ut = ''; spt = ''; type = 'Other'; sub = 'General' }
    ) {
        $c = Get-SIProfileAssetClassification -Item (ConvertTo-SIIdentityClassificationItem -Maps $script:Maps -Kind $kind -UserType $ut -ServicePrincipalType $spt) -Index $script:Index
        $c.Type | Should -Be $type
        $c.Subtype | Should -Be $sub
    }
    It 'a public IP is Public IP / Public IP address (the dimension''s spelling)' {
        $c = Get-SIProfileAssetClassification -Item (ConvertTo-SIPublicIpClassificationItem) -Index $script:Index
        $c.Type | Should -Be 'Public IP'; $c.Subtype | Should -Be 'Public IP address'
    }
    It 'the identity and public IP builders write AssetType / AssetSubtype from the classification; the schemas declare both' {
        $i = [IO.File]::ReadAllText((Join-Path $script:SIRoot 'engine\asset-profiling\shared\Build-IdentityProfileRow.ps1'))
        $i | Should -Match 'ConvertTo-SIIdentityClassificationItem -Maps \(Get-SIProfileValueMaps\)'
        $i | Should -Match "\`$row\['AssetType'\] = \`$cls\.Type; \`$row\['AssetSubtype'\] = \`$cls\.Subtype"
        $pip = [IO.File]::ReadAllText((Join-Path $script:SIRoot 'engine\asset-profiling\shared\Build-PublicIpProfileRow.ps1'))
        $pip | Should -Match 'Get-SIProfileAssetClassification -Item \(ConvertTo-SIPublicIpClassificationItem\)'
        foreach ($s in 'identity', 'public-ip') {
            $j = Get-Content -Raw (Join-Path $script:SIRoot ("asset-profiling-schema\{0}.schema.locked.json" -f $s)) | ConvertFrom-Json
            foreach ($n in 'AssetType', 'AssetSubtype') { @($j.fields | Where-Object { $_.name -eq $n }).Count | Should -Be 1 -Because "$s declares $n" }
        }
    }
    It 'the Classify stage''s AI error fallback says Unknown, never Workstation' {
        $c = [IO.File]::ReadAllText((Join-Path $script:SIRoot 'engine\asset-profiling\stages\Invoke-Classify.ps1'))
        $c | Should -Match "elseif \(\`$hasExch\) \{ 'ExchangeServer' \} else \{ 'Unknown' \}"
    }
}
Describe 'ONE mapping: the profile and the CI build read the same data' {
    It 'the device type / category value maps the profile uses are the mde / eg mappings'' maps' {
        foreach ($p in 'mde', 'eg') {
            $m = @($script:Model.Mappings[$p].mappings | Where-Object { $_.field -eq 'si_asset_type' })[0]
            @($m.normalize) | Should -Contain 'enum:device_type' -Because $p
            $c = @($script:Model.Mappings[$p].mappings | Where-Object { $_.field -eq 'si_device_category' })[0]
            @($c.normalize) | Should -Contain 'enum:device_category' -Because $p
            @($script:Model.Mappings[$p].mappings | Where-Object { $_.field -eq 'si_device_subtype' }).Count | Should -Be 1 -Because "$p maps the device subtype the subtype rows read"
        }
        $script:Maps.device_type.Printer | Should -Be 'printer'
        $script:Maps.device_type.AudioAndVideo | Should -Be 'iot'
    }
    It 'the eg mapping normalises a node label with the same expression as the profile' {
        $m = @($script:Model.Mappings['eg'].mappings | Where-Object { $_.field -eq 'si_azure_resource_type' })[0]
        @($m.normalize) | Should -Contain ('regex_extract:' + $script:SIAzureResourceTypePattern)
    }
    It 'the CI build classifies a CI from the same fields to the same values (a printer, a discovered server, an unknown device)' {
        function Ci([hashtable]$F) { $ci = [ordered]@{}; foreach ($k in $F.Keys) { $ci[$k] = $F[$k] }; $null = Invoke-SIAssetClassification -Ci $ci -Index $script:Index -Context @{}; $ci }
        (Ci @{ si_class = 'device'; si_asset_type = 'printer' }).si_asset_type | Should -Be 'Printer'
        (Ci @{ si_class = 'device'; si_os_platform = 'windows_server' }).si_asset_type | Should -Be 'Server'
        (Ci @{ si_class = 'device'; si_asset_type = 'unknown'; si_os_platform = 'other' }).si_asset_type | Should -Be 'Unknown'
        (Ci @{ si_class = 'device'; si_asset_type = 'network_device'; si_device_subtype = 'Switch' }).si_asset_subtype | Should -Be 'Switch'
        $vm = Ci @{ si_class = 'device'; si_asset_type = 'server'; si_os_platform = 'windows_server'; si_azure_resource_type = 'microsoft.compute/virtualmachines' }
        $vm.si_asset_type | Should -Be 'Server' -Because 'the Compute catch-all sits below the VM row'
    }
    It 'the whole data model still validates (dimensions, rows, the field catalog the rows read)' {
        @(Test-SIDataModel -Model $script:Model) | Should -BeNullOrEmpty
    }
    It 'the endpoint builder writes AssetType / AssetSubtype from the classification, the Defender DeviceInfo query brings DeviceSubtype' {
        $b = [IO.File]::ReadAllText((Join-Path $script:SIRoot 'engine\asset-profiling\shared\Build-EndpointProfileRow.ps1'))
        $b | Should -Match 'ConvertTo-SIEndpointClassificationItem -Maps \(Get-SIProfileValueMaps\)'
        $b | Should -Match "\`$row\['AssetType'\] = \`$cls\.Type; \`$row\['AssetSubtype'\] = \`$cls\.Subtype"
        $c = [IO.File]::ReadAllText((Join-Path $script:SIRoot 'engine\asset-profiling\stages\Invoke-Collect.ps1'))
        $c | Should -Match "DeviceSubtype\s+= column_ifexists\('DeviceSubtype'"
    }
}
