#Requires -Version 5.1
<#
    A BATCH OF DEVICE / AZURE-RESOURCE CIs WITH VERY LARGE SOURCE OBJECTS IS BUILT IN SECONDS, AND SAYS WHERE IT STANDS.

    A new install's CI build (2026-10-12 / 13, three runs in a row) built its seven identity batches and then stood still
    in the FIRST batch of devices and Azure resources: nothing in the log and no database work for more than an hour,
    until the platform stopped the job. The same version built far larger installs without trouble, so it was the shape of
    this install's data. Its Azure data has unusually large resource objects: Logic App definitions (deeply nested, 17-83
    KB), workbook templates (25-183 KB, long JSON kept as text), dashboards, virtual networks up to 127 KB, load
    balancers, 1,259 VM extensions and 237 Arc machine extensions rolled up into their machines.

    What is held here:
      * THE TIMING HARNESS -- one batch of such assets is made from raw Azure / Defender / Exposure Graph objects through
        the real record capture and field mapping, then taken through every in-memory step of one batch of the CI build
        (engine/data-model/SI-CiBuildRun.ps1, the batch loop of Invoke-SICiBuild), each step timed on its own. Every size
        runs in its OWN PROCESS with a time limit, so a step that stands still stops the measurement, never the test run.
      * THE BOUND -- the whole batch stays under a generous limit.
      * THE PROGRESS LINES -- a batch whose CIs take long to build says which CI it is working on.

    OFFLINE: no database, no tenant, no network. PowerShell 7 (the runtime of every v3 job).
#>

BeforeDiscovery {
    # PowerShell 7 is the runtime of every v3 job (containers only); the harness starts its child processes with it
    $script:IsPwsh = $PSVersionTable.PSVersion.Major -ge 7
}

BeforeAll {
    $script:SIRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    . (Join-Path $script:SIRoot 'engine\data-model\SI-RecordCapture.ps1')
    . (Join-Path $script:SIRoot 'engine\data-model\SI-CiBuildRun.ps1')
    $script:Model = Get-SIDataModel -Root (Join-Path $script:SIRoot 'data-model')
    $script:Work = Join-Path ([IO.Path]::GetTempPath()) ('si-heavy-' + [guid]::NewGuid().ToString('N').Substring(0, 10))
    $null = New-Item -ItemType Directory -Force -Path $script:Work

    # ---- the harness: the synthetic batch and the timed steps. Kept as TEXT so that a child process loads the same code ----
    $script:HarnessText = @'
function New-HvObject {
    <# An ordered dictionary tree -> the object a REST read hands back (PSCustomObject / arrays). #>
    param($Tree)
    ConvertFrom-Json -InputObject (ConvertTo-Json -InputObject $Tree -Depth 60 -Compress) -Depth 100
}

function New-HvLogicDefinition {
    <# A Logic App definition: Scope / If / Foreach actions nested 12 deep, about -TargetBytes of JSON. #>
    param([int]$TargetBytes, [int]$Seed = 1)
    $state = @{ Left = [Math]::Max(4, [int]($TargetBytes / 520)); N = $Seed * 1000 }
    $build = $null
    $build = {
        param([int]$Depth)
        $actions = [ordered]@{}
        $k = 0
        while ($state.Left -gt 0 -and $k -lt 4) {
            $k++; $state.N++; $n = $state.N; $state.Left--
            if ($Depth -lt 12 -and ($n % 3) -ne 0) {
                $inner = & $build ($Depth + 1)
                if (($n % 3) -eq 1) {
                    $actions["Condition_$n"] = [ordered]@{ type = 'If'; expression = [ordered]@{ and = @([ordered]@{ equals = @("@variables('v$n')", $n) }, [ordered]@{ not = [ordered]@{ contains = @("@body('Parse_$n')?['items']", "z$n") } }) }
                        actions = $inner; else = [ordered]@{ actions = [ordered]@{ "Terminate_$n" = [ordered]@{ type = 'Terminate'; inputs = [ordered]@{ runStatus = 'Failed'; runError = [ordered]@{ code = "E$n"; message = 'the step failed' } } } } }; runAfter = [ordered]@{} }
                } else {
                    $actions["For_each_$n"] = [ordered]@{ type = 'Foreach'; foreach = "@body('List_$n')?['value']"; actions = $inner; runAfter = [ordered]@{}; runtimeConfiguration = [ordered]@{ concurrency = [ordered]@{ repetitions = 20 } } }
                }
            } else {
                $actions["Send_$n"] = [ordered]@{ type = 'ApiConnection'; inputs = [ordered]@{ host = [ordered]@{ connection = [ordered]@{ name = "@parameters('`$connections')['office365']['connectionId']" } }
                        method = 'post'; path = "/v2/Mail/$n"; body = [ordered]@{ To = "team$n@contoso.example"; Subject = "Alert $n for @{triggerBody()?['name']}"; Body = ('<p>' + ('lorem ipsum dolor sit amet ' * 5) + '</p>') } }; runAfter = [ordered]@{} }
            }
        }
        $actions
    }
    $top = [ordered]@{}
    while ($state.Left -gt 0) { $state.N++; $top["Scope_$($state.N)"] = [ordered]@{ type = 'Scope'; actions = (& $build 1); runAfter = [ordered]@{} } }
    [ordered]@{ '$schema' = 'https://schema.management.azure.com/providers/Microsoft.Logic/schemas/2016-06-01/workflowdefinition.json#'; contentVersion = '1.0.0.0'
        parameters = [ordered]@{ '$connections' = [ordered]@{ defaultValue = [ordered]@{}; type = 'Object' } }
        triggers = [ordered]@{ manual = [ordered]@{ type = 'Request'; kind = 'Http'; inputs = [ordered]@{ schema = [ordered]@{ type = 'object'; properties = [ordered]@{ name = [ordered]@{ type = 'string' } } } } } }
        actions = $top; outputs = [ordered]@{} }
}

function New-HvTags {
    param([int]$N)
    $t = [ordered]@{ Owner = ('owner{0}@contoso.example' -f ($N % 400)); Environment = 'Production'; CostCenter = ('CC{0:D5}' -f ($N % 97)); Application = ('app-{0}' -f ($N % 50)) }
    for ($i = 0; $i -lt 11; $i++) { $t["tag$i"] = ('value {0} of resource {1} ' -f $i, $N) + ('x' * (20 + (($N + $i) % 180))) }
    $t
}

function New-HvAzureObjects {
    <# The raw Azure objects of one batch, shaped like the install that stood still. -Heavy = the number of Logic Apps. #>
    param([int]$Heavy)
    $sub = '/subscriptions/00000000-0000-0000-0000-00000000000a'
    $out = New-Object System.Collections.Generic.List[object]
    $arm = { param([string]$Id, [string]$Type, $Props, [int]$N, [hashtable]$Extra)
        $o = [ordered]@{ id = $Id; name = ($Id -split '/')[-1]; type = $Type; location = 'westeurope'; subscriptionId = '00000000-0000-0000-0000-00000000000a'
            resourceGroup = ($Id -split '/')[4]; tags = (New-HvTags $N); properties = $Props }
        if ($Extra) { foreach ($k in $Extra.Keys) { $o[$k] = $Extra[$k] } }
        $out.Add((New-HvObject $o))
    }
    # Logic Apps: 20-80 KB, deeply nested
    for ($i = 0; $i -lt $Heavy; $i++) {
        $kb = 20 + (($i * 7) % 61)
        & $arm "$sub/resourceGroups/rg-integration-$($i % 9)/providers/Microsoft.Logic/workflows/la-order-flow-$i" 'microsoft.logic/workflows' ([ordered]@{ state = 'Enabled'; provisioningState = 'Succeeded'
                createdTime = '2024-03-01T10:00:00Z'; changedTime = '2026-09-01T10:00:00Z'; version = '0858'; accessEndpoint = "https://prod-$i.westeurope.logic.azure.com:443/workflows/x$i"
                definition = (New-HvLogicDefinition -TargetBytes ($kb * 1024) -Seed ($i + 1)); parameters = [ordered]@{ '$connections' = [ordered]@{ value = [ordered]@{ office365 = [ordered]@{ connectionId = "$sub/resourceGroups/rg/providers/Microsoft.Web/connections/office365"; connectionName = 'office365' } } } } }) $i $null
    }
    # workbook templates: 100-180 KB, long JSON kept as text (every second one as an object)
    $nWb = [Math]::Max(2, [int]($Heavy / 3))
    for ($i = 0; $i -lt $nWb; $i++) {
        $kb = 100 + (($i * 13) % 81)
        $items = @(1..([Math]::Max(1, [int]($kb * 1024 / 1400))) | ForEach-Object { [ordered]@{ type = 3; name = "query - $_"; content = [ordered]@{ version = 'KqlItem/1.0'; size = 0; queryType = 0; resourceType = 'microsoft.operationalinsights/workspaces'
                    query = ("SecurityEvent | where TimeGenerated > ago(7d) | where EventID == $_ | summarize count() by Computer, bin(TimeGenerated, 1h) | extend label = strcat('a', \`"b\`", '{', Computer, '}') `n" * 7) } } })
        $data = [ordered]@{ version = 'Notebook/1.0'; items = $items; styleSettings = [ordered]@{}; fallbackResourceIds = @('Azure Monitor') }
        $td = $data; if (($i % 2) -eq 0) { $td = (ConvertTo-Json -InputObject $data -Depth 20 -Compress) }
        & $arm "$sub/resourceGroups/rg-monitor/providers/Microsoft.Insights/workbooktemplates/wbt-security-$i" 'microsoft.insights/workbooktemplates' ([ordered]@{ priority = 1; author = 'Contoso'
                galleries = @([ordered]@{ name = "Security overview $i"; category = 'Deployed Templates'; order = 100; type = 'workbook'; resourceType = 'Azure Monitor' }); templateData = $td; localized = [ordered]@{} }) (1000 + $i) $null
    }
    # dashboards: 18-76 KB
    $nDb = [Math]::Max(2, [int]($Heavy / 3))
    for ($i = 0; $i -lt $nDb; $i++) {
        $kb = 18 + (($i * 11) % 59)
        $parts = @(1..([Math]::Max(1, [int]($kb * 1024 / 1100))) | ForEach-Object { [ordered]@{ position = [ordered]@{ x = ($_ % 12); y = $_; colSpan = 6; rowSpan = 4 }
                metadata = [ordered]@{ type = 'Extension/HubsExtension/PartType/MonitorChartPart'; inputs = @([ordered]@{ name = 'options'; isOptional = $true; value = [ordered]@{ chart = [ordered]@{ title = "CPU $_"; titleKind = 1
                                    metrics = @([ordered]@{ resourceMetadata = [ordered]@{ id = "$sub/resourceGroups/rg/providers/Microsoft.Compute/virtualMachines/vm-$_" }; name = 'Percentage CPU'; aggregationType = 4; namespace = 'microsoft.compute/virtualmachines'
                                            metricVisualization = [ordered]@{ displayName = 'Percentage CPU'; resourceDisplayName = "vm-$_" } }); visualization = [ordered]@{ chartType = 2; legendVisualization = [ordered]@{ isVisible = $true; position = 2 } } } } })
                    settings = [ordered]@{ content = [ordered]@{ options = [ordered]@{ chart = [ordered]@{ title = "CPU $_"; note = ('y' * 300) } } } } } } })
        & $arm "$sub/resourceGroups/rg-dashboards/providers/Microsoft.Portal/dashboards/dash-operations-$i" 'microsoft.portal/dashboards' ([ordered]@{ lenses = @([ordered]@{ order = 0; parts = $parts }); metadata = [ordered]@{ model = [ordered]@{ timeRange = [ordered]@{ value = [ordered]@{ relative = [ordered]@{ duration = 24; timeUnit = 1 } } } } } }) (2000 + $i) $null
    }
    # virtual networks with many subnets (the network itself up to ~127 KB), each subnet also read as its own object
    $nVnet = [Math]::Max(1, [int]($Heavy / 20))
    for ($i = 0; $i -lt $nVnet; $i++) {
        $vn = "$sub/resourceGroups/rg-network/providers/Microsoft.Network/virtualNetworks/vnet-hub-$i"
        $subnets = @(0..79 | ForEach-Object { [ordered]@{ id = "$vn/subnets/snet-$_"; name = "snet-$_"; type = 'Microsoft.Network/virtualNetworks/subnets'; properties = [ordered]@{ addressPrefix = "10.$i.$_.0/24"; provisioningState = 'Succeeded'
                    networkSecurityGroup = [ordered]@{ id = "$sub/resourceGroups/rg-network/providers/Microsoft.Network/networkSecurityGroups/nsg-$_" }
                    ipConfigurations = @(0..7 | ForEach-Object { [ordered]@{ id = "$sub/resourceGroups/rg-app/providers/Microsoft.Network/networkInterfaces/nic-$_/ipConfigurations/ipconfig1" } })
                    serviceEndpoints = @([ordered]@{ service = 'Microsoft.Storage'; locations = @('westeurope', 'northeurope'); provisioningState = 'Succeeded' }); delegations = @() } } })
        & $arm $vn 'microsoft.network/virtualnetworks' ([ordered]@{ provisioningState = 'Succeeded'; addressSpace = [ordered]@{ addressPrefixes = @("10.$i.0.0/16") }; subnets = $subnets; enableDdosProtection = $false }) (3000 + $i) $null
        foreach ($s in $subnets) { $out.Add((New-HvObject ([ordered]@{ id = $s.id; name = $s.name; type = 'microsoft.network/virtualnetworks/subnets'; properties = $s.properties }))) }
    }
    # load balancers (~74 KB)
    $nLb = [Math]::Max(1, [int]($Heavy / 20))
    for ($i = 0; $i -lt $nLb; $i++) {
        $lb = "$sub/resourceGroups/rg-network/providers/Microsoft.Network/loadBalancers/lb-app-$i"
        $rulesLb = @(0..119 | ForEach-Object { [ordered]@{ id = "$lb/loadBalancingRules/rule-$_"; name = "rule-$_"; properties = [ordered]@{ frontendIPConfiguration = [ordered]@{ id = "$lb/frontendIPConfigurations/fe-$_" }
                    backendAddressPool = [ordered]@{ id = "$lb/backendAddressPools/pool-$_" }; probe = [ordered]@{ id = "$lb/probes/probe-$_" }; protocol = 'Tcp'; frontendPort = (8000 + $_); backendPort = (8000 + $_); idleTimeoutInMinutes = 4; loadDistribution = 'Default' } } })
        & $arm $lb 'microsoft.network/loadbalancers' ([ordered]@{ provisioningState = 'Succeeded'; loadBalancingRules = $rulesLb; frontendIPConfigurations = @(0..19 | ForEach-Object { [ordered]@{ id = "$lb/frontendIPConfigurations/fe-$_"; properties = [ordered]@{ privateIPAddress = "10.9.0.$_" } } }) }) (4000 + $i) $null
    }
    # virtual machines with 20 extensions, two disks and a network interface each
    $nVm = [Math]::Max(2, [int]($Heavy / 5))
    for ($i = 0; $i -lt $nVm; $i++) {
        $rg = "$sub/resourceGroups/rg-app-$($i % 12)/providers"
        $vm = "$rg/Microsoft.Compute/virtualMachines/vm-app-$i"
        & $arm $vm 'microsoft.compute/virtualmachines' ([ordered]@{ vmId = ('aaaaaaaa-0000-0000-0000-{0:D12}' -f $i); provisioningState = 'Succeeded'; hardwareProfile = [ordered]@{ vmSize = 'Standard_D4s_v5' }
                osProfile = [ordered]@{ computerName = "vm-app-$i"; windowsConfiguration = [ordered]@{ patchSettings = [ordered]@{ patchMode = 'AutomaticByPlatform' } } }
                storageProfile = [ordered]@{ osDisk = [ordered]@{ osType = 'Windows'; managedDisk = [ordered]@{ id = "$rg/Microsoft.Compute/disks/vm-app-$i-os" } } }
                securityProfile = [ordered]@{ securityType = 'TrustedLaunch'; uefiSettings = [ordered]@{ secureBootEnabled = $true; vTpmEnabled = $true } }
                extended = [ordered]@{ instanceView = [ordered]@{ powerState = [ordered]@{ code = 'PowerState/running' } } } }) (5000 + $i) $null
        for ($e = 0; $e -lt 20; $e++) {
            $names = 'MDE.Windows', 'AzureMonitorWindowsAgent', 'AzurePolicyforWindows', 'CustomScriptExtension', 'DependencyAgentWindows'
            $en = if ($e -lt 5) { $names[$e] } else { "Extension$e" }
            $out.Add((New-HvObject ([ordered]@{ id = "$vm/extensions/$en"; name = $en; type = 'microsoft.compute/virtualmachines/extensions'
                        properties = [ordered]@{ type = $en; publisher = 'Microsoft.Azure.Extensions'; typeHandlerVersion = "1.$e"; autoUpgradeMinorVersion = $true; settings = [ordered]@{ commandToExecute = ('powershell -File x.ps1 ' * 40); fileUris = @(0..9 | ForEach-Object { "https://st.blob.core.windows.net/scripts/s$_.ps1" }) } } })))
        }
        foreach ($d in 'os', 'data') { $out.Add((New-HvObject ([ordered]@{ id = "$rg/Microsoft.Compute/disks/vm-app-$i-$d"; name = "vm-app-$i-$d"; type = 'microsoft.compute/disks'; managedBy = $vm; sku = [ordered]@{ name = 'Premium_LRS' }; properties = [ordered]@{ diskSizeGB = 128; osType = 'Windows'; encryption = [ordered]@{ type = 'EncryptionAtRestWithPlatformKey' }; networkAccessPolicy = 'AllowAll' } }))) }
        $out.Add((New-HvObject ([ordered]@{ id = "$rg/Microsoft.Network/networkInterfaces/vm-app-$i-nic"; name = "vm-app-$i-nic"; type = 'microsoft.network/networkinterfaces'
                    properties = [ordered]@{ virtualMachine = [ordered]@{ id = $vm }; ipConfigurations = @([ordered]@{ properties = [ordered]@{ privateIPAddress = "10.20.$($i % 250).4" } }); networkSecurityGroup = [ordered]@{ id = "$rg/Microsoft.Network/networkSecurityGroups/nsg-app" } } })))
    }
    # Arc machines with their extensions
    $nArc = [Math]::Max(1, [int]($Heavy / 10))
    for ($i = 0; $i -lt $nArc; $i++) {
        $m = "$sub/resourceGroups/rg-arc/providers/Microsoft.HybridCompute/machines/srv-onprem-$i"
        & $arm $m 'microsoft.hybridcompute/machines' ([ordered]@{ status = 'Connected'; lastStatusChange = '2026-10-10T08:00:00Z'; agentVersion = '1.46.0'; osName = 'windows'; osSku = 'Windows Server 2022 Datacenter'; machineFqdn = "srv-onprem-$i.corp.contoso.example"
                detectedProperties = [ordered]@{ manufacturer = 'HPE'; model = 'ProLiant DL380'; processorCount = '2'; totalPhysicalMemoryInBytes = '68719476736' } }) (6000 + $i) $null
        foreach ($en in 'MDE.Windows', 'AzureMonitorWindowsAgent', 'WindowsPatchExtension', 'WindowsOsUpdateExtension', 'ChangeTracking-Windows') {
            $out.Add((New-HvObject ([ordered]@{ id = "$m/extensions/$en"; name = $en; type = 'microsoft.hybridcompute/machines/extensions'; properties = [ordered]@{ type = $en; publisher = 'Microsoft.Azure'; typeHandlerVersion = '1.0'; settings = [ordered]@{ note = ('z' * 2000) } } })))
        }
    }
    , $out.ToArray()
}

function New-HvExposureNodes {
    <# Exposure Graph nodes: one per virtual machine (they join the machine's CI), 18 more on the first machine (a CI of 20 records). #>
    param([int]$Heavy)
    $sub = '/subscriptions/00000000-0000-0000-0000-00000000000a'
    $nVm = [Math]::Max(2, [int]($Heavy / 5))
    $node = { param([string]$NodeId, [string]$Vm, [int]$N)
        [pscustomobject]@{ NodeId = $NodeId; NodeLabel = 'microsoft.compute/virtualmachines'; NodeName = ($Vm -split '/')[-1]
            EntityIds = ('[{"type":"AzureResourceId","id":"' + $Vm + '"}]')
            NodeProperties = [pscustomobject]@{ rawData = [pscustomobject]@{ exposedToInternet = [pscustomobject]@{ type = 'InternetExposure'; reasons = @('public ip', 'open port 443')
                        effectiveRules = @(0..39 | ForEach-Object { [pscustomobject]@{ sourceCidr = "20.$N.$_.0/24"; port = 443 } }) }
                    criticalityLevel = [pscustomobject]@{ criticalityLevel = 1; ruleNames = @('Azure Virtual Machine with a Critical User Signed In', 'Databases with sensitive data') }
                    dataSensitivity = [pscustomobject]@{ classificationLabels = @('Confidential', 'PII') } } } }
    }
    $out = New-Object System.Collections.Generic.List[object]
    for ($i = 0; $i -lt $nVm; $i++) {
        $vm = "$sub/resourceGroups/rg-app-$($i % 12)/providers/Microsoft.Compute/virtualMachines/vm-app-$i"
        $out.Add((& $node ('eg-vm-{0:D6}' -f $i) $vm $i))
        if ($i -eq 0) { for ($k = 0; $k -lt 18; $k++) { $out.Add((& $node ('eg-vm-extra-{0:D3}' -f $k) $vm $k)) } }
    }
    , $out.ToArray()
}

function New-HvDefenderDevices {
    <# Defender devices: installed software, tags, addresses, and the users who logged on (one device names very many). #>
    # -Devices: that many devices shaped like a real batch (60-300 software names each, every 50th one 1,000); else a few
    # devices with 1,200 names each
    param([int]$Heavy, [int]$Devices = 0)
    $n = [Math]::Max(2, [int]($Heavy / 5)); if ($Devices -gt 0) { $n = $Devices }
    $out = New-Object System.Collections.Generic.List[object]
    for ($i = 0; $i -lt $n; $i++) {
        $users = 40; if ($Devices -gt 0) { $users = 4 }; if ($i -eq 0) { $users = 1500 }
        $swN = 1200; if ($Devices -gt 0) { $swN = 60 + (($i * 37) % 240); if (($i % 50) -eq 0) { $swN = 1000 } }
        $logged = @(0..($users - 1) | ForEach-Object { [ordered]@{ UserName = "user$($_ + $i)"; DomainName = 'CORP'; Sid = ('S-1-5-21-1111111111-2222222222-3333333333-{0}' -f (1000 + $_ + $i)) } })
        $out.Add([pscustomobject]@{ Id = ('{0:x40}' -f ($i + 1))
                Machine = [pscustomobject]@{ id = ('{0:x40}' -f ($i + 1)); computerDnsName = "srv-defender-$i.corp.contoso.example"; osPlatform = 'WindowsServer2022'; lastSeen = '2026-10-12T20:00:00Z'; lastIpAddress = "10.30.$($i % 250).10"
                    ipAddresses = @(0..5 | ForEach-Object { [pscustomobject]@{ ipAddress = "10.30.$($i % 250).$(10 + $_)"; macAddress = ('00155D{0:X6}' -f ($i * 8 + $_)); type = 'Ethernet'; operationalStatus = 'Up' } })
                    machineTags = @('Servers--tier1--SI', "app-$($i % 40)", 'patch-group-b'); rbacGroupName = 'Servers'; healthStatus = 'Active'; onboardingStatus = 'Onboarded' }
                DeviceInfo = [pscustomobject]@{ LoggedOnUsers = (ConvertTo-Json -InputObject $logged -Compress); MachineGroup = 'Servers'; Timestamp = '2026-10-12T20:00:00Z' }
                Software = @(0..($swN - 1) | ForEach-Object { 'vendor{0}/product_{1}' -f ($_ % 90), ($_ + $i) }) + @('microsoft/sql_server_2019', 'microsoft/internet_information_services') })
    }
    , $out.ToArray()
}

function Measure-HvBatch {
    <#
        ONE BATCH, EVERY STEP TIMED. -Heavy: the number of Logic Apps (the other assets follow it). -HeavyInScope: the large
        resource types (Logic Apps, workbook templates, dashboards) are CI types of this install (else the shipped list decides).
        Answers @{ Heavy; InScope; Stats; Steps (name -> seconds, in order); Total (the steps of the CI build only) }.
        -TraceFile: a line when each step starts and ends, so a process that is stopped says which step it stood in.
    #>
    param([int]$Heavy, [bool]$HeavyInScope = $true, [int]$Devices = 0, [Parameter(Mandatory)]$Model, [AllowEmptyCollection()][object[]]$Rules = @(), [string]$TraceFile = '', [scriptblock]$Log)
    $T = [datetime]::SpecifyKind([datetime]'2026-10-12T21:00:00', [DateTimeKind]::Utc)
    $steps = [ordered]@{}; $sw = [System.Diagnostics.Stopwatch]::new(); $c = @{}
    $step = {
        param([string]$Name, [scriptblock]$Block)
        if ($TraceFile) { [IO.File]::AppendAllText($TraceFile, "START $Name`n") }
        $sw.Restart(); . $Block; $steps[$Name] = [Math]::Round($sw.Elapsed.TotalSeconds, 2)
        if ($TraceFile) { [IO.File]::AppendAllText($TraceFile, ("END {0} {1}`n" -f $Name, $steps[$Name])) }
    }
    # ---- the collection side (not part of the CI build; timed to see what the records carry) ----
    & $step 'make: raw objects' { $c.Arm = New-HvAzureObjects -Heavy $Heavy; $c.Eg = New-HvExposureNodes -Heavy $Heavy; $c.Mde = New-HvDefenderDevices -Heavy $Heavy -Devices $Devices }
    $scope = ConvertTo-SIAzureCiScope -Document $Model['collection-scope']
    if ($HeavyInScope) { foreach ($armType in 'microsoft.logic/workflows', 'microsoft.insights/workbooktemplates', 'microsoft.portal/dashboards', 'microsoft.network/loadbalancers', 'microsoft.hybridcompute/machines') { [void]$scope.Top.Add($armType) } }
    try {
        Set-SIAzureCiScope -Scope $scope
        & $step 'make: record capture' {
            $null = Reset-SIRecordCapture -Engine azure -Clear
            foreach ($o in $c.Arm) { Add-SIRecordPartFromSource -SourceSystem arm -Object $o 3>$null }
            foreach ($o in $c.Eg) { Add-SIRecordPartFromSource -SourceSystem exposure-graph -Object $o 3>$null }
            foreach ($d in $c.Mde) {
                Add-SIRecordPart -Provider mde -RecordType device -Key $d.Id -Part machine -Object $d.Machine 3>$null
                Add-SIRecordPart -Provider mde -RecordType device -Key $d.Id -Part deviceInfo -Object $d.DeviceInfo 3>$null
                Add-SIRecordPart -Provider mde -RecordType device -Key $d.Id -Part software -Object $d.Software 3>$null
            }
        }
        & $step 'make: records from the capture' {
            $c.Caps = @(Get-SICapturedRecords)
            $c.RecRows = (ConvertTo-SIRecordRows -Captured $c.Caps -Model $Model -CollectionTime $T -RunId 'heavy').Rows
            $c.Items = ConvertTo-SIRecordSqlItems -Rows $c.RecRows -Now $T
        }
    } finally { Set-SIAzureCiScope -Scope $null; $null = Reset-SIRecordCapture -Clear }
    $c.Arm = $null; $c.Eg = $null; $c.Mde = $null; $c.Caps = $null
    # the batch's rows as the database hands them over: group key, record key, the columns, the record's JSON
    $g0 = Get-SICiGroups -Records @($c.RecRows)
    $gkOf = @{}
    foreach ($g in @($g0.Groups)) {
        [string[]]$ks = @($g.Members | ForEach-Object { [string](Get-SIItemValue $_.Record 'si_record_key') }); [Array]::Sort($ks, [StringComparer]::Ordinal)
        foreach ($k in $ks) { $gkOf[$k] = $ks[0] }
    }
    $batchRows = New-Object System.Collections.Generic.List[object]
    $maxRec = 0; $sumRec = [long]0
    foreach ($it in @($c.Items.Records)) {
        $rk = [string]$it['RecordKey']; if (-not $gkOf.ContainsKey($rk)) { continue }
        $len = ([string]$it['DocJson']).Length; if ($len -gt $maxRec) { $maxRec = $len }; $sumRec += $len
        $batchRows.Add([pscustomobject]@{ GroupKey = $gkOf[$rk]; RecordKey = $rk; CollectionTime = $T; Complete = $true; SourceLastSeen = $T.AddHours(-1); DocJson = [string]$it['DocJson']; PrevCiId = $null; PrevHash = $null; Dirty = $true })
    }
    $types = @{}; foreach ($f in @($Model['field-catalog'].fields)) { $types[[string]$f.name] = [string]$f.type }
    $feeds = Get-SIFeedLatest -Records @($c.RecRows)
    $c.RecRows = $null; $c.Items = $null
    # 13,000 identity CIs a device or resource can name (the owner tag, the users who logged on)
    $idRows = New-Object System.Collections.Generic.List[object]
    for ($i = 0; $i -lt 400; $i++) { $idRows.Add([pscustomobject]@{ K = "owner$i@contoso.example"; CiId = ('00000000-0000-0000-0001-{0:D12}' -f $i) }) }
    for ($i = 0; $i -lt 12600; $i++) { $idRows.Add([pscustomobject]@{ K = ('s-1-5-21-1111111111-2222222222-3333333333-{0}' -f (1000 + $i)); CiId = ('00000000-0000-0000-0002-{0:D12}' -f $i) }) }
    $svcIndex = $null; try { $svcIndex = Get-SICiServiceIndex -Log { param($l, $m) } } catch { $svcIndex = $null }
    $relRules = @(); try { $relRules = @(Get-SICiRelationRules -Model $Model) } catch { }

    # ---- one batch of the CI build, step by step (Invoke-SICiBuild's batch loop) ----
    & $step 'read: rows -> groups' { $c.Bg = ConvertTo-SICiBatchGroups -Rows $batchRows.ToArray() -Types $types; $c.Stored = Get-SICiBatchStored -Rows $batchRows.ToArray() }
    & $step 'ledger keys' { $c.Keys = @(Get-SICiGroupLedgerKeys -Groups $c.Bg.Groups) }
    if ($Log) {
        # the build's own core, with its progress lines
        & $step 'core (ids, documents, rules, classification)' { $c.Core = Invoke-SICiCore -Groups $c.Bg.Groups -FeedLatest $feeds -Ledger @{} -Model $Model -Rules @($Rules) -CmdbIndex (New-SICiCmdbIndex) -Now $T -RunId 'heavy' -ServiceIndex $svcIndex -Log $Log }
        $c.Docs = $c.Core.Docs
    } else {
        & $step 'core: ids' { $c.Idy = Resolve-SIObjectIdentity -Groups @($c.Bg.Groups) -Ledger @{} -Now $T }
        & $step 'core: documents' {
            $owner = Get-SICmdbOwner; $plan = @(Get-SICiFieldPlan -Catalog $Model['field-catalog'])
            $docs = New-Object System.Collections.Generic.List[object]
            foreach ($d in @($c.Idy.Decisions)) {
                if (-not $d.CorrelationId) { continue }
                $recs = @(foreach ($m in @($d.Group.Members)) { $m.Record })
                $doc = New-SICiDocument -CiId ([string]$d.CorrelationId) -Records $recs -Catalog $Model['field-catalog'] -FeedLatest $feeds -Now $T -RunId 'heavy' -CmdbOwner $owner -FieldPlan $plan
                $doc['si_ci_action'] = [string]$d.Action
                $docs.Add($doc)
            }
            $c.Docs = $docs.ToArray()
        }
        if ($TraceFile -and $env:SI_HEAVY_DIG -eq '1') {
            # DIG: the same calls the enrichment makes, one at a time, each named in the trace before it starts
            $ctx = @{ Lists = (Merge-SIRiskFactorRanges -Lists (Get-SIDataModelListContext $Model)); Now = $T }
            $trust = Get-SICiTrustIndex $Model['trust']; $byClass = Get-SICiRulesByClass -Rules $Rules
            $lab = { param($d) '{0} [{1} / {2} / {3} linked]' -f [string]$d['si_asset_name'], [string]$d['si_class'], [string]$d['si_azure_resource_type'], [string]$d['si_link_count'] }
            $sub = [System.Diagnostics.Stopwatch]::new()
            & $step 'dig: every rule condition on every CI' {
                foreach ($d in $c.Docs) {
                    $l = & $lab $d
                    foreach ($r in @($byClass[[string]$d['si_class']])) {
                        if ($null -eq $r) { continue }
                        [IO.File]::AppendAllText($TraceFile, "SUB rule $($r.id) on $l`n")
                        $sub.Restart(); try { $null = Test-SICondition -Condition $r.when -Item $d -Context $ctx } catch { }
                        if ($sub.Elapsed.TotalSeconds -ge 0.5) { [IO.File]::AppendAllText($TraceFile, ("SLOW {0:N1} s rule {1} on {2}`n" -f $sub.Elapsed.TotalSeconds, $r.id, $l)) }
                    }
                }
                [IO.File]::AppendAllText($TraceFile, "SUBEND`n")
            }
            & $step 'dig: the enrichment, call by call' {
                $fc = @{}; $owner = Get-SICmdbOwner; $cm = $Model['criticality-mapping']
                foreach ($d in $c.Docs) {
                    $l = & $lab $d
                    foreach ($fn in 'break glass', 'rules', 'services', 'criticality', 'risk factors') {
                        [IO.File]::AppendAllText($TraceFile, "SUB $fn on $l`n")
                        $sub.Restart()
                        switch ($fn) {
                            'break glass' { $null = Set-SICiBreakGlass -Ci $d -Context $ctx }
                            'rules' { $null = Invoke-SICiRules -Ci $d -Rules $Rules -Trust $trust -Context $ctx -Now $T -RulesByClass $byClass -FieldCache $fc }
                            'services' { if ($svcIndex) { $null = Set-SICiServices -Ci $d -Index $svcIndex -Mapping $cm -EnvironmentOrder ([string[]]@()) -CmdbOwner $owner } }
                            'criticality' { $null = Set-SICiCriticality -Ci $d -Mapping $cm -CmdbOwner $owner }
                            'risk factors' { $null = Invoke-SICiRiskFactors -Ci $d -Factors $Model['risk-factors'] -Checks $Model['coverage-checks'] -Context $ctx }
                        }
                        if ($sub.Elapsed.TotalSeconds -ge 0.5) { [IO.File]::AppendAllText($TraceFile, ("SLOW {0:N1} s {1} on {2}`n" -f $sub.Elapsed.TotalSeconds, $fn, $l)) }
                    }
                }
                [IO.File]::AppendAllText($TraceFile, "SUBEND`n")
            }
        }
        & $step 'core: rules, risk factors, services' { $null = Invoke-SICiEnrichment -Cis $c.Docs -Model $Model -Rules @($Rules) -CmdbOwner (Get-SICmdbOwner) -CmdbIndex (New-SICiCmdbIndex) -Now $T -ServiceIndex $svcIndex }
        & $step 'core: classification' { $null = Invoke-SICiClassification -Cis $c.Docs -Model $Model -Context @{ Lists = (Get-SIDataModelListContext $Model); Now = $T } }
    }
    & $step 'identity links' { $c.IdLinks = Set-SICiIdentityLinks -Docs $c.Docs -Index (ConvertTo-SICiIdentityIndex -Rows $idRows.ToArray()) }
    & $step 'database items (hash + document JSON)' { $c.SqlItems = ConvertTo-SICiSqlItems -Cis $c.Docs -Stored $c.Stored }
    & $step 'reconcile check' { $null = @(Get-SICiReconcileMismatch -Items $c.SqlItems.Cis -Docs $c.Docs -DirtyRecords (New-Object 'System.Collections.Generic.HashSet[string]') -Stored $c.Stored) }
    & $step 'JSON for the write' { $c.J = ConvertTo-SIJsonArray $c.SqlItems.Cis -Depth 14; $c.L = ConvertTo-SIJsonArray $c.SqlItems.Links; $c.M = ConvertTo-SIJsonArray $c.SqlItems.Map }
    & $step 'identity + CMDB refs JSON' { $c.R1 = ConvertTo-SIJsonArray @($c.IdLinks.Refs); $cr = Get-SICiCmdbRefs -Docs $c.Docs; $c.R2 = ConvertTo-SIJsonArray @($cr.Refs) }
    & $step 'graph items' { $gi = ConvertTo-SICiGraphItems -Docs $c.Docs -Rules $relRules -Only $null; $c.G = (ConvertTo-SIJsonArray @($gi.Services)).Length + (ConvertTo-SIJsonArray @($gi.Claims)).Length }
    & $step 'rows for SI_CI_CL' {
        $rows = New-Object System.Collections.Generic.List[object]
        foreach ($p in $c.SqlItems.Post) { $rows.Add($p.Seen) }
        foreach ($p in @(Select-SICiPostRows -Post $c.SqlItems.Post -PostedHash @{} -Full)) { $rows.Add($p.Row) }
        $c.PostBytes = (ConvertTo-Json -InputObject $rows.ToArray() -Compress -Depth 8).Length
    }
    $total = 0.0; foreach ($k in $steps.Keys) { if (-not $k.StartsWith('make:')) { $total += [double]$steps[$k] } }
    $maxDoc = 0; foreach ($i in @($c.SqlItems.Cis)) { $l = ([string]$i['DocJson']).Length; if ($l -gt $maxDoc) { $maxDoc = $l } }
    $classes = @{}; foreach ($d in $c.Docs) { $k = [string]$d['si_class']; $classes[$k] = [int]$classes[$k] + 1 }
    [pscustomobject]@{ Heavy = $Heavy; InScope = $HeavyInScope; Steps = $steps; Total = [Math]::Round($total, 2)
        Stats = [ordered]@{ Records = $batchRows.Count; Cis = @($c.Docs).Count; Classes = (($classes.Keys | Sort-Object | ForEach-Object { '{0} {1}' -f $_, $classes[$_] }) -join ', ')
            MaxRecordKB = [Math]::Round($maxRec / 1KB, 1); AllRecordsKB = [Math]::Round($sumRec / 1KB); MaxCiDocKB = [Math]::Round($maxDoc / 1KB, 1); WriteJsonKB = [Math]::Round(([string]$c.J).Length / 1KB)
            Links = @($c.SqlItems.Links).Count; IdentityRefs = @($c.IdLinks.Refs).Count; LinkedToIdentity = [int]$c.IdLinks.Linked; PostKB = [Math]::Round($c.PostBytes / 1KB) } }
}
'@
    . ([scriptblock]::Create($script:HarnessText))

    # ---- one size in its own process, with a time limit: a step that stands still stops the measurement, not the run ----
    $script:HarnessFile = Join-Path $script:Work 'heavy-harness.ps1'
    [IO.File]::WriteAllText($script:HarnessFile, $script:HarnessText)
    $script:BootFile = Join-Path $script:Work 'heavy-boot.ps1'
    [IO.File]::WriteAllText($script:BootFile, @'
param([string]$SIRoot, [string]$HarnessFile, [int]$Heavy, [int]$InScope, [int]$Devices = 0, [string]$Out, [string]$Trace)
$ErrorActionPreference = 'Stop'
try {
    . (Join-Path $SIRoot 'engine\data-model\SI-RecordCapture.ps1')
    . (Join-Path $SIRoot 'engine\data-model\SI-CiBuildRun.ps1')
    . $HarnessFile
    $model = Get-SIDataModel -Root (Join-Path $SIRoot 'data-model')
    # the threads a customer's job has (4 CPUs), whatever this machine has
    $global:SI_CiParallel = 4
    $rules = @(Get-SICiBuildRules -Log { param($l, $m) })
    $r = Measure-HvBatch -Heavy $Heavy -HeavyInScope ([bool]$InScope) -Devices $Devices -Model $model -Rules $rules -TraceFile $Trace
    $r | Add-Member -NotePropertyName Rules -NotePropertyValue $rules.Count
    [IO.File]::WriteAllText($Out, (ConvertTo-Json -InputObject $r -Depth 6 -Compress))
} catch {
    [IO.File]::WriteAllText($Out, (ConvertTo-Json -InputObject @{ Error = ('{0} @ {1}' -f $_.Exception.Message, ($_.ScriptStackTrace -split "`n")[0]) } -Compress))
    exit 1
}
'@)
    function script:Invoke-HvChild {
        param([int]$Heavy, [bool]$InScope = $true, [int]$TimeoutSeconds = 180, [int]$Devices = 0)
        $tag = '{0}-{1}-{2}' -f $Heavy, [int]$InScope, [guid]::NewGuid().ToString('N').Substring(0, 6)
        $out = Join-Path $script:Work "hv-$tag.json"; $trace = Join-Path $script:Work "hv-$tag.trace"
        $q = { param($s) '"' + [string]$s + '"' }
        $argList = @('-NoProfile', '-NonInteractive', '-File', (& $q $script:BootFile), '-SIRoot', (& $q $script:SIRoot), '-HarnessFile', (& $q $script:HarnessFile), '-Heavy', $Heavy, '-InScope', [int]$InScope, '-Devices', $Devices, '-Out', (& $q $out), '-Trace', (& $q $trace))
        $sw = [System.Diagnostics.Stopwatch]::StartNew()
        $p = Start-Process -FilePath (Get-Process -Id $PID).Path -ArgumentList $argList -PassThru -WindowStyle Hidden
        $timedOut = -not $p.WaitForExit($TimeoutSeconds * 1000)
        if ($timedOut) { try { $p.Kill($true) } catch { }; try { $null = $p.WaitForExit(15000) } catch { } }
        $res = $null
        if (Test-Path -LiteralPath $out) { try { $res = Get-Content -LiteralPath $out -Raw | ConvertFrom-Json } catch { } }
        $traceLines = @(); if (Test-Path -LiteralPath $trace) { $traceLines = @(Get-Content -LiteralPath $trace) }
        $standing = ''
        if ($timedOut -and $traceLines.Count -gt 0 -and ($traceLines[-1].StartsWith('START ') -or $traceLines[-1].StartsWith('SUB '))) { $standing = $traceLines[-1] }
        [pscustomobject]@{ Heavy = $Heavy; InScope = $InScope; Devices = $Devices; TimedOut = $timedOut; StoodIn = $standing; Seconds = [Math]::Round($sw.Elapsed.TotalSeconds, 1); Result = $res
            Done = @($traceLines | Where-Object { $_.StartsWith('END ') -or $_.StartsWith('SLOW ') } | ForEach-Object { $_.Substring(4) }) }
    }
    function script:Format-HvLine {
        param($Run)
        $head = 'heavy {0}, devices {2} (large types are CI types: {1})' -f $Run.Heavy, $Run.InScope, $Run.Devices
        if ($Run.TimedOut) { return ('{0}: STOPPED after {1} s, standing in step [{2}]; finished before it: {3}' -f $head, $Run.Seconds, $Run.StoodIn, ($Run.Done -join '; ')) }
        if ($null -eq $Run.Result) { return ('{0}: no result after {1} s' -f $head, $Run.Seconds) }
        if ($Run.Result.PSObject.Properties['Error']) { return ('{0}: FAILED -- {1}' -f $head, $Run.Result.Error) }
        $st = $Run.Result.Stats
        '{0}: {1} record(s) -> {2} CI(s) [{3}], {4} rule(s); largest record {5} KB, all records {6} KB, largest CI document {7} KB, write {8} KB; build steps {9} s -- {10}' -f $head, $st.Records, $st.Cis, $st.Classes, $Run.Result.Rules,
            $st.MaxRecordKB, $st.AllRecordsKB, $st.MaxCiDocKB, $st.WriteJsonKB, $Run.Result.Total, (($Run.Result.Steps.PSObject.Properties | ForEach-Object { '{0} {1}' -f $_.Name, $_.Value }) -join '; ')
    }
}

AfterAll { if ($script:Work -and (Test-Path -LiteralPath $script:Work)) { Remove-Item -LiteralPath $script:Work -Recurse -Force -ErrorAction SilentlyContinue } }

Describe 'A batch of devices and Azure resources with very large source objects: every step timed' -Skip:(-not $script:IsPwsh) {
    It 'builds a small batch with large Azure objects and two devices of 1,200 software names well inside its limit (before the correction it stood in the rules for more than 4 minutes)' {
        $env:SI_HEAVY_DIG = ''
        $run = Invoke-HvChild -Heavy 10 -InScope $true -TimeoutSeconds 150
        Write-Host ('    ' + (Format-HvLine $run))
        $run.TimedOut | Should -BeFalse -Because ('the batch must not stand still -- it stood in: ' + $run.StoodIn)
        $run.Result | Should -Not -BeNullOrEmpty
        $run.Result.PSObject.Properties['Error'] | Should -BeNullOrEmpty -Because ([string]$run.Result.Error)
        [int]$run.Result.Stats.Cis | Should -BeGreaterThan 20
        [double]$run.Result.Total | Should -BeLessThan 45 -Because 'every in-memory step of the batch together takes seconds'
        foreach ($p in $run.Result.Steps.PSObject.Properties) { [double]$p.Value | Should -BeLessThan 30 -Because ("step '{0}' must not be the one that stands" -f $p.Name) }
    }

    It 'builds a batch shaped like the install that stood still -- 1,100 Defender devices with 60 to 1,000 software names each, on 4 threads -- in minutes' -Tag 'Scale' {
        $env:SI_HEAVY_DIG = ''
        $run = Invoke-HvChild -Heavy 5 -InScope $true -Devices 1100 -TimeoutSeconds 900
        Write-Host ('    ' + (Format-HvLine $run))
        $run.TimedOut | Should -BeFalse -Because ('the batch must not stand still -- it stood in: ' + $run.StoodIn)
        $run.Result.PSObject.Properties['Error'] | Should -BeNullOrEmpty -Because ([string]$run.Result.Error)
        [int]$run.Result.Stats.Cis | Should -BeGreaterThan 1100
        [double]$run.Result.Total | Should -BeLessThan 420
    }
}

Describe 'A long list is matched once per pattern -- with the same answers as value by value' {
    BeforeAll {
        # the matching as it was before: every pattern built again, every value walked through Get-SIMatchTexts
        function script:Ref-Like($Actual, $Patterns) {
            foreach ($pat in @($Patterns)) {
                $wc = New-Object System.Management.Automation.WildcardPattern([string]$pat, [System.Management.Automation.WildcardOptions]::IgnoreCase)
                foreach ($v in (Get-SIValueList $Actual)) { foreach ($s in (Get-SIMatchTexts $v)) { if ($wc.IsMatch($s)) { return $true } } }
            }
            return $false
        }
        function script:Ref-Matches($Actual, $Patterns) {
            foreach ($pat in @($Patterns)) {
                $rx = New-Object System.Text.RegularExpressions.Regex([string]$pat, ([System.Text.RegularExpressions.RegexOptions]::IgnoreCase -bor [System.Text.RegularExpressions.RegexOptions]::CultureInvariant))
                foreach ($v in (Get-SIValueList $Actual)) { foreach ($s in (Get-SIMatchTexts $v)) { if ($rx.IsMatch($s)) { return $true } } }
            }
            return $false
        }
        function script:Like($Actual, $Patterns) { Test-SICondition -Condition @{ field = 'f'; op = 'like'; value = @($Patterns) } -Item @{ f = $Actual } -Context @{} }
        $script:Soft = @(0..59 | ForEach-Object { 'vendor{0}/product_{1}' -f ($_ % 7), $_ }) + @('microsoft/sql_server_2019', 'Microsoft/Internet_Information_Services', 'a.b/c+d (x64)', '', 'plain', 'ab', 'a-middle-b')
        $script:Pats = @('microsoft/sql_server*', '*/sql_server*', 'sql_server*', '*/internet_information_services', 'INTERNET*', '*', '', 'plain', 'plai', 'a*b', 'a*b*', '*a*b', 'a**b', '*middle*', '*/product_5', '*/product_5*', 'vendor3/*',
            'vendor?/product_1', '[mv]*/product_59', 'a.b/c+d (x64)', 'a.b/c+d*', '*(x64)', '*(x86)', 'vendor9*', '*product_60', 'nothing*like*this', '*/', 'a`*b')
    }

    It 'like on a long list answers as value by value does, for every kind of wildcard (<_>)' -ForEach @('microsoft/sql_server*', '*/sql_server*', 'sql_server*', '*/internet_information_services', 'INTERNET*', '*', '', 'plain', 'plai', 'a*b', 'a*b*', '*a*b', 'a**b', '*middle*', '*/product_5', '*/product_5*', 'vendor3/*',
        'vendor?/product_1', '[mv]*/product_59', 'a.b/c+d (x64)', 'a.b/c+d*', '*(x64)', '*(x86)', 'vendor9*', '*product_60', 'nothing*like*this', '*/', 'a`*b') {
        (Like $script:Soft $_) | Should -Be (Ref-Like $script:Soft $_) -Because "pattern '$_'"
    }

    It 'like with several patterns, on tag entries, on a short list and on one value answers as before' {
        $tags = @(0..19 | ForEach-Object { [pscustomobject]@{ source = 'azure'; name = "key$_"; value = "value $_" } }) + @([pscustomobject]@{ source = 'azure'; name = 'Owner'; value = '' }, 'bare-tag', 42)
        foreach ($p in 'key7=value 7', 'key7=*', 'key1*', 'value 1?', '*=value 19', 'owner', 'owner=*', 'bare*', '4?', '42', 'key99*') { (Like $tags $p) | Should -Be (Ref-Like $tags $p) -Because "tag pattern '$p'" }
        (Like $script:Soft @('nothing*', '*/product_59')) | Should -BeTrue
        (Like $script:Soft @('nothing*', 'none')) | Should -BeFalse
        foreach ($p in $script:Pats) {
            (Like @('plain', 'a-middle-b') $p) | Should -Be (Ref-Like @('plain', 'a-middle-b') $p) -Because "short list, '$p'"
            (Like 'microsoft/sql_server_2019' $p) | Should -Be (Ref-Like 'microsoft/sql_server_2019' $p) -Because "one value, '$p'"
        }
        (Like $null 'a*') | Should -BeFalse
        (Like @(1..20 | ForEach-Object { $null }) '*') | Should -Be (Ref-Like @(1..20 | ForEach-Object { $null }) '*')
    }

    It 'a text that holds the joining character, or a line break, is still matched as a whole text' {
        $odd = @(0..19 | ForEach-Object { "name$_" }) + @(("left" + [char]1 + "right"), "two`nlines")
        foreach ($p in 'right', 'left*', '*right', 'left*right', 'lines', 'two*', 'two*lines', 'name1', 'name1*') { (Like $odd $p) | Should -Be (Ref-Like $odd $p) -Because "pattern '$p'" }
        $nl = @(0..19 | ForEach-Object { "name$_" }) + @("two`nlines")
        foreach ($p in 'lines', 'two*', 'two*lines', '*lines', 'name19') { (Like $nl $p) | Should -Be (Ref-Like $nl $p) -Because "pattern '$p'" }
    }

    It 'the texts of one item are never used for another item' {
        $a = @(0..29 | ForEach-Object { "alpha$_" }); $b = @(0..29 | ForEach-Object { "beta$_" })
        (Like $a 'alpha7') | Should -BeTrue
        (Like $b 'alpha7') | Should -BeFalse
        (Like $b 'beta7') | Should -BeTrue
        (Like $a 'beta7') | Should -BeFalse
    }

    It 'matches on a long list answers as value by value does, and a pattern that is not valid still throws' {
        foreach ($p in '(?i)^microsoft/sql', 'product_5$', '^plain$', 'x64', 'VENDOR3', '^$', 'nothing here', '\(x64\)') {
            (Test-SICondition -Condition @{ field = 'f'; op = 'matches'; value = $p } -Item @{ f = $script:Soft } -Context @{}) | Should -Be (Ref-Matches $script:Soft $p) -Because "pattern '$p'"
            (Test-SICondition -Condition @{ field = 'f'; op = 'matches'; value = $p } -Item @{ f = 'microsoft/sql_server_2019' } -Context @{}) | Should -Be (Ref-Matches 'microsoft/sql_server_2019' $p) -Because "one value, '$p'"
        }
        { Test-SICondition -Condition @{ field = 'f'; op = 'matches'; value = '(' } -Item @{ f = $script:Soft } -Context @{} } | Should -Throw
        # the same pattern in another letter case is another pattern
        (Test-SICondition -Condition @{ field = 'f'; op = 'matches'; value = '^\d+$' } -Item @{ f = '123' } -Context @{}) | Should -BeTrue
        (Test-SICondition -Condition @{ field = 'f'; op = 'matches'; value = '^\D+$' } -Item @{ f = '123' } -Context @{}) | Should -BeFalse
    }

    It 'a device with 1,500 software names is tested against 3,000 name patterns in seconds (it took minutes)' {
        $soft = @(0..1499 | ForEach-Object { 'vendor{0}/product_{1}' -f ($_ % 90), $_ })
        $item = @{ si_installed_software = $soft }
        $sw = [System.Diagnostics.Stopwatch]::StartNew()
        $hits = 0
        for ($i = 0; $i -lt 1500; $i++) {
            if (Test-SICondition -Condition @{ field = 'si_installed_software'; op = 'like'; value = @("role_software_$i*", "*/role_software_$i*") } -Item $item -Context @{}) { $hits++ }
        }
        $sw.Stop()
        Write-Host ('    1,500 rules x 2 patterns x 1,500 software names: {0:N1} s' -f $sw.Elapsed.TotalSeconds)
        $hits | Should -Be 0
        (Test-SICondition -Condition @{ field = 'si_installed_software'; op = 'like'; value = @('nothing*', '*/product_1499') } -Item $item -Context @{}) | Should -BeTrue
        $sw.Elapsed.TotalSeconds | Should -BeLessThan 20
    }
}

Describe 'A batch that takes long says which CI it is working on' {
    It 'names a CI by its name, its kind and its sizes -- never by what a property holds' {
        $ci = [ordered]@{ si_ci_id = 'c1'; si_asset_name = "srv-app-01"; si_class = 'device'; si_asset_type = 'server'; si_installed_software = @(0..1203 | ForEach-Object { "secret-vendor/secret-product-$_" })
            si_tags = @(0..2 | ForEach-Object { [ordered]@{ name = 'k'; value = 'secret-tag-value' } }); si_owner = 'secret.owner@contoso.example' }
        $l = Get-SICiWatchLabel $ci
        $l | Should -Be ('srv-app-01 (device, server, {0:N0} installed software)' -f 1204)
        $l | Should -Not -Match 'secret'
        Get-SICiWatchLabel ([pscustomobject]@{ si_asset_name = 'la-orders'; si_class = 'cloud_resource'; si_azure_resource_type = 'microsoft.logic/workflows'; si_asset_type = 'workflows' }) 3 | Should -Be 'la-orders (cloud_resource, microsoft.logic/workflows, 3 records)'
        Get-SICiWatchLabel ([pscustomobject]@{ si_record_key = 'eg:n1' }) | Should -Be 'eg:n1'
        (Get-SICiWatchLabel ([pscustomobject]@{ si_asset_name = ('x' * 300) })).Length | Should -BeLessOrEqual 80
        Get-SICiWatchLabel $null | Should -Be 'a CI'
    }

    It 'writes a line when a step has run for its interval -- the batch, the step, how many CIs are done and the CI it is on -- and again while it goes on' {
        $w = Start-SICiWatch -EverySeconds 1 -PollMs 100 -Quiet
        try {
            $w | Should -Not -BeNullOrEmpty
            # the watch's own thread is running (on a busy machine it takes a moment to start)
            for ($i = 0; $i -lt 300 -and [int]$w['Turns'] -lt 1; $i++) { Start-Sleep -Milliseconds 100 }
            [int]$w['Turns'] | Should -BeGreaterThan 0 -Because ('the watch runs (state {0}; error [{1}])' -f $w.PowerShell.InvocationStateInfo.State, $w['Error'])
            $w.What = 'batch 8 of 11 -- '
            Set-SICiWatchPhase -Watch $w -Phase 'applying the rules, the services and the risk factors' -Total 1950
            $w.Slots['t1'] = @('srv-app-01 (device, 1,204 installed software)', [datetime]::UtcNow.Ticks, 811)
            $w.Slots['t2'] = @('', [datetime]::UtcNow.Ticks, 1)
            # wait for the lines instead of a fixed sleep: on a busy test machine the watch's thread runs late (a gate with 70
            # suites at once missed the 2.8 s window); the checks below are the same -- one line per interval, never more
            $sw = [Diagnostics.Stopwatch]::StartNew()
            while ($w.Lines.Count -lt 2 -and $sw.Elapsed.TotalSeconds -lt 30) { Start-Sleep -Milliseconds 100 }
            $lines = @($w.Lines.ToArray())
            $lines.Count | Should -BeGreaterOrEqual 2 -Because ('one line per interval while the step goes on (turns {0}; error [{1}])' -f $w['Turns'], $w['Error'])
            $lines.Count | Should -BeLessOrEqual ([int][Math]::Ceiling($sw.Elapsed.TotalSeconds) + 2) -Because 'at most one line per 1 s interval'
            $lines[0] | Should -Match '^CIs: batch 8 of 11 -- applying the rules, the services and the risk factors: 812 of 1.950 CI\(s\) done after 0 minute\(s\); working on srv-app-01 \(device, 1,204 installed software\) for \d+ s$'
            # the next step starts its own clock; a step without CIs to count says how long it has run
            Set-SICiWatchPhase -Watch $w -Phase 'preparing them for the database'
            $before = $w.Lines.Count
            Start-Sleep -Milliseconds 500
            @($w.Lines.ToArray() | Select-Object -Skip $before | Where-Object { $_ -match 'preparing them for the database' }).Count | Should -Be 0 -Because 'a step that just started says nothing'
            $sw = [Diagnostics.Stopwatch]::StartNew()
            while (-not @($w.Lines.ToArray() | Select-Object -Skip $before | Where-Object { $_ -match 'preparing them for the database' }).Count -and $sw.Elapsed.TotalSeconds -lt 30) { Start-Sleep -Milliseconds 100 }
            [string](@($w.Lines.ToArray() | Where-Object { $_ -match 'preparing them for the database' })[-1]) | Should -Match '^CIs: batch 8 of 11 -- preparing them for the database: 0 minute\(s\) so far$'
            # between steps nothing is said
            Set-SICiWatchPhase -Watch $w
            $before = $w.Lines.Count
            Start-Sleep -Milliseconds 1500
            $w.Lines.Count | Should -Be $before
        } finally { Stop-SICiWatch -Watch $w }
        { Stop-SICiWatch -Watch $w; Stop-SICiWatch -Watch $null; Set-SICiWatchPhase -Watch $null -Phase 'x' } | Should -Not -Throw
    }

    It 'the core of a batch notes where it stands, builds the same CIs with and without the watch, and leaves no step behind' {
        $T = [datetime]::SpecifyKind([datetime]'2026-10-12T21:00:00', [DateTimeKind]::Utc)
        $recs = @(0..5 | ForEach-Object { [pscustomobject][ordered]@{ si_provider = 'mde'; si_record_type = 'device'; si_class = 'device'; si_record_key = "mde:m$_"; si_collection_time = $T; si_source_last_seen = $T.AddHours(-1)
                    si_collection_complete = $true; mde_device_id = "m$_"; si_asset_name = "srv-$_"; si_hostname = "srv-$_"; si_installed_software = @(0..39 | ForEach-Object { "vendor/product_$_" }) } })
        $feeds = Get-SIFeedLatest -Records $recs
        $plain = Invoke-SICiCore -Groups @((Get-SICiGroups -Records $recs).Groups) -FeedLatest $feeds -Ledger @{} -Model $script:Model -Rules @() -Now $T -RunId 'r'
        $w = Start-SICiWatch -EverySeconds 3600 -Quiet
        try {
            $seen = New-Object System.Collections.Generic.List[string]
            $watched = Invoke-SICiCore -Groups @((Get-SICiGroups -Records $recs).Groups) -FeedLatest $feeds -Ledger @{} -Model $script:Model -Rules @() -Now $T -RunId 'r' -Watch $w
            $w.Phase | Should -BeNullOrEmpty -Because 'after the core no step is running'
            $w.Lines.Count | Should -Be 0
        } finally { Stop-SICiWatch -Watch $w }
        $watched.Docs.Count | Should -Be 6
        (ConvertTo-Json -InputObject $watched.Docs -Depth 12 -Compress) | Should -Be (ConvertTo-Json -InputObject $plain.Docs -Depth 12 -Compress)
    }

    It 'the batch loop starts the watch, hands it to the core of every batch and ends it whatever happens; every thread of the rules step notes its CI' {
        $run = [IO.File]::ReadAllText((Join-Path $script:SIRoot 'engine\data-model\SI-CiBuildRun.ps1'))
        $run | Should -Match '\$ciWatch = Start-SICiWatch'
        $run | Should -Match 'Invoke-SICiCore -Groups \$bg\.Groups [^\r\n]* -Watch \$ciWatch'
        $run | Should -Match 'Stop-SICiWatch -Watch \$ciWatch; \$ciWatch = \$null' -Because 'the watch ends when the batches are done'
        $run | Should -Match '(?s)\} catch \{\s+Stop-SICiWatch -Watch \$ciWatch' -Because 'and where a failed build is caught'
        $run | Should -Match '\$ciWatch\.What = \(''batch \{0\} of \{1\} -- '''
        $enrich = [IO.File]::ReadAllText((Join-Path $script:SIRoot 'engine\data-model\SI-CiEnrich.ps1'))
        $enrich | Should -Match '\$w = \$using:Watch'
        $enrich | Should -Match '\$w\.Slots\[\$slot\] = @\(\(Get-SICiWatchLabel \$ci\)'
        $enrich | Should -Match '\$Watch\.Slots\[''main''\] = @\(\(Get-SICiWatchLabel \$ci\)'
    }
}

Describe 'One CI never holds the build: the rules of one CI have a time limit' {
    BeforeAll {
        function script:CiRule([string]$Id, $When, $Set, [int]$Order) {
            [pscustomobject][ordered]@{ id = $Id; family = 't'; file = 't.yaml'; name = $Id; stage = 'production'; priority = 100; pack = 't'; order = $Order; classes = @('device'); osScope = @(); fallback = $false
                mechanism = 'name.pattern'; mechanisms = @('name.pattern'); when = $When; set = $Set; exclude = @(); key = '' }
        }
        $script:BT = [datetime]::SpecifyKind([datetime]'2026-10-12T21:00:00', [DateTimeKind]::Utc)
        # one device whose NAME makes every pattern below run into the 200 ms limit of a pattern; three ordinary ones
        $script:SlowName = ('a' * 30) + '!'
        $script:BRecs = @(foreach ($i in 1..4) {
                $name = "srv-$i"; if ($i -eq 3) { $name = $script:SlowName }
                [pscustomobject][ordered]@{ si_provider = 'mde'; si_record_type = 'device'; si_class = 'device'; si_record_key = "mde:b$i"; si_collection_time = $script:BT
                    si_source_last_seen = $script:BT.AddHours(-1); si_collection_complete = $true; mde_device_id = "b$i"; si_asset_name = $name }
            })
        # six slow rules first, then the rule that sets the tier of every device
        $script:BRules = @(foreach ($i in 1..6) { CiRule "slow-$i" ([ordered]@{ any = @([ordered]@{ field = 'si_asset_name'; op = 'matches'; value = ('^(a+)+' + $i + '$') }) }) ([ordered]@{ si_purpose = "P$i" }) $i }) +
            @((CiRule 'tier-one' ([ordered]@{ any = @([ordered]@{ field = 'si_class'; op = 'in'; value = @('device') }) }) ([ordered]@{ si_tier = 1; si_purpose = 'Server' }) 7))
        function script:Build-Budget($Budget) {
            $old = $global:SI_CiRulesBudgetSeconds
            try {
                $global:SI_CiRulesBudgetSeconds = $Budget
                Invoke-SICiCore -Groups @((Get-SICiGroups -Records $script:BRecs).Groups) -FeedLatest (Get-SIFeedLatest -Records $script:BRecs) -Ledger @{} -Model $script:Model -Rules $script:BRules -Now $script:BT -RunId 'b'
            } finally { $global:SI_CiRulesBudgetSeconds = $old }
        }
    }

    It 'the limit is a setting: 60 s unless SI_CiRulesBudgetSeconds says otherwise, off = none' {
        Get-SICiRulesBudgetSeconds -Setting $null | Should -Be 60
        Get-SICiRulesBudgetSeconds -Setting '' | Should -Be 60
        Get-SICiRulesBudgetSeconds -Setting '15' | Should -Be 15
        Get-SICiRulesBudgetSeconds -Setting 2.5 | Should -Be 2.5
        Get-SICiRulesBudgetSeconds -Setting 'off' | Should -Be 0
        Get-SICiRulesBudgetSeconds -Setting 0 | Should -Be 0
        Get-SICiRulesBudgetSeconds -Setting 'soon' | Should -Be 60
        Get-SICiRulesBudgetSeconds -Setting -5 | Should -Be 60
    }

    It 'a CI whose rules take too long is stopped, named and counted -- the batch finishes and the other CIs are complete' {
        $sw = [System.Diagnostics.Stopwatch]::StartNew()
        $core = Build-Budget 0.5
        $sw.Stop()
        $core.Docs.Count | Should -Be 4 -Because 'the core hands every CI back; the build keeps the stopped one out (Get-SICiHeld)'
        @($core.Incomplete).Count | Should -Be 1
        $core.Incomplete[0].Label | Should -BeLike ($script:SlowName + '*')
        [double]$core.Incomplete[0].Seconds | Should -BeGreaterOrEqual 0.5 -Because 'the seconds are kept with one decimal'
        @($core.Incomplete[0].RecordKeys) | Should -Be @('mde:b3') -Because 'the build has exactly its records built again'
        $slow = @($core.Docs | Where-Object { [string]$_['si_asset_name'] -eq $script:SlowName })[0]
        $core.Incomplete[0].CiId | Should -Be ([string]$slow['si_ci_id'])
        @($core.Docs | Where-Object { $_.Contains('si_ci_rules_cut') }).Count | Should -Be 0 -Because 'the mark never reaches a written CI'
        $slow['si_tier'] | Should -Not -Be 1 -Because 'the rule after the limit was not applied to it in this run -- which is why it must not be written'
        foreach ($d in @($core.Docs | Where-Object { [string]$_['si_asset_name'] -ne $script:SlowName })) {
            $d['si_tier'] | Should -Be 1 -Because ('{0} is complete' -f $d['si_asset_name'])
            $d['si_purpose'] | Should -Be 'Server'
        }
        $sw.Elapsed.TotalSeconds | Should -BeLessThan 15
    }

    It 'without a limit the same CI gets every rule (it only takes longer), and nothing is counted' {
        $core = Build-Budget 'off'
        @($core.Incomplete).Count | Should -Be 0
        foreach ($d in $core.Docs) { $d['si_tier'] | Should -Be 1 }
        $held = Get-SICiHeld -Docs $core.Docs -Incomplete $core.Incomplete
        @($held.Docs).Count | Should -Be 4 -Because 'nothing was stopped: every CI is written'
        (@($held.Kept).Count, @($held.LeftOut).Count, @($held.Items).Count, @($held.RecordKeys).Count) | Should -Be @(0, 0, 0, 0)
    }

    It 'keep it out until fully evaluated: a stopped CI that was never evaluated completely is left out of everything the batch writes and sends' {
        $core = Build-Budget 0.5
        $slowId = [string]$core.Incomplete[0].CiId
        $held = Get-SICiHeld -Docs $core.Docs -Incomplete $core.Incomplete -Stored ([pscustomobject]@{ Hash = @{}; RecordCi = @{} })
        @($held.Docs).Count | Should -Be 3 -Because 'the other CIs of the batch are complete and written'
        @($held.Docs | Where-Object { [string]$_['si_ci_id'] -eq $slowId }).Count | Should -Be 0
        (@($held.Kept).Count, @($held.LeftOut).Count, @($held.Items).Count) | Should -Be @(0, 1, 0)
        $held.LeftOut[0].Kept | Should -BeFalse
        @($held.RecordKeys) | Should -Be @('mde:b3')
        $held.KeptIds.Count | Should -Be 0
        # what the batch writes and posts is made from the complete CIs only: no item, link, record link or SI_CI_CL row of it
        $items = ConvertTo-SICiSqlItems -Cis @($held.Docs)
        (@($items.Cis).Count, @($items.Post).Count) | Should -Be @(3, 3)
        foreach ($set in @($items.Cis), @($items.Links), @($items.Map)) { @($set | Where-Object { [string]$_['CiId'] -eq $slowId }).Count | Should -Be 0 }
        @($items.Post | Where-Object { [string]$_.CiId -eq $slowId }).Count | Should -Be 0 -Because 'neither a full row nor a seen row: on a first run it is left out'
    }

    It 'keep it out until fully evaluated: a stopped CI that has a complete evaluation keeps it -- nothing of it is rewritten, it is only seen' {
        $core = Build-Budget 0.5
        $slowId = [string]$core.Incomplete[0].CiId
        $was = 'AB' * 32
        $held = Get-SICiHeld -Docs $core.Docs -Incomplete $core.Incomplete -Stored ([pscustomobject]@{ Hash = @{ $slowId = $was }; RecordCi = @{ 'mde:b3' = $slowId } })
        @($held.Docs).Count | Should -Be 3
        (@($held.Kept).Count, @($held.LeftOut).Count, @($held.Items).Count) | Should -Be @(1, 0, 1)
        $held.Kept[0].Kept | Should -BeTrue
        $held.KeptIds.Contains($slowId) | Should -BeTrue
        @($held.RecordKeys) | Should -Be @('mde:b3') -Because 'its records lose their built marks: the next build takes it up again'
        # the slim item an unchanged CI sends: its STORED content hash (the database rewrites nothing), no document, no posted hash
        $it = $held.Items[0]
        $it['CiId'] | Should -Be $slowId
        $it['Hash'] | Should -Be $was
        $it['DocJson'] | Should -BeNullOrEmpty
        $it['PostHash'] | Should -BeNullOrEmpty -Because 'the hash of its SI_CI_CL full row stays the one of its last complete evaluation'
        $it.Contains('LastSeen') | Should -BeTrue -Because 'it is seen in this run: its last seen moves with its records, so it never looks gone'
        $it['CollectionTime'] | Should -Not -BeNullOrEmpty
        @($it.Keys | Where-Object { $_ -in 'Tier', 'TierSetBy', 'TierReason', 'RiskFactors', 'Class', 'Name' }).Count | Should -Be 0 -Because 'no tier and no field of half the rules leaves the build'
        $w = Get-SICiWriteSql
        $w | Should -Match 'INSERT @chg SELECT c\.CiId FROM @c c LEFT JOIN sidata\.Ci t ON t\.CiId = c\.CiId WHERE t\.CiId IS NULL OR t\.ContentHash IS NULL OR t\.ContentHash <> c\.Hash' -Because 'an item with the stored hash is not a changed CI'
        $w | Should -Match 'UPDATE t SET LastSeen = c\.LastSeen FROM sidata\.Ci t JOIN @c c ON c\.CiId = t\.CiId' -Because 'only its last seen moves'
        $w | Should -Match 'c\.PostHash IS NOT NULL AND \(t\.PostRowHash IS NULL OR t\.PostRowHash <> c\.PostHash\)' -Because 'an item without a posted hash leaves PostRowHash as it is'
    }

    It 'the log lines name the CI (name and kind only) and say in plain words what happens to it; the state text holds whole names' {
        $core = Build-Budget 0.5
        $new = Format-SICiIncompleteLine -Item $core.Incomplete[0] -Budget 60
        $new | Should -BeLike ('CIs: ' + $script:SlowName + '* took longer than 60 s in the rules -- not fully evaluated in this run; it is new and is left out until it is fully evaluated. It is evaluated again, with every rule, in the next run.')
        $kept = Format-SICiIncompleteLine -Item $core.Incomplete[0] -Budget 60 -Kept $true
        $kept | Should -BeLike '*not fully evaluated in this run; it keeps what it had from its last complete evaluation. It is evaluated again, with every rule, in the next run.'
        $sum = Format-SICiIncompleteSummary -Count 3 -Kept 2 -LeftOut 1 -Budget 60
        $sum | Should -Be 'CIs: 3 asset(s) not fully evaluated in this run -- their rules took longer than 60 s each. 2 keep what they had from their last complete evaluation; 1 are new and are left out until they are fully evaluated. No tier and no finding is based on part of the rules. They are evaluated again, with every rule, in the next run.'
        foreach ($l in $new, $kept, $sum) { $l | Should -Not -Match '#\d|si_ci_rules_cut|budget|PostedHash|BuiltHash' -Because 'a customer reads this line' }
        Format-SICiIncompleteNames -Labels @() | Should -Be ''
        Format-SICiIncompleteNames -Labels @('srv-a (device)', 'srv-b (device)') | Should -Be 'srv-a (device); srv-b (device)'
        Format-SICiIncompleteNames -Labels @('srv-a (device)', 'srv-b (device)') -Total 14 | Should -Be 'srv-a (device); srv-b (device) ... and 12 more'
        $long = @(1..50 | ForEach-Object { 'server-with-a-long-name-{0:D3} (device, 1,204 installed software)' -f $_ })
        $text = Format-SICiIncompleteNames -Labels $long -Total 80
        $text.Length | Should -BeLessOrEqual 400 -Because 'the build state holds 400 characters'
        $text | Should -Match '^server-with-a-long-name-001 \(device, 1,204 installed software\); '
        $text | Should -Match ' \.\.\. and \d+ more$'
        $shown = @($text -split '; ').Count
        $text | Should -Match (' \.\.\. and {0} more$' -f (80 - $shown)) -Because 'every CI is either named or counted'
    }

    It 'a build from records in hand leaves the stopped CI out, says so and counts it' {
        # no ledger store in this test: an empty ledger is read, and a dry run writes none
        Mock Read-SIObjectLedger { [pscustomobject]@{ Ledger = @{}; ETag = 'e'; Existed = $true } }
        Mock Write-SIObjectLedger { throw 'a dry run must not write the ledger' }
        Mock Close-SIObjectLedgerProvider { }
        $script:HeldLines = New-Object System.Collections.Generic.List[string]
        $lines = $script:HeldLines
        $old = $global:SI_CiRulesBudgetSeconds
        try {
            $global:SI_CiRulesBudgetSeconds = 0.5
            $res = Invoke-SICiBuild -Records $script:BRecs -DryRun -Rules $script:BRules -CmdbIndex (New-SICiCmdbIndex) -LedgerProvider ([pscustomobject]@{ Kind = 'blob' }) -Log { param($l, $m) $script:HeldLines.Add(($l + ' ' + $m)) }
        } finally { $global:SI_CiRulesBudgetSeconds = $old }
        $res.Reason | Should -BeNullOrEmpty -Because (@($lines) -join ' | ')
        $res.Failed | Should -BeFalse
        $res.CiCount | Should -Be 3
        @($res.Cis | Where-Object { [string]$_['si_asset_name'] -eq $script:SlowName }).Count | Should -Be 0
        foreach ($d in $res.Cis) { $d['si_tier'] | Should -Be 1 }
        $res.Incomplete | Should -Be 1
        @($res.IncompleteCis)[0] | Should -BeLike ($script:SlowName + '*')
        @($lines | Where-Object { $_ -like ('INFO CIs: ' + $script:SlowName + '* -- not fully evaluated in this run; it is new and is left out*') }).Count | Should -Be 1
        @($lines | Where-Object { $_ -like 'WARN CIs: 1 asset(s) not fully evaluated in this run*' }).Count | Should -Be 1
    }

    It 'the build: only the complete CIs of a batch are written, posted, linked and handed on; a kept CI is seen; the records of both lose their built marks; the count is in the result and the build state' {
        $run = [IO.File]::ReadAllText((Join-Path $script:SIRoot 'engine\data-model\SI-CiBuildRun.ps1'))
        $from = $run.IndexOf('for ($b = 1; $b -le $nBatches; $b++)'); $to = $run.IndexOf('the last batch''s posted marks')
        $loop = $run.Substring($from, $to - $from)
        $loop | Should -Match '\$held = Get-SICiHeld -Docs \$core\.Docs -Incomplete \$core\.Incomplete -Stored \$stored\s+\$docs = @\(\$held\.Docs\)'
        # after that line the batch never touches the core's own list again, except to ask whether there is anything to write
        $after = $loop.Substring($loop.IndexOf('$docs = @($held.Docs)'))
        @([regex]::Matches($after, '\$core\.Docs') | ForEach-Object { $after.Substring($_.Index, [Math]::Min(22, $after.Length - $_.Index)) }) | Should -Be @('$core.Docs.Count -gt 0') -Because 'a stopped CI reaches no write, post, link, reference, graph or workbook step'
        foreach ($use in 'ConvertTo-SICiSqlItems -Cis $docs -Stored $stored', 'Set-SICiIdentityLinks -Docs $docs', 'Get-SICiCmdbRefs -Docs $docs', 'ConvertTo-SICiGraphItems -Docs $docs', 'Get-SICiReconcileMismatch -Items $items.Cis -Docs $docs', 'Add-SICiUnknownFactorCounts -Counts $unknownFactorCounts -Cis $docs') {
            $loop.Contains($use) | Should -BeTrue -Because $use
        }
        $loop.Contains('j = (ConvertTo-SIJsonArray (@($items.Cis) + @($held.Items)) -Depth 14)') | Should -BeTrue -Because 'a kept CI rides in the batch''s write as a slim item: seen, not rewritten'
        $loop.Contains('if (-not $held.KeptIds.Contains($rid)) { $resend.Add($rid) }') | Should -BeTrue -Because 'a kept CI is never sent whole'
        $loop | Should -Match "si_row_kind = 'seen'; si_collection_time = \`$k\.CollectionTime; si_content_hash = \`$ph; si_last_seen = \`$k\.LastSeen" -Because 'its seen row carries the hash of the full row SI_CI_CL already holds'
        $loop.Contains('foreach ($x in $sel) { $pendingMarks.Add([ordered]@{ CiId = $x.CiId; Hash = $x.Hash }) }') | Should -BeTrue
        $loop.Contains('h = (ConvertTo-SIJsonArray @($held.RecordKeys))') | Should -BeTrue -Because 'a kept batch does not keep the records of a stopped CI as built'
        $run.Contains('h = (ConvertTo-SIJsonArray $heldRecords.ToArray())') | Should -BeTrue -Because 'the end of the build takes their built marks off'
        $run.Contains('Format-SICiIncompleteSummary -Count $t.Incomplete -Kept $t.IncompleteKept -LeftOut $t.IncompleteLeftOut') | Should -BeTrue
        $run | Should -Match "n = 'NotFullyEvaluated'; v = \[string\]\`$t\.Incomplete" -Because 'the web app and support read the count of the last build from the build state'
        $run | Should -Match "n = 'NotFullyEvaluatedCis'; v = \(Format-SICiIncompleteNames -Labels \`$heldNames\.ToArray\(\) -Total \`$t\.Incomplete\)"
        $run | Should -Match 'Incomplete = \$t\.Incomplete; IncompleteKept = \$t\.IncompleteKept; IncompleteLeftOut = \$t\.IncompleteLeftOut; IncompleteCis = \$heldNames\.ToArray\(\)'
        # what makes the next build take it up again: the hash its records were built from is gone (after the marks, same transaction)
        (Get-SICiMarkBatchBuiltSql) | Should -Match "(?s)SET @marked = @@ROWCOUNT;.*IF @h IS NOT NULL AND @h <> N'' AND @h <> N'\[\]'\s+UPDATE r SET BuiltHash = NULL, BuiltAt = NULL\s+FROM sidata\.CiRecord r JOIN OPENJSON\(@h\) WITH \(RecordKey NVARCHAR\(450\) '\$'\) x ON x\.RecordKey = r\.RecordKey;.*COMMIT TRANSACTION;"
        # #881 the end-of-build marks run in key ranges (each its own transaction): a held record is never marked in any range,
        # and loses the hash it was built from after the marks
        $mk = Get-SICiMarkBuiltSql
        $mk | Should -Match "(?s)INSERT #held \(RecordKey\) SELECT DISTINCT x\.RecordKey FROM OPENJSON\(@h\).*AND NOT EXISTS \(SELECT 1 FROM #held hk WHERE hk\.RecordKey = r\.RecordKey\);.*UPDATE r SET BuiltHash = NULL, BuiltAt = NULL FROM sidata\.CiRecord r JOIN #held x ON x\.RecordKey = r\.RecordKey;"
        $dirty = Get-SICiDirtySql -LookbackDays 30
        $dirty | Should -Match 'WHERE r\.BuiltGroupKey IS NULL OR r\.BuiltHash IS NULL OR m\.CurHash IS NULL OR r\.BuiltHash <> m\.CurHash' -Because 'a record without the hash it was built from makes its group one the next build builds'
        $dirty | Should -Match 'WHERE \(r\.BuiltAt IS NULL OR r\.BuiltAt < @since\)' -Because 'and a build that carries on a stopped rebuild takes it up too'
        $enrich = [IO.File]::ReadAllText((Join-Path $script:SIRoot 'engine\data-model\SI-CiEnrich.ps1'))
        $enrich | Should -Match '-FieldCache \$fc -BudgetSeconds \$using:budget'
        $enrich | Should -Match '-FieldCache \$fieldCache -BudgetSeconds \$budget'
    }
}
