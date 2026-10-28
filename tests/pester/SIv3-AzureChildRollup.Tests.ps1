#Requires -Version 5.1
<#
    AZURE CHILD RESOURCES ROLL UP INTO THEIR PARENT CI; ONLY THE LISTED AZURE TYPES BECOME CIs (owner 2026-10-11: "extensions
    suddenly show as risk from azure ... we had defined some classes that we excluded. chk v2.2 code").

    What these tests keep true (engine/data-model/SI-AzureChildren.ps1, data-model/collection-scope.locked.json):
      * THE LIST: collection-scope azureResourceTypes is the CI scope; a type with rollUpInto is a CHILD (v2.2
        subResourceRollupRules + the owner's decisions: disks fold into their VM by managedBy, SQL databases into their
        server); a public IP stays a CI and is ALSO listed on what it is attached to; a customer may add a type
      * RECORD CAPTURE: a child is a part of its parent's record, never a record (a CI) of its own -- from the Azure read,
        Defender for Cloud and the Exposure Graph alike; a type that is not a CI type is not recorded; the parent lists its
        children (si_child_resources, si_vm_extensions, si_disks ...)
      * THE CI: every child id is a linked object of the parent CI (record_key '', type child_resource), so a finding on
        the child lands on the parent; the parent's own links, primary ids and lifecycle are unchanged
      * DEFENDER FOR CLOUD: one recommendation row per parent with the children in AffectedEntities
      * RETIREMENT: a CI no current record builds is retired once unseen longer than the brake -- never deleted
      * SI_CI_CL carries the Azure type, subscription, resource group and region, and the VM extensions
    The Pro half (the data sync's findings writer, real-SQL retirement) is SIv3-AzureChildRollupPro.
#>

BeforeAll {
    $script:SIRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
    . (Join-Path $script:SIRoot 'engine\data-model\SI-RecordCapture.ps1')
    . (Join-Path $script:SIRoot 'engine\data-model\SI-RecordHandover.ps1')
    . (Join-Path $script:SIRoot 'engine\data-model\SI-CiBuildRun.ps1')
    . (Join-Path $script:SIRoot 'engine\asset-profiling\discovery\Invoke-SIArgPaged.ps1')
    . (Join-Path $script:SIRoot 'engine\asset-profiling\discovery\Get-SIDefenderRecommendations.ps1')
    $script:Dm = Join-Path $script:SIRoot 'data-model'
    $script:Model = Get-SIDataModel -Root $script:Dm
    $script:Scope = ConvertTo-SIAzureCiScope -Document $script:Model['collection-scope']
    $script:Rg = '/subscriptions/s1/resourceGroups/RG1/providers'
    $script:Vm = "$script:Rg/Microsoft.Compute/virtualMachines/VM1"
    $script:VmL = $script:Vm.ToLowerInvariant()
    function script:Arm([string]$Id, [string]$Type, [hashtable]$Extra = @{}) {
        $o = [ordered]@{ id = $Id; name = ($Id -split '/')[-1]; type = $Type; properties = [pscustomobject]@{} }
        foreach ($k in $Extra.Keys) { $o[$k] = $Extra[$k] }
        [pscustomobject]$o
    }
    function script:Capture {
        $null = Reset-SIRecordCapture -Engine azure -Clear
        Set-SIAzureCiScope -Scope $script:Scope
        $vmProps = [pscustomobject]@{ hardwareProfile = [pscustomobject]@{ vmSize = 'Standard_D2s_v5' } }
        Add-SIRecordPartFromSource -SourceSystem arm -Object (Arm $script:Vm 'microsoft.compute/virtualmachines' @{ properties = $vmProps })
        Add-SIRecordPartFromSource -SourceSystem arm -Object (Arm "$script:Vm/extensions/MDE.Windows" 'microsoft.compute/virtualmachines/extensions' @{ properties = [pscustomobject]@{ type = 'MDE.Windows'; publisher = 'Microsoft.Azure.AzureDefenderForServers'; typeHandlerVersion = '1.0' } })
        Add-SIRecordPartFromSource -SourceSystem arm -Object (Arm "$script:Vm/extensions/AzureMonitorWindowsAgent" 'microsoft.compute/virtualmachines/extensions' @{ properties = [pscustomobject]@{ type = 'AzureMonitorWindowsAgent'; publisher = 'Microsoft.Azure.Monitor' } })
        # a public IP BEFORE its network interface: listed on the NIC first, which is folded into the VM afterwards
        Add-SIRecordPartFromSource -SourceSystem arm -Object (Arm "$script:Rg/Microsoft.Network/publicIPAddresses/pip1" 'microsoft.network/publicipaddresses' @{ properties = [pscustomobject]@{ ipAddress = '20.1.2.3'; ipConfiguration = [pscustomobject]@{ id = "$script:Rg/Microsoft.Network/networkInterfaces/nic1/ipConfigurations/ipconfig1" } } })
        Add-SIRecordPartFromSource -SourceSystem arm -Object (Arm "$script:Rg/Microsoft.Network/networkInterfaces/nic1" 'microsoft.network/networkinterfaces' @{ properties = [pscustomobject]@{ virtualMachine = [pscustomobject]@{ id = $script:Vm }; ipConfigurations = @([pscustomobject]@{ properties = [pscustomobject]@{ privateIPAddress = '10.0.0.4' } }) } })
        Add-SIRecordPartFromSource -SourceSystem arm -Object (Arm "$script:Rg/Microsoft.Compute/disks/VM1_OsDisk" 'microsoft.compute/disks' @{ managedBy = $script:Vm; sku = [pscustomobject]@{ name = 'Premium_LRS' }; properties = [pscustomobject]@{ diskSizeGB = 128; osType = 'Windows' } })
        # an unattached disk (no parent), a data collection rule (not a CI type), a SQL server with a database and a firewall rule
        Add-SIRecordPartFromSource -SourceSystem arm -Object (Arm "$script:Rg/Microsoft.Compute/disks/orphan" 'microsoft.compute/disks')
        Add-SIRecordPartFromSource -SourceSystem arm -Object (Arm "$script:Rg/Microsoft.Insights/dataCollectionRules/dcr1" 'microsoft.insights/datacollectionrules')
        Add-SIRecordPartFromSource -SourceSystem arm -Object (Arm "$script:Rg/Microsoft.Sql/servers/sql1" 'microsoft.sql/servers')
        Add-SIRecordPartFromSource -SourceSystem arm -Object (Arm "$script:Rg/Microsoft.Sql/servers/sql1/databases/db1" 'microsoft.sql/servers/databases' @{ sku = [pscustomobject]@{ name = 'S0' } })
        Add-SIRecordPartFromSource -SourceSystem arm -Object (Arm "$script:Rg/Microsoft.Sql/servers/sql1/firewallRules/AllowAll" 'microsoft.sql/servers/firewallrules' @{ properties = [pscustomobject]@{ startIpAddress = '0.0.0.0'; endIpAddress = '255.255.255.255' } })
        # the same extension seen by Defender for Cloud and the Exposure Graph: still a part of the VM, never a record of its own
        Add-SIRecordPart -Provider mdc -RecordType azure_resource -Key "$script:Vm/extensions/MDE.Windows" -Part exposure -Object ([pscustomobject]@{ resourceId = "$script:Vm/extensions/MDE.Windows"; internetExposed = $false })
        Add-SIRecordPartFromSource -SourceSystem exposure-graph -Object ([pscustomobject]@{ NodeId = 'eg-ext'; NodeLabel = 'microsoft.compute/virtualmachines/extensions'; EntityIds = '[{"type":"AzureResourceId","id":"' + "$script:Vm/extensions/MDE.Windows" + '"}]' })
        Add-SIRecordPartFromSource -SourceSystem exposure-graph -Object ([pscustomobject]@{ NodeId = 'eg-dcr'; NodeLabel = 'microsoft.insights/datacollectionrules'; EntityIds = '[{"type":"AzureResourceId","id":"' + "$script:Rg/Microsoft.Insights/dataCollectionRules/dcr1" + '"}]' })
        Add-SIRecordPartFromSource -SourceSystem exposure-graph -Object ([pscustomobject]@{ NodeId = 'eg-vm'; NodeLabel = 'microsoft.compute/virtualmachines'; EntityIds = '[{"type":"AzureResourceId","id":"' + $script:Vm + '"}]' })
        Set-SIRecordPullFromSource -SourceSystem arm -Complete $true
        @(Get-SICapturedRecords)
    }
}

AfterAll { Set-SIAzureCiScope -Scope $null }

Describe 'the list: Azure CI types and the child types that roll up (data-model collection-scope)' {
    It 'reads an ARM id: type after the last provider, the path parent, lower case' {
        $i = Get-SIArmIdInfo "$script:Vm/extensions/MDE.Windows"
        $i.Type | Should -Be 'microsoft.compute/virtualmachines/extensions'
        $i.Name | Should -Be 'mde.windows'
        $i.Parent | Should -Be $script:VmL
        (Get-SIArmIdInfo $script:Vm).Parent | Should -Be ''
        Get-SIArmIdInfo '/subscriptions/s1' | Should -BeNullOrEmpty
        Get-SIArmIdInfo "$script:Vm/extensions" | Should -BeNullOrEmpty -Because 'a type without a name is not a resource id'
        (Get-SIArmIdInfo "$script:Vm/providers/Microsoft.Insights/diagnosticSettings/d1").Type | Should -Be 'microsoft.insights/diagnosticsettings'
    }
    It 'the shipped list: the CI types, the child rules (v2.2 roll-up rules + the owner''s disks and SQL databases), a public IP kept as its own CI' {
        foreach ($t in 'microsoft.compute/virtualmachines', 'microsoft.sql/servers', 'microsoft.network/virtualnetworks', 'microsoft.network/publicipaddresses', 'microsoft.cognitiveservices/accounts') {
            $script:Scope.Top.Contains($t) | Should -BeTrue -Because $t
        }
        foreach ($t in 'microsoft.insights/datacollectionrules', 'microsoft.app/jobs', 'microsoft.insights/metricalerts', 'microsoft.compute/virtualmachines/extensions', 'microsoft.sql/servers/databases') {
            $script:Scope.Top.Contains($t) | Should -BeFalse -Because "$t is not a CI type"
        }
        $exp = @{
            'microsoft.compute/virtualmachines/extensions'      = 'si_vm_extensions'
            'microsoft.compute/disks'                           = 'si_disks'
            'microsoft.network/networkinterfaces'               = 'si_network_interfaces'
            'microsoft.network/virtualnetworks/subnets'         = 'si_subnets'
            'microsoft.sql/servers/databases'                   = 'si_sql_databases'
            'microsoft.sql/servers/firewallrules'               = 'si_sql_firewall_rules'
            'microsoft.cognitiveservices/accounts/deployments'  = 'si_ai_deployments'
            'microsoft.network/publicipaddresses'               = 'si_public_ip_addresses'
        }
        foreach ($k in $exp.Keys) { $script:Scope.Rules[$k].Field | Should -Be $exp[$k] -Because $k }
        $script:Scope.Rules['microsoft.compute/disks'].ParentBy | Should -Be @('managedBy') -Because 'owner 2026-10-11: a disk folds into its VM by managedBy'
        $script:Scope.Rules['microsoft.network/publicipaddresses'].KeepOwnCi | Should -BeTrue
        $script:Scope.Rules['microsoft.compute/virtualmachines/extensions'].KeepOwnCi | Should -BeFalse
    }
    It 'the shipped data model is valid; a rollUpInto with an unknown field or a bad parentBy is refused' {
        @(Test-SIDataModel -Model $script:Model) | Should -BeNullOrEmpty
        $doc = [pscustomobject]@{ azureResourceTypes = @([pscustomobject]@{ type = 'microsoft.compute/virtualmachines/extensions'; rollUpInto = [pscustomobject]@{ parentTypes = @(); parentBy = @('a b'); field = 'si_nope' } }, [pscustomobject]@{ type = 'not-a-type' }) }
        $fields = @{}; foreach ($f in @($script:Model['field-catalog'].fields)) { $fields[[string]$f.name] = $f }
        $p = @(Test-SIAzureCiScopeItems -Document $doc -Fields $fields)
        ($p -join ' | ') | Should -Match 'names no parentTypes'
        ($p -join ' | ') | Should -Match "parentBy 'a b'"
        ($p -join ' | ') | Should -Match "field 'si_nope' is not in the field catalog"
        ($p -join ' | ') | Should -Match "'not-a-type' is not an Azure resource type"
    }
    It 'a customer adds a type (collection-scope.custom.json): it becomes a CI type' {
        $ov = Join-Path ([IO.Path]::GetTempPath()) ('si-scope-' + [guid]::NewGuid().ToString('N'))
        New-Item -ItemType Directory -Path $ov | Out-Null
        try {
            [IO.File]::WriteAllText((Join-Path $ov 'collection-scope.custom.json'), '{ "kind": "collection-scope", "azureResourceTypes": [ { "type": "microsoft.insights/datacollectionrules", "group": "monitoring" } ] }')
            $t = Get-SIDataModelTemplate -Name 'collection-scope' -Root $script:Dm -OverlayRoot $ov
            $s = ConvertTo-SIAzureCiScope -Document $t.Document
            $s.Top.Contains('microsoft.insights/datacollectionrules') | Should -BeTrue
            (Resolve-SIAzurePlacement -Id "$script:Rg/Microsoft.Insights/dataCollectionRules/dcr1" -Scope $s).Action | Should -Be 'record'
            (Resolve-SIAzurePlacement -Id "$script:Rg/Microsoft.Insights/dataCollectionRules/dcr1" -Scope $script:Scope).Action | Should -Be 'drop'
        } finally { Remove-Item -LiteralPath $ov -Recurse -Force -ErrorAction SilentlyContinue }
    }
    It 'the install''s scope is read once from the data model (shipped + overrides); unreadable = every type recorded as before' {
        Set-SIAzureCiScope -Scope $null
        $s = Get-SIAzureCiScope
        $s.Top.Contains('microsoft.compute/virtualmachines') | Should -BeTrue
        $s.Rules.ContainsKey('microsoft.compute/disks') | Should -BeTrue
        (Resolve-SIAzurePlacement -Id "$script:Vm/extensions/x" -Scope $null).Action | Should -Be 'record' -Because 'no scope: nothing is held back'
    }
}

Describe 'placement: child, CI type, not recorded' {
    It 'path children, managedBy disks, network interfaces by their VM, an unlisted nested type under a listed parent' {
        $p = Resolve-SIAzurePlacement -Id "$script:Vm/extensions/MDE.Windows" -Scope $script:Scope
        $p.Action | Should -Be 'child'; $p.ParentId | Should -Be $script:VmL
        $d = Resolve-SIAzurePlacement -Id "$script:Rg/Microsoft.Compute/disks/d1" -Object ([pscustomobject]@{ managedBy = $script:Vm }) -Scope $script:Scope
        $d.Action | Should -Be 'child'; $d.ParentId | Should -Be $script:VmL
        $n = Resolve-SIAzurePlacement -Id "$script:Rg/Microsoft.Network/networkInterfaces/n1" -Object ([pscustomobject]@{ properties = [pscustomobject]@{ virtualMachine = [pscustomobject]@{ id = $script:Vm } } }) -Scope $script:Scope
        $n.Action | Should -Be 'child'; $n.ParentId | Should -Be $script:VmL
        (Resolve-SIAzurePlacement -Id "$script:Rg/Microsoft.Network/virtualNetworks/vn1/subnets/default" -Scope $script:Scope).ParentId | Should -Be "$script:Rg/Microsoft.Network/virtualNetworks/vn1".ToLowerInvariant()
        (Resolve-SIAzurePlacement -Id "$script:Rg/Microsoft.Sql/servers/sql1/databases/db1" -Scope $script:Scope).ParentId | Should -Be "$script:Rg/Microsoft.Sql/servers/sql1".ToLowerInvariant()
        $slot = Resolve-SIAzurePlacement -Id "$script:Rg/Microsoft.Web/sites/app1/slots/staging" -Scope $script:Scope
        $slot.Action | Should -Be 'child' -Because 'a nested type that is not listed is a part of its listed parent'
        $slot.ParentId | Should -Be "$script:Rg/Microsoft.Web/sites/app1".ToLowerInvariant()
    }
    It 'not recorded: a type that is not a CI type, a child whose parent is not known; a public IP is a CI AND listed on its NIC' {
        foreach ($id in "$script:Rg/Microsoft.Insights/dataCollectionRules/d", "$script:Rg/Microsoft.App/jobs/j", "$script:Rg/Microsoft.Insights/metricAlerts/a") {
            (Resolve-SIAzurePlacement -Id $id -Scope $script:Scope).Action | Should -Be 'drop' -Because $id
        }
        $u = Resolve-SIAzurePlacement -Id "$script:Rg/Microsoft.Compute/disks/unattached" -Object ([pscustomobject]@{ managedBy = $null }) -Scope $script:Scope
        $u.Action | Should -Be 'drop' -Because 'a child is never a CI of its own -- an unattached disk has no parent CI'
        $ip = Resolve-SIAzurePlacement -Id "$script:Rg/Microsoft.Network/publicIPAddresses/pip1" -Object ([pscustomobject]@{ properties = [pscustomobject]@{ ipConfiguration = [pscustomobject]@{ id = "$script:Rg/Microsoft.Network/networkInterfaces/nic1/ipConfigurations/c1" } } }) -Scope $script:Scope
        $ip.Action | Should -Be 'record'
        $ip.AlsoChildOf | Should -Be "$script:Rg/Microsoft.Network/networkInterfaces/nic1".ToLowerInvariant()
    }
}

Describe 'record capture: a child is a part of its parent, never a record of its own' {
    BeforeAll { $script:Caps = Capture }
    It 'records only the CI types: the VM, the public IP, the SQL server and the Exposure Graph VM node -- no extension, NIC, disk, database, firewall rule or DCR' {
        $keys = @($script:Caps | ForEach-Object { '{0}|{1}|{2}' -f $_.Provider, $_.RecordType, $_.Key } | Sort-Object)
        $keys | Should -Be @(
            "azure|azure_resource|$script:VmL",
            "azure|azure_resource|$($script:Rg.ToLowerInvariant())/microsoft.sql/servers/sql1",
            "azure|public_ip|$($script:Rg.ToLowerInvariant())/microsoft.network/publicipaddresses/pip1",
            'eg|azure_resource|eg-vm')
        $global:SIRecordCaptureState.Dropped.Values | Measure-Object -Sum | Select-Object -ExpandProperty Sum | Should -Be 2 -Because 'the unattached disk and the DCR of the Azure read are counted as not recorded (the Exposure Graph''s DCR node is simply not routed)'
    }
    It 'the VM record lists every child: extensions (name, type, publisher), the NIC, the disk, the public IP folded up from the NIC' {
        $vm = @($script:Caps | Where-Object { $_.Key -eq $script:VmL -and $_.Provider -eq 'azure' })[0]
        $ids = @($vm.Object.children | ForEach-Object { $_.id } | Sort-Object)
        $ids | Should -Be @(
            "$($script:Rg.ToLowerInvariant())/microsoft.compute/disks/vm1_osdisk",
            "$script:VmL/extensions/azuremonitorwindowsagent",
            "$script:VmL/extensions/mde.windows",
            "$($script:Rg.ToLowerInvariant())/microsoft.network/networkinterfaces/nic1",
            "$($script:Rg.ToLowerInvariant())/microsoft.network/publicipaddresses/pip1")
        $res = ConvertTo-SIRecordRows -Captured @($script:Caps) -Model $script:Model
        @($res.Errors) | Should -BeNullOrEmpty
        $row = @($res.Rows | Where-Object { $_.si_record_key -eq "azure:$script:VmL" })[0]
        @($row.si_vm_extensions).Count | Should -Be 2
        $mde = @($row.si_vm_extensions | Where-Object { $_.type -eq 'MDE.Windows' })[0]
        $mde.publisher | Should -Be 'Microsoft.Azure.AzureDefenderForServers'
        $mde.name | Should -Be 'MDE.Windows'
        @($row.si_disks)[0].sku | Should -Be 'Premium_LRS'
        @($row.si_network_interfaces)[0].private_ip_addresses | Should -Be '10.0.0.4'
        @($row.si_public_ip_addresses)[0].ip_address | Should -Be '20.1.2.3'
        @($row.si_child_resources).Count | Should -Be 5
        $sql = @($res.Rows | Where-Object { $_.si_record_key -like 'azure:*/microsoft.sql/servers/sql1' })[0]
        @($sql.si_sql_databases)[0].sku | Should -Be 'S0' -Because 'owner 2026-10-11: a SQL database folds into its server'
        @($sql.si_sql_firewall_rules)[0].end_ip | Should -Be '255.255.255.255'
    }
    It 'Defender for Cloud and the Exposure Graph never replace the Azure read''s richer view of a child' {
        $vm = @($script:Caps | Where-Object { $_.Key -eq $script:VmL -and $_.Provider -eq 'azure' })[0]
        $ext = @($vm.Object.children | Where-Object { $_.id -eq "$script:VmL/extensions/mde.windows" })[0]
        $ext.shape.publisher | Should -Be 'Microsoft.Azure.AzureDefenderForServers'
    }
    It 'a child seen only by the Exposure Graph is still a part of its parent (its ARM id names it)' {
        $null = Reset-SIRecordCapture -Engine azure -Clear
        Set-SIAzureCiScope -Scope $script:Scope
        Add-SIRecordPartFromSource -SourceSystem arm -Object (Arm "$script:Rg/Microsoft.Network/virtualNetworks/vn1" 'microsoft.network/virtualnetworks')
        Add-SIRecordPartFromSource -SourceSystem exposure-graph -Object ([pscustomobject]@{ NodeId = 'eg-sn'; NodeLabel = 'microsoft.network/virtualnetworks/subnets'; EntityIds = @([pscustomobject]@{ type = 'AzureResourceId'; id = "$script:Rg/Microsoft.Network/virtualNetworks/vn1/subnets/default" }) })
        $c = @(Get-SICapturedRecords)
        $c.Count | Should -Be 1
        @($c[0].Object.children)[0].id | Should -Be "$($script:Rg.ToLowerInvariant())/microsoft.network/virtualnetworks/vn1/subnets/default"
    }
    It 'a run collected in parts: the folding runs before the hand-over is bucketed; a parent never captured is not published' {
        $null = Reset-SIRecordCapture -Engine azure -Clear
        Set-SIAzureCiScope -Scope $script:Scope
        # the public IP first: listed on the NIC, which only later turns out to be the VM's child
        Add-SIRecordPartFromSource -SourceSystem arm -Object (Arm "$script:Rg/Microsoft.Network/publicIPAddresses/pip9" 'microsoft.network/publicipaddresses' @{ properties = [pscustomobject]@{ ipConfiguration = [pscustomobject]@{ id = "$script:Rg/Microsoft.Network/networkInterfaces/nic9/ipConfigurations/c" } } })
        Add-SIRecordPartFromSource -SourceSystem arm -Object (Arm "$script:Rg/Microsoft.Network/networkInterfaces/nic9" 'microsoft.network/networkinterfaces' @{ properties = [pscustomobject]@{ virtualMachine = [pscustomobject]@{ id = $script:Vm } } })
        Add-SIRecordPartFromSource -SourceSystem arm -Object (Arm "$script:Vm/extensions/e9" 'microsoft.compute/virtualmachines/extensions')
        $st = $global:SIRecordCaptureState
        @($st.Records.Keys | Where-Object { $_ -like '*networkinterfaces/nic9' }).Count | Should -Be 1 -Because 'before the fold the NIC holds the public IP''s link'
        Resolve-SIRecordChildren -State $st | Should -Be 1
        $vmRec = $st.Records["azure|azure_resource|$script:VmL"]
        @($vmRec.Parts.Keys | Where-Object { $_ -like 'child|*' }).Count | Should -Be 3
        # the VM itself was never captured in this process: its record is child parts only -> not published, dropped at the merge
        Test-SIRecordChildOnly $vmRec | Should -BeTrue
        @(Get-SICapturedRecords | Where-Object { $_.RecordType -eq 'azure_resource' }).Count | Should -Be 0
        Remove-SIRecordHandoverOrphans -State $st | Should -BeGreaterThan 0
        $st.Records.ContainsKey("azure|azure_resource|$script:VmL") | Should -BeFalse
        $t = [IO.File]::ReadAllText((Join-Path $script:SIRoot 'engine\data-model\SI-RecordHandover.ps1'))
        $t.IndexOf('Resolve-SIRecordChildren -State $State') | Should -BeLessThan $t.IndexOf('Get-SICollectPartIndex -Key ([string]$e.Key) -Parts $Buckets', $t.IndexOf('function Save-SIRecordHandover'))
    }
}

Describe 'the CI: every child id is a linked object of its parent' {
    It 'child links (type child_resource, no record key) follow the records; primary ids, lifecycle and the record links are unchanged' {
        $now = [datetime]::UtcNow
        $rec = [pscustomobject]@{ si_provider = 'azure'; si_record_type = 'azure_resource'; si_class = 'cloud_resource'; si_record_key = "azure:$script:VmL"
            si_collection_time = $now; si_source_last_seen = $now; si_collection_complete = $true; azure_resource_id = $script:VmL; si_asset_name = 'VM1'
            si_child_resources = @([pscustomobject]@{ id = "$script:VmL/extensions/mde.windows"; type = 'microsoft.compute/virtualmachines/extensions'; name = 'MDE.Windows' }, [pscustomobject]@{ id = "$script:VmL/extensions/ama"; type = 'microsoft.compute/virtualmachines/extensions'; name = 'ama' })
            si_vm_extensions = @([pscustomobject]@{ name = 'MDE.Windows'; type = 'MDE.Windows' }) }
        $mde = [pscustomobject]@{ si_provider = 'mde'; si_record_type = 'device'; si_class = 'device'; si_record_key = 'mde:m1'; si_collection_time = $now; si_source_last_seen = $now; si_collection_complete = $true; mde_device_id = 'm1'; azure_resource_id = $script:VmL }
        $ci = New-SICiDocument -CiId 'ci-1' -Records @($rec, $mde) -Catalog $script:Model['field-catalog'] -FeedLatest (Get-SIFeedLatest -Records @($rec, $mde)) -Now $now
        $links = @($ci['si_linked_objects'])
        $links.Count | Should -Be 4
        $kids = @($links | Where-Object { $_.type -eq 'child_resource' })
        @($kids | ForEach-Object { $_.id }) | Should -Be @("$script:VmL/extensions/ama", "$script:VmL/extensions/mde.windows")
        foreach ($k in $kids) { $k.record_key | Should -Be ''; $k.primary | Should -BeFalse; $k.state | Should -Be 'active'; $k.provider | Should -Be 'azure' }
        $ci['si_link_azure'] | Should -Be $script:VmL
        $ci['si_link_mde'] | Should -Be 'm1'
        $ci['si_lifecycle'] | Should -Be 'active'
        @($ci['si_vm_extensions']).Count | Should -Be 1
        # the SQL items: a child id becomes a sidata.CiLink row (a finding on it finds the CI), never a record -> CI mapping
        $items = ConvertTo-SICiSqlItems -Cis @($ci)
        @($items.Links | Where-Object { $_.RecordType -eq 'child_resource' }).Count | Should -Be 2
        @($items.Map | ForEach-Object { $_.RecordKey }) | Should -Not -Contain ''
        # SI_CI_CL: Risk Analysis reads every linked id (its _ciKeys) -- the child ids lead to this CI there too
        $row = ConvertTo-SICiPostRow -Ci $ci
        @($row.si_linked_objects | ForEach-Object { $_.id }) | Should -Contain "$script:VmL/extensions/mde.windows"
        @($row.si_vm_extensions).Count | Should -Be 1
    }
    It 'SI_CI_CL carries the Azure type, subscription, resource group and region, and the VM extensions; the CI build version moved' {
        foreach ($f in 'si_azure_resource_type', 'si_azure_subscription_id', 'si_azure_resource_group', 'si_azure_location', 'si_vm_extensions') { $script:SICiPostFields | Should -Contain $f }
        $ci = [ordered]@{ si_ci_id = 'c'; si_class = 'cloud_resource'; si_azure_resource_type = 'microsoft.web/sites'; si_azure_subscription_id = 's1'; si_azure_resource_group = 'rg1'; si_azure_location = 'westeurope'; si_collection_time = [datetime]::UtcNow }
        $r = ConvertTo-SICiPostRow -Ci $ci
        $r.si_azure_resource_type | Should -Be 'microsoft.web/sites'
        $r.si_azure_location | Should -Be 'westeurope'
        $script:SICiBuildVersion | Should -BeGreaterOrEqual 6 -Because 'the CIs change (children roll up, the CI scope): every CI is rebuilt once'
    }
}

Describe 'Defender for Cloud: one row per parent, the children listed' {
    BeforeAll {
        function script:Raw($id, $rid, $rec, $name, $sev = 'Medium') {
            [pscustomobject]@{ AssessmentId = $id; AssessmentKey = $id; ResourceId = $rid; ResourceName = $name; ResourceType = 'x'; ResourceSource = 'Azure'
                SubscriptionId = 's1'; ResourceGroup = 'RG1'; Recommendation = $rec; Severity = $sev; RecommendationCategory = ''; SecurityIssue = ''; Categories = ''
                Tactics = ''; Threats = ''; Description = ''; Remediation = ''; ImplementationEffort = ''; UserImpact = ''; PortalLink = ''; RiskLevel = ''; RiskFactors = ''
                FirstEvaluated = ''; StatusChanged = ''; MaxCvssScore = ''; ImageUri = '' }
        }
        $script:RecRaw = @(
            (Raw 'a1' "$script:Vm/extensions/MDE.Windows" 'Only approved VM extensions should be installed' 'MDE.Windows'),
            (Raw 'a2' "$script:Vm/extensions/CustomScript" 'Only approved VM extensions should be installed' 'CustomScript' 'High'),
            (Raw 'a3' "$script:Rg/Microsoft.Sql/servers/sql1/databases/db1" 'Vulnerabilities on your SQL databases should be remediated' 'db1'),
            (Raw 'a4' "$script:Rg/Microsoft.Sql/servers/sql1/databases/db2" 'Vulnerabilities on your SQL databases should be remediated' 'db2'),
            (Raw 'a5' "$script:Rg/Microsoft.Compute/disks/VM1_OsDisk" 'Disks should be encrypted' 'VM1_OsDisk'),
            (Raw 'a6' "$script:Rg/Microsoft.KeyVault/vaults/kv1" 'Enable purge protection' 'kv1')
        )
    }
    It 'extensions -> one VM row; SQL databases -> one server row; the disk by the VM the capture knows; a CI type stays its own row' {
        $kids = @{ ("$script:Rg/Microsoft.Compute/disks/VM1_OsDisk").ToLowerInvariant() = $script:VmL }
        $rows = @(ConvertTo-SIDefenderRecommendationRows -Raw $script:RecRaw -CollectionTime ([datetime]::UtcNow) -RunId 'r1' -Scope $script:Scope -ChildParents $kids)
        $ext = @($rows | Where-Object { $_.Recommendation -like 'Only approved*' })
        $ext.Count | Should -Be 1
        $ext[0].ResourceId | Should -Be $script:Vm -Because 'the parent as the child id spells it'
        $ext[0].ResourceName | Should -Be 'VM1'
        $ext[0].ResourceType | Should -Be 'microsoft.compute/virtualmachines'
        $ext[0].RowKind | Should -Be 'RolledUpEntities'
        $ext[0].AffectedEntityKind | Should -Be 'AzureChildResource'
        $ext[0].AffectedEntityCount | Should -Be 2
        $ext[0].AffectedEntities | Should -Be 'CustomScript; MDE.Windows'
        $ext[0].Severity | Should -Be 'High'
        $db = @($rows | Where-Object { $_.Recommendation -like 'Vulnerabilities on your SQL*' })
        $db.Count | Should -Be 1
        $db[0].ResourceId | Should -Be "$script:Rg/Microsoft.Sql/servers/sql1"
        $db[0].AffectedEntities | Should -Be 'db1; db2'
        $disk = @($rows | Where-Object { $_.Recommendation -eq 'Disks should be encrypted' })[0]
        $disk.ResourceId | Should -Be $script:VmL
        $disk.AffectedEntities | Should -Be 'VM1_OsDisk'
        $kv = @($rows | Where-Object { $_.Recommendation -eq 'Enable purge protection' })[0]
        $kv.RowKind | Should -Be 'Resource'
    }
    It 'without the capture''s map a disk keeps its own row (its id is still a linked object of the VM CI); without a scope nothing rolls up' {
        $rows = @(ConvertTo-SIDefenderRecommendationRows -Raw $script:RecRaw -CollectionTime ([datetime]::UtcNow) -RunId 'r1' -Scope $script:Scope)
        @($rows | Where-Object { $_.Recommendation -eq 'Disks should be encrypted' })[0].RowKind | Should -Be 'Resource'
        $plain = @(ConvertTo-SIDefenderRecommendationRows -Raw $script:RecRaw -CollectionTime ([datetime]::UtcNow) -RunId 'r1')
        @($plain | Where-Object RowKind -eq 'Resource').Count | Should -Be 6
    }
    It 'the recommendations stage passes the install''s scope and the capture''s child map' {
        $t = [IO.File]::ReadAllText((Join-Path $script:SIRoot 'engine\asset-profiling\stages\Invoke-Recommendations.ps1'))
        $t | Should -Match 'Get-SIDefenderRecommendations -CollectionTime \$ct -RunId \(\[string\]\$RunContext\.RunId\) -Scope \$azScope -ChildParents \$childParents'
        $t | Should -Match 'Get-SIRecordChildParentMap'
    }
}

Describe 'retirement: a CI no current record builds is retired, never deleted' {
    It 'the statement: only CIs no grouping member points to, older than the brake; retired + hash cleared + recorded; nothing deleted' {
        $s = Get-SICiRetireSql -FloorDays 7
        $s | Should -Match 'DATEADD\(day, -7, SYSUTCDATETIME\(\)\)'
        $s | Should -Match 'NOT EXISTS \(SELECT 1 FROM sidata\.CiGroupMember m JOIN sidata\.CiRecord r ON r\.RecordKey = m\.RecordKey WHERE r\.CiId = c\.CiId\)'
        $s | Should -Match "SET Lifecycle = N'retired', ContentHash = NULL"
        $s | Should -Match "JSON_MODIFY\(c\.DocJson, '\$\.si_lifecycle', N'retired'\)"
        $s | Should -Match 'INSERT sidata\.CiChange'
        $s | Should -Not -Match '(?i)\bDELETE\b|\bTRUNCATE\b|\bDROP\b'
        (Get-SICiRetireSql -FloorDays 0) | Should -Match 'DATEADD\(day, -1,' -Because 'never under 1 day'
        Get-SICiRetireDays -Value $null | Should -Be 7
        Get-SICiRetireDays -Value '14' | Should -Be 14
        Get-SICiRetireDays -Value 'x' | Should -Be 7
    }
    It 'the CI build runs it after the batches, before the build state, and says what it retired' {
        $t = [IO.File]::ReadAllText((Join-Path $script:SIRoot 'engine\data-model\SI-CiBuildRun.ps1'))
        $i = $t.IndexOf('Get-SICiRetireSql -FloorDays (Get-SICiRetireDays)')
        $i | Should -BeGreaterThan $t.IndexOf('Invoke-SICiRelationStep @relArgs')
        $i | Should -BeLessThan $t.IndexOf('Get-SICiMarkBuiltSql -Thresholds $thresholds')
    }
}
