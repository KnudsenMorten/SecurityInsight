#Requires -Version 5.1
<#
    #727 -- THE AZURE RECORDS STREAM TOO (owner 2026-10-16: "same method across all cust ... like streaming no matter size" /
    "tenants can have millions of azure obj").

    After #721 the producer streamed every record but the Azure ones: an Azure child resource (a disk, a network interface,
    an extension ...) folds into its parent's record at the hand-over, so the Azure records stayed held -- and the Azure
    reads after the sources (Defender for Cloud, the management groups, the Azure context) read them back from memory.
    What these keep true (offline):
      1. EQUIVALENCE: the streamed Azure hand-over gives EXACTLY the records the in-memory capture gave -- every part, the
         ORDER of the children, the later part wins, the engines -- with children read before their parent, a public IP
         read before its network interface (folded up twice), a parent that never arrives, the graph's poorer view of a
         child replaced by the Azure read; tiny, small and larger sets through the one path;
      2. THE AZURE READS on a streamed capture: the context parts, the management groups and Defender for Cloud reach the
         streamed records (none held), the same counts as in memory; Resource Graph is read page by page;
      3. BOUNDED: what is kept per Azure record is on disk (the record index) or one number (the groups); the hand-over
         folds one group file at a time; an Azure record counts once for the bucket count; the bucket count grows with the
         records;
      4. GUARD: no provider is kept in memory by the capture, no count or size picks a method, the reads stay page by page.
    PS 5.1 and pwsh 7.
#>

BeforeAll {
    $script:SIRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    . (Join-Path $script:SIRoot 'engine\_shared\SI-CollectParts.ps1')
    . (Join-Path $script:SIRoot 'engine\_shared\SI-DiskLookup.ps1')
    . (Join-Path $script:SIRoot 'engine\data-model\SI-RecordCapture.ps1')
    . (Join-Path $script:SIRoot 'engine\data-model\SI-RecordHandover.ps1')
    . (Join-Path $script:SIRoot 'engine\data-model\SI-DataModelTemplates.ps1')
    . (Join-Path $script:SIRoot 'engine\asset-profiling\discovery\Invoke-SIArgPaged.ps1')
    . (Join-Path $script:SIRoot 'engine\asset-profiling\discovery\Get-SIMdcExposure.ps1')
    . (Join-Path $script:SIRoot 'engine\asset-profiling\discovery\Get-SIMdcAssessmentSummary.ps1')
    . (Join-Path $script:SIRoot 'engine\asset-profiling\discovery\Get-SIDerivedSources.ps1')
    . (Join-Path $script:SIRoot 'engine\asset-profiling\discovery\Get-SIAzureContext.ps1')
    $script:Scope = ConvertTo-SIAzureCiScope -Document (Get-SIDataModel -Root (Join-Path $script:SIRoot 'data-model'))['collection-scope']
    function script:MemStore {
        $m = @{}
        [pscustomobject]@{
            Data  = $m
            Write = { param($Path, $Text) $m[$Path] = [string]$Text }.GetNewClosure()
            Read  = { param($Path) $m[$Path] }.GetNewClosure()
            List  = { param($Prefix) @($m.Keys | Where-Object { $_.StartsWith($Prefix) } | Sort-Object) }.GetNewClosure()
        }
    }
    function script:Ids([int]$u) {
        $rg = '/subscriptions/sub{0}/resourceGroups/RG{1}' -f ($u % 3), ($u % 4)
        $vm = "$rg/providers/Microsoft.Compute/virtualMachines/VM$u"; $nic = "$rg/providers/Microsoft.Network/networkInterfaces/nic$u"
        @{ Rg = $rg.ToLowerInvariant(); Sub = ('sub{0}' -f ($u % 3)); Vm = $vm; Nic = $nic; Disk = "$rg/providers/Microsoft.Compute/disks/VM${u}_os"
            PipA = "$rg/providers/Microsoft.Network/publicIPAddresses/pip${u}a"; PipB = "$rg/providers/Microsoft.Network/publicIPAddresses/pip${u}b"
            Ext1 = "$vm/extensions/MDE.Windows"; Ext2 = "$vm/extensions/AzureMonitorWindowsAgent"; Kv = "$rg/providers/Microsoft.KeyVault/vaults/kv$u"
            NicLost = "$rg/providers/Microsoft.Network/networkInterfaces/nic$u-lost"; VmGone = "$rg/providers/Microsoft.Compute/virtualMachines/VM$u-gone"
            DiskSpare = "$rg/providers/Microsoft.Compute/disks/spare$u"; Dcr = "$rg/providers/Microsoft.Insights/dataCollectionRules/dcr$u" }
    }
    function script:Arm([string]$Id, [string]$Type, [hashtable]$Extra = @{}) {
        $o = [ordered]@{ id = $Id; name = ($Id -split '/')[-1]; type = $Type; properties = [pscustomobject]@{} }
        foreach ($k in $Extra.Keys) { $o[$k] = $Extra[$k] }
        [pscustomobject]$o
    }
    function script:EgNode([string]$Id, [string]$Label, [int]$n) {
        [pscustomobject]@{ NodeId = "eg-$n"; NodeLabel = $Label; NodeName = ($Id -split '/')[-1]; EntityIds = ('[{"type":"AzureResourceId","id":"' + $Id + '"}]') }
    }
    # the Azure reads after the sources, as one answer each (the -Query seams)
    function script:ContextQuery([int]$U) {
        $script:CtxU = $U
        {
            param($Kql, $Label, $Unscoped)
            $units = 0..($script:CtxU - 1)
            $rows = @()
            if ($Kql -match '^recoveryservicesresources') { $rows = @($units | Where-Object { $_ % 2 -eq 0 } | ForEach-Object { [pscustomobject]@{ ResourceId = (Ids $_).Vm.ToLowerInvariant(); LastTime = '2026-10-10T01:15:00Z'; LastStatus = 'Completed'; State = 'Protected'; VaultName = 'rsv'; Items = 1 } }) }
            elseif ($Kql -match '^authorizationresources') { $rows = @($units | ForEach-Object { $x = Ids $_; $sc = if ($_ % 2) { $x.Kv.ToLowerInvariant() } else { $x.Rg }; [pscustomobject]@{ Scope = $sc; Assignments = @([pscustomobject]@{ p = ('bbbbbbbb-0000-0000-0000-{0:D12}' -f ($_ % 5)); t = 'User'; r = '8e3af657-a8ff-443c-a75c-2fe8c4bcb635' }) } }) }
            elseif ($Kql -match 'policyinsights/policystates') { $rows = @($units | Where-Object { $_ % 3 -eq 0 } | ForEach-Object { [pscustomobject]@{ ResourceId = (Ids $_).Kv.ToLowerInvariant(); NonCompliant = 2; Top = @([pscustomobject]@{ id = '/p/p1'; name = 'Purge protection' }, [pscustomobject]@{ id = '/p/p2'; name = '' }) } }) }
            elseif ($Kql -match "policydefinitions'\s*\r?\n\| project") { $rows = @([pscustomobject]@{ PolicyId = '/p/p2'; PolicyName = 'Private link' }) }
            elseif ($Kql -match '^resourcechanges') { $rows = @($units | ForEach-Object { $t = '2026-10-0{0}T12:00:00Z' -f (1 + $_ % 9); $tv = $t; if ($_ % 2) { $tv = [datetime]::Parse($t, [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::AdjustToUniversal) }; [pscustomobject]@{ ResourceId = (Ids $_).Kv.ToLowerInvariant(); ChangeTime = $tv; ChangedBy = ('cccccccc-0000-0000-0000-{0:D12}' -f ($_ % 4)); ChangedByType = 'Application'; ChangeType = 'Update'; ClientType = 'CLI'; Changes = 1 + $_ % 3 } }) }
            elseif ($Kql -match '^patchassessmentresources') { $rows = @($units | ForEach-Object { [pscustomobject]@{ ResourceId = (Ids $_).Vm.ToLowerInvariant(); AssessedAt = '2026-10-11T02:00:00Z'; Critical = $_ % 3; Security = 5; RebootPending = $true; Status = 'Succeeded' } }) }
            elseif ($Kql -match '^securityresources') { $rows = @(0..2 | ForEach-Object { [pscustomobject]@{ SubscriptionId = "sub$_"; Plan = 'VirtualMachines'; Tier = 'Standard'; SubPlan = 'P2' }; [pscustomobject]@{ SubscriptionId = "sub$_"; Plan = 'CloudPosture'; Tier = 'Standard'; SubPlan = '' } }) }
            [pscustomobject]@{ Rows = $rows; Complete = $true; Error = $null }
        }
    }
    # one deterministic Azure discovery: the graph's nodes first (an extension seen by the graph before the Azure read), then
    # per unit the Azure read -- a disk BEFORE its machine, a public IP BEFORE its network interface (folded up twice at the
    # hand-over), the machine, its extensions, the network interface, a second public IP after it, a key vault, a network
    # interface whose machine never arrives, an unattached disk and a data collection rule (not recorded); then Defender for
    # Cloud, the management groups and the Azure context
    function script:Invoke-AzCapture([int]$U, [switch]$NoMg) {
        Set-SIAzureCiScope -Scope $script:Scope
        for ($k = 0; $k -lt $U; $k++) {
            $x = Ids $k
            Add-SIRecordPartFromSource -SourceSystem exposure-graph -Object (EgNode $x.Vm 'microsoft.compute/virtualmachines' (3 * $k))
            Add-SIRecordPartFromSource -SourceSystem exposure-graph -Object (EgNode $x.Ext1 'microsoft.compute/virtualmachines/extensions' (3 * $k + 1))
        }
        for ($k = 0; $k -lt $U; $k++) {
            $x = Ids $k
            Add-SIRecordPartFromSource -SourceSystem arm -Object (Arm $x.Disk 'microsoft.compute/disks' @{ managedBy = $x.Vm; sku = [pscustomobject]@{ name = 'Premium_LRS' }; properties = [pscustomobject]@{ diskSizeGB = 128 + $k } })
            Add-SIRecordPartFromSource -SourceSystem arm -Object (Arm $x.PipA 'microsoft.network/publicipaddresses' @{ properties = [pscustomobject]@{ ipAddress = "20.0.0.$k"; ipConfiguration = [pscustomobject]@{ id = "$($x.Nic)/ipConfigurations/ipconfig1" } } })
            Add-SIRecordPartFromSource -SourceSystem arm -Object (Arm $x.Vm 'microsoft.compute/virtualmachines' @{ properties = [pscustomobject]@{ hardwareProfile = [pscustomobject]@{ vmSize = 'Standard_D2s_v5' } } })
            Add-SIRecordPartFromSource -SourceSystem arm -Object (Arm $x.Ext1 'microsoft.compute/virtualmachines/extensions' @{ properties = [pscustomobject]@{ type = 'MDE.Windows'; publisher = 'Microsoft.Azure.AzureDefenderForServers' } })
            Add-SIRecordPartFromSource -SourceSystem arm -Object (Arm $x.Ext2 'microsoft.compute/virtualmachines/extensions' @{ properties = [pscustomobject]@{ type = 'AzureMonitorWindowsAgent'; publisher = 'Microsoft.Azure.Monitor' } })
            Add-SIRecordPartFromSource -SourceSystem arm -Object (Arm $x.Nic 'microsoft.network/networkinterfaces' @{ properties = [pscustomobject]@{ virtualMachine = [pscustomobject]@{ id = $x.Vm } } })
            Add-SIRecordPartFromSource -SourceSystem arm -Object (Arm $x.PipB 'microsoft.network/publicipaddresses' @{ properties = [pscustomobject]@{ ipAddress = "52.0.0.$k"; ipConfiguration = [pscustomobject]@{ id = "$($x.Nic)/ipConfigurations/ipconfig2" } } })
            Add-SIRecordPartFromSource -SourceSystem arm -Object (Arm $x.Kv 'microsoft.keyvault/vaults' @{ properties = [pscustomobject]@{ enableSoftDelete = $true } })
            Add-SIRecordPartFromSource -SourceSystem arm -Object (Arm $x.NicLost 'microsoft.network/networkinterfaces' @{ properties = [pscustomobject]@{ virtualMachine = [pscustomobject]@{ id = $x.VmGone } } })
            Add-SIRecordPartFromSource -SourceSystem arm -Object (Arm $x.DiskSpare 'microsoft.compute/disks')
            Add-SIRecordPartFromSource -SourceSystem arm -Object (Arm $x.Dcr 'microsoft.insights/datacollectionrules')
        }
        Set-SIRecordPullFromSource -SourceSystem arm -Complete $true
        $script:CtxU = $U
        $null = Invoke-SIMdcExposureCapture -Query { param($q) @(0..($script:CtxU - 1) | Where-Object { $_ % 2 } | ForEach-Object { [pscustomobject]@{ ResourceId = (Ids $_).Vm; Assessments = @('Management ports should be closed on your virtual machines') } }) }
        $null = Invoke-SIMdcAssessmentSummaryCapture -Query { param($q) @(0..($script:CtxU - 1) | ForEach-Object { $x = Ids $_; foreach ($id in $x.Vm, $x.Disk) { [pscustomobject]@{ ResourceId = $id; Assessed = 4; Unhealthy = 1; High = 1; Medium = 0; Low = 0; TopHigh = @([pscustomobject]@{ id = 'k'; name = 'n'; severity = 'High' }) } } }) } 3>$null
        if (-not $NoMg) { $null = Invoke-SIManagementGroupCapture -Query { param($q) @(0..2 | ForEach-Object { [pscustomobject]@{ SubscriptionId = "sub$_"; SubscriptionName = "Sub $_"; Chain = @([pscustomobject]@{ name = 'prod'; displayName = 'Production' }, [pscustomobject]@{ name = 'root'; displayName = 'Tenant Root Group' }) } }) } -TenantNames @{} }
        $script:Done = Invoke-SIAzureContextCapture -Query (ContextQuery $U) -PrincipalNames { param([string[]]$Ids) $m = @{}; foreach ($i in $Ids) { $m[$i.ToLowerInvariant()] = 'name-' + $i.Substring(0, 4) }; $m } -Log { param($l, $m) }
    }
    # the records as the last step merges them (orphans dropped, as Publish-SIRecordHandover does): id -> everything a record
    # carries, its parts IN ORDER (the children's order is the parent's 'children' list)
    function script:Get-Merged($Store, [int]$Buckets) {
        $out = @{}
        for ($b = 0; $b -lt $Buckets; $b++) {
            $paths = @($Store.Data.Keys | Where-Object { $_ -match ('/bucket-{0:D5}-\d{{5}}\.json$' -f $b) } | Sort-Object)
            $m = $null
            foreach ($p in $paths) { $m = Merge-SIRecordHandover -Documents @($Store.Data[$p] | ConvertFrom-Json) -Into $m }
            if ($null -eq $m) { continue }
            $null = Remove-SIRecordHandoverOrphans -State $m
            foreach ($e in $m.Records.GetEnumerator()) {
                $r = $e.Value
                $parts = (@($r.Parts.Keys) | ForEach-Object { '{0}={1}' -f $_, [string]$r.Parts[$_].SIJson }) -join ';'
                $out[[string]$e.Key] = '{0}|{1}|{2}|{3}|{4}|{5}' -f $r.Provider, $r.RecordType, $r.Key, $r.ResourceType, ((@($r.Engines) | Where-Object { $_ } | Sort-Object) -join ','), $parts
            }
        }
        $out
    }
    function script:Invoke-Both([int]$U, [int]$Buckets, [switch]$NoMg) {
        $null = Reset-SIRecordCapture -Engine 'azure' -Clear
        Invoke-AzCapture $U -NoMg:$NoMg
        $doneA = $script:Done
        $a = MemStore; $null = Save-SIRecordHandover -Store $a -Engine azure -RunId r -Who discover -Buckets $Buckets -ChunkSize 37
        $null = Reset-SIRecordCapture -Engine 'azure' -Clear
        $s = Start-SIRecordCaptureStream
        Invoke-AzCapture $U -NoMg:$NoMg
        $held = $global:SIRecordCaptureState.Records.Count
        $count = Get-SIRecordCaptureCount
        $azRecords = $s.AzureIndex.Count; $azLines = $s.AzureLines; $idxPath = $s.AzureIndex.Path
        $b = MemStore; $nb = Save-SIRecordHandover -Store $b -Engine azure -RunId r -Who discover -Buckets $Buckets -ChunkSize 37
        [pscustomobject]@{ Memory = (Get-Merged $a $Buckets); Stream = (Get-Merged $b $Buckets); DoneMemory = $doneA; DoneStream = $script:Done; Held = $held
            Count = $count; AzRecords = $azRecords; AzLines = $azLines; StreamPath = $s.Path; IndexPath = $idxPath; Handed = $nb }
    }
}

AfterAll { $null = Reset-SIRecordCapture -Clear; Set-SIAzureCiScope -Scope $null }

Describe '1. EQUIVALENCE: the streamed Azure hand-over is the in-memory one' {
    It 'a <Name> estate: the same records, every part IN ORDER, the engines -- and nothing held' -TestCases @(
        @{ Name = 'tiny (1 unit)'; U = 1; Buckets = 1 }
        @{ Name = 'small (12 units)'; U = 12; Buckets = 3 }
        @{ Name = 'larger (150 units)'; U = 150; Buckets = 7 }
    ) {
        $r = Invoke-Both -U $U -Buckets $Buckets
        $r.Memory.Count | Should -BeGreaterThan 0
        @($r.Stream.Keys | Sort-Object) | Should -Be @($r.Memory.Keys | Sort-Object)
        foreach ($k in $r.Memory.Keys) { $r.Stream[$k] | Should -BeExactly $r.Memory[$k] -Because "record $k" }
        $r.Held | Should -Be 0 -Because 'every Azure part went to the stream'
        # the reads after the sources decorated the same records in both
        foreach ($k in @($r.DoneMemory.Keys)) { $r.DoneStream[$k] | Should -Be $r.DoneMemory[$k] -Because "context part $k" }
        $r.DoneStream.backup | Should -BeGreaterThan 0; $r.DoneStream.access | Should -BeGreaterThan 0; $r.DoneStream.attached | Should -BeGreaterThan 0
        # the stream's file and the record index's file are gone after the hand-over
        Test-Path -LiteralPath $r.StreamPath | Should -BeFalse
        Test-Path -LiteralPath $r.IndexPath | Should -BeFalse
    }
    It 'the fold: a disk read before its machine, a public IP read before its network interface (folded up twice), extensions -- all on the machine' {
        # without the management-group part: it keeps a child-only record from folding (#731, the same in memory -- below)
        $r = Invoke-Both -U 2 -Buckets 2 -NoMg
        foreach ($k in $r.Memory.Keys) { $r.Stream[$k] | Should -BeExactly $r.Memory[$k] -Because "record $k" }
        $x = Ids 1
        $vm = $r.Stream['azure|azure_resource|' + $x.Vm.ToLowerInvariant()]
        foreach ($c in $x.Disk, $x.PipA, $x.PipB, $x.Nic, $x.Ext1, $x.Ext2) { $vm | Should -Match ([regex]::Escape('child|' + $c.ToLowerInvariant() + '=')) }
        $r.Stream.ContainsKey('azure|azure_resource|' + $x.Nic.ToLowerInvariant()) | Should -BeFalse -Because 'the network interface folded into its machine'
        $r.Stream.ContainsKey('azure|public_ip|' + $x.PipA.ToLowerInvariant()) | Should -BeTrue -Because 'a public IP stays a CI of its own'
        $r.Stream.ContainsKey('azure|azure_resource|' + $x.VmGone.ToLowerInvariant()) | Should -BeFalse -Because 'a parent that never arrived is never published'
        $r.Stream.ContainsKey('azure|azure_resource|' + $x.Dcr.ToLowerInvariant()) | Should -BeFalse
        # the later part wins: the Azure read's view of the extension replaced the graph's (it names the publisher)
        $vm | Should -Match 'AzureDefenderForServers'
        # the context, the management groups and Defender for Cloud on the streamed records
        $vm | Should -Match 'backup=' ; $vm | Should -Match 'patch=' ; $vm | Should -Match 'defender='
        $r.Stream['azure|public_ip|' + $x.PipA.ToLowerInvariant()] | Should -Match ([regex]::Escape('"id":"' + $x.Vm.ToLowerInvariant() + '"'))
        $r.Stream['mdc|azure_resource|' + $x.Vm.ToLowerInvariant()] | Should -Match 'assessments='
    }
    It 'the management-group part on a child-only record keeps it from folding -- in memory and streamed alike (#731, recorded, not changed here)' {
        $r = Invoke-Both -U 2 -Buckets 2
        $x = Ids 1
        $nic = 'azure|azure_resource|' + $x.Nic.ToLowerInvariant()
        $r.Memory.ContainsKey($nic) | Should -BeTrue
        $r.Stream[$nic] | Should -BeExactly $r.Memory[$nic]
        $r.Stream[$nic] | Should -Match ([regex]::Escape('child|' + $x.PipA.ToLowerInvariant() + '='))
        $r.Stream[$nic] | Should -Match 'mg='
    }
    It 'an Azure record counts once for the bucket count (its context adds several lines)' {        $r = Invoke-Both -U 5 -Buckets 1
        $r.AzLines | Should -BeGreaterThan $r.AzRecords
        $r.Count | Should -BeLessThan ($r.Count - $r.AzRecords + $r.AzLines)
    }
}

Describe '2. the Azure reads, page by page' {
    It 'Resource Graph pages go to -OnPage and are let go: no rows kept, the count said' {
        $seenPages = New-Object System.Collections.Generic.List[int]
        $fetch = { param($p) $start = 0; if ($p.SkipToken) { $start = [int]$p.SkipToken }; $rows = @($start..($start + 2) | ForEach-Object { [pscustomobject]@{ n = $_ } })
            $o = New-Object System.Collections.Generic.List[object]; foreach ($x in $rows) { $o.Add($x) }
            Add-Member -InputObject $o -NotePropertyName SkipToken -NotePropertyValue $(if ($start -lt 6) { [string]($start + 3) } else { $null }); , $o }
        $res = Invoke-SIArgPaged -Query 'q' -SourceLabel 't' -PageFetcher $fetch -OnPage { param($Rows) $seenPages.Add(@($Rows).Count) }
        @($seenPages) | Should -Be @(3, 3, 3)
        @($res.Rows).Count | Should -Be 0
        $res.RowCount | Should -Be 9
        $res.Complete | Should -BeTrue
        (Invoke-SIArgPaged -Query 'q' -SourceLabel 't' -PageFetcher $fetch).Rows.Count | Should -Be 9 -Because 'without -OnPage the rows come back as before'
    }
    It 'a part on a streamed record is a line of that record -- no record is held, none is made' {
        $null = Reset-SIRecordCapture -Engine 'azure' -Clear
        $s = Start-SIRecordCaptureStream
        Set-SIAzureCiScope -Scope $script:Scope
        $x = Ids 0
        # nothing comes back from a captured part (a source builds its assets from its own output: a stray value became an asset)
        @(Add-SIRecordPartFromSource -SourceSystem arm -Object (Arm $x.Kv 'microsoft.keyvault/vaults')).Count | Should -Be 0
        @(Add-SIRecordPartFromSource -SourceSystem arm -Object (Arm $x.Nic 'microsoft.network/networkinterfaces' @{ properties = [pscustomobject]@{ virtualMachine = [pscustomobject]@{ id = $x.Vm } } })).Count | Should -Be 0
        $done = Invoke-SIAzureContextCapture -Query (ContextQuery 1) -PrincipalNames { param([string[]]$Ids) @{} } -Log { param($l, $m) }
        $global:SIRecordCaptureState.Records.Count | Should -Be 0
        $done.access | Should -Be 1
        $done.change | Should -Be 1
        $done.policy | Should -Be 1
        $i = Get-SIRecordStreamAzureInfo -Stream $s -Id ('azure|azure_resource|' + $x.Kv.ToLowerInvariant())
        $i.HasResource | Should -BeTrue
        $i.Name | Should -Be 'kv0'
        $i.ResourceType | Should -Be 'microsoft.keyvault/vaults'
        Stop-SIRecordCaptureStream
    }
}

Describe '3. bounded: on disk, keys only, one group at a time' {
    It 'the text lookup keeps each entry in its file and only the keys in memory; a later write replaces; Dispose removes the file' {
        $l = New-SIDiskTextLookup -Name 'test'
        $l['A'] = 'one'; $l.Put('b', 'two'); $l['a'] = 'three'
        $l['A'] | Should -Be 'three'
        $l.ContainsKey('B') | Should -BeTrue
        $l['missing'] | Should -BeNullOrEmpty
        $l.Count | Should -Be 2
        $p = $l.Path; Test-Path -LiteralPath $p | Should -BeTrue
        $l.Dispose(); Test-Path -LiteralPath $p | Should -BeFalse
    }
    It 'the groups: a resource and every child resource listed on it find one key; a key never joined is its own' {
        $g = New-Object SecurityInsight.KeyGroups
        $g.Union('vm1', 'nic1'); $g.Union('nic1', 'pip1'); $g.Union('VM2', 'disk2')
        $g.Find('pip1') | Should -Be $g.Find('vm1')
        $g.Find('PIP1') | Should -Be $g.Find('vm1')
        $g.Find('disk2') | Should -Be $g.Find('vm2')
        $g.Find('disk2') | Should -Not -Be $g.Find('vm1')
        $g.Find('kv9') | Should -Be 'kv9'
    }
    It 'the capture''s child -> parent map is on disk while streaming, and goes with the capture' {
        $null = Reset-SIRecordCapture -Engine 'azure' -Clear
        $null = Start-SIRecordCaptureStream
        Set-SIAzureCiScope -Scope $script:Scope
        $x = Ids 3
        Add-SIRecordPartFromSource -SourceSystem arm -Object (Arm $x.Nic 'microsoft.network/networkinterfaces' @{ properties = [pscustomobject]@{ virtualMachine = [pscustomobject]@{ id = $x.Vm } } })
        $co = $global:SIRecordCaptureState.ChildOf
        $co.GetType().FullName | Should -Be 'SecurityInsight.DiskTextLookup'
        $co[$x.Nic.ToLowerInvariant()] | Should -Be $x.Vm.ToLowerInvariant()
        (Get-SIRecordChildParentMap)[$x.Nic.ToLowerInvariant()] | Should -Be $x.Vm.ToLowerInvariant()
        $p = $co.Path
        $null = Reset-SIRecordCapture -Engine 'azure' -Clear
        Test-Path -LiteralPath $p | Should -BeFalse
    }
    It 'the record buckets grow with the records (~5,000 each), up to what the file names hold' {
        Get-SIRecordBucketCount -Records 9000000 -Parts 1 | Should -Be 1800
        Get-SIRecordBucketCount -Records 900000000 -Parts 1 | Should -Be 99999
    }
}

Describe '4. GUARD: no provider in memory, no size picks a method, the reads stay page by page' {
    BeforeAll { $script:Read = { param($rel) [IO.File]::ReadAllText((Join-Path $script:SIRoot $rel)) } }
    It 'the capture keeps no provider in memory: an Azure part goes to the record index and the stream' {
        $c = & $script:Read 'engine\data-model\SI-RecordCapture.ps1'
        $c | Should -Not -Match 'SIRecordStreamInMemory'
        $c | Should -Match ([regex]::Escape("if (`$p -eq 'azure') { Register-SIRecordStreamAzure -Stream `$cs.Stream -Id `$id"))
    }
    It 'the hand-over folds the Azure records one GROUP file at a time, never all of them' {
        $h = & $script:Read 'engine\data-model\SI-RecordHandover.ps1'
        $h | Should -Match ([regex]::Escape("`$g = Get-SICollectPartIndex -Key (`$groups.Find("))
        $h | Should -Match ([regex]::Escape("`$merged = Merge-SIRecordHandover -Documents @([pscustomobject]@{ Who = 'discover'; Pulls = @(); Records = `$items.ToArray() })"))
        $h | Should -Match ([regex]::Escape("            `$null = Resolve-SIRecordChildren -State `$merged"))
        # a scope without the fold FAILS the hand-over -- it never hands over unfolded children (the container's own scope, 2105)
        $h | Should -Match ([regex]::Escape("throw 'the record hand-over cannot fold the Azure child resources: Resolve-SIRecordChildren is not loaded in this scope"))
    }
    It 'the Azure reads take Resource Graph page by page and read the records from the stream''s index' -TestCases @(
        @{ f = 'engine\asset-profiling\discovery\Get-SIAzureContext.ps1'; must = "OnPage = { param(`$PageRows) & `$OnRows @(`$PageRows) }" }
        @{ f = 'engine\asset-profiling\discovery\Get-SIMdcAssessmentSummary.ps1'; must = '-OnPage $take' }
        @{ f = 'engine\asset-profiling\discovery\Get-SIMdcExposure.ps1'; must = '$null = & $take $rowsOfPage.ToArray()' }
        @{ f = 'engine\asset-profiling\discovery\Get-SIDerivedSources.ps1'; must = 'foreach ($id in $s.AzureIndex.Keys) {'; perSubscription = $true }
    ) {
        $t = & $script:Read $f
        $t | Should -Match ([regex]::Escape($must))
        # the management-group read is one row per SUBSCRIPTION (not per resource): it may keep its rows
        if (-not $perSubscription) { $t | Should -Not -Match '\$all\.Add\(' -Because 'no read collects every page' }
    }
    It 'no record, row or object COUNT selects a method in the Azure reads or the hand-over' -TestCases @(
        @{ f = 'engine\data-model\SI-RecordCapture.ps1' }
        @{ f = 'engine\data-model\SI-RecordHandover.ps1' }
        @{ f = 'engine\asset-profiling\discovery\Get-SIAzureContext.ps1' }
        @{ f = 'engine\asset-profiling\discovery\Get-SIMdcExposure.ps1' }
        @{ f = 'engine\asset-profiling\discovery\Get-SIMdcAssessmentSummary.ps1' }
        @{ f = 'engine\asset-profiling\discovery\Get-SIDerivedSources.ps1' }
    ) {
        $code = (& $script:Read $f) -split "`r?`n" | Where-Object { $_ -notmatch '^\s*#' }
        $hits = @($code | Where-Object { $_ -match '\bif\s*\(.*(Records\.Count|Items|AzureLines|AzureResources|AzureIndex\.Count|RowCount|\$rows\.Count|\$assets\.Count|RecordCount)\s*-(gt|ge|lt|le)\s*\$?(?!0\b|1\b)\w' })
        $hits | Should -BeNullOrEmpty
        $code -join "`n" | Should -Not -Match 'SI_RecordStream(Threshold|Min|Max)|StreamAbove|InMemoryBelow|AzureInMemory'
    }
}
