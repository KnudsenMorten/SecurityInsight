#Requires -Version 5.1
<#
    #1052 (owner 2026-11-02, "fix this, we must trust the data quality") -- ONE MACHINE, ONE CI.

      1. AN AD COMPUTER ACCOUNT IS NEVER A DEVICE CI OF ITS OWN. The pilot: the Exposure Graph computer-account node of a
         domain controller (azvm-dc01 -- AD object GUID only, isDomainController) was taken in as an eg DEVICE record and
         became a CI of its own: Tier 0 "Domain Controller" with 0 findings, while the real VM (Defender + Azure id, 2,202
         findings) stayed Tier 3 without the role. Now the account is record type computer_account, whose only strong
         identifier is the Defender device id of a SAFE match (one Defender device with its name, onboarded,
         domain-joined, its domain proven) -- it then brings the role to the real device's CI; without a safe match it is
         no CI at all.
      2. THE OLD WRONG CIs LEAVE THE RIGHT WAY: an eg device record with AD ids and no device id is a GONE link, so its CI
         is retired AT ONCE with the reason -- and a real device's CI that holds such a record stays active.
      3. ONE HARD ID, ONE ACTIVE CI: a CI whose records now build another CI (a merge left its old row behind -- the pilot's
         xel-sql-05: the same Defender, Azure, Defender for Cloud ids on two active CIs; an Azure VM whose Exposure Graph
         node id changed) is retired at once, naming the survivor (Get-SICiMergedRetireSql) -- on a real SQL Server too.
    Offline: every query is a seam. Real-SQL cases run against the test VM's local SQL Server Express and skip, saying so,
    where there is none. PS 5.1 + 7.
#>

BeforeDiscovery {
    $script:HasSql = [bool]((Get-Command sqlcmd -ErrorAction SilentlyContinue) -and (Get-Service -Name 'MSSQL$SQLEXPRESS' -ErrorAction SilentlyContinue | Where-Object Status -eq 'Running'))
}

BeforeAll {
    $script:SIRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    . (Join-Path $script:SIRoot 'engine\data-model\SI-RecordCapture.ps1')
    . (Join-Path $script:SIRoot 'engine\data-model\SI-DataModelTemplates.ps1')
    . (Join-Path $script:SIRoot 'engine\data-model\SI-CiBuildRun.ps1')
    if (-not (Get-Command -Name Read-SISqlRows -ErrorAction SilentlyContinue)) { . (Join-Path $script:SIRoot 'engine\data-model\SI-RecordSql.ps1') }
    $script:Clone = { param($src) $c = [ordered]@{}; foreach ($k in @($src.Keys)) { $c[$k] = $src[$k] }; $c }
    . (Join-Path $script:SIRoot 'engine\asset-profiling\shared\SI-FullAssetProperties.ps1')
    . (Join-Path $script:SIRoot 'engine\asset-profiling\discovery\Get-SIEgAdComputers.ps1')
    . (Join-Path $script:SIRoot 'engine\pro-data\_shared\SI-DataCi.ps1')
    . (Join-Path $script:SIRoot 'engine\pro-data\_shared\SI-DataViewContext.ps1')
    $script:Model = Get-SIDataModel
    $script:Rows = { (ConvertTo-SIRecordRows -Captured @(Get-SICapturedRecords) -Model $script:Model) }
    $script:Now = [datetime]::UtcNow

    # the pilot's machines (ids invented, shapes as read live 2026-11-02)
    $script:Dc1Dev = '316b51c35b687707888c5f6331be6d05a07e386e'
    $script:Dc2Dev = '4a1b51c35b687707888c5f6331be6d05a07e3999'
    $script:SqlA = 'aaaa51c35b687707888c5f6331be6d05a07e3001'
    $script:SqlB = 'bbbb51c35b687707888c5f6331be6d05a07e3002'
    $script:Ws01 = 'cccc51c35b687707888c5f6331be6d05a07e3003'
    $script:DomSid = 'S-1-5-21-1111111111-2222222222-3333333333'
    $script:Cand = { param($id, $name, $join = 'Domain Joined', $onb = 'Onboarded') [pscustomobject]@{ DeviceId = $id; DeviceName = $name; JoinType = $join; OnboardingStatus = $onb } }
    # one node row as Get-SIEgAdComputerKql answers it
    $script:Node = {
        param($nodeId, $name, [object[]]$cands = @(), [int]$count = -1, $raw = $null, [string]$guid = '')
        if ($null -eq $raw) { $raw = [pscustomobject]@{} }
        if ($count -lt 0) { $count = @($cands).Count }
        $eids = @(); if ($guid) { $eids = @('{"type":"ActiveDirectoryObjectGuid","id":"' + $guid + '"}') }
        [pscustomobject]@{ NodeId = $nodeId; NodeLabel = 'computer-account'; NodeName = $name; Categories = @('computer_account', 'identities', 'identity')
            EntityIds = $eids; NodeProperties = [pscustomobject]@{ rawData = $raw }; SIDeviceCandidateCount = $count; SIDeviceCandidates = @($cands) }
    }
    $script:DcRaw = { param($rid) [pscustomobject]@{ adSid = ($script:DomSid + '-' + $rid); isDomainController = $true; isSensitive = $true; isExchangeServerDnsName = $false; isTaggedAsExchangeServer = $false } }
    # the domain map: five unique onboarded domain-joined matches of the domain SID are in hngmn.local
    $script:DomainRows = @([pscustomobject]@{ DomainSid = $script:DomSid; Suffix = 'hngmn.local'; Matches = 5 })
    $script:Map = ConvertTo-SIEgAdComputerDomainMap -Rows $script:DomainRows
}

Describe '#1052 the safe match (Resolve-SIEgAdComputerMatch)' {
    It 'the pilot''s domain controller: one Defender device with its name, onboarded, domain-joined, in its SID''s proven domain -> matched' {
        $row = & $script:Node 'n-dc7' 'azvm-dc01' @((& $script:Cand $script:Dc1Dev 'azvm-dc01.hngmn.local')) -raw (& $script:DcRaw 1001)
        $m = Resolve-SIEgAdComputerMatch -Row $row -DomainMap $script:Map
        ($m.State, $m.DeviceId) | Should -Be @('matched', $script:Dc1Dev)
        $m.Reason | Should -Match 'hngmn\.local'
    }
    It 'its own DNS domain proves it directly (dnsHostName / dotted name / distinguished name); another DNS domain is refused' {
        $c = @((& $script:Cand $script:Dc1Dev 'srv7.corp.contoso.com'))
        (Resolve-SIEgAdComputerMatch -Row (& $script:Node 'n' 'SRV7$' $c -raw ([pscustomobject]@{ dnsHostName = 'srv7.corp.contoso.com' }))).State | Should -Be 'matched'
        (Resolve-SIEgAdComputerMatch -Row (& $script:Node 'n' 'srv7.corp.contoso.com' $c)).State | Should -Be 'matched'
        (Resolve-SIEgAdComputerMatch -Row (& $script:Node 'n' 'srv7' $c -raw ([pscustomobject]@{ distinguishedName = 'CN=SRV7,OU=Servers,DC=corp,DC=contoso,DC=com' }))).State | Should -Be 'matched'
        (Resolve-SIEgAdComputerMatch -Row (& $script:Node 'n' 'srv7' $c -raw ([pscustomobject]@{ dnsHostName = 'srv7.fabrikam.local' }))).State | Should -Be 'domain_mismatch'
    }
    It 'the name is the sAMAccountName without its $, else the node name -- the first label, any case' {
        $row = & $script:Node 'n' 'ignored' @((& $script:Cand $script:Dc1Dev 'AZVM-DC01.hngmn.local')) -raw ([pscustomobject]@{ sAMAccountName = 'AZVM-DC01$'; adSid = ($script:DomSid + '-1001') })
        Get-SIEgAdComputerShortName -Row $row | Should -Be 'azvm-dc01'
        (Resolve-SIEgAdComputerMatch -Row $row -DomainMap $script:Map).State | Should -Be 'matched'
    }
    It 'NEVER a wrong merge: two devices with the name (or a count above the list) are ambiguous; none is no_device' {
        $two = @((& $script:Cand $script:SqlA 'sql01.hngmn.local'), (& $script:Cand $script:SqlB 'sql01.other.local'))
        (Resolve-SIEgAdComputerMatch -Row (& $script:Node 'n' 'sql01' $two -raw (& $script:DcRaw 1101)) -DomainMap $script:Map).State | Should -Be 'ambiguous'
        (Resolve-SIEgAdComputerMatch -Row (& $script:Node 'n' 'sql01' @($two[0]) 3 -raw (& $script:DcRaw 1101)) -DomainMap $script:Map).State | Should -Be 'ambiguous' -Because 'the count is exact, the list is capped'
        (Resolve-SIEgAdComputerMatch -Row (& $script:Node 'n' 'ghost01' @() -raw (& $script:DcRaw 1102)) -DomainMap $script:Map).State | Should -Be 'no_device'
        (Resolve-SIEgAdComputerMatch -Row (& $script:Node 'n' '' @())).State | Should -Be 'no_name'
    }
    It 'the one device must be onboarded and domain-joined' {
        $raw = & $script:DcRaw 1103
        (Resolve-SIEgAdComputerMatch -Row (& $script:Node 'n' 'ws01' @((& $script:Cand $script:Ws01 'ws01.hngmn.local' 'Domain Joined' 'Can be onboarded')) -raw $raw) -DomainMap $script:Map).State | Should -Be 'not_onboarded'
        foreach ($j in 'Workgroup', 'AAD Joined', '') {
            (Resolve-SIEgAdComputerMatch -Row (& $script:Node 'n' 'ws01' @((& $script:Cand $script:Ws01 'ws01.hngmn.local' $j)) -raw $raw) -DomainMap $script:Map).State | Should -Be 'not_domain_joined' -Because "join type '$j'"
        }
        (Resolve-SIEgAdComputerMatch -Row (& $script:Node 'n' 'ws01' @((& $script:Cand $script:Ws01 'ws01.hngmn.local' 'Hybrid Azure AD Join')) -raw $raw) -DomainMap $script:Map).State | Should -Be 'matched'
    }
    It 'a domain nothing proves is refused: no SID and no DNS domain, a SID domain only one machine vouches for, or split evenly' {
        $c = @((& $script:Cand $script:Dc1Dev 'azvm-dc01.hngmn.local'))
        (Resolve-SIEgAdComputerMatch -Row (& $script:Node 'n' 'azvm-dc01' $c) -DomainMap $script:Map).State | Should -Be 'domain_unproven'
        $one = ConvertTo-SIEgAdComputerDomainMap -Rows @([pscustomobject]@{ DomainSid = $script:DomSid; Suffix = 'hngmn.local'; Matches = 1 })
        (Resolve-SIEgAdComputerMatch -Row (& $script:Node 'n' 'azvm-dc01' $c -raw (& $script:DcRaw 1001)) -DomainMap $one).State | Should -Be 'domain_unproven'
        $split = ConvertTo-SIEgAdComputerDomainMap -Rows @([pscustomobject]@{ DomainSid = $script:DomSid; Suffix = 'hngmn.local'; Matches = 3 }, [pscustomobject]@{ DomainSid = $script:DomSid; Suffix = 'other.local'; Matches = 3 })
        $split[$script:DomSid].Suffix | Should -BeNullOrEmpty
        (Resolve-SIEgAdComputerMatch -Row (& $script:Node 'n' 'azvm-dc01' $c -raw (& $script:DcRaw 1001)) -DomainMap $split).State | Should -Be 'domain_unproven'
    }
    It 'a device in ANOTHER domain than the one its SID''s machines are in is refused (the cross-domain twin)' {
        # domain A's account SRV01 is not in Defender; domain B's srv01.b.local is -- a unique name, but the wrong machine
        $c = @((& $script:Cand $script:SqlA 'srv01.b.local'))
        (Resolve-SIEgAdComputerMatch -Row (& $script:Node 'n' 'SRV01' $c -raw (& $script:DcRaw 1200)) -DomainMap $script:Map).State | Should -Be 'domain_mismatch'
    }
    It 'the domain map: a strict majority and at least two machines; per domain SID' {
        $m = ConvertTo-SIEgAdComputerDomainMap -Rows @(
            [pscustomobject]@{ DomainSid = 'S-1-5-21-1-2-3'; Suffix = 'a.local'; Matches = 7 }, [pscustomobject]@{ DomainSid = 'S-1-5-21-1-2-3'; Suffix = 'b.local'; Matches = 2 }
            [pscustomobject]@{ DomainSid = 'S-1-5-21-4-5-6'; Suffix = 'c.local'; Matches = 2 })
        ($m['S-1-5-21-1-2-3'].Suffix, $m['S-1-5-21-4-5-6'].Suffix) | Should -Be @('a.local', 'c.local')
        Get-SIEgAdComputerDomainSid 'S-1-5-21-1-2-3-1105' | Should -Be 'S-1-5-21-1-2-3'
        Get-SIEgAdComputerDomainSid 'S-1-5-32-544' | Should -BeNullOrEmpty -Because 'a builtin SID names no domain'
    }
    It 'candidates read back as JSON text (the hunting API''s dynamic column) decide the same' {
        $row = & $script:Node 'n-dc7' 'azvm-dc01' @() 1 -raw (& $script:DcRaw 1001)
        $row.SIDeviceCandidates = (ConvertTo-Json -InputObject @((& $script:Cand $script:Dc1Dev 'azvm-dc01.hngmn.local')) -Compress)
        (Resolve-SIEgAdComputerMatch -Row $row -DomainMap $script:Map).State | Should -Be 'matched'
    }
}

Describe '#1052 the queries' {
    It 'the node query carries each account''s Defender name candidates (30 days, one row per device, exact count + capped list); the count probe is unchanged' {
        $q = Get-SIEgAdComputerKql -Buckets 3 -Bucket 1
        $q | Should -Match 'DeviceInfo\s+\| where Timestamp > ago\(30d\)\s+\| summarize arg_max\(Timestamp, DeviceName, JoinType, OnboardingStatus\) by DeviceId'
        $q | Should -Match 'SIDeviceCandidateCount = count\(\), SIDeviceCandidates = make_list\(bag_pack\(.*\), 10\) by _short'
        $q | Should -Match "where NodeLabel == 'computer-account'\s+\| where hash\(NodeId, 3\) == 1"
        $q | Should -Match 'join kind=leftouter _dev on _short'
        $q | Should -Match '\| project NodeId, NodeLabel, NodeName, Categories, EntityIds, NodeProperties, SIDeviceCandidateCount, SIDeviceCandidates$'
        $q | Should -Match ([regex]::Escape("trim_end(@'\$'"))
        Get-SIEgAdComputerKql -Count | Should -Match "NodeLabel == 'computer-account'\s+\| count$"
    }
    It 'the domain map query: unique, onboarded, domain-joined name matches per domain SID and DNS suffix' {
        $q = Get-SIEgAdComputerDomainKql
        $q | Should -Match "where _n == 1 and isnotempty\(_sfx\) and _join in~ \('Domain Joined', 'Hybrid Azure AD Join', 'Hybrid Azure AD Joined'\) and _onb =~ 'Onboarded'"
        $q | Should -Match ([regex]::Escape("extract(@'^(S-1-5-21-\d+-\d+-\d+)-\d+$', 1, _sid)"))
        $q | Should -Match 'join kind=inner _dev on _short\s+\| summarize Matches = count\(\) by DomainSid, Suffix = _sfx$'
    }
}

Describe '#1052 BEFORE / AFTER on the pilot fixture' {
    BeforeEach { $null = Reset-SIRecordCapture -Engine endpoint -Clear }
    BeforeAll {
        # the pilot's estate: azvm-dc01 + azvm-dc02 (Defender devices, the Azure VM of dc01 with its graph node), two sql01
        # (ambiguous), a computer account without a device (ghost01)
        $script:Arm1 = '/subscriptions/00000000-0000-0000-0000-000000000001/resourcegroups/rg-dc/providers/microsoft.compute/virtualmachines/azvm-dc01'
        $script:Estate = {
            Add-SIRecordPart -Provider mde -RecordType device -Key $script:Dc1Dev -Part machine -Object ([pscustomobject]@{ id = $script:Dc1Dev; computerDnsName = 'azvm-dc01.hngmn.local'; osPlatform = 'WindowsServer2022'; onboardingStatus = 'Onboarded'; healthStatus = 'Active'; lastSeen = $script:Now.AddHours(-2).ToString('o') })
            Add-SIRecordPart -Provider mde -RecordType device -Key $script:Dc2Dev -Part machine -Object ([pscustomobject]@{ id = $script:Dc2Dev; computerDnsName = 'azvm-dc02.hngmn.local'; osPlatform = 'WindowsServer2022'; onboardingStatus = 'Onboarded'; healthStatus = 'Active'; lastSeen = $script:Now.AddHours(-2).ToString('o') })
            foreach ($d in $script:SqlA, $script:SqlB) { Add-SIRecordPart -Provider mde -RecordType device -Key $d -Part machine -Object ([pscustomobject]@{ id = $d; computerDnsName = 'sql01.hngmn.local'; osPlatform = 'WindowsServer2019'; lastSeen = $script:Now.AddHours(-2).ToString('o') }) }
            Add-SIRecordPartFromSource -SourceSystem 'exposure-graph' -Object ([pscustomobject]@{ NodeId = 'dddd0000000000000000000000000dc1'; NodeLabel = 'device'; NodeName = 'azvm-dc01.hngmn.local'
                    EntityIds = @('{"type":"SenseDeviceId","id":"' + $script:Dc1Dev + '"}'); NodeProperties = '{"rawData":{}}' })
            Add-SIRecordPartFromSource -SourceSystem 'exposure-graph' -Object ([pscustomobject]@{ NodeId = '875fbc2f00000000000000000000aaaa'; NodeLabel = 'microsoft.compute/virtualmachines'; NodeName = 'azvm-dc01'
                    EntityIds = @('{"type":"AzureResourceId","id":"' + $script:Arm1.ToUpperInvariant() + '"}'); NodeProperties = '{"rawData":{}}' })
            Add-SIRecordPart -Provider azure -RecordType azure_resource -Key $script:Arm1 -Part resource -Object ([pscustomobject]@{ id = $script:Arm1; name = 'azvm-dc01'; type = 'microsoft.compute/virtualmachines'; properties = [pscustomobject]@{ extended = [pscustomobject]@{ instanceView = [pscustomobject]@{ computerName = 'azvm-dc01' } } } }) -ResourceType 'microsoft.compute/virtualmachines'
        }
        $script:AccountRows = @(
            (& $script:Node '777358c6613b4935b6ab5962926ef275' 'azvm-dc01' @((& $script:Cand $script:Dc1Dev 'azvm-dc01.hngmn.local')) -raw (& $script:DcRaw 1001) -guid '6f9619ff-8b86-d011-b42d-00c04fc96401')
            (& $script:Node '888358c6613b4935b6ab5962926ef276' 'azvm-dc02' @((& $script:Cand $script:Dc2Dev 'azvm-dc02.hngmn.local')) -raw (& $script:DcRaw 1002) -guid '6f9619ff-8b86-d011-b42d-00c04fc96402')
            (& $script:Node '999358c6613b4935b6ab5962926ef277' 'sql01' @((& $script:Cand $script:SqlA 'sql01.hngmn.local'), (& $script:Cand $script:SqlB 'sql01.hngmn.local')) -raw (& $script:DcRaw 1101) -guid '6f9619ff-8b86-d011-b42d-00c04fc96403')
            (& $script:Node 'aaa358c6613b4935b6ab5962926ef278' 'ghost01' @() -raw (& $script:DcRaw 1102) -guid '6f9619ff-8b86-d011-b42d-00c04fc96404'))
        $script:Ask = { param($k) if ($k -match '\| count$') { return @{ Ok = $true; Rows = @([pscustomobject]@{ Count = 4 }); Error = '' } }
            if ($k -match 'summarize Matches = count\(\) by DomainSid') { return @{ Ok = $true; Rows = $script:DomainRows; Error = '' } }
            @{ Ok = $true; Rows = $script:AccountRows; Error = '' } }
        $script:Doc = {
            param([object[]]$recs)
            $fl = Get-SIFeedLatest -Records $recs
            New-SICiDocument -CiId 'ci-x' -Records $recs -Catalog $script:Model['field-catalog'] -FeedLatest $fl -Now $script:Now
        }
    }
    It 'BEFORE (the defect, as the build before the fix recorded it): the computer account is a device CI of its own, with the role; the real device has none' {
        & $script:Estate
        # what Get-SIEgRecordType answered before the fix: the account as an eg DEVICE record
        $acc = ConvertTo-SIEgAdComputerNode -Row $script:AccountRows[0]
        Add-SIRecordPart -Provider eg -RecordType device -Key $acc.NodeId -Part node -Object $acc
        $res = & $script:Rows
        @($res.Errors) | Should -BeNullOrEmpty
        $g = Get-SICiGroups -Records @($res.Rows)
        $alone = @($g.Groups | Where-Object { @($_.Members).Count -eq 1 -and [string]$_.Members[0].Record.si_provider -eq 'eg' -and [string]$_.Members[0].Record.si_record_type -eq 'device' })
        $alone.Count | Should -Be 1 -Because 'the defect: one machine, two CIs'
        @($alone[0].Members[0].Record.si_device_roles) | Should -Contain 'domain_controller'
        $real = @($g.Groups | Where-Object { @($_.Members | Where-Object { $_.Record.mde_device_id -eq $script:Dc1Dev }).Count -gt 0 })[0]
        @($real.Members | ForEach-Object { @($_.Record.si_device_roles) }) | Should -Not -Contain 'domain_controller'
    }
    It 'AFTER: the accounts are computer_account records; the two DCs join their Defender devices, the ambiguous and the deviceless are no CI' {
        & $script:Estate
        $out = Invoke-SIEgAdComputerCapture -Query $script:Ask
        ($out.Nodes, $out.Matched, $out.Ambiguous, $out.NoDevice, $out.Refused, $out.Failed) | Should -Be @(4, 2, 1, 1, 0, 0)
        foreach ($x in '4 computer account\(s\)', '2 enrich their Defender device', '1 ambiguous', '1 without a Defender device', 'none of them is a device CI of its own') { $out.Text | Should -Match $x }
        $global:SIRecordCaptureState.Pulls['eg'].Complete | Should -BeTrue
        $res = & $script:Rows
        @($res.Errors) | Should -BeNullOrEmpty
        $acc = @($res.Rows | Where-Object si_record_type -eq 'computer_account')
        $acc.Count | Should -Be 4
        @($acc | Where-Object { $_.eg_node_id -or $_.ad_sid -or $_.ad_object_guid }).Count | Should -Be 0 -Because 'no AD / graph id is a join key of an account'
        (@($acc | Where-Object { $_.si_record_key -eq 'eg:777358c6613b4935b6ab5962926ef275' })[0]).mde_device_id | Should -Be $script:Dc1Dev
        (@($acc | Where-Object { $_.si_record_key -eq 'eg:999358c6613b4935b6ab5962926ef277' })[0]).mde_device_id | Should -BeNullOrEmpty -Because 'ambiguous: no strong id'
        $g = Get-SICiGroups -Records @($res.Rows)
        @($g.Unkeyable | Where-Object si_record_type -eq 'computer_account').Count | Should -Be 2 -Because 'sql01 (ambiguous) and ghost01 (no device): no CI at all'
        @($g.Groups | Where-Object { @($_.Members | Where-Object { $_.Record.si_record_type -ne 'computer_account' }).Count -eq 0 }).Count | Should -Be 0 -Because 'NO CI is made of computer accounts alone'
        # every Defender device is still its own CI (sql01's two devices were never merged by a name)
        foreach ($d in $script:Dc1Dev, $script:Dc2Dev, $script:SqlA, $script:SqlB) { @($g.Groups | Where-Object { @($_.Members | Where-Object { $_.Record.mde_device_id -eq $d }).Count -gt 0 }).Count | Should -Be 1 }
        @($g.Groups | Where-Object { @($_.Members | Where-Object { $_.Record.mde_device_id -in $script:SqlA, $script:SqlB }).Count -eq 2 }).Count | Should -Be 0
    }
    It 'AFTER: the real domain controller''s CI carries the role, stays a device with its own graph node as the primary eg link, and is Tier 0' {
        & $script:Estate
        $null = Invoke-SIEgAdComputerCapture -Query $script:Ask
        $res = & $script:Rows
        $g = Get-SICiGroups -Records @($res.Rows)
        $dc = @($g.Groups | Where-Object { @($_.Members | Where-Object { $_.Record.mde_device_id -eq $script:Dc1Dev }).Count -gt 0 })[0]
        $recs = @($dc.Members | ForEach-Object { $_.Record })
        @($recs | Where-Object si_record_type -eq 'computer_account').Count | Should -Be 1
        $ci = & $script:Doc $recs
        $ci['si_class'] | Should -Be 'device'
        $ci['si_lifecycle'] | Should -Be 'active'
        @($ci['si_device_roles']) | Should -Contain 'domain_controller'
        $ci['si_link_mde'] | Should -Be $script:Dc1Dev
        @($ci['si_linked_objects'] | Where-Object { $_.type -eq 'computer_account' -and $_.primary }).Count | Should -Be 0 -Because 'the account never is the provider''s primary link'
        $ci['si_link_eg'] | Should -Be 'dddd0000000000000000000000000dc1' -Because 'the device''s own graph node'
        # the shipped endpoint rules, converted as the CI build does: the role makes it a Domain Controller, Tier 0
        if (-not (Get-Command -Name Write-SIInfo -ErrorAction SilentlyContinue)) { . (Join-Path $script:SIRoot 'engine\asset-profiling\_shared\Write-SIStyle.ps1') }
        . (Join-Path $script:SIRoot 'engine\asset-profiling\shared\Get-SIRuleSet.ps1')
        $all = Get-SIRuleSet -Engine endpoint 3>$null; $fb = Get-SIRuleSet -Engine endpoint -Fallback 3>$null
        $rules = @((ConvertTo-SICiRules -RuleSet @(@(@($all) + @($fb) | Where-Object { $_ }))).Rules)
        $ctx = @{ Lists = (Get-SIDataModelListContext $script:Model); Now = $script:Now }
        $null = Invoke-SICiRules -Ci $ci -Rules $rules -Trust (Get-SICiTrustIndex $script:Model['trust']) -Context $ctx -Now $script:Now -RulesByClass (Get-SICiRulesByClass -Rules $rules) -FieldCache @{}
        $ci['si_tier'] | Should -Be 0
        $ci['si_tier_reason'] | Should -Match 'Domain Controller'
    }
}

Describe '#1052 the old wrong CIs leave the right way -- and a real CMDB row is never closed wrongly' {
    BeforeAll {
        $script:OldAcc = [ordered]@{ si_provider = 'eg'; si_record_type = 'device'; si_class = 'device'; si_record_key = 'eg:777358c6613b4935b6ab5962926ef275'
            eg_node_id = '777358c6613b4935b6ab5962926ef275'; ad_object_guid = '6f9619ff-8b86-d011-b42d-00c04fc96401'; si_device_roles = @('domain_controller'); si_asset_name = 'azvm-dc01'
            si_collection_time = $script:Now.AddDays(-13); si_source_last_seen = $script:Now.AddDays(-13); si_collection_complete = $true }
        $script:Mde = [ordered]@{ si_provider = 'mde'; si_record_type = 'device'; si_class = 'device'; si_record_key = ('mde:' + $script:Dc1Dev); mde_device_id = $script:Dc1Dev
            si_asset_name = 'azvm-dc01.hngmn.local'; si_collection_time = $script:Now; si_source_last_seen = $script:Now.AddHours(-1); si_collection_complete = $true }
        $script:EgDev = [ordered]@{ si_provider = 'eg'; si_record_type = 'device'; si_class = 'device'; si_record_key = 'eg:5555'; eg_node_id = '5555'; si_collection_time = $script:Now; si_source_last_seen = $script:Now; si_collection_complete = $true }
        $script:Cat = $script:Model['field-catalog']
    }
    It 'an eg device record with AD ids and no device id is gone -- its CI is retired AT ONCE, saying why' {
        Test-SIRecordAdAccountAsDevice $script:OldAcc | Should -BeTrue
        $l = Get-SIRecordLink -Record $script:OldAcc -FeedLatest (Get-SIFeedLatest -Records @($script:OldAcc, $script:EgDev)) -Now $script:Now -SeenWithinDays 8
        ($l.State) | Should -Be 'gone'
        $l.Reason | Should -Match 'Active Directory computer account, not a device of its own \(#1052\)'
        $ci = New-SICiDocument -CiId '0346fbd5' -Records @($script:OldAcc) -Catalog $script:Cat -FeedLatest (Get-SIFeedLatest -Records @($script:OldAcc, $script:EgDev)) -Now $script:Now -Previous @{ Lifecycle = 'active'; Since = $script:Now.AddDays(-13); Reason = 'seen by eg' }
        $ci['si_lifecycle'] | Should -Be 'retired'
        $ci['si_lifecycle_reason'] | Should -Match '^retired at once: every linked object is gone \(eg -- an Active Directory computer account'
    }
    It 'retired even while the graph still lists the node (the pilot: EG still has it) -- the evidence is what the record IS, not its absence' {
        $listed = & $script:Clone $script:OldAcc; $listed['si_collection_time'] = $script:Now
        (Get-SIRecordLink -Record $listed -FeedLatest (Get-SIFeedLatest -Records @($listed, $script:EgDev)) -Now $script:Now).State | Should -Be 'gone'
    }
    It 'NEVER CLOSES A REAL ROW: a device CI with its Defender record and such a record stays active; a graph device node with a device id is never gone' {
        $fl = Get-SIFeedLatest -Records @($script:OldAcc, $script:Mde, $script:EgDev)
        $ci = New-SICiDocument -CiId 'eb990ec2' -Records @($script:Mde, $script:OldAcc) -Catalog $script:Cat -FeedLatest $fl -Now $script:Now -Previous @{ Lifecycle = 'active'; Since = $script:Now.AddDays(-30); Reason = 'seen by mde' }
        $ci['si_lifecycle'] | Should -Be 'active'
        $withId = & $script:Clone $script:OldAcc; $withId['mde_device_id'] = $script:Dc1Dev
        Test-SIRecordAdAccountAsDevice $withId | Should -BeFalse
        Test-SIRecordAdAccountAsDevice $script:EgDev | Should -BeFalse -Because 'no AD id: an ordinary graph device'
        $notEg = & $script:Clone $script:OldAcc; $notEg['si_provider'] = 'ad'
        Test-SIRecordAdAccountAsDevice $notEg | Should -BeFalse -Because 'only the Exposure Graph''s device records'
        $acct = & $script:Clone $script:OldAcc; $acct['si_record_type'] = 'computer_account'
        Test-SIRecordAdAccountAsDevice $acct | Should -BeFalse -Because 'the new record type is never gone by this'
    }
    It 'the CI build version is bumped: every CI is rebuilt once after the update (which retires the old duplicates)' {
        $script:SICiBuildVersion | Should -BeGreaterOrEqual 11
    }
}

Describe '#1052 one hard id, one active CI' {
    It 'a NEW Exposure Graph node id for an Azure VM joins the CI that holds its Azure resource id (xel-sql-05: 859bdbc0 -> d12c5e6e -> 627a780c)' {
        $null = Reset-SIRecordCapture -Engine azure -Clear
        $arm = '/subscriptions/00000000-0000-0000-0000-000000000001/resourcegroups/rg-lz-datacenter01-xellent/providers/microsoft.compute/virtualmachines/xel-sql-05'
        Add-SIRecordPart -Provider azure -RecordType azure_resource -Key $arm -Part resource -Object ([pscustomobject]@{ id = $arm; name = 'xel-sql-05'; type = 'microsoft.compute/virtualmachines' }) -ResourceType 'microsoft.compute/virtualmachines'
        foreach ($n in 'd12c5e6e000000000000000000000001', '627a780c000000000000000000000002') {
            Add-SIRecordPartFromSource -SourceSystem 'exposure-graph' -Object ([pscustomobject]@{ NodeId = $n; NodeLabel = 'microsoft.compute/virtualmachines'; NodeName = 'xel-sql-05'; EntityIds = @('{"type":"AzureResourceId","id":"' + $arm.ToUpperInvariant() + '"}'); NodeProperties = '{"rawData":{}}' })
        }
        $res = ConvertTo-SIRecordRows -Captured @(Get-SICapturedRecords) -Model $script:Model
        @($res.Errors) | Should -BeNullOrEmpty
        @((Get-SICiGroups -Records @($res.Rows)).Groups).Count | Should -Be 1
    }
    It 'the merged CI is retired at once (the statement): only CIs no current record builds, whose linked record builds another live CI; retired + reason + recorded; nothing deleted' {
        $s = Get-SICiMergedRetireSql
        $s | Should -Match 'NOT EXISTS \(SELECT 1 FROM sidata\.CiGroupMember m JOIN sidata\.CiRecord r ON r\.RecordKey = m\.RecordKey WHERE r\.CiId = c\.CiId\)'
        $s | Should -Match "JOIN sidata\.CiRecord r ON r\.RecordKey = l\.Provider \+ N':' \+ l\.NativeId"
        $s | Should -Match "JOIN sidata\.Ci d ON d\.CiId = r\.CiId AND ISNULL\(d\.Lifecycle, N''\) <> N'retired'"
        $s | Should -Match "SET Lifecycle = N'retired', ContentHash = NULL"
        $s | Should -Match "retired at once: merged into CI "
        $s | Should -Match 'INSERT sidata\.CiChange'
        $s | Should -Not -Match '(?i)\bDELETE\b|\bTRUNCATE\b|\bDROP\b'
    }
    It 'the CI build runs it after the batches and the relations, BEFORE the retire brake, and says what it retired' {
        $t = [IO.File]::ReadAllText((Join-Path $script:SIRoot 'engine\data-model\SI-CiBuildRun.ps1'))
        $i = $t.IndexOf('Get-SICiMergedRetireSql')
        $i | Should -BeGreaterThan $t.IndexOf('Invoke-SICiRelationStep @relArgs')
        $i | Should -BeLessThan $t.IndexOf('Get-SICiRetireSql -FloorDays (Get-SICiRetireDays)')
        $t | Should -Match "retired at once -- merged into the CI their records build now"
    }
}

Describe '#1052 real SQL: the merged twin is retired, the survivor and an unrelated CI are not (local SQL Server Express)' -Skip:(-not $script:HasSql) {
    BeforeAll {
        $script:DbName = 'si_test_1052_' + [guid]::NewGuid().ToString('N').Substring(0, 8)
        $m = New-Object System.Data.SqlClient.SqlConnection 'Server=.\SQLEXPRESS;Database=master;Integrated Security=SSPI;Connection Timeout=30'
        $m.Open(); try { $c = $m.CreateCommand(); $c.CommandText = "CREATE DATABASE [$script:DbName]"; $c.CommandTimeout = 300; [void]$c.ExecuteNonQuery() } finally { $m.Dispose() }
        $script:Cn = New-Object System.Data.SqlClient.SqlConnection ("Server=.\SQLEXPRESS;Database=$script:DbName;Integrated Security=SSPI;Connection Timeout=30;Pooling=false")
        $script:Cn.Open()
        $c = $script:Cn.CreateCommand(); $c.CommandTimeout = 300; $c.CommandText = [IO.File]::ReadAllText((Join-Path $script:SIRoot 'sql\si-data-schema.sql')); [void]$c.ExecuteNonQuery()
        # the ENGINE's rights only (db_datareader + db_datawriter), as setup grants them
        $c = $script:Cn.CreateCommand(); $c.CommandText = "CREATE USER si_engine WITHOUT LOGIN; ALTER ROLE db_datareader ADD MEMBER si_engine; ALTER ROLE db_datawriter ADD MEMBER si_engine; EXECUTE AS USER = N'si_engine';"; [void]$c.ExecuteNonQuery()
        $script:Sql = {
            param($Sql, $Params, $Mode)
            $c = $script:Cn.CreateCommand(); $c.CommandText = $Sql; $c.CommandTimeout = 300  # test data of thousands of rows on a SQL Express that 4 gate lanes share: 90 s timed out under load (2026-11-04); the setup commands above use 300 too
            if ($Params) { foreach ($k in $Params.Keys) { $pp = $c.Parameters.Add('@' + $k, [System.Data.SqlDbType]::NVarChar, -1); $pp.Value = [string]$Params[$k] } }
            if ($Mode -eq 'rows') { return @(Read-SISqlRows -Command $c) }
            $c.ExecuteNonQuery()
        }
        function script:Q([string]$s) { @(& $script:Sql $s @{} 'rows') }
    }
    AfterAll {
        if ($script:Cn) { try { $script:Cn.Dispose() } catch { } }
        [System.Data.SqlClient.SqlConnection]::ClearAllPools()
        $m = New-Object System.Data.SqlClient.SqlConnection 'Server=.\SQLEXPRESS;Database=master;Integrated Security=SSPI;Connection Timeout=30'
        $m.Open(); try { $c = $m.CreateCommand(); $c.CommandTimeout = 300; $c.CommandText = "ALTER DATABASE [$script:DbName] SET SINGLE_USER WITH ROLLBACK IMMEDIATE; DROP DATABASE [$script:DbName]"; [void]$c.ExecuteNonQuery() } finally { $m.Dispose() }
    }
    It 'xel-sql-05: the twin (same Defender / Azure / Defender for Cloud ids, no current record) and the old graph-node CI are retired naming the survivor; the survivor, a current CI and a lone orphan inside the brake are untouched' {
        $arm = '/subscriptions/s1/resourcegroups/rg-lz-datacenter01-xellent/providers/microsoft.compute/virtualmachines/xel-sql-05'
        $mde = '0d9c7d5f00000000000000000000000000000001'
        $null = & $script:Sql @"
INSERT sidata.Ci (CiId, Lifecycle, LastSeen, CollectionTime, DocJson, ContentHash) VALUES
 (N'5802bfcd', N'active', SYSUTCDATETIME(), SYSUTCDATETIME(), N'{"si_lifecycle":"active"}', 0x01),
 (N'a7b37ed0', N'active', DATEADD(day, -6, SYSUTCDATETIME()), SYSUTCDATETIME(), N'{"si_lifecycle":"active"}', 0x02),
 (N'a0b8f186', N'active', DATEADD(day, -2, SYSUTCDATETIME()), SYSUTCDATETIME(), N'{"si_lifecycle":"active"}', 0x03),
 (N'other001', N'active', SYSUTCDATETIME(), SYSUTCDATETIME(), N'{"si_lifecycle":"active"}', 0x04),
 (N'orphan01', N'active', DATEADD(day, -2, SYSUTCDATETIME()), SYSUTCDATETIME(), N'{"si_lifecycle":"active"}', 0x05);
INSERT sidata.CiLink (CiId, Provider, RecordType, NativeId, IsPrimary, State) VALUES
 (N'5802bfcd', N'mde', N'device', N'$mde', 1, N'active'), (N'5802bfcd', N'azure', N'azure_resource', N'$arm', 1, N'active'), (N'5802bfcd', N'mdc', N'azure_resource', N'$arm', 1, N'active'), (N'5802bfcd', N'eg', N'azure_resource', N'd12c5e6e', 0, N'active'),
 (N'a7b37ed0', N'mde', N'device', N'$mde', 1, N'active'), (N'a7b37ed0', N'azure', N'azure_resource', N'$arm', 1, N'active'), (N'a7b37ed0', N'mdc', N'azure_resource', N'$arm', 1, N'active'),
 (N'a0b8f186', N'eg', N'azure_resource', N'd12c5e6e', 1, N'active'),
 (N'other001', N'mde', N'device', N'ffff000000000000000000000000000000000001', 1, N'active'),
 (N'orphan01', N'mde', N'device', N'eeee000000000000000000000000000000000001', 1, N'active');
INSERT sidata.CiRecord (RecordKey, CiId, Provider, CollectionTime) VALUES
 (N'mde:$mde', N'5802bfcd', N'mde', SYSUTCDATETIME()), (N'azure:$arm', N'5802bfcd', N'azure', SYSUTCDATETIME()), (N'mdc:$arm', N'5802bfcd', N'mdc', SYSUTCDATETIME()), (N'eg:d12c5e6e', N'5802bfcd', N'eg', SYSUTCDATETIME()),
 (N'mde:ffff000000000000000000000000000000000001', N'other001', N'mde', SYSUTCDATETIME());
INSERT sidata.CiGroupMember (RecordKey, GroupKey, BatchNo) VALUES
 (N'mde:$mde', N'g1', 1), (N'azure:$arm', N'g1', 1), (N'mdc:$arm', N'g1', 1), (N'eg:d12c5e6e', N'g1', 1), (N'mde:ffff000000000000000000000000000000000001', N'g2', 1);
"@ @{} 'nonquery'
        $r = @(& $script:Sql (Get-SICiMergedRetireSql) @{ run = 'run-1' } 'rows')[0]
        [int]$r.Retired | Should -Be 2
        [int]$r.SharedLive | Should -Be 0 -Because 'after the retirement every hard id is on ONE active CI'
        $st = @{}; foreach ($x in (Q 'SELECT CiId, Lifecycle, ContentHash, JSON_VALUE(DocJson, ''$.si_lifecycle'') AS Doc, JSON_VALUE(DocJson, ''$.si_lifecycle_reason'') AS Why FROM sidata.Ci')) { $st[[string]$x.CiId] = $x }
        $st['a7b37ed0'].Lifecycle | Should -Be 'retired'
        $st['a7b37ed0'].Doc | Should -Be 'retired'
        $st['a7b37ed0'].Why | Should -Match '^retired at once: merged into CI 5802bfcd -- its (azure|mdc|mde) record '
        $st['a7b37ed0'].ContentHash | Should -BeNullOrEmpty
        $st['a0b8f186'].Lifecycle | Should -Be 'retired' -Because 'its only record (the old graph node) builds the survivor now'
        $st['a0b8f186'].Why | Should -Match 'merged into CI 5802bfcd -- its eg record d12c5e6e'
        $st['5802bfcd'].Lifecycle | Should -Be 'active' -Because 'the survivor: its records build it'
        $st['other001'].Lifecycle | Should -Be 'active'
        $st['orphan01'].Lifecycle | Should -Be 'active' -Because 'an orphan whose records went nowhere is the retire brake''s, not merged'
        (Q 'SELECT COUNT(*) AS N FROM sidata.Ci')[0].N | Should -Be 5 -Because 'nothing is deleted'
        @(Q "SELECT CiId FROM sidata.CiChange WHERE Field = N'si_lifecycle' AND NewValue = N'retired' AND RunId = N'run-1' AND Reason LIKE N'merged into CI 5802bfcd%'").Count | Should -Be 2
        [int](@(& $script:Sql (Get-SICiMergedRetireSql) @{ run = 'run-2' } 'rows')[0].Retired) | Should -Be 0 -Because 'retired once'
    }
    It 'vmvdpool13img2: the twin''s 2,559 findings and their lifecycle rows move to the survivor IN THE SAME STEP -- the survivor carries them all, none belongs to no CI, no count is lost' {
        $twin = '58d23e45'; $surv = 'da5c1492'; $dev = '7777000000000000000000000000000000000013'
        $null = & $script:Sql @"
INSERT sidata.Ci (CiId, Lifecycle, LastSeen, CollectionTime, DocJson, ContentHash, OpenFindings) VALUES
 (N'$twin', N'active', DATEADD(day, -3, SYSUTCDATETIME()), SYSUTCDATETIME(), N'{"si_lifecycle":"active","si_asset_name":"vmvdpool13img2"}', 0x11, 2559),
 (N'$surv', N'active', SYSUTCDATETIME(), SYSUTCDATETIME(), N'{"si_lifecycle":"active","si_asset_name":"vmvdpool13img2"}', 0x12, 4),
 (N'oldtwin1', N'retired', DATEADD(day, -40, SYSUTCDATETIME()), SYSUTCDATETIME(), N'{"si_lifecycle":"retired","si_merged_into":"$twin"}', NULL, 0);
INSERT sidata.CiLink (CiId, Provider, RecordType, NativeId, IsPrimary, State) VALUES (N'$twin', N'mde', N'device', N'$dev', 1, N'active'), (N'$surv', N'mde', N'device', N'$dev', 1, N'active');
INSERT sidata.CiRecord (RecordKey, CiId, Provider, CollectionTime) VALUES (N'mde:$dev', N'$surv', N'mde', SYSUTCDATETIME());
INSERT sidata.CiGroupMember (RecordKey, GroupKey, BatchNo) VALUES (N'mde:$dev', N'g-vmvd', 1);
;WITH n AS (SELECT TOP (2559) ROW_NUMBER() OVER (ORDER BY (SELECT NULL)) AS i FROM sys.all_columns a CROSS JOIN sys.all_columns b)
INSERT sidata.CiFinding (CiId, AssetId, FindingKey, RiskScore, WeightedRiskScore, CollectionTime) SELECT N'$twin', N'$twin', N'TW-' + CAST(i AS NVARCHAR(10)), 1, 2, SYSUTCDATETIME() FROM n;
;WITH n AS (SELECT TOP (2559) ROW_NUMBER() OVER (ORDER BY (SELECT NULL)) AS i FROM sys.all_columns a CROSS JOIN sys.all_columns b)
INSERT sidata.CiFindingState (OwnerKey, FindingKey, CiId, State, FirstDetected, LastSeen, LastSnapshot) SELECT N'$twin', N'TW-' + CAST(i AS NVARCHAR(10)), N'$twin', N'open', DATEADD(day, -60, SYSUTCDATETIME()), SYSUTCDATETIME(), SYSUTCDATETIME() FROM n;
INSERT sidata.CiFinding (CiId, AssetId, FindingKey, RiskScore, WeightedRiskScore, CollectionTime) VALUES (N'$surv', N'$surv', N'SV-1', 1, 2, SYSUTCDATETIME()), (N'$surv', N'$surv', N'SV-2', 1, 2, SYSUTCDATETIME()), (N'$surv', N'$surv', N'SV-3', 1, 2, SYSUTCDATETIME()), (N'$surv', N'$surv', N'SV-4', 1, 2, SYSUTCDATETIME());
"@ @{} 'nonquery'
        $before = [int](Q "SELECT COUNT(*) AS N FROM sidata.CiFinding WHERE CiId IN (N'$twin', N'$surv')")[0].N
        $before | Should -Be 2563
        $r = @(& $script:Sql (Get-SICiMergedRetireSql) @{ run = 'run-vmvd' } 'rows')[0]
        [int]$r.Retired | Should -Be 1
        [int]$r.FindingsMoved | Should -Be 2559
        [int]$r.StatesMoved | Should -Be 2559
        (Q "SELECT COUNT(*) AS N FROM sidata.CiFinding WHERE CiId = N'$surv'")[0].N | Should -Be 2563 -Because 'the survivor carries them all'
        (Q "SELECT COUNT(*) AS N FROM sidata.CiFinding WHERE CiId = N'$twin'")[0].N | Should -Be 0
        (Q "SELECT COUNT(*) AS N FROM sidata.CiFinding WHERE CiId IS NULL")[0].N | Should -Be 0 -Because 'no finding belongs to no CI'
        (Q "SELECT COUNT(*) AS N FROM sidata.CiFindingState WHERE OwnerKey = N'$surv' AND State = N'open'")[0].N | Should -Be 2559 -Because 'the lifecycle (first detected, open) moves with them'
        (Q "SELECT MIN(FirstDetected) AS F FROM sidata.CiFindingState WHERE OwnerKey = N'$surv'")[0].F | Should -BeLessThan ([datetime]::UtcNow.AddDays(-59))
        $st = @{}; foreach ($x in (Q "SELECT CiId, Lifecycle, OpenFindings, JSON_VALUE(DocJson, '$.si_merged_into') AS MergedInto FROM sidata.Ci WHERE CiId IN (N'$twin', N'$surv', N'oldtwin1')")) { $st[[string]$x.CiId] = $x }
        ([int]$st[$surv].OpenFindings, [string]$st[$surv].Lifecycle) | Should -Be @(2563, 'active') -Because 'the count on the CI list is the same number'
        ([string]$st[$twin].Lifecycle, [int]$st[$twin].OpenFindings, [string]$st[$twin].MergedInto) | Should -Be @('retired', 0, $surv)
        [string]$st['oldtwin1'].MergedInto | Should -Be $surv -Because 'a CI an earlier merge pointed at the twin follows to the survivor'
    }
    It 'the data sync''s finding writer follows si_merged_into: a finding collection made before the merge (si_ci_id = the twin) lands on the survivor' {
        $items = @(
            [ordered]@{ CiId = '58d23e45'; AssetId = '58d23e45'; FindingKey = 'OLD-1'; CollectionTime = '2026-11-02T00:00:00Z' }
            [ordered]@{ CiId = ''; AssetId = '58d23e45'; FindingKey = 'OLD-2'; CollectionTime = '2026-11-02T00:00:00Z' }
            [ordered]@{ CiId = ''; AssetId = '7777000000000000000000000000000000000013'; FindingKey = 'OLD-3'; CollectionTime = '2026-11-02T00:00:00Z' })
        $s = Get-SIDataWriteCiFindingSql -Stage -First
        $s | Should -Match "JSON_VALUE\(m\.DocJson, '\$\.si_merged_into'\)"
        $n = & $script:Sql $s @{ j = (ConvertTo-Json -InputObject $items -Compress) } 'nonquery'
        @(Q "SELECT CiId FROM sidata.CiFindingStage WHERE FindingKey LIKE N'OLD-%' AND CiId <> N'da5c1492'").Count | Should -Be 0 -Because 'by id, by asset id and by a link the twin also held: all on the survivor'
        (Q "SELECT COUNT(*) AS N FROM sidata.CiFindingStage WHERE FindingKey LIKE N'OLD-%'")[0].N | Should -Be 3
    }
    It 'the read-only pilot check runs on a real SQL Server (no aggregate over a subquery -- Azure SQL refuses it)' {
        $txt = [IO.File]::ReadAllText((Join-Path $script:SIRoot 'diagnostics\Measure-SIComputerAccountCis.sql'))
        $txt | Should -Not -Match '(?is)\b(SUM|COUNT|MIN|MAX|AVG)\s*\(\s*CASE\s+WHEN\s+(NOT\s+)?EXISTS'
        $txt | Should -Not -Match '(?i)\b(INSERT|UPDATE|DELETE|MERGE|TRUNCATE|DROP|ALTER|CREATE)\s+(INTO\s+)?(sidata|cfg)\.' -Because 'read only'
        { $null = & $script:Sql $txt @{} 'nonquery' } | Should -Not -Throw
    }
    It 'two live CIs that share a hard id (each with current records -- an operator never-merge) are reported, never retired' {
        $null = & $script:Sql @"
INSERT sidata.Ci (CiId, Lifecycle, LastSeen, CollectionTime, DocJson, ContentHash) VALUES (N'live-a', N'active', SYSUTCDATETIME(), SYSUTCDATETIME(), N'{}', 0x01), (N'live-b', N'active', SYSUTCDATETIME(), SYSUTCDATETIME(), N'{}', 0x02);
INSERT sidata.CiLink (CiId, Provider, RecordType, NativeId, IsPrimary, State) VALUES (N'live-a', N'entra', N'device', N'shared-dev', 1, N'active'), (N'live-b', N'entra', N'device', N'shared-dev', 1, N'active'), (N'live-b', N'intune', N'device', N'int-b', 1, N'active');
INSERT sidata.CiRecord (RecordKey, CiId, Provider, CollectionTime) VALUES (N'entra:shared-dev', N'live-a', N'entra', SYSUTCDATETIME()), (N'intune:int-b', N'live-b', N'intune', SYSUTCDATETIME());
INSERT sidata.CiGroupMember (RecordKey, GroupKey, BatchNo) VALUES (N'entra:shared-dev', N'ga', 1), (N'intune:int-b', N'gb', 1);
"@ @{} 'nonquery'
        $r = @(& $script:Sql (Get-SICiMergedRetireSql) @{ run = 'run-3' } 'rows')[0]
        [int]$r.Retired | Should -Be 0
        [int]$r.SharedLive | Should -Be 1
        @(Q "SELECT CiId FROM sidata.Ci WHERE CiId IN (N'live-a', N'live-b') AND Lifecycle = N'active'").Count | Should -Be 2
    }
}
