#Requires -Version 5.1
<#
    #677 -- DOES A ROW LOSE THE CI CONTEXT OF ITS *OTHER* ASSET IN A SLICED RUN? PROVED HERE: YES, IN FOUR SHAPES.

    A report that goes to advanced hunting has its CI lookup _ciLink inlined into the request, CUT PER SLICE on _ciKey
    (Get-SICLBucketKey -> SHA-256 bucket). The graph rows of the slice are cut by the report's bucket filter on its
    DeviceKey. A join of a row against _ciLink is complete only when its key is the key the row was sliced on: any other
    key's CI row sits in the slice ITS key hashes to, and in every other slice the join finds nothing -- silently, as a
    leftouter join does.

      S1  the 8 Identity_*LogonTo_*Device_* reports: rows sliced on the USER, the device's CI joined on DeviceCiKey.
          A device lost its CI id and factors; InternetExposedDevice dropped the finding (the filter reads the factor);
          LowTierDevice reported a tier-0 device as a low-tier one (its tier read null). FIXED here.
      S2  Attack_Paths_Detailed_Device_with_high_severity_..._Azure: rows sliced on the ENTRY DEVICE, the Azure target's
          CI (tier, CMDB) joined on its node id through _TargetCi = _ciLink. The target fell to tier 3, no CMDB. FIXED here.
      S3  Attack_Paths_*_Credential_Based_Lateral_Movement: the bucket filter sits on the credential edges (no DeviceKey
          there, so it cut on SourceNodeId, a graph node id); every CI join was on a CI key.
      S4  the other 8 Attack_Paths_* reports (Github_to_Azure, Public_IP_to_VM, Identity_Group_Membership,
          Data_Sensitivity): the filter cut the Nodes catalog only; the paths were not cut, so every slice emitted every
          path, with the source's context only in the source's slice and the target's only in the target's.
      S3 + S4 FIXED (second round): the slice filter sits on the edge set that gives each path its FINAL TARGET, keyed on
          that target's node id, so a path -- whose grain includes its target -- is built in exactly one slice from the
          same rows as unsliced, and a Summary's count over targets adds up over the slices. The Nodes catalog is not
          sliced and reads no CI; the CI of both ends comes from _ciPeer after the cut point; _ciLink is gone from them.
          SIv3-SliceKeyJoinGuard keeps every join against a slice-cut lookup on the key that lookup is cut on.

    The fix for S1/S2 is the CI block _ciPeer (RA-CiKql.ps1 -Kind peer): the same CIs and keys as _ciLink under names the
    slice cut does not key on (_peerKey, peer_*), joined after the slice filter at the report's //__SI_LOOKUP_KEYS_HERE__
    and declared under LookupNeededKeys. It travels whole while it fits; when it does not, each slice gets only the rows
    its own rows can match (the engine's existing reduction, as for _dfcPairs) -- it is never copied whole above the
    request budget. Like SIv3-SubscriptionTierSliced (#675), no KQL is run: the engine's own inlining is called, the
    rows each slice carries are read back, and the join is evaluated over them.
#>

BeforeAll {
    $script:SIRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
    . (Join-Path $script:SIRoot 'engine\risk-analysis\_shared\RA-ProfileAugment.ps1')
    . (Join-Path $script:SIRoot 'engine\risk-analysis\_shared\RA-CiKql.ps1')
    . (Join-Path $script:SIRoot 'engine\risk-analysis\_shared\RA-BucketFilters.ps1')
    function script:Write-Info  { param($m) }
    function script:Write-Diag  { param($m) }
    function script:Write-Warn2 { param($m) }
    function script:Write-Err2  { param($m) }
    function script:Invoke-LogAnalyticsKqlQuery { param($WorkspaceResourceId, $Query) }
    $script:Ws = '/subscriptions/x/resourceGroups/rg/providers/Microsoft.OperationalInsights/workspaces/w'
    $script:Yaml = [IO.File]::ReadAllText((Join-Path $script:SIRoot 'risk-analysis-detection\RiskAnalysis_Queries_Locked.yaml')) -replace "`r", ''

    function script:Get-Hex { param([string]$Seed, [int]$Len = 40)
        $sha = [System.Security.Cryptography.SHA1]::Create()
        try { (-join ($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($Seed)) | ForEach-Object { $_.ToString('x2') })).Substring(0, $Len) } finally { $sha.Dispose() }
    }
    function script:Get-Report { param([string]$Name)
        $s = $script:Yaml.IndexOf("    - ReportName: $Name`n")
        if ($s -lt 0) { throw "no report $Name" }
        $e = $script:Yaml.IndexOf("`n    - ReportName: ", $s + 10)
        return $script:Yaml.Substring($s, $e - $s)
    }
    function script:Get-Block { param([string]$Text, [string]$Begin, [string]$End)
        $m = [regex]::Match($Text, '(?ms)^[ \t]*' + [regex]::Escape($Begin) + '.*?' + [regex]::Escape($End))
        if (-not $m.Success) { throw "no $Begin" }
        return $m.Value
    }
    function script:Reset-State {
        $script:_HybridRowsCache = @{}; $script:_HybridSnapshotCache = @{}; $script:_HybridBucketGroupsCache = @{}; $script:_HybridBucketGroupsWhole = @{}
        $script:_HybridColumnTypesCache = @{}; $script:_HybridKeyIndexCache = @{}; $script:_CrossDomainBucketCoalesce = @(); $script:_SkipEGBucketForCrossDomain = $false
        $script:_RALookupNeededKeySets = $null; $script:_LastHybridQueryBodyOverheadBytes = 0; $script:_LastHybridBytesPerRow = 0
    }
    # The rows one binding carries in one slice -- what that slice's KQL joins against -- from the engine's own caches.
    function script:Get-InlinedRows { param([string]$Var, [int]$N, [int]$B)
        $k = @($script:_HybridRowsCache.Keys | Where-Object { $_ -like ($Var + '|*') })[0]
        if ($N -le 1) { return @($script:_HybridRowsCache[$k]) }
        return @($script:_HybridBucketGroupsCache[('{0}::{1}' -f $k, $N)][$B])
    }
    # The slice a graph row lands in: the bucket filter's hash of its DeviceKey (Get-SISha256Bucket is the same math).
    function script:Remove-Strings { param([string]$Text) [regex]::Replace([regex]::Replace([regex]::Replace($Text, '//[^\r\n]*', ''), '"[^"\r\n]*"', '""'), "'[^'\r\n]*'", "''") }
    function script:Get-Slice { param([string]$Key, [int]$N) Get-SISha256Bucket -Key $Key -BucketCount $N }

    # ---- fixture: 200 users, each signing in to one device; 200 Azure targets, each reached from one device ----
    $script:Pairs = @(0..199 | ForEach-Object {
        [pscustomobject]@{
            User = ('{0}-aaaa-4bbb-8ccc-{1}' -f (Get-Hex "u$_" 8), (Get-Hex "u$_" 12)); Device = Get-Hex "d$_"
            Target = Get-Hex "t$_" 32; DeviceCi = "ci-dev-$_"; DeviceTier = ($_ % 4); TargetCi = "ci-tgt-$_"; TargetTier = ($_ % 3); TargetCmdb = "cmdb-$_"
        } })
    # _ciLink as the old reports read it: identities AND devices / cloud resources, keyed _ciKey
    $script:LinkRows = @(
        $script:Pairs | ForEach-Object { [pscustomobject]@{ _ciKey = $_.User; si_ci_id = "ci-usr-$($_.User)"; si_class = 'identity'; si_tier = 0; si_cmdb_id = '' } }
        $script:Pairs | ForEach-Object { [pscustomobject]@{ _ciKey = $_.Device; si_ci_id = $_.DeviceCi; si_class = 'device'; si_tier = $_.DeviceTier; si_cmdb_id = '' } }
        $script:Pairs | ForEach-Object { [pscustomobject]@{ _ciKey = $_.Target; si_ci_id = $_.TargetCi; si_class = 'cloud_resource'; si_tier = $_.TargetTier; si_cmdb_id = $_.TargetCmdb } })
    # _ciPeer, the same CIs under the peer block's names
    $script:PeerRows = @(
        $script:Pairs | ForEach-Object { [pscustomobject]@{ _peerKey = $_.Device; peer_ci_id = $_.DeviceCi; peer_tier = $_.DeviceTier; peer_cmdb_id = ''; peer_cmdb_name = ''; peer_cmdb_criticality = ''; peer_cmdb_data_sensitivity = ''; peer_rf_p = '["internet_exposed","unsupported_os"]'; peer_rf_names = '["InternetExposed","UnsupportedOS"]'; peer_in_scope = $true } }
        $script:Pairs | ForEach-Object { [pscustomobject]@{ _peerKey = $_.Target; peer_ci_id = $_.TargetCi; peer_tier = $_.TargetTier; peer_cmdb_id = $_.TargetCmdb; peer_cmdb_name = ''; peer_cmdb_criticality = ''; peer_cmdb_data_sensitivity = ''; peer_rf_p = '[]'; peer_rf_names = '[]'; peer_in_scope = $true } })
    $script:IdentityLinkRows = @($script:LinkRows | Where-Object { $_.si_class -eq 'identity' })

    $script:LogonTo = @('Identity_Admin_LogonTo_VulnerableDevice_Summary', 'Identity_Admin_LogonTo_VulnerableDevice_Detailed',
        'Identity_Admin_LogonTo_InternetExposedDevice_Summary', 'Identity_Admin_LogonTo_InternetExposedDevice_Detailed',
        'Identity_Admin_LogonTo_LowTierDevice_Summary', 'Identity_Admin_LogonTo_LowTierDevice_Detailed',
        'Identity_EligibleAdmin_LogonTo_ExploitableDevice_Summary', 'Identity_EligibleAdmin_LogonTo_ExploitableDevice_Detailed')
    $script:S2 = 'Attack_Paths_Detailed_Device_with_high_severity_vulnerabilities_allows_lateral_movement_Azure'
}

Describe 'S1 REPRODUCED -- a user''s row loses its DEVICE''s CI: the device''s _ciLink row is in another slice' {
    BeforeEach { Reset-State; Mock Invoke-LogAnalyticsKqlQuery { $script:LinkRows } }

    It 'unsliced, every user''s device has its CI (control)' {
        $q = "let _ciLink = SI_CI_CL | project _ciKey, si_ci_id, si_class, si_tier;`nExposureGraphNodes"
        $null = Resolve-ProfileCLLetBlocks -Query $q -WorkspaceResourceId $script:Ws -BucketCount 1 -BucketIndex 0
        $have = @{}; foreach ($r in (Get-InlinedRows -Var '_ciLink' -N 1 -B 0)) { $have[[string]$r._ciKey] = $r }
        foreach ($p in $script:Pairs) { $have[$p.Device].si_ci_id | Should -Be $p.DeviceCi }
    }
    It 'at 8 slices, the slice holding the user''s row lacks the device''s CI whenever the device hashes elsewhere' {
        $q = "let _ciLink = SI_CI_CL | project _ciKey, si_ci_id, si_class, si_tier;`nExposureGraphNodes"
        $lost = 0; $other = 0
        foreach ($b in 0..7) {
            $null = Resolve-ProfileCLLetBlocks -Query $q -WorkspaceResourceId $script:Ws -BucketCount 8 -BucketIndex $b
            $keys = @{}; foreach ($r in (Get-InlinedRows -Var '_ciLink' -N 8 -B $b)) { $keys[[string]$r._ciKey] = $true }
            foreach ($p in @($script:Pairs | Where-Object { (Get-Slice $_.User 8) -eq $b })) {
                $keys.ContainsKey($p.User) | Should -BeTrue -Because 'the user''s own CI is cut with the row (aligned)'
                if ((Get-Slice $p.Device 8) -ne $b) { $other++; if (-not $keys.ContainsKey($p.Device)) { $lost++ } }
            }
        }
        $other | Should -BeGreaterThan 150 -Because 'the fixture must put most devices in another slice than their user'
        $lost | Should -Be $other -Because 'the defect: every device in another slice than its user lost its CI id, tier and factors'
    }
}

Describe 'S1 FIXED -- the device''s CI is its own lookup (_ciPeer), complete in every slice, at 1, 2 and 8 slices' {
    BeforeAll {
        $script:R1 = Get-Report $script:LogonTo[0]
        $script:Q1 = (Get-Block $script:R1 '//__SI_CI_LINK_BEGIN__' '//__SI_CI_LINK_END__') + "`n" + (Get-Block $script:R1 '//__SI_CI_PEER_BEGIN__' '//__SI_CI_PEER_END__') + "`nExposureGraphNodes"
    }
    BeforeEach { Reset-State; Mock Invoke-LogAnalyticsKqlQuery { if ($Query -match '_peerKey') { @($script:PeerRows | Where-Object { $_.peer_ci_id -like 'ci-dev-*' }) } else { $script:IdentityLinkRows } } }

    It 'every user row finds its own CI AND its device''s CI with the right id and tier, at <N> slice(s)' -ForEach @(@{ N = 1 }, @{ N = 2 }, @{ N = 8 }) {
        $checked = 0
        foreach ($b in 0..($N - 1)) {
            $out = Resolve-ProfileCLLetBlocks -Query $script:Q1 -WorkspaceResourceId $script:Ws -BucketCount $N -BucketIndex $b
            $out | Should -Match 'let _ciPeer = datatable'
            $usr = @{}; foreach ($r in (Get-InlinedRows -Var '_ciLink' -N $N -B $b)) { $usr[[string]$r._ciKey] = $r }
            $dev = @{}; foreach ($r in (Get-InlinedRows -Var '_ciPeer' -N $N -B $b)) { $dev[[string]$r._peerKey] = $r }
            foreach ($p in @($script:Pairs | Where-Object { (Get-Slice $_.User $N) -eq $b })) {
                $usr.ContainsKey($p.User) | Should -BeTrue
                $dev[$p.Device].peer_ci_id | Should -Be $p.DeviceCi
                $dev[$p.Device].peer_tier  | Should -Be $p.DeviceTier
                $checked++
            }
            if ($N -gt 1) {
                @($script:_RAHybridLookups | Where-Object { $_.Name -eq '_ciPeer' })[0].Whole | Should -BeTrue -Because 'no key the slices are cut on: it travels whole while it fits'
                @($script:_RAHybridLookups | Where-Object { $_.Name -eq '_ciLink' })[0].Whole | Should -BeFalse -Because '_ciLink itself is still cut with the user rows'
            }
        }
        $checked | Should -Be 200
    }
    It 'when it does not fit whole, each of 8 slices carries only its own devices -- and still every one of them' {
        $all = 0
        foreach ($b in 0..7) {
            $mine = @($script:Pairs | Where-Object { (Get-Slice $_.User 8) -eq $b })
            $set = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::Ordinal)
            foreach ($p in $mine) { [void]$set.Add($p.Device) }
            # what Invoke-RALookupKeyDiscovery leaves behind: the keys this slice's graph rows have (the report's Keys lines)
            $script:_RALookupNeededKeySets = @{ '_ciPeer' = @{ Column = '_peerKey'; KeySet = $set } }
            $out = Resolve-ProfileCLLetBlocks -Query $script:Q1 -WorkspaceResourceId $script:Ws -BucketCount 8 -BucketIndex $b
            $l = @($script:_RAHybridLookups | Where-Object { $_.Name -eq '_ciPeer' })[0]
            $l.Whole | Should -BeFalse
            $l.Rows  | Should -Be $mine.Count -Because 'one CI row per device key the slice has -- bounded by the slice, not the tenant'
            foreach ($p in $mine) { $out | Should -Match ([regex]::Escape('"' + $p.Device + '"')) }
            $all += $l.Rows
        }
        $all | Should -Be 200 -Because 'over all slices every device row is sent exactly once'
    }
    It 'the peer row is small: measured bytes per inlined row (sizing the whole-or-reduced decision)' {
        $dt = Convert-RowsToKqlDatatable -LetVarName '_ciPeer' -Rows @($script:PeerRows | Select-Object -First 100) -BodyKqlForSchemaHint ''
        $per = [math]::Round($dt.Length / 100.0, 1)
        Write-Host ("[#677] _ciPeer inlined: {0} bytes per row (100 rows = {1} bytes)" -f $per, $dt.Length)
        $per | Should -BeLessThan 400
    }
}

Describe 'S1 FIXED -- the 8 Identity_*LogonTo_*Device_* reports as written' -ForEach @(
    @{ Name = 'Identity_Admin_LogonTo_VulnerableDevice_Summary' }, @{ Name = 'Identity_Admin_LogonTo_VulnerableDevice_Detailed' },
    @{ Name = 'Identity_Admin_LogonTo_InternetExposedDevice_Summary' }, @{ Name = 'Identity_Admin_LogonTo_InternetExposedDevice_Detailed' },
    @{ Name = 'Identity_Admin_LogonTo_LowTierDevice_Summary' }, @{ Name = 'Identity_Admin_LogonTo_LowTierDevice_Detailed' },
    @{ Name = 'Identity_EligibleAdmin_LogonTo_ExploitableDevice_Summary' }, @{ Name = 'Identity_EligibleAdmin_LogonTo_ExploitableDevice_Detailed' }) {
    BeforeAll {
        $script:R = Get-Report $Name
        $script:Q = $script:R.Substring($script:R.IndexOf('ReportQuery:'))
    }
    It 'reads the device''s CI only from _ciPeer, after the slice filter, on the device''s own key' {
        $script:Q | Should -Not -Match '_ciLink \| where si_class == "device"'
        $script:Q | Should -Match ([regex]::Escape('where tostring(si_class) in ("identity")')) -Because '_ciLink now serves the user side only (smaller per slice)'
        $cut = $script:Q.IndexOf('//__SI_LOOKUP_KEYS_HERE__')
        $cut | Should -BeGreaterThan $script:Q.IndexOf('//__BUCKET_FILTER_END__')
        $script:Q.IndexOf('| join kind=leftouter (_ciPeer) on $left.DeviceCiKey == $right._peerKey') | Should -BeGreaterThan $cut
        $script:Q.IndexOf('let _devices') | Should -BeLessThan $cut
        $dv = [regex]::Match($script:Q, '(?s)let _devices =.*?;').Value
        $dv | Should -Not -Match '\bsi_[a-z]' -Because 'the graph-only let no longer reads a CI'
        $dv | Should -Match 'DeviceNodeId = NodeId, MdeDeviceId'
    }
    It 'declares the reduction of _ciPeer with the query''s own key line' {
        $script:R | Should -Match '(?m)^      LookupNeededKeys:\n      - Lookup: _ciPeer\n        Column: _peerKey\n        Keys: \|-\n          \| extend DeviceCiKey = iif\(isnotempty\(MdeDeviceId\), MdeDeviceId, tolower\(DeviceNodeId\)\)\n          \| project __siNeeded = pack_array\(DeviceCiKey\)$'
        ($script:Q -split "`n" | ForEach-Object { $_.Trim() }) | Should -Contain '| extend DeviceCiKey = iif(isnotempty(MdeDeviceId), MdeDeviceId, tolower(DeviceNodeId))'
    }
    It 'the key query of a slice ends in that slice''s device keys' {
        $kq = Get-RALookupKeyQuery -ResolvedQuery $script:Q -KeysKql "| extend DeviceCiKey = iif(isnotempty(MdeDeviceId), MdeDeviceId, tolower(DeviceNodeId))`n| project __siNeeded = pack_array(DeviceCiKey)"
        $kq | Should -Match '__BUCKET_FILTER_END__'
        $kq | Should -Not -Match '_ciPeer\) on'
        $kq.TrimEnd() | Should -Match '\| summarize by __siNeeded$'
    }
    It 'the peer block is the canonical one (the engine regenerates it unchanged)' {
        $b = Get-Block $script:R '//__SI_CI_PEER_BEGIN__' '//__SI_CI_PEER_END__'
        (Resolve-RACiBlocks -Query $b -StaleDays 30) | Should -Be $b
        $b | Should -Match ([regex]::Escape('where tostring(si_class) in ("device")'))
    }
}

Describe 'S2 REPRODUCED + FIXED -- the Azure target''s CI of a vulnerable-device path' {
    It 'REPRODUCED -- _TargetCi read from the sliced _ciLink lacks the target whenever it hashes elsewhere than the entry device' {
        Reset-State; Mock Invoke-LogAnalyticsKqlQuery { $script:LinkRows }
        $q = "let _ciLink = SI_CI_CL | project _ciKey, si_ci_id, si_class, si_tier, si_cmdb_id;`nlet _TargetCi = _ciLink | project _tKey = _ciKey, Target_Tier = si_tier;`nExposureGraphNodes"
        $lost = 0; $other = 0
        foreach ($b in 0..7) {
            $null = Resolve-ProfileCLLetBlocks -Query $q -WorkspaceResourceId $script:Ws -BucketCount 8 -BucketIndex $b
            $keys = @{}; foreach ($r in (Get-InlinedRows -Var '_ciLink' -N 8 -B $b)) { $keys[[string]$r._ciKey] = $true }
            foreach ($p in @($script:Pairs | Where-Object { (Get-Slice $_.Device 8) -eq $b })) {
                if ((Get-Slice $p.Target 8) -ne $b) { $other++; if (-not $keys.ContainsKey($p.Target)) { $lost++ } }
            }
        }
        $other | Should -BeGreaterThan 150
        $lost | Should -Be $other -Because 'the defect: the target fell to the default tier 3 with no CMDB values'
    }
    It 'FIXED -- every entry-device row finds its target''s tier and CMDB at <N> slice(s)' -ForEach @(@{ N = 1 }, @{ N = 2 }, @{ N = 8 }) {
        Reset-State; Mock Invoke-LogAnalyticsKqlQuery { if ($Query -match '_peerKey') { @($script:PeerRows | Where-Object { $_.peer_ci_id -like 'ci-tgt-*' }) } else { @($script:LinkRows | Where-Object { $_.si_class -ne 'identity' }) } }
        $r = Get-Report $script:S2
        $q = (Get-Block $r '//__SI_CI_LINK_BEGIN__' '//__SI_CI_LINK_END__') + "`n" + (Get-Block $r '//__SI_CI_PEER_BEGIN__' '//__SI_CI_PEER_END__') + "`nExposureGraphNodes"
        $checked = 0
        foreach ($b in 0..($N - 1)) {
            $null = Resolve-ProfileCLLetBlocks -Query $q -WorkspaceResourceId $script:Ws -BucketCount $N -BucketIndex $b
            $tgt = @{}; foreach ($x in (Get-InlinedRows -Var '_ciPeer' -N $N -B $b)) { $tgt[[string]$x._peerKey] = $x }
            foreach ($p in @($script:Pairs | Where-Object { (Get-Slice $_.Device $N) -eq $b })) {
                $tgt[$p.Target].peer_tier    | Should -Be $p.TargetTier
                $tgt[$p.Target].peer_cmdb_id | Should -Be $p.TargetCmdb
                $checked++
            }
        }
        $checked | Should -Be 200
    }
    It 'the report reads the target''s CI from _ciPeer after the cut point and declares its reduction' {
        $r = Get-Report $script:S2
        $q = $r.Substring($r.IndexOf('ReportQuery:'))
        $q | Should -Not -Match 'let _TargetCi = _ciLink'
        $cut = $q.IndexOf('//__SI_LOOKUP_KEYS_HERE__')
        $cut | Should -BeGreaterThan $q.IndexOf('//__BUCKET_FILTER_END__')
        $q.IndexOf('| join kind=leftouter (_ciPeer) on $left.TargetKey == $right._peerKey') | Should -BeGreaterThan $cut
        $r | Should -Match '(?m)^      - Lookup: _ciPeer\n        Column: _peerKey\n        Keys: \|-\n          \| extend TargetKey = tolower\(TargetAzureAssetId\)\n          \| project __siNeeded = pack_array\(TargetKey\)$'
        (Resolve-RACiBlocks -Query (Get-Block $r '//__SI_CI_PEER_BEGIN__' '//__SI_CI_PEER_END__') -StaleDays 30) | Should -Be (Get-Block $r '//__SI_CI_PEER_BEGIN__' '//__SI_CI_PEER_END__')
    }
}

Describe 'S3 + S4 FIXED -- the 10 attack-path reports cut their PATHS on the final target and read both ends'' CI from _ciPeer' -ForEach @(
    @{ Name = 'Attack_Paths_Summary_Credential_Based_Lateral_Movement';  Col = 'TargetNodeId'; Let = 'Hop2Edges'; Grain = 'FinalTargetId'; Ends = 2 }
    @{ Name = 'Attack_Paths_Detailed_Credential_Based_Lateral_Movement'; Col = 'TargetNodeId'; Let = 'Hop2Edges'; Grain = 'FinalTargetId'; Ends = 2 }
    @{ Name = 'Attack_Paths_Summary_Github_to_Azure_Resources';  Col = 'TargetNodeId'; Let = 'Hop2'; Grain = 'FinalTargetId'; Ends = 1 }
    @{ Name = 'Attack_Paths_Detailed_Github_to_Azure_Resources'; Col = 'TargetNodeId'; Let = '';     Grain = 'FinalTargetId'; Ends = 1 }
    @{ Name = 'Attack_Paths_Summary_Public_IP_to_VM_with_CVE_Exploitation';  Col = 'ExposedResourceNodeId'; Let = 'PublicIPConnections'; Grain = 'ExposedResourceNodeId'; Ends = 1 }
    @{ Name = 'Attack_Paths_Detailed_Public_IP_to_VM_with_CVE_Exploitation'; Col = 'ExposedResourceNodeId'; Let = 'PublicIPConnections'; Grain = 'ExposedResourceNodeId'; Ends = 1 }
    @{ Name = 'Attack_Paths_Summary_Identity_Group_Membership_to_Privileged_Resources';  Col = 'FinalTargetId'; Let = 'GroupAccessToTargets'; Grain = 'FinalTargetId'; Ends = 2 }
    @{ Name = 'Attack_Paths_Detailed_Identity_Group_Membership_to_Privileged_Resources'; Col = 'FinalTargetId'; Let = 'GroupAccessToTargets'; Grain = 'FinalTargetId'; Ends = 2 }
    @{ Name = 'Attack_Paths_Summary_Data_Sensitivity_to_Exposed_Credentials';  Col = 'TargetNodeId'; Let = 'SensitiveDataLocations'; Grain = 'DataLocationNodeId'; Ends = 2 }
    @{ Name = 'Attack_Paths_Detailed_Data_Sensitivity_to_Exposed_Credentials'; Col = 'TargetNodeId'; Let = 'SensitiveDataLocations'; Grain = 'DataLocationNodeId'; Ends = 2 }) {
    BeforeAll {
        $script:R = Get-Report $Name
        $script:Q = $script:R.Substring($script:R.IndexOf('ReportQuery:'))
    }
    It 'one slice filter, on the final target''s node id, in the edge set that gives the path its target (never in Nodes)' {
        ([regex]::Matches($script:Q, '//__BUCKET_FILTER_BEGIN__')).Count | Should -Be 1
        $f = $script:Q.IndexOf('//__BUCKET_FILTER_BEGIN__')
        $script:Q.Substring(0, $f) | Should -Match ('\| extend DeviceKey = ' + $Col + '\s*\n(?:\s*//[^\n]*\n)*\s*$') -Because 'the slice key is the target node id, set right before the filter'
        if ($Let) {
            $owner = [regex]::Matches($script:Q.Substring(0, $f), '\blet\s+(\w+)\s*=') | Select-Object -Last 1
            $owner.Groups[1].Value | Should -Be $Let
        }
        [regex]::Match($script:Q, '(?s)let Nodes =.*?;').Value | Should -Not -Match '__BUCKET_FILTER_'
    }
    It 'the path grain includes the target, so a path is built in exactly one slice' {
        $rest = $script:Q.Substring($script:Q.IndexOf('//__BUCKET_FILTER_END__'))
        $rest | Should -Match ('(?s)\bsummarize\b[^;]*?\bby\b[^;|]*\b' + $Grain + '\b')
    }
    It 'no _ciLink; Nodes reads no CI; each end''s CI is a _ciPeer join after the cut point, declared for reduction' {
        $script:Q | Should -Not -Match '\b_ciLink\b'
        [regex]::Match($script:Q, '(?s)let Nodes =.*?;').Value | Should -Not -Match '_NodeCiTier|_ciPeer'
        $cut = $script:Q.IndexOf('//__SI_LOOKUP_KEYS_HERE__')
        $cut | Should -BeGreaterThan $script:Q.IndexOf('//__BUCKET_FILTER_END__')
        $joins = @([regex]::Matches($script:Q, '\| join kind=leftouter \(_ciPeer\) on \$left\.(\w+) == \$right\._peerKey'))
        $joins.Count | Should -Be $Ends
        foreach ($j in $joins) { $j.Index | Should -BeGreaterThan $cut; $j.Groups[1].Value | Should -BeIn @('SourceCiKey', 'TargetCiKey') }
        $script:R | Should -Match '(?m)^      - Lookup: _ciPeer\n        Column: _peerKey\n'
        $script:R | Should -Match ('\| project __siNeeded = pack_array\(' + $(if ($Ends -eq 2) { 'SourceCiKey, TargetCiKey' } else { 'TargetCiKey' }) + '\)')
        (Resolve-RACiBlocks -Query (Get-Block $script:R '//__SI_CI_PEER_BEGIN__' '//__SI_CI_PEER_END__') -StaleDays 30) | Should -Be (Get-Block $script:R '//__SI_CI_PEER_BEGIN__' '//__SI_CI_PEER_END__')
    }
    It 'the key query of a slice is valid where the cut point sits inside a let: the let is closed and is the result' {
        $keys = ([regex]::Match($script:R, '(?s)Keys: \|-\n(.*?)\n      ReportPurpose:')).Groups[1].Value -replace '(?m)^          ', ''
        $kq = Get-RALookupKeyQuery -ResolvedQuery $script:Q -KeysKql $keys
        $kq | Should -Not -Match '_ciPeer\) on'
        $let = Get-RALookupCutLetName -Head $script:Q.Substring(0, $script:Q.IndexOf('//__SI_LOOKUP_KEYS_HERE__'))
        # the let the cut point sits in, read independently: the last `let X =` before it that no `;` has closed
        $head = $script:Q.Substring(0, $script:Q.IndexOf('//__SI_LOOKUP_KEYS_HERE__'))
        $own = [regex]::Matches($head, '(?m)^\s*let\s+(\w+)\s*=') | Select-Object -Last 1
        $inLet = ($own -and ((Remove-Strings $head.Substring($own.Index)) -notmatch ';'))
        if ($inLet) {
            $let | Should -Be $own.Groups[1].Value
            $kq.TrimEnd() | Should -Match ('\| summarize by __siNeeded;\r?\n' + $let + '$')
        } else {
            $let | Should -BeNullOrEmpty
            $kq.TrimEnd() | Should -Match '\| summarize by __siNeeded$'
        }
    }
}

Describe 'the cut point inside a let (Get-RALookupCutLetName)' {
    It 'names the let the text ends in, ignoring semicolons in strings, comments and inlined values' {
        Get-RALookupCutLetName -Head "let a = T;`nlet B = X`n| where y == `"p;q`" // a;b`n| extend z = 'r;s'" | Should -Be 'B'
        Get-RALookupCutLetName -Head "let a = datatable(k:string)[`"x;y`"];`nT`n| where 1 == 1" | Should -Be ''
        Get-RALookupCutLetName -Head 'T | where 1 == 1' | Should -Be ''
    }
}

Describe 'S3 + S4 FIXED -- sliced on the target, every path once, both ends'' CI in the row, identical to unsliced at 1, 2 and 8 slices' {
    BeforeAll {
        # paths: source user -> target; several paths share a target (a hub) and several share a source
        $script:Paths = @(0..299 | ForEach-Object {
            $p = $script:Pairs[$_ % 200]; $tg = $script:Pairs[($_ * 7) % 200]
            [pscustomobject]@{ PathKey = "$($p.User)->$($tg.Target)->$_"; TargetNodeId = "node-$($tg.Target)"; SourceCiKey = $p.Device; TargetCiKey = $tg.Target; Cmdb = $tg.TargetCmdb }
        })
        $script:PeerAll = @($script:PeerRows)
        $r = Get-Report 'Attack_Paths_Detailed_Credential_Based_Lateral_Movement'
        $script:QP = (Get-Block $r '//__SI_CI_PEER_BEGIN__' '//__SI_CI_PEER_END__') + "`nExposureGraphNodes"
        function script:Get-Enriched { param([object[]]$Rows, [hashtable]$Peer)
            foreach ($x in $Rows) {
                $s = $Peer[$x.SourceCiKey]; $t = $Peer[$x.TargetCiKey]
                '{0}|src={1}:{2}|tgt={3}:{4}:{5}' -f $x.PathKey, $(if ($s) { $s.peer_ci_id } else { '' }), $(if ($s) { $s.peer_tier } else { '' }), $(if ($t) { $t.peer_ci_id } else { '' }), $(if ($t) { $t.peer_tier } else { '' }), $(if ($t) { $t.peer_cmdb_id } else { '' })
            }
        }
        $all = @{}; foreach ($x in $script:PeerAll) { $all[[string]$x._peerKey] = $x }
        $script:Truth = @(Get-Enriched -Rows $script:Paths -Peer $all | Sort-Object)
    }
    BeforeEach { Reset-State; Mock Invoke-LogAnalyticsKqlQuery { $script:PeerAll } }

    It 'unsliced: every path has both ends'' CI (control)' {
        @($script:Truth | Where-Object { $_ -match 'src=:|tgt=:' }).Count | Should -Be 0
        $script:Truth.Count | Should -Be 300
    }
    It 'at <N> slice(s), whole: the union of the slices is the unsliced result, row for row, no path twice' -ForEach @(@{ N = 1 }, @{ N = 2 }, @{ N = 8 }) {
        $got = New-Object System.Collections.Generic.List[string]
        foreach ($b in 0..($N - 1)) {
            $null = Resolve-ProfileCLLetBlocks -Query $script:QP -WorkspaceResourceId $script:Ws -BucketCount $N -BucketIndex $b
            $peer = @{}; foreach ($x in (Get-InlinedRows -Var '_ciPeer' -N $N -B $b)) { $peer[[string]$x._peerKey] = $x }
            $mine = @($script:Paths | Where-Object { (Get-Slice $_.TargetNodeId $N) -eq $b })
            foreach ($e in (Get-Enriched -Rows $mine -Peer $peer)) { $got.Add($e) }
        }
        @($got | Sort-Object) | Should -Be $script:Truth
        @($got | ForEach-Object { ($_ -split '\|')[0] } | Group-Object | Where-Object Count -gt 1).Count | Should -Be 0
    }
    It 'at 8 slices, reduced: each slice carries only its own ends'' rows, and the union is still the unsliced result' {
        $got = New-Object System.Collections.Generic.List[string]; $sent = 0
        foreach ($b in 0..7) {
            Reset-State
            $mine = @($script:Paths | Where-Object { (Get-Slice $_.TargetNodeId 8) -eq $b })
            $set = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::Ordinal)
            foreach ($x in $mine) { [void]$set.Add($x.SourceCiKey); [void]$set.Add($x.TargetCiKey) }
            $script:_RALookupNeededKeySets = @{ '_ciPeer' = @{ Column = '_peerKey'; KeySet = $set } }
            $null = Resolve-ProfileCLLetBlocks -Query $script:QP -WorkspaceResourceId $script:Ws -BucketCount 8 -BucketIndex $b
            $l = @($script:_RAHybridLookups | Where-Object { $_.Name -eq '_ciPeer' })[0]
            $l.Rows | Should -Be $set.Count -Because 'one row per key the slice''s paths have -- the per-slice worst case is that, not the tenant'
            $sent += $l.Rows
            $peer = @{}; foreach ($x in (Get-RALookupRowsForKeys -CacheKey 'k' -AllRows $script:PeerAll -Column '_peerKey' -Keys $set)) { $peer[[string]$x._peerKey] = $x }
            foreach ($e in (Get-Enriched -Rows $mine -Peer $peer)) { $got.Add($e) }
        }
        @($got | Sort-Object) | Should -Be $script:Truth
        $sent | Should -BeLessThan (8 * $script:PeerAll.Count) -Because 'never the whole lookup in every slice'
    }
    It 'a Summary''s count over targets adds up over the slices (the bucket merge sums a dcount of FinalTargetId)' {
        $truth = @($script:Paths | Group-Object Cmdb | ForEach-Object { '{0}={1}' -f $_.Name, @($_.Group.TargetNodeId | Sort-Object -Unique).Count } | Sort-Object)
        $sum = @{}
        foreach ($b in 0..7) {
            foreach ($g in @($script:Paths | Where-Object { (Get-Slice $_.TargetNodeId 8) -eq $b } | Group-Object Cmdb)) {
                $sum[$g.Name] = [int]$sum[$g.Name] + @($g.Group.TargetNodeId | Sort-Object -Unique).Count
            }
        }
        @($sum.GetEnumerator() | ForEach-Object { '{0}={1}' -f $_.Key, $_.Value } | Sort-Object) | Should -Be $truth
        $script:RA_AssetIdentityColumns = $null
        . (Join-Path $script:SIRoot 'engine\risk-analysis\_shared\RA-SummaryBucketMerge.ps1')
        $script:RA_AssetIdentityColumns | Should -Contain 'FinalTargetId'
    }
}
