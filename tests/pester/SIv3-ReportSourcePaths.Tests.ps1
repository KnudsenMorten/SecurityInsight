#Requires -Version 5.1
<#
    #690 items 17-21 -- THE IDENTITY AND PUBLIC-IP REPORTS READ WHAT THE SOURCE REALLY HOLDS, AND NOTHING IS LOST IN SILENCE.

    Found by the report certification (#688, ops\report-certification\reviews\review-E.md + verify.md), counts read-only on
    internal 2026-10-15 (Defender advanced hunting through the Support app):
      (17) The four Identity_*LogonTo_*Device pairs read rawData.userPrincipalName -- no Exposure Graph user node has it
           (0 of 130; SI's own eg mapping takes si_upn from rawData.accountUpn), and dropped every account without a UPN.
           Only "device" nodes were targets (the graph ties "can authenticate to" to virtual-machine nodes too, 30 of 42),
           and only direct edges counted (a group that can authenticate, nested groups). The exploit keys hasExploit /
           isInExploitKit / isExploitVerified do not exist (the graph holds explotabilityLevels under
           vulnerableToRemoteCodeExecution / vulnerableToPrivilegeEscalation); the EligibleAdmin pair had no eligibility
           filter. Graph part read-only on internal after the fix: 42 account x machine rows (was 0), 8 eligible-admin rows
           on an exploitable machine (was 0).
      (18) `mv-expand` on an EMPTY array drops the row (`print a=dynamic([]) | mv-expand a | count` = 0) -- the sign-in
           reports lost exactly the sign-ins with no location (the untrusted ones). Every mv-expand left in the catalog is
           on a reviewed list below, with why dropping an empty list is the report's purpose.
      (19) Four privilege reports selected on the ASSET tier (si_tier) where their purpose is a privileged ROLE -- the role
           tier SI already holds (si_privilege_tier_permanent / si_privilege_tier_eligible) now decides, and the asset tier
           still counts (never fewer rows than before).
      (20) Identity_PIM_DuplicateRoleAssignment required BOTH sides to be a Tier 0/1 role -- the question is the same role
           held active (permanent or time-bound) and eligible, whatever its tier.
      (21) The public IP to VM attack paths started from microsoft.network/publicipaddresses only (no outgoing edge there);
           the graph's routing nodes are labelled "IP address". After the fix: 2 exposed machines (was 0).
    Offline: reads the shipped YAML with SecurityInsight's own reader. No query is run.
#>

BeforeAll {
    $script:SIRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    . (Join-Path $script:SIRoot 'engine\_shared\SI-Yaml.ps1')
    $script:Path = Join-Path $script:SIRoot 'risk-analysis-detection\RiskAnalysis_Queries_Locked.yaml'
    $script:Catalog = ConvertFrom-SIYaml -Yaml ([IO.File]::ReadAllText($script:Path)) -SourceName $script:Path
    $script:Reports = @($script:Catalog.Reports)
    function script:Report([string]$Name) { @($script:Reports | Where-Object { [string]$_.ReportName -eq $Name })[0] }
    # the report's own KQL: the engine-generated blocks (scope, CI) and comment lines left out
    function script:OwnLines($r) {
        $out = New-Object System.Collections.Generic.List[string]
        $skip = $false
        foreach ($l in ((@($r.ReportQuery) | ForEach-Object { [string]$_ }) -join "`n" -split "`r?`n")) {
            if ($l -match '//__SI_(SCOPE|CI_\w+?)_BEGIN__') { $skip = $true; continue }
            if ($l -match '//__SI_(SCOPE|CI_\w+?)_END__') { $skip = $false; continue }
            if ($skip -or $l.Trim() -match '^//') { continue }
            $out.Add($l)
        }
        $out.ToArray()
    }
    function script:CodeOf([string]$Name) {
        $r = Report $Name
        $r | Should -Not -BeNullOrEmpty -Because "$Name is in the catalog"
        (OwnLines $r) -join "`n"
    }
    $script:LogonTo = @('Identity_Admin_LogonTo_VulnerableDevice_Summary', 'Identity_Admin_LogonTo_VulnerableDevice_Detailed',
        'Identity_Admin_LogonTo_InternetExposedDevice_Summary', 'Identity_Admin_LogonTo_InternetExposedDevice_Detailed',
        'Identity_Admin_LogonTo_LowTierDevice_Summary', 'Identity_Admin_LogonTo_LowTierDevice_Detailed',
        'Identity_EligibleAdmin_LogonTo_ExploitableDevice_Summary', 'Identity_EligibleAdmin_LogonTo_ExploitableDevice_Detailed')
    $script:RoleTier = @('Identity_PrivilegedUser_StalePassword_Summary', 'Identity_PrivilegedUser_StalePassword_Detailed',
        'Identity_AdminAccount_OnPremSynced_Summary', 'Identity_AdminAccount_OnPremSynced_Detailed',
        'Identity_AdminAccount_NeverUsed_Summary', 'Identity_AdminAccount_NeverUsed_Detailed')
    $script:ScopeTemplate = Get-Content -Raw (Join-Path $script:SIRoot 'data-model\report-scope.locked.json') | ConvertFrom-Json
}

Describe '(17) the graph''s user and device nodes, read by the names the graph writes' {
    It 'no report reads a graph node''s rawData.userPrincipalName (the graph holds accountUpn)' {
        $hits = foreach ($r in $script:Reports) { if (((OwnLines $r) -join "`n") -match 'rawData\.userPrincipalName') { [string]$r.ReportName } }
        @($hits) -join ', ' | Should -BeExactly ''
    }
    It 'no report reads the exploit keys the graph does not hold (hasExploit / isInExploitKit / isExploitVerified)' {
        $hits = foreach ($r in $script:Reports) { if (((OwnLines $r) -join "`n") -match 'highRiskVulnerabilityInsights\.(hasExploit|isInExploitKit|isExploitVerified)\b') { [string]$r.ReportName } }
        @($hits) -join ', ' | Should -BeExactly ''
    }
    It '<_> reads accountUpn, keeps an account without a UPN, and follows virtual-machine nodes and group edges' -ForEach @(
        'Identity_Admin_LogonTo_VulnerableDevice_Summary', 'Identity_Admin_LogonTo_VulnerableDevice_Detailed',
        'Identity_Admin_LogonTo_InternetExposedDevice_Summary', 'Identity_Admin_LogonTo_InternetExposedDevice_Detailed',
        'Identity_Admin_LogonTo_LowTierDevice_Summary', 'Identity_Admin_LogonTo_LowTierDevice_Detailed',
        'Identity_EligibleAdmin_LogonTo_ExploitableDevice_Summary', 'Identity_EligibleAdmin_LogonTo_ExploitableDevice_Detailed') {
        $c = CodeOf $_
        $c | Should -Match ([regex]::Escape('| extend UserUPN         = tolower(tostring(rawData.accountUpn))'))
        $c | Should -Not -Match 'where isnotempty\(UserUPN\)' -Because 'a gMSA or a sync account can authenticate to a device and has no UPN'
        $c | Should -Match 'rawData\.accountDisplayName'
        $c | Should -Match ([regex]::Escape('| where NodeLabel in~ ("device", "microsoft.compute/virtualmachines")'))
        $c | Should -Match 'EdgeLabel =~ "member of"' -Because 'a group that can authenticate to a device gives that right to its members'
        foreach ($n in 1..5) { $c | Should -Match ('let _auth{0} = _memberOf \| join kind=inner \(_auth{1}\)' -f $n, ($n - 1)) }
        $c | Should -Match 'let _authTo = union _auth0, _auth1, _auth2, _auth3, _auth4, _auth5'
        $c | Should -Match ([regex]::Escape('| summarize arg_max(DeviceNodeId, *) by UserNodeId, _machineKey')) -Because 'one row per account and machine'
        # the order the slicing rests on (#677): the graph rows, then the slice filter, then the device's CI
        $q = @((Report $_).ReportQuery) -join "`n"
        $q.IndexOf('_authTo') | Should -BeGreaterThan 0
        $q.IndexOf('_authTo') | Should -BeLessThan $q.IndexOf('//__BUCKET_FILTER_BEGIN__')
        $q.IndexOf('//__BUCKET_FILTER_END__') | Should -BeLessThan $q.IndexOf('| join kind=leftouter (_ciPeer) on $left.DeviceCiKey == $right._peerKey')
    }
    It 'the EligibleAdmin pair keeps PIM-eligible accounts only, and reads the exploit from the graph''s levels AND Defender vulnerability management' -ForEach @(
        'Identity_EligibleAdmin_LogonTo_ExploitableDevice_Summary', 'Identity_EligibleAdmin_LogonTo_ExploitableDevice_Detailed') {
        $c = CodeOf $_
        $c | Should -Match ([regex]::Escape('| where array_length(rawData.eligibleRoles) > 0'))
        $c | Should -Match 'vulnerableToRemoteCodeExecution\.explotabilityLevels'
        $c | Should -Match 'vulnerableToPrivilegeEscalation\.explotabilityLevels'
        foreach ($lv in 'ExploitIsInKit', 'ExploitIsVerified', 'ExploitIsPublic') { $c | Should -Match ('"' + $lv + '"') }
        $c | Should -Match 'DeviceTvmSoftwareVulnerabilitiesKB \| where IsExploitAvailable == true'
        $c | Should -Match ([regex]::Escape('| where tolower(DeviceId) in (_authTargetMde)')) -Because 'Defender vulnerability management is read for the reachable devices only'
        $c | Should -Match ([regex]::Escape('| extend HasExploit = HasExploit or isnotempty(TvmExploitDeviceId)'))
        (Report $_).ReportPurpose | Should -Not -Match 'isExploitVerified|isInExploitKit'
    }
    It 'the other three pairs do not filter on eligibility (their purpose is not PIM-eligible accounts)' {
        foreach ($n in @($script:LogonTo | Where-Object { $_ -notlike 'Identity_EligibleAdmin_*' })) { (CodeOf $n) | Should -Not -Match 'eligibleRoles' -Because $n }
    }
}

Describe '(18) mv-expand never drops a row the report needs' {
    BeforeAll {
        # every mv-expand left in the catalog's own KQL, with why an EMPTY list dropping the row is the report's purpose
        $script:MvExpandReviewed = @{
            'Azure_Recommendations_Summary|| mv-expand _dfcKey = _keys to typeof(string))'  = 'the hand-off key list to the Defender report -- no key, nothing to hand off'
            'Azure_Recommendations_Detailed|| mv-expand _dfcKey = _keys to typeof(string))' = 'the same'
            'Azure_Recommendations_Summary|| mv-expand Category = Categories'  = 'selects the graph''s finding nodes by category -- a node with no category is not a finding'
            'Azure_Recommendations_Detailed|| mv-expand Category = Categories' = 'the same'
            'PublicIP_OpenPorts_Summary|| mv-expand Port = si_open_ports to typeof(int)'  = 'one finding per open port -- no open port, no finding'
            'PublicIP_OpenPorts_Detailed|| mv-expand Port = si_open_ports to typeof(int)' = 'the same'
            'PublicIP_Vulnerabilities_Summary|| mv-expand Cve = si_vulns to typeof(string)'  = 'one finding per CVE on the address -- no CVE, no finding'
            'PublicIP_Vulnerabilities_Detailed|| mv-expand Cve = si_vulns to typeof(string)' = 'the same'
            'Identity_SPN_OwnsResourcePublicAccess_Summary|| mv-expand _role = si_azure_role_assignments'  = 'one finding per role on a public resource -- no role, no finding'
            'Identity_SPN_OwnsResourcePublicAccess_Detailed|| mv-expand _role = si_azure_role_assignments' = 'the same'
            'Endpoint_ConflictingTierTags_Summary|| mv-expand _t = si_tags to typeof(dynamic)'  = 'the question is conflicting tier TAGS -- an asset without tags has no conflict (#690 (11): the tag array itself, never its JSON text)'
            'Endpoint_ConflictingTierTags_Detailed|| mv-expand _t = si_tags to typeof(dynamic)' = 'the same'
            'Identity_SPN_OwnsResourcePublicAccess_Summary|| mv-expand _n = range(2, array_length(_idParts) - 1, 1) to typeof(int)'  = 'the scopes of a resource id (#690 (3)): a resource id always has a subscription part -- the list is never empty'
            'Identity_SPN_OwnsResourcePublicAccess_Detailed|| mv-expand _n = range(2, array_length(_idParts) - 1, 1) to typeof(int)' = 'the same'
            # #691: one finding per owner of a privileged application -- an application without an owner has no owner route
            'Attack_Paths_Summary_Owner_to_Privileged_Service_Principal|| mv-expand _ow = _owners to typeof(dynamic)'  = 'one finding per owner of the application -- no owner, no owner route (the orphan report covers that)'
            'Attack_Paths_Detailed_Owner_to_Privileged_Service_Principal|| mv-expand _ow = _owners to typeof(dynamic)' = 'the same'
            'Device_Certificates_Summary|| mv-expand _kind = _kinds to typeof(string)'  ='one finding per problem of a certificate -- the list is never empty after the where that keeps a certificate with at least one problem'
            'Device_Certificates_Detailed|| mv-expand _kind = _kinds to typeof(string)' = 'the same'
            # the device's own-tier lookup carries one row per link key of a device CI so it can be cut to each slice's devices;
            # a CI with no link key is no slice's device (the device CI is matched on those keys), and the join reads it
            # summarized back to one row per CI -- no finding row is dropped here
            'Identity_Admin_LogonTo_LowTierDevice_Summary|| mv-expand _dtKey = _dtKeys to typeof(string)'  = 'one row per link key of a device CI (the lookup cut per slice) -- a CI with no link key is no device of any slice; summarized back per CI before the join'
            'Identity_Admin_LogonTo_LowTierDevice_Detailed|| mv-expand _dtKey = _dtKeys to typeof(string)' = 'the same'
        }
        foreach ($n in 'Github_to_Azure_Resources', 'Public_IP_to_VM_with_CVE_Exploitation', 'Identity_Group_Membership_to_Privileged_Resources',
                       'Data_Sensitivity_to_Exposed_Credentials', 'Credential_Based_Lateral_Movement') {
            foreach ($v in '_d', '_s') {
                $script:MvExpandReviewed[('Attack_Paths_Summary_{0}|| mv-expand {1} to typeof(string)' -f $n, $v)] = 'the detail text split into its parts (a split always keeps one part) and joined back leftouter -- no path is lost'
            }
        }
    }
    It 'the scan finds the catalog''s mv-expands (control -- green must not mean "scanned nothing")' {
        $all = foreach ($r in $script:Reports) { foreach ($l in (OwnLines $r)) { if ($l -match '\bmv-expand\b') { 1 } } }
        @($all).Count | Should -BeGreaterThan 15
    }
    It 'every mv-expand in a report''s own KQL is reviewed: an empty list dropping its row is the report''s purpose' {
        $found = foreach ($r in $script:Reports) { foreach ($l in (OwnLines $r)) { $t = $l.Trim(); if ($t -match '\bmv-expand\b') { '{0}|{1}' -f $r.ReportName, $t } } }
        @($found | Where-Object { -not $script:MvExpandReviewed.ContainsKey($_) }) -join ' || ' | Should -BeExactly '' -Because 'an mv-expand on an empty array drops the row -- keep the row (has / leftouter / a summarize after mv-apply) or review it here'
    }
    It 'no sign-in report expands the network-location list -- a sign-in with an empty list is kept and is untrusted' {
        foreach ($n in 'Identity_PrivilegedUser_SignIn_NonTrustedLocation_Summary', 'Identity_PrivilegedUser_SignIn_NonTrustedLocation_Detailed',
                       'Identity_ServiceAccount_SignIn_NonTrustedLocation_Summary', 'Identity_BreakGlass_SignIn_Detected_Summary',
                       'Identity_ServiceAccount_InteractiveSignIn_Summary') {
            $c = CodeOf $n
            $c | Should -Not -Match 'mv-expand\s+(NetLoc|NetworkLocationDetails)\b' -Because $n
            $c | Should -Match ([regex]::Escape('| extend IsTrusted = iff(tostring(NetworkLocationDetails) has "trustedNamedLocation", 1, 0)')) -Because $n
        }
    }
    It 'the trusted test, as KQL has compares terms: an empty list is untrusted, any trusted location makes the sign-in trusted' {
        # has matches whole terms, ignoring case -- the same test here over the JSON text the column holds
        $isTrusted = { param([string]$j) ([regex]::Matches($j, '[A-Za-z0-9_]+') | Where-Object { $_.Value -ieq 'trustedNamedLocation' }).Count -gt 0 }
        (& $isTrusted '[]') | Should -BeFalse
        (& $isTrusted '[{"networkType":"namedNetwork","networkNames":["X"]}]') | Should -BeFalse
        (& $isTrusted '[{"networkType":"namedNetwork"},{"networkType":"trustedNamedLocation"}]') | Should -BeTrue
    }
}

Describe '(19) a privileged-ROLE report decides on the role tier, and keeps every row the asset tier kept' {
    It '<_> selects on the role tier or the account''s own tier, and its tier is the more critical of the two' -ForEach @(
        'Identity_PrivilegedUser_StalePassword_Summary', 'Identity_PrivilegedUser_StalePassword_Detailed',
        'Identity_AdminAccount_OnPremSynced_Summary', 'Identity_AdminAccount_OnPremSynced_Detailed',
        'Identity_AdminAccount_NeverUsed_Summary', 'Identity_AdminAccount_NeverUsed_Detailed') {
        $c = CodeOf $_
        $c | Should -Match ([regex]::Escape('| extend _roleTier = min_of(coalesce(si_privilege_tier_permanent, 99), coalesce(si_privilege_tier_eligible, 99))'))
        $c | Should -Match ([regex]::Escape('| where _roleTier <= 1 or isnull(si_tier) or si_tier in (0, 1)'))
        # #690 (15): no tier default -- a row with neither a role tier (0-3) nor an asset tier keeps an empty tier (the tier rules decide)
        $c | Should -Match ([regex]::Escape('| extend CriticalityTier = toint(case(isnull(si_tier) and _roleTier > 3, int(null), isnull(si_tier), _roleTier, _roleTier > 3, toint(si_tier), min_of(_roleTier, toint(si_tier))))'))
        $id = $_
        $spec = @($script:ScopeTemplate.reports | Where-Object { $_.id -eq $id })[0]
        $spec.scope.tier | Should -BeFalse -Because 'the CI block must not cut on the asset tier before the query sees the role tier'
        $block = [regex]::Match((@((Report $_).ReportQuery) -join "`n"), '(?s)//__SI_CI_ASSET_BEGIN__.*?//__SI_CI_ASSET_END__').Value
        $block | Should -Match 'si_privilege_tier_permanent' -Because 'the CI block carries the role tier'
        $block | Should -Not -Match 'si_tier", int\(null\)\)\) in \(' -Because 'no asset-tier cut in the CI block'
    }
    It 'the role tier fields exist in the field catalog (no new si field)' {
        $fc = Get-Content -Raw (Join-Path $script:SIRoot 'data-model\field-catalog.locked.json')
        foreach ($f in 'si_privilege_tier_permanent', 'si_privilege_tier_eligible') { $fc | Should -Match ('"name": "' + $f + '"') }
    }
    It 'the new-account report asks for a Tier 0 ROLE (permanent or eligible), or an account SI rates Tier 0' {
        foreach ($n in 'Identity_NewAccount_ImmediateTier0Role_Summary', 'Identity_NewAccount_ImmediateTier0Role_Detailed') {
            (CodeOf $n) | Should -Match ([regex]::Escape('| where si_privilege_tier_permanent == 0 or si_privilege_tier_eligible == 0 or si_tier == 0')) -Because $n
        }
    }
}

Describe '(20) a duplicate role is the same role held active and eligible, whatever its tier' {
    It '<_> keeps the role overlap as its only condition' -ForEach @('Identity_PIM_DuplicateRoleAssignment_Summary', 'Identity_PIM_DuplicateRoleAssignment_Detailed') {
        $c = CodeOf $_
        $c | Should -Not -Match '\|\s*where HasPermanentPrivilegedRole' -Because 'a time-bound active Attribute Definition Administrator + the same role eligible is a duplicate too'
        $c | Should -Not -Match '\|\s*where IsPrivilegedEligible'
        $c | Should -Match ([regex]::Escape('| where array_length(set_intersect(_rolesPermanent, _rolesEligible)) > 0'))
    }
    It 'the active list is every active assignment that is not a PIM activation -- permanent and time-bound alike (the collector)' {
        $f = Get-Content -Raw (Join-Path $script:SIRoot 'engine\asset-profiling\shared\IdentityRoleFetcher.ps1')
        # #899: the list is read through the check that reads it until two reads agree -- still the whole, unfiltered list
        $f | Should -Match "Read-SIEntraRoleSetChecked -RelativeUrl '/roleManagement/directory/roleAssignments'" -Because 'roleAssignments lists every active assignment, time-bound ones included'
        $f | Should -Not -Match 'roleAssignments\?\$filter=[^'']*endDateTime'
    }
}

Describe '(21) the public IP to VM attack paths start from the graph''s routing nodes' {
    It '<_> takes the "IP address" label as well as the Azure public IP resource, ignoring case, and follows a network interface to its machine' -ForEach @(
        'Attack_Paths_Summary_Public_IP_to_VM_with_CVE_Exploitation', 'Attack_Paths_Detailed_Public_IP_to_VM_with_CVE_Exploitation') {
        $c = CodeOf $_
        $c | Should -Match ([regex]::Escape('SourceNodeLabel in~ ("microsoft.network/publicipaddresses", "IP address")'))
        $c | Should -Not -Match 'SourceNodeLabel == "microsoft\.network/publicipaddresses"'
        $c | Should -Match ([regex]::Escape('| where SourceNodeLabel =~ "microsoft.network/networkinterfaces"')) -Because 'IP address -> network interface -> virtual machine'
        $c | Should -Match ([regex]::Escape('| join kind=inner (_CveCarrierNodes) on $left._machineName == $right._carrierName')) -Because 'the machine node the address routes to and the node that carries its CVEs are tied'
        $c | Should -Match ([regex]::Escape('| where isnotempty(_carrierName)')) -Because 'an empty name must never tie two machines'
        # the slice key is still the final target, set in PublicIPConnections (#677)
        $q = @((Report $_).ReportQuery) -join "`n"
        $f = $q.IndexOf('//__BUCKET_FILTER_BEGIN__')
        $f | Should -BeGreaterThan 0
        ([regex]::Matches($q.Substring(0, $f), '\blet\s+(\w+)\s*=') | Select-Object -Last 1).Groups[1].Value | Should -Be 'PublicIPConnections'
    }
    It 'the generated CI block of the pair is the peer block (__SI_CI_PEER__) -- the path ends'' CI, as the #677 slicing requires' {
        foreach ($n in 'Attack_Paths_Summary_Public_IP_to_VM_with_CVE_Exploitation', 'Attack_Paths_Detailed_Public_IP_to_VM_with_CVE_Exploitation') {
            $q = @((Report $n).ReportQuery) -join "`n"
            $q | Should -Match '//__SI_CI_PEER_BEGIN__' -Because $n
            $q | Should -Not -Match '\b_ciLink\b' -Because "$n is sliced on the target -- a _ciLink block is cut per slice (#677)"
        }
    }
}

Describe 'the output names of every changed report are untouched (#692)' {
    It 'no changed report adds or loses a projected column (the output contract suite pins OutputPropertyOrder)' {
        $contract = (Get-Content -Raw (Join-Path $PSScriptRoot 'fixtures\report-output-contract.json') | ConvertFrom-Json).reports
        foreach ($n in @($script:LogonTo + $script:RoleTier + @('Identity_PIM_DuplicateRoleAssignment_Summary', 'Identity_PIM_DuplicateRoleAssignment_Detailed',
                'Attack_Paths_Summary_Public_IP_to_VM_with_CVE_Exploitation', 'Attack_Paths_Detailed_Public_IP_to_VM_with_CVE_Exploitation'))) {
            $pin = @($contract.$n)
            $pin.Count | Should -BeGreaterThan 5 -Because "$n is pinned"
            @($pin | Where-Object { $_ -notin @((Report $n).OutputPropertyOrder) }) -join ',' | Should -BeExactly '' -Because $n
        }
    }
}
