#Requires -Version 5.1
<#
    THE EXPOSURE GRAPH IDENTITY READ ASKS ONLY FOR WHAT SI KEEPS (engine\asset-profiling\shared\IdentityRoleFetcher.ps1
    Get-SIEgIdentityQueryText + SI-IdentityScopeChoice.ps1 Get-SIEgNeverSyncedSkipKql).

    With SI_Identity_SkipNeverSyncedDisabledAd on, the user nodes the decision after the read could only leave out (an
    on-premises AD account never synced to Entra ID, disabled and not privileged) are left out in the hunting query itself:
    never fetched, never counted toward the buckets. What these tests keep true:
      * OFF: every query is the text the read always sent -- no filter anywhere;
      * ON: the user count probe and every user page (single and hash bucket) carry the SAME filter; other labels none;
        the buckets follow the smaller count;
      * EQUIVALENCE over one fixed input set (synced, never-synced, every privilege signal, every disabled form, upper-case
        field names, the forms the query cannot decide): the records SI keeps are IDENTICAL with the filter in the query and
        with the decision after the read only (as before), and the left-out / kept counts are the same counts -- the log
        now says how many were not fetched;
      * THE WIDER SWITCH (SI_Identity_SkipNeverSyncedAd, 2026-11-08): the same equivalence over the same input set with the
        skip that has no enabled-state test -- every never-synced non-privileged AD account is left out (most in the query),
        a privileged / synced one and a node that is not an AD account never.
    KQL cannot run offline: the hunting service is played by a PowerShell reading of the generated KQL (the test-side
    Test-KqlSkip below, written step by step from the KQL's own operators), and the KQL text is checked to carry every step.
    Offline (fakes). PS 5.1 and pwsh 7.
#>

BeforeAll {
    $script:SIRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    . (Join-Path $script:SIRoot 'engine\asset-profiling\_shared\Write-SIStyle.ps1')
    . (Join-Path $script:SIRoot 'engine\asset-correlation\_shared\SI-CorrelationCore.ps1')
    . (Join-Path $script:SIRoot 'engine\data-model\identity\SI-ObjectIdentity.ps1')
    . (Join-Path $script:SIRoot 'engine\data-model\identity\SI-ObjectLedgerProvider.ps1')
    . (Join-Path $script:SIRoot 'engine\data-model\SI-RecordCapture.ps1')
    . (Join-Path $script:SIRoot 'engine\data-model\SI-CiBuildRun.ps1')
    . (Join-Path $script:SIRoot 'engine\asset-profiling\shared\SI-FullAssetProperties.ps1')
    . (Join-Path $script:SIRoot 'engine\asset-profiling\shared\SI-IdentityScopeChoice.ps1')
    . (Join-Path $script:SIRoot 'engine\asset-profiling\shared\IdentityRoleFetcher.ps1')
    $script:Model = Get-SIDataModel -Root (Join-Path $script:SIRoot 'data-model')
    $script:Tier = Get-SIIdentityCriticalAdGroupNames -SIRoot $script:SIRoot
    $script:Switches = @('SI_Identity_SkipNeverSyncedAd', 'SI_Identity_SkipNeverSyncedDisabledAd', 'SI_Identity_SkipDeletedGroups')
    # a switch not named here is set OFF (a stored false): unset means the shipped default
    function script:Set-Switches([object]$Ad = $false, [object]$Wide = $false) {
        Set-Variable -Name 'SI_Identity_SkipNeverSyncedAd' -Scope Global -Value $Wide
        Set-Variable -Name 'SI_Identity_SkipNeverSyncedDisabledAd' -Scope Global -Value $Ad
        Set-Variable -Name 'SI_Identity_SkipDeletedGroups' -Scope Global -Value $false
    }

    function script:EgRow([string]$id, [string]$name, [string[]]$entityJson, $raw) {
        $props = $null
        if ($null -ne $raw) { $props = ConvertTo-Json -InputObject @{ rawData = $raw } -Compress -Depth 8 }
        [pscustomobject]@{ NodeId = $id; NodeLabel = 'user'; NodeName = $name; Categories = '["identity"]'
            EntityIds = (ConvertTo-Json -InputObject @($entityJson) -Compress); NodeProperties = $props }
    }
    function script:SidJ([string]$sid) { '{{"type":"SecurityIdentifier","id":"{0}"}}' -f $sid }
    function script:OidJ([string]$oid) { '{{"type":"AadObjectId","id":"{0}"}}' -f $oid }
    $u1 = 'bbbb0001-0000-4000-8000-000000000001'
    $u2 = 'bbbb0002-0000-4000-8000-000000000002'
    $script:Users = @(
        # synced (an Entra object id), disabled -- kept
        (EgRow 'u-syn' 'Synced Disabled' @((OidJ $u1), (SidJ 'S-1-5-21-1-2-3-1001')) @{ accountName = 'syn'; accountDomain = 'corp'; accountEnabled = $false })
        # synced only through rawData.aadId, disabled -- kept (the query counts any oid field as synced)
        (EgRow 'u-rawoid' 'Raw oid' @((SidJ 'S-1-5-21-1-2-3-1002')) @{ aadId = $u2; accountName = 'rawoid'; accountDomain = 'corp'; accountEnabled = $false })
        # never synced, disabled, not privileged -- left out (in the query)
        (EgRow 'u-dis' 'old1' @((SidJ 'S-1-5-21-1-2-3-2001')) @{ accountName = 'old1'; accountDomain = 'corp'; accountEnabled = $false })
        (EgRow 'u-uac' 'old2' @((SidJ 'S-1-5-21-1-2-3-2002')) @{ accountName = 'old2'; accountDomain = 'corp'; userAccountControl = @('NormalAccount', 'AccountDisabled') })
        (EgRow 'u-uacnum' 'old3' @((SidJ 'S-1-5-21-1-2-3-2010')) @{ accountName = 'old3'; accountDomain = 'corp'; userAccountControl = 514 })
        (EgRow 'u-uacstr' 'old4' @((SidJ 'S-1-5-21-1-2-3-2011')) @{ accountName = 'old4'; accountDomain = 'corp'; userAccountControl = 'NormalAccount, AccountDisabled' })
        (EgRow 'u-upper' 'old5' @((SidJ 'S-1-5-21-1-2-3-2012')) @{ AccountName = 'old5'; AccountDomain = 'corp'; AccountEnabled = $false })
        (EgRow 'u-sidraw' 'old6' @() @{ accountSid = 'S-1-5-21-1-2-3-2013'; accountEnabled = 0 })
        (EgRow 'u-critempty' 'old7' @((SidJ 'S-1-5-21-1-2-3-2014')) @{ accountName = 'old7'; accountDomain = 'corp'; accountEnabled = 'false'; nestedCriticalAdGroups = @{ type = 'NestedCriticalAdGroups'; data = @() }; nestedAdGroupNames = @('Domain Users') })
        # never synced, disabled, but the query cannot decide it -- fetched, left out AFTER the read
        (EgRow 'u-flagodd' 'old8' @((SidJ 'S-1-5-21-1-2-3-2015')) @{ accountName = 'old8'; accountDomain = 'corp'; accountEnabled = $false; hasServicePrincipalName = 'maybe' })
        (EgRow 'u-uacjson' 'old9' @((SidJ 'S-1-5-21-1-2-3-2016')) @{ accountName = 'old9'; accountDomain = 'corp'; userAccountControl = '["NormalAccount","AccountDisabled"]' })
        # never synced, disabled, privileged by each signal -- kept
        (EgRow 'u-da' 'adm-old' @((SidJ 'S-1-5-21-1-2-3-2003')) @{ accountName = 'adm-old'; accountDomain = 'corp'; accountEnabled = $false; nestedAdGroupNames = @('Domain Users', 'Domain Admins') })
        (EgRow 'u-dastr' 'adm-old2' @((SidJ 'S-1-5-21-1-2-3-2020')) @{ accountName = 'adm-old2'; accountDomain = 'corp'; accountEnabled = $false; nestedAdGroupNames = ' domain admins; Domain Users' })
        (EgRow 'u-crit' 'crit-old' @((SidJ 'S-1-5-21-1-2-3-2004')) @{ accountName = 'crit-old'; accountDomain = 'corp'; accountEnabled = $false
            nestedCriticalAdGroups = @{ type = 'NestedCriticalAdGroups'; data = @('{"groupUniqueId":"S-1-5-21-1-2-3-519","groupName":"Enterprise Admins"}') } })
        (EgRow 'u-svc' 'svc-old' @((SidJ 'S-1-5-21-1-2-3-2005')) @{ accountName = 'svc-old'; accountDomain = 'corp'; accountEnabled = $false; hasServicePrincipalName = $true })
        (EgRow 'u-acstr' 'ac-old' @((SidJ 'S-1-5-21-1-2-3-2021')) @{ accountName = 'ac-old'; accountDomain = 'corp'; accountEnabled = $false; adminCount = '1' })
        (EgRow 'u-roles' 'roles-old' @((SidJ 'S-1-5-21-1-2-3-2022')) @{ accountName = 'roles-old'; accountDomain = 'corp'; accountEnabled = $false; assignedRoles = @{ role = 'x' } })
        (EgRow 'u-critlvl' 'lvl-old' @((SidJ 'S-1-5-21-1-2-3-2023')) @{ accountName = 'lvl-old'; accountDomain = 'corp'; accountEnabled = $false; criticalityLevel = @{ criticalityLevel = 0 } })
        (EgRow 'u-sens' 'sens-old' @((SidJ 'S-1-5-21-1-2-3-2024')) @{ accountName = 'sens-old'; accountDomain = 'corp'; accountEnabled = $false; isSensitive = 'True' })
        # never synced, enabled / says nothing -- kept
        (EgRow 'u-en' 'live' @((SidJ 'S-1-5-21-1-2-3-2006')) @{ accountName = 'live'; accountDomain = 'corp'; accountEnabled = $true })
        (EgRow 'u-enstr' 'live2' @((SidJ 'S-1-5-21-1-2-3-2025')) @{ accountName = 'live2'; accountDomain = 'corp'; accountEnabled = 'True'; userAccountControl = 512 })
        (EgRow 'u-unk' 'unknown' @((SidJ 'S-1-5-21-1-2-3-2007')) @{ accountName = 'unknown'; accountDomain = 'corp' })
        # never synced, disabled, neither Entra nor AD -- dropped either way (fetched: the query counts only AD accounts)
        (EgRow 'u-noad' 'noad' @() @{ displayName = 'noad'; accountEnabled = $false })
        # no properties -- dropped either way
        (EgRow 'u-ghost' 'ghost' @() $null)
    )
    $script:InQuery = @('u-dis', 'u-uac', 'u-uacnum', 'u-uacstr', 'u-upper', 'u-sidraw', 'u-critempty')
    $script:AfterRead = @('u-flagodd', 'u-uacjson')
    # the wider switch: the query leaves out every never-synced non-privileged AD account it can decide, enabled or not;
    # u-flagodd (a service-account flag the query cannot read as false) is left out after the read
    $script:InQueryWide = @('u-dis', 'u-uac', 'u-uacnum', 'u-uacstr', 'u-upper', 'u-sidraw', 'u-critempty', 'u-uacjson', 'u-en', 'u-enstr', 'u-unk')
    $script:AfterReadWide = @('u-flagodd')
    $script:KeptWide = @('u-syn', 'u-rawoid', 'u-da', 'u-dastr', 'u-crit', 'u-svc', 'u-acstr', 'u-roles', 'u-critlvl', 'u-sens')

    # ---- the hunting service, played offline: the generated KQL read step by step (KQL's own operators) ----
    function script:KStr($v) {
        if ($null -eq $v) { return '' }
        if ($v -is [string]) { return $v }
        if ($v -is [bool]) { if ($v) { return 'true' } else { return 'false' } }
        if ($v -is [int] -or $v -is [long] -or $v -is [double] -or $v -is [decimal]) { return ([System.IFormattable]$v).ToString($null, [Globalization.CultureInfo]::InvariantCulture) }
        ConvertTo-Json -InputObject $v -Compress -Depth 20
    }
    function script:KType($v) {
        if ($null -eq $v) { return 'null' }
        if ($v -is [string]) { return 'string' }
        if ($v -is [bool]) { return 'bool' }
        if ($v -is [int] -or $v -is [long]) { return 'long' }
        if ($v -is [double] -or $v -is [decimal]) { return 'real' }
        if ($v -is [System.Management.Automation.PSCustomObject]) { return 'dictionary' }
        if ($v -is [System.Collections.IEnumerable]) { return 'array' }
        'other'
    }
    function script:KGet($bag, [string]$k) { if ($null -eq $bag -or (KType $bag) -ne 'dictionary') { return $null }; $p = $bag.PSObject.Properties[$k]; if ($p -and $null -ne $p.Value) { , $p.Value } else { $null } }
    function script:KTrim([string]$s) { $s -replace '^[\t\n\f\r ]+|[\t\n\f\r ]+$', '' }
    function script:Test-KqlSkip($Row, [switch]$AnyState) {
        $ids = ([string]$Row.EntityIds).ToLowerInvariant()
        $rd = $null; if ($Row.NodeProperties) { $rd = KGet ($Row.NodeProperties | ConvertFrom-Json) 'rawData' }
        $rl = $null
        if ((KType $rd) -eq 'dictionary' -and -not $ids.Contains('aadobjectid')) { $rl = (ConvertTo-Json -InputObject $rd -Compress -Depth 20).ToLowerInvariant() | ConvertFrom-Json }
        if ($null -eq $rl) { return $false }
        $s = { param($k) KStr (KGet $rl $k) }
        $hasOid = $ids.Contains('aadobjectid') -or ((@('aadid', 'accountobjectid', 'objectid', 'aadobjectid', 'groupid', 'principalid', 'userid', 'id') | ForEach-Object { & $s $_ }) -join ' ') -cmatch '[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}'
        $sid = ''; if ($ids -cmatch 'securityidentifier[^}]*?(s-1-[0-9-]+)') { $sid = $Matches[1] }
        if (-not $sid) { foreach ($k in 'adsid', 'accountsid', 'onpremsid', 'onpremisessecurityidentifier', 'securityidentifier', 'sid') { if ((& $s $k) -cmatch '^s-1-[0-9]') { $sid = & $s $k; break } } }
        $isAd = $sid.StartsWith('s-1-5-21-') -or ((KType (KGet $rl 'accountname')) -eq 'string' -and (& $s 'accountname') -and (KType (KGet $rl 'accountdomain')) -eq 'string' -and (& $s 'accountdomain'))
        $uac = KGet $rl 'useraccountcontrol'; $uacT = KType $uac; $uacS = KTrim (KStr $uac)
        $dis = (@('accountenabled', 'isenabled', 'enabled') | Where-Object { (KTrim (& $s $_)) -in 'false', '0', 'off', 'no' }).Count -gt 0
        if ($uacT -eq 'long' -and ([long]$uac -band 2) -eq 2) { $dis = $true }
        if ($uacT -eq 'string' -and $uacS -cmatch '^[0-9]+$' -and ([long]$uacS -band 2) -eq 2) { $dis = $true }
        if ($uacT -eq 'array' -and @(@($uac) | Where-Object { $_ -is [string] -and $_ -cin 'accountdisabled', 'accountdisable', 'account_disabled', 'disabled' }).Count -gt 0) { $dis = $true }
        if ($uacT -eq 'string' -and -not $uacS.StartsWith('[') -and $uacS -cmatch '(^|[,;])[\t\n\f\r ]*(accountdisabled|accountdisable|account_disabled|disabled)[\t\n\f\r ]*($|[,;])') { $dis = $true }
        $crit = KGet $rl 'nestedcriticaladgroups'; $critS = KStr $crit
        $critData = KGet $crit 'data'
        $critEmpty = ($critS -in '', '[]', '{}') -or ((KType $crit) -eq 'dictionary' -and (KType $critData) -eq 'array' -and $critData.Count -eq 0)
        $names = @(@($script:Tier) | ForEach-Object { ([string]$_).Trim().ToLowerInvariant().Replace('.', '\.') })
        $grp = (& $s 'nestedadgroupnames') -cmatch ('(^|[^a-z0-9]|\\u[0-9a-f]{4})(' + ($names -join '|') + ')($|[^a-z0-9])')
        $flag = { param($k) (KTrim (& $s $k)) -notin '', 'false', '0', 'off', 'no' }
        $cl = KGet $rl 'criticalitylevel'
        $lvl = if ((KType $cl) -eq 'dictionary') { [bool](KStr (KGet $cl 'criticalitylevel')) } else { [bool](KStr $cl) }
        $priv = ((& $s 'admincount') -cmatch '[1-9]') -or -not $critEmpty -or $grp -or ((& $s 'assignedroles') -notin '', '[]') -or (& $flag 'hasserviceprincipalname') -or (& $flag 'isserviceaccount') -or (& $flag 'issensitive') -or $lvl
        [bool](-not $hasOid -and $isAd -and ($AnyState -or $dis) -and -not $priv)
    }
    # -Mode Old: the service ignores the filter (= the read before it existed); New: it applies it
    function script:Get-Answer([string]$Query, [string]$Mode) {
        $label = ''; if ($Query -match "NodeLabel == '([a-z]+)'") { $label = $Matches[1] }
        $rows = @(); if ($label -eq 'user') { $rows = @($script:Users) }
        if ($Query -match 'hash\(NodeId, (\d+)\) \| where _bucket == (\d+)') {
            $n = [int]$Matches[1]; $b = [int]$Matches[2]
            $rows = @(for ($i = 0; $i -lt $rows.Count; $i++) { if (($i % $n) -eq $b) { $rows[$i] } })
        }
        $filtered = $Mode -eq 'New' -and $Query.Contains('_siSkip')
        # the query says which skip it is: without a _siDisabled step it is the wider switch's (no enabled-state test)
        $any = $filtered -and -not $Query.Contains('_siDisabled')
        $skipped = @(); if ($filtered) { $skipped = @($rows | Where-Object { Test-KqlSkip $_ -AnyState:$any }); $rows = @($rows | Where-Object { -not (Test-KqlSkip $_ -AnyState:$any) }) }
        if ($Query -match '\| count$') { return , @([pscustomobject]@{ Count = $rows.Count }) }
        if ($Query -match '\| summarize Count = countif\(not\(_siSkip\)\), NotFetched = countif\(_siSkip\)$') { return , @([pscustomobject]@{ Count = $rows.Count; NotFetched = $skipped.Count }) }
        , @($rows)
    }
    function script:Invoke-EgRun([string]$Mode, [int]$PageRows = 0) {
        $null = Reset-SIFullAssetProperties -Engine 'identity'
        $null = Reset-SIRecordCapture -Engine 'identity' -Clear
        $script:_SICache = @{}
        $script:Info = New-Object System.Collections.Generic.List[string]
        $script:Queries = New-Object System.Collections.Generic.List[string]
        $script:Written = New-Object System.Collections.Generic.List[object]
        $script:Mode = $Mode
        $script:SIEgIdentitySleep = { param($s) }
        $script:SIEgIdentitySendMany = { param([string[]]$qs) , @(foreach ($q in $qs) { $script:Queries.Add($q); [pscustomobject]@{ Ok = $true; Rows = (Get-Answer $q $script:Mode); Status = 200 } }) }
        $global:SI_EgIdentityPageRows = $null; if ($PageRows -gt 0) { $global:SI_EgIdentityPageRows = $PageRows }
        try { $map = Get-SIExposureGraphIdentities } finally { $global:SI_EgIdentityPageRows = $null; $script:SIEgIdentitySendMany = $null; $script:SIEgIdentitySleep = $null }
        $cap = @(Get-SICapturedRecords)
        $out = ConvertTo-SIRecordRows -Captured $cap -Model $script:Model -Pulls $global:SIRecordCaptureState.Pulls
        $by = [ordered]@{}; foreach ($r in @($out.Rows | Sort-Object { [string]$_.eg_node_id })) { $by[[string]$r.eg_node_id] = $r }
        [string[]]$infoA = $script:Info.ToArray(); [string[]]$qA = $script:Queries.ToArray(); [object[]]$wA = $script:Written.ToArray(); [object[]]$errA = @($out.Errors)
        $mapCount = 0; $hasU2 = $false
        if ($null -ne $map) { $mapCount = @($map.Keys).Count; $hasU2 = [bool]$map.ContainsKey('bbbb0002-0000-4000-8000-000000000002') }
        [pscustomobject]@{ MapCount = $mapCount; HasU2 = $hasU2; ByNode = $by; Info = $infoA; Errors = $errA; Queries = $qA; Written = $wA }
    }
    function script:RowDiff($A, $B) {
        $pa = @{}; foreach ($x in $A.PSObject.Properties) { if ($x.Name -notmatch '^si_(collection_|run_|source_last_seen$)') { $pa[$x.Name] = ConvertTo-Json -InputObject $x.Value -Compress -Depth 8 } }
        $pb = @{}; foreach ($x in $B.PSObject.Properties) { if ($x.Name -notmatch '^si_(collection_|run_|source_last_seen$)') { $pb[$x.Name] = ConvertTo-Json -InputObject $x.Value -Compress -Depth 8 } }
        foreach ($n in @(@($pa.Keys) + @($pb.Keys) | Sort-Object -Unique)) { if ([string]$pa[$n] -cne [string]$pb[$n]) { '{0}: {1} <> {2}' -f $n, $pa[$n], $pb[$n] } }
    }
}

AfterAll { foreach ($n in $script:Switches) { Remove-Variable -Name $n -Scope Global -ErrorAction SilentlyContinue }; $global:SI_EgIdentityPageRows = $null }

Describe 'the query text: the filter only when the setting is on, the same filter in the count and in every page' {
    It 'OFF: the count, the single page and a bucket are the text the read always sent' {
        Get-SIEgIdentityQueryText -Label user -Kind count | Should -BeExactly "ExposureGraphNodes | where NodeLabel == 'user' | count"
        Get-SIEgIdentityQueryText -Label user -Kind page | Should -BeExactly "ExposureGraphNodes | where NodeLabel == 'user' | project NodeId, NodeLabel, NodeName, Categories, EntityIds, NodeProperties"
        Get-SIEgIdentityQueryText -Label group -Kind page -Buckets 8 -Bucket 3 | Should -BeExactly "ExposureGraphNodes | where NodeLabel == 'group' | extend _bucket = hash(NodeId, 8) | where _bucket == 3 | project NodeId, NodeLabel, NodeName, Categories, EntityIds, NodeProperties"
    }
    It 'the filter reads every signal of the decision (field names lower-cased once), and the tier 0/1 groups of the catalog' {
        $f = Get-SIEgNeverSyncedSkipKql -CriticalGroups $script:Tier
        foreach ($s in 'tolower(tostring(_siRd))', '_siIds contains "aadobjectid"', 'tostring(_siRl.aadid)', 'tostring(_siRl.id)',
                       'accountenabled', 'isenabled', '(_siRl.enabled)', 'useraccountcontrol', 'binary_and(', '"accountdisabled"',
                       'admincount', 'nestedcriticaladgroups', 'nestedadgroupnames', 'domain admins', 'enterprise admins', 'assignedroles',
                       'hasserviceprincipalname', 'isserviceaccount', 'issensitive', 'criticalitylevel',
                       '_siSkip = isnotnull(_siRl) and not(_siHasOid) and _siIsAd and _siDisabled and not(_siPriv)') {
            $f.Contains($s) | Should -BeTrue -Because "the filter reads $s"
        }
        (Get-SIEgNeverSyncedSkipKql -CriticalGroups @('Domain Admins', "O'Brien \ Admins")) | Should -Match ([regex]::Escape('not(tostring(_siRl.nestedadgroupnames) in ("", "[]"))')) -Because 'a name that cannot be matched safely makes any group list count as privileged'
    }
    Context 'one identity read, switch OFF and ON (bucketed: 3 rows a page)' {
        BeforeAll {
            Mock Invoke-SIEgIdentityQuery { param($Query) $script:Queries.Add($Query); @{ Ok = $true; Rows = (Get-Answer $Query $script:Mode); Error = '' } }
            Mock Write-SIInfo { param($Message) $script:Info.Add([string]$Message) }
            Mock Write-SIIdentityScopeCounts { param($Counts) foreach ($c in @($Counts)) { $script:Written.Add($c) }; @($Counts).Count }
            $script:SetupError = ''
            try {
                Set-Switches
                $script:Off = Invoke-EgRun -Mode New -PageRows 3
                Set-Switches -Ad $true
                $script:On = Invoke-EgRun -Mode New -PageRows 3
            } catch { $script:SetupError = (('{0} | {1} | {2} | {3}' -f $_.Exception.GetType().FullName, $_.Exception.Message, $_.InvocationInfo.PositionMessage, $_.ScriptStackTrace) -replace '\r?\n', ' // ') } finally { Set-Switches }
        }
        It 'the read ran' { $script:SetupError | Should -BeNullOrEmpty }
        It 'OFF: no query carries the filter, the count probe is the plain count' {
            @($script:Off.Queries | Where-Object { $_.Contains('_siSkip') }).Count | Should -Be 0
            @($script:Off.Queries) | Should -Contain "ExposureGraphNodes | where NodeLabel == 'user' | count"
        }
        It 'ON: the user count and every user page carry the SAME filter; the other labels none' {
            $count = @($script:On.Queries | Where-Object { $_ -match "^ExposureGraphNodes \| where NodeLabel == 'user' \| extend _siIds" })
            $count.Count | Should -Be 1
            $count[0] | Should -Match 'summarize Count = countif\(not\(_siSkip\)\), NotFetched = countif\(_siSkip\)$'
            $filter = Get-SIEgNeverSyncedSkipKql -CriticalGroups $script:Tier
            $count[0].Contains($filter) | Should -BeTrue
            $pages = @($script:On.Queries | Where-Object { $_ -match "NodeLabel == 'user'" -and $_ -match 'project NodeId' })
            $pages.Count | Should -BeGreaterThan 1
            foreach ($p in $pages) { $p.Contains($filter + ' | where not(_siSkip) | project NodeId') | Should -BeTrue -Because $p }
            @($script:On.Queries | Where-Object { $_ -notmatch "NodeLabel == 'user'" -and $_.Contains('_siSkip') }).Count | Should -Be 0
        }
        It 'ON: the buckets follow the smaller count (the nodes the query leaves out are not counted toward them)' {
            $all = $script:Users.Count; $nf = $script:InQuery.Count
            $nOff = [int]([regex]::Match(($script:Off.Queries -join "`n"), "'user' \| extend _bucket = hash\(NodeId, (\d+)\)").Groups[1].Value)
            $nOn = [int]([regex]::Match(($script:On.Queries -join "`n"), "'user' \| extend _bucket = hash\(NodeId, (\d+)\)").Groups[1].Value)
            $nOff | Should -Be ([int][Math]::Ceiling($all / 3.0))
            $nOn | Should -Be ([int][Math]::Ceiling(($all - $nf) / 3.0))
            ($script:On.Info -join "`n") | Should -Match ([regex]::Escape(('count={0,5}' -f ($all - $nf))))
            ($script:On.Info -join "`n") | Should -Match ([regex]::Escape(('({0:N0} not fetched: never synced to Entra ID, disabled and not privileged -- SI_Identity_SkipNeverSyncedDisabledAd is on)' -f $nf)))
        }
    }
}

Describe 'EQUIVALENCE: the records SI keeps are the same with the filter in the query and after the read only' {
    BeforeAll {
        Mock Invoke-SIEgIdentityQuery { param($Query) $script:Queries.Add($Query); @{ Ok = $true; Rows = (Get-Answer $Query $script:Mode); Error = '' } }
        Mock Write-SIInfo { param($Message) $script:Info.Add([string]$Message) }
        Mock Write-SIIdentityScopeCounts { param($Counts) foreach ($c in @($Counts)) { $script:Written.Add($c) }; @($Counts).Count }
        $script:SetupError2 = ''
        try {
            Set-Switches -Ad $true
            $script:Old = Invoke-EgRun -Mode Old
            $script:New = Invoke-EgRun -Mode New
            $script:OldB = Invoke-EgRun -Mode Old -PageRows 4
            $script:NewB = Invoke-EgRun -Mode New -PageRows 4
        } catch { $script:SetupError2 = (('{0} | {1} | {2} | {3}' -f $_.Exception.GetType().FullName, $_.Exception.Message, $_.InvocationInfo.PositionMessage, $_.ScriptStackTrace) -replace '\r?\n', ' // ') } finally { Set-Switches }
    }
    It 'the reads ran' { $script:SetupError2 | Should -BeNullOrEmpty }
    It 'the played service leaves out exactly the nodes the query can decide, and none it cannot' {
        @($script:Users | Where-Object { Test-KqlSkip $_ } | ForEach-Object { $_.NodeId } | Sort-Object) | Should -Be @($script:InQuery | Sort-Object)
    }
    It 'every node left out in the query is one the decision after the read leaves out (none SI keeps)' {
        foreach ($k in $script:InQuery + $script:AfterRead) { $script:Old.ByNode.Contains($k) | Should -BeFalse -Because "$k is left out by the decision" }
    }
    It 'the same records, field for field -- one query and bucketed' {
        ($script:Old.Errors + $script:New.Errors) | Should -BeNullOrEmpty
        @($script:New.ByNode.Keys) | Should -Be @($script:Old.ByNode.Keys)
        @($script:NewB.ByNode.Keys) | Should -Be @($script:Old.ByNode.Keys)
        @($script:OldB.ByNode.Keys) | Should -Be @($script:Old.ByNode.Keys)
        foreach ($k in @($script:Old.ByNode.Keys)) {
            @(RowDiff $script:New.ByNode[$k] $script:Old.ByNode[$k]) | Should -BeNullOrEmpty -Because "$k is the same record"
            @(RowDiff $script:NewB.ByNode[$k] $script:Old.ByNode[$k]) | Should -BeNullOrEmpty -Because "$k is the same record (bucketed)"
        }
        foreach ($k in 'u-syn', 'u-rawoid', 'u-da', 'u-dastr', 'u-crit', 'u-svc', 'u-acstr', 'u-roles', 'u-critlvl', 'u-sens', 'u-en', 'u-enstr', 'u-unk') { $script:New.ByNode.Contains($k) | Should -BeTrue -Because "$k is kept" }
    }
    It 'the same index of Entra objects' {
        $script:New.MapCount | Should -Be $script:Old.MapCount
        $script:New.HasU2 | Should -BeTrue -Because 'an account synced only through rawData stays in the index'
    }
    It 'the same counts: left out and kept, and the log says how many were not fetched' {
        $o = $script:Old.Written[0]; $n = $script:New.Written[0]
        ($n.Setting, [long]$n.LeftOut, [long]$n.Kept) | Should -Be @('SI_Identity_SkipNeverSyncedDisabledAd', [long]$o.LeftOut, [long]$o.Kept)
        [long]$o.LeftOut | Should -Be ($script:InQuery.Count + $script:AfterRead.Count)
        [long]$script:NewB.Written[0].LeftOut | Should -Be ([long]$o.LeftOut)
        $line = @($script:New.Info | Where-Object { $_ -match 'Exposure Graph identities: ' })[0]
        $line | Should -Match ([regex]::Escape(('Exposure Graph identities: {0} on-premises AD account(s) never synced to Entra ID, disabled and not privileged, got no asset (SI_Identity_SkipNeverSyncedDisabledAd is on): {1} not fetched (left out in the Exposure Graph query itself), {2} left out after the read; {3} never-synced account(s) kept' -f [long]$o.LeftOut, $script:InQuery.Count, $script:AfterRead.Count, [long]$o.Kept)))
        $lineOld = @($script:Old.Info | Where-Object { $_ -match 'Exposure Graph identities: ' })[0]
        $lineOld | Should -Match ([regex]::Escape(('Exposure Graph identities: {0} on-premises AD account(s) never synced to Entra ID, disabled and not privileged, got no asset (SI_Identity_SkipNeverSyncedDisabledAd is on); {1} never-synced' -f [long]$o.LeftOut, [long]$o.Kept))) -Because 'nothing not fetched: the line of before'
    }
    It 'a count probe that fails: the label is read without the filter, every node decided after the read, the same records' {
        Mock Invoke-SIEgIdentityQuery { param($Query) $script:Queries.Add($Query); if ($Query.Contains('summarize Count')) { return @{ Ok = $false; Rows = @(); Error = 'HTTP 500' } }; @{ Ok = $true; Rows = (Get-Answer $Query $script:Mode); Error = '' } }
        Mock Write-Warning { }
        Set-Switches -Ad $true
        try { $r = Invoke-EgRun -Mode New } finally { Set-Switches }
        @($r.Queries | Where-Object { $_.Contains('_siSkip') -and -not $_.Contains('summarize') }).Count | Should -Be 0
        @($r.ByNode.Keys) | Should -Be @($script:Old.ByNode.Keys)
        [long]$r.Written[0].LeftOut | Should -Be ([long]$script:Old.Written[0].LeftOut)
    }
}

Describe 'EQUIVALENCE with the wider switch SI_Identity_SkipNeverSyncedAd (no enabled-state test)' {
    BeforeAll {
        Mock Invoke-SIEgIdentityQuery { param($Query) $script:Queries.Add($Query); @{ Ok = $true; Rows = (Get-Answer $Query $script:Mode); Error = '' } }
        Mock Write-SIInfo { param($Message) $script:Info.Add([string]$Message) }
        Mock Write-SIIdentityScopeCounts { param($Counts) foreach ($c in @($Counts)) { $script:Written.Add($c) }; @($Counts).Count }
        $script:SetupError3 = ''
        try {
            # 1C on too: the wider switch decides, 1C decides nothing
            Set-Switches -Ad $true -Wide $true
            $script:OldW = Invoke-EgRun -Mode Old
            $script:NewW = Invoke-EgRun -Mode New
            $script:NewWB = Invoke-EgRun -Mode New -PageRows 3
        } catch { $script:SetupError3 = (('{0} | {1} | {2} | {3}' -f $_.Exception.GetType().FullName, $_.Exception.Message, $_.InvocationInfo.PositionMessage, $_.ScriptStackTrace) -replace '\r?\n', ' // ') } finally { Set-Switches }
    }
    It 'the reads ran' { $script:SetupError3 | Should -BeNullOrEmpty }
    It 'the user queries carry the skip without the enabled-state test' {
        $filter = Get-SIEgNeverSyncedSkipKql -CriticalGroups $script:Tier -AnyEnabledState
        $userQ = @($script:NewW.Queries | Where-Object { $_ -match "NodeLabel == 'user'" })
        $userQ.Count | Should -BeGreaterThan 1
        foreach ($q in $userQ) { $q.Contains($filter) | Should -BeTrue; $q.Contains('_siDisabled') | Should -BeFalse }
    }
    It 'the played service leaves out exactly the never-synced non-privileged AD accounts it can decide, enabled or not' {
        @($script:Users | Where-Object { Test-KqlSkip $_ -AnyState } | ForEach-Object { $_.NodeId } | Sort-Object) | Should -Be @($script:InQueryWide | Sort-Object)
    }
    It 'every node left out in the query is one the decision after the read leaves out; the privileged and synced ones are kept' {
        foreach ($k in $script:InQueryWide + $script:AfterReadWide) { $script:OldW.ByNode.Contains($k) | Should -BeFalse -Because "$k is left out by the decision" }
        foreach ($k in $script:KeptWide) { $script:NewW.ByNode.Contains($k) | Should -BeTrue -Because "$k is kept" }
        $script:NewW.ByNode.Contains('u-noad') | Should -BeFalse -Because 'neither Entra nor AD: dropped as before, never by the switch'
    }
    It 'the same records, field for field -- one query and bucketed' {
        ($script:OldW.Errors + $script:NewW.Errors) | Should -BeNullOrEmpty
        @($script:NewW.ByNode.Keys) | Should -Be @($script:OldW.ByNode.Keys)
        @($script:NewWB.ByNode.Keys) | Should -Be @($script:OldW.ByNode.Keys)
        foreach ($k in @($script:OldW.ByNode.Keys)) { @(RowDiff $script:NewW.ByNode[$k] $script:OldW.ByNode[$k]) | Should -BeNullOrEmpty -Because "$k is the same record" }
    }
    It 'the same counts on the wider switch''s counter only, and the log names it' {
        @($script:NewW.Written | ForEach-Object { $_.Setting }) | Should -Be @('SI_Identity_SkipNeverSyncedAd')
        $o = $script:OldW.Written[0]; $n = $script:NewW.Written[0]
        [long]$o.LeftOut | Should -Be ($script:InQueryWide.Count + $script:AfterReadWide.Count)
        ([long]$n.LeftOut, [long]$n.Kept) | Should -Be @([long]$o.LeftOut, [long]$o.Kept)
        [long]$script:NewWB.Written[0].LeftOut | Should -Be ([long]$o.LeftOut)
        $all = $script:NewW.Info -join "`n"
        $all | Should -Match ([regex]::Escape(('({0:N0} not fetched: never synced to Entra ID and not privileged -- SI_Identity_SkipNeverSyncedAd is on)' -f $script:InQueryWide.Count)))
        $all | Should -Match ([regex]::Escape(('{0} not fetched (left out in the Exposure Graph query itself), {1} left out after the read' -f $script:InQueryWide.Count, $script:AfterReadWide.Count)))
    }
}

Describe 'WIRING: the read builds every user query from the one builder, with the filter only when the setting is on' {
    It 'the count, the single page and the buckets go through Get-SIEgIdentityQueryText with the label''s filter' {
        $t = [IO.File]::ReadAllText((Join-Path $script:SIRoot 'engine\asset-profiling\shared\IdentityRoleFetcher.ps1'))
        $t | Should -Match ([regex]::Escape('$countQ = Get-SIEgIdentityQueryText -Label $label -Kind count -Filter $labelFilter'))
        $t | Should -Match ([regex]::Escape('$kql    = Get-SIEgIdentityQueryText -Label $label -Kind page -Filter $labelFilter'))
        $t | Should -Match ([regex]::Escape('Get-SIEgIdentityQueryText -Label $label -Kind page -Filter $labelFilter -Buckets $n -Bucket $bk'))
        $t | Should -Match ([regex]::Escape('if ($scopeOn -and $scopeNeverSynced -eq ''SI_Identity_SkipNeverSyncedAd'') { $userSkipKql = Get-SIEgNeverSyncedSkipKql -CriticalGroups $scopeCritical -AnyEnabledState }'))
        $t | Should -Match ([regex]::Escape('elseif ($scopeOn -and $scopeNeverSynced -eq ''SI_Identity_SkipNeverSyncedDisabledAd'') { $userSkipKql = Get-SIEgNeverSyncedSkipKql -CriticalGroups $scopeCritical }'))
        $t | Should -Match ([regex]::Escape('$nfC = $null; if ($scopeNeverSynced) { $nfC = $scopeCounter[$scopeNeverSynced] }'))
        $t | Should -Not -MatchExactly "ExposureGraphNodes \| where NodeLabel == '\`$label'"
    }
}

Describe 'THE QUERY TEXT IS VALID KQL: every count probe and page, every label, with and without the filter' {
    # Field 2026-11-12: the user count probe answered HTTP 400 "The incomplete fragment is unexpected" every run -- the
    # filter's privilege step closed one parenthesis too many -- and the read fell back to the unfiltered bucketed fetch.
    # The offline reading above never parses the KQL, so the text itself is checked here: string literals stripped (the
    # Risk Analysis lint's Get-RAKqlStripped), then balanced brackets and no dangling operator.
    BeforeAll {
        . (Join-Path $PSScriptRoot '_RaKqlDynamicLint.ps1')
        function script:Get-KqlShapeProblems([string]$Kql) {
            $out = New-Object System.Collections.Generic.List[string]
            $s = Get-RAKqlStripped $Kql
            # (the stripper leaves every literal as "s" / 's'; a quote left over after those is one that never closed)
            $q = $s.Replace('"s"', '').Replace("'s'", '')
            if ($q.Contains('"')) { $out.Add('an unclosed double quote') }
            if ($q.Contains("'")) { $out.Add('an unclosed single quote') }
            $stack = New-Object System.Collections.Generic.Stack[char]
            $pair = @{ [char]')' = [char]'('; [char]']' = [char]'['; [char]'}' = [char]'{' }
            for ($i = 0; $i -lt $s.Length; $i++) {
                $c = $s[$i]
                if ($c -eq '(' -or $c -eq '[' -or $c -eq '{') { $stack.Push($c) }
                elseif ($pair.ContainsKey($c)) {
                    if ($stack.Count -eq 0 -or $stack.Pop() -ne $pair[$c]) { $out.Add(('an unmatched "{0}" at {1}: ...{2}' -f $c, $i, $s.Substring([Math]::Max(0, $i - 60), [Math]::Min(60, $i)))); break }
                }
            }
            if ($stack.Count -gt 0) { $out.Add(('{0} bracket(s) never closed' -f $stack.Count)) }
            foreach ($bad in '\|\s*\|', '\|\s*$', '^\s*\|', '\(\s*\)','\(\s*,', ',\s*\)', ',\s*,', '\b(and|or|not)\s*[),|]', '\b(and|or)\s*$', '(==|!=|=)\s*[),|]', '\b(and|or)\s+(and|or)\b') {
                if ($s -match $bad) { $out.Add(('a dangling operator ({0}): {1}' -f $bad, $Matches[0])) }
            }
            $out.ToArray()
        }
        $script:Filters = [ordered]@{
            'no filter'                              = ''
            'SI_Identity_SkipNeverSyncedDisabledAd' = (Get-SIEgNeverSyncedSkipKql -CriticalGroups $script:Tier)
            'SI_Identity_SkipNeverSyncedAd'         = (Get-SIEgNeverSyncedSkipKql -CriticalGroups $script:Tier -AnyEnabledState)
            'a group name that is not safe'          = (Get-SIEgNeverSyncedSkipKql -CriticalGroups @('Domain Admins', "O'Brien \ Admins"))
            'no tier 0/1 group names'                = (Get-SIEgNeverSyncedSkipKql -CriticalGroups @())
        }
    }
    It 'the checker itself finds the field defect (one closing parenthesis too many) and a dangling operator' {
        @(Get-KqlShapeProblems 'T | extend a = iff(isnotempty(tostring(x)), 1, 2))').Count | Should -BeGreaterThan 0
        @(Get-KqlShapeProblems 'T | where a == 1 and | count').Count | Should -BeGreaterThan 0
        @(Get-KqlShapeProblems "T | where a == 'x").Count | Should -BeGreaterThan 0
        @(Get-KqlShapeProblems "T | where a == 'x(' | extend b = dynamic(null) | count").Count | Should -Be 0
    }
    It 'every label''s count probe and pages (single and bucket) are sound with every filter' {
        foreach ($label in 'user', 'serviceprincipal', 'managedidentity', 'group') {
            foreach ($k in $script:Filters.Keys) {
                $flt = $script:Filters[$k]
                foreach ($q in @((Get-SIEgIdentityQueryText -Label $label -Kind count -Filter $flt),
                                 (Get-SIEgIdentityQueryText -Label $label -Kind page -Filter $flt),
                                 (Get-SIEgIdentityQueryText -Label $label -Kind page -Filter $flt -Buckets 8 -Bucket 3))) {
                    @(Get-KqlShapeProblems $q) | Should -BeNullOrEmpty -Because ('{0} / {1}: {2}' -f $label, $k, $q)
                }
            }
        }
    }
    It 'the corrected privilege step is pinned: the criticality level test closes exactly the iff it opens' {
        $f = Get-SIEgNeverSyncedSkipKql -CriticalGroups $script:Tier
        $f | Should -Match ([regex]::Escape(' or iff(gettype(_siRl.criticalitylevel) == "dictionary", isnotempty(tostring(_siRl.criticalitylevel.criticalitylevel)), isnotempty(tostring(_siRl.criticalitylevel))) | extend _siSkip = '))
        $f | Should -Not -Match ([regex]::Escape('isnotempty(tostring(_siRl.criticalitylevel))))'))
    }
}