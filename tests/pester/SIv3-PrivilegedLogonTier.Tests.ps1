#Requires -Version 5.1
<#
    ANY PRIVILEGED LOGON COUNTS FOR A DEVICE'S TIER (#1209, owner 2026-11-12) -- engine/asset-profiling/shared/SI-PrivilegedLogon.ps1,
    the rule asset-profiling-enrichment/endpoint/AssetProfileByPrivilegedLogon.locked.yaml (kind privilegedLogonTier), the
    tier attribution (source PrivilegedLogonTier), the CI rule (si_privileged_logon_tier) and Risk Analysis's tier weight.

    Owner: "if tier 0/1/2 logon happens classify device with tier"; "if not it is tier 3 device if tier 3 user"; "build all
    scenarios so we finetune this" (two sources with modes on / shadow / off; a support filter built but OFF by default,
    dynamic per tenant: "it must be dynamic"); on scale "will not scale well if customer has 200000 devices" (read BY
    ACCOUNT, incremental from a stored rolling window, first hit, split by time on limits); "work autom in all tenants" (no
    setting needed).

    Offline. The Defender read is a FAKE advanced hunting that applies the query's OWN account lists, time range, count
    boundary, logon-type list and LogonSuccess filter to raw logon events and summarises like the query (days, types) -- so
    "31 days ago", "a network logon", "not asked for" and "read twice" are decided by the query text the engine sends. The
    state store is a fake with an ETag. Script-scope stubs only. The 200,000-device measurement is tagged Scale (on demand
    only, never in a gate).
#>

BeforeAll {
    $script:SIRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    . (Join-Path $script:SIRoot 'engine\asset-profiling\shared\SI-PrivilegedLogon.ps1')
    . (Join-Path $script:SIRoot 'engine\asset-profiling\shared\Get-SITierAttribution.ps1')
    . (Join-Path $script:SIRoot 'engine\_shared\SI-Yaml.ps1')
    . (Join-Path $script:SIRoot 'engine\asset-profiling\shared\RuleEval.ps1')
    . (Join-Path $script:SIRoot 'engine\asset-profiling\shared\Get-SIRuleSet.ps1')

    # no setting is set (a fresh or an updated install): every #1209 global is cleared for this suite and put back after
    $script:SettingNames = @('SI_Endpoint_MostFrequentUserTier_Mode', 'SI_Endpoint_PrivilegedLogon_Mode', 'SI_Endpoint_PrivilegedLogon_WindowDays',
        'SI_Endpoint_PrivilegedLogon_LogonTypes', 'SI_Endpoint_PrivilegedLogon_SupportFilter', 'SI_Endpoint_PrivilegedLogon_MinDays',
        'SI_Endpoint_PrivilegedLogon_PrimaryUserCounts', 'SI_Endpoint_PrivilegedLogon_ExcludeGroups', 'SI_Endpoint_PrivilegedLogon_Tier0Once')
    $script:SavedSettings = @{}
    foreach ($n in $script:SettingNames) { if (Test-Path "variable:global:$n") { $script:SavedSettings[$n] = Get-Variable -Name $n -Scope Global -ValueOnly; Remove-Variable -Name $n -Scope Global } }

    $script:Info = New-Object System.Collections.Generic.List[string]
    $script:Issues = New-Object System.Collections.Generic.List[string]
    function script:Write-SIInfo { param($m) $script:Info.Add([string]$m) }
    function script:Add-SIEnrichIssue { param($Text) $script:Issues.Add([string]$Text) }

    $script:Dev1 = 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa1'
    $script:Dev2 = 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa2'
    $script:Dev3 = 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa3'
    $script:AdminSid = 'S-1-5-21-1004336348-1177238915-682003330-1105'
    $script:HrSid = 'S-1-5-21-1004336348-1177238915-682003330-3301'
    $script:HelpSid = 'S-1-5-21-1004336348-1177238915-682003330-4401'
    $script:OfficeSid = 'S-1-5-21-1004336348-1177238915-682003330-2201'
    $script:AdminOid = '11111111-2222-3333-4444-555555555555'
    $script:HrOid = '22222222-3333-4444-5555-666666666666'
    $script:HelpOid = '33333333-4444-5555-6666-777777777777'
    $script:OfficeOid = '66666666-7777-8888-9999-000000000000'
    $script:Now = [datetime]::new(2026, 11, 12, 12, 0, 0, [DateTimeKind]::Utc)

    # this run's identity profile (fictional): a Tier 0 admin (eligible role), a Tier 2 finance user (the customer's
    # group-membership rule), a Tier 1 helpdesk account, a Tier 3 office user
    $script:FinanceRules = '[{"RuleId":"AssetProfileByGroupMembership","DetectionId":"OrgFinanceMember","Tier":2,"Purpose":"Finance team member","Category":"Business"}]'
    function script:IdRows([string]$HrGroups = '["org-finance"]') {
        @(
            [pscustomobject]@{ ObjectId = $script:AdminOid; Sid = $script:AdminSid; Upn = 'admin-t0@contoso.test'; Tier = '0'; SIRules = '[]'; TierReason = 'Tier 0 set by entra-role -- an eligible (PIM) Entra ID directory role (Global Administrator).'; Groups = '' }
            [pscustomobject]@{ ObjectId = $script:HrOid; Sid = $script:HrSid; Upn = 'finance.user@contoso.test'; Tier = '2'; SIRules = $script:FinanceRules; TierReason = ''; Groups = $HrGroups }
            [pscustomobject]@{ ObjectId = $script:HelpOid; Sid = $script:HelpSid; Upn = 'helpdesk1@contoso.test'; Tier = '1'; SIRules = '[]'; TierReason = 'Tier 1 set by entra-role -- a permanent Entra ID directory role (Helpdesk Administrator).'; Groups = '["Helpdesk Operators"]' }
            [pscustomobject]@{ ObjectId = $script:OfficeOid; Sid = $script:OfficeSid; Upn = 'office.user@contoso.test'; Tier = '3'; SIRules = '[]'; TierReason = ''; Groups = '' }
        )
    }
    $script:Identities = IdRows
    $script:IdOk = { @{ Complete = $true; Missing = $false; Rows = $script:Identities } }

    function script:Ev([string]$Dev, [string]$Sid, [string]$Type, [double]$DaysAgo, [string]$Action = 'LogonSuccess') {
        [pscustomobject]@{ DeviceId = $Dev; AccountSid = $Sid; LogonType = $Type; ActionType = $Action; Timestamp = $script:Now.AddDays(-$DaysAgo) }
    }
    function script:Settings([hashtable]$Over = @{}) {
        $s = Get-SIPrivilegedLogonSettings
        foreach ($k in $Over.Keys) { $s.$k = $Over[$k] }
        $s
    }

    # a fake advanced hunting: the query's OWN filters applied to raw events, summarised like the query does
    $script:Calls = New-Object System.Collections.Generic.List[string]
    $script:Events = @()
    $script:FailIf = $null     # { param($kql, $since, $until, $sids) } -> $true = answer with a service limit error
    $script:FailText = 'HTTP 504 Gateway Timeout: the query exceeded the allowed limits'
    function script:KqlList([string]$kql, [string]$name) { @([regex]::Matches([regex]::Match($kql, ('let {0} = dynamic\(\[([^\]]*)\]\)' -f $name)).Groups[1].Value, '"([^"]+)"') | ForEach-Object { $_.Groups[1].Value }) }
    function script:KqlTime([string]$s) { [datetime]::Parse($s, [System.Globalization.CultureInfo]::InvariantCulture, [System.Globalization.DateTimeStyles]::AdjustToUniversal) }
    $script:FakeHunt = {
        param($kql)
        $script:Calls.Add([string]$kql)
        $m = [regex]::Match($kql, 'Timestamp > datetime\(([^)]+)\) and Timestamp <= datetime\(([^)]+)\)')
        $since = KqlTime $m.Groups[1].Value; $until = KqlTime $m.Groups[2].Value
        $countFrom = KqlTime ([regex]::Match($kql, 'let _countFrom = datetime\(([^)]+)\)').Groups[1].Value)
        $types = @([regex]::Matches([regex]::Match($kql, 'LogonType in \(([^)]*)\)').Groups[1].Value, '"([^"]+)"') | ForEach-Object { $_.Groups[1].Value })
        $sids = KqlList $kql '_sids'
        if ($script:FailIf -and (& $script:FailIf $kql $since $until $sids)) { throw $script:FailText }
        $needsSuccess = $kql -match 'ActionType == "LogonSuccess"'
        $hits = @($script:Events | Where-Object {
            ($_.ActionType -eq 'LogonSuccess' -or -not $needsSuccess) -and ($types -contains $_.LogonType) -and ($sids -contains $_.AccountSid.ToUpperInvariant()) -and
            ($_.Timestamp -gt $since) -and ($_.Timestamp -le $until)
        })
        foreach ($g in @($hits | Group-Object DeviceId, AccountSid)) {
            $last = @($g.Group | Sort-Object Timestamp -Descending)[0]
            [pscustomobject]@{ DeviceId = $last.DeviceId; AccountSid = $last.AccountSid.ToUpperInvariant(); AccountUpn = ''; AccountObjectId = ''
                LastLogonUtc = $last.Timestamp.ToString('o'); LastLogonType = $last.LogonType; Counted = @($g.Group | Where-Object { $_.Timestamp -gt $countFrom }).Count
                Days = @($g.Group | ForEach-Object { $_.Timestamp.ToString('yyyy-MM-dd') } | Sort-Object -Unique); Types = @($g.Group | ForEach-Object { $_.LogonType } | Sort-Object -Unique) }
        }
    }
    function script:New-FakeStore([string]$Json = $null) {
        $s = [pscustomobject]@{ Json = $Json; ETag = 0; Writes = 0; RaceOnce = $null }
        Add-Member -InputObject $s -MemberType ScriptMethod -Name Read -Value { @{ Doc = $(if ($this.Json) { $this.Json | ConvertFrom-Json } else { $null }); ETag = $(if ($this.Json) { [string]$this.ETag } else { '' }); Existed = [bool]$this.Json } }
        Add-Member -InputObject $s -MemberType ScriptMethod -Name Write -Value {
            param([string]$Json, [string]$ETag)
            if ($this.RaceOnce) { $this.Json = $this.RaceOnce; $this.ETag++; $this.RaceOnce = $null; throw '412 ConditionNotMet' }
            if ($this.Json -and $ETag -ne [string]$this.ETag) { throw '412 ConditionNotMet' }
            $this.Json = $Json; $this.ETag++; $this.Writes++
        }
        $s
    }
    function script:Run([object[]]$Events, [string[]]$Devices = @($script:Dev1), $Store = $null, [datetime]$At = $script:Now, [string]$RunId = '', $Ids = $script:IdOk, $S = $null, [hashtable]$Primary = @{}) {
        if ($null -eq $S) { $S = Settings }
        $script:Events = $Events; $script:Calls.Clear(); $script:Info.Clear(); $script:Issues.Clear(); $global:SI_EnrichScopedNotes = $null
        Get-SIBulkPrivilegedLogons -MdeDeviceIds $Devices -Now $At -RunId $RunId -Query $script:FakeHunt -PrivilegedIdentities $Ids -Store $Store -Settings $S -PrimaryUsers $Primary
    }
    # a state with rows: @(@(device, account, distinct days), ...)
    function script:New-State([object[]]$Rows) {
        $st = ConvertFrom-SIPrivilegedLogonState $null
        foreach ($r in $Rows) {
            $days = New-Object 'System.Collections.Generic.HashSet[string]'
            foreach ($i in 1..([int]$r[2])) { [void]$days.Add($script:Now.AddDays(-$i).ToString('yyyy-MM-dd')) }
            $st.Rows[('{0}|{1}' -f $r[0], $r[1])] = @{ D = [string]$r[0]; A = [string]$r[1]; T = $script:Now.AddDays(-1); Y = 'Interactive'; C = [int]$r[2]; S = $days; P = (New-Object 'System.Collections.Generic.HashSet[string]') }
        }
        $st
    }

    # the shipped rule, loaded by the engine's own loader from a scratch tree that holds only it
    $script:Folder = 'asset-profiling-enrichment\endpoint'
    $script:Tree = Join-Path ([System.IO.Path]::GetTempPath()) ('siplt-' + [guid]::NewGuid().ToString('N').Substring(0, 10))
    New-Item -ItemType Directory -Force (Join-Path $script:Tree $script:Folder) | Out-Null
    Copy-Item -LiteralPath (Join-Path $script:SIRoot (Join-Path $script:Folder 'AssetProfileByPrivilegedLogon.locked.yaml')) -Destination (Join-Path $script:Tree $script:Folder)
    $script:Saved = $global:SI_EnrichmentDataRoot
    if (Test-Path variable:global:SI_EnrichmentDataRoot) { Remove-Variable -Name SI_EnrichmentDataRoot -Scope Global }
    $all = Get-SIRuleSet -Engine endpoint -SolutionRootOverride $script:Tree 3>$null
    $script:Rule = @(@($all) | Where-Object { $_.Id -eq 'AssetProfileByPrivilegedLogon' })[0]
    function script:V([int]$Tier, [string]$Top = '', [int]$Count = 1) { [pscustomobject]@{ Tier = $Tier; TopMatch = $Top; MatchCount = $Count } }
}

AfterAll {
    Remove-Item -Recurse -Force $script:Tree -ErrorAction SilentlyContinue
    if ($null -ne $script:Saved) { $global:SI_EnrichmentDataRoot = $script:Saved }
    foreach ($n in $script:SavedSettings.Keys) { Set-Variable -Name $n -Scope Global -Value $script:SavedSettings[$n] }
    # the source's process-wide notes never leak into a later suite (a run report test would see them as Reports[])
    foreach ($n in 'SI_RunNoteCodes', 'SI_EnrichScopedNotes', 'SI_PrivilegedLogonPart') { Remove-Variable -Name $n -Scope Global -ErrorAction SilentlyContinue }
}

Describe 'no setting set (a fresh or an updated install): the defaults run' {
    It 'every setting has its default: privileged logon ON, frequent user ON, 30 days, the six logon types, no filter' {
        $s = Get-SIPrivilegedLogonSettings
        $s.Mode | Should -Be 'on'
        $s.MostFrequentMode | Should -Be 'on'
        $s.WindowDays | Should -Be 30
        @($s.LogonTypes) | Should -Be @('Interactive', 'RemoteInteractive', 'CachedInteractive', 'CachedRemoteInteractive', 'Unlock', 'CachedUnlock')
        $s.SupportFilter | Should -Be 'off'
        $s.MinDays | Should -BeNullOrEmpty
        $s.PrimaryUserCounts | Should -BeTrue
        @($s.ExcludeGroups).Count | Should -Be 0
        $s.Tier0Once | Should -BeTrue
    }
    It 'a value that is not valid falls back to the default' {
        $global:SI_Endpoint_PrivilegedLogon_Mode = 'maybe'; $global:SI_Endpoint_PrivilegedLogon_WindowDays = '0'; $global:SI_Endpoint_PrivilegedLogon_LogonTypes = 'Bogus'
        try {
            $s = Get-SIPrivilegedLogonSettings
            $s.Mode | Should -Be 'on'; $s.WindowDays | Should -Be 30; @($s.LogonTypes).Count | Should -Be 6
        } finally { Remove-Variable -Name SI_Endpoint_PrivilegedLogon_Mode, SI_Endpoint_PrivilegedLogon_WindowDays, SI_Endpoint_PrivilegedLogon_LogonTypes -Scope Global }
    }
    It 'runs without any setting and without a store (the first run of a new install)' {
        $script:Events = @((Ev $script:Dev1 $script:HrSid 'Interactive' 2)); $script:Calls.Clear()
        $r = Get-SIBulkPrivilegedLogons -MdeDeviceIds @($script:Dev1) -Now $script:Now -Query $script:FakeHunt -PrivilegedIdentities $script:IdOk
        $r.ByDevice[$script:Dev1].PrivilegedLogonTier | Should -Be 2
    }
    It 'an updated install''s store of the first format (no days / types) is read and carried on' {
        $old = '{"SchemaVersion":1,"RunId":"old","Complete":true,"WindowDays":30,"Accounts":[{"Id":"' + $script:HrOid + '","ReadUntil":"' + $script:Now.AddHours(-30).ToString('yyyy-MM-ddTHH:mm:ssZ') + '"}],"Rows":[{"D":"' + $script:Dev1 + '","A":"' + $script:HrOid + '","T":"' + $script:Now.AddDays(-3).ToString('yyyy-MM-ddTHH:mm:ssZ') + '","Y":"Interactive","C":1}]}'
        $store = New-FakeStore $old
        $r = Run @() @($script:Dev1) $store $script:Now 'new'
        $r.ByDevice[$script:Dev1].PrivilegedLogonTier | Should -Be 2
        ($store.Json | ConvertFrom-Json).SchemaVersion | Should -Be 2
    }
}

Describe 'the query: filtered by the Tier 0-2 accounts, never by device, summarised in the query' {
    It 'one query for the accounts, whatever the number of devices; no device id is ever in it' {
        $ev = @((Ev $script:Dev1 $script:AdminSid 'RemoteInteractive' 2))
        $null = Run $ev @($script:Dev1)
        $q1 = $script:Calls.Count
        $many = @(1..2000 | ForEach-Object { 'b{0:x39}' -f $_ })
        $r2 = Run $ev (@($script:Dev1) + $many)
        $q1 | Should -Be 1
        $script:Calls.Count | Should -Be $q1 -Because 'the device count never changes the query count'
        $script:Calls[0] | Should -Not -Match $script:Dev1
        $r2.ByDevice.Count | Should -Be 2001
    }
    It 'only Tier 0-2 accounts are asked for (a Tier 3 account is never in the query)' {
        $null = Run @()
        foreach ($sid in $script:AdminSid, $script:HrSid, $script:HelpSid) { $script:Calls[0] | Should -Match ([regex]::Escape($sid)) }
        $script:Calls[0] | Should -Not -Match ([regex]::Escape($script:OfficeSid))
    }
    It 'thousands of accounts travel in key lists sized by their text -- one query per list, never per account' {
        $big = @(1..3000 | ForEach-Object { [pscustomobject]@{ ObjectId = ('{0:x8}-0000-4000-8000-{1:x12}' -f $_, $_); Sid = ('S-1-5-21-1-2-3-{0}' -f (10000 + $_)); Upn = "u$_@contoso.test"; Tier = '2' } })
        $st = ConvertFrom-SIPrivilegedLogonState $null
        $script:Calls.Clear(); $script:Events = @()
        $u = Update-SIPrivilegedLogonState -Accounts @($big | ForEach-Object { ConvertTo-SIPrivilegedAccount $_ }) -State $st -Now $script:Now -Days 30 -Query $script:FakeHunt -KeyChars 20000
        $u.Lists | Should -BeGreaterThan 1
        $u.Queries | Should -Be $u.Lists
        $u.Queries | Should -BeLessThan 50
    }
    It 'the KQL: DeviceLogonEvents, successful logons, the counted types, the days and types summarised per device and account key' {
        $k = Get-SIPrivilegedLogonKql -Accounts @((ConvertTo-SIPrivilegedAccount $script:Identities[0])) -Since $script:Now.AddDays(-30) -Until $script:Now
        $k | Should -Match 'DeviceLogonEvents'
        $k | Should -Match 'ActionType == "LogonSuccess"'
        foreach ($t in 'Interactive', 'RemoteInteractive', 'CachedInteractive', 'CachedRemoteInteractive', 'Unlock', 'CachedUnlock') { $k | Should -Match ('"' + $t + '"') }
        foreach ($t in 'Network', 'Service', 'Batch', 'NetworkCleartext', 'NewCredentials') { $k | Should -Not -Match ('"' + $t + '"') }
        $k | Should -Match 'summarize Counted = countif\(Timestamp > _countFrom\), Days = make_set\(_day, 400\), Types = make_set\(LogonType, 16\), arg_max\(Timestamp, LogonType\) by DeviceId'
        $k | Should -Match ([regex]::Escape((ConvertTo-SICloudSid $script:AdminOid)))
    }
    It 'the logon types follow the setting (a changed list reads the whole window again)' {
        $k = Get-SIPrivilegedLogonKql -Accounts @((ConvertTo-SIPrivilegedAccount $script:Identities[0])) -Since $script:Now.AddDays(-1) -Until $script:Now -LogonTypes @('Interactive', 'Service')
        $k | Should -Match '"Service"'
        $store = New-FakeStore
        $null = Run @() @($script:Dev1) $store $script:Now 'a'
        $null = Run @() @($script:Dev1) $store $script:Now.AddHours(5) 'b' -S (Settings @{ LogonTypes = [string[]]@('Interactive', 'Service') })
        $script:Calls[0] | Should -Match ([regex]::Escape(('Timestamp > datetime({0}' -f $script:Now.AddHours(5).AddDays(-30).ToString('yyyy-MM-ddTHH:mm:ss'))))
    }
}

Describe 'DEFAULT (mode on, no filter): any Tier 0-2 logon makes the device that tier' {
    BeforeAll {
        $script:R0 = Run @((Ev $script:Dev1 $script:AdminSid 'RemoteInteractive' 2), (Ev $script:Dev1 $script:OfficeSid 'Interactive' 1), (Ev $script:Dev2 $script:HrSid 'Interactive' 3), (Ev $script:Dev3 $script:OfficeSid 'Interactive' 1)) @($script:Dev1, $script:Dev2, $script:Dev3)
        $script:Date0 = $script:Now.AddDays(-2).ToString('yyyy-MM-dd'); $script:Date2 = $script:Now.AddDays(-3).ToString('yyyy-MM-dd')
    }
    It 'a Tier 0 RDP logon -> Tier 0, the evidence names the account, why it is Tier 0, the date and RDP' {
        $e = $script:R0.ByDevice[$script:Dev1]
        $e.PrivilegedLogonTier | Should -Be 0
        $e.PrivilegedLogonComputedTier | Should -Be 0
        $e.PrivilegedLogonStatus | Should -Be 'read'
        $e.PrivilegedLogonEvidence | Should -Be ("admin-t0@contoso.test (Tier 0: entra-role -- an eligible (PIM) Entra ID directory role (Global Administrator).) logged on {0} (RDP)" -f $script:Date0)
    }
    It 'ONE Tier 2 logon of a group-membership identity (finance) raises a Tier 3 office PC to Tier 2, naming the rule' {
        $e = $script:R0.ByDevice[$script:Dev2]
        $e.PrivilegedLogonTier | Should -Be 2
        $e.PrivilegedLogonEvidence | Should -Be ("finance.user@contoso.test (Tier 2: Finance team member (AssetProfileByGroupMembership/OrgFinanceMember)) logged on {0} (at the device)" -f $script:Date2)
        @($e.PrivilegedLogons)[0].Counted | Should -BeTrue
        [int](Invoke-SIRuleEval -Asset ([pscustomobject]@{ Name = 'pc2'; PrivilegedLogonTier = 2 }) -Rule $script:Rule).Set.Tier | Should -Be 2
    }
    It 'a single Tier 1 logon counts too (helpdesk -- the support filter is off by default)' {
        $e = (Run @((Ev $script:Dev3 $script:HelpSid 'RemoteInteractive' 4)) @($script:Dev3)).ByDevice[$script:Dev3]
        $e.PrivilegedLogonTier | Should -Be 1
    }
    It 'only Tier 3 users logged on -> the privileged-logon source sets nothing; the device is Tier 3 from its user' {
        $e = $script:R0.ByDevice[$script:Dev3]
        $e.PrivilegedLogonTier | Should -BeNullOrEmpty
        $e.PrivilegedLogonComputedTier | Should -BeNullOrEmpty
        $e.PrivilegedLogonStatus | Should -Be 'read'
        Invoke-SIRuleEval -Asset ([pscustomobject]@{ Name = 'pc3'; PrivilegedLogonTier = $e.PrivilegedLogonTier }) -Rule $script:Rule | Should -BeNullOrEmpty
        $a = Get-SITierAttribution -FinalTier 3 -Sources @{ SIRules = V 3 'AssetProfileByLogonUser/LogonByT3User'; MostFrequentUserTier = 3 }
        $a.SI_TierSetBy | Should -BeExactly 'logon+rule'
        $a.SI_TierReason | Should -Match 'AssetProfileByLogonUser/LogonByT3User'
        $a.SI_TierClaims | Should -Not -Match 'privileged-logon'
    }
    It 'the shipped rule maps 0 / 1 / 2 to Tier 0 / 1 / 2; nothing for none or 3' {
        $h = Invoke-SIRuleEval -Asset ([pscustomobject]@{ Name = 'pc1'; Metadata = [pscustomobject]@{ PrivilegedLogonTier = 0 } }) -Rule $script:Rule
        $h.DetectionId | Should -Be 'PrivilegedLogonByT0Account'; [int]$h.Set.Tier | Should -Be 0
        [int](Invoke-SIRuleEval -Asset ([pscustomobject]@{ Name = 'pc1'; PrivilegedLogonTier = 1 }) -Rule $script:Rule).Set.Tier | Should -Be 1
        Invoke-SIRuleEval -Asset ([pscustomobject]@{ Name = 'pc1' }) -Rule $script:Rule | Should -BeNullOrEmpty
        Invoke-SIRuleEval -Asset ([pscustomobject]@{ Name = 'pc1'; PrivilegedLogonTier = 3 }) -Rule $script:Rule | Should -BeNullOrEmpty
    }
    It 'the tier reason is the privileged logon -- not "asset-profiling rule matched"; a rule with its own reason keeps it' {
        $ev = $script:R0.ByDevice[$script:Dev2].PrivilegedLogonEvidence
        $a = Get-SITierAttribution -FinalTier 2 -Sources @{ SIRules = V 2 'AssetProfileByPrivilegedLogon/PrivilegedLogonByT2Account' 2; MostFrequentUserTier = 3
            PrivilegedLogonTier = [pscustomobject]@{ Tier = 2; TopMatch = $ev; MatchCount = 1; Sentence = $ev } }
        $a.SI_TierSetBy | Should -BeExactly 'privileged-logon+rule'
        $a.SI_TierReason | Should -BeLike 'Tier 2 set by privileged-logon+rule -- finance.user@contoso.test (Tier 2: Finance team member*'
        $b = Get-SITierAttribution -FinalTier 0 -Sources @{ SIRules = V 0 'AssetProfileByDeviceType/DomainController'; PrivilegedLogonTier = [pscustomobject]@{ Tier = 0; TopMatch = 'x'; MatchCount = 1; Sentence = 'x (Tier 0) logged on 2026-11-10 (RDP)' } }
        $b.SI_TierReason | Should -Match 'DomainController'
        (ConvertTo-SITierClaim -SourceKey 'SIRules' -Verdict (V 1 'r')).PSObject.Properties['Sentence'] | Should -BeNullOrEmpty
    }
    It 'FIRST HIT: a device with a counted Tier 0 logon stops there (no lower tier exists)' {
        $e = (Run @((Ev $script:Dev1 $script:HrSid 'Interactive' 1), (Ev $script:Dev1 $script:AdminSid 'Unlock' 5))).ByDevice[$script:Dev1]
        $e.PrivilegedLogonTier | Should -Be 0
        @($e.PrivilegedLogons).Count | Should -Be 1
        $e.PrivilegedLogonEvidence | Should -Match '\(unlock\)$'
    }
    It 'not counted: the same logon 31 days ago, a network / service / batch / runas-netonly / clear-text logon, a failed logon' {
        (Run @((Ev $script:Dev1 $script:AdminSid 'RemoteInteractive' 31))).ByDevice[$script:Dev1].PrivilegedLogonTier | Should -BeNullOrEmpty
        foreach ($t in 'Network', 'Service', 'Batch', 'NewCredentials', 'NetworkCleartext') {
            (Run @((Ev $script:Dev1 $script:AdminSid $t 1))).ByDevice[$script:Dev1].PrivilegedLogonTier | Should -BeNullOrEmpty -Because "$t leaves no reusable credential on the device"
        }
        (Run @((Ev $script:Dev1 $script:AdminSid 'RemoteInteractive' 1 'LogonFailed'))).ByDevice[$script:Dev1].PrivilegedLogonTier | Should -BeNullOrEmpty
    }
    It 'a cloud SID (an Entra-joined device) maps to the object id it is made from' {
        $cloudSid = ConvertTo-SICloudSid $script:AdminOid
        ConvertFrom-SICloudSid $cloudSid | Should -Be $script:AdminOid
        (Run @((Ev $script:Dev1 $cloudSid 'RemoteInteractive' 1))).ByDevice[$script:Dev1].PrivilegedLogonTier | Should -Be 0
    }
}

Describe 'the modes: on / shadow / off' {
    It 'SHADOW computes and records (tier + evidence) but never sets the device''s tier' {
        $e = (Run @((Ev $script:Dev2 $script:HrSid 'Interactive' 3)) @($script:Dev2) -S (Settings @{ Mode = 'shadow' })).ByDevice[$script:Dev2]
        $e.PrivilegedLogonComputedTier | Should -Be 2
        $e.PrivilegedLogonTier | Should -BeNullOrEmpty
        $e.PrivilegedLogonEvidence | Should -Match 'finance.user@contoso.test \(Tier 2'
        Invoke-SIRuleEval -Asset ([pscustomobject]@{ Name = 'pc2'; PrivilegedLogonTier = $e.PrivilegedLogonTier }) -Rule $script:Rule | Should -BeNullOrEmpty
    }
    It 'OFF reads nothing and stamps nothing' {
        $r = Run @((Ev $script:Dev2 $script:HrSid 'Interactive' 3)) @($script:Dev2) -S (Settings @{ Mode = 'off' })
        $script:Calls.Count | Should -Be 0
        $r.ByDevice.Count | Should -Be 0
    }
    It 'the frequent-user mode: Enrich empties MostFrequentUserTier in shadow / off and records MostFrequentUserComputedTier' {
        $en = [IO.File]::ReadAllText((Join-Path $script:SIRoot 'engine\asset-profiling\stages\Invoke-Enrich.ps1'))
        $en | Should -Match "if \(\`$mfuMode -ne 'on'\) \{ \`$u = @\{ MostFrequentUserTier = \`$null"
        $en | Should -Match "MostFrequentUserComputedTier'\] = \`$mfuComputed"
        $en | Should -Match "if \(\`$plSettings\.MostFrequentMode -eq 'off'\)"
    }
}

Describe 'the support filter (OFF by default; dynamic per tenant) and the overrides' {
    It 'the cut-off follows the tenant''s own distribution: 9 devices once each is SUPPORT in a small tenant, not in a VDI-heavy one' {
        $small = New-State (@(@('d1', 'u1', 1), @('d2', 'u2', 1), @('d3', 'u3', 3), @('d4', 'u3', 2)) + @(1..9 | ForEach-Object { , @("h$_", 'help', 1) }))
        $ps = Get-SIPrivilegedLogonPatterns -State $small
        $ps.CutOff | Should -BeLessThan 9
        $ps.Accounts['help'].Support | Should -BeTrue
        $ps.Accounts['u3'].Support | Should -BeFalse
        $rows = New-Object System.Collections.Generic.List[object]
        foreach ($u in 1..40) { foreach ($d in 1..(5 + ($u % 4))) { $rows.Add(@("v$u-$d", "u$u", 1)) } }
        foreach ($d in 1..9) { $rows.Add(@("h$d", 'help', 1)) }
        $pl = Get-SIPrivilegedLogonPatterns -State (New-State $rows.ToArray())
        $pl.CutOff | Should -BeGreaterThan 9
        $pl.Accounts['help'].Support | Should -BeFalse -Because 'in this tenant 9 devices is an ordinary user''s fan-out'
    }
    It 'many devices on SEVERAL days each is a user pattern, not support' {
        $st = New-State (@(@('d1', 'u1', 1), @('d2', 'u2', 1)) + @(1..9 | ForEach-Object { , @("s$_", 'admin', 3) }))
        (Get-SIPrivilegedLogonPatterns -State $st).Accounts['admin'].Support | Should -BeFalse
    }
    BeforeEach {
        # the helpdesk account: one session on each of 10 devices; the finance user: 3 days on Dev2, once on Dev3; six more
        # Tier 2 users, each on their own device on two days (the tenant's ordinary user pattern)
        $script:SupEv = @(1..10 | ForEach-Object { Ev ('c{0:x39}' -f $_) $script:HelpSid 'RemoteInteractive' 2 }) +
            @((Ev $script:Dev2 $script:HrSid 'Interactive' 1), (Ev $script:Dev2 $script:HrSid 'Interactive' 2), (Ev $script:Dev2 $script:HrSid 'Interactive' 3), (Ev $script:Dev3 $script:HrSid 'Interactive' 4)) +
            @(1..6 | ForEach-Object { (Ev ('e{0:x39}' -f $_) ('S-1-5-21-5-5-5-{0}' -f (5000 + $_)) 'Interactive' 1); (Ev ('e{0:x39}' -f $_) ('S-1-5-21-5-5-5-{0}' -f (5000 + $_)) 'Interactive' 2) })
        $script:SupDev = @(@(1..10 | ForEach-Object { 'c{0:x39}' -f $_ }) + @($script:Dev2, $script:Dev3))
        $extra = @(1..6 | ForEach-Object { [pscustomobject]@{ ObjectId = ('{0:x8}-5555-4000-8000-000000000000' -f $_); Sid = ('S-1-5-21-5-5-5-{0}' -f (5000 + $_)); Upn = "user$_@contoso.test"; Tier = '2'; SIRules = ''; TierReason = ''; Groups = '' } })
        $allIds = @($script:Identities) + @($extra)
        $script:SupIds = { @{ Complete = $true; Missing = $false; Rows = $allIds } }.GetNewClosure()
    }
    It 'OFF (default): the helpdesk one-off sessions raise their devices -- and the summary says so' {
        $r = Run $script:SupEv $script:SupDev -Ids $script:SupIds
        $r.ByDevice[('c{0:x39}' -f 1)].PrivilegedLogonTier | Should -Be 1
        $r.ByDevice[$script:Dev3].PrivilegedLogonTier | Should -Be 2
        $r.Summary.RaisedBySupportAccount | Should -Be 10
        $r.Summary.RaisedByOneOff | Should -Be 11
        $r.Summary.SupportAccounts | Should -Be 1
    }
    It 'DYNAMIC: a support-pattern account never raises (recorded, said why); a user-pattern account raises the device it came back to; its one-off is recorded, not raised' {
        $r = Run $script:SupEv $script:SupDev -Ids $script:SupIds -S (Settings @{ SupportFilter = 'dynamic' })
        $h = $r.ByDevice[('c{0:x39}' -f 1)]
        $h.PrivilegedLogonTier | Should -BeNullOrEmpty
        @($h.PrivilegedLogons)[0].Counted | Should -BeFalse
        @($h.PrivilegedLogons)[0].Why | Should -Match 'support pattern \(10 devices, one session each\)'
        $h.PrivilegedLogonEvidence | Should -Match 'not counted: support pattern'
        $r.ByDevice[$script:Dev2].PrivilegedLogonTier | Should -Be 2
        @($r.ByDevice[$script:Dev2].PrivilegedLogons)[0].Why | Should -Be 'returns: 3 days'
        $r.ByDevice[$script:Dev3].PrivilegedLogonTier | Should -BeNullOrEmpty
        @($r.ByDevice[$script:Dev3].PrivilegedLogons)[0].Why | Should -Be 'privileged logon seen once -- not counted'
        $r.Summary.NotCountedSupport | Should -Be 10
        $r.Summary.NotCountedOneOff | Should -Be 1
        $r.Summary.SupportCutOff | Should -BeGreaterThan 0
    }
    It 'the device''s own user still counts on one logon (PrimaryUserCounts); off -> it needs the days too' {
        $f = Settings @{ SupportFilter = 'dynamic' }
        (Run $script:SupEv $script:SupDev -Ids $script:SupIds -S $f -Primary @{ $script:Dev3 = @('finance.user@contoso.test') }).ByDevice[$script:Dev3].PrivilegedLogonTier | Should -Be 2
        $f2 = Settings @{ SupportFilter = 'dynamic'; PrimaryUserCounts = $false }
        (Run $script:SupEv $script:SupDev -Ids $script:SupIds -S $f2 -Primary @{ $script:Dev3 = @('finance.user@contoso.test') }).ByDevice[$script:Dev3].PrivilegedLogonTier | Should -BeNullOrEmpty
    }
    It 'MinDays (override) beats the dynamic rule: 3 days needed -> 3 counts, 2 does not' {
        $ev = @((Ev $script:Dev2 $script:HrSid 'Interactive' 1), (Ev $script:Dev2 $script:HrSid 'Interactive' 2), (Ev $script:Dev3 $script:HrSid 'Interactive' 1), (Ev $script:Dev3 $script:HrSid 'Interactive' 2), (Ev $script:Dev3 $script:HrSid 'Interactive' 3))
        $r = Run $ev @($script:Dev2, $script:Dev3) -S (Settings @{ MinDays = 3 })
        $r.ByDevice[$script:Dev2].PrivilegedLogonTier | Should -BeNullOrEmpty
        @($r.ByDevice[$script:Dev2].PrivilegedLogons)[0].Why | Should -Be 'not counted: 2 of 3 days'
        $r.ByDevice[$script:Dev3].PrivilegedLogonTier | Should -Be 2
    }
    It 'Tier 0 counts on ONE logon under any filter (Tier0Once); off -> it follows the filter' {
        $ev = @((Ev $script:Dev1 $script:AdminSid 'RemoteInteractive' 2))
        (Run $ev -S (Settings @{ MinDays = 3 })).ByDevice[$script:Dev1].PrivilegedLogonTier | Should -Be 0
        (Run $ev -S (Settings @{ MinDays = 3; Tier0Once = $false })).ByDevice[$script:Dev1].PrivilegedLogonTier | Should -BeNullOrEmpty
    }
    It 'an excluded group never counts (also by default), recorded with the group' {
        $r = Run @((Ev $script:Dev3 $script:HelpSid 'RemoteInteractive' 2), (Ev $script:Dev2 $script:HrSid 'Interactive' 2)) @($script:Dev2, $script:Dev3) -S (Settings @{ ExcludeGroups = [string[]]@('Helpdesk Operators') })
        $r.ByDevice[$script:Dev3].PrivilegedLogonTier | Should -BeNullOrEmpty
        @($r.ByDevice[$script:Dev3].PrivilegedLogons)[0].Why | Should -Be 'not counted: member of the excluded group Helpdesk Operators'
        $r.ByDevice[$script:Dev2].PrivilegedLogonTier | Should -Be 2
        $r.Summary.NotCountedExcluded | Should -Be 1
    }
}

Describe 'incremental: the stored rolling window, decay, a tier change at once, the parts of a run' {
    It 'the first run reads the window; the next only since its read point (24 h overlap), counting nothing twice' {
        $store = New-FakeStore
        $ev1 = @((Ev $script:Dev1 $script:AdminSid 'RemoteInteractive' 5))
        $null = Run $ev1 @($script:Dev1) $store $script:Now 'run1'
        $script:Calls[0] | Should -Match ([regex]::Escape(('Timestamp > datetime({0}' -f $script:Now.AddDays(-30).ToString('yyyy-MM-ddTHH:mm:ss'))))
        $next = $script:Now.AddDays(1)
        $ev2 = @($ev1) + @([pscustomobject]@{ DeviceId = $script:Dev1; AccountSid = $script:AdminSid; LogonType = 'Interactive'; ActionType = 'LogonSuccess'; Timestamp = $next.AddHours(-2) })
        $r = Run $ev2 @($script:Dev1) $store $next 'run2'
        $prevUntil = $script:Now.AddHours(-1)
        $script:Calls.Count | Should -Be 1
        $script:Calls[0] | Should -Match ([regex]::Escape(('Timestamp > datetime({0}' -f $prevUntil.AddHours(-24).ToString('yyyy-MM-ddTHH:mm:ss'))))
        $script:Calls[0] | Should -Match ([regex]::Escape(('let _countFrom = datetime({0}' -f $prevUntil.ToString('yyyy-MM-ddTHH:mm:ss'))))
        $p = @($r.ByDevice[$script:Dev1].PrivilegedLogons)[0]
        $p.Count | Should -Be 2
        $p.Days | Should -Be 2
        $p.LogonType | Should -Be 'Interactive'
        $r3 = Run $ev2 @($script:Dev1) $store $next.AddHours(3) 'run3'
        @($r3.ByDevice[$script:Dev1].PrivilegedLogons)[0].Count | Should -Be 2 -Because 'the overlap re-reads the new logon but never counts it again'
    }
    It 'DECAY: when the logons age out of the window the device falls back by itself; the store forgets them' {
        $store = New-FakeStore
        $r1 = Run @((Ev $script:Dev2 $script:HrSid 'Interactive' 20)) @($script:Dev2) $store $script:Now 'a'
        $r1.ByDevice[$script:Dev2].PrivilegedLogonTier | Should -Be 2
        $r2 = Run @() @($script:Dev2) $store $script:Now.AddDays(11) 'b'
        $r2.ByDevice[$script:Dev2].PrivilegedLogonTier | Should -BeNullOrEmpty
        $r2.StateRows | Should -Be 0
        @(($store.Json | ConvertFrom-Json).Rows).Count | Should -Be 0
    }
    It 'a tier change applies at once: no longer Tier 0-2 leaves; newly Tier 0-2 is read for the whole window' {
        $store = New-FakeStore
        $ev = @((Ev $script:Dev1 $script:AdminSid 'RemoteInteractive' 3), (Ev $script:Dev2 $script:OfficeSid 'Interactive' 10))
        $null = Run $ev @($script:Dev1, $script:Dev2) $store $script:Now 'a'
        $changed = { @{ Complete = $true; Missing = $false; Rows = @(
            [pscustomobject]@{ ObjectId = $script:AdminOid; Sid = $script:AdminSid; Upn = 'admin-t0@contoso.test'; Tier = '3' }
            [pscustomobject]@{ ObjectId = $script:OfficeOid; Sid = $script:OfficeSid; Upn = 'office.user@contoso.test'; Tier = '1' }) } }
        $r = Run $ev @($script:Dev1, $script:Dev2) $store $script:Now.AddHours(2) 'b' $changed
        $r.ByDevice[$script:Dev1].PrivilegedLogonTier | Should -BeNullOrEmpty
        $r.ByDevice[$script:Dev2].PrivilegedLogonTier | Should -Be 1
    }
    It 'a later part of the SAME run uses the stored read (no query); a lost write race uses what that part stored' {
        $store = New-FakeStore
        $ev = @((Ev $script:Dev1 $script:AdminSid 'RemoteInteractive' 2))
        $null = Run $ev @($script:Dev1) $store $script:Now 'same'
        $r = Run $ev @($script:Dev2, $script:Dev1) $store $script:Now 'same'
        $script:Calls.Count | Should -Be 0
        $r.Reused | Should -BeTrue
        $r.ByDevice[$script:Dev1].PrivilegedLogonTier | Should -Be 0
        $other = ($store.Json | ConvertFrom-Json); $other.RunId = 'y'
        $store.RaceOnce = (ConvertTo-Json -InputObject $other -Depth 6 -Compress)
        $r2 = Run $ev @($script:Dev1) $store $script:Now.AddHours(1) 'y'
        $r2.Reused | Should -BeTrue
        $r2.ByDevice[$script:Dev1].PrivilegedLogonTier | Should -Be 0
    }
    It 'THE COMPARISON is kept with the run: the tenant cut-offs, the accounts, what each rule raised' {
        $store = New-FakeStore
        $r = Run @((Ev $script:Dev1 $script:AdminSid 'RemoteInteractive' 2), (Ev $script:Dev2 $script:HrSid 'Interactive' 3)) @($script:Dev1, $script:Dev2, $script:Dev3) $store $script:Now 'cmp'
        $r.Summary.RaisedDevices | Should -Be 2
        $r.Summary.RaisedByTier0 | Should -Be 1
        $r.Summary.RaisedByOneOff | Should -Be 2
        $r.Summary.Devices | Should -Be 3
        $r.Summary.Mode | Should -Be 'on'
        $s = ($store.Json | ConvertFrom-Json).Summary
        $s.PrivilegedAccounts | Should -Be 3
        $s.AccountsWithLogons | Should -Be 2
        $null -ne $s.SupportCutOff | Should -BeTrue
    }
}

Describe 'limits: split by time, then by account; unread is UNKNOWN, never "no privileged logon"' {
    AfterEach { $script:FailIf = $null; $script:FailText = 'HTTP 504 Gateway Timeout: the query exceeded the allowed limits' }
    It 'a read refused for a long range is split by time until it answers; the result is the same' {
        $script:FailIf = { param($k, $s, $u, $sids) ($u - $s).TotalDays -gt 4 }
        $r = Run @((Ev $script:Dev1 $script:AdminSid 'RemoteInteractive' 20), (Ev $script:Dev2 $script:HrSid 'Interactive' 2)) @($script:Dev1, $script:Dev2)
        $r.Splits | Should -BeGreaterThan 0
        $r.ByDevice[$script:Dev1].PrivilegedLogonTier | Should -Be 0
        $r.ByDevice[$script:Dev2].PrivilegedLogonTier | Should -Be 2
    }
    It 'a list refused even for small ranges is halved by account until it answers' {
        $script:FailIf = { param($k, $s, $u, $sids) @($sids).Count -gt 3 }
        $r = Run @((Ev $script:Dev1 $script:AdminSid 'RemoteInteractive' 2), (Ev $script:Dev2 $script:HrSid 'Interactive' 2)) @($script:Dev1, $script:Dev2)
        $r.ByDevice[$script:Dev1].PrivilegedLogonTier | Should -Be 0
        $r.ByDevice[$script:Dev2].PrivilegedLogonTier | Should -Be 2
    }
    It 'a part that stays unread: the devices are UNKNOWN (said), the read point does not move, the next run reads again' {
        $store = New-FakeStore
        $script:FailIf = { param($k, $s, $u, $sids) $true }
        $r = Run @((Ev $script:Dev1 $script:HrSid 'Interactive' 2)) @($script:Dev1, $script:Dev2) $store $script:Now 'a'
        foreach ($d in $script:Dev1, $script:Dev2) { $r.ByDevice[$d].PrivilegedLogonStatus | Should -Match '^unknown -- ' }
        ($global:SI_EnrichScopedNotes -join "`n") | Should -Match 'UNKNOWN this run, not "no privileged logon".*\[si-col-0505\]'
        $script:Issues.Count | Should -Be 0 -Because '#1227: a gap of this source never makes the run INCOMPLETE'
        @(($store.Json | ConvertFrom-Json).Accounts).Count | Should -Be 0
        $script:FailIf = $null
        $r2 = Run @((Ev $script:Dev1 $script:HrSid 'Interactive' 2)) @($script:Dev1) $store $script:Now.AddHours(1) 'b'
        $r2.ByDevice[$script:Dev1].PrivilegedLogonTier | Should -Be 2
        $r2.ByDevice[$script:Dev1].PrivilegedLogonStatus | Should -Be 'read'
    }
    It 'no DeviceLogonEvents in the tenant (no Defender for Endpoint data): said once, every device unknown, the run goes on' {
        $script:FailText = "Failed to resolve table expression named 'DeviceLogonEvents'"
        $script:FailIf = { param($k, $s, $u, $sids) $true }
        $r = Run @() @($script:Dev1, $script:Dev2)
        $script:Calls.Count | Should -Be 1 -Because 'a missing table is not split or asked again'
        $r.ByDevice[$script:Dev1].PrivilegedLogonStatus | Should -Be 'unknown -- this tenant has no Defender device logons'
        @($global:SI_EnrichScopedNotes | Where-Object { $_ -match 'no Defender device logons.*\[si-col-0503\]' }).Count | Should -Be 1
        $script:Issues.Count | Should -Be 0
    }
    It 'the identity tiers cannot be read, or are not there yet -> every device unknown, said; no query' {
        $r = Run @((Ev $script:Dev1 $script:AdminSid 'RemoteInteractive' 1)) -Ids { @{ Complete = $false; Missing = $false; Rows = @() } }
        $r.ByDevice[$script:Dev1].PrivilegedLogonStatus | Should -Match '^unknown -- the identity tiers could not be read'
        $script:Calls.Count | Should -Be 0
        (Run @() -Ids { @{ Complete = $true; Missing = $true; Rows = @() } }).ByDevice[$script:Dev1].PrivilegedLogonStatus | Should -Match 'identity profile is not there yet'
    }
}

Describe 'end to end: a Tier 2 device is patched before a Tier 3 device' {
    BeforeAll {
        . (Join-Path $script:SIRoot 'engine\data-model\SI-RecordCapture.ps1')
        . (Join-Path $script:SIRoot 'engine\data-model\SI-CiEnrich.ps1')
        . (Join-Path $script:SIRoot 'engine\data-model\SI-DataModelTemplates.ps1')
        $script:Model = Get-SIDataModel -Root (Join-Path $script:SIRoot 'data-model')
        function script:Write-Info { param($m) }
        function script:Write-Warn2 { param($m) }
        function script:Write-Ok { param($m) }
        $ast = [System.Management.Automation.Language.Parser]::ParseFile((Join-Path $script:SIRoot 'engine\risk-analysis\_shared\RA-ExcelReport.ps1'), [ref]$null, [ref]$null)
        $fn = $ast.Find({ param($x) $x -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $x.Name -eq 'New-RiskIndex' }, $true)
        . ([scriptblock]::Create($fn.Extent.Text))
        . (Join-Path $script:SIRoot 'engine\risk-analysis\_shared\RA-RiskIndexOrder.ps1')
        . (Join-Path $script:SIRoot 'engine\risk-analysis\_shared\RA-RiskIndexSi.ps1')
        . (Join-Path $script:SIRoot 'engine\risk-analysis\_shared\RA-FactorKeys.ps1')
        . (Join-Path $script:SIRoot 'engine\risk-analysis\_shared\RA-RiskScore.ps1')
        $global:RA_FactorAliasMap = $null; $global:RA_FactorImpactMap = $null; $global:RA_FactorCatalogFactors = $null
        $script:Index = New-RiskIndex -CsvRows @(Import-Csv -LiteralPath (Join-Path $script:SIRoot 'risk-analysis-detection\riskscore.index.locked.csv'))
        function script:Score([int]$Tier) {
            $lvl = @('Critical - tier 0', 'High - tier 1', 'Medium - tier 2', 'Low - tier 3')[$Tier]
            $h = [ordered]@{ SecurityDomain = 'Endpoint'; Category = 'Vulnerabilities'; Subcategory = 'CVEs (Missing Updates)'; ConfigurationName = 'Update vulnerable software'
                ConfigurationId = 'CVE-2026-0001'; SecuritySeverity = 'High'; CriticalityTier = $Tier; CriticalityTierLevel = $lvl; AssetName = "pc-t$Tier"
                RiskFactor_Probability = 0; RiskFactor_Probability_Detailed = '' }
            $ProgressPreference = 'SilentlyContinue'
            @(Calculate-RiskScore -Rows @([pscustomobject]$h) -RiskIndex $script:Index -CategoryInputName Category -SubCategoryInputName Subcategory -ConfigurationIdInputName ConfigurationId `
                -SecuritySeverityInputName SecuritySeverity -CriticalityTierLevelInputName CriticalityTierLevel -SecurityDomainInputName SecurityDomain -ReportName 'T_Detailed')[0]
        }
    }
    It 'the privileged-logon tier (mode on) reaches the CI''s tier through the CI rule converted from the same shipped rule' {
        $all = Get-SIRuleSet -Engine endpoint -SolutionRootOverride $script:Tree 3>$null
        $rules = (ConvertTo-SICiRules -RuleSet @($all)).Rules
        $ci2 = [ordered]@{ si_class = 'device'; si_asset_name = 'pc2'; si_privileged_logon_tier = 2 }
        $ci3 = [ordered]@{ si_class = 'device'; si_asset_name = 'pc3' }
        $null = Invoke-SICiEnrichment -Cis @($ci2, $ci3) -Model $script:Model -Rules $rules -Now $script:Now
        $ci2['si_tier'] | Should -Be 2
        $ci3['si_tier'] | Should -Not -Be 2
    }
    It 'Risk Analysis takes the CI''s tier as CriticalityTier (the CVE reports read si_tier)' {
        [IO.File]::ReadAllText((Join-Path $script:SIRoot 'risk-analysis-detection\RiskAnalysis_Queries_Locked.yaml')) | Should -Match 'extend CriticalityTier = toint\(si_tier\)'
    }
    It 'the same CVE ranks ABOVE on the Tier 2 device: the risk score (asset base by tier) and the KPI weight (SI_RiskReport_TierMultiplier_T2 1.0 vs _T3 0.5)' {
        $t2 = Score 2; $t3 = Score 3
        [double]$t2.RiskScoreTotal | Should -BeGreaterThan ([double]$t3.RiskScoreTotal)
        [double]$t2.RiskConsequenceScore | Should -BeGreaterThan ([double]$t3.RiskConsequenceScore)
        [int]$t2.RiskScoreDomainKPI | Should -BeGreaterThan ([int]$t3.RiskScoreDomainKPI)
    }
}

Describe '#1227 -- a gap of this source never breaks the run (live 2026-11-12: one failed read made every 3.1.10+ run partial)' {
    BeforeAll {
        $script:Enrich = [IO.File]::ReadAllText((Join-Path $script:SIRoot 'engine\asset-profiling\stages\Invoke-Enrich.ps1'))
        $script:PlSrc = [IO.File]::ReadAllText((Join-Path $script:SIRoot 'engine\asset-profiling\shared\SI-PrivilegedLogon.ps1'))
    }
    It 'the source raises no run issue at all -- every gap is a scoped note with a stable code' {
        $fn = [regex]::Match($script:PlSrc, '(?s)function Get-SIBulkPrivilegedLogons \{.*?\n\}').Value
        $fn | Should -Not -BeNullOrEmpty
        $fn | Should -Not -Match 'Add-SIEnrichIssue'
        foreach ($c in 'si-col-0504', 'si-col-0503', 'si-col-0505') { $fn | Should -Match ([regex]::Escape("'$c'")) }
    }
    It 'Enrich: a throw in the read is a scoped note that names the part -- never Add-SIEnrichIssue (which makes the step INCOMPLETE)' {
        $blk = [regex]::Match($script:Enrich, '(?s)if \(\$privLogonAsked\) \{ try \{.*?\} catch \{.*?\} \}').Value
        $blk | Should -Not -BeNullOrEmpty
        $catch = $blk.Substring($blk.LastIndexOf('} catch {'))
        $catch | Should -Not -Match 'Add-SIEnrichIssue'
        $catch | Should -Match "Write-SIPrivilegedLogonNote -Code 'si-col-0502'"
        $catch | Should -Match 'SI_PrivilegedLogonPart'
        $catch | Should -Match '\$privLogonByDevice = @\{\}' -Because 'every device is then stamped UNKNOWN by the row loop'
    }
    It 'a note is one warning line with its code, kept in the scoped notes, never in the run issues' {
        $global:SI_EnrichScopedNotes = $null; $script:Issues.Clear()
        Write-SIPrivilegedLogonNote -Code 'si-col-0502' -Text 'The privileged logons were not read.' 3>$null
        @($global:SI_EnrichScopedNotes) | Should -Be @('The privileged logons were not read. [si-col-0502]')
        $script:Issues.Count | Should -Be 0
    }
    It 'Invardia (2): after a throw the map is EMPTY and every device the run asked for is stamped UNKNOWN on its row -- never "no privileged logon"' {
        # the row loop: a device without an entry, when the logons were asked, gets the UNKNOWN status and no tier
        $script:Enrich | Should -Match "if \(\`$privLogonAsked\) \{\s+\`$pe = \`$privLogonByDevice\[\`$devKey\]\s+if \(\`$null -eq \`$pe\) \{ \`$pe = @\{ PrivilegedLogonComputedTier = \`$null; PrivilegedLogonTier = \`$null; PrivilegedLogons = @\(\); PrivilegedLogonStatus = 'unknown -- the device logons could not be read this run'"
        # and the catch empties the map (so EVERY device takes that branch)
        $blk = [regex]::Match($script:Enrich, '(?s)if \(\$privLogonAsked\) \{ try \{.*?\} catch \{.*?\} finally \{.*?\} \}').Value
        $blk | Should -Match '\$privLogonByDevice = @\{\}'
    }
    It 'Invardia (3): the part is reset before the block and cleared after it (finally)' {
        $blk = [regex]::Match($script:Enrich, '(?s)if \(\$privLogonAsked\) \{ try \{.*?\} catch \{.*?\} finally \{.*?\} \}').Value
        $blk | Should -Not -BeNullOrEmpty
        $blk | Should -Match '(?s)try \{.*?\$global:SI_PrivilegedLogonPart = \$null\s+\$global:SI_PrivilegedLogonPart = ''listing'
        $blk | Should -Match '\} finally \{ \$global:SI_PrivilegedLogonPart = \$null \} \}$'
    }
    It 'Invardia (1): a note''s catalogue code reaches the run report (Reports[]) -- the catalogue knows every code' {
        . (Join-Path $script:SIRoot 'engine\_shared\SI-UplinkCauses.ps1')
        foreach ($c in 'si-col-0502', 'si-col-0503', 'si-col-0504', 'si-col-0505') {
            $it = @(ConvertTo-SIUplinkFailureItem -Code $c -Job 'endpoint' -Step 'privileged-logons' -Text 'x' -Identified)
            $it.Count | Should -Be 1 -Because "$c must be in data-model\errors.locked.json, else the item is dropped"
            $it[0].Code | Should -Be $c; $it[0].Report | Should -Be 'endpoint-privileged-logons'
        }
        $cat = Get-Content -Raw (Join-Path $script:SIRoot 'data-model\errors.locked.json') | ConvertFrom-Json
        @($cat | Where-Object { $_.code -eq 'si-col-0502' })[0].opensTicket | Should -BeTrue -Because 'the read failure is an SI defect: one fix request'
        # the note records its code once per process
        $global:SI_RunNoteCodes = $null
        Write-SIPrivilegedLogonNote -Code 'si-col-0502' -Text 'a' 3>$null; Write-SIPrivilegedLogonNote -Code 'si-col-0502' -Text 'b' 3>$null
        $global:SI_RunNoteCodes.Count | Should -Be 1 -Because 'once per code (never @( ) around a List[object]: it throws on pwsh 7.6)'
        $global:SI_RunNoteCodes[0].Step | Should -Be 'privileged-logons'
        # the run report adds them
        $send = [IO.File]::ReadAllText((Join-Path $script:SIRoot 'engine\_shared\SI-TelemetrySend.ps1'))
        $send | Should -Match 'foreach \(\$n in @\(\$global:SI_RunNoteCodes'
        $send | Should -Match 'ConvertTo-SIUplinkFailureItem -Code \(\[string\]\$n\.Code\)'
        $global:SI_RunNoteCodes = $null
    }
    It '#1223 THE LIVE FAILURE: the identity rows arrive as a List[object] (as Get-SIPrivilegedIdentities built them) -- the read works' {
        # pwsh 7.6 / .NET 10: @( ) around a List[object] throws "Argument types do not match"; live 2026-11-12 at every 3.1.10+
        # install the caller did @(@($pi.Rows) | ...). The rows are now piped (and the producer returns an array).
        $rows = New-Object System.Collections.Generic.List[object]
        foreach ($x in $script:Identities) { $rows.Add($x) }
        $ids = { @{ Complete = $true; Missing = $false; Rows = $rows } }.GetNewClosure()
        $script:FailIf = $null; $global:SI_RunNoteCodes = $null
        $r = Run @((Ev $script:Dev1 $script:AdminSid 'RemoteInteractive' 2)) -Ids $ids
        $r.ByDevice[$script:Dev1].PrivilegedLogonTier | Should -Be 0
        $r.ByDevice[$script:Dev1].PrivilegedLogonStatus | Should -Be 'read'
        ($null -eq $global:SI_RunNoteCodes -or $global:SI_RunNoteCodes.Count -eq 0) | Should -BeTrue -Because 'no note: the read worked'
    }
    It '#1223: the producer returns the identity rows as a plain array, never a List[object]' {
        $script:PlSrc | Should -Match '\$out\.Rows = \$out\.Rows\.ToArray\(\)\s+return \$out'
        $script:PlSrc | Should -Not -Match '@\(@\(\$pi\.Rows\)'
    }
    It 'a throw inside the read names the part it happened in (the part is set before each step)' {
        $global:SI_PrivilegedLogonPart = $null
        $boom = { param($kql) throw 'Argument types do not match' }
        # the hunting answer throws -> the read of that list is not Ok -> a scoped PARTIAL note, the part was the Defender read
        $r = Get-SIBulkPrivilegedLogons -MdeDeviceIds @($script:Dev1) -Now $script:Now -Query $boom -PrivilegedIdentities $script:IdOk -Settings (Settings) 3>$null
        $r.ByDevice[$script:Dev1].PrivilegedLogonStatus | Should -Match '^unknown -- '
        "$global:SI_PrivilegedLogonPart" | Should -Not -BeNullOrEmpty
        foreach ($p in 'reading the Tier 0-2 accounts', 'reading the stored sign-ins', 'reading the sign-ins from Defender', 'combining the sign-ins Defender returned', 'saving the sign-ins', "working out each device''s tier") {
            $script:PlSrc | Should -Match ([regex]::Escape("SI_PrivilegedLogonPart = '$p'"))
        }
    }
}

Describe 'WIRING -- the sources reach the device tier through the existing paths' {
    BeforeAll {
        $script:Enrich = [IO.File]::ReadAllText((Join-Path $script:SIRoot 'engine\asset-profiling\stages\Invoke-Enrich.ps1'))
        $script:Row = [IO.File]::ReadAllText((Join-Path $script:SIRoot 'engine\asset-profiling\shared\Build-EndpointProfileRow.ps1'))
        $script:Schema = Get-Content -Raw (Join-Path $script:SIRoot 'asset-profiling-schema\endpoint.schema.locked.json') | ConvertFrom-Json
        $script:Catalog = Get-Content -Raw (Join-Path $script:SIRoot 'config\settings.catalog.locked.json') | ConvertFrom-Json
    }
    It 'Enrich reads once per part with the settings, the run id, the state store and the primary users, and stamps every device it asked for' {
        $script:Enrich | Should -Match "shared\\SI-PrivilegedLogon\.ps1"
        $script:Enrich | Should -Match 'New-SIPrivilegedLogonBlobStore -StorageContext \$RunContext\.StorageContext'
        $script:Enrich | Should -Match 'Get-SIBulkPrivilegedLogons -MdeDeviceIds \$deviceIds\.ToArray\(\) -RunId \(\[string\]\$RunContext\.RunId\) -Store \$plStore -PrimaryUsers \$plPrimary -Settings \$plSettings'
        $script:Enrich | Should -Match "foreach \(\`$pk in 'PrivilegedLogonTier', 'PrivilegedLogonComputedTier', 'PrivilegedLogons', 'PrivilegedLogonStatus', 'PrivilegedLogonEvidence'\)"
    }
    It 'the kind is registered in the engine and in the web app''s rule editor' {
        (Get-SIKindRegistry)['privilegedLogonTier'] | Should -Be 'Test-SIKind_privilegedLogonTier'
        [IO.File]::ReadAllText((Join-Path $script:SIRoot 'pro-management\src\SI.Management.Web\Changes\DocumentValidator.cs')) | Should -Match '"privilegedLogonTier"'
        [IO.File]::ReadAllText((Join-Path $script:SIRoot 'pro-management\src\SI.Management.Web\Pages\Rules\RuleForm.cs')) | Should -Match '\["privilegedLogonTier"\] = \["tierValues"\]'
    }
    It 'the profile row carries the columns and hands the claim to the tier attribution' {
        foreach ($c in 'PrivilegedLogonTier', 'PrivilegedLogonComputedTier', 'PrivilegedLogonEvidence', 'PrivilegedLogons', 'PrivilegedLogonStatus', 'MostFrequentUserComputedTier') {
            @($script:Schema.fields | Where-Object { $_.name -eq $c }).Count | Should -Be 1 -Because $c
            $script:Row | Should -Match ([regex]::Escape("'$c'")) -Because $c
        }
        $script:Row | Should -Match "\`$tierSourcesForAttribution\['PrivilegedLogonTier'\]"
    }
    It 'every setting is in the settings catalog (Community edition: Pro and Community alike), with its default words' {
        foreach ($n in $script:SettingNames) { @($script:Catalog.settings | Where-Object { $_.name -eq $n }).Count | Should -Be 1 -Because $n }
        @($script:Catalog.settings | Where-Object { $_.name -like 'SI_Endpoint_PrivilegedLogon*' -or $_.name -eq 'SI_Endpoint_MostFrequentUserTier_Mode' } | Where-Object { $_.edition -ne 'community' }).Count | Should -Be 0
    }
    It 'the CI rules convert the kind to si_privileged_logon_tier (mechanism mde.logon_user)' {
        . (Join-Path $script:SIRoot 'engine\data-model\SI-CiEnrich.ps1')
        $c = ConvertTo-SICiKindCondition -Spec ([pscustomobject]@{ kind = 'privilegedLogonTier'; tierValues = @(0) }) -RuleId 'AssetProfileByPrivilegedLogon'
        $c.field | Should -Be 'si_privileged_logon_tier'
        Get-SICiKindMechanism -Kind 'privilegedLogonTier' | Should -Be 'mde.logon_user'
    }
}

Describe 'SCALE (on demand only): 200,000 devices, tens of thousands of Tier 0-2 accounts, tens of millions of logons' -Tag 'Scale' {
    It 'the query count follows the account lists and the rows the privileged accounts x the devices they touched -- never the devices' {
        $devices = 200000; $priv = 30000; $logons = 40000000
        $rows = @(1..$priv | ForEach-Object { [pscustomobject]@{ ObjectId = ('{0:x8}-0000-4000-8000-{1:x12}' -f $_, $_); Sid = ('S-1-5-21-7-7-7-{0}' -f (100000 + $_)); Upn = "p$_@contoso.test"; Tier = [string]($_ % 3) } })
        $ids = { @{ Complete = $true; Missing = $false; Rows = $rows } }.GetNewClosure()
        $script:ScaleRows = 0
        $q = {
            param($kql)
            foreach ($s in (KqlList $kql '_sids')) {
                if ($s -notmatch '^S-1-5-21-7-7-7-(\d+)$') { continue }
                $n = [int]$Matches[1]
                foreach ($j in 0..2) {
                    $script:ScaleRows++
                    [pscustomobject]@{ DeviceId = ('c{0:x39}' -f (($n * 7 + $j * 13) % $devices)); AccountSid = $s; AccountUpn = ''; AccountObjectId = ''
                        LastLogonUtc = $script:Now.AddDays(-1).ToString('o'); LastLogonType = 'RemoteInteractive'; Counted = 2; Days = @($script:Now.AddDays(-1).ToString('yyyy-MM-dd')); Types = @('RemoteInteractive') }
                }
            }
        }
        $devIds = @(0..($devices - 1) | ForEach-Object { 'c{0:x39}' -f $_ })
        $sw = [System.Diagnostics.Stopwatch]::StartNew()
        $r = Get-SIBulkPrivilegedLogons -MdeDeviceIds $devIds -Now $script:Now -Query $q -PrivilegedIdentities $ids -Settings (Settings)
        $sw.Stop()
        Write-Host ('SCALE: {0:N0} devices, {1:N0} Tier 0-2 accounts, {2:N0} logons in the window -> {3} queries, {4:N0} rows returned, {5:N0} account x device rows kept, {6:N1} s' -f $devices, $priv, $logons, $r.Queries, $script:ScaleRows, $r.StateRows, $sw.Elapsed.TotalSeconds)
        $r.Queries | Should -BeLessThan 100
        $script:ScaleRows | Should -Be ($priv * 3)
        $r.ByDevice.Count | Should -Be $devices
    }
}
