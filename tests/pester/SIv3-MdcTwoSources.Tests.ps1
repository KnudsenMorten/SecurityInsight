#Requires -Version 5.1
<#
    DEFENDER FOR CLOUD READ FROM TWO SOURCES (2026-11-20, priority 1 -- engine/asset-profiling/discovery/
    Get-SIMdcAssessmentSources.ps1).

    Live 2026-11-20: since about 2026-11-10 Azure Resource Graph returns 0 `microsoft.security/assessments` rows for many
    free-plan subscriptions while the ARM assessments API still returns them (6 installs); at other installs Resource Graph
    holds MORE than the API. SecurityInsight read Resource Graph only and took 0 rows as "complete, nothing there".

    What these tests keep true (OFFLINE -- both reads are seams):
      * UNION per assessment (key = the resource id + the assessment name): one in both is kept once (the newer status
        change wins); a resource only the API has is kept; a resource only Resource Graph has is kept;
      * the ARM API is read per subscription to its end (nextLink);
      * a subscription whose API read answers 500 (or any 4xx/5xx) makes the read INCOMPLETE -- the pull is recorded
        incomplete, never "0 = nothing there"; what was read is still kept;
      * the summary capture and the exposure capture give the SAME record parts as before (the shape is unchanged);
      * a row without a severity takes it from Defender for Cloud's assessment catalogue;
      * the data-health check judges the COMBINED data: Resource Graph 0 + the API with rows is said as a source-read gap,
        and the check's rows are the API's;
      * REST only, no PowerShell module.
    PS 7 (v3 gate).
#>

BeforeAll {
    $script:SIRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
    . (Join-Path $script:SIRoot 'engine\data-model\SI-RecordCapture.ps1')
    . (Join-Path $script:SIRoot 'engine\data-model\SI-DataModelTemplates.ps1')
    . (Join-Path $script:SIRoot 'engine\asset-profiling\discovery\Get-SIMdcExposure.ps1')
    . (Join-Path $script:SIRoot 'engine\asset-profiling\discovery\Get-SIMdcAssessmentSummary.ps1')
    $script:Model = Get-SIDataModel
    $script:Base = 'https://management.azure.com'
    $script:Vm1 = '/subscriptions/s1/resourcegroups/rg/providers/microsoft.compute/virtualmachines/vm1'
    $script:Vm2 = '/subscriptions/s1/resourcegroups/rg/providers/microsoft.compute/virtualmachines/vm2'
    $script:Kv9 = '/subscriptions/s2/resourcegroups/rg/providers/microsoft.keyvault/vaults/kv9'
    # one assessment as the ARM API returns it (resourceDetails.Id as the API writes it)
    function script:ApiA([string]$Res, [string]$Key, [string]$Status = 'Unhealthy', [string]$Sev = 'High', [string]$Name = 'Some assessment', [string]$Changed = '2026-10-22T08:00:00Z', [switch]$NoMeta) {
        $p = [ordered]@{ resourceDetails = [pscustomobject]@{ Source = 'Azure'; Id = $Res }; displayName = $Name
                         status = [pscustomobject]@{ code = $Status; firstEvaluationDate = '2026-01-05T00:00:00Z'; statusChangeDate = $Changed } }
        if (-not $NoMeta) { $p['metadata'] = [pscustomobject]@{ severity = $Sev } }
        [pscustomobject]@{ id = "$Res/providers/Microsoft.Security/assessments/$Key"; name = $Key; type = 'Microsoft.Security/assessments'; properties = [pscustomobject]$p }
    }
    # one assessment as the Resource Graph query (Get-SIMdcAssessmentRowsKql) returns it
    function script:ArgA([string]$Res, [string]$Key, [string]$Status = 'Unhealthy', [string]$Sev = 'High', [string]$Name = 'Some assessment', [string]$Changed = '2026-10-22T08:00:00Z', [string]$Sub = 's1') {
        [pscustomobject]@{ ResourceId = $Res; AssessmentKey = $Key; Status = $Status; Severity = $Sev; DisplayName = $Name; FirstEvaluated = '2026-01-05T00:00:00Z'; StatusChanged = $Changed; SubscriptionId = $Sub }
    }
    function script:AssessUri([string]$Sub) { '{0}/subscriptions/{1}/providers/Microsoft.Security/assessments?api-version=2021-06-01' -f $script:Base, $Sub }
    # the fake ARM: Uri -> page; a Uri in $script:Fail throws as the REST client does
    $script:Pages = @{}; $script:Fail = @{}; $script:Asked = New-Object System.Collections.Generic.List[string]
    $script:Get = {
        param([string]$Uri)
        $script:Asked.Add($Uri)
        if ($script:Fail.ContainsKey($Uri)) { throw ('Defender for Cloud assessments API failed. HTTP Status: {0} (InternalServerError) Response: {{}}' -f $script:Fail[$Uri]) }
        if ($script:Pages.ContainsKey($Uri)) { return $script:Pages[$Uri] }
        [pscustomobject]@{ value = @() }
    }
}

Describe 'the two sources are combined per assessment' {
    BeforeEach { $script:Pages = @{}; $script:Fail = @{}; $script:Asked.Clear() }
    It 'UNION: one assessment in both is kept once (the newer status change wins); each source''s own ones are kept' {
        $script:Pages[(AssessUri 's1')] = [pscustomobject]@{ value = @((ApiA $script:Vm1 'AAA' 'Healthy' 'High' 'a' '2026-11-01T00:00:00Z'), (ApiA $script:Vm1 'BBB')) }
        $graph = { param($q) @((ArgA $script:Vm1 'aaa' 'Unhealthy' 'High' 'a' '2026-10-01T00:00:00Z'), (ArgA $script:Vm2 'ccc')) }
        $r = Get-SIMdcAssessmentRows -SubscriptionIds 's1' -GraphQuery $graph -ArmGet $script:Get
        $r.Complete | Should -BeTrue
        @($r.Rows).Count | Should -Be 3 -Because 'vm1/aaa once, vm1/bbb from the API, vm2/ccc from Resource Graph'
        $a = @($r.Rows | Where-Object { $_.ResourceId -eq $script:Vm1 -and $_.AssessmentKey -eq 'aaa' })
        $a.Count | Should -Be 1
        $a[0].Status | Should -Be 'Healthy' -Because 'the API''s row changed later'
        @($r.Rows | ForEach-Object { $_.ResourceId + '|' + $_.AssessmentKey }) | Should -Be @("$($script:Vm1)|aaa", "$($script:Vm1)|bbb", "$($script:Vm2)|ccc")
    }
    It 'API-only rows are kept: Resource Graph answers 0, the API has them -- complete, and the gap is said' {
        $script:Pages[(AssessUri 's1')] = [pscustomobject]@{ value = @((ApiA $script:Vm1 'k1'), (ApiA $script:Vm1 'k2' 'Healthy')) }
        $r = Get-SIMdcAssessmentRows -SubscriptionIds 's1' -GraphQuery { param($q) @() } -ArmGet $script:Get
        $r.Complete | Should -BeTrue
        @($r.Rows).Count | Should -Be 2
        $r.GraphCount | Should -Be 0; $r.ApiCount | Should -Be 2
        @($r.GraphEmptySubscriptions) | Should -Be @('s1')
        Format-SIMdcSourceGapText -Subscriptions $r.GraphEmptySubscriptions | Should -Match '^Resource Graph no longer returns Defender for Cloud assessments for 1 subscription\(s\)'
        Format-SIMdcSourceGapText -Subscriptions @() | Should -Be ''
    }
    It 'Resource-Graph-only rows are kept: the API holds fewer -- never fewer rows than either source' {
        $script:Pages[(AssessUri 's1')] = [pscustomobject]@{ value = @((ApiA $script:Vm1 'k1')) }
        $graph = { param($q) @((ArgA $script:Vm1 'k1'), (ArgA $script:Vm1 'k2'), (ArgA $script:Vm2 'k3')) }
        $r = Get-SIMdcAssessmentRows -SubscriptionIds 's1' -GraphQuery $graph -ArmGet $script:Get
        @($r.Rows).Count | Should -Be 3
        @($r.GraphEmptySubscriptions).Count | Should -Be 0
    }
    It 'the API is read to its end: every nextLink page' {
        $next1 = '{0}/subscriptions/s1/providers/Microsoft.Security/assessments?api-version=2021-06-01&$skipToken=p2' -f $script:Base
        $next2 = '{0}/subscriptions/s1/providers/Microsoft.Security/assessments?api-version=2021-06-01&$skipToken=p3' -f $script:Base
        $script:Pages[(AssessUri 's1')] = [pscustomobject]@{ value = @((ApiA $script:Vm1 'p1')); nextLink = $next1 }
        $script:Pages[$next1] = [pscustomobject]@{ value = @((ApiA $script:Vm1 'p2')); nextLink = $next2 }
        $script:Pages[$next2] = [pscustomobject]@{ value = @((ApiA $script:Vm2 'p3')) }
        $r = Get-SIMdcAssessmentRows -SubscriptionIds 's1' -GraphQuery { param($q) @() } -ArmGet $script:Get
        $r.Complete | Should -BeTrue
        @($r.Rows.AssessmentKey) | Should -Be @('p1', 'p2', 'p3')
        @($script:Asked) | Should -Be @((AssessUri 's1'), $next1, $next2)
    }
    It 'a nextLink handed back twice is a read that cannot finish -- incomplete, never a loop' {
        $script:Pages[(AssessUri 's1')] = [pscustomobject]@{ value = @((ApiA $script:Vm1 'p1')); nextLink = (AssessUri 's1') }
        $r = Read-SIMdcArmAssessments -SubscriptionIds 's1' -Get $script:Get
        $r.Complete | Should -BeFalse
    }
    It 'a 500 on ONE subscription that Resource Graph has no rows for = INCOMPLETE (named), never "0 = nothing there"; the rows read are kept' {
        $script:Pages[(AssessUri 's1')] = [pscustomobject]@{ value = @((ApiA $script:Vm1 'k1')) }
        $script:Fail[(AssessUri 's2')] = 500
        $r = Get-SIMdcAssessmentRows -SubscriptionIds @('s1', 's2') -GraphQuery { param($q) @() } -ArmGet $script:Get
        $r.Complete | Should -BeFalse
        $r.Error | Should -Match 'did not answer for subscription s2 and Resource Graph has no rows for it -- unknown, not "nothing there" \(.*HTTP Status: 500'
        @($r.Rows).Count | Should -Be 1
    }
    It 'a 403 is incomplete too; a Resource Graph read that fails is incomplete even when the API answered' {
        $script:Fail[(AssessUri 's1')] = 403
        (Get-SIMdcAssessmentRows -SubscriptionIds 's1' -GraphQuery { param($q) @() } -ArmGet $script:Get).Complete | Should -BeFalse
        $script:Fail = @{}
        $script:Pages[(AssessUri 's1')] = [pscustomobject]@{ value = @((ApiA $script:Vm1 'k1')) }
        $g = Get-SIMdcAssessmentRows -SubscriptionIds 's1' -GraphQuery { param($q) throw 'Resource Graph: throttled' } -ArmGet $script:Get
        $g.Complete | Should -BeFalse
        $g.Error | Should -Match 'throttled'
        @($g.Rows).Count | Should -Be 1 -Because 'what the API answered is still kept'
    }
    It 'no subscription given: every readable subscription is listed (Disabled left out) and read' {
        $script:Pages['https://management.azure.com/subscriptions?api-version=2022-12-01'] = [pscustomobject]@{ value = @(
            [pscustomobject]@{ subscriptionId = 'S1'; state = 'Enabled' }, [pscustomobject]@{ subscriptionId = 's3'; state = 'Disabled' }) }
        $script:Pages[(AssessUri 's1')] = [pscustomobject]@{ value = @((ApiA $script:Vm1 'k1')) }
        $r = Read-SIMdcArmAssessments -Get $script:Get
        @($r.Subscriptions) | Should -Be @('s1')
        @($r.Rows).Count | Should -Be 1
        $script:Asked | Should -Not -Contain (AssessUri 's3')
    }
    It 'the subscriptions cannot be listed = incomplete' {
        $script:Fail['https://management.azure.com/subscriptions?api-version=2022-12-01'] = 500
        (Read-SIMdcArmAssessments -Get $script:Get).Complete | Should -BeFalse
    }
    It 'a row without a severity takes it from Defender for Cloud''s assessment catalogue' {
        $script:Pages[(AssessUri 's1')] = [pscustomobject]@{ value = @((ApiA $script:Vm1 'k1' -NoMeta)) }
        $script:Pages['https://management.azure.com/providers/Microsoft.Security/assessmentMetadata?api-version=2021-06-01'] = [pscustomobject]@{ value = @(
            [pscustomobject]@{ name = 'K1'; properties = [pscustomobject]@{ severity = 'Medium' } }) }
        $r = Get-SIMdcAssessmentRows -SubscriptionIds 's1' -GraphQuery { param($q) @() } -ArmGet $script:Get
        @($r.Rows)[0].Severity | Should -Be 'Medium'
        $r.Note | Should -Be ''
    }
}

Describe 'per subscription: a release never makes a working install worse' {
    # live 2026-11-20 (one install): Resource Graph alone works today, some subscriptions answer the API with 500
    BeforeEach { $null = Reset-SIRecordCapture -Engine azure -Clear; $script:Pages = @{}; $script:Fail = @{}; $script:Asked.Clear() }
    It 'API 500 + Resource Graph rows for that subscription = COMPLETE with Resource Graph''s rows and ONE warning naming it' {
        $script:Fail[(AssessUri 's2')] = 500
        $graph = { param($q) @((ArgA $script:Kv9 'k9' 'Unhealthy' 'High' 'n' '2026-10-22T08:00:00Z' 's2')) }
        $r = Get-SIMdcAssessmentRows -SubscriptionIds 's2' -GraphQuery $graph -ArmGet $script:Get
        $r.Complete | Should -BeTrue -Because 'exactly the behaviour before the API was read'
        $r.Error | Should -Be ''
        @($r.Rows).Count | Should -Be 1
        @($r.Warnings).Count | Should -Be 1
        @($r.Warnings)[0] | Should -Match '^Defender for Cloud assessments API did not answer for subscription s2 \(.*HTTP Status: 500.*\) -- Resource Graph''s rows are that subscription''s answer'
        # the summary capture: not a hold -- the pull is complete and the warning is said once
        $all = @(Invoke-SIMdcAssessmentSummaryCapture -SubscriptionIds 's2' -GraphQuery $graph -ArmGet $script:Get 3>&1)
        $w = @($all | Where-Object { $_ -is [System.Management.Automation.WarningRecord] })
        @($all | Where-Object { $_ -isnot [System.Management.Automation.WarningRecord] }) | Should -Be @(1)
        $global:SIRecordCaptureState.Pulls['mdc'].Complete | Should -BeTrue
        @($w | Where-Object { "$_" -match 'did not answer for subscription s2' }).Count | Should -Be 1
    }
    It 'API 500 + Resource Graph 0 rows for that subscription = INCOMPLETE (unknown, never "nothing there")' {
        $script:Fail[(AssessUri 's2')] = 500
        $r = Get-SIMdcAssessmentRows -SubscriptionIds 's2' -GraphQuery { param($q) @() } -ArmGet $script:Get
        $r.Complete | Should -BeFalse
        @($r.Warnings).Count | Should -Be 0
        $null = Invoke-SIMdcAssessmentSummaryCapture -SubscriptionIds 's2' -GraphQuery { param($q) @() } -ArmGet $script:Get 3>$null
        $global:SIRecordCaptureState.Pulls['mdc'].Complete | Should -BeFalse
    }
    It 'a mix: s1 answered (union), s2 failed with Resource Graph rows (warned), s3 failed with none (incomplete)' {
        $script:Pages[(AssessUri 's1')] = [pscustomobject]@{ value = @((ApiA $script:Vm1 'k1')) }
        $script:Fail[(AssessUri 's2')] = 500
        $script:Fail[(AssessUri 's3')] = 503
        $graph = { param($q) @((ArgA $script:Vm2 'k2' 'Unhealthy' 'High' 'n' '2026-10-22T08:00:00Z' 's1'), (ArgA $script:Kv9 'k9' 'Unhealthy' 'High' 'n' '2026-10-22T08:00:00Z' 's2')) }
        $r = Get-SIMdcAssessmentRows -SubscriptionIds @('s1', 's2', 's3') -GraphQuery $graph -ArmGet $script:Get
        $r.Complete | Should -BeFalse -Because 's3 is unknown'
        $r.Error | Should -Match 'subscription s3 and Resource Graph has no rows'
        $r.Error | Should -Not -Match 'subscription s2'
        @($r.Warnings).Count | Should -Be 1
        @($r.Warnings)[0] | Should -Match 'subscription s2'
        @($r.Rows).Count | Should -Be 3 -Because 's1''s API row, s1''s and s2''s Resource Graph rows'
        # without s3: complete
        $ok = Get-SIMdcAssessmentRows -SubscriptionIds @('s1', 's2') -GraphQuery $graph -ArmGet $script:Get
        $ok.Complete | Should -BeTrue
        @($ok.Warnings).Count | Should -Be 1
    }
    It 'a failed Resource Graph read never vouches for a subscription the API failed for' {
        $script:Fail[(AssessUri 's2')] = 500
        $r = Get-SIMdcAssessmentRows -SubscriptionIds 's2' -GraphQuery { param($q) throw 'Resource Graph: throttled' } -ArmGet $script:Get
        $r.Complete | Should -BeFalse
    }
    It 'data health follows the same rule: it reads the same result and says the warning' {
        $t = [IO.File]::ReadAllText((Join-Path $script:SIRoot 'engine\data-health\Invoke-SIDataHealth.ps1'))
        $t | Should -Match ([regex]::Escape("foreach (`$w in @(`$read.Warnings)) { if (`$w) { & `$log 'WARN' ([string]`$w) } }"))
        $t.IndexOf('$read = Get-SIMdcAssessmentRows -NoCache') | Should -BeLessThan $t.IndexOf("if (-not `$read.Complete) { throw")
    }
}

Describe 'the callers keep their shape' {
    BeforeEach { $null = Reset-SIRecordCapture -Engine azure -Clear; $script:Pages = @{}; $script:Fail = @{}; $script:Asked.Clear() }
    It 'the summary capture: an API-only resource becomes the same mdc record as a Resource Graph summary did' {
        $script:Pages[(AssessUri 's1')] = [pscustomobject]@{ value = @((ApiA $script:Vm1 'key-h' 'Unhealthy' 'High' 'Management ports should be closed on your virtual machines'),
            (ApiA $script:Vm1 'key-m' 'Unhealthy' 'Medium' 'Machines should have a vulnerability assessment solution'), (ApiA $script:Vm1 'key-ok' 'Healthy' 'Low')) }
        $n = Invoke-SIMdcAssessmentSummaryCapture -SubscriptionIds 's1' -GraphQuery { param($q) @() } -ArmGet $script:Get 3>$null
        $n | Should -Be 1
        $res = ConvertTo-SIRecordRows -Captured @(Get-SICapturedRecords) -Model $script:Model
        @($res.Errors) | Should -BeNullOrEmpty
        $r = @($res.Rows)[0]
        $r.si_record_key | Should -Be ('mdc:' + $script:Vm1)
        ($r.si_mdc_assessed_count, $r.si_mdc_unhealthy_count, $r.si_mdc_high_count, $r.si_mdc_medium_count, $r.si_mdc_low_count) | Should -Be @(3, 2, 1, 1, 0)
        @($r.si_mdc_top) | Should -Be @('key-h -- Management ports should be closed on your virtual machines (High)', 'key-m -- Machines should have a vulnerability assessment solution (Medium)')
        $global:SIRecordCaptureState.Pulls['mdc'].Complete | Should -BeTrue
    }
    It 'the summary capture: a 500 on a subscription records the pull INCOMPLETE and keeps what was read' {
        $script:Pages[(AssessUri 's1')] = [pscustomobject]@{ value = @((ApiA $script:Vm1 'k1')) }
        $script:Fail[(AssessUri 's2')] = 500
        $n = Invoke-SIMdcAssessmentSummaryCapture -SubscriptionIds @('s1', 's2') -GraphQuery { param($q) @() } -ArmGet $script:Get 3>$null
        $n | Should -Be 1
        $global:SIRecordCaptureState.Pulls['mdc'].Complete | Should -BeFalse
    }
    It 'the exposure capture: an Unhealthy internet-exposure assessment from the API alone is an exposed resource' {
        $script:Pages[(AssessUri 's1')] = [pscustomobject]@{ value = @((ApiA $script:Vm1 '22730e10-96f6-4aac-ad84-9383d35b5917' 'Unhealthy' 'High' 'Management ports should be closed on your virtual machines'),
            (ApiA $script:Vm2 'x' 'Unhealthy' 'Low' 'Disks should be encrypted'), (ApiA $script:Kv9 'y' 'Healthy' 'Low' 'Internet access should be restricted')) }
        $n = Invoke-SIMdcExposureCapture -SubscriptionIds 's1' -GraphQuery { param($q) @() } -ArmGet $script:Get 3>$null
        $n | Should -Be 1 -Because 'vm2 is not an exposure assessment and kv9''s is Healthy'
        $res = ConvertTo-SIRecordRows -Captured @(Get-SICapturedRecords) -Model $script:Model
        @($res.Rows)[0].azure_resource_id | Should -Be $script:Vm1
        @($res.Rows)[0].si_internet_exposed | Should -BeTrue
        $global:SIRecordCaptureState.Pulls['mdc'].Complete | Should -BeTrue
    }
    It 'the exposure capture: an incomplete read is said and the pull incomplete' {
        $script:Fail[(AssessUri 's1')] = 500
        $null = Invoke-SIMdcExposureCapture -SubscriptionIds 's1' -GraphQuery { param($q) @() } -ArmGet $script:Get -WarningAction SilentlyContinue
        $global:SIRecordCaptureState.Pulls['mdc'].Complete | Should -BeFalse
    }
    It 'the summary rows have the Resource Graph summary''s shape' {
        $rows = @((ArgA $script:Vm1 'a' 'Unhealthy' 'High'), (ArgA $script:Vm1 'b' 'Unhealthy' 'Low'), (ArgA $script:Vm1 'c' 'Healthy'), (ArgA $script:Vm2 'd' 'Healthy'))
        $s = ConvertTo-SIMdcAssessmentSummaryRows -Rows $rows
        $s.Count | Should -Be 2
        ($s[0].Assessed, $s[0].Unhealthy, $s[0].High, $s[0].Low) | Should -Be @(3, 2, 1, 1)
        @($s[0].TopHigh.id) | Should -Be @('a'); @($s[0].TopLow.id) | Should -Be @('b')
        ($s[1].Assessed, $s[1].Unhealthy) | Should -Be @(1, 0)
        $o = ConvertTo-SIMdcAssessmentObjects -Rows $s; $o.Count | Should -Be 2
    }
}

Describe 'the data-health check judges the combined data' {
    It 'its mdc rows come from the combined read: Resource Graph 0 + the API''s rows is no empty source' {
        $rows = @((ArgA $script:Vm1 'a' 'Unhealthy' 'High' 'n' '2026-10-01T00:00:00Z'), (ArgA $script:Vm1 'b' 'Healthy' 'High' 'n' '2026-10-20T00:00:00Z'), (ArgA $script:Vm2 'c' 'Unhealthy'))
        $h = ConvertTo-SIMdcHealthRows -Rows $rows
        $h.Count | Should -Be 2
        $h[0].Unhealthy | Should -Be 1
        $h[0].Changed | Should -Be ([datetime]::new(2026, 10, 20, 0, 0, 0, [DateTimeKind]::Utc))
    }
    It 'the check is wired to the combined read, says the gap, and a read that is not whole is not a read' {
        $t = [IO.File]::ReadAllText((Join-Path $script:SIRoot 'engine\data-health\Invoke-SIDataHealth.ps1'))
        $t | Should -Match ([regex]::Escape('$read = Get-SIMdcAssessmentRows -NoCache'))
        $t | Should -Match ([regex]::Escape("if (-not `$read.Complete) { throw"))
        $t | Should -Match ([regex]::Escape('Format-SIMdcSourceGapText -Subscriptions @($read.GraphEmptySubscriptions)'))
        $t | Should -Match ([regex]::Escape('$hr = ConvertTo-SIMdcHealthRows -Rows @($read.Rows)'))
        $t | Should -Not -Match "Search-SIResourceGraph -Query \`$q\)"
    }
}

Describe 'REST only' {
    It 'no PowerShell module, the engine''s own REST client' {
        $t = [IO.File]::ReadAllText((Join-Path $script:SIRoot 'engine\asset-profiling\discovery\Get-SIMdcAssessmentSources.ps1'))
        $t | Should -Match 'Invoke-SIAzRestRequest -Method GET -Uri \$Uri'
        $t | Should -Match 'Invoke-SIArgPaged -Query \$kql'
        $t | Should -Not -Match '(?m)^[^#]*\b(Import-Module|Search-AzGraph|Get-AzSecurity|Invoke-AzRestMethod)\b'
    }
}
