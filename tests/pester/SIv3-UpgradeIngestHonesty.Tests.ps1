#Requires -Version 5.1
<#
    THE 2.2 -> 3.0 UPGRADE: A PUBLISH IS NEVER REPORTED AS WHOLE WHEN IT IS NOT, AND A 2.2 RULE IS NEVER TAKEN OVER.

    Found by the live upgrade rehearsal (2.2.460 -> 3.0.0, VM mode, Community):
      * The first 3.0 run updated each existing 2.2 data collection rule with the new columns (SI_AssetName,
        SI_AssetId) and posted at once: the rows landed, the new columns EMPTY on 134 of 134 rows -- and the run said
        success. Azure takes a while to start storing a column added to an existing rule.
      * Run health said 'success' and the run exited 0 when the Log Analytics post had FAILED ("1/2 sink(s) OK").
      * A setup-written 2.2 config named its public-IP rule 'dcr-si-publicip-profile' (feeding the 2.2 public-IP
        table); 3.0's default reuses that name for SI_PublicIP_Profile_CL, and the update rewrote the 2.2 rule.
    Covered here on the REST ingest path (SecurityInsight uses no PowerShell module). OFFLINE: every HTTP call
    goes through Invoke-SILogIngestHttp, mocked by a fake ARM / Log Analytics service.
#>

BeforeAll {
    $script:SIRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
    . (Join-Path $script:SIRoot 'engine\_shared\SI-LogIngest.ps1')
    . (Join-Path $script:SIRoot 'engine\_shared\SI-RunOutcome.ps1')

    $script:Sub = '11111111-1111-1111-1111-111111111111'
    $script:Ws  = "/subscriptions/$($script:Sub)/resourceGroups/rg-la/providers/Microsoft.OperationalInsights/workspaces/ws-si"
    $script:GlobalNames = 'SI_LogIngest_Engine', 'SI_LogIngestRunCache', 'SI_AzSubscriptionId', 'SI_WorkspaceResourceId', 'SI_DcrResourceGroup',
                          'SI_DceResourceGroup', 'SI_DceName', 'SI_LogIngestNotes', 'SI_LogIngestNewColumns', 'SI_LogIngest_NewColumnCheckSec'

    function script:Ok([object]$o) { [pscustomobject]@{ StatusCode = 200; Content = ($o | ConvertTo-Json -Depth 30 -Compress); RetryAfter = $null } }
    function script:Status([int]$c, [string]$body = '') { [pscustomobject]@{ StatusCode = $c; Content = $body; RetryAfter = $null } }
    function script:ArmKey([string]$uri) { ([uri]$uri).AbsolutePath.ToLowerInvariant().TrimEnd('/') }
    function script:Put-Arm([string]$path, $obj) { $script:Arm[$path.ToLowerInvariant()] = ($obj | ConvertTo-Json -Depth 30 | ConvertFrom-Json) }
    function script:DcrPath([string]$name) { "/subscriptions/$($script:Sub)/resourceGroups/rg-si/providers/Microsoft.Insights/dataCollectionRules/$name" }
    function script:New-Dcr([string]$name, [string]$table, [string[]]$cols) {
        $stream = 'Custom-' + $table + '_CL'
        [pscustomobject]@{
            id = (DcrPath $name); name = $name; location = 'westeurope'
            properties = [pscustomobject]@{
                immutableId = 'dcr-imm-old'; dataCollectionEndpointId = "/subscriptions/$($script:Sub)/resourceGroups/rg-si/providers/Microsoft.Insights/dataCollectionEndpoints/dce-si"
                streamDeclarations = [pscustomobject]@{ $stream = [pscustomobject]@{ columns = @($cols | ForEach-Object { [pscustomobject]@{ name = $_; type = 'string' } }) } }
                destinations = [pscustomobject]@{ logAnalytics = @([pscustomobject]@{ workspaceResourceId = $script:Ws; name = 'ws-si' }) }
                dataFlows = @([pscustomobject]@{ streams = @($stream); destinations = @('ws-si'); transformKql = 'source | extend TimeGenerated = now()'; outputStream = $stream })
            }
        }
    }
    # The Log Analytics answer the fake service gives: Rows + C0.. per new column.
    function script:LaAnswer([long]$rows, [long[]]$filled) {
        $cols = @(@{ name = 'Rows'; type = 'long' }) + @(for ($i = 0; $i -lt $filled.Count; $i++) { @{ name = "C$i"; type = 'long' } })
        Ok @{ tables = @(@{ name = 'PrimaryResult'; columns = $cols; rows = @(, (@($rows) + @($filled))) }) }
    }
}

Describe 'the 2.2 -> 3.0 upgrade: honest publishing' {

BeforeEach {
    $script:keep = @{}
    foreach ($n in $script:GlobalNames) { $script:keep[$n] = Get-Variable -Scope Global -Name $n -ValueOnly -ErrorAction SilentlyContinue }
    foreach ($n in $script:GlobalNames) { Remove-Variable -Scope Global -Name $n -ErrorAction SilentlyContinue }
    $global:SI_AzSubscriptionId = $script:Sub; $global:SI_WorkspaceResourceId = $script:Ws
    $global:SI_DcrResourceGroup = 'rg-si'; $global:SI_DceName = 'dce-si'
    $script:Arm = @{}
    $script:Calls = New-Object System.Collections.Generic.List[object]
    $script:La = { LaAnswer 0 @(0) }
    Put-Arm $script:Ws @{ id = $script:Ws; properties = @{ customerId = '22222222-2222-2222-2222-222222222222' } }
    Put-Arm "/subscriptions/$($script:Sub)/resourceGroups/rg-si/providers/Microsoft.Insights/dataCollectionEndpoints/dce-si" @{
        id = "/subscriptions/$($script:Sub)/resourceGroups/rg-si/providers/Microsoft.Insights/dataCollectionEndpoints/dce-si"; name = 'dce-si'; location = 'westeurope'
        properties = @{ logsIngestion = @{ endpoint = 'https://dce-si.westeurope-1.ingest.monitor.azure.com' } } }
    Mock Get-SILogIngestToken { 'tok' }
    Mock Start-Sleep { }
    Mock Write-Host { }
    Mock Invoke-SILogIngestHttp {
        $script:Calls.Add([pscustomobject]@{ Method = $Method; Uri = $Uri; Body = $Body })
        if ($Uri -like 'https://api.loganalytics.io/*') { return (& $script:La) }
        if ($Uri -like '*/dataCollectionRules/*/streams/*') { return (Status 204) }
        if ($Uri -like 'https://management.azure.com/*') {
            $k = ArmKey $Uri
            if ($Method -eq 'GET') { if ($script:Arm.ContainsKey($k)) { return (Ok $script:Arm[$k]) }; return (Status 404 '{"error":{"code":"ResourceNotFound"}}') }
            $o = $Body | ConvertFrom-Json
            if (-not $o.PSObject.Properties['id']) { $o | Add-Member -NotePropertyName id -NotePropertyValue ([uri]$Uri).AbsolutePath }
            if ($k -like '*/datacollectionrules/*' -and -not $o.properties.PSObject.Properties['immutableId']) { $o.properties | Add-Member -NotePropertyName immutableId -NotePropertyValue 'dcr-imm-new' }
            $script:Arm[$k] = $o
            return (Ok $o)
        }
        return (Status 404)
    }
}

AfterEach {
    foreach ($n in $script:GlobalNames) { Set-Variable -Scope Global -Name $n -Value $script:keep[$n] }
}

Describe 'a rule that feeds ANOTHER table is never taken over (the public-IP rule of a 2.2 setup)' {
    BeforeEach {
        # what a setup-written 2.2 install has: dcr-si-publicip-profile -> the 2.2 public-IP table
        Put-Arm (DcrPath 'dcr-si-publicip-profile') (New-Dcr 'dcr-si-publicip-profile' 'SI_VulnerabilityPIP' @('IpAddress', 'Port'))
        Put-Arm "$($script:Ws)/tables/SI_PublicIP_Profile_CL" @{ properties = @{ schema = @{ name = 'SI_PublicIP_Profile_CL'; columns = @(@{ name = 'TimeGenerated'; type = 'datetime' }, @{ name = 'IpAddress'; type = 'string' }) } } }
    }

    It 'Rest: the update is refused with a clear message, and nothing is written to the 2.2 rule' {
        $global:SI_LogIngest_Engine = 'Rest'
        { Update-SILogTableSchema -AzLogWorkspaceResourceId $script:Ws -AzAppId 'a' -AzAppSecret 's' -TenantId 't' -DceName 'dce-si' -DcrName 'dcr-si-publicip-profile' `
              -DcrResourceGroup 'rg-si' -TableName 'SI_PublicIP_Profile' -Data @([pscustomobject]@{ IpAddress = '1.2.3.4' }) -AzLogDcrTableCreateFromAnyMachine $true -AzLogDcrTableCreateFromReferenceMachine @() } |
            Should -Throw "*already sends data to SI_VulnerabilityPIP_CL*left unchanged*"
        @($script:Calls | Where-Object { $_.Method -ne 'GET' -and $_.Uri -like '*dataCollectionRules/dcr-si-publicip-profile*' }).Count | Should -Be 0
        $script:Arm[(DcrPath 'dcr-si-publicip-profile').ToLowerInvariant()].properties.dataFlows[0].outputStream | Should -Be 'Custom-SI_VulnerabilityPIP_CL'
    }

    It 'the rule update alone (Set-SILogDcr) is refused the same way -- the 2.2 rule is never rebuilt for the new table' {
        { Update-SILogTableSchema -AzLogWorkspaceResourceId $script:Ws -AzAppId 'a' -AzAppSecret 's' -TenantId 't' -DceName 'dce-si' -DcrName 'dcr-si-publicip-profile' `
              -DcrResourceGroup 'rg-si' -TableName 'SI_PublicIP_Profile' -Data @([pscustomobject]@{ IpAddress = '1.2.3.4' }) -AzLogDcrTableCreateFromAnyMachine $true -AzLogDcrTableCreateFromReferenceMachine @() } | Should -Throw '*already sends data to*'
        { Set-SILogDcr -SchemaSourceObject @(@{ name = 'IpAddress'; type = 'string' }) -AzLogWorkspaceResourceId $script:Ws -DceName 'dce-si' -DcrResourceGroup 'rg-si' `
              -DcrName 'dcr-si-publicip-profile' -TableName 'SI_PublicIP_Profile' -AzAppId 'a' -AzAppSecret 's' -TenantId 't' } | Should -Throw '*already sends data to*'
        @($script:Calls | Where-Object { $_.Method -ne 'GET' -and $_.Uri -like '*dataCollectionRules/dcr-si-publicip-profile*' }).Count | Should -Be 0
    }
    It 'the profiler picks a rule of its own (the name plus the resource group), the same name on every run, and says why' {
        $r = Resolve-SILogDcrNameForTable -DcrName 'dcr-si-publicip-profile' -DcrResourceGroup 'rg-si' -TableName 'SI_PublicIP_Profile' -WorkspaceResourceId $script:Ws -Bound @{ AzAppId = 'a'; AzAppSecret = 's'; TenantId = 't' }
        $r.Name | Should -Be 'dcr-si-publicip-profile-rg-si'
        $r.Reason | Should -Match 'already sends data to SI_VulnerabilityPIP_CL and is left unchanged'
        $r.Reason | Should -Not -Match '#\d'
        (Get-SILogAlternateDcrName -DcrName 'dcr-si-publicip-profile' -ResourceGroup 'rg-si') | Should -Be $r.Name
    }

    It 'a long resource group gives a short, stable hashed name' {
        $n = Get-SILogAlternateDcrName -DcrName 'dcr-si-publicip-profile' -ResourceGroup ('rg-' + ('x' * 60))
        $n.Length | Should -BeLessOrEqual 60
        $n | Should -Match '^dcr-si-publicip-profile-[0-9a-f]{8}$'
        (Get-SILogAlternateDcrName -DcrName 'dcr-si-publicip-profile' -ResourceGroup ('rg-' + ('x' * 60))) | Should -Be $n
    }

    It 'a rule that already feeds THIS table, or no rule at all, keeps its name' {
        Put-Arm (DcrPath 'dcr-mine') (New-Dcr 'dcr-mine' 'SI_PublicIP_Profile' @('IpAddress'))
        (Resolve-SILogDcrNameForTable -DcrName 'dcr-mine' -DcrResourceGroup 'rg-si' -TableName 'SI_PublicIP_Profile' -WorkspaceResourceId $script:Ws -Bound @{}).Name | Should -Be 'dcr-mine'
        (Resolve-SILogDcrNameForTable -DcrName 'dcr-none' -DcrResourceGroup 'rg-si' -TableName 'SI_PublicIP_Profile' -WorkspaceResourceId $script:Ws -Bound @{}).Name | Should -Be 'dcr-none'
    }

    It 'the alternate taken by yet another table too: the original name stays, so the update refuses it out loud' {
        Put-Arm (DcrPath 'dcr-si-publicip-profile-rg-si') (New-Dcr 'dcr-si-publicip-profile-rg-si' 'SI_Other' @('x'))
        (Resolve-SILogDcrNameForTable -DcrName 'dcr-si-publicip-profile' -DcrResourceGroup 'rg-si' -TableName 'SI_PublicIP_Profile' -WorkspaceResourceId $script:Ws -Bound @{}).Name | Should -Be 'dcr-si-publicip-profile'
    }

    It 'WIRING: the profilers'' output resolves the rule name before anything is created, and a refusal is a FAILED sink' {
        $src = Get-Content -Raw (Join-Path $script:SIRoot 'engine\asset-profiling\stages\Invoke-Output.ps1')
        $iResolve = $src.IndexOf('Resolve-SILogDcrNameForTable -DcrName $dcrName')
        $iResolve | Should -BeGreaterThan 0
        $iResolve | Should -BeLessThan $src.IndexOf("Write-SIInfo ('table : {0}_CL' -f `$tableName)")
        $src | Should -Match "already sends data to'\) \{ return \('FAILED: "
    }
}

Describe 'columns added to an EXISTING rule: the post checks they were stored (both engines)' {
    BeforeEach {
        Put-Arm (DcrPath 'dcr-si-endpoint-profile') (New-Dcr 'dcr-si-endpoint-profile' 'SI_Endpoint_Profile' @('Hostname', 'CollectionTime'))
        Put-Arm "$($script:Ws)/tables/SI_Endpoint_Profile_CL" @{ properties = @{ schema = @{ name = 'SI_Endpoint_Profile_CL'; columns = @(@{ name = 'TimeGenerated'; type = 'datetime' }, @{ name = 'Hostname'; type = 'string' }, @{ name = 'CollectionTime'; type = 'datetime' }) } } }
        $script:rows = @(
            [pscustomobject]@{ Hostname = 'pc1'; SI_AssetName = 'pc1'; SI_AssetId = 'id-1'; CollectionTime = [datetime]::SpecifyKind([datetime]'2026-10-04T15:28:00', 'Utc') },
            [pscustomobject]@{ Hostname = 'pc2'; SI_AssetName = 'pc2'; SI_AssetId = 'id-2'; CollectionTime = [datetime]::SpecifyKind([datetime]'2026-10-04T15:28:00', 'Utc') })
        $script:upd = @{ AzLogWorkspaceResourceId = $script:Ws; AzAppId = 'a'; AzAppSecret = 's'; TenantId = 't'; DceName = 'dce-si'; DcrName = 'dcr-si-endpoint-profile'
                         DcrResourceGroup = 'rg-si'; TableName = 'SI_Endpoint_Profile'; AzLogDcrTableCreateFromAnyMachine = $true; AzLogDcrTableCreateFromReferenceMachine = @() }
    }

    It 'Rest: Azure not yet storing them -> one warning naming the columns, and a note that makes the run partial' {
        $global:SI_LogIngest_Engine = 'Rest'
        $null = Update-SILogTableSchema @upd -Data $script:rows
        $script:La = { LaAnswer 2 @(0, 0, 2, 2) }   # both rows arrived, both new columns empty (the columns the rule had, C2 / C3, are filled) -- what the upgrade night measured
        $w = @()
        $null = Send-SILogData -DceName 'dce-si' -DcrName 'dcr-si-endpoint-profile' -TableName 'SI_Endpoint_Profile' -Data $script:rows -AzAppId 'a' -AzAppSecret 's' -TenantId 't' -WarningVariable +w -WarningAction SilentlyContinue
        @($w).Count | Should -Be 1
        [string]$w[0] | Should -Match 'SI_Endpoint_Profile_CL: the data collection rule was changed in this run.*for (SI_AssetName, SI_AssetId|SI_AssetId, SI_AssetName) are missing.*next run'
        $notes = @(Get-SILogIngestNotes)
        $notes.Count | Should -Be 1
        (Get-SIRunOutcome -StageResults @{} -IngestNotes $notes).ExitReason | Should -Be 'success-partial'
        $q = @($script:Calls | Where-Object { $_.Uri -like 'https://api.loganalytics.io/*' })
        $q.Count | Should -BeGreaterThan 0
        ($q[0].Body | ConvertFrom-Json).query | Should -Match 'SI_Endpoint_Profile_CL'
        ($q[0].Body | ConvertFrom-Json).query | Should -Match 'CollectionTime between \(datetime\(2026-10-04T15:28:00.000Z\)'
    }

    It 'Azure already storing the new columns -> no warning, no note' {
        $null = Update-SILogTableSchema @upd -Data $script:rows
        $script:La = { LaAnswer 2 @(2, 2, 2, 2) }
        $w = @()
        $null = Send-SILogData -DceName 'dce-si' -DcrName 'dcr-si-endpoint-profile' -TableName 'SI_Endpoint_Profile' -Data $script:rows -AzAppId 'a' -AzAppSecret 's' -TenantId 't' -WarningVariable +w -WarningAction SilentlyContinue
        @($w).Count | Should -Be 0
        @(Get-SILogIngestNotes).Count | Should -Be 0
    }
    It 'the check waits for the rows to arrive (Azure''s ingestion delay), then decides' {
        $global:SI_LogIngest_Engine = 'Rest'
        $null = Update-SILogTableSchema @upd -Data $script:rows
        $script:n = 0
        $script:La = { $script:n++; if ($script:n -lt 3) { LaAnswer 0 @(0, 0) } else { LaAnswer 2 @(2, 2, 2, 2) } }
        $null = Send-SILogData -DceName 'dce-si' -DcrName 'dcr-si-endpoint-profile' -TableName 'SI_Endpoint_Profile' -Data $script:rows -AzAppId 'a' -AzAppSecret 's' -TenantId 't' -WarningAction SilentlyContinue
        $script:n | Should -Be 3
        @(Get-SILogIngestNotes).Count | Should -Be 0
    }

    It 'rows that never become queryable within the window are reported as unknown, not as stored' {
        $global:SI_LogIngest_Engine = 'Rest'
        $global:SI_LogIngest_NewColumnCheckSec = 60
        $null = Update-SILogTableSchema @upd -Data $script:rows
        $script:La = { LaAnswer 0 @(0, 0) }
        $null = Send-SILogData -DceName 'dce-si' -DcrName 'dcr-si-endpoint-profile' -TableName 'SI_Endpoint_Profile' -Data $script:rows -AzAppId 'a' -AzAppSecret 's' -TenantId 't' -WarningAction SilentlyContinue
        @(Get-SILogIngestNotes).Count | Should -Be 1
        [string](Get-SILogIngestNotes)[0].Message | Should -Match 'not known whether'
    }

    It 'no column added (the rule already had them), or no value in the new columns: nothing is checked' {
        $global:SI_LogIngest_Engine = 'Rest'
        $null = Update-SILogTableSchema @upd -Data @([pscustomobject]@{ Hostname = 'pc1'; CollectionTime = [datetime]::UtcNow })
        $null = Send-SILogData -DceName 'dce-si' -DcrName 'dcr-si-endpoint-profile' -TableName 'SI_Endpoint_Profile' -Data @([pscustomobject]@{ Hostname = 'pc1' }) -AzAppId 'a' -AzAppSecret 's' -TenantId 't'
        @($script:Calls | Where-Object { $_.Uri -like 'https://api.loganalytics.io/*' }).Count | Should -Be 0
        $empty = @([pscustomobject]@{ Hostname = 'pc1'; SI_AssetName = ''; CollectionTime = [datetime]::UtcNow })
        $null = Update-SILogTableSchema @upd -Data $empty
        $null = Send-SILogData -DceName 'dce-si' -DcrName 'dcr-si-endpoint-profile' -TableName 'SI_Endpoint_Profile' -Data $empty -AzAppId 'a' -AzAppSecret 's' -TenantId 't'
        @($script:Calls | Where-Object { $_.Uri -like 'https://api.loganalytics.io/*' }).Count | Should -Be 0
    }

    It 'a NEW rule (first run of a table) is not a column change -- the existing wait for a new rule covers it' {
        $global:SI_LogIngest_Engine = 'Rest'
        $global:SI_DceResourceGroup = 'rg-si'
        $u2 = $upd.Clone(); $u2.DcrName = 'dcr-brand-new'; $u2.TableName = 'SI_Trend'
        $null = Update-SILogTableSchema @u2 -Data $script:rows
        $global:SI_LogIngestNewColumns.Count | Should -Be 0
    }

    It 'the verdict: no rows yet / a column empty on every row / every column filled' {
        (Get-SILogColumnCheckVerdict -Result ([pscustomobject]@{ Rows = 0; C0 = 0 }) -Columns 'A').Verdict | Should -Be 'not-landed'
        $v = Get-SILogColumnCheckVerdict -Result ([pscustomobject]@{ Rows = 5; C0 = 5; C1 = 0 }) -Columns 'A', 'B'
        $v.Verdict | Should -Be 'not-stored'; $v.Missing | Should -Be @('B')
        (Get-SILogColumnCheckVerdict -Result @{ Rows = 5; C0 = 1; C1 = 3 } -Columns 'A', 'B').Verdict | Should -Be 'stored'
    }
}

Describe 'a run that did not publish in full does not report success (run health + exit code)' {
    It 'Log Analytics failed, Excel written: success-partial, with the reason' {
        $o = Get-SISinkOutcome -SinkResults @{ LA = "FAILED: DCR 'dcr-x' not created in target RG after 240s"; Excel = 'C:\out\endpoint.csv' }
        $o.ExitReason | Should -Be 'success-partial'
        $o.Message | Should -Match "LA was not written \(DCR 'dcr-x' not created"
    }
    It 'every output failed: error (the run throws, so the exit code is non-zero as in 2.2)' {
        (Get-SISinkOutcome -SinkResults @{ LA = 'FAILED: connection reset' }).ExitReason | Should -Be 'error'
    }
    It 'Log Analytics asked for but not signed in (SKIPPED): not a whole publish either' {
        (Get-SISinkOutcome -SinkResults @{ LA = 'SKIPPED -- no auth configured.'; Excel = 'x.csv' }).ExitReason | Should -Be 'success-partial'
    }
    It 'nothing to write is a correct, empty publish' {
        (Get-SISinkOutcome -SinkResults @{ LA = 'skipped (no records to write)'; Excel = 'x.csv' }).ExitReason | Should -Be 'success'
        (Get-SISinkOutcome -SinkResults @{ LA = 'OK -- 3 rows'; Excel = 'x.csv' }).ExitReason | Should -Be 'success'
    }
    It 'the run outcome reads every stage: a failed sink, an INCOMPLETE publish, an ingest note -- the worst wins' {
        $st = @{ Output = [pscustomobject]@{ SinkResults = @{ LA = 'OK'; Excel = 'x' }; Summary = 'ok' }; Recommendations = [pscustomobject]@{ Summary = 'INCOMPLETE -- not published (12 read before failure)' } }
        (Get-SIRunOutcome -StageResults $st).ExitReason | Should -Be 'success-partial'
        (Get-SIRunOutcome -StageResults @{ Output = [pscustomobject]@{ SinkResults = @{ LA = 'OK' } } }).ExitReason | Should -Be 'success'
        (Get-SIRunOutcome -StageResults @{ Output = [pscustomobject]@{ SinkResults = @{ LA = 'FAILED: x' } } }).ExitReason | Should -Be 'error'
        Merge-SIExitReason 'success-partial' 'success' | Should -Be 'success-partial'
        Merge-SIExitReason 'success-partial' 'error' | Should -Be 'error'
    }
    It 'WIRING: the profiling run records that outcome in run health, and throws when nothing was published' {
        $src = Get-Content -Raw (Join-Path $script:SIRoot 'engine\asset-profiling\Invoke-SIEngineRun.ps1')
        $src | Should -Match "Get-SIRunOutcome -StageResults \`$runContext.StageResults"
        # an error outcome throws: the database failure with its own sentence, anything else as "nothing was published"
        $src | Should -Match "if \(\`$__outcome.ExitReason -eq 'error'\) \{[\s\S]{0,700}?throw \('Nothing was published: \{0\}' -f \`$__outcome.Message\)"
        $src | Should -Match "DatabaseFailed\) \{\s*throw \('The records could not be written to the database"
        $src | Should -Match '\$exitReason\s+=\s+\$__outcome.ExitReason'
        $src | Should -Match "SI-RunOutcome\.ps1"
        $src.IndexOf('$exitReason   = $__outcome.ExitReason') | Should -BeLessThan $src.IndexOf("-ExitReason `$exitReason")
    }
    It 'WIRING: no profiling or Risk Analysis launcher prints "completed successfully" over a partial run' {
        foreach ($e in 'endpoint', 'identity', 'azure', 'publicip', 'risk-analysis') {
            foreach ($k in 'community-vm', 'internal-vm') {
                $l = Get-Content -Raw (Join-Path $script:SIRoot "launcher\$e\launcher.$k.ps1")
                $l | Should -Match "if \(\`$global:SI_LastRunExitReason -eq 'success-partial'\) \{[^\r\n]*PARTIAL[^\r\n]*\} else \{ Write-Ok `"Engine completed successfully`" \}" -Because "$e $k"
            }
        }
    }
}

Describe 'Risk Analysis: a failed or incomplete publish, or a partial profile under it, is a partial run' {
    BeforeAll {
        $ra = Join-Path $script:SIRoot 'engine\risk-analysis\Invoke-RiskAnalysis.ps1'
        $ast = [System.Management.Automation.Language.Parser]::ParseFile($ra, [ref]$null, [ref]$null)
        $fn = $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq 'Send-RARunHealthEnd' }, $true) | Select-Object -First 1
        # the real function, lifted from the engine
        . ([scriptblock]::Create($fn.Extent.Text))
        $script:RaSrc = Get-Content -Raw $ra
    }
    BeforeEach {
        $script:sent = $null
        function script:Send-SIRunHealthRow { param($RunContext, $Phase, $AssetCount, $ExitReason, $ErrorMessage) $script:sent = @{ ExitReason = $ExitReason; ErrorMessage = $ErrorMessage } }
        $script:_RunHealthEndSent = $false; $script:_RABucketLossRun = $null; $script:_RAUpstreamOutcome = $null
        $script:_RAPublishFailures = New-Object System.Collections.Generic.List[string]
        $script:_RunHealthCtx = [pscustomobject]@{ RunId = 'r' }
    }
    It 'a Log Analytics post that failed: success-partial with the reason' {
        $script:_RAPublishFailures.Add('Log Analytics: SI_RiskAnalysis_Detailed_CL was not written in full (connection reset)')
        Send-RARunHealthEnd -ExitReason 'success'
        $script:sent.ExitReason | Should -Be 'success-partial'
        $script:sent.ErrorMessage | Should -Match 'SI_RiskAnalysis_Detailed_CL was not written'
    }
    It 'a profile whose newest run was partial: this run is partial too, and says findings are unknown, not resolved' {
        $script:_RAUpstreamOutcome = Get-SIUpstreamOutcome -Rows @([pscustomobject]@{ Engine = 'endpoint'; ExitReason = 'success-partial' }, [pscustomobject]@{ Engine = 'identity'; ExitReason = 'success' })
        Send-RARunHealthEnd -ExitReason 'success'
        $script:sent.ExitReason | Should -Be 'success-partial'
        $script:sent.ErrorMessage | Should -Match "endpoint profile run ended 'success-partial'.*unknown, not resolved"
    }
    It 'a profile run that ended in error published nothing -- the previous whole snapshot is current, so it does not count' {
        (Get-SIUpstreamOutcome -Rows @([pscustomobject]@{ Engine = 'azure'; ExitReason = 'error' })).ExitReason | Should -Be 'success'
        (Get-SIUpstreamOutcome -Rows @()).ExitReason | Should -Be 'success'
    }
    It 'a clean run stays success' {
        Send-RARunHealthEnd -ExitReason 'success'
        $script:sent.ExitReason | Should -Be 'success'
    }
    It 'WIRING: the ingest failure is recorded, and the profile check runs before the final run-health record' {
        $script:RaSrc | Should -Match '\[void\]\$script:_RAPublishFailures\.Add\('
        $iCheck = $script:RaSrc.IndexOf('Get-SIUpstreamOutcome -Rows $__up')
        $iCheck | Should -BeGreaterThan 0
        $iCheck | Should -BeLessThan $script:RaSrc.LastIndexOf("Send-RARunHealthEnd -ExitReason 'success'")
        $script:RaSrc | Should -Match "Get-SIUpstreamRunHealthKql"
    }
}

Describe 'Risk Analysis: a result that did not reach Log Analytics in full is a FAILED run (run health error, the job ends failed)' {
    # A large install, 2026-10-13: the Detailed run built its result, ran out of memory while preparing the rows for Log
    # Analytics, logged a warning and ended Succeeded. The pipeline went on, the data sync found nothing new, and the web
    # app showed the collection of three days earlier with every run green.
    BeforeAll {
        $ra = Join-Path $script:SIRoot 'engine\risk-analysis\Invoke-RiskAnalysis.ps1'
        $script:RaSrc2 = Get-Content -Raw $ra
        $ast = [System.Management.Automation.Language.Parser]::ParseFile($ra, [ref]$null, [ref]$null)
        # the engine's own end-of-run decision, lifted from the shipped source: the assignment and the `if` after it
        $assign = $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.AssignmentStatementAst] -and $n.Left.Extent.Text -eq '$__raNotDelivered' }, $true) | Select-Object -First 1
        # #882 a report that fails fails alone: the run's end verdict (Get-RARunEndVerdict, RA-Delivery.ps1) decides, and BOTH
        # decisions after it (nothing could be stored / Log Analytics did not take the result) are lifted, in their order
        $verdictFn = [System.Management.Automation.Language.Parser]::ParseFile((Join-Path $script:SIRoot 'engine\risk-analysis\_shared\RA-Delivery.ps1'), [ref]$null, [ref]$null).FindAll({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq 'Get-RARunEndVerdict' }, $true) | Select-Object -First 1
        . ([scriptblock]::Create($verdictFn.Extent.Text))
        $verdict = $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.AssignmentStatementAst] -and $n.Left.Extent.Text -eq '$__raEndVerdict' }, $true) | Select-Object -First 1
        $decide = @($ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.IfStatementAst] -and $n.Clauses[0].Item1.Extent.Text -match '__raNotDelivered\.Count' -and $n.Clauses[0].Item1.Extent.Text -match '_RAIngestRefused' }, $true))
        # the decision is RECORDED where the collection is completed and the run ENDS FAILED after the workbook and the mail
        # (the export hotfix, 2026-10-16): both halves, in their order
        $finish = $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.IfStatementAst] -and $n.Clauses[0].Item1.Extent.Text -eq '$null -ne $script:_RAEndFailure' }, $true) | Select-Object -First 1
        $script:EndBlock = [scriptblock]::Create('$script:_RAEndFailure = $null' + "`n" + $assign.Extent.Text + "`n" + $verdict.Extent.Text + "`n" + (@($decide | ForEach-Object { $_.Extent.Text }) -join "`n") + "`n" + $finish.Extent.Text)
        $script:AssignOffset = $assign.Extent.StartOffset
        $script:FinishOffset = $finish.Extent.StartOffset
    }
    BeforeEach {
        $script:Order = New-Object System.Collections.Generic.List[string]
        $script:Lines = New-Object System.Collections.Generic.List[string]
        function script:Send-RARunHealthEnd { param($ExitReason, $ErrorMessage) $script:Order.Add('health'); $script:Health = @{ ExitReason = $ExitReason; ErrorMessage = $ErrorMessage } }
        function script:Write-Section { param($t) $script:Lines.Add([string]$t) }
        function script:Write-Err2 { param($m) $script:Lines.Add([string]$m) }
        $script:Health = $null
        $script:_RAIngestRefused = New-Object System.Collections.Generic.List[string]
        $script:_RAResultNotDelivered = New-Object System.Collections.Generic.List[string]
        $global:OutputXlsx = $null
    }
    AfterAll { $global:OutputXlsx = $null }
    It 'the result table was not written in full: run health error first, then the run throws (the job ends failed)' {
        $script:_RAResultNotDelivered.Add("SI_RiskAnalysis_Detailed_CL did not receive this run's result in full: Exception of type 'System.OutOfMemoryException' was thrown.")
        { . $script:EndBlock } | Should -Throw '*did not publish its Log Analytics snapshot*SI_RiskAnalysis_Detailed_CL*'
        $script:Health.ExitReason | Should -Be 'error'
        $script:Health.ErrorMessage | Should -Match 'SI_RiskAnalysis_Detailed_CL did not receive'
        $script:Health.ErrorMessage | Should -Match 'OutOfMemory'   # the job sizing reads this word and raises the job
        $script:Order[0] | Should -Be 'health'
    }
    It 'the last lines say it plainly: not delivered, the web app keeps the earlier run, nothing downstream got a partial result' {
        $script:_RAResultNotDelivered.Add("SI_RiskAnalysis_Detailed_CL did not receive this run's result in full: boom")
        $wb = Join-Path $TestDrive 'RiskAnalysis_Detailed.xlsx'; Set-Content -LiteralPath $wb -Value 'x'
        $global:OutputXlsx = $wb
        try { . $script:EndBlock } catch { }
        $all = $script:Lines -join "`n"
        $all | Should -Match 'script completed with an error'
        $all | Should -Match 'NOT delivered to Log Analytics'
        $all | Should -Match 'The web app keeps showing the earlier run'
        $all | Should -Match 'Nothing downstream was given a partial result'
        $all | Should -Match ([regex]::Escape($wb))
        $all | Should -Not -Match '#\d+|audit'
    }
    It 'a refused post still fails the run as before, without the not-delivered lines' {
        $script:_RAIngestRefused.Add('Log Analytics: SI_RiskAnalysis_Detailed_CL was NOT written -- every row has CollectionTime empty')
        { . $script:EndBlock } | Should -Throw '*did not publish its Log Analytics snapshot*'
        $script:Health.ExitReason | Should -Be 'error'
        ($script:Lines -join "`n") | Should -Not -Match 'The web app keeps showing'
    }
    It 'a delivered result does not fail the run' {
        { . $script:EndBlock } | Should -Not -Throw
        $script:Health | Should -BeNullOrEmpty
    }
    It 'WIRING: the ingest failure is recorded as not delivered (a refusal keeps its own path), and the decision comes after the files, before the success record' {
        $iCatch = $script:RaSrc2.IndexOf('Write-Warn ("Log Analytics ingest failed:')
        $iAdd = $script:RaSrc2.IndexOf('[void]$script:_RAResultNotDelivered.Add(')
        $iCatch | Should -BeGreaterThan 0
        $iAdd | Should -BeGreaterThan $iCatch
        ($iAdd - $iCatch) | Should -BeLessThan 1500
        $script:RaSrc2.Substring($iCatch, $iAdd - $iCatch) | Should -Match 'if \(-not \(\$_\.Exception -is \[System\.IO\.InvalidDataException\]\)\)'
        $script:RaSrc2 | Should -Not -Match 'continuing -- xlsx \+ json still on disk'
        # decided after the JSON file and the Log Analytics post, where the collection is completed (before the workbook and
        # the upload); the run ends failed after the workbook, the upload and the mail, before the run's success record
        $script:AssignOffset | Should -BeGreaterThan $script:RaSrc2.IndexOf('exporting JSON sibling')
        # the workbook step's block (#873 A wrapped it in its phase timing: the anchor is the block's own heading)
        $iWb = $script:RaSrc2.IndexOf('# THE WORKBOOK (RA-WorkbookExport.ps1) -- from the completed result')
        $iWb | Should -BeGreaterThan 0
        $script:AssignOffset | Should -BeLessThan $iWb
        $script:AssignOffset | Should -BeLessThan $script:RaSrc2.IndexOf('Uploading export files to')
        $script:FinishOffset | Should -BeGreaterThan $script:RaSrc2.IndexOf('Uploading export files to')
        $script:FinishOffset | Should -BeGreaterThan $script:RaSrc2.IndexOf('Write-Section "mail dispatch decision"')
        $script:FinishOffset | Should -BeLessThan $script:RaSrc2.LastIndexOf("Send-RARunHealthEnd -ExitReason 'success'")
    }
    It 'WIRING: the pipeline reads a step''s exit (never run health), and the steps that read the Detailed result need that step' {
        $jf = Get-Content -Raw (Join-Path $script:SIRoot 'engine\_shared\SI-JobFlow.ps1')
        $jf | Should -Match "if \(\`$p\.ExitCode -eq 0\) \{ 'Succeeded' \} else \{ 'Failed' \}"
        $map = Get-Content -Raw (Join-Path $script:SIRoot 'config\job-flow.locked.json') | ConvertFrom-Json
        foreach ($k in 'asset-vulnerabilities', 'asset-vulns-servicenow', 'asset-datasync') {
            @(@($map.jobs | Where-Object { $_.key -eq $k })[0].needs) | Should -Contain 'risk-analysis-detailed' -Because $k
        }
        # the container wrapper runs the engine with errors terminating: the throw ends the process non-zero
        (Get-Content -Raw (Join-Path $script:SIRoot 'container\Start-RiskAnalysisInContainer.ps1')) | Should -Match "(?m)^\`$ErrorActionPreference = 'Stop'"
    }
}
}
