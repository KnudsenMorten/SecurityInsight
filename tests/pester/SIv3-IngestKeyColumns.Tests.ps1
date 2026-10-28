#Requires -Version 5.1
<#
    A RISK ANALYSIS SNAPSHOT NEVER LOSES ITS KEY COLUMNS ON THE WAY TO LOG ANALYTICS (#294).

    Found live 2026-10-05 on ring 1: a Risk Analysis Detailed run posted 14,624 rows to SI_RiskAnalysis_Detailed_CL with
    CollectionTime, ConfigurationId, SecuritySeverity, CriticalityTier, RiskScoreTotal and SolutionVersion EMPTY on every
    row (only AssetName, AssetId, the report name and 8 more columns arrived), and the run logged success. Root cause,
    read from the live rule and the job's log:
      1. Bootstrap passed NO setting to the jobs ("0 setting(s) ... go to every job") because the deploy had loaded the
         config earlier in the same session -- Bootstrap counted only the globals that APPEARED when it loaded the file.
         The jobs ran on default names and without the Pro settings database;
      2. the default rule name did not exist; AzLogDcrIngestPS creates a rule in two steps (the data's first 11 columns,
         then all), and the second step was refused (InvalidTransformOutput: Impact produced Dynamic, table String), so
         the rule kept 11 columns;
      3. the next run's module looked the rule up by name across the tenant, found another install's complete rule, saw
         nothing missing -- and the rows went through the 11-column rule, which dropped every other value.
    Each step is fixed and each has a test here, plus the two independent lines behind them: the Risk Analysis post is
    REFUSED (run health 'error') when a key column is empty on every row, and the Pro data sync REFUSES a snapshot whose
    rows lack ConfigurationId or CollectionTime (never a day; said in run health).
    OFFLINE: Azure is the same fake ARM / ingestion service the REST ingest tests use. Runs on PS 5.1 and pwsh 7.
#>

BeforeAll {
    $script:SIRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
    . (Join-Path $script:SIRoot 'engine\_shared\SI-LogIngest.ps1')
    . (Join-Path $script:SIRoot 'auth\Find-SICertificate.ps1')
    . (Join-Path $script:SIRoot 'auth\SI-ManagedIdentity.ps1')
    . (Join-Path $script:SIRoot 'engine\risk-analysis\_shared\RA-ColumnTypeAlign.ps1')
    . (Join-Path $script:SIRoot 'engine\risk-analysis\_shared\RA-IngestKeyColumns.ps1')
    if (-not (Get-Command -Name Get-AzAccessToken -ErrorAction SilentlyContinue)) { function script:Get-AzAccessToken { param($ResourceUrl) } }

    $script:Sub = '11111111-1111-1111-1111-111111111111'
    $script:Ws  = "/subscriptions/$($script:Sub)/resourceGroups/rg-la/providers/Microsoft.OperationalInsights/workspaces/ws-si"
    $script:GlobalNames = 'SI_LogIngest_Engine', 'SI_LogIngestRunCache', 'SI_LogIngestRunCollectionTime', 'SI_AzSubscriptionId', 'SI_WorkspaceResourceId',
                          'SI_DcrResourceGroup', 'SI_DceResourceGroup', 'SI_DceName', 'SI_UseManagedIdentity', 'SI_UAMI_ClientId', 'EnableCompressionDefault',
                          'UseManagedIdentityDefault', 'SI_LogIngestEngineWarned', 'SubscriptionId', 'SI_LogIngestNotes', 'SI_LogIngestNewColumns'
    $script:Key = @('CollectionTime', 'SolutionVersion', 'ConfigurationId', 'SecuritySeverity', 'CriticalityTier', 'RiskScoreTotal')

    function script:Ok([object]$o) { [pscustomobject]@{ StatusCode = 200; Content = ($o | ConvertTo-Json -Depth 30 -Compress); RetryAfter = $null } }
    function script:Status([int]$c, [string]$body = '') { [pscustomobject]@{ StatusCode = $c; Content = $body; RetryAfter = $null } }
    function script:ArmKey([string]$uri) { ([uri]$uri).AbsolutePath.ToLowerInvariant().TrimEnd('/') }
    function script:Put-Arm([string]$path, $obj) { $script:Arm[$path.ToLowerInvariant()] = ($obj | ConvertTo-Json -Depth 30 | ConvertFrom-Json) }
    function script:DcrPath([string]$name) { "/subscriptions/$($script:Sub)/resourceGroups/rg-si/providers/Microsoft.Insights/dataCollectionRules/$name" }
    function script:DcePath { "/subscriptions/$($script:Sub)/resourceGroups/rg-si/providers/Microsoft.Insights/dataCollectionEndpoints/dce-si" }
    function script:New-Dcr([string]$name, [string]$table, [object[]]$cols) {
        $stream = 'Custom-' + $table + '_CL'
        [pscustomobject]@{ id = (DcrPath $name); name = $name; location = 'westeurope'
            properties = [pscustomobject]@{ immutableId = 'dcr-imm-11'; dataCollectionEndpointId = (DcePath)
                streamDeclarations = [pscustomobject]@{ $stream = [pscustomobject]@{ columns = @($cols) } }
                destinations = [pscustomobject]@{ logAnalytics = @([pscustomobject]@{ workspaceResourceId = $script:Ws; name = 'ws-si' }) }
                dataFlows = @([pscustomobject]@{ streams = @($stream); destinations = @('ws-si'); transformKql = 'source | extend TimeGenerated = now()'; outputStream = $stream }) } }
    }
    function script:Get-DcrColumns([string]$name, [string]$table) {
        $d = $script:Arm[(DcrPath $name).ToLowerInvariant()]
        @($d.properties.streamDeclarations.('Custom-' + $table + '_CL').columns | ForEach-Object { [string]$_.name })
    }

    # A realistic Risk Analysis Detailed row set: the columns the live table carries (types as in Log Analytics), a nested
    # object, an OData artifact column, a prohibited name, and a late row that adds the attack-path block (AUDIT #48).
    function script:New-RaRows([int]$Count = 40) {
        $ct = [datetime]::SpecifyKind([datetime]'2026-10-05T07:18:53', 'Utc')
        $rows = New-Object System.Collections.Generic.List[object]
        for ($i = 0; $i -lt $Count; $i++) {
            $o = [ordered]@{
                AssetDetectedInReportName = 'Device_Recommendations_Detailed'; AssetId = ('{0:x40}' -f (1000 + ($i % 7))); AssetIdSource = 'SecurityInsight asset id'
                AssetName = ('host-{0}.contoso.local' -f ($i % 7)); AssetType = 'Endpoint'; AzureResourceId = ''; Category = 'Application'
                cmdbCriticality = 'High'; cmdbDataSensitivity = 'Confidential'; cmdbId = 'CI0001'; cmdbName = 'Domain controllers'
                ConfigurationId = ('scid-{0}' -f (2000 + $i)); ConfigurationName = 'Secure Microsoft Defender firewall'; CriticalityTier = ($i % 4)
                CriticalityTierLevel = 'Critical - tier 0'; Impact = 'Medium'; MITRE_Tactics = 'TA0005'
                RiskFactor_Consequence = 4; RiskFactor_Probability = 3; RiskScoreTotal = 120 + $i; RiskScoreTotal_Weighted = 130 + $i
                SecurityDomain = 'Endpoint'; SecuritySeverity = 'High'; Subcategory = 'Firewall'
                EntraAppPermissions_Application = [pscustomobject]@{ roles = @('Directory.Read.All') }
                'AllIdentities@odata.type' = '#Collection(String)'
                TenantId = '00000000-0000-0000-0000-00000000000a'
            }
            if ($i -eq $Count - 1) { $o['AttackPath'] = 'dc1 -> svc -> tier0'; $o['SourceCriticalityTier'] = 0; $o['FinalTarget'] = 'Domain Admins' }
            $o['CollectionTime'] = $ct; $o['SolutionVersion'] = '3.0.0+v3'; $o['TraceName'] = 'RA'; $o['TraceID'] = 'abc'
            $rows.Add([pscustomobject]$o)
        }
        , $rows.ToArray()
    }
    # the table's real column types (as read live from SI_RiskAnalysis_Detailed_CL)
    $script:LaTypes = @{ CollectionTime = 'datetime'; CriticalityTier = 'long'; RiskScoreTotal = 'long'; RiskScoreTotal_Weighted = 'long'; RiskFactor_Consequence = 'long'
                         RiskFactor_Probability = 'long'; SourceCriticalityTier = 'long'; Impact = 'string'; EntraAppPermissions_Application = 'string'; SecuritySeverity = 'string'
                         ConfigurationId = 'string'; SolutionVersion = 'string' }

    function script:Get-TableFromRows([object[]]$Rows, [string]$Name) {
        $cols = New-Object System.Collections.Generic.List[object]
        $cols.Add(@{ name = 'TimeGenerated'; type = 'datetime' })
        foreach ($n in (Get-SILogDataColumnNames -Rows $Rows)) {
            $t = if ($script:LaTypes.ContainsKey($n)) { $script:LaTypes[$n] } else { 'string' }
            $cols.Add(@{ name = $n; type = $t })
        }
        @{ properties = @{ schema = @{ name = "$($Name)_CL"; columns = @($cols.ToArray()); standardColumns = @(@{ name = 'TenantId'; type = 'guid' }) } } }
    }
}

Describe 'a Risk Analysis snapshot never loses its key columns (#294)' {

BeforeEach {
    $script:keep = @{}
    foreach ($n in $script:GlobalNames) { $script:keep[$n] = Get-Variable -Scope Global -Name $n -ValueOnly -ErrorAction SilentlyContinue }
    foreach ($n in $script:GlobalNames) { Remove-Variable -Scope Global -Name $n -ErrorAction SilentlyContinue }
    $global:SI_AzSubscriptionId = $script:Sub; $global:SI_WorkspaceResourceId = $script:Ws
    $global:SI_DcrResourceGroup = 'rg-si'; $global:SI_DceName = 'dce-si'; $global:SI_DceResourceGroup = 'rg-si'
    $script:Arm = @{}
    $script:Calls = New-Object System.Collections.Generic.List[object]
    $script:FreezeDcr = $false
    Mock Get-SILogIngestToken { 'tok' }
    Mock Invoke-SILogIngestHttp {
        $script:Calls.Add([pscustomobject]@{ Method = $Method; Uri = $Uri; Body = $Body; Headers = $Headers })
        if ($Uri -like '*/dataCollectionRules/*/streams/*') { return (Status 204) }
        if ($Uri -like 'https://management.azure.com/*') {
            $k = ArmKey $Uri
            if ($Method -eq 'GET') { if ($script:Arm.ContainsKey($k)) { return (Ok $script:Arm[$k]) }; return (Status 404 '{"error":{"code":"ResourceNotFound"}}') }
            $o = $Body | ConvertFrom-Json
            if ($k -like '*/datacollectionrules/*') {
                if ($script:FreezeDcr) { return (Ok $script:Arm[$k]) }   # Azure answers, but the rule does not change
                if (-not $o.PSObject.Properties['id']) { $o | Add-Member -NotePropertyName id -NotePropertyValue ([uri]$Uri).AbsolutePath }
                if (-not $o.properties.PSObject.Properties['immutableId']) { $o.properties | Add-Member -NotePropertyName immutableId -NotePropertyValue 'dcr-imm-new' }
                $o | Add-Member -NotePropertyName name -NotePropertyValue (($k -split '/')[-1]) -Force
            }
            $script:Arm[$k] = $o
            return (Ok $o)
        }
        return (Status 404)
    }
    Mock Start-Sleep { }
    Put-Arm (DcePath) ([pscustomobject]@{ id = (DcePath); name = 'dce-si'; location = 'westeurope'; properties = [pscustomobject]@{ logsIngestion = [pscustomobject]@{ endpoint = 'https://dce-si.westeurope-1.ingest.monitor.azure.com' } } })
}

AfterEach {
    foreach ($n in $script:GlobalNames) { Set-Variable -Scope Global -Name $n -Value $script:keep[$n] }
    Remove-Item function:\CheckCreateUpdate-TableDcr-Structure -ErrorAction SilentlyContinue
}

Describe 'a full Risk Analysis row keeps EVERY column through the ingest path' {
    It 'REST engine: stamp, host columns, name repair, schema alignment and type alignment keep every key column filled on every row' {
        $global:SI_LogIngest_Engine = 'Rest'
        $rows = New-RaRows
        $d = Add-SICollectionTime -Data $rows
        $d = Add-SIColumnData -Data $d -Column1Name Computer -Column1Data 'host' -Column2Name ComputerFqdn -Column2Data 'host.f' -Column3Name UserLoggedOn -Column3Data 'container'
        $d = Repair-SILogColumnName -Data $d
        $d = Format-SILogRowsToSchema -Data $d
        $null = Set-RALaColumnTypes -Rows $d -Types $script:LaTypes
        @($d).Count | Should -Be 40
        foreach ($c in $script:Key) { @($d | Where-Object { [string]::IsNullOrWhiteSpace([string]$_.$c) }).Count | Should -Be 0 -Because "$c must survive the ingest path" }
        @(Get-RAIngestKeyColumnGaps -Rows $d).Count | Should -Be 0
        ($d[0].CriticalityTier -is [int] -or $d[0].CriticalityTier -is [long]) | Should -BeTrue -Because 'a whole number stays a number for the long column'
        $d[0].CollectionTime.ToString('yyyy-MM-ddTHH:mm:ss') | Should -Be '2026-10-05T07:18:53' -Because 'the run''s own stamp is kept'
        $d[0].PSObject.Properties.Name | Should -Contain 'TenantId_' -Because 'a prohibited name is renamed, not dropped'
        $d[0].PSObject.Properties.Name | Should -Contain 'AttackPath' -Because 'a column of the LAST row is a column of every row'
    }
    It 'the post carries every key column on every row (REST, through the rule that declares them)' {
        $global:SI_LogIngest_Engine = 'Rest'
        $rows = New-RaRows
        Put-Arm "$($script:Ws)/tables/SI_RiskAnalysis_Detailed_CL" (Get-TableFromRows -Rows (Repair-SILogColumnName -Data $rows) -Name 'SI_RiskAnalysis_Detailed')
        $null = Update-SILogTableSchema -AzLogWorkspaceResourceId $script:Ws -DceName 'dce-si' -DcrName 'dcr-ra' -DcrResourceGroup 'rg-si' -TableName 'SI_RiskAnalysis_Detailed' `
                    -Data (Repair-SILogColumnName -Data $rows) -AzLogDcrTableCreateFromAnyMachine $true -AzLogDcrTableCreateFromReferenceMachine @()
        $declared = Get-DcrColumns 'dcr-ra' 'SI_RiskAnalysis_Detailed'
        foreach ($c in $script:Key) { $declared | Should -Contain $c }
        $d = Format-SILogRowsToSchema -Data (Repair-SILogColumnName -Data (Add-SICollectionTime -Data $rows))
        $null = Send-SILogData -Data $d -DcrName 'dcr-ra' -DceName 'dce-si' -TableName 'SI_RiskAnalysis_Detailed'
        $posts = @($script:Calls | Where-Object { $_.Uri -like '*/streams/*' })
        $posts.Count | Should -BeGreaterThan 0
        $posted = foreach ($p in $posts) { $raw = if ($p.Body -is [byte[]]) { [System.Text.Encoding]::UTF8.GetString($p.Body) } else { [string]$p.Body }; foreach ($r in ($raw | ConvertFrom-Json)) { $r } }
        @($posted).Count | Should -Be 40
        foreach ($c in $script:Key) { @($posted | Where-Object { [string]::IsNullOrWhiteSpace([string]$_.$c) }).Count | Should -Be 0 -Because "$c is posted" }
    }
}

Describe 'the rule this install posts through must declare every column of the data (Assert-SILogDcrCoversData)' {
    BeforeEach {
        $script:rows = Repair-SILogColumnName -Data (New-RaRows)
        Put-Arm "$($script:Ws)/tables/SI_RiskAnalysis_Detailed_CL" (Get-TableFromRows -Rows $script:rows -Name 'SI_RiskAnalysis_Detailed')
        # ring 1, 2026-10-05: the rule the module left behind -- the data's FIRST 11 columns in alphabetical order
        $first11 = @(Get-SILogDataColumnNames -Rows $script:rows | Sort-Object | Select-Object -First 11 | ForEach-Object { @{ name = $_; type = 'string' } })
        Put-Arm (DcrPath 'dcr-si-risk-analysis-detailed') (New-Dcr 'dcr-si-risk-analysis-detailed' 'SI_RiskAnalysis_Detailed' $first11)
    }
    It 'the 11-column rule gets the missing columns, typed FROM THE TABLE, and they are checked after the post like any new column' {
        $null = Update-SILogTableSchema -AzLogWorkspaceResourceId $script:Ws -DceName 'dce-si' -DcrName 'dcr-si-risk-analysis-detailed' -DcrResourceGroup 'rg-si' `
                    -TableName 'SI_RiskAnalysis_Detailed' -Data $script:rows -AzLogDcrTableCreateFromAnyMachine $true -AzLogDcrTableCreateFromReferenceMachine @() 6>$null
        $declared = Get-DcrColumns 'dcr-si-risk-analysis-detailed' 'SI_RiskAnalysis_Detailed'
        foreach ($c in $script:Key) { $declared | Should -Contain $c }
        $put = @($script:Calls | Where-Object { $_.Method -eq 'PUT' -and $_.Uri -like '*dataCollectionRules/dcr-si-risk-analysis-detailed*' })
        $put.Count | Should -Be 1
        $cols = ($put[0].Body | ConvertFrom-Json).properties.streamDeclarations.'Custom-SI_RiskAnalysis_Detailed_CL'.columns
        ($cols | Where-Object name -eq 'CriticalityTier').type | Should -Be 'long' -Because 'the TABLE''s type, never the data''s'
        ($cols | Where-Object name -eq 'EntraAppPermissions_Application').type | Should -Be 'string' -Because 'the type Azure refused when declared from the data'
        $global:SI_LogIngestNewColumns['dcr-si-risk-analysis-detailed'].Columns | Should -Contain 'ConfigurationId' -Because 'Azure stores a column added to a rule only after a while -- the post checks it'
    }
    It 'REST engine: the same rule is completed the same way' {
        $global:SI_LogIngest_Engine = 'Rest'
        $null = Update-SILogTableSchema -AzLogWorkspaceResourceId $script:Ws -DceName 'dce-si' -DcrName 'dcr-si-risk-analysis-detailed' -DcrResourceGroup 'rg-si' `
                    -TableName 'SI_RiskAnalysis_Detailed' -Data $script:rows -AzLogDcrTableCreateFromAnyMachine $true -AzLogDcrTableCreateFromReferenceMachine @() 6>$null
        $declared = Get-DcrColumns 'dcr-si-risk-analysis-detailed' 'SI_RiskAnalysis_Detailed'
        foreach ($c in $script:Key) { $declared | Should -Contain $c }
    }
    It 'a column that cannot be added to the rule REFUSES the post (InvalidDataException) -- nothing is posted through a rule that would drop it' {
        $script:FreezeDcr = $true
        $err = $null
        try {
            $null = Update-SILogTableSchema -AzLogWorkspaceResourceId $script:Ws -DceName 'dce-si' -DcrName 'dcr-si-risk-analysis-detailed' -DcrResourceGroup 'rg-si' `
                        -TableName 'SI_RiskAnalysis_Detailed' -Data $script:rows -AzLogDcrTableCreateFromAnyMachine $true -AzLogDcrTableCreateFromReferenceMachine @() 6>$null
        } catch { $err = $_ }
        $err | Should -Not -BeNullOrEmpty
        $err.Exception | Should -BeOfType [System.IO.InvalidDataException]
        $err.Exception.Message | Should -Match 'CollectionTime'
        $err.Exception.Message | Should -Match 'nothing is posted'
    }
    It 'schema management switched off for this machine: nothing is declared here, so nothing is checked' {
        $r = Assert-SILogDcrCoversData -DcrName 'dcr-si-risk-analysis-detailed' -DcrResourceGroup 'rg-si' -TableName 'SI_RiskAnalysis_Detailed' -WorkspaceResourceId $script:Ws `
                 -DceName 'dce-si' -Data $script:rows -Bound @{ AzLogDcrTableCreateFromAnyMachine = $false; AzLogDcrTableCreateFromReferenceMachine = @('OTHER-HOST') }
        $r.Verdict | Should -Be 'skipped'
        @($script:Calls | Where-Object { $_.Method -ne 'GET' }).Count | Should -Be 0
    }
    It 'a column the TABLE does not have either is said and makes the run partial -- not refused' {
        $r = Assert-SILogDcrCoversData -DcrName 'dcr-si-risk-analysis-detailed' -DcrResourceGroup 'rg-si' -TableName 'SI_RiskAnalysis_Detailed' -WorkspaceResourceId $script:Ws `
                 -DceName 'dce-si' -Data @(@($script:rows) + @([pscustomobject]@{ BrandNewColumn = 'x' })) -Bound @{} 3>$null 6>$null
        $r.Verdict | Should -Be 'partial'
        $r.Missing | Should -Contain 'BrandNewColumn'
        @(Get-SILogIngestNotes | Where-Object { $_.Columns -contains 'BrandNewColumn' }).Count | Should -Be 1
    }
    It 'a rule that does not exist after the update refuses the post' {
        { Assert-SILogDcrCoversData -DcrName 'dcr-missing' -DcrResourceGroup 'rg-si' -TableName 'SI_RiskAnalysis_Detailed' -WorkspaceResourceId $script:Ws -DceName 'dce-si' -Data $script:rows -Bound @{} } |
            Should -Throw '*does not exist*nothing is posted*'
    }
    It 'a rule that declares every column: covered, no write' {
        $all = @(Get-SILogDataColumnNames -Rows $script:rows | ForEach-Object { @{ name = $_; type = 'string' } })
        Put-Arm (DcrPath 'dcr-full') (New-Dcr 'dcr-full' 'SI_RiskAnalysis_Detailed' $all)
        (Assert-SILogDcrCoversData -DcrName 'dcr-full' -DcrResourceGroup 'rg-si' -TableName 'SI_RiskAnalysis_Detailed' -WorkspaceResourceId $script:Ws -DceName 'dce-si' -Data $script:rows -Bound @{}).Verdict | Should -Be 'covered'
        @($script:Calls | Where-Object { $_.Method -ne 'GET' }).Count | Should -Be 0
    }
}

Describe 'a NEW rule for an EXISTING table is declared from the table (no 11-column first step)' {
    It 'the rule is created from the table''s columns and types in ONE step' {
        $rows = Repair-SILogColumnName -Data (New-RaRows)
        Put-Arm "$($script:Ws)/tables/SI_RiskAnalysis_Detailed_CL" (Get-TableFromRows -Rows $rows -Name 'SI_RiskAnalysis_Detailed')
        $null = Update-SILogTableSchema -AzLogWorkspaceResourceId $script:Ws -DceName 'dce-si' -DcrName 'dcr-si-risk-analysis-detailed' -DcrResourceGroup 'rg-si' `
                    -TableName 'SI_RiskAnalysis_Detailed' -Data $rows -AzLogDcrTableCreateFromAnyMachine $true -AzLogDcrTableCreateFromReferenceMachine @() 6>$null
        $rule = $script:Arm[(DcrPath 'dcr-si-risk-analysis-detailed').ToLowerInvariant()]
        $rule | Should -Not -BeNullOrEmpty
        @($script:Calls | Where-Object { $_.Method -eq 'PUT' -and $_.Uri -like '*dataCollectionRules/dcr-si-risk-analysis-detailed*' }).Count | Should -Be 1 -Because 'one complete create, never an 11-column first step'
        $cols = $rule.properties.streamDeclarations.'Custom-SI_RiskAnalysis_Detailed_CL'.columns
        foreach ($n in @(Get-SILogDataColumnNames -Rows $rows)) { @($cols.name) | Should -Contain $n -Because 'every column of the data is declared' }
        $tableCols = @($script:Arm[("$($script:Ws)/tables/SI_RiskAnalysis_Detailed_CL").ToLowerInvariant()].properties.schema.columns.name)
        foreach ($n in @($cols.name)) { $tableCols | Should -Contain $n -Because 'the rule declares the table''s columns' }
        ($cols | Where-Object name -eq 'EntraAppPermissions_Application').type | Should -Be 'string'
        @($cols | Where-Object name -eq 'TimeGenerated').Count | Should -Be 0
    }
    It 'Get-SILogNewRuleColumns: the table''s columns with the table''s types first, then the data''s new ones' {
        $t = [pscustomobject]@{ properties = [pscustomobject]@{ schema = [pscustomobject]@{ columns = @([pscustomobject]@{ name = 'TimeGenerated'; type = 'datetime' }, [pscustomobject]@{ name = 'Impact'; type = 'string' }) } } }
        $c = @(Get-SILogNewRuleColumns -Table $t -SchemaSourceObject @(@{ name = 'Impact'; type = 'dynamic' }, @{ name = 'New'; type = 'int' }))
        ($c | ForEach-Object { '{0}:{1}' -f $_.name, $_.type }) -join ',' | Should -Be 'Impact:string,New:int'
        @(Get-SILogNewRuleColumns -Table $null -SchemaSourceObject @(@{ name = 'a'; type = 'int' })).Count | Should -Be 1
    }
}

Describe 'Risk Analysis refuses to post a snapshot whose key columns are empty on every row' {
    It 'a key column empty on EVERY row is a gap; one filled row is not' {
        $rows = New-RaRows 5
        foreach ($r in $rows) { $r.ConfigurationId = ''; $r.SolutionVersion = $null }
        $rows[2].CriticalityTier = $null
        @(Get-RAIngestKeyColumnGaps -Rows $rows) -join ',' | Should -Be 'SolutionVersion,ConfigurationId'
    }
    It 'the ring 1 snapshot (only AssetName, AssetId and the report name) is refused on every key column' {
        $rows = 1..3 | ForEach-Object { [pscustomobject]@{ AssetName = 'dc1'; AssetId = 'x'; AssetDetectedInReportName = 'Device_Recommendations_Detailed'; CollectionTime = $null; ConfigurationId = $null } }
        @(Get-RAIngestKeyColumnGaps -Rows $rows) -join ',' | Should -Be ($script:Key -join ',')
        Get-RAIngestKeyColumnMessage -Columns @('CollectionTime') -Rows 3 -TableName 'SI_RiskAnalysis_Detailed' | Should -Match 'Every one of the 3 row\(s\) for SI_RiskAnalysis_Detailed_CL has CollectionTime empty'
    }
    It 'no rows: nothing to refuse' { @(Get-RAIngestKeyColumnGaps -Rows @()).Count | Should -Be 0 }
    It 'WIRING: the check runs on the rows about to be posted, before Send-SILogData, and a refusal fails the run with run health ''error''' {
        $src = Get-Content -Raw -LiteralPath (Join-Path $script:SIRoot 'engine\risk-analysis\Invoke-RiskAnalysis.ps1')
        $src | Should -Match "_shared/RA-IngestKeyColumns\.ps1"
        # posted in chunks (RA-Delivery.ps1): checked on the whole result before the first chunk, and on the prepared
        # chunks as they go (a key column the preparation emptied on every row fails the run after the loop)
        $iGap = $src.IndexOf('Get-RAIngestKeyColumnGaps -Rows @($__pgPage) -Columns $__keyGaps'); $iSend = $src.IndexOf('$__laDelivery = Invoke-RALaPagedPost')
        $iGap | Should -BeGreaterThan 0
        $iGap | Should -BeLessThan $iSend
        $src | Should -Match ([regex]::Escape("`$__keyCols = @(Get-RAIngestKeyColumns | Where-Object { `$_ -ne 'CollectionTime' })"))
        $src | Should -Match ([regex]::Escape('Invoke-RALaPagedPost -Pager $__pgL -KeyColumns @(Get-RAIngestKeyColumns)'))   # #738: each page through Invoke-RALaChunkedPost with the gaps so far (RA-Delivery.ps1)
        (Get-Content -Raw -LiteralPath (Join-Path $script:SIRoot 'engine\risk-analysis\_shared\RA-Delivery.ps1')) | Should -Match ([regex]::Escape('Invoke-RALaChunkedPost -Rows @($page) -KeyColumns @($all.KeyGaps)'))
        $src.IndexOf('if (@($__laDelivery.KeyGaps).Count -gt 0)') | Should -BeGreaterThan $iSend
        $src | Should -Match 'New-Object System\.IO\.InvalidDataException\(\(Get-RAIngestKeyColumnMessage'
        $src | Should -Match '\$_\.Exception -is \[System\.IO\.InvalidDataException\]'
        # recorded where the collection is completed; the run ends failed after the workbook and the mail (export hotfix)
        $src | Should -Match ([regex]::Escape('$script:_RAEndFailure = [pscustomobject]@{ Health = $__refusedMsg;'))
        $src | Should -Match ([regex]::Escape("Send-RARunHealthEnd -ExitReason 'error' -ErrorMessage ([string]`$script:_RAEndFailure.Health)"))
        $iErr = $src.IndexOf("Send-RARunHealthEnd -ExitReason 'error'"); $iOk = $src.LastIndexOf("Send-RARunHealthEnd -ExitReason 'success'")
        $iErr | Should -BeLessThan $iOk
    }
}

Describe 'Bootstrap passes the config''s settings to the jobs even when the config was loaded before' {
    It 'Get-SIConfigFileSettingNames reads every $global: assignment from the file -- nothing is run' {
        . (Join-Path $script:SIRoot 'container\_shared\SI-ContainerConfig.ps1')
        $f = Join-Path $TestDrive 'SecurityInsight.custom.ps1'
        Set-Content -LiteralPath $f -Encoding UTF8 -Value @'
$global:SI_RiskAnalysis_DcrName_Detailed = 'dcr-si-r1-pro-ca-risk-analysis-detailed'
[string]$global:SI_ProSqlServer = 'server.database.windows.net'
if ($true) { $global:SI_DcrResourceGroup = 'rg-si-r1-pro-ca' }
$local = 'not a setting'
$env:NOT_A_SETTING = 1
throw 'this file is never run'
'@
        $global:SI_RiskAnalysis_DcrName_Detailed = 'already-loaded'   # the session had loaded the config before
        try {
            $n = @(Get-SIConfigFileSettingNames -Path $f)
            $n -join ',' | Should -Be 'SI_RiskAnalysis_DcrName_Detailed,SI_ProSqlServer,SI_DcrResourceGroup'
        } finally { Remove-Variable -Scope Global -Name SI_RiskAnalysis_DcrName_Detailed -ErrorAction SilentlyContinue }
        @(Get-SIConfigFileSettingNames -Path (Join-Path $TestDrive 'none.ps1')).Count | Should -Be 0
    }
    It 'WIRING: Bootstrap adds the names the file assigns to the names that appeared when it loaded the file' {
        $src = Get-Content -Raw -LiteralPath (Join-Path $script:SIRoot 'Bootstrap-ContainerAppJob.ps1')
        $src | Should -Match '\$configSetNames = @\(@\(\$configSetNames\) \+ @\(Get-SIConfigFileSettingNames -Path \$customFile\)'
        $src.IndexOf('Get-SIConfigFileSettingNames -Path $customFile') | Should -BeLessThan $src.IndexOf('$cfgNames = @($configSetNames')
    }
}
}
