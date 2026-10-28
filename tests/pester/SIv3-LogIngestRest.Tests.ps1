#Requires -Version 5.1
<#
    LOG INGESTION OVER PLAIN REST (REQUIREMENTS 9.3, decision 2) -- engine/_shared/SI-LogIngest.ps1.

    No module, no switch (#305): every SI call site goes through an SI wrapper that does the job over plain REST. Where
    AzLogDcrIngestPS happens to be installed on the test host, the parity tests compare the REST shapes with it (the
    module is never needed by SecurityInsight itself).

    OFFLINE: every HTTP call goes through Invoke-SILogIngestHttp, which is mocked here by a fake ARM / token / ingestion
    service. No tenant, no network, no credentials.
#>

BeforeAll {
    $script:SIRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
    . (Join-Path $script:SIRoot 'engine\_shared\SI-LogIngest.ps1')
    # the token helpers the REST path signs in with -- loaded so they can be mocked
    . (Join-Path $script:SIRoot 'auth\Find-SICertificate.ps1')
    . (Join-Path $script:SIRoot 'auth\SI-ManagedIdentity.ps1')
    # Test-Path, not Get-Command: in PowerShell 7 Get-Command IMPORTS an installed Az.Accounts, which then leaks a real
    # Azure session into every later suite of the run (#413 detects a loaded session).
    if (-not (Test-Path -LiteralPath 'Function:\Get-AzAccessToken')) { function script:Get-AzAccessToken { param($ResourceUrl) } }

    $script:Sub = '11111111-1111-1111-1111-111111111111'
    $script:Ws  = "/subscriptions/$($script:Sub)/resourceGroups/rg-la/providers/Microsoft.OperationalInsights/workspaces/ws-si"
    $script:GlobalNames = 'SI_LogIngest_Engine', 'SI_LogIngestRunCache', 'SI_LogIngestRunCollectionTime', 'SI_AzSubscriptionId', 'SI_WorkspaceResourceId',
                          'SI_DcrResourceGroup', 'SI_DceResourceGroup', 'SI_DceName', 'SI_UseManagedIdentity', 'SI_UAMI_ClientId', 'EnableCompressionDefault',
                          'UseManagedIdentityDefault', 'SI_LogIngestEngineWarned', 'SubscriptionId'

    function script:Ok([object]$o) { [pscustomobject]@{ StatusCode = 200; Content = ($o | ConvertTo-Json -Depth 30 -Compress); RetryAfter = $null } }
    function script:Status([int]$c, [string]$body = '', [string]$retryAfter = $null) { [pscustomobject]@{ StatusCode = $c; Content = $body; RetryAfter = $retryAfter } }
    function script:ArmKey([string]$uri) { ([uri]$uri).AbsolutePath.ToLowerInvariant().TrimEnd('/') }
    function script:Put-Arm([string]$path, $obj) { $script:Arm[$path.ToLowerInvariant()] = ($obj | ConvertTo-Json -Depth 30 | ConvertFrom-Json) }
    function script:New-Dce([string]$rg, [string]$name = 'dce-si', [string]$sub = $script:Sub) {
        $id = "/subscriptions/$sub/resourceGroups/$rg/providers/Microsoft.Insights/dataCollectionEndpoints/$name"
        [pscustomobject]@{ id = $id; name = $name; location = 'westeurope'; properties = [pscustomobject]@{ logsIngestion = [pscustomobject]@{ endpoint = "https://$name-$rg.westeurope-1.ingest.monitor.azure.com" } } }
    }
    function script:New-Dcr([string]$rg, [string]$name, [string]$imm, [string]$dceId, [string]$table = 'T', [object[]]$cols = @(@{ name = 'a'; type = 'string' }), [string]$kql = 'source | extend TimeGenerated = now()') {
        $stream = 'Custom-' + $table + '_CL'
        $id = "/subscriptions/$($script:Sub)/resourceGroups/$rg/providers/Microsoft.Insights/dataCollectionRules/$name"
        [pscustomobject]@{
            id = $id; name = $name; location = 'westeurope'
            properties = [pscustomobject]@{
                immutableId = $imm; provisioningState = 'Succeeded'; dataCollectionEndpointId = $dceId
                streamDeclarations = [pscustomobject]@{ $stream = [pscustomobject]@{ columns = @($cols) } }
                destinations = [pscustomobject]@{ logAnalytics = @([pscustomobject]@{ workspaceResourceId = $script:Ws; name = 'ws-si' }) }
                dataFlows = @([pscustomobject]@{ streams = @($stream); destinations = @('ws-si'); transformKql = $kql; outputStream = $stream })
            }
        }
    }
    function script:Expand-Body($b, [hashtable]$h) {
        $bytes = if ($b -is [byte[]]) { $b } else { [System.Text.Encoding]::UTF8.GetBytes([string]$b) }
        if ($h -and $h['Content-Encoding'] -eq 'gzip') {
            $in = New-Object System.IO.MemoryStream(, $bytes); $gz = New-Object System.IO.Compression.GZipStream($in, [System.IO.Compression.CompressionMode]::Decompress)
            $out = New-Object System.IO.MemoryStream; $gz.CopyTo($out); $gz.Dispose(); $bytes = $out.ToArray()
        }
        [System.Text.Encoding]::UTF8.GetString($bytes)
    }
    function script:Get-PostedRows([object[]]$posts) {
        # the rows of each posted JSON array -- enumerated explicitly: PS 5.1's ConvertFrom-Json returns an array as ONE object
        foreach ($p in $posts) { $j = (Expand-Body $p.Body $p.Headers) | ConvertFrom-Json; foreach ($r in $j) { $r } }
    }
}

Describe 'SI log ingest -- the wrappers and their REST twins' {

BeforeEach {
    $script:keep = @{}
    foreach ($n in $script:GlobalNames) { $script:keep[$n] = Get-Variable -Scope Global -Name $n -ValueOnly -ErrorAction SilentlyContinue }
    foreach ($n in $script:GlobalNames) { Remove-Variable -Scope Global -Name $n -ErrorAction SilentlyContinue }
    $global:SI_AzSubscriptionId = $script:Sub; $global:SI_WorkspaceResourceId = $script:Ws
    $global:SI_DcrResourceGroup = 'rg-si'; $global:SI_DceName = 'dce-si'
    $script:Arm = @{}
    $script:Calls = New-Object System.Collections.Generic.List[object]
    $script:Ingest = $null
    $script:Override = $null
    # the fake service: tokens, ARM (GET from $script:Arm, writes stored), ingestion via $script:Ingest (default 204)
    Mock Invoke-SILogIngestHttp {
        $script:Calls.Add([pscustomobject]@{ Method = $Method; Uri = $Uri; Headers = $Headers; Body = $Body; ContentType = $ContentType })
        if ($script:Override) { $o = & $script:Override $Method $Uri; if ($o) { return $o } }
        if ($Uri -like 'https://login.microsoftonline.com/*') { return (Ok @{ access_token = 'tok-secret'; expires_in = 3600 }) }
        if ($Uri -like '*/dataCollectionRules/*/streams/*') { if ($script:Ingest) { return (& $script:Ingest $Uri $Headers $Body) }; return (Status 204) }
        if ($Uri -like 'https://management.azure.com/*') {
            $k = ArmKey $Uri
            if ($Method -eq 'GET') { if ($script:Arm.ContainsKey($k)) { return (Ok $script:Arm[$k]) }; return (Status 404 '{"error":{"code":"ResourceNotFound"}}') }
            $o = $Body | ConvertFrom-Json
            if ($k -like '*/datacollectionrules/*' -and $k -notlike '*/roleassignments/*') {
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
}

AfterEach {
    foreach ($n in $script:GlobalNames) { Set-Variable -Scope Global -Name $n -Value $script:keep[$n] }
}

Describe 'there is no switch -- log ingestion is REST only' {
    It 'the old switch function is gone' { Get-Command -Name Get-SILogIngestEngine -ErrorAction SilentlyContinue | Should -BeNullOrEmpty }
    It 'a leftover SI_LogIngest_Engine = Module in a customer configuration changes nothing: the REST twin runs' {
        $global:SI_LogIngest_Engine = 'Module'
        Mock Send-SILogDataRest { 'rest' }
        Send-SILogData -DceName 'dce' -DcrName 'dcr' -Data @([pscustomobject]@{ a = 1 }) -TableName 'T' | Should -Be 'rest'
        Should -Invoke Send-SILogDataRest -Times 1 -Exactly
    }
}

Describe 'WIRING -- every former direct call goes through the wrapper' {
    It 'no SI script calls an AzLogDcrIngestPS function -- not even SI-LogIngest.ps1' {
        $map = Get-SILogIngestWrapperMap
        $moduleFns = @($map.Values | ForEach-Object { $_.Replaces })
        $moduleFns += 'Post-AzLogAnalyticsLogIngestCustomLogDcrDce', 'Get-AzDcrDceDetails', 'Get-AzAccessTokenManagement', 'Update-AzDataCollectionRuleTransformKql',
                      'Update-AzDataCollectionRuleResetTransformKqlDefault', 'Update-AzDataCollectionRuleDceEndpoint', 'Delete-AzDataCollectionRules',
                      'Delete-AzLogAnalyticsCustomLogTables', 'Convert-CimArrayToObjectFixStructure', 'Convert-PSArrayToObjectFixStructure', 'Filter-ObjectExcludeProperty'
        $wrappers = @($map.Keys)
        $hits = New-Object System.Collections.Generic.List[string]
        Get-ChildItem $script:SIRoot -Recurse -Filter *.ps1 | Where-Object { $_.FullName -notmatch '[\\/]tests[\\/]' } | ForEach-Object {
            $ast = [System.Management.Automation.Language.Parser]::ParseFile($_.FullName, [ref]$null, [ref]$null)
            foreach ($c in $ast.FindAll({ $args[0] -is [System.Management.Automation.Language.CommandAst] }, $true)) {
                $n = $c.GetCommandName()
                if (-not $n -or $n -notin $moduleFns) { continue }
                $hits.Add(('{0}:{1} {2}' -f $_.FullName.Substring($script:SIRoot.Length + 1), $c.Extent.StartLineNumber, $n))
            }
        }
        $hits | Should -BeNullOrEmpty
    }
    It 'the rerouted call sites call the wrappers (the ingest paths of every engine)' {
        $expect = @{
            'engine\asset-profiling\stages\Invoke-Output.ps1'               = @('Get-SIDceList', 'Get-SIDcrList', 'Update-SILogTableSchema', 'Test-SILogTableDcrStatus', 'Set-SILogTable', 'Set-SILogDcr', 'Get-SILogSchemaArray', 'Get-SILogSchemaHash', 'Add-SIColumnData', 'Repair-SILogColumnName', 'Format-SILogRowsToSchema', 'Send-SILogData')
            'engine\asset-profiling\stages\Invoke-SchemaOutput.ps1'         = @('Get-SIDceList', 'Update-SILogTableSchema', 'Send-SILogData')
            'engine\asset-profiling\stages\Invoke-Tagging.ps1'              = @('Get-SIDceList', 'Update-SILogTableSchema', 'Send-SILogData')
            'engine\asset-profiling\shared\Send-SIRunHealthRow.ps1'         = @('Get-SIDcrList', 'Update-SILogTableSchema', 'Send-SILogData')
            'engine\asset-trend\Invoke-SITrend.ps1'                         = @('Update-SILogTableSchema', 'Send-SILogData')
            'engine\risk-analysis\Invoke-RiskAnalysis.ps1'                  = @('Update-SILogTableSchema', 'Send-SILogData')
            # the rows are prepared part by part here (2026-10-13, a large install ran out of memory preparing them whole)
            'engine\risk-analysis\_shared\RA-Delivery.ps1'                  = @('Add-SICollectionTime', 'Add-SIColumnData', 'Repair-SILogColumnName', 'Format-SILogRowsToSchema')
            'engine\risk-analysis\_shared\Ensure-SecurityInsightInfra.ps1'  = @('Get-SIDceList', 'Get-SIDcrList')
            'engine\_shared\SI-LogIngest.ps1'                               = @('Get-SIDceList', 'Update-SILogTableSchema', 'Send-SILogData')
            'setup\Validate-SILogAnalytics.ps1'                             = @('Get-SIDcrList', 'Update-SILogTableSchema')
        }
        $pro = Join-Path $script:SIRoot 'engine\asset-properties\_shared\SI-AssetPropertiesIngest.ps1'
        if (Test-Path $pro) { $expect['engine\asset-properties\_shared\SI-AssetPropertiesIngest.ps1'] = @('Get-SIDceList', 'Update-SILogTableSchema', 'Send-SILogData') }
        foreach ($f in $expect.Keys) {
            $ast = [System.Management.Automation.Language.Parser]::ParseFile((Join-Path $script:SIRoot $f), [ref]$null, [ref]$null)
            $names = @($ast.FindAll({ $args[0] -is [System.Management.Automation.Language.CommandAst] }, $true) | ForEach-Object { $_.GetCommandName() })
            foreach ($w in $expect[$f]) { $names | Should -Contain $w -Because "$f must post through the wrapper" }
        }
    }
    It 'every file that calls a wrapper loads SI-LogIngest.ps1, or runs under an entry point that does' {
        $wrappers = @((Get-SILogIngestWrapperMap).Keys)
        # stages run inside Invoke-SIEngineRun / Invoke-RiskAnalysis, which dot-source Send-SIRunHealthRow.ps1 first
        $hosted = 'Invoke-Output.ps1', 'Invoke-SchemaOutput.ps1', 'Invoke-Tagging.ps1', 'Invoke-RiskAnalysis.ps1', 'SI-LogIngest.ps1'
        Get-ChildItem $script:SIRoot -Recurse -Filter *.ps1 | Where-Object { $_.FullName -notmatch '[\\/]tests[\\/]' -and $_.Name -notin $hosted } | ForEach-Object {
            $ast = [System.Management.Automation.Language.Parser]::ParseFile($_.FullName, [ref]$null, [ref]$null)
            $calls = @($ast.FindAll({ $args[0] -is [System.Management.Automation.Language.CommandAst] }, $true) | Where-Object { $_.GetCommandName() -in $wrappers })
            if ($calls.Count) { (Get-Content -Raw $_.FullName) | Should -Match 'SI-LogIngest\.ps1' -Because "$($_.Name) calls the wrappers" }
        }
        $runner = Get-Content -Raw (Join-Path $script:SIRoot 'engine\asset-profiling\Invoke-SIEngineRun.ps1')
        $runner.IndexOf("shared\Send-SIRunHealthRow.ps1") | Should -BeLessThan $runner.IndexOf('$stagesRoot = Join-Path')
        (Get-Content -Raw (Join-Path $script:SIRoot 'engine\risk-analysis\Invoke-RiskAnalysis.ps1')) | Should -Match "asset-profiling/shared/Send-SIRunHealthRow\.ps1"
    }
    It 'each wrapper forwards @PSBoundParameters to its REST twin -- never @args, never the module function' {
        $map = Get-SILogIngestWrapperMap
        foreach ($w in $map.Keys) {
            $body = (Get-Command $w).ScriptBlock.ToString()
            $body | Should -Not -Match ([regex]::Escape($map[$w].Replaces) + '\b')
            $body | Should -Match ([regex]::Escape($map[$w].Rest) + '.*@PSBoundParameters')
            $body | Should -Not -Match '@args'
        }
    }
    It 'each wrapper''s parameters are accepted by its REST twin (a call site never binds a name REST does not know)' {
        $map = Get-SILogIngestWrapperMap
        $common = [System.Management.Automation.PSCmdlet]::CommonParameters
        foreach ($w in $map.Keys) {
            $rest = @((Get-Command $map[$w].Rest).Parameters.Keys)
            foreach ($p in (Get-Command $w).Parameters.Keys) { if ($p -notin $common) { $rest | Should -Contain $p -Because "$w -$p" } }
        }
    }
    It 'each wrapper declares the module''s parameter names and types (when AzLogDcrIngestPS is installed here)' {
        $m = Get-Module -ListAvailable -Name AzLogDcrIngestPS | Sort-Object Version -Descending | Select-Object -First 1
        if (-not $m) { Set-ItResult -Skipped -Because 'AzLogDcrIngestPS is not installed on this host'; return }
        $loaded = Get-Module -Name AzLogDcrIngestPS
        $mod = Import-Module $m.Path -PassThru -Force -DisableNameChecking -WarningAction SilentlyContinue
        try {
            $map = Get-SILogIngestWrapperMap
            $common = [System.Management.Automation.PSCmdlet]::CommonParameters
            foreach ($w in $map.Keys) {
                $mp = $mod.ExportedCommands[$map[$w].Replaces].Parameters
                foreach ($p in (Get-Command $w).Parameters.Values) {
                    if ($p.Name -in $common) { continue }
                    $mp.ContainsKey($p.Name) | Should -BeTrue -Because "$($map[$w].Replaces) has -$($p.Name)"
                    $p.ParameterType | Should -Be $mp[$p.Name].ParameterType -Because "$w -$($p.Name)"
                }
            }
        } finally { if (-not $loaded) { Remove-Module -ModuleInfo $mod -Force -ErrorAction SilentlyContinue } }
    }
    It 'the REST module ships in both editions: no Pro path is referenced' {
        # the CODE, not the comments (the file's history note names the correlation folder it moved out of)
        $tokens = $null; $null = [System.Management.Automation.Language.Parser]::ParseFile((Join-Path $script:SIRoot 'engine\_shared\SI-LogIngest.ps1'), [ref]$tokens, [ref]$null)
        $code = ($tokens | Where-Object { $_.Kind -ne 'Comment' } | ForEach-Object { $_.Text }) -join ' '
        # every path the Community copy leaves out (solution.publish.json excludePaths), by its last segment
        $pub = Get-Content -Raw (Join-Path $script:SIRoot 'solution.publish.json') | ConvertFrom-Json
        $leaves = @($pub.excludePaths | ForEach-Object { Split-Path -Leaf ("$_".TrimEnd('\', '/')) } | Where-Object { $_ -match '[-.]' } | Sort-Object -Unique)
        $leaves.Count | Should -BeGreaterThan 3
        foreach ($l in $leaves) { $code.Contains($l) | Should -BeFalse -Because "SI-LogIngest.ps1 ships in Community and must not reference $l" }
    }
    It 'PS 5.1 safe: no ?. / ?? operators and no ImportFromPem' {
        $src = Get-Content -Raw (Join-Path $script:SIRoot 'engine\_shared\SI-LogIngest.ps1')
        $tokens = $null; $null = [System.Management.Automation.Language.Parser]::ParseInput($src, [ref]$tokens, [ref]$null)
        @($tokens | Where-Object { $_.Kind -in 'QuestionDot', 'QuestionQuestion', 'QuestionQuestionEquals', 'QuestionLBracket' }).Count | Should -Be 0
        (($tokens | Where-Object { $_.Kind -ne 'Comment' } | ForEach-Object { $_.Text }) -join ' ') | Should -Not -Match 'ImportFromPem'
    }
}

Describe 'tokens follow the sign-in decision' {
    It 'secret: client_credentials for the requested audience, cached per run' {
        $a = Resolve-SILogIngestAuth -Bound @{ AzAppId = 'app'; AzAppSecret = 'p@ss'; TenantId = 'ten' }
        $a.Mode | Should -Be 'Secret'
        Get-SILogIngestToken -Resource 'https://monitor.azure.com/' -Auth $a | Should -Be 'tok-secret'
        Get-SILogIngestToken -Resource 'https://monitor.azure.com/' -Auth $a | Should -Be 'tok-secret'
        $t = @($script:Calls | Where-Object { $_.Uri -like 'https://login.microsoftonline.com/*' })
        $t.Count | Should -Be 1
        $t[0].Uri | Should -Be 'https://login.microsoftonline.com/ten/oauth2/v2.0/token'
        $t[0].Body | Should -Match 'grant_type=client_credentials'
        $t[0].Body | Should -Match ('scope=' + [regex]::Escape([uri]::EscapeDataString('https://monitor.azure.com/.default')))
        $t[0].Body | Should -Match 'client_secret=p%40ss'
    }
    It 'managed identity: the identity endpoint helper, with the client id, for ingestion and for ARM' {
        Mock Get-SIManagedIdentityToken { "mi|$Resource|$ClientId" }
        $a = Resolve-SILogIngestAuth -Bound @{ UseManagedIdentity = $true; ManagedIdentityClientId = 'uami'; AzAppId = 'ignored'; AzAppSecret = 'ignored'; TenantId = 't' }
        $a.Mode | Should -Be 'ManagedIdentity'
        Get-SILogIngestToken -Resource 'https://monitor.azure.com' -Auth $a | Should -Be 'mi|https://monitor.azure.com/|uami'
        Get-SILogIngestToken -Resource 'https://management.azure.com/' -Auth $a | Should -Be 'mi|https://management.azure.com/|uami'
    }
    It 'certificate: a JWT assertion signed from the certificate store (the shared helper), thumbprint without spaces' {
        Mock Get-SICertificateClientToken { "cert|$TenantId|$ClientId|$Thumbprint|$Resource" }
        $a = Resolve-SILogIngestAuth -Bound @{ AzAppId = 'app'; AzAppCertificateThumbprint = 'AB CD'; TenantId = 'ten'; AzAppSecret = 'also-set' }
        $a.Mode | Should -Be 'Certificate' -Because 'certificate wins over secret, as in the module'
        Get-SILogIngestToken -Resource 'https://management.azure.com/' -Auth $a | Should -Be 'cert|ten|app|ABCD|https://management.azure.com/'
    }
    It 'no credentials handed over: the run''s managed-identity decision (#222), else the run''s own sign-in (REST)' {
        $global:SI_UseManagedIdentity = $true; $global:SI_UAMI_ClientId = ''
        (Resolve-SILogIngestAuth -Bound @{ TenantId = 't' }).Mode | Should -Be 'ManagedIdentity'
        $global:SI_UseManagedIdentity = $false
        (Resolve-SILogIngestAuth -Bound @{ TenantId = 't' }).Mode | Should -Be 'Run'
        Mock Get-SIAzAccessToken { [pscustomobject]@{ Token = 'az-ctx'; ExpiresOn = [DateTimeOffset]::UtcNow.AddHours(1) } }
        Get-SILogIngestToken -Resource 'https://management.azure.com/' -Auth @{ Mode = 'Run' } | Should -Be 'az-ctx'
    }
    It 'a failed secret sign-in throws with Azure''s answer' {
        Mock Invoke-SILogIngestHttp { Status 401 '{"error":"invalid_client","error_description":"AADSTS7000215"}' }
        { Get-SILogIngestToken -Resource 'https://monitor.azure.com/' -Auth @{ Mode = 'Secret'; AppId = 'a'; TenantId = 't'; Secret = 'x' } } | Should -Throw '*AADSTS7000215*'
    }
}

Describe 'DCE / DCR lookup by name, in the configured scope only' {
    BeforeEach { Mock Get-SILogIngestToken { 'tok' } }
    It 'two rules with the same name in different resource groups: the configured one, read by its own id' {
        $dce = New-Dce 'rg-si'
        Put-Arm $dce.id $dce
        Put-Arm "/subscriptions/$($script:Sub)/resourceGroups/rg-other/providers/Microsoft.Insights/dataCollectionRules/dcr-x" (New-Dcr 'rg-other' 'dcr-x' 'imm-OTHER' $dce.id)
        Put-Arm "/subscriptions/$($script:Sub)/resourceGroups/rg-si/providers/Microsoft.Insights/dataCollectionRules/dcr-x"    (New-Dcr 'rg-si' 'dcr-x' 'imm-MINE' $dce.id)
        $r = Find-SILogResourceByName -Kind Dcr -Name 'dcr-x' -SubscriptionId $script:Sub -ResourceGroup 'rg-si'
        $r.properties.immutableId | Should -Be 'imm-MINE'
        $null = Send-SILogDataRest -Data @([pscustomobject]@{ a = 'x' }) -DcrName 'dcr-x' -DceName 'dce-si' -TableName 'T'
        $post = @($script:Calls | Where-Object { $_.Method -eq 'POST' })
        $post.Count | Should -Be 1
        $post[0].Uri | Should -BeLike '*/dataCollectionRules/imm-MINE/streams/*'
        @($script:Calls | Where-Object { $_.Uri -like '*Microsoft.ResourceGraph*' }).Count | Should -Be 0 -Because 'never a tenant-wide Resource Graph query'
    }
    It 'no resource group configured and the name is in two: refused, nothing posted' {
        $global:SI_DcrResourceGroup = $null
        Put-Arm "/subscriptions/$($script:Sub)/providers/Microsoft.Insights/dataCollectionRules" @{ value = @((New-Dcr 'rg-a' 'dcr-x' 'i1' 'e'), (New-Dcr 'rg-b' 'dcr-x' 'i2' 'e')) }
        { Send-SILogDataRest -Data @([pscustomobject]@{ a = 'x' }) -DcrName 'dcr-x' -DceName 'dce-si' -TableName 'T' } | Should -Throw '*exists 2 times*'
        @($script:Calls | Where-Object { $_.Method -eq 'POST' }).Count | Should -Be 0
    }
    It 'the lists are read per SUBSCRIPTION (never tenant-wide), and refuse without one' {
        Put-Arm "/subscriptions/$($script:Sub)/providers/Microsoft.Insights/dataCollectionEndpoints" @{ value = @((New-Dce 'rg-si'), (New-Dce 'rg-x')) }
        $l = Get-SIDceListRest -AzAppId 'a' -AzAppSecret 's' -TenantId 't'
        @($l).Count | Should -Be 2
        $l[0].subscriptionId | Should -Be $script:Sub
        $l[0].resourceGroup | Should -Be 'rg-si'
        $script:Calls.Count | Should -Be 1
        $script:Calls[0].Uri | Should -BeLike "https://management.azure.com/subscriptions/$($script:Sub)/providers/Microsoft.Insights/dataCollectionEndpoints?api-version=*"
        $global:SI_AzSubscriptionId = $null; $global:SI_WorkspaceResourceId = $null; $global:SubscriptionId = $null
        { Get-SIDcrListRest -AzAppId 'a' -AzAppSecret 's' -TenantId 't' } | Should -Throw '*never read tenant-wide*'
    }
    It 'lists follow nextLink' {
        $p1 = "/subscriptions/$($script:Sub)/providers/Microsoft.Insights/dataCollectionRules"
        Put-Arm $p1 @{ value = @((New-Dcr 'rg-a' 'r1' 'i1' 'e')); nextLink = "https://management.azure.com/subscriptions/$($script:Sub)/providers/Microsoft.Insights/dataCollectionRulesPage2?api-version=2022-06-01&`$skipToken=x" }
        Put-Arm "$p1`Page2" @{ value = @((New-Dcr 'rg-b' 'r2' 'i2' 'e')) }
        @(Get-SIDcrListRest).name -join ',' | Should -Be 'r1,r2'
    }
    It 'cached per run: the same rule is read once' {
        $p = "/subscriptions/$($script:Sub)/resourceGroups/rg-si/providers/Microsoft.Insights/dataCollectionRules/dcr-x"
        Put-Arm $p (New-Dcr 'rg-si' 'dcr-x' 'imm' 'e')
        $null = Find-SILogResourceByName -Kind Dcr -Name 'dcr-x' -SubscriptionId $script:Sub -ResourceGroup 'rg-si'
        $null = Find-SILogResourceByName -Kind Dcr -Name 'dcr-x' -SubscriptionId $script:Sub -ResourceGroup 'rg-si'
        @($script:Calls | Where-Object { $_.Method -eq 'GET' }).Count | Should -Be 1
    }
    It 'an endpoint not in its resource group: ONE of that name in the subscription is used, several refuse' {
        Put-Arm "/subscriptions/$($script:Sub)/providers/Microsoft.Insights/dataCollectionEndpoints" @{ value = @((New-Dce 'rg-elsewhere')) }
        (Find-SILogResourceByName -Kind Dce -Name 'dce-si' -SubscriptionId $script:Sub -ResourceGroup 'rg-si' -AnyResourceGroupWhenMissing).id | Should -Match 'rg-elsewhere'
        $global:SI_LogIngestRunCache = $null
        Put-Arm "/subscriptions/$($script:Sub)/providers/Microsoft.Insights/dataCollectionEndpoints" @{ value = @((New-Dce 'rg-a'), (New-Dce 'rg-b')) }
        { Find-SILogResourceByName -Kind Dce -Name 'dce-si' -SubscriptionId $script:Sub -ResourceGroup 'rg-si' -AnyResourceGroupWhenMissing } | Should -Throw '*exists 2 times*'
    }
}

Describe 'schema build -- the module''s type mapping' {
    It 'v3 runs on pwsh 7: an integer column declares long whatever the first row holds (no int/long split by row order)' -Skip:($PSVersionTable.PSVersion.Major -lt 7) {
        # The 2.2 exposure was PowerShell 5.1 + a small first value -> 'int', later values above 2,147,483,647 lost.
        # pwsh 7's JSON reader gives every integer Int64, so the declared type no longer depends on row order.
        $small = @(Get-SILogSchemaRest -Data @([pscustomobject]@{ N = 1024 }, [pscustomobject]@{ N = 8000000000 }) -As Array)
        $big   = @(Get-SILogSchemaRest -Data @([pscustomobject]@{ N = 8000000000 }, [pscustomobject]@{ N = 1024 }) -As Array)
        ($small | Where-Object name -eq 'N').type | Should -Be 'long'
        ($big   | Where-Object name -eq 'N').type | Should -Be 'long'
    }
    It 'types from the JSON round trip, the WHOLE set declares, Table adds TimeGenerated' {
        $rows = @(
            [pscustomobject]@{ S = 'x'; I = 5; L = 5000000000; B = $true; O = [pscustomobject]@{ k = 1 }; A = @(1, 2) },
            [pscustomobject]@{ S = 'y'; Late = 'only on row 2' }
        )
        $dcr = @(Get-SILogSchemaRest -Data $rows -As Array)
        ($dcr | Where-Object name -eq 'S').type | Should -Be 'string'
        # int vs long follows the host's JSON reader, as in the module: PS 5.1 reads 5 as Int32, pwsh 7 as Int64
        $hostInt = if ((ConvertFrom-Json '{"I":5}').I -is [long]) { 'long' } else { 'int' }
        ($dcr | Where-Object name -eq 'I').type | Should -Be $hostInt
        ($dcr | Where-Object name -eq 'L').type | Should -Be 'long'
        ($dcr | Where-Object name -eq 'B').type | Should -Be 'boolean'
        ($dcr | Where-Object name -eq 'O').type | Should -Be 'dynamic'
        ($dcr | Where-Object name -eq 'A').type | Should -Be 'dynamic'
        ($dcr | Where-Object name -eq 'Late').type | Should -Be 'string'
        $dcr.name | Should -Not -Contain 'TimeGenerated'
        $tbl = @(Get-SILogSchemaRest -Data $rows -As Hash -ReturnType Table)
        $tbl[0].name | Should -Be 'TimeGenerated'
        $tbl[0] | Should -BeOfType [hashtable]
        @(Get-SILogSchemaRest -Data $rows -As Hash).Count | Should -Be 0 -Because 'like Get-ObjectSchemaAsHash, nothing without -ReturnType'
    }
    It 'parity with AzLogDcrIngestPS on the same host (schema, column-name fix-up, alignment) when it is installed' {
        $m = Get-Module -ListAvailable -Name AzLogDcrIngestPS | Sort-Object Version -Descending | Select-Object -First 1
        if (-not $m) { Set-ItResult -Skipped -Because 'AzLogDcrIngestPS is not installed on this host'; return }
        $loaded = Get-Module -Name AzLogDcrIngestPS
        $mod = Import-Module $m.Path -PassThru -Force -DisableNameChecking -WarningAction SilentlyContinue
        try {
            $mk = { @(
                [pscustomobject]@{ Name = 'n1'; 'Bad-Name' = 'h'; 'a.b' = 1; Type = 'T'; id = 'x'; _Lead = 'l'; Count = 3; Big = 9000000000; Flag = $false; Obj = @{ q = 1 }; When = [datetime]'2026-10-03T10:00:00Z' },
                [pscustomobject]@{ Name = 'n2'; Extra = 'e'; ('X' * 50) = 'long name' }
            ) }
            $restSchema = @(Get-SILogSchemaRest -Data (& $mk) -As Array) | ForEach-Object { '{0}:{1}' -f $_.name, $_.type }
            $modSchema  = @(& $mod { param($d) Get-ObjectSchemaAsArray -Data $d } (& $mk)) | ForEach-Object { '{0}:{1}' -f $_.name, $_.type }
            ($restSchema -join '|') | Should -Be ($modSchema -join '|')
            $restFix = Repair-SILogColumnNameRest -Data (& $mk) | ConvertTo-Json -Depth 5 -Compress
            $modFix  = & $mod { param($d) ValidateFix-AzLogAnalyticsTableSchemaColumnNames -Data $d } (& $mk) | ConvertTo-Json -Depth 5 -Compress
            $restFix | Should -Be $modFix
            $restAl = Format-SILogRowsToSchemaRest -Data (Repair-SILogColumnNameRest -Data (& $mk)) | ConvertTo-Json -Depth 5 -Compress
            $modAl  = & $mod { param($d) Build-DataArrayToAlignWithSchema -Data (ValidateFix-AzLogAnalyticsTableSchemaColumnNames -Data $d) } (& $mk) | ConvertTo-Json -Depth 5 -Compress
            $restAl | Should -Be $modAl
            $restCol = Add-SIColumnDataRest -Data (& $mk) -Column1Name Computer -Column1Data 'h' -Column2Name UserLoggedOn -Column2Data 'u' | ConvertTo-Json -Depth 5 -Compress
            $modCol  = & $mod { param($d) Add-ColumnDataToAllEntriesInArray -Data $d -Column1Name Computer -Column1Data 'h' -Column2Name UserLoggedOn -Column2Data 'u' } (& $mk) | ConvertTo-Json -Depth 5 -Compress
            $restCol | Should -Be $modCol
        } finally { if (-not $loaded) { Remove-Module -ModuleInfo $mod -Force -ErrorAction SilentlyContinue } }
    }
}

Describe 'table + rule update is ADDITIVE only' {
    BeforeEach {
        Mock Get-SILogIngestToken { 'tok' }
        $script:tablePath = "$($script:Ws)/tables/T_CL"
        $script:dce = New-Dce 'rg-si'
        Put-Arm $script:dce.id $script:dce
    }
    It 'an existing table: only the missing column is added (PATCH), an existing column keeps its type, nothing is deleted' {
        Put-Arm $script:tablePath @{ properties = @{ schema = @{ name = 'T_CL'; columns = @(@{ name = 'TimeGenerated'; type = 'datetime' }, @{ name = 'a'; type = 'string' }, @{ name = 'b'; type = 'int' }); standardColumns = @(@{ name = 'TenantId'; type = 'guid' }) } } }
        $schema = @(@{ name = 'TimeGenerated'; type = 'datetime' }, @{ name = 'a'; type = 'int' }, @{ name = 'b'; type = 'int' }, @{ name = 'c'; type = 'long' })
        $out = Set-SILogTableRest -TableName 'T' -SchemaSourceObject $schema -AzLogWorkspaceResourceId $script:Ws
        "$out" | Should -Match '1 column\(s\) added \(c\)'
        $w = @($script:Calls | Where-Object { $_.Method -ne 'GET' })
        $w.Count | Should -Be 1
        $w[0].Method | Should -Be 'PATCH'
        $cols = ($w[0].Body | ConvertFrom-Json).properties.schema.columns
        ($cols | Where-Object name -eq 'a').type | Should -Be 'string'
        $cols.name -join ',' | Should -Be 'TimeGenerated,a,b,c'
        @($script:Calls | Where-Object { $_.Method -eq 'DELETE' }).Count | Should -Be 0
    }
    It 'no table: created with the data''s schema (PUT)' {
        $out = Set-SILogTableRest -TableName 'T' -SchemaSourceObject @(@{ name = 'TimeGenerated'; type = 'datetime' }, @{ name = 'a'; type = 'string' }) -AzLogWorkspaceResourceId $script:Ws
        "$out" | Should -Match 'created'
        $w = @($script:Calls | Where-Object { $_.Method -eq 'PUT' })
        $w.Count | Should -Be 1
        ($w[0].Body | ConvertFrom-Json).properties.schema.name | Should -Be 'T_CL'
    }
    It 'a refused table write FAILS with Azure''s answer -- the table is never deleted and re-created' {
        Put-Arm $script:tablePath @{ properties = @{ schema = @{ name = 'T_CL'; columns = @(@{ name = 'a'; type = 'string' }) } } }
        $script:Override = { param($m, $u) if ($m -eq 'PATCH') { Status 400 '{"error":{"code":"InvalidParameter","message":"User provided schema is invalid"}}' } }
        { Set-SILogTableRest -TableName 'T' -SchemaSourceObject @(@{ name = 'z'; type = 'string' }) -AzLogWorkspaceResourceId $script:Ws } | Should -Throw '*HTTP Status: 400*User provided schema is invalid*'
        @($script:Calls | Where-Object { $_.Method -eq 'DELETE' }).Count | Should -Be 0
    }
    It 'an existing rule: the new column is ADDED to its stream; its endpoint, transform and other columns are kept' {
        Put-Arm $script:tablePath @{ properties = @{ schema = @{ name = 'T_CL'; columns = @(@{ name = 'TimeGenerated'; type = 'datetime' }, @{ name = 'a'; type = 'string' }, @{ name = 'c'; type = 'long' }) } } }
        $bound = "/subscriptions/$($script:Sub)/resourceGroups/rg-dce-other/providers/Microsoft.Insights/dataCollectionEndpoints/dce-si"
        $p = "/subscriptions/$($script:Sub)/resourceGroups/rg-si/providers/Microsoft.Insights/dataCollectionRules/dcr-x"
        Put-Arm $p (New-Dcr 'rg-si' 'dcr-x' 'imm' $bound 'T' @(@{ name = 'a'; type = 'string' }, @{ name = 'old'; type = 'int' }) 'source | where a != ""')
        $out = Set-SILogDcrRest -SchemaSourceObject @(@{ name = 'a'; type = 'string' }, @{ name = 'c'; type = 'long' }) -AzLogWorkspaceResourceId $script:Ws -DceName 'dce-si' -DcrResourceGroup 'rg-si' -DcrName 'dcr-x' -TableName 'T'
        "$out" | Should -Match '1 column\(s\) added'
        $put = @($script:Calls | Where-Object { $_.Method -eq 'PUT' })
        $put.Count | Should -Be 1
        $b = $put[0].Body | ConvertFrom-Json
        $b.properties.dataCollectionEndpointId | Should -Be $bound -Because 'the rule is never re-bound (#198)'
        $b.properties.dataFlows[0].transformKql | Should -Be 'source | where a != ""'
        $b.properties.streamDeclarations.'Custom-T_CL'.columns.name -join ',' | Should -Be 'a,old,c'
        $b.properties.PSObject.Properties['immutableId'] | Should -BeNullOrEmpty
        Should -Invoke Start-Sleep -Times 0
    }
    It 'an existing rule with every column: no write' {
        Put-Arm $script:tablePath @{ properties = @{ schema = @{ name = 'T_CL'; columns = @(@{ name = 'TimeGenerated'; type = 'datetime' }, @{ name = 'a'; type = 'string' }) } } }
        Put-Arm "/subscriptions/$($script:Sub)/resourceGroups/rg-si/providers/Microsoft.Insights/dataCollectionRules/dcr-x" (New-Dcr 'rg-si' 'dcr-x' 'imm' $script:dce.id)
        $null = Set-SILogDcrRest -SchemaSourceObject @(@{ name = 'a'; type = 'string' }) -AzLogWorkspaceResourceId $script:Ws -DceName 'dce-si' -DcrResourceGroup 'rg-si' -DcrName 'dcr-x' -TableName 'T'
        @($script:Calls | Where-Object { $_.Method -ne 'GET' }).Count | Should -Be 0
    }
    It 'no rule: created in the configured subscription + resource group, on THIS install''s endpoint, then a wait for Azure to settle' {
        $global:SI_DceResourceGroup = 'rg-si'
        $null = Set-SILogDcrRest -SchemaSourceObject @(@{ name = 'a'; type = 'string' }) -AzLogWorkspaceResourceId $script:Ws -DceName 'dce-si' -DcrResourceGroup 'rg-si' -DcrName 'dcr-new' -TableName 'T'
        $put = @($script:Calls | Where-Object { $_.Method -eq 'PUT' })
        $put.Count | Should -Be 1
        $put[0].Uri | Should -BeLike "https://management.azure.com/subscriptions/$($script:Sub)/resourceGroups/rg-si/providers/Microsoft.Insights/dataCollectionRules/dcr-new?api-version=*"
        $b = $put[0].Body | ConvertFrom-Json
        $b.properties.dataCollectionEndpointId | Should -Be $script:dce.id
        $b.location | Should -Be 'westeurope'
        $b.properties.dataFlows[0].outputStream | Should -Be 'Custom-T_CL'
        Should -Invoke Start-Sleep -Times 1 -ParameterFilter { $Seconds -eq 15 }
    }
    It 'Update-SILogTableSchemaRest end to end on a fresh install: table, then rule, then the post uses that rule' {
        $global:SI_DceResourceGroup = 'rg-si'
        $rows = @([pscustomobject]@{ a = 'x'; n = 1 }, [pscustomobject]@{ a = 'y'; n = 2; late = 'z' })
        $null = Update-SILogTableSchemaRest -AzLogWorkspaceResourceId $script:Ws -AzAppId 'app' -AzAppSecret 's' -TenantId 't' -DceName 'dce-si' -DcrName 'dcr-new' `
                    -DcrResourceGroup 'rg-si' -TableName 'T' -Data $rows -AzDcrSetLogIngestApiAppPermissionsDcrLevel $false -AzLogDcrTableCreateFromAnyMachine $true -AzLogDcrTableCreateFromReferenceMachine @()
        $tbl = @($script:Calls | Where-Object { $_.Method -eq 'PUT' -and $_.Uri -like '*/tables/T_CL*' })
        $tbl.Count | Should -Be 1
        ($tbl[0].Body | ConvertFrom-Json).properties.schema.columns.name -join ',' | Should -Be 'TimeGenerated,a,n,late'
        $null = Send-SILogDataRest -Data $rows -DcrName 'dcr-new' -DceName 'dce-si' -TableName 'T'
        @($script:Calls | Where-Object { $_.Method -eq 'POST' })[0].Uri | Should -BeLike '*/dataCollectionRules/dcr-imm-new/streams/Custom-T_CL?api-version=2023-01-01'
    }
    It 'Update-SILogTableSchemaRest with nothing to add writes nothing' {
        Put-Arm $script:tablePath @{ properties = @{ schema = @{ name = 'T_CL'; columns = @(@{ name = 'TimeGenerated'; type = 'datetime' }, @{ name = 'a'; type = 'string' }) } } }
        Put-Arm "/subscriptions/$($script:Sub)/resourceGroups/rg-si/providers/Microsoft.Insights/dataCollectionRules/dcr-x" (New-Dcr 'rg-si' 'dcr-x' 'imm' $script:dce.id)
        $null = Update-SILogTableSchemaRest -AzLogWorkspaceResourceId $script:Ws -DcrName 'dcr-x' -DcrResourceGroup 'rg-si' -TableName 'T' -Data @([pscustomobject]@{ a = 'x' }) -AzLogDcrTableCreateFromAnyMachine $true -AzLogDcrTableCreateFromReferenceMachine @()
        @($script:Calls | Where-Object { $_.Method -ne 'GET' }).Count | Should -Be 0
    }
}

Describe 'upload' {
    BeforeEach {
        Mock Get-SILogIngestToken { 'tok-monitor' }
        $script:dce = New-Dce 'rg-si'
        Put-Arm $script:dce.id $script:dce
        Put-Arm "/subscriptions/$($script:Sub)/resourceGroups/rg-si/providers/Microsoft.Insights/dataCollectionRules/dcr-x" (New-Dcr 'rg-si' 'dcr-x' 'imm-1' $script:dce.id)
        $script:rows = @(1..40 | ForEach-Object { [pscustomobject]@{ Id_ = $_; Text = ('r{0}-' -f $_) + ('x' * (100 + ($_ % 7) * 30)); Nested = [pscustomobject]@{ k = $_ } } })
        $script:Send = { param($rows, [long]$max = 2000, $compress = $false) Send-SILogDataRest -Data $rows -DcrName 'dcr-x' -DceName 'dce-si' -TableName 'T' -MaxPayloadBytes $max -EnableCompression $compress 6>$null }
    }
    It 'posts to the rule''s OWN endpoint, the rule''s immutable id, Custom-<table>_CL, api-version 2023-01-01, as the monitor audience' {
        $r = & $script:Send @($script:rows[0]) 1MB
        $post = @($script:Calls | Where-Object { $_.Method -eq 'POST' })
        $post[0].Uri | Should -Be ('https://dce-si-rg-si.westeurope-1.ingest.monitor.azure.com/dataCollectionRules/imm-1/streams/Custom-T_CL?api-version=2023-01-01')
        $post[0].Headers['Authorization'] | Should -Be 'Bearer tok-monitor'
        Should -Invoke Get-SILogIngestToken -ParameterFilter { $Resource -eq 'https://monitor.azure.com/' }
        $r.RowsPosted | Should -Be 1
    }
    It 'batches are sized from the MEASURED bytes: every payload under the limit, no batch could have taken the next row, all rows posted once' {
        $r = & $script:Send $script:rows 2000
        $posts = @($script:Calls | Where-Object { $_.Method -eq 'POST' })
        $posts.Count | Should -BeGreaterThan 3
        $sizes = @($posts | ForEach-Object { ([byte[]]$_.Body).Length })
        foreach ($s in $sizes) { $s | Should -BeLessOrEqual 2000 }
        $posted = @(Get-PostedRows $posts)
        $posted.Count | Should -Be 40
        ($posted.Id_ -join ',') | Should -Be ((1..40) -join ',')
        for ($i = 0; $i -lt $posts.Count - 1; $i++) {
            $nextRowId = @(Get-PostedRows @($posts[$i + 1]))[0].Id_
            $nextLen = [System.Text.Encoding]::UTF8.GetByteCount((ConvertTo-Json -Depth 100 -InputObject $script:rows[$nextRowId - 1] -Compress))
            ($sizes[$i] + 1 + $nextLen) | Should -BeGreaterThan 2000 -Because 'a batch closes only when the next row would not fit'
        }
        $r.RowsPosted | Should -Be 40
        $r.Batches | Should -Be $posts.Count
    }
    It 'rows are serialised exactly as the module did (ConvertTo-Json -Depth 100 -Compress): a nested object stays an object' {
        $null = & $script:Send @($script:rows[0]) 1MB
        $body = Expand-Body (@($script:Calls | Where-Object { $_.Method -eq 'POST' })[0].Body) @{}
        $body | Should -Be ('[' + (ConvertTo-Json -Depth 100 -InputObject $script:rows[0] -Compress) + ']')
    }
    It 'compressed: gzip on the wire, each COMPRESSED payload under the limit, every row posted' {
        $null = & $script:Send $script:rows 600 $true
        $posts = @($script:Calls | Where-Object { $_.Method -eq 'POST' })
        foreach ($p in $posts) { $p.Headers['Content-Encoding'] | Should -Be 'gzip'; ([byte[]]$p.Body).Length | Should -BeLessOrEqual 600 }
        @(Get-PostedRows $posts).Count | Should -Be 40
    }
    It 'compression follows $global:EnableCompressionDefault when not passed, as the module did' {
        $global:EnableCompressionDefault = $true
        $null = Send-SILogDataRest -Data @($script:rows[0]) -DcrName 'dcr-x' -DceName 'dce-si' -TableName 'T' 6>$null
        @($script:Calls | Where-Object { $_.Method -eq 'POST' })[0].Headers['Content-Encoding'] | Should -Be 'gzip'
    }
    It '429: waits the Retry-After the service sent, then posts again' {
        $script:n = 0
        $script:Ingest = { param($u, $h, $b) $script:n++; if ($script:n -eq 1) { Status 429 '{"error":"throttled"}' '7' } else { Status 204 } }
        $r = & $script:Send @($script:rows[0]) 1MB
        $r.RowsPosted | Should -Be 1
        @($script:Calls | Where-Object { $_.Method -eq 'POST' }).Count | Should -Be 2
        Should -Invoke Start-Sleep -Times 1 -ParameterFilter { $Seconds -eq 7 }
    }
    It '503 without Retry-After: retried with back-off' {
        $script:n = 0
        $script:Ingest = { param($u, $h, $b) $script:n++; if ($script:n -le 2) { Status 503 'busy' } else { Status 204 } }
        $null = & $script:Send @($script:rows[0]) 1MB
        @($script:Calls | Where-Object { $_.Method -eq 'POST' }).Count | Should -Be 3
        Should -Invoke Start-Sleep -Times 2
    }
    It '400: fails at once with the response body -- re-sending an invalid request fails identically' {
        $script:Ingest = { param($u, $h, $b) Status 400 '{"error":{"code":"InvalidStream","message":"Stream Custom-T_CL is not declared"}}' }
        { & $script:Send @($script:rows[0]) 1MB } | Should -Throw '*Log Ingestion API request failed. HTTP Status: 400*InvalidStream*'
        @($script:Calls | Where-Object { $_.Method -eq 'POST' }).Count | Should -Be 1
        Should -Invoke Start-Sleep -Times 0
    }
    It 'a persistent 5xx gives up after the retries and says so' {
        $script:Ingest = { param($u, $h, $b) Status 500 'boom' }
        { & $script:Send @($script:rows[0]) 1MB } | Should -Throw '*HTTP Status: 500*'
        @($script:Calls | Where-Object { $_.Method -eq 'POST' }).Count | Should -Be 6
    }
    It 'the rows posted are COUNTED against the rows given: a shortfall throws, it is never reported as done' {
        Mock Send-SILogIngestBatch { $State.Posted += ($Rows.Count - 1); $State.Batches++ }
        { & $script:Send $script:rows 2000 } | Should -Throw '*Posted * of 40 row(s)*UNKNOWN*'
    }
    It 'a single row larger than the limit is refused, not truncated' {
        { & $script:Send @([pscustomobject]@{ big = ('x' * 3000) }) 2000 } | Should -Throw '*single record*larger than*'
    }
    It 'no rule in scope: refused before anything is posted' {
        { Send-SILogDataRest -Data @($script:rows[0]) -DcrName 'dcr-missing' -DceName 'dce-si' -TableName 'T' } | Should -Throw "*'dcr-missing' was not found*nothing was posted*"
    }
    It 'nothing to post: nothing is called' {
        Send-SILogDataRest -Data @() -DcrName 'dcr-x' -DceName 'dce-si' -TableName 'T' | Should -BeNullOrEmpty
        $script:Calls.Count | Should -Be 0
    }
}

Describe 'the real HTTP seam (not mocked) reads a status, its body and Retry-After the same way on 5.1 and 7' {
    BeforeAll {
        # a one-shot raw HTTP responder on loopback -- no HttpListener (that needs a URL reservation on Windows)
        function script:Invoke-OneShotHttp([string]$Response, [scriptblock]$Client) {
            $l = New-Object System.Net.Sockets.TcpListener([System.Net.IPAddress]::Loopback, 0); $l.Start()
            $port = ([System.Net.IPEndPoint]$l.LocalEndpoint).Port
            $ps = [powershell]::Create()
            $null = $ps.AddScript({ param($l, $resp)
                $c = $l.AcceptTcpClient(); $s = $c.GetStream(); $buf = New-Object byte[] 65536; $got = ''
                do { $n = $s.Read($buf, 0, $buf.Length); $got += [System.Text.Encoding]::ASCII.GetString($buf, 0, $n) } while ($got -notmatch "`r`n`r`n" -and $n -gt 0)
                if ($got -match 'Content-Length:\s*(\d+)') { $len = [int]$Matches[1]; $have = $got.Length - ($got.IndexOf("`r`n`r`n") + 4); while ($have -lt $len) { $n = $s.Read($buf, 0, $buf.Length); $have += $n } }
                $b = [System.Text.Encoding]::ASCII.GetBytes($resp); $s.Write($b, 0, $b.Length); $s.Flush(); Start-Sleep -Milliseconds 200; $c.Close()
            }).AddArgument($l).AddArgument($Response)
            $h = $ps.BeginInvoke()
            try { & $Client ("http://127.0.0.1:{0}/x" -f $port) } finally { $null = $h.AsyncWaitHandle.WaitOne(5000); $ps.Dispose(); $l.Stop() }
        }
    }
    It '429 with Retry-After: status, header and body come back, nothing is thrown' {
        $body = '{"error":"throttled"}'
        $r = Invoke-OneShotHttp ("HTTP/1.1 429 Too Many Requests`r`nRetry-After: 7`r`nContent-Type: application/json`r`nContent-Length: {0}`r`nConnection: close`r`n`r`n{1}" -f $body.Length, $body) {
            param($u)
            (Get-Item function:Invoke-SILogIngestHttp).ScriptBlock.Invoke('POST', $u, @{ 'Content-Encoding' = 'gzip' }, [byte[]](1, 2, 3), 'application/json', 30)
        }
        $r = @($r)[0]
        $r.StatusCode | Should -Be 429
        $r.RetryAfter | Should -Be '7'
        $r.Content | Should -Be $body
    }
    It '400: the body is returned for the error message' {
        $body = '{"error":{"code":"InvalidStream"}}'
        $r = Invoke-OneShotHttp ("HTTP/1.1 400 Bad Request`r`nContent-Length: {0}`r`nConnection: close`r`n`r`n{1}" -f $body.Length, $body) {
            param($u) (Get-Item function:Invoke-SILogIngestHttp).ScriptBlock.Invoke('GET', $u, $null, $null, $null, 30)
        }
        $r = @($r)[0]
        $r.StatusCode | Should -Be 400
        $r.Content | Should -Be $body
    }
    It 'no listener at all: status 0, not an exception (treated as transient by the retry rule)' {
        $l = New-Object System.Net.Sockets.TcpListener([System.Net.IPAddress]::Loopback, 0); $l.Start(); $port = ([System.Net.IPEndPoint]$l.LocalEndpoint).Port; $l.Stop()
        $r = @((Get-Item function:Invoke-SILogIngestHttp).ScriptBlock.Invoke('GET', ("http://127.0.0.1:{0}/x" -f $port), $null, $null, $null, 10))[0]
        $r.StatusCode | Should -Be 0
    }
}

Describe 'CollectionTime -- identical across every batch and shard of one run' {
    BeforeEach {
        Mock Get-SILogIngestToken { 'tok' }
        $dce = New-Dce 'rg-si'; Put-Arm $dce.id $dce
        Put-Arm "/subscriptions/$($script:Sub)/resourceGroups/rg-si/providers/Microsoft.Insights/dataCollectionRules/dcr-x" (New-Dcr 'rg-si' 'dcr-x' 'imm-1' $dce.id)
    }
    It 'one value per run: two calls, rows split over many batches, every posted row carries the same CollectionTime' {
        $a = Add-SICollectionTimeRest -Data @(1..15 | ForEach-Object { [pscustomobject]@{ n = $_; pad = ('p' * 120) } })
        $b = Add-SICollectionTimeRest -Data @(16..30 | ForEach-Object { [pscustomobject]@{ n = $_; pad = ('p' * 120) } })
        $null = Send-SILogDataRest -Data (@($a) + @($b)) -DcrName 'dcr-x' -DceName 'dce-si' -TableName 'T' -MaxPayloadBytes 1500 6>$null
        $posts = @($script:Calls | Where-Object { $_.Method -eq 'POST' })
        $posts.Count | Should -BeGreaterThan 2
        $times = @(Get-PostedRows $posts | ForEach-Object { [string]$_.CollectionTime })
        $times.Count | Should -Be 30
        @($times | Sort-Object -Unique).Count | Should -Be 1
        $global:SI_LogIngestRunCollectionTime | Should -BeOfType [datetime]
    }
    It 'a row already stamped with the run''s CollectionTime keeps it (the shards'' shared value is never overwritten)' {
        $shared = [datetime]'2026-10-03T08:00:00'
        $rows = @([pscustomobject]@{ n = 1; CollectionTime = $shared }, [pscustomobject]@{ n = 2 })
        $out = Add-SICollectionTimeRest -Data $rows
        $out[0].CollectionTime | Should -Be $shared
        $out[1].CollectionTime | Should -BeOfType [datetime]
    }
}
}
